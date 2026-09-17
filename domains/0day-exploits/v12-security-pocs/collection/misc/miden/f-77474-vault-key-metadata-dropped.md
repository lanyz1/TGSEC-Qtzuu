# Vault key metadata dropped

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2222](https://github.com/0xMiden/node/pull/2222)
- Severity: high
- Maintainer validity: valid

## Summary

The partial-delta vault path collapses each fungible `vault_key` to only its `faucet_id` before reading and writing balances. `prepare_partial_account_update()` receives the authoritative delta key but calls `vault_key.faucet_id()`, and `select_vault_balances_by_faucet_ids()` reconstructs lookup keys with `FungibleAsset::new(*faucet_id, 0).vault_key()` instead of preserving the original key. The same loss happens when the pending row is built: the code constructs `prev_asset` and `delta` from only `faucet_id`, then pushes `new_balance.vault_key()` for insertion. Repository tests show fungible `AssetVaultKey` construction includes an `AssetCallbackFlag`, so callback-enabled and callback-disabled assets from the same faucet are distinct vault keys even though this path aliases them by faucet ID. The account row's `vault_root` is computed from the full existing vault and the original delta, but the follow-up `account_vault_assets` row stores the metadata-stripped key, leaving the persisted vault details inconsistent with the committed account root.

## Impact

A valid transaction involving a callback-enabled fungible asset can commit an account row whose root no longer matches the persisted vault-asset detail rows. Subsequent partial updates reload those detail rows to recompute the vault root, so affected accounts can fail commitment checks and become unable to process future updates through the store.

## Root Cause

`select_vault_balances_by_faucet_ids()` and the partial-update caller use `AccountId` faucet IDs as the identity for fungible vault entries. This drops metadata carried by `AssetVaultKey`, including callback flags, before persisting the updated vault row.

## Source Locations

### 1. crates/store/src/db/models/queries/accounts/delta.rs:150-189

Balance lookup accepts only faucet IDs and reconstructs vault keys via `FungibleAsset::new(...).vault_key()`.

```text
pub(super) fn select_vault_balances_by_faucet_ids(
    conn: &mut SqliteConnection,
    account_id: AccountId,
    faucet_ids: &[AccountId],
) -> Result<HashMap<AccountId, u64>, DatabaseError> {
    use schema::account_vault_assets as vault;

    if faucet_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let account_id_bytes = account_id.to_bytes();

    // Compute vault keys for each faucet ID
    let vault_keys: Vec<Vec<u8>> = Result::from_iter(faucet_ids.iter().map(|faucet_id| {
        let asset = FungibleAsset::new(*faucet_id, 0)
            .map_err(|_| DatabaseError::DataCorrupted(format!("Invalid faucet id {faucet_id}")))?;
        let key: Word = asset.vault_key().into();
        Ok::<_, DatabaseError>(key.to_bytes())
    }))?;

    let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> =
        SelectDsl::select(vault::table, (vault::vault_key, vault::asset))
            .filter(vault::account_id.eq(&account_id_bytes))
            .filter(vault::is_latest.eq(true))
            .filter(vault::vault_key.eq_any(&vault_keys))
            .load(conn)?;

    let mut balances = HashMap::from_iter(faucet_ids.iter().map(|faucet_id| (*faucet_id, 0)));

    for (_vault_key_bytes, maybe_asset_bytes) in entries {
        if let Some(asset_bytes) = maybe_asset_bytes {
            let asset = Asset::read_from_bytes(&asset_bytes)?;
            if let Asset::Fungible(fungible) = asset {
                balances.insert(fungible.faucet_id(), fungible.amount().as_u64());
            }
        }
    }

    Ok(balances)
```

### 2. crates/store/src/db/models/queries/accounts.rs:1187-1211

The partial update derives `faucet_id` from the original `vault_key`, reconstructs assets from only that ID, and queues the reconstructed key for insertion.

```text
let faucet_ids =
        Vec::from_iter(delta.vault().fungible().iter().map(|(vault_key, _)| vault_key.faucet_id()));
    let prev_balances = select_vault_balances_by_faucet_ids(conn, account_id, &faucet_ids)?;

    // Encode `Some` as update and `None` as removal.
    let mut assets = Vec::new();

    // Update fungible assets.
    for (vault_key, amount_delta) in delta.vault().fungible().iter() {
        let faucet_id = vault_key.faucet_id();
        let prev_amount = prev_balances.get(&faucet_id).copied().unwrap_or(0);
        let prev_asset = FungibleAsset::new(faucet_id, prev_amount)?;
        let amount_abs = amount_delta.unsigned_abs();
        let delta = FungibleAsset::new(faucet_id, amount_abs)?;
        let new_balance = if *amount_delta < 0 {
            prev_asset.sub(delta)?
        } else {
            prev_asset.add(delta)?
        };
        let update_or_remove = if new_balance.amount().as_u64() == 0 {
            None
        } else {
            Some(Asset::from(new_balance))
        };
        assets.push((account_id, new_balance.vault_key(), update_or_remove));
```

### 3. crates/store/src/db/models/queries/accounts.rs:1247-1252

The account row's vault root is recomputed from the full vault and original delta, creating a split from the metadata-stripped pending row.

```text
// --- Update the vault root by constructing the asset vault from DB.
    let new_vault_root = {
        let assets = select_latest_vault_assets(conn, account_id)?;
        let mut vault = AssetVault::new(&assets)?;
        vault.apply_delta(delta.vault())?;
        vault.root()
```

### 4. crates/store/src/db/models/queries/accounts.rs:1458-1459

Queued vault detail rows are inserted after the account row is written.

```text
for (acc_id, vault_key, update) in pending_asset_inserts {
            insert_account_vault_asset(conn, acc_id, block_num, vault_key, update)?;
```

### 5. crates/store/src/db/models/queries/accounts/delta.rs:201-219

Future partial updates reload persisted latest vault detail rows to reconstruct `AssetVault`.

```text
pub(super) fn select_latest_vault_assets(
    conn: &mut SqliteConnection,
    account_id: AccountId,
) -> Result<Vec<Asset>, DatabaseError> {
    use schema::account_vault_assets as vault;

    let entries: Vec<(Vec<u8>, Option<Vec<u8>>)> =
        SelectDsl::select(vault::table, (vault::vault_key, vault::asset))
            .filter(vault::account_id.eq(account_id.to_bytes()))
            .filter(vault::is_latest.eq(true))
            .load(conn)?;

    entries
        .into_iter()
        .filter_map(|(_vault_key_bytes, maybe_asset_bytes)| {
            maybe_asset_bytes.map(|bytes| Asset::read_from_bytes(&bytes))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
```

### 6. crates/store/src/db/models/queries/accounts/tests.rs:1013-1040

Repository usage shows fungible `AssetVaultKey` construction includes an `AssetCallbackFlag`, so faucet ID alone is not the full key identity.

```text
use miden_protocol::asset::{AssetCallbackFlag, AssetVaultKey, FungibleAsset};
    use miden_protocol::testing::account_id::ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET;

    let mut conn = setup_test_db();
    let (account, _) = create_test_account_with_storage();
    let account_id = account.id();

    let faucet_id = AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET).unwrap();

    let blocks: Vec<BlockNumber> = (0..BLOCK_COUNT).map(BlockNumber::from).collect();

    for block in &blocks {
        insert_block_header(&mut conn, *block);
    }

    let delta = AccountDelta::try_from(account.clone()).unwrap();
    let account_update = BlockAccountUpdate::new(
        account_id,
        account.to_commitment(),
        AccountUpdateDetails::Delta(delta),
    );

    for block in &blocks {
        upsert_accounts(&mut conn, std::slice::from_ref(&account_update), *block)
            .expect("upsert_accounts failed");
    }

    let vault_key = AssetVaultKey::new_fungible(faucet_id, AssetCallbackFlag::Disabled);
```

