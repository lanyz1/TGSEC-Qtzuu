# Unbounded `SlotData::All` requests enable store and block-processing DoS

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2284](https://github.com/0xMiden/node/pull/2284)
- Severity: medium
- Maintainer validity: valid

## Summary

`get_account` enforces `QueryParamStorageMapKeyTotalLimit` only over `SlotData::MapKeys`, while `SlotData::All` contributes nothing to the limit and `AccountDetailRequest` places no separate bound on the length of `storage_requests`. The store then splits out every `SlotData::All` request and processes them one by one, so a caller can repeat the same all-entry slot many times in a single request and force repeated forest lookups or database-backed reconstruction. When a requested map is not already available from the forest cache, `reconstruct_storage_map_details_from_db` rebuilds the map from SQLite and then acquires the forest write lock to cache the keys. Because `apply_block` requires that same write lock, these attacker-controlled all-entry requests can translate directly into long sequences of expensive DB work and lock acquisitions. The missing bound and deduplication on `SlotData::All` therefore turns a public account query into an attacker-controlled denial-of-service path against both RPC handling and chain-state advancement.

## Impact

A single unauthenticated caller can send one valid `get_account` request that drives large amounts of CPU, memory, database, and response-allocation work by including many `SlotData::All` entries. On cache misses, the request also repeatedly acquires the forest write lock needed by `apply_block`, which can delay block application and make store-backed RPCs time out or become unavailable. Repeating the request from one or more clients can sustain a service outage and stall chain progress until the load stops.

## Root Cause

The implementation treats `SlotData::All` as free at the RPC boundary and later executes each entry independently without a cap or deduplication, even though cache-miss handling takes the same forest write lock used by `apply_block`.

## Source Locations

### 1. crates/rpc/src/server/api.rs:709-727

Only `MapKeys` contribute to the enforced limit; all-entry requests are forwarded to the store.

```text
// Validate total storage map key limit before forwarding to store
        if let Some(details) = &request.details {
            let _span = info_span!(target: COMPONENT, "validate_storage_map_keys").entered();
            let total_keys: usize = details
                .storage_requests
                .iter()
                .filter_map(|d| match &d.slot_data {
                    SlotData::All => None,
                    SlotData::MapKeys(items) => Some(items.len()),
                })
                .sum();
            check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
        }

        let account_data = self
            .store
            .get_account(request.account_id, request.block_num, request.details)
            .await
            .map_err(get_account_error_to_status)?;
```

### 2. crates/proto/src/domain/account.rs:166-170

Account details contain an attacker-controlled vector of storage map requests.

```text
pub struct AccountDetailRequest {
    pub code_commitment: Option<Word>,
    pub asset_vault_commitment: Option<Word>,
    pub storage_requests: Vec<StorageMapRequest>,
}
```

### 3. crates/proto/src/domain/account.rs:230-233

`SlotData::All` is a distinct request variant with no key count.

```text
pub enum SlotData {
    All,
    MapKeys(Vec<StorageMapKey>),
}
```

### 4. crates/store/src/state/mod.rs:991-1003

The store collects every all-entry request into `all_entries_requests`.

```text
for (index, StorageMapRequest { slot_name, slot_data }) in
            storage_requests.into_iter().enumerate()
        {
            storage_request_slots.push(slot_name.clone());
            match slot_data {
                SlotData::MapKeys(keys) => {
                    map_keys_requests.push((index, slot_name, keys));
                },
                SlotData::All => {
                    all_entries_requests.push((index, slot_name));
                },
            }
        }
```

### 5. crates/store/src/state/mod.rs:1029-1039

Each all-entry request triggers forest lookup or database reconstruction.

```text
for (index, slot_name) in all_entries_requests {
            let details = match self
                .get_storage_map_details_from_forest(account_id, &slot_name, block_num)?
            {
                Some(details) => details,
                None => {
                    self.reconstruct_storage_map_details_from_db(account_id, slot_name, block_num)
                        .await?
                },
            };
            storage_map_details_by_index[index] = Some(details);
```

### 6. crates/store/src/state/mod.rs:926-1062

fetch_public_account_details: unbounded sequential processing of storage_requests, forest read/write lock usage per entry

```text
#[expect(clippy::too_many_lines)]
    #[instrument(target = COMPONENT, skip_all)]
    async fn fetch_public_account_details(
        &self,
        account_id: AccountId,
        block_num: BlockNumber,
        detail_request: AccountDetailRequest,
    ) -> Result<AccountDetails, GetAccountError> {
        let AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_requests,
        } = detail_request;

        if !account_id.is_public() {
            return Err(GetAccountError::AccountNotPublic(account_id));
        }

        // Validate block exists in the blockchain before querying the database
        {
            let inner = self.inner.read().instrument(tracing::info_span!("acquire_inner")).await;
            let latest_block_num = inner.latest_block_num();

            if block_num > latest_block_num {
                return Err(GetAccountError::UnknownBlock(block_num));
            }
        }

        // Query account header and storage header together in a single DB call
        let (account_header, storage_header) = self
            .db
            .select_account_header_with_storage_header_at_block(account_id, block_num)
            .await?
            .ok_or(GetAccountError::AccountNotFound(account_id, block_num))?;

        let account_code = match code_commitment {
            Some(commitment) if commitment == account_header.code_commitment() => None,
            Some(_) => {
                self.db
                    .select_account_code_by_commitment(account_header.code_commitment())
                    .await?
            },
            None => None,
        };

        let vault_details = match asset_vault_commitment {
            Some(commitment) if commitment == account_header.vault_root() => {
                AccountVaultDetails::empty()
            },
            Some(_) => self.with_forest_read_blocking(|forest| {
                forest.get_vault_details(account_id, block_num).map_err(|err| {
                    DatabaseError::DataCorrupted(format!(
                        "failed to reconstruct vault for account {account_id} at block {block_num}: {err}"
                    ))
                })
            })?,
            None => AccountVaultDetails::empty(),
        };

        let mut storage_map_details =
            Vec::<AccountStorageMapDetails>::with_capacity(storage_requests.len());
        let mut map_keys_requests = Vec::new();
        let mut all_entries_requests = Vec::new();
        let mut storage_request_slots = Vec::with_capacity(storage_requests.len());

        for (index, StorageMapRequest { slot_name, slot_data }) in
            storage_requests.into_iter().enumerate()
        {
            storage_request_slots.push(slot_name.clone());
            match slot_data {
                SlotData::MapKeys(keys) => {
                    map_keys_requests.push((index, slot_name, keys));
                },
                SlotData::All => {
                    all_entries_requests.push((index, slot_name));
                },
            }
        }

        let mut storage_map_details_by_index = vec![None; storage_request_slots.len()];

        if !map_keys_requests.is_empty() {
            self.with_forest_read_blocking(|forest| {
                for (index, slot_name, keys) in map_keys_requests {
                    let details = forest
                        .get_storage_map_details_for_keys(
                            account_id,
                            slot_name.clone(),
                            block_num,
                            &keys,
                        )
                        .ok_or_else(|| DatabaseError::StorageRootNotFound {
                            account_id,
                            slot_name: slot_name.to_string(),
                            block_num,
                        })?
                        .map_err(DatabaseError::MerkleError)?;
                    storage_map_details_by_index[index] = Some(details);
                }
                Ok::<(), DatabaseError>(())
            })?;
        }

        for (index, slot_name) in all_entries_requests {
            let details = match self
                .get_storage_map_details_from_forest(account_id, &slot_name, block_num)?
            {
                Some(details) => details,
                None => {
                    self.reconstruct_storage_map_details_from_db(account_id, slot_name, block_num)
                        .await?
                },
            };
            storage_map_details_by_index[index] = Some(details);
        }

        for (details, slot_name) in
            storage_map_details_by_index.into_iter().zip(storage_request_slots)
        {
            let details = details.ok_or_else(|| DatabaseError::StorageRootNotFound {
                account_id,
                slot_name: slot_name.to_string(),
                block_num,
            })?;
            storage_map_details.push(details);
        }

        Ok(AccountDetails {
            account_header,
            account_code,
            vault_details,
            storage_details: AccountStorageDetails {
                header: storage_header,
                map_details: storage_map_details,
            },
        })
    }
```

### 7. crates/store/src/state/mod.rs:889-914

reconstruct_storage_map_details_from_db acquires forest write lock via cache_storage_map_keys after each DB reconstruction

```text
/// Returns storage map details by reconstructing the storage map from the database.
    async fn reconstruct_storage_map_details_from_db(
        &self,
        account_id: AccountId,
        slot_name: StorageSlotName,
        block_num: BlockNumber,
    ) -> Result<AccountStorageMapDetails, DatabaseError> {
        let details = self
            .db
            .reconstruct_storage_map_from_db(
                account_id,
                slot_name,
                block_num,
                Some(AccountStorageMapDetails::MAX_RETURN_ENTRIES),
            )
            .await?;

        if let StorageMapEntries::AllEntries(entries) = &details.entries {
            self.forest
                .write()
                .await
                .cache_storage_map_keys(entries.iter().map(|(raw_key, _)| *raw_key));
        }

        Ok(details)
    }
```

### 8. crates/store/src/state/apply_block.rs:179-181

apply_block needs the same forest write lock to commit a block

```text
self.with_forest_write_blocking(|forest| {
            forest.apply_block_updates(block_num, account_deltas)
        })?;
```

### 9. crates/rpc/src/server/api.rs:710-721

RPC-side limit only counts MapKeys; SlotData::All is filter-mapped out and uncounted

```text
if let Some(details) = &request.details {
            let _span = info_span!(target: COMPONENT, "validate_storage_map_keys").entered();
            let total_keys: usize = details
                .storage_requests
                .iter()
                .filter_map(|d| match &d.slot_data {
                    SlotData::All => None,
                    SlotData::MapKeys(items) => Some(items.len()),
                })
                .sum();
            check::<QueryParamStorageMapKeyTotalLimit>(total_keys)?;
        }
```

### 10. crates/proto/src/domain/account.rs:165-199

AccountDetailRequest conversion does not bound storage_requests length

```text
/// Represents a request for account details alongside specific storage data.
pub struct AccountDetailRequest {
    pub code_commitment: Option<Word>,
    pub asset_vault_commitment: Option<Word>,
    pub storage_requests: Vec<StorageMapRequest>,
}

impl TryFrom<proto::rpc::account_request::AccountDetailRequest> for AccountDetailRequest {
    type Error = ConversionError;

    fn try_from(
        value: proto::rpc::account_request::AccountDetailRequest,
    ) -> Result<Self, Self::Error> {
        let proto::rpc::account_request::AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_maps,
        } = value;

        let code_commitment =
            code_commitment.map(TryFrom::try_from).transpose().context("code_commitment")?;
        let asset_vault_commitment = asset_vault_commitment
            .map(TryFrom::try_from)
            .transpose()
            .context("asset_vault_commitment")?;
        let storage_requests =
            try_convert(storage_maps).collect::<Result<_, _>>().context("storage_maps")?;

        Ok(AccountDetailRequest {
            code_commitment,
            asset_vault_commitment,
            storage_requests,
        })
    }
}
```

### 11. crates/store/src/state/mod.rs:991-1039

Store code separates every `SlotData::All` entry and performs work once per request.

```text
for (index, StorageMapRequest { slot_name, slot_data }) in
            storage_requests.into_iter().enumerate()
        {
            storage_request_slots.push(slot_name.clone());
            match slot_data {
                SlotData::MapKeys(keys) => {
                    map_keys_requests.push((index, slot_name, keys));
                },
                SlotData::All => {
                    all_entries_requests.push((index, slot_name));
                },
            }
        }

        let mut storage_map_details_by_index = vec![None; storage_request_slots.len()];

        if !map_keys_requests.is_empty() {
            self.with_forest_read_blocking(|forest| {
                for (index, slot_name, keys) in map_keys_requests {
                    let details = forest
                        .get_storage_map_details_for_keys(
                            account_id,
                            slot_name.clone(),
                            block_num,
                            &keys,
                        )
                        .ok_or_else(|| DatabaseError::StorageRootNotFound {
                            account_id,
                            slot_name: slot_name.to_string(),
                            block_num,
                        })?
                        .map_err(DatabaseError::MerkleError)?;
                    storage_map_details_by_index[index] = Some(details);
                }
                Ok::<(), DatabaseError>(())
            })?;
        }

        for (index, slot_name) in all_entries_requests {
            let details = match self
                .get_storage_map_details_from_forest(account_id, &slot_name, block_num)?
            {
                Some(details) => details,
                None => {
                    self.reconstruct_storage_map_details_from_db(account_id, slot_name, block_num)
                        .await?
                },
            };
            storage_map_details_by_index[index] = Some(details);
        }
```

