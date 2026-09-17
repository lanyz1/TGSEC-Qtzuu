# Mutable same-height signing lets the validator equivocate

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2283](https://github.com/0xMiden/node/pull/2283)
- Severity: high
- Maintainer validity: valid

## Summary

The validator allows a proposal whose `block_num()` equals the current tip to be handled as a mutable replacement instead of an already-final signed block. In that branch, `validate_block` only requires the proposal to point to the parent of the current tip, so a different header at the same height can pass validation as long as it shares the same parent commitment. The `sign_block` flow then signs that new header and persists it with `upsert_block_header`, which uses `replace_into` to overwrite the previously stored header for that height. Because `load_chain_tip` later derives the tip only from the highest stored row, the validator's local view silently switches to the newer header even though the earlier signature remains valid. Fixing this requires making signed history immutable for a given height or commitment and rejecting any second distinct header once a block number has already been signed.

## Impact

A caller that can reach `sign_block`, including the normal block-producer path, can obtain two valid validator signatures for conflicting headers at the same height. Different downstream consumers can then accept incompatible histories based on different signed headers, causing rollback- or double-spend-like finality failures without compromising the validator key.

## Root Cause

The validator models signed blocks as a mutable per-height tip by combining same-height acceptance in `validate_block` with overwrite semantics in `upsert_block_header` instead of enforcing an immutable signed commitment per `block_num()`.

## Source Locations

### 1. bin/validator/src/block_validation/mod.rs:78-108

Same-height proposals are accepted as replacements, checked only against the parent commitment, and then signed.

```text
// If the proposed block has the same block number as the current chain tip, this is a
    // replacement block. Validate it against the previous block header.
    let prev = if proposed_header.block_num() == chain_tip.block_num() {
        // The genesis block cannot be replaced (genesis block has no parent).
        let prev_block_num =
            chain_tip.block_num().parent().ok_or(BlockValidationError::NoPrevBlockHeader)?;
        db.query("load_block_header", move |conn| load_block_header(conn, prev_block_num))
            .await
            .map_err(BlockValidationError::DatabaseError)?
            .ok_or(BlockValidationError::NoPrevBlockHeader)?
    } else {
        // Proposed block is a new block. Block number must be sequential.
        let expected_block_num = chain_tip.block_num().child();
        if proposed_header.block_num() != expected_block_num {
            return Err(BlockValidationError::BlockNumberMismatch {
                expected: expected_block_num,
                actual: proposed_header.block_num(),
            });
        }
        // Current chain tip is the parent of the proposed block.
        chain_tip
    };

    // The proposed block's parent must match the block that the Validator has determined is its
    // parent (either chain tip or parent of chain tip).
    if proposed_header.prev_block_commitment() != prev.commitment() {
        return Err(BlockValidationError::PrevBlockCommitmentMismatch);
    }

    let signature = sign_header(signer, &proposed_header).await?;
    Ok((signature, proposed_header))
```

### 2. bin/validator/src/server/sign_block.rs:47-67

The handler signs the validated block and persists the returned header after validation.

```text
// Validate the block against the current chain tip.
        let (signature, header) = validate_block(proposed_block, &self.signer, &self.db, chain_tip)
            .await
            .map_err(|err| {
                tonic::Status::invalid_argument(format!(
                    "Failed to validate block: {}",
                    err.as_report()
                ))
            })?;

        // Persist the validated block header.
        let new_block_num = header.block_num().as_u32();
        self.db
            .transact("upsert_block_header", move |conn| upsert_block_header(conn, &header))
            .await
            .map_err(|err| {
                tonic::Status::internal(format!(
                    "Failed to persist block header: {}",
                    err.as_report()
                ))
            })?;
```

### 3. bin/validator/src/db/mod.rs:94-108

Persistence uses `replace_into`, overwriting any existing block header at the same height.

```text
/// Upserts a block header into the database.
///
/// Inserts a new row if no block header exists at the given block number, or replaces the
/// existing block header if one already exists.
#[instrument(target = COMPONENT, skip(conn, header), err)]
pub fn upsert_block_header(
    conn: &mut SqliteConnection,
    header: &BlockHeader,
) -> Result<(), DatabaseError> {
    let row = BlockHeaderRowInsert {
        block_num: header.block_num().to_raw_sql(),
        block_header: header.to_bytes(),
    };
    diesel::replace_into(schema::block_headers::table).values(row).execute(conn)?;
    Ok(())
```

### 4. bin/validator/src/db/mod.rs:111-127

The validator tip is reconstructed only from the highest persisted block number.

```text
/// Loads the chain tip (block header with the highest block number) from the database.
///
/// Returns `None` if no block headers have been persisted (i.e. bootstrap has not been run).
#[instrument(target = COMPONENT, skip(conn), err)]
pub fn load_chain_tip(conn: &mut SqliteConnection) -> Result<Option<BlockHeader>, DatabaseError> {
    let row = schema::block_headers::table
        .order(schema::block_headers::block_num.desc())
        .select(schema::block_headers::block_header)
        .first::<Vec<u8>>(conn)
        .optional()?;

    row.map(|bytes| {
        BlockHeader::read_from_bytes(&bytes)
            .map_err(|err| DatabaseError::deserialization("BlockHeader", err))
    })
    .transpose()
}
```

### 5. bin/validator/src/block_validation/mod.rs:78-105

Same-height proposals are accepted as replacements and checked against the previous header.

```text
// If the proposed block has the same block number as the current chain tip, this is a
    // replacement block. Validate it against the previous block header.
    let prev = if proposed_header.block_num() == chain_tip.block_num() {
        // The genesis block cannot be replaced (genesis block has no parent).
        let prev_block_num =
            chain_tip.block_num().parent().ok_or(BlockValidationError::NoPrevBlockHeader)?;
        db.query("load_block_header", move |conn| load_block_header(conn, prev_block_num))
            .await
            .map_err(BlockValidationError::DatabaseError)?
            .ok_or(BlockValidationError::NoPrevBlockHeader)?
    } else {
        // Proposed block is a new block. Block number must be sequential.
        let expected_block_num = chain_tip.block_num().child();
        if proposed_header.block_num() != expected_block_num {
            return Err(BlockValidationError::BlockNumberMismatch {
                expected: expected_block_num,
                actual: proposed_header.block_num(),
            });
        }
        // Current chain tip is the parent of the proposed block.
        chain_tip
    };

    // The proposed block's parent must match the block that the Validator has determined is its
    // parent (either chain tip or parent of chain tip).
    if proposed_header.prev_block_commitment() != prev.commitment() {
        return Err(BlockValidationError::PrevBlockCommitmentMismatch);
    }
```

### 6. bin/validator/src/server/sign_block.rs:37-67

The signing handler loads the mutable tip, validates, and persists the replacement header before returning the signature.

```text
// Load the current chain tip from the database.
        let chain_tip = self
            .db
            .query("load_chain_tip", load_chain_tip)
            .await
            .map_err(|err| {
                tonic::Status::internal(format!("Failed to load chain tip: {}", err.as_report()))
            })?
            .ok_or_else(|| tonic::Status::internal("Chain tip not found in database"))?;

        // Validate the block against the current chain tip.
        let (signature, header) = validate_block(proposed_block, &self.signer, &self.db, chain_tip)
            .await
            .map_err(|err| {
                tonic::Status::invalid_argument(format!(
                    "Failed to validate block: {}",
                    err.as_report()
                ))
            })?;

        // Persist the validated block header.
        let new_block_num = header.block_num().as_u32();
        self.db
            .transact("upsert_block_header", move |conn| upsert_block_header(conn, &header))
            .await
            .map_err(|err| {
                tonic::Status::internal(format!(
                    "Failed to persist block header: {}",
                    err.as_report()
                ))
            })?;
```

### 7. crates/block-producer/src/block_builder/mod.rs:235-244

The normal block producer obtains the validator signature before attempting to commit the signed block to the store.

```text
// Concurrently build the block and validate it via the validator.
        let build_result = spawn_blocking_in_current_span({
            let proposed_block = proposed_block.clone();
            move || proposed_block.into_header_and_body()
        });
        let signature = self
            .validator
            .sign_block(proposed_block.clone())
            .await
            .map_err(|err| BuildBlockError::ValidateBlockFailed(err.into()))?;
```

### 8. crates/block-producer/src/block_builder/mod.rs:282-284

Store commit happens after the validator has already signed.

```text
self.store
            .apply_block_with_proving_inputs(ordered_batches, block_inputs, signed_block)
            .await
```

### 9. docs/internal/src/validator.md:22-27

The documented invariant is sequential signing against the previously signed block.

```text
## Block verification

The validator ensures that each new block is sequential with the previously signed block. i.e. `header.parent_commitment == last_block.commitment`.
It also checks that the block contains only transactions that it has previously seen and verified.

Once verified, the block is signed and returned to the sender.
```

