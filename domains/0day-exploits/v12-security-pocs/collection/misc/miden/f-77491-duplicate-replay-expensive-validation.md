# Duplicate replay reaches expensive validation before deduplication

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2275](https://github.com/0xMiden/node/pull/2275)
- Severity: low
- Maintainer validity: valid

## Summary

The validator's public submission path is not idempotent for already accepted transaction IDs because it routes `SubmitProvenTx` requests into `SubmitProvenTransaction` as long as `transaction_inputs` are present, then performs full `validate_transaction` work before learning whether the transaction is new. That validation path clones the `ProvenTransaction`, verifies the proof on a Tokio blocking worker, and re-executes the transaction in the VM on another blocking worker, so even a replay of a previously accepted payload consumes substantial CPU and blocking-thread capacity. Only after those expensive steps does the code call `insert_transaction`, where `on_conflict_do_nothing()` silently drops duplicates based on the primary key `id`. As a result, repeatedly resubmitting one known-valid transaction forces repeated heavy work even though the database state does not change. The practical fix is to add a cheap duplicate check keyed by `input.tx.id()` before proof verification and VM execution, or otherwise make the validation endpoint reject already-seen IDs prior to the expensive path.

## Impact

An attacker can replay the same valid transaction and repeatedly consume validator CPU and blocking-worker capacity without generating new proofs or new state transitions. Under sustained load, legitimate transaction validation can be starved and block signing or transaction inclusion can be delayed until the replay traffic stops.

## Root Cause

`SubmitProvenTransaction` defers deduplication of `input.tx.id()` until `insert_transaction(...).on_conflict_do_nothing()` after the expensive `validate_transaction` proof-verification and VM-execution path has already run.

## Source Locations

### 1. crates/rpc/src/server/api.rs:817-823

Public submission forwards any request with transaction inputs to the validator.

```text
// Transaction inputs must be provided in order to allow for transaction re-execution via
        // the Validator.
        if request.transaction_inputs.is_some() {
            validator.clone().submit_proven_transaction(request.clone()).await?;
        } else {
            return Err(Status::invalid_argument("Transaction inputs must be provided"));
        }
```

### 2. bin/validator/src/server/submit_proven_transaction.rs:22-36

The handler validates first, then inserts and only updates metrics after the insert result.

```text
// Validate the transaction.
        let tx_info = validate_transaction(input.tx, input.inputs).await.map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction"))
        })?;

        // Store the validated transaction.
        let count = self
            .db
            .transact("insert_transaction", move |conn| insert_transaction(conn, &tx_info))
            .await
            .map_err(|err| {
                Status::internal(err.as_report_context("Failed to insert transaction"))
            })?;

        self.validated_transactions_count.fetch_add(count as u64, Ordering::Relaxed);
```

### 3. bin/validator/src/tx_validation/mod.rs:43-76

Validation performs proof verification and VM execution on blocking workers.

```text
// Proof verification is CPU-intensive; run it on a dedicated blocking thread.
    let proven_tx_clone = proven_tx.clone();
    spawn_blocking_in_span(
        move || TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven_tx_clone),
        info_span!("verify"),
    )
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;

    // Create a DataStore from the transaction inputs.
    let data_store = TransactionInputsDataStore::new(tx_inputs.clone());

    // VM execution may not yield; run it on a dedicated blocking thread.
    let (account, block_header, _, input_notes, tx_args) = tx_inputs.into_parts();
    let execute_span = info_span!("execute").or_current();
    let executed_tx = spawn_blocking_in_current_span(move || {
        let executor: TransactionExecutor<'_, '_, _, UnreachableAuth> =
            TransactionExecutor::new(&data_store);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build tokio runtime")
            .block_on(
                executor
                    .execute_transaction(
                        account.id(),
                        block_header.block_num(),
                        input_notes,
                        tx_args,
                    )
                    .instrument(execute_span),
            )
    })
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;
```

### 4. bin/validator/src/db/mod.rs:46-57

Duplicate rows are ignored only at insert time via on-conflict-do-nothing.

```text
/// Inserts a new validated transaction into the database.
#[instrument(target = COMPONENT, skip_all, fields(tx_id = %tx_info.tx_id()), err)]
pub(crate) fn insert_transaction(
    conn: &mut SqliteConnection,
    tx_info: &ValidatedTransaction,
) -> Result<usize, DatabaseError> {
    let row = ValidatedTransactionRowInsert::new(tx_info);
    let count = diesel::insert_into(schema::validated_transactions::table)
        .values(row)
        .on_conflict_do_nothing()
        .execute(conn)?;
    Ok(count)
```

### 5. bin/validator/src/tx_validation/mod.rs:43-50

Proof verification is performed before any duplicate check.

```text
// Proof verification is CPU-intensive; run it on a dedicated blocking thread.
    let proven_tx_clone = proven_tx.clone();
    spawn_blocking_in_span(
        move || TransactionVerifier::new(MIN_PROOF_SECURITY_LEVEL).verify(&proven_tx_clone),
        info_span!("verify"),
    )
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;
```

### 6. bin/validator/src/tx_validation/mod.rs:55-76

VM re-execution is performed before any duplicate check.

```text
// VM execution may not yield; run it on a dedicated blocking thread.
    let (account, block_header, _, input_notes, tx_args) = tx_inputs.into_parts();
    let execute_span = info_span!("execute").or_current();
    let executed_tx = spawn_blocking_in_current_span(move || {
        let executor: TransactionExecutor<'_, '_, _, UnreachableAuth> =
            TransactionExecutor::new(&data_store);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("failed to build tokio runtime")
            .block_on(
                executor
                    .execute_transaction(
                        account.id(),
                        block_header.block_num(),
                        input_notes,
                        tx_args,
                    )
                    .instrument(execute_span),
            )
    })
    .await
    .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))?;
```

### 7. bin/validator/src/server/submit_proven_transaction.rs:22-30

The handler validates first, then attempts to store the transaction.

```text
// Validate the transaction.
        let tx_info = validate_transaction(input.tx, input.inputs).await.map_err(|err| {
            Status::invalid_argument(err.as_report_context("Invalid transaction"))
        })?;

        // Store the validated transaction.
        let count = self
            .db
            .transact("insert_transaction", move |conn| insert_transaction(conn, &tx_info))
```

### 8. bin/validator/src/db/mod.rs:52-56

Duplicate transaction IDs are ignored only at insertion time.

```text
let row = ValidatedTransactionRowInsert::new(tx_info);
    let count = diesel::insert_into(schema::validated_transactions::table)
        .values(row)
        .on_conflict_do_nothing()
        .execute(conn)?;
```

### 9. bin/validator/src/db/migrations/001_initial.sql:1-12

The transaction ID is the table primary key that makes replays duplicates.

```text
CREATE TABLE validated_transactions (
    id                    BLOB NOT NULL,
    block_num             BIGINT NOT NULL,
    account_id            BLOB NOT NULL,
    account_delta         BLOB NOT NULL,
    input_notes           BLOB,
    output_notes          BLOB,
    initial_account_hash  BLOB NOT NULL,
    final_account_hash    BLOB NOT NULL,
    fee                   BLOB NOT NULL,
    PRIMARY KEY (id)
) WITHOUT ROWID;
```

