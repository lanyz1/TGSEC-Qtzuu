# Truncated Pages Look Complete

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2285](https://github.com/0xMiden/node/pull/2285)
- Severity: low
- Maintainer validity: valid

## Summary

`select_transactions_records` enforces the 4 MiB response cap by appending rows until the next row no longer fits, then breaks out of the chunk loop. The function only treats the response as truncated when `total_size >= max_payload_bytes`; in the normal case where the next positive-size transaction would exceed the cap while `total_size` remains below it, execution falls through to the success branch and returns `*block_range.end()` as the last included block. The public `SyncTransactions` pagination contract tells clients to resume only when the returned `block_num` is less than the requested upper bound, so this response is indistinguishable from a complete scan. Any matching transactions after the first non-fitting row are silently omitted from the returned page and cannot be recovered by ordinary block-based pagination for that request range. The code comment explicitly intends to exclude partial blocks, but that protection is bypassed for almost every size-limit hit that does not fill the byte budget exactly.

## Impact

A valid set of large or numerous matching transactions can make public transaction history incomplete while the server reports that the requested range was fully covered. Indexers, wallets, or monitors using `SyncTransactions` can miss committed transaction records and output-note proofs without receiving an error or a pagination cursor to continue from.

## Root Cause

`select_transactions_records` uses the accumulated byte total as a proxy for whether truncation happened instead of tracking the explicit `next row did not fit` condition. As a result, the byte-limit control flow returns `block_range.end()` after a partial page whenever the cap is approached but not exactly reached.

## Source Locations

### 1. crates/store/src/db/models/queries/transactions.rs:201-211

Defines the size-limited transaction-record query and derives the 4 MiB byte cap.

```text
pub fn select_transactions_records(
    conn: &mut SqliteConnection,
    account_ids: &[AccountId],
    block_range: RangeInclusive<BlockNumber>,
) -> Result<(BlockNumber, Vec<crate::db::TransactionRecord>), DatabaseError> {
    const NUM_TXS_PER_CHUNK: i64 = 1000; // Read 1000 transactions at a time

    QueryParamAccountIdLimit::check(account_ids.len())?;

    let max_payload_bytes =
        i64::try_from(MAX_RESPONSE_PAYLOAD_BYTES).expect("payload limit fits within i64");
```

### 2. crates/store/src/db/models/queries/transactions.rs:248-277

Stops adding rows when the next transaction does not fit, but records only the rows already added.

```text
let chunk = query
            .order((
                schema::transactions::block_num.asc(),
                schema::transactions::transaction_id.asc(),
            ))
            .limit(NUM_TXS_PER_CHUNK)
            .load::<TransactionRecordRaw>(conn)
            .map_err(DatabaseError::from)?;

        // Add transactions from this chunk one by one until we hit the limit
        let mut added_from_chunk = 0;

        for tx in chunk {
            if total_size + tx.size_in_bytes <= max_payload_bytes {
                total_size += tx.size_in_bytes;
                last_block_num = Some(tx.block_num);
                last_transaction_id = Some(tx.transaction_id.clone());
                all_transactions.push(tx);
                added_from_chunk += 1;
            } else {
                // Can't fit this transaction, stop here
                break;
            }
        }

        // Break if chunk incomplete (size limit hit or data exhausted)
        if added_from_chunk < NUM_TXS_PER_CHUNK {
            break;
        }
    }
```

### 3. crates/store/src/db/models/queries/transactions.rs:279-301

Handles truncation only when total_size reaches the cap; otherwise returns block_range.end() as complete.

```text
// Ensure block consistency: remove the last block if it's incomplete (we may have stopped
    // loading mid-block due to size constraints)
    if total_size >= max_payload_bytes {
        // SAFETY: We're guaranteed to have at least one transaction since total_size > 0
        let last_block_num = last_block_num.expect(
            "guaranteed to have processed at least one transaction when size limit is reached",
        );
        let filtered_transactions = with_output_note_proofs(
            conn,
            all_transactions
                .into_iter()
                .take_while(|row| row.block_num != last_block_num)
                .collect(),
        )?;

        // SAFETY: block_num came from the database and was previously validated. Subtraction is
        // safe under the assumption that genesis block (where it could fail) does not have any
        // transactions.
        let last_included_block = BlockNumber::from_raw_sql(last_block_num.saturating_sub(1))?;
        Ok((last_included_block, filtered_transactions))
    } else {
        Ok((*block_range.end(), with_output_note_proofs(conn, all_transactions)?))
    }
```

### 4. crates/rpc/src/server/api.rs:944-981

Public SyncTransactions endpoint forwards the returned last_block_included into pagination_info.block_num.

```text
async fn sync_transactions(
        &self,
        request: Request<proto::rpc::SyncTransactionsRequest>,
    ) -> Result<Response<proto::rpc::SyncTransactionsResponse>, Status> {
        let range =
            read_block_range::<Status>(request.get_ref().block_range, "SyncTransactionsRequest")?;
        let n_accounts = request.get_ref().account_ids.len();
        let account_ids =
            read_account_ids::<Status, _>(request.get_ref().account_ids.iter().take(10).cloned())?;

        let span = Span::current();
        span.set_attribute("block_range.from", range.block_from);
        span.set_attribute("block_range.to", range.block_to);
        span.set_attribute("account.ids", format!("{account_ids:?}").as_str());
        span.set_attribute("account.ids.count", n_accounts);

        debug!(target: COMPONENT, request = ?request);

        check::<QueryParamAccountIdLimit>(request.get_ref().account_ids.len())?;

        let request = request.into_inner();
        let block_range = range
            .into_inclusive_range::<RpcInvalidBlockRange>()
            .map_err(invalid_block_range_to_status)?;
        let account_ids = read_account_ids::<Status, _>(request.account_ids)?;
        let (last_block_included, transaction_records_db) = self
            .store
            .sync_transactions(account_ids, block_range)
            .await
            .map_err(|err| database_error_to_status(&err))?;
        let transactions =
            transaction_records_db.into_iter().map(transaction_record_to_proto).collect();
        let chain_tip = self.store.chain_tip(Finality::Committed).await;

        Ok(Response::new(proto::rpc::SyncTransactionsResponse {
            pagination_info: Some(proto::rpc::PaginationInfo {
                chain_tip: chain_tip.as_u32(),
                block_num: last_block_included.as_u32(),
```

### 5. proto/proto/rpc.proto:632-637

Pagination contract tells clients to continue only when the returned block_num is below the requested upper bound.

```text
// The block number of the last check included in this response.
    //
    // For chunked responses, this may be less than `request.block_range.block_to`.
    // If it is less than request.block_range.block_to, the user is expected to make a subsequent request
    // starting from the next block to this one (ie, request.block_range.block_from = block_num + 1).
    fixed32 block_num = 2;
```

