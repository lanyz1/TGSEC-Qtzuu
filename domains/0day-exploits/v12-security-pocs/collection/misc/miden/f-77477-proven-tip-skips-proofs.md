# Proven tip skips proofs

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2275](https://github.com/0xMiden/node/pull/2275)
- Severity: medium
- Maintainer validity: valid

## Summary

`ProvenTipWriter::advance()` treats any greater `BlockNumber` as a valid proven-tip advance, even though the surrounding state describes this value as the latest block proven in an unbroken sequence from genesis. The proof-application path persists the caller-supplied proof and then advances this writer with the same block number, while the full-node proof sync loop applies every upstream proof-subscription event without checking that it is the immediate child of the current proven tip. A malicious upstream RPC endpoint or on-path attacker against the non-TLS sync client can therefore send a proof event for a far-future block before earlier proofs arrive, causing the store to persist that far-future `proven_tip`. Public proven-finality RPC paths then read this poisoned watch value as the proven chain tip, so the node advertises unproven ranges as proven and proof subscriptions attempt to replay missing intermediate proofs. If the poisoned tip is ahead of the committed block database, `sync_chain_mmr()` reaches an internal `expect()` that assumes the validated tip has a header and can panic on a public proven-finality request.

## Impact

An attacker can corrupt a full node's local finality view so clients syncing through that node receive materially incorrect proven-finality metadata or lose proof-subscription service for the skipped range. The same poisoned value can turn later public proven-finality queries into a node availability failure when the advertised proven tip has no committed header.

## Root Cause

`ProvenTipWriter::advance()` encodes only monotonicity, not the stronger consecutive proven-tip invariant required by `Finality::Proven`. Callers that receive proofs from the sync boundary can therefore commit a non-contiguous proof and make later code trust the skipped range as proven.

## Source Locations

### 1. crates/store/src/proven_tip.rs:23-34

The writer accepts any greater block number as a valid advance.

```text
/// Advances the tip to `new_tip` if it is greater than the current value.
    ///
    /// Notifies all subscribers only when the tip actually increases.
    pub fn advance(&self, new_tip: BlockNumber) {
        self.0.send_if_modified(|current| {
            if new_tip > *current {
                *current = new_tip;
                true
            } else {
                false
            }
        });
```

### 2. crates/store/src/state/apply_proof.rs:10-18

Applying a proof persists it and advances the proven-tip writer with the supplied block number.

```text
pub async fn apply_proof(
        &self,
        block_num: BlockNumber,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.block_store.commit_proof(block_num, &proof_bytes).await?;
        self.proof_cache.push(block_num, ProofNotification::new(block_num, proof_bytes));
        self.proven_tip.advance(block_num);
        Ok(())
```

### 3. crates/store/src/blocks.rs:228-235

The block store documents strict ascending commits but does not enforce the order before saving the disk proven tip.

```text
/// Saves the proof, advances the proven tip, and deletes the proving inputs.
    ///
    /// Must be called in strictly ascending [`BlockNumber`] order: the proven tip file records
    /// the highest consecutive proven block, so committing out of order would leave a gap.
    pub async fn commit_proof(&self, block_num: BlockNumber, proof: &[u8]) -> std::io::Result<()> {
        self.save_proof(block_num, proof).await?;
        self.save_proven_tip(block_num)?;
        self.delete_proving_inputs(block_num).await
```

### 4. crates/block-producer/src/rpc_sync.rs:113-127

Full-node proof sync applies upstream proof events directly using the event block number.

```text
async fn sync(&self) -> anyhow::Result<()> {
        let block_from = self.state.chain_tip(Finality::Proven).await.as_u32().saturating_add(1);
        info!(block_from, "Connecting to upstream RPC for proofs");

        let mut client = self.source_rpc.clone();
        let mut stream = client
            .proof_subscription(ProofSubscriptionRequest { block_from })
            .await?
            .into_inner();

        while let Some(result) = stream.next().await {
            let event = result?;
            let block_num = BlockNumber::from(event.block_num);
            self.state.apply_proof(block_num, event.proof).await?;
        }
```

### 5. bin/node/src/commands/modes.rs:149-157

The upstream RPC sync client is constructed without TLS or metadata binding.

```text
impl SyncOptions {
    fn source_rpc_client(&self) -> RpcClient {
        Builder::new(self.block_source_url.clone())
            .without_tls()
            .without_timeout()
            .without_metadata_version()
            .without_metadata_genesis()
            .with_otel_context_injection()
            .connect_lazy::<RpcClient>()
```

### 6. crates/store/src/state/mod.rs:1064-1078

Public proven-finality state reads the cached proven-tip value.

```text
/// Returns the effective chain tip for the given finality level.
    ///
    /// - [`Finality::Committed`]: returns the latest committed block number (from in-memory MMR).
    /// - [`Finality::Proven`]: returns the latest proven-in-sequence block number (cached via watch
    ///   channel, updated by the proof scheduler).
    pub async fn chain_tip(&self, finality: Finality) -> BlockNumber {
        match finality {
            Finality::Committed => self
                .inner
                .read()
                .instrument(tracing::info_span!("acquire_inner"))
                .await
                .latest_block_num(),
            Finality::Proven => self.proven_tip.read(),
        }
```

### 7. crates/rpc/src/server/api.rs:412-419

The public SyncChainMmr handler uses the poisoned proven tip as the target for Proven finality.

```text
let request = request.into_inner();
        let current_client_block_height = BlockNumber::from(request.current_client_block_height);
        let sync_target = match request.finality_level() {
            proto::rpc::FinalityLevel::Committed | proto::rpc::FinalityLevel::Unspecified => {
                self.store.chain_tip(Finality::Committed).await
            },
            proto::rpc::FinalityLevel::Proven => self.store.chain_tip(Finality::Proven).await,
        };
```

### 8. crates/store/src/state/sync_state.rs:38-44

The MMR sync path assumes the caller-validated target block exists and panics if no header is present.

```text
// SAFETY: block_to has been validated to be <= the effective tip (chain tip or latest
        // proven block) by the caller, so it must exist in the database.
        let (block_header, signature) = self
            .db
            .select_block_header_and_signature_by_block_num(block_to)
            .await?
            .expect("block_to should exist in the database");
```

### 9. crates/store/src/state/subscription.rs:143-172

Proof subscriptions replay every block up to the proven tip, exposing skipped proofs as missing-proof failures.

```text
async fn run_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    mut tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<ProofSubscriptionEvent, StateSubscriptionError>>,
) -> Result<(), StateSubscriptionError> {
    let mut next = from;
    loop {
        let mut tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let proof = fetch_proof(next, &cache, &state).await?;
            tip = *tip_rx.borrow_and_update();
            if tx
                .send(Ok(ProofSubscriptionEvent {
                    block_num: next,
                    proof,
                    proven_chain_tip: tip,
                }))
                .await
                .is_err()
            {
                return Ok(());
            }
            next = next.child();
        }
        if tip_rx.changed().await.is_err() {
            return Ok(());
        }
    }
```

