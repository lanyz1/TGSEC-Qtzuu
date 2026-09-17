# Unverified proofs poison finality

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2275](https://github.com/0xMiden/node/pull/2275)
- Severity: medium
- Maintainer validity: valid

## Summary

`ProofNotification` stores an arbitrary `Vec<u8>` as a block proof and exposes those bytes unchanged to replica subscribers. The only visible writer, `State::apply_proof`, accepts the same raw bytes, persists them, inserts them into the `ProofCache`, and advances the proven tip without deserializing the bytes as a `BlockProof`, verifying the proof, checking that it belongs to the block number, or enforcing sequential progression. This is reachable in full-node mode because `ProofSync` consumes proof subscription events from the configured upstream RPC and passes `event.proof` and `event.block_num` directly into `apply_proof`. The backing `BlockStore::commit_proof` explicitly says it must be called in strictly ascending order, but it only saves the supplied proof and writes the supplied block number as the proven tip. `ProvenTipWriter::advance` then accepts any higher block number, so a single forged high-numbered proof event can poison both the persisted and in-memory proven-finality state.

## Impact

A malicious or intercepted upstream proof stream can make a full node report and persist a false proven tip, including block numbers for which it has no committed block or valid proof. Downstream RPC clients and replicas can receive invalid cached proof bytes or fail when the node tries to serve missing proofs below the forged tip, breaking synchronization and finality reporting until operator repair.

## Root Cause

The proof-replica path treats proof payloads as opaque bytes and pushes caller-supplied block numbers through `ProofNotification`, `commit_proof`, and `ProvenTipWriter::advance` without enforcing proof validity or contiguous proven-tip advancement at the trust boundary.

## Source Locations

### 1. crates/store/src/state/replica.rs:40-51

Proof notifications wrap and expose raw proof bytes without validation.

```text
impl ProofNotification {
    pub fn new(block_num: BlockNumber, proof_bytes: Vec<u8>) -> Self {
        Self(Arc::new(Proof { block_num, proof_bytes }))
    }

    pub fn block_num(&self) -> BlockNumber {
        self.0.block_num
    }

    pub fn proof_bytes(&self) -> &[u8] {
        &self.0.proof_bytes
    }
```

### 2. crates/store/src/state/apply_proof.rs:10-17

Raw proof bytes are committed, cached, and used to advance the proven tip.

```text
pub async fn apply_proof(
        &self,
        block_num: BlockNumber,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.block_store.commit_proof(block_num, &proof_bytes).await?;
        self.proof_cache.push(block_num, ProofNotification::new(block_num, proof_bytes));
        self.proven_tip.advance(block_num);
```

### 3. crates/block-producer/src/rpc_sync.rs:113-127

Full-node proof sync forwards upstream proof events directly into apply_proof.

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

### 4. crates/store/src/blocks.rs:228-235

commit_proof documents the strict-order requirement but only writes the supplied proof and tip.

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

### 5. crates/store/src/proven_tip.rs:23-34

The in-memory proven tip advances to any greater block number.

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

### 6. bin/node/src/commands/modes.rs:121-143

Full-node mode runs the upstream RPC sync task alongside its public RPC server.

```text
impl FullNodeCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let runtime = self.runtime.runtime_config(&self.store);
        let source_rpc = self.sync.source_rpc_client();
        let network_tx_auth = self.runtime.rpc.network_tx_auth()?;
        let state = load_state(&runtime).await?;
        let _disk_monitor = state.spawn_disk_monitor();
        let sync = RpcSync {
            state: Arc::clone(&state),
            source_rpc: source_rpc.clone(),
        };

        let rpc = Rpc {
            listener: bind_rpc(runtime.rpc_listen).await?,
            store: state,
            mode: RpcMode::full_node(source_rpc),
            ntx_builder: None,
            grpc_options: runtime.external_grpc_options,
            network_tx_auth,
        };
        let mut tasks = Tasks::new();
        tasks.spawn("RPC sync", sync.run());
        tasks.spawn("RPC server", rpc.serve());
```

