# Upstream-supplied proof events corrupt proven tip

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2275](https://github.com/0xMiden/node/pull/2275)
- Severity: medium
- Maintainer validity: valid

## Summary

`ProofSync::sync()` reads `block_num` and `proof` directly from upstream subscription events and forwards them to `State::apply_proof` without validating that the block number is strictly greater than the current proven tip, that it is bounded by the locally committed tip, or that the proof bytes have any expected shape. Downstream, `State::apply_proof` calls `BlockStore::commit_proof`, which itself documents that callers must invoke it in strictly ascending `BlockNumber` order, then unconditionally overwrites the on-disk `proven_tip` file with whatever value was supplied. The in-memory `ProvenTipWriter::advance` guard prevents regression for the running process, but the disk write happens before that guard, so the persisted tip can be set to any attacker-chosen value. Because `bin/node/src/commands/modes.rs:152` builds the source RPC client with `.without_tls()`, a network MITM (in addition to a compromised upstream operator) is sufficient to inject crafted `ProofSubscriptionResponse` events. Unlike `BlockSync`, which is salvaged by `validate_block_header`'s sequential and parent-commitment checks inside `apply_block`, the proof path has no equivalent defense, so a single malicious event is enough to persistently desynchronize the node's `Finality::Proven` state from the actual proven chain.

## Impact

An attacker with MITM access to (or control of) the upstream RPC can persistently corrupt the local proven-chain tip: setting it to a value like `u32::MAX` makes `ProofSync` subscribe from that height forever (since `block_from = proven_tip.saturating_add(1) == u32::MAX`) and causes `chain_tip(Finality::Proven)` and every downstream `proof_subscription` consumer of this node to be told the chain has billions of proven blocks. Lower-than-current values regress the on-disk tip so that after a restart the node re-fetches proofs already overwritten with attacker-supplied bytes, propagating those bytes to replicas via `proof_cache` and `load_proof`, and breaking the documented invariant that proven blocks are a subset of committed blocks.

## Root Cause

`ProofSync::sync` (and `State::apply_proof` it calls) trust upstream-supplied `block_num` and `proof` bytes without enforcing the strict-ascending and committed-tip bounds that `BlockStore::commit_proof` documents as required, while the upstream connection is established with TLS disabled.

## Source Locations

### 1. crates/block-producer/src/rpc_sync.rs:113-130

ProofSync::sync forwards upstream block_num/proof without validation

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

        Ok(())
    }
```

### 2. crates/store/src/state/apply_proof.rs:7-19

apply_proof writes proof, caches it, and advances tip with no validation

```text
impl State {
    /// Saves a block proof, advances the proven-in-sequence tip, and notifies replica subscribers.
    #[instrument(target = COMPONENT, skip_all, err, fields(block.number = block_num.as_u32()))]
    pub async fn apply_proof(
        &self,
        block_num: BlockNumber,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.block_store.commit_proof(block_num, &proof_bytes).await?;
        self.proof_cache.push(block_num, ProofNotification::new(block_num, proof_bytes));
        self.proven_tip.advance(block_num);
        Ok(())
    }
```

### 3. crates/store/src/blocks.rs:228-249

commit_proof requires strictly ascending order in docs but does not enforce it; save_proven_tip unconditionally overwrites disk file

```text
/// Saves the proof, advances the proven tip, and deletes the proving inputs.
    ///
    /// Must be called in strictly ascending [`BlockNumber`] order: the proven tip file records
    /// the highest consecutive proven block, so committing out of order would leave a gap.
    pub async fn commit_proof(&self, block_num: BlockNumber, proof: &[u8]) -> std::io::Result<()> {
        self.save_proof(block_num, proof).await?;
        self.save_proven_tip(block_num)?;
        self.delete_proving_inputs(block_num).await
    }

    /// Reads the proven tip from disk and returns it.
    pub fn load_proven_tip(&self) -> std::io::Result<BlockNumber> {
        Self::read_proven_tip_from(&self.proven_tip_path())
    }

    /// Atomically writes `tip` to the proven tip file (write to temp, then rename).
    fn save_proven_tip(&self, tip: BlockNumber) -> std::io::Result<()> {
        let path = self.proven_tip_path();
        let tmp = path.with_extension("tmp");
        fs_err::write(&tmp, tip.as_u32().to_le_bytes())?;
        fs_err::rename(&tmp, &path)
    }
```

### 4. crates/store/src/proven_tip.rs:23-35

in-memory advance guard runs after the disk write, so it does not protect the persisted tip

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
    }
```

### 5. bin/node/src/commands/modes.rs:149-158

source RPC client constructed without TLS, enabling MITM injection of ProofSubscriptionResponse frames

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
    }
```

