# Remote block prover sends an incompatible block payload

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2280](https://github.com/0xMiden/node/pull/2280)
- Severity: medium
- Maintainer validity: valid

## Summary

Remote block proving uses incompatible wire formats on the two sides of the same API. The client path for `ProofType::Block` constructs a `ProposedBlock` and serializes that value into `payload`, while the protocol and server both define block requests as serialized `BlockProofRequest` values. On the worker side, request decoding reads the payload into `BlockProofRequest` and then passes `tx_batches`, `block_header`, and `block_inputs` into `LocalBlockProver`, so the client's bytes do not match the expected layout. This mismatch means remote block proof requests can fail during decode or otherwise arrive without the full data shape the server expects. The implementation and the documented contract therefore diverge at the serialization boundary, breaking the production remote block proving path.

## Impact

Deployments using the remote block prover cannot reliably generate block proofs, so the proven tip may stop advancing when block proving is routed through this path. The proof scheduler retries these failures and eventually returns an error, which can halt proof finalization for committed blocks and in the sequencer task set can terminate the long-running service group.

## Root Cause

`RemoteBlockProver` serializes `ProposedBlock` for `ProofType::Block` instead of the `BlockProofRequest` wire format that the remote prover server decodes and the protocol specifies.

## Source Locations

### 1. bin/remote-prover/src/server/prover.rs:129-140

Worker-side block prover input is `BlockProofRequest` and its decoded fields are passed to `LocalBlockProver`.

```text
impl ProveRequest for LocalBlockProver {
    type Input = BlockProofRequest;
    type Output = BlockProof;

    async fn prove(&self, input: Self::Input) -> Result<Self::Output, tonic::Status> {
        let prover = self.clone();
        let BlockProofRequest { tx_batches, block_header, block_inputs } = input;

        spawn_blocking_in_current_span(move || {
            prover
                .prove(tx_batches, &block_header, block_inputs)
                .map_err(|e| tonic::Status::internal(e.as_report_context("failed to prove block")))
```

### 2. crates/proto/src/domain/proof_request.rs:20-39

`BlockProofRequest` serialization layout is `tx_batches`, `block_header`, then `block_inputs`.

```text
impl Serializable for BlockProofRequest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { tx_batches, block_header, block_inputs } = self;
        tx_batches.write_into(target);
        block_header.write_into(target);
        block_inputs.write_into(target);
    }
}

impl Deserializable for BlockProofRequest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let block = Self {
            tx_batches: OrderedBatches::read_from(source)?,
            block_header: BlockHeader::read_from(source)?,
            block_inputs: BlockInputs::read_from(source)?,
        };

        Ok(block)
    }
}
```

### 3. proto/proto/remote_prover.proto:32-37

API contract documents `BLOCK` request payloads as encoded `BlockProofRequest`.

```text
// Serialized payload requiring proof generation. The encoding format is
    // type-specific:
    // - TRANSACTION: TransactionInputs encoded.
    // - BATCH: ProposedBatch encoded.
    // - BLOCK: BlockProofRequest encoded.
    bytes payload = 2;
```

### 4. crates/remote-prover-client/src/remote_prover/block_prover.rs:123-132

Client constructs a `ProposedBlock` for the remote proof request.

```text
let block_proof_request =
            ProposedBlock::new_at(block_inputs, tx_batches.into_vec(), block_header.timestamp())
                .map_err(|err| {
                    RemoteProverClientError::other_with_source(
                        "failed to create proposed block",
                        err,
                    )
                })?;

        let request = tonic::Request::new(block_proof_request.into());
```

### 5. crates/remote-prover-client/src/remote_prover/block_prover.rs:161-166

Client serializes `ProposedBlock` as the `BLOCK` payload.

```text
impl From<ProposedBlock> for proto::ProofRequest {
    fn from(proposed_block: ProposedBlock) -> Self {
        proto::ProofRequest {
            proof_type: proto::ProofType::Block.into(),
            payload: proposed_block.to_bytes(),
        }
```

### 6. crates/block-producer/src/block_prover.rs:23-29

Remote block proving is the production-oriented block prover variant.

```text
/// Block prover which allows for proving via either local or remote backend.
///
/// The local proving variant is intended for development and testing purposes.
/// The remote proving variant is intended for production use.
pub enum BlockProver {
    Local(LocalBlockProver),
    Remote(RemoteBlockProver),
```

### 7. crates/block-producer/src/proof_scheduler.rs:184-203

Repeated proving failures eventually abort the per-block proof task.

```text
match result {
                Ok(Ok(proof)) => return Ok((block_num, proof.to_bytes())),
                Ok(Err(ProveBlockError::Fatal(err))) => Err(err).context("fatal error")?,
                Ok(Err(ProveBlockError::Transient(err))) => {
                    attempt_span.record("error", tracing::field::display(&err));
                },
                Err(elapsed) => {
                    attempt_span.record("timed_out", elapsed.to_string());
                },
            }

            if attempt >= MAX_PROVE_ATTEMPTS {
                anyhow::bail!("block {} failed after {attempt} attempts", block_num.as_u32());
            }
        }
    })
    .await
    .context(format!(
        "block proving overall timeout ({BLOCK_PROVE_OVERALL_TIMEOUT:?}) exceeded"
    ))?
```

### 8. crates/remote-prover-client/src/remote_prover/block_prover.rs:161-167

`ProofType::Block` is assigned to the serialized `ProposedBlock` payload.

```text
impl From<ProposedBlock> for proto::ProofRequest {
    fn from(proposed_block: ProposedBlock) -> Self {
        proto::ProofRequest {
            proof_type: proto::ProofType::Block.into(),
            payload: proposed_block.to_bytes(),
        }
    }
```

### 9. proto/proto/remote_prover.proto:27-37

The protocol specifies that BLOCK payloads are encoded `BlockProofRequest` values.

```text
// Request message for proof generation containing payload and proof type metadata.
message ProofRequest {
    // Type of proof being requested, determines payload interpretation
    ProofType proof_type = 1;

    // Serialized payload requiring proof generation. The encoding format is
    // type-specific:
    // - TRANSACTION: TransactionInputs encoded.
    // - BATCH: ProposedBatch encoded.
    // - BLOCK: BlockProofRequest encoded.
    bytes payload = 2;
```

### 10. bin/remote-prover/src/server/prover.rs:81-87

The server decodes request bytes into the prover input type.

```text
#[instrument(target=COMPONENT, skip_all, err)]
    fn decode_request(request: proto::ProofRequest) -> Result<Self::Input, tonic::Status> {
        use miden_protocol::utils::serde::Deserializable;

        Self::Input::read_from_bytes(&request.payload).map_err(|e| {
            tonic::Status::invalid_argument(e.as_report_context("failed to decode request"))
        })
```

### 11. crates/proto/src/domain/proof_request.rs:14-18

`BlockProofRequest` carries `tx_batches`, `block_header`, and `block_inputs`.

```text
pub struct BlockProofRequest {
    pub tx_batches: OrderedBatches,
    pub block_header: BlockHeader,
    pub block_inputs: BlockInputs,
}
```

### 12. crates/block-producer/src/block_prover.rs:37-64

Production remote block proving delegates to `RemoteBlockProver::prove`.

```text
pub fn remote(endpoint: impl Into<String>) -> Self {
        Self::Remote(RemoteBlockProver::new(endpoint))
    }

    #[instrument(target = COMPONENT, skip_all, err)]
    pub async fn prove(
        &self,
        tx_batches: OrderedBatches,
        block_inputs: BlockInputs,
        block_header: &BlockHeader,
    ) -> Result<BlockProof, ProverError> {
        match self {
            Self::Local(prover) => {
                let prover = prover.clone();
                let block_header = block_header.clone();

                spawn_blocking_in_current_span(move || {
                    prover
                        .prove(tx_batches, &block_header, block_inputs)
                        .map_err(ProverError::LocalProvingFailed)
                })
                .await
                .map_err(ProverError::LocalProvingTaskJoin)?
            },
            Self::Remote(prover) => Ok(prover
                .prove(tx_batches, block_header, block_inputs)
                .await
                .map_err(ProverError::RemoteProvingFailed)?),
```

### 13. crates/block-producer/src/proof_scheduler.rs:184-196

Transient proof failures are retried and then abort the block proof task after three attempts.

```text
match result {
                Ok(Ok(proof)) => return Ok((block_num, proof.to_bytes())),
                Ok(Err(ProveBlockError::Fatal(err))) => Err(err).context("fatal error")?,
                Ok(Err(ProveBlockError::Transient(err))) => {
                    attempt_span.record("error", tracing::field::display(&err));
                },
                Err(elapsed) => {
                    attempt_span.record("timed_out", elapsed.to_string());
                },
            }

            if attempt >= MAX_PROVE_ATTEMPTS {
                anyhow::bail!("block {} failed after {attempt} attempts", block_num.as_u32());
```

### 14. crates/block-producer/src/server/mod.rs:130-152

A failing proof scheduler is part of the long-running sequencer task set that aborts on task failure.

```text
// Spawn batch builder, block builder, and proof scheduler. The builders communicate
        // indirectly via a shared mempool.
        //
        // These should run forever, so if any complete or fail, the sequencer reports the failure
        // and aborts the rest when the task set is dropped.
        let mut tasks = Tasks::new();

        tasks.spawn("batch-builder", {
            let mempool = mempool.clone();
            async { batch_builder.run(mempool).await }
        });
        tasks.spawn("block-builder", {
            let mempool = mempool.clone();
            async { block_builder.run(mempool).await }
        });
        tasks.spawn("proof-scheduler", {
            let store = Arc::clone(&api.store);
            async move {
                proof_scheduler::run(block_prover, store, chain_tip_rx, self.max_concurrent_proofs)
                    .await
            }
        });
        let task = tokio::spawn(async move { tasks.join_next_as_error().await });
```

