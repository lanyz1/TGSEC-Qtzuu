# Future Subscriptions Leak Tasks

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2279](https://github.com/0xMiden/node/pull/2279)
- Severity: medium
- Maintainer validity: valid

## Summary

`block_subscription` and `proof_subscription` create detached Tokio tasks for every subscription and only notice a disconnected client when they reach a `tx.send(...)` call. If the requested `from` block is higher than the current tip, `run_block_stream` and `run_proof_stream` skip the send path entirely and park on `tip_rx.changed().await` without also waiting for `tx.closed()`. The public RPC handlers accept `block_from` directly and wrap only the returned receiver stream in `GuardedStream`, so client disconnect releases the semaphore permit but does not abort the detached store task. An attacker can repeatedly open a subscription for a far-future block number and immediately disconnect, leaving each spawned task and watch receiver alive until the chain reaches that height or the node shuts down. This bypasses the intended active-subscription cap because the leaked tasks are no longer associated with the guarded response stream.

## Impact

Repeated far-future subscriptions accumulate unbounded background tasks, watch receivers, and `Arc<State>` references, consuming memory and scheduler resources in the RPC/store process. In bundled deployments this can degrade or crash the node, disrupting public transaction ingress and replica synchronization until restart.

## Root Cause

The subscription tasks are detached from the lifetime of the returned stream and wait only on tip changes when there is no immediate event to send. They do not validate future `from` values or select on `mpsc::Sender::closed()` to terminate when the client disconnects.

## Source Locations

### 1. crates/rpc/src/server/api.rs:90-108

The semaphore permit is owned by the returned stream wrapper, not by the detached store task.

```text
struct GuardedStream<S> {
    inner: S,
    _permit: OwnedSemaphorePermit,
}

impl<S> GuardedStream<S> {
    fn new(inner: S, permit: OwnedSemaphorePermit) -> Self {
        Self { inner, _permit: permit }
    }
}

impl<S> Stream for GuardedStream<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
```

### 2. crates/rpc/src/server/api.rs:445-468

The public block subscription handler accepts `block_from` directly and wraps only the receiver stream.

```text
async fn block_subscription(
        &self,
        request: Request<proto::rpc::BlockSubscriptionRequest>,
    ) -> Result<Response<Self::BlockSubscriptionStream>, Status> {
        let request_ref = request.get_ref();
        Span::current().set_attribute("block.from", request_ref.block_from);

        debug!(target: COMPONENT, request = ?request_ref);

        let permit = Arc::clone(&self.block_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum block subscriptions reached"))?;

        let from = BlockNumber::from(request_ref.block_from);
        let stream = self.store.block_subscription(from).map(|event| {
            event
                .map(|event| proto::rpc::BlockSubscriptionResponse {
                    block: event.block,
                    committed_chain_tip: event.committed_chain_tip.as_u32(),
                })
                .map_err(state_subscription_error_to_status)
        });
        let stream: Self::BlockSubscriptionStream =
            Box::pin(GuardedStream::new(Box::pin(stream), permit));
```

### 3. crates/rpc/src/server/api.rs:472-496

The public proof subscription handler has the same unchecked future-start behavior.

```text
async fn proof_subscription(
        &self,
        request: Request<proto::rpc::ProofSubscriptionRequest>,
    ) -> Result<Response<Self::ProofSubscriptionStream>, Status> {
        let request_ref = request.get_ref();
        Span::current().set_attribute("block.from", request_ref.block_from);

        debug!(target: COMPONENT, request = ?request_ref);

        let permit = Arc::clone(&self.proof_subscription_semaphore)
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("maximum proof subscriptions reached"))?;

        let from = BlockNumber::from(request_ref.block_from);
        let stream = self.store.proof_subscription(from).map(|event| {
            event
                .map(|event| proto::rpc::ProofSubscriptionResponse {
                    block_num: event.block_num.as_u32(),
                    proof: event.proof,
                    proven_chain_tip: event.proven_chain_tip.as_u32(),
                })
                .map_err(state_subscription_error_to_status)
        });
        let stream: Self::ProofSubscriptionStream =
            Box::pin(GuardedStream::new(Box::pin(stream), permit));
```

### 4. crates/store/src/state/subscription.rs:88-108

Each subscription starts a detached Tokio task and returns only the channel receiver.

```text
let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(err) = run_block_stream(from, cache, tip_rx, state, &tx).await {
            let _ = tx.send(Err(err)).await;
        }
    });
    ReceiverStream::new(rx)
}

fn build_proof_stream(
    from: BlockNumber,
    cache: ProofCache,
    tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
) -> impl Stream<Item = Result<ProofSubscriptionEvent, StateSubscriptionError>> + Send + 'static {
    let (tx, rx) = mpsc::channel(32);
    tokio::spawn(async move {
        if let Err(err) = run_proof_stream(from, cache, tip_rx, state, &tx).await {
            let _ = tx.send(Err(err)).await;
        }
    });
```

### 5. crates/store/src/state/subscription.rs:122-139

A block subscription whose `from` is above the tip waits only for tip changes and never observes receiver closure.

```text
let mut next = from;
    loop {
        let mut tip = *tip_rx.borrow_and_update();
        while next <= tip {
            let block = fetch_block(next, &cache, &state).await?;
            tip = *tip_rx.borrow_and_update();
            if tx
                .send(Ok(BlockSubscriptionEvent { block, committed_chain_tip: tip }))
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
```

### 6. crates/store/src/state/subscription.rs:150-170

A proof subscription whose `from` is above the tip has the same lifetime leak.

```text
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
```

