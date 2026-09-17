# Future subscriptions exhaust slots

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2279](https://github.com/0xMiden/node/pull/2279)
- Severity: low
- Maintainer validity: valid

## Summary

`block_subscription` and `proof_subscription` acquire one of only ten global subscription permits before doing any range validation on `block_from`. Both methods accept any `u32`, convert it directly to `BlockNumber`, and return a `GuardedStream` that holds the semaphore permit for the lifetime of the client stream. In the store stream implementation, a future `from` height simply skips the replay loop and waits on `tip_rx.changed()` until the chain reaches that height. A caller can open ten streams with a very large `block_from` value and keep them idle, causing every later legitimate block or proof subscription to fail with `resource_exhausted`. This is reachable with valid gRPC requests and does not require high request volume.

## Impact

An unauthenticated client can deny all replica block/proof subscription slots on the RPC instance. Full nodes or monitoring clients relying on these streaming endpoints lose live block/proof delivery until the attacker disconnects or the server drops the streams.

## Root Cause

Subscription admission is governed only by a small global semaphore, but `block_from` is not validated before a permit is reserved. Future-height streams can therefore hold scarce permits indefinitely without producing data.

## Source Locations

### 1. crates/rpc/src/server/api.rs:69-70

Only ten block/proof subscriptions are allowed per RPC instance.

```text
/// Maximum number of concurrent block or proof subscriptions served by this RPC instance.
const MAX_REPLICA_SUBSCRIPTIONS: usize = 10;
```

### 2. crates/rpc/src/server/api.rs:90-108

`GuardedStream` retains the semaphore permit for the stream lifetime.

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

### 3. crates/rpc/src/server/api.rs:445-469

Block subscriptions acquire a permit and accept arbitrary `block_from`.

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
        Ok(Response::new(stream))
```

### 4. crates/rpc/src/server/api.rs:472-497

Proof subscriptions have the same permit and range handling.

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
        Ok(Response::new(stream))
```

### 5. crates/store/src/state/subscription.rs:115-140

A future block subscription waits for tip changes instead of rejecting.

```text
async fn run_block_stream(
    from: BlockNumber,
    cache: BlockCache,
    mut tip_rx: watch::Receiver<BlockNumber>,
    state: Arc<State>,
    tx: &mpsc::Sender<Result<BlockSubscriptionEvent, StateSubscriptionError>>,
) -> Result<(), StateSubscriptionError> {
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
    }
```

### 6. crates/store/src/state/subscription.rs:143-172

A future proof subscription waits in the same way.

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

