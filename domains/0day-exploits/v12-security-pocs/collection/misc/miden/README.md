# Miden Node security findings

These bugs were found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

Source issue: [0xMiden/node#2276](https://github.com/0xMiden/node/issues/2276)

| Finding | Report | Summary | Responsive PR |
| --- | --- | --- | --- |
| F-77474 | [Vault key metadata dropped](./f-77474-vault-key-metadata-dropped.md) | Partial-delta vault updates collapsed fungible vault keys to faucet IDs, dropping callback metadata and making persisted vault rows diverge from the committed account root. | [#2222](https://github.com/0xMiden/node/pull/2222) |
| F-77490 | [Mutable same-height signing lets validator equivocate](./f-77490-mutable-same-height-signing.md) | Same-height proposals could replace the stored header, letting a validator sign conflicting headers at one block number. | [#2283](https://github.com/0xMiden/node/pull/2283) |
| F-77369 | [Idle actors never expire](./f-77369-idle-actors-never-expire.md) | Global per-block notifications reset idle timers, allowing no-work or never-committed NTX actors to remain resident indefinitely. | [#2277](https://github.com/0xMiden/node/pull/2277) |
| F-77448 | [Upstream-supplied proof events corrupt proven tip](./f-77448-upstream-proof-events-corrupt-proven-tip.md) | Proof sync accepted upstream block numbers and proof bytes without validation, allowing a malicious upstream or MITM to persist an arbitrary proven tip. | [#2275](https://github.com/0xMiden/node/pull/2275) |
| F-77477 | [Proven tip skips proofs](./f-77477-proven-tip-skips-proofs.md) | Proven-tip advancement enforced monotonicity but not contiguity, so far-future proof events could poison finality and break proof synchronization. | [#2275](https://github.com/0xMiden/node/pull/2275) |
| F-77482 | [Unverified proofs poison finality](./f-77482-unverified-proofs-poison-finality.md) | Raw proof bytes were persisted and used to advance proven finality without deserialization, verification, or block-number binding. | [#2275](https://github.com/0xMiden/node/pull/2275) |
| F-77484 | [Future subscriptions leak tasks](./f-77484-future-subscriptions-leak-tasks.md) | Far-future block and proof subscriptions parked detached tasks on tip changes without observing client disconnects. | [#2279](https://github.com/0xMiden/node/pull/2279) |
| F-77489 | [Remote block prover wire-format mismatch](./f-77489-remote-block-prover-wire-format-mismatch.md) | The remote prover client serialized a `ProposedBlock`, while the server decoded a `BlockProofRequest`, breaking remote block proving. | [#2280](https://github.com/0xMiden/node/pull/2280) |
| F-77492 | [Unbounded `SlotData::All` requests](./f-77492-unbounded-slotdata-all-requests.md) | `SlotData::All` entries bypassed the storage-key limit, enabling repeated expensive forest and database work from one account query. | [#2284](https://github.com/0xMiden/node/pull/2284) |
| F-77460 | [Future subscriptions exhaust slots](./f-77460-future-subscriptions-exhaust-slots.md) | Subscription permits were acquired before validating `block_from`, so future-height streams could consume all replica slots. | [#2279](https://github.com/0xMiden/node/pull/2279) |
| F-77475 | [Truncated pages look complete](./f-77475-truncated-pages-look-complete.md) | Transaction pagination reported completion unless total size exactly hit the cap, silently dropping rows after the first non-fitting transaction. | [#2285](https://github.com/0xMiden/node/pull/2285) |
| F-77491 | [Duplicate replay reaches expensive validation](./f-77491-duplicate-replay-expensive-validation.md) | Duplicate transaction submissions reached proof verification and VM re-execution before database deduplication suppressed the insert. | [#2275](https://github.com/0xMiden/node/pull/2275) |
