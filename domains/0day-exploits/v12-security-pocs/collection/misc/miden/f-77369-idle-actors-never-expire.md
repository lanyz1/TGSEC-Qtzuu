# Idle actors never expire

This bug was found autonomously using [V12](https://v12.sh) by the [V12 security team](https://x.com/v12sec).

- Responsive PR: [0xMiden/node#2277](https://github.com/0xMiden/node/pull/2277)
- Severity: medium
- Maintainer validity: valid

## Summary

`AccountActor` attempts to enforce idle shutdown by sleeping only while in `NoViableNotes`, and it also sleeps while waiting for an account to be committed. Both sleeps are recreated after every notification, and `reevaluate_mode` turns any non-`WaitForBlock` notification back into `NotesAvailable` without checking whether any note is viable. The coordinator spawns an actor for each target account observed in network notes and then calls `notify()` on every registered actor for every committed block. On an active chain whose block interval is shorter than `idle_timeout`, these global notifications continually reset both the idle timer and the account-commit wait timer. One note per target can therefore leave many never-committed or no-work account actors resident indefinitely.

## Impact

Those pinned actors perform per-block database checks and compete for scheduler, pool, and semaphore resources even when they have no valid work. A low-cost stream of targeted notes can grow this background load until legitimate network-account actors are delayed or the NTX builder becomes unavailable.

## Root Cause

The idle timeout is implemented as a per-loop sleep that resets on any notification, while notifications are global per block rather than scoped to actors with actual state changes. There is no actor-count cap or pre-spawn viability check that removes actors whose target account never commits or has no viable notes.

## Source Locations

### 1. bin/ntx-builder/src/committed_block.rs:34-42

Committed public network notes define the target accounts that can drive actor creation.

```text
let mut network_notes = Vec::new();
        for batch in body.output_note_batches() {
            for (_idx, output_note) in batch {
                if let OutputNote::Public(public) = output_note
                    && let Ok(network_note) =
                        AccountTargetNetworkNote::new(public.as_note().clone())
                {
                    network_notes.push(network_note);
                }
```

### 2. bin/ntx-builder/src/coordinator.rs:151-165

Each committed block spawns actors for targeted accounts and wakes every active actor.

```text
pub fn handle_committed_block(&mut self, effects: &CommittedBlockEffects) {
        let mut targeted: HashSet<AccountId> = HashSet::new();
        for note in &effects.network_notes {
            targeted.insert(note.target_account_id());
        }

        for account_id in &targeted {
            if !self.actor_registry.contains_key(account_id) {
                self.spawn_actor(*account_id);
            }
        }

        for handle in self.actor_registry.values() {
            handle.notify();
        }
```

### 3. bin/ntx-builder/src/actor/mod.rs:312-337

The idle timeout is a sleep created only for the current `NoViableNotes` loop iteration.

```text
let idle_timeout_sleep = match mode {
                ActorMode::NoViableNotes => tokio::time::sleep(self.config.idle_timeout).boxed(),
                _ => std::future::pending().boxed(),
            };

            tokio::select! {
                // A committed block touched this account (or the coordinator woke everyone).
                _ = self.notify.notified() => {
                    mode = self.reevaluate_mode(account_id, mode).await?;
                },
                // Execute a transaction once a permit is available.
                permit = tx_permit_acquisition => {
                    let _permit = permit.context("semaphore closed")?;
                    let chain_state = self.state.chain.get_cloned();
                    let tx_candidate =
                        self.select_candidate_from_db(account_id, chain_state).await?;
                    mode = match tx_candidate {
                        Some(candidate) => self.execute_transactions(account_id, candidate).await,
                        None => ActorMode::NoViableNotes,
                    };
                }
                // Idle timeout: actor has been idle too long, deactivate.
                () = idle_timeout_sleep => {
                    tracing::info!(%account_id, "Account actor deactivated due to idle timeout");
                    return Ok(());
                }
```

### 4. bin/ntx-builder/src/actor/mod.rs:351-385

Any notification outside `WaitForBlock` moves the actor to `NotesAvailable` without verifying available work.

```text
async fn reevaluate_mode(
        &self,
        account_id: AccountId,
        mode: ActorMode,
    ) -> anyhow::Result<ActorMode> {
        match mode {
            ActorMode::WaitForBlock { submitted_tx_id, submitted_at } => {
                let landed = self
                    .state
                    .db
                    .account_last_tx(account_id)
                    .await
                    .context("failed to check submitted tx landing")?
                    == Some(submitted_tx_id);
                if landed {
                    return Ok(ActorMode::NotesAvailable);
                }

                let chain_tip = self.state.chain.chain_tip_block_number();
                let elapsed = chain_tip.checked_sub(submitted_at.as_u32()).unwrap_or_default();
                if elapsed.as_u32() >= u32::from(self.config.tx_expiration_delta.get()) {
                    tracing::info!(
                        %account_id,
                        %submitted_at,
                        current_tip = %chain_tip,
                        delta = self.config.tx_expiration_delta,
                        "submitted transaction expired",
                    );
                    return Ok(ActorMode::NotesAvailable);
                }

                Ok(ActorMode::WaitForBlock { submitted_tx_id, submitted_at })
            },
            _ => Ok(ActorMode::NotesAvailable),
        }
```

### 5. bin/ntx-builder/src/actor/mod.rs:450-484

The account-commit wait timeout is recreated after each notification that does not find a committed account.

```text
async fn wait_for_committed_account(&self, account_id: AccountId) -> anyhow::Result<bool> {
        // Check if the account is already committed.
        if self
            .state
            .db
            .has_committed_account(account_id)
            .await
            .context("failed to check for committed account")?
        {
            return Ok(true);
        }

        loop {
            tokio::select! {
                _ = self.notify.notified() => {
                    if self
                        .state
                        .db
                        .has_committed_account(account_id)
                        .await
                        .context("failed to check for committed account")?
                    {
                        tracing::info!(account.id=%account_id, "Account committed, starting normal operation");
                        return Ok(true);
                    }
                }
                _ = tokio::time::sleep(self.config.idle_timeout) => {
                    tracing::info!(
                        %account_id,
                        "Account actor deactivated while waiting for account commit",
                    );
                    return Ok(false);
                }
            }
        }
```

