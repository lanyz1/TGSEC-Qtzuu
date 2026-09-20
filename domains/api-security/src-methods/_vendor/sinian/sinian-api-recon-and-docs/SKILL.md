---
name: api-recon-and-docs
description: >-
  API reconnaissance and documentation review playbook. Use when discovering endpoints, schemas, versions, OpenAPI specs, hidden docs, mobile API paths, and surface area for API testing before exploitation.
---

# SKILL: API Recon and Docs — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert API surface discovery. Covers JS-bundle and source-map mining, APK reverse engineering for hardcoded paths, OpenAPI/Swagger discovery and exploitation, version drift (v1 vs v2 vs mobile vs legacy), hidden docs and `.well-known` metadata, parameter mining from schemas, content discovery on API base paths, batch/admin/actuator endpoint enumeration, and GraphQL endpoint location. This skill is the mandatory first step — every finding here feeds a downstream exploitation skill.

## 0. RELATED ROUTING

Use this file for discovery and surface mapping only — exploitation routes elsewhere. Also load:

- [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md) once a GraphQL endpoint or hidden field is found
- [api authorization and bola](../api-authorization-and-bola/SKILL.md) for object-level authorization testing on discovered endpoints
- [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) when auth tokens, roles, or scopes are discovered in docs/JS
- [business logic vulnerabilities](../business-logic-vulnerabilities/SKILL.md) when a discovered endpoint has a suspicious business flow
- [idor broken object level authorization](../idor-broken-object-authorization/SKILL.md) for ID-type analysis on discovered resources

---

## 1. PRIMARY GOALS

1. Map every reachable API entrypoint (REST, GraphQL, mobile, admin).
2. Extract schemas, optional/deprecated fields, and role/tenant differences.
3. Identify old versions, mobile paths, and undocumented parameters that weaken security.

> **Rule**: recon is read-only discovery. Once you start manipulating IDs, tokens, or business state, route to the exploitation skill.

---

## 2. JAVASCRIPT BUNDLE MINING

Modern SPAs ship the entire API surface in client bundles. Mining them usually yields more endpoints than any scanner.

### 2a. Endpoint Extraction with Regex

```bash
# Pull the main bundle and extract API paths
curl -s https://target/static/js/main.abc123.js \
  | grep -oE '"/(api|rest|v1|v2|graphql|gql|internal|admin|mobile)[/a-zA-Z0-9_\-{}:.]+"' \
  | tr -d '"' | sort -u

# Broader: catch any /path-like string
curl -s https://target/static/js/main.abc123.js \
  | grep -oE '"/[a-zA-Z0-9_/{}\-]{3,}"' | tr -d '"' | sort -u > endpoints.txt
```

### 2b. Source Map Leakage

Production builds sometimes expose `.map` files. These contain original source with full field names and even comments:

```bash
# Discover references to source maps
curl -s https://target/static/js/main.abc123.js | grep -oE '[a-zA-Z0-9._-]+\.js\.map'

# Fetch and reconstruct
curl -s https://target/static/js/main.abc123.js.map -o main.map
# Extract original source files
jq -r '.sources[]' main.map
# Unpack source content
jq -r '.sourcesContent[]' main.map > recovered_source.js
grep -oE '"/api/[a-zA-Z0-9_/{}]+"' recovered_source.js | sort -u
```

Tool: `unwebpack-sourcemap` auto-reconstructs the full directory tree.

### 2c. Webpack Chunk Enumeration

Webpack splits code into numbered chunks. Enumerate them:

```bash
# Find chunk manifest in the bundle, then fetch each chunk
for i in $(seq 0 50); do
  curl -s -o /dev/null -w "%{http_code} chunk$i\n" "https://target/static/js/$i.abc123.chunk.js"
done
# Each chunk often maps a lazy-loaded route with its own API calls
```

---

## 3. MOBILE APK REVERSE ENGINEERING

Mobile apps hardcode API paths, headers, feature flags, and even secrets that never appear in web clients.

### 3a. APK Toolchain

```bash
# Decompile APK
apktool d target.apk -o target_decoded

# Extract URL/path strings from smali + resources
grep -rhoE 'https?://[a-zA-Z0-9./_:?=&%-]+' target_decoded/ | sort -u
grep -rhoE '"/(api|v1|v2|mobile|rest|graphql)[a-zA-Z0-9_/{}.-]*"' target_decoded/ | sort -u

# Look for API keys, tokens, base URLs in resources
grep -rhoE 'AIza[A-Za-z0-9_-]{35}|sk_live_[a-zA-Z0-9]{24}|x-api-key' target_decoded/res/

# Dex to Java for richer analysis
jadx target.apk -d target_java
grep -rhoE '"/api/[a-zA-Z0-9_/{}]+"' target_java/ | sort -u
```

### 3b. iOS IPA

```bash
# Unzip IPA, inspect Info.plist and binaries
unzip target.ipa -d target_ipa
plutil -p target_ipa/Payload/*.app/Info.plist
strings target_ipa/Payload/*.app/target | grep -E '/(api|v1|mobile)/'
```

### 3c. Passive Network Collection

Proxy the mobile app through Burp/mitmproxy and capture every API call. Mobile traffic reveals endpoints, headers, and parameter sets the web UI never uses.

---

## 4. OPENAPI / SWAGGER DISCOVERY & EXPLOITATION

The OpenAPI/Swagger spec is the single richest recon artifact — it lists every endpoint, parameter, request/response schema, and sometimes auth role requirements.

### 4a. Common Spec Paths (exhaustive)

Probe these; many are left world-readable:

```text
/swagger.json
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/openapi.json
/openapi.yaml
/openapi/v1/openapi.json
/api-docs
/api-docs/json
/api/swagger.json
/api/openapi.json
/v1/api-docs
/v2/api-docs
/v3/api-docs
/v3/api-docs/swagger-config
/api/v1/swagger.json
/api/v2/openapi.json
/swagger-ui.html
/swagger-ui/index.html
/swagger
/swagger-ui/
/api/swagger-ui.html
/doc
/docs
/redoc
/api-docs.yaml
/swagger.yaml
/spec
/spec.json
```

```bash
# Bulk probe
for p in /swagger.json /openapi.json /v3/api-docs /swagger-ui.html /api-docs /api/swagger.json; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target$p")
  echo "$p -> $code"
done
```

### 4b. Extract Everything from a Spec

```bash
SPEC=https://target/v3/api-docs

# All endpoints (method + path)
curl -s $SPEC | jq -r '.paths | to_entries[] | .key as $path | .value | to_entries[] | "\(.key | ascii_upcase) \($path)"'

# All parameters across endpoints
curl -s $SPEC | jq -r '.paths[].parameters[]?.name' | sort -u

# All request body schema fields
curl -s $SPEC | jq -r '.components.schemas | to_entries[] | .value.properties | keys[]?' | sort -u

# Find additionalProperties: true (arbitrary-key acceptance → mass assignment)
curl -s $SPEC | jq -r '.components.schemas | to_entries[] | select(.value.additionalProperties != null) | .key'
```

### 4c. Swagger UI Unauthenticated Access

Swagger UI itself is often left public even when auth protects the API. Read the spec through the UI's `?url=` parameter or the raw JSON to extract the full surface, then test endpoints directly with your own token.

### 4d. Role Differences in Specs

Some specs tag endpoints with role info (`x-roles`, `security` scopes). Diff these to find endpoints where a low-priv role is unexpectedly permitted:

```bash
curl -s $SPEC | jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | select(.value.security != null) | "\(.value.security)  \(.key | ascii_upcase) \($p)"'
```

---

## 5. VERSION DRIFT

APIs evolve; old versions are frequently deprecated but never decommissioned and never backport security fixes.

### 5a. Version Matrix to Probe

```text
/api/v1/...        /api/v2/...        /api/v3/...
/api/...           (unversioned)
/api/internal/...  /api/mobile/...    /api/legacy/...
/api/private/...   /api/admin/...     /api/old/...
/api/beta/...      /api/rc/...        /api/staging/...
```

```bash
# Fuzz version segments
for v in v1 v2 v3 v4 internal mobile legacy private admin old beta rc staging; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target/api/$v/users")
  echo "/api/$v/users -> $code"
done
```

### 5b. Old-Version Authorization Weaker

Older versions often predate authorization hardening. If `/api/v2/users/{id}` enforces ownership but `/api/v1/users/{id}` does not, v1 is the IDOR vector:

```bash
# As user A, fetch user B's data on each version
curl -s -H "Authorization: Bearer $A_TOKEN" https://target/api/v1/users/$B_ID
curl -s -H "Authorization: Bearer $A_TOKEN" https://target/api/v2/users/$B_ID
# Compare response bodies / status codes
```

### 5c. Deprecated-but-Active Detection

Specs mark deprecated endpoints (`deprecated: true`). They still work. Always test them:

```bash
curl -s $SPEC | jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | select(.value.deprecated==true) | "\(.key | ascii_upcase) \($p) [DEPRECATED]"'
```

---

## 6. HIDDEN DOCS & METADATA

```text
/.well-known/
/.well-known/security.txt
/.well-known/openapi.json
/.well-known/assetlinks.json   (Android app links)
/api/.well-known/
/robots.txt
/sitemap.xml
/sitemap.xml.gz
/.git/config                  (exposed repo)
/.git/HEAD
/source.zip, /backup.zip, /api.zip
/api/docs, /api/help, /api/status
/swagger-resources
/configuration/security        (Spring)
/env, /actuator                (Spring Boot)
```

```bash
# Fast metadata sweep
for p in /.well-known/security.txt /robots.txt /sitemap.xml /.git/config /swagger-resources /actuator; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target$p")
  echo "$p -> $code"
done
```

`robots.txt` and `sitemap.xml` frequently list admin/internal paths meant to be hidden from crawlers — a direct endpoint list.

---

## 7. MOBILE API PATHS

Mobile clients often hit a parallel API tree with weaker controls.

### 7a. Mobile Path Variants

```text
/api/mobile/...
/mobile/v1/...
/m/api/...
/m/v1/...
/api/m/...
/app/v1/...          (app-specific)
```

### 7b. User-Agent Triggered Differentiation

Some gateways route by User-Agent. A mobile UA may unlock endpoints the web UA never sees:

```bash
# Web client
curl -s -A "Mozilla/5.0" https://target/api/users

# Mobile client — may return different fields or endpoints
curl -s -A "TargetApp/3.2.0 (Android 13)" https://target/api/users
curl -s -A "Target/3.2.0 CFNetwork/1410 (iOS)" https://target/api/users

# Internal/test UA sometimes bypasses WAF
curl -s -A "GoogleBot/2.1" https://target/api/internal/health
curl -s -H "X-Internal: true" https://target/api/users
```

Diff the JSON response between UAs — mobile often returns extra PII or admin fields.

---

## 8. PARAMETER MINING FROM SCHEMA

### 8a. Optional / Deprecated Fields

```bash
# Optional fields (nullable or not required) — often accepted via mass assignment
curl -s $SPEC | jq -r '.components.schemas | to_entries[] | .key as $s | .value.properties | to_entries[] | select(.value.nullable==true or .value.readOnly!=true) | "\($s).\(.key)"'

# Deprecated fields still accepted
curl -s $SPEC | jq -r '.components.schemas | to_entries[] | .key as $s | .value.properties | to_entries[] | select(.value.deprecated==true) | "\($s).\(.key)"'
```

### 8b. additionalProperties Schemas

Schemas with `additionalProperties: true` accept arbitrary keys — prime mass-assignment surface:

```bash
curl -s $SPEC | jq -r '.components.schemas | to_entries[] | select(.value.additionalProperties==true or (.value.additionalProperties|type=="object")) | .key'
```

### 8c. Filter / Sort / Role / Tenant Parameters

Scan all parameters for privilege-affecting names:

```bash
curl -s $SPEC | jq -r '.paths[].parameters[].name' | grep -iE 'role|tenant|org|admin|filter|sort|user|owner|as|imperson|debug|internal|export|all'
```

---

## 9. CONTENT DISCOVERY ON API BASE PATHS

Treat the API base path like a web root and brute-force it.

### 9a. Directory Brute Force

```bash
# ffuf against an API base
ffuf -u https://target/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,201,202,204,301,302,401,403 -mc all -fc 404 -t 50

# feroxbuster recurses
feroxbuster -u https://target/api/v1/ -w api-endpoints.txt -t 50 -d 3
```

### 9b. HTTP Method Enumeration

```bash
# OPTIONS reveals allowed methods
curl -s -X OPTIONS https://target/api/v1/users -i | grep -i allow

# Brute methods on every discovered path
for m in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X $m https://target/api/v1/users)
  echo "$m -> $code"
done
```

### 9c. Accept Header Variant Triggers

Different `Accept` values can trigger different parsers and response shapes — sometimes leaking XML/CSV export endpoints or debug views:

```bash
curl -s -H "Accept: application/xml" https://target/api/v1/users
curl -s -H "Accept: text/csv"        https://target/api/v1/users
curl -s -H "Accept: application/vnd.target.v2+json" https://target/api/v1/users
curl -s -H "Accept: */*"             https://target/api/v1/users
```

---

## 10. BATCH & HIGH-VALUE ENDPOINT DISCOVERY

Bulk/export endpoints aggregate data and are high-value recon targets. Append these to every resource path:

| Suffix | Example | Why valuable |
|---|---|---|
| `/bulk` | `POST /api/v1/users/bulk` | Batch create/update, weaker per-item checks |
| `/export` | `GET /api/v1/users/export` | Full dataset dump, often unpaginated |
| `/search` | `POST /api/v1/users/search` | Wildcard/filter injection |
| `/list` | `GET /api/v1/users/list` | No pagination, leaks all |
| `/all` | `GET /api/v1/users/all` | Bypasses ownership scoping |
| `/count`, `/stats` | `GET /api/v1/users/stats` | Enumerate total records |
| `/import` | `POST /api/v1/users/import` | CSV injection, mass write |
| `/archive` | `GET /api/v1/orders/archive` | Old data, weaker auth |

```bash
for suf in bulk export search list all count stats import archive; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target/api/v1/users/$suf")
  echo "/users/$suf -> $code"
done
```

---

## 11. ADMIN / MANAGEMENT ENDPOINTS

### 11a. Framework-Specific Actuator (Spring Boot)

Spring Boot Actuator endpoints are notoriously left exposed and unprotected:

```text
/actuator
/actuator/health
/actuator/env          (env vars + secrets)
/actuator/configprops
/actuator/mappings     (ALL routes incl. internal)
/actuator/heapdump     (memory dump → secrets)
/actuator/threaddump
/actuator/beans
/actuator/loggers
/actuator/metrics
/actuator/httptrace    (recent requests incl. headers/tokens)
/mappings
/env
```

```bash
for p in /actuator /actuator/env /actuator/mappings /actuator/heapdump /actuator/httptrace /env /mappings; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target$p")
  echo "$p -> $code"
done
```

`/actuator/mappings` enumerates every registered route — better than any wordlist. `/actuator/heapdump` yields in-memory secrets.

### 11b. Generic Admin/Internal Paths

```text
/admin
/admin/api
/admin/users
/admin/dashboard
/internal
/internal/api
/debug
/debug/vars
/debug/pprof         (Go)
/health
/healthz
/status
/metrics
/api/admin
/api/internal
/api/debug
/manage
/management
```

---

## 12. GRAPHQL ENDPOINT DISCOVERY

GraphQL is covered in depth in its own skill; here is the discovery layer:

```bash
for p in /graphql /api/graphql /graphql/v1 /gql /api/v1/graphql /query /graphql/console /graphiql /playground /api/v2/graphql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target$p" \
    -H "Content-Type: application/json" -d '{"query":"{__typename}"}')
  echo "$p -> $code"
done

# Also grep JS bundles for graphql references
curl -s https://target/static/js/main.abc123.js | grep -oiE '/[a-z0-9/_-]*graphql[a-z0-9/_-]*' | sort -u
```

Once found → route to [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md).

---

## 13. RECON QUICK REFERENCE

| Recon action | Command/tool | Yields |
|---|---|---|
| JS endpoint mining | `grep -oE '"/api/..."'` | hidden routes |
| Source map | `.map` + `unwebpack-sourcemap` | original field names |
| APK decompile | `apktool` / `jadx` | mobile-only paths + keys |
| Spec extraction | `jq` over openapi.json | full endpoint/param/field map |
| Version fuzz | `/api/v1..v3`, internal, mobile | deprecated weak versions |
| Metadata sweep | `.well-known`, robots, sitemap | admin/internal paths |
| UA diff | mobile vs web UA | extra response fields |
| Dir brute | `ffuf` / `feroxbuster` | unlisted endpoints |
| Method fuzz | OPTIONS + all verbs | hidden write methods |
| Actuator | `/actuator/mappings` | complete route map |

---

## 14. TESTING CHECKLIST

```
□ Mine all JS bundles with grep for /api, /graphql, /internal paths
□ Check for and fetch .js.map source maps; reconstruct original source
□ Enumerate and fetch webpack chunks
□ Decompile mobile APK/IPA; extract hardcoded paths, keys, base URLs
□ Proxy mobile app through Burp; capture mobile-only endpoints/fields
□ Probe exhaustive OpenAPI/Swagger paths; fetch any accessible spec
□ Extract endpoints, params, fields, deprecated flags, additionalProperties from spec with jq
□ Check Swagger UI for unauthenticated access (?url=)
□ Fuzz version segments: v1/v2/v3/internal/mobile/legacy/beta/staging
□ Compare authorization strength across API versions (old often weaker)
□ Sweep metadata: .well-known, robots.txt, sitemap.xml, .git, backup zips
□ Probe mobile path variants and switch User-Agent (mobile/GoogleBot/internal)
□ Mine optional/deprecated/additionalProperties fields for mass-assignment
□ Brute-force API base path with ffuf/feroxbuster
□ Enumerate HTTP methods (OPTIONS + all verbs) on every discovered path
□ Test Accept header variants (xml, csv, vendor versioned) for different responses
□ Probe bulk/export/search/list/all/count/import suffixes on every resource
□ Sweep Spring Boot actuator endpoints (/actuator/mappings, /env, /heapdump)
□ Sweep generic admin/internal/debug/health/metrics paths
□ Locate GraphQL endpoint; route to the GraphQL skill for exploitation
```

---

## 15. NEXT ROUTING

| Finding | Next Skill |
|---|---|
| GraphQL endpoint or hidden field found | [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md) |
| Object IDs exposed on discovered endpoints | [api authorization and bola](../api-authorization-and-bola/SKILL.md) |
| JWT/OAuth tokens, roles, or scopes in docs/JS | [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) |
| Strong auth boundary but suspicious business flow | [business logic vulnerabilities](../business-logic-vulnerabilities/SKILL.md) |
| ID type/predictability analysis needed | [idor broken object level authorization](../idor-broken-object-authorization/SKILL.md) |

---

## 16. 2026 EMERGING TECHNIQUES

### 16.1 AI/LLM API & MCP Endpoint Discovery

2026年API侦察的最大变化是AI/LLM基础设施端点的爆发式增长。MCP (Model Context Protocol)远程HTTP服务器正在取代本地stdio成为部署标准。

**Nmap NSE脚本（NCC Group, 2026-06）— 生产级AI基础设施枚举：**

```bash
# MCP服务器检测与枚举（支持Streamable HTTP + 传统SSE）
nmap --script mcp-info,mcp-enum -p 80,443,3000,8000,8080 <target>
# 输出：OAuth 2.1受保护资源发现(RFC 9728)、工具/资源/提示枚举、基于模式的风险标记

# LLM推理API检测（OpenAI兼容/vLLM/SGLang/Ollama/HF TGI/llama.cpp/Triton/TorchServe/Anthropic）
nmap --script llm-info -p 80,443,8000,8080,11434 <target>
# 输出：框架指纹、认证状态、模型枚举、信息泄露标记
```

**生产MCP端点生态（2026 Q1-Q2）：**

| 提供商 | MCP端点 | 工具数 | 认证 | 侦察价值 |
|---|---|---|---|---|
| Stripe | `mcp.stripe.com` | 25个专用工具 | OAuth 2.1 | 支付/退款/客户API全量暴露 |
| Cloudflare | `api.cloudflare.com/mcp` | ~2,500端点压缩至1K tokens | OAuth 2.1 | 2,500个API端点的schema一次性获取 |
| GitHub | `api.github.com/mcp` | 读写工具 | OAuth 2.1 | 仓库/Issue/PR读写权限 |
| Sentry | MCP端点 | 错误监控工具 | OAuth 2.1 | 项目错误数据访问 |
| Linear | MCP端点 | 项目管理工具 | OAuth 2.1 | 内部任务/计划读取 |
| AWS Bedrock | AWS MCP服务器 | Bedrock模型管理 | IAM | 模型调用/管理权限 |
| Azure | Azure MCP预览版 | Azure服务管理 | Entra ID | 云资源管理权限 |

**MCP端点发现方法论：**

```bash
# 1. MCP服务器探测 — JSON-RPC初始化握手
curl -s -X POST https://target.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"recon","version":"1.0"}}}'

# 2. 工具枚举（无需认证的开放MCP服务器）
curl -s -X POST https://target.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# 3. OAuth 2.1受保护资源发现（RFC 9728）
curl -s https://target.com/.well-known/oauth-protected-resource

# 4. MCP注册表搜索（官方100+验证服务器）
# https://registry.modelcontextprotocol.io/
```

**LLM API枚举（与传统API枚举的差异）：**

LLM API枚举探测模型级接口——特定能力、限制、内容策略、模型变体和行为特征，而非CRUD端点。

```bash
# OpenAI兼容API — 模型列表枚举
curl -s https://target.com/v1/models -H "Authorization: Bearer <key>"
# 返回所有可用模型及其权限范围

# vLLM/SGLang — 服务器信息泄露
curl -s https://target.com/v1/models        # 模型列表
curl -s https://target.com/get_model_info   # SGLang模型信息
curl -s https://target.com/get_server_info  # SGLang服务器配置

# Ollama — 无认证模型枚举
curl -s http://target:11434/api/tags        # 所有已加载模型
curl -s http://target:11434/api/ps          # 运行中模型

# HuggingFace TGI — 模型信息
curl -s https://target.com/info             # 模型配置、量化方式
curl -s https://target.com/metrics          # Prometheus指标
```

### 16.2 gRPC / Protobuf API 侦察

gRPC使用HTTP/2 + Protocol Buffers二进制编码，传统HTTP代理和扫描器无法有效检测。

**gRPC反射服务枚举（无需.proto文件）：**

```bash
# grpcurl — 利用gRPC Server Reflection发现所有服务和方法
grpcurl -plaintext target:9090 list                    # 列出所有服务
grpcurl -plaintext target:9090 list package.ServiceName # 列出某服务的所有方法
grpcurl -plaintext target:9090 describe package.ServiceName.Method # 获取方法签名和消息类型

# grpcui — 交互式gRPC Web UI（自动从反射生成）
grpcui -plaintext target:9090
# 在浏览器中直接调用gRPC方法，类似Swagger UI for gRPC

# 检测gRPC服务是否存在反射（无反射则无法枚举）
grpcurl -plaintext -connect-timeout 3s target:9090 list 2>&1 | grep "Server does not support reflection"
```

**gRPC端点发现（无反射时）：**

```bash
# 从proto文件提取端点
protoc --decode_raw < binary_payload.bin    # 解码未知protobuf消息
protoc --proto_path=. --decode=package.Message message.proto < data.bin

# 从JS/前端代码中提取gRPC-Web端点
grep -rhoE '/[a-z]\.[A-Za-z]+/[A-Za-z]+' main.js | sort -u
# gRPC-Web路径格式: /package.Service/Method

# Burp Suite gRPC插件：自动解码/编码protobuf消息
# 使用 BEnc-64 或 Protobuf plugin for Burp
```

**gRPC安全测试要点：**

| 攻击面 | 测试方法 |
|---|---|
| 反射服务暴露 | `grpcurl list` 无需认证即可枚举所有服务 |
| TLS缺失 | `-plaintext` 连接成功说明未启用TLS |
| 认证缺失 | 不带token直接调用方法 |
| 消息注入 | 构造超大字段/嵌套消息导致解析器DoS |
| 流注入 | 在server-streaming/client-streaming中注入恶意帧 |

### 16.3 Serverless API Gateway 新特性

**AWS API Gateway HTTP API v2（2026默认）：**

```bash
# 新的API路由格式 — 更紧凑的路径定义
# 旧: /items/{itemId}  新: /items/{itemId} (相同，但v2支持$default通配)
# $default 捕获所有未匹配路由 → 隐藏端点可能通过$default暴露

# 探测HTTP API v2 vs REST API v1
curl -s https://api.example.com/  # v2返回 {"message":"Not Found"} 无版本头
curl -s https://api.example.com/  # v1返回 {"message":"Missing Authentication Token"}
# v2的$default路由可捕获任意路径 → 枚举隐藏端点
```

**Azure API Management 2026：**
- 自托管网关（self-hosted gateway）暴露在公网时，管理API可能未认证
- 探测端点: `https://target/mgmt 2024-01-01-preview`

**Google API Gateway：**
- OpenAPI spec后端可配置多个后端URL → SSRF测试面
- 配置文件在GCS存储桶中 → 存储桶权限检查

### 16.4 GraphQL over WebSocket & SSE

2026年GraphQL订阅(subscription)通过WebSocket和SSE的部署激增。

```bash
# GraphQL over WebSocket — subscription枚举
# 使用 graphql-ws 协议（2026标准，取代旧graphql-transport-ws）
wscat -c "wss://target.com/graphql" \
  -x '{"type":"connection_init","payload":{}}'

# 发送subscription查询
wscat -c "wss://target.com/graphql" \
  -s '{"type":"subscribe","id":"1","payload":{"query":"subscription{messageAdded{id,content}}"}}'

# GraphQL over SSE — Server-Sent Events订阅
curl -N https://target.com/graphql \
  -H "Accept: text/event-stream" \
  -H "Content-Type: application/json" \
  -d '{"query":"subscription{userStatus{userId,status}}"}'
```

**APQ (Automatic Persisted Queries) hash预测：**

Apollo Persisted Query通过SHA256 hash缓存查询，可绕过内省禁用。

```bash
# 1. 计算已知查询的hash
echo -n '{"query":"query{__typename}"}' | sha256sum
# 2. 用hash直接请求（无需发送完整query）
curl "https://target.com/graphql?extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22<hash>%22%7D%7D"
# 3. 如果hash匹配已缓存查询，返回结果（无需内省权限）
```

### 16.5 AI Agent 工具调用端点枚举

AI Agent通过Function Calling/MCP暴露的端点是2026年全新的API攻击面。

**Function Calling端点发现：**

```bash
# 从前端JS中提取function definitions
grep -rhoE '"name"\s*:\s*"[a-z_]+"\s*,\s*"description"' main.js | sort -u
grep -rhoE '"function"\s*:\s*\{[^}]+\}' main.js | jq .

# OpenAI Function Calling schema提取
grep -rhoE '"parameters"\s*:\s*\{[^}]+\}' main.js | jq .

# 探测AI Agent后端API
curl -s https://target.com/api/agent/tools      # 工具列表
curl -s https://target.com/api/agent/functions   # 函数列表
curl -s https://target.com/api/chat/completions  # OpenAI兼容端点
curl -s https://target.com/api/agent/execute     # 工具执行端点
```

**AI Agent API安全测试清单补充：**

```
□ 探测MCP端点 (/mcp, /sse, /.well-known/oauth-protected-resource)
□ 枚举MCP工具列表 (tools/list, resources/list, prompts/list)
□ 检测LLM推理API (/v1/models, /info, /metrics, /api/tags)
□ 测试gRPC反射服务 (grpcurl list)
□ 枚举GraphQL subscription (WebSocket + SSE)
□ 提取前端Function Calling schema
□ 探测$default通配路由 (HTTP API v2)
□ 检查AI Agent工具执行端点认证
□ 测试MCP OAuth 2.1认证是否可绕过
□ 枚举LLM模型列表检测信息泄露
```

### 16.6 2026 API侦察速查表

| 技术 | 端点/命令 | 发现内容 |
|---|---|---|
| MCP枚举 | `POST /mcp {"method":"tools/list"}` | AI工具全量列表 |
| LLM API | `GET /v1/models` | 模型列表及权限 |
| gRPC反射 | `grpcurl -plaintext host:9090 list` | gRPC服务和方法 |
| GraphQL WS | `wscat -c wss://target/graphql` | subscription端点 |
| GraphQL APQ | `?extensions={persistedQuery...}` | 绕过内省禁用 |
| HTTP API v2 | `GET /$default` | 通配路由捕获 |
| Ollama | `GET :11434/api/tags` | 已加载模型 |
| SGLang | `GET /get_server_info` | 服务器配置泄露 |

**参考来源：**
- NCC Group Nmap NSE scripts for MCP/LLM detection (2026-06, seclists.org/nmap-dev)
- APIScout "Top APIs With MCP Endpoints 2026" (2026-04)
- ESET Threat Report H1 2026 (malicious AI skills analysis)
