---
name: cdn-origin-tracing
description: "Use for CDN/WAF origin IP tracing."
version: 0.1.0
author: 思念 (狗盾思念), Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [cdn, waf, cloudflare, origin-ip, recon, bypass]
    related_skills: [pentest-execution, black-cat-redteam, tgsec-suite]
---

# CDN Origin Tracing

Find origin IPs behind Cloudflare/Akamai/阿里云/腾讯云/AWS CDN. Prefer layered discovery + fingerprint verification over single tricks. Full handbook: `references/full-handbook-v5.1.md`.

## When to Use

- CDN / WAF / Cloudflare / 源站 / 真实 IP / origin IP / CDN bypass
- Target has `cf-ray`, multi-region Anycast, or rate-limit only on CDN edge
- Need direct-IP connect to bypass WAF/captcha before auth brute / xmlrpc / admin

Don't use for: Turnstile token farming alone (`pentest-execution/references/cloudflare-turnstile-bypass.md`); pure static CDN gambling nodes with no origin (`pentest-execution/references/cdn-static-gambling-recon.md`).

## Prerequisites

- `terminal` with `curl`, `dig`/`nslookup`, `python3`
- Optional: `jq`, `openssl`, SecurityTrails/VT API keys
- Scripts: `scripts/cdn_quick_trace.py`, `scripts/cdn_ranges.py` (stdlib + `requests`)

## How to Run

```bash
# quick passive+verify pipeline
python3 scripts/cdn_quick_trace.py target.com
python3 scripts/cdn_quick_trace.py target.com --passive-only
python3 scripts/cdn_quick_trace.py target.com -o /tmp/cdn_report.json

# classify / filter candidate IPs
python3 scripts/cdn_ranges.py 104.16.1.1
python3 scripts/cdn_ranges.py --filter 1.2.3.4 104.16.1.1 8.8.8.8
```

Frame all invocations via `terminal`. Use `web_search` / `web_extract` when FOFA/Shodan UI is needed.

## Procedure

1. **Identify CDN** — `curl -sI https://target` for `cf-ray`/`x-amz-cf`/`via`/`x-cache`; multi-geo ping if needed. Done when vendor known or "no CDN".
2. **Discover candidates (layer 1–2)** — run `cdn_quick_trace.py` or manually: crt.sh → subdomains (mail/dev/origin/direct) → historical DNS → MX/SPF → FOFA/Shodan `cert="target"` excluding CDN issuer. Done when ≥1 non-CDN A/AAAA exists.
3. **Filter** — `cdn_ranges.py --filter <ips>`; drop CDN ranges. Done when candidate list is non-CDN only.
4. **Verify (mandatory)** — Host-header curl to candidate: `curl -sk --resolve target:443:IP https://target/ -o /tmp/o.html -D -`. Confirm with body hash / title / TLS SAN match. Host 200 alone ≠ origin (shared host / CDN node). Done when hash/title/SAN align or P≥0.80 with fingerprint evidence.
5. **Exploit path** — direct IP + Host/`--resolve` for WAF-bypassed scans (xmlrpc, admin, brute). Record origin in engagement notes.

Branching by portrait: see `references/decision-tree.md`. Method ranking: `references/method-matrix.md`.

## Quick Reference

| Goal | Command / query |
|------|-----------------|
| CT subs | `curl -s "https://crt.sh/?q=%.target.com&output=json" \| jq -r '.[].name_value' \| sort -u` |
| Passive DNS free | `curl -s "https://api.hackertarget.com/iphistory/?q=target.com"` |
| MX/SPF | `dig MX target.com +short`; `dig TXT target.com +short` |
| Host verify | `curl -sk --resolve target.com:443:IP https://target.com/ -D- -o /tmp/b.html` |
| FOFA | `cert="target.com" && header!="cf-ray"` |
| Shodan | `ssl.cert.subject.cn:target.com` |
| CF ranges | `curl -s https://www.cloudflare.com/ips-v4` |

High-hit bypass sub labels: `mail smtp cpanel direct origin backend dev staging ftp vpn admin api`.

## Pitfalls

- Host-header 200 on shared hosting ≠ origin — require fingerprint/hash.
- Cloudflare Tunnel (`cfargotunnel.com`) has no classic origin A record — pivot config leak / Pages / Workers / sibling domains.
- Domestic 鸡哥/Anti-DDoS may reuse non-obvious ASN ranges — refresh ranges before concluding.
- Pure static CDN edge (masscan 0 app ports, all API 404) → APK/subdomain pivot, not more Host fuzz on the edge IP.
- Do not burn hours on Turnstile automation; origin bypass first, then human/browser login if needed.

## Verification

- [ ] CDN vendor identified or ruled out
- [ ] Candidates filtered through `cdn_ranges` / known CIDRs
- [ ] At least one verified origin (hash/title/SAN) **or** documented blocker (Tunnel/no public origin)
- [ ] Direct-IP request path recorded for follow-on attacks
- [ ] Report JSON or notes saved (`-o` / engagement log)

## Related

- Full 50-method handbook: `references/full-handbook-v5.1.md`
- Pentest early step: `pentest-execution` § CDN bypass
- Recon routing: `black-cat-redteam` → `techniques/recon.md`
