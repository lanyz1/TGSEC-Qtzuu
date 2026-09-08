# CDN Origin Decision Tree

```
start → target.com
  │
  ├─ 1. CDN detect (cf-ray / x-amz-cf-id / via / multi-geo IP?)
  │     ├─ no CDN → dig A/AAAA, done
  │     └─ has CDN → branch
  │
  ├─ 2. Cloudflare Tunnel? (CNAME → cfargotunnel.com)
  │     ├─ yes → Tunnel/Pages/Workers/config leak/sibling domains
  │     └─ no → 3
  │
  ├─ 3. Portrait branch
  │     ├─ CN site → ICP + mail/ftp/cpanel grey-cloud + MX/SPF + OSS/COS
  │     ├─ AWS → S3 + Lambda@Edge + CloudFront alt + origin ranges
  │     ├─ Serverless → pages.dev / vercel.app CNAME + error pages
  │     ├─ K8s → Ingress/Traefik dashboards on space engines
  │     ├─ WordPress → xmlrpc pingback + /feed + mail headers
  │     └─ Mobile → APK hardcode IP + Frida / traffic
  │
  ├─ 4. Universal discovery (always)
  │     crt.sh → subs → historical DNS → passive DNS → FOFA/Shodan cert
  │
  ├─ 5. Filter CDN ranges
  │
  ├─ 6. Fingerprint verify
  │     Host header → TLS SAN/issuer → body hash → favicon
  │
  └─ 7. Score → P≥0.95 confirm / else strengthen branch 3
```

## Score cheat sheet

| Evidence combo | Posterior | Action |
|----------------|-----------|--------|
| Fingerprint + Cert | 95%+ | Confirm origin |
| Fingerprint + Cert + DNS history | 99%+ | Archive |
| Cert + DNS + Sub (no fingerprint) | 80–90% | Add Host/hash |
| Space-engine only | 30–50% | High false-positive; must fingerprint |
| Mail only | 40–60% | Mail host ≠ web origin |
| Fingerprint alone | 70–85% | Strong; add cert/DNS |

## Bayesian LLR (v5)

| Dim | Hit | Miss |
|-----|-----|------|
| A cert | +3.0 | −1.0 |
| B DNS history | +2.5 | −1.5 |
| C subdomain | +2.0 | −1.0 |
| D mail | +2.0 | −0.5 |
| E fingerprint | +4.0 | −2.0 |
| F space engine | +1.5 | −2.0 |

Prior logit ≈ log(0.2/0.8). P≥0.95 confirm; 0.80–0.95 add E; <0.50 drop.
