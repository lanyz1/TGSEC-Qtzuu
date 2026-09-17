# Method Matrix (top practical ranks)

Full writeups for all 50 methods live in `full-handbook-v5.1.md`.
Cost-tiered P0–P4 pipeline (fast wins → deep dig; vendor bypass matrix; cert-serial decision table): `p0-p4-priority-playbook.md`.

| Rank | Method | Hit rate | Speed | Auto |
|------|--------|----------|-------|------|
| 1 | SSL CT (crt.sh / Censys) | 85% | sec | Y |
| 2 | Subdomain enum + bypass labels | 80% | min | Y |
| 3 | Historical DNS (CN add: ipchaxun / ip138) | 75% | sec | Y |
| 4 | FOFA / Shodan / ZoomEye / Censys | 70% | sec | Y |
| 5 | CNAME chain | 70% | sec | Y |
| 6 | CDN range filter / ASN | 65% | min | Y |
| 7 | SPF | 60% | sec | Y |
| 8 | MX linkage | 55% | sec | Y |
| 9 | Host-header verify | 55% | min | Y |
| 10 | 3rd-party IDs (GA/AdSense/百度) | 50% | min | N |
| 12 | ICP (CN) | 45% | sec | N |
| 13 | WP xmlrpc pingback | 40% | sec | Y |
| 14 | Mail headers (trigger / Received) | 45% | min | N |
| 15 | Favicon mmh3 | 40% | min | partial |
| 24 | Passive DNS aggregate (OTX/DNSDumpster/URLScan) | 80% | sec | Y |
| 27 | CF Tunnel / cloudflared | 35% | min | partial |
| 28 | CF Pages/Workers/R2 | 45% | sec | Y |
| 34 | Cloud buckets S3/OSS/COS | 50% | min | Y |
| 40 | Mobile/APK hardcoded IP | 45% | min | Y |
| 49 | Origin drift monitor | 50% | min | Y |
| ★ | Cert serial exact-match (decisive verify) | 95%+ | sec | Y |
| ★ | CF CrimeFlare DB | 40% | sec | N |
| ★ | ACME renewal window / new-subdomain monitor | 30% | slow | Y |

## Default combo (≈3 min)

1. crt.sh full names → resolve A/AAAA → filter CDN
2. HackerTarget / SecurityTrails history + **ipchaxun.com / site.ip138.com**（CN 优选）
3. dig MX + TXT (SPF includes)
4. FOFA/Shodan cert without cf-ray
5. Host verify + sha256 body vs CDN front + **cert serial exact-match（决定性）**

## CN quick combo (≈1 min)

`ipchaxun.com/<domain>/` 取最早 A 记录 → `site.ip138.com/<ip>/` 反查同 IP 域名 → ICP 备案主体 → MX/SPF 内网 IP

## Bypass subdomain labels (high hit)

`mail smtp pop3 imap webmail mx cpanel whm admin ftp ftps sftp direct origin backend real unprotected bypass no-cdn raw vpn ns1 ns2 mysql db redis ssh git staging dev test uat beta api api2 ws m mobile`

CN 增补：`direct-connect silent greycloud uncdn`
