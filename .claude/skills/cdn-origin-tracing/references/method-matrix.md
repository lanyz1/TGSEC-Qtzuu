# Method Matrix (top practical ranks)

Full writeups for all 50 methods live in `full-handbook-v5.1.md`.

| Rank | Method | Hit rate | Speed | Auto |
|------|--------|----------|-------|------|
| 1 | SSL CT (crt.sh / Censys) | 85% | sec | Y |
| 2 | Subdomain enum + bypass labels | 80% | min | Y |
| 3 | Historical DNS | 75% | sec | Y |
| 4 | FOFA / Shodan / ZoomEye / Censys | 70% | sec | Y |
| 5 | CNAME chain | 70% | sec | Y |
| 6 | CDN range filter / ASN | 65% | min | Y |
| 7 | SPF | 60% | sec | Y |
| 8 | MX linkage | 55% | sec | Y |
| 9 | Host-header verify | 55% | min | Y |
| 10 | 3rd-party IDs (GA/百度) | 50% | min | N |
| 12 | ICP (CN) | 45% | sec | N |
| 13 | WP xmlrpc pingback | 40% | sec | Y |
| 14 | Mail headers | 45% | min | N |
| 15 | Favicon mmh3 | 40% | min | partial |
| 24 | Passive DNS aggregate | 80% | sec | Y |
| 27 | CF Tunnel / cloudflared | 35% | min | partial |
| 28 | CF Pages/Workers/R2 | 45% | sec | Y |
| 34 | Cloud buckets S3/OSS/COS | 50% | min | Y |
| 40 | Mobile/APK hardcoded IP | 45% | min | Y |
| 49 | Origin drift monitor | 50% | min | Y |

## Default combo (≈3 min)

1. crt.sh full names → resolve A/AAAA → filter CDN
2. HackerTarget / SecurityTrails history
3. dig MX + TXT (SPF includes)
4. FOFA/Shodan cert without cf-ray
5. Host verify + sha256 body vs CDN front

## Bypass subdomain labels (high hit)

`mail smtp pop3 imap webmail mx cpanel whm admin ftp ftps sftp direct origin backend real unprotected bypass no-cdn raw vpn ns1 ns2 mysql db redis ssh git staging dev test uat beta api api2 ws m mobile`
