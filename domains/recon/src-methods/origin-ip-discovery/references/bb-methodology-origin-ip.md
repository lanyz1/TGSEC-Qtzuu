# Bug Bounty Methodology — Origin IP / CDN excerpts

3. [Phase 3 — Infrastructure Mapping (ASN / CIDR / IPs)](#phase-3--infrastructure-mapping-asn--cidr--ips)
4. [Phase 4 — WAF Bypass & Origin IP Discovery](#phase-4--waf-bypass--origin-ip-discovery)
## Phase 3 — Infrastructure Mapping (ASN / CIDR / IPs)

> Most hunters stop at subdomains. This is where you go deeper — mapping the entire IP infrastructure of the organization.

### Step 1 — Find the ASN

```bash
# asnmap — resolves domain to ASN
asnmap -d target.com

whois <IP> | grep -i "origin\|as\|route"
# spk — finds all ASNs for a company by name
spk -json -s "Tesla"
```

**Web alternatives:**
- https://bgp.he.net — search by company name
- https://bgp.tools — clean interface
- https://asnlookup.com — search by org name, ASN, or CIDR

### Step 2 — ASN to IP Ranges (CIDR)

```bash
# asnmap — direct CIDR extraction
asnmap -a AS33905 -silent

whois -h whois.radb.net -- '-i origin AS33905' \
whois -h whois.radb.net -- '-i origin AS20461' \
echo "ASN33905" | metabigor net --asn
prips 2.18.48.0/21 > ips_asn.txt
## Phase 4 — WAF Bypass & Origin IP Discovery

> Cloudflare and similar WAFs protect 70%+ of bug bounty targets. Finding the origin IP exposes the raw server — no firewall, no rate limiting.

### Method 1 — Favicon Hash (Most Reliable)

Companies reuse the same favicon across all their infrastructure. The hash is a fingerprint you can search in Shodan.

```bash
# favUp — finds origin IP via favicon hash + Shodan
python3 favUp.py -ff favicon.ico --shodan-cli
python3 favUp.py --web target-behind-cloudflare.com -sc

# favirecon — lightweight favicon recon
favirecon -u https://target.com/ -v

# FavFreak — identifies unique favicon hashes across your subdomain list
1. Go to https://favicons.teamtailor-cdn.com/ → paste target URL → get the favicon
2. Go to https://favicon-hash.kmsec.uk/ → paste favicon URL → get the hash
3. Search Shodan: `http.favicon.hash:-382492124`
**If an IP returns your target's favicon but isn't a Cloudflare IP → that's your origin server.**
# originiphunter — queries multiple sources for historical IPs
echo "target.com" | originiphunter
cat domains.txt | originiphunter
```

**OSINT sources for historical IPs:**
- https://securitytrails.com — DNS history
- https://viewdns.info/reverseip/ — reverse IP lookup
- https://search.censys.io — search `parsed.names: target.com`
- https://www.shodan.io — search `ssl.cert.subject.cn:target.com`
- https://netlas.io — deep infrastructure search

curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*.js.map$"
  -H "X-Original-URL: /FUZZ" \
cdn.target.com [CNAME] storage.s3.amazonaws.com ← check bucket name
| DNS — Best | `sudo wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt` |
| https://securitytrails.com | DNS history, subdomain data |
| https://search.censys.io | Internet-wide host scanning |
| https://www.shodan.io | IoT and service discovery |
| https://bgp.he.net | ASN and BGP routing data |
| https://asnlookup.com | ASN search by org name |
| https://bgp.tools | Modern BGP/ASN explorer |
| https://www.favihash.com | Manual favicon hash generator |

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
