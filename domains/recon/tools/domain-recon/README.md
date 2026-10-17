#  Domain Recon 🍓

## 🌟 Introduction
** Domain Recon** is a WHOIS and DNS reconnaissance tool for domain analysis, subdomain enumeration, and network intelligence.

> ⚠️ **Legal & Ethical Notice:** This tool is for authorized security testing and educational purposes only. Unauthorized use against domains without permission may be illegal.

## Features ✨
- WHOIS lookups with automatic referral-following (works beyond just `.com`/`.net`/`.org`/`.ir`)
- Subdomain discovery via Certificate Transparency logs (crt.sh) + common-subdomain brute-forcing
- DNS record lookup (A, AAAA, CNAME, MX, TXT)
- Domain expiry warning (flags domains expiring within 30 days)
- Proxy support (SOCKS5/SOCKS4/HTTP) for both the WHOIS query and the crt.sh lookup
- JSON and CSV export
- Rate-limited (3 queries/minute) to stay polite to WHOIS servers

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com//Domain-Recon.git
cd Domain-Recon

# install dependencies
pip install -r requirements.txt

# run the tool
python domain_recon.py -d example.com
```

## Usage

### 1. Basic lookup
```bash
python domain_recon.py -d example.com
```

### 2. Save result to JSON
```bash
python domain_recon.py -d example.com -o results.json
```

### 3. Raw WHOIS JSON output
```bash
python domain_recon.py -d example.com --raw
```

### 4. Route through a proxy (e.g. Tor)
```bash
python domain_recon.py -d example.com --proxies socks5://127.0.0.1:9050
```

### 5. Export to CSV
```bash
python domain_recon.py -d example.com --csv report.csv
```

### 6. Strict SSL verification for the crt.sh lookup
```bash
python domain_recon.py -d example.com --strict-ssl
```

### 7. Full scan with all options
```bash
python domain_recon.py -d example.com \
    -o results.json \
    --csv report.csv \
    --proxies socks5://127.0.0.1:9050 \
    --strict-ssl
```

## Command-Line Options

| Flag | Default | Description |
|---|---|---|
| `-d`, `--domain` | *(required)* | Target domain |
| `-o`, `--output` | none | Save result to a JSON file |
| `--csv` | none | Export result to a CSV file |
| `--raw` | off | Print the raw parsed WHOIS JSON instead of a table |
| `--proxies` | none | Proxy URL, e.g. `socks5://127.0.0.1:9050` or `http://proxy:port` — applies to the WHOIS query *and* the crt.sh subdomain lookup |
| `--strict-ssl` | off | Enable strict SSL certificate verification for the crt.sh lookup |

## Sample Output

```
[Table]
 Field            Value
 ────────────────────────────────────────────
 Domain Name      EXAMPLE.COM
 Registrar        RESERVED-Internet Assigned Numbers Authority
 Creation Date    1995-08-14T04:00:00Z
 Expiry Date      2026-08-13T04:00:00Z
 Name Servers     a.iana-servers.net
                  b.iana-servers.net
 Subdomains       www.example.com
 IP/DNS Records   93.184.216.34
 TXT Records      No TXT records found

[+] Results saved to results.json
```

Note: field availability depends on what the registrar's WHOIS server returns — not every TLD exposes the same fields.

## License
MIT — see [LICENSE](LICENSE).
