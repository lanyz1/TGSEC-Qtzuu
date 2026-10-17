#  CerberusX 🍓

## 🌟 Introduction
** CerberusX** is an ethical XSS scanner designed for security professionals to detect vulnerabilities in web applications.

> ⚠️ **Use only against targets you own or have explicit written authorization to test.** Active scanning (crawling, payload injection, subdomain enumeration) against systems outside your authorized scope may be illegal.

## Features ✨
- ✅ Multi-Type XSS Detection (Reflected, Stored, DOM-Based)
- 🕷️ Auto-Crawling for URL discovery (respects `robots.txt`)
- 🌐 Subdomain discovery (crt.sh + Wayback Machine, with DNS resolution check)
- 🔄 116+ payloads with WAF bypass, polyglot, and template-injection techniques
- 🎯 Confidence scoring (High/Medium/Low) to cut down false positives
- 📊 JSON logging with automatic rotation and SHA-256 integrity hash
- ⚡ Concurrent, multi-threaded scanning

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com//CerberusX.git
cd CerberusX

# install dependencies
pip install -r requirements.txt

# run the scanner
python cerberusX.py -t https://example.com
```

## Usage

### 1. Basic scan
```bash
python cerberusX.py -t https://example.com
```

### 2. Advanced scan with all features
```bash
python cerberusX.py -t https://example.com \
    --advanced \
    --strict-ssl \
    --proxy http://localhost:8080 \
    --delay 0.5 \
    --max-pages 100 \
    --threads 20
```

### 3. Limit crawl depth
```bash
# Crawl up to 100 pages instead of the default 50
python cerberusX.py -t https://example.com --max-pages 100

# Scan only the target URL itself, skip discovering other pages
python cerberusX.py -t https://example.com --max-pages 1
```

### 4. Custom payloads and output file
```bash
python cerberusX.py -t https://example.com \
    --payloads my_payloads.txt \
    --output results/example_scan.json
```

### 5. Individual flags
```bash
# Route traffic through a proxy (e.g. Burp Suite)
python cerberusX.py -t https://example.com --proxy http://proxy.example.com:8080

# Also test POST/PUT/DELETE on discovered forms
python cerberusX.py -t https://example.com --advanced

# Delay between requests, in seconds (default: 0.2)
python cerberusX.py -t https://example.com --delay 0.5

# Reduce console noise during crawling/subdomain checks
python cerberusX.py -t https://example.com --quiet
```

## Command-Line Options

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | *(required)* | Target URL or domain |
| `--delay` | `0.2` | Delay between requests, in seconds |
| `--strict-ssl` | off | Enable strict SSL certificate verification |
| `--advanced` | off | Also test POST/PUT/DELETE on discovered forms |
| `--proxy` | none | Proxy server, e.g. `http://proxy.example.com:8080` |
| `--max-pages` | `50` | Maximum pages to crawl |
| `--threads` | `15` | Concurrent scan workers |
| `--output` | `xss_scan_results.json` | Custom path for the JSON results log |
| `--payloads` | `xss_payloads.txt` | Path to a custom payload file |
| `--quiet` | off | Suppress verbose crawl/subdomain output |

## Sample Output

```
  CerberusX ASCII banner...

[Scan] Scanning https://example.com...

🕷️ Crawling website to discover all paths...
[Crawling] Found: https://example.com/login
[Crawling] Found: https://example.com/search
[Crawling] Found: https://example.com/contact

🌐 Discovering and checking subdomains...
✅ 2/4 subdomains resolved

✅ Found 14 URLs to scan (Main + Subdomains + Crawled paths)

🔥 Vulnerable URLs found:
1. [Reflected|High] GET https://example.com/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E
2. [DOM-Based] GET https://example.com/dashboard#javascript:alert(1)
3. [Stored (Potential)|High] POST https://example.com/comments

⏱️ Scan finished in 42.1s — 14 URLs tested, 3 findings.

Enter number to test in browser (0 to exit):
```

Full results (timestamp, type, and the exact payload/URL for every finding) are written to `xss_scan_results.json` as they're discovered, with a `xss_scan_results.sha256` hash file alongside it for integrity verification.

## Payloads
Payloads are loaded from `xss_payloads.txt` in the working directory (or the file passed to `--payloads`), one payload per line. Lines starting with a section header (`# === Name ===`) are skipped; everything else, including lines that start with `#` for other reasons (e.g. the `#{alert(1)}` template-injection payload), is loaded. If no payload file is found, the tool falls back to a small built-in default list.

## License
MIT — see [LICENSE](LICENSE).
