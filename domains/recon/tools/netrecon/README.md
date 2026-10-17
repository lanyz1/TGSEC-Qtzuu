#  NetRecon v3.1 🍓
## NetRecon - Professional Network Reconnaissance Tool

## 🌟 Introduction
** NetRecon** A powerful yet ethical WHOIS and network reconnaissance tool for security professionals.

## Features ✨
- Comprehensive WHOIS lookups for domains and IPs
- DNS record retrieval (A, MX, TXT, SOA, etc.)
- Reverse IP lookups to find associated domains
- Common port scanning (21, 22, 80, 443, etc.)
- Beautiful console output with rich formatting
- Rate limiting to prevent abuse
- Proxy support for anonymity
- JSON/CSV output support

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

```bash
git clone https://github.com//NetRecon.git
cd NetRecon-tools

# install dependencies
pip install -r requirements.txt

# run the scanner
python netrecon.py

# Usage
1.Basic domain lookup
```bash
python netrecon.py -d example.com

2.IP address lookup
```bash
python netrecon.py -d 8.8.8.8

3.With DNS records
```bash
python netrecon.py -d example.com --dns A MX TXT

4.Save to JSON
```bash
python netrecon.py -d example.com -o result.json

5.Save to CVS
```bash
python netrecon.py -d example.com -o result.cvs

6.Show ethical guidelines
```bash
python netrecon.py --ethics


## Options
-h & --help --> Show help message
-d & --domain --> Target domain or IP
-o & --output --> Save results to file (JSON/CSV)
--raw --> Show raw response
--proxy --> Use proxy (http://user:pass@host:port)
--dns --> Get DNS records (A, MX, TXT, etc.)
--ethics --> Show ethical guidelines
--no-log --> Disable logging

# Sample Output
## Domain Lookup
      🍓Professional NetRecon Tool - Secure & Ethical🍓
╭──────────────────────── WHOIS Results ────────────────────────╮
│ Field           Value                                         │
│ Domain Name     example.com                                   │
│ Registrar       NameCheap, Inc.                               │
│ Creation Date   1995-08-14T04:00:00Z                          │
│ Update          2022-07-31T07:34:38Z                          │
│ Expiry Date     2023-08-13T04:00:00Z                          │
│ Organization    Example Inc.                                  │
│ City            Los Angeles                                   │
│ Country         US                                            │
│ Email           admin@example.com                             │
│ Phone           +1.5551234567                                 │
│ Name Servers    ns1.example.com                               │
│                 ns2.example.com                               │
│ Status          clientTransferProhibited                      │
╰───────────────────────────────────────────────────────────────╯

╭──────────────────────── DNS Records ──────────────────────────╮
│ Record Type   Value                                           │
│ A            93.184.216.34                                    │
│ MX           10 mail.example.com                              │
│ TXT          "v=spf1 include:_spf.example.com ~all"           │
│ TXT          "google-site-verification=ABC123"                │
╰───────────────────────────────────────────────────────────────╯

## IP Lookup
╭────────────────── IP Information for 8.8.8.8 ──────────────────╮
│ Field               Value                                      │
│ IP Address         8.8.8.8                                     │
│ PTR Record         dns.google                                  │
│ Network Name       GOOGLE                                      │
│ Organization       Google LLC                                  │
│ Country            US                                          │
│ Description        Google Public DNS                           │
│ AS Number          AS15169                                     │
│ Last Updated       2023-05-01T00:00:00Z                        │
│ Domain Count       150                                         │
│ Sample Domains     google.com                                  │
│                    mail.google.com                             │
│                    docs.google.com                             │
│                    drive.google.com                            │
│                    calendar.google.com                         │
│ Open Ports         53, 80, 443                                 │
╰────────────────────────────────────────────────────────────────╯

## JSON Format
{
  "Domain Name": "example.com",
  "Registrar": "NameCheap, Inc.",
  "Creation Date": "1995-08-14T04:00:00Z",
  "Update": "2022-07-31T07:34:38Z",
  "Expiry Date": "2023-08-13T04:00:00Z",
  "Organization": "Example Inc.",
  "City": "Los Angeles",
  "Country": "US",
  "Email": "admin@example.com",
  "Phone": "+1.5551234567",
  "Name Servers": [
    "ns1.example.com",
    "ns2.example.com"
  ],
  "Status": "clientTransferProhibited",
  "DNS Records": {
    "A": ["93.184.216.34"],
    "MX": ["10 mail.example.com"],
    "TXT": [
      "\"v=spf1 include:_spf.example.com ~all\"",
      "\"google-site-verification=ABC123\""
    ]
  }
}

## Ethics
[ Ethical Guidelines ]
1. Use this tool ONLY for authorized security assessments.
2. Never scan domains/IPs without explicit permission.
3. Respect data privacy laws (GDPR, HIPAA).
4. Do not use for malicious purposes.
5. Limit query rates to avoid overloading servers.
6. Always comply with local and international laws.