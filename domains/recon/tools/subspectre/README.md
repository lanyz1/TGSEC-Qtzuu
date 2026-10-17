#  SubSpectre 🍓

## Introduction 🌟
**SubSpectre** is a professional-grade subdomain discovery and status code analysis tool designed for penetration testers, security researchers, and bug bounty hunters. It provides complete infrastructure visibility through DNS brute-forcing and comprehensive HTTP analysis. 

## Features ✨
- 🔍 **DNS Brute-Force Discovery** - Find active subdomains via DNS resolution
- 📊 **HTTP/HTTPS Status Analysis** - Check both protocols with detailed responses
- 🚀 **High-Performance Multi-threading** - Scan hundreds of subdomains quickly
- 🎨 **Beautiful Console Interface** - Rich tables, progress bars, and color-coded output
- 📈 **Comprehensive Reporting** - Statistics, percentages, and categorized results
- ⚡ **JSON Export** - Save complete results for automation and analysis
- 🕷️ **Pentester's Status Code Guide** - Built-in reference for security testing
- 🔒 **Professional Tooling** - Designed for ethical security assessments

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com//SubSpectre.git
cd SubSpectre-tools  

# install dependencies
pip install -r requirements.txt

# run the scanner
python subspectre.py

# Usage Example:
1.Basic Domain Scan
```bash
python subspectre.py -d example.com

2.Advanced Scan with Custom Wordlist
```bash
python subspectre.py -d target.com -w subdomains.txt -t 30 --timeout 10

3.Save Results to Custom File
```bash
python subspectre.py -d example.com -o scan_results.json

4.Full Options Scan
```bash
python subspectre.py -d target.com -w wordlist.txt -t 50 --timeout 15 -o results.json
```

## Command Line Options 📋
Option Description Default
-d, --domain Target domain (required) -
-w, --wordlist Custom subdomain wordlist Built-in (100+ common)
-t, --threads Concurrent threads 20
--timeout Request timeout (seconds) 5
-o, --output Output JSON file domain_scan_results.json

## Use Cases 🎯
· Penetration Testing: Infrastructure reconnaissance
· Bug Bounty Hunting: Surface area discovery
· Security Audits: Asset inventory and verification
· Red Team Operations: Target mapping and enumeration
· Blue Team Defense: Monitoring own infrastructure

## ETHICAL & LEGAL WARNING ⚠️
THIS TOOL IS FOR:
- Authorized penetration testing
- Security research with permission  
- Educational purposes
- Testing YOUR OWN systems

STRICTLY PROHIBITED:
- Unauthorized access to systems
- Illegal hacking activities
- Violating terms of service

By using this tool, you agree to use it only legally and ethically.
The author is NOT responsible for any misuse or damage.

## Contributing 🤝
Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request