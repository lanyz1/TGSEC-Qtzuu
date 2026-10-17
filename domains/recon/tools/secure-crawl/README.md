#  Secure Crawl v3.1 🍓

## 🌟 Introduction
** Secure Crawl** Advanced Web Security Scanner and Crawler.

## Key Features ✨
- Intelligent website crawling with adjustable depth
- Automatic URL parameter detection
- Cookie, token, and security header extraction
- Professional JSON reporting with colorful terminal output
- Security header analysis (CSP, HSTS, X-Frame-Options)

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com//Secure_Crawl.git
cd Secure_Crawl-tools

# install dependencies
pip install -r requirements.txt

#Usage
python secure_crawl.py

#JSON Report Structure:
{
  "scan_info": {
    "target": "https://example.com",
    "total_urls": 42,
    "security_headers": {
      "CSP": "🟢",
      "HSTS": "🔴"
    }
  },
  "details": {
    "tokens": {
      "api_key=ABC123": "https://example.com/login"
    }
  }
}

# Sample Output
Enter target URL: example.com

Scanning: https://example.com
[»] Crawling: https://example.com

=== SCAN RESULTS ===
Total URLs found: 42
URLs with parameters: 7 
Important cookies: 3
Security tokens detected: 2
HTTP headers collected: 12
Errors encountered: 1

=== KEY FINDINGS ===
1. Login page: https://example.com/login
2. Search with params: https://example.com/search?q=test
3. Admin cookie: sessionid=ABC123...
4. JWT token: eyJhbGciOiJIUzI1NiIsInR5...

Scan completed. Full results saved to scan_results_example.com_20240515.json