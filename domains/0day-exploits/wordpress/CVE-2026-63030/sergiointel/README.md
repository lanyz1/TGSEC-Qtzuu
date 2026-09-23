# wp2shell PoC

The first ever poc of the pre-auth timing-based SQL injection PoC for the WordPress REST API batch-route confusion chain ([CVE-2026-63030](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ff9f-jf42-662q) + [CVE-2026-60137](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf))

Achieved command execution, without just trying to crack the admins password.

**Affected:** WordPress 6.9.0–6.9.4 and 7.0.0–7.0.1. Fixed in 6.9.5 and 7.0.2.

```bash
python3 poc.py https://target.example
python3 poc.py https://target.example 'SELECT DATABASE()'
python3 poc.py https://target.example -c "echo "you got pwned" > /tmp/pwned.txt && id"
```

**Research:** [Searchlight Cyber](https://slcyber.io/research-center/wp2shell-pre-authentication-rce-in-wordpress-core) · [Aikido](https://www.aikido.dev/blog/unauthenticated-rce-in-wordpress-wp2shell) · [Aikido Intel](https://intel.aikido.dev/cve/AIKIDO-2026-696183) · [WordPress](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)

> **Disclaimer:** This proof of concept is provided solely for authorized educational, security research, and incident response purposes; meaning, use it only on systems you own or have explicit permission to test.
