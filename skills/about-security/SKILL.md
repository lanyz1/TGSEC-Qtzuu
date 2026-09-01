---
name: about-security
description: "Use when needing structured pentest skills or payloads."
version: 1.0.0
---

# AboutSecurity (local) — /root/AboutSecurity

Largest structured pentest knowledge base . 68MB, 1884 files.

## Content

| Area | Path | Description |
|---|---|---|
| **Skills** (200+) | `skills/` | ai-security, cloud, code-audit(PHP/Java), ctf, dfir, evasion, exploit(auth/binary/web-method/network-service), lateral(AD/NTLM), malware, mobile(Android/iOS), postexploit, recon, hardware, threat-intel, tool |
| **Dictionaries** | `Dic/` | auth(passwords/usernames/default-device), network(subdomain), port(21-5432, 28 services), regular(patterns), web(CMS/api-param) |
| **Payloads** | `Payload/` | xss, sqli, ssrf, rce, ssti, upload, xxe, cors, reverse-shell, lfi, hpp, access-bypass, prompt-injection, email, format |
| **Vulnerability DB** | `Vuln/` | ai, cloud, middleware, network, web |
| **Docs** | `Doc/` | Cheatsheet, Checklist, Skill-Benchmark-Guide, 报告模板, 行业名词, 默认密码 |
| **Scripts** | `scripts/` | generate-index, bench-skill, sync-claude-skills, grade-eval |

## Usage

```
# Find skill
search_files(pattern, path=/root/AboutSecurity/skills)

# Load dictionaries
read_file(/root/AboutSecurity/Dic/auth/password/xxx.txt)

# Load payloads
read_file(/root/AboutSecurity/Payload/xss/xxx.txt)
```

## Notes

- 200+ skill methodologies in AI Agent-executable format
- Structured into 17 skill categories covering full pentest chain
- Dictionaries organized by service/port for brute-force
- Payloads organized by vulnerability type
- claude-compatible skills in .claude/skills/
