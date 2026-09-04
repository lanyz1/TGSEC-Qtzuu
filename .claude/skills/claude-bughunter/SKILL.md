---
name: claude-bughunter
description: "Use for bug bounty and disclosed-report hunts."
version: 1.0.0
---

> **路径说明（全 AI）：** 知识正文在包根 `domains/`；配合 `ROUTING.md` / `MASTER.md` / `START.md`。Windows 请优先用 `domains/`，勿依赖 Linux 专用绝对路径。


# Claude-BugHunter (local) — /root/Claude-BugHunter

Claude skill bundle for bug hunting & red-team (elementalsouls/Claude-BugHunter). 83 skills, 15 slash commands, 681 disclosed-report patterns.

## Content

| Area | Path | Description |
|---|---|---|
| **Skills** (83) | `skills/` | apk-redteam, bb-methodology, bug-bounty, cloud-iam, enterprise-vpn, evidence-hygiene, hunt-* (api-misconfig, aspnet, ato, auth-bypass, brute-force, biz-logic, cache-poison, captcha, cicd, clickjacking, cloud, cors, csrf, deserialization, dom, file-upload, fintech-graphql, forgot-password, graphql, grpc, iac, idor, jwt, lfi, llm, mobile-api, oauth, payment, race-condition, rate-limit, s3, ssti, ssti-custom, ssrf, sqli, waf, xss, xxe, zip-slip...) |
| **Slash Commands** (15) | `commands/` | autopilot, chain, hunt, intel, memory-gc, pickup, recon, remember, report, scope, surface, token-scan, triage, validate, web3-audit |
| **Disclosed Reports** (681) | `docs/disclosed-reports/` | 433 individually cited & auditable patterns across 24+ vuln classes |
| **CLI** | `cbh/` | cbh CLI tool, data |
| **Verification** | `docs/verification/` | hardened-lab, phase2-* labs, playwright |
| **Research** | `research/reports/` | Research reports |
| **Automation** | `docs/automation/` | Automation docs |
| **Superpowers** | `docs/superpowers/` | Plans & specs |

## Usage

```
# Load a hunt skill
read_file(/root/Claude-BugHunter/skills/hunt-<vuln-class>/SKILL.md)

# Load command docs
read_file(/root/Claude-BugHunter/commands/<cmd>.md)

# Search disclosed reports
search_files(pattern, path=/root/Claude-BugHunter/docs/disclosed-reports)
```

## Notes

- 83 skills covering full bug-bounty attack surface
- 15 slash commands for engagement workflow
- 681 disclosed-report patterns for reference
- Burp MCP integration
- Battle-tested on DVWA, Juice Shop, Hacker101, vulnweb
