---
name: secatlas
description: "Use for Chinese pentest technique cards/cases."
version: 1.0.0
---

# SecAtlas 渗透知识库 (local mirror)

Local clone: `/root/SecAtlas` (shuaiqideyu/SecAtlas, depth-1).
Structured Chinese pentest knowledge base maintained by multiple AI agents.

## Content inventory

| Area | Path | Count |
|---|---|---|
| Technique cards (YAML) | `techniques/<cat>/` | 46 cards, 23 categories |
| Knowledge entries | `knowledge/categories/*.md` | 136 entries, 18 categories |
| Case studies | `cases/{ctf,authorized,lab,pwn}/` | 17 cases |
| Deep references | `references/<topic>/` | 62 docs, 12 topics |
| Tools | `tools/` | 18 (Python/Go/Shell) |
| Agent manifest | `agent-manifest.yaml` | multi-agent registry |
| Master index | `MASTER_INDEX.md`, `CAPABILITY.md` | full inventory |

## Technique card format (YAML)

`id / name / category / severity / description / trigger_signals / payloads / success_indicators / prerequisites`
Each card = trigger signal → payload matrix → observable success criteria. Read the matching card before testing a vuln class.

## Lookup order

1. **Find the right technique card**: `search_files(pattern, path=/root/SecAtlas/techniques)` — e.g. `sqli`, `jwt`, `ssrf`, `request-smuggling`, `cache-poisoning`, `payment-bypass`.
2. **Deep knowledge**: `read_file(/root/SecAtlas/knowledge/categories/<class>.md)` — sqli, xss, ssrf, ssti, idor, jwt, oauth, deserialization, pwn, xxe, command-injection, request-smuggling, agentic-ai, blockchain, acl.
3. **Frameworks**: `knowledge/frameworks/ruoyi-vulnerabilities-full.md` (40+ CVEs, RuoYi/Shiro chains).
4. **Case replay**: `cases/<type>/<case>.yaml` — full attack chain with failures + evidence.
5. **Deep topics**: `references/<topic>/` — sql-injection (9 docs), request-smuggling (desync), cloud-metadata, oauth-oidc, passkey-webauthn, dns-dnssec, tls-pki (0-RTT), sbom-supply-chain, agentic-ai, websocket-sse, payment-callback-discovery, pentest-tools-library.
6. **Tools**: `tools/` — jwt-analyzer.py, js-extractor.py, redis-exploit.py, cache-poison-detector.go, chain_scan.py.

## Categories (technique cards)

recon · sqli · xss · ssrf · ssti · jwt · cmd-injection · idor · request-smuggling · deserialization · api-bypass · auth · payment-bypass · blockchain · pwn · waf-bypass · cache-poisoning · cicd-poisoning · log-poisoning · network-poisoning · data-poisoning · code-audit · xxe

## Notes

- Case files use YAML; technique cards are YAML — parse with python yaml if needed.
- Multi-agent collaboration protocol in AGENTS.md; register agents via agent-manifest.yaml.
- Keep as router; load specific cards/docs on demand via read_file to conserve context.
