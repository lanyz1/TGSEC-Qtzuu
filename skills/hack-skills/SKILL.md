---
name: hack-skills
description: "Use when performing web/API/binary/AD security or CTF."
version: 1.0.0
---

# HACK.SKILLS Arsenal (local mirror)

Local clone: `/root/hack-skills` (yaklang/hack-skills, depth-1).
101 deep-topic skills + 6 category entries + 1 master entry across 14 domains.

## Loading order (per upstream design)

1. **Master entry** — `read_file(/root/hack-skills/skills/hack/SKILL.md)` first: phase determination (Recon/Validation/PrivEsc/Chain), behavior-signal routing table, testing order.
2. **Category entry** — then read the matching category router:
   - `recon-for-sec` — recon/methodology, new target
   - `api-sec` — REST/GraphQL/mobile backend
   - `auth-sec` — auth/session/OAuth/JWT/authorization
   - `injection-checking` — XSS/SQLi/SSRF/XXE/SSTI/CMDi/NoSQL routing
   - `file-access-vuln` — upload/download/LFI/path control
3. **Deep topic skill** — `read_file(/root/hack-skills/skills/<semantic-id>/SKILL.md)` on demand.

## Skill index / lookup

- `site/data/skills.json` — full machine-readable index (name, category, description, tier, blobUrl).
- `site/data/categories.yaml` — category → skill membership (single source of truth).
- Use `search_files(pattern, path=/root/hack-skills/skills)` to find the right semantic-id before reading.

## Categories (id → focus)

recon · api · auth · advweb (advanced web) · inj (injection) · file (file access) · windows (AD/privesc/evasion) · linux · macos · mobile · pwn · crypto · blockchain · ai

## Notes

- Each SKILL.md has frontmatter name/description; description begins with "Use when..." — match against it for routing.
- Deep skills are playbooks: principle, detection steps, payload matrices, WAF bypass, error triage, full chain, wrap-up.
- Keep this as a router only; load deep SKILL.md files on demand via read_file to conserve context.
