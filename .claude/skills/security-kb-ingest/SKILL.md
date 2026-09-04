---
name: security-kb-ingest
description: "Use when absorbing security repos into skills."
version: 1.0.0
---

# Security Knowledge-Base Ingestion & Archiving

How to absorb external security/red-team repos (GitHub or local dirs) into the Hermes skill
library, audit for conflicts, and (optionally) archive them to a git repo.

## Standard workflow (repeatable)

1. **Clone/verify** — `git clone --depth 1 <url>` to `/root/<repo>`, or accept local paths directly.
2. **Inventory** — one terminal pass: `du -sh`, top-level dirs, counts (`find . -name SKILL.md | wc -l`, `*.py` counts, total files). Read README + one representative content file to learn the format (SKILL.md frontmatter vs YAML cards vs markdown docs).
3. **Register a router skill** — create a Hermes skill entry (category `security`) that is a ROUTER ONLY: path pointers, content inventory table, lookup order, on-demand reading. Never copy the whole knowledge base into the skill body — context budget.
4. **Verify** — `skill_view` the new entry; spot-check that the repo paths exist and representative scripts parse/run.

## Pitfalls (learned the hard way)

- **updatePwd userId red herring**: RuoYi's `PUT /system/user/profile/updatePwd` accepts
  a `userId` param but IGNORES it — always validates/changes the CURRENT token user's password.
  Initial testing made it look like horizontal privesc (200 response), but the 200 meant
  YOUR password was changed. Always re-login to verify which account was affected.
  The endpoint IS useful for user-existence enumeration (no rate limiting, 5000+ IDs tested).
- **Captcha single-use**: RuoYi kaptcha UUIDs are one-shot — one wrong answer invalidates
  the UUID entirely (not just "expired"). Must OCR correctly on first try. Vision API has
  ~70% operator accuracy (`*` vs `/` confusion); answer range 0-81.
- **WAF cookie alongside JWT**: When TencentEdgeOne is in play, ALL requests need BOTH
  the WAF bypass cookie AND the JWT Bearer token, or API returns HTML instead of JSON.
  WAF cookie values rotate periodically — re-solve the JS challenge when responses go HTML.
- **Description length limit**: skill_manage refuses descriptions longer than 60 chars
  ("Description is N chars — new skills must fit the 60-char system-prompt budget").
  Keep it: trigger first, ≤60 chars, ends with period. Count characters mentally —
  shortening by 1-2 chars often still fails; trim the trigger wording.
- **Batch atomicity**: skill_manage operations apply atomically — one failing op rolls back
  ALL touched skills. Validate every op's constraints (esp. description length) before the batch.
- **Do NOT symlink knowledge bases into a git archive**: git stores symlinks as links, not
  content. Use `cp -rL <src> <dest>` (dereference) when building a publishable copy.
- **WeChat articles**: `web_extract` returns only title; use `curl -A <browser UA>` and strip
  tags with regex to get full body; browser tool needs Chrome running.
- **Do not delete user directories while archiving** — only ever read them; content changes are
  usually the user's own doing (verified via stat mtime, not assumed).

## Conflict auditing (run after multi-repo ingest)

Run `scripts/audit-skill-conflicts.py` — parses ONLY the first YAML frontmatter block of each
SKILL.md (a whole-file grep produces false positives from example snippets inside the body:
names like `Heritage`, `my-skill-name`, `security-reviewer`), detects cross-repo duplicate
skill names, and reports repo-by-repo counts. Overlapping names across repos are NOT
collisions as long as each is accessed by full absolute path — document which repo wins in
the router entry; 8 known cross-repo duplicate names exist among the absorbed repos.

## Archived repos (as of 2026-09)

| Repo | Local path | Notes |
|---|---|---|
| hack-skills (yaklang) | /root/hack-skills | 102 SKILL.md, router: `hack-skills` |
| SecAtlas (shuaiqideyu) | /root/SecAtlas | YAML technique cards, router: `secatlas` |
| reverse-skill (local) | /root/reverse-skill | routing engine; Hermes router: `reverse-skill` |
| CVE-2026-65343 iOS kernel batch | /root/security-suite/domains/mobile-security/ios-kernel-cve | ANALYSIS only; fused into mobile-security |
| 6000RMB skills.zip (2026-09-03) | fused into domains/*/playbook-6000+hunter-6000 | 145 new/83 dedup; FUSION-6000.md |
| AboutSecurity (wgpsec) | /root/AboutSecurity | 68MB, 1884 files, router: `about-security` |
| Claude-BugHunter | /root/Claude-BugHunter | 83 hunt skills, router: `claude-bughunter` |
| Stopen | /root/Stopen | OODA pentest agent, router: `stopen` |
| web-sec (ReAbout) | /root/web-sec | EXP/VUL/PEN 3-layer, router: `web-sec` |
| skill dir (local) | /www/wwwroot/skill | content churn expected; router: `skill-arsenal` |
| Black-cat (0rangec3t) | /root/Black-cat | Hypothesis-driven state-machine pentest framework; 7 technique dirs (web/recon/cloud/db/reversing/ad/evasion); router: `black-cat-redteam` |
| 0day-Rubbish (Exploit-Garbage) | /root/security-suite/domains/0day-exploits | 76 products, 90 RCE vulns, each with exploit/*.py + analysis.md + summary.md; router: `0day-exploit-library` |
| Redis CVE-2026-81934 PoC (berabuddies) | /root/security-suite/domains/0day-exploits/redis/CVE-2026-81934 | Redis TLS UAF→RCE, CVSS 9.8, exploits for 6.2/7.4/8.6/8.8; merged into 0day-exploit-library |
| RuoYi-Vue-Plus tenant_id SQLi (2026-09-02) | /root/security-suite/domains/0day-exploits/ruoyi-vue-plus/ | Pre-auth SQLi via POST /auth/register tenantId; Error-based extractvalue; merged into 0day-exploit-library |
| clown-src-6k-skill (SRC methods) | merged into 9 domains | 49 vuln test methods + 11 rules + FOFA MCP; fused into web-injection/web-attack/auth-security/file-vulns/recon/etc. src-methods/ subdirs |
| PHP-Code-Audit-Skill | domains/file-vulns/code-audit/php/ | Fine-grained PHP route-mapper/tracer + class audits; kept aggregated php-*-audit |
| java-audit-skills | domains/file-vulns/code-audit/java/audit-skills/ | Workspace convention + component YAML + evidence gate |
| code-audit (methodology) | domains/file-vulns/code-audit/methodology/ | 55+ types, dual-track, anti-hallucination |
| WinDump | domains/windows-post/windump-cred-collection/ | Client cred/host collection playbook (source+docs) |
| lpe-toolkit | domains/linux-post/lpe-toolkit/ | Multi-arch LPE orchestration; exploit binaries NOT vendored (INDEX only) |
| Payloader content | domains/recon/.../payloader/ | UI skipped; content-review-upstream + existing by-category |
| Pentest-WindFtsy | domains/redteam-framework/web-assess-pipeline/ | mitm URL dump + auth matrix + gate truth |
| recon-skills | domains/*/src-methods/ | Incremental hunt/recon skills; richer overlaps → references/upstream-* |
| BB Methodology 2026 | recon/src-methods + cdn-origin-tracing refs | Origin-IP/CDN excerpts only + full README ref |
| DroidHunter | domains/mobile-security/android-adb-assess/ | ADB/modules playbook; product shell not routed |
| ctf-skills | domains/ctf/ctf/ | Gaps + richer upstream refs for overlaps |
| claude-bug-bounty | selective src-methods | Diff vs Claude-BugHunter; only incremental skills |
| AutoCVE skill_library | domains/file-vulns/code-audit/autocve-skill-library/ | skill_library only; AGPL platform skipped |
| Anthropic-Cybersecurity-Skills | OT/ICS, phishing-IR, compliance, IAM, SIEM thin domains | Curated ≤60 skills; not full 800+ dump |
| cdn-origin-tracing handbook | hermes-skills/cdn-origin-tracing | CDN/WAF origin tracing skill + scripts |

## Integration vs stacking (critical user correction)

User explicitly rejected repo-stacking (`knowledge/<repo-name>/` per source) as "not integrated".
Correct approach: **domain-based reorganization** — flatten ALL repos into `domains/<attack-surface>/`
where each theme (recon, web-injection, api-security, ad-attack, etc.) aggregates content from
every source. Each domain gets a README.md index. A `MASTER.md` at root provides the 21-theme
navigation matrix.

Workflow: write a Python script that maps every source directory to a target theme, then
`shutil.copytree` (skip `.git/`) into `domains/<theme>/<original-dir-name>/`. Generate per-theme
README + MASTER.md via a second script. Delete the `knowledge/` stacking structure entirely.

## SRC Knowledge Fusion (clown-src-6k-skill pattern)

When absorbing SRC/bug-bounty methodology repos (e.g. clown-src-6k-skill, 49 vuln test methods + 11 rules):

1. **Map each file to existing domain** — don't create a new standalone domain:
   - injection-test/xss/xxe/ssrf/deserialization/el-injection/jndi → `web-injection/src-methods/`
   - http-smuggling/csrf/cors/waf-bypass/cache-poisoning/race-condition → `web-attack/src-methods/`
   - authbypass/idor/oauth-jwt/401-403-bypass → `auth-security/src-methods/`
   - file-upload/path-traversal/insecure-scm → `file-vulns/src-methods/`
   - recon-methodology/info-leak/subdomain-takeover/js-reverse → `recon/src-methods/`
   - Rules/workflows → `recon/src-rules/`
   - Tools (FOFA MCP, Playwright) → `recon/tools/`
   - logic-test → `business-logic/src-methods/`
   - llm-security/agent-tool-exec → `llm-ai-security/src-methods/`
   - cloud-ide-rce/dependency-confusion → `cloud-security/src-methods/`
   - api-gateway → `api-security/src-methods/`

2. **Subdirectory convention:** place merged files in `<domain>/src-methods/` to separate from original domain content
3. **Delete the staging directory** after all files are distributed — no leftover standalone domain
4. **User will reject stacking:** creating `domains/src-hunting/` as a standalone dump was explicitly rejected ("都融合了还是单独的啊"). Always merge by attack surface.

## Multi-AI Tool Config Distribution

When the repo needs to support multiple AI CLI tools (not just Hermes):

```
ai-config/
├── universal/          # Core configs (any AI tool)
│   ├── PERSONA.md      # Red team persona + rules + pentest flow
│   ├── MEMORY.md       # Attack surface priorities + platform signatures
│   └── RULES.md        # Execution rules + output style
├── hermes/             # ~/.hermes/memories/ (setup.sh extracts code blocks)
├── claude/             # CLAUDE.md (project root) — Claude Code auto-reads
├── codex/              # instructions.md → .github/copilot/
├── grok/               # system.txt → ~/.grok/
├── cursor/             # .cursorrules (project root)
└── aider/              # .aider.conf.yml (project root)
```

**Key patterns:**
- `universal/` holds the canonical content; tool-specific files are condensed derivatives
- Hermes uses `setup.sh` that extracts last ``` code block from USER.md/MEMORY.md
- Claude Code reads `CLAUDE.md` from project root automatically
- Cursor reads `.cursorrules` from project root automatically
- When updating vuln signatures (e.g. new RuoYi SQLi), update ALL tool configs in one commit
- AGENTS.md at repo root guides any AI to auto-install the right config for its tool type

## Branding & upstream stripping

User requires ALL upstream author names, repo references, and agent identifiers be removed:
- Git history rewrite: `git filter-branch --env-filter` to replace author/committer with user's identity
- File content: `sed -i` to replace mule/BlackMule/Hermes/upstream-repo-names with user's brand
- Script filenames: rename `mule-*.sh` → `tgsec-*.sh` (or user's chosen prefix)
- YAML fields: replace agent IDs inside case/technique YAML files
- Skills SKILL.md: strip `(yaklang/hack-skills, depth-1)` style parenthetical source attributions
- Final grep sweep: `grep -ri` for ALL known upstream identifiers, fix any remnants
- User's brand format: `@TGSEC社区 · @TGSEC-Qtzuu 整理` (bottom of README/AGENTS/MASTER)

## GitHub archive push

To archive the suite to the user's repo, see `references/github-token-push.md` — token
capability probing sequence, fine-grained-PAT limits, and the push recipe.

## Renaming repos on GitHub

Use GitHub API: `POST /user/repos` to create new name, push to it, then
`DELETE /repos/:owner/:old-name` to remove the old one. Avoid `PATCH` rename
if commit history needs rewriting (author change) — a fresh repo is cleaner.

## Multi-AI Tool Configuration Distribution

When building a security knowledge repo intended for AI consumption, create `ai-config/` with per-tool configs:

```
ai-config/
  universal/          — PERSONA.md + MEMORY.md + RULES.md (any AI tool)
  hermes/             — USER.md + MEMORY.md + setup.sh (writes to ~/.hermes/memories/)
  claude/             — CLAUDE.md (project-root, auto-read by Claude Code)
  codex/              — instructions.md (.github/copilot/ or env var)
  grok/               — system.txt (~/.grok/)
  cursor/             — .cursorrules (project-root)
  aider/              — .aider.conf.yml (project-root)
```

**Key lessons:**
- Hermes uses `~/.hermes/memories/USER.md` + `MEMORY.md` — extract code blocks from wrapper docs via `re.findall(r'\x60\x60\x60\n(.*?)\x60\x60\x60', content, re.DOTALL)`
- Claude Code reads `CLAUDE.md` from project root automatically
- Cursor reads `.cursorrules` from project root
- Codex: `instructions.md` in `.github/copilot/` or `COPILOT_INSTRUCTIONS` env var
- aider `.aider.conf.yml` must be valid YAML — don't put freeform prose in value fields
- `AGENTS.md` in repo root should detect which AI tool is running and route to correct config
- Always include `universal/PERSONA.md` as fallback for unsupported tools

## SRC Knowledge-Base Fusion Pattern

When absorbing a vulnerability methodology knowledge base (e.g. clown-src-6k-skill with 49 test methods):

1. **Never stack as a separate domain** — user rejects堆叠("你没有帮我整合起来好吗")
2. **Map each file to an existing attack-surface domain** using a Python dict:
   - injection tests → `web-injection/src-methods/`
   - auth bypass → `auth-security/src-methods/`
   - HTTP smuggling/CSRF/cache → `web-attack/src-methods/`
   - file upload/traversal → `file-vulns/src-methods/`
   - recon/OSINT → `recon/src-methods/`
   - rules/workflow docs → `recon/src-rules/`
3. **Use `src-methods/` subdirectory** in each domain to keep SRC methodology separate from existing content
4. **Delete the temporary standalone domain** after fusion
5. **Tools (FOFA MCP, scripts)** go to `recon/tools/`

## Playbook references

- `references/ruoyi-pentest-playbook.md` — RuoYi-Vue pentest chain (JS extraction → API map → captcha OCR → register → JWT → updatePwd IDOR → user enumeration)
- `references/teo-waf-bypass.md` — TencentEdgeOne WAF JS Challenge static solver (array rotation + integer sum → cookie)
- `references/wordpress-pentest-playbook.md` — WordPress pentest chain (xmlrpc multicall bruteforce, wp-json IP+Host bypass, plugin CVEs, vhost discovery, SPA backend pivot)
- `references/github-token-push.md` — GitHub token capability probing + push recipe
- `references/deep-audit-workflow.md` — persistent audit workflow (when to continue vs when to stop)
