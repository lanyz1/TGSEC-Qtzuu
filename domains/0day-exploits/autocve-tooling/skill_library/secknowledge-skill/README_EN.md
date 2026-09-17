# SecKnowledge - Web & AI Security Testing Skill

📖 [中文](README.md)

> A security testing expert skill for Claude Code / Cursor that distills 88,636 real-world vulnerability cases, 5,600+ security research papers, and 150 AI security risks into an instantly accessible penetration testing knowledge base.

---

## Why This Skill?

When using Claude Code or Cursor for security testing, generic AI knowledge often falls short in depth and coverage. This Skill transforms your AI into a **seasoned security testing expert**:

- Given a target, it systematically enumerates attack surfaces and test cases
- When blocked by a WAF, it draws from 88,636 real bypass cases to suggest countermeasures
- For AI application testing, it covers 150 GAARM risks + OWASP LLM/Agent Top 10
- When you need payloads, it provides battle-tested cheat sheets

## Knowledge Sources

| Source | Scale | Content |
|--------|-------|---------|
| **WooYun Vulnerability DB** | 88,636 real vulnerabilities | SQL injection, XSS, command execution, file upload, logic flaws — real-world cases & bypass techniques |
| **Xianzhi Security Community** | 5,600+ security papers | L1-L4 Security Research Thinking Pyramid methodology |
| **GAARM Risk Matrix** | 150 AI security risks | From NSFOCUS AISS community, covering 6 security domains × 3 lifecycle stages |
| **OWASP Frameworks** | LLM Top 10 / Agentic AI Top 10 / WSTG | Latest 2025-2026 compliance mapping |

## Coverage

### Web Security (Traditional + Modern)

```
Injection Attacks    SQL Injection / XSS / Command Execution / XXE / Deserialization
Logic Flaws          Authorization Bypass / Payment Tampering / Password Reset / Race Conditions
File Security        File Upload / Path Traversal / SSRF / Information Disclosure
Modern Protocols     CORS / GraphQL / HTTP Smuggling / WebSocket / OAuth
Deployment           Supply Chain / Cloud Services / TLS / Containers / CI/CD
Framework Security   Fingerprinting → CVE Matching → PoC Verification (generic methodology)
```

### AI Security (6 Domains × 150 Risks)

```
AI App Security(34)       Prompt Injection / CoT Attacks / MCP Poisoning / Agent Exploitation
AI Model Security(42)     Jailbreak / Hallucination Abuse / Adversarial Samples / Model Theft
AI Data Security(32)      Prompt Leakage / Data Exfiltration / Inference Attacks / RAG Poisoning
AI Identity Security(23)  Role Escape / Permission Failures / Agent Impersonation / Session Hijacking
AI Infra Security(19)     Sandbox Escape / Container Escape / Supply Chain / DoS
Frontier Risks            MCP Tool Poisoning / Agent Worms / Skills Injection / Claude Code CVEs
```

### Core Methodologies

```
Xianzhi L1-L4          Attack Surface ID → Hypothesis Verification → Deep Exploitation → Defense Reversal
WooYun Essence         Vuln = Expected Behavior - Actual Behavior = Developer Assumptions ⊕ Attacker Input
GAARM Matrix           6 Security Domains × 3 Lifecycle Stages = Systematic AI Risk Coverage
OWASP Mapping          LLM01-10 / ASI01-10 / WSTG-* Compliance IDs
```

## File Structure

```
SKILL.md                              # Entry: quick-ref cards + decision tree + navigation
references/
├── [Web - by vulnerability type]
│   ├── web-sqli.md                   # SQL Injection + SQLMap cheat (~245 lines)
│   ├── web-xss.md                    # XSS (~187 lines)
│   ├── web-rce.md                    # Command Execution (~232 lines)
│   ├── web-xxe.md                    # XXE External Entity (~106 lines)
│   ├── web-deser.md                  # Deserialization (~151 lines)
│   ├── web-upload.md                 # File Upload + Webshell bypass (~174 lines)
│   ├── web-traversal.md              # Path Traversal / File Inclusion (~145 lines)
│   ├── web-leak.md                   # Information Disclosure (~136 lines)
│   └── web-ssrf-misc.md              # SSRF + Misconfig + CMS/URL appendix (~191 lines)
├── [Web - logic & modern protocols]
│   ├── web-logic-auth.md             # AuthZ/Payment/Password Reset/Logic (582 lines)
│   ├── web-modern-protocols.md       # CORS/GraphQL/HTTP Smuggling/WS/OAuth (348 lines)
│   └── web-deployment-security.md    # Supply Chain/Cloud/Framework CVE (449 lines)
├── [AI App Security - App phase by risk class + Deploy/Training + Frontier]
│   ├── ai-app-prompt.md              # App subset: Prompt injection + variants (~535 lines)
│   ├── ai-app-mcp.md                 # App subset: MCP protocol attacks (~261 lines)
│   ├── ai-app-agent-cot.md           # App subset: Agent & CoT attacks (~536 lines)
│   ├── ai-app-deploy.md              # Deploy phase: API/Source (~154 lines)
│   ├── ai-app-train.md               # Training phase: 3rd-party/Plugins (~427 lines)
│   └── ai-app-frontier.md            # Frontier: Agent/MCP/Skills 2025-2026 (~121 lines)
├── [AI Model Security - App phase by risk category + Deploy/Training]
│   ├── ai-model-jailbreak.md         # App subset: Jailbreak GAARM.0027.x (~404 lines)
│   ├── ai-model-hallucination.md     # App subset: Hallucination GAARM.0028/0064 (~252 lines)
│   ├── ai-model-content.md           # App subset: Non-compliant content GAARM.0029.x (~550 lines)
│   ├── ai-model-copyright.md         # App subset: Copyright/Commercial GAARM.0030.x (~154 lines)
│   ├── ai-model-misuse.md            # App subset: Misuse/Fakery GAARM.0031.x/0033/0062/0063 (~543 lines)
│   ├── ai-model-extraction.md        # App subset: Adversarial/Extraction GAARM.0032.x (~363 lines)
│   ├── ai-model-deploy.md            # Deploy: File theft/Param tamper (~136 lines)
│   └── ai-model-train.md             # Training: Backdoor/Alignment/Poison (~292 lines)
├── [AI Data Security - GAARM 3-phase]
│   ├── ai-data-app.md                # App: Prompt leak/Inference (~903 lines)
│   ├── ai-data-deploy.md             # Deploy: Backup/Transit/Storage (~230 lines)
│   └── ai-data-train.md              # Training: Data protection/Poison (~590 lines)
├── [AI Identity Security - GAARM 3-phase]
│   ├── ai-identity-app.md            # App: Role escape/Agent spoofing (~906 lines)
│   ├── ai-identity-deploy.md         # Deploy: Unauthorized access (~226 lines)
│   └── ai-identity-train.md          # Training: Permission design (~148 lines)
├── [AI Infra Security - GAARM 3-phase + escape]
│   ├── ai-baseline-app.md            # App: Container escape/DoS (~278 lines)
│   ├── ai-baseline-deploy.md         # Deploy: Container/Cloud/Supply (~551 lines)
│   ├── ai-baseline-train.md          # Training: Dev tools/Env isolation (~202 lines)
│   └── ai-baseline-escape.md         # Container & sandbox escape methodology (~159 lines)
├── [Core index & methodology]
│   ├── gaarm-risk-matrix.md          # 150 AI Risk Index Table (158 lines)
│   └── testing-methodology.md        # Unified Testing Methodology (589 lines)
```

> **Split principles**:
> - AI files first split by GAARM 3-phase (App/Deploy/Training)
> - AI App/Model app-phase further split by risk class (Prompt/MCP/Agent-CoT, Jailbreak/Hallucination/Content/Copyright/Misuse/Extraction)
> - Web injection/file split by vuln subtype (SQLi/XSS/RCE/XXE/Deser/Upload/Traversal/Leak/SSRF)
> - Payloads inlined per topic file, no standalone payload file
> - All 38 reference files ≤ 1000 lines (single-Read friendly)

**Total**: 38 reference files + 1 SKILL.md = 39 files | Max file 906 lines | 100% single-Read friendly

## Installation

### Claude Code

Clone this repo to Claude Code's skills directory:

```bash
git clone https://github.com/Pa55w0rd/secknowledge-skill.git ~/.claude/skills/secknowledge
```

### Cursor

Clone this repo to Cursor's skills directory:

```bash
git clone https://github.com/Pa55w0rd/secknowledge-skill.git ~/.cursor/skills/secknowledge
```

Once cloned, the AI will automatically load this Skill when you engage in security-related tasks.

## Usage Examples

### Scenario 1: Web Penetration Testing

```
User: Test target.com for SQL injection
AI:   [Auto-loads SKILL.md → web-sqli.md]
      → Lists high-risk injection points, DB fingerprinting, WAF bypass techniques, full exploitation chain
```

### Scenario 2: AI Application Security Assessment

```
User: Test this chatbot's prompt injection defenses
AI:   [Auto-loads SKILL.md → ai-app-prompt.md / ai-app-mcp.md (by risk type)]
      → Systematic testing: direct injection / indirect injection / MCP poisoning / Agent exploitation
```

### Scenario 3: Hybrid Application Attack Chains

```
User: This AI app has file upload and RAG features, how to test?
AI:   [Loads cross-layer attack chains]
      → Web layer (file upload bypass) → AI layer (RAG poisoning / indirect injection) → combined exploitation
```

### Scenario 4: Query Specific Risks

```
User: What is GAARM.0039?
AI:   [Consults gaarm-risk-matrix.md → ai-app-prompt.md (GAARM.0039 is app-phase Prompt injection)]
      → Returns full attack overview, cases, risk analysis, mitigations
```

## Trigger Keywords

The following keywords automatically trigger Skill loading:

> vulnerability research, penetration testing, security audit, code review, security assessment, red team,
> CTF, SQL injection, XSS, command execution, file upload, SSRF, authorization bypass, logic flaws,
> prompt injection, jailbreak, MCP security, agent security, LLM security, sandbox escape,
> data leakage, model security, RAG poisoning, supply chain security

## Methodology Framework

```
User Request
│
├─ Web App ──→ SQL? → [web-sqli.md]   XSS? → [web-xss.md]   RCE? → [web-rce.md]
│              Upload? → [web-upload.md]   Traversal? → [web-traversal.md]
│              Logic? → [web-logic-auth.md]   Modern? → [web-modern-protocols.md]
│
├─ AI App ──→ Prompt inj → [ai-app-prompt.md]   MCP → [ai-app-mcp.md]   Agent/CoT → [ai-app-agent-cot.md]
│              Jailbreak → [ai-model-jailbreak.md]   Hallucination → [ai-model-hallucination.md]
│              Prompt leak/Data theft → [ai-data-app.md]
│              Role escape/Permission → [ai-identity-app.md]
│
├─ Deployment → Supply chain/Cloud/Framework CVE [web-deployment-security.md]
│
└─ Container/Sandbox → Escape/Persistence/Lateral movement [ai-baseline-escape.md]
```

## Changelog

### v2.0 (2026-05-18) — Structural refactor + split optimization

**SKILL.md entry upgrade**:
- 3 behavioral rules with ❗ marker (Payload citation / Hypothesis vs Confirmed / Authorization boundary) + "self-check before every output" mechanism
- New "Dependency chain constraints" section: Step 2 input == Step 1 output, Step 3 references ⊆ Step 2 loaded set, no re-searching
- Equation-based acceptance criteria: `cited count + UNABLE TO CITE count == total hypothesis count`
- Each Step adds "fail → retry → degrade → no skipping" 3-stage failure path
- Trigger refinement: CTF short code snippet + exploit idea → this Skill; full project dir + systematic white-box → code-audit-skill

**Reference split** (12 → 38 files):
- 1st split (by GAARM 3-phase): 5 AI files + 2 Web files → 26 sub-files
- 2nd split (ai-model-app.md 2231 lines) → 6 risk categories (Jailbreak/Hallucination/Content/Copyright/Misuse/Extraction)
- 3rd split (ai-app-app.md 1318 lines) → 3 risk classes (Prompt injection/MCP/Agent-CoT)
- Max file 2651 → 906 lines, **100% references ≤ 1000 lines**
- Removed redundant payloads.md; payloads now inlined per scenario

**Index reconstruction**:
- gaarm-risk-matrix.md 116 risk entries remapped by "GAARM domain + phase + risk category" to 38 sub-files
- testing-methodology.md OWASP three frameworks (LLM01-10 / ASI01-10 / WSTG-*) mappings fully aligned
- SKILL.md scenario navigation: AI security by "domain × phase × risk category" 3-level navigation

### v1.0 (Initial) — 12 reference files

Initial fusion of WooYun 88,636 cases + Xianzhi 5,600+ docs + GAARM 150 risks + OWASP three frameworks.

---

## Acknowledgments & References

This Skill's knowledge system is built upon the following outstanding projects and communities:

| Project | Description |
|---------|-------------|
| [WooYun Legacy](https://github.com/tanweai/wooyun-legacy) | A Claude Code Skill curated by the Tanwei Security Research Team, containing 88,636 real vulnerability cases. This project's web security knowledge (injection, file operations, logic flaws, etc.) is distilled from this vulnerability database |
| [Xianzhi Security Research Methodology](https://github.com/tanweai/xianzhi-research) | L1-L4 meta-thinking methodology framework extracted from 5,621 security papers in the Xianzhi community. This project's four-layer thinking model and cross-domain attack chain thinking originate from this work |
| [AISS - NSFOCUS AI Security Smart Link Community](https://aiss.nsfocus.com/) | AI security knowledge base by NSFOCUS, providing the GAARM risk matrix with 150 AI security risk entries covering 6 security domains × 3 lifecycle stages |
| [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | 2025 edition — Top 10 risks for LLM applications |
| [OWASP Agentic AI Security Top 10](https://owasp.org/www-project-agentic-ai-security-initiative/) | 2026 edition — Top 10 risks for AI Agents |
| [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) | v4.2 — Web Security Testing Guide with WSTG-* classification |

## Author

[Pa55w0rd](https://github.com/Pa55w0rd)

## Disclaimer

All content in this Skill is **for security research and defensive purposes only**. Please conduct security testing only with proper authorization and in compliance with local laws and regulations. All knowledge sources are from publicly available security communities and standard frameworks.

## License

MIT License

---

*Version: v2.0 (2026-05-18) | Author: Pa55w0rd | Knowledge Fusion: WooYun 88,636 cases × Xianzhi 5,600+ papers × GAARM 150 risks × OWASP LLM/ASI/WSTG × 200+ test cases | Structure: 38 references, 100% single-Read friendly*
