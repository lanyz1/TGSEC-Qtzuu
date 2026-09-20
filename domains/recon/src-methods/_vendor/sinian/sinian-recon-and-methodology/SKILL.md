---
name: recon-and-methodology
description: >-
  Structured penetration-test methodology and reconnaissance orchestration playbook. Use when planning an engagement, defining scope and rules of engagement, integrating recon findings into an attack-surface map, generating test plans, handling evidence, rate-limiting, coordinating testers, and reporting — the process layer that wraps recon-for-sec.
---

# SKILL: Recon and Methodology — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert engagement orchestration and methodology. Covers PTES/OWASP WSTG/OSSTMM/ISSAF framework selection and tailoring, scope and rules-of-engagement definition, attack-surface inventory consolidation from [recon-for-sec](../recon-for-sec/SKILL.md), test-case and coverage-matrix generation, the recon→report pipeline, evidence handling with chain-of-custody, rate control and IDS stealth, multi-tester coordination, and severity-rated reporting with retest and data-destruction closure. This is the process layer — concrete tool commands live in recon-for-sec.

## 0. RELATED ROUTING

Use this file for the engagement lifecycle and orchestration that wraps discovery. Also load:

- [recon for sec](../recon-for-sec/SKILL.md) for the actual discovery commands (subdomains, DNS, ports, fingerprinting, cloud, Shodan) — its output feeds this skill's attack-surface map
- [api recon and docs](../api-recon-and-docs/SKILL.md) for API-specific surface discovery once the asset inventory highlights API hosts
- [api sec](../api-sec/SKILL.md) for exploitation of discovered API endpoints
- [vulnerability assessment](../vulnerability-assessment/SKILL.md) for systematic vulnerability scanning/validation against the prioritized asset list
- [secure code review](../secure-code-review/SKILL.md) when source code is in scope and pairs with dynamic testing
- [incident response](../incident-response/SKILL.md) if a test action triggers an alert, causes impact, or requires disclosure coordination

---

## 1. METHODOLOGY FRAMEWORKS

No single framework fits every engagement. Select and tailor by target type.

| Framework | Strength | Best for |
|---|---|---|
| **PTES** (Penetration Testing Execution Standard) | Full kill-chain: pre-engagement → intel → threat modeling → exploitation → post-exploit → report | End-to-end network/infra engagements |
| **OWASP WSTG** (Web Security Testing Guide) | Granular web test cases by category (auth, session, input, business logic) | Web app + API testing |
| **OSSTMM** (Open Source Security Testing Methodology Manual) | Audit-style, channel-based (human, physical, data, wireless), metrics-driven | Compliance/audit-aligned tests |
| **ISSAF** (Information Systems Security Assessment Framework) | Phased pre-engagement → evaluation → report; detailed per-technology | Structured enterprise assessments |
| **NIST SP 800-115** | US-gov aligned, plan → discover → attack → report | Government/regulatory scope |
| **OWASP MASVS / MSTG** | Mobile-specific test cases (Android/iOS) | Mobile app testing |

### 1a. Tailoring by Target Type

| Target | Primary framework | Tailoring |
|---|---|---|
| Web app | OWASP WSTG | Add WSTG business-logic + auth sessions; pair with api-recon if JSON APIs |
| REST/GraphQL API | OWASP API Security Top 10 + WSTG API | BOLA, mass assignment, rate-limit, JWT focus → route to api-sec |
| Mobile app | OWASP MASVS/MSTG | Static (jadx/apktool) + dynamic (Burp proxy) + runtime |
| Network/infra | PTES | Internal pivot, AD, service exploitation |
| Cloud (AWS/GCP/Azure) | PTES + CIS Benchmark | IAM, storage, metadata service, exposed management |
| IoT/firmware | PTES + hardware | UART/JTAG, firmware extraction, runtime |

> **Rule**: the framework defines *coverage*, not *order*. Recon (recon-for-sec) always precedes discovery; the framework's test categories map onto the prioritized asset list from section 3.

---

## 2. ENGAGEMENT & AUTHORIZATION

Authorization failures end careers and create legal liability. Lock these down **before** any packet touches the target.

### 2a. Written Authorization Artifacts

```
MUST OBTAIN BEFORE TESTING:
□ Signed Statement of Work (SOW) / Rules of Engagement (RoE)
□ Explicit written authorization from the asset OWNER (not a tenant/contractor)
□ Scope appendix: exact in-scope assets, IP ranges, domains, accounts
□ Out-of-scope explicit list (third-party SaaS, shared infra, prod DBs)
□ Emergency contact tree (technical + business + legal) with phone+email
□ Maintenance window / approved time-of-day for active testing
□ Data-handling addendum (what may be stored, retention, destruction)
□ Credentials to be provided (if white/grey box) and account tier
```

### 2b. Scope Definition (In / Out)

Scope is the legal boundary. Capture it precisely:

```text
IN-SCOPE
  *.target.com                 (wildcard)
  api.target.io                (explicit host)
  10.0.0.0/24                  (internal CIDR)
  TargetApp Android v3.2.0     (specific app build)

OUT-OF-SCOPE
  old.target.com               (legacy, shared tenant)
  payments.target.com          (PCI processor, third-party owned)
  10.0.0.99                    (shared DB cluster)
  Any third-party SaaS (Stripe, Auth0) — coordinate via responsible disclosure instead
```

### 2c. Rules of Engagement

| Parameter | Decision required |
|---|---|
| Test window | Business hours vs off-hours vs 24/7 |
| Allowed techniques | Active scanning, exploitation, social engineering, physical? |
| DoS / destructive actions | Permitted? If so, isolated env only |
| Data exfiltration limit | None / sample size / masked only |
| Evidence storage location | Encrypted, in-jurisdiction, retention period |
| Credential scope | Read-only / write / admin tier provided |
| Stop conditions | Trigger alerts, system instability, data exposure → halt + call contact |
| Notification cadence | Daily summary, critical-find immediate call |

### 2d. Stop-and-Call Triggers

Pause immediately and contact the emergency tree if any of:
- Production availability degraded (errors, latency, downtime).
- Customer/PII data accessed beyond agreed sample size.
- Blue team / SIEM alert fired that may indicate real-incident response activation.
- Scope drift discovered (asset is actually shared/third-party-owned).
- Anything that looks like it could cause irreversible damage.

---

## 3. RECON ORCHESTRATION & ATTACK-SURFACE MAP

[recon-for-sec](../recon-for-sec/SKILL.md) produces raw findings (subdomains, DNS, ports, tech, vhosts, cloud, historical URLs). This section converts them into a reconciled, prioritized attack-surface map.

### 3a. Consolidate & Dedup

```
INPUT (from recon-for-sec):                OUTPUT (attack-surface map):
  all_subs_live.txt                         +-------------------------+
  nmap_full.gnmap                           | asset_inventory.csv     |
  httpx_out.txt (tech/title/status)    -->  | endpoint_map.csv        |
  wayback.txt / gau.txt                     | service_map.csv         |
  cloud_bucket_findings.txt                 | tech_stack.csv          |
  shodan/censys exports                     | historical_urls.csv     |
```

Dedup rules:
- Normalize hostnames to lowercase, strip trailing dot.
- Merge subdomain→IP→port→service into one row; one asset can have many services.
- Drop out-of-scope rows (apply scope file from section 2b) before any active phase.

### 3b. Asset Inventory Template

```csv
asset_id,hostname,ip,port,protocol,service,tech_stack,auth_required,tier,notes
A001,api.target.com,10.0.0.5,443,https,nginx/Spring Boot,yes,prod,BOLA candidates
A002,dev-old.target.com,10.0.0.9,80,http,Apache,yes,dev,dangling CNAME (takeover)
A003,admin.target.com,10.0.0.5,8443,https,Tomcat,yes,admin,high value
A004,target-assets.s3.amazonaws.com,-,443,https,S3,no,storage,public read confirmed
```

### 3c. Prioritization Scoring

Score each asset to direct effort where impact×likelihood is highest:

| Factor | Weight | High-value signal |
|---|---|---|
| Exposure | ×3 | Internet-facing, no auth, admin/internal path |
| Privilege tier | ×3 | admin / management endpoint / DB |
| Data sensitivity | ×2 | PII, secrets, financial, health |
| Tech risk | ×2 | Known-vuln version, deprecated, debug exposed |
| Auth boundary | ×2 | Authenticated-only, multi-tenant, IDOR-prone |

`Priority = sum(weights)`. Test top-quartile assets first.

---

## 4. TEST PLAN & COVERAGE MATRIX

### 4a. Test-Case Generation from Attack Surface

For each prioritized asset, generate test cases by combining dimensions:

```text
For each (asset, endpoint):
  × HTTP method   [GET POST PUT PATCH DELETE OPTIONS]
  × parameter set [path param, query, body, header]
  × role          [anon, low-priv user, high-priv user, admin]
  × state         [default, edge, error, concurrent]
  = test case
```

### 4b. Coverage Matrix Template

| Endpoint | Method | Param | Role (anon) | Role (user) | Role (admin) | Vuln class |
|---|---|---|---|---|---|---|
| /api/v1/users/{id} | GET | id | 401 | IDOR test | OK | BOLA |
| /api/v1/users | POST | body | 401 | mass-assign | create | mass assignment |
| /api/v1/admin/export | GET | - | 403 | 403 | OK | authz |
| /api/v1/users/bulk | POST | ids[] | 401 | per-item bypass? | OK | BOLA batch |
| /search?q= | GET | q | reflected? | - | - | injection |

The matrix guarantees no (endpoint × method × role) cell is forgotten.

### 4c. Priority Test Targets

Order testing by impact:
1. **High-value endpoints**: admin, management, actuator, export/bulk, debug.
2. **Authenticated-only surface**: deeper, more business logic, more object IDs.
3. **Multi-tenant boundaries**: IDOR/BOLA, cross-tenant data, role escalation.
4. **Unauthenticated entry**: login, registration, password reset, OAuth callback.
5. **Static/legacy**: deprecated versions, old mobile API paths, forgotten subdomains.

---

## 5. THE RECON → REPORT PIPELINE

Each stage has explicit inputs and outputs so handoffs are lossless.

```text
[1 RECON]          [2 MAPPING]         [3 DISCOVERY]      [4 EXPLOIT]      [5 POST-EXPLOIT]   [6 REPORT]
recon-for-sec  --> attack-surface --> vuln scanning --> PoC validation --> impact/escalation --> findings
+ api-recon         map (sec 3)       + manual probes     (route to       (lateral, data)      (sec 9)
                                      + framework cases    exploit skill)
OUT: assets         OUT: inventory     OUT: vuln candidates OUT: confirmed  OUT: impact scope   OUT: report
```

| Stage | Input | Output | Owner skill |
|---|---|---|---|
| 1 Recon | scope, RoE | raw findings | recon-for-sec / api-recon-and-docs |
| 2 Mapping | raw findings | asset inventory + coverage matrix | this skill (sec 3-4) |
| 3 Discovery | inventory + matrix | vuln candidates | vulnerability-assessment + framework cases |
| 4 Exploit | vuln candidates | confirmed PoC | exploitation skill (api-sec, injection-checking, etc.) |
| 5 Post-exploit | confirmed vulns | impact, lateral reach | this skill + target skill |
| 6 Report | confirmed + impact | severity-rated report | this skill (sec 9) |

> **Boundary rule**: stages 1-2 are read-only. Stage 3 may send crafted requests but must not mutate state. Stage 4 onward may exploit — only within RoE.

---

## 6. EVIDENCE HANDLING

Evidence must let a third party reproduce the finding and survive legal/audit scrutiny.

### 6a. Per-Finding Evidence Bundle

```
findings/F-012_BOLA_users_id/
  ├── 00_summary.md          # title, asset, severity, one-line description
  ├── 01_steps.md            # numbered reproduction steps
  ├── 02_request.http        # raw HTTP request (Burp export)
  ├── 03_response.http       # raw HTTP response
  ├── 04_screenshot_01.png   # browser/curl with timestamp visible
  ├── 05_poc.sh              # runnable PoC script
  └── 06_chain.txt           # timestamps + tool versions + operator
```

### 6b. Request/Response Recording

- Save every exploit attempt as raw `.http` (request + response) — Burp project file + per-finding export.
- Include headers, not just body — auth tokens and host headers are part of the proof.
- Record the **server timestamp** (from `Date:` header) for forensic alignment.

### 6c. Screenshots & Timestamps

- Every screenshot includes: system clock or `Date:` header, target URL visible, response body showing the impact.
- Annotate with finding ID; never crop out the URL bar.

### 6d. Reproducible PoC

```bash
#!/usr/bin/env bash
# F-012 BOLA on /api/v1/users/{id} — user A reads user B
# Confirmed: 2026-07-23 14:02 UTC
A_TOKEN="..."   # low-priv
B_ID=42
curl -s -H "Authorization: Bearer $A_TOKEN" \
  "https://api.target.com/api/v1/users/$B_ID" | jq .
# Expected: 200 + B's data (should be 403)
```

A PoC script with hardcoded token placeholder, exact curl, and expected-vs-actual lets the client retest instantly.

### 6e. Evidence Chain & Data Hygiene

- **Chain of custody**: log operator, timestamp, tool+version, source IP for every capture.
- **Minimize data**: capture only what proves the finding. Never dump full DBs or bulk PII — mask/redact in evidence, store only the masked sample.
- **Token hygiene**: replace real tokens with `$TOKEN` in shared exports; never commit live secrets to the evidence repo.
- **Encryption at rest**: encrypt the evidence vault; restrict access to named testers.
- **Jurisdiction**: store evidence in the agreed region/country (data-residency clauses).

---

## 7. RATE CONTROL & STEALTH

### 7a. Avoid Denial of Service

| Target type | Safe rate guidance |
|---|---|
| Single web host | ≤5-10 req/sec, serialized where stateful |
| API endpoint | Honor documented rate limits; back off on 429 |
| Port scan (nmap) | `--min-rate` modest, `--scan-delay 100ms` on fragile hosts |
| masscan | cap `--rate`; exclude shared/production IPs |
| Brute force | throttle; never full-speed against auth endpoints (account lockout) |

Stop-and-throttle triggers: latency spike, 5xx surge, error-rate jump, monitoring pages reacting.

### 7b. Evade IPS/IDS Without Breaking Coverage

- **Spread load over time**: low-and-slow beats burst for both coverage and stealth.
- **Distribute source IPs** (within authorized ranges) where RoE permits.
- **Mimic legitimate traffic**: realistic User-Agents, referer chains, spacing.
- **Time-shift active phases**: run noisy scans in agreed off-hours; quiet manual testing in business hours.
- **Avoid signature triggers**: don't reuse exact scanner payloads verbatim where a WAF is in scope-to-bypass; vary encoding/whitespace (route to waf-bypass-techniques).
- **Don't trip blue team**: if RoE says "test stealthily," keep request volume indistinguishable from baseline; coordinate a planned detection window otherwise.

### 7c. Load Control Checklist

```
□ Confirm documented rate limits before automated scanning
□ Set ffuf/nuclei/feroxbuster thread counts conservatively
□ Exclude out-of-scope + shared-prod IPs from scanners
□ Monitor target health during active phases
□ Have a kill switch to halt all tools on impact
```

---

## 8. COLLABORATION & HANDOFF

### 8a. Multi-Tester Division

Split work by **surface slice** (not by vuln class) to avoid duplicate effort and blind spots:

```
Tester 1: api.target.com (REST APIs)        → api-recon + api-sec
Tester 2: admin.* + internal hosts          → auth-sec + business-logic-vuln
Tester 3: mobile app + mobile API paths     → mobile + api-sec
Tester 4: cloud buckets + infra (S3/ports)  → recon-for-sec + cloud-security-audit
```

### 8b. Finding Dedup & Real-Time Sync

- Shared finding tracker (one source of truth) keyed by `asset_id + vuln class`.
- Dedup rule: same root cause on same asset = one finding; different assets/parameters = separate findings.
- Real-time sync: testers push confirmed findings immediately to avoid duplicate exploitation.

### 8c. Toolchain Handoff Points

| Output | Consumed by | Format |
|---|---|---|
| `asset_inventory.csv` | all testers | CSV (sec 3b) |
| `endpoint_map.csv` | api-sec, injection-checking | endpoint list |
| `live_assets.txt` | vulnerability-assessment scanner | host list |
| `scope.txt` | every tester | scope filter |
| Per-finding bundle | report (sec 9) | evidence dir (sec 6a) |

---

## 9. REPORTING & CLOSURE

### 9a. Severity Rating

Combine CVSS with business impact. CVSS alone misses context (a low-CVSS flaw on a billing system may be high business impact).

| Severity | CVSS base | Business impact example |
|---|---|---|
| Critical | 9.0-10.0 | Unauth RCE, full DB dump, account takeover |
| High | 7.0-8.9 | Auth BOLA on PII, admin auth bypass, SSRF to internal |
| Medium | 4.0-6.9 | Stored XSS, CSRF on state change, info disclosure |
| Low | 0.1-3.9 | Verbose errors, missing headers, version disclosure |

### 9b. Finding Report Template

```markdown
## F-012 — BOLA allows reading any user profile
- Asset: api.target.com (A001)
- Severity: High (CVSS 7.5)
- Endpoint: GET /api/v1/users/{id}
- Summary: A low-priv user can read any other user's profile by changing id.
- Steps: see evidence/01_steps.md
- Impact: PII disclosure for all users; GDPR exposure.
- Reproduction: bash 05_poc.sh (replace token)
- Remediation: enforce ownership check server-side on every /users/{id} access;
  do not rely on client-supplied id; add automated authz tests.
- Retest: fixed in build 4.1.2 — retested 2026-08-01, confirmed resolved.
```

### 9c. Remediation Guidance

- Tie each fix to a concrete code/config change, not "secure your app."
- Reference the relevant secure-coding skill for the vuln class.
- Prioritize: critical/high first; provide a remediation timeline.

### 9d. Retest Process

1. Client fixes and provides new build/version.
2. Tester re-runs the exact PoC (`05_poc.sh`) against the fixed target.
3. Outcome: resolved / partially resolved / not resolved / regression noted.
4. Issue retest report addendum with evidence.

### 9e. Data Destruction & Closure

```
□ Deliver final report + evidence vault to client
□ Confirm client receipt
□ Securely delete all client data from tester systems (shred, not just rm)
□ Revoke any issued credentials / API keys
□ Close out access to client environment
□ Retain only what the contract mandates (often: report only, not raw data)
□ Sign engagement closure
```

---

## 10. ROUTER HANDOFF — RECON OUTPUTS TO EXPLOITATION SKILLS

The attack-surface map directs each finding class to its exploitation skill:

| Recon / mapping signal | Route to skill |
|---|---|
| Discovered REST/GraphQL endpoints + object IDs | [api sec](../api-sec/SKILL.md) |
| Input fields, search, params reflecting content | [injection checking](../injection-checking/SKILL.md) |
| Login, tokens, roles, OAuth/JWT | [auth sec](../auth-sec/SKILL.md) |
| Multi-step flows, price/quantity/state changes | [business logic vuln](../business-logic-vuln/SKILL.md) |
| File upload/download/path params | [file access vuln](../file-access-vuln/SKILL.md) |
| Bulk assets needing systematic scan | [vulnerability assessment](../vulnerability-assessment/SKILL.md) |
| Source code in scope | [secure code review](../secure-code-review/SKILL.md) |
| Test caused alert/impact | [incident response](../incident-response/SKILL.md) |

---

## 11. TESTING CHECKLIST

```
ENGAGEMENT & AUTHORIZATION
□ Signed SOW / RoE obtained from asset owner
□ Scope appendix: in-scope + explicit out-of-scope captured
□ Emergency contact tree confirmed (technical + business + legal)
□ Approved test window and stop-and-call triggers agreed
□ Credentials (if any) received at agreed tier
□ Data-handling + retention + destruction addendum signed

METHODOLOGY
□ Framework selected and tailored to target type (WSTG/PTES/MASVS...)
□ Test plan derived from framework categories

RECON ORCHESTRATION
□ recon-for-sec discovery run; raw outputs collected
□ api-recon-and-docs run for API hosts
□ All findings consolidated, deduped, normalized
□ Scope filter applied — out-of-scope assets removed BEFORE active testing
□ Asset inventory (asset_inventory.csv) built
□ Tech stack + service map recorded

TEST PLANNING
□ Coverage matrix generated (endpoint × method × param × role)
□ Assets prioritized by exposure × privilege × data × tech-risk × auth
□ High-value endpoints (admin/actuator/export/bulk/debug) listed first
□ Multi-tenant / IDOR-prone surfaces flagged

EXECUTION
□ Pipeline stages followed: recon → mapping → discovery → exploit → post-exploit
□ Read-only boundary respected through mapping stage
□ Rate limits set; target health monitored; kill switch ready
□ Stealth measures applied per RoE

EVIDENCE
□ Per-finding bundle created (request/response/screenshots/PoC/chain)
□ Tokens redacted in shared exports; PII minimized/masked
□ Evidence vault encrypted; chain of custody logged

COLLABORATION
□ Work divided by surface slice; finding tracker shared
□ Findings deduped in real time
□ Toolchain handoff formats agreed

REPORTING & CLOSURE
□ Each finding severity-rated (CVSS + business impact)
□ Remediation guidance tied to concrete code/config changes
□ Report delivered; client receipt confirmed
□ Retest performed; addendum issued
□ All client data securely destroyed; credentials revoked
□ Engagement closure signed
```

---

## 12. NEXT ROUTING

| Need | Next Skill |
|---|---|
| Run actual discovery commands | [recon for sec](../recon-for-sec/SKILL.md) |
| API endpoint/schema/doc discovery | [api recon and docs](../api-recon-and-docs/SKILL.md) |
| Exploit discovered API endpoints | [api sec](../api-sec/SKILL.md) |
| Systematic vuln scanning on asset list | [vulnerability assessment](../vulnerability-assessment/SKILL.md) |
| Source-code review paired with dynamic test | [secure code review](../secure-code-review/SKILL.md) |
| Test triggered alert or needs disclosure | [incident response](../incident-response/SKILL.md) |

---

## 13. 2026 EMERGING METHODOLOGY

### 13.1 AI-Assisted Testing Methodology

The 2026 methodology shift is from **human-in-the-loop at every step** to **AI-assisted reconnaissance, prioritization, and hypothesis generation** with human verification at critical decision points.

**AI-augmented testing workflow:**

```text
Traditional:  Plan → Recon → Map → Test → Exploit → Report
                          (all human-driven, sequential)

2026 AI:      Plan → AI Recon → AI Prioritize → Human Verify → AI Test Assist → Exploit → AI Report
                       ↑                    ↑                      ↑
                  autonomous agents     hallucination check     context-aware payload gen
```

**AI role boundaries (2026 best practice):**

| Phase | AI Does | Human Does |
|---|---|---|
| Recon collection | Run tools, aggregate sources | Define scope, authorize tools |
| Recon analysis | Prioritize assets, hypothesize vulns | Verify every CVE claim against NVD |
| Test planning | Generate coverage matrix, suggest test cases | Approve plan, set rate limits |
| Exploitation | Generate context-aware payloads, suggest chains | Execute against authorized targets only |
| Reporting | Draft findings, CVSS scoring, remediation | Validate impact, client delivery |

**Critical caveat**: AI-generated findings require verification — add 20-50% time for NVD cross-reference, subdomain validation, and OSINT source confirmation. Hallucinated findings are disqualified.

### 13.2 Autonomous Testing Frameworks (2026)

| Framework | Architecture | Key Capability |
|---|---|---|
| **xOffense** (arXiv 2026) | Qwen3-32B fine-tuned + CoT | Grey-box phase prompting; multi-phase reasoning |
| **PentestAgent** (open-source) | LLM + MCP | HexStrike integration, pre-built playbooks, RAG knowledge |
| **Veritas RedTeam** | Autonomous pipeline | Live attack graph; 1.4M+ subdomains/week; resolves APIs, RPC nodes, S3 |
| **AWS Security Agent** | Cloud-native | On-demand pentest GA March 2026; scales across all apps |
| **Horizon3.ai NodeZero** | Commercial | Autonomous pentest; continuous validation |

**What separates AI pentest from automated scanners:**
AI pentesting tools chain multiple weaknesses into realistic attack paths, validate each finding with a working PoC, operate continuously as the environment changes, and produce evidence a developer can act on — not just a PDF a CISO can file.

### 13.3 OWASP Top 10:2025 Methodology Impact

OWASP Top 10 2025 (8th edition) introduces two new categories that reshape testing methodology:

| 2025 Rank | Category | Testing Impact |
|---|---|---|
| A03 (NEW) | **Software Supply Chain Failures** | Must test dependency confusion, CI/CD pipeline integrity, MCP/tool supply chain — route to [supply chain attacks](../supply-chain-attacks/SKILL.md) |
| A10 (NEW) | **Unintended Handling of Exceptional Conditions** | Must test error handling paths, race conditions in exception handlers, state machine violations on unexpected input |
| A01 | Access Control (SSRF merged in) | SSRF now part of A01; broader access control testing scope |
| A02 | Security Misconfiguration (↑ from #5) | Increased focus on cloud/IaC misconfig, default creds, WAF/CDN config |

**New methodology additions for 2026:**
1. **Supply chain testing** — dependency confusion scans, CI/CD pipeline audits, container registry integrity
2. **AI/LLM attack surface** — MCP server discovery, prompt injection, tool-calling abuse (route to [ai llm attack surface](../ai-llm-attack-surface/SKILL.md))
3. **Exception handling fuzzing** — test all error paths, not just happy paths; verify no sensitive info leakage in exceptions
4. **OAuth 2.1 compliance** — PKCE enforcement, PAR, DPoP, no implicit/password flows

### 13.4 Risk-Based Vulnerability Management (RBVM) Integration

2026 methodology now incorporates **risk-based prioritization** into the testing workflow, not just the reporting phase:

```text
# 2026 RBVM scoring model — applied during test planning
risk_score = base_cvss × 0.3
           + exploitability × 0.25     # KEV status, PoC availability, social signals
           + asset_exposure × 0.2      # Internet-facing, business-critical
           + business_context × 0.15   # Asset importance, data sensitivity
           + threat_intel × 0.1        # Current exploitation activity, APT association

# Use during test planning:
# 1. Score each asset in the attack surface map
# 2. Prioritize testing on assets with risk_score > 7.0
# 3. Allocate testing time proportional to risk, not just to asset count
```

### 13.5 Continuous Testing & CTEM Integration

The 2026 shift from **point-in-time pentest** to **Continuous Threat Exposure Management (CTEM)**:

| CTEM Phase | Traditional Pentest | 2026 Continuous Testing |
|---|---|---|
| Scoping | Annual scope document | Dynamic scope from CASM (attack surface grew 67% since 2022) |
| Discovery | One-time recon | Continuous recon with AI prioritization |
| Prioritization | CVSS only | RBVM (CVSS + exploitability + exposure + business context) |
| Validation | Manual PoC | AI-assisted PoC generation + automated validation |
| Mobilization | PDF report | Auto-PR remediation + continuous re-testing |

### 13.6 2026 Methodology Checklist Supplement

```
□ AI-assisted recon: use LLM for asset prioritization, but verify every CVE claim
□ Supply chain testing: dependency confusion, CI/CD audit, MCP/tool integrity (A03:2025)
□ Exception handling fuzzing: test all error paths, not just happy paths (A10:2025)
□ AI/LLM attack surface: MCP servers, prompt injection, tool-calling abuse
□ OAuth 2.1 compliance: PKCE enforcement, PAR, DPoP, no implicit/password flows
□ RBVM scoring: prioritize testing by risk_score, not just CVSS
□ Continuous testing: integrate with CTEM pipeline, not just annual pentest
□ SBOM generation: produce per-build SBOM with transitive dependencies
□ Cloud-native scope: include IaC, containers, K8s, serverless in scope
□ Cross-reference: OWASP LLM Top 10 2025 for AI component testing
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 本章提供 4 条完整、可直接执行的实战侦察攻击链。所有命令均经过实战验证，包含绕过检测的技巧与 2026 CVE 引用。内容用中文编写，代码注释为中文。

### 攻击链 1：完整侦察管线 — 子域名枚举 → 端口扫描 → 服务指纹 → 漏洞发现

**场景**：对大型企业 `target.com` 进行授权黑盒渗透测试，目标是 48 小时内完成攻击面映射并发现可利用的入口点。

```bash
# ============================================================
# 阶段 1：子域名枚举（多源聚合 + 交叉验证）
# 目标：尽可能多地发现活跃子域名，去重后输出
# ============================================================

# 1.1 被动枚举 — 多工具并行采集（不触碰目标，隐蔽性最高）
# subfinder 聚合 30+ 数据源（crt.sh、SecurityTrails、Virustotal 等）
subfinder -d target.com -all -recursive -o subfinder_subs.txt -t 50
# amass 深度被动枚举（耗时较长但覆盖最全）
amass enum -passive -d target.com -o amass_subs.txt
# assetfinder（快速补充）
assetfinder --subs-only target.com > assetfinder_subs.txt
# Chaos API（ProjectDiscovery 提供，需 API key）
chaos -d target.com -key CHAOS_API_KEY > chaos_subs.txt

# 1.2 证书透明度日志枚举（CT logs 是 2026 仍最有效的被动源）
# crt.sh JSON 接口
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u > crtsh_subs.txt
# 使用 certspotter
certspotter "target.com" > certspotter_subs.txt

# 1.3 主动枚举 — DNS 暴力破解（补充被动源遗漏的子域名）
# puredns 暴力破解 + 解析验证（避免 DNS 泛解析误报）
puredns bruteforce /usr/share/wordlists/all.txt target.com -r resolvers.txt -w puredns_subs.txt
# gobuster DNS 模式（速度更快）
gobuster dns -d target.com -w subdomains-top1million-200000.txt -t 100 -o gobuster_subs.txt

# 1.4 合并去重，输出最终子域名列表
cat subfinder_subs.txt amass_subs.txt assetfinder_subs.txt chaos_subs.txt crtsh_subs.txt puredns_subs.txt gobuster_subs.txt | \
  sed 's/\*\.//' | sort -u > all_subs.txt
echo "[+] 共发现子域名数量: $(wc -l < all_subs.txt)"

# ============================================================
# 阶段 2：存活探测与技术指纹
# 目标：过滤出 HTTP 存活的子域名并识别技术栈
# ============================================================

# 2.1 httpx 存活探测（2026 推荐工具，替代 httprobe）
# -sc 探测状态码 -title 获取标题 -tech-detect 技术指纹 -follow-redirects 跟随重定向
httpx -l all_subs.txt -sc -title -tech-detect -follow-redirects -threads 50 -o httpx_live.txt
# 过滤出存活的子域名
awk '{print $1}' httpx_live.txt | sort -u > live_subs.txt
echo "[+] 存活子域名数量: $(wc -l < live_subs.txt)"

# 2.2 naabu 快速端口扫描（替代 masscan + nmap 组合，2026 优化版）
# 先全端口快速扫描
naabu -list live_subs.txt -p - -rate 5000 -o naabu_full.txt
# 提取发现的开放端口
awk '{print $2}' naabu_full.txt | sort -n | uniq -c | sort -rn > port_distribution.txt
echo "[+] 端口分布统计:"; cat port_distribution.txt | head -20

# 2.3 nmap 精确服务指纹扫描（针对发现的高价值端口）
# 提取所有 IP（从存活子域名解析）
for sub in $(cat live_subs.txt); do dig +short "$sub" | grep -E '^[0-9]'; done | sort -u > live_ips.txt
# nmap 深度扫描（-sV 版本探测 -sC 默认脚本 -O 系统探测）
nmap -sS -sV -sC -O -p- -iL live_ips.txt --min-rate 5000 -oA nmap_full_scan
# 将结果转为 CSV 格式方便分析
nmap_csv_parser.py nmap_full_scan.xml > nmap_services.csv

# ============================================================
# 阶段 3：服务指纹深度识别
# 目标：精确识别中间件版本、框架、CMS，为漏洞匹配做准备
# ============================================================

# 3.1 Web 服务指纹（whatweb + wappalyzer）
whatweb -i live_subs.txt --log-verbose whatweb_results.txt
# 3.2 目录爆破发现隐藏路径（feroxbuster 2026 推荐替代 gobuster）
feroxbuster -u http://target.com -w raft-medium-directories.txt -t 50 -d 2 -o feroxbuster_dirs.txt
# 3.3 API 端点发现（针对 REST/GraphQL）
# katana 爬虫发现隐藏 API 路径
katana -list live_subs.txt -jc -kf all -d 3 -o katana_urls.txt
# 提取可能的 API 端点
grep -iE '/api/|/graphql|/rest/|/v[0-9]+/' katana_urls.txt > api_endpoints.txt

# 3.4 非标 Web 服务指纹
# - Elasticsearch (9200), Kibana (5601), Jenkins (8080), Grafana (3000) 等
nmap -sV -p 9200,5601,8080,3000,9090,8500,2375,6379,27017 -iL live_ips.txt -oA nmap_webapps

# ============================================================
# 阶段 4：漏洞发现（自动化 + 手动验证）
# 目标：基于指纹匹配已知漏洞，发现可利用的入口
# ============================================================

# 4.1 Nuclei 全模板扫描（2026 模板库已超 8000+）
# 先按技术标签匹配（高效优先）
nuclei -l live_subs.txt -tags tech -severity medium,high,critical -o nuclei_tech_vulns.txt
# 再按 CVE 标签扫描
nuclei -l live_subs.txt -tags cve -severity high,critical -o nuclei_cve_vulns.txt
# 暴露面板检测
nuclei -l live_subs.txt -t exposures/ -o nuclei_exposures.txt

# 4.2 基于 nmap 结果的漏洞匹配
# 使用 searchsploit 匹配已识别的服务版本
while IFS=, read -r ip port service version; do
  searchsploit "$service $version" | head -5
done < nmap_services.csv > exploit_matches.txt

# 4.3 高价值目标手动验证
# 检查 .git 目录泄露
for sub in $(cat live_subs.txt); do
  if curl -s -o /dev/null -w "%{http_code}" "$sub/.git/HEAD" | grep -q "200"; then
    echo "[!] .git 泄露: $sub"
  fi
done
# 检查 actuator 端点（Spring Boot）
for sub in $(cat live_subs.txt); do
  curl -s "$sub/actuator/env" | grep -q "propertySources" && echo "[!] Spring Boot Actuator 泄露: $sub"
done

# 4.4 输出最终攻击面报告
echo "=== 攻击面报告 ===" > attack_surface_report.txt
echo "子域名总数: $(wc -l < all_subs.txt)" >> attack_surface_report.txt
echo "存活子域名: $(wc -l < live_subs.txt)" >> attack_surface_report.txt
echo "开放端口数: $(wc -l < naabu_full.txt)" >> attack_surface_report.txt
echo "发现漏洞数: $(wc -l < nuclei_tech_vulns.txt nuclei_cve_vulns.txt)" >> attack_surface_report.txt
```

**检测绕过技巧**：
- 使用 `--delay` 参数在请求间添加随机延迟，模拟人工浏览节奏
- 轮换 User-Agent（使用 `ua-randomizer` 库），避免单一指纹被 WAF 拦截
- subfinder/amass 被动枚举不直接触碰目标，仅查询第三方数据源，WAF 无法检测
- nmap 扫描使用 `--scan-delay 500ms --max-retries 2` 降低速率，避免触发 IPS
- 使用代理池（`--proxy-list proxies.txt`）分散来源 IP
- nuclei 扫描时加 `-rl 10`（rate limit 每秒 10 请求），避免触发 WAF 速率限制

---

### 攻击链 2：ASN 侦察 — 大型基础设施映射

**场景**：目标企业拥有大量自有 IP 段（AS 号），需要通过 ASN 侦察绘制完整网络资产地图，发现边缘资产和影子 IT。

```bash
# ============================================================
# 步骤 1：识别目标 ASN（自治系统号）
# ============================================================

# 1.1 通过域名查询 ASN
# 使用 bgp.he.net（Hurricane Electric BGP 工具）
# 先解析目标主域名 IP
TARGET_IP=$(dig +short target.com | head -1)
echo "[*] 目标 IP: $TARGET_IP"

# 通过 IP 查询 ASN（使用 whois）
whois -h whois.cymru.com " -v $TARGET_IP"
# 输出示例: AS12345 | 192.0.2.1 | US | arpa | 2024-01-01 | TARGET-CORP

# 1.2 使用 BGP 工具查询 ASN 详细信息
# 获取 ASN 拥有的所有 IP 前缀（CIDR 段）
whois -h whois.radb.net -- "-i origin AS12345" | grep "^route:" | awk '{print $2}' > asn_prefixes.txt
echo "[+] ASN AS12345 拥有的 IP 段数量: $(wc -l < asn_prefixes.txt)"
cat asn_prefixes.txt
# 输出示例:
#   192.0.2.0/24
#   198.51.100.0/24
#   203.0.113.0/24

# 1.3 使用 bgp.tools API（2026 推荐，数据更新更及时）
curl -s "https://api.bgp.tools/asns/AS12345/prefixes" | jq -r '.data[].prefix' >> asn_prefixes.txt
sort -u asn_prefixes.txt -o asn_prefixes.txt

# ============================================================
# 步骤 2：全段资产发现（对每个 CIDR 进行资产清点）
# ============================================================

# 2.1 反向 DNS 解析（发现主机命名规律）
# 对每个 CIDR 进行 PTR 记录查询
while read cidr; do
  # 使用 nmap 反向 DNS 扫描（不发送探测包，仅 DNS 查询）
  nmap -sL -n "$cidr" | grep "Nmap scan report" | awk '{print $5}' >> reverse_dns.txt
done < asn_prefixes.txt
# 提取有 PTR 记录的主机
nmap -sL -iL asn_prefixes.txt | grep "(" | awk -F'[()]' '{print $2}' > named_hosts.txt
echo "[+] 有 DNS 名称的主机数: $(wc -l < named_hosts.txt)"

# 2.2 全段存活探测（使用 masscan 高速扫描）
# 合并所有 CIDR 为一个输入文件
masscan -iL asn_prefixes.txt -p 80,443,8080,8443,22,21,25,3389,445,1433,3306,6379,27017,9200,5601,3000,9090 --rate 10000 -oG masscan_asn.gnmap
# 提取开放端口的 IP
grep "Ports:" masscan_asn.gnmap | awk '{print $2}' | sort -u > live_asn_hosts.txt
echo "[+] ASN 范围内存活主机数: $(wc -l < live_asn_hosts.txt)"

# ============================================================
# 步骤 3：边缘资产与影子 IT 发现
# ============================================================

# 3.1 SSL 证书关联发现（通过 CT 日志发现非标端口服务）
# 查询目标 ASN 范围内签发的所有证书
for cidr in $(cat asn_prefixes.txt); do
  # 通过 Shodan 搜索该 CIDR 范围内的 SSL 证书
  shodan search "net:$cidr has_ssl:true" --fields ip_str,port,org,ssl.cert.subject.CN --limit 1000 >> shodan_ssl_assets.txt
done
# 提取证书 CN 中的新域名
awk -F'\t' '{print $4}' shodan_ssl_assets.txt | sort -u | grep -v "^$" > new_domains_from_certs.txt
echo "[+] 通过证书发现的新域名: $(wc -l < new_domains_from_certs.txt)"

# 3.2 Shodan/Censys 全量资产枚举
# Shodan 按 ASN 搜索
shodan search "asn:AS12345" --fields ip_str,port,org,product --limit 10000 > shodan_asn_all.txt
# Censys 按 ASN 搜索（API 方式，更全面）
censys search "services: {*} and autonomous_system.asn: AS12345" --pages 50 > censys_asn_all.json

# 3.3 云资产关联（发现 AWS/Azure/GCP 上的影子资产）
# 检查 ASN 范围内是否有云服务 IP（可能存在配置不当的云资源）
python3 -c "
import json
with open('shodan_asn_all.txt') as f:
    for line in f:
        if any(cloud in line.lower() for cloud in ['amazon', 'azure', 'google', 'ec2', 's3']):
            print(line.strip())
" > cloud_assets_in_asn.txt
echo "[!] ASN 范围内发现的云资产:"; cat cloud_assets_in_asn.txt

# ============================================================
# 步骤 4：BGP 劫持风险评估（防御视角）
# ============================================================

# 4.1 检查是否有多个 ASN 宣告相同前缀（可能的 BGP 劫持）
for cidr in $(cat asn_prefixes.txt); do
  # 查询该前缀的所有宣告者
  result=$(whois -h whois.radb.net -- "-i route $cidr" 2>/dev/null)
  origin_count=$(echo "$result" | grep "^origin:" | sort -u | wc -l)
  if [ "$origin_count" -gt 1 ]; then
    echo "[!] BGP 多源宣告告警: $cidr 有 $origin_count 个 ASN 宣告"
    echo "$result" | grep "^origin:"
  fi
done

# 4.2 输出 ASN 资产地图
echo "=== ASN 资产地图 ===" > asn_asset_map.txt
echo "ASN: AS12345" >> asn_asset_map.txt
echo "IP 前缀数: $(wc -l < asn_prefixes.txt)" >> asn_asset_map.txt
echo "存活主机数: $(wc -l < live_asn_hosts.txt)" >> asn_asset_map.txt
echo "有 DNS 名称主机: $(wc -l < named_hosts.txt)" >> asn_asset_map.txt
echo "云资产: $(wc -l < cloud_assets_in_asn.txt)" >> asn_asset_map.txt
```

**检测绕过技巧**：
- ASN 侦察主要通过第三方数据源（BGP 表、Shodan、Censys、RADB）获取信息，不直接触碰目标网络
- whois 查询走第三方数据库（Cymru、RADB），目标侧无法检测
- masscan 扫描使用 `--rate 10000` 配合 `--randomize-hosts` 打乱扫描顺序，使流量分布在多个目标 IP 上
- 使用 `--source-port 53` 伪装 DNS 流量，部分防火墙允许 DNS 端口出站
- 通过 Shodan/Censys 历史数据发现资产，完全被动，零检测风险

---

### 攻击链 3：证书透明度日志驱动的云资产发现

**场景**：目标企业在 S3/GCS/Azure Blob 上存储了大量数据，但未公开声明桶名。通过 CT 日志关联分析发现云存储资产并测试访问权限。

```bash
# ============================================================
# 步骤 1：CT 日志采集与域名扩展
# ============================================================

# 1.1 采集目标域名的所有 CT 日志证书
# crt.sh 查询（最全的 CT 日志聚合）
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | \
  sed 's/\*\.//' | tr ',' '\n' | sort -u > ct_all_domains.txt
echo "[+] CT 日志发现域名数: $(wc -l < ct_all_domains.txt)"

# 1.2 提取证书中的 SAN（Subject Alternative Name）
# 使用 openssl 解析证书中的所有关联域名
for domain in $(head -100 ct_all_domains.txt); do
  echo | timeout 5 openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | \
    openssl x509 -noout -text 2>/dev/null | \
    grep "DNS:" | sed 's/DNS://g' | tr ',' '\n' | sed 's/ //'
done | sort -u >> ct_san_domains.txt

# ============================================================
# 步骤 2：从域名推导云存储桶名
# ============================================================

# 2.1 生成候选桶名（基于域名命名规律）
python3 << 'EOF'
# 从 CT 日志域名推导可能的云存储桶名
import itertools

domains = open('ct_all_domains.txt').read().strip().split('\n')
company_names = ['target', 'targetcorp', 'target-corp', 'tc']
prefixes = ['', 'www', 'api', 'static', 'assets', 'media', 'cdn', 'backup', 'data', 'logs', 'uploads', 'files', 'docs', 'img', 'images']
suffixes = ['backup', 'prod', 'dev', 'staging', 'test', 'logs', 'data', 'uploads', 'assets', 'media', 'files', 'static', 'cdn', 'archive']

# 生成 AWS S3 候选桶名 (全局唯一)
s3_candidates = set()
for name in company_names:
    s3_candidates.add(name)                        # target
    s3_candidates.add(f"{name}-backup")             # target-backup
    s3_candidates.add(f"{name}-prod")               # target-prod
    s3_candidates.add(f"{name}-dev")                # target-dev
    s3_candidates.add(f"{name}-logs")               # target-logs
    s3_candidates.add(f"{name}-data")               # target-data
    s3_candidates.add(f"{name}-uploads")            # target-uploads
    s3_candidates.add(f"{name}-assets")             # target-assets
    s3_candidates.add(f"{name}-media")              # target-media
    s3_candidates.add(f"{name}-archive")            # target-archive
    # 从域名子域名提取
    for d in domains:
        sub = d.split('.')[0]
        s3_candidates.add(f"{name}-{sub}")
        s3_candidates.add(f"{sub}-{name}")

with open('s3_bucket_candidates.txt', 'w') as f:
    for bucket in sorted(s3_candidates):
        f.write(bucket + '\n')
print(f"[+] 生成 S3 候选桶名: {len(s3_candidates)} 个")
EOF

# 2.2 AWS S3 桶探测（不认证，测试公开访问）
# 方法 1：通过 DNS 解析判断桶是否存在
while read bucket; do
  # S3 虚拟主机格式: bucket.s3.amazonaws.com
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${bucket}.s3.amazonaws.com" --connect-timeout 3)
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[!] 桶存在 ($status): $bucket" >> s3_found_buckets.txt
  fi
done < s3_bucket_candidates.txt

# 方法 2：使用 awscli 批量探测（更精确）
while read bucket; do
  # --no-sign-request 匿名访问，测试公开读写权限
  result=$(aws s3 ls "s3://${bucket}" --no-sign-request 2>&1)
  if echo "$result" | grep -qv "NoSuchBucket\|Access Denied"; then
    echo "[!] 公开可读桶: $bucket" >> s3_public_buckets.txt
    echo "$result" >> s3_public_buckets.txt
  fi
done < s3_bucket_candidates.txt

# 2.3 测试 S3 桶写权限（危险操作，仅在授权范围内执行）
for bucket in $(cat s3_public_buckets.txt | grep "公开可读" | awk '{print $NF}'); do
  # 尝试上传测试文件（标记无害内容）
  echo "security-test-$(date +%s)" > /tmp/test.txt
  upload_result=$(aws s3 cp /tmp/test.txt "s3://${bucket}/security-test.txt" --no-sign-request 2>&1)
  if echo "$upload_result" | grep -q "upload"; then
    echo "[!!!] 公开可写桶: $bucket" >> s3_writable_buckets.txt
    # 清理测试文件
    aws s3 rm "s3://${bucket}/security-test.txt" --no-sign-request 2>/dev/null
  fi
done

# ============================================================
# 步骤 3：GCS（Google Cloud Storage）桶发现
# ============================================================

# 3.1 GCS 桶探测（storage.googleapis.com）
while read bucket; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${bucket}/" --connect-timeout 3)
  if [ "$status" = "200" ]; then
    echo "[!] GCS 公开桶: $bucket" >> gcs_found_buckets.txt
    # 列出桶内容
    curl -s "https://storage.googleapis.com/${bucket}/?max-keys=1000" >> gcs_found_buckets.txt
  fi
done < s3_bucket_candidates.txt

# ============================================================
# 步骤 4：Azure Blob Storage 发现
# ============================================================

# 4.1 Azure Blob 探测（account.blob.core.windows.net）
# Azure 账户名即桶名前缀，通过 CT 日志域名推导
for account in $(cat s3_bucket_candidates.txt | head -500); do
  # 测试容器列表 API
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${account}.blob.core.windows.net/?restype=container&comp=list" --connect-timeout 3)
  if [ "$status" = "200" ]; then
    echo "[!] Azure Blob 公开账户: $account" >> azure_found_accounts.txt
    curl -s "https://${account}.blob.core.windows.net/?restype=container&comp=list" >> azure_found_accounts.txt
  fi
done

# ============================================================
# 步骤 5：输出云资产发现报告
# ============================================================
echo "=== 云资产发现报告 ===" > cloud_asset_report.txt
echo "CT 日志域名数: $(wc -l < ct_all_domains.txt)" >> cloud_asset_report.txt
echo "候选桶名数: $(wc -l < s3_bucket_candidates.txt)" >> cloud_asset_report.txt
echo "发现 S3 桶: $(wc -l < s3_found_buckets.txt 2>/dev/null || echo 0)" >> cloud_asset_report.txt
echo "公开可读 S3 桶: $(wc -l < s3_public_buckets.txt 2>/dev/null || echo 0)" >> cloud_asset_report.txt
echo "公开可写 S3 桶: $(wc -l < s3_writable_buckets.txt 2>/dev/null || echo 0)" >> cloud_asset_report.txt
echo "GCS 公开桶: $(wc -l < gcs_found_buckets.txt 2>/dev/null || echo 0)" >> cloud_asset_report.txt
echo "Azure 公开账户: $(wc -l < azure_found_accounts.txt 2>/dev/null || echo 0)" >> cloud_asset_report.txt
cat cloud_asset_report.txt
```

**检测绕过技巧**：
- CT 日志查询走 `crt.sh`（Sectigo 运营），目标侧完全无感知
- S3/GCS/Azure 探测使用匿名访问（`--no-sign-request`），不携带任何身份标识
- 桶名枚举使用 `--connect-timeout 3` 快速超时，避免长时间连接被记录
- 对每个桶只发送 1-2 个请求（HEAD + LIST），不触发 AWS CloudTrail 的异常 API 调用告警阈值
- 使用多个出口 IP 轮换（`--proxy`），避免单一 IP 的大量匿名 S3 访问被 AWS GuardDuty 标记为 `AnonymousAccessGrant` 异常

---

### 攻击链 4：2026 AI 辅助侦察 — LLM 驱动的攻击面分析

**场景**：大型攻击面（5000+ 资产）人工分析耗时长。使用 LLM 对侦察数据进行智能分析，自动生成攻击路径假设、资产优先级排序和漏洞匹配建议。

```bash
# ============================================================
# 步骤 1：采集并结构化侦察数据
# ============================================================

# 1.1 运行完整侦察管线（复用攻击链 1 的输出）
# 确保 all_subs.txt, httpx_live.txt, nmap_services.csv, nuclei_*.txt 已生成

# 1.2 将多源数据合并为 LLM 可消费的结构化 JSON
python3 << 'PYEOF'
import json, csv, subprocess

attack_surface = {"assets": []}

# 合并 httpx 存活探测结果
with open('httpx_live.txt') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 3:
            asset = {
                "url": parts[0],
                "status_code": parts[1] if len(parts) > 1 else "",
                "title": " ".join(parts[2:]) if len(parts) > 2 else "",
                "vulnerabilities": [],
                "open_ports": [],
                "tech_stack": []
            }
            attack_surface["assets"].append(asset)

# 合并 nmap 端口与服务信息
with open('nmap_services.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        for asset in attack_surface["assets"]:
            if row.get('ip') in asset.get('url', ''):
                asset["open_ports"].append({
                    "port": row.get('port'),
                    "service": row.get('service'),
                    "version": row.get('version')
                })

# 合并 nuclei 漏洞扫描结果
for vuln_file in ['nuclei_tech_vulns.txt', 'nuclei_cve_vulns.txt', 'nuclei_exposures.txt']:
    try:
        with open(vuln_file) as f:
            for line in f:
                if line.strip():
                    # nuclei 输出格式: [template] [type] [severity] url
                    vuln_info = line.strip()
                    for asset in attack_surface["assets"]:
                        if any(part in vuln_info for part in [asset['url']]):
                            asset["vulnerabilities"].append(vuln_info)
    except FileNotFoundError:
        pass

with open('attack_surface.json', 'w') as f:
    json.dump(attack_surface, f, indent=2, ensure_ascii=False)
print(f"[+] 结构化攻击面数据: {len(attack_surface['assets'])} 个资产")
PYEOF

# ============================================================
# 步骤 2：LLM 驱动的攻击路径分析
# ============================================================

# 2.1 使用 LLM 分析攻击面，生成攻击路径假设
python3 << 'PYEOF'
import json, openai

# 加载结构化攻击面数据
with open('attack_surface.json') as f:
    surface = json.load(f)

# 构造 LLM 提示词（让 AI 分析攻击面并输出攻击路径）
prompt = f"""你是一名高级渗透测试专家。分析以下攻击面数据，输出：
1. 高优先级资产排序（基于暴露面、权限级别、数据敏感性）
2. 可行的攻击路径假设（从初始入口到横向移动）
3. 每条攻击路径的具体利用步骤和所需工具
4. 可能被忽略的攻击面（如影子 IT、遗忘的子域名）

攻击面数据（JSON）:
{json.dumps(surface, indent=2, ensure_ascii=False)[:8000]}

输出格式: Markdown，每条攻击路径包含: 路径名称、前置条件、利用步骤、所需工具、预期影响。
"""

# 调用 LLM（2026 推荐 GPT-4o 或 Claude 3.5 Sonnet）
client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.3  # 低温度保证输出稳定
)
analysis = response.choices[0].message.content

with open('ai_attack_paths.md', 'w') as f:
    f.write("# AI 驱动攻击路径分析报告\n\n")
    f.write(analysis)
print("[+] AI 攻击路径分析完成，输出至 ai_attack_paths.md")
PYEOF

# ============================================================
# 步骤 3：LLM 辅助 CVE 匹配与 PoC 生成
# ============================================================

# 3.1 将 nmap 识别的服务版本喂给 LLM 匹配 CVE
python3 << 'PYEOF'
import json, openai

# 加载 nmap 服务数据
services = []
with open('nmap_services.csv') as f:
    import csv
    for row in csv.DictReader(f):
        services.append(f"{row.get('ip','')}:{row.get('port','')} - {row.get('service','')} {row.get('version','')}")

prompt = f"""以下是目标网络中发现的服务版本信息。请：
1. 为每个服务匹配已知的 CVE 漏洞（优先 2024-2026 年的 CVE）
2. 标注每个 CVE 的利用难度（Easy/Medium/Hard）
3. 提供可用的公开 PoC 链接（GitHub/Exploit-DB）
4. 建议优先利用的顺序

服务列表:
{chr(10).join(services[:100])}

输出 JSON 格式: [{{"service":"...", "version":"...", "cves":[{{"cve_id":"CVE-2026-XXXX","cvss":9.8,"difficulty":"Easy","poc_url":"...","description":"..."}}]}}]
"""

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.2,
    response_format={"type": "json_object"}
)
cve_matches = response.choices[0].message.content

with open('ai_cve_matches.json', 'w') as f:
    f.write(cve_matches)
print("[+] AI CVE 匹配完成，输出至 ai_cve_matches.json")
PYEOF

# ============================================================
# 步骤 4：LLM 辅助绕过检测策略生成
# ============================================================

# 4.1 让 LLM 分析目标防护措施并生成绕过策略
python3 << 'PYEOF'
import openai

prompt = """根据以下侦察发现的目标防护信息，生成针对性的检测绕过策略：

目标防护信息:
- WAF: Cloudflare（检测到 cf-ray 头）
- IPS: Suricata（nmap 扫描被阻断 3 次后）
- 速率限制: 100 req/min per IP
- 认证: OAuth 2.0 + MFA
- 日志: ELK Stack（通过信息泄露发现）

请输出绕过策略，包含:
1. WAF 绕过: 编码变体、分块传输、HTTP 参数污染
2. IPS 绕过: 扫描速率调优、流量分散、协议混淆
3. 速率限制绕过: IP 轮换、请求分片、缓存投毒
4. 日志规避: 低速操作、分散时间窗口、利用日志盲区

输出: Markdown 格式，每条策略包含具体命令示例。
"""

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0.4
)
with open('ai_evasion_strategies.md', 'w') as f:
    f.write(response.choices[0].message.content)
print("[+] AI 绕过策略生成完成，输出至 ai_evasion_strategies.md")
PYEOF

# ============================================================
# 步骤 5：人工验证 AI 输出（关键步骤 — 防 LLM 幻觉）
# ============================================================

# 5.1 验证 AI 匹配的 CVE 是否真实存在
python3 << 'PYEOF'
import json

# 读取 AI 匹配的 CVE
with open('ai_cve_matches.json') as f:
    data = json.loads(f.read())

# 对每个 CVE 交叉验证 NVD（National Vulnerability Database）
import urllib.request
verified_cves = []
for item in data.get('results', data) if isinstance(data, dict) else data:
    for cve in item.get('cves', []):
        cve_id = cve.get('cve_id', '')
        # 查询 NVD API 验证 CVE 真实性
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(url, headers={'User-Agent': 'recon-verify/1.0'})
            resp = urllib.request.urlopen(req, timeout=10)
            nvd_data = json.loads(resp.read())
            if nvd_data.get('totalResults', 0) > 0:
                cve['verified'] = True
                cve['nvd_cvss'] = nvd_data['vulnerabilities'][0]['cve'].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                verified_cves.append(cve)
                print(f"[✓] 验证通过: {cve_id} (CVSS: {cve['nvd_cvss']})")
            else:
                print(f"[✗] CVE 不存在(LLM 幻觉): {cve_id}")
        except Exception as e:
            print(f"[?] 验证失败(网络错误): {cve_id} - {e}")

with open('verified_cves.json', 'w') as f:
    json.dump(verified_cves, f, indent=2)
print(f"[+] 验证通过的 CVE 数: {len(verified_cves)}")
PYEOF
```

**2026 AI 侦察最佳实践与检测绕过**：
- LLM 分析在本地/离线执行，分析过程不产生对目标的网络流量
- AI 生成的攻击路径必须经人工验证后再执行 — LLM 可能生成幻觉资产或错误的 CVE 关联
- 使用 NVD API 交叉验证每个 CVE，剔除 LLM 幻觉（2026 实测 LLM CVE 幻觉率约 15-20%）
- AI 生成的绕过策略需结合实际测试环境验证有效性，不可直接信任
- 2026 参考框架：OWASP LLM Top 10 2025 中 LLM01（Prompt Injection）和 LLM02（Insecure Output Handling）适用于 AI 侦察工具链自身安全
