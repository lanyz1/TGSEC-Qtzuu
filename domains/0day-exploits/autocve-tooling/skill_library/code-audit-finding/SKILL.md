---
name: "code-audit-finding"
description: "DeepAudit Finding overlay for source-code auditing with code-audit-main references, mandatory reading routes, and progressive WooYun disclosure."
tags: ["finding", "code-audit", "source-audit", "auth", "idor", "business-logic"]
---

# Code Audit Finding Overlay

This skill adapts the `code-audit-main` knowledge base for DeepAudit's `Finding` agent.

Use this skill to strengthen source-code auditing for:
- authorization and access-control flaws
- IDOR and tenant-isolation issues
- business-logic and state-machine flaws
- file operations and path handling
- input-validation gaps
- attack-chain driven source-to-sink review

This skill keeps DeepAudit's current role split intact:
- `recon` provides project navigation and scope
- `finding` produces source-audit conclusions
- `verification` performs follow-up validation

## Required Startup Protocol

1. Read this `SKILL.md` first with `load_skill_body`.
2. Use `skill_resource_lookup(mode="list")` before opening a new reference directory family.
3. Use `skill_resource_lookup(mode="read")` for every required file you rely on.
4. Do not claim a checklist, framework rule, control requirement, or case pattern unless you have actually read the corresponding file.

## Fixed-First Reading Order

After reading this `SKILL.md`, always read these files first:
- `references/core/anti_hallucination.md`
- `references/core/false_positive_filter.md`
- `references/checklists/coverage_matrix.md`
- `references/core/comprehensive_audit_methodology.md`
- `references/core/data_flow_methodology.md`
- `references/core/taint_analysis.md`

## Conditional Mandatory Reading

After the fixed-first set, route by project signals:

- Languages:
  - `references/checklists/<language>.md`
  - `references/languages/<language>.md`
- Frameworks:
  - `references/frameworks/<framework>.md`
- Security domains:
  - `references/security/authentication_authorization.md`
  - `references/security/business_logic.md`
  - `references/security/file_operations.md`
  - `references/security/input_validation.md`
  - `references/security/api_security.md`
  - `references/security/race_conditions.md`
  - plus other matching files under `references/security/`
- Control verification:
  - `references/adapters/<language>.yaml`

## Finding-Specific Constraints

- Audit must stay evidence-driven.
- Cases and historical vulns can guide search direction, but they never count as evidence.
- If you have not read the relevant reference file, do not say that topic is fully audited.
- If you want to claim a missing control at high confidence, read the matching adapter first.
- Use the references to guide code reading, not to replace code reading.

## Progressive Disclosure for WooYun and Cases

Use four levels of disclosure:

1. Default:
   - do not preload WooYun case bodies
2. Index first:
   - read `references/wooyun/INDEX.md`
3. Evidence-gated expansion:
   - only after you already have project-specific code evidence may you read one or two related case files
4. Strict evidence boundary:
   - WooYun and real-world cases only expand search directions, bypass ideas, and missed-check hints
   - they do not justify a finding on their own

Relevant case sources:
- `references/wooyun/`
- `references/cases/real_world_vulns.md`

## Intentionally Excluded From Required Runtime Flow

`agent.md` is preserved in this skill root for reference, but its deep multi-agent orchestration is not part of Finding's required runtime reading path.

The original upstream `SKILL.md` is preserved at:
- `references/core/original_skill_reference.md`
