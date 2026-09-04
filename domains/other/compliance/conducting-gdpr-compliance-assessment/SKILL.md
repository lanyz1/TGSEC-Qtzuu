---
name: conducting-gdpr-compliance-assessment
description: >-
  Conduct comprehensive GDPR compliance assessments by evaluating data processing
  activities against EU Regulation 2016/679, including Article 30 records of processing,
  lawful basis validation, data subject rights implementation, Data Protection Impact
  Assessments (DPIAs) under Article 35, breach notification procedures, international
  transfer safeguards (SCCs, adequacy decisions), and technical/organizational measures
  under Article 32. Use when processing personal data of EU residents, preparing for
  supervisory authority audits, implementing privacy-by-design for new systems, scoping
  compliance gaps for M&A due diligence, assessing third-party processors, or responding
  to data subject access requests at scale. Incorporates 2026 guidance from ICO, EDPB,
  and post-Data (Use and Access) Act 2025 UK-GDPR considerations. Do not use for implementing
  specific Article 32 controls — use implementing-gdpr-data-protection-controls; or for DSAR
  automation — use implementing-gdpr-data-subject-access-request.
domain: cybersecurity
subdomain: compliance-governance
tags:
- gdpr
- data-protection
- privacy
- compliance
- dpia
- data-subject-rights
- article-30
- controller
- processor
- eu-regulation
- ico
- supervisory-authority
version: "1.0"
author: dakshverma23
license: Apache-2.0
nist_csf:
- GV.OC-02
- GV.PO-01
- GV.RM-04
- PR.DS-01
- PR.DS-02
- ID.AM-05
mitre_attack:
- T1530
- T1567
---
# Conducting GDPR Compliance Assessment

> **Effective Date**: August 2026  
> **Legal Basis**: EU Regulation 2016/679 (GDPR), UK GDPR as amended by Data Protection Act 2018 and Data (Use and Access) Act 2025 (ukpga/2025/18)  
> **Pending Changes**: Digital Omnibus proposal (COM(2025) 837) would change Article 30(5) threshold from 250 to 750 employees and Article 33 breach notification from 72h to 96h. Still in proposal stage; current requirements remain in force.

## When to Use

- When an organization **processes personal data of EU residents** (Article 3 territorial scope applies)
- When preparing for a **supervisory authority audit** (ICO, CNIL, BfDI) or responding to formal inquiry
- When implementing **privacy-by-design** requirements (Article 25) for new systems or data flows
- When **scoping compliance gaps** before M&A due diligence or contract negotiations with EU entities
- When responding to **data subject access requests (DSARs)** and discovering gaps in data inventory
- When assessing **third-party processors** for GDPR compliance before signing Data Processing Agreements (DPAs)
- After **data breach incidents** to verify notification procedures meet 72-hour requirement (Article 33)

**Do not use** for:
- **Technical implementation** of specific GDPR controls (encryption, pseudonymization, access controls) — use **implementing-gdpr-data-protection-controls** for Article 32 technical/organizational measures
- **Automated DSAR processing workflows** (identity verification, PII discovery, redaction, delivery) — use **implementing-gdpr-data-subject-access-request** for DSAR automation
- Non-EU privacy frameworks alone (CCPA, PIPEDA, LGPD); those require separate assessments with jurisdiction-specific criteria
- This skill is for **comprehensive compliance assessment** across all GDPR articles; use the specialized skills for focused implementation tasks

## Prerequisites

- Understanding of GDPR Articles 5-32 and key definitions
- Access to Article 30 records of processing activities
- Data Processing Agreements with third-party processors
- Privacy policies, consent forms, cookie notices
- Knowledge of lawful bases (Article 6)
- Data breach response plan and incident register
- List of international data transfers with safeguards

## Workflow

**For detailed procedures, templates, and examples, see `references/detailed-workflow.md`**

### Phase 1: Determine Territorial Applicability (Article 3)

GDPR applies if:
1. Organization has establishment in EU
2. Offers goods/services to EU residents
3. Monitors behavior of EU residents

**Check**: EU office? EU website targeting? Behavioral tracking?

### Phase 2: Inventory Data Processing Activities (Article 30)

Document for EACH activity:
- Controller/processor details
- Processing purposes (specific)
- Data categories and special categories (Art. 9)
- Recipients and international transfers
- Retention periods
- Security measures

**Tools**: Use `scripts/article30_parser.py`, `article30_validator.py`, `generate_ropa_report.py`

**Common gaps**: Missing retention periods (68%), vague purposes, undocumented transfers

### Phase 3: Validate Lawful Basis (Article 6)

| Basis | Use Case | Key Requirement |
|-------|----------|-----------------|
| **Consent** (6(1)(a)) | Marketing, profiling | Freely given, specific, withdrawable |
| **Contract** (6(1)(b)) | Order fulfillment | Strictly necessary only |
| **Legal Obligation** (6(1)(c)) | Tax records | Cite specific law |
| **Legitimate Interest** (6(1)(f)) | Fraud prevention, analytics | Three-part test + balancing |

**Action**: Map each Article 30 activity to one lawful basis. Document legitimate interest assessments.

### Phase 4: Assess Data Subject Rights (Articles 12-23)

Verify capability for:
- **Access** (15): Provide copy in machine-readable format within 1 month
- **Rectification** (16): Correct inaccurate data
- **Erasure** (17): "Right to be forgotten" (with exceptions)
- **Portability** (20): Transfer data in structured format
- **Objection** (21): Opt-out of legitimate interest processing
- **Automated Decision-Making** (22): Human review of algorithmic decisions

**Test**: Process sample DSAR through full workflow. Use `scripts/` for automation.

### Phase 5: Review DPIAs (Article 35)

DPIA **mandatory** for:
- Large-scale profiling with automated decisions
- Large-scale special categories processing
- Systematic monitoring of public areas (facial recognition)

**Template**: See `references/detailed-workflow.md` for complete DPIA structure

**Content**: Description, necessity, risks, mitigation, consultation (DPO, supervisory authority if novel high-risk)

### Phase 6: Audit Breach Notification (Articles 33-34)

**72-hour rule**: Notify supervisory authority within 72 hours of becoming aware of breach likely to risk rights.

**Decision tree**:
- Unencrypted SSNs stolen? → NOTIFY + notify data subjects
- Encrypted backup stolen (key secure)? → Document only
- Temporary exposure (2 hours, no financial data)? → NOTIFY authority, assess data subject notification

**Content**: Nature, categories/numbers, DPO contact, consequences, mitigation

### Phase 7: Verify International Transfers (Chapter V)

**Mechanisms**:
- Adequacy decisions (UK, Japan, etc.)
- Standard Contractual Clauses (SCCs) 2021 + Transfer Impact Assessment
- Binding Corporate Rules (BCRs)
- Derogations (Article 49 - limited)

**Post-Schrems II**: Assess destination country surveillance laws, implement supplementary measures (encryption with EU-held keys)

### Phase 8: Assess Security Measures (Article 32)

"Security appropriate to the risk":
- **Low risk**: TLS 1.2+, password hashing, access logs, patching
- **Medium risk**: AES-256 encryption, MFA, RBAC, penetration testing, SOC 2
- **High risk**: HSMs, key rotation, SIEM, bug bounty, ISO 27001

**Pseudonymization** vs. **Anonymization**: Pseudo = reversible (still personal data); Anon = irreversible (no longer GDPR)

### Phase 9: Compile Findings and Remediation Roadmap

Generate compliance report:
- Executive summary (overall status, high-priority gaps)
- Article-by-article findings
- Risk-prioritized remediation plan (Critical/High/Medium/Low)
- Cost estimates and timelines
- Responsible parties (DPO, IT, Legal, Business)

**Format**: See Output Format section below

## Key Concepts

| Term | Definition |
|------|------------|
| **Controller** | Determines purposes and means of processing (Article 4(7)) |
| **Processor** | Processes on behalf of controller (Article 4(8); requires DPA per Article 28) |
| **Personal Data** | Any information relating to identified/identifiable natural person (Article 4(1)) |
| **Special Categories** | Health, biometric, genetic, racial, political, religious, trade union, sex life data (Article 9; heightened protection) |
| **Consent** | Freely given, specific, informed, unambiguous indication of wishes (Article 4(11)) |
| **Legitimate Interest** | Lawful basis requiring three-part test: purpose, necessity, balancing (Recital 47) |
| **DPIA** | Data Protection Impact Assessment for high-risk processing (Article 35) |
| **DPO** | Data Protection Officer (Article 37; mandatory for public authorities, large-scale monitoring/special categories) |
| **SCCs** | Standard Contractual Clauses for international transfers (Commission Implementing Decision 2021/914) |
| **Supervisory Authority** | National data protection regulator (ICO for UK, CNIL for France, BfDI for Germany) |

## Tools & Systems

- **ICO Self-Assessment**: https://ico.org.uk/for-organisations/sme-web-hub/checklists/gdpr-check-list/
- **EDPB Guidelines**: https://edpb.europa.eu/our-work-tools/general-guidance_en
- **OneTrust / TrustArc**: Commercial GRC platforms with DPIA, Article 30, cookie consent modules
- **Article 30 Scripts**: `article30_parser.py`, `article30_validator.py` (included)
- **SCCs (2021)**: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/standard-contractual-clauses-scc_en
- **DPO Certification**: IAPP CIPP/E (Certified Information Privacy Professional/Europe)

## Common Scenarios

### Scenario: M&A Due Diligence

**Context**: Acquiring SaaS company with 50K EU customers. Need compliance assessment within 2 weeks.

**Approach**:
1. Request Article 30 records + DPAs with processors (AWS, Stripe, Mailchimp)
2. Validate lawful basis: Consent for marketing, Contract for service delivery
3. Check breach notification procedures (Article 33): No procedures found → HIGH RISK
4. Review international transfers: AWS US-East-1 without SCCs → BLOCKER
5. Deliverable: Gap analysis with remediation costs ($120K for SCCs + DPO hire + breach procedures)

### Scenario: Supervisory Authority Audit

**Context**: ICO formal inquiry after consumer complaint about unsubscribe not working.

**Response**:
1. Produce Article 30 records within 7 days
2. Demonstrate consent records (timestamp, version, scope)
3. Show withdrawal mechanism (unsubscribe link functional, processed within 48h)
4. Provide audit logs of DSAR/erasure requests
5. Outcome: Warning + 3-month corrective order (no fine due to cooperation)

## Output Format

```
GDPR COMPLIANCE ASSESSMENT REPORT
===================================
Organization: XYZ Corp | Assessment Date: 2026-08-24
Assessor: Jane Smith, CIPP/E | DPO: dpo@xyzcorp.com

EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━
Overall Status: PARTIAL COMPLIANCE (67/100)
Critical Gaps: 3 | High: 5 | Medium: 8 | Low: 12

CRITICAL FINDINGS
━━━━━━━━━━━━━━━━━
1. Article 33: No breach notification procedures (72-hour deadline unmet)
2. Chapter V: International transfers to US without SCCs (Schrems II violation)
3. Article 30: Records incomplete (retention periods missing for 40% of activities)

ARTICLE-BY-ARTICLE STATUS
━━━━━━━━━━━━━━━━━━━━━━━━
✅ Article 3: Applicability confirmed (EU establishment)
⚠️  Article 6: Lawful basis documented but 3 activities use invalid bundled consent
✅ Article 15-23: DSAR procedures operational (18-day avg response time)
❌ Article 28: 40% of processors lack signed DPAs
⚠️  Article 32: Encryption at rest implemented but no MFA on admin accounts
❌ Article 33/34: No breach notification procedures
⚠️  Article 35: DPIA completed for profiling but not reviewed in 18 months
❌ Chapter V: US transfers without SCCs

REMEDIATION ROADMAP
━━━━━━━━━━━━━━━━━━━
Priority 1 (0-30 days, $50K):
  - Implement breach notification procedures + incident register
  - Execute SCCs with AWS, Stripe (Module 2)
  - Complete Article 30 records (retention periods, security measures)

Priority 2 (1-3 months, $80K):
  - Execute DPAs with remaining 8 processors
  - Deploy MFA on all admin accounts
  - Conduct legitimate interest assessments for analytics

Priority 3 (3-6 months, $40K):
  - Review and update DPIA
  - Automated DSAR response workflow
  - Annual GDPR training for staff

COMPLIANCE SCORE: 67/100 → Target 90/100 (6 months post-remediation)
```

## Verification Checklist

- [ ] Article 3 applicability determination documented
- [ ] Article 30 records complete for all activities (controller + processor roles)
- [ ] Lawful basis identified and documented for each activity
- [ ] Legitimate interest assessments documented with balancing test
- [ ] Consent mechanism is granular, withdrawable, and logged
- [ ] Data subject rights procedures operational (1-month response time)
- [ ] DPIA completed for high-risk processing (profiling, special categories, monitoring)
- [ ] Breach notification procedures documented (72-hour timeline)
- [ ] DPAs executed with all processors (Article 28 requirements)
- [ ] International transfers use SCCs 2021 + Transfer Impact Assessment
- [ ] Security measures appropriate to risk (encryption, MFA, logging, testing)
- [ ] Retention periods defined and automated deletion implemented
- [ ] Privacy policy published and updated within 12 months
- [ ] DPO designated if required (Article 37 criteria met)
- [ ] Staff trained on GDPR principles and data subject rights

