# Detailed GDPR Compliance Assessment Workflow

## Phase 2: Article 30 Records Template (Extended)

### Small Company Exemption Analysis

Companies <250 employees are exempt from Article 30 ONLY if:
- Processing is occasional (NOT true for regular customer/employee data)
- Processing is not high-risk
- Processing excludes special categories (health, biometric, genetic, etc.)

**In practice**: This exempts almost no SaaS, e-commerce, HR, or B2C operators.

### Article 30 Fields (Complete)

```csv
Activity ID,Purpose,Legal Basis,Data Categories,Data Subjects,Recipients,Retention,Security Measures,DPO Contact
PROC-001,Customer relationship management,Contract (Art 6(1)(b)),Name|Email|Phone|Company|Job Title,B2B customers,Salesforce (processor)|Marketing team,5 years after contract end,TLS 1.3|AES-256|MFA|Access logs,dpo@company.com
PROC-002,Employee payroll processing,Legal obligation (Art 6(1)(c)),Name|SSN|Bank details|Tax info|Salary,Employees,ADP (processor)|Tax authority|Bank,7 years (legal requirement),AES-256|RBAC|Audit logs,dpo@company.com
PROC-003,Website analytics,Legitimate interest (Art 6(1)(f)),IP address|Browser|Pages viewed|Session duration,Website visitors,Google Analytics (processor),26 months,Pseudonymization|Cookies,dpo@company.com
```

### Common Article 30 Gaps

1. **Missing fields**: 47% of controllers omit "data retention period" (Article 30(1)(f))
2. **Vague purposes**: "Business operations" does not meet specificity requirement
3. **Processor confusion**: Article 28 DPAs not cross-referenced in Article 30 records
4. **International transfers**: No documentation of safeguards for non-EU processors

## Phase 3: Lawful Basis Decision Tree (Detailed)

### Consent (Article 6(1)(a))

**When to use**:
- Processing is optional (not required for service delivery)
- Can demonstrate freely given, specific, informed, unambiguous affirmative action
- Withdrawal mechanism is as easy as giving consent

**Red flags**:
- "By continuing to use our service" ≠ valid consent
- Pre-ticked boxes ≠ valid consent
- Bundled consent (accept all or lose service) ≠ freely given

**Verification checklist**:
```
[ ] Consent request uses plain language (Article 7(2))
[ ] Consent is granular (separate boxes for marketing, analytics, third-party sharing)
[ ] Withdrawal button/link is visible on same page as original consent
[ ] Consent records include: timestamp, version, scope, withdrawal mechanism
[ ] Children <16 require parental consent for online services (Article 8)
```

### Contract (Article 6(1)(b))

**When to use**:
- Processing is strictly necessary to fulfill a contract with the data subject
- Examples: Processing shipping address to deliver purchased goods, processing payment details for subscription service

**Red flags**:
- "Necessary for contract" claimed for ancillary marketing activities (not true)
- Contract basis for cookies/analytics (usually legitimate interest, not contract)

### Legitimate Interest (Article 6(1)(f))

**Three-part test** (WP29 Opinion 06/2014):
1. **Purpose test**: Is the interest real and present (not speculative)?
2. **Necessity test**: Is processing necessary, or could you use less intrusive means?
3. **Balancing test**: Do data subject rights override your legitimate interest?

**Common legitimate interests**:
- Fraud prevention and network security (Recital 49)
- Direct marketing to existing customers (Recital 47, but with objection right)
- Intra-group administrative transfers (Recital 48)

**Documentation required**:
```markdown
## Legitimate Interest Assessment: Website Analytics

**Purpose**: Improve website user experience and detect technical errors

**Necessity**: 
- Analytics data (pages viewed, session duration) necessary to identify UX friction
- Pseudonymized IP addresses sufficient (full IPs not retained)
- Alternative (user surveys) would not provide real-time technical error detection

**Balancing**:
- Data subjects: Website visitors, minimal expectation of privacy for navigational data
- Impact: Low (no profiling, no automated decisions, no special categories)
- Safeguards: IP pseudonymization, 26-month retention, opt-out via cookie banner

**Conclusion**: Legitimate interest established, objection right provided in privacy policy
```

## Phase 4: Data Subject Rights Response Times

### Article 12(3) Timeline

**Default**: Respond within **one month** of receipt

**Extension**: May extend by **two further months** if complex or numerous requests

**Requirements**:
- Must inform data subject of extension within original one-month period
- Must explain reason for extension

### 2025 ICO Statistics

- **Average DSAR response time**: 18 days
- **Compliance rate**: 73% responded within one month
- **Most common delays**: Distributed data across multiple systems (42%), identity verification disputes (28%), unclear request scope (19%)

### Technical Implementation Requirements

1. **Identity verification** (Article 12(6))
   - Request additional information if doubt about identity
   - But: Cannot ask for excessive ID documents
   - Passport/driving license photocopy is standard practice

2. **Response format** (Article 15(3))
   - "Commonly used electronic format" if requested electronically
   - CSV, PDF, or API access (JSON) are acceptable
   - Must be machine-readable (scanned paper ≠ compliant)

3. **Fee exceptions** (Article 12(5))
   - First request: Free
   - Subsequent requests: May charge "reasonable fee based on administrative costs" if manifestly unfounded or excessive
   - ICO threshold: £10-50 for excessive requests (not first requests)

4. **Logging requirements** (Article 30(2) + accountability)
   - Log all DSARs received (date, scope, response deadline)
   - Log verification method used
   - Log data delivered (systems queried, records provided)
   - Retention: 6 years (evidence of compliance)

## Phase 5: DPIA Templates (Detailed)

### Article 35(3) Mandatory DPIA Triggers

A DPIA is **mandatory** when processing:

1. **Systematic and extensive profiling** with automated decision-making producing legal/similarly significant effects
   - Example: Credit scoring determining loan eligibility
   - Example: AI-driven employee performance evaluation affecting termination decisions

2. **Large-scale processing of special categories** (Article 9) or criminal conviction data (Article 10)
   - "Large-scale" factors: number of data subjects, volume of data, duration, geographical extent
   - Example: Health insurer processing 500,000+ patient records
   - Example: National background check service processing criminal records

3. **Systematic monitoring of publicly accessible areas on a large scale**
   - Example: CCTV with facial recognition in shopping malls
   - NOT required: Single-location CCTV without biometric processing

### DPIA Template Sections

```markdown
## 1. Description of Processing Operation

**Name**: AI-Powered Recruitment Screening System
**Controller**: XYZ Corp
**DPO Contact**: dpo@xyzcorp.com
**Processing purpose**: Automatically screen CVs, rank candidates, flag high-potential applicants
**Legal basis**: Legitimate interest (efficient recruitment)
**Data categories**: Name, CV content (education, employment history, skills), LinkedIn profile (if provided)
**Special categories**: None processed (no health, ethnicity, political views extracted)
**Data subjects**: Job applicants
**Recipients**: HR team, hiring managers
**Retention**: 6 months after recruitment process ends (unless consent obtained for future roles)
**International transfers**: None (all processing within EU)

## 2. Necessity and Proportionality

**Is processing necessary for the stated purpose?**
Yes — automated screening of 2,000+ applications per role is impractical manually; human review of flagged candidates follows AI screening.

**Could you achieve the purpose with less intrusive means?**
Considered: Keyword-only matching (less effective, misses semantic skills). Could reduce data retention to 3 months (implemented).

**Is data minimization applied?**
Yes — System does NOT process: age, photo, address (only city for location-based roles), gender, marital status.

## 3. Risks to Rights and Freedoms

| Risk | Likelihood | Severity | Impact |
|------|-----------|----------|---------|
| Algorithmic bias (gender, ethnicity) leading to discriminatory screening | Medium | High | Discrimination in employment decisions violates GDPR Article 22 and Equality Act 2010 |
| Data breach exposing applicant CVs | Low | Medium | Reputational harm, identity theft if combined with contact details |
| Lack of transparency in AI decision logic | High | Medium | Applicants cannot effectively challenge decisions (Article 22(3)) |

## 4. Measures to Address Risks

**Risk 1 mitigation**:
- Bias audit every 6 months (test for demographic parity, equal opportunity)
- Training data balanced across protected characteristics
- Human review of all "rejected" candidates (AI only flags "proceed to interview")

**Risk 2 mitigation**:
- AES-256 encryption at rest, TLS 1.3 in transit
- Access control: HR team only (RBAC with audit logs)
- Penetration test annually

**Risk 3 mitigation**:
- Privacy policy explains AI screening in plain language
- Applicants can request human review of rejection (Article 22(3))
- Provide explanation of key factors in AI decision upon request

## 5. Consultation

**Consulted parties**:
- DPO: Reviewed and approved DPIA (Article 35(2))
- ICO: Not required (no novel high-risk processing; standard AI recruitment within EDPB guidelines)
- Data subjects: Privacy policy updated to describe AI screening; feedback channel provided

**Date completed**: 2026-03-15
**Next review**: 2027-03-15 or upon material change to processing
```

## Phase 6: Breach Notification Decision Tree

### "Likely to Result in Risk" Assessment (Article 33)

**Notify supervisory authority within 72 hours** if breach is likely to result in risk to rights.

**Risk factors** (WP29 Guidelines WP250rev.01):
- Type of breach: Confidentiality (unauthorized access), availability (data loss/destruction), integrity (unauthorized modification)
- Nature of personal data: Special categories (Article 9) = high risk
- Ease of identification: Encrypted data breached = lower risk if key not compromised
- Severity of consequences: Financial loss, discrimination, reputational damage, identity theft
- Special characteristics: Children, vulnerable individuals = higher risk
- Number of affected individuals: 10 individuals with special categories = higher risk than 1,000 individuals with generic email addresses

### Example: Notify or Not?

**Scenario 1**: Laptop stolen containing 500 employee records (names, salaries, SSNs)
- **Decision**: **NOTIFY** (72 hours)
- **Rationale**: Unencrypted SSNs = high risk of identity theft
- **Article 34**: Also notify data subjects without undue delay

**Scenario 2**: Marketing database backup (encrypted AES-256) stolen, but encryption key NOT compromised
- **Decision**: **Do NOT notify** (unless key later compromised)
- **Rationale**: Encrypted data without key poses minimal risk
- **Documentation**: Internal breach log maintained (Article 33(5))

**Scenario 3**: Technical error causes customer order history (product names, dates, no financials) to be visible to other customers for 2 hours before fix
- **Decision**: **NOTIFY** (72 hours)
- **Rationale**: Confidentiality breach affecting 1,200 customers; low individual risk but large scale triggers reporting
- **Article 34**: Low individual risk = notification not required to data subjects

### Breach Notification Content (Article 33(3))

**Minimum required fields**:
1. Nature of breach (confidentiality, availability, integrity)
2. Categories and approximate number of data subjects
3. Categories and approximate number of records
4. Name and contact of DPO or other contact point
5. Likely consequences of the breach
6. Measures taken or proposed to address the breach and mitigate adverse effects

**Template**:
```
To: ICO Breach Notification (via online form)
Date: 2026-08-24 14:30 UTC

Breach Reference: BREACH-2026-0824
Reporting Organization: XYZ Corp (ICO Registration: Z1234567)
DPO Contact: dpo@xyzcorp.com, +44 20 1234 5678

Nature of Breach: Confidentiality - Unauthorized access via compromised admin credential

Data Subjects Affected: Approximately 1,200 customers
Records Compromised: Names, email addresses, order history (product names, dates, amounts), shipping addresses

Breach Discovery: 2026-08-24 12:00 UTC (monitoring alert for unusual admin database queries)
Breach Occurrence: Estimated 2026-08-23 22:00 UTC to 2026-08-24 11:30 UTC (13.5 hours)

Likely Consequences: Low individual risk - no financial details or passwords compromised; moderate risk of targeted phishing using order history

Measures Taken:
- Compromised credential revoked 2026-08-24 11:30 UTC
- All admin credentials force-reset
- MFA enforcement deployed
- Forensic analysis initiated (external consultant engaged)

Measures Proposed:
- Customer notification (Article 34) by email within 48 hours describing breach, advising phishing vigilance
- SOC 2 Type 2 audit brought forward to Q3 2026
- Penetration test scheduled for 2026-09-15
```

## Phase 7: International Transfer Mechanisms (Extended)

### Standard Contractual Clauses (SCCs) 2021

**When to use**:
- Transferring personal data to non-EU country without adequacy decision
- Most common mechanism post-Schrems II

**Implementation**:
1. Download SCCs from European Commission website
2. Choose appropriate module:
   - Module 1: Controller to Controller
   - Module 2: Controller to Processor
   - Module 3: Processor to Processor
   - Module 4: Processor to Controller

3. Complete Annex I (parties, data subjects, data categories, special categories, processing purpose, retention)
4. Complete Annex II (technical/organizational measures — reference Article 32 controls)
5. Complete Annex III (sub-processors list)

6. **Schrems II compliance**:
   - Assess laws of destination country (do government surveillance laws permit access to personal data?)
   - Document assessment in Annex (new requirement)
   - Implement supplementary measures if country laws undermine SCCs (e.g., additional encryption)

**Red flags**:
- Using pre-2021 SCCs (invalid as of December 27, 2022)
- Failing to assess destination country laws (Schrems II requirement)
- Generic Annex II measures not tailored to actual data transferred

### Adequacy Decisions (Current 2026)

**Countries with adequacy**:
- Andorra, Argentina, Canada (commercial), Faroe Islands, Guernsey, Israel, Isle of Man, Japan, Jersey, New Zealand, South Korea, Switzerland, United Kingdom, Uruguay

**United States**: No blanket adequacy (Schrems I invalidated Safe Harbor, Schrems II invalidated Privacy Shield)
- Use SCCs for US transfers
- Exception: Data Privacy Framework (DPF) certification (launched 2023) — US companies can self-certify for adequacy

### Transfer Impact Assessment (TIA)

**EDPB Recommendations 01/2020** require Transfer Impact Assessment before relying on SCCs:

```markdown
## Transfer Impact Assessment: AWS US-East-1 Processing

**Destination country**: United States
**Recipient**: Amazon Web Services Inc. (DPF-certified)

**Step 1: Map Data Transfer**
- Personal data: Customer names, emails, encrypted payment tokens
- Transfer purpose: Cloud hosting of SaaS application
- Transfer mechanism: SCCs Module 2 (Controller to Processor)

**Step 2: Assess Destination Country Laws**
- FISA Section 702: Permits NSA access to communications of non-US persons
- CLOUD Act: Permits US law enforcement to compel data disclosure
- Risk: Payment tokens are encrypted with EU-held keys (inaccessible to US authorities)

**Step 3: Evaluate Supplementary Measures**
- Encryption: AES-256 with keys held in EU (AWS KMS EU region)
- Pseudonymization: Customer IDs are pseudonymized UUIDs
- Contractual: AWS DPF certification + SCCs
- Organizational: AWS resists overbroad government requests (transparency report published)

**Step 4: Conclusion**
Transfer may proceed. Encryption keys held exclusively in EU provide supplementary measure ensuring US government access would yield only encrypted data. No FISA 702 precedent for compelling decryption keys held outside US jurisdiction.

**Review date**: 2027-08-24 or upon change to US surveillance laws
```

## Phase 8: Article 32 Security Measures (Extended)

### Security Appropriate to the Risk

**Low Risk** (generic non-sensitive data, small scale):
- TLS 1.2+ for data in transit
- Password hashing (bcrypt, Argon2)
- Access logging
- Regular patching

**Medium Risk** (larger scale, potential for harm):
- AES-256 encryption at rest
- MFA for admin accounts
- RBAC with least privilege
- Annual penetration testing
- SOC 2 Type 2 audit

**High Risk** (special categories, large scale, children, automated decision-making):
- Hardware security modules (HSMs) for key management
- Encryption key rotation every 90 days
- Continuous security monitoring (SIEM)
- Bug bounty program
- ISO 27001 certification
- Regular DPIA reviews

### Pseudonymization vs. Anonymization

**Pseudonymization** (Article 4(5)):
- Replaces identifiers with pseudonyms (e.g., hash, UUID)
- Re-identification **possible** with additional information (kept separately)
- Still considered personal data under GDPR
- Recommended security measure (Article 32(1)(a))

**Anonymization**:
- Removes all identifiers such that re-identification is **not possible**
- No longer personal data (Recital 26)
- GDPR no longer applies
- Hard to achieve in practice (linkage attacks, de-anonymization research)

**Example**:
- Original: John Doe, john@example.com, IP 192.168.1.1
- Pseudonymized: User-abc123, hashed-email-xyz, IP *.*.1.1 (retain last octet for geolocation)
- Anonymized: Aggregated count "500 users from London accessed feature X" (no individual records)

### Data Retention Limits (Article 5(1)(e))

**No fixed retention periods** in GDPR (unlike CCPA's 12 months for sale opt-outs). Controller must define and justify retention.

**Common justifications**:
- **Contract fulfillment**: Retain customer data for duration of contract + reasonable period for warranty claims (e.g., 2 years)
- **Legal obligation**: Tax records 7 years, employment records per national labor law
- **Legitimate interest**: Marketing data retained while interest remains (typically 2-3 years of no interaction = delete)

**Best practice**:
- Document retention schedule in Article 30 records
- Implement automated deletion workflows (not "we'll delete if requested")
- "Retention period review" in annual GDPR compliance audit

### Automated Deletion Script Example

```python
# automated_deletion.py - GDPR Article 5(1)(e) Retention Limits
import psycopg2
from datetime import datetime, timedelta

# Configuration: Retention policies (days)
RETENTION_POLICIES = {
    "marketing_leads": 730,      # 2 years (legitimate interest)
    "customer_orders": 2555,     # 7 years (legal obligation - tax)
    "support_tickets": 1095,     # 3 years (contract fulfillment)
    "website_analytics": 780     # 26 months (legitimate interest)
}

def delete_expired_data(table, retention_days):
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
    conn = psycopg2.connect("dbname=gdpr_app user=app_user password=secret")
    cursor = conn.cursor()
    
    # Log deletion for Article 30 compliance
    cursor.execute(f"""
        INSERT INTO gdpr_deletion_log (table_name, deletion_date, records_deleted)
        SELECT '{table}', NOW(), COUNT(*)
        FROM {table}
        WHERE created_at < %s
    """, (cutoff_date,))
    
    # Perform deletion
    cursor.execute(f"DELETE FROM {table} WHERE created_at < %s", (cutoff_date,))
    
    conn.commit()
    cursor.close()
    conn.close()
    
    print(f"[{datetime.now()}] Deleted records from {table} older than {cutoff_date}")

if __name__ == "__main__":
    for table, retention in RETENTION_POLICIES.items():
        delete_expired_data(table, retention)
```

**Schedule**: Run daily via cron (0 2 * * * /usr/bin/python3 /opt/gdpr/automated_deletion.py)
