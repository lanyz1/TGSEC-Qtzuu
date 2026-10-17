# Bug Bounty - Methodology
A structured methodology for performing organized reconnaissance, security research, vulnerability discovery, validation, and responsible reporting during authorized bug bounty programs.

---

# Overview
A successful bug bounty workflow is not only about finding vulnerabilities.
A professional methodology focuses on:
- Understanding the target
- Mapping the attack surface
- Prioritizing interesting assets
- Testing systematically
- Documenting findings clearly
- Reporting responsibly

---

# Phase 1 - Program Understanding
Before any research:
Review:
- Program scope
- Allowed assets
- Out-of-scope assets
- Testing restrictions
- Rate limits
- Reporting requirements
- Reward information

Create a scope document:
| Field | Description |
|---|---|
| Program | Target program |
| Assets | Allowed targets |
| Restrictions | Testing limitations |
| Notes | Important rules |

---

# Phase 2 - Reconnaissance
Goal:
Build a complete understanding of the target environment.
Collect:
- Domains
- Subdomains
- IP addresses
- Applications
- APIs
- Technologies
- Public resources
- Documentation

---

# Passive Reconnaissance
Passive recon means collecting publicly available information without directly interacting with target systems.
Sources:
- Search engines
- Public documentation
- Public repositories
- Certificate information
- Public records
- Archived resources

Examples of collected information:
- Subdomains
- Technologies
- Public files
- API documentation

---

# Active Reconnaissance
Active reconnaissance involves interacting with authorized target infrastructure.
Examples:
- Checking services
- Reviewing application behavior
- Mapping endpoints

Always confirm:
- Authorization
- Scope
- Testing limits

---

# Phase 3 - Asset Mapping
Create an attack surface map.
Organize:

## Domains
- Main domains
- Subdomains

## Applications
- Web applications
- Mobile applications
- APIs

## Infrastructure
- Servers
- Cloud resources
- Services

## Technologies
- Frameworks
- Libraries
- Platforms

---

# Phase 4 - Endpoint Discovery
Identify:
- URLs
- Routes
- API endpoints
- Parameters
- Forms
- Authentication flows

Document:
| Endpoint | Function | Notes |
|---|---|---|
| /login | Authentication | Login system |
| /api | API | Application interface |

---

# Phase 5 - Vulnerability Research
Prioritize areas based on:
- Application functionality
- User impact
- Security importance

Common research areas:
- Authentication
- Authorization
- IDOR / BOLA
- XSS
- SSRF
- SQL Injection
- File Upload
- CORS
- Open Redirect
- Information Disclosure

---

# Phase 6 - Validation
A finding should be validated before reporting.
Confirm:
- Is it reproducible?
- Is it within scope?
- Does it have security impact?
- Can the behavior be explained clearly?

Avoid:
- Unnecessary testing
- Excessive requests
- Data exposure
- Destructive actions

---

# Phase 7 - Documentation
A professional report should include:

## Title
A clear vulnerability description.
Example:
"Broken Object Authorization in User Profile API"

## Summary
Short explanation of the issue.

## Steps To Reproduce
Clear and repeatable steps.

## Impact
Explain security consequences.

## Evidence
Include:
- Screenshots
- Requests
- Responses
- Relevant details

## Recommendation
Suggest possible mitigation.

---

# Prioritization Model
## High Priority
Examples:
- Account compromise
- Sensitive data exposure
- Critical authorization issues

## Medium Priority
Examples:
- Limited information disclosure
- Security control weaknesses

## Low Priority
Examples:
- Minor configuration issues
- Low-impact findings

---

# Research Notes Management
Keep organized notes:
Recommended structure:
Target/
├── Recon/
├── Assets/
├── Endpoints/
├── Technologies/
├── Findings/
└── Reports/

---

# Continuous Improvement
Improve skills by:
- Reading security reports
- Studying vulnerability classes
- Practicing on labs
- Reviewing disclosed findings
- Learning new technologies

---

# Bug Bounty Checklist
## Preparation
- [ ] Program rules reviewed
- [ ] Scope confirmed
- [ ] Testing limits understood

## Recon
- [ ] Domains collected
- [ ] Subdomains identified
- [ ] Technologies identified
- [ ] Endpoints mapped
- [ ] APIs reviewed

## Research
- [ ] Authentication reviewed
- [ ] Authorization reviewed
- [ ] Input handling reviewed
- [ ] Business logic reviewed

## Reporting
- [ ] Vulnerability confirmed
- [ ] Impact explained
- [ ] Evidence collected
- [ ] Report written clearly

---

# Important Notes
- Finding a possible issue is not the same as confirming a vulnerability.
- Always respect authorization boundaries.
- Avoid impacting users or production systems.
- Follow responsible disclosure practices.
- Quality is more important than quantity.

---

# Responsible Research
A professional security researcher focuses on:
- Permission
- Accuracy
- Minimal impact
- Clear communication
- Responsible disclosure
The goal is to help improve security, not to damage systems.