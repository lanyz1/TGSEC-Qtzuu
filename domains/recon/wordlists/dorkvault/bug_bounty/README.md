# Bug Bounty Dorks
A curated collection of reconnaissance queries, discovery techniques, vulnerability-oriented research resources, and methodologies for authorized bug bounty programs.

---

## Contents
### Reconnaissance
- [Reconnaissance](reconnaissance.md)
- [Subdomains](subdomains.md)
- [Assets](assets.md)
- [Endpoints](endpoints.md)
- [Parameters](parameters.md)
- [APIs](apis.md)
- [JavaScript](javascript.md)

### Authentication & Authorization
- [Authentication](Authentication.md)
- [IDOR / BOLA](idor_bola.md)

### Vulnerability Research
- [XSS](xss.md)
- [SSRF](ssrf.md)
- [SQL Injection](sqli.md)
- [LFI / RFI](lfi_rfi.md)
- [Open Redirect](open_redirect.md)
- [CORS](cors.md)
- [File Upload](file_upload.md)

### Exposure & Methodology
- [Exposed Resources](exposed_resources.md)
- [Methodology](methodology.md)

---

## Purpose
This section is designed to help security researchers systematically discover and investigate assets, endpoints, parameters, APIs, technologies, and potential security issues within authorized bug bounty programs.
The collection focuses on reconnaissance and vulnerability research rather than unauthorized exploitation.

---

## Reconnaissance Workflow
A typical bug bounty workflow:
1. Identify the target and read its security policy.
2. Determine the exact in-scope assets.
3. Perform passive reconnaissance.
4. Discover subdomains and related assets.
5. Identify technologies and attack-surface components.
6. Discover endpoints, parameters, APIs, and JavaScript resources.
7. Investigate authentication and authorization mechanisms.
8. Test vulnerability classes that are relevant to the target.
9. Validate findings carefully.
10. Document reproducible evidence.
11. Report valid vulnerabilities through the appropriate channel.

---

## Core Research Areas
### Asset Discovery
Discover and organize:
- Domains
- Subdomains
- IP addresses
- Hosts
- Cloud assets
- Web applications
- APIs
- Development environments

### Endpoint Discovery
Research:
- URLs
- Routes
- API endpoints
- Hidden functionality
- JavaScript-referenced endpoints
- Historical endpoints

### Parameter Discovery
Identify:
- URL parameters
- Form parameters
- API parameters
- JSON fields
- Header-based inputs
- Path parameters

### Technology Discovery
Identify:
- Frameworks
- CMS platforms
- Web servers
- JavaScript libraries
- APIs
- Authentication technologies
- Cloud services

---

## Vulnerability Categories
This repository covers common bug bounty vulnerability classes including:
- Cross-Site Scripting (XSS)
- Server-Side Request Forgery (SSRF)
- SQL Injection (SQLi)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Open Redirect
- Cross-Origin Resource Sharing (CORS)
- File Upload Issues
- IDOR / BOLA
- Authentication Issues
- Authorization Issues
- Exposed Resources

---

## Responsible Research
Before testing any target:
- Read the bug bounty program policy.
- Confirm that the target is in scope.
- Check prohibited testing methods.
- Respect rate limits.
- Avoid destructive actions.
- Do not access other users' private information.
- Do not modify or delete data.
- Stop testing when the impact exceeds the authorized scope.

---

## Evidence Collection
A valid report should normally contain:
- Affected asset
- Vulnerability type
- Clear reproduction steps
- Relevant request and response information
- Security impact
- Supporting screenshots when appropriate
- Suggested remediation when useful

Never include unnecessary sensitive information in a report.

---

## Quality Standards
Queries and techniques in this section should prioritize:
- Accuracy
- Reproducibility
- Clear documentation
- Practical usefulness
- Minimal false positives
- Responsible disclosure
- Authorized security testing

---

## Important Notes
Finding an endpoint, parameter, subdomain, technology, file, login page, or exposed service does not automatically indicate a vulnerability.
A vulnerability should be validated based on its actual security impact and the rules of the applicable bug bounty program.
Always distinguish between:
- Interesting
- Potentially vulnerable
- Confirmed vulnerability

---

## Disclaimer
This collection is intended for educational purposes, authorized security research, and legitimate bug bounty activities.
Do not use these techniques against systems without explicit authorization.
Always follow applicable laws, program policies, scope restrictions, rate limits, and responsible disclosure requirements.