# Bug Bounty - Reconnaissance
A practical collection of reconnaissance queries and techniques for identifying publicly observable assets during authorized bug bounty research.

---

# Target Identification
## Main Domain
site:example.com

## Domain References
"example.com"

## External References
"example.com" -site:example.com

## Public Documentation
site:example.com (documentation OR docs OR developer)

## Security Information
site:example.com (security OR "security.txt")

---

# Subdomain Discovery
## Indexed Subdomains
site:example.com -www

## Common Subdomain Keywords
site:example.com (dev OR test OR staging OR beta OR api OR admin)

## Development Environments
site:example.com (dev OR development OR staging OR test OR testing)

## API Subdomains
site:example.com (api OR api-dev OR api-test OR api-staging)

---

# Technology Discovery
## Technology Keywords
site:example.com (framework OR technology OR platform)

## CMS References
site:example.com (WordPress OR Drupal OR Joomla)

## Developer Resources
site:example.com (developer OR developers OR engineering)

## API Documentation
site:example.com (api OR API) (documentation OR docs)

---

# Public Files
## PDF Files
site:example.com filetype:pdf

## Document Files
site:example.com (filetype:doc OR filetype:docx)

## Spreadsheet Files
site:example.com (filetype:xls OR filetype:xlsx)

## Presentation Files
site:example.com (filetype:ppt OR filetype:pptx)

---

# Public Resources
## Directory References
site:example.com intitle:"index of"

## Backup References
site:example.com (backup OR archive)

## Log References
site:example.com (logs OR logfile)

## Configuration References
site:example.com (config OR configuration)

---

# Web Application Discovery
## Login Pages
site:example.com (inurl:login OR intitle:login)

## Admin References
site:example.com (inurl:admin OR intitle:admin)

## Dashboard References
site:example.com (inurl:dashboard OR intitle:dashboard)

## Portal References
site:example.com (inurl:portal OR intitle:portal)

---

# API Reconnaissance
## API URLs
site:example.com inurl:api

## API Documentation
site:example.com (inurl:api OR intitle:api) (docs OR documentation)

## API Versions
site:example.com inurl:api (v1 OR v2 OR v3)

---

# JavaScript Reconnaissance
## JavaScript Files
site:example.com filetype:js

## JavaScript References
site:example.com (javascript OR "JavaScript")

## Developer Scripts
site:example.com filetype:js (api OR endpoint OR route)

---

# Security Research References
## Vulnerability References
"example.com" (vulnerability OR CVE)

## Bug Bounty References
"example.com" ("bug bounty" OR "security researcher")

## Security Advisories
"example.com" ("security advisory" OR "security bulletin")

## Public Security Reports
"example.com" ("security report" OR "penetration test")

---

# External Intelligence
## GitHub References
"example.com" site:github.com

## GitLab References
"example.com" site:gitlab.com

## LinkedIn References
"Example Organization" site:linkedin.com

## Public Documents
"example.com" (site:github.com OR site:gitlab.com)

---

# Reconnaissance Methodology
## Phase 1 - Scope
1. Identify the bug bounty program.
2. Read the program policy.
3. Record all in-scope assets.
4. Record excluded assets and prohibited actions.

## Phase 2 - Passive Discovery
1. Search the target domain.
2. Identify indexed subdomains.
3. Search public documentation.
4. Identify public files and resources.
5. Identify technologies and frameworks.
6. Search public repositories and references.

## Phase 3 - Attack Surface Mapping
Organize discovered information into:
- Domains
- Subdomains
- IP addresses
- Applications
- APIs
- Endpoints
- Parameters
- Technologies
- Authentication systems
- Public resources

## Phase 4 - Validation
1. Remove duplicate assets.
2. Verify that assets belong to the authorized target.
3. Confirm that assets are in scope.
4. Manually validate interesting findings.
5. Prioritize assets based on potential security impact.

---

# Recon Checklist
- [ ] Program scope reviewed
- [ ] Main domains identified
- [ ] Subdomains identified
- [ ] IP ranges identified
- [ ] Technologies identified
- [ ] APIs identified
- [ ] JavaScript resources identified
- [ ] Public files reviewed
- [ ] Authentication surfaces identified
- [ ] Interesting endpoints documented
- [ ] Findings validated
- [ ] Out-of-scope assets excluded

---

# Important Notes
- Search engine results are incomplete and can become outdated.
- A discovered asset does not automatically belong to the target.
- A publicly indexed resource does not automatically indicate a vulnerability.
- Verify ownership and scope before performing active testing.
- Do not access private information.
- Do not attempt authentication bypasses or credential attacks during passive reconnaissance.
- Respect rate limits and program-specific rules.
- Only perform active security testing when explicitly authorized.

---

# Reporting
For confirmed vulnerabilities, document:
- Target asset
- Affected endpoint
- Vulnerability type
- Reproduction steps
- Evidence
- Security impact
- Scope confirmation
- Suggested remediation

Follow the reporting requirements of the relevant bug bounty program.