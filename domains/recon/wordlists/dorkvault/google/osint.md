# Google Dorks - OSINT
A curated collection of Google search queries for OSINT, public information discovery, domain research and authorized reconnaissance.

---

# Domain Research
## Domain Discovery
site:example.com

## Subdomain References
site:*.example.com

## Related Domains
"example.com" OR "www.example.com"

## Domain References
"example.com" -site:example.com

---

# Organization Research
## Organization Name
"Example Organization"

## Organization + Website
"Example Organization" "example.com"

## Organization + Documentation
"Example Organization" (documentation OR docs)

## Organization + Projects
"Example Organization" (projects OR products OR services)

---

# Public Documentation
## Documentation
site:example.com (documentation OR docs)

## Developer Documentation
site:example.com (developer OR developers) (documentation OR docs)

## API Documentation
site:example.com (api OR API) (documentation OR docs)

## Technical Documentation
site:example.com ("technical documentation" OR "developer documentation")

---

# Public Reports
## Reports
site:example.com (report OR reports)

## Annual Reports
site:example.com ("annual report" OR "annual reports")

## Research Reports
site:example.com (research OR "research report")

## Security Reports
site:example.com ("security report" OR "security assessment")

---

# Public Presentations
## Presentations
site:example.com (filetype:ppt OR filetype:pptx)

## Presentation Keywords
site:example.com (filetype:ppt OR filetype:pptx) (presentation OR conference)

---

# Public Documents
## PDF Documents
site:example.com filetype:pdf

## Word Documents
site:example.com (filetype:doc OR filetype:docx)

## Spreadsheet Documents
site:example.com (filetype:xls OR filetype:xlsx)

---

# News and Publications
## Organization News
"Example Organization" (news OR announcement)

## Press Releases
"Example Organization" ("press release" OR announcement)

## Public Articles
"Example Organization" (article OR interview OR publication)

---

# GitHub References
## GitHub Mentions
"example.com" site:github.com

## Organization GitHub References
"Example Organization" site:github.com

## Public Code References
"example.com" site:github.com (code OR repository)

---

# Social Media References
## LinkedIn
"Example Organization" site:linkedin.com

## X / Twitter
"Example Organization" (site:x.com OR site:twitter.com)

## YouTube

---

# Domain + Technology
## Technology References
"example.com" (technology OR framework OR platform)

## Developer Stack References
"example.com" (developer OR engineering) (technology OR stack)

## API References
"example.com" (API OR API documentation)

---

# Infrastructure References
## Hostname References
"example.com" (hostname OR host)

## Service References
"example.com" (service OR services)

## Infrastructure Documentation
"example.com" (infrastructure OR architecture)

---

# Security Research
## Security Advisories
"example.com" (security advisory OR security bulletin)

## Vulnerability References
"example.com" (vulnerability OR CVE)

## Bug Bounty References
"example.com" ("bug bounty" OR "security researcher")

## Security Program
"example.com" ("security program" OR "security.txt")

---

# Public Contact Pages
## Contact Information
site:example.com (contact OR "contact us")

## Support Pages
site:example.com (support OR help)

## Press Contact
site:example.com ("press contact" OR "media contact")

---

# Search Engine Exclusions
## Search External References
"example.com" -site:example.com

## Search Specific Domains
"example.com" (site:github.com OR site:gitlab.com)

## Exclude Common Results
"example.com" -site:example.com -site:facebook.com -site:instagram.com

---

# OSINT Workflow
1. Start with the target domain or organization name.
2. Identify publicly indexed documentation and resources.
3. Search for public reports and publications.
4. Identify public code repositories and developer resources.
5. Identify publicly documented technologiesand infrastructure references.
6. Correlate information from multiple public sources.
7. Verify findings before using them in security research.

---

# Notes
- Replace example.com with a domain you are authorized to research.
- Replace Example Organization with the organization being researched.
- OSINT should rely on information that is publicly available.
- Do not collect, expose or misuse sensitive personal information.
- Do not attempt unauthorized access to discovered services.
- A search result does not prove ownership, vulnerability or security impact.
- These queries are intended for educational purposes, OSINT and authorized security research.