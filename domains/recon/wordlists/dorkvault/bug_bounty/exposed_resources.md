# Bug Bounty - Exposed Resources
A practical collection of exposed resource reconnaissance concepts, research areas, and discovery techniques for authorized bug bounty programs.

---

# Overview
## Exposed Resources
Exposed resources are publicly accessible files, services, configurations, or information that may unintentionally reveal internal details or sensitive data.
Common examples:
- Configuration files
- Backup files
- Logs
- Documentation
- Development resources
- Debug information
- Public storage resources

---

# Exposed Resource Discovery
## Directory Listing
site:example.com intitle:"index of"

## Backup Files
site:example.com (backup OR archive OR old)

## Configuration Files
site:example.com (config OR configuration)

## Log Files
site:example.com (log OR logs OR logfile)

---

# Sensitive File Discovery
## Environment Files
site:example.com ".env"

## Configuration References
site:example.com (config.php OR settings OR configuration)

## Backup Extensions
Search for:
- .bak
- .backup
- .old
- .zip
- .tar
- .gz

## Documentation Files
site:example.com (documentation OR docs OR guide)

---

# Public Documents
## PDF Files
site:example.com filetype:pdf

## Word Documents
site:example.com (filetype:doc OR filetype:docx)

## Spreadsheet Files
site:example.com (filetype:xls OR filetype:xlsx)

## Presentations
site:example.com (filetype:ppt OR filetype:pptx)

---

# Debug Information Discovery
## Debug Pages
site:example.com (debug OR test)

## Error Pages
site:example.com (error OR exception)

## Development References
site:example.com (dev OR development OR staging)

---

# Source Code Exposure
## Repository References
"example.com" site:github.com

## Git References
site:example.com (.git OR git)

## Public Code Search
"example.com" (source OR repository OR code)

---

# Cloud Resource Discovery
## Storage References
site:example.com (bucket OR storage OR upload)

## Cloud Keywords
site:example.com (AWS OR Azure OR GCP)

## CDN Resources
site:example.com (cdn OR assets OR static)

---

# API Resource Exposure
## API Documentation
site:example.com (api OR developer) (docs OR documentation)

## API Specifications
site:example.com (swagger OR OpenAPI)

## API Examples
site:example.com ("sample response" OR "example request")

---

# Common Exposed Resources
## Backup Resources
Examples:
- Old versions
- Archived files
- Temporary copies

## Development Resources
Examples:
- Test environments
- Debug pages
- Development documentation

## Logs
Examples:
- Application logs
- Error logs
- Access logs

## Configuration
Examples:
- Application settings
- Environment information
- Service configuration

---

# Exposed Resources Research Workflow
## Phase 1 - Discovery
1. Identify public resources.
2. Search indexed files.
3. Review documentation.
4. Identify technology-related files.
5. Map exposed information.

---

## Phase 2 - Classification
Classify findings:
- Public documentation
- Configuration
- Backup files
- Logs
- Source code
- Debug information
- Cloud resources

---

## Phase 3 - Validation
1. Confirm asset ownership.
2. Confirm scope.
3. Determine information sensitivity.
4. Document impact.
5. Report responsibly.

---

# Documentation Template
| Field | Description |
|---|---|
| Resource | Exposed item |
| Location | URL or asset |
| Type | File, Service, Document |
| Information | Discovered content |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional details |

---

# Potential Security Impact
Exposed resources may lead to:
- Information disclosure
- Technology leakage
- Internal structure discovery
- Configuration exposure
- Increased attack surface visibility

Impact depends on:
- Data sensitivity
- Resource type
- Access restrictions
- Application architecture

---

# Prevention Concepts
Developers can reduce exposure risks by:
- Removing unnecessary files
- Restricting access permissions
- Securing backups
- Disabling directory listing
- Protecting configuration files
- Separating development resources
- Reviewing public deployments

---

# Important Notes
- A public file is not always a vulnerability.
- Documentation may be intentionally public.
- Do not access sensitive information unnecessarily.
- Do not download or store private data.
- Always verify scope before testing.
- Respect bug bounty rules and limitations.

---

# Responsible Research
Exposed resource research should focus on identifying unintended information exposure while minimizing impact.
Only perform testing against authorized targets and follow responsible disclosure practices.