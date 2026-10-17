# Bug Bounty - Assets
A practical collection of reconnaissance queries and techniques for identifying and organizing publicly observable assets during authorized bug bounty research.

---

# Domain Assets
## Main Domain
site:example.com

## Domain References
"example.com"

## External Domain References
"example.com" -site:example.com

---

# Subdomain Assets
## Indexed Subdomains
site:example.com -www

## Development Assets
site:example.com (dev OR development OR staging OR stage)

## API Assets
site:example.com (api OR api-dev OR api-test OR api-staging)

## Authentication Assets
site:example.com (login OR auth OR sso OR signin)

## Administrative Assets
site:example.com (admin OR administrator OR dashboard OR panel)

---

# Web Assets
## HTTP Resources
site:example.com (http OR https)

## Login Pages
site:example.com (inurl:login OR intitle:login)

## Dashboard Pages
site:example.com (inurl:dashboard OR intitle:dashboard)

## Portal Pages
site:example.com (inurl:portal OR intitle:portal)

## API Pages
site:example.com (inurl:api OR intitle:api)

---

# Technology Assets
## CMS
site:example.com (WordPress OR Drupal OR Joomla)

## JavaScript
site:example.com filetype:js

## PHP
site:example.com filetype:php

## ASP.NET
site:example.com (filetype:asp OR filetype:aspx)

## Java
site:example.com filetype:jsp

---

# API Assets
## API References
site:example.com inurl:api

## API Documentation
site:example.com (api OR developer) (docs OR documentation)

## API Versions
site:example.com inurl:api (v1 OR v2 OR v3)

## Public API References
site:example.com ("API" OR "REST API" OR "GraphQL")

---

# Cloud Assets
## Cloud References
site:example.com (AWS OR Azure OR "Google Cloud")

## Cloud Documentation
site:example.com (cloud OR infrastructure)

## Storage References
site:example.com (storage OR bucket OR object)

---

# Infrastructure Assets
## Network References
"example.com" (IP OR network OR infrastructure)

## DNS References
"example.com" (DNS OR nameserver)

## CDN References
"example.com" (CDN OR "content delivery")

## Monitoring
site:example.com (monitoring OR metrics OR observability)

---

# Public File Assets
## PDF
site:example.com filetype:pdf

## Documents
site:example.com (filetype:doc OR filetype:docx)

## Spreadsheets
site:example.com (filetype:xls OR filetype:xlsx)

## Presentations
site:example.com (filetype:ppt OR filetype:pptx)

---

# Public Resource Assets
## Directory Listings
site:example.com intitle:"index of"

## Backup References
site:example.com (backup OR archive)

## Log References
site:example.com (log OR logs OR logfile)

## Configuration References
site:example.com (config OR configuration)

---

# External Assets
## GitHub
"example.com" site:github.com

## GitLab
"example.com" site:gitlab.com

## LinkedIn
"Example Organization" site:linkedin.com

## Public Documents
"example.com" (site:github.com OR site:gitlab.com)

---

# Asset Classification
Classify discovered assets into:
- Domains
- Subdomains
- Web Applications
- APIs
- IP Addresses
- Network Ranges
- Cloud Assets
- Storage
- Authentication Systems
- Administrative Interfaces
- Development Environments
- Testing Environments
- Staging Environments
- Third-Party Services
- Public Resources

---

# Asset Prioritization
A practical priority model:

## High Priority
- Production applications
- Authentication systems
- APIs
- Administrative interfaces
- Sensitive business functionality

## Medium Priority
- Development environments
- Staging environments
- Supporting applications
- Public documentation

## Low Priority
- Marketing pages
- Static resources
- Public informational pages

Priority should always be adjusted according to the bug bounty program's scope and rules.

---

# Asset Inventory
Recommended fields for documenting discovered assets:
| Field | Description |
|---|---|
| Asset | Domain, host, IP or application |
| Type | Web, API, Cloud, Network, etc. |
| Environment | Production, Staging, Dev, Test |
| Technology | Identified technology |
| Source | Discovery source |
| Scope | In-scope / Out-of-scope |
| Status | Active / Inactive / Unknown |
| Notes | Additional observations |

---

# Asset Discovery Workflow
1. Identify the main target.
2. Read the bug bounty scope.
3. Discover domains and subdomains.
4. Identify IP addresses and network ranges.
5. Discover web applications and APIs.
6. Identify cloud and third-party services.
7. Identify technologies.
8. Classify discovered assets.
9. Verify ownership and scope.
10. Prioritize assets for authorized testing.

---

# Important Notes
- Asset discovery is not equivalent to vulnerability discovery.
- Search engine results can be incomplete or outdated.
- Third-party assets may appear related to a target without being owned by it.
- Always verify ownership and scope.
- Do not access restricted resources during passive reconnaissance.
- Do not perform active scanning unless explicitly authorized.
- Respect rate limits and program-specific restrictions.
- Do not collect unnecessary sensitive information.

---

# Responsible Research
The goal of asset discovery is to build an accurate and authorized attack-surface map while minimizing unnecessary interaction with target infrastructure.
Only test assets that are explicitly within the applicable security scope.