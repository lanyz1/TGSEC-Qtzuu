# Google Dorks - Exposed Resources
A curated collection of Google search queries for discovering publicly indexed resources, directories, backups, logs and other potentially exposed web content during authorized security research.

---

# Directory Listings
## Basic Directory Listing
intitle:"index of"

## Directory Listing on a Specific Domain
site:example.com intitle:"index of"

## Directory Listing with a Keyword
site:example.com intitle:"index of" "keyword"

## Directory Listing for Documents
site:example.com intitle:"index of" (pdf OR doc OR docx)

## Directory Listing for Archives
site:example.com intitle:"index of" (zip OR tar OR gz)

---

# Backup Files
## Backup Keyword Search
site:example.com (backup OR backups)

## Old Files
site:example.com (old OR previous OR archive)

## Backup and Archive References
site:example.com ("backup" OR "archive" OR "old version")

## Backup Files by Extension
site:example.com (filetype:bak OR filetype:old)

---

# Log Files
## Log File Discovery
site:example.com filetype:log

## Error Logs
site:example.com ("error log" OR "error_log")

## Application Logs
site:example.com ("application log" OR "application logs")

## Access Logs
site:example.com ("access log" OR "access.log")

---

# Configuration References
## Configuration Files
site:example.com (filetype:conf OR filetype:config)

## Configuration References
site:example.com ("configuration file" OR "config file")

## Environment References
site:example.com ("environment configuration" OR "environment variables")

---

# Temporary and Development Files
## Temporary Files
site:example.com (filetype:tmp OR filetype:temp)

## Development Files
site:example.com (development OR staging OR testing)

## Test Environments
site:example.com (test OR testing OR staging)

---

# Debug and Error Pages
## Debug References
site:example.com (debug OR debugging)

## Error Pages
site:example.com (error OR exception)

## Stack Trace References
site:example.com ("stack trace" OR "exception trace")

## Debugging Documentation
site:example.com (debug OR "debug mode") (documentation OR guide)

---

# Administrative Interfaces
## Login Pages
site:example.com (inurl:login OR inurl:signin)

## Administrative Pages
site:example.com (inurl:admin OR intitle:admin)

## Management Interfaces
site:example.com (inurl:manage OR inurl:management)

## Dashboard Pages
site:example.com (inurl:dashboard OR intitle:dashboard)

---

# Development and Documentation Paths
## Development Directories
site:example.com inurl:dev

## Test Directories
site:example.com inurl:test

## Staging Directories
site:example.com inurl:staging

## Documentation Directories
site:example.com inurl:docs

## Upload Directories
site:example.com inurl:uploads

---

# Source Code Discovery
## JavaScript Files
site:example.com filetype:js

## PHP Files
site:example.com filetype:php

## ASP Files
site:example.com filetype:asp

## ASPX Files
site:example.com filetype:aspx

## JSP Files
site:example.com filetype:jsp

---

# Public Documents
## Public Documents
site:example.com (filetype:pdf OR filetype:docx)

## Technical Documents
site:example.com (filetype:pdf OR filetype:docx) (technical OR documentation)

## Reports
site:example.com (filetype:pdf OR filetype:docx) (report OR assessment)

---

# Combined Reconnaissance Queries
## Exposed Directory + Keyword
site:example.com intitle:"index of" "keyword"

## Backup + File Type
site:example.com (backup OR archive) (filetype:zip OR filetype:tar OR filetype:gz)

## Logs + Keyword
site:example.com filetype:log "keyword"

## Development + Documentation
site:example.com (inurl:dev OR inurl:staging OR inurl:test) (filetype:pdf OR filetype:docx)

## Administrative Pages
site:example.com (inurl:admin OR inurl:login OR inurl:dashboard)

---

# Research Workflow
1. Start with the target domain.
2. Identify indexed directories and documents.
3. Search for development, testing and staging references.
4. Search for publicly indexed logs and backup-related resources.
5. Review results manually.
6. Verify whether discovered resources are intentionally public or potentially exposed.

---

# Notes
- Replace example.com with a domain you are authorized to research.
- Replace keyword with a relevant search term.
- Search results depend on Google's indexing.
- An indexed resource is not automatically a security vulnerability.
- Do not access, download or use private information without authorization.
- Do not attempt authentication or exploitation against discovered resources.
- These queries are intended for educational purposes, OSINT and authorized security research.