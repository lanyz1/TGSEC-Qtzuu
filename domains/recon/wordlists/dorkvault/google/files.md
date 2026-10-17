# Google Dorks - Files
A curated collection of Google search queries for discovering publicly indexed files during authorized security research, OSINT and bug bounty reconnaissance.

---

# PDF Files
## Public PDF Documents
site:example.com filetype:pdf

## PDF Files Containing a Keyword
site:example.com filetype:pdf "keyword"

## Security-Related PDF Files
site:example.com filetype:pdf (security OR cybersecurity OR pentest)

## Documentation
site:example.com filetype:pdf (documentation OR manual OR guide)

---

# Microsoft Word Documents
## DOC Files
site:example.com filetype:doc

## DOCX Files
site:example.com filetype:docx

## Documents Containing Keywords
site:example.com (filetype:doc OR filetype:docx) "keyword"

---

# Microsoft Excel Files
## XLS Files
site:example.com filetype:xls

## XLSX Files
site:example.com filetype:xlsx

## Spreadsheet Search
site:example.com (filetype:xls OR filetype:xlsx)

---

# Microsoft PowerPoin
## PPT Files
site:example.com filetype:ppt

## PPTX Files
site:example.com filetype:pptx

## Presentation Search
site:example.com (filetype:ppt OR filetype:pptx)

---

# Text and Data Files
## TXT Files
site:example.com filetype:txt

## CSV Files
site:example.com filetype:csv

## XML Files
site:example.com filetype:xml

## JSON Files
site:example.com filetype:json

---

# Configuration and Development Files
## Configuration-Related Files
site:example.com (filetype:conf OR filetype:config)

## YAML Files
site:example.com (filetype:yml OR filetype:yaml)

## JavaScript Files
site:example.com filetype:js

## Source Code Files
site:example.com (filetype:php OR filetype:asp OR filetype:aspx OR filetype:jsp)

---

# Backup and Archive Files
## Backup-Related Keywords
site:example.com (backup OR archive OR old)

## Archive Files
site:example.com (filetype:zip OR filetype:tar OR filetype:gz)

## Old Documents
site:example.com (filetype:pdf OR filetype:doc OR filetype:docx) (old OR backup OR archive)

---

# Log Files
## Public Log Files
site:example.com filetype:log

## Log-Related Search
site:example.com (filetype:log OR "log file")

---

# Database-Related Files
## SQL Files
site:example.com filetype:sql

## Database-Related Documents
site:example.com (database OR "database backup" OR dump)

---

# Documentation and Reports
## Technical Documentation
site:example.com (filetype:pdf OR filetype:docx) (technical OR documentation)

## Security Reports
site:example.com (filetype:pdf OR filetype:docx) (security OR audit OR assessment)

## Research Reports
site:example.com (filetype:pdf OR filetype:docx) (research OR report)

---

# File Discovery with URL Operators
## Files in a Specific URL Path
site:example.com inurl:files filetype:pdf

## Documents in a Docs Path
site:example.com inurl:docs filetype:pdf

## Downloads
site:example.com inurl:download filetype:pdf

## Uploads
site:example.com inurl:uploads filetype:pdf

---

# File Discovery with Titles
## Document Indexes
site:example.com intitle:"index of" filetype:pdf

## Directory Listings
site:example.com intitle:"index of" (pdf OR doc OR xls)

---

# Combined Queries
## Documents + Keyword
site:example.com filetype:pdf "keyword"

## Documents + URL Path
site:example.com inurl:docs filetype:pdf "keyword"

## Documents + Title
site:example.com intitle:"keyword" filetype:pdf

## Multiple File Types
site:example.com (filetype:pdf OR filetype:docx OR filetype:xlsx)

## Multiple File Types + Keyword
site:example.com (filetype:pdf OR filetype:docx OR filetype:xlsx) "keyword"

---

# Notes
- Replace example.com with a domain you are authorized to research.
- Replace keyword with a relevant search term.
- Search results depend on Google's indexing and are not guaranteed to be complete.
- A file being indexed does not necessarily mean that it is sensitive or vulnerable.
- Do not access, download or use private information without authorization.
- These queries are intended for educational purposes, OSINT and authorized security research.