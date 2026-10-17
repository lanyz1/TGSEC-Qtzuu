# Google Dorks
A curated collection of Google search queries for security research, OSINT, reconnaissance and authorized bug bounty activities.

---

## Contents
- [Operators](operators.md)
- [Files](files.md)
- [Exposed Resources](exposed.md)
- [Login Panels](login_panels.md)
- [Technology](technology.md)
- [OSINT](osint.md)
- [Endpoint & URL Parameters](endpoint_parameters.md)
- [Path Based](path_based_dorks.md)
- [Vulnerability Parameters](vulnerability_parameters.md)

---

## Categories
### Operators
Core Google search operators used to build advanced search queries.

See:
[Operators.md](operators.md)

---

### Files
Search queries for discovering publicly indexed documents, source files, archives, logs and other file types.

See:
[Files.md](files.md)

---

### Exposed Resources
Search queries for identifying publicly indexed directories, backups, logs, development resources and other potentially exposed web content.

See:
[Exposed.md](exposed.md)

---

### Login Panels
Search queries for discovering publicly indexed login pages, administrative interfaces, dashboards and authentication portals.

See:
[Login_Panels.md](login_panels.md)

---

### Technology
Search queries for identifying publicly indexed technologies, frameworks, CMS platforms, APIs and developer resources.

See:
[Technology.md](technology.md)

---

### OSINT
Search queries for domain research, organizations, public documentation, reports, repositories and other publicly available information.

See:
[OSINT.md](osint.md)

---

### Endpoint & URL Parameters
Collection of common URL and redirect parameter names useful for identifying endpoints that handle URL navigation, redirects, return paths, and related functionality.

see:
[Endpoint_Parameters.md](endpoint_parameters.md)

---

### Path Based
if you find a domain and a path that looks something like “/assets/scripts/” or “/private/documents/” you can use any of these combinations.

see:
[Path_Based.md](path_based_dorks.md)

---

### Vulnerability Parameters
Parameters that are related to specific vulnerability categories in security tests.

see:
[Vulnerability_Parameters.md](vulnerability_parameters.md)

---

## Usage
Replace placeholders such as:
example.com
with a domain that you are authorized to research.

Example:
site:example.com filetype:pdf

---

## Research Workflow
1. Define the authorized target.
2. Start with basic Google operators.
3. Identify indexed files and resources.
4. Search for publicly exposed directories and development resources.
5. Identify technologies and public-facing interfaces.
6. Correlate information using OSINT techniques.
7. Validate findings manually.
8. Follow the target's security policy and scope before performing any security testing.

---

## Important Notes
- Google Dorks are search queries, not exploits.
- Search results depend on Google's indexing and may be incomplete.
- Finding a resource through Google does not automatically mean that it is vulnerable.
- Do not attempt unauthorized access, authentication attacks or exploitation.
- Do not collect or misuse private or sensitive information.
- Only perform security testing against systems for which you have explicit authorization.

---

## Purpose
The purpose of this collection is to provide a structured reference for:
- Security Research
- OSINT
- Reconnaissance
- Bug Bounty
- Web Application Security
- Educational Research

---

## Disclaimer
This repository is intended for educational purposes, OSINT and authorized security research only.
The author is not responsible for any misuse of the information or queries contained in this repository.