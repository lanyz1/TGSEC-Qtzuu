# Google Dorks - Login Panels
A curated collection of Google search queries for discovering publicly indexed login pages, authentication portals and administrative interfaces during authorized security research.

---

# Login Pages
## Generic Login Pages
site:example.com inurl:login

## Sign-in Pages
site:example.com inurl:signin

## Authentication Pages
site:example.com (inurl:login OR inurl:signin OR inurl:auth)

## Login Keyword in Page Title
site:example.com intitle:login

## Login Keyword in Page Content
site:example.com intext:"login"

---

# Administrative Panels
## Admin URL
site:example.com inurl:admin

## Admin Title
site:example.com intitle:admin

## Admin Login
site:example.com (inurl:admin OR intitle:admin) (inurl:login OR intitle:login)

## Administration Pages
site:example.com (inurl:admin OR inurl:administrator)

---

# Management Interfaces
## Management URLs
site:example.com inurl:manage

## Management Pages
site:example.com (inurl:manage OR inurl:management)

## Management Login
site:example.com (inurl:manage OR inurl:management) (inurl:login OR inurl:signin)

---

# Dashboard Pages
## Dashboard URL
site:example.com inurl:dashboard

## Dashboard Title
site:example.com intitle:dashboard

## Dashboard Authentication
site:example.com inurl:dashboard (inurl:login OR inurl:signin)

---

# Control Panels
## Control Panel
site:example.com ("control panel" OR "control-panel")

## Control Panel Login
site:example.com ("control panel" OR "control-panel") (login OR signin)

---

# Portal Pages
## Portal URL
site:example.com inurl:portal

## Portal Title
site:example.com intitle:portal

## Portal Authentication
site:example.com inurl:portal (login OR signin OR authentication)

---

# Authentication Systems
## Authentication Keywords
site:example.com (authentication OR authenticate)

## Sign-in Keywords
site:example.com ("sign in" OR "sign-in")

## Account Login
site:example.com ("account login" OR "user login")

---

# Common Login Paths
## Login Path Variations
site:example.com (inurl:login OR inurl:signin OR inurl:sign-in)

## Admin Login Variations
site:example.com (inurl:admin OR inurl:administrator) (login OR signin)

## Portal Login Variations
site:example.com (inurl:portal OR inurl:dashboard) (login OR signin)

---

# Technology-Oriented Searches
## WordPress Login
site:example.com inurl:wp-login.php

## WordPress Administration
site:example.com inurl:wp-admin

## Jenkins Login
site:example.com intitle:"Dashboard [Jenkins]"

## GitLab Pages
site:example.com (inurl:users/sign_in OR intitle:"GitLab")

---

# Combined Queries
## Login + Admin
site:example.com (login OR signin) (admin OR administrator)

## Login + Dashboard
site:example.com (login OR signin) (dashboard OR portal)

## Authentication + Admin
site:example.com (authentication OR authenticate) (admin OR administrator)

## Login + Management
site:example.com (login OR signin) (manage OR management)

---

# Research Workflow
1. Start with the authorized target domain.
2. Search for common authentication paths.
3. Identify publicly indexed administrative or management interfaces.
4. Determine the underlying technology when possible.
5. Verify whether the interface is intentionally exposed.
6. Follow the relevant bug bounty or security testing policy before interacting with the target.

---

# Notes
- Replace example.com with a domain you are authorized to assess.
- Google indexing is incomplete and results may change over time.
- Finding a login page is not itself a vulnerability.
- Do not attempt credential attacks, authentication bypasses or unauthorized access.
- Do not use discovered interfaces against systems without permission.
- These queries are intended for educational purposes, OSINT and authorized security research.