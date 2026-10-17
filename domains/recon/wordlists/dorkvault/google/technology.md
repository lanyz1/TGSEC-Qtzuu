# Google Dorks - Technology
A curated collection of Google search queries for identifying publicly indexed web technologies, frameworks, CMS platforms and technology-related resources during authorized security research.

---

# WordPress
## WordPress Sites
site:example.com inurl:wp-content

## WordPress Login
site:example.com inurl:wp-login.php

## WordPress Administration
site:example.com inurl:wp-admin

## WordPress Plugins
site:example.com inurl:wp-content/plugins

---

# Drupal
## Drupal References
site:example.com (inurl:node OR inurl:sites/default)

## Drupal Files
site:example.com inurl:sites/default/files

---

# Joomla
## Joomla References
site:example.com inurl:component

## Joomla Administration
site:example.com inurl:administrator

---

# Laravel
## Laravel References
site:example.com (Laravel OR "Laravel Framework")

## Laravel Documentation
site:example.com (Laravel OR "Laravel Framework") (documentation OR docs)

---

# Django
## Django References
site:example.com (Django OR "Django Framework")

## Django Documentation
site:example.com (Django OR "Django Framework") (documentation OR docs)

---

# React
## React References
site:example.com (React OR "React.js")

## React Documentation
site:example.com (React OR "React.js") (documentation OR docs)

---

# Vue
## Vue References
site:example.com (Vue OR "Vue.js")

## Vue Documentation
site:example.com (Vue OR "Vue.js") (documentation OR docs)

---

# Angular
## Angular References
site:example.com (Angular OR "AngularJS")

## Angular Documentation
site:example.com (Angular OR "AngularJS") (documentation OR docs)

---

# Node.js
## Node.js References
site:example.com ("Node.js" OR NodeJS)

## Node.js Documentation
site:example.com ("Node.js" OR NodeJS) (documentation OR docs)

---

# PHP
## PHP References
site:example.com (PHP OR "PHP Framework")

## PHP Documentation
site:example.com (PHP OR "PHP Manual") documentation

---

# Web Servers
## Apache
site:example.com (Apache OR "Apache HTTP Server")

## Nginx
site:example.com (Nginx OR "nginx web server")

## IIS
site:example.com ("Microsoft IIS" OR "Internet Information Services")

---

# APIs
## API References
site:example.com (inurl:api OR intitle:api)

## API Documentation
site:example.com (inurl:api OR intitle:api) (documentation OR docs)

## API Versioning
site:example.com inurl:api (inurl:v1 OR inurl:v2 OR inurl:v3)

---

# Documentation
## Technology Documentation
site:example.com (documentation OR docs) (framework OR platform OR API)

## Developer Documentation
site:example.com (developer OR developers) (documentation OR docs)

## Technical Documentation
site:example.com (technical documentation OR developer documentation)

---

# JavaScript
## JavaScript Files
site:example.com filetype:js

## JavaScript Documentation
site:example.com filetype:js (documentation OR docs)

---

# Source Code
## Common Source Files
site:example.com (filetype:php OR filetype:asp OR filetype:aspx OR filetype:jsp)

## Source Code + Technology
site:example.com (filetype:php OR filetype:js) (React OR Vue OR Angular)

---

# Technology Discovery Workflow
1. Identify the target domain.
2. Search for technology-specific URLs and indexed resources.
3. Search for documentation and developer resources.
4. Identify frameworks, CMS platforms and web technologies.
5. Correlate discovered technologies with authorized reconnaissance.

---

# Notes
- Replace example.com with a domain you are authorized to assess.
- Technology-related searches may produce false positives.
- Google indexing is incomplete and may not reveal all technologies used by a website.
- Technology identification alone does not indicate a vulnerability.
- Do not attempt exploitation against technologies or services without authorization.
- These queries are intended for educational purposes, OSINT and authorized security research.