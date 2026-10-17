# Google Dorks
A collection of Google search dorks for authorized reconnaissance, exposure discovery, and security research.
Replace target-specific terms where appropriate. Use these queries only against systems, domains, and organizations that are explicitly within your authorized scope.

---

## 1. Directory Listing & Indexing
intitle:"index of" inurl:ftp intext:admin
intitle:"index of" "system/config"
intitle:"index of" "admin/config"
"index of" "/config/sql"
intitle:"index of" "api/admin"
intitle:"index of" "tinyfilemanager.php"
intitle:"index of" "test/storage/framework/sessions/"
intitle:"index of" "symfony/config"
intitle:"index of" "graphql/subscription"
intitle:"index of" "/admin/backup"
intitle:"index of" "admin/json"
intitle:"index of" "/admin_backup"
intitle:"index of" "git-jira-log"
intitle:"index of" db.frm
intitle:"index of" "/db_backups/"
intitle:"index of" "common.crt" OR "ca.crt"
intitle:"index of" "global.asa"
intitle:"index of" "proxy.pac" OR "proxy.pac.bak"
intitle:"index of" "MySQL-Router"
intitle:"index of" "owncloud/config/*"
"index of" "backup.sql"
"index of" "settings.json"
"index of" "api_key"
"index of" "server-status"

---

## 2. Configuration & Sensitive Files
filetype:ini "password" site:org
filetype:txt "credentials" site:gov
filetype:yaml "secret_key" -examples
filetype:key "PRIVATE KEY"
filetype:pem "PRIVATE KEY"
filetype:json "db_password" -github
filetype:db "database" site:org
filetype:conf "db_user" site:org
filetype:config "ftp" site:gov
filetype:xml "web.config" site:edu
filetype:env "SECRET_KEY"
filetype:json "api_token"
filetype:txt "api_secret"

---

## 3. Logs & Debug Information
filetype:log "debug" "error"
filetype:log "Stack trace" site:edu
filetype:log "unable to connect"
filetype:log "authentication failed"

---

## 4. Backups & Database Files
filetype:sql "INSERT INTO" "VALUES" site:edu
filetype:dump "database" site:gov
filetype:db "database" site:org
"index of" "backup.sql"

---

## 5. Credentials & API Secrets
filetype:ini "password" site:org
filetype:json "db_password" -github
filetype:env "SECRET_KEY"
filetype:json "api_token"
filetype:txt "api_secret"
site:pastebin.com "password"
site:github.com "SECRET_KEY"
site:gitlab.com "PRIVATE_KEY"
site:bitbucket.org "db_password"

---

## 6. Administrative Interfaces
"admin login" filetype:php
"admin dashboard" "login"
"index of" "server-status"
filetype:php "mysql_connect" site:gov

---

## 7. Sensitive Documents
filetype:pdf "not for distribution" site:gov
filetype:xlsx "confidential report" site:edu
filetype:doc "salary" "employee"
filetype:docx "restricted access"
filetype:xlsx "username" "password" site:gov
filetype:xls "username" "password" site:gov
filetype:xlsx "username" site:gov
filetype:xls "username" site:gov
filetype:xlsx "database" site:gov
filetype:xls "database" site:gov
filetype:xlsx "financial" site:gov
filetype:xls "financial" site:gov
filetype:xlsx "password" site:gov
filetype:xls "password" site:gov

---

## 8. Cloud Storage & Code Hosting
site:example.com "password"
site:example.com "confidential"
site:example.com "important"
site:example.com "restricted"
site:example.com "password"
site:example.com "SECRET_KEY"
site:example.com "PRIVATE_KEY"
site:example.com "db_password"

---

## 9. Basic Content Discovery
site:example.com

---

## 10. Exposed Directories
site:example.com intitle:index.of

---

## 11. Sensitive Configuration Files
site:example.com ext:conf | ext:cnf | ext:config | ext:ini

---

## 12. Database Files
site:example.com ext:sql | ext:db | ext:dbf | ext:mdb

---

## 13. Log files
site:example.com ext:log

---

## 14. Backup Files
site:example.com ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup

---

## 15. Source Code Files
site:example.com ext:php | ext:jsp | ext:asp | ext:aspx | ext:js | ext:java | ext:py | ext:c | ext:cpp | ext:pl

---

## 16. Sensitive Document Files
site:example.com  ext:doc | ext:docx | ext:pdf | ext:xls | ext:xlsx | ext:ppt | ext:pptx

---

## 17. Usernames and Passwords
site:example.com intext:username | intext:password | intext:passwd

---

## 18. XMLPRC.PHP file
site:example.com inurl:xmlrpc.php

---

## 19. Admin Panels
site:example.com inurl:admin | inurl:login | inurl:dashboard

---

## 20. Exposed APIs
site:example.com inurl:api | inurl:rest | inurl:graphql

---

## 21. Exposed .git Repos
site:example.com inurl:.git

---

## 22. Sensitive Development Files
site:example.com ext:env | ext:yaml | ext:json

---

## 23. Error Pages
site:example.com intext:"error" | intext:"warning" | intext:"not found" | intext:"exception"

---

## 24. PHP Information Disclosures
site:example.com ext:php intext:"phpinfo()" | intext:"PHP Version"

---

## 25. Session IDs in URLs
site:example.com inurl:sessionid | inurl:JSESSIONID | inurl:PHPSESSID

---

## 26. Directory Listing
site:example.com "parent directory"

---

## 27. CMS Exposure
site:example.com inurl:wp- | inurl:joomla | inurl:drupal | inurl:magento

---

## 28. Information Disclosure Dork
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)

---

## 29. find senstive files on website
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)

---

## 30. Sensitive Docs
ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx
intext:“confidential” | intext:“Not for Public Release” | intext:”internal use only” | intext:“do not distribute” site:example[.]com

---

## 31. File Uploads
site:example[.]com intext:"choose file" | intext:"select file" | intext:"upload PDF"

---

## 32. XSS Prone Parameters
site:example[.]com inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:&

---

## Usage Notes
- Use these queries only for authorized security research.
- Apply domain, organization, or other scope restrictions whenever appropriate.
- Search results can contain false positives and outdated information.
- Do not access, download, authenticate to, or use exposed credentials without explicit authorization.
- Treat potentially sensitive documents, credentials, logs, and keys as confidential.
- Do not disclose sensitive values publicly.
- Follow the applicable bug bounty rules and responsible disclosure policy.

---

## Safety & Scope
A search result is not automatically a vulnerability.
Before considering a finding, verify:
1. Ownership of the resource.
2. Whether it is within the authorized scope.
3. Whether the exposure is actually accessible.
4. Whether sensitive information is genuinely exposed.
5. Whether there is a meaningful security impact.

Minimize interaction with discovered resources and avoid unnecessary access to sensitive information.