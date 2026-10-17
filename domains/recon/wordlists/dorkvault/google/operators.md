# Google Search Operators
Core Google search operators used for advanced searching, OSINT and security research.

---

# Basic Operators
## site:
Description:
Limit search results to a specific domain.

Syntax:
site:example.com

Examples:
site:github.com security
site:example.com

---

## filetype:
Description:
Search for specific file extensions.

Syntax:
filetype:extension

Examples:
filetype:pdf report
filetype:xlsx

---

## inurl:
Description:
Search for keywords inside URLs.

Syntax:
inurl:keyword

Examples:
inurl:login
inurl:admin

---

## allinurl:
Description:
Search URLs containing all specified keywords.

Syntax:
allinurl:keyword1 keyword2


Example:
allinurl:admin login

---

## intitle:
Description:
Search pages with a specific keyword in the title.

Syntax:
intitle:keyword

Examples:
intitle:dashboard
intitle:"index of"

---

## allintitle:
Description:
Search titles containing all specified keywords.

Syntax:
allintitle:keyword1 keyword2

Example:
allintitle:admin panel

---

## intext:
Description:
Search for keywords inside page content.

Syntax:
intext:"keyword"

Examples:
intext:"documentation"
intext:"privacy policy"

---

## allintext:
Description:
Search pages containing all specified text keywords.

Syntax:
allintext:keyword1 keyword2

Example:
allintext:username password

---

# Combination Operators
## OR
Description:
Search for multiple alternatives.

Syntax:
keyword1 OR keyword2

Examples:
admin OR login
security OR cybersecurity

---

## -
Description:
Exclude keywords from results.

Syntax:
keyword -excluded

Examples:
security -course
python -download

---

## ""
Description:
Search for an exact phrase.

Syntax:
"exact phrase"

Examples:
"forgot password"
"privacy policy"

---

## ()
Description:
Group multiple search operators.

Syntax:
(keyword1 OR keyword2)


Example:
(site:example.com OR site:test.com)

---

# Advanced Operators
## before:
Description:
Find pages published before a specific date.

Syntax:
before:YYYY-MM-DD

Example:
before:2025-01-01


---

## after:
Description:
Find pages published after a specific date.

Syntax:
after:YYYY-MM-DD

Example:
after:2024-01-01

---

## related:
Description:
Find websites related to another website.

Syntax:
related:example.com

Example:
related:github.com

---

## define:
Description:
Find definitions of a word.

Syntax:
define:keyword

Example:
define:malware

---

# URL Related Operators
## cache:
Description:
Search cached versions of pages.

Syntax:
cache:example.com

---

## link:
Description:
Find pages linking to a website.

Syntax:
link:example.com

---

# Common Operator Combinations
Find files:
site:example.com filetype:pdf

Search login-related pages:
site:example.com inurl:login

Search keywords inside a website:
site:example.com intext:"keyword"


Search specific page titles:
site:example.com intitle:"keyword"

---

# Notes
- Operators can be combined to create advanced search queries.
- Results depend on search engine indexing.
- Use only for authorized security research and OSINT activities.