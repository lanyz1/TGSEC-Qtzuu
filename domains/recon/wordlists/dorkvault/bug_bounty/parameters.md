# Bug Bounty - Parameters
A practical collection of parameter discovery queries, patterns and reconnaissance techniques for authorized bug bounty research.

---

# Parameter Discovery
## Common Parameter Keywords
site:example.com inurl:id
site:example.com inurl:user
site:example.com inurl:account
site:example.com inurl:page
site:example.com inurl:file
site:example.com inurl:path
site:example.com inurl:url
site:example.com inurl:redirect

---

# Search Parameters
## Query
site:example.com inurl:q

## Search
site:example.com inurl:search

## Query String
site:example.com inurl:query

## Keyword
site:example.com inurl:keyword

---

# Identifier Parameters
## ID
site:example.com inurl:id

## User ID
site:example.com inurl:userid

## Account ID
site:example.com inurl:accountid

## Object ID
site:example.com inurl:objectid

## Product ID
site:example.com inurl:productid

## Order ID
site:example.com inurl:orderid

---

# File Parameters
## File
site:example.com inurl:file

## Filename
site:example.com inurl:filename

## Path
site:example.com inurl:path

## Document
site:example.com inurl:document

## Download
site:example.com inurl:download

---

# URL and Redirect Parameters
## URL
site:example.com inurl:url

## Redirect
site:example.com inurl:redirect

## Return URL
site:example.com inurl:return

## Callback
site:example.com inurl:callback

## Next
site:example.com inurl:next

## Continue
site:example.com inurl:continue

---

# Authentication Parameters
## Username
site:example.com inurl:username

## Email
site:example.com inurl:email

## Token
site:example.com inurl:token

## Session
site:example.com inurl:session

## Authentication
site:example.com inurl:auth

---

# API Parameters
## API Query
site:example.com inurl:api inurl:id

## API User
site:example.com inurl:api inurl:user

## API Account
site:example.com inurl:api inurl:account

## API Resource
site:example.com inurl:api inurl:resource

---

# Pagination Parameters
## Page
site:example.com inurl:page

## Offset
site:example.com inurl:offset

## Limit
site:example.com inurl:limit

## Cursor
site:example.com inurl:cursor

## Start
site:example.com inurl:start

---

# Sorting and Filtering Parameters
## Sort
site:example.com inurl:sort

## Order
site:example.com inurl:order

## Filter
site:example.com inurl:filter

## Category
site:example.com inurl:category

## Type
site:example.com inurl:type

---

# Language and Localization Parameters
## Language
site:example.com inurl:lang

## Locale
site:example.com inurl:locale

## Region
site:example.com inurl:region

## Country
site:example.com inurl:country

---

# Content Parameters
## Title
site:example.com inurl:title

## Name
site:example.com inurl:name

## Description
site:example.com inurl:description

## Message
site:example.com inurl:message

## Content
site:example.com inurl:content

---

# API Documentation
## Parameter Documentation
site:example.com (api OR developer) (parameter OR parameters)

## API Examples
site:example.com (api OR developer) ("?id=" OR "?user=")

## OpenAPI
site:example.com ("OpenAPI" OR Swagger) parameter

---

# JavaScript Parameter Discovery
## JavaScript Files
site:example.com filetype:js

## JavaScript + Parameters
site:example.com filetype:js (parameter OR params)

## JavaScript + Query
site:example.com filetype:js ("?id=" OR "?url=" OR "?page=")

## JavaScript + API
site:example.com filetype:js ("/api/" OR "api.")

---

# Historical Parameter Discovery
## Public References
"example.com" ("?id=" OR "?user=" OR "?page=")

## URL Parameter References
"example.com" ("?url=" OR "?redirect=" OR "?next=")

## API Parameter References
"example.com" ("?api_key=" OR "?token=" OR "?id=")

---

# Parameter Categories
Classify discovered parameters into:
- Identification
- Authentication
- Authorization
- Search
- Pagination
- Filtering
- Sorting
- File Handling
- URL Handling
- Redirects
- Callback
- Localization
- Content
- API Resources
- Account Management

---

# Parameter Research Workflow
1. Identify an authorized target.
2. Discover publicly indexed URLs.
3. Search for common parameter names.
4. Review API documentation.
5. Review publicly available JavaScript.
6. Search historical public references.
7. Group parameters by functionality.
8. Remove duplicates.
9. Verify that the associated endpoint is in scope.
10. Prioritize parameters for authorized testing.

---

# Parameter Documentation
Recommended fields:
| Field | Description |
|---|---|
| Parameter | Parameter name |
| Endpoint | Associated endpoint |
| Method | HTTP method |
| Type | Query, Path, Body, Header |
| Function | Intended purpose |
| Source | Discovery source |
| Scope | In-scope / Out-of-scope |
| Notes | Additional observations |

---

# Vulnerability-Oriented Research
Parameters can be useful during authorized testing for investigating:
- IDOR / BOLA
- XSS
- SQL Injection
- SSRF
- Open Redirect
- LFI / RFI
- Access Control Issues
- Business Logic Issues
- Input Validation Issues

The presence of a parameter does not indicate that it is vulnerable.

---

# Important Notes
- Search engine indexing is incomplete.
- Parameter names may be outdated or unrelated.
- A parameter should not be tested simply because it was discovered.
- Always verify the endpoint and authorization scope first.
- Do not submit destructive payloads.
- Do not access another user's private information.
- Respect rate limits and program rules.
- Perform active vulnerability testing only when explicitly authorized.

---

# Responsible Research
Parameter discovery should be used to map application functionality and identify potential areas for authorized security testing.
The goal is to understand how an application accepts input without causing unnecessary impact to the target or its users.