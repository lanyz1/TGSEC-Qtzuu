# Bug Bounty - Endpoints
A practical collection of endpoint discovery queries and techniques for identifying publicly observable application routes, URLs and API endpoints during authorized bug bounty research.

---

# URL Discovery
## Site URLs
site:example.com

## URLs Containing API
site:example.com inurl:api

## URLs Containing Admin
site:example.com inurl:admin

## URLs Containing Login
site:example.com inurl:login

## URLs Containing Dashboard
site:example.com inurl:dashboard

## URLs Containing Portal
site:example.com inurl:portal

---

# Common Endpoint Names
## Authentication
site:example.com (inurl:login OR inurl:signin OR inurl:auth)

## Registration
site:example.com (inurl:register OR inurl:signup)

## Password Reset
site:example.com (inurl:reset OR inurl:forgot-password OR inurl:password-reset)

## User Account
site:example.com (inurl:account OR inurl:profile OR inurl:user)

## Administration
site:example.com (inurl:admin OR inurl:administrator OR inurl:manage)

---

# API Endpoint Discovery
## API
site:example.com inurl:api

## REST API
site:example.com ("REST API" OR "RESTful API")

## GraphQL
site:example.com (GraphQL OR graphql)

## API Versions
site:example.com inurl:api (v1 OR v2 OR v3 OR v4)

## API Documentation
site:example.com (api OR developer) (documentation OR docs)

---

# Functional Endpoints
## Search
site:example.com (inurl:search OR inurl:query)

## Upload
site:example.com (inurl:upload OR inurl:file-upload)

## Download
site:example.com (inurl:download OR inurl:export)

## Import
site:example.com (inurl:import)

## Export
site:example.com (inurl:export)

## Payment
site:example.com (inurl:payment OR inurl:checkout)

## Orders
site:example.com (inurl:order OR inurl:orders)

## Products
site:example.com (inurl:product OR inurl:products)

---

# Parameter-Oriented Endpoint Discovery
## Query Parameters
site:example.com inurl:"?"

## Common Parameter Keywords
site:example.com (inurl:id OR inurl:user OR inurl:account)

## File Parameters
site:example.com (inurl:file OR inurl:path OR inurl:document)

## Redirect Parameters
site:example.com (inurl:url OR inurl:redirect OR inurl:return)

## Search Parameters
site:example.com (inurl:q OR inurl:query OR inurl:search)

---

# JavaScript Endpoint Discovery
## JavaScript Files
site:example.com filetype:js

## JavaScript + API
site:example.com filetype:js (api OR endpoint)

## JavaScript + URL
site:example.com filetype:js ("http://" OR "https://")

## JavaScript + Fetch
site:example.com filetype:js (fetch OR XMLHttpRequest)

---

# Documentation-Based Discovery
## API Documentation
site:example.com (api OR API) (docs OR documentation)

## Developer Documentation
site:example.com (developer OR developers) (docs OR documentation)

## Swagger
site:example.com (swagger OR "OpenAPI")

## API Specification
site:example.com ("OpenAPI specification" OR "API specification")

---

# Common API Paths
## Versioned APIs
site:example.com inurl:api/v1
site:example.com inurl:api/v2
site:example.com inurl:api/v3

## REST Resources
site:example.com inurl:api (users OR accounts OR products OR orders)

---

# Historical Endpoint Discovery
## Archived References
"example.com" ("/api/" OR "/admin/" OR "/login/")

## Historical API References
"example.com" ("api/v1" OR "api/v2" OR "api/v3")

## Public Repository References
"example.com" site:github.com

## GitLab References
"example.com" site:gitlab.com

---

# Endpoint Classification
Classify discovered endpoints into:
- Authentication
- Registration
- Account Management
- Administration
- Search
- Upload
- Download
- Import
- Export
- Payment
- Orders
- Products
- API
- GraphQL
- Documentation
- File Handling
- Redirects

---

# Endpoint Research Workflow
1. Identify the authorized target.
2. Discover indexed URLs.
3. Search for common application routes.
4. Identify API documentation.
5. Inspect publicly available JavaScript resources.
6. Search public repositories for endpoint references.
7. Classify discovered endpoints.
8. Verify that endpoints belong to an in-scope asset.
9. Prioritize endpoints based on application functionality.
10. Perform active testing only when explicitly authorized.

---

# Endpoint Documentation
Recommended fields:
| Field | Description |
|---|---|
| Endpoint | URL or route |
| Method | GET, POST, PUT, DELETE, etc. |
| Function | Purpose of the endpoint |
| Parameters | Known input parameters |
| Authentication | Required / Not required / Unknown |
| Source | Discovery source |
| Scope | In-scope / Out-of-scope |
| Notes | Additional observations |

---

# Important Notes
- Search engines do not provide complete endpoint enumeration.
- Some indexed endpoints may be obsolete.
- Endpoint discovery alone does not indicate a vulnerability.
- Do not send unauthorized requests to discovered endpoints.
- Do not attempt authentication bypasses or destructive actions.
- Verify scope before active testing.
- Respect rate limits and program-specific restrictions.
- Minimize interaction with sensitive functionality.

---

# Responsible Research
Endpoint discovery should be used to understand an application's publicly observable attack surface.
Only perform security testing against endpoints that belong to explicitly authorized assets and remain within the applicable bug bounty rules.