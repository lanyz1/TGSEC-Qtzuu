# Bug Bounty - APIs
A practical collection of API reconnaissance queries, discovery techniques, and research methods for authorized bug bounty programs.

---

# API Discovery
## Basic API Search
site:example.com inurl:api

## API Keyword Search
site:example.com (api OR API OR endpoint OR endpoints)

## API Documentation Search
site:example.com (api OR developer) (docs OR documentation)

## REST API Search
site:example.com ("REST API" OR "RESTful API")

## GraphQL Search
site:example.com (GraphQL OR graphql)

---

# API Documentation Discovery
## Swagger Documentation
site:example.com (swagger OR "Swagger UI")

## OpenAPI Documentation
site:example.com ("OpenAPI" OR "Open API")

## API Reference Pages
site:example.com (api OR developer) (reference OR documentation)

## Developer Portal
site:example.com (developer OR developers OR devportal)

---

# API Version Discovery
## Version 1 APIs
site:example.com inurl:api/v1

## Version 2 APIs
site:example.com inurl:api/v2

## Version 3 APIs
site:example.com inurl:api/v3

## Generic API Versions
site:example.com inurl:api (v1 OR v2 OR v3 OR version)

---

# Common API Endpoints
## Users
site:example.com inurl:api (users OR user)

## Accounts
site:example.com inurl:api (accounts OR account)

## Profiles
site:example.com inurl:api (profile OR profiles)

## Products
site:example.com inurl:api (products OR product)

## Orders
site:example.com inurl:api (orders OR order)

## Payments
site:example.com inurl:api (payment OR payments)

---

# Authentication APIs
## Login API
site:example.com inurl:api (login OR signin OR auth)

## Token API
site:example.com inurl:api (token OR access_token)

## Session API
site:example.com inurl:api (session OR sessions)

## OAuth
site:example.com (oauth OR OAuth)

---

# API Parameters Discovery
## API Parameters
site:example.com inurl:api ("?" OR "=")

## ID Parameters
site:example.com inurl:api (id OR uid OR user_id)

## File Parameters
site:example.com inurl:api (file OR filename OR path)

## URL Parameters
site:example.com inurl:api (url OR redirect OR callback)

---

# API Technology Discovery
## JSON APIs
site:example.com ("application/json" OR json)

## REST Endpoints
site:example.com ("REST" OR "RESTful")

## GraphQL Endpoints
site:example.com graphql

## API Gateway
site:example.com ("API Gateway" OR gateway)

---

# JavaScript API Discovery
## JavaScript Files
site:example.com filetype:js

## JavaScript API References
site:example.com filetype:js (api OR endpoint)

## JavaScript URLs
site:example.com filetype:js ("http://" OR "https://")

## JavaScript Tokens
site:example.com filetype:js (token OR key OR secret)

---

# Public API Resources
## API Examples
site:example.com ("api.example.com" OR "/api/")

## API Collections
site:example.com (postman OR collection)

## API Samples
site:example.com ("sample request" OR "sample response")

## API Keys References
site:example.com ("api_key" OR "apikey")

---

# API Asset Discovery
## API Subdomains
site:example.com (api.example.com OR api-dev.example.com)

## Development APIs
site:example.com (api-dev OR dev-api OR api-test)

## Staging APIs
site:example.com (api-stage OR api-staging)

## Internal API References
site:example.com (internal-api OR private-api)

---

# API Research Workflow
## Phase 1 - Discovery
1. Identify API-related subdomains.
2. Search API documentation.
3. Review JavaScript files.
4. Identify API endpoints.
5. Collect public API references.

## Phase 2 - Classification
Classify APIs into:
- REST
- GraphQL
- SOAP
- Internal APIs
- Public APIs
- Mobile APIs
- Partner APIs

## Phase 3 - Documentation
Record:
- API URL
- Endpoint
- HTTP Method
- Parameters
- Authentication Type
- Technology
- Source
- Scope

## Phase 4 - Validation
1. Verify the API belongs to the target.
2. Confirm it is in scope.
3. Understand intended functionality.
4. Perform testing only if authorized.

---

# API Documentation Template
| Field | Description |
|---|---|
| API URL | API endpoint address |
| Method | GET, POST, PUT, DELETE |
| Authentication | Required authentication type |
| Parameters | Input parameters |
| Response | Response format |
| Source | Discovery source |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# API Security Research Areas
APIs may require testing for:
- Authentication Issues
- Authorization Issues
- IDOR / BOLA
- Input Validation Issues
- Rate Limit Issues
- Information Disclosure
- Business Logic Issues
- Sensitive Data Exposure

The existence of an API does not automatically indicate a vulnerability.

---

# Important Notes
- API discovery is part of reconnaissance, not proof of vulnerability.
- Public APIs may be intentionally exposed.
- Documentation does not indicate a security issue.
- Always verify authorization and scope.
- Do not access private data.
- Do not abuse API functionality.
- Respect rate limits and program policies.
- Perform active testing only when explicitly authorized.

---

# Responsible Research
API reconnaissance should help researchers understand application architecture and identify areas for authorized security testing.
Always minimize impact and follow responsible disclosure practices.