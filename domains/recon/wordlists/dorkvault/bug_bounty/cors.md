# Bug Bounty - CORS
A practical collection of Cross-Origin Resource Sharing (CORS) reconnaissance concepts, research areas, and testing methodology for authorized bug bounty programs.

---

# Overview
## CORS
CORS (Cross-Origin Resource Sharing) is a browser security mechanism that controls how web applications request resources from different origins.
An origin consists of:
- Protocol
- Domain
- Port

Example:
https://example.com/

---

# CORS Reconnaissance
## CORS References
site:example.com (CORS OR "Cross-Origin Resource Sharing")

## API Discovery
site:example.com inurl:api

## Developer Documentation
site:example.com (developer OR api) (cors OR documentation)

---

# CORS-Related Headers
Common CORS headers:

## Access-Control-Allow-Origin
Defines which origins can access resources.

## Access-Control-Allow-Methods
Defines allowed HTTP methods.

## Access-Control-Allow-Headers
Defines allowed request headers.

## Access-Control-Allow-Credentials
Controls whether credentials can be included.

## Origin Header
Used by browsers to indicate the requesting origin.

---

# CORS Configuration Discovery
## API Endpoints
Possible locations:
- REST APIs
- GraphQL APIs
- Authentication APIs
- Public resources

## Documentation
Possible locations:
- API documentation
- Developer portals
- Integration guides

## JavaScript Applications
Possible locations:
- Frontend applications
- AJAX requests
- Fetch requests

---

# CORS Research Areas
## Origin Validation
Review:
- Allowed origins
- Wildcard usage
- Dynamic origin handling
- Origin reflection behavior

## Credential Handling
Review:
- Authentication cookies
- Session handling
- Cross-origin requests

## API Access Control
Review:
- Public APIs
- Private APIs
- User-specific resources

---

# Common CORS Misconfigurations
## Overly Permissive Origins
Examples:
- Unnecessary allowed origins
- Excessive trust relationships

## Wildcard Configuration
Examples:
- Broad resource exposure
- Incorrect origin policies

## Improper Credential Handling
Examples:
- Incorrect credential settings
- Unsafe cross-origin authentication flows

## Missing Origin Validation
Examples:
- Weak origin checking
- Incorrect validation logic

---

# CORS Research Workflow
## Phase 1 - Discovery
1. Identify APIs and cross-origin resources.
2. Review application architecture.
3. Identify CORS-related headers.
4. Understand expected behavior.

---

## Phase 2 - Analysis
Review:
- Allowed origins
- Allowed methods
- Allowed headers
- Credential policies
- Application requirements

---

## Phase 3 - Validation
1. Confirm the target is authorized.
2. Understand intended CORS behavior.
3. Verify security impact safely.
4. Document findings.
5. Report responsibly.

---

# CORS Documentation Template
| Field | Description |
|---|---|
| Endpoint | Affected resource |
| Origin Behavior | CORS response behavior |
| Headers | Related headers |
| Authentication | Credential requirements |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# Impact Areas
Potential impacts may include:
- Unauthorized cross-origin data access
- Exposure of sensitive responses
- Abuse of authenticated requests
- Security boundary issues

Impact depends on:
- Application design
- Authentication mechanism
- Data sensitivity
- Browser behavior

---

# Prevention Concepts
Developers can reduce CORS risks by:
- Allowing only trusted origins
- Avoiding unnecessary wildcard policies
- Validating origins properly
- Restricting allowed methods
- Reviewing credential settings
- Applying least privilege principles

---

# Important Notes
- CORS configuration alone does not automatically indicate a vulnerability.
- Browsers enforce CORS policies.
- Public resources may intentionally allow cross-origin access.
- Security impact depends on exposed data and authentication context.
- Always verify scope before testing.
- Do not access unauthorized data.
- Respect bug bounty rules and limitations.

---

# Responsible Research
CORS research should focus on identifying unsafe cross-origin configurations while minimizing impact.
Only perform testing against authorized applications and follow responsible disclosure practices.