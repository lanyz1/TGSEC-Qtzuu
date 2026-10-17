# Bug Bounty - SSRF
A practical collection of Server-Side Request Forgery (SSRF) reconnaissance concepts, research areas, and testing methodology for authorized bug bounty programs.

---

# Overview
## SSRF
SSRF (Server-Side Request Forgery) is a security issue where an application server can be influenced to make requests to unintended locations.
In SSRF scenarios, the server becomes the component making the request instead of the user's browser.
Common affected functionality:
- URL fetchers
- Image processors
- Webhooks
- Import features
- Document processors
- External integrations

---

# SSRF Reconnaissance
## URL Parameters
site:example.com inurl:url
site:example.com inurl=uri
site:example.com inurl=link
site:example.com inurl=path

## Callback Parameters
site:example.com inurl:callback
site:example.com inurl=webhook
site:example.com inurl=notify

---

# Common SSRF Entry Points
## Image Loading
Examples:
- Remote image import
- Avatar fetching
- Image preview systems

## File Import
Examples:
- External file processing
- Remote document import
- Data synchronization

## Webhooks
Examples:
- Notification systems
- Third-party integrations
- Event callbacks

## URL Preview Features
Examples:
- Link previews
- Metadata extraction
- Content fetching

---

# API SSRF Discovery
## API URL Parameters
site:example.com inurl:api (url OR uri OR link)

## Webhook APIs
site:example.com inurl:api (webhook OR callback)

## Import APIs
site:example.com inurl:api (import OR fetch)

---

# SSRF-Related Parameters
Common parameter names:
- url
- uri
- link
- path
- source
- target
- destination
- callback
- webhook
- redirect
- image
- file
- fetch

---

# SSRF Research Workflow
## Phase 1 - Discovery
1. Identify features that process external resources.
2. Find URL-related parameters.
3. Identify API endpoints.
4. Map server-side request functionality.

---

## Phase 2 - Analysis
Review:
- URL handling logic
- Input validation
- Request filtering
- Allowed destinations
- Application behavior

---

## Phase 3 - Validation
1. Confirm the functionality belongs to an authorized target.
2. Understand expected application behavior.
3. Verify security impact safely.
4. Document evidence.
5. Follow program requirements.

---

# SSRF Categories
## Basic SSRF
The application makes server-side requests based on user input.

## Blind SSRF
The server makes the request but the response is not directly visible.

## Internal Resource Access
Applications may unintentionally interact with internal services.

## Third-Party Service Interaction
Applications may communicate with external systems through user-controlled input.

---

# SSRF Documentation Template
| Field | Description |
|---|---|
| Endpoint | Affected URL/API |
| Parameter | User-controlled input |
| Function | URL fetching feature |
| Request Type | Server-side request behavior |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# SSRF Impact Areas
Potential impacts may include:
- Unauthorized server-side requests
- Exposure of internal resources
- Access to unintended services
- Information disclosure
- Security boundary issues

Impact depends on:
- Application architecture
- Network design
- Access controls
- Filtering mechanisms

---

# Prevention Concepts
Developers can reduce SSRF risks by:
- Validating and restricting URLs
- Allowing only required destinations
- Blocking unnecessary internal access
- Using network segmentation
- Avoiding direct user-controlled server requests
- Applying secure allowlists

---

# Important Notes
- URL parameters do not automatically indicate SSRF.
- Many applications legitimately fetch external resources.
- Testing must respect authorization and scope.
- Avoid accessing private systems without permission.
- Do not perform destructive requests.
- Minimize interaction with sensitive services.
- Follow bug bounty rules.

---

# Responsible Research
SSRF research should focus on identifying unsafe server-side request handling while minimizing impact.Only test authorized applications and follow responsible disclosure practices.