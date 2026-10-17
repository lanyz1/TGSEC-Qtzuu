# Bug Bounty - Open Redirect
A practical collection of Open Redirect reconnaissance concepts, research areas, and testing methodology for authorized bug bounty programs.

---

# Overview
## Open Redirect
Open Redirect is a security issue where an application allows users to control a redirect destination without properly validating the target URL.
Common affected functionality:
- Login redirects
- External links
- Callback URLs
- Marketing campaigns
- Tracking systems
- Authentication flows

---

# Open Redirect Reconnaissance
## Redirect Parameters
site:example.com inurl:url
site:example.com inurl=redirect
site:example.com inurl=return
site:example.com inurl=next
site:example.com inurl=target

---

# Common Redirect Parameters
Common parameter names:
- url
- redirect
- redirect_url
- return
- return_url
- next
- continue
- destination
- target
- callback
- goto
- link
- out

---

# Redirect Function Discovery
## Login Redirects
site:example.com (login OR signin) (redirect OR return)

## OAuth Redirects
site:example.com (oauth OR authorize) (redirect OR callback)

## External Links
site:example.com (out OR external OR redirect)

---

# Application Areas
## Authentication Systems
Possible locations:
- Login pages
- Logout pages
- Account verification
- OAuth flows

## Marketing Systems
Possible locations:
- Tracking links
- Campaign URLs
- Referral systems

## Navigation Systems
Possible locations:
- External resources
- Link shorteners
- Redirect handlers

---

# Open Redirect Research Workflow
## Phase 1 - Discovery
1. Identify redirect-related functionality.
2. Find URL parameters.
3. Map redirect behavior.
4. Understand expected destinations.

---

## Phase 2 - Analysis
Review:
- Redirect validation
- URL parsing logic
- Allowed destinations
- Application behavior
- User interaction flow

---

## Phase 3 - Validation
1. Confirm the target is authorized.
2. Verify redirect behavior safely.
3. Determine security impact.
4. Document evidence.
5. Follow responsible disclosure.

---

# Common Redirect Locations
## Login Flow
Examples:
- After authentication
- Account switching
- Session expiration

## Password Recovery
Examples:
- Verification links
- Recovery workflows

## OAuth Flow
Examples:
- Authorization callbacks
- Third-party integrations

## External Navigation
Examples:
- Outbound links
- Resource forwarding

---

# Open Redirect Documentation Template
| Field | Description |
|---|---|
| Endpoint | Redirect location |
| Parameter | Redirect parameter |
| Function | Redirect purpose |
| Behavior | Observed behavior |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# Impact Areas
Potential impacts may include:
- Phishing assistance
- Trust abuse
- Security workflow manipulation
- User confusion
- Abuse of trusted domains

Impact depends on:
- Application context
- User interaction
- Authentication flows
- Program rules

---

# Prevention Concepts
Developers can reduce Open Redirect risks by:
- Validating redirect destinations
- Using allowlists
- Avoiding user-controlled redirects
- Restricting external destinations
- Using safe navigation mechanisms

---

# Important Notes
- A redirect parameter does not automatically indicate a vulnerability.
- Redirect functionality is common in modern applications.
- Context determines security impact.
- Never use findings against real users.
- Always verify scope before testing.
- Respect bug bounty rules and limitations.

---

# Responsible Research
Open Redirect research should focus on identifying unsafe redirect handling while minimizing impact.
Only test authorized applications and follow responsible disclosure practices.