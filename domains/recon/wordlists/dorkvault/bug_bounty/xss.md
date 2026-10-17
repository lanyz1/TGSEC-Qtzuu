# Bug Bounty - XSS
A practical collection of Cross-Site Scripting (XSS) reconnaissance concepts, research areas, and testing methodology for authorized bug bounty programs.

---

# Overview
## XSS
XSS (Cross-Site Scripting) is a client-side security issue where untrusted data is processed by a browser in a way that can affect application behavior.
Common XSS categories:
- Reflected XSS
- Stored XSS
- DOM-Based XSS

---

# XSS Reconnaissance
## Search Parameters
site:example.com inurl:q
site:example.com inurl:search
site:example.com inurl:query
site:example.com inurl:name
site:example.com inurl:message

---

# Input Reflection Discovery
## Common Input Locations
Search for:
- Search fields
- Comments
- Profile fields
- Feedback forms
- Contact forms
- User-generated content
- URL parameters

---

# JavaScript-Based Discovery
## JavaScript Files
site:example.com filetype:js

## JavaScript DOM References
site:example.com filetype:js (innerHTML OR document.write OR location)

## Client-Side Input Handling
site:example.com filetype:js (input OR parameter OR query)

---

# XSS Types
## Reflected XSS
Characteristics:
- Input is immediately reflected in the response.
- Commonly appears through URL parameters or form submissions.
- Requires user interaction in many cases.

Common locations:
- Search pages
- Error messages
- Redirect pages
- Query parameters

---

## Stored XSS
Characteristics:
- User input is stored by the application.
- The payload may affect multiple users.
- Often appears in user-generated content.

Common locations:
- Comments
- Profiles
- Messages
- Reviews
- Posts

---

## DOM-Based XSS
Characteristics:
- Happens inside client-side JavaScript.
- The browser modifies the page using unsafe data handling.

Common sources:
- URL fragments
- Query parameters
- Browser storage
- Client-side variables

---

# XSS Research Workflow
## Phase 1 - Discovery
1. Identify user-controlled inputs.
2. Identify parameters.
3. Identify forms and interactive features.
4. Review JavaScript behavior.
5. Map data flow.

---

## Phase 2 - Analysis
Review:
- Input handling
- Output encoding
- HTML context
- JavaScript context
- DOM manipulation
- Security controls

---

## Phase 3 - Validation
1. Confirm the target is in scope.
2. Understand expected behavior.
3. Verify the security impact.
4. Document reproducible evidence.
5. Follow responsible disclosure.

---

# Common XSS Locations
## URL Parameters
Examples:
- Search
- Filters
- Redirect parameters
- Language parameters

## Forms
Examples:
- Comments
- Feedback
- Profile information
- Messages

## APIs
Examples:
- JSON responses
- User-generated content
- Data rendering systems

## Client-Side Applications
Examples:
- Single Page Applications
- JavaScript frameworks
- Dynamic content rendering

---

# XSS Documentation Template
| Field | Description |
|---|---|
| URL | Affected location |
| Parameter | User-controlled input |
| Type | Reflected / Stored / DOM |
| Context | HTML, JS, DOM |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# XSS Impact Areas
Potential impacts may include:
- Unauthorized actions through user sessions
- Data exposure
- Account compromise scenarios
- Phishing opportunities
- Application integrity issues

Impact depends on:
- Application design
- User privileges
- Browser behavior
- Security controls

---

# Prevention Concepts
Developers can reduce XSS risks by:
- Applying proper output encoding
- Validating input appropriately
- Using secure frameworks
- Implementing Content Security Policy (CSP)
- Avoiding unsafe DOM manipulation
- Following secure coding practices

---

# Important Notes
- Not every reflected input is a vulnerability.
- User input appearing in a page does not automatically mean XSS exists.
- Modern frameworks may provide built-in protections.
- Always verify the real security impact.
- Do not test users outside authorized scope.
- Avoid collecting sensitive information.
- Respect bug bounty rules.

---

# Responsible Research
XSS research should focus on identifying unsafe handling of user-controlled data while minimizing impact.
Only perform testing on authorized targets and follow responsible disclosure practices.