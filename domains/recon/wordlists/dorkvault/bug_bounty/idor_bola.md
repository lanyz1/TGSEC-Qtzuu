# Bug Bounty - IDOR / BOLA
A practical collection of reconnaissance concepts, research areas, and testing methodology for identifying Insecure Direct Object Reference (IDOR) and Broken Object Level Authorization (BOLA) issues during authorized bug bounty programs.

---

# Overview
## IDOR
IDOR (Insecure Direct Object Reference) occurs when an application exposes direct references to internal objects such as:
- User IDs
- Account IDs
- File IDs
- Order IDs
- Document IDs
- Resource IDs

without properly validating whether the current user is authorized to access that object.

---

## BOLA
BOLA (Broken Object Level Authorization) is an API-focused access control issue where an application fails to properly verify permissions when accessing specific objects.

Common objects:
- Users
- Profiles
- Orders
- Messages
- Documents
- Transactions
- Projects

---

# Object Discovery
## ID Parameters
site:example.com inurl:id

## User References
site:example.com (user_id OR userid OR uid)

## Account References
site:example.com (account_id OR account)

## Resource References
site:example.com (resource OR object OR item)

## Document References
site:example.com (document OR file OR report)

---

# API Object Discovery
## API Resources
site:example.com inurl:api (users OR accounts OR orders)

## User APIs
site:example.com inurl:api/user

## Account APIs
site:example.com inurl:api/account

## Object APIs
site:example.com inurl:api/resource

---

# Common Object Types
## User Objects
Examples:
- User profile
- User settings
- User information
- User preferences

## Financial Objects
Examples:
- Orders
- Payments
- Invoices
- Transactions

## Content Objects
Examples:
- Posts
- Comments
- Documents
- Files

## Business Objects
Examples:
- Projects
- Teams
- Organizations
- Reports

---

# Object Mapping
Create an inventory of:
| Object | Identifier | Location |
|---|---|---|
| User | user_id | API / Web |
| Order | order_id | API |
| File | file_id | Download |
| Document | document_id | Application |

---

# Authorization Research Areas
Research areas:
- Object ownership validation
- User permission checks
- Role-based access control
- Resource isolation
- API authorization logic
- Multi-tenant separation

---

# IDOR / BOLA Research Workflow
## Phase 1 - Discovery
1. Identify application objects.
2. Identify object identifiers.
3. Locate endpoints handling objects.
4. Understand normal application behavior.

---

## Phase 2 - Mapping
Document:
- Endpoint
- HTTP method
- Object type
- Identifier location
- Expected permission model

---

## Phase 3 - Validation
During authorized testing:
1. Verify the endpoint behavior.
2. Confirm authorization requirements.
3. Check whether access controls are correctly applied.
4. Document security impact.

---

# Common Locations
IDOR/BOLA issues are often related to:

## URL Parameters
Examples:
- /profile?id=
- /document?id=
- /order?id=

## API Parameters
Examples:
- user_id
- account_id
- object_id
- resource_id

## JSON Bodies
Examples:
- User references
- Resource identifiers
- Ownership fields

## Headers
Examples:
- Custom identifiers
- Context information

---

# Documentation Template
| Field | Description |
|---|---|
| Endpoint | Affected URL/API |
| Method | HTTP method |
| Object | Affected resource |
| Identifier | Object reference |
| Authorization | Expected permission |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional details |

---

# Impact Examples
Potential impacts may include:
- Unauthorized access to resources
- Exposure of user data
- Access to other accounts' objects
- Unauthorized modification of resources
- Privacy violations
- Business impact

Impact depends on:
- Object sensitivity
- User permissions
- Application design
- Program rules

---

# Prevention Concepts
Developers can reduce IDOR/BOLA risks by:
- Enforcing server-side authorization
- Validating object ownership
- Avoiding client-side trust
- Using centralized authorization controls
- Applying least privilege principles
- Testing access control paths

---

# Important Notes
- Finding an identifier does not mean a vulnerability exists.
- Object references are common in modern applications.
- Authorization decisions must always be verified by the server.
- Never access another user's data without explicit authorization.
- Never modify real user resources during testing.
- Respect bug bounty rules and scope.
- Minimize data exposure during research.

---

# Responsible Research
IDOR and BOLA testing should only be performed against authorized targets.
The objective is to identify broken authorization controls responsibly while protecting user privacy and minimizing impact.