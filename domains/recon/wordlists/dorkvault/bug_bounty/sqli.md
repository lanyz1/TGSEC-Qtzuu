# Bug Bounty - SQL Injection (SQLi)
A practical collection of SQL Injection reconnaissance concepts, research areas, and testing methodology for authorized bug bounty programs.

---

# Overview
## SQL Injection
SQL Injection (SQLi) is a security issue that occurs when an application handles user-controlled input in a way that affects database queries.
SQL databases commonly store:
- User accounts
- Application data
- Transactions
- Content
- Configuration information

---

# SQLi Reconnaissance
## Database Keywords
site:example.com (database OR db OR mysql OR sql)

## Query Parameters
site:example.com inurl:id
site:example.com inurl:user
site:example.com inurl:search
site:example.com inurl:category

---

# Common SQLi Entry Points
## URL Parameters
Examples:
- id
- user_id
- product_id
- category
- search
- page

## Form Inputs
Examples:
- Login forms
- Search fields
- Filters
- Registration forms
- Feedback forms

## API Inputs
Examples:
- JSON parameters
- Query parameters
- Request body fields

---

# SQLi Discovery Areas
## Search Functionality
Possible locations:
- Product search
- User search
- Internal search systems

## Authentication Functions
Possible locations:
- Login systems
- Account verification
- User lookup

## Data Filtering
Possible locations:
- Categories
- Sorting
- Filtering options

## Reports and Exports
Possible locations:
- Data reports
- Export functions
- Analytics pages

---

# Database Technology Discovery
## MySQL References
site:example.com (mysql OR MariaDB)

## PostgreSQL References
site:example.com (postgres OR PostgreSQL)

## Microsoft SQL Server
site:example.com ("SQL Server" OR MSSQL)

## Oracle Database
site:example.com (Oracle OR database)

---

# API SQLi Research
## API Parameters
site:example.com inurl:api (id OR query OR search)

## JSON APIs
site:example.com ("application/json" OR json)

## API Documentation
site:example.com (api OR developer) (docs OR documentation)

---

# SQLi Research Workflow
## Phase 1 - Discovery
1. Identify database-related functionality.
2. Find user-controlled inputs.
3. Map parameters and endpoints.
4. Understand application behavior.

---

## Phase 2 - Analysis
Review:
- Input handling
- Database interaction points
- Error handling
- Application responses
- Data processing logic

---

## Phase 3 - Validation
1. Confirm the target is authorized.
2. Verify the behavior safely.
3. Determine actual security impact.
4. Document evidence.
5. Follow responsible disclosure.

---

# SQL Injection Categories
## Classic SQL Injection
Occurs when user input directly influences database queries.

## Blind SQL Injection
The application does not directly reveal database responses, but behavior may indicate differences.

## Error-Based SQL Injection
Database errors may reveal information about query processing.

## Time-Based SQL Injection
Application response behavior may indicate database query execution.

---

# SQLi Documentation Template
| Field | Description |
|---|---|
| Endpoint | Affected location |
| Parameter | Input location |
| Database | Known database type |
| Behavior | Observed behavior |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# SQLi Impact Areas
Potential impacts may include:
- Unauthorized data access
- Sensitive information exposure
- Database manipulation
- Application compromise scenarios
- Data integrity issues

Impact depends on:
- Database permissions
- Application architecture
- Query design
- Security controls

---

# Prevention Concepts
Developers can reduce SQL Injection risks by:
- Using prepared statements
- Applying parameterized queries
- Validating input
- Limiting database permissions
- Avoiding dynamic query construction
- Using secure database libraries

---

# Important Notes
- A database-related parameter does not automatically mean SQL Injection exists.
- Error messages alone do not always indicate a vulnerability.
- Never access unauthorized data.
- Do not modify or delete database content.
- Always test within the allowed scope.
- Respect bug bounty rules and limitations.

---

# Responsible Research
SQL Injection research should focus on identifying unsafe database interaction patterns while minimizing impact.
Only perform testing on authorized targets and follow responsible disclosure practices.