# GitHub Secrets Discovery
A collection of GitHub secrets discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
Repositories may contain configuration data, credentials, or sensitive information accidentally committed during development.
Common examples:
- API keys
- Access tokens
- Service credentials
- Private configuration references
- Deployment secrets

The presence of a secret-like string does not automatically mean a security issue exists. Always verify ownership, scope, and authorization.

---

# Secret Discovery Areas
## Source Code
Review:
- Application code
- Configuration logic
- Authentication flows
- Integration files

---

## Configuration Files
Common locations:
- Environment files
- Configuration files
- Deployment files
- CI/CD files

Examples:
- .env
- config files
- settings files

---

## Documentation
Review:
- Setup guides
- Installation instructions
- Examples
- Development notes

---

## Commit History
Review:
- Previous changes
- Removed files
- Historical project states

---

# Common Secret Categories
## API Credentials
Examples:
- Service keys
- Application tokens
- Integration credentials

---

## Cloud Credentials
Examples:
- Cloud service references
- Storage configuration
- Deployment credentials

---

## Database Information
Examples:
- Connection references
- Database configuration
- Service settings

---

## Third-Party Integrations
Examples:
- External services
- Payment systems
- Communication platforms

---

# Secret-Related Files
Common files to review:
.env
.env.example
config.yml
config.json
settings.json
docker-compose.yml

---

# GitHub Search Concepts
## File-Based Search
Search for specific file types:
filename:.env
filename:config
filename:settings

---

## Technology-Based Search
Examples:
language:javascript
language:python
language:go

---

## Organization-Based Search
Search within authorized organizations:
org:organization-name

---

# Secret Analysis Workflow
## Phase 1 - Discovery
Identify:
- Related repositories
- Project technologies
- Configuration files
- Development resources

---

## Phase 2 - Classification
Classify discovered information:
- Public configuration
- Example values
- Test data
- Sensitive-looking information

---

## Phase 3 - Validation
Before reporting:
- Confirm asset ownership
- Confirm scope
- Determine actual impact
- Avoid accessing unauthorized services

---

# Documentation Template
| Field | Description |
|---|---|
| Repository | Repository name |
| File | Location of information |
| Type | Information category |
| Exposure | Public visibility |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional details |

---

# Prevention Concepts
Developers can reduce accidental exposure by:
- Using environment variables
- Removing sensitive data from repositories
- Reviewing commits before publishing
- Using secret management systems
- Applying access controls
- Scanning repositories regularly

---

# Security Research Notes
When reviewing public repositories:
- Do not attempt unauthorized access.
- Do not use discovered credentials.
- Do not interact with external services without permission.
- Do not collect unnecessary sensitive information.
- Follow responsible disclosure practices.

---

# Responsible Research
GitHub secrets research should focus on identifying accidental exposure and helping organizations improve their security posture.
Always follow:
- Authorization requirements
- Bug bounty rules
- Responsible disclosure guidelines
- Legal boundaries