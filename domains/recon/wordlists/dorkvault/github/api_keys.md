# GitHub API Keys Discovery
A collection of GitHub API key discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
API keys are authentication identifiers used by applications to communicate with external services.
They are commonly used for:
- APIs
- Cloud services
- Third-party integrations
- Monitoring platforms
- Development tools

During repository research, API keys may appear accidentally in:
- Source code
- Configuration files
- Documentation
- Deployment files
- Commit history

The presence of an API key pattern does not automatically mean a security issue exists.
Always verify authorization, ownership, and scope.

---

# API Key Discovery Areas
## Source Code
Review:
- Application files
- Integration code
- Service configuration
- API client implementations

---

## Configuration Files
Common locations:
- Environment files
- Application settings
- Deployment configuration
- Local development files

Examples:
- .env
- config files
- settings files

---

## Documentation
Review:
- Setup guides
- API examples
- Integration instructions
- Developer documentation

---

## Commit History
Review:
- Previous changes
- Removed configurations
- Historical development files

---

# API Key Categories
## Cloud API Keys
Examples:
- Cloud service integrations
- Storage services
- Infrastructure platforms

---

## Third-Party Service Keys
Examples:
- Communication platforms
- Analytics services
- External APIs

---

## Application API Keys
Examples:
- Internal application integrations
- Client communication systems

---

## Development Keys
Examples:
- Testing environments
- Local development configurations
- Example projects

---

# Common API Key Locations
## Environment Files
Common examples:
- .env
- .env.example
- .env.local

---

## Configuration Files
Common examples:
- config.json
- settings.json
- application.yml

---

## Deployment Resources
Common examples:
- Docker configuration
- CI/CD files
- Infrastructure files

---

## Application Code
Common examples:
- API clients
- Service integrations
- Configuration modules

---

# GitHub Search Concepts
## File-Based Search
Examples:
filename:.env
filename:config
filename:settings

---

## Technology-Based Search
Examples:
language:python
language:javascript
language:go

---

## Organization-Based Search
Search within authorized organizations:
org:organization-name

---

# API Key Research Workflow
## Phase 1 - Discovery
Collect:
- Related repositories
- Project owners
- Technologies
- Configuration resources

---

## Phase 2 - Classification
Classify discovered information:
- Public examples
- Test configurations
- Documentation references
- Sensitive-looking data

---

## Phase 3 - Validation
Before reporting:
- Confirm ownership
- Confirm scope
- Determine actual impact
- Avoid unauthorized access

---

# Documentation Template
| Field | Description |
|---|---|
| Repository | Repository name |
| Location | File or commit location |
| Category | API key type |
| Exposure | Public visibility |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# Prevention Concepts
Developers can reduce API key exposure by:
- Using environment variables
- Using secret management systems
- Removing keys from source code
- Reviewing commits before publishing
- Rotating exposed keys
- Limiting key permissions
- Monitoring key usage

---

# Security Research Notes
When identifying API key-related information:
- Do not use discovered keys.
- Do not access external services.
- Do not perform unauthorized actions.
- Do not collect unnecessary sensitive data.
- Report through appropriate channels.

---

# Responsible Research
API key research should focus on identifying accidental exposure and helping organizations improve security practices.
Always follow:
- Authorization requirements
- Bug bounty policies
- Responsible disclosure practices
- Legal boundaries