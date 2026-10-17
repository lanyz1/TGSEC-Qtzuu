# GitHub Credentials Discovery
A collection of GitHub credential discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
Credentials are sensitive authentication materials used to access systems, services, or applications.
During repository research, credentials may appear accidentally through:
- Development files
- Configuration files
- Documentation
- Commit history
- Example configurations

The presence of credential-like information does not automatically mean a vulnerability exists.
Always verify authorization, ownership, and scope.

---

# Credential Discovery Areas
## Source Code
Review:
- Authentication logic
- Integration code
- Configuration handling
- Service connections

---

## Configuration Files
Common locations:
- Environment files
- Application settings
- Deployment configurations
- Local development files

Examples:
- .env
- config.json
- settings.yml
- application.properties

---

## Documentation Files
Review:
- Setup instructions
- Installation guides
- Examples
- Development documentation

Common locations:
- README files
- Documentation folders
- Example configurations

---

## Commit History
Review:
- Previous commits
- Removed files
- Changed configurations
- Development history

---

# Credential Categories
## Application Credentials
Examples:
- Application authentication data
- Service integration values
- Development credentials

---

## API Authentication Data
Examples:
- API access information
- Integration references
- Service connection details

---

## Database Credentials
Examples:
- Database connection settings
- Application database configuration
- Service references

---

## Cloud Service Information
Examples:
- Cloud configuration
- Deployment references
- Storage configuration

---

## Third-Party Service Credentials
Examples:
- External integrations
- Communication services
- Monitoring platforms

---

# Common Credential Locations
## Environment Files
Examples:
- .env
- .env.example
- .env.local

---

## Configuration Files
Examples:
- config.yml
- config.json
- settings.json

---

## Deployment Files
Examples:
- docker-compose.yml
- deployment.yml
- values.yaml

---

## CI/CD Files
Examples:
- .github/workflows/
- Pipeline configuration files
- Automation scripts

---

# GitHub Search Concepts
## File Name Search
Examples:
filename:.env
filename:config
filename:settings

---

## Organization Search
Search within authorized organizations:
org:organization-name

---

## Language Filtering
Examples:
language:python
language:javascript
language:go

---

# Credential Research Workflow
## Phase 1 - Discovery
Collect:
- Related repositories
- Project owners
- Technologies
- Configuration resources

---

## Phase 2 - Classification
Classify discovered information:
- Example configuration
- Test values
- Public references
- Sensitive-looking information

---

## Phase 3 - Validation
Before reporting:
- Confirm ownership
- Confirm scope
- Determine security impact
- Avoid unauthorized access

---

# Documentation Template
| Field | Description |
|---|---|
| Repository | Repository name |
| Location | File or commit location |
| Category | Credential type |
| Exposure | Public visibility |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional information |

---

# Prevention Concepts
Developers can reduce credential exposure by:
- Using secret management solutions
- Removing credentials from source code
- Reviewing commits before publishing
- Using environment variables
- Rotating exposed credentials
- Applying access controls
- Performing regular security scans

---

# Security Research Notes
When identifying credential-related information:
- Do not use discovered credentials.
- Do not attempt unauthorized authentication.
- Do not access external systems.
- Avoid collecting unnecessary sensitive information.
- Report responsibly through approved channels.

---

# Responsible Research
Credential research should focus on identifying accidentalexposure and helping organizations improve security.
Always follow:
- Authorization requirements
- Bug bounty policies
- Responsible disclosure practices
- Legal boundaries