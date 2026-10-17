# GitHub Workflows Discovery
A collection of GitHub Actions and workflow discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
GitHub workflows automate tasks such as:
- Building applications
- Running tests
- Packaging releases
- Deploying applications
- Performing security checks
- Managing development workflows

Workflow files can provide useful information about an application's development and deployment architecture.
They may also contain references to:
- Environments
- Cloud services
- External integrations
- Permissions
- Dependencies
- Deployment processes

Always verify authorization, ownership, and scope before performing any security testing.

---

# Workflow Discovery Areas
## GitHub Actions
The primary location for GitHub Actions workflows is:
.github/workflows/

Common workflow file formats:
- .yml
- .yaml

---

## Build Workflows
Review workflows responsible for:
- Compiling applications
- Installing dependencies
- Building packages
- Generating artifacts

---

## Test Workflows
Review:
- Unit tests
- Integration tests
- Security testing
- Automated validation

---

## Deployment Workflows
Review:
- Staging deployments
- Production deployments
- Release automation
- Infrastructure deployment

---

# Workflow Components
## Triggers
Review events that start workflows.
Common examples:
- push
- pull_request
- workflow_dispatch
- schedule
- release

---

## Jobs
Review:
- Job names
- Job dependencies
- Execution environments
- Job permissions

---

## Steps
Review:
- Actions used
- Shell commands
- Scripts
- Build operations
- Deployment operations

---

## Permissions
Review workflow permission settings.
Important areas include:
- Repository permissions
- Token permissions
- Read access
- Write access

Excessive permissions may increase security risk.

---

# Workflow Research Areas
## Third-Party Actions
Review:
- Action sources
- Action versions
- External dependencies
- Unpinned references

---

## Environment References
Look for:
- Development environments
- Staging environments
- Production environments

---

## Deployment References
Review:
- Cloud platforms
- Container registries
- Hosting services
- Infrastructure tools

---

## Secret References
Look for references to GitHub-managed secrets.
Examples:
- Secret variables
- Environment secrets
- Organization secrets

Do not attempt to retrieve, test, or misuse secret values.

---

# GitHub Search Concepts
## Workflow Path
Search for workflow files using:
path:.github/workflows

---

## Workflow Files
Examples:
filename:workflow.yml
filename:workflow.yaml

---

## Action References
Search for:
uses:

---

## Deployment References
Search for:
deploy
deployment
release

---

## Environment References
Search for:
environment
staging
production
development

---

# Workflow Research Workflow
## Phase 1 - Discovery
Collect:
- Workflow files
- Action references
- Deployment workflows
- Build workflows
- Test workflows

---

## Phase 2 - Classification
Classify workflows:
- Build
- Test
- Security
- Deployment
- Release
- Automation

---

## Phase 3 - Analysis
Review:
- Triggers
- Jobs
- Steps
- Permissions
- External actions
- Environment references

---

## Phase 4 - Documentation
Record:
| Field | Description |
|---|---|
| Workflow | Workflow name |
| Trigger | Workflow trigger |
| Jobs | Main jobs |
| Actions | External actions |
| Environment | Target environment |
| Permissions | Workflow permissions |
| Notes | Additional information |

---

# Security Considerations
Workflow configurations can introduce security risks when they contain:
- Excessive permissions
- Unsafe automation
- Untrusted input handling
- Unnecessary external dependencies
- Insecure deployment logic

However, the presence of a potentially risky configuration does not automatically mean it is exploitable.
Security impact depends on the workflow context and program scope.

---

# Prevention Concepts
Organizations can improve workflow security by:
- Applying least-privilege permissions
- Reviewing third-party actions
- Pinning trusted dependencies
- Separating deployment environments
- Restricting sensitive workflow operations
- Reviewing pull request workflows
- Protecting deployment environments
- Auditing workflow changes

---

# Security Research Notes
When reviewing workflows:
- Do not trigger destructive workflows.
- Do not modify workflow files without authorization.
- Do not attempt to access secret values.
- Do not deploy unauthorized resources.
- Do not abuse workflow permissions.
- Respect program rules and rate limits.

---

# Responsible Research
Workflow reconnaissance should focus on understanding public automation logic and identifying legitimate security concerns without disrupting development or deployment systems.

Always follow:
- Authorization requirements
- Bug bounty policies
- Responsible disclosure practices
- Legal boundaries