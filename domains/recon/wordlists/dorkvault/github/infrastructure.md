# GitHub Infrastructure Discovery
A collection of GitHub infrastructure discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
Infrastructure-related information in public repositories can reveal how applications are built, deployed, and maintained.
Common examples include:
- Cloud infrastructure
- Containers
- Deployment systems
- CI/CD pipelines
- Infrastructure as Code
- Network configuration references
- Hosting platforms

Infrastructure information should be treated as reconnaissance data. Its presence does not automatically indicate a vulnerability.
Always verify authorization, ownership, and scope before testing.

---

# Infrastructure Discovery Areas
## Infrastructure as Code
Review:
- Terraform files
- CloudFormation templates
- Kubernetes manifests
- Helm charts
- Deployment configuration

Common file extensions:
- .tf
- .yaml
- .yml
- .json

---

## Container Infrastructure
Review:
- Dockerfiles
- Docker Compose files
- Container configuration
- Image references

Common files:
- Dockerfile
- docker-compose.yml
- compose.yml

---

## CI/CD Infrastructure
Review:
- GitHub Actions
- Build pipelines
- Deployment workflows
- Automation scripts

Common locations:
- .github/workflows/
- CI configuration files
- Pipeline definitions

---

## Cloud Infrastructure
Review references to:
- Cloud providers
- Storage services
- Compute resources
- Managed databases
- Serverless services

Common providers may include:
- AWS
- Azure
- Google Cloud

---

# Infrastructure Categories
## Compute
Examples:
- Virtual machines
- Containers
- Serverless functions

---

## Storage
Examples:
- Object storage
- File storage
- Backup storage

---

## Databases
Examples:
- Relational databases
- NoSQL databases
- Managed database services

---

## Networking
Examples:
- Load balancers
- Proxies
- DNS references
- Network configuration

---

## Deployment
Examples:
- Continuous integration
- Continuous deployment
- Release automation

---

# GitHub Search Concepts
## Infrastructure Files
Examples:
filename:Dockerfile
filename:docker-compose.yml
filename:terraform

---

## Terraform Resources
Search for:
extension:tf

---

## Kubernetes Resources
Search for:
kubernetes
filename:deployment.yml
filename:service.yml

---

## CI/CD Resources
Search for:
path:.github/workflows
filename:workflow

---

# Infrastructure Research Workflow
## Phase 1 - Discovery
Collect:
- Infrastructure files
- Deployment resources
- Cloud references
- Container configuration
- Automation workflows

---

## Phase 2 - Classification
Classify discovered resources:
- Cloud
- Container
- Kubernetes
- CI/CD
- Infrastructure as Code
- Networking

---

## Phase 3 - Architecture Mapping
Create a simple infrastructure map:
| Resource | Category | Purpose | Repository |
|---|---|---|---|
| Resource name | Infrastructure type | Observed purpose | Source repository |

---

## Phase 4 - Analysis
Review:
- Technology choices
- Deployment architecture
- Service relationships
- Public configuration
- Infrastructure dependencies

---

# Infrastructure Information
Infrastructure files may reveal:
- Cloud provider usage
- Deployment architecture
- Service dependencies
- Application components
- Technology stack

This information can be useful for understanding an authorized target's public attack surface.

---

# Security Considerations
Infrastructure information is not automatically sensitive or vulnerable.

Consider:
- Is the information intentionally public?
- Is the referenced asset within scope?
- Does the information expose a security weakness?
- Is there an actual security impact?

Avoid accessing infrastructure simply because a repository references it.

---

# Documentation Template
| Field | Description |
|---|---|
| Repository | Repository name |
| Resource | Infrastructure resource |
| Category | Cloud, container, CI/CD, etc. |
| Technology | Technology used |
| Purpose | Observed purpose |
| Scope | In-scope / Out-of-scope |
| Impact | Security impact |
| Notes | Additional information |

---

# Prevention Concepts
Organizations can reduce infrastructure exposure by:
- Reviewing public repositories
- Separating public and private configuration
- Removing unnecessary infrastructure details
- Using secure secret management
- Restricting infrastructure access
- Applying least-privilege permissions
- Reviewing CI/CD permissions
- Monitoring infrastructure changes

---

# Security Research Notes
When reviewing infrastructure information:
- Do not access unauthorized infrastructure.
- Do not modify cloud resources.
- Do not deploy workloads without permission.
- Do not test credentials or tokens.
- Do not perform destructive actions.
- Respect bug bounty scope and rate limits.

---

# Responsible Research
Infrastructure reconnaissance should focus on understanding publicly available architecture and identifying legitimate security concerns without causing operational impact.

Always follow:
- Authorization requirements
- Bug bounty policies
- Responsible disclosure practices
- Legal boundaries