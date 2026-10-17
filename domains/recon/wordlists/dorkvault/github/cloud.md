# GitHub Cloud Discovery
A collection of GitHub cloud infrastructure discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
Public repositories can contain references to cloud infrastructure used by applications and development teams.
Common cloud-related information includes:
- Cloud providers
- Storage services
- Compute resources
- Serverless applications
- Managed databases
- Deployment configurations
- Infrastructure as Code
- CI/CD integrations

Cloud references are useful for understanding an authorized target's technology landscape, but their presence does not automatically indicate a vulnerability.
Always verify authorization, ownership, and scope before testing.

---

# Cloud Discovery Areas
## Cloud Provider Identification
Review repositories for references to:
- AWS
- Microsoft Azure
- Google Cloud
- Other cloud platforms

Possible sources:
- Configuration files
- Infrastructure definitions
- Deployment scripts
- Documentation

---

## Cloud Storage
Review references to:
- Object storage
- File storage
- Backup storage
- Static asset hosting

Common concepts:
- Storage buckets
- Containers
- Public assets
- CDN integrations

---

## Cloud Compute
Review references to:
- Virtual machines
- Container services
- Serverless functions
- Managed application platforms

---

## Cloud Databases
Review references to:
- Managed SQL databases
- NoSQL databases
- Data warehouses
- Caching services

---

# Infrastructure as Code
Common technologies:
- Terraform
- CloudFormation
- Pulumi
- Kubernetes
- Helm

Common file types:
- .tf
- .yaml
- .yml
- .json

---

# Cloud Deployment Discovery
Review:
- Deployment workflows
- CI/CD configuration
- Infrastructure scripts
- Container configuration
- Release automation

Possible information:
- Deployment targets
- Cloud services
- Environment names
- Application components

---

# GitHub Search Concepts
## Cloud Provider Keywords
Examples:
aws
azure
gcp
google cloud

---

## Infrastructure Files
Examples:
filename:terraform
extension:tf
filename:cloudformation

---

## Container Resources
Examples:
filename:Dockerfile
filename:docker-compose.yml

---

## Kubernetes Resources
Examples:
kubernetes
filename:deployment.yml
filename:service.yml

---

## CI/CD Resources
Examples:
path:.github/workflows
filename:workflow

---

# Cloud Research Workflow
## Phase 1 - Discovery
Collect:
- Cloud provider references
- Infrastructure files
- Deployment resources
- Storage references
- Service integrations

---

## Phase 2 - Classification
Classify resources:
- Compute
- Storage
- Database
- Networking
- Serverless
- Containers
- CI/CD

---

## Phase 3 - Relationship Mapping
Create a cloud resource map:
| Resource | Provider | Category | Purpose |
|---|---|---|---|
| Resource name | Cloud provider | Resource type | Observed purpose |

---

## Phase 4 - Analysis
Review:
- Cloud architecture
- Service relationships
- Deployment methods
- Public configuration
- Technology dependencies

---

# Cloud Information Categories
## Storage References
May reveal:
- Asset hosting
- Storage architecture
- Backup systems
- CDN relationships

---

## Compute References
May reveal:
- Application hosting
- Container infrastructure
- Serverless architecture

---

## Database References
May reveal:
- Database technology
- Application architecture
- Service dependencies

---

## Deployment References
May reveal:
- Release workflows
- Environment structure
- Cloud integrations

---

# Security Considerations
Cloud information should be treated carefully.
Consider:
- Is the resource publicly documented intentionally?
- Is the cloud resource within scope?
- Does the information expose a real security weakness?
- Is there a measurable security impact?

Do not attempt to access cloud resources merely because they are referenced in public code.

---

# Documentation Template
| Field | Description |
|---|---|
| Repository | Repository name |
| Resource | Cloud resource |
| Provider | Cloud platform || Category | Resource category |
| Purpose | Observed purpose |
| Scope | In-scope / Out-of-scope |
| Impact | Security impact |
| Notes | Additional information |

---

# Prevention Concepts
Organizations can reduce cloud exposure by:
- Reviewing public repositories
- Separating public and private configuration
- Using secure secret management
- Applying least-privilege permissions
- Restricting cloud resources
- Reviewing deployment permissions
- Monitoring cloud activity
- Removing unnecessary infrastructure references

---

# Security Research Notes
When reviewing cloud-related information:
- Do not access unauthorized cloud resources.
- Do not use exposed credentials.
- Do not modify cloud infrastructure.
- Do not create or delete resources.
- Do not deploy workloads without authorization.
- Respect scope and testing limitations.

---

# Responsible Research
Cloud reconnaissance should focus on understanding publicly available infrastructure information while avoiding operational impact.
Always follow:
- Authorization requirements
- Bug bounty policies
- Responsible disclosure practices
- Legal boundaries