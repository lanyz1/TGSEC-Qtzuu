# GitHub Dependencies Discovery
A collection of GitHub dependency discovery concepts, research notes, and security considerations for authorized security research.

---

# Overview
Software projects commonly depend on third-party libraries, frameworks, packages, and external components.
Dependency information can help researchers understand:
- Technology stacks
- Framework usage
- Package versions
- Third-party integrations
- Potentially outdated components
- Software supply-chain relationships

Dependency information alone does not indicate a vulnerability.
Always verify authorization, ownership, and scope before performing security testing.

---

# Dependency Discovery Areas
## Package Manifests
Common package management files include:
- package.json
- package-lock.json
- yarn.lock
- pnpm-lock.yaml
- requirements.txt
- Pipfile
- poetry.lock
- Gemfile
- Gemfile.lock
- composer.json
- composer.lock
- pom.xml
- build.gradle
- go.mod
- go.sum
- Cargo.toml
- Cargo.lock

---

# JavaScript Dependencies
Review:
- package.json
- package-lock.json
- yarn.lock
- pnpm-lock.yaml

Useful information:
- Package names
- Version ranges
- Development dependencies
- Runtime dependencies
- Build tools

---

# Python Dependencies
Review:
- requirements.txt
- Pipfile
- poetry.lock
- pyproject.toml

Useful information:
- Python packages
- Version constraints
- Development dependencies
- Application frameworks

---

# PHP Dependencies
Review:
- composer.json
- composer.lock

Useful information:
- PHP packages
- Frameworks
- Version constraints
- Development packages

---

# Java Dependencies
Review:
- pom.xml
- build.gradle
- gradle files

Useful information:
- Java libraries
- Frameworks
- Build plugins
- Version information

---

# Go Dependencies
Review:
- go.mod
- go.sum

Useful information:
- Go modules
- Module versions
- External packages

---

# Rust Dependencies
Review:
- Cargo.toml
- Cargo.lock

Useful information:
- Rust crates
- Package versions
- Build dependencies

---

# Dependency Categories
## Runtime Dependencies
Libraries required by the application during normal operation.
Examples:
- Web frameworks
- Database libraries
- Authentication libraries
- API clients

---

## Development Dependencies
Libraries used during development.
Examples:
- Testing frameworks
- Linters
- Build tools
- Code formatters

---

## Build Dependencies
Components used to:
- Compile code
- Bundle applications
- Generate artifacts
- Package releases

---

# Dependency Research Workflow
## Phase 1 - Discovery
Identify:
- Package manifests
- Lock files
- Dependency managers
- Frameworks
- Major libraries

---

## Phase 2 - Classification
Classify dependencies into:
- Runtime
- Development
- Build
- Testing
- Optional

---

## Phase 3 - Version Analysis
Review:
- Installed versions
- Version ranges
- Lock files
- Release history

Do not assume an old version is vulnerable without confirming the affected component and vulnerability.

---

## Phase 4 - Security Review
Check whether dependencies are associated with:
- Publicly documented vulnerabilities
- Unsupported versions
- Known security advisories
- Supply-chain concerns

Use authoritative security advisories when validating a potential issue.

---

# GitHub Search Concepts
## Package Manifest Search
Examples:
filename:package.json
filename:requirements.txt
filename:composer.json
filename:pom.xml

---

## Lock File Search
Examples:
filename:package-lock.json
filename:yarn.lock
filename:Gemfile.lock
filename:poetry.lock

---

## Language Filtering
Examples:
language:javascript filename:package.json
language:python filename:requirements.txt
language:go filename:go.mod

---

# Dependency Mapping
Create a dependency inventory:
| Dependency | Version | Type | Repository | Notes |
|---|---|---|---|---|
| Package name | Version | Runtime/Dev | Repository | Additional information |

---

# Supply Chain Research
Review:
- Third-party packages
- External repositories
- Build dependencies
- Package sources
- Maintainer information
- Dependency update practices

Potential research areas include:
- Typosquatting
- Dependency confusion
- Malicious packages
- Compromised dependencies
- Unmaintained components

These areas should only be investigated within authorized scope.

---

# Security Considerations
Dependency information may reveal:
- Application technologies
- Framework versions
- Third-party components
- Build architecture

However:
- An outdated package is not automatically exploitable.
- Version numbers should be verified carefully.
- Security advisories may apply only to specific versions or configurations.
- Exploit testing should only be performed when explicitly authorized.

---

# Prevention Concepts
Organizations can improve dependency security by:
- Keeping dependencies updated
- Using lock files where appropriate
- Monitoring security advisories
- Reviewing dependency changes
- Removing unused packages
- Using trusted package sources
- Applying software composition analysis
- Reviewing third-party dependencies

---

# Security Research Notes
When reviewing dependencies:
- Do not install untrusted packages on production systems.
- Do not modify target repositories.
- Do not introduce test dependencies without authorization.
- Do not exploit vulnerable dependencies unless explicitly permitted.
- Document evidence carefully.
- Respect bug bounty scope and limitations.

---

# Responsible Research
Dependency reconnaissance should help researchers understand software composition and identify legitimate security concerns while minimizing operational impact.
Always follow:
- Authorization requirements
- Bug bounty policies
- Responsible disclosure practices
- Legal boundaries