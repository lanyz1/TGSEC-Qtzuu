# GitHub Search Operators
A collection of GitHub search operators and techniques for efficient repository, code, and resource discovery during authorized security research.

---

# Overview
GitHub search operators help researchers filter and organize search results.
They can be used to discover:
- Repositories
- Code
- Organizations
- Users
- Technologies
- Public resources

---

# Repository Search Operators
## Repository Name
Search repositories by name:
repo:repository-name

---

## Repository Owner
Search repositories owned by a specific user:
user:username

Example:
user:octocat

---

## Organization Search
Search repositories belonging to an organization:
org:organization-name

Example:
org:github

---

## Programming Language
Filter repositories by programming language:
language:python

Examples:
language:javascript
language:go
language:java
language:php

---

## Stars Filter
Search repositories based on stars:
stars:>100
Examples:
stars:>50
stars:100..500

---

## Fork Filter
Search forked repositories:
fork:true
Search only original repositories:
fork:false

---

## Archived Repositories
Search archived repositories:
archived:true

---

# Code Search Operators
## File Name Search
Search files by name:
filename:config
Examples:
filename:README
filename:Dockerfile
filename:package.json

---

## File Extension Search
Search specific file extensions:
extension:js
Examples:
extension:py
extension:json
extension:yml
extension:yaml

---

## Path Search
Search inside specific directories:
path:src
Examples:
path:config
path:docs
path:app

---

## Exact Match Search
Search exact phrases:
"search phrase"
Example:
"api endpoint"

---

# Technology Discovery
## Framework Search
Examples:
language:javascript react
language:python django
language:javascript vue

---

## Dependency Search
Search dependency files:
filename:package.json
filename:requirements.txt
filename:Gemfile
filename:pom.xml

---

# Configuration Discovery
## Configuration Files
Search configuration-related files:
filename:config
filename:settings
filename:configuration

---

## Environment Files
Search environment references:
filename:.env

---

## Container Files
Search container configurations:
filename:Dockerfile
filename:docker-compose.yml

---

## Infrastructure Files
Search infrastructure resources:
filename:terraform
filename:kubernetes
filename:helm

---

# Documentation Discovery
## Documentation Files
filename:README
filename:CHANGELOG
filename:CONTRIBUTING

---

## API Documentation
Search API-related documentation:
swagger
OpenAPI
API reference
api documentation

---

# Repository Intelligence
## Recently Updated Repositories
Search recently updated projects:
pushed:>2025-01-01

---

## Recently Created Repositories
Search newly created projects:
created:>2025-01-01

---

## Repository Size
Search by repository size:
size:>1000

---

# Combined Search Examples
## Find Python Projects
language:python stars:>50

---

## Find JavaScript Projects
language:javascript stars:>100

---

## Find Projects Using Docker
filename:Dockerfile

---

## Find API Projects
api filename:README

---

## Find Configuration Files
filename:config

---

# Research Workflow
## Step 1 - Identify Target
Collect:
- Organization name
- Repository names
- Technologies
- Related domains

---

## Step 2 - Search
Use:
- Repository operators
- Code operators
- Language filters
- File filters

---

## Step 3 - Analyze
Review:
- Project structure
- Technologies
- Documentation
- Public information

---

## Step 4 - Document
Record:
| Field | Description |
|---|---|
| Repository | Repository name |
| Owner | User or organization |
| Technology | Used technology |
| Purpose | Project purpose |
| Notes | Additional information |

---

# Important Notes
- GitHub search results are public information.
- Public repositories are not automatically vulnerabilities.
- Always verify authorization and scope.
- Do not misuse discovered information.
- Respect repository owners.
- Followresponsible disclosure practices.

---

# Responsible Research
GitHub search operators are reconnaissance tools used to understand public code and resources.
Use them responsibly and only within authorized security research activities.