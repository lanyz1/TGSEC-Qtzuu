# Bug Bounty - Subdomains
A practical collection of search queries and reconnaissance techniques for discovering publicly indexed subdomains during authorized bug bounty research.

---

# Basic Subdomain Discovery
## Indexed Subdomains
site:example.com -www

## All Indexed Hosts
site:*.example.com

## Subdomain Keyword Search
site:example.com (subdomain OR hostname)

## Specific Subdomain References
"*.example.com"

---

# Common Subdomain Names
## Development
site:example.com (dev OR development)

## Testing
site:example.com (test OR testing)

## Staging
site:example.com (stage OR staging)

## Beta
site:example.com beta

## API
site:example.com (api OR api-dev OR api-test OR api-staging)

## Admin
site:example.com (admin OR administrator)

## Portal
site:example.com (portal OR gateway)

## Dashboard
site:example.com (dashboard OR panel)

## Support
site:example.com (support OR help)

## Mail
site:example.com (mail OR webmail)

---

# Environment Discovery
## Development Environments
site:example.com (dev OR development OR develop)

## Testing Environments
site:example.com (test OR testing OR qa)

## Staging Environments
site:example.com (stage OR staging)

## Pre-Production
site:example.com (preprod OR "pre-production")

## Beta Environments
site:example.com (beta OR preview)

---

# API Subdomains
## API
site:example.com inurl:api

## API Versions
site:example.com (api OR api-v1 OR api-v2 OR api-v3)

## API Documentation
site:example.com (api OR developer) (docs OR documentation)

---

# Infrastructure Subdomains
## Cloud
site:example.com (cloud OR aws OR azure OR gcp)

## CDN
site:example.com (cdn OR static OR assets)

## Storage
site:example.com (storage OR files OR uploads)

## Monitoring
site:example.com (monitor OR monitoring OR metrics)

## Logging
site:example.com (log OR logs OR logging)

---

# Authentication Subdomains
## Login
site:example.com (login OR signin OR "sign-in")

## Authentication
site:example.com (auth OR authentication)

## SSO
site:example.com (sso OR "single sign-on")

## Account
site:example.com (account OR accounts)

---

# Regional Subdomains
## US
site:example.com (us OR usa)

## EU
site:example.com (eu OR europe)

## Asia
site:example.com (asia OR apac)

## Regional Keywords
site:example.com (us OR eu OR uk OR de OR fr OR jp)

---

# Technology-Specific Subdomains
## WordPress
site:example.com (wp OR wordpress)

## Git
site:example.com (git OR gitlab OR github)

## Jenkins
site:example.com jenkins

## Grafana
site:example.com grafana

## Kubernetes
site:example.com kubernetes

---

# Public Search Engine Correlation
## Domain References Outside Target
"example.com" -site:example.com

## GitHub References
"example.com" site:github.com

## GitLab References
"example.com" site:gitlab.com

## Public Documentation
"example.com" (documentation OR docs OR developer)

---

# Subdomain Research Workflow
## Phase 1 - Passive Discovery
1. Identify the main domain.
2. Search indexed subdomains.
3. Search common environment names.
4. Search API and authentication-related names.
5. Search public documentation.
6. Search public repositories and external references.

## Phase 2 - Classification
Classify discovered subdomains as:
- Production
- Development
- Testing
- Staging
- API
- Authentication
- Administration
- Support
- Infrastructure
- Regional
- Unknown

## Phase 3 - Validation
1. Verify that the subdomain belongs to the target.
2. Check whether it is in scope.
3. Remove duplicate or unrelated results.
4. Record useful metadata.
5. Prioritize interesting assets for further authorized research.

---

# Subdomain Checklist
- [ ] Main domain identified
- [ ] Indexed subdomains collected
- [ ] Development hosts checked
- [ ] Testing hosts checked
- [ ] Staging hosts checked
- [ ] API hosts checked
- [ ] Authentication hosts checked
- [ ] Infrastructure hosts checked
- [ ] Regional hosts checked
- [ ] External references checked
- [ ] Ownership verified
- [ ] Scope verified
- [ ] Duplicate results removed

---

# Important Notes
- Search engines do not provide complete subdomain enumeration.
- Search results may contain outdated or unrelated hosts.
- A subdomain being discovered does not prove that it is in scope.
- Verify ownership before performing active testing.
- Do not access private or restricted resources.
- Do not perform unauthorized authentication attacks.
- Respect program scope, rate limits and testing restrictions.
- Use active enumeration only when explicitly permitted.

---

# Responsible Disclosure
If a subdomain exposes an unexpected service or potentially sensitive resource:
1. Verify that the asset is in scope.
2. Minimize interaction with the asset.
3. Avoid accessing unnecessary sensitive information.
4. Collect only the evidence required to demonstrate the issue.
5. Report the finding through the official bug bounty channel.