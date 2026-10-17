# Shodan - Cloud
A curated collection of Shodan search queries for researching publicly observable cloud-hosted infrastructure, services and assets during authorized security research and reconnaissance.

---

# Cloud Infrastructure
## Generic Cloud Search
cloud

## Cloud Infrastructure by Country
country:US cloud

## Cloud Infrastructure by Organization
org:"Example Organization" cloud

---

# Amazon Web Services
## AWS References
"AWS"

## Amazon Web Services
"Amazon Web Services"

## AWS by Organization
org:"Example Organization" "AWS"

## AWS by Country
country:US "AWS"

---

# Microsoft Azure
## Azure References
"Azure"

## Microsoft Azure
"Microsoft Azure"

## Azure by Organization
org:"Example Organization" "Azure"

## Azure by Country
country:US "Azure"

---

# Google Cloud
## Google Cloud References
"Google Cloud"

## GCP References
"GCP"

## Google Cloud by Organization
org:"Example Organization" "Google Cloud"

## Google Cloud by Country
country:US "Google Cloud"

---

# Cloudflare
## Cloudflare
"Cloudflare"

## Cloudflare by Organization
org:"Example Organization" "Cloudflare"

## Cloudflare by Country
country:US "Cloudflare"

---

# Cloud Services
## HTTPS Cloud Services
cloud port:443

## HTTP Cloud Services
cloud port:80

## Cloud Services with Screenshots
cloud has_screenshot:true

---

# Cloud-Based Web Services
## Cloud Web Services
cloud service:http

## Cloud HTTPS Services
cloud service:https

## Cloud Web Servers
cloud (product:"nginx" OR product:"Apache httpd")

---

# Organization-Based Cloud Research
## AWS Infrastructure
org:"Example Organization" "AWS"

## Azure Infrastructure
org:"Example Organization" "Azure"

## Google Cloud Infrastructure
org:"Example Organization" "Google Cloud"

## Cloud Infrastructure
org:"Example Organization" cloud

---

# Geographic Cloud Research
## Cloud Services by Country
country:US cloud

## Cloud Services by City
city:"New York" cloud

## AWS by Country
country:US "AWS"

## Azure by Country
country:US "Azure"

---

# Cloud Technology Research
## Cloud + Kubernetes
cloud Kubernetes

## Cloud + Docker
cloud Docker

## Cloud + API
cloud API

## Cloud + Web
cloud web

---

# Cloud and Container Research
## Kubernetes
Kubernetes

## Docker
Docker

## Kubernetes by Organization
org:"Example Organization" Kubernetes

## Docker by Organization
org:"Example Organization" Docker

---

# Cloud Certificate Research
## Cloud + SSL
cloud has_ssl:true

## Cloud + HTTPS
cloud port:443

## AWS + SSL
"AWS" has_ssl:true

## Azure + SSL
"Azure" has_ssl:true

---

# Combined Searches
## Cloud + HTTPS + Organization
org:"Example Organization" cloud port:443

## Cloud + HTTP
cloud service:http

## Cloud + Screenshot
cloud has_screenshot:true

## Cloud + Kubernetes
cloud Kubernetes

## Cloud + Docker
cloud Docker

## Cloud + API
cloud API

---

# Cloud Reconnaissance Workflow
1. Define the authorized organization or target.
2. Identify publicly observable cloud-related assets.
3. Determine the cloud provider when possible.
4. Identify associated services and technologies.
5. Correlate cloud assets with known domains and infrastructure.
6. Record publicly observable ports and services.
7. Validate findings within the authorized scope.
8. Report unintended exposure according to the applicable security policy.

---

# Important Notes
- Cloud-related search terms can produce false positives.
- Shodan data may be incomplete or outdated.
- Identifying a cloud provider does not indicate a vulnerability.
- Do not attempt to access cloud resources without authorization.
- Do not attempt credential attacks or authentication bypasses.
- Do not access private cloud data or storage resources.
- Cloud infrastructure may contain sensitive or critical workloads.
- Only perform active testing when explicitly authorized.
- Respect bug bounty scope and cloud provider policies.
- These queries are intended for educational purposes, OSINT and authorized security research.