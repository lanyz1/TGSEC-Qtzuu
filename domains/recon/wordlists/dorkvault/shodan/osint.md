# Shodan - OSINT
A curated collection of Shodan search queries and techniques for OSINT, infrastructure research, asset discovery and authorized reconnaissance.

---

# Domain Research
## Domain Search
domain:example.com

## Hostname Search
hostname:example.com

## Domain + HTTPS
domain:example.com port:443

## Domain + HTTP
domain:example.com port:80

## Domain + SSL
domain:example.com ssl:true

---

# Organization Research
## Organization
org:"Example Organization"

## Organization + Web Services
org:"Example Organization" service:http

## Organization + HTTPS
org:"Example Organization" port:443

## Organization + SSL
org:"Example Organization" ssl:true

---

# IP Research
## Specific IP
ip:192.0.2.10

## Network Range
net:192.0.2.0/24

## Organization Network
org:"Example Organization" net:192.0.2.0/24

---

# Technology Research
## Nginx
product:"nginx"

## Apache
product:"Apache httpd"

## OpenSSH
product:"OpenSSH"

## Microsoft IIS
product:"Microsoft IIS"

## WordPress
http.component:"WordPress"

---

# Service Research
## HTTP
service:http

## HTTPS
service:https

## SSH
service:ssh

## FTP
service:ftp

## SMTP
service:smtp

## DNS
service:dns

---

# Certificate Research
## Certificate Common Name
ssl.cert.subject.cn:"example.com"

## Certificate Organization
ssl.cert.subject.o:"Example Organization"

## Certificate Issuer
ssl.cert.issuer.cn:"Issuer Name"

## Certificate Fingerprint
ssl.cert.fingerprint:"fingerprint"

---

# Web Intelligence
## Login Pages
http.title:"Login"

## Dashboard Pages
http.title:"Dashboard"

## Admin Pages
http.title:"Admin"

## API References
http.html:"API"

## Documentation
http.html:"documentation"

---

# Geographic Research
## Country
country:US

## Country + Organization
country:US org:"Example Organization"

## City
city:"New York"

## City + Organization
city:"New York" org:"Example Organization"

## Geographic Coordinates
geo:40.7128,-74.0060

---

# Infrastructure Research
## Web Infrastructure
org:"Example Organization" (port:80 OR port:443)

## Remote Access Infrastructure
org:"Example Organization" (port:22 OR port:3389 OR port:5900)

## Mail Infrastructure
org:"Example Organization" (port:25 OR port:465 OR port:587 OR port:993)

## Database Infrastructure
org:"Example Organization" (port:3306 OR port:5432 OR port:1433 OR port:27017 OR port:6379)

---

# Cloud Research
## AWS
"AWS"

## Azure
"Azure"

## Google Cloud
"Google Cloud"

## Cloud + Organization
org:"Example Organization" cloud

---

# IoT Research
## Generic IoT
IoT

## Cameras
camera

## Printers
printer

## Routers
router

## Industrial Systems
SCADA

---

# Screenshot Research
## HTTP Screenshots
service:http has_screenshot:true

## Organization Screenshots
org:"Example Organization" has_screenshot:true

## Dashboard Screenshots
http.title:"Dashboard" has_screenshot:true

## Camera Screenshots
camera has_screenshot:true

---

# Historical and Correlation Research
## Domain + Technology
domain:example.com product:"nginx"

## Domain + Port
domain:example.com port:443

## Organization + Technology
org:"Example Organization" product:"nginx"

## Organization + Certificate
org:"Example Organization" ssl:true

## Organization + Country
org:"Example Organization" country:US

---

# OSINT Correlation Workflow
1. Start with a known domain, hostname, IP address or organization.
2. Search Shodan for publicly observable assets.
3. Identify associated services and technologies.
4. Review certificate information for additional asset clues.
5. Group assets by network, organization and location.
6. Compare findings with other public information sources.
7. Build an authorized attack-surface inventory.
8. Verify important findings independently.
9. Document only information relevant to the authorized research.

---

# Useful Correlation Sources
## DNS
Use DNS records to correlate hostnames and IP addresses.

## WHOIS / RDAP
Use registration and allocation information to understand domain and network ownership.

## Certificate Transparency
Use publiccertificate records to identify certificate names and related domains.

## Public Code Repositories
Search authorized organization names and domains in public code repositories.

## Search Engines
Use search engines to correlate domains, technologies and public documentation.

---

# OSINT Methodology
## Phase 1 - Identify
Identify:
- Domains
- Hostnames
- IP addresses
- Organizations
- Network ranges
- Technologies

## Phase 2 - Enumerate
Enumerate publicly observable:
- Web services
- Network services
- Certificates
- Cloud infrastructure
- IoT devices
- Databases

## Phase 3 - Correlate
Correlate:
- Domain → Hostname
- Hostname → IP
- IP → Organization
- IP → Network
- Certificate → Domain
- Technology → Asset

## Phase 4 - Validate
Verify important findings using independent public sources.

## Phase 5 - Document
Document:
- Asset
- Service
- Technology
- Evidence
- Source
- Date
- Authorization scope

---

# Important Notes
- Shodan is an intelligence and reconnaissance source, not proof of ownership.
- Search results can be incomplete or outdated.
- Organization and geographic attribution may contain false positives.
- Certificate information can reveal relationships between publicly observable assets.
- Do not use OSINT techniques to obtain or expose private information.
- Do not attempt unauthorized access to discovered services.
- Do not perform active scanning or exploitation without explicit authorization.
- Respect bug bounty scope and applicable security policies.
- These queries are intended for educational purposes, OSINT and authorized security research.