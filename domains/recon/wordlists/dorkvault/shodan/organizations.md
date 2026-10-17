# Shodan - Organizations
A curated collection of Shodan search queries for discovering publicly observable assets associated with organizations, companies and authorized targets.

---

# Organization Search
## Basic Organization Search
org:"Example Organization"

## Organization + HTTP
org:"Example Organization" service:http

## Organization + HTTPS
org:"Example Organization" port:443

## Organization + IP Network
org:"Example Organization" net:192.0.2.0/24

---

# Organization by Service
## SSH
org:"Example Organization" port:22

## FTP
org:"Example Organization" port:21

## SMTP
org:"Example Organization" port:25

## DNS
org:"Example Organization" port:53

## HTTP
org:"Example Organization" port:80

## HTTPS
org:"Example Organization" port:443

## RDP
org:"Example Organization" port:3389

---

# Organization by Technology
## Nginx
org:"Example Organization" product:"nginx"

## Apache
org:"Example Organization" product:"Apache httpd"

## OpenSSH
org:"Example Organization" product:"OpenSSH"

## Microsoft IIS
org:"Example Organization" product:"Microsoft IIS"

---

# Organization by Web Technology
## WordPress
org:"Example Organization" http.component:"WordPress"

## Dashboard Pages
org:"Example Organization" http.title:"Dashboard"

## Login Pages
org:"Example Organization" http.title:"Login"

## API Services
org:"Example Organization" (http.title:"API" OR http.html:"API")

---

# Organization by Database
## MySQL
org:"Example Organization" port:3306

## PostgreSQL
org:"Example Organization" port:5432

## Microsoft SQL Server
org:"Example Organization" port:1433

## MongoDB
org:"Example Organization" port:27017

## Redis
org:"Example Organization" port:6379

## Elasticsearch
org:"Example Organization" port:9200

---

# Organization by Remote Access
## SSH
org:"Example Organization" service:ssh

## RDP
org:"Example Organization" port:3389

## VNC
org:"Example Organization" port:5900

---

# Organization by Mail Services
## SMTP
org:"Example Organization" service:smtp

## SMTP Port
org:"Example Organization" port:25

## Submission
org:"Example Organization" port:587

## IMAP
org:"Example Organization" port:143

## IMAPS
org:"Example Organization" port:993

---

# Organization by Location
## Country
org:"Example Organization" country:US

## City
org:"Example Organization" city:"New York"

## State
org:"Example Organization" state:"California"

---

# Organization by SSL/TLS
## SSL Services
org:"Example Organization" ssl:true

## HTTPS
org:"Example Organization" port:443

## Certificate Organization
org:"Example Organization" ssl.cert.subject.o:"Example Organization"

## Certificate Common Name
org:"Example Organization" ssl.cert.subject.cn:"example.com"

---

# Organization by Network
## Network Range
org:"Example Organization" net:192.0.2.0/24

## Specific IP
org:"Example Organization" ip:192.0.2.10

## Common Web Ports
org:"Example Organization" (port:80 OR port:443)

## Common Remote Access Ports
org:"Example Organization" (port:22 OR port:3389 OR port:5900)

---

# Organization by Cloud
## Cloud References
org:"Example Organization" cloud

## AWS References
org:"Example Organization" "AWS"

## Azure References
org:"Example Organization" "Azure"

## Google Cloud References
org:"Example Organization" "Google Cloud"

---

# Organization by IoT
## IoT References
org:"Example Organization" IoT

## Cameras
org:"Example Organization" camera

## Printers
org:"Example Organization" printer

## Network Devices
org:"Example Organization" ("network device" OR router OR switch)

---

# Organization Asset Discovery
## Web Assets
org:"Example Organization" service:http

## HTTPS Assets
org:"Example Organization" port:443

## Network Services
org:"Example Organization" (port:21 OR port:22 OR port:25 OR port:53 OR port:80 OR port:443)

## Database Services
org:"Example Organization" (port:3306 OR port:5432 OR port:1433 OR port:27017 OR port:6379 OR port:9200)

---

# Organization + Screenshots
## Web Screenshots
org:"Example Organization" has_screenshot:true

## HTTPS Screenshots
org:"Example Organization" port:443 has_screenshot:true

## Dashboard Screenshots
org:"Example Organization" http.title:"Dashboard" has_screenshot:true

---

# Organization Reconnaissance Workflow
1. Define the organization that is authorized for research.
2. Search using the organization's Shodan organization name.
3. Identify associated hosts and network ranges.
4. Categorize discovered assets by service and technology.
5. Identify publicly observable web, network, database and cloud services.
6. Correlate Shodan results with known domains and public information.
7. Validate discovered assets manually.
8. Compare findings against the authorized security scope.
9. Report unintended exposure through the appropriate security channel.

---

# Important Notes
- The Shodan org filter is based on Shodan's organization attribution.
- Organization names can produce false positives or incomplete results.
- An asset appearing under an organization does not necessarily prove ownership.
- IP ownership and organization attribution should be independently verified.
- A publicly observable service does not automatically represent a vulnerability.
- Do not attempt unauthorized access, authentication attacks or exploitation.
- Only perform active security testing against explicitly authorized assets.
- Respect bug bounty scope and program rules.
- These queries are intended for educational purposes, OSINT and authorized security research.