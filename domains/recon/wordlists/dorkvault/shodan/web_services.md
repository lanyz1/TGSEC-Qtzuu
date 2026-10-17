# Shodan - Web Services
A curated collection of Shodan search queries for discovering and researching publicly observable web services during authorized security research and reconnaissance.

---

# HTTP Services
## HTTP Services
service:http

## HTTPS Services
service:https

## HTTP on Port 80
port:80

## HTTPS on Port 443
port:443

## HTTP Services by Domain
domain:example.com service:http

## HTTPS Services by Domain
domain:example.com port:443

---

# Web Server Identification
## Apache
product:"Apache httpd"

## Nginx
product:"nginx"

## Microsoft IIS
product:"Microsoft IIS"

## LiteSpeed
product:"LiteSpeed"

## Caddy
product:"Caddy"

---

# HTTP Server Headers
## Apache Server
http.server:"Apache"

## Nginx Server
http.server:"nginx"

## Microsoft IIS
http.server:"Microsoft-IIS"

---

# HTTP Status Codes
## Successful Responses
http.status:200

## Redirects
http.status:301

## Temporary Redirects
http.status:302

## Forbidden Responses
http.status:403

## Not Found Responses
http.status:404

## Server Errors
http.status:500

---

# Web Page Titles
## Login Pages
http.title:"Login"

## Sign In Pages
http.title:"Sign In"

## Dashboard Pages
http.title:"Dashboard"

## Admin Pages
http.title:"Admin"

## Management Interfaces
http.title:"Management"

## Control Panels
http.title:"Control Panel"

---

# Web Content Discovery
## Login Keyword
http.html:"login"

## Sign In Keyword
http.html:"sign in"

## Dashboard Keyword
http.html:"dashboard"

## Administration Keyword
http.html:"administration"

## Documentation Keyword
http.html:"documentation"

## API Keyword
http.html:"API"

---

# Web Technologies
## WordPress
http.component:"WordPress"

## PHP
product:"PHP"

## Node.js
product:"Node.js"

## Django
http.component:"Django"

## React
http.component:"React"

---

# Web Services by Port
## Common HTTP Ports
port:80
port:443
port:8080
port:8000
port:8008
port:8081
port:8443

## Alternative Web Port Search
(port:80 OR port:443 OR port:8080 OR port:8000 OR port:8443)

---

# Domain-Based Reconnaissance
## Web Services for a Domain
domain:example.com service:http

## Web Services for a Hostname
hostname:example.com service:http

## HTTPS Services for a Domain
domain:example.com port:443

## Web Technologies for a Domain
domain:example.com http

---

# Organization-Based Reconnaissance
## Web Services by Organization
org:"Example Organization" service:http

## HTTPS Services by Organization
org:"Example Organization" port:443

## Nginx Services by Organization
org:"Example Organization" product:"nginx"

## Apache Services by Organization
org:"Example Organization" product:"Apache httpd"

---

# Geographic Searches
## Web Services in a Country
country:US service:http

## HTTPS Services in a Country
country:US port:443

## Web Services in a City
city:"New York" service:http

---

# Combined Searches
## Login Pages on HTTPS
http.title:"Login" port:443

## Dashboard Pages on HTTPS
http.title:"Dashboard" port:443

## Nginx HTTPS Services
product:"nginx" port:443

## Apache HTTPS Services
product:"Apache httpd" port:443

## Web Services with Screenshots
service:http has_screenshot:true

## Dashboard Pages with Screenshots
http.title:"Dashboard" has_screenshot:true

---

# Web Service Research Workflow
1. Start with the authorized domain or organization.
2. Identify publicly observable HTTP and HTTPS services.
3. Identify common web servers and technologies.
4. Review page titles and publicly visible content.
5. Identify alternative web ports.
6. Correlate technologies with the authorized security scope.
7. Validate findings manually.
8. Perform active testing only when explicitly permitted.

---

# Important Notes
- Shodan results represent publicly observable services and may become outdated.
- A web service being indexed does not indicate a vulnerability.
- HTTP titles and content can contain false positives.
- Product and technology identification should be manually verified.
- Do not attempt unauthorized authentication, exploitation or access.
- Respect the target's bug bounty scope and rules.
- These queries are intended for educational purposes, OSINT and authorized security research.