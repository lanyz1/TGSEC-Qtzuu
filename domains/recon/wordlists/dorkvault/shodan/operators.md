# Shodan Operators
A curated reference of Shodan search filters and operators used for asset discovery, reconnaissance, OSINT and authorized security research.

---

# Basic Filters
## hostname:
Search for hosts associated with a specific hostname.
Syntax:
hostname:example.com

Example:
hostname:example.com

---

## domain:
Search for hosts associated with a specific domain.
Syntax:
domain:example.com

Example:
domain:example.com

---

## ip:
Search for a specific IP address.
Syntax:
ip:8.8.8.8

Example:
ip:8.8.8.8

---

## net:
Search within a specific IP network or CIDR range.
Syntax:
net:192.168.1.0/24

Example:
net:8.8.8.0/24

---

# Location Filters
## country:
Filter results by country.
Syntax:
country:US

Examples:
country:US
country:DE
country:JP

---

## city:
Filter results by city.
Syntax:
city:"New York"

Example:
city:"San Francisco"

---

## state:
Filter results by state or region.
Syntax:
state:"California"

Example:
state:"California"

---

## geo:
Search using geographic coordinates.
Syntax:
geo:latitude,longitude

Example:
geo:37.7749,-122.4194

---

# Organization Filters
## org:
Search for hosts associated with an organization.
Syntax:
org:"Organization Name"

Example:
org:"Example Organization"

---

## isp:
Filter results by Internet Service Provider.
Syntax:
isp:"ISP Name"

Example:
isp:"Example ISP"

---

# Port and Service Filters
## port:
Search for services running on a specific port.
Syntax:
port:443

Examples:
port:80
port:443
port:22

---

## product:
Search for a specific product or service.
Syntax:
product:"Product Name"

Examples:
product:"Apache httpd"
product:"nginx"

---

## version:
Search for a specific product version.
Syntax:
version:"Version"

Example:
version:"2.4.49"

---

## service:
Filter results by service type.
Syntax:
service:http

Examples:
service:http
service:ssh
service:ftp

---

# Operating System
## os:
Search for hosts associated with an operating system.
Syntax:
os:"Operating System"

Examples:
os:"Ubuntu"
os:"Windows Server 2019"

---

# Web Filters
## http.title:
Search for a specific HTTP page title.
Syntax:
http.title:"Title"

Example:
http.title:"Dashboard"

---

## http.html:
Search for text found in HTTP response HTML.
Syntax:
http.html:"keyword"

Example:
http.html:"login"

---

## http.status:
Filter HTTP responses by status code.
Syntax:
http.status:200

Examples:
http.status:200
http.status:301
http.status:403

---

## http.server:
Search for a specific HTTP server.
Syntax:
http.server:"Server"

Examples:
http.server:"Apache"
http.server:"nginx"

---

## http.component:
Search for a specific web component.
Syntax:
http.component:"Component"

Example:
http.component:"WordPress"

---

# SSL/TLS Filters
## ssl:
Search for hosts exposing SSL/TLS services.
Syntax:
ssl:true

Example:
ssl:true

---

## ssl.cert.subject.cn:
Search certificates by Common Name.
Syntax:
ssl.cert.subject.cn:"example.com"

Example:
ssl.cert.subject.cn:"example.com"

---

## ssl.cert.issuer.cn:
Search certificates by issuer Common Name.
Syntax:
ssl.cert.issuer.cn:"Issuer"

Example:
ssl.cert.issuer.cn:"Let's Encrypt"

---

# Vulnerability Research
## has_vuln:
Search for hosts with vulnerability information associated with the result.

Syntax:
has_vuln:true

Example:
has_vuln:true

---

## vuln:
Search for a specific vulnerability identifier.
Syntax:
vuln:CVE-YYYY-NNNN

Example:
vuln:CVE-2021-44228

---

# File and Content Filters
## has_screenshot:
Search for results that have an associated screenshot.
Syntax:
has_screenshot:true

Example:
has_screenshot:true

---

## has_ssl:
Search for results with SSL information.
Syntax:
has_ssl:true

Example:
has_ssl:true

---

# Combined Queries
## Organization + Port
org:"Example Organization" port:443

---

## Domain + Port
hostname:example.com port:443

---

## Domain + Web Service
domain:example.com service:http

---

## Organization + HTTP
org:"Example Organization" http

---

## Country + Service
country:USservice:http

---

## Product + Country
product:"nginx" country:US

---

## HTTP Title + Port
http.title:"Dashboard" port:443

---

## HTTP Server + Country
http.server:"nginx" country:US

---

## SSL + Domain
domain:example.com has_ssl:true

---

# Search Strategy
1. Start with the organization's domain.
2. Search using hostname or domain filters.
3. Identify associated IP ranges and organizations.
4. Filter by ports and services.
5. Identify technologies and software versions.
6. Correlate results with public OSINT sources.
7. Validate findings within the authorized scope.

---

# Important Notes
- Shodan filter syntax and available fields may change over time.
- Some filters require specific Shodan plans or features.
- Search results depend on Shodan's available data and scanning history.
- A Shodan result does not automatically indicate a vulnerability.
- Do not attempt unauthorized access or exploitation.
- Only perform active security testing against assets you are authorized to assess.

---

# References
- Shodan Search Documentation
- Shodan Search Query Syntax
- Shodan Developer Documentation