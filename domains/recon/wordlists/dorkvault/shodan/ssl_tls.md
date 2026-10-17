# Shodan - SSL/TLS
A curated collection of Shodan search queries for researching publicly observable SSL/TLS certificates, encrypted services and certificate metadata during authorized security research and reconnaissance.

---

# SSL Services
## SSL Enabled Services
ssl:true

## HTTPS Services
port:443 ssl:true

## SSL Services by Domain
domain:example.com ssl:true

## SSL Services by Organization
org:"Example Organization" ssl:true

---

# Certificate Common Name
## Search Certificate CN
ssl.cert.subject.cn:"example.com"

## Certificate CN by Organization
org:"Example Organization" ssl.cert.subject.cn:"example.com"

## Certificate CN Keywords
ssl.cert.subject.cn:"keyword"

---

# Certificate Issuer
## Search Certificate Issuer
ssl.cert.issuer.cn:"Issuer Name"

## Let's Encrypt Certificates
ssl.cert.issuer.cn:"Let's Encrypt"

## DigiCert Certificates
ssl.cert.issuer.cn:"DigiCert"

---

# Certificate Organization
## Certificate Organization Name
ssl.cert.subject.o:"Organization Name"

## Certificate Organization Search
ssl.cert.subject.o:"Example Organization"

---

# SSL Versions
## TLS Services
ssl.version:TLSv1

## TLS 1.2
ssl.version:TLSv1.2

## TLS 1.3
ssl.version:TLSv1.3

---

# HTTPS Services
## HTTPS
port:443

## Alternative HTTPS Ports
(port:443 OR port:8443 OR port:9443)

## HTTPS by Organization
org:"Example Organization" port:443

## HTTPS by Country
country:US port:443

---

# Certificate Expiration Research
## Expired Certificates
ssl.cert.expired:true

## Certificates with Expiration Information
ssl.cert.expiry

---

# Certificate Fingerprints
## Certificate Hash
ssl.cert.fingerprint:"fingerprint"

## Certificate Fingerprint Research
ssl.cert.fingerprint

---

# Domain Certificate Research
## Domain Certificates
ssl.cert.subject.cn:"example.com"

## Subdomain Certificates
ssl.cert.subject.cn:"*.example.com"

## Certificate Domain Search
ssl.cert.subject.cn:example.com

---

# Organization Certificate Research
## Organization Certificates
org:"Example Organization" ssl.cert.subject.o:"Example Organization"

## Organization SSL Assets
org:"Example Organization" ssl:true

---

# Combined Searches
## Domain + HTTPS
domain:example.com port:443

## Domain + SSL Certificate
domain:example.com ssl:true

## Organization + HTTPS
org:"Example Organization" port:443

## SSL + Screenshot
ssl:true has_screenshot:true

## HTTPS + Web Server
port:443 (product:"nginx" OR product:"Apache httpd")

---

# Certificate-Based Reconnaissance Workflow
1. Start with an authorized domain or organization.
2. Search available SSL/TLS certificates.
3. Identify certificate names and related domains.
4. Correlate certificate information with known assets.
5. Identify publicly observable HTTPS services.
6. Validate certificate and service information manually.
7. Document findings within the authorized security scope.

---

# Important Notes
- SSL/TLS information is useful for asset discovery and reconnaissance.
- Certificate data does not automatically indicate a vulnerability.
- Certificate records may be outdated.
- Certificate names can include multiple unrelated assets.
- Do not attempt unauthorized access to discovered services.
- Do not perform attacks against SSL/TLS services without authorization.
- Respect bug bounty scope and security policies.
- These queries are intended for educational purposes, OSINT and authorized security research.