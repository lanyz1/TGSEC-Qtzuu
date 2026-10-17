# Shodan Dorks
A curated collection of Shodan search queries and filters for security research, reconnaissance, OSINT and authorized asset discovery.

---

## Contents
- [Operators](operators.md)
- [Web Services](web_services.md)
- [Network Services](network_services.md)
- [Databases](databases.md)
- [IoT](iot.md)
- [Cloud](cloud.md)
- [SSL/TLS](ssl_tls.md)
- [Organizations](organizations.md)
- [OSINT](osint.md)

---

## Categories
### Operators
Core Shodan filters and search operators used to build advanced queries.
[Operators.md](operators.md)

---

### Web Services
Queries for discovering HTTP/HTTPS services, web servers and publicly observable web infrastructure.
[Web_Services.md](web_services.md)

---

### Network Services
Queries for discovering network services, ports and publicly exposed services.
[Network_Services.md](network_services.md)

---

### Databases
Queries for identifying publicly observable database services and database-related infrastructure.
[Databases.md](databases.md)

---

### IoT
Queries for researching publicly observable Internet of Things devices and services.
[IoT.md](iot.md)

---

### Cloud
Queries for researching publicly observable cloud infrastructure and cloud-hosted services.
[Cloud.md](cloud.md)

---

### SSL/TLS
Queries based on SSL/TLS certificates, certificate metadata and related infrastructure.
[SSL_TLS.md](ssl_tls.md)

---

### Organizations
Queries for discovering assets associated with organizations, companies and other authorized targets.
[Organizations.md](organizations.md)

---

### OSINT
Queries and techniques for combining Shodan with publicly available information during reconnaissance.
[OSINT.md](osint.md)

---

## Basic Shodan Query Structure
A Shodan search can combine keywords with filters.

Example:
hostname:example.com

Example:
port:443

Example:
country:US

Example:
org:"Example Organization"

---

## Research Workflow
1. Define the authorized target.
2. Identify the organization's known domains or infrastructure.
3. Start with basic Shodan searches.
4. Apply filters to narrow the results.
5. Identify exposed services and technologies.
6. Correlate Shodan results with other public sources.
7. Validate findings manually.
8. Follow the target's security policy and scope before performing security testing.

---

## Important Notes
- Shodan indexes publicly observable internet-connected services.
- Search results can become outdated.
- Finding a service in Shodan does not automatically mean that the service is vulnerable.
- Do not attempt unauthorized access or exploitation.
- Only perform active security testing against systems for which you have explicit authorization.
- Respect bug bounty scope and program rules.

---

## Purpose
This collection is intended for:
- Security Research
- Reconnaissance
- OSINT
- Bug Bounty
- Attack Surface Discovery
- Network Security Research
- Educational Research

---

## Disclaimer
This repository is intended for educational purposes, OSINT and authorized security research only.
The author is not responsible for misuse of the information or queries contained in this repository.