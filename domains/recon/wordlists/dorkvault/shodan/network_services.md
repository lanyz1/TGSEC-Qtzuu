# Shodan - Network Services
A curated collection of Shodan search queries for discovering and researching publicly observable network services during authorized security research and reconnaissance.

---

# Common Network Services
## SSH
port:22

## FTP
port:21

## Telnet
port:23

## SMTP
port:25

## DNS
port:53

## POP3
port:110

## IMAP
port:143

## LDAP
port:389

## SMB
port:445

## RDP
port:3389

## VNC
port:5900

---

# Service Identification
## SSH Services
service:ssh

## FTP Services
service:ftp

## SMTP Services
service:smtp

## DNS Services
service:dns

## LDAP Services
service:ldap

## SMB Services
service:smb

---

# SSH Research
## SSH Services
port:22

## SSH by Country
country:US port:22

## SSH by Organization
org:"Example Organization" port:22

## SSH by Product
port:22 product:"OpenSSH"

---

# FTP Research
## FTP Services
port:21

## FTP by Country
country:US port:21

## FTP by Organization
org:"Example Organization" port:21

---

# SMTP Research
## SMTP Services
port:25

## SMTP Submission
port:587

## SMTPS
port:465

## SMTP by Organization
org:"Example Organization" port:25

---

# DNS Research
## DNS Services
port:53

## DNS by Organization
org:"Example Organization" port:53

---

# LDAP Research
## LDAP Services
port:389

## LDAPS
port:636

## LDAP by Organization
org:"Example Organization" port:389

---

# SMB Research
## SMB Services
port:445

## SMB by Organization
org:"Example Organization" port:445

---

# Remote Desktop Services
## RDP
port:3389

## RDP by Country
country:US port:3389

## RDP by Organization
org:"Example Organization" port:3389

---

# VNC
## VNC Services
port:5900

## VNC by Organization
org:"Example Organization" port:5900

---

# Network Service Discovery by Organization
## Common Services
org:"Example Organization" (port:22 OR port:21 OR port:25 OR port:53 OR port:80 OR port:443)

## Remote Access Services
org:"Example Organization" (port:22 OR port:3389 OR port:5900)

## Mail Services
org:"Example Organization" (port:25 OR port:465 OR port:587 OR port:110 OR port:143)

---

# Network Service Discovery by Country
## Common Services
country:US (port:22 OR port:21 OR port:25 OR port:53 OR port:80 OR port:443)

## Remote Access Services
country:US (port:22 OR port:3389 OR port:5900)

---

# Product-Based Searches
## OpenSSH
product:"OpenSSH"

## vsftpd
product:"vsftpd"

## Postfix
product:"Postfix"

## Exim
product:"Exim"

---

# Version Research
## OpenSSH Version
product:"OpenSSH" version:"version"

## FTP Server Version
service:ftp version:"version"

## SMTP Server Version
service:smtp version:"version"

---

# Network Reconnaissance Workflow
1. Start with the authorized domain or organization.
2. Identify associated networks and hosts.
3. Enumerate publicly observable services.
4. Group services by protocol and function.
5. Identify products and versions when available.
6. Correlate findings with the authorized attack surface.
7. Validate results manually.
8. Perform active testing only when explicitly authorized.

---

# Important Notes
- Shodan service data represents publicly observable network services.
- Results may become outdated between scans.
- An exposed network service does not automatically indicate a vulnerability.
- Service banners and product versions should be treated as reconnaissance data until verified.
- Do not attempt unauthorized authentication or exploitation.
- Do not conduct brute-force attacks against discovered services.
- Respect the target's bug bounty scope and security policy.
- These queries are intended for educational purposes, OSINT and authorized security research.