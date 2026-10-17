# DorkVault
A curated collection of search queries, reconnaissance techniques, OSINT resources, and security research references.
DorkVault is designed as a structured and practical reference for authorized security researchers, bug bounty hunters, penetration testers, and cybersecurity learners.

---

## Contents
- [Google Dorks](google/README.md)
- [Shodan Dorks](shodan/README.md)
- [Bug Bounty Dorks](bug_bounty/README.md)

---

## Repository Structure
DorkVault/
├── README.md
├── Google/
│   ├── README.md
│   ├── Operators.md
│   ├── Files.md
│   ├── Exposed.md
│   ├── Login_Panels.md
│   ├── Technology.md
│   └── OSINT.md
│
├── Shodan/
│   ├── README.md
│   ├── Operators.md
│   ├── Web_Services.md
│   ├── Network_Services.md
│   ├── Databases.md
│   ├── IoT.md
│   ├── Cloud.md
│   ├── SSL_TLS.md
│   ├── Organizations.md
│   └── OSINT.md
│
└── Bug_Bounty/
    └── ...

---

## Google Dorks
A collection of advanced Google search queries for authorized security research and OSINT.
Topics include:
- Search Operators
- File Discovery
- Exposed Resources
- Login Panels
- Technology Discovery
- OSINT

[Explore Google Dorks](google/README.md)

---

## Shodan Dorks
A collection of Shodan search filters and queries for publicly observable internet infrastructure.
Topics include:
- Shodan Operators
- Web Services
- Network Services
- Databases
- IoT
- Cloud Infrastructure
- SSL/TLS
- Organizations
- OSINT

[Explore Shodan Dorks](shodan/README.md)

---

## Bug Bounty Dorks
A dedicated collection of search queries and reconnaissance techniques for authorized bug bounty programs and web security research.
Topics will include:
- Reconnaissance
- Asset Discovery
- Endpoint Discovery
- Parameter Discovery
- Technology Discovery
- Publicly Indexed Resources
- Vulnerability-Oriented Recon
- Program-Specific Research

[Explore Bug Bounty Dorks](bug_bounty/README.md)

---

## Research Methodology
A typical workflow for using this repository:
1. Define the authorized target.
2. Read the target's security policy and scope.
3. Identify known domains, subdomains, IP ranges, and technologies.
4. Perform passive reconnaissance.
5. Use appropriate search queries and filters.
6. Correlate information from multiple public sources.
7. Validate relevant findings.
8. Perform active testing only when explicitly authorized.
9. Document evidence and report valid findings responsibly.

---

## Responsible Use
DorkVault is intended for:
- Security Research
- OSINT
- Reconnaissance
- Bug Bounty
- Penetration Testing
- Attack Surface Discovery
- Web Application Security
- Network Security
- Cybersecurity Education

Only use the information in this repository against systems and assets you are authorized to assess.

---

## Important Notes
A search result does not automatically indicate a vulnerability.
Finding a:
- File
- Directory
- Login page
- Database
- Network service
- IoT device
- Cloud asset
- Technology
- API
- Certificate

does not by itself prove that the asset is vulnerable.
Always verify authorization, ownership, scope, and security impact before performing any active testing.

---

## Contributions
DorkVault is intended to remain a clean and curated security research reference.
Contributions should:
- Follow the existing repository structure.
- Use clear and descriptive filenames.
- Include accurate descriptions.
- Avoid duplicate queries.
- Avoid private credentials or personal information.
- Avoid sensitive data.
- Include appropriate context for security research.
- Follow responsible disclosure principles.

---

## Quality Standards
Every contribution should prioritize:
- Accuracy
- Reproducibility
- Clear documentation
- Practical usefulness
- Responsible security research
- Proper categorization

---

## Disclaimer
DorkVault is provided for educational purposes, OSINT, authorized security research, and legitimate bug bounty activities.
The information contained in this repository should not be used to gain unauthorized access, bypass authentication, compromise systems, access private information, or conduct illegal activity.
The author is not responsible for misuse of the information contained in this repository.
Always follow applicable laws, security policies, bug bounty rules, and responsible disclosure guidelines.