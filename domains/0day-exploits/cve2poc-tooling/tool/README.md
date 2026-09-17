# CVE2PoC

![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)
![Version 1.1](http://img.shields.io/badge/version-v1.0-orange.svg) ![License](https://img.shields.io/badge/license-GPLv3.0-red.svg) ![Maintained](https://img.shields.io/badge/Maintained%3F-Yes-96c40f)

CVE2PoC is a tool that helps penetration testers, bug hunters, and security researchers quickly find public exploits, Proof-of-Concepts (PoCs), and advisories related to a CVE ID.  

# Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
   * [Public Exploits Finding](#public-exploits-finding)
   * [Report Generation](#report-generation)
   * [CVE Description](#cve-description)
   * [Vulnerable Docker Environment and Hands-on Labs](#vulnerable-docker-environment-and-hands-on-labs)
   * [Bug Bounty Reports](#bug-bounty-reports)
   * [Remediation Steps](#remediation-steps)
   * [Exploit Documentation](#exploit-documentation)
   * [CPE to CVE IDs](#cpe-to-cve-ids)
   * [CVE ID to CPEs](#cve-id-to-cpes)
   * [Filters](#filters)
- [Post Installation Setup](#post-installation-setup)
- [Linting and Formating](#linting-and-formating)
- [Credits](#credits)
- [Disclaimer](#disclaimer)

# Features

- 🔍 **Public Exploits Aggregation:** Search and centralize public exploits from GitHub, Nuclei, ExploitDB and Metasploit
- 🐳 **Isolated Testing Environments:** Docker-based environments for safe exploit testing
- 📊 **CVE Intelligence:** Retrieve CVSS, CWE, EPSS, CISA KEV, Vector String
- 📢 **Security Advisories:** Vendor advisories and GHSA references
- 📝 **Report Generation:** Detailed technical report
- ✨ **Ease of Use:** Simple setup and intuitive usage
- 🎯 **Hands-on Labs:** HackTheBox and TryHackMe labs related to a CVE ID
- 🐞 **Bug Bounty Reports:** Bug Bounty write-ups related to a CVE ID
- 🛠️ **Remediation Steps**: Remediation steps to fix a vulnerability 
- ↔️ **CVE/CPE Mapping:** Retrieve CVEs related to a CPE and vice-versa

# Installation

CVE2PoC can be installed using `pipx` or `uv`.  

## Pipx

```bash
pipx install git+https://github.com/0liverFlow/cve2poc
```

## Uv

```bash
uv tool install git+https://github.com/0liverFlow/CVE2PoC
```

```bash
uvx git+https://github.com/0liverFlow/CVE2PoC
```


# Usage

CVE2PoC usage is straightforward. You can use it by simply specifying a CVE ID.  

Refer to the help menu and the demonstration section below to better understand the tool's features.  

```                                      
usage: cve2poc.py [-h] [-x] [-d] [-f FILE] [-o OUTPUT] [-l LANGUAGE] [--limit LIMIT] [-t] [--labs CVE ID]
                  [--bugbounty-reports CVE ID] [--mitigations CVE ID] [--cve2cpe CVE ID] [--cpe2cve CPE] [-s FILE]
                  [--api-keys] [--no-banner]
                  [cve]

A simple yet powerful tool to quickly find PoCs related to a CVE ID

positional arguments:
  cve                               CVE ID

options:
  -h, --help                        show this help message and exit
  -x , --examine                    Examine an exploit's README file
  -d, --description                 Display a CVE ID description
  -f FILE, --file FILE              Specify a file containing a list of CVE IDs
  -o OUTPUT, --output OUTPUT        Output directory to store the reports
  -l LANGUAGE, --language LANGUAGE  Filter PoCs by programming language
  --limit LIMIT                     Number of PoCs to display
  -t , --threads                    Number of concurrent threads
  --labs CVE ID                     Search pre-built docker environments and Hands-on labs related to a CVE ID
  --bugbounty-reports CVE ID        Search Bug Bounty reports related to a CVE ID
  --mitigations CVE ID              Remediation steps to fix a vulnerability
  --cve2cpe CVE ID                  Retrieve CPEs related to a CVE ID
  --cpe2cve CPE                     Retrieve CVEs related to a CPE
  -s FILE, --save FILE              Output file to save CPE2CVE results
  --api-keys                        Configure your GitHub and NVD API keys (Not required)
  --no-banner                       Remove banner
```


## Public Exploits Finding

Run this command to search for public exploits related to a CVE ID:  

```bash
cve2poc <CVE ID>
```

![search_public exploits related to_a_cve_id](assets/search_public_exploits.gif)

> By default, the tool will return the **top 10 exploits**, sorted by their stars and forks.  
> Additionally, it will search for **Metasploit modules**, **Nuclei templates** and **Exploit-DB exploits** related to the specified CVE ID. 


## Report Generation

To search for multiple CVEs, specify a file containing a list of CVE IDs (one CVE per line) using the `-f` flag:  

```bash
cve2poc -f <file>
```

![report generation](assets/report_generation.gif)

![CVE2PoC_report](assets/CVE2PoC_report.png)

> By default, CVE2PoC automatically generates a detailed JSON and HTML reports in the current directory.  
To use a different output directory, use the `-o` flag.  

To test this feature, use the provided [sample files](CVE2PoC/data/samples).


## CVE Description

The command below returns a CVE ID description, as well as additional references to better understand the vulnerability:  

```bash
cve2poc --description <CVE ID>
```

![cve description](assets/get_cve_description.png)


## Vulnerable Docker Environment and Hands-on Labs

CVE2PoC can be used to find ready-to-use Docker environments and hands-on labs to safely understand and test exploits before using them in real-world environments, reducing the risk of production disruptions.  

```bash
cve2poc --labs <CVE ID>
```

![get vulnerable docker environment and hands on labs](assets/get_vulnerable_docker_environment_and_hands_on_labs.png)


## Bug Bounty Reports

Bug Bounty reports can be useful to better understand how a CVE was exploited in real life scenarios. They may also contain PoCs which can help you reproduce the vulnerability.  

```bash
cve2poc --bugbounty-reports <CVE ID>
```

![search bug bounty reports](assets/search_bug_bounty_reports.png)


## Remediation Steps

To quickly identify remediation steps for a vulnerability, use this command:  

```bash
cve2poc --mitigations <CVE ID>
```

![remediation_steps](assets/remediation_steps.png)


## Exploit Documentation

CVE2PoC has a feature similar to `searchsploit -x`, that allows you to read the `README` file of an exploit directly from your terminal. This is handy especially if you need to have a quick understanding of how the exploit works without using your browser.  

To examine the exploit documentation, use this command:  

```bash
cve2poc --examine <GitHub Clone URL>
```

![examine_exploit_readme](assets/examine_exploit.gif)

> The **GitHub Clone URL** is the URL returned by CVE2PoC for each PoC.  

## CPE to CVE IDs

To retrieve CVE IDs related to a CPE, run this command:  

```bash
cve2poc --cpe2cve <CPE>
```

![cpe to cves](assets/cpe_to_cves.png)


## CVE ID to CPEs

To retrieve CPEs related to a CVE ID, run this command:  

```bash
cve2poc --cve2cpe <CVE ID>
```

![cve to cpess](assets/cve_to_cpes.png)


##  Filters

### Filter Public Exploits By Programming Language

CVE2PoC has a feature that can help you search for PoCs written in a specific programming language. To use it, run this command:  

```bash
cve2poc <CVE ID> --language <Programming Language>
```

![filter_pocs by_programming_language](assets/filter_by_programming_language.png)


### Limit The Number of Exploits to Display

By default, CVE2PoC returns the top 10 exploits found on GitHub. Nevertheless, you can display more or fewer exploits using the `--limit` flag:  

```bash
cve2poc <CVE ID> --limit <N>
```

![limit_number_of_pocs_to_display](assets/limit_number_of_pocs_to_display.png)  

> **N** must be greater than or equal to 1.  


# Post Installation Setup

CVE2PoC uses `argcomplete` to automatically perform tab completion via argparse.  

```bash
sudo apt install python3-argcomplete

# For Bash
register-python-argcomplete cve2poc >> ~/.bashrc
source ~/.bashrc

# For Zsh
register-python-argcomplete cve2poc >> ~/.zshrc
source ~/.zshrc
```


# Linting and Formating

CVE2PoC uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting.  

```
# Run linter
uv run ruff check .

# Run linter with auto-fix
uv run ruff check --fix .

# Run formatter
uv run ruff format .
```


# Credits

A huge thanks to the following sources on which CVE2PoC relies on:  
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [FIRST EPSS](https://www.first.org/epss/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [The CVE Program](https://www.cve.org/)
- [Nomi-sec ](https://github.com/nomi-sec/PoC-in-GitHub)
- [Trickest CVE](https://github.com/trickest/cve)
- [Vulhub](https://github.com/vulhub/vulhub)
- [GitHub Advisory Database (GHSA)](https://github.com/advisories)


# Disclaimer

This tool is intended for educational, research, and authorized security testing purposes only. Use it only on systems you own or have explicit permission to assess. The author is not responsible for any misuse or damage resulting from its use.
