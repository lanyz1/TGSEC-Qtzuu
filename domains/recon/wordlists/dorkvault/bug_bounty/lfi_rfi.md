# Bug Bounty - LFI / RFI
A practical collection of Local File Inclusion (LFI) and Remote File Inclusion (RFI) reconnaissance concepts, research areas, and testing methodology for authorized bug bounty programs.

---

# Overview
## LFI
LFI (Local File Inclusion) is a security issue where an application improperly handles file references and may unintentionally expose local resources.
Common affected functionality:
- File viewers
- Document previews
- Template loading
- Language files
- Include mechanisms

---

## RFI
RFI (Remote File Inclusion) is a security issue where an application improperly allows remote resources to be included.
Common affected functionality:
- Remote templates
- External resources
- Dynamic file loading

---

# LFI / RFI Reconnaissance
## File Parameters
site:example.com inurl:file
site:example.com inurl=page
site:example.com inurl=path
site:example.com inurl=template
site:example.com inurl=document

---

# Common Inclusion Parameters
Common parameter names:
- file
- page
- path
- template
- include
- document
- view
- folder
- lang
- language
- module
- theme

---

# File Handling Discovery
## Document Features
Possible locations:
- File viewers
- Document previews
- Report generators
- Download systems

## Template Features
Possible locations:
- Themes
- Email templates
- Page rendering systems

## Language Features
Possible locations:
- Localization files
- Translation systems
- Language selectors

---

# Application Discovery
## PHP Applications
site:example.com filetype:php

## Include References
site:example.com (include OR require)

## Template Systems
site:example.com (template OR view OR theme)

---

# LFI Research Areas
Researchers may review:
- File loading functionality
- Path handling
- Access controls
- Input validation
- Application architecture

---

# RFI Research Areas
Researchers may review:
- External resource handling
- Remote content loading
- URL validation
- Allowlist mechanisms

---

# LFI / RFI Research Workflow
## Phase 1 - Discovery
1. Identify file-related functionality.
2. Find parameters controlling resources.
3. Map application behavior.
4. Identify technologies.

---

## Phase 2 - Analysis
Review:
- File path handling
- Input validation
- File permissions
- Application logic
- Resource loading behavior

---

## Phase 3 - Validation
1. Confirm the application is authorized for testing.
2. Understand expected functionality.
3. Verify security impact safely.
4. Document findings.
5. Report through the correct channel.

---

# Common Affected Components
## File Viewer
Examples:
- Document preview
- Online reader
- File browser

## Template Engine
Examples:
- Theme loading
- Email templates
- Page rendering

## Language System
Examples:
- Translation files
- Localization resources

## Download System
Examples:
- File retrieval
- Export functionality

---

# Documentation Template
| Field | Description |
|---|---|
| Endpoint | Affected URL/API |
| Parameter | File-related input |
| Function | File handling feature |
| Technology | Application technology |
| Impact | Security impact |
| Scope | In-scope / Out-of-scope |
| Notes | Additional details |

---

# Impact Areas
Potential impacts may include:
- Unauthorized file exposure
- Sensitive information disclosure
- Application configuration exposure
- Security boundary issues

Impact depends on:
- Server configuration
- File permissions
- Application design
- Access controls

---

# Prevention Concepts
Developers can reduce inclusion risks by:
- Validating file references
- Avoiding direct user-controlled file paths
- Using secure file handling methods
- Restricting accessible directories
- Applying proper authorization checks

---

# Important Notes
- A file parameter does not automatically indicate LFI/RFI.
- File loading is common application functionality.
- Never access unauthorized files.
- Never attempt to retrieve sensitive resources.
- Always verify scope before testing.
- Respect bug bounty policies and limitations.

---

# Responsible Research
LFI/RFI research should focus on identifying insecure file handling practices while minimizing impact.
Only perform testing against authorized targets and follow responsible disclosure practices.