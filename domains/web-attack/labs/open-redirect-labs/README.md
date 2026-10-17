# 🔀 Open Redirect Labs
Hands-on Open Redirect labs designed to help security learners understand, practice, and analyze Open Redirect vulnerabilities in a safe local environment.
The goal of this project is not just to demonstrate redirect behavior, but to teach the reasoning behind Open Redirect:
Source → Data Flow → URL Handling → Validation → Redirect → Browser Navigation → Impact → Mitigation

---

## 🎯 Project Goals
This project focuses on understanding:
Basic Open Redirect  
Server-Side Redirects  
Client-Side Redirects  
URL Parameters  
Redirect Parameters  
`window.location`  
`location.href`  
`location.assign()`  
`location.replace()`  
Flask `redirect()`  
HTTP Redirects  
HTTP 3xx Responses  
`Location` Header  
URL Encoding  
Double URL Encoding  
URL Parsing  
URL Components  
URL Schemes  
Hostnames  
Origins  
Relative URLs  
Absolute URLs  
Scheme-relative URLs  
URL Validation  
Allowlisting  
Blocklisting  
Domain Validation  
Subdomain Validation  
Validation Bypass  
Parameter Pollution  
Authentication Redirects  
Login Redirects  
Logout Redirects  
OAuth-style Redirect Flows  
Open Redirect Impact  
Open Redirect Mitigation

Each Lab introduces a specific concept and becomes progressively more challenging.

---

## 🧠 What is Open Redirect?
An Open Redirect vulnerability occurs when an application allows an attacker to influence the destination of a redirect without properly validating the destination.
A simplified example is:
    https://example.com/redirect?url=https://example.org

If the application takes the `url` parameter and redirects the browser to that value without appropriate validation, the destination may be controlled by the user.
The vulnerability is not simply about redirecting a user.

The important security issue is:
    Untrusted Input
          ↓
    Redirect Destination
          ↓
    Browser Navigation

Understanding where the redirect destination comes from, how it is processed, and whether it is properly validated is the core of Open Redirect analysis.

---

## 🎯 Learning Objectives
By completing these Labs, you will learn how to:
- Identify Open Redirect vulnerabilities.
- Find user-controlled redirect parameters.
- Trace redirect data from source to sink.
- Understand server-side redirects.
- Understand client-side redirects.
- Analyze HTTP redirect responses.
- Understand the `Location` header.
- Understand different redirect APIs.
- Analyze URL parameters.
- Understand absolute and relative URLs.
- Understand URL schemes.
- Understand hostnames and origins.
- Analyze URL parsing behavior.
- Understand URL encoding.
- Understand double encoding.
- Identify weak URL validation.
- Analyze allowlists.
- Analyze blocklists.
- Understand common validation mistakes.
- Identify validation bypass opportunities.
- Analyze redirect behavior in authentication flows.
- Understand the security impact of Open Redirect.
- Implement safer redirect logic.

---

## 🚀 How to Use
Each Lab is self-contained and follows the same structure:
    lab_XX_name/
    ├── app.py
    ├── requirements.txt
    ├── README.md
    ├── templates/
    │   └── index.html
    └── solution/
        └── README.md

### `app.py`

Contains the intentionally vulnerable application.

### `requirements.txt`

Contains the dependencies required to run the Lab.

### `README.md`

Contains the challenge, scenario, mission, hints, and learning objectives.

### `templates/`

Contains the HTML templates used by the Lab.

### `solution/`

Contains the explanation, vulnerability analysis, exploitation flow, root cause, and mitigation.

---

## 🔍 Recommended Workflow
Do not immediately open the solution.
Try to solve each Lab yourself first.

Recommended workflow:
    Read the Lab
        ↓
    Understand the application
        ↓
    Inspect the source code
        ↓
    Identify user-controlled input
        ↓
    Follow the data flow
        ↓
    Find the redirect operation
        ↓
    Analyze URL handling
        ↓
    Test your hypothesis
        ↓
    Identify the vulnerability
        ↓
    Understand the root cause
        ↓
    Study the mitigation

---

## 🔬 Investigation Methodology
When investigating an Open Redirect vulnerability, follow the redirect destination from its source to the browser.
A typical flow looks like:
    User Input
        ↓
    URL Parameter
        ↓
    Application Variable
        ↓
    URL Processing
        ↓
    Validation
        ↓
    Redirect Function
        ↓
    HTTP Response / JavaScript
        ↓
    Browser Navigation
        ↓
    Destination

During your investigation, ask:

### 1. Where does the destination come from?
Look for user-controlled values such as:
    url
    next
    redirect
    redirect_url
    return
    return_url
    destination
    target

---

### 2. Can the user control the value?
Determine whether the redirect destination comes directly or indirectly from:
    Query Parameters
    Form Parameters
    Cookies
    Headers
    Client-Side Storage
    JavaScript Variables
    Authentication Parameters

---

### 3. How is the redirect performed?
Look for server-side mechanisms such as:
    Flask redirect()
    HTTP 301
    HTTP 302
    HTTP 303
    HTTP 307
    HTTP 308

Or client-side mechanisms such as:
    window.location
    location.href
    location.assign()
    location.replace()

---

### 4. Is the destination validated?
Check whether the application validates:
    Scheme
    Hostname
    Origin
    Port
    Path
    Destination

---

### 5. How is the URL parsed?
Determine whether the application correctly understands the structure of the URL.
A URL can contain multiple components:
    scheme://hostname:port/path?query#fragment

Incorrect parsing or incomplete validation can result in unexpected behavior.

---

### 6. Is there an allowlist?
An application may allow only trusted destinations.
For example:
    example.com
    trusted.example.com

The important question is whether the validation actually verifies the intended component of the URL.

---

### 7. Is there a blocklist?
Some applications attempt to block known dangerous destinations.
Blocklists can be difficult to maintain because URL syntax has many valid representations.
The Labs demonstrate different validation patterns so you can understand why URL validation must be designed carefully.

---

## 🌐 URL Concepts
Understanding Open Redirect requires a solid understanding of URLs.
Important concepts include:

### Scheme
Examples:
    http:
    https:

---

### Hostname
Example:
    example.com

---

### Port
Example:
    example.com:8080

---

### Path
Example:
    /login

---

### Query
Example:
    ?next=/dashboard

---

### Fragment
Example:
    #section

---

### Absolute URL
Example:
    https://example.com/login

---

### Relative URL
Example:
    /login

---

### Scheme-relative URL
Example:
    //example.com/login

Understanding these components is important when analyzing redirect validation.

---

## 🧩 Redirect Mechanisms
Open Redirect vulnerabilities can appear in different parts of an application.

### Server-Side Redirects
The server determines the destination and sends a redirect response to the browser.
Typical flow:
    Browser
       ↓
    Server
       ↓
    HTTP 3xx
       ↓
    Location Header
       ↓
    Browser
       ↓
    Destination

---

### Client-Side Redirects
JavaScript determines the destination.
Common APIs include:
    window.location
    location.href
    location.assign()
    location.replace()

Typical flow:
    User Input
        ↓
    JavaScript
        ↓
    Location API
        ↓
    Browser
        ↓
    Destination

---

## 🧪 URL Validation
One of the most important concepts in this project is URL validation.
A secure application should not blindly trust a redirect destination supplied by the user.

Depending on the application's requirements, validation may involve:
- Allowlisting trusted destinations.
- Restricting redirects to relative paths.
- Validating the URL scheme.
- Parsing the URL before validation.
- Validating the hostname.
- Validating the origin.
- Rejecting unexpected external destinations.
- Avoiding weak string comparisons.
- Avoiding incomplete blocklists.

The correct validation strategy depends on the application's intended redirect behavior.

---

## 🛡️ Mitigation
Common defensive strategies include:

### Prefer Relative Paths
If the application only needs to redirect users inside the same application, relative paths can reduce unnecessary exposure to external destinations.
Example:
    /dashboard

instead of accepting arbitrary absolute URLs.

---

### Use an Allowlist
If external redirects are required, explicitly define trusted destinations.
For example:
    https://trusted.example.com

Only destinations that satisfy the application's requirements should be accepted.

---

### Parse URLs Correctly
Do not rely solely on simple string operations when validating URLs.
Parse the URL and validate the components that actually matter to the application's security policy.

---

### Validate the Scheme
If only secure web URLs are expected, restrict accepted schemes appropriately.
For example:
    https:

---

### Validate the Hostname
If redirects are intended only for trusted domains, validate the parsed hostname according to the application's actual trust boundary.

---

### Avoid Weak String Checks
Checks such as:
    url.startswith("https://trusted.example.com")

may not be sufficient as a complete URL security policy.
The entire URL structure and relevant components should be considered.

---

## ⚠️ Security Impact
Open Redirect vulnerabilities can have security consequences depending on where and how the redirect is used.
Potential impact can include:
- Phishing assistance
- Social engineering
- Abuse of trusted links
- Misleading authentication flows
- Redirect manipulation
- Abuse of login or logout flows
- Increased credibility of malicious links
- Interaction with other application vulnerabilities

The actual impact depends on the application, the redirect location, and the surrounding security controls.

---

## 🔗 Open Redirect and Authentication
Redirect parameters frequently appear in authentication-related functionality.
Examples include:
    /login?next=/dashboard

or:
    /logout?redirect=/home

Redirect functionality can also appear in:
- Login flows
- Logout flows
- Password reset flows
- Account recovery flows
- OAuth-style flows
- Single Sign-On flows

These situations require additional care because redirect behavior can become part of a security-sensitive workflow.

---

## 🧠 Source-to-Sink Thinking
A key goal of this project is learning to think in terms of:
    Source → Data Flow → Validation → Sink → Browser → Impact

For Open Redirect:
    Source
      ↓
    User-Controlled URL
      ↓
    Data Flow
      ↓
    URL Parsing / Validation
      ↓
    Redirect Sink
      ↓
    Browser Navigation
      ↓
    External Destination

This methodology is more important than memorizing individual payloads or bypass techniques.

---

## 📚 Concepts Covered
Throughout the Labs, you may encounter:
- Open Redirect
- HTTP Redirects
- HTTP 3xx Status Codes
- `Location` Header
- Server-Side Redirects
- Client-Side Redirects
- `window.location`
- `location.href`
- `location.assign()`
- `location.replace()`
- Flask `redirect()`
- URL Parameters
- `next`
- `redirect`
- `url`
- `destination`
- URL Parsing
- URL Encoding
- Double Encoding
- Absolute URLs
- Relative URLs
- Scheme-relative URLs
- URL Schemes
- Hostnames
- Origins
- Ports
- Paths
- Query Strings
- Allowlists
- Blocklists
- Domain Validation
- Subdomain Validation
- Validation Bypass
- Parameter Pollution
- Authentication Redirects
- OAuth-style Redirect Flows
- Secure Redirect Design

---

## 📈 Difficulty
The Labs gradually increase in difficulty.

### 🟢 Easy
Focuses on:
- Basic redirects
- Simple URL parameters
- Basic server-side redirects
- Basic client-side redirects
- Understanding redirect flow

### 🟡 Medium
Focuses on:
- URL parsing
- URL encoding
- Validation logic
- Allowlists
- Blocklists
- Domain validation
- Redirect parameters
- Authentication-related redirects

### ?? Hard
Focuses on:
- Complex URL parsing
- Validation weaknesses
- Multiple URL representations
- Validation bypass techniques
- Parameter pollution
- Complex redirect flows
- Advanced Open Redirect scenarios

---

## 🧪 Lab Philosophy
These Labs are intentionally vulnerable.
The purpose is not simply to find a working redirect.
The purpose is to understand:
    Why is the input controllable?
    How does the input reach the redirect?
    How is the URL interpreted?
    What validation exists?
    Is the validation sufficient?
    What is the security impact?
    How should the vulnerability be fixed?

Understanding the reasoning behind the vulnerability is more important than memorizing a specific technique.

---

## 🔐 Safe Testing
All Labs are designed to run in a controlled local environment.
Use the Labs to practice:
- Source-code analysis
- Manual testing
- URL analysis
- Browser debugging
- HTTP inspection
- Vulnerability identification
- Secure coding
- Mitigation techniques

Only test Open Redirect vulnerabilities against systems that you own or have explicit authorization to assess.

---

## ⚠️ Rules
- Run the Labs locally.
- Do not test against websites you do not own.
- Do not use these Labs to conduct unauthorized attacks.
- Use only controlled environments for experimentation.
- Use harmless destinations during testing.
- Focus on understanding the vulnerability and its mitigation.
- Obtain permission before performing security testing against any external system.

---

## 🏗️ Project Structure
The repository is organized so that each vulnerability is isolated in its own Lab.
    open_redirect_labs/
    │
    ├── lab_01_*/
    │   ├── app.py
    │   ├── requirements.txt
    │   ├── README.md
    │   ├── templates/
    │   │   └── index.html
    │   └── solution/
    │       └── README.md
    │
    ├── lab_02_*/
    │   ├── app.py
    │   ├── requirements.txt
    │   ├── README.md
    │   ├── templates/
    │   │   └── index.html
    │   └── solution/
    │       └── README.md
    │
    ├── ...
    │
    ├── .gitignore
    └── README.md

Each Lab is independent and can be studied separately.

---

## ▶️ Running a Lab
Move into the Lab directory:
    cd lab_XX_name

Install the requirements:
    pip install -r requirements.txt

Run the application:
    python app.py

Then open the local application in your browser:
    http://127.0.0.1:5000/

The exact behavior and testing instructions are provided in each Lab's `README.md`.

---

## 📝 Lab Documentation
Each Lab contains its own documentation.

### Challenge README
The main `README.md` inside a Lab explains:
- Objective
- Scenario
- Mission
- Hints
- Goal
- Running instructions
- Learning objectives
- Concepts
- Difficulty
- Vulnerability type

### Solution README
The `solution/README.md` explains:
- Vulnerability
- Source
- Data Flow
- Redirect Sink
- URL Handling
- Root Cause
- Proof of Concept
- Impact
- Mitigation
- Secure Implementation
- Investigation Methodology
- Key Takeaways

Try to solve the Lab before reading the solution.

---

## 🎓 What This Project Teaches
The most important lesson of this project is learning how to reason about user-controlled URLs.
A vulnerability is not simply:
    "The application redirects."

Instead, investigate:

    Where does the destination come from?
             ↓
    Can the user control it?
             ↓
    How is it processed?
             ↓
    Is it parsed correctly?
             ↓
    Is it validated?
             ↓
    Where is it sent?
             ↓
    How does the browser interpret it?
             ↓
    What security impact can result?

This way of thinking can be applied to real-world security testing and secure application development.

---

## 🚧 Project Status
**In Progress**
This repository is continuously expanding with new Open Redirect scenarios and progressively more challenging vulnerability patterns.
The Labs are designed as a structured learning path, starting from fundamental redirect behavior and progressing toward advanced URL validation and security concepts.

---

## 👤 Author

Security learner & creator of this project.

---

## ⚖️ Disclaimer
This project is created for educational purposes, security research, and authorized security testing.
All vulnerabilities demonstrated in this repository are intentionally introduced into controlled environments.
The author does not encourage unauthorized testing or attacks against systems that you do not own or do not have explicit permission to assess.
Always obtain proper authorization before performing security testing on external systems.

---
Created by  🕷️