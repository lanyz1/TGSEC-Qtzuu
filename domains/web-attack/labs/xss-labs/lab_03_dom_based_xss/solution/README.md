# Solution — Lab 03: DOM-based XSS

## Vulnerability
This lab contains a DOM-based Cross-Site Scripting (DOM XSS) vulnerability.
Unlike Reflected XSS and Stored XSS, the vulnerable behavior in this lab happens entirely on the client side through JavaScript and the DOM.

---

## Step 1 — Identify the Source
The application reads the `message` parameter from the URL:
const params = new URLSearchParams(window.location.search);
const message = params.get("message");
The source is:
window.location.search

More specifically, the attacker-controlled value comes from:

message

The data flow starts with:

URL
  ↓
window.location.search
  ↓
URLSearchParams
  ↓
params.get("message")

---

## Step 2 — Follow the Data Flow
After retrieving the value from the URL, the application stores it in the `message` variable:
const message = params.get("message");
The value is then passed to the DOM:
document.getElementById("output").innerHTML = message || "Hello!";

The complete data flow is:
URL
  ↓
message parameter
  ↓
window.location.search
  ↓
params.get("message")
  ↓
message
  ↓
innerHTML
  ↓
DOM
  ↓
Browser Interpretation

---
## Step 3 — Identify the Sink
The vulnerable sink is:
innerHTML
Specifically:
document.getElementById("output").innerHTML = message || "Hello!";
The application takes attacker-controlled data and assigns it directly to `innerHTML`.
Because `innerHTML` interprets HTML markup, untrusted input can become HTML inside the page.

---

## Step 4 — Confirm the Vulnerability
A harmless proof of concept can be used:
<script>alert(1)</script>
The payload is supplied through the `message` URL parameter.
For example:
http://127.0.0.1:5000/?message=YOUR_PAYLOAD
When the JavaScript reads the parameter and assigns it to `innerHTML`, the browser interprets the supplied HTML.
The JavaScript then executes:
alert(1)

---

## Why Is This DOM-based XSS?
The important characteristic of DOM XSS is that the vulnerable behavior occurs in client-side JavaScript.
The server does not need to reflect or store the payload.
The browser receives the page, JavaScript reads attacker-controlled data, and the JavaScript inserts that data into a dangerous DOM sink.

The flow is:
Attacker-Controlled URL
  ↓
Client-Side JavaScript
  ↓
DOM Sink
  ↓
Browser
  ↓
JavaScript Execution

---

## Difference Between Reflected, Stored and DOM XSS
### Reflected XSS
The payload is sent to the server and reflected in the HTTP response.
Request
  ↓
Server
  ↓
Response
  ↓
Browser
  ↓
Execution

---

### Stored XSS
The payload is sent to the server and stored.
Request
  ↓
Server
  ↓
Storage
  ↓
Later Response
  ↓
Browser
  ↓
Execution

---

### DOM-based XSS
The vulnerability occurs in client-side JavaScript.
URL / User Input
  ↓
JavaScript
  ↓
DOM Sink
  ↓
Browser
  ↓
Execution

---

## Root Cause
The root cause is inserting untrusted data directly into `innerHTML`.
Vulnerable code:
document.getElementById("output").innerHTML = message || "Hello!";
The application assumes that the value retrieved from the URL is safe.
However, URL parameters are controlled by the user and should be treated as untrusted input.

---

## Mitigation
The safest simple fix for this Lab is to use `textContent` instead of `innerHTML`.

### Vulnerable
document.getElementById("output").innerHTML = message || "Hello!";

### Safer
document.getElementById("output").textContent = message || "Hello!";
`textContent` treats the supplied value as text instead of parsing it as HTML.

---
## Why `textContent` Is Safer
With `innerHTML`:

User Input
  ↓
HTML Parsing
  ↓
DOM Elements

With `textContent`:

User Input
  ↓
Text
  ↓
DOM Text Node

Therefore, HTML supplied by the user is displayed as text rather than being interpreted as markup.

---
## Secure Version
Replace:
document.getElementById("output").innerHTML = message || "Hello!";

with:
document.getElementById("output").textContent = message || "Hello!";

---

## Important Security Concept
When analyzing DOM XSS, always identify both:
1. The Source
2. The Sink

Common DOM sources include:
window.location
window.location.search
window.location.hash
document.referrer
localStorage
sessionStorage

Common dangerous sinks include:
innerHTML
outerHTML
document.write()
insertAdjacentHTML()

The exact security impact depends on how data flows from the source to the sink.

---

## Key Takeaways
- DOM XSS happens on the client side.
- The server does not necessarily need to process the payload.
- `window.location.search` can contain attacker-controlled input.
- `innerHTML` is a dangerous DOM sink when used with untrusted data.
- `textContent` is safer when HTML rendering is not required.
- Always trace data from Source to Sink.
- Context matters when analyzing XSS.

---

## Analysis Methodology
When investigating a potential DOM XSS vulnerability:
Source
  ↓
Track the Data
  ↓
Identify Transformations
  ↓
Find the Sink
  ↓
Determine the Context
  ↓
Test with a Harmless PoC
  ↓
Identify the Root Cause
  ↓
Apply the Correct Mitigation

---

## Lab Summary
Lab: 03 — DOM-based XSS
Difficulty: Easy
Category: Web Security / XSS
Vulnerability: DOM-based Cross-Site Scripting
Source: window.location.search
Parameter: message
Sink: innerHTML
Mitigation: textContent
Author: 