# Solution — Lab 05: Event Handler XSS

## Vulnerability
This lab contains a Cross-Site Scripting vulnerability inside an HTML event handler.
The application places user-controlled input inside an `onclick` attribute, where the value is interpreted as JavaScript.

---

## Step 1 — Identify the Input Source
The application receives the `message` parameter from the URL:
message = request.args.get("message", "")

The data flow starts with:
URL
  ↓
message parameter
  ↓
Flask
  ↓
message variable
  ↓
HTML Template

---

## Step 2 — Identify the Context
The important part of this Lab is the rendering context.
The user-controlled value is placed inside an HTML event handler:
onclick="showMessage('{{ message | safe }}')"
Unlike a normal HTML attribute, an event handler such as `onclick` contains JavaScript code.

Therefore, the input is interpreted through two contexts:
HTML Attribute
  ↓
JavaScript

---

## Step 3 — Identify the Dangerous Sink
The vulnerable location is:
onclick="showMessage('{{ message | safe }}')"
The application inserts untrusted input directly into JavaScript code inside an event handler.
The use of the `safe` filter also disables Jinja's automatic HTML escaping.

---

## Step 4 — Understand the JavaScript Context
The original generated HTML looks approximately like this:
onclick="showMessage('USER_INPUT')"

The important part is:
showMessage('USER_INPUT')
The attacker-controlled value is therefore located inside a JavaScript string.
To exploit this type of vulnerability, the attacker must understand the JavaScript context rather than treating the input as ordinary HTML text.

---

## Step 5 — Confirm the Vulnerability
A harmless proof of concept can be used to demonstrate JavaScript execution.
The goal is to:
1. Break out of the JavaScript string.
2. Introduce JavaScript syntax controlled by the attacker.
3. Keep the resulting event handler syntactically valid.
4. Trigger the handler by clicking the button.

A simple PoC can demonstrate execution with:
alert(1)
The test should only be performed against the local lab.

---

## Why Is This Event Handler XSS?
The vulnerability occurs because attacker-controlled data is inserted into an event handler such as:
onclick
Event handler attributes are special because their contents are interpreted as JavaScript.
Therefore, the security context is:

HTML
  ↓
Event Handler Attribute
  ↓
JavaScript
  ↓
JavaScript Execution

---

## Root Cause
The root cause is inserting untrusted user input directly into JavaScript code inside an HTML event handler.

Vulnerable code:
onclick="showMessage('{{ message | safe }}')"
The `safe` filter tells Jinja not to escape the user-controlled value.
This allows the value to influence the JavaScript source code.

---

## Mitigation
The preferred solution is to avoid putting untrusted data directly into inline JavaScript event handlers.

Instead of:
onclick="showMessage('{{ message | safe }}')"
use a safer design where the data is treated as data rather than JavaScript source code.
For example, the application can use a DOM event listener:
const button = document.getElementById("message-button");
button.addEventListener("click", () => {
    // Use trusted application logic here.
});

User-controlled values should be handled as data and should not be concatenated into executable JavaScript.

---

## Secure Design Principle
Avoid:
HTML
  ↓
Inline JavaScript
  ↓
User Input

Prefer:

HTML
  ↓
DOM Element
  ↓
JavaScript Event Listener
  ↓
User Input as Data

Separating JavaScript from HTML makes the application easier to secure and maintain.

---

## Important Security Concept
XSS is context-dependent.
The same user input can behave differently depending on where it is inserted.
For example:
HTML Body:
<div>USER_INPUT</div>

HTML Attribute:
<input value="USER_INPUT">

JavaScript String:
<script>
    const message = "USER_INPUT";
</script>

Event Handler:
<button onclick="showMessage('USER_INPUT')">
    Show
</button>

Each context has different parsing rules and therefore requires appropriate defenses.

---

## Analysis Methodology
When analyzing an event-handler XSS vulnerability:
Source
  ↓
Track User Input
  ↓
Identify HTML Context
  ↓
Identify JavaScript Context
  ↓
Understand String Boundaries
  ↓
Determine Whether Input Can Affect Code
  ↓
Confirm With a Harmless PoC
  ↓
Apply Proper Mitigation

---

## Key Takeaways
- Event handlers such as `onclick` contain executable JavaScript.
- HTML attributes and JavaScript strings have different parsing rules.
- XSS payloads are context-dependent.
- The `safe` filter should not be used with untrusted input.
- Avoid inline JavaScript when possible.
- Treat user-controlled values as data, not executable code.
- Understanding parser boundaries is more important than memorizing payloads.

---

## Lab Summary
Lab: 05 — Event Handler XSS
Difficulty: Medium
Category: Web Security / XSS
Vulnerability Type: Event Handler XSS
Source: URL Parameter (`message`)
Context: HTML Event Handler / JavaScript String
Sink: `onclick`

Root Cause: Untrusted input inserted into executable JavaScript
Mitigation: Avoid inline event handlers and treat user input as data
Author: 