# Solution — Lab 06: XSS in JavaScript Context

## Vulnerability
This lab contains a Cross-Site Scripting vulnerability inside a JavaScript string.
The application places user-controlled input directly inside a JavaScript string within a `<script>` block.

---

## Step 1 — Identify the Input Source
The application receives the `username` parameter from the URL:
username = request.args.get("username", "")

The data flow is:
URL
  ↓
username parameter
  ↓
Flask
  ↓
username variable
  ↓
HTML Template
  ↓
JavaScript

---

## Step 2 — Identify the Context
The vulnerable code is:
const username = '{{ username | safe }}';

The user-controlled value is inside:
<script>
    const username = 'USER_INPUT';
</script>

Therefore, the input is inside a:
JavaScript String Context
This is different from the HTML Attribute context used in Lab 04.

---

## Step 3 — Identify the Dangerous Location
The vulnerable location is:
const username = '{{ username | safe }}';
The application inserts untrusted input directly into executable JavaScript.
The `safe` filter also disables Jinja's normal escaping for the value.

---

## Step 4 — Understand the String Boundary
The original JavaScript structure is:
const username = 'USER_INPUT';
The single quotes define the JavaScript string.
If attacker-controlled input can affect those string boundaries, the input may stop being treated as ordinary string data and start influencing JavaScript syntax.

The important concept is:
JavaScript String
    ↓
String Boundary
    ↓
JavaScript Syntax
    ↓
Execution

---

## Step 5 — Confirm the Vulnerability
A harmless proof of concept can be used to demonstrate JavaScript execution.
The objective is to escape the existing JavaScript string and introduce controlled JavaScript syntax.
For example, the PoC can demonstrate execution with:
alert(1)

Only test the PoC against the local educational lab.

---

## Why Is This JavaScript Context XSS?
The vulnerability occurs because attacker-controlled input is placed directly inside a JavaScript string.
The browser processes the page approximately as:
HTML Parser
    ↓
<script>
    ↓
JavaScript Parser
    ↓
JavaScript String
    ↓
JavaScript Syntax

Because the input becomes part of JavaScript source code, escaping the JavaScript string boundary can change how the browser interprets the code.

---

## Root Cause
The root cause is inserting untrusted user input directly into executable JavaScript.
Vulnerable code:
const username = '{{ username | safe }}';

The `safe` filter prevents Jinja from applying its normal HTML escaping.
More importantly, the application places the untrusted value directly inside a JavaScript string.

---

## Mitigation
Do not insert untrusted user input directly into JavaScript source code.
A safer approach is to keep user-controlled data separate from executable JavaScript.
For example, the application can pass data through a safe data channel and then treat it as data on the client side.
For simple text rendering, the application should ensure that user-controlled values are handled as data rather than executable source code.

---

## Important Security Concept
HTML escaping alone is not enough for every context.
Different contexts have different parsing rules.

Examples:
HTML Body Context:
<div>USER_INPUT</div>

HTML Attribute Context:
<input value="USER_INPUT">

Event Handler Context:
<button onclick="doSomething('USER_INPUT')">

JavaScript String Context:
<script>
    const username = 'USER_INPUT';
</script>

Each context requires an appropriate defense.

---

## Why Context Matters
A security control designed for HTML does not automatically make JavaScript source safe.
When analyzing XSS, always ask:
1. Where does the input come from?
2. Where does the input end up?
3. Which parser interprets it?
4. What characters define the current context?
5. Can the input change the surrounding syntax?

---

## Analysis Methodology
When analyzing JavaScript-context XSS:
Source
  ↓
Track User Input
  ↓
Identify JavaScript Context
  ↓
Identify String Boundary
  ↓Determine Parser Behavior
  ↓
Test With a Harmless PoC
  ↓
Identify Root Cause
  ↓
Apply Context-Appropriate Mitigation

---

## Key Takeaways
- JavaScript strings are a separate XSS context.
- HTML escaping and JavaScript escaping are different concepts.
- User-controlled data should not be concatenated into executable JavaScript.
- The `safe` filter should not be used with untrusted input.
- Understanding string boundaries is essential when analyzing JavaScript-context XSS.
- Always identify the parser responsible for interpreting the input.
- Treat user-controlled values as data, not executable code.

---

## Lab Summary
Lab: 06 — XSS in JavaScript Context
Difficulty: Medium
Category: Web Security / XSS
Vulnerability Type: JavaScript Context XSS
Source: URL Parameter (`username`)
Context: JavaScript String
Sink: Inline JavaScript
Root Cause: Untrusted input inserted into executable JavaScript
Mitigation: Keep untrusted data separate from JavaScript source code
Author: 