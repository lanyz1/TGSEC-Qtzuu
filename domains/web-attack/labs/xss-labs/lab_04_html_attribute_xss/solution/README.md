# Solution — Lab 04: XSS in HTML Attributes

## Vulnerability
This lab contains an HTML Attribute-based Cross-Site Scripting vulnerability.
The application takes user-controlled input from the URL and places it inside an HTML attribute without proper escaping.
Because the input is placed inside an HTML attribute context, an attacker may be able to break out of the existing attribute and inject new HTML or JavaScript behavior.

---

## Step 1 — Identify the Input Source
The user-controlled input comes from the URL parameter:
name

The application receives the value using Flask:
name = request.args.get("name", "")

The data flow starts from:

URL Parameter
    ↓
request.args.get("name")
    ↓
name variable
    ↓
HTML Template

---

## Step 2 — Identify the Context
The important part of this Lab is understanding the context.
The user input is placed inside an HTML attribute:
<input value="{{ name }}">

The input is not inside normal HTML text.

It is inside:
HTML Attribute Context

Example:
<input value="USER_INPUT">

This means the browser interprets the value differently compared to normal HTML content.

---

## Step 3 — Find the Dangerous Sink
The vulnerable location is:
<input
    type="text"
    value="{{ name }}"
>

The application inserts user-controlled data directly into an HTML attribute.
If the input is not properly escaped, the attacker may be able to escape the current attribute context.

---

## Step 4 — Understanding Context Breaking
The browser sees:
<input value="USER_INPUT">

The goal in this type of XSS is not simply inserting JavaScript.
The goal is to first break out of the existing attribute context.
The general idea:
Existing Context:
value="USER_INPUT"

↓

Break the attribute

↓

Create a new HTML context

↓

Execute JavaScript behavior

---

## Step 5 — Confirm the Vulnerability
A harmless proof of concept can be used to verify execution.
The payload should demonstrate that the attacker-controlled input can escape the attribute context and create a new executable context.

Example concept:

Break attribute
    ↓
Inject new element or event handler
    ↓
Browser executes JavaScript

---

## Why Is This HTML Attribute XSS?
Because the vulnerable input is located inside an HTML attribute.
Different XSS contexts require different analysis.

Examples:
HTML Body Context:
<div>
    USER_INPUT
</div>

HTML Attribute Context:
<input value="USER_INPUT">

JavaScript Context:
<script>
    var x = "USER_INPUT";
</script>

The same payload does not work everywhere because browsers interpret each context differently.

---

## Root Cause
The root cause is placing untrusted user input directly into an HTML attribute and disabling Jinja's automatic escaping by using the safe filter.
The vulnerable code is:
<input value="{{ name | safe }}">
The safe filter tells Jinja not to escape the user-controlled value, allowing HTML interpretation.

---

## Mitigation
The correct defense depends on the context.
For HTML attributes:
- Apply proper HTML attribute encoding.
- Never insert untrusted data into HTML structure.
- Use secure templating features.
- Avoid disabling automatic escaping.

A safer approach is allowing the template engine to escape the value:
{{ name }}
instead of manually marking data as safe.

---

## Secure Version
Unsafe:
<input value="{{ name }}">

Safer:
<input value="{{ name | e }}">
The value is encoded before being placed into the attribute.

---

## Important Security Concept
XSS is context-dependent.
Always ask:
Where does the input land?

Possible contexts:
- HTML Body
- HTML Attribute
- JavaScript
- CSS
- URL

Each context requires a different defense strategy.

---

## Analysis Methodology
When testing for HTML Attribute XSS:
Source
    ↓
Track User Input
    ↓
Identify Context
    ↓
Find Escape Characters
    ↓
Break Context
    ↓
Reach Dangerous HTML Behavior
    ↓
Apply Proper Encoding

---

## Key Takeaways
- HTML attributes are different from HTML body content.
- Context determines how XSS works.
- User input should never control HTML structure.
- Output encoding must match the rendering context.
- Understanding the browser parser is more important than memorizing payloads.

---

## Lab Summary
Lab: 04 — XSS in HTML Attributes
Difficulty: Medium
Category: Web Security / XSS
Vulnerability Type: HTML Attribute XSS
Source: URL Parameter (name)
Context: HTML Attribute
Sink: HTML attribute rendering
Mitigation: Proper Output Encoding
Author: 