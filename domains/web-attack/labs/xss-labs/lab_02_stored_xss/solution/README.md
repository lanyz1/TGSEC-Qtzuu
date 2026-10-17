# Solution — Lab 02: Stored XSS

## Vulnerability
This lab is vulnerable to Stored Cross-Site Scripting (Stored XSS).

The application accepts a message from the user, stores it on the server, and later renders the stored message back into the HTML page without proper output encoding.

---

## Step 1 — Identify the Input
The application accepts user input through the message form:

<textarea name="message"></textarea>

The submitted message is received by Flask:

message = request.form.get("message", "")

---

## Step 2 — Follow the Data Flow
The data flow is:

User Input
    ↓
POST Request
    ↓
request.form.get("message")
    ↓
messages.append(message)
    ↓
messages
    ↓
index.html
    ↓
Browser

The message is stored inside the messages list:

messages.append(message)

---

## Step 3 — Find the Dangerous Sink
The stored message is rendered here:

{{ message | safe }}

The safe filter tells Jinja that the value should be treated as trusted HTML.

This disables the normal HTML escaping that would normally protect the page.

---

## Step 4 — Confirm the Vulnerability
Use a harmless proof of concept to confirm JavaScript execution:

<script>alert(1)</script>

Post the payload as a message.

Because the application stores the message and later renders it as HTML, the browser interprets the script element and executes the JavaScript.

---

## Why Is This Stored XSS?
The key difference from Reflected XSS is that the payload is stored before it is rendered.

Reflected XSS:

Request
   ↓
Server
   ↓
Response
   ↓
Browser

Stored XSS:

Request
   ↓
Server
   ↓
Storage
   ↓
Later Request
   ↓
Response
   ↓
Browser

The stored input can therefore affect users who later view the content.

---

## Root Cause
The root cause is rendering untrusted user input as HTML without proper output encoding.

The vulnerable code is:

{{ message | safe }}

User-controlled data should not be marked as trusted HTML unless it has been properly sanitized and there is a specific reason to allow HTML.

---

## Mitigation
The simplest fix is to remove the safe filter:

{{ message }}

Jinja will then HTML-escape the user-controlled value.

For example:

<script>alert(1)</script>

will be displayed as text instead of being interpreted as executable HTML.

---

## Secure Version
Vulnerable:

{{ message | safe }}

Secure:

{{ message }}

---

## Key Takeaways
- Stored XSS persists beyond the original request.
- Always trace user-controlled input from source to sink.
- Do not trust user input as HTML.
- Avoid unnecessary use of the safe filter.
- Output encoding should match the context where data is rendered.
- Perform security testing only in authorized environments.

---

## Learning Path
Input
  ↓
Data Flow
  ↓
Storage
  ↓
Dangerous Sink
  ↓
XSS Execution
  ↓
Root Cause
  ↓
Mitigation

---

Lab: 02 — Stored XSS
Difficulty: Easy
Author: 