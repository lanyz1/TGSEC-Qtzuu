# Lab 08 — HTML Tag Context XSS | Solution

## Vulnerability
The application contains a Cross-Site Scripting (XSS) vulnerability because user-controlled input is inserted directly into the HTML document without proper output encoding.

The input is placed inside the content of an HTML element.

---

## Source
The attacker-controlled input comes from the `name` query parameter.
The application retrieves the value using:
    name = request.args.get("name", "")

The value is then passed to the template:

    return render_template("index.html", name=name)

### Data Flow
    URL Parameter
         ↓
    request.args.get("name")
         ↓
    Flask
         ↓
    Jinja Template
         ↓
    HTML Content
         ↓
    Browser

---

## Vulnerable Code
The vulnerable template contains:

    <h2 class="text-xl font-semibold">
        Hello, {{ name | safe }}
    </h2>

The `| safe` filter disables Jinja's automatic HTML escaping.
Therefore, HTML supplied by the user is interpreted as HTML by the browser instead of being displayed as plain text.

---

## Context
The user-controlled value is inserted between the opening and closing tags of an HTML element:

    <h2>
        USER_INPUT
    </h2>

This is an **HTML Text Context**.
The browser parses the supplied value as part of the HTML document.

---

## Proof of Concept
A harmless proof of concept for the local lab is:

    <script>alert(1)</script>

When submitted as the `name` parameter, the supplied HTML is interpreted by the browser.
This demonstrates that the application is allowing attacker-controlled HTML to reach the page without proper encoding.

---

## Root Cause
The root cause is the use of the Jinja `safe` filter on untrusted user input:
    {{ name | safe }}

Normally, Jinja automatically escapes HTML-sensitive characters.

For example:
    {{ name }}

would cause HTML characters such as `<` and `>` to be escaped.

But:
    {{ name | safe }}

explicitly tells Jinja to treat the value as trusted HTML.
This allows attacker-controlled markup to become part of the rendered HTML document.

---

## Why `| safe` Is Dangerous
The `safe` filter should only be used when the content is known to be trusted or has been properly sanitized.
For example:
    {{ name | safe }}

can turn user input such as:
    <script>alert(1)</script>

into actual HTML/JavaScript in the browser.
Without `safe`, Jinja escapes the input so that it is treated as text instead of markup.

---

## Mitigation
### 1. Remove `| safe`
Instead of:
    {{ name | safe }}

use:
    {{ name }}

Jinja will then automatically HTML-escape the user-controlled value.

---

### 2. Treat User Input as Untrusted
User-controlled data should not be considered trusted HTML.
A safer data flow is:
    User Input
        ↓
    Flask
        ↓
    Jinja Autoescaping
        ↓
    HTML-Encoded Output
        ↓
    Browser

---

### 3. Use Sanitization When HTML Is Actually Required
If an application genuinely needs to allow users to submit limited HTML, simply removing `safe` may not provide the intended functionality.
In that case, the application should use a well-designed HTML sanitization process with an explicit allowlist of permitted elements and attributes.
For normal text such as a username, HTML should not be allowed at all.

---

## Secure Example
The vulnerable code:

    <h2>
        Hello, {{ name | safe }}
    </h2>

should become:

    <h2>
        Hello, {{ name }}
    </h2>

Now an input such as:

    <script>alert(1)</script>

will be rendered as text rather than being interpreted as HTML.

---

## Investigation Methodology
When analyzing an HTML Context XSS vulnerability, follow these steps.

### 1. Identify the Source
Find where the user-controlled input enters the application:

    request.args.get("name")

### 2. Trace the Data
Follow the value from Flask to the template:

    name
      ↓
    render_template()
      ↓
    {{ name | safe }}

### 3. Identify the Context
Determine where the value is inserted:

    <h2>
        USER_INPUT
    </h2>

The value is inside anHTML text context.

### 4. Check Output Encoding
Ask whether the template engine escapes the input.
Compare:
    {{ name }}

with:
    {{ name | safe }}

### 5. Test With a Harmless PoC
Use a local proof of concept to determine whether the browser interprets the input as HTML/JavaScript.

---

## Vulnerability Chain
    Attacker-Controlled Input
            ↓
    request.args.get("name")
            ↓
          Flask
            ↓
      Jinja Template
            ↓
    {{ name | safe }}
            ↓
       Raw HTML Output
            ↓
         Browser
            ↓
    HTML/JavaScript Interpretation

---

## Key Takeaways
- XSS can occur inside normal HTML text content.
- User input should be treated as untrusted by default.
- Jinja autoescaping provides important protection against HTML injection.
- The `safe` filter disables that protection for the selected value.
- Do not use `| safe` on untrusted input.
- If HTML input is intentionally supported, use proper sanitization.
- Always identify the Source, Context, and Sink when analyzing XSS.

---

## Lab Summary

| Property | Value |
|---|---|
| Vulnerability | Cross-Site Scripting |
| Type | HTML Context XSS |
| Source | `name` query parameter |
| Context | HTML Text Context |
| Sink | HTML element content |
| Dangerous Behavior | Raw user input rendered as HTML |
| Jinja Filter | `safe` |
| Difficulty | Medium |
| Environment | Local |
| Status | Solved |

---

## What This Lab Teaches
This lab demonstrates how XSS can occur even when the attacker-controlled input is not placed inside an attribute or JavaScript block.
The critical question is always:
    Where does the untrusted input end up?

In this lab, the answer is:
    HTML Text Context

Understanding the rendering context makes it easier to identify the appropriate security control.

---

## Author
****
Educational purpose only.
Run this lab locally and never use these techniques against systems without explicit authorization.