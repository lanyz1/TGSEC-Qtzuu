# Lab 07 — URL Context XSS | Solution

## Vulnerability
The application contains a Cross-Site Scripting (XSS) vulnerability in a URL context.
User-controlled input is inserted directly into the `href` attribute of an HTML `<a>` element without proper URL scheme validation.

---

## Source
The attacker-controlled input comes from the `url` query parameter.
The application retrieves the value using:
    url = request.args.get("url", "")

The value is then passed to the template:
    return render_template("index.html", url=url)

### Data Flow
    URL Parameter
         ↓
    request.args.get("url")
         ↓
    Flask
         ↓
    Jinja Template
         ↓
    href attribute

---

## Vulnerable Code
The vulnerable code is:
    <a href="{{ url | safe }}">
        Open Link
    </a>

The `| safe` filter tells Jinja not to escape the supplied value.
As a result, the user-controlled value is placed directly into the `href` attribute.

---

## Context
The vulnerable input is placed inside:
    href="USER_INPUT"

This is an HTML URL Context.

The important point is that the browser does not treat every value inside `href` as an ordinary HTTP or HTTPS URL.
Different URL schemes can have different behavior.

---

## Proof of Concept
For this local educational lab, a harmless proof of concept is:
    javascript:alert(1)

When the generated link is opened, the browser interprets the supplied value as a JavaScript URL.
The important lesson is not the payload itself, but understanding how attacker-controlled data reaches a URL context.

---

## Root Cause
The vulnerability exists because the application:
1. Accepts a URL from the user.
2. Does not validate the URL scheme.
3. Places the value directly inside an `href` attribute.
4. Uses the Jinja `safe` filter.
5. Allows the browser to interpret the resulting URL.

The main security issue is trusting an attacker-controlled URL without validating which schemes are allowed.

---

## Why `| safe` Is Dangerous Here
Normally, Jinja automatically escapes HTML-sensitive characters.
For example:
    {{ url }}

is safer than:
    {{ url | safe }}

because `| safe` disables Jinja's normal HTML escaping for that value.
However, HTML escaping alone is not enough for arbitrary URLs.
An application should also validate the URL scheme.

For example, an application may allow:
    https://example.com
    http://example.com

while rejecting dangerous or unexpected schemes.

---

## Mitigation
### 1. Validate the URL Scheme
Only allow expected schemes such as:
    http
    https

Reject unexpected schemes.

Conceptually:
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return "Invalid URL"

---

### 2. Do Not Use `| safe` on Untrusted Input
Instead of:
    <a href="{{ url | safe }}">

use normal Jinja escaping:
    <a href="{{ url }}">

---

### 3. Validate Before Rendering
A safer flow is:
    User Input
        ↓
    Parse URL
        ↓
    Validate Scheme
        ↓
    Allow HTTP/HTTPS
        ↓
    Render with normal escaping

---

## Secure Example
A simplified safer implementation:

    from flask import Flask, request, render_template
    from urllib.parse import urlparse

    app = Flask(__name__)

    @app.route("/")
    def index():
        url = request.args.get("url", "")

        parsed = urlparse(url)

        if url and parsed.scheme not in {"http", "https"}:
            url = ""

        return render_template("index.html", url=url)


    if __name__ == "__main__":
        app.run(debug=True)

And in the template:

    <a href="{{ url }}">
        Open Link
    </a>

---

## Key Takeaways
- XSS can occur in different contexts.
- URL context requires more than simply escaping HTML characters.
- Never blindly trust user-controlled URLs.
- Validate and allowlist URL schemes.
- `| safe` disables Jinja's automatic HTML escaping.
- `href` values should be treated as security-sensitive input.
- `http` and `https` are common schemes to allow for ordinary external links.
- Context-awareoutput handling is essential.

---

## Investigation Methodology
When analyzing a URL Context XSS vulnerability, ask:

### 1. What is the Source?
Where does the attacker-controlled data come from?
    request.args.get("url")

### 2. Where does the data go?
Follow the value through the application:
    url parameter
        ↓
    Flask variable
        ↓
    Jinja template

### 3. What is the Context?
Determine exactly where the value is inserted:
    href="USER_INPUT"

Therefore:
    HTML URL Context

### 4. How does the browser interpret it?
Ask whether the supplied value is treated as:
    HTTP URL
    HTTPS URL
    JavaScript URL
    Other URL scheme

### 5. Is the input validated?
Check whether the application restricts the URL scheme.
If arbitrary schemes are accepted, investigate the security impact.

---

## Vulnerability Chain
    Attacker-Controlled URL
            ↓
    request.args.get("url")
            ↓
          Flask
            ↓
      Jinja Template
            ↓
    href="{{ url | safe }}"
            ↓
         Browser
            ↓
    URL Scheme Interpretation
            ↓
      JavaScript Execution

---

## Lab Summary
| Property | Value |
|---|---|
| Vulnerability | XSS |
| Type | URL Context XSS |
| Source | `url` query parameter |
| Context | HTML `href` / URL |
| Sink | `<a href>` |
| Dangerous Behavior | Unvalidated URL scheme |
| Jinja Filter | `safe` |
| Difficulty | Medium |
| Environment | Local |
| Status | Solved |

---

## What This Lab Teaches
This lab demonstrates that XSS is not limited to:

    <script>

or:

    <div>

Security problems can also appear when attacker-controlled data is inserted into URL-bearing attributes such as:

    href
    src
    action

Understanding the context in which untrusted data is inserted is one of the most important skills when analyzing XSS.

---

## Author
****
Educational purpose only.
Run this lab locally and never use these techniques against systems without explicit authorization.