# Lab 14 — iframe `srcdoc` XSS — Solution

## Vulnerability
This lab demonstrates **XSS through the `iframe srcdoc` attribute**.
The application places user-controlled input directly inside an iframe's `srcdoc` attribute:
    <iframe
        srcdoc="<p class='text-slate-700'>{{ content | safe }}</p>"
    ></iframe>

Because `srcdoc` is interpreted as an HTML document, attacker-controlled HTML can become part of the iframe's document.

---

## Source
The user-controlled input comes from the URL parameter:
    content = request.args.get("content", "")

The value is then passed to the template:
    return render_template("index.html", content=content)

---

## Data Flow
    URL parameter
          ↓
    request.args.get("content")
          ↓
    Flask template
          ↓
    {{ content | safe }}
          ↓
    iframe srcdoc
          ↓
    Browser parses srcdoc as HTML
          ↓
    Attacker-controlled HTML is interpreted

---

## Vulnerable Code
The vulnerable code is:
    <iframe
        srcdoc="<p class='text-slate-700'>{{ content | safe }}</p>"
    ></iframe>

The important part is:
    {{ content | safe }}

The `safe` filter disables Jinja's normal HTML escaping.

---

## Context
The input is placed inside the **`srcdoc` attribute of an iframe**.
Unlike a normal text attribute, `srcdoc` has special browser behavior: its value is parsed as an HTML document for the iframe.
This creates a nested HTML parsing context.

---

## Sink
The effective sink is:
    iframe[srcdoc]

The browser takes the value of `srcdoc` and parses it as HTML.

---

## Proof of Concept
A simple HTML payload can demonstrate that the input is interpreted as HTML:
    <h2>Hello</h2>

A harmless event-handler PoC for the local lab is:
    <img src=x onerror=alert(1)>

For example:
    http://127.0.0.1:5000/?content=<img%20src=x%20onerror=alert(1)>

If the payload executes, the JavaScript runs inside the iframe document.

---

## Root Cause
The vulnerability exists because untrusted user input is inserted into an HTML-sensitive context with escaping disabled:

    {{ content | safe }}

The application does not distinguish between trusted HTML and untrusted user input.
Additionally, `srcdoc` is a special context because the browser interprets its value as a complete HTML document.

---

## Mitigation
### 1. Do not use `safe` with untrusted input
The first step is to remove:
    |safe

and allow Jinja's normal HTML escaping to occur.

However, when dealing specifically with `srcdoc`, simply relying on escaping should not be the only security boundary. The application should avoid putting untrusted HTML into `srcdoc` whenever possible.

### 2. Treat `srcdoc` as an HTML document context
If `srcdoc` is not required, remove it and render trusted content using safer DOM APIs or normal text rendering.

### 3. Validate expected input
If the application expects plain text, enforce that expectation and reject unexpected markup.

### 4. Use sandboxing when appropriate
An iframe that must render untrusted HTML can be isolated with an appropriate `sandbox` configuration.
Example:
    <iframe
        sandbox
        srcdoc="..."
    ></iframe>

Sandboxing should be considered an additional defense layer rather than a replacement for proper output handling.

---

## Secure Example
If the application only needs to display the user's input as text, avoid interpreting it as HTML.
For example:
    <p>{{ content }}</p>

Jinja will HTML-escape the value by default.

If an iframe is genuinely required, the application should carefully control what document is placed inside `srcdoc` rather than directly injecting arbitrary user input as HTML.

---

## Investigation Methodology
When investigating this vulnerability, follow the data:
1. Identify the user-controlled source.
       request.args.get("content")

2. Follow the value into the template.
       {{ content | safe }}

3. Identify the output context.
       iframe srcdoc

4. Determine how the browser interprets that context.
       srcdoc → HTML document

5. Test with harmless HTML first.
       <h2>test</h2>

6. Confirm that the browser interprets the input as HTML.
7. Test the local lab with a harmless event-based PoC.

---

## Vulnerability Chain
    User Input
       ↓
    URL ?content=
       ↓
    Flask request.args
       ↓
    Jinja template
       ↓
    |safe
       ↓
    iframe srcdoc
       ↓
    HTML parsing
       ↓
    JavaScript execution

---

## Key Takeaways
- `srcdoc` is an HTML-sensitive browser context.
- An iframe's `srcdoc` value is parsed as an HTML document.
- Jinja's `safe` filter disables automatic HTML escaping.
- Context matters when analyzing XSS.
- A value that looks like ordinary text can become executable HTML when inserted into an HTML-parsing context.
- Sandboxing can provide an additional isolation layer for untrusted iframe content.
- Always trace data from **source → transformation → context → sink**.

---

## Lab Summary
| Property | Value |
|---|---|
| Lab | 14 |
| Category | XSS |
| Vulnerability Type | XSS via iframe `srcdoc` |
| Source | `request.args.get("content")` |
| Sink | `iframe[srcdoc]` |
| Dangerous Behavior | Untrusted HTML interpreted inside `srcdoc` |
| Main Issue | `{{ content \| safe }}` |
| Difficulty | Medium |
| Status | Solved |
| Author |  |

---

## What This Lab Teaches
This lab demonstrates why identifying the **exact output context** is critical during XSS analysis.
The important question is not simply:
> "Is user input reflected?"

The better question is:
> "Where is the input inserted, and how will the browser interpret that context?"

In this lab, the answer is:
    User input
        ↓
    iframe srcdoc
        ↓
    HTML document
        ↓
    HTML interpretation

That context transformation is the key concept behind the vulnerability.