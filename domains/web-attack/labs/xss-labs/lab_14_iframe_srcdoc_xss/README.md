# Lab 14 — iframe `srcdoc` XSS

## Objective
Learn how user-controlled input can become HTML when it is placed inside an iframe's `srcdoc` attribute.
This lab focuses on understanding a different HTML context and how the browser parses `srcdoc` content.

---

## Scenario
The application provides a simple preview feature.
You can provide content through the `content` URL parameter, and the application places that content inside an iframe:
    <iframe
        srcdoc="<p class='text-slate-700'>{{ content | safe }}</p>"
    ></iframe>

Your goal is to determine whether the supplied input can escape the intended behavior and be interpreted as HTML inside the iframe.

---

## Mission
Investigate the application and answer these questions:
1. Where does the user-controlled input come from?
2. Where is the input inserted into the page?
3. What does the `srcdoc` attribute do?
4. What does the Jinja `safe` filter change?
5. Can you make the iframe interpret your input as HTML?
6. Can you demonstrate JavaScript execution in the local lab?

---

## Hints
### Hint 1
Start by looking at:
    request.args.get("content")

Where does this value go afterward?

### Hint 2
Pay close attention to:
    {{ content | safe }}

What normally happens to HTML characters in Jinja templates?
What changes when `safe` is used?

### Hint 3
The input is not being placed inside an ordinary paragraph only.
Look at:
    iframe
    srcdoc

Research what `srcdoc` represents.

### Hint 4
Before trying JavaScript, test whether ordinary HTML is interpreted.
For example, try a harmless HTML element such as:
    <h2>Test</h2>

If the browser renders it as HTML, continue investigating the context.

---

## Goal
Successfully demonstrate that user-controlled content can be interpreted as HTML inside the iframe's `srcdoc` document.
Then demonstrate JavaScript execution using a harmless local proof of concept.

---

## Running the Lab
From the `lab-14` directory:
    python app.py

Then open:
    http://127.0.0.1:5000/

You can provide input through the `content` parameter:
    http://127.0.0.1:5000/?content=test

---

## Investigation Methodology
Follow the data from source to sink:
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

The goal is to understand every step of this flow rather than simply finding a working payload.

---

## What You Should Learn
After completing this lab, you should understand:
- What `iframe srcdoc` is
- Why `srcdoc` is an HTML-sensitive context
- How Jinja's `safe` filter affects output encoding
- Why browser parsing context matters in XSS
- How to trace user input from source to sink
- Why untrusted HTML should not be inserted directly into `srcdoc`
- How sandboxing can provide an additional layer of isolation for untrusted iframe content

---

## Concepts Covered
- Reflected XSS
- HTML Context
- iframe
- `srcdoc`
- Jinja2
- Output Encoding
- `safe` Filter
- HTML Parsing
- Source-to-Sink Analysis
- Browser Security Contexts
- Sandbox Isolation

---

## Rules
- Run the lab locally.
- Do not test the payloads against third-party websites.
- Use harmless proof-of-concept payloads.
- Focus on understanding the vulnerability rather than simply copying a payload.
- Read the source code and trace the data flow.

---

## Difficulty
Medium

---

## Category
XSS

---

## Vulnerability Type
XSS via iframe `srcdoc`

---

## Status
Unsolved

---

## Author
