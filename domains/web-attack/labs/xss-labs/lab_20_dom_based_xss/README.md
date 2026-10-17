# Lab 20 — DOM XSS via `Range.createContextualFragment()`

## Objective
Learn how DOM XSS can occur when attacker-controlled data is passed to `Range.createContextualFragment()`.
This lab introduces `createContextualFragment()` as another HTML-parsing DOM API and helps you understand how untrusted data can become DOM nodes.

---

## Scenario
The application displays a message provided through the URL.
The application reads the `message` parameter and places it inside an HTML string.

That string is then passed to:
    Range.createContextualFragment()

The resulting `DocumentFragment` is inserted into the page.
Your task is to investigate the complete data flow and determine whether the `message` parameter can control the resulting HTML.

---

## Mission
Find the complete data flow:
    URL
      ↓
    window.location.search
      ↓
    URLSearchParams
      ↓
    message
      ↓
    HTML string
      ↓
    createContextualFragment()
      ↓
    DocumentFragment
      ↓
    replaceChildren()
      ↓
    DOM

Determine whether attacker-controlled input can be interpreted as HTML.

---

## Hints
### Hint 1
Start by looking at how the application reads the URL:
    new URLSearchParams(window.location.search)

---

### Hint 2
Find the parameter being extracted:
    message

---

### Hint 3
Look at how the value is used:
    "<p>" + message + "</p>"

Ask yourself:
> What happens when user-controlled data becomes part of an HTML string?

---

### Hint 4
Pay special attention to:
    createContextualFragment()

Ask yourself:
> Does this API treat the supplied string as plain text or parse it as HTML?

---

### Hint 5
Before testing JavaScript execution, try harmless HTML.
For example:
    <b>Hello</b>

If `Hello` appears in bold, you have confirmed that the input is being interpreted as HTML.

---

## Goal
Demonstrate that attacker-controlled input from the URL can reach an HTML-parsing DOM API and become part of the page's DOM.
Use only harmless local proof-of-concept payloads against this intentionally vulnerable lab.

---

## Running the Lab
Install the dependency:
    pip install -r requirements.txt

Run the application:
    python app.py

Then open:
    http://127.0.0.1:5000/

---

## What You Should Learn
By completing this lab, you should understand:
- What `Range.createContextualFragment()` does
- What a `DocumentFragment` is
- How strings can be converted into DOM nodes
- How URL parameters can become DOM data
- What an HTML-parsing DOM sink is
- How DOM XSS can occur through HTML fragment creation
- Why untrusted data should not be placed directly into HTML
- How to trace a DOM XSS source-to-sink data flow

---

## Investigation Methodology
When investigating this vulnerability, follow the data:
1. Identify the source.
2. Identify the URL parameter.
3. Track the value through the JavaScript variables.
4. Find where the value becomes part of an HTML string.
5. Identify the API that parses the HTML.
6. Follow the resulting `DocumentFragment`.
7. Test with harmless HTML first.
8. Demonstrate the vulnerability with a local proof of concept.
9. Identify a safer way to handle the data.

---

## Concepts Covered
- DOM XSS
- `window.location.search`
- `URLSearchParams`
- `Range.createContextualFragment()`
- `DocumentFragment`
- `replaceChildren()`
- DOM manipulation
- HTML parsing
- Source-to-sink analysis
- Dangerous DOM APIs
- `textContent`

---

## Rules
- Run the lab locally.
- Do not test payloads against websites you do not own.
- Use harmless proof-of-concepts.
- Do not attack real users or systems.
- Focus on understanding the source-to-sink vulnerability chain.

---

## Difficulty
**Medium**

---

## Category
**DOM XSS**

---

## Vulnerability Type
**DOM XSS via `Range.createContextualFragment()`**

---

## Status
**Unsolved**

---

## Author
****