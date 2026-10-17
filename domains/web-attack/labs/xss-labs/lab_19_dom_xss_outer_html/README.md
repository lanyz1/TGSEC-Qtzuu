# Lab 19 — DOM XSS via `outerHTML`

## Objective
Learn how DOM XSS can occur when attacker-controlled data is inserted into the DOM through the `outerHTML` property.
This lab introduces `outerHTML` as a DOM XSS sink and helps you understand why constructing HTML with untrusted input can be dangerous.

---

## Scenario
The application displays a simple profile message.
The username/message is taken from the URL using the `message` parameter.
The application then builds an HTML string and assigns it to:
    outerHTML

Your task is to investigate how the URL input flows through the application and determine whether you can control the HTML that is inserted into the page.

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
    outerHTML
      ↓
    DOM

Determine whether the `message` parameter can be interpreted as HTML.

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
Look for where the `message` variable is used.
Pay special attention to:
    outerHTML

Ask yourself:
> What happens when an HTML string is assigned to `outerHTML`?

---

### Hint 4
Before trying to demonstrate JavaScript execution, test with harmless HTML.
For example:
    <b>Test</b>

If `Test` becomes bold, you have confirmed that your input is being interpreted as HTML.

---

## Goal
Demonstrate that attacker-controlled input from the URL can reach an HTML-parsing DOM sink.
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
- What `outerHTML` does
- How `outerHTML` can replace an existing DOM element
- What a DOM XSS sink is
- How URL parameters can become DOM data
- How attacker-controlled data can reach an HTML-parsing API
- Why constructing HTML with untrusted input is dangerous
- The difference between HTML insertion and safe text insertion
- How to trace a DOM XSS source-to-sink data flow

---

## Investigation Methodology
When investigating this vulnerability, follow the data:
1. Identify the source.
2. Identify the URL parameter.
3. Track the value through the JavaScript variables.
4. Find the DOM operation that consumes the value.
5. Determine whether the DOM operation parses HTML.
6. Test with harmless HTML first.
7. Demonstrate the vulnerability with a local proof of concept.
8. Identify a safer way to handle the data.

---

## Concepts Covered
- DOM XSS
- `window.location.search`
- `URLSearchParams`
- `outerHTML`
- DOM manipulation
- HTML parsing
- DOM replacement
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
**DOM XSS via `outerHTML`**

---

## Status
**Unsolved**

---

## Author
****