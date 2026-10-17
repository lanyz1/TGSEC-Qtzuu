# Lab 18 — DOM XSS via `insertAdjacentHTML()`

## Objective
Learn how DOM XSS can occur when user-controlled data is passed to the `insertAdjacentHTML()` method.
This lab introduces a new DOM XSS sink and helps you understand how HTML can be dynamically inserted into the page.

---

## Scenario
The application reads a `message` parameter from the URL.
The value is then inserted into the page using:
    insertAdjacentHTML()

The developer assumes that the message is just normal text.
Your task is to investigate how the data flows through the application and determine whether the input can be interpreted as HTML.

---

## Mission
Find the complete data flow:
    URL
      ↓
    URLSearchParams
      ↓
    message
      ↓
    insertAdjacentHTML()
      ↓
    DOM

Then determine whether you can control the HTML inserted into the page.

---

## Hints
### Hint 1
Look at how the application reads the URL:
    new URLSearchParams(window.location.search)

---

### Hint 2
Find where the `message` variable is used.

---

### Hint 3
Pay special attention to:
    insertAdjacentHTML()

Ask yourself:
> Does this method treat the provided string as plain text or HTML?

---

### Hint 4
Before testing JavaScript execution, try inserting harmless HTML.
For example:
    <b>Hello</b>

If the word becomes bold, you have confirmed that the input is being interpreted as HTML.

---

## Goal
Demonstrate that attacker-controlled input can be interpreted as HTML by the browser.
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
- What `insertAdjacentHTML()` does
- What a DOM XSS sink is
- How URL parameters can become DOM data
- How user-controlled data reaches a dangerous DOM API
- Why HTML insertion APIs require careful handling
- The difference between inserting text and inserting HTML
- How to trace a DOM XSS data flow

---

## Investigation Methodology
When investigating this vulnerability, follow the data:
1. Identify the source.
2. Identify the transformation.
3. Identify the variable receiving the data.
4. Identify the DOM sink.
5. Determine whether the sink interprets the input as HTML.
6. Test with harmless HTML first.
7. Only then demonstrate the vulnerability with a local proof of concept.

---

## Concepts Covered
- DOM XSS
- `window.location.search`
- `URLSearchParams`
- `insertAdjacentHTML()`
- DOM manipulation
- HTML parsing
- Source-to-sink data flow
- Dangerous DOM APIs

---

## Rules
- Run the lab locally.
- Do not test the payloads against websites you do not own.
- Use harmless proof-of-concepts.
- Focus on understanding the vulnerability rather than simply finding a payload.

---

## Difficulty
**Medium**

---

## Category
**DOM XSS**

---

## Vulnerability Type
**DOM XSS via `insertAdjacentHTML()`**

---

## Status
**Unsolved**

---

## Author
****