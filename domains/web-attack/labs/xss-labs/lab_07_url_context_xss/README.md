# Lab 07 — URL Context XSS

## Objective
Learn how Cross-Site Scripting (XSS) can occur when user-controlled input is placed inside an HTML URL context such as an `href` attribute.
In this lab, you will investigate how a URL provided by the user flows through the application and is eventually inserted into a link.

---

## Scenario
The application allows the user to enter a URL and generate a clickable link.
The application expects a normal URL such as:
    https://example.com

However, the application does not properly validate the URL scheme before placing the value inside the `href` attribute.
Your goal is to identify the vulnerability and understand how the browser interprets the supplied URL.

---

## Mission
Your mission is to:
1. Identify the source of the user-controlled input.
2. Trace the input through the Flask application.
3. Find where the value is inserted into the HTML.
4. Identify the exact security context.
5. Determine whether the URL scheme is properly validated.
6. Demonstrate the XSS vulnerability using a harmless local proof of concept.
7. Explain why the browser executes the supplied value.

---

## Hint
Pay close attention to:
    request.args.get("url")

Then search for where the `url` variable is used inside the template.

Ask yourself:
    Where is my input placed?
    Is it inside normal HTML text?
    Is it inside an HTML attribute?
    What type of attribute is it?
    Does the application validate the URL scheme?

---

## Investigation
Follow the data flow:
    User Input
        ↓
    URL Parameter
        ↓
    Flask
        ↓
    Template
        ↓
    href attribute
        ↓
    Browser

The key is to understand what happens when attacker-controlled data reaches a URL-bearing HTML attribute.

---

## Important Concept
Not every value that looks like a URL is necessarily an HTTP or HTTPS URL.
For example, browsers support different URL schemes.
Examples include:
    http://
    https://
    javascript:

The application should not blindly trust a user-provided URL.

---

## Goal
Successfully demonstrate that the application allows attacker-controlled URL input to reach the `href` attribute in an unsafe way.
Use only a harmless proof of concept in this local educational lab.

---

## Running the Lab
Install the dependencies:
    pip install -r requirements.txt

Run the application:
    python app.py

Then open the local application in your browser.
The lab is designed to run locally.

---

## What You Should Learn
After completing this lab, you should understand:
- What URL Context XSS is.
- How attacker-controlled data can reach an `href` attribute.
- Why URL scheme validation is important.
- The difference between HTML escaping and URL validation.
- Why `| safe` can be dangerous with untrusted input.
- How to trace data from source to sink.
- How browsers interpret different URL schemes.
- Why context-aware output handling matters.

---

## Investigation Methodology
When testing for XSS, always identify these three things:

### 1. Source
Where does the attacker-controlled data come from?
Example:
    URL parameter

### 2. Context
Where is the data inserted?
Example:
    href="USER_INPUT"

### 3. Sink
What HTML or JavaScript feature consumes the data?
Example:
    <a href="...">

Understanding:
    Source → Context → Sink

is one of the most important techniques for analyzing XSS vulnerabilities.

---

## Concepts Covered
- Cross-Site Scripting (XSS)
- URL Context
- HTML Attributes
- `href`
- URL Schemes
- User-Controlled Input
- Flask
- Jinja2
- Template Rendering
- Output Encoding
- Input Validation
- Source → Context → Sink

---

## Rules
- Run the lab locally.
- Do not test against systems you do not own or have explicit permission to test.
- Use harmless proof-of-concept payloads.
- The purpose of this lab is education and secure coding practice.

---

## Difficulty
**Medium 🟡**

---

## Category
**Cross-Site Scripting (XSS)**

---

## Vulnerability Type
**URL Context XSS**

---

## Status
🟢 Completed

---

## Author
****
Educational XSS Lab — Local Environment Only.