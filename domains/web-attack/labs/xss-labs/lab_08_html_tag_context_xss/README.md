# Lab 08 — HTML Tag Context XSS

## Objective
Learn how Cross-Site Scripting (XSS) can occur when user-controlled input is inserted directly into the content of an HTML element.
In this lab, you will investigate how user input flows through the Flask application and is eventually rendered inside an HTML tag.

---

## Scenario
The application asks the user to enter their name and then displays a greeting.
For example:
    Hello, Nazanin

The application should treat the submitted name as plain text.
However, the application contains an unsafe template configuration that allows HTML supplied by the user to be interpreted by the browser.
Your goal is to identify the vulnerability and understand why it occurs.

---

## Mission
Your mission is to:
1. Identify the source of the user-controlled input.
2. Trace the input through the Flask application.
3. Find where the value is inserted into the HTML.
4. Identify the exact HTML context.
5. Determine why the browser interprets the input as HTML.
6. Demonstrate the vulnerability using a harmless local proof of concept.
7. Explain how the vulnerability can be prevented.

---

## Hint
Start by looking at how the application retrieves the user's input:
    request.args.get("name")

Then follow the `name` variable into the template.
Pay close attention to this type of expression:
    {{ name | safe }}

Ask yourself:
    What does | safe do?
    Where is the value inserted?
    Is the value treated as text or HTML?

---

## Investigation
Follow the data flow:
    User Input
        ↓
    URL Parameter
        ↓
    Flask
        ↓
    Jinja Template
        ↓
    HTML Element
        ↓
    Browser

Your goal is to determine what happens when HTML markup is supplied instead of a normal name.

---

## Important Concept
HTML has different contexts where user-controlled data can be inserted.
In this lab, the input is placed between the opening and closing tags of an HTML element.

Example:
    <h2>
        USER_INPUT
    </h2>

This is an HTML Text Context.
If the application allows the browser to interpret the supplied value as HTML, attacker-controlled markup may become part of the page.

---

## Goal
Successfully demonstrate that user-controlled input can be interpreted as HTML/JavaScript because the application disables Jinja's normal escaping for the value.
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
- What HTML Context XSS is.
- How user-controlled data can become part of an HTML document.
- What Jinja autoescaping does.
- What the `safe` filter does.
- Why disabling automatic escaping can introduce XSS.
- How to trace data from source to sink.
- Why output encoding is important.
- The difference between displaying text and rendering HTML.

---

## Investigation Methodology
When analyzing an XSS vulnerability, identify these three things:

### 1. Source
Where does the attacker-controlled data come from?
Example:
    name query parameter

### 2. Context
Where is the data inserted?
Example:

    <h2>
        USER_INPUT
    </h2>

Therefore:

    HTML Text Context

### 3. Sink
What consumes or interprets the data?
In this lab, the browser parses the rendered HTML.

Understanding:
    Source → Context → Sink

is one of the most useful techniques for analyzing XSS vulnerabilities.

---

## Concepts Covered
- Cross-Site Scripting (XSS)
- HTML Context
- HTML Tags
- HTML Text Context
- User-Controlled Input
- Flask
- Jinja2
- Template Rendering
- Autoescaping
- `safe` Filter
- Output Encoding
- Source → Context → Sink

---

## Rules
- Run the lab locally.
- Do not test against systems you do not own or have explicit permission to test.
- Use harmless proof-of-concept payloads.
- Do not use the lab techniques against real websites without authorization.
- The purpose of this lab is education and secure coding practice.

---

## Difficulty
**Medium 🟡**

---

## Category
**Cross-Site Scripting (XSS)**

---

## Vulnerability Type
**HTML Context XSS**

---

## Status
🟢 Completed

---

## Author
****
Educational XSS Lab — Local Environment Only.