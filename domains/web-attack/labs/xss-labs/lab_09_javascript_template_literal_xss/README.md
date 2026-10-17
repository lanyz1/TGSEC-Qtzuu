# Lab 09 — JavaScript Template Literal XSS

## Objective
Learn how Cross-Site Scripting (XSS) can occur when user-controlled input is inserted directly into a JavaScript Template Literal.
In this lab, you will investigate how user input flows from a URL parameter into JavaScript code and understand why Template Literals require special attention.

---

## Scenario
The application allows the user to enter a message.
The message is then passed from the Flask application to the HTML template and inserted into a JavaScript Template Literal.

The application expects normal text such as:
    Hello World

However, the input is inserted directly into JavaScript code without proper JavaScript-context handling.
Your goal is to identify the vulnerability and understand how JavaScript interprets the supplied input.

---

## Mission
Your mission is to:
1. Identify the source of the user-controlled input.
2. Trace the input through the Flask application.
3. Find where the value is inserted into JavaScript.
4. Identify the exact JavaScript context.
5. Understand how JavaScript Template Literals work.
6. Determine the role of `${...}` inside a Template Literal.
7. Demonstrate the vulnerability using a harmless local proof of concept.
8. Identify whether `textContent` is the vulnerable part.
9. Explain how the vulnerability can be prevented.

---

## Hint
Start by looking at how the application retrieves the user's input:
    request.args.get("message")
Then follow the `message` variable into the HTML template.

Pay close attention to:
    const message = `{{ message | safe }}`;

Ask yourself:
    What type of JavaScript string is this?
    What does `| safe` do?

    What special syntax does a Template Literal support?
    Where does the browser parse the user-controlled value?

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
    JavaScript Template Literal
        ↓
    JavaScript Parser
        ↓
    Browser

Your goal is to understand what happens when user-controlled input becomes part of JavaScript source code.

---

## Important Concept
JavaScript has several types of strings.
Traditional strings can use:
    "Hello World"

or:
    'Hello World'

Template Literals use backticks:
    `Hello World`

Template Literals also support JavaScript expressions using:
    ${...}

For example:
    `Hello ${name}`

The expression inside `${...}` is evaluated by JavaScript.
This makes Template Literals an important context to understand when analyzing XSS.

---

## Goal
Successfully demonstrate that attacker-controlled input can reach a JavaScript Template Literal in an unsafe way.
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
- What JavaScript Template Literals are.
- How Template Literals differ from normal JavaScript strings.
- What `${...}` means inside a Template Literal.
- How user-controlled data can enter JavaScript source code.
- Why JavaScript context requires JavaScript-aware output handling.
- What the Jinja `safe` filter does.
- Why HTML escaping and JavaScript escaping are different.
- Why `textContent` is not the vulnerable part of this lab.
- How to trace data from source to execution context.
- How JSON serialization can be used when passing data to JavaScript.

---

## Investigation Methodology
When analyzing XSS inside JavaScript, identify these components:

### 1. Source
Where does the attacker-controlled data come from?
Example:
    message query parameter

### 2. Context
Where is the data inserted?
Example:
    const message = `USER_INPUT`;

Therefore:
    JavaScript Template Literal Context

### 3. Parser
Which parser interprets the data?
In this lab:
    JavaScript Parser### 4. Sink

What happens after the value is interpreted?

The resulting value is assigned to:
    const message

and later displayed using:
    textContent

Remember that `textContent` safely treats the resulting value as text.
The important security boundary is where the user-controlled data enters JavaScript source code.

---

## Important Difference
Do not confuse:
    JavaScript Context

with:
    HTML Context

For example:
    <h1>{{ value }}</h1>

is an HTML context.

But:
    <script>
        const value = `{{ value }}`;
    </script>

is a JavaScript context.

The correct security mechanism depends on the context.

---

## Concepts Covered
- Cross-Site Scripting (XSS)
- JavaScript Context
- JavaScript Strings
- Template Literals
- Backticks
- `${...}` Expressions
- JavaScript Parser
- User-Controlled Input
- Flask
- Jinja2
- `safe` Filter
- `textContent`
- Output Encoding
- JSON Serialization
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
**JavaScript Template Literal XSS**

---

## Status
🟢 Completed

---

## Author
****
Educational XSS Lab — Local Environment Only.