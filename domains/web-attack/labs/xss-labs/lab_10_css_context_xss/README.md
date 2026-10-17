# Lab 10 — CSS Context XSS

## Objective
Learn how security issues can occur when user-controlled input is inserted directly into a CSS context.
In this lab, you will investigate how a value supplied by the user flows through the Flask application and is eventually inserted into an inline CSS declaration.

---

## Scenario
The application allows the user to enter a color.
For example:
    red

The application then uses the submitted value to change the color of some text.
The application expects a simple color value.
However, the user-controlled value is inserted directly into a CSS context without proper validation.
Your goal is to identify the vulnerability and determine whether the issue is CSS Injection, XSS, or both.

---

## Mission
Your mission is to:
1. Identify the source of the user-controlled input.
2. Trace the input through the Flask application.
3. Find where the value is inserted into the HTML.
4. Identify the exact security context.
5. Understand the role of the `safe` filter.
6. Determine whether the input can modify the intended CSS declaration.
7. Determine the actual security impact.
8. Understand the difference between CSS Injection and XSS.
9. Identify an appropriate mitigation.

---

## Hint
Start by looking at:
    request.args.get("color")
Then follow the `color` variable into the template.

Pay close attention to:
    style="color: {{ color | safe }};"

Ask yourself:
    What context is this value inside?
    What does | safe do?

    What does the browser do with the resulting style attribute?
    Is the application expecting arbitrary CSS or only a color?

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
    style Attribute
        ↓
    CSS Parser
        ↓
    Browser

Your goal is to determine whether the supplied value can escape its intended CSS value and influence additional CSS declarations.

---

## Important Concept
CSS is its own security context.
For example:
    style="color: red;"

contains a CSS declaration:
    color: red;

If user-controlled data is inserted into this declaration without proper validation, the user may be able to influence more than the intended color value.

---

## CSS Injection vs XSS
An important part of this lab is understanding that:
    CSS Injection ≠ JavaScript XSS

A CSS injection vulnerability does not automatically mean that JavaScript can be executed.
Modern browsers have restricted many historical techniques that attempted to use CSS to execute JavaScript.

Therefore, you should determine the actual impact of the injection rather than automatically calling every CSS injection an XSS vulnerability.

---

## Goal
Successfully identify the unsafe CSS context and determine how attacker-controlled input can influence the generated CSS.
Then explain:
    Source
    Context
    Sink
    Impact
    Mitigation

Use only harmless tests in this local educational lab.

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
- What a CSS Context is.
- What CSS Injection means.
- How user-controlled input can reach an inline `style` attribute.
- What the Jinja `safe` filter does.
- Why arbitrary CSS should not be trusted.
- The difference between CSS Injection and XSS.
- Why modern browsers behave differently from older browsers.
- Why input validation is important.
- Why allowlisting is useful when only specific CSS values are expected.
- How to determine the real impact of an injection vulnerability.

---

## Investigation Methodology
When analyzing an injection vulnerability, identify these components:

### 1. Source
Where does the attacker-controlled input come from?
Example:
    color query parameter

### 2. Context
Where is the data inserted?
Example:
    style="color: USER_INPUT;"

Therefore:
    CSS Context

### 3. Sink
What consumes the data?
In this lab, the browser's CSS parser processes the resulting `style` attribute.

### 4. Expected Value
Ask what the application actually expects.
In this lab:
    color

For example:
    red
    blue
    #ff0000

### 5. Actual Impact
Determine whether the attacker can:
    change only the intended property

or:
    inject additional CSS declarations

Then determine whether any further security impact exists.

---

## Important Questions
While solving the lab, ask yourself:
    Is the input limited to valid colors?
    Can additional CSS syntax be introduced?
    Does the browser accept the resulting CSS?
    Can the attacker control properties other than color?
    Does this result in JavaScript execution?
    If not, what is the actual impact?

These questions help distinguish vulnerability classification from assumptions about impact.

---

## Concepts Covered
- Cross-Site Scripting (XSS)
- CSS Injection
- CSS Context
- Inline CSS
- `style` Attribute
- CSS Properties
- User-Controlled Input
- Flask
- Jinja2
- `safe` Filter
- Output Encoding
- Input Validation
- Allowlisting
- Browser CSS Parser
- Source → Context → Sink
- Vulnerability Impact Analysis

---

## Rules
- Run the lab locally.
- Do not test against systems you do not own or have explicit permission to test.
- Use harmless proof-of-concept inputs.
- Do not use the lab techniques against real websites without authorization.
- The purpose of this lab is education and secure coding practice.

---

## Difficulty
**Medium 🟡**

---

## Category
**Injection / Cross-Site Scripting**

---

## Vulnerability Type
**CSS Injection**

---

## Status
🟢 Completed

---

## Author
****
Educational Security Lab — Local Environment Only.