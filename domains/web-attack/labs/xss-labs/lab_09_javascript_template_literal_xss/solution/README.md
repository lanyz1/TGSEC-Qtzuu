# Lab 09 — JavaScript Template Literal XSS | Solution

## Vulnerability
The application contains a Cross-Site Scripting (XSS) vulnerability inside a JavaScript template literal.
User-controlled input is inserted directly into an inline JavaScript string using Jinja's `safe` filter.

Because the value is placed inside executable JavaScript code without proper JavaScript-context escaping, an attacker can potentially break out of the intended string context and inject JavaScript.

---

## Source
The attacker-controlled input comes from the `message` query parameter.
The application retrieves the value using:
    message = request.args.get("message", "")

The value is then passed to the template:
    return render_template("index.html", message=message)

### Data Flow
    URL Parameter
         ↓
    request.args.get("message")
         ↓
    Flask
         ↓
    Jinja Template
         ↓
    JavaScript Template Literal
         ↓
    Browser

---

## Vulnerable Code
The vulnerable code is:
    const message = `{{ message | safe }}`;

The user-controlled value is inserted directly into a JavaScript template literal.
The `| safe` filter disables Jinja's normal HTML escaping.
This is dangerous because the value is not being safely encoded for the JavaScript context.

---

## Context
The input is placed inside a JavaScript template literal:
    const message = `USER_INPUT`;

A JavaScript template literal is a string surrounded by backticks:
    `Hello World`

It can also contain JavaScript expressions using `${...}`.

Because the application places untrusted data directly inside this JavaScript context, the input must be handled according to JavaScript-context rules.

---

## Sink
The final execution context is the inline JavaScript block:
    <script>
        const message = `{{ message | safe }}`;
    </script>

The important security boundary is the JavaScript parser.

The later use of:
    document.getElementById("result").textContent = message;

is not the vulnerable sink.
`textContent` safely treats the resulting value as text.
The vulnerability happens earlier, when attacker-controlled data is inserted into executable JavaScript.

---

## Proof of Concept
A harmless proof of concept for this local educational lab is:
    ${alert(1)}

When placed inside the template literal, the browser interprets `${...}` as a JavaScript expression.
The important lesson is that JavaScript template literals are not simply ordinary text strings.
They have their own syntax and execution behavior.

---

## Why `${...}` Matters
A normal JavaScript string might look like:
    "Hello World"

A template literal uses backticks:
    `Hello World`

Template literals support expressions:
    `Hello ${name}`

The expression inside `${...}` is evaluated as JavaScript.

Therefore, if untrusted input is inserted directly into a template literal, special template-literal syntax can become security-sensitive.

---

## Root Cause
The root cause is the direct insertion of untrusted input into executable JavaScript:
    const message = `{{ message | safe }}`;

There are two important problems:
1. The value is inserted inside JavaScript code.
2. The `safe` filter prevents Jinja from escaping the value.

The application therefore mixes untrusted data with executable JavaScript.

---

## Why `| safe` Is Dangerous
Normally, Jinja performs HTML escaping.
For example:
    {{ message }}

is automatically escaped according to Jinja's HTML template behavior.

But:
    {{ message | safe }}

marks the value as safe HTML and disables the normal escaping behavior.
This is especially dangerous when the value is inserted into a JavaScript context.
HTML escaping and JavaScript escaping are not the same thing.

---

## Important Context Rule
One of the most important lessons from this lab is:
    HTML Context ≠ JavaScript Context

Encoding appropriate for HTML does not automatically make data safe inside JavaScript.
The output handling must match the context where the data is inserted.

For JavaScript code, the safest approach is generally to avoid constructing executable JavaScript using string interpolation from untrusted input.

---

## Mitigation
### 1. Avoid Putting User Input Directly Inside JavaScript
Instead of:
    const message = `{{ message | safe }}`;

keep the untrusted data outside executable JavaScript whenever possible.
For example, use a normal HTML element to hold the data and read it as text.

---

### 2. Use `textContent` for Text
A safer pattern is:
    <div id="message" data-message="{{ message }}"></div>

Then retrieve the value using JavaScript and treat it as data rather than executable code.
Another simple approach is to render the message directly as escaped HTML text when JavaScript is not necessary.

---

### 3. Use JSON Serialization When Data Must Be Passed to JavaScript
When server-side data genuinely needs to be embedded into JavaScript, use a framework-supported JSON serialization mechanism rather than manually inserting the value into a JavaScript string.

For Flask/Jinja applications, the `tojson` filter can be used for safely serializing data for JavaScript contexts.

Example:
    const message = {{ message | tojson }};

This allows the value to be represented as JavaScript data rather than manually constructing a JavaScript string.

---

## Secure Example
A safer Jinja/JavaScript pattern is:
    <script>
        const message = {{ message | tojson }};

        document.getElementById("result").textContent = message;
    </script>

The important difference is that the value is serialized as JavaScript data instead of being blindly concatenated into a JavaScript template literal.

---

## Investigation Methodology
When analyzing JavaScript-context XSS, follow these steps.

### 1. Identify the Source
Find where the user-controlled value enters the application:
    request.args.get("message")

### 2. Trace the Data
Follow the value from Flask to the template:
    message
      ↓
    render_template()
      ↓
    {{ message | safe }}

### 3. Identify the Context
Determine where the value is inserted:
    const message = `USER_INPUT`;

The context is:
    JavaScript Template Literal

### 4. Identify the Parser
Ask which parser will interpret the data.
In this case:
    JavaScript Parser

### 5. Check the Encoding
Determine whether the value is properly encoded for JavaScript.
The use of:
    | safe

is a major warning sign.

### 6. Check the Final Sink
Determine what happens after the value is assigned.
In this lab:
    textContent

is not the vulnerable part.

The dangerous operation occurs when the browser parses the inline JavaScript containing the attacker-controlled value.

---

## Vulnerability Chain
    Attacker-Controlled Input
            ↓
    request.args.get("message")
            ↓
          Flask
            ↓
      Jinja Template
            ↓
    {{ message | safe }}
            ↓
    JavaScript Template Literal
            ↓
      JavaScript Parser
            ↓
    JavaScript Execution

---

## Key Takeaways
- JavaScript contexts require JavaScript-aware output handling.
- Template literals use backticks.
- Template literals support `${...}` expressions.
- User input should never be blindly inserted into executable JavaScript.
- `| safe` disables Jinja's normal escaping.
- HTML escaping and JavaScript escaping are different concepts.
- `textContent` is not the vulnerable part of this lab.
- The vulnerability occurs when untrusted data enters executable JavaScript.
- `tojson` is a safer way to pass server-side data into JavaScript.
- Always identify the exact context before choosing a mitigation.

---

## Lab Summary
| Property | Value |
|---|---|
| Vulnerability | Cross-Site Scripting |
| Type | JavaScript Context XSS |
| Subtype | Template Literal XSS |
| Source | `message` query parameter |
| Context | JavaScript Template Literal |
| Parser | JavaScript |
| Dangerous Behavior | Untrusted input inserted into executable JavaScript |
| Jinja Filter | `safe` |
| Safe Output API | `textContent` |
| Recommended Serialization | `tojson` |
| Difficulty | Medium |
| Environment |Local |
| Status | Solved |

---

## What This Lab Teaches
This lab demonstrates that XSS is highly dependent on context.
The same user input can behave differently depending on whether it is placed inside:
    HTML
    HTML Attribute
    URL
    JavaScript
    JavaScript String
    JavaScript Template Literal

In this lab, the important question is:
    "What happens when untrusted input becomes part of JavaScript source code?"

Understanding this distinction is essential for finding and preventing JavaScript-context XSS vulnerabilities.

---

## Author
****
Educational purpose only.
Run this lab locally and never use these techniques against systems without explicit authorization.