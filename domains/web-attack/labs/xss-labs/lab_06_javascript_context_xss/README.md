# Lab 06 — XSS in JavaScript Context

## 🎯 Objective
Find and understand the Cross-Site Scripting vulnerability inside a JavaScript context.
Your goal is to identify how user-controlled input is inserted into a JavaScript string and determine whether the input can affect the JavaScript code executed by the browser.

---

## 🧩 Scenario
This application receives a username through a URL parameter.
The username is then inserted into a JavaScript string inside a `<script>` block.
Your task is to investigate how the browser interprets this value and determine whether the JavaScript context can be escaped.

---

## 🔎 Your Mission
Find:
1. Where the user-controlled input enters the application.
2. How the input reaches the template.
3. Which context contains the input.
4. What characters define the JavaScript string boundary.
5. Whether the input can change the surrounding JavaScript syntax.
6. A harmless proof of concept demonstrating JavaScript execution.

---

## 💡 Hints
### Hint 1
Start by inspecting how the `username` parameter is received by Flask.

### Hint 2
Follow the value from:
URL
↓
Flask
↓
Template
↓
Tag <script>
↓
JavaScript

### Hint 3
Look carefully at the JavaScript code that contains the username.
Ask yourself:
"Is the username being treated as data or as part of JavaScript source code?"

### Hint 4
Pay attention to the quotes surrounding the username.
What defines the beginning and end of the JavaScript string?

### Hint 5
Think about what happens if user-controlled input can affect those string boundaries.

---

## 🚩 Goal
Demonstrate that the user-controlled username can influence JavaScript execution.

Use a harmless proof of concept such as:
alert(1)

Only test the vulnerability inside this local educational lab.

---

## 🛠️ Running the Lab
Make sure Python is installed.

Install the dependencies:
pip install -r requirements.txt

Start the application:
python app.py

Then open:
http://127.0.0.1:5000

---

## 🧠 What You Should Learn
After completing this Lab, you should understand:
- What JavaScript Context XSS is
- How XSS can occur inside a `<script>` block
- The difference between HTML and JavaScript contexts
- How JavaScript string boundaries work
- Why context-specific encoding is important
- Why untrusted data should not be inserted directly into JavaScript source code
- How to identify the correct parser for a given XSS context

---

## 🔬 Investigation Method
When analyzing JavaScript-context XSS, follow this process:
Source
  ↓
User-Controlled Input
  ↓
JavaScript Context
  ↓
String Boundary
  ↓
JavaScript Syntax
  ↓
Browser Execution
  ↓
Impact
  ↓
Mitigation

---

## 📚 Concepts Covered
- Cross-Site Scripting (XSS)
- JavaScript Context
- JavaScript Strings
- String Boundaries
- Inline JavaScript
- Context-Specific Encoding
- Browser Parsing
- Secure Data Handling

---

## ⚠️ Rules
Try to solve the Lab before opening the solution.
The complete walkthrough is available inside:
solution/README.md

This application is intentionally vulnerable and is provided for educational purposes.
Only perform security testing on systems you own or have explicit permission to test.

---

## Difficulty
🟡 Medium

## Category
Web Security / XSS

## Vulnerability Type
JavaScript Context XSS

## Author
