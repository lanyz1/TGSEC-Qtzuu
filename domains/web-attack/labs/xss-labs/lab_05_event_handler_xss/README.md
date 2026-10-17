# Lab 05 — Event Handler XSS

## 🎯 Objective
Find and understand the Cross-Site Scripting vulnerability inside an HTML event handler.
Your goal is to identify how user-controlled input is inserted into an `onclick` attribute and determine whether it can affect the JavaScript executed by the browser.

---

## 🧩 Scenario
This application displays a message through a button.
The message comes from a user-controlled URL parameter and is inserted into an HTML event handler.
Your task is to analyze the application and determine whether the input can escape its current JavaScript context.

---

## 🔎 Your Mission
Find:
1. Where the user-controlled input enters the application.
2. How the input reaches the HTML template.
3. Which HTML context contains the input.
4. Which JavaScript context contains the input.
5. Whether the input can modify the existing JavaScript.
6. A harmless proof of concept demonstrating JavaScript execution.

---

## 💡 Hints
### Hint 1
Start by looking at how the `message` parameter is received by Flask.

### Hint 2
Follow the value from:
URL
↓
Flask
↓
Template
↓
HTML
↓
JavaScript

### Hint 3
Look carefully at the `onclick` attribute.
Ask yourself:
"What does the browser do with the contents of an onclick attribute?"

### Hint 4
The input is not simply inside normal HTML text.
It is part of JavaScript code.

### Hint 5
Look at the quotes surrounding the user-controlled value.
Can the input affect the boundaries of the JavaScript string?

---

## 🚩 Goal
Demonstrate that the user-controlled input can influence JavaScript execution inside the event handler.
Use a harmless proof of concept such as:
alert(1)
Only test the vulnerability inside this local lab.

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
- What Event Handler XSS is
- Why `onclick` is a JavaScript execution context
- The difference between HTML and JavaScript contexts
- How quote boundaries affect JavaScript strings
- Why XSS payloads are context-dependent
- Why inline JavaScript can introduce security risks
- Why user-controlled data should not become executable code

---

## 🔬 Investigation Method
When analyzing an Event Handler XSS vulnerability, follow this process:
Source
  ↓
User-Controlled Input
  ↓
HTML Attribute
  ↓
JavaScript Context
  ↓
String Boundary
  ↓
JavaScript Execution
  ↓
Impact
  ↓
Mitigation

---

## 📚 Concepts Covered
- Cross-Site Scripting (XSS)
- Event Handler XSS
- HTML Attribute Context
- JavaScript Context
- JavaScript String Boundaries
- Inline Event Handlers
- Output Encoding
- Secure DOM Event Handling

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
Event Handler XSS

## Author
