# Lab 04 — XSS in HTML Attributes

## 🎯 Objective
Find and understand the HTML Attribute-based Cross-Site Scripting vulnerability in this application.
Your goal is to analyze how user-controlled input is placed inside an HTML attribute and determine whether it is possible to escape the existing context.

---

## 🧩 Scenario
This application displays a username value inside an HTML input field.
The value comes from a user-controlled URL parameter and is inserted into an HTML attribute.
Your task is to investigate how the browser interprets this input and identify whether the application safely handles the provided value.

---

## 🔎 Your Mission
Find:
1. Where the user-controlled input enters the application.
2. How the input is transferred to the template.
3. Which HTML context contains the input.
4. Whether the input can break out of the current context.
5. A harmless proof of concept demonstrating the vulnerability.

---

## 💡 Hints
### Hint 1
Start by looking at how the application receives the `name` parameter.

### Hint 2
Follow the value from:
URL
↓
Flask
↓
Template
↓
HTML

### Hint 3
Pay attention to where the input is placed.

Is it inside:
HTML Body?

or:
HTML Attribute?

### Hint 4
Remember that XSS depends on context.
The same input does not behave the same way everywhere.

---

## 🚩 Goal
Demonstrate that user-controlled input can affect the structure of an HTML attribute.
Use only a harmless proof of concept inside this local lab environment.

---

## 🛠️ Running the Lab
Make sure Python is installed.
Install dependencies:
pip install -r requirements.txt

Run the application:
python app.py

Open:
http://127.0.0.1:5000

---

## 🧠 What You Should Learn
After completing this Lab, you should understand:
- What HTML Attribute XSS is
- Why XSS is context-dependent
- The difference between HTML body and attribute contexts
- How browsers parse HTML attributes
- Why escaping is important
- How output encoding prevents XSS

---

## 🔬 Investigation Method
When analyzing XSS vulnerabilities, follow this process:

Source

↓

Data Flow

↓

Context Identification

↓

Dangerous Location

↓

Browser Interpretation

↓

Impact

↓

Mitigation

---

## 📚 Concepts Covered
- Cross-Site Scripting (XSS)
- HTML Attribute Context
- Context Breaking
- Output Encoding
- Browser HTML Parsing
- Secure Rendering

---

## ⚠️ Rules
Try to solve the Lab before opening the solution.
The complete walkthrough is available inside:
solution/README.md
This application is intentionally vulnerable and created for educational purposes.
Only test security vulnerabilities on systems you own or have explicit permission to test.

---

## Difficulty
🟡 Medium

## Category
Web Security / XSS

## Vulnerability Type
HTML Attribute XSS

## Author
