# Lab 02 — Stored XSS

## 🎯 Objective
Find and exploit the Stored Cross-Site Scripting (Stored XSS) vulnerability in this application.
Your goal is to understand how user-controlled input is stored by the server and later rendered back to users.

---

## 🧩 Scenario
This application contains a simple message board.
Users can submit messages, and the application stores those messages and displays them on the page.
Your task is to investigate how the submitted message is handled and determine whether the application safely renders user-controlled content.

---

## 🔎 Your Mission
Find the vulnerable input and determine whether you can execute JavaScript through a stored message.
You should investigate:
- Where user input enters the application
- How the server processes the input
- Where the input is stored
- How the stored value is rendered
- Whether the browser interprets the stored value as HTML

---

## 💡 Hints
### Hint 1
Start by inspecting the message submission form.

### Hint 2
Follow the submitted value through the Flask application.

### Hint 3
Ask yourself:
"Is the user input only reflected in the current response, or is it stored somewhere?"

### Hint 4
Inspect the template carefully and look for places where user-controlled data is rendered.

---

## 🚩 Goal
Successfully demonstrate that JavaScript can be executed through a stored message.
Use a harmless proof of concept such as:
<script>alert(1)</script>
Do not use this lab to target external systems.

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
- What Stored XSS is
- How Stored XSS differs from Reflected XSS
- How to trace user-controlled input
- How server-side storage can affect XSS
- How to identify dangerous rendering
- Why output encoding matters

---

## ⚠️ Rules
Try to solve the Lab before looking at the solution.
The `solution/` directory contains a complete walkthrough.
This project is intentionally vulnerable and is provided for educational purposes.
Only perform security testing on systems you own or have explicit permission to test.

---

## Difficulty
🟢 Easy

## Category
Web Security / XSS

## Author
Created by  🕷️