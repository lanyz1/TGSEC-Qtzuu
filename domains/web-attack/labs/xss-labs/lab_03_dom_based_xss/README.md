# Lab 03 — DOM-based XSS

## 🎯 Objective
Find the DOM-based Cross-Site Scripting vulnerability in this application.
Your goal is to identify how user-controlled data travels from the URL into the DOM and determine whether it can lead to JavaScript execution.

---

## 🧩 Scenario
This application reads information from the URL and displays it on the page using client-side JavaScript.
Unlike the previous labs, the vulnerability in this Lab does not require the server to reflect or store the input.
Your task is to investigate the JavaScript code and follow the data from its source to its final destination.

---

## 🔎 Your Mission
Find:
1. The source of the user-controlled input.
2. How the input is processed.
3. The DOM element where the input is inserted.
4. The dangerous DOM sink.
5. A harmless proof of concept demonstrating JavaScript execution.

---

## 💡 Hints
### Hint 1
Start by inspecting the JavaScript code at the bottom of the page.

### Hint 2
Look for data being read from the current URL.

### Hint 3
Ask yourself:
"Can a user control the value returned from the URL?"

### Hint 4
Follow that value until it reaches the DOM.

### Hint 5
Pay close attention to APIs that insert content into an HTML document.

---

## 🚩 Goal
Successfully demonstrate DOM-based XSS using a harmless proof of concept.
For example:
<script>alert(1)</script>
The vulnerability should be demonstrated only inside this local lab.

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
- What DOM-based XSS is
- How DOM XSS differs from Reflected XSS
- How client-side JavaScript can introduce XSS
- What a DOM Source is
- What a DOM Sink is
- Why innerHTML can be dangerous
- Why textContent is safer for plain text
- How to trace data from Source to Sink

---

## 🔬 Investigation Method
When analyzing DOM XSS, follow this process:
Source
  ↓
User-Controlled Data
  ↓
JavaScript Processing
  ↓
DOM Sink
  ↓
Browser Interpretation

Try to identify every step before looking at the solution.

---

## ⚠️ Rules
Try to solve the Lab before opening the solution.
The solution is available inside:
solution/README.md
This project contains intentionally vulnerable code and is designed for educational purposes.
Only perform security testing on systems you own or have explicit permission to test.

---

## Difficulty
🟢 Easy

## Category
Web Security / XSS

## Vulnerability Type
DOM-based Cross-Site Scripting

## Author
