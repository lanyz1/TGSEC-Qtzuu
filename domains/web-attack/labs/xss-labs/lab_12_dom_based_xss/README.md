# Lab 12 — DOM XSS via document.write()
## 🎯 Objective
Learn how a **DOM-based Cross-Site Scripting (DOM XSS)** vulnerability can occur when user-controlled data from the URL is passed to `document.write()`.

This lab focuses on understanding the relationship between:
    Source → Data Flow → Sink

---

## 🧩 Scenario
The application displays a personalized greeting based on a `name` parameter in the URL.
For example:
    http://127.0.0.1:5000/?name=Guest

The application reads the value directly in the browser using JavaScript.
Your task is to investigate how this value flows through the application and determine whether it can be interpreted as HTML.

---

## 🎯 Mission
Your mission is to:
1. Identify the source of the user-controlled data.
2. Find how the `name` parameter is extracted.
3. Follow the value through the JavaScript code.
4. Identify the DOM sink.
5. Determine how the browser interprets the supplied value.
6. Prove whether JavaScript execution is possible.

---

## 💡 Hints
### Hint 1
The input does not come from a Flask request.
Look at the browser's current URL.

---

### Hint 2
Search the JavaScript code for:
    window.location

Then investigate what happens to the value afterward.

---

### Hint 3
The application uses:
    URLSearchParams

Find out what it does with the `name` parameter.

---

### Hint 4
Look carefully at the function that eventually writes the greeting to the page.
Ask yourself:
> Is the value being treated as plain text or HTML?

---

### Hint 5
In DOM XSS investigations, always look for the relationship between:
    Source

and:
    Sink

---

## 🔎 Investigation
Start by identifying the source of the input.
Then follow the value step by step:
    URL
     ↓
    JavaScript
     ↓
    Variable
     ↓
    DOM API
     ↓
    Browser

Inspect the generated DOM and determine how the browser processes the supplied value.

---

## 🏁 Goal
Successfully demonstrate whether the `name` parameter can be used to cause JavaScript execution through the vulnerable DOM operation.
Use only a harmless proof of concept in this local educational lab.

---

## ▶️ Running the Lab
Install the required dependency:
    pip install -r requirements.txt

Run the application:
    python app.py

Then open:
    http://127.0.0.1:5000

---

## 🧠 What You Should Learn
By completing this lab, you should understand:
- What DOM-based XSS is
- What a DOM XSS source is
- What a DOM XSS sink is
- How URL parameters can become attacker-controlled data
- How `window.location.search` works
- How `URLSearchParams` extracts query parameters
- Why certain DOM APIs can be dangerous
- How to trace data from source to sink
- How the browser interprets dynamically generated HTML

---

## 🔬 Concepts Covered
- Cross-Site Scripting (XSS)
- DOM-based XSS
- DOM Sources
- DOM Sinks
- `window.location.search`
- `URLSearchParams`
- `document.write()`
- HTML Parsing
- Client-Side JavaScript
- User-Controlled Input
- Data Flow Analysis

---

## ⚠️ Rules
- This lab is intended for local educational use.
- Test only against the provided application.
- Use harmless payloads.
- Do not test against systems you do not own or have explicit permission to test.

---

## 📊 Difficulty
Medium

---

## 🏷️ Category
Cross-Site Scripting

---

## 🧪 Vulnerability Type
DOM-based XSS

---

## 📌 Status
🟢 Completed

---

## 👤 Author

Educational XSS laboratory for security learning and practice.