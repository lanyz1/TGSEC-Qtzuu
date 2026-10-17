# Lab 13 — DOM XSS via location.hash and innerHTML

## 🎯 Objective
Learn how a **DOM-based Cross-Site Scripting (DOM XSS)** vulnerability can occur when user-controlled data from the URL fragment is inserted into the DOM using `innerHTML`.

This lab focuses on understanding:
    Source → Transformation → Sink

---

## 🧩 Scenario
The application displays a search result based on information provided in the URL.
Unlike previous labs, the application does not receive the value through a Flask request.
Instead, JavaScript reads the value directly from the URL fragment.

For example:
    http://127.0.0.1:5000/#hello

The application processes this value in the browser and displays it on the page.
Your task is to investigate how this value flows through the JavaScript code and determine whether it can be interpreted as HTML.

---

## 🎯 Mission
Your mission is to:
1. Identify the source of the user-controlled data.
2. Find how the URL fragment is extracted.
3. Follow the value through the JavaScript code.
4. Identify any transformations applied to the value.
5. Identify the DOM sink.
6. Determine whether the value is treated as text or HTML.
7. Prove whether JavaScript execution is possible.

---

## 💡 Hints
### Hint 1
The input is not coming from:
    request.args

Look at the browser's URL.

---

### Hint 2
Search the JavaScript code for:
    window.location

Pay special attention to:
    location.hash

---

### Hint 3
The application performs a transformation on the value.
Look for:
    decodeURIComponent()

Ask yourself:
> Does decoding make untrusted input safe?

---

### Hint 4
Find where the processed value is eventually inserted into the page.
Look for:
    innerHTML

---

### Hint 5
In DOM XSS investigations, try to identify:
    Source
    ↓
    Data Flow
    ↓
    Sink

---

## 🔎 Investigation
Start by identifying the source of the data.
Then follow the value through each step:
    URL Fragment
        ↓
    JavaScript
        ↓
    Variable
        ↓
    Transformation
        ↓
    DOM API
        ↓
    Browser

Inspect the resulting DOM and determine how the browser interprets the supplied value.

---

## 🏁 Goal
Successfully demonstrate whether the URL fragment can be used to cause JavaScript execution through the vulnerable DOM operation.
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
- What `location.hash` represents
- How URL fragments can become DOM XSS sources
- How JavaScript reads values from the URL
- What `decodeURIComponent()` does
- Why decoding does not automatically make input safe
- How `innerHTML` handles strings
- How to identify DOM XSS sources
- How to identify DOM XSS sinks
- How to trace data from source to sink

---

## 🔬 Concepts Covered
- Cross-Site Scripting (XSS)
- DOM-based XSS
- DOM Sources
- DOM Sinks
- `window.location`
- `location.hash`
- `decodeURIComponent()`
- `innerHTML`
- HTML Parsing
- Client-Side JavaScript
- User-Controlled Input
- Data Flow Analysis

---

## 🔍 Questions to Answer
Before considering the lab complete, try to answer these questions:
1. Where does the user-controlled data originate?
2. Is the data processed by the server?
3. What does `location.hash` return?
4. What does `decodeURIComponent()` do?
5. Where does the value end up?
6. Is the final DOM operation treating the value as text or HTML?
7. What makes this vulnerability DOM-based?
8. What safer DOM API could be used for plain text?

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