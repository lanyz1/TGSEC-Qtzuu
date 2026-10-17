# 🧪 Lab 01 — Reflected XSS

**Difficulty:** 🟢 Easy

## 🎯 Objective

Find and demonstrate a Reflected Cross-Site Scripting (XSS) vulnerability in the search functionality.
Your goal is to make the browser execute a harmless JavaScript proof of concept.

## 🧩 Scenario

You are testing a simple product search application.
It accepts a search query from the user and displays it on the results page.
Investigate how the user's input flows through the application and determine whether it can be interpreted as executable HTML/JavaScript.

## 🛠️ Technology

Python · Flask · Jinja2 · HTML

## 🚀 Setup

1. Install the dependencies (from this directory):

```bash
pip install -r requirements.txt
```

2. Start the application:

```bash
python app.py
```

3. Open `http://127.0.0.1:5000` in your browser.

## 🎯 Target

The target functionality is the search parameter:

```
GET /?q=YOUR_INPUT
```

For example: `http://127.0.0.1:5000/?q=hello`

Try different values and observe how the application handles them.

## 🧪 Challenge

Determine whether the `q` parameter can be used to execute JavaScript in the browser.
Use a harmless JavaScript proof of concept that shows an `alert(1)` dialog.

## ✅ Success Condition

The lab is solved when `alert(1)` is executed by the browser.

## 🔍 Investigation

Before looking at the solution, try to answer:

- Where does the user-controlled input enter the application?
- How does Flask retrieve the input?
- Where is the input sent after it is retrieved?
- Where is the input reflected in the HTML?
- In which HTML context is the input placed?
- Is the input escaped or rendered as HTML?
- Why does the browser execute the supplied JavaScript?

## 💡 Hints

**Hint 1** — Start with the `q` parameter. Where is this value retrieved in `app.py`?

**Hint 2** — Look for `request.args.get(...)`. What happens to the returned value?

**Hint 3** — Follow the value into `templates/index.html`. Find where `query` is rendered.

**Hint 4** — Think about the difference between plain text and HTML markup. How does the template engine decide whether input is treated as text or HTML?

**Hint 5** — A harmless payload you can try:

```html
<script>alert(1)</script>
```

## 🧠 Learning Objectives

- What Reflected XSS is
- How user-controlled input enters a web application
- Source and data flow
- HTML body context
- Jinja2 auto-escaping
- Unsafe HTML rendering
- Basic XSS exploitation and mitigation

## 📌 Questions to Think About

1. Why is this vulnerability called Reflected XSS?
2. What is the source of the user-controlled input?
3. Where is the input reflected?
4. What is the XSS context?
5. Why does the browser execute the payload?
6. How could a developer prevent this vulnerability?

## ⚠️ Disclaimer

This application is intentionally vulnerable and is designed for educational purposes, local security testing, and authorized security research.
Run it locally and never deploy it to a public production environment.
Only test systems that you own or have explicit permission to test.

## 🏁 Stuck?

Try to solve the lab yourself first, identifying:

```
Source → Data Flow → Context → Sink → Browser Interpretation
```

Then check the official solution: [Solution](solution/README.md)

## 🚀 Next Lab

**Lab 02 — Reflected XSS in HTML Attribute Context**
The next lab introduces a different context and requires you to think differently about how the browser interprets user-controlled input.

---

**Category:** Web Security / XSS
**Author:** Created by  🕷️