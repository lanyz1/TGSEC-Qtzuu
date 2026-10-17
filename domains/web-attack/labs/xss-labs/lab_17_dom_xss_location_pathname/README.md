# Lab 17 — DOM XSS via `location.pathname`

## Objective
Learn how attacker-controlled data from `window.location.pathname` can lead to DOM-based XSS when it is inserted into the page using `innerHTML`.
This lab focuses on understanding URL paths as a DOM XSS source and tracing the data from the URL to the final DOM sink.

---

## Scenario
The application displays a welcome message based on the current URL path.
For example:
    http://127.0.0.1:5000/Nazanin

The application reads the path and uses it as the username.

The relevant JavaScript is:
    const path = window.location.pathname;
    const username = decodeURIComponent(path.substring(1)) || "Guest";
    document.getElementById("profile").innerHTML =
        "<p>Welcome, " + username + "!</p>";

Your goal is to investigate how the URL path is processed and determine whether you can make the browser interpret your input as HTML.

---

## Mission
Investigate the application and answer these questions:
1. Where does the username value come from?
2. What does `window.location.pathname` return?
3. Why is `substring(1)` used?
4. What does `decodeURIComponent()` do?
5. Where is the resulting value inserted?
6. What happens when HTML is placed in the URL path?
7. Can you demonstrate JavaScript execution in the local lab?

---

## Hints
### Hint 1
Start with:
    window.location.pathname

Try opening:
    http://127.0.0.1:5000/Nazanin

and observe the value of the pathname.

### Hint 2
Look at:
    path.substring(1)

Why is the first character removed?

Remember that a normal URL path begins with:
    /

### Hint 3
Pay attention to:
    decodeURIComponent()

Does decoding make input safe, or does it simply convert encoded characters back to their original form?

### Hint 4
Follow the value to:
    innerHTML

Ask yourself what happens when HTML is inserted into `innerHTML`.

### Hint 5
Before testing JavaScript, start with harmless HTML.
For example:
    <b>Test</b>

If the browser renders the text in bold, you have confirmed that the input is being interpreted as HTML.

### Hint 6
The important data flow is:
    location.pathname
        ↓
    substring()
        ↓
    decodeURIComponent()
        ↓
    username
        ↓
    innerHTML

Follow this chain carefully.

---

## Goal
Demonstrate that attacker-controlled data from the URL path can reach an HTML-sensitive DOM sink.
First confirm HTML interpretation with harmless HTML.
Then demonstrate JavaScript execution using a harmless local proof of concept.

---

## Running the Lab
From the `lab-17` directory:
    python app.py

Then open:
    http://127.0.0.1:5000/

Try a normal path:
    http://127.0.0.1:5000/Nazanin

The page should display:
    Welcome, Nazanin!

---

## Investigation Methodology
Trace the complete data flow:
    URL Path
        ↓
    window.location.pathname
        ↓
    substring(1)
        ↓
    decodeURIComponent()
        ↓
    username
        ↓
    HTML string concatenation
        ↓
    innerHTML
        ↓
    Browser parses HTML

The objective is to understand the complete source-to-sink path instead of simply searching for a payload.

---

## What You Should Learn
After completing this lab, you should understand:
- What `window.location.pathname` contains
- Why URL paths are considered user-controlled input
- What `substring()` does in this context
- What `decodeURIComponent()` does
- Why decoding is not the same as sanitization
- How string concatenation can create an unsafe HTML context
- Why `innerHTML` is a dangerous sink for untrusted input
- How DOM XSS can originate from the URL path
- Why `textContent` is safer when displaying plain text

---

## Concepts Covered
- DOM XSS
- `window.location.pathname`
- `location`
- `substring()`
- `decodeURIComponent()`
- `innerHTML`
- HTML Context
- DOM Manipulation
- URL Encoding
- URL Decoding
- Source-to-Sink Analysis

---

## Questions to Consider
While solving the lab, think about:

### Question 1
What is the value of:
    window.location.pathname

when the URL is:
    http://127.0.0.1:5000/Nazanin

### Question 2
Why does the application use:
    substring(1)

### Question 3
Does `decodeURIComponent()` sanitize HTML?

### Question 4
What happens when the username contains:
    <b>Test</b>

### Question 5
Why does assigning the value to:
    innerHTML

change the security behavior?

### Question 6
What would happen if the application used:
    textContent

instead?

---

## Rules
- Run the lab locally.
- Do not test the payload against third-party websites.
- Use harmless proof-of-concept payloads.
- Do not target real users or external applications.
- Focus on understanding the source-to-sink data flow.
- Try to solve the lab before reading the solution.

---

## Difficulty
Medium

---

## Category
DOM XSS

---

## Vulnerability Type
DOM XSS via `location.pathname`

---

## Status
Unsolved

---

## Author
