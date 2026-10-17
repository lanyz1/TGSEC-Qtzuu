# Lab 16 — DOM XSS via Dangerous URL Scheme

## Objective
Learn how attacker-controlled URL parameters can lead to DOM-based XSS when they are assigned to an HTML `href` attribute without proper URL validation.
This lab focuses on understanding URL contexts, dangerous URL schemes, and DOM sinks such as `setAttribute()`.

---

## Scenario
The application provides a link based on a URL parameter called `next`.

The JavaScript reads the parameter from the current URL:
    const params = new URLSearchParams(document.location.search);
    const next = params.get("next") || "#";

The value is then assigned to the `href` attribute:
    document.getElementById("redirectLink").setAttribute("href", next);

Your goal is to investigate whether you can control the behavior of the generated link.

---

## Mission
Investigate the application and answer these questions:
1. Where does the `next` value come from?
2. How is the query parameter extracted?
3. Where is the value stored?
4. Where is the value inserted into the DOM?
5. How does the browser interpret an `href` value?
6. Are URL schemes validated?
7. Can a dangerous URL scheme be supplied?
8. Can you demonstrate JavaScript execution in the local lab?

---

## Hints
### Hint 1
Start with:
    document.location.search

What information does this property contain?

### Hint 2
Look at:
    URLSearchParams

The application extracts a parameter named:
    next

Try first with a normal value:
    ?next=https://example.com

### Hint 3
Follow the value to:
    setAttribute("href", next)

Ask yourself what happens when a browser receives different kinds of URLs through `href`.

### Hint 4
Not every URL starts with:
    http://
    https://

Investigate URL schemes and find out whether the application restricts which schemes are accepted.

### Hint 5
Start with a harmless navigation URL before testing anything else.
The important question is:
> Does the application validate the URL scheme before assigning it to `href`?

---

## Goal
Demonstrate that the application accepts an unsafe URL scheme through the `next` parameter.
Then demonstrate JavaScript execution using a harmless local proof of concept.

---

## Running the Lab
From the `lab-16` directory:
    python app.py

Then open:
    http://127.0.0.1:5000/

You can provide a value through the `next` parameter:
    http://127.0.0.1:5000/?next=https://example.com

Inspect the generated link and observe how its `href` changes.

---

## Investigation Methodology
Follow the data from source to sink:
    URL
      ↓
    document.location.search
      ↓
    URLSearchParams
      ↓
    params.get("next")
      ↓
    next
      ↓
    setAttribute("href", next)
      ↓
    Browser URL handling

Then investigate whether the application performs any validation between the source and sink.

---

## What You Should Learn
After completing this lab, you should understand:
- What `document.location.search` contains
- How `URLSearchParams` extracts query parameters
- How `setAttribute()` can affect URL-sensitive attributes
- Why `href` is a special URL context
- What URL schemes are
- Why `javascript:` is different from `http:` and `https:`
- Why attacker-controlled URLs must be validated
- How DOM XSS can occur without `innerHTML`

---

## Concepts Covered
- DOM XSS
- URL Context
- `document.location`
- `URLSearchParams`
- `setAttribute()`
- `href`
- URL Schemes
- `javascript:` Scheme
- URL Validation
- DOM Manipulation
- Source-to-Sink Analysis

---

## Questions to Consider
While solving the lab, think about:

### Question 1
What happens when:
    next=https://example.com

is supplied?

### Question 2
Does the application check whether `next` begins with `http://` or `https://`?

### Question 3
What other URL schemes can a browser understand?

### Question 4
What happens when an unexpected URL scheme reaches:
    href

### Question 5
Would simply escaping HTML characters solve this problem?

### Question 6
What would be a safer approach if the application only needs normal web URLs?

---

## Rules
- Run the lablocally.
- Do not test the payload against third-party websites.
- Use harmless proof-of-concept payloads.
- Do not target real users or external applications.
- Focus on understanding URL contexts.
- Try to solve the lab before reading the solution.

---

## Difficulty
Medium

---

## Category
DOM XSS

---

## Vulnerability Type
DOM XSS via Dangerous URL Scheme

---

## Status
Unsolved

---

## Author
