# Lab 17 — DOM XSS via `location.pathname` — Solution

## Vulnerability
This lab demonstrates **DOM XSS through `location.pathname`**.
The application reads user-controlled data from the URL path and inserts it directly into the DOM using `innerHTML`.
The vulnerable flow is:
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
    innerHTML
        ↓
    HTML parsing
        ↓
    Potential JavaScript execution

---

## Source
The source is:
    window.location.pathname

The application reads the current URL path:
    const path = window.location.pathname;

For example:
    http://127.0.0.1:5000/Nazanin

produces:
    /Nazanin

---

## Data Transformation
The application removes the first character of the path:
    path.substring(1)

This removes the `/`.

So:
    /Nazanin

becomes:
    Nazanin

The application then decodes URL-encoded characters:
    decodeURIComponent(path.substring(1))

The resulting value is stored in:
    username

---

## Data Flow
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
    "<p>Welcome, " + username + "!</p>"
        ↓
    innerHTML
        ↓
    Browser parses HTML
        ↓
    DOM XSS

---

## Vulnerable Code
The main vulnerable code is:
    const path = window.location.pathname;
    const username = decodeURIComponent(path.substring(1)) || "Guest";

    document.getElementById("profile").innerHTML =
        "<p>Welcome, " + username + "!</p>";

The critical line is:
    document.getElementById("profile").innerHTML =
        "<p>Welcome, " + username + "!</p>";

The application combines a value derived from the URL with an HTML string and sends the result to `innerHTML`.

---

## Context
The attacker-controlled value is placed inside an HTML string:
    "<p>Welcome, " + username + "!</p>"

The complete string is then interpreted by the browser because it is assigned to:
    innerHTML

Therefore, HTML contained in `username` can become part of the DOM.

---

## Sink
The sink is:
    innerHTML

Specifically:
    document.getElementById("profile").innerHTML =
        "<p>Welcome, " + username + "!</p>";

This is the point where the browser parses the attacker-controlled value as HTML.

---

## Proof of Concept
First, test a normal path:
    http://127.0.0.1:5000/Nazanin

The page should display:
    Welcome, Nazanin!

Now test with harmless HTML.
For example, URL-encode:
    <b>Test</b>

and place it in the path.
The browser should interpret the `<b>` element as HTML.
A local XSS proof of concept can then use a harmless event-handler payload such as:
    <img src=x onerror=alert(1)>

Because special characters in a URL path may need encoding, the encoded payload can be used when testing it through the browser.

---

## Root Cause
The root cause is the combination of:
1. User-controlled data from `window.location.pathname`
2. Decoding the value
3. Concatenating it with an HTML string
4. Assigning the result to `innerHTML`

The application assumes that the URL path contains harmless text.
However, URL components are attacker-controlled input and must be treated as untrusted.

---

## Mitigation
### 1. Use `textContent`
If the application only needs to display the username as text, replace:
    innerHTML

with:
    textContent

For example:
    document.getElementById("profile").textContent =
        "Welcome, " + username + "!";

Now HTML characters inside `username` are treated as text rather than being parsed as HTML.

---

### 2. Avoid HTML string concatenation
Instead of:
    "<p>Welcome, " + username + "!</p>"

create the DOM element separately and assign the username as text.

For example:
    const paragraph = document.createElement("p");
    paragraph.textContent = "Welcome, " + username + "!";
    document.getElementById("profile").replaceChildren(paragraph);

This avoids treating the username as HTML.

---

### 3. Validate expected input
If a username is expected to contain onlycertain characters, validate it against the application's requirements.
For example, an application could allow:
    letters
    numbers
    underscore

and reject unexpected characters.
Validation should be considered an additional defense, not a replacement for safe output handling.

---

## Secure Example
A simple secure version is:
    const path = window.location.pathname;
    const username = decodeURIComponent(path.substring(1)) || "Guest";

    document.getElementById("profile").textContent =
        "Welcome, " + username + "!";

Here the username is rendered as text.
Even if the path contains HTML-like characters, they are not interpreted as HTML.

---

## Investigation Methodology
When investigating this vulnerability:
1. Identify the source.
       window.location.pathname

2. Check whether the value is transformed.
       substring(1)

3. Check for decoding.
       decodeURIComponent()

4. Follow the resulting value.
       username

5. Find where the value is used.
       "<p>Welcome, " + username + "!</p>"

6. Identify the sink.
       innerHTML

7. Test with ordinary text first.
       /Nazanin

8. Test with harmless HTML.
       /<b>Test</b>

9. Determine whether the browser interprets the input as HTML.
10. Only then demonstrate JavaScript execution in the local lab.

---

## Vulnerability Chain
    Attacker-Controlled URL
            ↓
    location.pathname
            ↓
    substring()
            ↓
    decodeURIComponent()
            ↓
    username
            ↓
    HTML String Concatenation
            ↓
    innerHTML
            ↓
    HTML Parsing
            ↓
    DOM XSS

---

## Key Takeaways
- `window.location.pathname` is a source of attacker-controlled input.
- URL paths should not automatically be considered trusted.
- `decodeURIComponent()` decodes data; it does not sanitize it.
- String concatenation can become dangerous when the result is passed to an HTML parser.
- `innerHTML` interprets its value as HTML.
- `textContent` is safer when the application only needs to display text.
- Always trace the complete path:

      Source → Transformation → Context → Sink

---

## Important Distinction
This lab is similar to Lab 13 because both involve a location-based DOM source.
However, the source is different.

Lab 13:
    window.location.hash

Lab 17:
    window.location.pathname

The important lesson is that different parts of the URL can become DOM XSS sources when they eventually reach an unsafe sink.

---

## Lab Summary
| Property | Value |
|---|---|
| Lab | 17 |
| Category | DOM XSS |
| Vulnerability Type | DOM XSS via `location.pathname` |
| Source | `window.location.pathname` |
| Transformation | `substring()` + `decodeURIComponent()` |
| Variable | `username` |
| Sink | `innerHTML` |
| Main Issue | URL path inserted into HTML |
| Safer Alternative | `textContent` |
| Difficulty | Medium |
| Status | Solved |
| Author |  |

---

## What This Lab Teaches
The most important concept in this lab is that the location of user input inside the URL does not make it trustworthy.
The path:
    /username

can be controlled by the user.

If the application processes that value and eventually sends it to an HTML parser:
    location.pathname
          ↓
    username
          ↓
    innerHTML

the input can become executable HTML.

The key lesson is:
> Always treat URL-derived data as untrusted until it reaches a safe output context.

---

## Author
