# Lab 13 — DOM XSS via location.hash and innerHTML — Solution

## 🎯 Vulnerability
This lab demonstrates a **DOM-based Cross-Site Scripting (DOM XSS)** vulnerability caused by taking attacker-controlled data from `location.hash` and inserting it into the page using `innerHTML`.

The vulnerable pattern is:
    const hashValue = window.location.hash.substring(1);
    const decodedValue = decodeURIComponent(hashValue);
    document.getElementById("result").innerHTML =
        "<p>Result: " + decodedValue + "</p>";

The important concept in this lab is the flow:

    Source → Transformation → Sink

---

## 🔍 Source
The source of the attacker-controlled data is:
    window.location.hash

The URL fragment is everything after the `#` character.

For example:
    http://127.0.0.1:5000/#hello

The fragment is:
    #hello

The application then removes the first character:
    substring(1)

resulting in:
    hello

---

## 🔄 Data Flow
The complete data flow is:
    URL Fragment
         ↓
    window.location.hash
         ↓
    substring(1)
         ↓
    decodeURIComponent()
         ↓
    decodedValue
         ↓
    String Concatenation
         ↓
    innerHTML
         ↓
    DOM
         ↓
    XSS

---

## ⚠️ Vulnerable Code
The vulnerable code is:
    const hashValue = window.location.hash.substring(1);
    const decodedValue = decodeURIComponent(hashValue);
    document.getElementById("result").innerHTML =
        "<p>Result: " + decodedValue + "</p>";

There are two important parts:

### Source
    window.location.hash

### Sink
    innerHTML

The application takes data from the URL and eventually inserts it into an HTML context.

---

## 🧠 Understanding the Source
`window.location.hash` represents the fragment portion of the current URL.
For example:
    http://127.0.0.1:5000/#

The value of:
    window.location.hash

is:
    #

The application removes the `#` character using:
    substring(1)

So the resulting value becomes:
    

Because the URL is controlled by the user, the resulting value must be considered untrusted input.

---

## 🔄 Understanding `decodeURIComponent()`
The application then performs:
    decodeURIComponent(hashValue)

`decodeURIComponent()` converts percent-encoded characters back into their original representation.

For example, encoded characters can be transformed back into characters such as:
    <
    >
    "
    '

This is important because the resulting value is later passed to an HTML-parsing sink.
The decoding operation itself is not the vulnerability.
The problem is what happens to the decoded value afterward.

---

## 💥 Understanding the Sink
The final operation is:
    document.getElementById("result").innerHTML =
        "<p>Result: " + decodedValue + "</p>";

`innerHTML` tells the browser to interpret the assigned string as HTML.

This is different from:
    textContent

With `textContent`, the value is treated as text.
With `innerHTML`, HTML markup contained in the value can be parsed as part of the DOM.

---

## 🧪 Proof of Concept
A harmless local PoC is:
    <img src=x onerror=alert(1)>

The important part is that the supplied value contains HTML markup.

Conceptually, the browser receives something similar to:
    <p>
        Result:
        <img src=x onerror=alert(1)>
    </p>

The injected HTML becomes part of the DOM.
When the browser encounters the invalid image source, the `error` event can fire and execute the JavaScript in the event handler.
A successful alert demonstrates DOM-based XSS.

---

## 🌐 Example URL
For local testing, the concept is:
    http://127.0.0.1:5000/#<img src=x onerror=alert(1)>

Depending on the browser and URL handling, special characters may need to be percent-encoded.

The important point is that the payload is placed after:
    #

because the application reads:
    window.location.hash

---

## 🔬 Why Does It Work?
The browser processes the URL fragment.
The application then performs:
    window.location.hash

↓

    substring(1)

↓

    decodeURIComponent()

↓

    innerHTMLThe final HTML becomes conceptually:
    <p>Result: USER_INPUT</p>

Because `innerHTML` parses the resulting string as HTML, attacker-controlled markup can become part of the DOM.

This creates the following vulnerability:
    Attacker-Controlled Source
            +
    HTML Parsing Sink
            =
    DOM XSS

---

## 🚨 Root Cause
The root cause is the use of attacker-controlled URL data with an HTML-parsing DOM API.
The complete vulnerable chain is:
    location.hash
        ↓
    decodeURIComponent()
        ↓
    HTML String Construction
        ↓
    innerHTML
        ↓
    HTML Parsing
        ↓
    JavaScript Execution

The main issue is not `location.hash` itself.
The issue is sending untrusted data to an unsafe sink.

---

## 🛡️ Mitigation
The safest solution is to use `textContent` when the application only needs to display text.
Replace:
    document.getElementById("result").innerHTML =
        "<p>Result: " + decodedValue + "</p>";

with:

    const result = document.getElementById("result");
    result.textContent = "Result: " + decodedValue;

Now the browser treats the supplied value as text instead of parsing it as HTML.

---

## ✅ Secure Example
A safer implementation is:
    const hashValue = window.location.hash.substring(1);
    const decodedValue = decodeURIComponent(hashValue);
    const result = document.getElementById("result");
    result.textContent = "Result: " + decodedValue;

If the user supplies HTML such as:
    <script>alert(1)</script>

the browser displays it as text instead of creating a script element.

---

## 🧩 Another Safe Approach
If the application genuinely needs to create HTML elements, avoid concatenating untrusted input into HTML strings.
Instead, create the element separately:
    const result = document.getElementById("result");
    const paragraph = document.createElement("p");
    paragraph.textContent = "Result: " + decodedValue;
    result.appendChild(paragraph);

This keeps the user-controlled value in a text context.

---

## 🔎 Investigation Methodology
When investigating DOM XSS, trace the data from the source to the sink.

### Step 1 — Find the Source
Search for browser-controlled values such as:
    location
    location.search
    location.hash
    document.URL
    document.referrer

In this lab:
    window.location.hash

is the source.

---

### Step 2 — Follow Transformations
Look for functions that modify the value.
In this lab:
    substring(1)

and:
    decodeURIComponent()

are used.

These transformations do not make the value trusted.

---

### Step 3 — Track the Variable
The transformed value is stored in:
    decodedValue

Follow this variable through the rest of the JavaScript code.

---

### Step 4 — Identify the Sink
Look for DOM APIs that interpret strings as HTML.
Examples include:
    innerHTML
    outerHTML
    document.write()
    insertAdjacentHTML()

In this lab:
    innerHTML

is the sink.

---

### Step 5 — Determine the Context
Ask:
> Is the data being treated as text or HTML?

Here:
    innerHTML

causes the browser to parse the resulting string as HTML.

---

### Step 6 — Test With a Harmless PoC
Use a harmless local payload to determine whether HTML markup is interpreted.
The objective is to verify the complete chain:

    Source
       ↓
    Transformation
       ↓
    Sink
       ↓
    Browser Parsing
       ↓
    JavaScript Execution

---

## 🧠 Important Distinction
This lab uses:
    location.hash

The fragment is different from a normal query parameter.

For example:
    /?name=test

uses a query string.

While:
    /#test

uses a URL fragment.

The fragment is available to client-side JavaScript through:
    window.location.hash

This makes it a common source when investigating DOM-based vulnerabilities.

---

## 📚 Key Takeaways
### 1. `location.hash` is user-controlled
Never assume URL fragments are trusted.

---

### 2. Transformations do not make input safe
Functions such as:
    decodeURIComponent()

only transform data.

They do not sanitize it.

---

### 3. `innerHTML` parses HTML
When untrusted data reaches `innerHTML`, the browser may interpret that data as HTML.

---

### 4. Source and Sink are critical
For this lab:
    Source:
    window.location.hash

    Sink:
    innerHTML

Understanding this relationship makes DOM XSS much easier to identify.

---

### 5. Prefer `textContent` for text
If the application only needs to display user-controlled text, use:
    textContent

instead of:
    innerHTML

---

### 6. Avoid unnecessary HTML string construction
Building HTML by concatenating strings with user-controlled data creates unnecessary security risks.
Prefer DOM APIs that keep untrusted values in a text context.

---

## 🧪 Lab Summary
**Lab:** 13  
**Category:** Cross-Site Scripting  
**Difficulty:** Medium  
**Type:** DOM-based XSS  
**Source:** `window.location.hash`  
**Transformation:** `decodeURIComponent()`  
**Sink:** `innerHTML`  
**Root Cause:** Untrusted URL fragment inserted into an HTML-parsing sink

---

## 🎓 What This Lab Teaches
After completing this lab, you should understand:
- What `location.hash` is
- How URL fragments can become DOM XSS sources
- How `URLSearchParams` differs from URL fragments
- What `decodeURIComponent()` does
- Why decoding does not equal sanitization
- How `innerHTML` parses strings as HTML
- How to identify DOM XSS sources
- How to identify DOM XSS sinks
- How to trace data through JavaScript
- Why `textContent` is safer for displaying untrusted text
- How to construct a complete Source → Sink analysis

---

## 👤 Author

Educational XSS laboratory for security learning and practice.