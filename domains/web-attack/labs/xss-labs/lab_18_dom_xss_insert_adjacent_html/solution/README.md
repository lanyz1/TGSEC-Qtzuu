# Solution — Lab 18: DOM XSS via `insertAdjacentHTML()`

## Vulnerability
This lab contains a DOM-based Cross-Site Scripting (DOM XSS) vulnerability.
The application reads attacker-controlled data from the URL and passes it directly to:
    insertAdjacentHTML()

Because `insertAdjacentHTML()` parses the provided string as HTML, an attacker can inject HTML into the DOM.

---

## Source
The source of the user-controlled data is:
    window.location.search

The application reads the `message` parameter using:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Hello";

For example:
    http://127.0.0.1:5000/?message=Hello

The value of `message` is controlled by the URL.

---

## Data Flow
The complete data flow is:
    URL
      ↓
    window.location.search
      ↓
    URLSearchParams
      ↓
    message
      ↓
    insertAdjacentHTML()
      ↓
    DOM

The important part is that the data reaches an HTML-parsing DOM API without being safely handled as text.

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Hello";
    const result = document.getElementById("result");

    result.insertAdjacentHTML(
        "beforeend",
        "<p>" + message + "</p>"
    );

The application takes the attacker-controlled `message` and concatenates it into an HTML string.

That string is then passed to:
    insertAdjacentHTML()

---

## Why Is `insertAdjacentHTML()` Dangerous?
`insertAdjacentHTML()` does not treat the supplied string as plain text.
It parses the string as HTML and inserts the resulting nodes into the DOM.

For example, if the value is:
    <b>Hello</b>

the browser interprets it as an HTML element.

The result is rendered as:
    Hello

with bold formatting.
This demonstrates that the input is being interpreted as HTML rather than displayed as ordinary text.

---

## Context
The vulnerable context is:
**HTML / DOM insertion context**

The attacker-controlled value is placed inside an HTML string:
    "<p>" + message + "</p>"

and then parsed by:
    insertAdjacentHTML()

---

## Sink
The dangerous sink is:
    insertAdjacentHTML()

Specifically:
    result.insertAdjacentHTML("beforeend", ...)

This API parses the supplied string as HTML.

---

## Proof of Concept
First, test with harmless HTML:
    http://127.0.0.1:5000/?message=<b>Hello</b>

If the text appears bold, the HTML injection is confirmed.

A local XSS proof of concept can then be demonstrated with:
    <img src=x onerror=alert(1)>

URL-encoded form:
    http://127.0.0.1:5000/?message=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E

The browser parses the injected `<img>` element.
Because the image source is invalid, the `error` event fires and the JavaScript executes.
This is a harmless proof of concept for the intentionally vulnerable local lab.

---

## Root Cause
The root cause is the direct insertion of attacker-controlled data into an HTML string:
    "<p>" + message + "</p>"

followed by:
    insertAdjacentHTML()

No output encoding or safe text insertion is performed before the data reaches the HTML parser.

---

## Secure Mitigation
If the application only needs to display text, do not use `insertAdjacentHTML()`.
Use `textContent` instead.

For example:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Hello";
    const result = document.getElementById("result");
    const paragraph = document.createElement("p");
    paragraph.textContent = message;

    result.appendChild(paragraph);

Now HTML entered by the user is treated as text rather than being interpreted as markup.

---

## Why `textContent` Is Safer
Consider this input:
    <b>Hello</b>

With `innerHTML` or `insertAdjacentHTML()`, the browser can interpret it as HTML.

With:
    textContent

the browser displays the characters literally:
    <b>Hello</b>

The browser does not create a `<b>` element.
This makes `textContent` the appropriate choice when the application expects plain text.

---

## Alternative Mitigation
If the application genuinely needs to allow users to submit HTML, the solution is not simply replacing one DOM API with another.
The HTML must be processed through a well-maintained HTML sanitization mechanism with an appropriate allowlist.
Only explicitly allowed elements and attributes should be permitted.
For ordinary messages, however, using `textContent` is the simpler and safer approach.

---

## Investigation Methodology
A useful way to identify this vulnerability is to follow the data from source to sink.

### 1. Identify the Source
Look for data coming from the browser:
    window.location.search

---

### 2. Identify the Parameter
The application extracts:
    message

using:
    URLSearchParams

---

### 3. Track the Variable
The resulting value is stored in:
    const message = ...

---

### 4. Identify the Sink
Search for DOM APIs that consume the variable.
Here we find:
    insertAdjacentHTML()

---

### 5. Determine How the Sink Handles Data
Ask:
> Does this API insert plain text or parse HTML?

`insertAdjacentHTML()` parses HTML.

---

### 6. Test With Harmless HTML
Use:
    <b>Test</b>

If it becomes bold, the input is being interpreted as HTML.

---

### 7. Demonstrate the Vulnerability
Use a harmless local XSS proof of concept such as:
    <img src=x onerror=alert(1)>

---

## Vulnerability Chain
The complete vulnerability chain is:
    Attacker-controlled URL
            ↓
    window.location.search
            ↓
    URLSearchParams
            ↓
    message
            ↓
    HTML string concatenation
            ↓
    insertAdjacentHTML()
            ↓
    HTML parsing
            ↓
    DOM modification
            ↓
    JavaScript execution

---

## Important Lesson
The problem is not that `URLSearchParams` is dangerous.
The problem is how the extracted data is eventually used.
This is safe as a data source:
    URL → URLSearchParams → message

The dangerous step is:
    message → HTML string → insertAdjacentHTML()

A DOM XSS vulnerability often comes from the combination of a controllable source and an unsafe sink.

---

## Key Takeaways
- `window.location.search` can contain attacker-controlled data.
- `URLSearchParams` extracts values from the URL.
- `insertAdjacentHTML()` parses strings as HTML.
- User-controlled data should not be inserted into HTML without proper handling.
- `textContent` is safer when displaying plain text.
- HTML sanitization is required when intentionally supporting user-provided HTML.
- Always trace DOM data from source to sink.
- A dangerous sink does not become safe simply because the data came from a URL.

---

## Lab Summary
**Lab:** 18
**Vulnerability:** DOM XSS
**Source:** `window.location.search`
**Parameter:** `message`
**Sink:** `insertAdjacentHTML()`
**Root Cause:** Attacker-controlled data is inserted into an HTML-parsing DOM API.
**Primary Mitigation:** Use `textContent` and safe DOM construction when HTML is not required.

---

## What This Lab Teaches
This lab demonstrates an important DOM XSS pattern:
    Source → Data Flow → Dangerous Sink

Understanding this pattern is more important than memorizing individual payloads.
Once you can identify the source, trace the data, and recognize dangerous sinks, you can investigate many different DOM XSS vulnerabilities.

---

## Author
****