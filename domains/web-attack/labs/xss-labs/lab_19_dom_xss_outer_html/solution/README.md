# Solution — Lab 19: DOM XSS via `outerHTML`

## Vulnerability
This lab contains a DOM-based Cross-Site Scripting (DOM XSS) vulnerability.
The application reads attacker-controlled data from the URL and inserts it into the DOM through the `outerHTML` property.
Because `outerHTML` parses the assigned string as HTML, attacker-controlled markup can modify the DOM and potentially execute JavaScript.

---

## Source
The source of the attacker-controlled data is:
    window.location.search

The application extracts the `message` parameter using:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Guest";

The value of `message` is therefore controlled by the URL.

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
    outerHTML
      ↓
    DOM

The important point is that the attacker-controlled value reaches an HTML-parsing DOM operation.

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Guest";
    const profile = document.getElementById("profile");
    profile.outerHTML =
        "<div id='profile' class='border border-slate-300 rounded-lg p-4'>" +
        "<p>Welcome, " + message + "!</p>" +
        "</div>";

The application concatenates the user-controlled `message` into an HTML string.

That string is then assigned to:
    profile.outerHTML

---

## What Is `outerHTML`?
`outerHTML` represents the HTML serialization of an element, including the element itself.
It can also be assigned a string to replace the current element with new HTML.

For example:
    element.outerHTML = "<div>Hello</div>";

The browser parses the assigned string as HTML and replaces the original element.
This is fundamentally different from assigning plain text.

---

## Context
The vulnerable context is:
**HTML / DOM replacement context**

The attacker-controlled value is inserted into an HTML string:
    "<p>Welcome, " + message + "!</p>"

The resulting string is then assigned to:
    outerHTML

---

## Sink
The dangerous sink is:
    outerHTML

Specifically:
    profile.outerHTML = ...

The assigned value is interpreted as HTML.

---

## Initial Test
Before testing JavaScript execution, use harmless HTML.
For example:
    <b>Test</b>

A local test URL can be:
    http://127.0.0.1:5000/?message=%3Cb%3ETest%3C%2Fb%3E

If `Test` appears in bold, this demonstrates that the supplied input is being interpreted as HTML.

---

## Proof of Concept
A harmless local XSS proof of concept is:
    <img src=x onerror=alert(1)>

URL-encoded form:
    http://127.0.0.1:5000/?message=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E

The resulting HTML becomes conceptually similar to:
    <p>Welcome, <img src=x onerror=alert(1)>!</p>

The browser parses the injected `<img>` element.
Because the image source is invalid, the `error` event fires and the JavaScript executes.
This proof of concept is intended only for the intentionally vulnerable local lab.

---

## Root Cause
The root cause is the direct concatenation of attacker-controlled data into an HTML string:
    "<p>Welcome, " + message + "!</p>"

followed by assigning that string to:
    outerHTML

The application does not ensure that the value is treated as plain text.

---

## Why `outerHTML` Is Dangerous
The problem is not the URL itself.
The problem is the combination of:
1. Attacker-controlled input
2. HTML string construction
3. An HTML-parsing DOM API

The vulnerable chain is:
    Attacker Input
        ↓
    message
        ↓
    HTML String
        ↓
    outerHTML
        ↓
    HTML Parsing
        ↓
    DOM

Whenever untrusted data reaches an HTML parser without appropriate protection, DOM XSS may be possible.

---

## Secure Mitigation
If the application only needs to display the user's message, avoid constructing HTML from the input.
A safer approach is to create the DOM elements and assign the user-controlled value with `textContent`.

For example:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Guest";
    const profile = document.getElementById("profile");
    const paragraph = document.createElement("p");
    paragraph.textContent = "Welcome, " + message + "!";

    profile.replaceChildren(paragraph);

This treats the user's input as text rather than HTML.

---

## Why `textContent` Is Safer
Consider:
    <b>Test</b>

If the value is inserted through an HTML parser, the browser can create a `<b>` element.

With:
    textContent

the browser displays the literal characters:
    <b>Test</b>

No `<b>` element is created.
Therefore, when the application expects plain text, `textContent` is generally the appropriate choice.

---

## Alternative Mitigation
If an application genuinely needs to support user-provided HTML, simply replacing `outerHTML` with another DOM API is not enough.
The HTML should be processed using a well-maintained HTML sanitization mechanism with an appropriate allowlist of permitted elements and attributes.
Only the HTML that the application explicitly intends to support should be allowed.
For ordinary user messages, however, treating the value as text is simpler and safer.

---

## Investigation Methodology
A useful method for finding this vulnerability is to trace the data from source to sink.

### 1. Identify the Source
Look for browser-controlled input:
    window.location.search

---

### 2. Identify the Parameter
The application extracts:
    message

using:
    URLSearchParams

---

### 3. Track the Variable
The extracted value is stored in:
    const message = ...

---

### 4. Identify the DOM Operation
Search for where `message` is used.
You will find:
    profile.outerHTML = ...

---

### 5. Understand the Sink
Ask:
> Does `outerHTML` treat the assigned value as plain text or HTML?

The assigned value is parsed as HTML.

---

### 6. Test With Harmless HTML
Try:
    <b>Test</b>

If it is rendered as bold text, HTML interpretation has been confirmed.

---

### 7. Demonstrate the Vulnerability
Use a harmless local proof of concept such as:
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
    outerHTML
            ↓
    HTML parsing
            ↓
    DOM replacement
            ↓
    JavaScript execution

---

## Important Lesson
`outerHTML` is not inherently malicious.
The vulnerability occurs because attacker-controlled data is placed inside an HTML string and then passed to an HTML-parsing DOM operation.

The key distinction is:
    Data Source ≠ Vulnerability

Instead, think in terms of:
    Source + Data Flow + Dangerous Sink

A URL parameter becomes dangerous when it reaches a sink that interprets it in an unsafe context.

---

## Key Takeaways
- `window.location.search` can contain attacker-controlled data.
- `URLSearchParams` extracts values from URL parameters.
- `outerHTML` can parse assigned strings as HTML.
- Concatenating untrusted data into HTML strings is dangerous.
- `textContent` is safer for displaying plain text.
- HTML sanitization is required when user-provided HTML is intentionally supported.
- Always trace data from source to sink.
- Test with harmless HTML before demonstrating XSS.
- Decoding or extracting a URL parameter does not make it safe.

---

## Lab Summary
**Lab:** 19
**Vulnerability:** DOM XSS
**Source:** `window.location.search`
**Parameter:** `message`
**Sink:** `outerHTML`
**Root Cause:** Attacker-controlled data is concatenated into an HTML string and assigned to an HTML-parsing DOM property.
**Primary Mitigation:** Use `textContent` and safe DOM construction when HTML is not required.

---

## What This Lab Teaches
This lab introduces another important DOM XSS sink:
    outerHTML

The goal is not to memorize a specificpayload.

The important skill is recognizing the pattern:
    Source
      ↓
    User-Controlled Data
      ↓
    HTML Construction
      ↓
    Dangerous DOM Sink

Once this pattern becomes familiar, investigating different DOM XSS vulnerabilities becomes much easier.

---

## Author
****