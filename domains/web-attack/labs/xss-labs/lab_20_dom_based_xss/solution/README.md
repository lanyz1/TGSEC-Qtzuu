# Solution — Lab 20: DOM XSS via `Range.createContextualFragment()`

## Vulnerability
This lab contains a DOM-based Cross-Site Scripting (DOM XSS) vulnerability.
The application reads attacker-controlled data from the URL and inserts that data into an HTML string passed to:
    Range.createContextualFragment()

Because `createContextualFragment()` parses the supplied string as HTML, attacker-controlled markup can be converted into DOM nodes.

---

## Source
The source of the attacker-controlled data is:
    window.location.search

The application extracts the `message` parameter using:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Hello";

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
    HTML string construction
      ↓
    createContextualFragment()
      ↓
    DocumentFragment
      ↓
    replaceChildren()
      ↓
    DOM

The important step is that attacker-controlled data reaches an API that parses the supplied string as HTML.

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Hello";
    const result = document.getElementById("result");
    const range = document.createRange();
    const fragment = range.createContextualFragment(
        "<p>" + message + "</p>"
    );

    result.replaceChildren(fragment);

The application takes the user-controlled `message` and concatenates it into an HTML string.

That string is then passed to:
    createContextualFragment()

---

## What Is `createContextualFragment()`?
`Range.createContextualFragment()` creates a `DocumentFragment` by parsing a string as HTML in the context of the current document.

For example:
    const range = document.createRange();
    const fragment = range.createContextualFragment(
        "<p>Hello</p>"
    );

The resulting `fragment` contains DOM nodes created from the supplied HTML.

The important security property is:
> The supplied string is interpreted as HTML rather than ordinary text.

---

## Context
The vulnerable context is:
**HTML / DOM fragment creation context**

The attacker-controlled value is inserted into:
    "<p>" + message + "</p>"

The resulting HTML string is then parsed by:
    createContextualFragment()

---

## Sink
The dangerous operation is:
    range.createContextualFragment(...)

The method parses the supplied string as HTML and creates DOM nodes from it.
The final DOM insertion is performed using:
    result.replaceChildren(fragment)

`replaceChildren()` is not the source of the vulnerability by itself.
The important dangerous operation is the creation of the HTML fragment from untrusted input.

---

## Initial Test
Before testing JavaScript execution, try harmless HTML.
For example:
    <b>Hello</b>

A local test URL can be:
    http://127.0.0.1:5000/?message=%3Cb%3EHello%3C%2Fb%3E

If `Hello` appears in bold, this demonstrates that the input is being interpreted as HTML.

---

## Proof of Concept
A harmless local XSS proof of concept is:
    <img src=x onerror=alert(1)>

URL-encoded form:
    http://127.0.0.1:5000/?message=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E

Conceptually, the resulting HTML becomes:
    <p>Welcome...</p>

with the attacker-controlled HTML represented by:
    <img src=x onerror=alert(1)>

The browser parses the HTML while creating the `DocumentFragment`.
Because the image source is invalid, the `error` event fires and the JavaScript executes.
This proof of concept is intended only for the intentionally vulnerable local lab.

---

## Root Cause
The root cause is the direct insertion of attacker-controlled data into an HTML string:
    "<p>" + message + "</p>"

followed by:
    range.createContextualFragment(...)

The application does not ensure that the user-controlled value is treated as plain text before HTML parsing occurs.

---## Why This Is Dangerous
The vulnerability is not caused by `URLSearchParams`.
`URLSearchParams` simply extracts data from the URL.

The dangerous part is the later use of that data:
    message
       ↓
    HTML string
       ↓
    createContextualFragment()
       ↓
    HTML parsing
       ↓
    DOM nodes

Whenever untrusted data reaches an HTML parser without appropriate protection, DOM XSS may be possible.

---

## DocumentFragment
A `DocumentFragment` is a lightweight container for DOM nodes.
It can contain elements such as:
    <p>
    <div>
    <img>

and other DOM nodes.

In this lab, the fragment is created from attacker-controlled HTML:
    const fragment = range.createContextualFragment(
        "<p>" + message + "</p>"
    );

The fragment is then inserted into the page:
    result.replaceChildren(fragment);

The important point is that the security problem occurs while the string is being parsed into DOM nodes.

---

## Secure Mitigation
If the application only needs to display the user's message, do not construct an HTML string from the input.
Instead, create the element and use `textContent`.
For example:
    const params = new URLSearchParams(window.location.search);
    const message = params.get("message") || "Hello";
    const result = document.getElementById("result");
    const paragraph = document.createElement("p");
    paragraph.textContent = message;

    result.replaceChildren(paragraph);

Now the message is treated as text.

---

## Why `textContent` Is Safer
Consider this input:
    <b>Hello</b>

When inserted through an HTML parser, it can create a real `<b>` element.

When assigned using:
    textContent

the browser displays:
    <b>Hello</b>

as literal text.

No `<b>` element is created.
Therefore, when the application expects ordinary text, `textContent` is a safer choice.

---

## Alternative Mitigation
If the application intentionally supports user-provided HTML, the solution should be based on proper HTML sanitization.
The sanitizer should use an explicit allowlist of permitted:
- Elements
- Attributes
- URL schemes
- Other relevant HTML features

Only the HTML that the application actually intends to support should be allowed.
For ordinary messages, however, avoiding HTML parsing entirely and using `textContent` is simpler.

---

## Investigation Methodology
A useful way to investigate this vulnerability is to follow the data from source to sink.

### 1. Identify the Source
Look for browser-controlled data:
    window.location.search

---

### 2. Identify the Parameter
The application extracts:
    message

using:
    URLSearchParams

---

### 3. Track the Data
The value is stored in:
    const message = ...

---

### 4. Find Where the Data Is Used
Search for:
    message

You will find it inside:
    "<p>" + message + "</p>"

---

### 5. Identify the HTML Parser
The constructed string is passed to:
    createContextualFragment()

This is the critical point.

---

### 6. Understand the Result
`createContextualFragment()` converts the HTML string into DOM nodes inside a `DocumentFragment`.

---

### 7. Follow the Fragment
The fragment is inserted using:
    result.replaceChildren(fragment)

---

### 8. Test With Harmless HTML
Try:
    <b>Test</b>

If it is rendered as bold text, HTML interpretation has been confirmed.

---

### 9. Demonstrate the Vulnerability
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
    createContextualFragment()
            ↓
    HTML parsing
            ↓
    DocumentFragment
            ↓
    replaceChildren()
            ↓
    DOM
            ↓
    JavaScript execution

---

## Important Lesson
The important lesson of this lab is not to memorize `createContextualFragment()` as a dangerous function.
Instead, learn to recognize the pattern:
    Untrusted Source
          ↓
    Data Flow
          ↓
    HTML Construction
          ↓
    HTML Parser
          ↓
    DOM

The same reasoning can be applied to many different DOM APIs.

---

## Comparison With Previous Labs
Several DOM APIs can become dangerous when they receive attacker-controlled HTML.
Examples include:
    innerHTML
    outerHTML
    insertAdjacentHTML()
    createContextualFragment()

The exact API is different, but the underlying security problem can be similar:
    Untrusted Data → HTML Parsing → DOM

Learning to recognize this pattern is more valuable than memorizing individual payloads.

---

## Key Takeaways
- `window.location.search` can contain attacker-controlled data.
- `URLSearchParams` extracts values from URL parameters.
- `createContextualFragment()` parses strings as HTML.
- Parsed HTML becomes DOM nodes inside a `DocumentFragment`.
- `replaceChildren()` inserts those nodes into the document.
- The vulnerability occurs because untrusted data reaches an HTML parser.
- `textContent` is safer when displaying plain text.
- HTML sanitization is necessary when user-provided HTML is intentionally supported.
- Always trace DOM data from source to sink.
- Test with harmless HTML before demonstrating XSS.

---

## Lab Summary
**Lab:** 20
**Vulnerability:** DOM XSS
**Source:** `window.location.search`
**Parameter:** `message`
**Dangerous Sink:** `Range.createContextualFragment()`
**DOM Insertion:** `replaceChildren()`
**Root Cause:** Attacker-controlled data is concatenated into an HTML string and parsed into DOM nodes.
**Primary Mitigation:** Use `textContent` and safe DOM construction when HTML is not required.

---

## What This Lab Teaches
This lab introduces another DOM XSS pattern involving HTML parsing and `DocumentFragment`.
The core skill is recognizing:
    Source
      ↓
    User-Controlled Data
      ↓
    HTML Construction
      ↓
    HTML Parsing
      ↓
    DOM

Once this source-to-sink pattern becomes familiar, investigating different DOM XSS vulnerabilities becomes much easier.

---

## Author
****