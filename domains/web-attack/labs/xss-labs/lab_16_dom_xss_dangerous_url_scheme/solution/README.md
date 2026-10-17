# Lab 16 — DOM XSS via Dangerous URL Scheme — Solution

## Vulnerability
This lab demonstrates **DOM XSS through a dangerous URL scheme**.
The application reads the `next` parameter from the URL and assigns it directly to the `href` attribute of an `<a>` element.

The vulnerable flow is:
    document.location.search
            ↓
    URLSearchParams
            ↓
    next
            ↓
    setAttribute("href", next)
            ↓
    Browser interprets the URL

The application does not validate which URL scheme is being assigned to `href`.

---

## Source
The source is:
    document.location.search

The application extracts the `next` parameter:
    const params = new URLSearchParams(document.location.search);
    const next = params.get("next") || "#";

For example:
    http://127.0.0.1:5000/?next=test

The value of `next` becomes:
    test

---

## Data Flow
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

---

## Vulnerable Code
The vulnerable code is:
    document.getElementById("redirectLink").setAttribute("href", next);

The application directly trusts the value extracted from the URL.

There is no validation such as:
    http://
    https://

or an explicit allowlist of acceptable schemes.

---

## Context
The user-controlled value is inserted into the `href` attribute of an anchor element.
The important detail is that `href` is not simply a text field.
The browser interprets its value as a URL.
Different URL schemes can have different browser behaviors.

---

## Sink
The sink is:
    setAttribute("href", next)

Specifically:
    document.getElementById("redirectLink").setAttribute("href", next);

The dangerous behavior comes from allowing an attacker-controlled URL scheme to reach the `href` attribute.

---

## Proof of Concept
First, test a normal URL:
    http://127.0.0.1:5000/?next=https://example.com

The generated link should point to:
    https://example.com

Now test a JavaScript URL scheme in the local lab:
    http://127.0.0.1:5000/?next=javascript:alert(1)

Click the generated link.
If the browser executes the JavaScript, the vulnerability has been demonstrated.
The important observation is not the payload itself.

The important observation is:
    attacker-controlled URL
            ↓
    href attribute
            ↓
    javascript: scheme
            ↓
    JavaScript execution

---

## Root Cause
The root cause is insufficient validation of a user-controlled URL.
The application assumes that every value supplied through:
    next

is a safe navigation URL.
However, a URL can use different schemes.

For example:
    https://example.com
    http://example.com
    javascript:...

The application does not restrict the value to the URL schemes it actually expects.

---

## Mitigation
### 1. Allowlist URL schemes
If the application only expects web URLs, allow only:
    http:
    https:

Reject values using unexpected schemes.

Conceptually:
    if url starts with "http://" or "https://":
        allow
    else:
        reject

A real implementation should parse the URL rather than relying only on string prefix checks.

---

### 2. Validate the parsed URL
A safer approach is to parse the URL and inspect its protocol.
For example:
    const parsed = new URL(next, window.location.origin);

    if (parsed.protocol !== "http:" &&
        parsed.protocol !== "https:") {
        throw new Error("Invalid URL scheme");
    }

Then assign the validated value.

---

### 3. Use relative URLs when possible
If the application only needs internal navigation, prefer relative paths such as:
    /profile
    /settings
    /products

rather than accepting arbitrary URLs.

---

## Secure Example
A safer client-side implementation could look like:
    const params = new URLSearchParams(document.location.search);
    const next = params.get("next") || "/";

    try {
        const parsed = new URL(next, window.location.origin);

        if (parsed.protocol !== "http:" &&parsed.protocol !== "https:") {
            throw new Error("Invalid URL scheme");
        }

        document
            .getElementById("redirectLink")
            .setAttribute("href", parsed.href);

        document
            .getElementById("redirectLink")
            .textContent = parsed.href;

    } catch {
        document
            .getElementById("redirectLink")
            .setAttribute("href", "/");

        document
            .getElementById("redirectLink")
            .textContent = "/";
    }

---

## Investigation Methodology
When investigating this type of DOM vulnerability:
1. Identify the source.
       document.location.search

2. Find how query parameters are extracted.
       URLSearchParams

3. Identify the attacker-controlled parameter.
       next

4. Follow the value through the application.
       const next = params.get("next")

5. Find where the value reaches the DOM.
       setAttribute("href", next)

6. Identify how the browser interprets the value.
       href → URL

7. Test with a normal URL first.
       https://example.com

8. Test whether an unexpected URL scheme is accepted.
9. Confirm whether the browser executes the resulting behavior.

---

## Vulnerability Chain
    Attacker-Controlled URL
            ↓
    document.location.search
            ↓
    URLSearchParams
            ↓
    next
            ↓
    setAttribute()
            ↓
    href
            ↓
    javascript: scheme
            ↓
    JavaScript execution

---

## Key Takeaways
- `href` is a URL-sensitive context.
- User-controlled URLs should not automatically be considered safe.
- URL schemes matter.
- `javascript:` is fundamentally different from `https:`.
- `setAttribute()` itself is not automatically dangerous; the security depends on what value is assigned and how the browser interprets that attribute.
- URL validation should happen before assigning untrusted values to navigation-related attributes.
- Prefer explicit allowlists for expected URL schemes.
- When possible, use relative URLs for internal navigation.

---

## Important Distinction
This vulnerability is different from the previous `innerHTML`-based labs.
In an `innerHTML` vulnerability:
    Input → HTML parser → DOM

In this lab:
    Input → href → URL parser / URL handling

The dangerous behavior comes from the browser interpreting an attacker-controlled value as a URL with an executable scheme.

---

## Lab Summary
| Property | Value |
|---|---|
| Lab | 16 |
| Category | DOM XSS |
| Vulnerability Type | DOM XSS via dangerous URL scheme |
| Source | `document.location.search` |
| Parameter | `next` |
| Sink | `setAttribute("href", next)` |
| Dangerous Scheme | `javascript:` |
| Main Issue | Missing URL scheme validation |
| Safer Approach | Allowlist `http:` / `https:` |
| Difficulty | Medium |
| Status | Solved |
| Author |  |

---

## What This Lab Teaches
This lab demonstrates that XSS does not always require `innerHTML`.
A vulnerability can also occur when attacker-controlled data reaches a browser feature that has its own interpretation rules.

Here, the critical path is:
    User Input
        ↓
    URL Parameter
        ↓
    href
        ↓
    URL Parsing
        ↓
    Dangerous Scheme
        ↓
    JavaScript Execution

The key lesson is:

> Always analyze the context in which untrusted data is used, not just the function receiving the data.

---

## Author
