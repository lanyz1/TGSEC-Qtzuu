# Lab 15 — DOM XSS via `postMessage()` — Solution

## Vulnerability
This lab demonstrates **DOM XSS via `postMessage()`**.
The page listens for messages using:
    window.addEventListener("message", function (event) {
        const message = event.data;

        document.getElementById("result").innerHTML = message;
    });

The received message is inserted directly into the DOM using `innerHTML`.
Because the message is treated as HTML, attacker-controlled content can potentially result in script execution.

---

## Source
The source of the user-controlled data is:
    event.data

The browser provides the received message through the `MessageEvent` object.

The relevant code is:
    const message = event.data;

---

## Data Flow
    postMessage()
          ↓
    MessageEvent
          ↓
    event.data
          ↓
    message
          ↓
    innerHTML
          ↓
    Browser parses HTML
          ↓
    Potential JavaScript execution

---

## Vulnerable Code
The vulnerable code is:
    window.addEventListener("message", function (event) {
        const message = event.data;

        document.getElementById("result").innerHTML = message;
    });

The critical line is:
    document.getElementById("result").innerHTML = message;

The application takes data received from another browsing context and inserts it as HTML.

---

## Context
The application receives data through the browser's `postMessage()` mechanism.
Messages can be sent between windows, iframes, and other browsing contexts.

The receiver gets the supplied value through:
    event.data

The important security property is that message data should be treated as untrusted input.

---

## Sink
The sink is:
    innerHTML

Specifically:
    document.getElementById("result").innerHTML = message;

`innerHTML` causes the browser to parse the supplied value as HTML.

---

## Proof of Concept
A harmless HTML payload can first be used to confirm that the message is interpreted as HTML:
    <h2>Hello from postMessage</h2>

For a local XSS demonstration, a harmless event-handler payload can be used:
    <img src=x onerror=alert(1)>

The important point is that the message reaches `innerHTML` without being converted to plain text.

---

## Root Cause
There are two important security problems.

### 1. Untrusted message data reaches `innerHTML`
The application assumes that `event.data` is safe HTML:
    innerHTML = message

But messages should be considered untrusted unless their source and contents have been properly validated.

### 2. No origin validation
The application does not check:

    event.origin

A secure `postMessage` receiver should normally verify that the message came from an expected origin before processing sensitive or privileged data.

For example:
    if (event.origin !== "http://127.0.0.1:5000") {
        return;
    }

The exact allowed origin should be determined by the application's architecture.

---

## Mitigation
### 1. Prefer `textContent`
If the application only needs to display the received message as text:
    document.getElementById("result").textContent = message;

This prevents the browser from interpreting the message as HTML.

### 2. Validate the message origin
Check `event.origin` against an explicit allowlist:
    window.addEventListener("message", function (event) {
        if (event.origin !== "https://trusted.example") {
            return;
        }

        document.getElementById("result").textContent = event.data;
    });

Do not blindly trust arbitrary origins.

### 3. Validate the message format
If the application expects a specific structure, validate the received data before using it.
For example, if the application expects JSON:
    let data;
    try {
        data = JSON.parse(event.data);
    } catch {
        return;
    }

Then validate the expected properties and types.

### 4. Avoid unnecessary HTML interpretation
If HTML is not required, never use `innerHTML` for untrusted message data.
Use safer DOM APIs such as:
    textContent

or create individual DOM elements and assign text values explicitly.

---

## Secure Example
A safer version for plain-text messages is:
    window.addEventListener("message", function (event) {
        if (event.origin !== "http://127.0.0.1:5000") {
            return;
        }

        document.getElementById("result").textContent = event.data;
    });

This addresses both major issues:
- The sender origin is checked.
- The message is rendered as text instead of HTML.

---

## Investigation Methodology
When investigating a `postMessage` vulnerability:
1. Search for message event listeners.
       window.addEventListener("message", ...)

2. Identify the message source.
       event.data

3. Trace where the received data goes.
       const message = event.data

4. Identify the sink.
       innerHTML

5. Determine whether the data is interpreted as HTML.
6. Check whether `event.origin` is validated.
7. Test with harmless HTML before testing JavaScript execution.

---

## Vulnerability Chain
    External Message
          ↓
    postMessage()
          ↓
    message event
          ↓
    event.data
          ↓
    innerHTML
          ↓
    HTML parsing
          ↓
    Event handler execution
          ↓
    DOM XSS

---

## Key Takeaways
- `postMessage()` should be treated as an untrusted data source.
- `event.data` can contain attacker-controlled content.
- Always understand where a received message ends up.
- `innerHTML` interprets input as HTML.
- `textContent` is safer when HTML rendering is not required.
- `event.origin` should be validated when the sender is expected to come from a specific origin.
- Origin validation and output-safe DOM manipulation solve different problems and should not be treated as interchangeable defenses.
- Always trace the complete chain:

      Source → Validation → Transformation → Sink

---

## Lab Summary
| Property | Value |
|---|---|
| Lab | 15 |
| Category | DOM XSS |
| Vulnerability Type | DOM XSS via `postMessage()` |
| Source | `event.data` |
| Sink | `innerHTML` |
| Additional Issue | Missing `event.origin` validation |
| Main Risk | Untrusted message interpreted as HTML |
| Safer Alternative | `textContent` |
| Difficulty | Medium |
| Status | Solved |
| Author |  |

---

## What This Lab Teaches
This lab demonstrates an important DOM XSS pattern:
    Untrusted Message
          ↓
       event.data
          ↓
       innerHTML
          ↓
      HTML Parsing
          ↓
      DOM XSS

It also introduces an important security concept specific to `postMessage()`:
    Never assume that received messages are trusted.

A secure implementation should consider both:
1. **Who sent the message?**
2. **How is the message being used?**

Validating the sender's origin helps answer the first question, while safe DOM APIs such as `textContent` help prevent the second from becoming an XSS vulnerability.

---

## Author
