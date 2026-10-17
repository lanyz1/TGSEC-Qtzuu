# Lab 15 — DOM XSS via `postMessage()`

## Objective
Learn how insecure handling of messages received through `postMessage()` can lead to DOM-based XSS.
This lab focuses on identifying `event.data` as an untrusted source and tracing it to an unsafe DOM sink.

---

## Scenario
The application listens for messages sent to the current window:
    window.addEventListener("message", function (event) {
        const message = event.data;

        document.getElementById("result").innerHTML = message;
    });

The received message is then displayed inside the page.

Your goal is to investigate how the message is processed and determine whether you can make the application interpret the received data as HTML.

---

## Mission
Investigate the application and answer these questions:
1. Where does the message data come from?
2. What is `event.data`?
3. Where is the received data stored?
4. Where is the data inserted into the DOM?
5. Does the application validate `event.origin`?
6. Does the browser interpret the received data as HTML?
7. Can you demonstrate JavaScript execution in the local lab?

---

## Hints
### Hint 1
Look for:
    window.addEventListener("message", ...)

This is where the application receives messages.

### Hint 2
The received message is available through:
    event.data

Treat this value as untrusted input.

### Hint 3
Follow the value after:
    const message = event.data;

Where is `message` used?

### Hint 4
Pay close attention to:
    innerHTML

Ask yourself what happens when HTML is assigned to `innerHTML`.

### Hint 5
Before testing JavaScript, start with harmless HTML.
For example:
    <h2>Hello</h2>

If the text is rendered as a heading, you have confirmed that the message is being interpreted as HTML.

### Hint 6
There is another security issue to investigate:
    event.origin

Ask yourself whether the application checks where the message came from.

---

## Goal
Demonstrate that an untrusted message can reach an HTML-sensitive DOM sink.
Then demonstrate JavaScript execution using a harmless local proof of concept.

---

## Running the Lab
From the `lab-15` directory:
    python app.py

Then open:
    http://127.0.0.1:5000/

The application initially displays:
    Waiting for a message...

You will need to investigate how a message can be delivered to the page.

---

## Investigation Methodology
Trace the complete data flow:
    Message Sender
          ↓
    postMessage()
          ↓
    message event
          ↓
    event.data
          ↓
    message
          ↓
    innerHTML
          ↓
    Browser parses HTML

Also investigate whether the application verifies:
    event.origin

The objective is to understand the complete source-to-sink path rather than simply finding a working payload.

---

## What You Should Learn
After completing this lab, you should understand:
- How `postMessage()` works
- What `MessageEvent` represents
- What `event.data` contains
- Why received messages should be treated as untrusted input
- How `innerHTML` can create a DOM XSS sink
- Why `event.origin` validation matters
- The difference between origin validation and output encoding
- How to trace DOM-based vulnerabilities from source to sink

---

## Concepts Covered
- DOM XSS
- `postMessage()`
- `MessageEvent`
- `event.data`
- `event.origin`
- `innerHTML`
- Cross-Origin Communication
- Same-Origin Policy
- Source-to-Sink Analysis
- DOM Manipulation
- Input Validation

---

## Security Questions
While solving the lab, consider:

### Question 1
Can any window send a message to this page?

### Question 2
Does the application verify the sender's origin?

### Question 3
What happens when `event.data` contains HTML?

### Question 4
What changes if `innerHTML` is replaced with:
    textContent

### Question 5
Would checking only `event.origin` completely solve the XSS problem?
Think about these questions before looking at the solution.

---

## Rules
- Run the lab locally.
- Do not send test messages to third-party websites.
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
DOM XSS via `postMessage()`

---

## Status
Unsolved

---

## Author
