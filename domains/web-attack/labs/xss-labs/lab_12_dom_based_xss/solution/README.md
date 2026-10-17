# Lab 12 — DOM XSS via document.write() — Solution

## 🎯 Vulnerability
This lab demonstrates a **DOM-based Cross-Site Scripting (DOM XSS)** vulnerability caused by using `document.write()` with user-controlled data.

The vulnerable pattern is:
    const name = new URLSearchParams(window.location.search).get("name") || "Guest";
    document.write(
        '<p class="text-slate-800">Hello, ' + name + '!</p>'
    );

The application takes data directly from the URL and writes it into the HTML document without safely encoding it.

---

## 🔍 Source
The user-controlled input comes from:
    window.location.search

The application extracts the `name` parameter using:
    new URLSearchParams(window.location.search).get("name")

Therefore, a URL such as:
    http://127.0.0.1:5000/?name=VALUE

allows the user to control the value of `name`.

---

## 🔄 Data Flow
The complete data flow is:
    URL Query Parameter
            ↓
    window.location.search
            ↓
    URLSearchParams
            ↓
    name
            ↓
    String Concatenation
            ↓
    document.write()
            ↓
    HTML Parser
            ↓
    DOM XSS

---

## ⚠️ Vulnerable Code
The vulnerable code is:
    const name = new URLSearchParams(window.location.search).get("name") || "Guest";
    document.write(
        '<p class="text-slate-800">Hello, ' + name + '!</p>'
    );

The problem is not `URLSearchParams`.
`URLSearchParams` simply reads the value.

The dangerous operation is sending the untrusted value to:
    document.write()

without applying an appropriate safe output mechanism.

---

## 🧠 Understanding the Source
The first important part is:
    window.location.search

This represents the query string of the current URL.

For example:
    http://127.0.0.1:5000/?name=

The query string is:
    ?name=

Then:
    URLSearchParams

allows JavaScript to retrieve the value associated with `name`.

So:
    get("name")

returns:
    

That value is completely controlled by the URL.

---

## 💥 Understanding the Sink
The next important part is:
    document.write()

`document.write()` writes a string directly into the HTML document.
In this lab, the application constructs HTML by concatenating a fixed HTML string with user-controlled data:
    '<p>Hello, ' + name + '!</p>'

This means the browser receives the resulting string and parses it as HTML.
If the attacker-controlled value contains HTML markup, the browser may interpret that markup instead of treating it as ordinary text.

---

## 🧪 Proof of Concept
A harmless local proof of concept is:
    <script>alert(1)</script>

When supplied through the `name` parameter, the resulting HTML conceptually becomes:
    <p class="text-slate-800">
        Hello,
        <script>alert(1)</script>
        !
    </p>

Because `document.write()` writes the resulting string as HTML, the browser can interpret the injected `<script>` element.
A successful alert demonstrates DOM-based XSS.

---

## 🌐 Example URL
For local testing, the concept is:
    http://127.0.0.1:5000/?name=<script>alert(1)</script>

Depending on the browser and URL handling, special characters may need to be URL-encoded.
For example, the encoded form can be used when necessary.

---

## 🔬 Why Does It Work?
The important distinction in this lab is:
    Source → Sink

The source is:
    window.location.search

The sink is:
    document.write()

The application does not send the value to the server for rendering.

Instead:
1. The browser loads the page.
2. JavaScript reads the URL.
3. JavaScript extracts the `name` parameter.
4. The value is concatenated into an HTML string.
5. `document.write()` writes that string into the document.
6. The browser parses the resulting HTML.

This makes the vulnerability **DOM-based XSS**.

---

## 🚨 Root Cause
The root cause is the use of a user-controlled URL value inside `document.write()`.
The vulnerable chain is:
    Untrusted URL Input
        +
    HTML String Construction
        +
    document.write()
        =
    DOM XSS

The application assumes that the value returned from the URL is safe.
However, URL parameters are untrusted input and should never automatically be considered safe.

---

## 🛡️ Mitigation
The safest approach is to avoid `document.write()` for displaying user-controlled data.
Instead, create an element and assign the value using `textContent`.
For example:
    const name = new URLSearchParams(window.location.search).get("name") || "Guest";
    const output = document.getElementById("output");
    const message = document.createElement("p");

    message.className = "text-slate-800";
    message.textContent = "Hello, " + name + "!";

    output.appendChild(message);

`textContent` treats the supplied value as text rather than HTML.
Therefore, HTML entered by the user will not be interpreted as executable markup.

---

## ✅ Secure Example
A safer implementation is:
    const name = new URLSearchParams(window.location.search).get("name") || "Guest";
    const output = document.getElementById("output");
    const message = document.createElement("p");

    message.className = "text-slate-800";
    message.textContent = `Hello, ${name}!`;

    output.appendChild(message);

The important difference is:
    document.write()

is replaced with:
    textContent

This changes how the browser treats the user-controlled value.

---

## 🔎 Investigation Methodology
When investigating DOM XSS, follow the data from **source to sink**.

### Step 1 — Find the Source
Look for browser-controlled input such as:
    location
    location.search
    location.hash
    document.URL
    document.referrer

In this lab:
    window.location.search

is the source.

---

### Step 2 — Find the Extraction
The application extracts the parameter using:
    URLSearchParams

Specifically:
    get("name")

Now we know that the attacker controls the resulting `name` value.

---

### Step 3 — Track the Variable
The data is stored in:
    const name = ...

Follow this variable through the rest of the JavaScript code.

---

### Step 4 — Find the Sink
Look for dangerous DOM APIs.
Examples include:
    innerHTML
    outerHTML
    document.write()
    insertAdjacentHTML()
    eval()

In this lab:
    document.write()

is the sink.

---

### Step 5 — Analyze the Context
Determine whether the sink interprets the data as:
    Text

or:
    HTML

`document.write()` writes a string into the document and the browser parses it as HTML.

---

### Step 6 — Test With a Harmless PoC
Use a harmless local payload to determine whether HTML markup is interpreted.
The goal is not simply to inject characters.

The goal is to understand:
    Source → Data Flow → Sink → Browser Interpretation

---

## 🔗 Vulnerability Chain
    window.location.search
            ↓
    URLSearchParams
            ↓
    name
            ↓
    String Concatenation
            ↓
    document.write()
            ↓
    HTML Parsing
            ↓
    Script Execution
            ↓
    DOM XSS

---

## 🧠 Important Distinction
This lab is different from a traditional reflected XSS vulnerability.

### Reflected XSS
The typical flow is:

    User
      ↓
    HTTP Request
      ↓
    Server
      ↓
    HTML Response
      ↓
    Browser

### DOM XSS
The flow in this lab is:
    User
      ↓
    URL
      ↓
    Browser
      ↓
    JavaScript
      ↓
    DOM Sink
      ↓
    XSS

The server does not need to reflect the malicious value.
The vulnerable behavior occurs entirely in the browser.

---

## 📚 Key Takeaways
### 1. URL parameters are untrusted input
Anything controlled by the user should be treated as untrusted.

---

### 2. DOM XSS can happen entirely on the client
The server does not necessarily need to process the malicious value.

---

### 3. `document.write()` is dangerous with untrusted data
When user-controlled data is passed to `document.write()`, the browser may interpret that data as HTML.

---

### 4. Always identify Source and Sink
A useful DOM XSS investigation technique is:

    Source → Data Flow → Sink

In this lab:

    Source:
    window.location.searchSink:
    document.write()

---

### 5. Prefer text-based DOM APIs
When displaying untrusted text, prefer:

    textContent

instead of HTML-parsing APIs such as:

    document.write()
    innerHTML

when HTML rendering is not actually required.

---

## 🧪 Lab Summary
**Lab:** 12  
**Category:** Cross-Site Scripting  
**Difficulty:** Medium  
**Type:** DOM-based XSS  
**Source:** `window.location.search`  
**Sink:** `document.write()`  
**Root Cause:** User-controlled URL input written as HTML

---

## 🎓 What This Lab Teaches
After completing this lab, you should understand:
- What DOM-based XSS is
- What a DOM XSS source is
- What a DOM XSS sink is
- How `window.location.search` can become attacker-controlled data
- How `URLSearchParams` extracts URL parameters
- Why `document.write()` can be dangerous
- How HTML string concatenation can create XSS
- How to trace data from source to sink
- Why `textContent` is safer for displaying untrusted text
- The difference between Reflected XSS and DOM XSS

---

## 👤 Author

Educational XSS laboratory for security learning and practice.