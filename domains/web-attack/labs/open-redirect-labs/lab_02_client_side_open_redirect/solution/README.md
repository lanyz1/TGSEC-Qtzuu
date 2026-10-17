# Solution — Lab 02: Basic Client-Side Open Redirect

## Vulnerability
This lab contains a **Client-Side Open Redirect** vulnerability.
The application reads the `next` parameter from the URL using JavaScript and assigns the user-controlled value directly to:
    window.location.href

Because there is no validation of the destination, an attacker can control where the browser navigates.

---

## Source
The source of the untrusted data is the URL query parameter:
    next

The application reads it using:
    const params = new URLSearchParams(window.location.search);
    const next = params.get("next");

This means the value of `next` is controlled by the user.

---

## Data Flow
The complete vulnerability flow is:
    URL Query Parameter
            ↓
    window.location.search
            ↓
    URLSearchParams
            ↓
    params.get("next")
            ↓
    next
            ↓
    window.location.href
            ↓
    Browser Navigation
            ↓
    User-Controlled Destination

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const next = params.get("next");
    if (next) {
        window.location.href = next;
    }

The application does not verify whether `next` points to a trusted destination.

---

## Context
This is a **client-side navigation context**.
Unlike a server-side redirect, the redirect decision is made entirely by JavaScript running in the browser.
There is no Flask `redirect()` call involved.
The browser receives the page normally, JavaScript reads the URL parameter, and then JavaScript changes the current location.

---

## Sink
The security-sensitive sink is:
    window.location.href

Assigning a URL to `window.location.href` causes the browser to navigate to that destination.
The problem is that the value assigned to it comes directly from user-controlled input.

---

## Proof of Concept
The vulnerable parameter is:
    next

A harmless proof of concept is:
    http://127.0.0.1:5000/?next=https://example.com

The browser loads the local application, JavaScript reads the `next` parameter, and then navigates to:
    https://example.com

This demonstrates that the user controls the final destination.

---

## Why This Is an Open Redirect
An Open Redirect occurs when an application allows an attacker to control a navigation destination without properly validating it.
In this lab:
    User-Controlled URL
            ↓
        next parameter
            ↓
      JavaScript reads it
            ↓
    window.location.href
            ↓
    External Destination

The application effectively acts as a redirector.
The important point is that the redirect happens on the client side rather than through an HTTP 3xx response from the server.

---

## Server-Side vs Client-Side Redirect

### Lab 01
Lab 01 used a server-side redirect:
    User Input
        ↓
    Flask
        ↓
    redirect(url)
        ↓
    HTTP 302
        ↓
    Location Header
        ↓
    Browser

### Lab 02
Lab 02 uses a client-side redirect:
    User Input
        ↓
    URL Parameter
        ↓
    JavaScript
        ↓
    window.location.href
        ↓
    Browser Navigation

Both can result in an attacker-controlled destination, but the mechanism is different.

---

## Root Cause
The root cause is the direct use of untrusted input in a navigation sink.
The application effectively does:
    user_input → window.location.href

without performing destination validation.

There is no:
- Allowlist
- Origin validation
- Hostname validation
- Scheme validation
- Relative-path restriction

---

## Security Impact
The impact of an Open Redirect depends on how the vulnerable endpoint is used.
Potential consequences include:
- Phishing
- Social engineering
- Trusted-link abuse
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication or login flows

An attacker may be able to create a URL that appears to belong to the trusted application while ultimately sending the victim somewhere else.

---

## Mitigation
The safest approach is to avoid accepting arbitrary destinations whenever possible.
Prefer predefined internal destinations.
For example:
    const destinations = {
        home: "/",
        dashboard: "/dashboard",
        profile: "/profile"
    };

    const params = new URLSearchParams(window.location.search);
    const target = params.get("next");

    if (target && destinations[target]) {
        window.location.href = destinations[target];
    }

Instead of allowing:
    next=https://example.com

the application accepts a controlled key such as:
    next=dashboard

and maps that key to a known internal destination.

---

## Relative Path Validation
If the application genuinely needs to support user-controlled internal paths, the destination should be validated carefully.
For example, an application may restrict navigation to paths within its own origin.

A basic conceptual approach is:
    const target = new URL(next, window.location.origin);
    if (target.origin === window.location.origin) {
        window.location.href = target.pathname + target.search + target.hash;
    }

The exact validation strategy should depend on the application's requirements.

---

## Important Security Consideration
Simply checking whether a URL starts with a trusted string is not a reliable validation strategy.
For example, logic such as:
    if (next.startsWith("https://trusted.example.com")) {
        ...
    }

can be dangerous if implemented without proper URL parsing and origin validation.

URL validation should consider:
- Scheme
- Hostname
- Port
- Origin
- Relative vs absolute URLs

Use structured URL parsing rather than simple string matching.

---

## Investigation Methodology
When investigating a client-side Open Redirect, follow these steps.

### 1. Identify User-Controlled Input
Look for values coming from:
    window.location.search
    window.location.hash
    window.location.pathname
    URLSearchParams

---

### 2. Identify the Parameter
Determine which parameter controls navigation.
In this lab:
    next

---

### 3. Track the Data
Follow the value through the JavaScript code.
In this lab:
    params.get("next")
        ↓
    next

---

### 4. Identify the Navigation Sink
Look for browser navigation APIs such as:
    window.location.href

Other potentially relevant navigation mechanisms include:
    window.location.assign()
    window.location.replace()

---

### 5. Check for Validation
Ask:
- Is the destination validated?
- Is the origin checked?
- Is the hostname trusted?
- Is the scheme restricted?
- Are external destinations allowed?
- Can the user control the complete URL?

---

### 6. Test Your Hypothesis
Use a harmless destination such as:
    https://example.com

and observe whether the browser leaves the local application.

---

## Vulnerability Chain
The complete vulnerability chain is:
    Query Parameter
          ↓
    User-Controlled Input
          ↓
    URLSearchParams
          ↓
    next
          ↓
    window.location.href
          ↓
    Browser Navigation
          ↓
    External Destination

The key security boundary is crossed when untrusted input reaches the navigation sink without validation.

---

## Key Takeaways
- Open Redirects are not limited to server-side redirects.
- JavaScript can introduce Open Redirect vulnerabilities.
- `window.location.href` is a navigation sink.
- URL query parameters are user-controlled input.
- `URLSearchParams` does not validate the destination.
- Reading a parameter and using it in navigation without validation is dangerous.
- Allowlisting known destinations is generally safer than accepting arbitrary URLs.
- URL parsing is safer than simple string-based validation.
- Client-side and server-side redirects use different mechanisms but can have similar security consequences.

---

## Lab Summary
**Lab:** 02
**Name:** Basic Client-Side Open Redirect
**Category:** Open Redirect
**Vulnerability Type:** Client-Side Open Redirect
**Difficulty:** Easy
**Source:**
    URL Query Parameter → next

**Sink:**
    window.location.href

**Primary Issue:**
    Unvalidated user-controlled navigation

---

## What This Lab Teaches
This lab demonstrates how a seemingly simple JavaScript navigation feature can become a security vulnerability when it trusts user-controlled URL parameters.

The most important lesson is to recognize the pattern:
    User Input → Navigation Sink

and then determine whether the application properly restricts the destination.

---

## Author
****