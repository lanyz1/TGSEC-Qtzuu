# Solution — Lab 05: Open Redirect via `window.location` Assignment

## Vulnerability
This lab contains a **Client-Side Open Redirect** vulnerability.
The application reads the `destination` parameter from the URL and assigns the user-controlled value directly to:
    window.location = destination;

Because the destination is not validated, the user can influence where the browser navigates.

---

## Source
The source of the untrusted data is the URL query parameter:
    destination

The application retrieves it using:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("destination");

The value of `destination` is controlled by the user through the URL.

---

## Data Flow
The complete vulnerability flow is:
    URL Query Parameter
            ↓
    window.location.search
            ↓
    URLSearchParams
            ↓
    params.get("destination")
            ↓
    destination
            ↓
    window.location = destination
            ↓
    Browser Navigation
            ↓
    User-Controlled Destination

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("destination");

    if (destination) {
        window.location = destination;
    }

The application uses the value directly without validating whether the destination is trusted.

---

## Context
This is a **Client-Side Navigation** vulnerability.
The server serves the page normally. JavaScript then reads the query parameter and changes the browser's location.
Unlike Lab 01, this lab does not use Flask's `redirect()` function or rely on a server-generated HTTP 3xx response.
Instead, navigation occurs through a direct assignment to `window.location`.

---

## Sink
The security-sensitive sink is:
    window.location = destination;

Assigning a URL to `window.location` causes the browser to navigate to that URL.

The assignment itself is a legitimate browser feature. The vulnerability arises because the destination comes from untrusted input and is not validated.

---

## Proof of Concept
The vulnerable parameter is:
    destination

A harmless proof of concept is:
    http://127.0.0.1:5000/?destination=https://example.com

When the page loads:
1. JavaScript reads the query string.
2. `URLSearchParams` extracts the `destination` parameter.
3. The value is stored in the `destination` variable.
4. JavaScript assigns that value to `window.location`.
5. The browser navigates to the supplied URL.

The final destination becomes:
    https://example.com

This demonstrates that the user can control the browser's destination.

---

## Why This Is an Open Redirect
An Open Redirect occurs when an application allows an untrusted user to influence a navigation destination without sufficient validation.
In this lab:
    User-Controlled URL
            ↓
    destination parameter
            ↓
    URLSearchParams
            ↓
    destination variable
            ↓
    window.location assignment
            ↓
    External Destination

The application acts as a client-side redirector.
The critical issue is the unrestricted flow of user-controlled data into a navigation sink.

---

## Understanding `window.location`
`window.location` represents the current document's location.

Assigning a new URL to it initiates navigation:
    window.location = "/dashboard";

An absolute URL can also be assigned:
    window.location = "https://example.com";

Both examples demonstrate normal browser behavior.

The security issue appears when the destination is controlled by an untrusted user and the application does not restrict the permitted destinations.

---

## Comparison with Previous Labs
### Lab 02 — `window.location.href`
    window.location.href = next;

### Lab 03 — `window.location.assign()`
    window.location.assign(destination);

### Lab 04 — `window.location.replace()`
    window.location.replace(destination);

### Lab 05 — Direct `window.location` Assignment
    window.location = destination;

All four mechanisms can navigate the browser.

The primary difference in Lab 05 is the direct assignment to `window.location`. Its navigation behavior is broadly similar to assigning `window.location.href` or calling `window.location.assign()`.

The underlying security pattern remains the same:
    Untrusted Input
            ↓
    Navigation Sink
            ↓
    Browser Navigation

---

## Root Cause
The root cause is the direct use of user-controlled input as a navigation destination.
The vulnerable pattern is:
    User Input
        ↓
    destination
        ↓
    window.location = destination;

The application does not restrict navigation to approved destinations.

Missing security controls include:
- Destination allowlisting
- Origin validation
- Hostname validation
- Scheme validation
- Restriction to approved internal paths

---

## Security Impact
The impact depends on the application's functionality and the context in which the redirect occurs.
Potential consequences include:
- Phishing
- Social engineering
- Abuse of trusted application links
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication-related flows

An attacker may construct a URL that appears to belong to a trusted application but ultimately navigates the victim to an external website.

The actual impact depends on the application's design and surrounding security controls.

---

## Mitigation
The preferred approach is to avoid accepting arbitrary destinations.

Use a predefined mapping of approved destinations instead.
For example:
    const destinations = {
        home: "/",
        dashboard: "/dashboard",
        profile: "/profile"
    };

    const params = new URLSearchParams(window.location.search);
    const target = params.get("destination");

    if (target && destinations[target]) {
        window.location = destinations[target];
    }

In this example, the user supplies a controlled key such as:
    destination=dashboard

The application maps that key to a known internal path instead of accepting an arbitrary URL.

---

## Same-Origin Validation
If the application needs to accept internal paths, it can parse and validate the destination before navigating.
For example:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("destination");
    if (destination) {
        try {
            const target = new URL(
                destination,
                window.location.origin
            );

            if (target.origin === window.location.origin) {
                window.location = (
                    target.pathname +
                    target.search +
                    target.hash
                );
            }
        } catch {
            // Reject invalid URLs.
        }
    }

This example restricts navigation to the current origin.

The validation strategy should reflect the application's requirements. If only a few internal destinations are needed, an explicit allowlist is generally simpler and safer.

---

## Avoid Simple String Checks
Do not rely solely on checks such as:
    destination.startsWith("https://trusted.example.com")

Simple string matching can misclassify URLs.

Use structured URL parsing and validate the properties that matter, including:
- Scheme
- Hostname
- Port
- Origin
- Relative versus absolute URLs

An explicit allowlist of approved destinations is generally easier to reason about and maintain.

---

## Investigation Methodology
When investigating a Client-Side Open Redirect, follow the data from its source to the navigation sink.

### 1. Identify the Source
Look for data obtained from the current URL, such as:
    window.location.search
    window.location.hash
    window.location.pathname
    URLSearchParams

### 2. Identify the Parameter
Determine which query parameter controls the destination.
In this lab:
    destination

### 3. Track the Data
Follow the value after it is extracted:
    params.get("destination")
            ↓
    destination

Determine whether any transformation or validationoccurs before the value is used.

### 4. Identify the Navigation Sink
Look for browser navigation mechanisms, including:
    window.location.href
    window.location.assign()
    window.location.replace()
    window.location = destination

### 5. Check for Validation
Ask:
- Is the destination validated?
- Is the origin checked?
- Is the hostname trusted?
- Is the scheme restricted?
- Are external destinations allowed?
- Can the user control the complete URL?

### 6. Test Your Hypothesis
Use a harmless destination such as:
    https://example.com

Test only the intentionally vulnerable local application and observe the browser's navigation behavior.

---

## Vulnerability Chain
The complete vulnerability chain is:
    Query Parameter
          ↓
    User-Controlled Input
          ↓
    URLSearchParams
          ↓
    destination
          ↓
    window.location = destination
          ↓
    Browser Navigation
          ↓
    External Destination

The security issue occurs when untrusted input reaches the navigation sink without sufficient destination validation.

---

## Key Takeaways
- `window.location` can be used to navigate the browser.
- Direct assignment to `window.location` can introduce an Open Redirect vulnerability.
- The assignment itself is not inherently vulnerable.
- `URLSearchParams` extracts query parameters but does not validate their destinations.
- The parameter name does not determine whether a vulnerability exists; the data flow does.
- Different JavaScript navigation mechanisms can produce the same underlying security issue.
- Allowlisting known destinations is generally safer than accepting arbitrary URLs.
- Proper URL parsing is preferable to simplistic string matching.
- Source-to-sink analysis helps identify client-side redirect vulnerabilities.

---

## Lab Summary
**Lab:** 05
**Name:** Open Redirect via `window.location` Assignment
**Category:** Open Redirect
**Vulnerability Type:** Client-Side Open Redirect
**Difficulty:** Easy

**Source:**
    URL Query Parameter → destination

**Sink:**
    window.location = destination

**Primary Issue:**
    Unvalidated user-controlled navigation

---

## What This Lab Teaches
This lab demonstrates how a direct assignment to `window.location` can become an Open Redirect sink when it receives a user-controlled destination.

It reinforces the importance of identifying browser navigation mechanisms and tracing user-controlled input to its final use.

The central security pattern is:
    User Input → Navigation Sink

The next step in any investigation is to determine whether the destination is properly validated.

---

## Author
****