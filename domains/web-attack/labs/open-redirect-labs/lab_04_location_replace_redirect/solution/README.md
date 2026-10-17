# Solution — Lab 04: Open Redirect via `window.location.replace()`

## Vulnerability
This lab contains a **Client-Side Open Redirect** vulnerability.
The application reads the `returnTo` parameter from the URL and passes the user-controlled value directly to:
    window.location.replace()

Because the destination is not validated, a user can control where the browser navigates.

---

## Source
The source of the untrusted data is the URL query parameter:
    returnTo

The application retrieves it using:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("returnTo");

The value of `returnTo` is controlled by the user.

---

## Data Flow
The complete vulnerability flow is:
    URL Query Parameter
            ↓
    window.location.search
            ↓
    URLSearchParams
            ↓
    params.get("returnTo")
            ↓
    destination
            ↓
    window.location.replace()
            ↓
    Browser Navigation
            ↓
    User-Controlled Destination

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("returnTo");

    if (destination) {
        window.location.replace(destination);
    }

The application uses the value directly without validating whether the destination is trusted.

---

## Context
This is a **Client-Side Navigation** vulnerability.
Unlike a server-side redirect, the application does not return an HTTP 3xx response to redirect the browser.
Instead, JavaScript reads the query parameter and performs navigation using:
    window.location.replace()

The security issue is not the method itself. The problem is passing untrusted input to a navigation sink without appropriate validation.

---

## Sink
The security-sensitive sink is:
    window.location.replace()

This method navigates the browser to the specified URL and replaces the current session-history entry.
As a result, pressing the browser's Back button generally will not return the user to the page that was replaced.
However, this history behavior is separate from the security vulnerability.
The Open Redirect exists because the destination is controlled by untrusted input.

---

## Proof of Concept
The vulnerable parameter is:
    returnTo

A harmless proof of concept is:
    http://127.0.0.1:5000/?returnTo=https://example.com

When the page loads:
1. JavaScript reads the query string.
2. `URLSearchParams` extracts the `returnTo` value.
3. The value is stored in `destination`.
4. `window.location.replace()` navigates the browser to the supplied URL.

The final destination becomes:
    https://example.com

This demonstrates that the user can control the destination.

---

## Why This Is an Open Redirect
An Open Redirect occurs when an application allows an untrusted user to influence a navigation destination without sufficient validation.

In this lab:
    User-Controlled URL
            ↓
    returnTo parameter
            ↓
    URLSearchParams
            ↓
    destination
            ↓
    window.location.replace()
            ↓
    External Destination

The application acts as a client-side redirector.
The same vulnerability pattern can exist with different parameter names and different navigation methods.

---

## Understanding `window.location.replace()`

The following example navigates to another page:
    window.location.replace("/dashboard");

The browser navigates to `/dashboard` and replaces the current history entry.

An absolute URL can also be used:
    window.location.replace("https://example.com");

The method is not inherently vulnerable.
The security problem arises when the destination comes from untrusted input and the application fails to restrict where the browser can navigate.

---

## Comparison with Other Navigation Methods
### Lab 02 — `window.location.href`
    window.location.href = next;

Navigates to a new URL and generally creates a history entry.

### Lab 03 — `window.location.assign()`
    window.location.assign(destination);

Navigatesto a new URL and generally creates a history entry.

### Lab 04 — `window.location.replace()`
    window.location.replace(destination);

Navigates to a new URL while replacing the current history entry.

All three mechanisms can contribute to an Open Redirect vulnerability if an untrusted destination reaches them without adequate validation.

---

## Root Cause
The root cause is the direct use of a user-controlled value in a navigation sink.
The vulnerable pattern is:
    User Input
        ↓
    destination
        ↓
    window.location.replace()

The application does not restrict the destination to trusted locations.

Missing security controls include:
- Destination allowlisting
- Origin validation
- Hostname validation
- Scheme validation
- Restriction to approved internal paths

---

## Security Impact
The impact depends on the application and the context in which the redirect is used.
Potential consequences include:
- Phishing
- Social engineering
- Abuse of trusted application links
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication-related flows

An attacker may construct a URL that appears to belong to a trusted application but ultimately navigates the victim to an external website.

The presence of an Open Redirect does not automatically mean that every listed impact is achievable; the actual risk depends on the application's behavior and surrounding security controls.

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
    const target = params.get("returnTo");

    if (target && destinations[target]) {
        window.location.replace(destinations[target]);
    }

In this example, the user supplies a key such as:
    returnTo=dashboard

The application maps that key to a known internal path rather than accepting an arbitrary URL.

---

## Same-Origin Validation
If the application needs to accept internal paths, it can parse and validate the destination before navigating.
For example:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("returnTo");
    if (destination) {
        try {
            const target = new URL(
                destination,
                window.location.origin
            );

            if (target.origin === window.location.origin) {
                window.location.replace(
                    target.pathname + target.search + target.hash
                );
            }
        } catch {
            // Reject invalid URLs.
        }
    }

This example restricts navigation to the current origin.

The exact validation logic should reflect the application's requirements. Applications that accept only internal paths can use a stricter path-based allowlist.

---

## Avoid Simple String Checks
Do not rely solely on checks such as:
    destination.startsWith("https://trusted.example.com")

Simple string matching can incorrectly classify URLs.

Use structured URL parsing and validate the properties that matter, including:
- Scheme
- Hostname
- Port
- Origin
- Relative versus absolute URLs

An explicit allowlist of approved destinations is generally easier to reason about and maintain.

---

## Investigation Methodology
When investigating a Client-Side Open Redirect, follow the data from its source to its final use.

### 1. Identify the Source
Look for data obtained from the current URL, such as:
    window.location.search
    window.location.hash
    window.location.pathname
    URLSearchParams

---

### 2. Identify the Parameter
Determine which query parameter controls the destination.
In this lab:
    returnTo

---

### 3. Track the Data
Follow the value after it is extracted:
    params.get("returnTo")
            ↓
    destination

Determine whether any transformation or validationoccurs before the value is used.

---

### 4. Identify the Navigation Sink
Look for browser navigation APIs, including:
    window.location.href
    window.location.assign()
    window.location.replace()

In this lab, the sink is:
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
- Does the validation reject malformed or unexpected URLs?

---

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
    returnTo
          ↓
    destination
          ↓
    window.location.replace()
          ↓
    Browser Navigation
          ↓
    External Destination

The security issue occurs when untrusted input reaches the navigation sink without sufficient destination validation.

---

## Key Takeaways
- `window.location.replace()` is a browser navigation method.
- It replaces the current history entry during navigation.
- Its history behavior does not itself create an Open Redirect vulnerability.
- The vulnerability arises when an untrusted destination reaches a navigation sink without validation.
- `URLSearchParams` extracts query parameters but does not validate their destinations.
- Different navigation methods can produce the same underlying vulnerability pattern.
- Allowlisting known destinations is generally safer than accepting arbitrary URLs.
- Proper URL parsing is preferable to simplistic string matching.
- Source-to-sink analysis helps identify client-side redirect vulnerabilities.

---

## Lab Summary
**Lab:** 04
**Name:** Open Redirect via `window.location.replace()`
**Category:** Open Redirect
**Vulnerability Type:** Client-Side Open Redirect
**Difficulty:** Easy

**Source:**
    URL Query Parameter → returnTo

**Sink:**
    window.location.replace()

**Primary Issue:**
    Unvalidated user-controlled navigation

---

## What This Lab Teaches
This lab demonstrates how `window.location.replace()` can become an Open Redirect sink when it receives a user-controlled destination.

It also highlights the difference between navigation methods that generally add a history entry and methods that replace the current history entry.

The central security pattern remains:
    User Input → Navigation Sink

The next step in any investigation is to determine whether the destination is properly validated.

---

## Author
****