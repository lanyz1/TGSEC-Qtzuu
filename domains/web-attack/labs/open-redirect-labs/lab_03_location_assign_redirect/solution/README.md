# Solution — Lab 03: Open Redirect via `window.location.assign()`

## Vulnerability
This lab contains a **Client-Side Open Redirect** vulnerability.
The application reads the `redirect` parameter from the URL and passes the user-controlled value directly to:
    window.location.assign()

Because the destination is not validated, the user can control where the browser navigates.

---

## Source
The source of the untrusted data is the URL query parameter:
    redirect

The application retrieves it using:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("redirect");

The value of `redirect` is therefore controlled by the user.

---

## Data Flow
The complete vulnerability flow is:
    URL Query Parameter
            ↓
    window.location.search
            ↓
    URLSearchParams
            ↓
    params.get("redirect")
            ↓
    destination
            ↓
    window.location.assign()
            ↓
    Browser Navigation
            ↓
    User-Controlled Destination

---

## Vulnerable Code
The vulnerable code is:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("redirect");

    if (destination) {
        window.location.assign(destination);
    }

The application does not validate the destination before passing it to `window.location.assign()`.

---

## Context
This is a **Client-Side Navigation** vulnerability.
Unlike Lab 01, the server does not issue an HTTP redirect.

Unlike Lab 02, the application does not use:
    window.location.href

Instead, the browser navigation is performed with:
    window.location.assign()

The important security pattern remains the same:
    User-Controlled Input
            ↓
    Navigation Sink

---

## Sink
The security-sensitive sink is:
    window.location.assign()

`window.location.assign()` tells the browser to navigate to the specified URL.
If the URL comes directly from an untrusted source, the destination can potentially be controlled by the user.

---

## Proof of Concept
The vulnerable parameter is:
    redirect

A harmless proof of concept is:
    http://127.0.0.1:5000/?redirect=https://example.com

The browser loads the local application, JavaScript reads the `redirect` parameter, and then calls:
    window.location.assign("https://example.com")

The browser consequently navigates to:
    https://example.com

This demonstrates that the user controls the final destination.

---

## Why This Is an Open Redirect

An Open Redirect occurs when an application allows an untrusted user to control a navigation destination without properly validating it.

In this lab:
    User-Controlled URL
            ↓
    redirect parameter
            ↓
    URLSearchParams
            ↓
    destination
            ↓
    window.location.assign()
            ↓
    External Destination

The application therefore acts as a client-side redirector.

---

## `window.location.assign()` Explained
`window.location.assign()` is a browser navigation method.

For example:
    window.location.assign("/dashboard");

navigates the browser to `/dashboard`.

It can also navigate to an absolute URL:
    window.location.assign("https://example.com");

The method itself is not inherently dangerous.
The vulnerability appears when an attacker-controlled value is passed to it without proper validation.

---

## Comparison with Lab 02
Lab 02 used:
    window.location.href = next;

Lab 03 uses:
    window.location.assign(destination);

Both can perform browser navigation.
The important lesson is that Open Redirect vulnerabilities can appear through multiple navigation mechanisms.

The sink changed, but the underlying vulnerability pattern remains:
    Untrusted Input
            ↓
    Navigation Sink
            ↓
    Attacker-Controlled Destination

---

## Root Cause
The root cause is the direct flow of user-controlled data into a navigation function.
The application effectively performs:
    user_input → window.location.assign()

without validating whether the destination is trusted.There is no:
- Allowlist
- Origin validation
- Hostname validation
- Scheme restriction
- Relative-path restriction

---

## Security Impact
The impact of an Open Redirect depends on the application and where the redirect functionality is used.
Potential consequences include:
- Phishing
- Social engineering
- Trusted-link abuse
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication-related flows

For example, an attacker may create a URL belonging to a trusted application that eventually sends a victim to an external website.

---

## Mitigation
The safest approach is to avoid accepting arbitrary URLs whenever possible.
Use predefined destinations instead.
For example:
    const destinations = {
        home: "/",
        dashboard: "/dashboard",
        profile: "/profile"
    };

    const params = new URLSearchParams(window.location.search);
    const target = params.get("redirect");

    if (target && destinations[target]) {
        window.location.assign(destinations[target]);
    }

The user provides a controlled key such as:
    redirect=dashboard

instead of providing an arbitrary URL.

---

## Same-Origin Validation
If arbitrary internal paths are required, the application should validate the destination before navigation.
A conceptual approach is:
    const params = new URLSearchParams(window.location.search);
    const destination = params.get("redirect");

    if (destination) {
        const target = new URL(destination, window.location.origin);

        if (target.origin === window.location.origin) {
            window.location.assign(
                target.pathname + target.search + target.hash
            );
        }
    }

This approach restricts navigation to the same origin.
The exact validation strategy should depend on the application's requirements.

---

## Avoid Simple String Checks
Do not rely on simplistic checks such as:
    if (destination.startsWith("https://trusted.example.com")) {
        ...
    }

String-based validation can be misleading when dealing with URLs.
Validation should consider structured URL properties such as:
- Scheme
- Hostname
- Port
- Origin
- Relative vs absolute URLs

Using a proper URL parser is safer than relying only on string prefixes.

---

## Investigation Methodology
When investigating a Client-Side Open Redirect, follow the data from its source to the final navigation sink.

### 1. Identify the Source
Look for values coming from:
    window.location.search
    window.location.hash
    window.location.pathname
    URLSearchParams

---

### 2. Identify the Parameter
Determine which parameter controls the navigation.
In this lab:
    redirect

---

### 3. Track the Data
Follow the value after it is extracted.
In this lab:
    params.get("redirect")
            ↓
    destination

---

### 4. Identify the Navigation Sink
Look for browser navigation functions.
In this lab:
    window.location.assign()

Other navigation sinks worth recognizing include:
    window.location.href
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
    redirect
          ↓
    destination
          ↓
    window.location.assign()
          ↓
    Browser Navigation
          ↓
    External Destination

The security issue occurs because the user-controlled value reaches the navigation sink without proper validation.

---

## Key Takeaways
- Open Redirect vulnerabilities can occur entirely on the client side.
- `window.location.assign()` is a browser navigation mechanism.
- Navigation functions become security-sensitive when they receive untrusted input.
- `URLSearchParams` extracts values but does not validate their security.
- The parameter name does not matter; the data flow does.
- Different JavaScript APIs can act as navigation sinks.
- Allowlisting known destinations is generally safer than accepting arbitrary URLs.
- Same-origin validation can help restrict navigation to trusted destinations.
- Proper URL parsing is preferable to simplistic string matching.

---

## Lab Summary
**Lab:** 03
**Name:** Open Redirect via `window.location.assign()`
**Category:** Open Redirect
**Vulnerability Type:** Client-Side Open Redirect
**Difficulty:** Easy

**Source:**
    URL Query Parameter → redirect

**Sink:**
    window.location.assign()

**Primary Issue:**
    Unvalidated user-controlled navigation

---

## What This Lab Teaches
This lab demonstrates how `window.location.assign()` can become an Open Redirect sink when it receives a user-controlled URL.
The key pattern to recognize is:
    User Input → Navigation Sink

Once this pattern is identified, the next step is to determine whether the destination is properly validated.

---

## Author
****