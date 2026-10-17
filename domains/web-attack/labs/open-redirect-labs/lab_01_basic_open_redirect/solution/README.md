# Solution — Lab 01: Basic Open Redirect

## Vulnerability
This lab contains a basic **Open Redirect** vulnerability.
The application accepts a user-controlled URL through the `url` query parameter and passes that value directly to Flask's `redirect()` function.
Because the destination is not validated, an attacker can control where the browser is redirected.

---

## Source
The source of the attacker-controlled data is the URL query parameter:
    ?url=

The application retrieves it using:
    request.args.get("url", "/")

This means the user can control the value of `url`.

---

## Data Flow
The complete data flow is:
    User Input
        ↓
    ?url=
        ↓
    request.args.get()
        ↓
    url
        ↓
    redirect(url)
        ↓
    HTTP 302 Response
        ↓
    Location Header
        ↓
    Browser
        ↓
    Destination

The important point is that the user-controlled value reaches the redirect function without validation.

---

## Vulnerable Code
The vulnerable code is:
    @app.route("/redirect")
    def redirect_user():
        url = request.args.get("url", "/")
        return redirect(url)

The application:
1. Reads the `url` parameter.
2. Stores it in `url`.
3. Passes it directly to `redirect()`.
4. Does not validate the destination.

---

## Understanding `redirect()`
Flask's `redirect()` function creates an HTTP redirect response.
For example:
    return redirect("/dashboard")

The browser receives a redirect response containing a `Location` header.

Conceptually:
    HTTP/1.1 302 Found
    Location: /dashboard

The browser then navigates to that location.

In this lab, the destination comes from user input:
    return redirect(url)

This is the security problem.

---

## Context
The vulnerable context is:
**Server-Side Redirect**

The attacker-controlled value is used as the destination of an HTTP redirect.
Unlike XSS, the application is not executing attacker-controlled JavaScript.
Instead, the vulnerability allows the attacker to influence the URL to which the browser is redirected.

---

## Sink
The security-sensitive operation is:
    redirect(url)

The `url` value is controlled by the user.
There is no validation restricting the destination.

Therefore:
    User-Controlled URL
            ↓
        redirect()
            ↓
       HTTP 302
            ↓
      Location Header
            ↓
         Browser

---

## Proof of Concept
A harmless proof of concept is to redirect the browser to:
    https://example.com

The vulnerable URL is:
    http://127.0.0.1:5000/redirect?url=https://example.com

When the application processes this request, Flask creates a redirect response.

The browser follows the redirect and navigates to:
    https://example.com

This demonstrates that the user controls the redirect destination.

---

## Root Cause
The root cause is the direct use of an untrusted URL in the redirect operation:
    url = request.args.get("url", "/")

followed by:
    return redirect(url)

There is no validation to determine whether the destination is trusted or allowed.
The application assumes that the supplied URL is safe.

---

## Why This Is an Open Redirect
The vulnerability exists because the application effectively behaves like this:
    /redirect?url=<user-controlled-destination>

The attacker can replace the destination with another URL.
For example:
    /redirect?url=https://example.com

The application does not distinguish between:
    /dashboard

and:
    https://example.com

Both values can be passed to `redirect()`.
The redirect destination is therefore controlled by the user.

---

## HTTP Redirect Flow
The browser sends:
    GET /redirect?url=https://example.com

The Flask application processes the request and responds with a redirect.
Conceptually:
    HTTP/1.1 302 FOUND
    Location: https://example.com

The browser sees the `Location` header and navigates to the specified destination.
The complete flow is:
    Browser
       ↓
    Flask Application
       ↓
    302 Redirect
       ↓
    Location: https://example.com
       ↓Browser
       ↓
    example.com

---

## Security Impact
The impact of an Open Redirect depends on where the vulnerable endpoint is used.
Possible security consequences can include:
- Phishing assistance
- Social engineering
- Abuse of trusted application URLs
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication-related flows
- Increased credibility of malicious links

The vulnerability itself does not automatically mean that JavaScript execution is possible.
Its primary issue is uncontrolled navigation.

---

## Why Trusted Domains Matter
Users often trust links that appear to belong to a known website.
For example:
    https://trusted.example/redirect?url=...

If the application allows arbitrary external destinations, the link may appear trustworthy while eventually sending the user somewhere else.
This is one reason Open Redirect vulnerabilities can be useful in phishing and social engineering scenarios.

---

## Secure Mitigation
The correct mitigation depends on the application's intended behavior.

### Option 1 — Use Relative Paths
If the application only needs to redirect users inside the same application, prefer relative paths.
For example:
    /dashboard

instead of allowing arbitrary external URLs.

---

### Option 2 — Allowlist Destinations
If external redirects are actually required, define an explicit allowlist of trusted destinations.
For example:
    https://trusted.example.com

Only destinations that satisfy the application's security policy should be accepted.

---

### Option 3 — Validate the Parsed URL
Do not rely only on simple string matching.
Parse the URL and validate the relevant components, such as:
- Scheme
- Hostname
- Port
- Path

The exact validation should match the application's intended trust boundary.

---

## Secure Example
If the application only needs to redirect to known internal pages, a safer approach is to map user-controlled values to predefined destinations.
For example:
    ALLOWED_DESTINATIONS = {
        "home": "/",
        "dashboard": "/dashboard",
        "profile": "/profile"
    }

Then:
    destination = request.args.get("next", "home")
    if destination not in ALLOWED_DESTINATIONS:
        destination = "home"

    return redirect(ALLOWED_DESTINATIONS[destination])

The user controls a key, not an arbitrary URL.

---

## Another Safe Approach
If only local paths are required, the application can enforce a policy that accepts only expected internal paths.

The important security principle is:
> Do not allow arbitrary user-controlled URLs when the application only needs internal navigation.

---

## Investigation Methodology
When investigating a possible Open Redirect, use the following process.

### 1. Find the Redirect Endpoint
Look for endpoints such as:
    /redirect
    /login
    /logout
    /continue
    /next
    /return

---

### 2. Identify Redirect Parameters
Look for parameters such as:
    url
    next
    redirect
    redirect_url
    return
    return_url
    destination
    target

---

### 3. Trace the Input
In this lab:
    request.args.get("url", "/")

is the source.

---

### 4. Follow the Value
The value is stored in:
    url

---

### 5. Find the Redirect Sink
The value reaches:
    redirect(url)

---

### 6. Check Validation
Ask:
    Is the URL validated?

In this lab, the answer is:
    No

---

### 7. Test a Harmless External Destination
Use a harmless destination such as:
    https://example.com

Then observe whether the browser leaves the local application.

---

### 8. Confirm the Data Flow
The final data flow should be:
    ?url=
       ↓
    request.args.get()
       ↓
    url
       ↓
    redirect(url)
       ↓
    302 Response
       ↓
    Location Header
       ↓
    Browser Navigation

---

## Vulnerability Chain
The complete vulnerability chain is:
    Attacker-Controlled Parameter
            ↓
        ?url=
            ↓
      request.args.get()
            ↓
           url
            ↓
       redirect(url)
            ↓
        HTTP 302↓
      Location Header
            ↓
          Browser
            ↓
    Attacker-Controlled Destination

---

## Key Takeaways
- Open Redirect occurs when a user can control a redirect destination.
- Query parameters are common sources of redirect destinations.
- Flask's `redirect()` creates an HTTP redirect response.
- The browser follows the `Location` header.
- `redirect()` is not inherently vulnerable.
- The vulnerability occurs when an untrusted destination reaches the redirect without appropriate validation.
- Open Redirect is different from XSS.
- The main impact is uncontrolled browser navigation.
- Relative paths are preferable when external redirects are unnecessary.
- Allowlisting is generally safer than trusting arbitrary destinations.
- URL validation should be based on the application's actual security requirements.
- Always trace the data from source to redirect sink.

---

## Lab Summary
**Lab:** 01
**Vulnerability:** Open Redirect
**Source:** `request.args.get("url")`
**Parameter:** `url`
**Sink:** `redirect(url)`
**Redirect Type:** Server-Side HTTP Redirect
**Root Cause:** User-controlled URL is passed directly to the redirect function without validation.
**Impact:** User-controlled browser navigation.
**Primary Mitigation:** Restrict redirects to trusted destinations or use predefined internal paths.

---

## What This Lab Teaches
This lab introduces the fundamental Open Redirect pattern:
    User Input
        ↓
    Redirect Parameter
        ↓
    Server-Side Redirect
        ↓
    Browser
        ↓
    User-Controlled Destination

The most important skill is learning to identify this source-to-sink relationship.
Once you understand this basic pattern, more advanced Open Redirect vulnerabilities can be analyzed by examining how the application parses, validates, and transforms the destination URL.

---

## Author
****