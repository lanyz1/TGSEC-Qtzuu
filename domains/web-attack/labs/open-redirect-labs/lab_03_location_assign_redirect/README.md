# Lab 03 — Open Redirect via `window.location.assign()`

## Objective
Learn how `window.location.assign()` can be used as a client-side navigation mechanism and how improper handling of user-controlled URLs can lead to an Open Redirect vulnerability.
In this lab, the application reads a destination from a URL query parameter and passes that value directly to `window.location.assign()`.

Your goal is to identify the source, trace the data flow, find the navigation sink, and determine whether you can control the final destination.

---

## Scenario
The application accepts a `redirect` parameter in the URL.
For example:
    /?redirect=/

The application uses JavaScript to read the parameter and navigate the browser to the specified destination.
Your task is to investigate how the value is processed and determine whether an external destination can be supplied.

---

## Mission
Find the complete data flow:
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
    Destination

Determine whether the `redirect` parameter can control the browser's final destination.

---

## Hints
### Hint 1
Start by looking for JavaScript that reads the current URL.
Look for:
    window.location.search

---

### Hint 2
Find the code that extracts query parameters.
Look for:
    URLSearchParams

---

### Hint 3
Identify the parameter that controls the destination.
Look for:
    redirect

Ask yourself:
> Where does this value come from?

---

### Hint 4
Find where the extracted value is used for browser navigation.
Look for:
    window.location.assign()

---

### Hint 5
First test the application's normal behavior.
Open:
    http://127.0.0.1:5000/

Then try adding the `redirect` parameter.

---

### Hint 6
Try changing the destination to a harmless external website.
For example:
    https://example.com

Observe whether the browser leaves the local application.

---

## Goal
Demonstrate that the user-controlled `redirect` parameter can influence the browser's navigation destination.
Use only harmless destinations and test the vulnerability against this intentionally vulnerable local application.

---

## Running the Lab
Install the required dependency:
    pip install -r requirements.txt

Run the application:
    python app.py

Then open:
    http://127.0.0.1:5000/

---

## Investigation Methodology
When investigating this lab, trace the user-controlled value from its source to the navigation sink.

### 1. Identify the Source
Find where the application receives information from the current URL.
Look for:
    window.location.search

---

### 2. Identify the Parameter
Determine which query parameter controls navigation.
In this lab:
    redirect

---

### 3. Track the Data
Follow the parameter after it is extracted.
Look for:
    params.get("redirect")

Then determine where the resulting value is stored.

---

### 4. Identify the Navigation Sink
Find the JavaScript API responsible for navigation.
Look for:
    window.location.assign()

---

### 5. Check for Validation
Ask:
- Is the destination validated?
- Is the origin checked?
- Is the hostname checked?
- Is the scheme restricted?
- Are external URLs allowed?
- Can the user control the complete destination?

---

### 6. Test Your Hypothesis
Use a harmless external destination and observe the browser's behavior.
For example:
    https://example.com

---

## What You Should Learn
By completing this lab, you should understand:
- What a Client-Side Open Redirect is
- How `window.location.assign()` performs browser navigation
- How `window.location.search` exposes query parameters
- How `URLSearchParams` reads user-controlled values
- How to trace data from a source to a navigation sink
- Why unvalidated navigation destinations are dangerous
- How `window.location.assign()` differs from `window.location.href`
- How to investigate client-side redirect vulnerabilities

---

## Concepts Covered
- Open Redirect
- Client-Side Open Redirect
- JavaScript Navigation
- `window.location.search`
- `URLSearchParams`
- Query Parameters
- `params.get()`
- `window.location.assign()`
- Browser Navigation
- User-Controlled Input
- Navigation Sink
- Source-to-Sink Analysis
- URL Validation

---

## Lab 02 vs Lab 03
Both labs demonstrate Client-Side Open Redirect, but they use different navigation mechanisms.

### Lab 02
    User Input
        ↓
    next
        ↓
    window.location.href
        ↓
    Browser Navigation

### Lab 03
    User Input
        ↓
    redirect
        ↓
    window.location.assign()
        ↓
    Browser Navigation

The important lesson is that the navigation sink can change while the underlying vulnerability pattern remains the same.

---

## Security Impact
An Open Redirect can allow an attacker to create a trusted-looking URL that eventually sends a user to an external destination.
Depending on how the vulnerable functionality is used, potential impacts include:
- Phishing
- Social engineering
- Trusted-link abuse
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication-related flows

The actual impact depends on the application's functionality and where the redirect is used.

---

## Rules
- Run the lab locally.
- Test only the intentionally vulnerable application.
- Use harmless destinations.
- Do not test these techniques against websites you do not own.
- Do not perform unauthorized security testing.
- Focus on understanding the vulnerability and its root cause.

---

## Difficulty
**Easy**

---

## Category
**Open Redirect**

---

## Vulnerability Type
**Client-Side Open Redirect via `window.location.assign()`**

---

## Status
**Unsolved**

---

## Author
****