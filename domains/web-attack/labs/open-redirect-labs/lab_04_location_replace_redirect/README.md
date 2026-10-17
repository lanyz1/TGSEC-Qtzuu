# Lab 04 — Open Redirect via `window.location.replace()`

## Objective
Learn how `window.location.replace()` can introduce a Client-Side Open Redirect vulnerability when it uses an unvalidated, user-controlled URL.

In this lab, the application reads a destination from a URL query parameter and passes that value directly to a JavaScript navigation method.

Your goal is to identify the source, trace the data flow, locate the navigation sink, and determine whether you can control the browser's final destination.

---

## Scenario
The application accepts a `returnTo` parameter in the URL.
For example:
    /?returnTo=/

JavaScript reads the parameter and uses its value to navigate the browser.
Your task is to investigate how the destination is processed and determine whether an external URL can be supplied.

---

## Mission
Trace the complete data flow:
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
    Destination

Determine whether the `returnTo` parameter can control the browser's final destination.

---

## Hints
### Hint 1
Start by looking for JavaScript that reads the current URL.
Look for:
    window.location.search

### Hint 2
Find the API responsible for extracting query parameters.
Look for:
    URLSearchParams

### Hint 3
Identify the parameter that controls the destination.
Look for:
    returnTo

Ask yourself:
> Where does this value come from, and can the user control it?

### Hint 4
Find where the extracted value is used for browser navigation.
Look for:
    window.location.replace()

### Hint 5
Test the application's normal behavior first.
Open:
    http://127.0.0.1:5000/

Then inspect how the application behaves when you add a `returnTo` parameter.

### Hint 6
Try changing the destination to a harmless external website.
For example:
    https://example.com

Observe whether the browser navigates away from the local application.

---

## Goal
Demonstrate whether the user-controlled `returnTo` parameter can influence the browser's navigation destination.
Use harmless destinations and test only this intentionally vulnerable local application.

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
Follow the user-controlled value from its source to the navigation sink.

### 1. Identify the Source
Find where the application reads information from the current URL.
Look for:
    window.location.search

### 2. Identify the Parameter
Determine which query parameter controls navigation.
In this lab:
    returnTo

### 3. Track the Data
Follow the value after it is extracted.
Look for:
    params.get("returnTo")

Determine where the resulting value is stored and whether it undergoes any validation.

### 4. Identify the Navigation Sink
Find the JavaScript method responsible for navigation.
Look for:
    window.location.replace()

### 5. Check for Validation
Ask yourself:
- Is the destination validated?
- Is the origin checked?
- Is the hostname checked?
- Is the URL scheme restricted?
- Are external destinations allowed?
- Can the user control the complete URL?

### 6. Test Your Hypothesis
Use a harmless external destination and observe the browser's behavior.

---

## What You Should Learn
By completing this lab, you should understand:
- What a Client-Side Open Redirect is
- How `window.location.replace()` performs navigation
- How `window.location.search` exposes query parameters
- How `URLSearchParams` extracts user-controlled values
- How to trace data from a source to a navigation sink
- How `window.location.replace()` differs from `window.location.href`
- Why unvalidated navigation destinations are dangerous
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
- `window.location.replace()`
- Browser Navigation
- User-Controlled Input
- Navigation Sink
- Source-to-Sink Analysis
- URL Validation
- Browser History

---

## Lab 02 vs Lab 03 vs Lab 04
These labs demonstrate the same general vulnerability pattern through different JavaScript navigation methods.

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

### Lab 04
    User Input
        ↓
    returnTo
        ↓
    window.location.replace()
        ↓
    Browser Navigation

The important lesson is that the navigation method can change while the underlying security issue remains the same.

---

## Security Impact
An Open Redirect can allow an attacker to create a trusted-looking URL that eventually sends a user to an external destination.
Depending on the application and its functionality, potential impacts include:
- Phishing
- Social engineering
- Abuse of trusted application links
- Misleading users about the final destination
- Redirect manipulation
- Abuse of authentication-related flows

The actual impact depends on the application's design and surrounding security controls.

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
**Client-Side Open Redirect via `window.location.replace()`**

---

## Status
**Unsolved**

---

## Author
****