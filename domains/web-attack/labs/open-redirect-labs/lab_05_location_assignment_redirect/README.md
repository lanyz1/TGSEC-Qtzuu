# Lab 05 — Open Redirect via `window.location` Assignment

## Objective
Learn how assigning a user-controlled URL directly to `window.location` can introduce a Client-Side Open Redirect vulnerability.

In this lab, the application reads a destination from a URL query parameter and uses JavaScript to navigate the browser to that destination.

Your goal is to identify the source, trace the data flow, locate the navigation sink, and determine whether you can control the browser's final destination.

---

## Scenario
The application accepts a `destination` parameter in the URL.
For example:
    /?destination=/

JavaScript reads the parameter and assigns its value to `window.location`.
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
    params.get("destination")
            ↓
    destination
            ↓
    window.location = destination
            ↓
    Browser Navigation
            ↓
    Final Destination

Determine whether the `destination` parameter can control the browser's final destination.

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
    destination

Ask yourself:
> Where does this value come from, and can the user control it?

### Hint 4
Find where the extracted value is used for browser navigation.
Look for:
    window.location

Pay attention to how it is used.

### Hint 5
Test the application's normal behavior first.
Open:
    http://127.0.0.1:5000/

Then investigate what happens when you add a `destination` parameter.

### Hint 6
Try changing the destination to a harmless external website.
For example:
    https://example.com

Observe whether the browser navigates away from the local application.

---

## Goal
Demonstrate whether the user-controlled `destination` parameter can influence the browser's navigation destination.
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
    destination

### 3. Track the Data
Follow the value after it is extracted.
Look for:
    params.get("destination")

Determine where the resulting value is stored and whether any validation occurs.

### 4. Identify the Navigation Sink
Find the JavaScript statement responsible for navigation.
Investigate:
    window.location = destination

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
- How assigning a value to `window.location` performs navigation
- How `window.location.search` exposes query parameters
- How `URLSearchParams` extracts user-controlled values
- How to trace data from a source to a navigation sink
- How direct location assignment compares with other navigation methods
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
- `window.location`
- Direct Location Assignment
- Browser Navigation
- User-Controlled Input
- Navigation Sink
- Source-to-Sink Analysis
- URL Validation

---

## Comparison with Previous Labs
These labs demonstrate similar vulnerability patterns using different navigation mechanisms.

### Lab 02
    window.location.href = next;

### Lab 03
    window.location.assign(destination);

### Lab 04
    window.location.replace(destination);

### Lab 05
    window.location = destination;

All four mechanisms can navigate the browser.

The main lesson is that different JavaScript navigation mechanisms can expose the same underlying security issue when they receive unvalidated user-controlled URLs.

---

## Security Impact
An Open Redirect can allow an attacker to create a trusted-looking URL that eventually sends a user to an external destination.
Depending on the application's functionality, potential impacts include:
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
**Client-Side Open Redirect via Direct `window.location` Assignment**

---

## Status
**Unsolved**

---

## Author
****