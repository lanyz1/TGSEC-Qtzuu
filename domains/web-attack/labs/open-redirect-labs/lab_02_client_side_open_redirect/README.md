# Lab 02 — Basic Client-Side Open Redirect

## Objective
Learn how an Open Redirect vulnerability can occur entirely on the client side through JavaScript.
In this lab, the application reads a destination from a URL query parameter and uses that value to control browser navigation.
Your goal is to identify the source of the user-controlled value, trace it through the JavaScript code, and determine whether you can control the final destination.

---

## Scenario
The application accepts a `next` parameter in the URL.
For example:
    /?next=/

The page uses JavaScript to read the `next` parameter and navigate the browser to that destination.
Your task is to investigate how the parameter is processed and determine whether an external destination can be supplied.

---

## Mission
Find the complete data flow:
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
    Destination

Determine whether the `next` parameter can be used to control the browser's final destination.

---

## Hints
### Hint 1
Start by looking for JavaScript that reads the current URL.
Look for:
    window.location.search

---

### Hint 2
Look for code that extracts query parameters.
A useful API to investigate is:
    URLSearchParams

---

### Hint 3
Find the parameter that controls the destination.
Look for:
    next

Ask yourself:
> Where does this value come from?

---

### Hint 4
Look for a browser navigation sink.
Common examples include:
    window.location.href
    window.location.assign()
    window.location.replace()

---

### Hint 5
First test the normal application behavior.
Open:
    http://127.0.0.1:5000/

Then inspect how the application behaves when a `next` parameter is added.

---

### Hint 6
Try changing the destination to a harmless external website.
For example:
    https://example.com

Observe whether the browser leaves the local application.

---

## Goal
Demonstrate that the user-controlled `next` parameter can influence the browser's navigation destination.
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
    next

---

### 3. Track the Data
Follow the parameter after it is extracted.
Look for:
    URLSearchParams

and:
    params.get("next")

---

### 4. Identify the Navigation Sink
Find where the value is used to navigate the browser.
Look for:
    window.location.href

---

### 5. Check for Validation
Ask:
- Is the destination validated?
- Is the hostname checked?
- Is the origin checked?
- Is the scheme restricted?
- Are external URLs allowed?
- Can the user control the complete destination?

---

### 6. Test Your Hypothesis
Use a harmless external destination and observe the browser's behavior.

---

## What You Should Learn
By completing this lab, you should understand:
- What a Client-Side Open Redirect is
- How JavaScript can control browser navigation
- How `window.location.search` exposes URL parameters
- How `URLSearchParams` reads query parameters
- How user-controlled data reaches a navigation sink
- How `window.location.href` performs navigation
- The difference between client-side and server-side redirects
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
- `window.location.href`
- Browser Navigation
- User-Controlled Input
- Navigation Sink
- Source-to-Sink Analysis
- URL Validation

---

## Client-Side vs Server-Side Redirect
This lab uses a different mechanism from Lab 01.

### Lab 01
The redirect happens on the server:
    User Input
        ↓
    Flask
        ↓
    redirect()
        ↓
    HTTP 302
        ↓
    Location Header
        ↓
    Browser

### Lab 02
The redirect happens in the browser:
    User Input
        ↓
    URL Parameter
        ↓
    JavaScript
        ↓
    window.location.href
        ↓
    Browser Navigation

Understanding this difference is important when investigating Open Redirect vulnerabilities.

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
**Basic Client-Side Open Redirect**

---

## Status
**Unsolved**

---

## Author
****