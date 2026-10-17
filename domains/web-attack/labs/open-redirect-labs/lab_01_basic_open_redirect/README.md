# Lab 01 — Basic Open Redirect

## Objective
Learn the fundamentals of an Open Redirect vulnerability.
In this lab, a web application accepts a destination URL from the user and uses that value in a server-side redirect.
Your goal is to identify where the redirect destination comes from, trace the data flow, and determine whether you can control the final destination.

---

## Scenario
The application provides a redirect endpoint that accepts a `url` parameter.
For example:
    /redirect?url=/

The application reads the value of the `url` parameter and passes it to the redirect function.
Your task is to investigate whether the destination can be controlled by the user.

---

## Mission
Find the complete data flow:
    URL Parameter
        ↓
    request.args.get()
        ↓
    url
        ↓
    redirect(url)
        ↓
    HTTP Redirect
        ↓
    Browser
        ↓
    Destination

Determine whether the `url` parameter can be used to control the redirect destination.

---

## Hints
### Hint 1
Start by looking at how the application reads the URL parameter.
Look for:
    request.args.get()

---

### Hint 2
Find the parameter that controls the destination.
Look for:
    url

---

### Hint 3
Find where the value is passed to a redirect function.
Look for:
    redirect()

Ask yourself:
> What happens if the value passed to `redirect()` comes directly from the user?

---

### Hint 4
First test the application with its normal behavior.
Open:
    http://127.0.0.1:5000/

Then inspect the redirect endpoint.

---

### Hint 5
Try changing the destination to a harmless external website.
For example:
    https://example.com

Observe whether the browser leaves the local application.

---

## Goal
Demonstrate that the user-controlled `url` parameter can influence the destination of the server-side redirect.
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
When investigating this Lab, follow the redirect destination from its source to its final use.

### 1. Identify the Source
Find where the application receives the destination.
For example:
    request.args.get("url")

---

### 2. Identify the Parameter
Determine which URL parameter controls the redirect.
In this Lab:
    url

---

### 3. Track the Data
Follow the value after it is extracted.

Ask:
> Where is this value stored and where is it used?

---

### 4. Identify the Redirect Sink
Find the function responsible for redirecting the browser.
Look for:
    redirect()

---

### 5. Check for Validation
Ask:
- Is the destination validated?
- Is the hostname checked?
- Is the scheme checked?
- Is the destination restricted?
- Can an external URL be supplied?

---

### 6. Test Your Hypothesis
Use a harmless external destination and observe the browser's behavior.

---

## What You Should Learn
By completing this Lab, you should understand:
- What an Open Redirect vulnerability is
- How server-side redirects work
- How Flask's `redirect()` works
- How query parameters can control application behavior
- How to trace a user-controlled value
- What a redirect sink is
- How HTTP redirects affect browser navigation
- Why unvalidated redirect destinations are dangerous
- How to approach Open Redirect investigations

---

## Concepts Covered
- Open Redirect
- Server-Side Redirect
- HTTP Redirect
- HTTP 3xx Response
- `Location` Header
- Query Parameters
- `request.args.get()`
- Flask `redirect()`
- User-Controlled Destination
- Source-to-Sink Analysis
- URL Validation

---

## Security Impact
An Open Redirect can allow an attacker to create a trusted-looking URL that eventually sends a user to an external destination.
Depending on where the vulnerable redirect exists, it may be useful for:
- Phishing
- Social engineering
- Misleading users about the final destination
- Abuse of trusted application links
- Redirect manipulation
- Authentication-related attack scenarios

The actual impact depends on the application and where the redirect is used.

---

## Rules
- Run the Lab locally.
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
**Basic Server-Side Open Redirect**

---

## Status
**Unsolved**

---

## Author
****