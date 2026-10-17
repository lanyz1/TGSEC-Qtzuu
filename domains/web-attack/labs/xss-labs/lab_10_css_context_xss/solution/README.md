# Lab 10 — CSS Context XSS | Solution

## Vulnerability
This lab demonstrates unsafe handling of user-controlled input inside a CSS context.
The application inserts the value of the `color` query parameter directly into an inline `style` attribute.
The important distinction is that this is primarily a **CSS Injection** issue rather than a guaranteed JavaScript-execution XSS in modern browsers.

---

## Source
The attacker-controlled input comes from the `color` query parameter.
The application retrieves the value using:
    color = request.args.get("color", "slate")

The value is then passed to the template:
    return render_template("index.html", color=color)

### Data Flow
    URL Parameter
         ↓
    request.args.get("color")
         ↓
    Flask
         ↓
    Jinja Template
         ↓
    style attribute
         ↓
    CSS Parser / Browser

---

## Vulnerable Code
The vulnerable code is:
    <div
        style="color: {{ color | safe }};"
    >
        This text uses your color input.
    </div>

The `| safe` filter disables Jinja's normal escaping.
As a result, attacker-controlled content is inserted directly into the CSS declaration.

---

## Context
The input is placed inside an inline CSS declaration:
    style="color: USER_INPUT;"

Therefore, the context is:
    CSS Context

More specifically, the value is being inserted into a CSS property value.

---

## Sink
The relevant sink is the inline `style` attribute:
    style="color: {{ color | safe }};"

The browser's CSS parser processes the resulting value.
Unlike the previous JavaScript-context labs, the browser is not automatically treating this value as JavaScript source code.

---

## Proof of Concept
A simple proof of concept is to supply a different CSS color:
    red

or:
    blue

This demonstrates that user input controls the CSS property.
A more useful injection test is to provide additional CSS syntax and observe whether the input can modify properties beyond the intended `color` value.

For example, conceptually:
    red; background: yellow

If the browser renders the element with both declarations, the input has escaped the intended logical value and injected an additional CSS declaration.

This demonstrates **CSS Injection**.

---

## Important Security Distinction
CSS Injection and XSS are not automatically the same vulnerability.
Historically, some browsers and legacy CSS features allowed CSS-based techniques that could result in script execution.
Modern browsers have significantly restricted these behaviors.
Therefore, an application allowing CSS injection does not necessarily mean that arbitrary JavaScript can be executed.

The security impact depends on:
- Browser behavior
- CSS features being used
- Where the injected CSS is placed
- What data the attacker can influence
- Whether the application exposes sensitive information through CSS-manipulable content

---

## Root Cause
The root cause is trusting user-controlled data as CSS:
    style="color: {{ color | safe }};"

The application expects a simple color value such as:
    red

or:
    #7c3aed

but does not enforce that expectation.
Because `| safe` disables Jinja escaping, the browser receives the supplied value as part of the CSS source.

---

## Why `| safe` Is Dangerous
The Jinja `safe` filter tells the template engine to treat the value as trusted.
For example:
    {{ color | safe }}

allows characters supplied by the user to reach the generated HTML without normal Jinja escaping.
When the value is placed inside a CSS context, blindly trusting it can allow an attacker to manipulate the CSS syntax.

---

## Mitigation
### 1. Do Not Trust Arbitrary CSS Input
If the application only needs a color, do not accept arbitrary CSS.
Define the expected input format.

For example, allow only a known set of colors:
    red
    blue
    green
    black
    white

---

### 2. Use an Allowlist
A simple server-side allowlist can be used:
    ALLOWED_COLORS = {
        "red",
        "blue",
        "green",
        "black",
        "white"
    }

Then reject values outside the allowlist.
Conceptually:
    if color not in ALLOWED_COLORS:
        color = "black"

This is much safer than allowing arbitrary CSS syntax.

---

### 3. Avoid `| safe`
Instead of:
    style="color: {{ color | safe }};"

use normal template escaping:
    style="color: {{ color }};"

However, escaping alone should not be treated as the complete solution when the application expects a restricted CSS value.
Input validation or allowlisting should enforce what the application actually expects.

---

## Secure Example
A safer Flask implementation could use an allowlist:
    from flask import Flask, request, render_template

    app = Flask(__name__)

    ALLOWED_COLORS = {
        "red",
        "blue",
        "green",
        "black",
        "white"
    }


    @app.route("/")
    def index():
        color = request.args.get("color", "black")

        if color not in ALLOWED_COLORS:
            color = "black"

        return render_template("index.html", color=color)


    if __name__ == "__main__":
        app.run(debug=True)

And the template can use normal escaping:
    <div style="color: {{ color }};">
        This text uses your color input.
    </div>

---

## Investigation Methodology
When analyzing a CSS-context vulnerability, follow these steps.

### 1. Identify the Source
Find where the attacker-controlled input enters the application:
    request.args.get("color")

### 2. Trace the Data
Follow the value from Flask to the template:
    color
      ↓
    render_template()
      ↓
    {{ color | safe }}

### 3. Identify the Context
Determine exactly where the value is inserted:
    style="color: USER_INPUT;"

Therefore:
    CSS Context

### 4. Identify the Expected Value
Ask what the application actually expects.
In this lab:
    color

The intended value might be:
    red

or:
    #ff0000

### 5. Test Whether the Context Can Be Escaped
Determine whether additional CSS syntax can be introduced.
For example, test whether a supplied value can introduce another CSS declaration.

### 6. Determine the Actual Impact
Do not automatically classify every CSS injection as JavaScript XSS.
Determine what the injected CSS can actually affect.

---

## Vulnerability Chain
    Attacker-Controlled Input
            ↓
    request.args.get("color")
            ↓
          Flask
            ↓
      Jinja Template
            ↓
    {{ color | safe }}
            ↓
      Inline CSS
            ↓
       CSS Parser
            ↓
    CSS Manipulation

---

## Key Takeaways
- CSS is a separate security context from HTML and JavaScript.
- User-controlled CSS should not be trusted by default.
- `| safe` disables Jinja's normal escaping.
- CSS Injection is not automatically equivalent to JavaScript XSS.
- Modern browsers restrict many historical CSS-to-JavaScript techniques.
- The correct security control depends on what the application expects.
- If only a small set of CSS values is required, use an allowlist.
- Normal escaping should still be used when rendering untrusted values.
- Always investigate the real impact of an injection instead of assuming code execution.

---

## Lab Summary
| Property | Value |
|---|---|
| Vulnerability | CSS Injection |
| Related Class | Client-Side Injection |
| Context | CSS |
| Source | `color` query parameter |
| Sink | Inline `style` attribute |
| Dangerous Behavior | Untrusted CSS inserted into a style declaration |
| Jinja Filter | `safe` |
| Primary Impact | CSS Manipulation |
| JavaScript Execution | Not guaranteed in modern browsers |
| Recommended Defense | Validation + Allowlisting + Proper Escaping |
| Difficulty | Medium |
| Environment | Local |
| Status | Solved |

---

## What This Lab Teaches
This lab demonstrates why identifying the exact injection context is important.
The presence of attacker-controlled input does not automatically mean that JavaScript execution is possible.

In this case, the input reaches:
    CSS Context

The correct analysis is therefore:
    Source → Context → Parser → Impact

rather than assuming:
    Input→ XSS

Understanding this distinction helps security researchers accurately classify vulnerabilities and helps developers choose appropriate defenses.

---

## Author
****
Educational purpose only.
Run this lab locally and never use these techniques against systems without explicit authorization.