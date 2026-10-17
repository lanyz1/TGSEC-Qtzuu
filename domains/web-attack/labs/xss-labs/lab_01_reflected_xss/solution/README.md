# Solution — Lab 01: Reflected XSS

## 🎯 Vulnerability

This lab contains a Reflected Cross-Site Scripting (XSS) vulnerability in the search functionality.
The vulnerability exists because user-controlled input is rendered as trusted HTML instead of being escaped.

---

## 1. Identify the Source

The application receives the `q` parameter from the HTTP request. In `app.py`:

```python
query = request.args.get("q", "")
```

The user controls the value of `q`, for example:

```
http://127.0.0.1:5000/?q=hello
```

Data flow so far:

```
User Input → ?q=hello → request.args.get("q") → query
```

**Source:** the `q` URL parameter.

## 2. Follow the Data Flow

The value is passed to the Jinja2 template:

```python
return render_template("index.html", query=query)
```

Complete server-side flow:

```
HTTP Request → ?q=USER_INPUT → request.args.get("q") → query → render_template() → index.html
```

## 3. Identify the Vulnerable Code

In `templates/index.html`:

```html
<div class="text-lg text-white break-words">{{ query | safe }}</div>
```

The important part is `{{ query | safe }}`.

## 4. Understand `safe`

Flask enables Jinja2 auto-escaping by default for `.html` templates, so special characters such as `<` and `>` are converted to HTML entities and displayed as text.

The `safe` filter tells Jinja2: *"This value is trusted HTML, do not escape it."*

```
User Input → {{ query | safe }} → Trusted HTML
```

This means attacker-controlled HTML can become part of the page.

## 5. Identify the XSS Context

The value is inserted between HTML tags:

```html
<div> USER_INPUT </div>
```

Context: **HTML Body Context**.

XSS behavior depends heavily on the context in which user-controlled data is interpreted.

## 6. Proof of Concept

A harmless proof of concept:

```html
<script>alert(1)</script>
```

Supplied through the `q` parameter (or the search box), the application reflects it into the response. Because it is rendered as trusted HTML, the browser parses the `<script>` element and executes `alert(1)`.

## 7. Why Is This Reflected XSS?

```
User → HTTP Request → q parameter → Flask → Jinja2 → HTTP Response → Browser → JavaScript Execution
```

The input is reflected from the request into the response and is **not stored** in a database. Therefore it is **Reflected XSS**.

## 8. Root Cause

Untrusted user input is rendered as HTML. `{{ query | safe }}` disables the normal escaping for this value.

## 9. Secure Fix

❌ Vulnerable:

```html
<div class="text-lg text-white break-words">{{ query | safe }}</div>
```

✅ Safer:

```html
<div class="text-lg text-white break-words">{{ query }}</div>
```

Jinja2 now applies its normal HTML escaping.

## 10. Verify the Fix

Restart the application (`debug=False`, so templates are not reloaded automatically) and test the same payload:

```html
<script>alert(1)</script>
```

The browser displays it as text. In View Source you will see `&lt;script&gt;alert(1)&lt;/script&gt;`.

```
Before fix: User Input → Trusted HTML → JavaScript Execution
After fix:  User Input → HTML Escaping → Text → No JavaScript Execution
```

## 11. Security Lesson

XSS analysis is not just about finding a payload. Understand the full data flow:

```
Source → User-Controlled Input → Processing → Context → Sink → Browser Interpretation
```

Ask yourself:

- Where does the input originate?
- Where does it go?
- Is it transformed?
- What context does it enter?
- How does the browser interpret that context?

## 12. Key Takeaways

- Reflected XSS occurs when user-controlled input is reflected into a response and interpreted as executable content.
- The `q` parameter is the source.
- Flask passes the value to the Jinja2 template.
- The vulnerable rendering happens in the HTML body context.
- `safe` makes Jinja2 treat the value as trusted HTML.
- Removing `safe` lets auto-escaping protect the output.
- XSS prevention must consider the context where data is rendered.
- CSP is defense-in-depth and must not replace fixing the root cause.

---

## 🛡️ Mitigation

1. **Use automatic escaping.** Let the template engine escape untrusted values: `{{ query }}`
2. **Avoid unnecessary raw HTML rendering.** Do not mark untrusted input as safe unless it is sanitized and HTML input is truly required.
3. **Use context-appropriate output encoding.** HTML, attribute, JavaScript, CSS and URL contexts each need different encoding.
4. **Sanitize when HTML is required.** Use a well-maintained sanitization library instead of just disabling escaping.
5. **Consider a Content Security Policy** as an additional layer of protection.

---

## 🏁 Lab Completed

```
Source → Data Flow → Context → Unsafe Rendering → Reflected XSS → Mitigation
```

**Lab:** 01 — Reflected XSS
**Difficulty:** Easy
**Author:** 