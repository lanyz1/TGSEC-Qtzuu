# FirefUXSS: Universal XSS in Firefox Focus for iOS via Redirect-Scheme Validation Race Condition

FirefUXSS was discovered with [V12](https://v12.sh) by [@RenwaX23](https://x.com/RenwaX23) of the [V12 security team](https://x.com/v12sec).

> Want to find issues like this in your own code? Try V12 at [v12.sh](https://v12.sh).

**Status:** 0-day, responsibly disclosed. After remaining unpatched for 11 months, we are now releasing our PoC (see Timeline below).

https://github.com/user-attachments/assets/23604288-9085-43b3-ad98-75fee26e47da

## Proof of Concept

A simplified PoC (`poc.php`) is included in this repository. It demonstrates script execution against `google.com`, `youtube.com`, `x.com`, and `reddit.com`.

A live demo is available at **[https://firefoxuxss.v12.sh](https://firefoxuxss.v12.sh)**.

> **Responsible disclosure note:** We are deliberately **not** publishing the full weaponized PoC shown in the video--the one capable of account takeover on X, Google, and Reddit--to limit the potential for abuse while the vulnerability remains unpatched.

## Summary

Firefox Focus for iOS contains a **Universal Cross-Site Scripting (UXSS)** vulnerability that allows an attacker to execute arbitrary JavaScript in the security context of effectively **any web origin** the victim can be steered through. By winning a race condition in the browser's redirect-scheme validation logic, an attacker can smuggle a `javascript:` (or other dangerous-scheme) navigation past the filter that is supposed to block it, causing the script to run **with the origin of the previously loaded document** rather than being neutralized.

In practice this means a single click on an attacker-controlled link can result in script execution on high-value origins such as `google.com`, `youtube.com`, `x.com`, or `reddit.com` — enabling session theft, account takeover, and arbitrary actions on behalf of the victim.

This was reported to Mozilla and remains unpatched. See the [Timeline](#timeline) for the full disclosure history.

## Background

Every modern browser refuses to follow **server-side redirects** (an HTTP `Location:` response header) that point at a dangerous URI scheme such as `javascript:`, `data:`, or `file:`. If a server responds with:

```
HTTP/1.1 302 Found
Location: javascript:alert(document.domain)
```

a conformant browser will not execute the script — the navigation is dropped or treated inertly, precisely to prevent the exact class of attack described here.

The expected guarantee is: **a redirect target's scheme is validated before the navigation is committed**, and dangerous schemes are rejected.

## Root Cause

Firefox Focus for iOS performs this scheme check, but the check is **not atomic with respect to the navigation it guards** — it is a classic time-of-check-to-time-of-use (TOCTOU) race.

Under normal load the validator rejects `javascript:` redirect targets correctly. However, when the redirect-handling path is flooded with a rapid burst of ordinary HTTP→HTTP redirects, the validator can be made to fall behind the navigation pipeline. By timing a final `javascript:` redirect to land inside this window, the dangerous-scheme check is effectively bypassed: the navigation is committed before (or instead of) being rejected.

Crucially, when the smuggled `javascript:` navigation does execute, it runs **inheriting the origin of the document that was being replaced**, rather than as a fresh, origin-less navigation. That origin inheritance is what turns a same-page script execution into a *universal* XSS — the script runs as `google.com`, `x.com`, etc.

### The `_self` requirement

The exploit only succeeds when the malicious page is loaded into the **`_self`** browsing context (i.e., navigating the current top-level document in place), not into a new window/tab.

Firefox Focus is a **single-window browser with no tab model**. We believe that loading the next document into `_self` collapses the navigation into the same browsing context that already holds the previous origin, and the race condition then exploits the resulting ambiguity about which origin the committed navigation belongs to. Opening in any other target breaks the origin-inheritance behavior and the attack fails.

### Finding an origin to pivot from

The final ingredient is an open redirect (or any controllable navigation) on the target origin that sends the user to the attacker's page **while remaining anchored to that origin's context**. These are widespread and trivial to find — during research we identified usable pivots on Google, X, YouTube, and Reddit, among others. The pivots used in the public PoC are included in the PoC code.

## Attack Flow

1. The attacker sends the victim a link to `attacker.com/poc.php`.
2. The victim clicks the link.
3. `poc.php` navigates the **`_self`** context to a Google open-redirect URL, e.g. `https://www.google.com/url?q=https://attacker.com/poc.php?pwn=1`.
4. Google issues a redirect back to `https://attacker.com/poc.php?pwn=1`, with the browsing context now associated with the `google.com` navigation.
5. `poc.php` (in `pwn=1` mode) triggers the race by emitting a rapid burst of self-referential HTTP redirects.
6. The final redirect in the burst points to `javascript:document.write(document.domain)`.
7. The scheme validator loses the race; the `javascript:` navigation commits and **executes in the `google.com` origin**, demonstrating UXSS.

In a weaponized version, step 6 is replaced with script that reads cookies/tokens or performs authenticated actions, yielding full account takeover on the targeted origin.

## Impact

- Arbitrary JavaScript execution in the context of attacker-chosen origins.
- Theft of session cookies and tokens; account takeover.
- Arbitrary authenticated actions on behalf of the victim.
- Triggered by a single user click — no further interaction required.

## Severity

**Critical — CVSS 9.3**

`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`

## Affected

- **Product:** Firefox Focus for iOS
- **Version:** Latest at time of testing (unpatched)
- **Platform:** iOS

## Timeline

| Date | Event |
|------|-------|
| 2025-07-04 | Report submitted to Mozilla. |
| 2025-07-09 | First response — Mozilla unable to reproduce. |
| 2025-07-09 – 2025-07-15 | Provided an improved PoC reliably triggering the race condition. |
| 2025-07-31 | Mozilla replicated the vulnerability. |
| 2025-09-02 | Mozilla unable to explain why the exploit is reliable on our setup but not theirs. |
| 2025-09-02 | Mozilla attempting to source an iOS engineer to develop a patch. |
| 2026-02-17 | A second Mozilla team member reproduced the vulnerability. |
| 2026-06-08 | After nearly a year without a concrete fix or commitment, we are publicly disclosing this critical vulnerability. |

## Disclosure

Maintainers are busy and the folks at Mozilla are wonderful people, but we are publishing this advisory after a disclosure window of 11 months months has elapsed. Users of Firefox Focus for iOS should exercise caution until a patch is released.
