# WebKit-NavigationAPI-SOP-Bypass

**WebKit Navigation API — Same-Origin Policy bypass via cross-port interception (CVE-2026-20643)**

| | |
|---|---|
| **CVE** | CVE-2026-20643 |
| **Discovered by** | Thomas Espach ([WebKit Bugzilla 306050](https://bugs.webkit.org/show_bug.cgi?id=306050)) |
| **Component** | WebKit — `WebCore::Navigation::innerDispatchNavigateEvent` |
| **Affected** | iOS 26.3.1 build `23D8133` (`iPhone18,2`) |
| **Class** | SOP bypass |
| **Interaction** | Click / link activation |
| **Confirmed** | Binary diff of vulnerable vs patched WebCore |

## Summary

`NavigateEvent.canIntercept` incorrectly returns `true` for same-site, cross-port navigations that differ in origin. The interception gate accepts any HTTP-family target after a same-site check without verifying that scheme, host, and **port** all match. This lets an attacker-controlled page intercept or suppress navigations that should cross an origin boundary.

## Root Cause

```cpp
// WebCore::Navigation::innerDispatchNavigateEvent — 0x1a1303304 (iOS 26.3.1 / 23D8133)

if (!isSameSite && !isSameOrigin)
    return false;
if (targetURL.protocolIsInHTTPFamily())
    return true;  // ← no port/host/scheme component equality check
                  //   cross-port navigations (e.g. :8000 → :8800) slip through
```

The WebKit mainline fix adds strict per-component equality (scheme / user / password / host / **port**) before allowing interception.

## PoC

Serve `poc_min.html` on port `8000` and open it on an affected device:

```sh
python3 -m http.server 8000
# http://127.0.0.1:8000/poc_min.html
```

Click **Run PoC**. The page triggers a cross-port navigation (`:8000` → `:8800`) and reports:

```
Vulnerable:  canIntercept=true
Patched:     canIntercept=false
```

## Files

| File | |
|---|---|
| [`findings.md`](findings.md) | Full root cause write-up and RE evidence |
| [`poc_min.html`](poc_min.html) | Self-contained detection PoC |
