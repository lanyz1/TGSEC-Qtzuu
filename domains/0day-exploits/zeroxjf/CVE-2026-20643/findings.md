# CVE-2026-20643 — Navigation API cross-origin gate bug (binary diff verified)

## Scope
- Vulnerable: iOS 26.3.1 restore build `23D8133` (iPhone18,2), WebCore in dyld cache.
- Patched (BSI OTA): iOS 26.3.1(a) `23D771330a`, binary diff in `cryptex-system-arm64e`.
- Function diffed: `WebCore::Navigation::innerDispatchNavigateEvent(...)` at `0x1a1303304`.

## What changed (exact)
### Vulnerable logic (23D8133, IDA pseudocode)
```cpp
isSameSiteAs = SecurityOrigin::isSameSiteAs(currOrigin, targetOrigin);
isSameOriginAs = SecurityOrigin::isSameOriginAs(currOrigin, targetOrigin);

if ((isSameSiteAs & 1) == 0 && !isSameOriginAs)
    v34 = 1; // deny intercept
else if ((*(_BYTE *)(targetURL + 32) & 2) != 0)
    v34 = 0; // allow intercept
else if (!URL::protocolIs(targetURL, "file")
      || isEqualIgnoringQueryAndFragments(docURL, targetURL))
    v34 = equalIgnoringFragmentIdentifier(docURL, targetURL) ^ 1;
else
    v34 = 1;
```

Key point: gate allows the fast-path when `isSameSiteAs` is true (even if not same-origin).

### Patched logic (23D771330a)
```cpp
v34 = 1; // default deny
if (SecurityOrigin::isSameOriginAs(currOrigin, targetOrigin)) {
    if (URL::user(docURL) == URL::user(targetURL) &&
        URL::password(docURL) == URL::password(targetURL)) {
        if ((*(_BYTE *)(targetURL + 32) & 2) != 0)
            v34 = 0;
        else if (!URL::protocolIs(targetURL, "file")
              || isEqualIgnoringQueryAndFragments(docURL, targetURL))
            v34 = equalIgnoringFragmentIdentifier(docURL, targetURL) ^ 1;
    }
}
```

Key point: old same-site gate was replaced by strict same-origin gate, plus explicit `user/password` validation.

## Evidence addresses
- Old build (`mcp__ida_headless_2`):
  - `0x1a1303480` -> `SecurityOrigin::isSameSiteAs`
  - `0x1a1303490` -> `SecurityOrigin::isSameOriginAs`
  - `0x1a1303b44` pseudocode: `if ((isSameSiteAs & 1) == 0 && !isSameOriginAs) ...`
- Patched build (`mcp__ida_headless_3`):
  - `0x1a1303484` -> `SecurityOrigin::isSameOriginAs`
  - `0x1a1303494`/`0x1a13034a0` -> `URL::user`
  - `0x1a13034bc`/`0x1a13034c8` -> `URL::password`
  - `0x1a13034ac`/`0x1a13034d0` -> `WTF::equal(StringImpl*, StringImpl*)`

## `canIntercept` plumbing confirmation
- `WebCore::jsNavigateEvent_canIntercept` (`0x19f84ab84`) reads `*(event + 160)`.
- `WebCore::NavigateEvent::NavigateEvent` (`0x1a12fa834`) writes init dword into `event+160`.
- `innerDispatchNavigateEvent` computes this bit from the above gate (`v34` inversion path).

## Trigger model
- Same-site but cross-origin navigation (e.g. cross-port localhost) reaches permissive path in vulnerable build.
- Patched build blocks that path unless strict same-origin plus user/password match.

## Impact
- Wrong cross-origin authorization in Navigation API interception path.
- Attacker-controlled content can get interception capability where origin boundary should deny it.
- Practical abuse: navigation flow manipulation/confusion across origin boundaries.

## Confidence
- High for root cause class and patch location: direct vulnerable vs patched function-level diff.
- Medium-high for exact externally observable trigger variants: dynamic JS runtime behavior still depends on Navigation API availability/mode on target build.
