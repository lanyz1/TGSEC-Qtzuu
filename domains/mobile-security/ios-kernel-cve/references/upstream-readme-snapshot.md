# CVE-2026-65343 — AppleKeyStore OOB Read (KASLR Defeat)

**Component:** `AppleKeyStore` kernel extension — `_LibSer_SEPControl_Deserialize`  
**Affected:** iOS / iPadOS 26.6 (23G71) and earlier  
**Fixed in:** iOS / iPadOS 26.6.1 (23G83)  
**Type:** Out-of-Bounds read in SEP control message deserialization  
**Impact:** Kernel pointer leak → KASLR defeat from a sandboxed, entitlement-free process (via DYLD_INTERPOSE ACM handle capture)

---

## Credits

Discovered by: **Drinor Selmanaj** (Sentry), **Surya Narayan Kushwaha**  
(per [Apple Security Advisory — iOS 26.6.1](https://support.apple.com/en-us/148282))

---

## Root Cause

`_LibSer_SEPControl_Deserialize` in the `AppleKeyStore` kernel extension publishes a `(payload_ptr, declared_length)` pair from an ACM (Credential Manager) message buffer to userspace via `copyout()`, **without validating that `declared_length ≤ remaining`**.

By supplying `declared_length = 0x800`, the driver copies approximately `0x7E8` bytes beyond the end of the kernel ACM message buffer — reading into adjacent kernel heap allocations. Those adjacent regions contain kernel pointers (`0xfffffff0xxxxxxxx`) which can be used to compute the KASLR slide.

```
; _LibSer_SEPControl_Deserialize (affected path, 26.6 / 23G71)
ldr  w2, [acm_msg + declared_length_offset]  ; user-controlled 0x800
; NO check: w2 <= (acm_msg_end - payload_ptr) ← MISSING
bl   copyout                                  ; copies w2 bytes to userspace
```

---

## ACM Handle Capture (DYLD_INTERPOSE)

Direct `IOServiceOpen("AppleKeyStore")` is blocked by the sandbox on sideloaded apps. However, the `Security.framework` Secure Enclave key-signing path calls `IOConnectCallMethod` **in-process** with a real ACM session handle.

The PoC uses a `__DATA,__interpose` hook (which runs at dyld load time, before `__DATA_CONST` is made read-only — `fishhook` is blocked on iOS 26 by DATA_CONST protection):

1. Arm the interpose capture flag
2. `SecKeyCreateRandomKey(kSecAttrTokenIDSecureEnclave)` → `SecKeyCreateSignature()` → in-process `IOConnectCallMethod` fires with a real ACM handle
3. Capture `(conn, handle[16])`
4. Replay with `declared_length = 0x800` across 163 AKS selectors
5. Scan output for `0xfffffff0xxxxxxxx` kernel pointers → compute KASLR slide

---

## PoC Behaviour

`poc_aks_oob.m` implements the full ACM handle capture and OOB probe chain:

- Creates a Secure Enclave P-256 key (`kSecAttrAccessibleAfterFirstUnlock`, no biometric)
- Signs a 32-byte message to trigger the in-process AKS IOKit call
- Replays with `declared_length = 0x800` across all 163 AKS selectors
- Prints any kernel pointers found at `KPTR @+XXXX = 0xfffffff0YYYYYYYY`
- Attempts to compute the KASLR slide from a known AKS symbol offset

If the SE key sign is routed through `secd` XPC instead of in-process, the fallback probe uses a zero handle (confirms OOB path reachability; all selectors will fail ACM validation, but the VNOP path is confirmed).

---

## iOS 26 Note: fishhook Blocked

On iOS 26, `__DATA_CONST` (which contains the GOT) is mapped read-only before any in-process code runs. Runtime GOT writes (as used by `fishhook`) trigger `KERN_PROTECTION_FAILURE → SIGBUS`. `DYLD_INTERPOSE` via `__DATA,__interpose` works because dyld processes the interpose table at image-load time, before the kernel enforces the `__DATA_CONST` protection.

---

## Requirements

- iOS 26.6 (23G71) or earlier
- Secure Enclave access (`kSecAttrTokenIDSecureEnclave`) — available to any sideloaded app without entitlements
- No sandbox escape required: SE key signing via `Security.framework` *may* invoke the AKS IOKit call
  in-process (device and iOS build dependent). On some configurations the call routes through `secd` XPC
  instead — in that case the zero-handle fallback confirms OOB path reachability but not full KASLR defeat.

---

## Build

```sh
# Xcode project — link Security.framework and Foundation.framework
clang -arch arm64 \
      -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
      -framework Security -framework Foundation \
      -o poc poc/poc_aks_oob.m

codesign -s "Apple Development" --entitlements ent.plist poc
```

Minimum entitlements (`ent.plist`):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>keychain-access-groups</key>
    <array><string>$(AppIdentifierPrefix)com.research.poc65343</string></array>
</dict></plist>
```

---

## Timeline

| Date | Event |
|------|-------|
| 2026-08-17 | iOS 26.6.1 released with fix |
| 2026-08-17 | Apple credits published in security advisory |

---

## References

- [Apple Security Advisory — iOS 26.6.1](https://support.apple.com/en-us/148282)
