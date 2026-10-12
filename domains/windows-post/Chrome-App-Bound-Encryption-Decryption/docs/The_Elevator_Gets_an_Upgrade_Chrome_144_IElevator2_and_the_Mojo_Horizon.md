# The Elevator Gets an Upgrade: Chrome 144, IElevator2, and the Mojo Horizon

**By Alexander 'xaitax' Hagenah**

*Initial release: January 11, 2026*

*Updated: January 25, 2026 - Added Brave 144 analysis, comprehensive browser comparison table*

Remember when bypassing Chrome's App-Bound Encryption (ABE) felt like you had finally cracked the code? Well, the Chromium team has been busy. Starting with Chrome 144, a new player enters the scene: `IElevator2`. The existing `IElevator` interface isn't going anywhere, but there's now a v2 sibling sitting alongside it - and the commit message is refreshingly candid about why.

This article digs into what changed, what stayed the same, and what the developers themselves say they're planning next.

## Setting the Stage: The IElevator Interface (Chrome 127-143)

Before diving into the new, let's recap the old. App-Bound Encryption, introduced around Chrome 127, protects sensitive user data (cookies, passwords, payment methods) by tying decryption to the legitimate browser process. The mechanism relies on a COM service - the Elevation Service - that exposes an `IElevator` interface with three methods:

```cpp
// IElevator - The original interface (IID: {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C})
interface IElevator : IUnknown {
    // VTable slot 3 (offset 24 bytes)
    HRESULT RunRecoveryCRXElevated(...);
    // VTable slot 4 (offset 32 bytes)
    HRESULT EncryptData(ProtectionLevel, BSTR plaintext, BSTR* ciphertext, DWORD* last_error);
    // VTable slot 5 (offset 40 bytes)
    HRESULT DecryptData(BSTR ciphertext, BSTR* plaintext, DWORD* last_error);
};
```

The inheritance pattern was straightforward - vendor-specific interfaces like `IElevatorChrome` (IID `{463ABECF-410D-407F-8AF5-0DF35A005CC8}`) inherited directly from `IElevator` without adding any methods. This kept things clean: one base interface, multiple vendor flavors, identical vtable layouts.

In Chrome 143, the type library exposed exactly **6 interfaces**:

| Interface | IID | Base |
|-----------|-----|------|
| `IElevator` | `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}` | `IUnknown` |
| `IElevatorChromium` | `{B88C45B9-8825-4629-B83E-77CC67D9CEED}` | `IElevator` |
| `IElevatorChrome` | `{463ABECF-410D-407F-8AF5-0DF35A005CC8}` | `IElevator` |
| `IElevatorChromeBeta` | `{A2721D66-376E-4D2F-9F0F-9070E9A42B5F}` | `IElevator` |
| `IElevatorChromeDev` | `{BB2AA26B-343A-4072-8B6F-80557B8CE571}` | `IElevator` |
| `IElevatorChromeCanary` | `{4F7CE041-28E9-484F-9DD0-61A8CACEFEE4}` | `IElevator` |

Simple, predictable, and - for my [Chrome App-Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/) project - straightforward to work with.

## Enter Chrome 144: The Interface Family Doubles

On November 7, 2025, Chromium commit [49620496b8f0b7c0c63e2666a82e01180df3f4c3](https://chromium.googlesource.com/chromium/src/+/49620496b8f0b7c0c63e2666a82e01180df3f4c3) landed with the title: **"Add two new interfaces on IElevator."**

Fast forward to the Chrome 144 Beta release, and the elevation service's type library has grown from 6 to **12 interfaces**:

| Interface | IID | Base | Methods Added |
|-----------|-----|------|---------------|
| `IElevator` | `{A949CB4E-...}` | `IUnknown` | 3 |
| `IElevatorChromium` | `{B88C45B9-...}` | `IElevator` | 0 |
| `IElevatorChrome` | `{463ABECF-...}` | `IElevator` | 0 |
| `IElevatorChromeBeta` | `{A2721D66-...}` | `IElevator` | 0 |
| `IElevatorChromeDev` | `{BB2AA26B-...}` | `IElevator` | 0 |
| `IElevatorChromeCanary` | `{4F7CE041-...}` | `IElevator` | 0 |
| **`IElevator2`** | **`{8F7B6792-784D-4047-845D-1782EFBEF205}`** | `IElevator` | **2** |
| **`IElevator2Chromium`** | **`{BB19A0E5-00C6-4966-94B2-5AFEC6FED93A}`** | `IElevator2` | 0 |
| **`IElevator2Chrome`** | **`{1BF5208B-295F-4992-B5F4-3A9BB6494838}`** | `IElevator2` | 0 |
| **`IElevator2ChromeBeta`** | **`{B96A14B8-D0B0-44D8-BA68-2385B2A03254}`** | `IElevator2` | 0 |
| **`IElevator2ChromeDev`** | **`{3FEFA48E-C8BF-461F-AED6-63F658CC850A}`** | `IElevator2` | 0 |
| **`IElevator2ChromeCanary`** | **`{FF672E9F-0994-4322-81E5-3A5A9746140A}`** | `IElevator2` | 0 |

A complete mirror of the v1 interface family - but with two additional methods in the base `IElevator2` interface.

## The New Methods: RunIsolatedChrome and AcceptInvitation

The `IElevator2` interface extends `IElevator` with two new methods, landing at vtable slots 6 and 7:

```cpp
// IElevator2 - The new interface (IID: {8F7B6792-784D-4047-845D-1782EFBEF205})
interface IElevator2 : IElevator {
    // VTable slot 6 (offset 48 bytes)
    HRESULT RunIsolatedChrome(
        LPCWSTR command_line,
        BSTR response_endpoint,
        BSTR invitation,
        ULONG_PTR* proc_handle
    );

    // VTable slot 7 (offset 56 bytes)
    HRESULT AcceptInvitation(
        BSTR invitation,
        BOOL* result
    );
};
```

The critical observation here: **the existing methods remain untouched**. `EncryptData` stays at vtable offset 32 bytes, `DecryptData` at offset 40 bytes. This is COM interface versioning done right - extend, don't modify.

### What Do These Methods Do?

**`RunIsolatedChrome`**: Launches a Chrome process in some form of isolated context. The parameters hint at inter-process communication setup - a command line to execute, a "response endpoint" for callbacks, and an "invitation" token of some kind.

**`AcceptInvitation`**: Validates or accepts the aforementioned invitation token. The boolean return suggests a simple success/failure handshake.

The naming convention - "invitation," "endpoint," "accept" - has a distinctly IPC flavor to it. Which brings us to...

## The Mojo Connection

What's particularly interesting is why these methods exist at all. A quick search through Chromium's bug tracker reveals [Issue 383157189](https://issues.chromium.org/issues/383157189): **"Consider migrating app-bound APIs to mojo."**

[Mojo](https://chromium.googlesource.com/chromium/src/+/HEAD/mojo/README.md) is Chromium's internal IPC framework - a more modern, type-safe, and secure alternative to raw COM for inter-process communication. The issue description and the commit's timing suggest these new methods are laying groundwork for exactly that migration.

The `AcceptInvitation` method name is particularly telling. In Mojo parlance, "invitations" are how processes bootstrap secure communication channels. An invitation contains the information needed to establish a message pipe between processes. The pattern looks like:

1. Elevated process creates a Mojo invitation
2. Invitation is passed to the browser process via COM (`AcceptInvitation`)
3. Once accepted, both sides can communicate over Mojo instead of COM

This would allow Chrome to eventually deprecate the COM-based `EncryptData`/`DecryptData` calls in favor of Mojo-based equivalents - which would be harder to intercept and potentially more resistant to the injection-based approach my tool uses.

## VTable Layout Comparison

For those who live and breathe vtable offsets (you know who you are), here's the complete layout comparison:

**IElevator (Chrome 143 and earlier):**
```
Slot 0 (offset  0): QueryInterface
Slot 1 (offset  8): AddRef
Slot 2 (offset 16): Release
Slot 3 (offset 24): RunRecoveryCRXElevated
Slot 4 (offset 32): EncryptData
Slot 5 (offset 40): DecryptData
```

**IElevator2 (Chrome 144+):**
```
Slot 0 (offset  0): QueryInterface
Slot 1 (offset  8): AddRef
Slot 2 (offset 16): Release
Slot 3 (offset 24): RunRecoveryCRXElevated
Slot 4 (offset 32): EncryptData         <-- SAME
Slot 5 (offset 40): DecryptData         <-- SAME
Slot 6 (offset 48): RunIsolatedChrome   <-- NEW
Slot 7 (offset 56): AcceptInvitation    <-- NEW
```

The preservation of existing offsets is crucial. It means code targeting `IElevator` continues to work against `IElevator2` objects - the additional methods are purely additive. This is textbook COM interface evolution.

## The Commit: What the Developers Actually Said

The [November 2025 commit](https://chromium.googlesource.com/chromium/src/+/49620496b8f0b7c0c63e2666a82e01180df3f4c3) by Will Harris (wfh@chromium.org) is candid about the intentions. The full commit message reads:

> **Add two new interfaces on IElevator**
>
> This CL creates a new IElevator2 which adds two new interfaces. The first is for launching a new isolated browser and the second is for using mojo over the COM interface. **A longer term plan is to move the existing COM interfaces to mojo so this provides that interface so hopefully the COM interface never has to change again.**
>
> Both are left unimplemented for now.
>
> To support version skew - the new IElevator2 has a different IID but also supports the old IElevator interface: Newer browser versions using this new IID will connect to the IElevator2 but earlier versions of browser before this version will connect to IElevator. This makes the code compatible with old versions of browser connecting to new versions of the elevation service.
>
> New versions of the browser needing IElevator2 connecting to an older version of the elevation service will fail to obtain the COM interface since IElevator2 is not implemented - this should not happen in theory since both are updated at the same time.

The commit references two bugs: [383157189](https://issues.chromium.org/issues/383157189) ("Consider migrating app-bound APIs to mojo") and [433545123](https://issues.chromium.org/issues/433545123) (not publicly accessible for mere mortals like me).

The new methods are explicitly groundwork for this transition, and the version skew handling ensures backward compatibility during the rollout.

The `elevation_service_idl.idl` changes in the commit show the full interface definition:

```idl
[uuid(8F7B6792-784D-4047-845D-1782EFBEF205)]
interface IElevator2 : IElevator {
    HRESULT RunIsolatedChrome([in, string] const WCHAR* command_line,
                              [in] BSTR response_endpoint,
                              [in] BSTR invitation,
                              [out] ULONG_PTR* proc_handle);
    HRESULT AcceptInvitation([in] BSTR invitation, [out] BOOL* result);
};
```

Notably, the commit states both methods are **"left unimplemented for now"** - they're placeholders preparing the interface contract for future functionality.

## Practical Implications: Backward Compatibility Preserved

For those maintaining tools that interact with Chrome's ABE infrastructure, the good news is clear: **backward compatibility is fully maintained**.

Chrome 144+ supports both interface families:
- Query `IElevatorChrome` (`{463ABECF-...}`) - works, returns an object supporting the v1 interface
- Query `IElevator2Chrome` (`{1BF5208B-...}`) - works, returns an object supporting the v2 interface

The v2 objects are binary-compatible with v1 method calls since the vtable layout is preserved. This means existing code continues to function, while new code can opt into v2 features.

My tool now attempts `IElevator2Chrome` first, falling back to `IElevatorChrome` if not available:

```cpp
// Try IElevator2 first if available (Chrome 144+)
if (iid_v2.has_value()) {
    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER,
                          iid_v2.value(), &elevator);
}

// Fall back to IElevator if v2 not available or failed (Chrome 143 and earlier)
if (!iid_v2.has_value() || hr == E_NOINTERFACE || FAILED(hr)) {
    hr = CoCreateInstance(clsid, nullptr, CLSCTX_LOCAL_SERVER,
                          iid, &elevator);
}
```

This ensures compatibility across Chrome versions while being ready for whatever comes next.

## Looking Forward: What Mojo Actually Changes (and Doesn't)

The commit explicitly states the long-term plan: migrate existing COM interfaces to Mojo. But what does that actually mean for ABE security?

### What Is Mojo?

[Mojo](https://chromium.googlesource.com/chromium/src/+/HEAD/mojo/README.md) is Chromium's internal IPC framework - a platform-agnostic message-passing system that handles communication between processes. According to Chromium's documentation, it's roughly 1/3 faster than legacy IPC with 1/3 fewer context switches. Message pipes are lightweight (creating one is "essentially generating two random numbers and stuffing them into a hash table"), and unlike alternatives like Protocol Buffers, Mojo can transfer native handles (file descriptors) across process boundaries.

### What Mojo Changes

**Type Safety**: Mojo uses structured types and code generation. Instead of passing raw `BSTR` strings through COM, data flows through well-defined interface contracts. This reduces certain classes of bugs - Chromium's [security documentation](https://github.com/chromium/chromium/blob/main/docs/security/mojo.md) emphasizes using proper abstractions like `mojo_base.mojom.Origin` over raw strings to prevent encoding attacks.

**Validation Framework**: Mojo has built-in patterns for validating data from less-privileged processes. When validation fails, the system calls `mojo::ReportBadMessage()` which can terminate the offending process. This is more standardized than ad-hoc COM error handling.

**Different Attack Surface**: Mojo has its own bug classes. Recent vulnerabilities like [CVE-2025-2783](https://fidelissecurity.com/vulnerabilities/cve-2025-2783/) (sandbox escape via improper handle validation) and [CVE-2025-10201](https://windowsforum.com/threads/cve-2025-10201-mojo-ipc-site-isolation-bypass-fixed-in-chrome-140.380595/) (site-isolation bypass) demonstrate that Mojo isn't immune to security issues.

### What Mojo Doesn't Change

Here's the thing: for injection-based ABE bypass, migrating from COM to Mojo doesn't fundamentally alter the trust model.

Currently, the flow is:
1. Browser process (trusted) calls COM to `elevation_service.exe`
2. Elevation service validates caller path
3. Decrypted key returns to browser process

With Mojo, it would be:
1. Browser process (trusted) calls Mojo to `elevation_service.exe`
2. Elevation service validates caller path
3. Decrypted key returns to browser process

The security boundary is between the browser process and the elevation service, not the IPC mechanism itself. Code running inside the browser process - whether via DLL injection or other means - sits inside the trusted boundary. It can make the decryption call regardless of whether that call travels over COM or Mojo.

Mojo's security model is designed to protect privileged processes from *less-privileged* processes (like compromised renderers). It's not designed to prevent code already running in the browser process from making legitimate IPC calls.

### The Real Question

The `RunIsolatedChrome` method is potentially more interesting from a security perspective. If Chrome eventually moves sensitive operations to a separate, more isolated process that communicates exclusively over Mojo, that could change things. But that's speculation - the method is currently unimplemented, and the commit doesn't detail what "isolated" means in this context.

## Verification: comrade_abe.py Analysis

For independent verification, I used my [comrade_abe.py](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/blob/main/tools/comrade_abe.py) tool to analyze Chrome 143, Chrome 144, Edge 144, and Brave 144's elevation services:

**Chrome 143 (143.0.7499.193):**
```
total_interfaces_scanned: 6
abe_capable_interfaces_found: 6
```

**Chrome 144 (144.0.7559.97):**
```
total_interfaces_scanned: 12
abe_capable_interfaces_found: 12
```

**Edge 144 (144.0.3719.92):**
```
total_interfaces_scanned: 12
abe_capable_interfaces_found: 11
```

**Brave 144 (144.1.86.142):**
```
total_interfaces_scanned: 13
abe_capable_interfaces_found: 13
```

All analyses confirmed that `EncryptData` and `DecryptData` maintain their vtable offsets across all interfaces - 32 and 40 bytes respectively for Chrome and Brave, 56 and 64 bytes for Edge (due to its `IElevatorEdgeBase` inheritance quirk). The `IElevator2` family simply adds two more methods at the end of the vtable.

## What About Edge? A Tale of Partial Adoption

Running the same analysis on Microsoft Edge 144 (144.0.3719.92) reveals an interesting divergence from Chrome's approach:

**Edge 144:**
```
total_interfaces_scanned: 12
abe_capable_interfaces_found: 11
```

Edge has 12 interfaces total (11 ABE-capable) - same count as Chrome 144 - but the composition tells a different story. The table below shows the 11 ABE-capable interfaces from the analysis:

| Interface | IID | Notes |
|-----------|-----|-------|
| `IElevator` | `{A949CB4E-...}` | Base, with `IElevatorEdgeBase` in chain |
| `IElevator2` | `{8F7B6792-...}` | **Adopted from Chrome** |
| `IElevatorUnbranded` | `{1844B907-...}` | |
| `IElevatorEdge` | `{C9C2B807-...}` | |
| `IElevatorEdgeBeta` | `{F84A0FB0-...}` | |
| `IElevatorEdgeDev` | `{1592D8FD-...}` | |
| `IElevatorEdgeCanary` | `{53FE64DB-...}` | |
| `IElevatorEdgeInternal` | `{F019E0F2-...}` | |
| `IElevatorCopilot` | `{17DF149F-...}` | **New - Copilot support** |
| `IElevatorCopilotDev` | `{10658E59-...}` | **New - Copilot support** |
| `IElevatorCopilotInternal` | `{763D675E-...}` | **New - Copilot support** |

### Key Observations

**1. IElevator2 Adopted, But No Vendor Variants**

Edge adopted the base `IElevator2` interface (IID `{8F7B6792-784D-4047-845D-1782EFBEF205}`) but notably did **not** create the vendor-specific variants that Chrome did. There's no `IElevator2Edge`, `IElevator2EdgeBeta`, etc. - just the base interface.

This suggests Microsoft may be taking a wait-and-see approach. They've pulled in the interface definition (likely from shared Chromium code), but haven't fully committed to the v2 pattern across their release channels yet.

**2. The VTable Offset Quirk Persists**

Remember the [Edge ABE vtable mystery](The_Curious_Case_of_the_Cantankerous_COM_Decrypting_Microsoft_Edge_ABE.md)? Edge's inheritance chain includes `IElevatorEdgeBase` between `IUnknown` and `IElevator`, pushing method offsets higher:

```
Edge's IElevator2 inheritance:
IUnknown -> IElevatorEdgeBase -> IElevator -> IElevator2

Edge vtable offsets:
- EncryptData: 56 bytes (vs Chrome's 32)
- DecryptData: 64 bytes (vs Chrome's 40)
```

Even with IElevator2, Edge maintains its distinct vtable layout. Any tool targeting Edge must still account for this offset difference.

**3. Copilot Interfaces**

Edge 144 includes three `IElevatorCopilot*` interfaces (`IElevatorCopilot`, `IElevatorCopilotDev`, `IElevatorCopilotInternal`), presumably supporting Microsoft Copilot integration with ABE-protected data. These follow the same pattern as the Edge variants - inheriting from `IElevator` with no additional methods, just distinct IIDs for the Copilot app. (When exactly these were introduced isn't clear from this analysis alone - they may have appeared in an earlier Edge version.)

## What About Brave? A Unique Hybrid Approach

Brave 144 (144.1.86.142) presents the most interesting case study - a browser that adopted the IElevator2 pattern while maintaining its own distinct identity:

**Brave 144:**
```
total_interfaces_scanned: 13
abe_capable_interfaces_found: 13
```

Brave actually has *more* interfaces than Chrome or Edge - 13 versus their 12. Here's the breakdown:

| Interface | IID | Notes |
|-----------|-----|-------|
| `IElevator` | `{5A9A9462-2FA1-4FEB-B7F2-DF3D19134463}` | **Different IID than Chrome/Edge** |
| `IElevator2` | `{8F7B6792-...}` | Same as Chrome |
| `IElevatorChromium` | `{3218DA17-...}` | Brave-specific IID |
| `IElevatorChrome` | `{F396861E-...}` | Brave-specific IID |
| `IElevatorChromeBeta` | `{9EBAD7AC-...}` | Brave-specific IID |
| `IElevatorChromeDev` | `{1E43C77B-...}` | Brave-specific IID |
| `IElevatorChromeCanary` | `{1DB2116F-...}` | Brave-specific IID |
| `IElevatorDevelopment` | `{17239BF1-A1DC-4642-846C-1BAC85F96A10}` | **Brave-unique interface** |
| `IElevator2Chromium` | `{BB19A0E5-...}` | Same as Chrome |
| `IElevator2Chrome` | `{1BF5208B-...}` | **Same as Chrome** |
| `IElevator2ChromeBeta` | `{B96A14B8-...}` | Same as Chrome |
| `IElevator2ChromeDev` | `{3FEFA48E-...}` | Same as Chrome |
| `IElevator2ChromeCanary` | `{FF672E9F-...}` | Same as Chrome |

### Key Observations

**1. Different Base IElevator IID**

Unlike Edge (which shares Chrome's base `IElevator` IID), Brave uses its own: `{5A9A9462-2FA1-4FEB-B7F2-DF3D19134463}` versus Chrome/Edge's `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}`. This is a deliberate divergence at the foundational level.

**2. Intentional IElevator2 IID Sharing**

Here's where it gets interesting: despite having different base IElevator IIDs, Brave deliberately reuses Chrome's `IElevator2Chrome` IID (`{1BF5208B-295F-4992-B5F4-3A9BB6494838}`). This is a conscious choice for forward compatibility - when the Mojo migration eventually happens, Brave can piggyback on Chrome's implementation without maintaining separate infrastructure.

**3. VTable Layout Matches Chrome (Mostly)**

Unlike Edge's offset quirk, Brave maintains Chrome's vtable layout for the ABE-relevant methods:
- `EncryptData`: offset 32 bytes (same as Chrome)
- `DecryptData`: offset 40 bytes (same as Chrome)

Interestingly, Brave's base `IElevator` interface defines 4 methods versus Chrome's 3 - there's an additional method somewhere in Brave's interface that the ABE analyzer doesn't track (since it only looks for `EncryptData`/`DecryptData`). However, since the offsets for the encryption methods are identical, this extra method doesn't affect ABE functionality. The same code path works for both Chrome and Brave.

**4. Unique IElevatorDevelopment Interface**

Brave includes an `IElevatorDevelopment` interface (`{17239BF1-A1DC-4642-846C-1BAC85F96A10}`) that neither Chrome nor Edge have. This appears to be for Brave's internal development builds, separate from the standard Chromium Dev channel.

### The Hybrid Strategy

Brave's approach is pragmatic: maintain independence where it matters (distinct base IElevator IID, unique development interface) while embracing compatibility where it helps (shared IElevator2 IIDs, identical vtable layout). It's the best of both worlds - brand differentiation without the maintenance burden of a completely forked ABE implementation.

## The Complete Picture: Browser Interface Comparison

With all three major Chromium browsers now on version 144, here's a comprehensive comparison:

| Aspect | Chrome 144 | Edge 144 | Brave 144 |
|--------|------------|----------|-----------|
| **Total Interfaces** | 12 | 12 | 13 |
| **ABE-Capable Interfaces** | 12 | 11 | 13 |
| **Elevation Service CLSID** | `{708860E0-F641-4611-8895-7D867DD3675B}` | `{1FCBE96C-1697-43AF-9140-2897C7C69767}` | `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` |
| **Base IElevator IID** | `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}` | `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}` | `{5A9A9462-2FA1-4FEB-B7F2-DF3D19134463}` |
| **IElevator2 Base IID** | `{8F7B6792-...}` | `{8F7B6792-...}` | `{8F7B6792-...}` |
| **IElevator2 Family** | All 6 (base + 5 variants) | Base only | All 6 (base + 5 variants) |
| **EncryptData Offset** | 32 bytes | 56 bytes | 32 bytes |
| **DecryptData Offset** | 40 bytes | 64 bytes | 40 bytes |
| **Unique Interfaces** | - | Copilot (3) | Development (1) |
| **IElevatorEdgeBase in Chain** | No | Yes | No |

### Interface Presence Matrix

| Interface Family | Chrome | Edge | Brave |
|-----------------|:------:|:----:|:-----:|
| `IElevator` (base) | ✅ | ✅ | ⚠️ different IID |
| `IElevator2` (base) | ✅ | ✅ | ✅ |
| `IElevatorChromium` | ✅ | ❌ | ⚠️ different IID |
| `IElevatorChrome` | ✅ | ❌ | ⚠️ different IID |
| `IElevatorChromeBeta` | ✅ | ❌ | ⚠️ different IID |
| `IElevatorChromeDev` | ✅ | ❌ | ⚠️ different IID |
| `IElevatorChromeCanary` | ✅ | ❌ | ⚠️ different IID |
| `IElevator2Chromium` | ✅ | ❌ | ✅ |
| `IElevator2Chrome` | ✅ | ❌ | ✅ |
| `IElevator2ChromeBeta` | ✅ | ❌ | ✅ |
| `IElevator2ChromeDev` | ✅ | ❌ | ✅ |
| `IElevator2ChromeCanary` | ✅ | ❌ | ✅ |
| `IElevatorUnbranded` | ❌ | ✅ | ❌ |
| `IElevatorEdge` | ❌ | ✅ | ❌ |
| `IElevatorEdgeBeta` | ❌ | ✅ | ❌ |
| `IElevatorEdgeDev` | ❌ | ✅ | ❌ |
| `IElevatorEdgeCanary` | ❌ | ✅ | ❌ |
| `IElevatorEdgeInternal` | ❌ | ✅ | ❌ |
| `IElevatorCopilot` | ❌ | ✅ | ❌ |
| `IElevatorCopilotDev` | ❌ | ✅ | ❌ |
| `IElevatorCopilotInternal` | ❌ | ✅ | ❌ |
| `IElevatorDevelopment` | ❌ | ❌ | ✅ |

## Conclusion

So what do we actually have here? Chrome 144 ships with `IElevator2` - two new methods that are explicitly unimplemented, sitting on top of the same `EncryptData`/`DecryptData` that have been there since Chrome 127. The vtable offsets haven't changed. The COM infrastructure hasn't changed. The path validation logic hasn't changed.

What *has* changed is intent. The commit message spells it out: they want to move to Mojo eventually, and these methods are the plumbing for that. Whether that happens in Chrome 150 or Chrome 200 is anyone's guess.

For practical purposes: if your code worked against Chrome 143, it works against Chrome 144. The interface IIDs are different, but the methods you care about are at the same offsets. My tool now tries `IElevator2Chrome` first and falls back to `IElevatorChrome` - belt and suspenders.

Edge adopted the base `IElevator2` interface but didn't bother with vendor-specific variants yet. Their vtable offset quirk persists. Brave took the most interesting path - different base IElevator IID, but deliberately sharing Chrome's IElevator2 IIDs for forward compatibility, plus a unique `IElevatorDevelopment` interface for good measure.

The Mojo migration, if and when it comes, won't be a magic bullet for ABE security. The trust boundary is between processes, not IPC mechanisms. As long as the browser process needs access to decrypted data, code running inside that process has access too. That's the fundamental design constraint, and no amount of interface reshuffling changes it.

For now, the elevator's still running on the same track. Just with a slightly fancier control panel.

---

## References

- [Chromium Commit 49620496b8f0b7c0c63e2666a82e01180df3f4c3](https://chromium.googlesource.com/chromium/src/+/49620496b8f0b7c0c63e2666a82e01180df3f4c3) - Original commit adding IElevator2 (November 7, 2025)
- [Chromium Issue 383157189](https://issues.chromium.org/issues/383157189) - "Consider migrating app-bound APIs to mojo"
- [Chromium Issue 433545123](https://issues.chromium.org/issues/433545123) - Related IElevator2 tracking bug (not publicly accessible)
- [Mojo IPC Documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/mojo/README.md) - Chromium's IPC framework
- [Mojo Security Documentation](https://github.com/chromium/chromium/blob/main/docs/security/mojo.md) - Security guidelines for Mojo interfaces
- [CVE-2025-2783](https://fidelissecurity.com/vulnerabilities/cve-2025-2783/) - Mojo sandbox escape vulnerability
- [CVE-2025-10201](https://windowsforum.com/threads/cve-2025-10201-mojo-ipc-site-isolation-bypass-fixed-in-chrome-140.380595/) - Mojo site-isolation bypass
- [Chrome App-Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/) - Research tool for ABE analysis
- [COMrade ABE Analyzer](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/blob/main/tools/comrade_abe.py) - Python tool for COM interface introspection
- [The Curious Case of the Cantankerous COM](The_Curious_Case_of_the_Cantankerous_COM_Decrypting_Microsoft_Edge_ABE.md) - Edge ABE vtable analysis

## Appendix A: IElevator2 Interface IIDs

For reference, here are all the IElevator2-family IIDs across browsers:

### Chrome 144

| Interface | IID |
|-----------|-----|
| `IElevator2` (base) | `{8F7B6792-784D-4047-845D-1782EFBEF205}` |
| `IElevator2Chromium` | `{BB19A0E5-00C6-4966-94B2-5AFEC6FED93A}` |
| `IElevator2Chrome` | `{1BF5208B-295F-4992-B5F4-3A9BB6494838}` |
| `IElevator2ChromeBeta` | `{B96A14B8-D0B0-44D8-BA68-2385B2A03254}` |
| `IElevator2ChromeDev` | `{3FEFA48E-C8BF-461F-AED6-63F658CC850A}` |
| `IElevator2ChromeCanary` | `{FF672E9F-0994-4322-81E5-3A5A9746140A}` |

### Edge 144

| Interface | IID |
|-----------|-----|
| `IElevator2` (base only) | `{8F7B6792-784D-4047-845D-1782EFBEF205}` |

*Note: Edge adopted only the base IElevator2 interface - no vendor-specific variants.*

### Brave 144

| Interface | IID | Notes |
|-----------|-----|-------|
| `IElevator2` (base) | `{8F7B6792-784D-4047-845D-1782EFBEF205}` | Same as Chrome |
| `IElevator2Chromium` | `{BB19A0E5-00C6-4966-94B2-5AFEC6FED93A}` | Same as Chrome |
| `IElevator2Chrome` | `{1BF5208B-295F-4992-B5F4-3A9BB6494838}` | Same as Chrome |
| `IElevator2ChromeBeta` | `{B96A14B8-D0B0-44D8-BA68-2385B2A03254}` | Same as Chrome |
| `IElevator2ChromeDev` | `{3FEFA48E-C8BF-461F-AED6-63F658CC850A}` | Same as Chrome |
| `IElevator2ChromeCanary` | `{FF672E9F-0994-4322-81E5-3A5A9746140A}` | Same as Chrome |

*Note: Brave deliberately reuses Chrome's IElevator2 IIDs for forward compatibility.*

## Appendix B: Elevation Service CLSIDs

| Browser | CLSID |
|---------|-------|
| Chrome | `{708860E0-F641-4611-8895-7D867DD3675B}` |
| Edge | `{1FCBE96C-1697-43AF-9140-2897C7C69767}` |
| Brave | `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` |

## Appendix C: Base IElevator IIDs (v1)

| Browser | IID |
|---------|-----|
| Chrome | `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}` |
| Edge | `{A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C}` (same as Chrome) |
| Brave | `{5A9A9462-2FA1-4FEB-B7F2-DF3D19134463}` (unique) |
