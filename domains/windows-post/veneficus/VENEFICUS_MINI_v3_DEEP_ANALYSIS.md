<p align="center"><em>For educational purposes only. 2026 All rights reversed.</em></p>

---

# Veneficus Mini v3.0 — kit analysis

| | |
| --- | --- |
| **Date** | 4 September 2026 |
| **Tree** | `Veneficus_Mini_v3/` |
| **Language** | Rust 2021 · PowerShell stager · Cloudflare Worker JS |
| **Target (stated)** | Windows 10/11 x64 |
| **This document** | What every file does, how the kit is wired, which CVEs it *names*, and what is stubbed or broken. Not a build or employment guide. |

---

## Contents

1. [What this kit is](#1-what-this-kit-is)
2. [Inventory](#2-inventory)
3. [How it is supposed to fit together](#3-how-it-is-supposed-to-fit-together)
4. [CVEs and methods the kit names](#4-cves-and-methods-the-kit-names)
5. [File-by-file](#5-file-by-file)
6. [Missing / broken](#6-missing--broken)
7. [What is relatively complete](#7-what-is-relatively-complete)
8. [Control plane](#8-control-plane)
9. [Blue-team notes](#9-blue-team-notes)
10. [This tree vs the README](#10-this-tree-vs-the-readme)
11. [References](#11-references)

---

## 1. What this kit is

Veneficus Mini v3 is a **Rust implant + PowerShell stager + Cloudflare Worker relay** designed around this loop:

1. Stager ([`resources/loader.ps1`](resources/loader.ps1)) downloads a PE from a Worker `/beacon` URL and launches it.
2. Implant ([`src/main.rs`](src/main.rs)) scores the host, optionally patches AMSI/ETW, tries BYOVD against a hardcoded EDR process list, then starts theft / persistence / SOCKS / HVNC / clipper threads.
3. A blocking C2 loop ([`src/c2.rs`](src/c2.rs)) beacons and polls `/commands`.
4. The Worker ([`cloudflare/worker.js`](cloudflare/worker.js)) is meant to gate UUIDs, queue commands, hold config, and forward ciphertext to Telegram.

On paper that is a complete steal-and-control kit. In this tree it is a **partially wired prototype**: the control-flow skeleton in `main.rs` is real; many of the “fallback chains” are stubs; the Worker never delivers a payload on `/beacon` and never stores full exfil.

<p align="center">
  <img src="docs/architecture.png" alt="Intended architecture: loader to implant to Worker to Telegram">
</p>

<p align="center">
  <img src="docs/module_map.png" alt="Which modules are real code vs stubs">
</p>

---

## 2. Inventory

| Path | Present? | Role |
| --- | --- | --- |
| [`Cargo.toml`](Cargo.toml) | yes | crate metadata, features, deps |
| [`build.rs`](build.rs) | yes | compile-time implant UUID |
| [`build_command.txt`](build_command.txt) | yes | copy-paste build notes |
| [`README.md`](README.md) | yes | operator-facing spec (overstates completeness) |
| [`cloudflare/worker.js`](cloudflare/worker.js) | yes | C2 relay |
| `cloudflare/wrangler.toml` | **missing** | Worker bindings / deploy config |
| [`resources/loader.ps1`](resources/loader.ps1) | yes | AMSI-bypass stager |
| [`drivers/`](drivers/) | **empty dir** | BYOVD `.sys` payloads |
| [`tools/`](tools/) | **empty dir** | LSASS fallback binaries |
| [`src/main.rs`](src/main.rs) | yes | process entry / phase machine |
| [`src/aes_gcm_crypto.rs`](src/aes_gcm_crypto.rs) | yes | AES-256-GCM + HMAC |
| [`src/c2.rs`](src/c2.rs) | yes | HTTPS C2 client |
| [`src/byovd.rs`](src/byovd.rs) | yes | vulnerable-driver EDR kill |
| [`src/persistence.rs`](src/persistence.rs) | yes | WMI / schtask / Run key |
| [`src/proxy.rs`](src/proxy.rs) | yes | SOCKS5 |
| [`src/self_destruct.rs`](src/self_destruct.rs) | yes | wipe / log clear / re-infect |
| [`src/utils.rs`](src/utils.rs) | yes | sandbox score + DPAPI + helpers |
| [`src/payload/`](src/payload/) | yes | fingerprint, steal, LSASS, clipper |
| [`src/stealth/`](src/stealth/) | yes | syscall / DKOM / AMSI / ETW / lacuna |
| [`src/backdoor/hvnc.rs`](src/backdoor/hvnc.rs) | yes | RFB listener skeleton |
| [`src/lateral/ntlm.rs`](src/lateral/ntlm.rs) | yes | NTLM coercion **unused** |
| `{src/{crypto,...}/` | yes | **junk zip artefact**, empty |

The zip that produced this tree also contained a brace-expansion path (`Veneficus_Mini/{src/{crypto,payload,...}}`). That is packaging damage, not a module.

---

## 3. How it is supposed to fit together

### 3.1 Boot (`main.rs`)

<p align="center">
  <img src="docs/boot_phases.png" alt="Boot phases including dead Phase 5">
</p>

| Phase | What it does | Skip in safe mode? |
| --- | --- | --- |
| 0 | Debug-only logger; read `IMPLANT_UUID` from [`build.rs`](build.rs) | no |
| 1 | [`utils::assess_environment()`](src/utils.rs) → score 0–100 | no |
| 1a | score > 80 → [`self_destruct::execute(true)`](src/self_destruct.rs) and exit | — |
| 1b | score > 60 → `SAFE_MODE = true` | — |
| 2 | [`stealth::initialize()`](src/stealth/mod.rs) then BYOVD kill of named EDR PIDs | yes |
| 3 | threads: payload, persistence, SOCKS, HVNC, clipper | yes (fingerprint-only) |
| 4 | [`c2::run_command_loop()`](src/c2.rs) — **never returns** (`-> !`) | no |
| 5 | join threads, wipe | **dead code** |

Safe mode is an `AtomicBool`. C2 commands `/enter_safe` and `/exit_safe` flip it, but threads already spawned in phase 3 are not torn down or started when the flag later changes.

### 3.2 C2 data path

<p align="center">
  <img src="docs/c2_path.png" alt="C2 path: broken relay URL and truncated Telegram exfil">
</p>

AES-256-GCM key = SHA-256(`IMPLANT_UUID`). The Worker is not supposed to decrypt. In this tree [`relay_url()`](src/c2.rs) discards `RELAY_URL_BYTES` and [`worker.js`](cloudflare/worker.js) forwards only `ct.slice(0, 60)` to Telegram — **steal data cannot arrive**.

### 3.3 Steal pipeline

<p align="center">
  <img src="docs/steal_pipeline.png" alt="payload::run fingerprint, creds, LSASS; cookies unused">
</p>

---

## 4. CVEs and methods the kit names

The kit **names** several public n-days. Naming them in comments is not the same as implementing them. IOCTL constants in [`byovd.rs`](src/byovd.rs) often **do not match** public write-ups. Treat the table as “what the author pointed at,” then read the method notes.

### 4.1 CVE-2025-7771 — ThrottleStop.sys (BYOVD / physmem)

| | |
| --- | --- |
| **NVD** | [CVE-2025-7771](https://nvd.nist.gov/vuln/detail/CVE-2025-7771) |
| **CVE.org** | [Record](https://www.cve.org/cverecord?id=CVE-2025-7771) |
| **CNA** | Kaspersky |
| **CWE** | [CWE-782](https://cwe.mitre.org/data/definitions/782.html) Exposed IOCTL with Insufficient Access Control |
| **CVSS 4.0** | 8.7 HIGH — `AV:L/AC:H/PR:H` (local, high priv) |
| **Vendor** | [TechPowerUp ThrottleStop](https://www.techpowerup.com/download/techpowerup-throttlestop/) |
| **In-the-wild** | [Kaspersky Securelist — AV killer](https://securelist.com/av-killer-exploiting-throttlestop-sys/117026/) (MedusaLocker-adjacent “ThrottleBlood.sys”, Brazil IR, Aug 2025) |

**What the bug is.** `ThrottleStop.sys` (signed CPU-throttling helper) exposes IOCTLs that map physical memory via `MmMapIoSpace` with no real access control beyond “can open the device.” A local admin can read/write physical memory, patch the kernel, and run ring-0 code — including killing AV/EDR.

**What this kit does.** [`ThrottleStopTerminator`](src/byovd.rs) looks for `ThrottleBlood.sys` (the attacker-renamed filename from the Kaspersky report) and sends IOCTL `0x80002044` with **PID bytes only**. The file comments admit VA→PA translation is missing. That is not the documented physmem primitive. `drivers/` is empty, so the load never happens here.

### 4.2 CVE-2025-1055 and CVE-2025-52915 — K7RKScan.sys (process-kill IOCTL)

| | CVE-2025-1055 | CVE-2025-52915 |
| --- | --- | --- |
| **Record** | [CVE.org](https://www.cve.org/CVERecord?id=CVE-2025-1055) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-1055) | [CVE.org](https://www.cve.org/CVERecord?id=CVE-2025-52915) · [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-52915) |
| **Driver** | K7RKScan.sys (K7 Computing anti-malware) | same family, later build |
| **Typical version** | before / around 15.1.0.6 (low-priv caller) | 23.0.0.10 (admin check added; BYOVD still useful) |
| **CWE** | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) Missing Authorization | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) Improper Privilege Management |
| **CVSS 3.1** | 5.6 MEDIUM (Pentraze) | DoS via killing protected processes |
| **Write-up** | [BlackSnufkin — BYOVD evolution](https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/) | same |
| **Vendor** | [K7 Computing](https://k7computing.com) · [advisory 2 Sep 2025](https://support.k7computing.com/index.php?/solutions/view-article/Advisory-issued-on-2nd-Sep-2025) |

**What the bug is.** The driver exposes a kernel process-termination IOCTL to user mode. Older builds: almost no caller check (LPE + BYOVD). Newer builds: some admin/process filtering, but loading the `.sys` yourself as admin (classic BYOVD) still yields a kill primitive against third-party protected processes.

**What this kit does.** First entry in the pool: device `\\.\K7RKScan`, IOCTL **`0x830020C4`**, input = PID little-endian. Public PoCs for these CVEs often use a **different** IOCTL (e.g. `0x222018` in [diego-tella/CVE-2025-1055-poc](https://github.com/diego-tella/CVE-2025-1055-poc)). The constant in this tree should not be trusted without a driver IDA pass. File not present in `drivers/`.

### 4.3 CVE-2025-70795 — Safetica STProcessMonitor (BYOVD)

| | |
| --- | --- |
| **NVD** | [CVE-2025-70795](https://nvd.nist.gov/vuln/detail/CVE-2025-70795) |
| **Vendor KB** | [Safetica — ProcessMonitorDriver BYOVD](https://support.safetica.com/en/knowledge-base/cve-2025-70795-processmonitordriver-vulnerability-byovd) |
| **LOLDrivers** | [magicsword-io/LOLDrivers#268](https://github.com/magicsword-io/LOLDrivers/issues/268) |
| **Affected example** | STProcessMonitor / `ProcessMonitorDriver.sys` 11.11.4.0 |
| **Public IOCTL** | `0xB822200C` (Aqua / GHSA) |
| **Fix** | driver **11.34.5.0+** (function removed); update Safetica 11.30.35 / 11.34.6 |

**What the bug is.** Insufficient validation on a process-termination IOCTL. Admin (or anyone who can load the driver) can kill processes that user-mode APIs would not.

**What this kit does.** [`SafeticaTerminator`](src/byovd.rs) uses IOCTL **`0x22E084`** — the **same copy-pasted value** as TrueSight and wsftprm. That does **not** match the public `0xB822200C`. Almost certainly wrong.

### 4.4 CVE-2025-33073 — Windows SMB client (not EFS)

| | |
| --- | --- |
| **MSRC** | [Windows SMB Client Elevation of Privilege](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073) |
| **CVE.org** | [CVE-2025-33073](https://www.cve.org/CVERecord?id=CVE-2025-33073) |
| **Patch** | June 2025 Patch Tuesday |
| **CVSS 3.1** | **8.8 HIGH** `AV:N/AC:L/PR:L` — any domain user, network |
| **CISA KEV** | listed (see [KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)) |
| **Research** | [RedTeam Pentesting](https://www.redteam-pentesting.de/) (June 2025) · [BreakPoint Labs](https://breakpoint-labs.com/exploiting-the-reflective-kerberos-relay-flaw-cve-2025-33073/) · [Praetorian](https://www.praetorian.com/advisories/windows-smb-ntlm-reflection-one-hop/) · [Synacktiv](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025) |

**What the bug is.** Improper access control in the **Windows SMB client**. With any domain-user creds and a victim that does not enforce SMB signing, an attacker can coerce authentication and reflect it for **SYSTEM on the victim**. Often discussed as “NTLM/Kerberos reflection” / “one-hop,” not as an EFS bug.

**What this kit does.** [`ntlm.rs`](src/lateral/ntlm.rs) comments call it “Windows EFS escalation” and run `python3 CVE-2025-33073.py` via `cmd`. That is the **wrong subsystem**, the **wrong host** (a Windows implant is not Impacket), and the module is **never called** from `main.rs`. PrinterBug / PetitPotam in the same file `return true` without RPC.

### 4.5 Other drivers in the pool (no CVE string in source)

These are classic **LOLDrivers** / BYOVD names. See [LOLDrivers](https://www.loldrivers.io/) and Microsoft’s [vulnerable driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules).

| Kit name | Typical origin | Notes vs this tree |
| --- | --- | --- |
| **BdApiUtil64** | Bitdefender-related helper historically abused | IOCTL `0x9C402440`; file missing |
| **TrueSight** | Dell/BioCatch-era `truesight.sys` family, often IOCTL process kill | Shares `0x22E084` with two other structs (copy-paste) |
| **wsftprm** | older “WinRing”-style / third-party monitor | same IOCTL as TrueSight |
| **RTCore64** | MSI Afterburner / RTCore — arbitrary kernel R/W, years of abuse | `GenericDriver` + `String` in a `&[&dyn]` array: **likely compile error**; IOCTL `0xAA013044` |
| **capcom** | Capcom `capcom.sys` — execute user function in kernel (old, blocklisted) | same IOCTL as RTCore64; **not** a PID-kill interface |

<p align="center">
  <img src="docs/byovd_chain.png" alt="BYOVD fallback pool and empty drivers directory">
</p>

### 4.6 Methods that are not CVEs (user-mode tradecraft)

| Method | Where | Reality in this tree |
| --- | --- | --- |
| **AMSI patch** | [`stomp.rs`](src/stealth/stomp.rs) `AmsiScanBuffer` → `mov eax, 0x80070057; ret` | Real bytes; `amsi.dll` often **not loaded** in this native EXE. Stager does a separate, signatured reflection bypass. Classic technique: [Microsoft AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal). |
| **ETW patch** | `EtwEventWrite` → `xor eax, eax; ret` | More likely to apply (ntdll always loaded). Well-known 3-byte patch. |
| **Tartarus / Halo’s Gate / ntdll unhook / indirect syscalls** | [`syscalls.rs`](src/stealth/syscalls.rs) | All inits are `return true`. Allocators return null. **Unused.** Background reading: [sektor7](https://blog.sektor7.net/), [Alice Climent-Pommeret on Halo’s Gate](https://alice.climent-pommeret.red/posts/how-and-why-to-unhook-the-ntdll/). |
| **Call stack spoofing** | [`lacuna.rs`](src/stealth/lacuna.rs) + [lacuna-rs](https://github.com/Karkas66/lacuna-rs) | Wrappers exist; **never used** to issue syscalls. [CallGhost](https://github.com/PatchRequest/CallGhost) is in `Cargo.toml` and never imported. |
| **DKOM** | [`dkom.rs`](src/stealth/dkom.rs) | All methods `return false`. Needs kernel R/W this BYOVD path does not export. |
| **Chromium cookie/password crypto** | [`steal.rs`](src/payload/steal.rs) | DPAPI on the login blob. Chrome v80+ is `v10` + AES-GCM with key in `Local State`. See [Chromium OSCrypt](https://source.chromium.org/chromium/chromium/src/+/main:components/os_crypt/). |
| **LSASS MiniDumpWriteDump** | [`lsass.rs`](src/payload/lsass.rs) | Real API; needs `dbghelp` feature + SeDebugPrivilege; **PPL** on modern Windows usually blocks. [PPL](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-). |
| **WMI / schtask / HKLM Run** | [`persistence.rs`](src/persistence.rs) | Real `cmd`/`powershell` one-liners. Noisy. MITRE [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1546.003](https://attack.mitre.org/techniques/T1546/003/), [T1053.005](https://attack.mitre.org/techniques/T1053/005/). |
| **SOCKS5** | [`proxy.rs`](src/proxy.rs) | CONNECT only, localhost, disabled until `/proxy_on`. |
| **HVNC** | [`hvnc.rs`](src/backdoor/hvnc.rs) | RFB 3.8 handshake, no hidden desktop, no framebuffer. |
| **Clipper** | [`clipper.rs`](src/payload/clipper.rs) | Real clipboard loop; no-op without C2 config. MITRE [T1115](https://attack.mitre.org/techniques/T1115/) / [T1204](https://attack.mitre.org/techniques/T1204/) adjacent. |
| **PrinterBug / PetitPotam** | [`ntlm.rs`](src/lateral/ntlm.rs) | Stubs. Real techniques: [SpoolSample](https://github.com/leechristensen/SpoolSample), [PetitPotam](https://github.com/topotam/PetitPotam) (MS-EFSRPC). **Uncalled.** |

<p align="center">
  <img src="docs/lsass_chain.png" alt="LSASS dump fallback chain">
</p>

---

## 5. File-by-file

### Build

- **[`build.rs`](build.rs)** — UUID v4-shaped string via `getrandom`, `cargo:rustc-env=IMPLANT_UUID`. Identity **and** AES seed. Recoverable with `strings`. Does **not** emit `RELAY_URL_BYTES`.
- **[`Cargo.toml`](Cargo.toml)** — `windows` unused; `callghost` unused; `dbghelp` feature missing for MiniDump; several crates never `use`d.
- **[`build_command.txt`](build_command.txt)** — cross-compile notes; format of `RELAY_URL_BYTES` disagrees with `c2.rs` (which ignores the var anyway).

### C2 and crypto

- **[`src/aes_gcm_crypto.rs`](src/aes_gcm_crypto.rs)** — `GoldenGhost`: AES-256-GCM + HMAC-SHA256. `decrypt`/`verify` unused on the implant.
- **[`src/c2.rs`](src/c2.rs)** — **BROKEN** `relay_url()`: `option_env!("RELAY_URL_BYTES")` is discarded. Always `http://RELAY_URL_NOT_SET`. Command set: `/self_destruct`, `/re_infect`, `/status`, `/proxy_on|off`, `/enter_safe`, `/exit_safe`, `/sleep N`. Loop is `-> !`.
- **[`cloudflare/worker.js`](cloudflare/worker.js)** — service-worker `fetch` + module-style `env.*` (**ReferenceError** on load). No `wrangler.toml`. No `/beacon`. `/exfil` truncates ciphertext. Admin routes: `/admin`, `/register`, `/unregister`, `/listing`, `/set_config` (`X-Admin-Key`).

### Entry, scoring, persistence, proxy, wipe

- **[`src/main.rs`](src/main.rs)** — phases; `mod lateral` never used; EDR names exact-match; `option_env!` for ports.
- **[`src/utils.rs`](src/utils.rs)** — sandbox score (debugger/VM/RAM/disk/idle/CPUID/Google GET). `get_pids_by_name` equality. DPAPI helper.
- **[`src/persistence.rs`](src/persistence.rs)** — WMI `VUpdate` → task `WindowsUpdateSvc` → Run `WindowsUpdateHelper`. Uninstall can delete **all** `__FilterToConsumerBinding` objects.
- **[`src/proxy.rs`](src/proxy.rs)** — binds immediately, gates accept on `PROXY_ENABLED` (starts false). Nested thread + Tokio runtime.
- **[`src/self_destruct.rs`](src/self_destruct.rs)** — 3-pass overwrite, `FileDispositionInfo` class 4, `MoveFileExW` reboot, `wevtutil cl`. `re_infect` needs working `/config`.

### Payload

- **[`src/payload/mod.rs`](src/payload/mod.rs)** — fingerprint, creds, LSASS; **not** cookies, **not** clipper (clipper is its own thread).
- **[`src/payload/steal.rs`](src/payload/steal.rs)** — Chromium SQLite copy + DPAPI (wrong for v80+). Firefox `logins.json` as `NSS_ENC:`. Cookies unimplemented at the call site.
- **[`src/payload/lsass.rs`](src/payload/lsass.rs)** — MiniDump → missing tools → RTCore64 “kill LSASS.”
- **[`src/payload/clipper.rs`](src/payload/clipper.rs)** — 250 ms clipboard poll; config keys must match regex names (`bitcoin` ≠ `bitcoin_bech32`).

### Stealth / backdoor / lateral

- **[`src/stealth/mod.rs`](src/stealth/mod.rs)** — always returns `true`.
- **[`src/stealth/syscalls.rs`](src/stealth/syscalls.rs)** — stubs; `direct_allocate` unused.
- **[`src/stealth/lacuna.rs`](src/stealth/lacuna.rs)** — git crate wrappers, unused.
- **[`src/stealth/dkom.rs`](src/stealth/dkom.rs)** — always `false`.
- **[`src/stealth/stomp.rs`](src/stealth/stomp.rs)** — real patches; `GetCurrentProcess` imported from the wrong `winapi` module.
- **[`src/backdoor/hvnc.rs`](src/backdoor/hvnc.rs)** — localhost RFB skeleton.
- **[`src/lateral/ntlm.rs`](src/lateral/ntlm.rs)** — uncalled; PrinterBug/PetitPotam fake-success; `python3 -c "ntlmrelayx.py ..."` is invalid.

### Stager

- **[`resources/loader.ps1`](resources/loader.ps1)** — XOR+base64 URL placeholder `YOUR_XOR_B64_URL`; AMSI `amsiContext = IntPtr.Zero`; GET `/beacon`; drop `%TEMP%\MicrosoftEdgeUpdate.exe`. Worker has no `/beacon`.

---

## 6. Missing / broken

### Will not compile (likely)

| Issue | Where |
| --- | --- |
| `winapi` missing `dbghelp` | [`lsass.rs`](src/payload/lsass.rs) / [`Cargo.toml`](Cargo.toml) |
| `GetCurrentProcess` from `handleapi` | [`stomp.rs`](src/stealth/stomp.rs) |
| `GenericDriver` temporaries in `&[&dyn DriverConfig]` | [`byovd.rs`](src/byovd.rs) |
| Host is macOS; crate is Windows-only | whole tree |

### Will not talk C2 even if it compiled

| Issue | Effect |
| --- | --- |
| `relay_url()` discards `RELAY_URL_BYTES` | all HTTPS → `http://RELAY_URL_NOT_SET` |
| Worker `env.*` in service-worker scope | crash on load |
| No `wrangler.toml` | KV/secrets unbound |
| No `/beacon` | stager 404 |
| `/exfil` keeps 60 chars of `ct`, no KV | **all steal/beacon payloads lost** |

### Advertised, not implemented

| README / comment | Reality |
| --- | --- |
| Syscall gates | `return true` / null alloc |
| DKOM | `return false` |
| Hidden HVNC | RFB handshake only |
| NTLM / CVE-2025-33073 | unused; wrong model |
| Cookie theft in `run()` | never called |
| Chromium v80+ AES-GCM | DPAPI-only |
| CallGhost | dependency only |
| PoisonX driver | comment only |
| ThrottleStop phys R/W | PID-only IOCTL |
| Rate limiting | comment only |
| Runtime `BYOVD_DRIVER_DIR` / `TOOLS_DIR` | `option_env!` is compile-time |
| Driver and tool binaries | empty dirs |
| IOCTL constants | several **mismatch** public advisories |

### Logic / OPSEC (if the above were fixed)

- Phase 5 unreachable; clipper never stops.
- Safe-mode toggle does not start/stop phase-3 threads.
- Score > 80 destroys the implant **before** beacon.
- Extra GET to `https://www.google.com` in phase 1.
- Persistence/BYOVD spawn `cmd.exe` / `powershell.exe`.
- SOCKS/HVNC bind localhost; SOCKS binds even when “off.”
- EDR process names often wrong.
- UUID in the PE **is** the crypto seed.

---

## 7. What is relatively complete

Real code (bugs aside), not empty TODOs:

- Process graph in `main.rs`
- Sandbox scoring
- AES-GCM + HMAC helpers
- Small C2 verb list
- Worker route **shapes**
- Chromium SQLite copy (obsolete crypto)
- Firefox `logins.json` harvest (still encrypted)
- Native MiniDumpWriteDump attempt
- Clipper regex engine
- WMI / schtask / Run scripts
- SOCKS5 CONNECT
- AMSI/ETW byte patches
- Three-pass delete + wevtutil
- Per-build UUID
- File headers + inline “BROKEN” comments (this pass)

---

## 8. Control plane

| Actor | Channel | Auth |
| --- | --- | --- |
| Implant | POST `/exfil`, `/commands`, `/config` | UUID in `UUID_KV` |
| Operator | `/admin`, `/register`, `/unregister`, `/set_config`, GET `/listing` | `X-Admin-Key` |
| Stager | GET `/beacon` | none (**route missing**) |
| Telegram | bot `sendMessage` | Worker secrets |

There is no interactive shell. Config keys actually read: `clipper_addresses`, `reinfect_url`.

---

## 9. Blue-team notes

**Host**

- Children: `cmd.exe` (`sc`, `schtasks`, `reg`, `wevtutil`), `powershell.exe -ExecutionPolicy Bypass`
- Service names: `K7RKScan`, `BdApiUtil64`, `TrueSight`, `ThrottleBlood`, `STProcessMonitor`, `wsftprm`, `RTCore64`, `capcom`
- Persistence: WMI `VUpdate` / `VUpdateConsumer`; task `WindowsUpdateSvc`; Run `WindowsUpdateHelper`
- Files: `%TEMP%\MicrosoftEdgeUpdate.exe`, `%TEMP%\*.sys`, `%TEMP%\ld_*.db` / `ck_*.db`, `%TEMP%\~*.tmp` / `~*.exe`
- In-process: AMSI / `EtwEventWrite` prologue patches
- Clipboard ~4 Hz if clipper thread is up

**Network**

- HTTPS POST JSON to a Worker; paths `/exfil`, `/commands`, `/config`
- Chrome UA in `c2.rs` and `loader.ps1`
- Beacon ~10s ±30% or ~60s ±30%
- Startup GET `https://www.google.com`
- Local `127.0.0.1:1080` (SOCKS) and `:5900` (RFB `RFB 003.008`)

**Binary**

- UTF-8 UUID from `build.rs`
- Strings: command verbs, driver filenames, `Veneficus Mini`

MITRE ATT&CK (claimed behaviour, not a validated mapping): [T1055](https://attack.mitre.org/techniques/T1055/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1555.003](https://attack.mitre.org/techniques/T1555/003/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1090](https://attack.mitre.org/techniques/T1090/), [T1115](https://attack.mitre.org/techniques/T1115/), [T1218](https://attack.mitre.org/techniques/T1218/) (BYOVD / vulnerable driver).

---

## 10. This tree vs the README

Treat [README.md](README.md) as a **spec the author was writing toward**. The v3 “bug-fix table” mixes real edits (`dkom.rs` filename, clipper UTF-16, Worker `TELEGRAaM` typo) with fixes that reintroduced breaks (`RELAY_URL_BYTES` still unused; Worker `env`; exfil truncation).

Honest summary:

> Modular Rust implant skeleton with a Cloudflare + Telegram control idea. Theft, persistence, and local listeners are sketched. Syscall, DKOM, HVNC, NTLM, BYOVD, and modern Chromium decrypt are not delivered. C2 URL handling and Worker exfil are broken in ways that prevent the kit from functioning as a pipeline even after a successful compile. Several CVE names are real public n-days; the IOCTLs and call sites in this repo often do not match those advisories.

---

## 11. References

**This project**

**CVEs**

- [CVE-2025-7771](https://nvd.nist.gov/vuln/detail/CVE-2025-7771) · [Kaspersky write-up](https://securelist.com/av-killer-exploiting-throttlestop-sys/117026/)
- [CVE-2025-1055](https://www.cve.org/CVERecord?id=CVE-2025-1055) · [CVE-2025-52915](https://nvd.nist.gov/vuln/detail/CVE-2025-52915) · [BlackSnufkin](https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/) · [K7 advisory](https://support.k7computing.com/index.php?/solutions/view-article/Advisory-issued-on-2nd-Sep-2025)
- [CVE-2025-70795](https://nvd.nist.gov/vuln/detail/CVE-2025-70795) · [Safetica KB](https://support.safetica.com/en/knowledge-base/cve-2025-70795-processmonitordriver-vulnerability-byovd)
- [CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073) · [BreakPoint Labs](https://breakpoint-labs.com/exploiting-the-reflective-kerberos-relay-flaw-cve-2025-33073/) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**Drivers / blocklists**

- [LOLDrivers](https://www.loldrivers.io/)
- [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)

**Platform**

- [pocsuite3](https://github.com/knownsec/pocsuite3) is **not** used here (FortiGate kit only)
- [Cloudflare Workers](https://developers.cloudflare.com/workers/) · [Wrangler](https://developers.cloudflare.com/workers/wrangler/)
- [MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump)
- [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

**Diagrams in `docs/`**

| File | What |
| --- | --- |
| [architecture.png](docs/architecture.png) | Intended host → Worker → Telegram |
| [boot_phases.png](docs/boot_phases.png) | `main.rs` score branches |
| [c2_path.png](docs/c2_path.png) | Broken relay + truncated exfil |
| [byovd_chain.png](docs/byovd_chain.png) | Driver pool |
| [lsass_chain.png](docs/lsass_chain.png) | Dump fallbacks |
| [steal_pipeline.png](docs/steal_pipeline.png) | payload::run |
| [module_map.png](docs/module_map.png) | Real vs stub modules |

---

*Analysis of the extracted `Veneficus_Mini_v3` tree plus public CVE records. Author claims in comments and README were checked against the source and against NVD/MSRC/vendor KBs, not taken as fact. IOCTL numbers in this repo are not verified against the live drivers (the `.sys` files are not in tree).*
