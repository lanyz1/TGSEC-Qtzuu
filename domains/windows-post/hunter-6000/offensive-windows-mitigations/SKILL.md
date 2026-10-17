---
name: offensive-windows-mitigations
description: "Deep-dive on Windows exploit mitigations: ASLR, DEP/NX, CFG, CET/Shadow Stack, SEHOP, Heap Guard, ACG, Arbitrary Code Guard. Covers both the protection mechanism and known bypass techniques. Use when researching Windows exploit mitigations, planning bypass strategies, or understanding protection depth."
---

# SKILL: Week 6: Understanding Windows Mitigations

## Metadata
- **Skill Name**: windows-mitigations
- **Folder**: offensive-windows-mitigations
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/6-windows-mitigations.md

## Description
Deep-dive on Windows exploit mitigations: ASLR, DEP/NX, CFG, CET/Shadow Stack, SEHOP, Heap Guard, ACG, Arbitrary Code Guard. Covers both the protection mechanism and known bypass techniques. Use when researching Windows exploit mitigations, planning bypass strategies, or understanding protection depth.

## Trigger Phrases
Use this skill when the conversation involves any of:
`Windows mitigations, ASLR, DEP, NX, CFG, CET, shadow stack, SEHOP, heap guard, ACG, mitigation bypass, exploit mitigation, Windows hardening`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# Week 6: Understanding Windows Mitigations

## Overview

_created by AnotherOne from @Pwn3rzs Telegram channel_.

Last week you learned basic exploitation in an environment without protections.
This week, you'll learn about the defensive mechanisms that modern Windows systems employ to prevent those attacks.
Understanding these mitigations is essential before learning to bypass them (Week 8). Week 7 continues with enterprise security topics (offensive reconnaissance, Windows 11 24H2/25H2 mitigations, cross-platform defenses).

**This Week's Focus**:

- Understand how each mitigation works
- Learn to detect active mitigations
- Verify mitigation effectiveness
- Test exploits against protected binaries
- Prepare for Week 7's boundaries and Week 8's bypass techniques

### Prerequisites

Before starting this week, ensure you have:

- Completed Week 5: Basic Exploitation (Linux) - you should be able to exploit stack overflows, build ROP chains, and use pwntools
- A Windows 11 VM (isolated, snapshot before each exercise)
- Visual Studio 2022 Build Tools installed
- WinDbg Preview installed
- Basic familiarity with x64 assembly and calling conventions

### Week 6 Deliverables

By the end of this week, you should have completed the following:

- [ ] **Lab Environment**: Windows 11 VM with Visual Studio Build Tools, WinDbg Preview, and Sysinternals installed
- [ ] **Test Binaries**: Compiled `vulnerable_suite_win_mitigated.c` and `vuln_server_win.c` with various mitigation flags
- [ ] **DEP Verified**: Demonstrated DEP blocking shellcode execution with crash analysis (Exception Code 0xC0000005, Param 8)
- [ ] **ASLR Measured**: Recorded addresses of `check_aslr.exe` across 3 reboots and documented randomization behavior
- [ ] **Stack Cookie Tested**: Triggered `/GS` cookie check failure and analyzed in WinDbg
- [ ] **CFG Validated**: Demonstrated CFG blocking indirect call to invalid target
- [ ] **Crash Dumps Analyzed**: Created at least 3 crash dumps and identified which mitigation caused each termination using `!analyze -v`
- [ ] **Week 5 Exploit Retesting**: Re-ran Week 5 exploits against mitigated binaries and documented failures
- [ ] **Mitigation Audit Report**: Generated system-wide and per-binary mitigation audit using PowerShell scripts
- [ ] **Hardening Capstone**: Completed the SecureServer v1.0 hardening exercise (Day 7)

### Context

Why Mitigations Matter: Modern exploits chain multiple vulnerabilities and bypass layers of protection. Understanding mitigations helps you:

- Recognize when an exploit is blocked vs. when it succeeds
- Analyze crash dumps to identify exploitation attempts
- Design defense-in-depth strategies
- Prepare for Weeks 7-8 (advanced mitigations and bypass techniques)

**Recent CVEs Demonstrating Mitigation Importance**:

| CVE            | Vulnerability                   | Mitigations Involved | Outcome                               |
| -------------- | ------------------------------- | -------------------- | ------------------------------------- |
| CVE-2024-21338 | AppLocker (appid.sys) EoP       | KASLR, SMEP, kCFG    | Admin-to-Kernel bypass of kCFG        |
| CVE-2024-30088 | Authz Kernel TOCTOU             | KASLR, SMEP, CFG     | Exploited via race condition          |
| CVE-2023-36802 | MSKSSRV Object Type Confusion   | KASLR, SMEP, CFG     | Pool spray + type confusion to EoP    |
| CVE-2025-29824 | CLFS Driver Use-After-Free      | KASLR, SMEP          | Zero-day exploited in wild (Apr 2025) |
| CVE-2024-49138 | CLFS Heap-Based Buffer Overflow | DEP, ASLR, KASLR     | EoP exploited in wild (Dec 2024)      |
| CVE-2023-32019 | Windows Kernel Info Disclosure  | KASLR                | Leaked kernel memory bypassing KASLR  |
| CVE-2023-28252 | CLFS Driver EoP                 | KASLR, SMEP          | Abused CLFS log file parsing          |
| CVE-2022-34718 | Windows TCP/IP RCE (EvilESP)    | DEP, ASLR, CFG       | Required sophisticated heap grooming  |

**Connection to Week 4 (Crash Analysis)**:

When you receive a crash dump, the exception codes reveal which mitigation stopped the exploit:

```text
Week 4 Crash Analysis -> Week 6 Mitigation Identification
─────────────────────────────────────────────────────────
Process Exit Code         WinDbg Exception Code        Mitigation
──────────────────────    ─────────────────────        ──────────
0xC0000005 (Param[0]=8)   0xC0000005                   DEP violation (execute on NX page)
0xC0000409                0xC0000409 (subcode 2)        /GS stack cookie corruption
0x80000003                0xC0000409 (subcode 10)       CFG indirect call validation failed
0x80000003                0xC0000407                    CET shadow stack mismatch
0xC0000374                0xC0000374                    Heap integrity check failed

IMPORTANT: Python/cmd see the PROCESS EXIT CODE. WinDbg sees the EXCEPTION CODE.
CFG and CET both use __fastfail() which raises int 0x29 -> exit code 0x80000003,
but the EXCEPTION RECORD inside WinDbg shows the original status code.
```

### Windows Mitigations Relevance

Understanding these bug classes prepares you for real-world vulnerability research:

| Bug Class        | Example CVE                | Mitigation Interaction                            | Week 8 Bypass        |
| ---------------- | -------------------------- | ------------------------------------------------- | -------------------- |
| Race Condition   | CVE-2024-30088 (Authz)     | TOCTOU bypasses simple checks                     | Timing manipulation  |
| Type Confusion   | CVE-2023-36802 (MSKSSRV)   | CFG validates calls, but confused object bypasses | Object spray         |
| Pointer Deref    | CVE-2024-21338 (appid.sys) | kCFG bypass via direct manipulation               | Arbitrary read/write |
| Integer Overflow | CVE-2021-34535 (RDP)       | Safe integer functions                            | Find unchecked paths |
| Arbitrary Write  | CVE-2023-28252 (CLFS)      | KASLR, SMEP                                       | Info leak chain      |

## Week 6 Summary

This week provided comprehensive understanding of Windows exploit mitigations:

**Skills Acquired**:

- Detect and verify mitigations using `dumpbin`, `Get-ProcessMitigation`, and WinDbg
- Compile binaries with/without specific protections for testing
- Analyze crash dumps to identify which mitigation blocked an exploit
- Understand the hardware foundations (NX bit, Intel CET, VBS)
- Map Linux mitigations to Windows equivalents

**Mitigation Quick Reference**:

| Mitigation    | Compile Flag     | Runtime Check    | Bypass Preview (Week 8)  |
| ------------- | ---------------- | ---------------- | ------------------------ |
| DEP           | `/NXCOMPAT`      | Execute fault    | ROP chains               |
| ASLR          | `/DYNAMICBASE`   | Random addresses | Info leaks               |
| High Entropy  | `/HIGHENTROPYVA` | 17+ bits entropy | Partial overwrites       |
| Stack Cookies | `/GS` (default)  | Cookie mismatch  | Leak/brute force         |
| CFG           | `/guard:cf`      | Bitmap check     | Valid targets, data-only |
| XFG           | OS-level (auto)  | Type hash check  | Type confusion           |
| CET           | `/CETCOMPAT`     | Shadow stack     | COOP, JOP (difficult)    |

**Connection to Other Weeks**:

```text
Week 4 (Crash Analysis)          Week 6 (Mitigations)
----------------------------------------------------------
Crash dump with 0xC0000005   ->   Identify DEP violation (Param[0]=8 for execute)
Process exit  0xC0000409     ->   Identify /GS cookie failure (subcode 2)
Process exit  0x80000003     ->   Identify CFG or CET block (__fastfail -> int 0x29)
WinDbg exc.   0xC0000409     ->   Check subcode: 2=/GS, 10=CFG (exit code differs!)
!analyze -v output           ->   Map to specific protection
Bucket ID patterns           ->   Determine exploit type

Week 5 (Basic Exploitation)      Week 6 (Mitigations)
----------------------------------------------------------
Stack overflow -> shellcode   ->   Blocked by DEP + ASLR + /GS
ret2libc with known addrs     ->   Blocked by ASLR
Heap overflow -> func ptr     ->   Blocked by CFG
Format string -> GOT write    ->   Blocked by CFG + ASLR

Week 6 (Mitigations)            Week 8 (Bypass Techniques)
----------------------------------------------------------
DEP blocks shellcode         ->   ROP/ret2libc bypass
ASLR hides addresses         ->   Info leak techniques
/GS detects overflow         ->   Canary leak/brute force
CFG validates calls          ->   Valid target abuse
```

**Looking Ahead to Week 7**:

Week 7 continues your mitigation education with advanced enterprise security topics:

- **Offensive Reconnaissance & Mitigation Fingerprinting**: Learn target enumeration - build comprehensive scanners to fingerprint system and process mitigations, identify weak points, and plan multi-stage attack paths
- **Windows 11 24H2/25H2 Specific Mitigations**: Learn the latest security features including KASLR API restrictions, Administrator Protection, Smart App Control, HVCI defaults, and enhanced Mark of the Web protections
- **Next-Gen Mitigations (Critical for 2025)**: Learn defenses like XFG (eXtended Flow Guard), Kernel CET Shadow Stack, ARM64 PAC/BTI/MTE, and Linux innovations like io_uring, Landlock, and eBPF LSM
- **Smart App Control (SAC) and Administrator Protection**: Bypass Windows 11's application whitelisting and admin authentication requirements through signed malware, LNK files, and trust chain abuse
- **Cross-platform mitigations**: Master both Windows and Linux defense landscapes - from CFG/XFG to seccomp/io_uring bypasses, and understand ARM64-specific protections
- **Kernel Data Protection (KDP) and Secure Boot**: Learn to bypass hypervisor-based protections, secure boot chains, and kernel-level exploit mitigations
- **Comprehensive mitigation scanner development**: Build offensive reconnaissance tools that enumerate all system-level and process-level protections remotely
- **Remote mitigation fingerprinting techniques**: Develop capabilities to identify attack surfaces, legacy binaries, and unprotected processes without direct system access
- **Real-world malware evasion and bypass strategies**: Study actual threat actor techniques for bypassing enterprise defenses and maintaining persistence

**Looking Ahead to Week 8**:

After completing Weeks 6-7 (understanding mitigations), Week 8 teaches bypass techniques:

- **Information Leaks and Defeating ASLR**: Master format string exploits, buffer over-reads, and UAF techniques to leak addresses and calculate base offsets, defeating address space layout randomization
- **Return-Oriented Programming (ROP) for DEP Bypass**: Build sophisticated ROP chains using existing code gadgets - from basic ret2libc to advanced techniques like ORW, ret2csu, SROP, and stack pivoting
- **Windows Data-Only Attacks, Indirect Syscalls & Stack Canary Bypass**: Learn modern techniques that avoid code execution entirely - overwrite function pointers, abuse indirect syscalls, and bypass /GS protections through canary leaks
- **Control Flow Guard (CFG) and XFG Bypasses**: Defeat Microsoft's control-flow integrity protections through valid target abuse, forward-edge CFI bypasses, and XFG circumvention techniques
- **Heap Exploitation with Modern Protections**: Master advanced heap techniques like tcache poisoning, safe linking bypasses, and House of Apple/Kiwi variants despite glibc hardening
- **CVE Case Studies and Real-World Exploit Chains**: Analyze complete exploit chains from actual vulnerabilities - understanding how multiple bypass techniques combine for full compromise
- **ARM64 Exploitation — PAC, BTI & MTE Bypass**: Learn ARM64-specific exploitation including pointer authentication code signing bypasses, branch target identification circumvention, and memory tagging exploitation

<!-- Written by AnotherOne from @Pwn3rzs Telegram channel -->
## 分册索引（按需加载，不要一次全读）

- [Day 1: DEP and ASLR Fundamentals](references/day-1-dep-and-aslr-fundamentals.md) — 62 KB
- [Day 2: Stack Protection Mechanisms](references/day-2-stack-protection-mechanisms.md) — 117 KB
- [Day 3: Control Flow Integrity (CFG, CET, XFG)](references/day-3-control-flow-integrity-cfg-cet-xfg.md) — 49 KB
- [Day 4: Heap Protections and Memory Integrity](references/day-4-heap-protections-and-memory-integrity.md) — 68 KB
- [Day 5: Virtualization-Based Security (VBS) and HVCI](references/day-5-virtualization-based-security-vbs-and-hvci.md) — 89 KB
- [Day 6: Comprehensive Mitigation Testing and Validation](references/day-6-comprehensive-mitigation-testing-and-validation.md) — 58 KB
- [Day 7: Capstone Project - The Hardening Campaign](references/day-7-capstone-project-the-hardening-campaign.md) — 13 KB
- [Appendix A: CLFS Deep Dive](references/appendix-a-clfs-deep-dive.md) — 26 KB
- [Appendix C: Some Other Mitigations](references/appendix-c-some-other-mitigations.md) — 13 KB

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
