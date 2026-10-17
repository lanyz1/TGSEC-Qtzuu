---
name: offensive-crash-analysis
description: "Week 4 exploit development curriculum. Crash triage and analysis methodology: WinDbg/GDB analysis, ASAN/MSAN output interpretation, exploitability assessment, register/stack trace reading, root cause identification. Use when analyzing crash dumps, assessing exploitability, or understanding fuzzer-generated crashes."
---

# SKILL: Week 4: Crash Analysis and Exploitability Assessment

## Metadata
- **Skill Name**: crash-analysis
- **Folder**: offensive-crash-analysis
- **Source**: https://github.com/SnailSploit/offensive-checklist/blob/main/4-crash-analysis.md

## Description
Week 4 exploit development curriculum. Crash triage and analysis methodology: WinDbg/GDB analysis, ASAN/MSAN output interpretation, exploitability assessment, register/stack trace reading, root cause identification. Use when analyzing crash dumps, assessing exploitability, or understanding fuzzer-generated crashes.

## Trigger Phrases
Use this skill when the conversation involves any of:
`crash analysis, crash triage, WinDbg, GDB, ASAN, MSAN, exploitability, stack trace, register dump, segfault, null deref, access violation, week 4`

## Instructions for Claude

When this skill is active:
1. Load and apply the full methodology below as your operational checklist
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target/context
4. Track which checklist items have been completed
5. Suggest next steps based on findings

---

## Full Methodology

# Week 4: Crash Analysis and Exploitability Assessment

## Overview

_created by AnotherOne from @Pwn3rzs Telegram channel_.

After finding potential vulnerabilities through fuzzing (Week 2) or patch diffing (Week 3), the next critical step is analyzing crashes to determine if they're exploitable. This week focuses on crash triage, debugger mastery, and techniques for identifying how to reach vulnerable code paths from attacker-controlled input.

Once you've confirmed a crash is exploitable and built a PoC, you'll be ready for Basic Exploitation in Week 5.

### Prerequisites

Before starting this week, ensure you have:

- A Windows VM (for WinDbg labs) and a Linux VM (for GDB/ASAN/CASR labs).
- Completed Week 2 fuzzing labs, including running AFL++ or libFuzzer against at least one C/C++ target
- Completed (or skimmed) Week 3 patch diffing labs:
  - Familiar with Ghidriff/Diaphora diff reports and how to interpret changed functions
  - Understand how to extract Windows updates and Linux kernel patches
  - Reviewed at least one case study (CVE-2022-34718 EvilESP, CVE-2024-1086 nf_tables, or 7-Zip symlink bugs)
- Comfortable understanding from Week 1 of basic vulnerability classes (buffer overflow, UAF, integer bugs, info leaks) and their exploit primitives

### Crash Analysis Decision Tree

Use this decision tree to select the appropriate tools and workflow for any crash you encounter:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CRASH RECEIVED                               │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ Source code available?│
                    └───────────────────────┘
                      │                    │
                     Yes                   No
                      │                    │
                      ▼                    ▼
        ┌─────────────────────┐   ┌──────────────────────────┐
        │ Recompile with      │   │ What platform?           │
        │ ASAN + UBSAN        │   └──────────────────────────┘
        │ (Day 2)             │     │         │         │
        └─────────────────────┘     │         │         │
                      │          Windows   Linux    Mobile
                      │             │         │         │
                      ▼             ▼         ▼         ▼
        ┌─────────────────────┐ ┌───────┐ ┌───────┐ ┌───────────┐
        │ Run crash input     │ │WinDbg │ │Pwndbg │ │ Tombstone │
        │ Get detailed report │ │+ TTD  │ │+ rr   │ │ + Frida   │
        └─────────────────────┘ │(Day 1)│ │(Day 1)│ │ (Future)  │
                      │         └───────┘ └───────┘ └───────────┘
                      │             │         │         │
                      └─────────────┴────┬────┴─────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────┐
                    │ Crash requires special environment? │
                    └─────────────────────────────────────┘
                       │                              │
                      Yes                             No
                       │                              │
                       ▼                              │
        ┌─────────────────────────────┐               │
        │ Setup reproduction env:     │               │
        │ - Network (tcpdump, proxy)  │               │
        │ - Files (strace, procmon)   │               │
        │ - Services (docker, VM)     │               │
        └─────────────────────────────┘               │
                       │                              │
                       └──────────────┬───────────────┘
                                      │
                                      ▼
                            ┌─────────────────────┐
                            │ Crash type known?   │
                            └─────────────────────┘
                              │                 │
                             Yes                No
                              │                 │
                              ▼                 ▼
                ┌─────────────────────┐  ┌─────────────────────┐
                │ Run CASR for        │  │ Manual analysis:    │
                │ classification      │  │ - Examine registers │
                │ (Day 3)             │  │ - Check memory      │
                └─────────────────────┘  │ - Disassemble       │
                              │          │ (Day 3)             │
                              │          └─────────────────────┘
                              │                 │
                              └────────┬────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ EXPLOITABILITY ASSESS   │
                          │ - Check mitigations     │
                          │ - Control analysis      │
                          │ - Reachability (Day 4)  │
                          └─────────────────────────┘
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ Multiple crashes?       │
                          └─────────────────────────┘
                            │                    │
                           Yes                   No
                            │                    │
                            ▼                    ▼
              ┌─────────────────────┐   ┌─────────────────────┐
              │ Deduplicate (Day 5) │   │ Minimize (Day 5)    │
              │ - CASR cluster      │   │ - afl-tmin          │
              │ - Stack hash        │   │ - Manual reduction  │
              └─────────────────────┘   └─────────────────────┘
                            │                    │
                            └────────┬───────────┘
                                     │
                                     ▼
                        ┌─────────────────────────┐
                        │ Create PoC (Day 6)      │
                        │ - Python + pwntools     │
                        │ - Verify reliability    │
                        │ - Document findings     │
                        └─────────────────────────┘
```

**Quick Reference - Tool Selection by Scenario**:

| Scenario                    | Primary Tool               | Secondary Tool   | Sanitizer    |
| --------------------------- | -------------------------- | ---------------- | ------------ |
| Linux binary, have source   | GDB + Pwndbg               | rr               | ASAN + UBSAN |
| Linux binary, no source     | GDB + Pwndbg               | Ghidra           | N/A          |
| Windows binary, have source | WinDbg + TTD               | Visual Studio    | ASAN         |
| Windows binary, no source   | WinDbg + TTD               | IDA/Ghidra       | N/A          |
| Fuzzer crash corpus         | CASR                       | afl-tmin         | ASAN         |
| Non-deterministic crash     | rr (Linux) / TTD (Windows) | Chaos mode       | TSAN         |
| Kernel crash (Linux)        | crash utility              | GDB + KASAN      | KASAN        |
| Kernel crash (Windows)      | WinDbg kernel              | Driver Verifier  | N/A          |
| Android app crash           | Tombstone + ndk-stack      | Frida            | HWASan       |
| Rust/Go crash               | Native debugger            | Sanitizer output | Built-in     |

## 分册索引（按需加载，不要一次全读）

- [分册 01](references/part-01.md) — 97 KB：Day 1: Debugger Fundamentals and Crash Dump Analysis
- [分册 02](references/part-02.md) — 57 KB：Crash: stack_overflow；Day 2: AddressSanitizer and Memory Error Classification
- [分册 03](references/part-03.md) — 58 KB：Bug: heap_overflow.c；Day 3: Exploitability Assessment with Automated Tools；What crashed?；What register/memory was accessed?；Is that value attacker-controlled?；What mitigations are active?；Initial classification；Exploitability Assessment；Summary；Unique Bug Classes (Clusters)；Priority Crashes (EXPLOITABLE)；Recommendations；Crash Signature；Primitive Classification；Attacker Control Assessment；Reachability Analysis；Active Mitigations；Reproduction；Recommended Priority；Raw Data；Crash Signature；Primitive Classification；Attacker Control Assessment
- [分册 04](references/part-04.md) — 52 KB：Reachability Analysis；Active Mitigations；Reproduction；Recommended Priority；Day 4: Reachability Analysis - Tracing Input to Crash；Reachability Analysis: HTTP Server Crash；Target Information；Input Source → Sink Path；Data Flow Evidence；Attack Surface Assessment；Proof of Concept；Verdict
- [分册 05](references/part-05.md) — 42 KB：Day 5: Crash Deduplication and Corpus Minimization
- [分册 06](references/part-06.md) — 38 KB：Day 6: Creating PoC Reproducers and Automation
- [分册 07](references/part-07.md) — 35 KB：Capstone Project - The Crash Analysis Pipeline；Executive Summary；Methodology；Findings；Recommendations；Attachments

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
