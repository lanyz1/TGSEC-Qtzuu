---
name: ctf-pwn
description: "CTF 二进制漏洞利用(Pwn)技术。当挑战提供 ELF/PE 可执行文件并开放 nc 端口、存在栈溢出/堆溢出/格式化字符串/UAF 漏洞时使用。覆盖 ROP 链构造、堆利用(tcache/House of Orange/Spirit)、内核利用、seccomp 沙箱逃逸、pwntools 自动化利用脚本编写"
metadata:
  tags: "ctf,pwn,binary,exploit,overflow,rop,heap,kernel,shellcode,格式化字符串"
  category: "ctf"
---

# CTF 二进制漏洞利用 (Pwn)

## 深入参考

以下参考资料**按漏洞类型组织**，按需加载：

| 漏洞类型 | skill 引用 |
|---------|----------------|
| 栈溢出 / ret2win / Canary绕过 | [references/stack-overflow.md](references/stack-overflow.md) |
| 格式化字符串 / 泄漏 / GOT覆写 / Blind Pwn | [references/format-string.md](references/format-string.md) |
| 堆(UAF/double free/tcache/House of X) | [references/heap-exploitation.md](references/heap-exploitation.md) |
| ROP(ret2csu/ret2libc/SROP/seccomp绕过/RETF) | [references/rop-techniques.md](references/rop-techniques.md) |
| 内核堆喷 / tty_struct / userfaultfd / modprobe_path | [references/kernel-exploitation.md](references/kernel-exploitation.md) |
| KASLR / KPTI / SMEP / SMAP / FGKASLR 绕过 | [references/kernel-bypass.md](references/kernel-bypass.md) |
| 自定义VM / JIT / 类型混淆 / FSOP / Windows / ARM | [references/advanced-pwn.md](references/advanced-pwn.md) |
| Python沙箱 / FUSE / Busybox / 受限Shell | [references/sandbox-escape.md](references/sandbox-escape.md) |
| 栈溢出基础 / 结构体覆写 / 有符号整数 / Canary | [references/overflow-basics.md](references/overflow-basics.md) |
| ROP链构造 / ret2csu / XOR编码 / shellcode | [references/rop-and-shellcode.md](references/rop-and-shellcode.md) |
| 高级ROP / 双栈迁移 / UTF-8 SROP / RETF绕seccomp | [references/rop-advanced.md](references/rop-advanced.md) |
| 堆技术(House of Apple2/Einherjar/自定义分配器) | [references/heap-techniques.md](references/heap-techniques.md) |
| 堆FILE结构(fastbin→stdout/vtable劫持/glibc 2.24+) | [references/heap-fsop.md](references/heap-fsop.md) |
| 内核基础(环境/堆喷结构/栈溢出/提权原语) | [references/kernel.md](references/kernel.md) |
| 内核技术(tty_struct/userfaultfd/SLUB/Panic泄漏) | [references/kernel-techniques.md](references/kernel-techniques.md) |
| 高级利用2(字节码/io_uring/整数截断/GC) | [references/advanced-exploits-2.md](references/advanced-exploits-2.md) |
| 高级利用3(栈变量重叠/1字节溢出/GOT覆写) | [references/advanced-exploits-3.md](references/advanced-exploits-3.md) |
| 高级利用4(Windows SEH/ARM Thumb/Forth/GF(2)) | [references/advanced-exploits-4.md](references/advanced-exploits-4.md) |
| 高级利用5(Chip-8模拟器/浮点Canary/Bloom Filter) | [references/advanced-exploits-5.md](references/advanced-exploits-5.md) |
| Pwn 实战笔记(堆速查/利用备忘/常用命令) | [references/field-notes.md](references/field-notes.md) |

### 大文件目录索引 (>300行，建议先看目录定位)

**format-string.md (331行)：**
- Format String Basics / Argument Retargeting / Blind Pwn / Filter Bypass / Canary+PIE Leak / \_\_free\_hook Overwrite / .rela.plt Patching / Game State / .bss Pivot / argv[0] Leak

**kernel-bypass.md (421行)：**
- KASLR/FGKASLR Bypass / KPTI Bypass (4 methods) / SMEP/SMAP Bypass / GDB Debug / Initramfs Workflow / Exploit Templates

**kernel-exploitation.md (398行)：**
- QEMU Setup / vmlinux提取 / Config Checks / Heap Spray Structures / ret2usr / kROP / modprobe\_path / core\_pattern / tty\_struct / userfaultfd / SLUB Internals / Cross-Cache / PTE Overlap

**advanced-pwn.md (591行)：**
- VM Exploitation / Integer Vulnerabilities / Memory Primitives / Arbitrary R/W / FSOP+Heap / Specialized (ASAN/DNS/ELF Signing/JIT) / TLS Destructor / GF(2) Gaussian / Windows/ARM/Forth

---

## 分类决策树

```
Pwn 题目分析？
├─ 检查保护: checksec binary
│  ├─ PIE 关闭 → 地址固定，直接覆写 GOT/PLT
│  ├─ Partial RELRO → GOT 可写 → GOT覆写
│  ├─ Full RELRO → 需找替代目标(hooks/vtable/.fini_array)
│  ├─ NX 开启 → 不能执行栈/堆shellcode → 用 ROP
│  └─ Canary → 需泄漏或用堆/字节溢出绕过
├─ 漏洞类型
│  ├─ 栈溢出
│  │  ├─ 基础 ret2win → `stack-overflow.md`
│  │  ├─ ret2libc / ROP → `rop-techniques.md`
│  │  ├─ Canary绕过 → `stack-overflow.md` + `advanced-pwn.md`
│  │  └─ 堆叠溢出 → `advanced-pwn.md`
│  ├─ 格式化字符串
│  │  └─ `format-string.md`
│  ├─ 堆(UAF/double free/tcache)
│  │  ├─ 基础 tcache poisoning → `heap-exploitation.md`
│  │  ├─ House of X/Orange/Lore → `heap-exploitation.md` + `advanced-pwn.md`
│  │  └─ FSOP → `advanced-pwn.md`
│  ├─ 内核模块
│  │  ├─ 基础环境/提权 → `kernel-exploitation.md`
│  │  └─ 保护绕过 → `kernel-bypass.md`
│  └─ 自定义 VM / JIT / 类型混淆
│     └─ `advanced-pwn.md`
└─ 利用链
   ├─ 泄漏 → 计算libc基址 → one_gadget / system / FSOP
   ├─ ROP → ret2libc / SROP / ret2dlresolve / seccomp绕过
   └─ 堆 → House of X / tcache poisoning → __free_hook / TLS dtors
```

---

## 保护机制速查

| 保护 | 状态 | 影响 | 绕过方法 |
|------|------|------|---------|
| PIE | 关闭 | GOT/PLT/函数地址固定 | 直接覆写 |
| PIE | 开启 | 地址随机化 | 泄漏 → 计算基址 |
| RELRO | Partial | GOT 可写 | GOT覆写 |
| RELRO | Full | GOT 只读 | hooks/vtable/.fini_array/FSOP |
| NX | 开启 | 栈不可执行 | ROP |
| NX | 关闭 | 栈可执行 | shellcode |
| Canary | 有 | 溢出被检测 | 泄漏/字节溢出/BRK |

---

## 常见危险函数

```
gets() / scanf("%s") / strcpy()  → 栈溢出
printf(user_input)               → 格式化字符串
free() 后继续使用               → UAF
read(fd, buf, size)              → 堆溢出 / 栈溢出
```

---

## pwntools 模板

```python
from pwn import *
context.binary = elf = ELF('./binary')
libc = ELF('./libc.so.6')
p = remote('host', port)  # or process('./binary')
# 泄漏 → 计算基址 → 覆写 → getshell
```

---

## 竞争条件利用

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

---

## 注意事项

- **先泄漏再攻击**：几乎所有 exploit 都依赖信息泄漏，优先找泄漏点
- **one_gadget 约束检查**：找到 gadget 后用 `one_gadget libc.so.6` 列出所有，再筛选满足约束的
- **seccomp-tools dump**：必先检查 seccomp 规则，再决定绕过方案
- **pwntools corefile**：崩溃后自动生成 core 文件，用 `cyclic_find()` 精确定位溢出偏移
