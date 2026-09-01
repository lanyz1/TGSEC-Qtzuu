---
name: ctf-reverse
description: "CTF 逆向工程技术。当挑战提供未知二进制文件需要分析算法逻辑、游戏客户端需要破解验证、混淆代码需要还原、自定义 VM 需要解释执行时使用。覆盖 Ghidra/IDA 静态分析、GDB/Frida 动态调试、反调试绕过、WASM/.NET/APK/Python 字节码/Go/Rust 多平台逆向"
metadata:
  tags: "ctf,reverse,逆向,ghidra,gdb,ida,frida,angr,反调试,binary,ELF,binary analysis,disassembly"
  category: "ctf"
---

# CTF 逆向工程

## 深入参考

以下参考资料**按需加载**，根据识别出的具体方向选择对应文件：

- 静态分析工具（GDB/Ghidra/radare2/IDA/WASM/APK/.NET） → [references/tools.md](references/tools.md)
- 动态分析工具（Frida/angr/lldb/Qiling/Triton） → [references/tools-dynamic.md](references/tools-dynamic.md)
- 高级工具（VMProtect/BinDiff/反混淆/Rizin/补丁） → [references/tools-advanced.md](references/tools-advanced.md)
- 反分析对抗（Linux/Windows反调试/反VM/反DBI/代码完整性） → [references/anti-analysis.md](references/anti-analysis.md)
- 语言特征（Python字节码/Lua/WASM/.NET IL/Solidity） → [references/languages.md](references/languages.md)
- 编译语言（Go/Rust/Swift/Kotlin/C++/D/Nim） → [references/languages-compiled.md](references/languages-compiled.md)
- 平台特定（嵌入式固件/macOS Mach-O/Android/Flutter/HarmonyOS） → [references/platforms.md](references/platforms.md)
- 语言与平台综合 → [references/languages-platforms.md](references/languages-platforms.md)
- 逆向模式（校验/编码/迷宫/虚拟机/游戏引擎） → [references/patterns.md](references/patterns.md)
- CTF 逆向模式 Part1（自定义加密/矩阵/Brainfuck JIT） → [references/patterns-ctf.md](references/patterns-ctf.md)
- CTF 逆向模式 Part2（约束求解/侧信道/混淆变换） → [references/patterns-ctf-2.md](references/patterns-ctf-2.md)
- CTF 逆向模式 Part3（Z3布尔电路/滑窗Popcount/多步加密） → [references/patterns-ctf-3.md](references/patterns-ctf-3.md)
- 运行时修补与Oracle（反分析Patch/多阶段Shellcode） → [references/patterns-runtime.md](references/patterns-runtime.md)
- CTF反分析实战（SIGILL/SIGFPE/ptrace时序/花指令） → [references/anti-analysis-ctf.md](references/anti-analysis-ctf.md)
- 仿真与侧信道工具（Qiling/Triton/Unicorn/指令计数） → [references/tools-emulation.md](references/tools-emulation.md)
- 硬件与特殊架构（HD44780 LCD/RISC-V/FPGA/自定义ISA） → [references/platforms-hardware.md](references/platforms-hardware.md)
- 逆向实战笔记（二进制类型速查/反调试绕过/常用patch） → [references/field-notes.md](references/field-notes.md)

---

## 分类决策树

```
拿到逆向题？
├─ 识别文件类型: file binary
│  ├─ ELF → GDB + Ghidra
│  ├─ PE/DLL → x64dbg + IDA
│  ├─ Mach-O → lldb + Hopper
│  ├─ APK → apktool + jadx (Flutter → Blutter)
│  ├─ .NET → dnSpy / ILSpy
│  ├─ Python .pyc → uncompyle6 / decompyle3
│  ├─ WASM → wasm-decompile / wasm2wat
│  └─ 未知 → binwalk + strings + hexdump
├─ 分析策略
│  ├─ 静态优先 → Ghidra反编译 → 找 main/check 函数
│  ├─ 动态辅助 → GDB断点 / Frida hook
│  ├─ 符号执行 → angr（自动探路）
│  └─ 反混淆 → D-810 / GOOMBA / Miasm
├─ 有反调试？ → [references/anti-analysis.md](references/anti-analysis.md)
│  ├─ ptrace → LD_PRELOAD hook
│  ├─ /proc/self/status → 修改返回值
│  └─ 时间检测 → 跳过或 patch
└─ 常见模式
   ├─ 逐字符校验 → 逐字节爆破/约束求解
   ├─ 矩阵变换 → numpy/Z3 逆运算
   ├─ 自定义VM → 提取opcode表 → 反汇编
   └─ 迷宫 → BFS/DFS 自动求解
```

## 快速启动命令

```bash
# 基础分析
file binary && checksec binary
strings -n 6 binary | grep -iE "flag|pass|correct"
objdump -d binary | head -100

# GDB 调试
gdb -q binary -ex 'b main' -ex 'r'

# Ghidra 无头分析
analyzeHeadless /tmp/proj proj -import binary -postScript ExportDecompiled.java

# angr 符号执行
python3 -c "
import angr
p = angr.Project('./binary')
s = p.factory.entry_state()
sm = p.factory.simgr(s)
sm.explore(find=0x TARGET_ADDR)
print(sm.found[0].posix.dumps(0))
"
```

## 常见反调试绕过

| 技术 | 绕过方法 |
|------|---------|
| ptrace(PTRACE_TRACEME) | `LD_PRELOAD` hook 返回0 |
| /proc/self/status | 修改 TracerPid |
| 时间检测 | patch 掉 rdtsc/clock |
| IsDebuggerPresent (Win) | PEB.BeingDebugged = 0 |

## 工具速查

| 工具 | 用途 |
|------|------|
| Ghidra | 免费反编译器（支持多架构） |
| GDB + pwndbg | Linux 动态调试 |
| Frida | 运行时 hook（跨平台） |
| angr | 符号执行引擎 |
| dogbolt.org | 在线多反编译器对比 |
