---
name: memory-forensics-evasion
description: "内存取证与反内存取证方法论。从蓝队视角理解内存取证如何发现恶意行为（Volatility3 分析流程），从红队视角掌握如何规避内存检测（进程隐藏、内存加密、痕迹清除）。当需要分析内存 dump 或设计反取证策略时使用"
metadata:
  tags: "memory,forensics,volatility,anti-forensics,process-hollow,injection,内存取证,反取证,进程隐藏"
  category: "dfir"
  mitre_attack: "T1055,T1070.004,T1014,T1620,T1055.012"
---

# 内存取证与反内存取证

> **双面视角**：理解蓝队如何从内存中找到你 → 设计红队对策让自己不被找到

## ⛔ 深入参考

- Volatility3 完整插件速查与实战命令 → [references/volatility3-cheatsheet.md](references/volatility3-cheatsheet.md)
- 反内存取证技术实现细节 → [references/anti-memory-forensics.md](references/anti-memory-forensics.md)

---

## Part A: 蓝队视角 — 内存取证分析流程

### Phase 1: 内存获取

```bash
# Windows (DumpIt)
DumpIt.exe /OUTPUT memory.raw

# Windows (WinPmem)
winpmem_mini_x64.exe memory.raw

# Linux (LiME)
sudo insmod lime-$(uname -r).ko "path=memory.lime format=lime"

# 远程 (Velociraptor)
# 通过 Velociraptor agent 远程获取内存
```

### Phase 2: Volatility3 分析决策树

```
内存分析目标？
├─ 发现恶意进程 → windows.pslist / windows.psscan / windows.cmdline
├─ 发现注入代码 → windows.malfind / windows.hollowprocesses
├─ 提取网络连接 → windows.netscan / windows.netstat
├─ 提取凭据 → windows.hashdump / windows.lsadump
├─ 发现隐藏进程 → windows.psscan（扫描已释放 EPROCESS）
├─ Rootkit 检测 → windows.ssdt / windows.callbacks
└─ 提取文件 → windows.filescan / windows.dumpfiles
```

**核心命令：**
```bash
# 系统信息
vol -f mem.raw windows.info

# 进程列表（链表遍历 → 已 unlink 的看不到）
vol -f mem.raw windows.pslist

# 进程扫描（池标签扫描 → 能找到隐藏进程）
vol -f mem.raw windows.psscan

# ⛔ 对比 pslist vs psscan → 差异 = 隐藏进程
# pslist 有但 psscan 无 → 异常
# psscan 有但 pslist 无 → 被 unlink 的进程（Rootkit）

# 注入检测（PAGE_EXECUTE_READWRITE 内存区域）
vol -f mem.raw windows.malfind

# 网络连接
vol -f mem.raw windows.netscan

# DLL 列表
vol -f mem.raw windows.dlllist --pid <PID>

# 命令行参数
vol -f mem.raw windows.cmdline
```

### Phase 3: 关键检测指标

| 蓝队检测项 | 含义 |
|-----------|------|
| RWX 内存页 (malfind) | 进程注入/Shellcode |
| 父进程异常 (svchost→cmd) | 恶意进程创建链 |
| pslist ≠ psscan | 进程隐藏（DKOM） |
| 同名异路径进程 | 进程伪装 |
| 异常 VAD 标签 | 内存区域被篡改 |
| SSDT/IDT hook | Rootkit |
| 网络连接到异常端口 | C2 通信 |

---

## Part B: 红队视角 — 反内存取证

### 策略 1: 避免被 malfind 发现

```
malfind 原理：扫描 PAGE_EXECUTE_READWRITE 的 VAD 节点
├─ 对策 1: 分配时用 RW，写入 shellcode 后改为 RX（不要 RWX）
├─ 对策 2: 使用 NtMapViewOfSection 映射 → 权限为 SECTION_MAP_EXECUTE
├─ 对策 3: Module Stomping — 覆盖合法 DLL 的 .text 节
└─ 对策 4: 使用回调执行（APC/Timer）→ 不创建远程线程
```

### 策略 2: 避免进程异常

```
父子进程关系审计绕过：
├─ Parent PID Spoofing → 伪造正常父进程
├─ 使用合法签名进程执行 → LOLBins
├─ 进程名/路径完全模仿 → svchost.exe 在正确路径
└─ 命令行参数正常化 → 不留异常 cmdline
```

### 策略 3: 内存加密（Sleep Mask）

```
Cobalt Strike Sleep Mask 原理：
1. Beacon 进入 Sleep 状态前 → 加密自身在内存中的代码段
2. 加密期间 → malfind 只看到随机数据，无 MZ 头/PE 特征
3. 唤醒时 → 解密执行 → 完成任务 → 再加密

现代 C2 实现：
├─ Havoc: Ekko/Zilean sleep obfuscation（加密 + 更改内存保护）
├─ Sliver: 无需 sleep mask（Go 二进制特征不同）
├─ BRC4: 自带 heap 加密
└─ 自定义: SystemFunction032 (RC4) + VirtualProtect(RW)
```

### 策略 4: 避免 Credential Dump 暴露

```
蓝队会检查 LSASS 访问：
├─ 对策: 用 MiniDumpWriteDump 的替代方式（NanoDump/HandleDuplicate）
├─ 对策: SSP 注入代替直接读取
├─ 对策: 使用 comsvcs.dll 的 MiniDump 导出函数
└─ 对策: Kerberos 票据攻击代替直接 dump
```

### 策略 5: 清除内存痕迹

```
⛔ 注意：内存获取通常是一次性快照，不像日志可以被删除
最佳策略：从一开始就不留痕迹（预防 > 清除）

有限清除手段：
├─ Unmap 已用内存区域 → VirtualFree
├─ 清除线程调用栈 → 伪造 Call Stack
├─ 结束并清理 worker 线程 → 不留挂起线程
└─ Module 卸载 + 内存置零
```

## 对照表：取证技术 vs 红队对策

| 取证技术 | 发现什么 | 红队对策 |
|----------|---------|---------|
| pslist/psscan 对比 | 隐藏进程 | 不隐藏进程，伪装合法进程 |
| malfind | 注入代码 | Module Stomping + RW→RX |
| netscan | C2 连接 | 使用合法流量混淆 |
| hashdump | 凭据被提取 | 使用 Kerberos 代替 NTLM |
| handles | 打开的文件/注册表 | 用完即关闭 handle |
| callbacks/SSDT | Rootkit hook | 避免内核操作 |
| YARA scan | 内存中的恶意特征 | Sleep Mask 加密 |

## 工具速查

| 工具 | 用途 | 方向 |
|------|------|------|
| Volatility3 | 内存取证框架 | 蓝 |
| MemProcFS | 内存文件系统化分析 | 蓝 |
| WinDbg | 内核调试/分析 | 蓝 |
| BeaconEye | 检测 CS Beacon | 蓝 |
| Moneta | 检测内存注入 | 蓝 |
| Sleep Mask Kit | CS sleep 加密 | 红 |
| SysWhispers3 | 直接 syscall（绕 hook）| 红 |
| NanoDump | LSASS 低检测 dump | 红 |
