---
name: sandbox-evasion-implement
description: "沙箱逃逸与反分析技术实现。当需要让恶意载荷绕过自动化沙箱分析（AnyRun/Cuckoo/CAPE/Joe/Windows Defender Sandbox）时使用。覆盖环境检测、定时欺骗、用户交互检测、虚拟化检测等主流逃逸技术的实现方法"
metadata:
  tags: "sandbox,evasion,anti-analysis,anti-vm,anti-debug,cuckoo,anyrun,沙箱逃逸,反分析,反虚拟化"
  category: "malware"
  mitre_attack: "T1497,T1497.001,T1497.002,T1497.003,T1622,T1480"
---

# 沙箱逃逸与反分析技术

> **定位**：红队载荷投递前的反沙箱层设计。不是"分析沙箱逃逸"，而是"实现沙箱逃逸"。

## ⛔ 深入参考

- 完整反虚拟化/反调试代码片段集 → [references/anti-vm-snippets.md](references/anti-vm-snippets.md)
- 定时与用户交互逃逸实现 → [references/timing-interaction.md](references/timing-interaction.md)

---

## 设计原则

⛔ **NEVER** 只用单一逃逸手法 — 沙箱可以 hook 任何单一 API
⛔ **ALWAYS** 组合 3+ 种不同类别的检测，通过才执行 payload

```
逃逸层架构（洋葱模型）：
┌─────────────────────────────────┐
│ Layer 1: 环境指纹（VM/沙箱检测）│
├─────────────────────────────────┤
│ Layer 2: 时间校验（Sleep 篡改） │
├─────────────────────────────────┤
│ Layer 3: 用户交互（非自动化）   │
├─────────────────────────────────┤
│ Layer 4: 执行守卫（地理/域/进程）│
├─────────────────────────────────┤
│         Payload 解密执行         │
└─────────────────────────────────┘
所有 Layer 通过 → 才解密执行 payload
任一 Layer 失败 → 执行 decoy 行为或静默退出
```

## Phase 1: 环境指纹检测

### 1.1 虚拟化检测（T1497.001）

```
检测项（选 3+ 组合）：
├─ CPUID 指令 → Hypervisor Brand String
├─ 注册表 → HKLM\SYSTEM\CurrentControlSet\Enum\*VMware*
├─ MAC 地址前缀 → 00:0C:29(VMware) / 08:00:27(VBox)
├─ 设备驱动 → vmtoolsd.exe / VBoxService.exe
├─ BIOS 字符串 → SMBIOS 中的 "VBOX" / "VMware"
├─ 硬件 → CPU 核心数 < 2 / RAM < 4GB / 磁盘 < 60GB
└─ RDTSC 时间差 → VM Exit 导致延迟异常
```

### 1.2 沙箱进程检测

```
已知沙箱进程名（存在即沙箱）：
├─ cuckoomon.dll / agent.py / analyzer.py (Cuckoo)
├─ SbieDll.dll (Sandboxie)
├─ dbghelp.dll in unexpected path (AnyRun)
├─ frida-agent / xposed (Mobile sandbox)
└─ 用 CreateToolhelp32Snapshot 枚举进程列表
```

### 1.3 硬件资源检测

```c
// 最简单有效：沙箱通常资源受限
MEMORYSTATUSEX mem;
mem.dwLength = sizeof(mem);
GlobalMemoryStatusEx(&mem);
if (mem.ullTotalPhys < 4LL * 1024 * 1024 * 1024) exit(0);  // < 4GB

SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) exit(0);  // < 2 CPU
```

## Phase 2: 时间校验逃逸（T1497.003）

```
原理：沙箱为加速分析会 patch Sleep() → 实际未等待
检测方式：
├─ Sleep 前后对比 GetTickCount → 差值远小于预期 = 被 hook
├─ NtDelayExecution + QueryPerformanceCounter 交叉验证
├─ RDTSC 指令直接读 CPU 时钟 → 不受 API hook 影响
└─ WaitForSingleObject(INVALID_HANDLE, timeout) 替代 Sleep
```

**核心模式（不依赖 Sleep API）：**
```
1. 记录时间 T1 (QueryPerformanceCounter)
2. 执行一段计算密集型操作（如 SHA256 10万次）
3. 记录时间 T2
4. T2 - T1 应在合理范围内 → 否则被加速/虚拟化
```

## Phase 3: 用户交互检测（T1497.002）

```
原理：沙箱通常无真实用户操作
├─ 鼠标移动 → GetCursorPos 间隔采样，无变化 = 沙箱
├─ 点击计数 → GetAsyncKeyState 检测至少 N 次点击
├─ 窗口交互 → 要求用户点击对话框/输入内容才继续
├─ 文档宏 → 需要滚动到特定页/关闭后触发
└─ 浏览器 → 需要真实鼠标路径（非直线移动）
```

## Phase 4: 执行守卫（Guardrails / T1480）

```
限制 payload 只在目标环境执行：
├─ 域名检测 → GetComputerNameEx() 匹配目标域
├─ 用户名检测 → 排除 "admin" / "sandbox" / "analyst"
├─ 地理位置 → IP 地理定位 API 或系统时区
├─ 已加入域 → 非 WORKGROUP = 企业环境
├─ 文件/注册表触发 → 特定文件存在才执行
└─ 环境变量 → 特定内部工具留下的 env var
```

## Phase 5: 逃逸后的 Payload 执行

```
所有检测通过后：
├─ 解密 payload（AES key 可从环境派生 → 沙箱无法解密）
├─ 内存加载（不落盘）
├─ 延迟执行（Sleep 真实 5-10 分钟后再连 C2）
└─ 清理检测痕迹
```

## 现代沙箱的反逃逸手段（需了解）

| 沙箱技术 | 对抗你的逃逸 | 你的应对 |
|----------|-------------|---------|
| Hook Sleep → 返回真实时间 | 打败简单 Sleep 检测 | 用 RDTSC / 计算密集型 |
| 模拟鼠标移动 | 打败简单 GetCursorPos | 检测移动轨迹是否自然 |
| 增加 CPU/RAM | 打败资源检测 | 组合多项，不依赖单一 |
| 伪装注册表 | 隐藏 VM 指纹 | 用 CPUID / RDTSC 底层指令 |
| 延长分析时间 | 等待 Sleep 结束 | Guardrails（域名/用户） |

## 决策：优先级排序

```
成本效益比（最高 → 最低）：
1. Guardrails（域/用户名）— 0 成本，直接过沙箱
2. 时间校验（RDTSC）— 底层，难 hook
3. 硬件资源（CPU+RAM+磁盘）— 简单有效
4. 用户交互（需配合社工载荷）
5. 虚拟化特征（最容易被对抗）
```
