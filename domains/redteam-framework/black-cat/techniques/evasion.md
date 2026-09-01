---
name: pentest-evasion
description: "免杀/EDR对抗：AI免杀管线、内核回调移除、调用栈欺骗、C2隐匿——信号→动作速查表"
allowed-tools: Read,Grep,Glob,Bash
---

# AV/EDR Evasion

> 仅在根路由选择本目录后读取，且仅限明确的 EDR/OPSEC 验证任务——不做宽泛自动触发。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 目标有 AV/EDR（Defender/CrowdStrike/SentinelOne/Carbon Black 等），payload 被检测或需在受监控环境操作。

## 领域决策直觉

1. 先确定 EDR 产品版本 —— 不同 EDR 的检测重心不同（CrowdStrike 重内核回调完整性、Defender 重 AMSI/ETW、SentinelOne 重行为分析）
2. 自底向上选择对抗层：通信隐匿 > 行为免杀 > 静态免杀 > 内核对抗。内核操作仅在用户态全部失效时使用
3. 始终在测��环境先验证 —— EDR 版本差异可能使某些技术完全失效

---

## 静态免杀

### AI 免杀管线（Trae + Skills 迭代）
- **信号**: Payload 被 AV 静态特征检测
- **假设**: LLM 重写源码结构 + 沙箱反馈闭环可每次产出不同的无损二进制
- **验证**: 原始 payload → LLM 重写源码结构 → 自动化沙箱测试（VirusTotal/GreyNoise/本地EDR）→ 对比检测结果 → 迭代优化 → per-build 二进制多样化
- **证实**: 沙箱检测率降至 0
- **升级**: 跨 campaign 使用不同变体 → 降低签名可检测性

### LLVM IR 混淆 + LLM 反推规则
- **信号**: EDR YARA 规则或静态特征匹配
- **假设**: LLM 分析 AV YARA 规则可反推检测特征，配合 IR 级混淆绕过
- **验证**: 自定义 LLVM pass 在 IR 级别插入虚假控制流/控制流扁平化 → LLM 分析 AV YARA 规则反推检测特征 → LLM 批量生成变体 → 沙箱观察 → 对比差异 → 推断检测逻辑 → 生成新一代绕过变体
- **证实**: 变体在保留功能的前提下绕过 YARA 规则
- **升级**: 持续迭代 → 对抗规则更新

### Ankou Poly Engine
- **信号**: 需要跨多次行动使用不同的 implant
- **假设**: 本地 LLM 可每次重写 implant 源码保持功能但改变结构
- **验证**: Ollama/LM Studio 本地 LLM 读取 implant 源码 → 重写结构保持功能 → 每次编译产出有意义的不同二进制
- **证实**: 两次编译的二进制 hash 不同但功能一致
- **升级**: 大规模 deploy → 每个目标不同二进制

### COFF Mixing（对象文件级隐藏）
- **信号**: 需要在编译/链接阶段隐藏恶意代码
- **假设**: 恶意代码分散在多个 COFF 对象间而非单一恶意 segment，可打败 PE 结构静态分析
- **验证**: 编译/链接阶段将恶意 COFF 对象与良性对象混合 → 恶意代码分布在多个 COFF → 最终二进制是正常编译产物，无异常 PE 特征
- **证实**: PE 分析工具未检测到异常 segment
- **升级**: 供应链/build-time 级别的隐藏 → 绕过所有 PE 层面的检测

### Egg Hunt 磁盘无 syscall
- **信号**: AV 静态扫描检测 syscall 字节（0F 05）
- **假设**: 编译时嵌入随机 egg 标记替代 syscall，运行时替换为真实字节
- **验证**: 编译时 syscall stub 中嵌入 8 字节随机 egg 替代 0F05 → 运行时 SW4_HatchEggs() 扫描 .text 段替换为真实 syscall 字节
- **证实**: 磁盘上的二进制无 0F05 syscall 特征
- **升级**: 配合其他绕过技术 → 完整免杀链

---

## 用户态 EDR 对抗

### AMSI WRITE RAID（零 VirtualProtect 绕过）
- **信号**: AMSI 检测 PowerShell/.NET payload
- **假设**: AMSI 调用链中存在已标记为 Read/Write 的内存条目，可直接覆盖无需 VirtualProtect
- **验证**: 找到 AMSI 调用链中 RW 标记的内存条目 → 直接覆盖 AmsiScanBuffer → 不修改任何内存保护属性 → EDR 无法通过 Hook VirtualProtect 检测 → 同类漏洞在 clr.dll(PowerShell v5) 和 coreclr.dll(PowerShell v7) 均存在 → 绕过 CFG：通过 guard_dispatch_icall_fptr 间接调用
- **证实**: AMSI 未检测到恶意 PowerShell 脚本执行
- **升级**: AMSI 已绕过 → 执行任意 PowerShell payload

### AMSI 5 层复合绕过
- **信号**: 单一 AMSI 绕过技术被检测
- **假设**: 多层组合可使每层都失效时有备份
- **验证**: (1) 非入口点 Patch 偏移 0x14 (2) 零长度缓冲区 (3) 硬件断点绕过 (4) DLL 加载阻止 DEBUG_PROCESS/NtCreateSection hook (5) Transactional NTFS 磁盘加载绕过
- **证实**: 5 层中至少 1 层在当前 EDR 版本有效
- **升级**: 纵深防御 → 即使 EDR 更新也需逐一突破

### ETW 完全禁用
- **信号**: EDR 依赖 ETW 遥测（几乎所有现代 EDR）
- **假设**: 内核回调移除 ETW TI 提供者可切断 EDR 遥测源
- **验证**: 枚举 ETW 提供者 → 找到 EDR 注册的 Threat Intelligence 提供者 → 利用 RTCore64.sys 任意物理内存读写 → 覆盖 ETW TI 提供者回调指针
- **证实**: EDR 控制台停止接收遥测但显示 Agent online
- **升级**: ETW 已盲 → 执行高检测风险操作

### PowerShell 免杀体系
- **信号**: PowerShell 脚本被 AMSI + ScriptBlock 日志 + CLM 三重检测拦截
- **假设**: AMSI Provider 反射修改 + ScriptBlock 日志绕过 + CLM 绕过可组合
- **验证**: AMSI Provider 反射修改（同时覆盖脚本和 assembly::load() 场景）→ ScriptBlock 日志绕过 → FullBypass AMSI+CLM 组合绕过 → 获得 FullLanguage 模式反向 Shell
- **证实**: PowerShell 执行任意命令且不产生 ScriptBlock 日志
- **升级**: 无限制 PowerShell → 內网枚举 → 横向移动

### EDR-GhostLocker（AppLocker 反制 EDR）
- **信号**: EDR 用户态进程约束操作
- **假设**: AppLocker deny 规则可阻止 EDR 用户态分析引擎运行而不影响内核驱动
- **验证**: 枚举 EDR 进程 → 构建 XML AppLocker deny 规则（Everyone Deny）→ PowerShell UTF-16LE Base64 编码执行 → EDR 内核驱动继续运行但用户态分析引擎被阻止 → 管理端仍报告 online 但不产生任何检测
- **证实**: 执行恶意操作后 EDR 控制台零告警
- **升级**: EDR 完全失明 → 大胆操作

---

## 调用栈欺骗

### 硬件断点调用栈欺骗（hw-call-stack）
- **信号**: EDR 通过栈回溯检测恶意调用链
- **假设**: CPU 调试寄存器可设置硬件断点，在目标函数返回地址触发并替换调用栈
- **验证**: 在目标函数返回地址设置硬件断点（DR0-DR3）→ 断点触发时替换为伪造调用链（合法系统 DLL 返回地址）→ canary 标记边界 → 返回后恢复原始堆栈
- **证实**: EDR 栈回溯看到的是合法调用链
- **升级**: 绕过基于栈回溯的 EDR 检测 → 执行敏感操作

### SilentMoonwalk ROP 解同步
- **信号**: EDR 分析 call stack 检测 EXE 模块基址
- **假设**: 分析 unwind 信息可构建 desync stack 完全移除 EXE 模块基址
- **验证**: 分析 unwind 信息构建 desync stack → 从堆栈完全移除 EXE 模块基址 → API 返回时通过 ROP gadget 恢复 → Synthetic 模式创建两个伪造帧链接回截断栈
- **证实**: 栈中无 EXE 模块基址
- **升级**: 无法被栈回溯检测 → 执行任意 Windows API

---

## 内核级对抗

### Kernel Callback Removal（RTCore64.sys）
- **信号**: EDR 注册了进程/线程/镜像加载/文件系统/网络/ETW 回调
- **假设**: 修改 callback entry 内部函数指针（而非回调数组指针）可绕过数组完整性检测
- **验证**: 加载 RTCore64.sys（MSI Afterburner 漏洞驱动）→ 任意物理内存读写 → 覆盖 4 种回调 entry 内部函数指针为 KCFG 兼容 ret 指令：进程/线程/镜像加载 + MiniFilter 文件系统 + WFP 网络 callout + ETW TI 提供者
- **证实**: EDR 回调全部失效但回调数组完整性检测通过
- **升级**: EDR 内核层完全失明 → 执行任意操作

### BYOVD 驱动级 EDR 终结链
- **信号**: 需要在有 EDR 保护的主机上执行高风险操作
- **假设**: 完整攻击链可终结 EDR：驱动加载 → 回调移除 → ETW 禁用 → LSASS 解锁
- **验证**: 加载漏洞签名驱动（truesight.sys 等）→ 内核读写 → 终止 EDR 保护进程 → 移除内核回调 → 禁用 ETW → 解除 LSASS 保护 → 完整链：驱动→回调→ETW→LSASS
- **证实**: 成功读取 LSASS 内存且 EDR 无反应
- **升级**: 凭据提取 → 横向移动

---

## 行为免杀

### Caro-Kann 两阶段绕过（EDR 扫描时机差）
- **信号**: EDR 在进程创建后立即扫描内存
- **假设**: EDR 扫描和恶意代码执行之间存在时间窗口可被利用
- **验证**: 加密恶意 shellcode 写入远程进程 RW 页 + 良性自写 shellcode 注入 RX 区域 → 线程创建时 ETWti 指向良性 shellcode → Sleep 等待 EDR 扫描完成 → 解密 RW 页改 RX → JMP 转移执行
- **证实**: EDR 扫描未发现恶意代码，后续执行成功
- **升级**: 在 EDR 已扫描的内存中执行 → 免杀

### Ekko 睡眠加密
- **信号**: EDR 在进程睡眠时扫描内存
- **假设**: 睡眠期间加密自身 .text 段可使扫描时发现加密内存（无可用特征）
- **验证**: RDTSC 生成随机 XOR 密钥 → 加密自身 .text 段 → 可等待定时器 + 排队 APC 解密 → 可警告状态睡眠 → EDR 扫描时发现加密内存
- **证实**: 睡眠期间 EDR 扫描无告警，醒来后正常执行
- **升级**: 长期驻留 → 间歇性激活

### RecycledGate 多策略 SSN 解析
- **信号**: EDR 钩子检测直接 syscall
- **假设**: 多层回退策略可确保在任何 EDR 配置下获取正确的 syscall 号
- **验证**: VA 排序获取 SSN + Hells Gate 操作码交叉验证 → SyscallsFromDisk 回退 → TartarusGate 检测 hook 模式 → HW Breakpoint 回退 → ntdll 中预定位 64 个 syscall;ret gadget → RDTSC 获取熵随机选择 gadget → 内核入口 RIP 始终在 ntdll 内
- **证实**: syscall 执行成功且未被 EDR hook 拦截
- **升级**: 直接 syscall → 绕过所有用户态 hook

### Module Stomping PIC
- **信号**: 进程注入被 EDR 检测到异常 RWX 内存区域
- **假设**: PIC shellcode 可写入已加载合法 DLL 内存，保留原始内存保护属性
- **验证**: 恶意 shellcode 写为 PIC 格式 → 注入已加载的合法 DLL 内存 → 无论被写入哪个模块或内存区域都能正确执行 → 被践踏模块保留原始内存保护属性，避免被标记为可疑 RWX
- **证实**: 注入成功且无 RWX 内存区域
- **升级**: 隐蔽代码执行 → 后续 payload 加载

---

## C2 通信隐匿

### Dev Tunnels C2（Ouroboros）
- **信号**: 需建立 C2 且网络出口被严格控制
- **假设**: VS Code Dev Tunnels 可武器化为 C2，流量经过微软域名信誉极高
- **验证**: REST 管理 API → WebSocket 中继 → SSH over WebSocket → MsgPack RPC 四层协议栈 → 流量经 *.devtunnels.ms 微软自有域名 → 使用签名二进制 `code --tunnel` 无需自定义恶意软件 → SSH 层用 None 认证+特定 MAC 协商使标准 SSH 检测工具无法解析
- **证实**: C2 通信正常且流量被标记为 Microsoft 合法流量
- **升级**: 长期 C2 通道 → 多主机控制

### C2 6 信道隐匿
- **信号**: 标准 HTTPS C2 被检测或需要备选信道
- **假设**: 6 种非标准信道各有适用场景
- **验证**: (1) SharpCovertTube YouTube 信道——视频缩略图 QR 码含 AES 加密命令 (2) ICMP-Ghost ICMP/DNS 协议动态切换——汇编级 VTable 内存操作 (3) DNS over HTTPS 隧道——与普通 HTTPS 无法区分 (4) CDN 域前置 (5) PULSE-C2 HTTPS 加密 (6) 云函数 C2（AWS Lambda/Azure Functions/GCP）
- **证实**: C2 通信正常，IDS/防火墙未检测
- **升级**: 多信道切换 → 抗阻断

### Cavern C2 7 层反分析
- **信号**: C2 样本被逆向分析或沙箱检测
- **假设**: 多层反分析技术可使逆向/沙箱完全失效
- **验证**: (1) .NET Native AOT 让 dnSpy/ILSpy 完全失效 (2) 空壳导出表反沙箱 83 个导出中 82 个为陷阱 (3) 自定义分隔符 _;;_ 绕过标准 IDS (4) DLL 侧加载合法 WinDirStat.exe + 篡改 uxtheme.dll (5) 热更新持久化 (6) RMM 信任链滥用 (7) AppDomain 临时驻留
- **证实**: 沙箱分析无有效输出，逆向工具无法解析
- **升级**: C2 长期存活 → 不被分析暴露

---

## 内网工具免杀开发（BOF + 原生 API）

> 核心原则：不产生 cmd.exe / powershell.exe 进程。所有操作通过 BOF 或直接 Windows API 调用完成。

### BOF（Beacon Object File）开发方法论
- **信号**: 需要用 C2 执行内网操作（信息收集/横向/提权），但 C2 的 `execute-assembly` 或 `shell` 命令会创建进程
- **假设**: BOF 在 C2 agent 进程内直接执行，零进程创建、零文件落地、零磁盘痕迹
- **开发关键**:
  - BOF 是编译为 `.o` (COFF) 的小型 C 程序，由 C2 agent 的 BOF loader 在内存中解析符号并执行
  - 入口函数 `go(char* args, int len)` —— 无 main、无 CRT、无全局变量初始化
  - 所有 Windows API 通过 `DECLSPEC_IMPORT` 动态链接声明，BOF loader 在运行时解析
  - 字符串用 `char*` 栈分配或 `MSVCRT$malloc`，不用全局字符串字面量
  - **关键限制**: BOF 在调用线程上执行，如线程属于 agent 主循环，长时间阻塞 BOF 会导致 C2 心跳超时
- **典型应用**: 端口扫描（ConnectEx BOF）、LDAP 查询（SA-LDAPCheck）、文件操作（ReadFile/WriteFile）、凭据提取（nanodump BOF 模式）、注册表操作、进程枚举
- **参考**: TrustedSec CS-Situational-Awareness-BOF、ajpc500/BOFs、outflanknl/C2-Tool-Collection
- **AI 盲区**: AI 知道 BOF 概念但不会给出 "用 Dynamic Function Resolution 替代 CRT、用栈字符串替代全局字符串、用 BOF loader 的符号解析替代静态链接" 的完整开发模式

### 原生 API 替代高危命令

> EDR 对进程创建（Event ID 4688）和命令行参数的监控力度远大于对单个 API 调用的监控。同一条信息，用 API 拿 vs 用命令拿，检测概率差 10 倍以上。

| 高危命令 | 替代 API | DLL | BOF 可行性 |
|---------|---------|-----|-----------|
| `whoami` / `whoami /priv` | `GetUserNameExW` + `OpenProcessToken` + `GetTokenInformation` | secur32 / advapi32 | ✅ 简单 |
| `netstat -ano` | `GetExtendedTcpTable` / `GetExtendedUdpTable` | IPHLPAPI | ✅ 中等 |
| `ipconfig /all` | `GetAdaptersAddresses` | IPHLPAPI | ✅ 中等 |
| `net session` | `NetSessionEnum` | netapi32 | ✅ 简单 |
| `net group "Domain Admins" /domain` | `NetGroupGetUsers` 或 LDAP `(&(objectClass=user)(memberOf=CN=Domain Admins,...))` | netapi32 / wldap32 | ✅ LDAP BOF |
| `arp -a` | `GetIpNetTable2` | IPHLPAPI | ✅ 简单 |
| `route print` | `GetIpForwardTable2` | IPHLPAPI | ✅ 简单 |
| `cmdkey /list` | `CredEnumerateW` 或 DPAPI `CryptUnprotectData` | credui / crypt32 | ✅ 中等 |
| `reg query / reg save` | `RegOpenKeyEx` + `RegQueryValueEx` / `RegSaveKeyEx` | advapi32 | ✅ 简单 |
| `nslookup` | `DnsQuery_W` / `DnsQueryEx` | dnsapi | ✅ 中等 |
| `tasklist` | `CreateToolhelp32Snapshot` + `Process32First/Next` | kernel32 | ✅ 简单 |
| `net view` | `NetShareEnum` / `NetServerEnum` | netapi32 | ✅ 简单 |
| `wmic product` | 枚举 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` 子键 | advapi32 (registry API) | ✅ 简单 |
| `sc` / `schtasks` | `OpenSCManager` + `CreateService` / `ITaskScheduler` COM 接口 | advapi32 / taskschd | ⚠️ 复杂 |
| `powershell` 脚本 | .NET Assembly 通过 CLR Hosting 内存加载 或 BOF 直接执行 | — | ✅ 用 BOF |

### 内网工具链免杀模式

**模式 1: 全部功能 BOF 化**
- 信息收集: TrustedSec SA BOF 系列（枚举用户/组/会话/共享/注册表/网络）
- 横向移动: WinRS BOF、WMI BOF（直接 COM 调用，不启动 wmic.exe）、计划任务 BOF
- 凭据操作: nanodump BOF（LSASS dump）、Seatbelt BOF（安全包凭据）、Rubeus BOF（Kerberos ticket）
- 文件操作: 读/写/列目录/下载/上传全部通过 BOF

**模式 2: .NET 程序集内存执行**
- 用 BOF 启动 CLR → `Assembly.Load(byte[])` 从内存加载 .NET 程序集 → 执行入口
- 优点: 可以用 C# 写复杂逻辑（比 C BOF 开发效率高），不产生 `csc.exe` / `msbuild.exe` 进程
- 风险: `Assembly.Load` 触发 AMSI 扫描 → 需配合 AMSI 绕过（见用户态 EDR 对抗）
- 备选: `Assembly.LoadFrom(disk_path)` 绕过 AMSI 内存扫描（CLR disk-load trick）

**模式 3: 间接 syscall 实现敏感操作**
- 需要进程注入/内存操作/线程创建时，不用 `CreateRemoteThread` 等被重度 hook 的 API
- 用 SysWhispers3 / Hell's Gate / Halo's Gate 生成间接 syscall stub → syscall 指令位于 ntdll 内 → 调用栈显示 `ntdll.dll` 而非攻击者 EXE
- 结合调用栈欺骗（SilentMoonwalk/CallStackSpoofer）让每次敏感操作的回溯栈看起来像合法系统行为

**模式 4: LOL 工具 + 参数混淆**
- 在必须创建进程的场景下（如某些 RDP/计划任务操作），用 LOLBAS 合法二进制 + 混淆参数
- 示例: 用 `msbuild.exe` 执行 inline task C# 代码替代 `powershell.exe -enc ...`
- 原理: LOL 工具本身不被拦截 + 混淆后的参数逃过命令行参数检测

### 内网免杀开发检查清单

进入内网操作前逐项确认：
1. [ ] 信息收集: 是否全部使用 BOF/原生 API，零 `cmd.exe` / `powershell.exe` 进程？
2. [ ] 横向移动: WMI 是否通过 COM 接口而非 `wmic.exe`？WinRM 是否通过 BOF 而非 `winrs.exe`？
3. [ ] 凭据提取: 是否通过内存操作（nanodump BOF）而非 `reg save` + `procdump`？
4. [ ] C2 通信: 是否复用 agent 进程内的 BOF 执行，而非用 `execute-assembly` 启动新进程？
5. [ ] 文件操作: 读取/写入是否通过 BOF 的 `ReadFile`/`WriteFile`，而非 `certutil -urlcache` / `bitsadmin`？
6. [ ] 调用栈: 敏感操作的回溯栈是否通过 syscall stub + 栈欺骗回到 ntdll 而非 EXE？

---

## Telemetry 分散与进程拆分

> 核心思想：EDR 从单个进程中收集行为特征进行判断。如果把恶意行为拆分到多个进程，每个进程单独看来都是良性的。

### 进程分叉 + 操作拆分（Divide and Conquer）
- **信号**: EDR 对单个进程内的敏感操作组合（如 VirtualAlloc + WriteProcessMemory + CreateRemoteThread）高度警觉
- **假设**: 将注入链的步骤分散到父子进程，EDR 的跨进程关联能力远弱于单进程行为分析
- **验证**: fork() 或 CreateProcess 创建子进程 → 父进程只做 VirtualAlloc → 子进程只做 WriteProcessMemory → 孙进程只触发执行 → 每个进程单独看都是无害的单一 API 调用
- **证实**: EDR 对每个进程单独打分均为低风险，不触发告警；注入链完整执行
- **升级**: 五进程拆分 → 单进程内行为特征完全消失

### 无线程进程注入（Entry Point Hijacking — EPI）
- **信号**: CreateRemoteThread / NtCreateThreadEx 被 EDR 重度 hook
- **假设**: 修改目标 PE 的入口点（AddressOfEntryPoint）可直接劫持执行流，不需要创建远程线程
- **验证**: 挂起目标进程 → 修改内存中 PE 的 OptionalHeader.AddressOfEntryPoint 指向 shellcode → 恢复进程 → shellcode 在主线程自然执行完毕 → 或使用 RegisterWaitForSingleObject / QueueUserAPC 等异步回调间接触发，同样无 CreateRemoteThread
- **证实**: shellcode 在目标进程中执行，EDR 侧无 CreateRemoteThread 事件，注入行为不可见
- **升级**: 全进程生命周期内零线程创建 → 绕过所有基于线程创建的检测
- **AI 盲区**: AI 知道 CreateRemoteThread 会被检测，但不会给出"修改 PE 入口点让目标自己跑过来"这种非线程依赖的代码执行思路

### SysWhispers4：覆盖 Windows 11 24H2 + ARM64
- **信号**: 已有的 syscall stub 在新 Windows 版本上失效（微软持续增加新的 syscall 和修改编号）
- **假设**: 更新 syscall 表覆盖到最新 Windows 11 24H2 和 ARM64/WoW64 可恢复直接 syscall 能力
- **验证**: 用 SysWhispers4（2026.03 更新）生成 x64/x86/WoW64/ARM64 全架构 stub → syscall 指令位于 ntdll 内 → 保持栈回溯显示 ntdll → 可选的 egg hunting（磁盘上无 syscall 字节）+ 随机化 gadget 选择
- **证实**: syscall 成功执行，栈回溯干净，静态分析看不到 syscall 指令
- **AI 盲区**: AI 只知道 "间接 syscall"，不知道该技术在 Windows 11 24H2 的具体变化和 ARM64 适配
