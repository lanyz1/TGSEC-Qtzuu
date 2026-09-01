# EDR 检测机制与规避逻辑分析

---

## 1. EDR 架构与检测层

### 1.1 现代 EDR 检测架构

```
EDR 检测层次（从内核到用户态）:

┌─────────────────────────────────────────────┐
│               Cloud Analysis                 │
│  (文件信誉/AI模型/威胁情报/沙箱分析)         │
├─────────────────────────────────────────────┤
│           Behavioral Analysis Engine         │
│  (行为链分析/机器学习/异常检测)              │
├─────────────────────────────────────────────┤
│              AMSI Integration                │
│  (脚本内容扫描: PS/VBS/JS/.NET)             │
├─────────────────────────────────────────────┤
│           ETW Providers (内核遥测)           │
│  (Microsoft-Windows-Threat-Intelligence)     │
├─────────────────────────────────────────────┤
│         User-Mode Hooks (ntdll.dll)          │
│  (NtWriteVirtualMemory/NtCreateThreadEx/...) │
├─────────────────────────────────────────────┤
│         Minifilter Drivers (文件系统)        │
│  (文件创建/修改/删除监控)                    │
├─────────────────────────────────────────────┤
│     Kernel Callbacks (进程/线程/对象)        │
│  (PsSetCreateProcessNotifyRoutine)           │
│  (PsSetCreateThreadNotifyRoutine)            │
│  (ObRegisterCallbacks)                       │
└─────────────────────────────────────────────┘
```

### 1.2 Kernel Callbacks

```
内核回调是 EDR 最底层的检测机制:

PsSetCreateProcessNotifyRoutine:
├─ 功能: 每当有进程创建/销毁时通知 EDR 驱动
├─ 数据: 进程 PID/PPID/ImageFileName/CommandLine
├─ 红队影响: 所有进程创建都被记录，无法通过用户态绑架
└─ 绕过难度: 极高（需要内核态操作）

PsSetCreateThreadNotifyRoutine:
├─ 功能: 每当有线程创建时通知
├─ 数据: 线程 TID/起始地址/所属进程
├─ 红队影响: CreateRemoteThread / APC 注入可被检测
└─ 关注: 线程起始地址不在已知模块中 → 异常

ObRegisterCallbacks:
├─ 功能: 监控对象句柄操作（进程/线程）
├─ 数据: 谁打开了谁的句柄，请求了什么权限
├─ 红队影响: OpenProcess(lsass) 的权限请求被记录
├─ 应用: LSASS 保护的核心机制
└─ 绕过: Handle duplication / 驱动级操作

CmRegisterCallbackEx:
├─ 功能: 注册表操作回调
├─ 数据: 注册表键值的创建/修改/删除
├─ 红队影响: 持久化（Run Key/Service）被记录
└─ 绕过: 使用替代持久化方式
```

### 1.3 ETW Providers

```
Event Tracing for Windows (ETW) — EDR 的主要遥测源:

Microsoft-Windows-Threat-Intelligence:
├─ 最关键的 ETW Provider（PPL 保护）
├─ 提供: 内存操作审计（VirtualAlloc/WriteProcessMemory）
├─ 数据: 源进程/目标进程/操作类型/内存区域
├─ 红队影响: 进程注入、shellcode 加载都被记录
└─ 绕过难度: 极高（Provider 运行在 PPL 中）

Microsoft-Windows-Kernel-Process:
├─ 进程创建/终止遥测
├─ 补充 Process Notify Callback
└─ 包含完整的命令行和环境变量

Microsoft-Windows-Kernel-File:
├─ 文件 I/O 操作
├─ 文件创建/修改/删除/重命名
└─ 补充 Minifilter 监控

Microsoft-Windows-DotNETRuntime:
├─ .NET Assembly 加载事件
├─ 关注: Assembly.Load(byte[]) → 内存加载检测
└─ 与 AMSI 配合检测 .NET 恶意程序

Microsoft-Windows-PowerShell:
├─ PowerShell ScriptBlock Logging (Event 4104)
├─ 记录完整的脚本内容（解混淆后）
└─ Module Logging / Transcription
```

### 1.4 User-Mode Hooks

```
EDR 用户态 Hook 机制:

原理:
├─ EDR 在进程加载时修改 ntdll.dll 中的函数入口
├─ 插入 JMP 指令跳转到 EDR 的监控 DLL
├─ EDR 检查参数后决定: 放行 / 告警 / 阻止
├─ 然后调用原始函数执行操作
└─ 几乎所有 EDR 都 hook ntdll.dll

常被 Hook 的函数:
├─ NtWriteVirtualMemory → 检测进程注入
├─ NtCreateThreadEx → 检测远程线程创建
├─ NtMapViewOfSection → 检测 section mapping 注入
├─ NtAllocateVirtualMemory → 检测 RWX 内存分配
├─ NtProtectVirtualMemory → 检测内存权限修改
├─ NtQueueApcThread → 检测 APC 注入
├─ NtCreateFile → 检测文件操作
├─ NtOpenProcess → 检测进程访问（lsass）
└─ NtSuspendThread / NtResumeThread → 检测线程操纵

Hook 检测方法:
├─ 读取 ntdll.dll 函数入口字节
├─ 正常入口: 4C 8B D1 B8 XX XX 00 00 (mov r10,rcx; mov eax,SSN)
├─ 被 Hook: E9 XX XX XX XX (JMP to EDR DLL) 或 FF 25 (indirect JMP)
└─ 如果不是标准 syscall stub → 被 Hook
```

### 1.5 AMSI (Anti-Malware Scan Interface)

```
AMSI 扫描覆盖:
├─ PowerShell 脚本 (ScriptBlock)
├─ VBScript / JScript
├─ .NET Assembly (4.8+ / .NET Core)
├─ Windows Script Host (WSH)
├─ Office VBA 宏 (Office 365)
└─ WMI (部分场景)

AMSI 调用链:
├─ 脚本引擎执行前调用 AmsiScanBuffer()
├─ amsi.dll → 将内容发送给注册的 AMSI Provider
├─ Provider (如 Windows Defender) → 扫描内容
├─ 返回结果: AMSI_RESULT_CLEAN / AMSI_RESULT_DETECTED
└─ 检测到 → 阻止执行

关键函数:
├─ AmsiInitialize() → 初始化 AMSI 会话
├─ AmsiOpenSession() → 打开扫描会话
├─ AmsiScanBuffer() → 扫描内存缓冲区 ← 核心
├─ AmsiScanString() → 扫描字符串
└─ AmsiCloseSession() → 关闭会话
```

---

## 2. 主流 EDR 特征

### 2.1 CrowdStrike Falcon

```
架构:
├─ 内核驱动: csagent.sys (Kernel-level sensor)
├─ 用户态: CSFalconService.exe + CSFalconContainer.exe
├─ 云端: 所有遥测上传到 Falcon Cloud 分析
├─ 特点: 轻量本地 agent + 重度云端分析

检测重点:
├─ 进程注入（所有形式）
├─ 凭据访问（LSASS 保护）
├─ 横向移动行为链
├─ Fileless 攻击（内存中的 PE/Shellcode）
├─ 脚本内容分析（PowerShell/VBS）
└─ 自定义 IOA (Indicators of Attack) 规则

已知特点:
├─ 内核级监控 → 用户态绕过无效
├─ 云端 AI 模型 → 新样本可能延迟检测
├─ 防篡改机制 → 难以卸载/禁用
├─ 进程树分析深度大
└─ 对 Direct Syscall 有一定检测能力
```

### 2.2 Microsoft Defender for Endpoint (MDE)

```
架构:
├─ 内核: WdFilter.sys (Minifilter) + WdNisDrv.sys
├─ 用户态: MsMpEng.exe (Antimalware Service)
├─ ETW: 重度依赖 ETW Provider 数据
├─ AMSI: 深度集成（PowerShell/VBS/.NET/Office）
├─ 云端: Microsoft Threat Intelligence

检测重点:
├─ AMSI 集成 → 脚本内容扫描最强
├─ ETW Threat Intelligence Provider → 内存操作监控
├─ ASR Rules (Attack Surface Reduction)
│   ├─ Block Office child processes
│   ├─ Block credential stealing from LSASS
│   ├─ Block process creation from WMI
│   └─ Block untrusted/unsigned processes from USB
├─ Tamper Protection → 防止关闭 Defender
└─ Smart Screen → 文件信誉检查

已知特点:
├─ ETW 数据最丰富（微软自家系统）
├─ AMSI bypass → 必须首先绕过
├─ ASR Rules → 限制常见攻击路径
├─ 与 Azure AD / Intune 深度集成
└─ 更新频繁 → 检测能力持续增强
```

### 2.3 SentinelOne

```
架构:
├─ 内核驱动: 进程/文件/网络监控
├─ 用户态 Agent: SentinelAgent.exe
├─ 本地 AI: Static AI (文件分析) + Behavioral AI (运行时)
├─ 特点: 自主决策（不强依赖云端）

检测重点:
├─ Static AI: PE 文件分析（熵值/结构/导入表/字符串）
├─ Behavioral AI: 运行时行为序列分析
├─ Storyline: 自动构建攻击链时间线
├─ 回滚: 可以回滚恶意操作的更改
└─ Deep Visibility: 详细的端点遥测

已知特点:
├─ 本地 AI 模型 → 无需联网即可检测
├─ 行为引擎较强 → 即使文件无特征也能检测行为
├─ 回滚能力 → 加密/修改文件可被恢复
├─ Storyline → 攻击链自动关联
└─ 对 Living-off-the-Land 有专门检测
```

### 2.4 Carbon Black (VMware)

```
架构:
├─ 内核驱动: cbk7.sys / cbk8.sys
├─ 用户态: cb.exe / RepMgr.exe
├─ 特点: 事件流式分析，强猎杀能力

检测重点:
├─ 进程事件流 → 完整的进程行为记录
├─ 二进制分析 → 信誉查询 + 自定义规则
├─ 威胁猎杀 → 强大的查询语言
├─ 自定义 watchlist → IOC 实时匹配
└─ Live Response → 实时远程取证

已知特点:
├─ 事件记录全面 → 猎杀友好
├─ 自定义规则灵活 → 可针对特定 TTP
├─ 响应能力强 → 实时隔离/取证
└─ 对内存中的操作检测依赖行为规则
```

### 2.5 Elastic Security

```
架构:
├─ Agent: Elastic Agent (beats 家族)
│   ├─ Filebeat → 文件/日志监控
│   ├─ Auditbeat → 系统审计
│   └─ Endpoint Security → EDR 功能
├─ Detection Rules: 开源规则库 (github.com/elastic/detection-rules)
├─ Elasticsearch + Kibana → 数据存储和查询
└─ 特点: 开源规则，可审计检测逻辑

已知特点:
├─ 检测规则公开 → 红队可以预研每条规则
├─ 基于 Elasticsearch 查询 → 规则逻辑透明
├─ 社区贡献规则 → 持续增长
├─ 灵活性高但部署复杂
└─ 行为检测依赖规则质量
```

---

## 3. 检测逻辑类型

### 3.1 Signature-Based (签名检测)

```
基于已知特征的匹配:
├─ YARA 规则: 文件/内存字节序列匹配
├─ Hash 匹配: SHA256/MD5 黑名单
├─ 导入表 (Imphash): 可疑 API 组合
├─ 字符串: 已知恶意字符串/命令

局限性:
├─ 多态/变形恶意软件 → 签名失效
├─ 新样本 → 无签名可匹配
├─ 内存中解密执行 → 磁盘签名无法检测
└─ 每次重新编译 → Hash 变化
```

### 3.2 Behavioral (行为检测)

```
基于行为链和操作序列:

攻击序列检测:
├─ Office → CMD/PowerShell → 网络连接 = 恶意文档
├─ VirtualAlloc(RWX) → WriteProcessMemory → CreateRemoteThread = 注入
├─ 文件创建 → 执行 → 删除 = Dropper
├─ LSASS 访问 + 凭据文件创建 = 凭据窃取
└─ 多主机短时间认证 = 横向移动

异常父子进程:
├─ outlook.exe → cmd.exe / powershell.exe (异常)
├─ svchost.exe → cmd.exe (可能正常也可能异常)
├─ w3wp.exe → cmd.exe (Web Shell 特征)
├─ services.exe → 非系统进程 (服务安装)
└─ WerFault.exe → 未预期的子进程 (Crash 利用)
```

### 3.3 Heuristic (启发式检测)

```
基于统计特征的异常检测:
├─ 文件熵值: > 7.0 → 高度加密/压缩 → 可疑
├─ 打包检测: 已知 packer 签名 (UPX/Themida/VMProtect)
├─ 节区异常: .text 段 RWX 权限 / 非标准节名
├─ 大小异常: 极小或极大的 PE 文件
├─ 数字签名: 无签名/无效签名/自签名
└─ 资源异常: 内嵌可执行文件/脚本
```

### 3.4 ML-Based (机器学习)

```
基于机器学习模型:

Static ML (文件分析):
├─ 输入: PE 结构特征向量
│   (导入函数/节区/熵值/字符串/大小/头部字段)
├─ 模型: 随机森林/梯度提升/神经网络
├─ 输出: 恶意概率分数
└─ 局限: 对新型文件结构可能误判

Behavioral ML (行为分析):
├─ 输入: 时序行为序列
│   (API 调用链/进程操作/网络行为/文件操作)
├─ 模型: LSTM/Transformer/序列分类
├─ 输出: 恶意行为概率
└─ 局限: 训练数据偏差 → Living-off-the-Land 难检测

Anomaly Detection (异常检测):
├─ 建立正常行为基线
├─ 偏离基线 → 标记异常
├─ 如: 用户首次执行 whoami → 异常
└─ 局限: 高误报率，需要长期基线训练
```

### 3.5 Telemetry Correlation (遥测关联)

```
跨端点/跨时间的事件关联:
├─ 同一用户在多台主机认证 → 横向移动
├─ 多台主机出现相同 Hash/Mutex → 蠕虫传播
├─ 时间线分析 → 攻击链重建
├─ 用户行为偏离历史模式 → 账户劫持
└─ 网络流量 + 端点行为联合 → 降低误报
```

---

## 4. 规避策略 (红队)

### 4.1 用户态 Hook Bypass: Direct Syscalls

```
原理: 跳过 ntdll.dll 中被 hook 的函数，直接执行 syscall 指令

方法 1: SysWhispers / SysWhispers3
├─ 自动生成 syscall stub (ASM)
├─ 编译时嵌入到你的工具中
├─ 运行时直接 syscall → 不经过 ntdll
└─ 风险: syscall 来源地址不在 ntdll → 可被检测

方法 2: HellsGate / HalosGate
├─ 运行时动态解析 syscall number
├─ 从 ntdll.dll 函数字节中提取 SSN
├─ HalosGate: 如果函数被 hook → 从相邻函数推算
└─ 优势: 不硬编码 SSN → 兼容多版本 Windows

方法 3: Indirect Syscalls
├─ 从 ntdll.dll 中找到 syscall;ret 指令地址
├─ 设置好参数后 JMP 到该地址执行
├─ 调用栈看起来来自 ntdll → 绕过栈回溯检测
└─ 当前最佳方案

检测方法:
├─ 栈回溯: syscall 的返回地址不在 ntdll.dll 范围内
├─ InstrumentationCallback: 捕获 syscall 调用
├─ 内核 ETW: TI Provider 不依赖用户态 hook
└─ 代码完整性: 扫描非 ntdll 内存中的 syscall 指令
```

### 4.2 ETW Blinding

```
原理: Patch ETW 相关函数使其不上报事件

方法: Patch EtwEventWrite
├─ 定位: ntdll!EtwEventWrite 函数入口
├─ 操作: 将入口改为 ret (0xC3) → 函数直接返回
├─ 效果: 该进程内的 ETW 事件不再上报
├─ 适用: 用户态 ETW Provider（PowerShell/DotNET）

局限:
├─ 内核态 ETW Provider 不受影响
├─ Microsoft-Windows-Threat-Intelligence → 内核态，无法 patch
├─ Patch 行为本身可能被检测
│   ├─ 内存权限变化（RX → RWX → RX）
│   └─ ntdll 代码完整性检查
└─ 仅影响当前进程，不影响其他进程的 ETW

检测:
├─ 周期性检查 ntdll!EtwEventWrite 完整性
├─ 监控 NtProtectVirtualMemory 对 ntdll 页面的权限修改
└─ ETW 日志突然中断 → 异常信号
```

### 4.3 AMSI Bypass

```
常见 AMSI 绕过方法:

方法 1: Patch AmsiScanBuffer
├─ 定位 amsi.dll!AmsiScanBuffer
├─ 修改函数使其始终返回 AMSI_RESULT_CLEAN
├─ 实现: 将入口改为 xor eax,eax; ret (返回 0 = clean)
└─ 注意: 需要在加载恶意脚本之前 patch

方法 2: Reflection (.NET)
├─ 通过反射修改 AMSI 内部字段
├─ 设置 amsiInitFailed = true → AMSI 认为初始化失败
├─ 后续扫描请求被跳过
└─ PowerShell: [Ref].Assembly... 的各种变体

方法 3: String 混淆
├─ 将恶意字符串分段拼接
├─ 运行时才组装完整命令
├─ AMSI 扫描每段时无恶意特征
└─ 效果: 绕过基于字符串的 AMSI 签名

方法 4: 避免触发 AMSI
├─ 使用编译型语言 (C/C++/Go/Rust) → 不经过脚本引擎
├─ 使用 BOF (Beacon Object Files) → 在 Beacon 进程内执行
├─ 使用 Unmanaged PowerShell → 不加载 System.Management.Automation
└─ 最佳: 完全不使用脚本语言

检测:
├─ 监控 amsi.dll 内存完整性
├─ 监控 NtProtectVirtualMemory 对 amsi.dll 的操作
├─ Event 4104 中出现 AMSI bypass 代码片段
└─ AMSI 日志突然中断 → 异常
```

### 4.4 Living-off-the-Land (LOLBAS/LOLBIN)

```
使用系统自带工具执行恶意操作:

执行类:
├─ msbuild.exe → 执行内联 C# 代码
├─ installutil.exe → 执行 .NET Assembly
├─ regsvr32.exe → 加载远程 SCT 脚本
├─ mshta.exe → 执行 HTA 应用
├─ certutil.exe → 下载文件 / Base64 解码
├─ bitsadmin.exe → 后台下载文件
├─ wmic.exe → 远程执行 / 进程创建
└─ rundll32.exe → 执行 DLL 导出函数

绕过类:
├─ 这些工具被微软签名 → 不触发签名检测
├─ 父子进程关系看起来合法
├─ 但现代 EDR 已有针对性规则
├─ 需要搭配其他技术使用
└─ 参考: lolbas-project.github.io
```

### 4.5 In-Memory Only Execution

```
全程内存执行，不落盘:

技术栈:
├─ Stage 0: 初始 payload (钓鱼/漏洞利用)
│   └─ 在内存中下载 Stage 1
├─ Stage 1: Shellcode Loader
│   ├─ VirtualAlloc → 分配内存
│   ├─ 从 C2 下载加密的 shellcode
│   ├─ 解密到内存
│   └─ 执行 (callback/thread/APC)
├─ Stage 2: C2 Implant
│   ├─ 反射加载到内存
│   ├─ 不创建新文件
│   ├─ 工具通过 BOF/内存加载执行
│   └─ Sleep 期间加密内存
└─ 全过程无文件落盘 → 文件扫描无效

检测:
├─ 内存扫描: 扫描进程内存中的 PE/shellcode
├─ Unbacked memory execution: 代码不属于任何文件映射
├─ RWX 内存区域: 可写+可执行 → 可疑
├─ ETW TI Provider: 内存操作审计
└─ 行为链: 合法进程突然进行网络连接/注入
```

---

## 5. 检测与规避的攻防平衡

```
当前检测趋势 vs 规避方向:

检测趋势:                          规避方向:
├─ 内核级监控增强               → Bring-Your-Own-Driver / 漏洞利用
├─ ETW TI Provider             → 无法从用户态绕过，需改变行为
├─ 栈回溯检测 syscall 来源    → Indirect Syscalls
├─ AMSI 完整性监控             → 不使用脚本语言
├─ 行为链 AI 分析              → 时间分散 + LOLBins + 断开行为链
├─ 云端分析                    → 离线环境操作 / 加密通信
├─ 内存扫描频率增加            → Sleep 加密 (Ekko/Foliage)
└─ 跨端点关联                  → 最小化操作范围 + 时间分散

⛔ 没有银弹 — 成功的规避需要:
├─ 深入了解目标 EDR 的具体检测能力
├─ 在同类 EDR 环境中充分测试
├─ 组合多种技术而非依赖单一方法
├─ 持续跟踪 EDR 更新和新检测能力
└─ 接受: 完全不被检测几乎不可能，目标是延迟检测
```

---

## 关联参考

- **Sigma/YARA 规则分析与绕过** → `detection-rules-bypass.md`
