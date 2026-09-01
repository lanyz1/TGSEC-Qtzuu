# 反内存取证技术实现细节

> 从理解蓝队的内存检测原理出发，设计红队的反检测策略

---

## 一、内存取证工具检测原理

### 1.1 Process Listing: PsList vs PsScan

```
PsList（链表遍历）:
├─ 遍历 EPROCESS 结构的 ActiveProcessLinks 双向链表
├─ 从 PsActiveProcessHead 开始
├─ 每个 EPROCESS 通过 Flink/Blink 指针连接
├─ 优点: 快速，只列出"活跃"进程
└─ 弱点: DKOM unlink 后看不到被隐藏的进程

PsScan（池标签扫描）:
├─ 扫描整个内存，搜索 EPROCESS 结构的池标签 "Proc"
├─ 不依赖链表 → 能发现被 unlink 的进程
├─ 也能发现已终止但内存未回收的进程
└─ 弱点: 池标签可被修改/覆盖

⛔ 对比两者差异 = 发现隐藏进程:
├─ PsList 有但 PsScan 无 → EPROCESS 结构已损坏
├─ PsScan 有但 PsList 无 → 被 DKOM 隐藏的进程
└─ 这是蓝队的标准检测手法
```

### 1.2 DLL/Module Listing

```
检测方法:
├─ windows.dlllist → 遍历 PEB.Ldr 中的 InLoadOrderModuleList
├─ windows.ldrmodules → 交叉对比三个 LDR 列表:
│   InLoadOrder / InMemoryOrder / InInitializationOrder
│   不在所有列表中 = 可能被隐藏
├─ VAD 扫描 → 检查 VAD 中 mapped 的 PE 文件
│   与 LDR 列表对比 → 发现 unlisted modules
└─ malfind → 扫描没有对应 mapped file 的可执行内存
```

### 1.3 Network Connection Enumeration

```
windows.netscan:
├─ 扫描内核 TCP/IP 栈的连接表
├─ 包含: 本地/远程 IP:Port, 状态, 关联 PID
├─ 能发现 ESTABLISHED, LISTENING, CLOSE_WAIT 等状态
└─ C2 连接最容易在这里暴露

检测点:
├─ ESTABLISHED 到异常外部 IP → C2 通信
├─ LISTENING 在高位随机端口 → 后门
├─ 关联 PID 对应异常进程 → 恶意软件
└─ svchost.exe 的非标准出站连接 → 注入
```

### 1.4 Malfind（VAD Scanning for Injected Code）

```
Malfind 原理:
├─ 遍历进程的 VAD (Virtual Address Descriptor) 树
├─ 寻找同时具有以下特征的内存区域:
│   ├─ Protection = PAGE_EXECUTE_READWRITE (RWX)
│   ├─ 不属于任何 mapped file（无磁盘文件映射）
│   └─ 非 Image 类型 VAD
├─ 这些区域高度可疑 → 通常是注入的 shellcode 或 PE
└─ 输出: 内存地址、保护标志、起始字节（用于识别 PE/shellcode）

常见特征:
├─ 0x4D5A (MZ) 开头 → 反射加载的 PE/DLL
├─ 0xFC (CLD) 开头 → Metasploit shellcode 常见前缀
├─ 0xE8 (CALL) 开头 → 位置无关代码常见模式
└─ 随机字节但 RWX → 可能是加密的 payload
```

### 1.5 SSDT/IDT Hooking Detection

```
SSDT (System Service Descriptor Table):
├─ 包含系统调用处理函数的地址表
├─ 正常: 所有地址指向 ntoskrnl.exe 范围内
├─ 异常: 某些地址指向非 ntoskrnl 模块 → Rootkit hook
└─ Volatility: windows.ssdt

IDT (Interrupt Descriptor Table):
├─ 中断处理函数地址表
├─ 正常: 指向 ntoskrnl/hal 范围
├─ 异常: 指向其他地址 → Rootkit
└─ Volatility: windows.idt（如果可用）

Callback:
├─ 内核回调机制（进程创建/线程创建/映像加载等）
├─ Rootkit/EDR 注册回调监控系统活动
├─ Volatility: windows.callbacks
└─ 异常回调: 回调地址指向非标准驱动模块
```

---

## 二、反内存取证技术

### 2.1 DKOM (Direct Kernel Object Manipulation)

```
Unlink EPROCESS from ActiveProcessLinks:

原理:
├─ EPROCESS 结构通过 ActiveProcessLinks (LIST_ENTRY) 形成双向链表
├─ 将目标进程的 Flink/Blink 指针修改 → 跳过自身
├─ PsList 遍历链表时看不到该进程
├─ 但 PsScan 通过池标签扫描仍能发现

伪代码:
target->ActiveProcessLinks.Blink->Flink = target->ActiveProcessLinks.Flink
target->ActiveProcessLinks.Flink->Blink = target->ActiveProcessLinks.Blink

效果:
├─ taskmgr.exe, tasklist, Get-Process → 看不到进程
├─ vol windows.pslist → 看不到
├─ vol windows.psscan → 仍能看到 ⛔
└─ 因此 DKOM 不足以对抗专业取证

增强:
├─ 同时修改 PEB 中的 ProcessParameters → 伪造进程信息
├─ 修改 OBJECT_HEADER → 影响句柄枚举
├─ 但池标签扫描几乎无法绕过（除非覆写池标签）
└─ 需要内核级别访问（驱动/漏洞利用）
```

### 2.2 Pool Tag Manipulation

```
池标签（Pool Tag）:
├─ EPROCESS 分配时使用 "Proc" 标签
├─ ETHREAD 使用 "Thre" 标签
├─ FILE_OBJECT 使用 "File" 标签
├─ PsScan 就是搜索这些标签

操纵方法:
├─ 覆写 EPROCESS 前面的池头部 → 修改 Pool Tag
│   将 "Proc" 改为 "Xxxx" → PsScan 找不到
├─ ⛔ 风险: 破坏内存管理器的追踪 → 可能蓝屏
├─ 需要精确计算 POOL_HEADER 偏移
└─ 某些版本 Windows 有额外校验
```

### 2.3 VAD Manipulation

```
修改 VAD 保护标志:
├─ 将 PAGE_EXECUTE_READWRITE 改为 PAGE_EXECUTE_READ
├─ Malfind 只搜索 RWX → 改为 RX 后不再被标记
├─ 但实际内存保护不变（PTE 层面仍是 RWX）
├─ Volatility 读取 VAD 信息而非实际 PTE → 可以欺骗

具体实现:
├─ 遍历目标进程的 VAD 树
├─ 找到 shellcode 所在的 VAD 节点
├─ 修改 VadFlags.Protection 字段
│   原值: PAGE_EXECUTE_READWRITE (6)
│   修改: PAGE_EXECUTE_READ (3) 或 PAGE_READONLY (1)
└─ Malfind 不再报警

更高级: 删除 VAD 节点
├─ 从 VAD 树中完全移除目标节点
├─ 该内存区域对取证工具完全不可见
├─ ⛔ 极高风险 → 可能导致进程崩溃
```

### 2.4 Sleep Mask / Memory Encryption

```
Cobalt Strike Sleep Mask:
├─ Beacon 进入 Sleep 前:
│   1. 加密自身 .text 段和堆数据
│   2. 将内存保护改为 PAGE_READWRITE（不可执行）
│   3. 调用 Sleep() / WaitForSingleObject()
│
├─ Beacon 唤醒后:
│   1. 将内存保护改回 PAGE_EXECUTE_READ
│   2. 解密代码段
│   3. 执行任务
│   4. 再次加密 → Sleep
│
└─ 效果:
    ├─ Sleep 期间 Malfind 只看到加密数据（非 RWX）
    ├─ YARA 特征码匹配失败（加密后无可识别特征）
    ├─ 内存 dump 中只有密文
    └─ 但唤醒瞬间仍可被捕获
```

```
Ekko Sleep Obfuscation:
├─ 使用 CreateTimerQueueTimer 实现异步 sleep
├─ 在 timer callback 中:
│   1. NtProtectVirtualMemory → RW
│   2. SystemFunction032 (RC4) 加密代码段
│   3. 等待下一个 timer 触发
│   4. SystemFunction032 解密
│   5. NtProtectVirtualMemory → RX
├─ 优势: timer callback 在线程池执行 → 调用栈更干净
└─ 规避 BeaconEye 等基于内存特征的检测

Foliage Sleep Obfuscation:
├─ 类似 Ekko 但使用 APC (Asynchronous Procedure Call)
├─ 在 APC 回调中执行加密/解密
├─ APC 在 alertable wait 时执行 → 更自然的执行上下文
└─ 配合 NtContinue 修改线程上下文 → 栈帧更隐蔽

Shellcode Position-Independent Sleep Encryption:
├─ 不依赖 C2 框架的通用方案
├─ Shellcode 自行实现:
│   1. 定位自身在内存中的位置（PIC 技术）
│   2. XOR/RC4 加密自身代码段
│   3. 修改内存保护为 RW
│   4. Sleep
│   5. 恢复 RX → 解密 → 继续执行
└─ 需要保留解密 stub 未加密 → 仍有小段可检测代码
```

### 2.5 Module Stomping / Phantom DLL Hollowing

```
Module Stomping:
├─ 加载合法 DLL（如 amsi.dll, dbghelp.dll）
├─ 将 shellcode 覆写到 DLL 的 .text 段
├─ 执行 shellcode 时:
│   ├─ 内存区域属于合法 DLL → 不被 Malfind 标记
│   ├─ 保护属性为 PAGE_EXECUTE_READ → 正常
│   └─ VAD 中显示为合法 DLL 映射 → 不可疑
├─ 缺陷: 覆写后 DLL 的 .text 与磁盘不一致
│   → Volatility 可通过对比 .text 哈希检测
└─ 对策: 选择不常被检查的 DLL

Phantom DLL Hollowing:
├─ 使用 SEC_IMAGE_NO_EXECUTE 创建 Section
├─ 映射后修改为可执行
├─ 由于是 NO_EXECUTE Section → 某些工具不检查
├─ 但映射的 DLL 路径可能暴露（如果使用已知 DLL 名）
└─ 可使用 Transaction NTFS + Rollback 实现无文件映射
```

### 2.6 Thread Pool Wait Callback Abuse

```
原理:
├─ Windows 线程池提供 Timer/Wait/IO callback
├─ 通过 CreateThreadpoolTimer/CreateThreadpoolWait 注册回调
├─ 回调在线程池工作线程中执行
├─ 调用栈看起来像正常的线程池操作:
│   ntdll!TppWorkerThread
│   → ntdll!TppAlpcpCallbackEpilog
│   → 你的代码
├─ 比 CreateRemoteThread 更隐蔽（不产生 Sysmon EID 8）
└─ 比 APC 更隐蔽（不需要 alertable wait）

用途:
├─ 作为 shellcode 的执行机制
├─ 作为 sleep obfuscation 的 timer 源
└─ 替代直接线程创建
```

### 2.7 Stack Spoofing (Return Address Masking)

```
原理:
├─ 取证工具分析线程调用栈（call stack）
├─ 异常的返回地址 = 可疑代码执行
│   例: stack 中出现非模块地址 → 注入代码
├─ Stack Spoofing 修改调用栈中的返回地址
│   使其看起来像合法的系统调用链

方法 1: Stack Spoofing via synthetic frames
├─ 在调用敏感 API 前
├─ 修改栈帧中的返回地址
├─ 指向合法模块中的 ret gadget
├─ API 返回后恢复真实栈帧
└─ 工具: CallStackMasker

方法 2: Thread Stack Spoofing
├─ 在 Sleep 前修改线程的整个调用栈
├─ 使其看起来像正常的系统等待
│   例: NtWaitForSingleObject → KernelBase!SleepEx → ntdll!...
├─ 取证分析时看到正常的栈帧
└─ 唤醒后恢复真实栈帧

检测方法（蓝队）:
├─ 验证返回地址是否在 call 指令之后
├─ 检查栈帧链的完整性（RBP chain）
├─ 对比多次采样的调用栈一致性
└─ Moneta/Hunt-Sleeping-Beacons 等工具
```

### 2.8 Anti-Dump Techniques

```
防止内存 Dump:
├─ Guard Pages
│   使用 PAGE_GUARD 属性设置关键内存页
│   任何访问触发异常 → 可以检测 dump 操作
│   缺点: 也可能影响正常执行
│
├─ NtProtectVirtualMemory Hook
│   Hook 该函数 → 拒绝将内存改为可读
│   阻止 MiniDumpWriteDump 等 dump 工具
│
├─ Working Set Manipulation
│   将关键页面移出 Working Set
│   Dump 时这些页面可能不在物理内存中
│   需要通过 page fault 重新加载
│
├─ VirtualLock/VirtualUnlock
│   锁定关键页面在物理内存中
│   防止被 swap 到磁盘（避免 pagefile 泄露）
│
└─ ETW 监控 + 自毁
    监控 ETW 事件 → 检测到 dump 工具运行
    → 立即清零内存 + 退出进程
```

---

## 三、Volatility3 Plugin 对抗

### 3.1 windows.malfind 规避

```
规避策略:
├─ 1. 避免 PAGE_EXECUTE_READWRITE
│   分配时用 PAGE_READWRITE → 写入 shellcode → VirtualProtect 改为 PAGE_EXECUTE_READ
│   不要保持 RWX 状态
│
├─ 2. 使用 Module Stomping
│   写入合法 DLL 的 .text 段 → VAD 显示为 Image 类型 → Malfind 跳过
│
├─ 3. 使用 NtMapViewOfSection
│   映射 Section 而非 VirtualAlloc → 不同的 VAD 类型
│   某些配置下 Malfind 不检查 mapped sections
│
├─ 4. Sleep Mask
│   Sleep 时内存为 RW（不可执行）+ 内容加密
│   大部分时间处于"安全"状态
│
└─ 5. VAD Manipulation
    直接修改 VAD 保护标志 → 欺骗 Volatility
```

### 3.2 windows.netscan 规避

```
规避策略:
├─ 1. 使用 Raw Socket + Direct Syscall
│   某些 netscan 实现依赖特定内核结构
│   非标准方式建立的连接可能不在常规连接表中
│
├─ 2. 连接完成后立即关闭
│   短连接 → 在 dump 时可能已经不存在
│   C2 使用短轮询而非持久连接
│
├─ 3. 利用合法进程的网络连接
│   通过注入到浏览器进程 → 复用其网络连接
│   netscan 显示的是浏览器的 PID → 不可疑
│
├─ 4. DNS-over-HTTPS
│   通过 HTTPS 通信 → 看起来像正常 HTTPS 流量
│   目标 IP 是合法 CDN → 不可疑
│
└─ 5. Named Pipe / COM 中继
    不直接建立网络连接 → 通过其他进程中继
    netscan 中看不到恶意进程的网络活动
```

### 3.3 windows.pstree 规避

```
规避策略:
├─ 1. 不隐藏进程 → 伪装合法进程
│   进程名设置为常见系统进程
│   路径设置为正确位置
│   命令行参数正常化
│   父进程设置为正确的进程（PPID Spoofing）
│
├─ 2. PPID Spoofing
│   使用 UpdateProcThreadAttribute 设置父进程
│   svchost.exe → 父进程应为 services.exe
│   chrome.exe → 父进程应为 explorer.exe
│   如果 svchost 的父进程是 cmd.exe → 异常
│
├─ 3. 使用已有进程（进程注入）
│   不创建新进程 → 注入到已有合法进程
│   进程树完全正常
│   但 Malfind 可能在该进程中发现注入代码
│
└─ 4. 使用合法的 Windows 进程名和路径
    C:\Windows\System32\svchost.exe -k netsvcs
    而非 C:\Users\Public\svchost.exe
```

---

## 四、工具速查

| 工具 | 用途 | 类型 |
|------|------|------|
| Ekko | Sleep obfuscation (Timer-based) | 红 |
| Foliage | Sleep obfuscation (APC-based) | 红 |
| Cobalt Strike Sleep Mask Kit | CS beacon 内存加密 | 红 |
| CallStackMasker | 调用栈伪造 | 红 |
| SleepMask BOF | BOF 格式 sleep mask | 红 |
| ThreadStackSpoofer | 线程栈伪造 | 红 |
| ModuleStomping | DLL 覆写注入 | 红 |
| PhantomDllHollower | Phantom DLL 注入 | 红 |
| Volatility3 | 内存取证框架 | 蓝 |
| Moneta | 内存注入检测 | 蓝 |
| BeaconEye | CS Beacon 检测 | 蓝 |
| Hunt-Sleeping-Beacons | 睡眠 Beacon 检测 | 蓝 |
| PE-sieve | 内存中 PE 扫描 | 蓝 |
| MalMemDetect | 恶意内存模式检测 | 蓝 |

---

## 五、综合规避策略

```
完整的反内存取证方案:

Phase 1: 初始执行
├─ Module Stomping 或 Phantom DLL → 避免 Malfind
├─ PPID Spoofing → 正常的进程树
├─ 使用 direct syscall → 避免 usermode hook 记录
└─ 命令行参数正常化 → cmdline 不可疑

Phase 2: 运行时
├─ Sleep Mask 加密 → 大部分时间内存无特征
├─ Stack Spoofing → 调用栈正常
├─ 通过合法进程中继网络 → netscan 不可疑
└─ 短连接 C2 → 减少连接存在时间

Phase 3: 如果检测到 Dump
├─ ETW 监控 dump 工具执行
├─ 自动清零内存 + 退出
└─ 或切换到纯加密 sleep 状态

⛔ 没有完美的反取证方案:
├─ 执行瞬间总会在内存中留下痕迹
├─ 硬件辅助 dump（DMA）无法对抗
├─ 内核级监控（PatchGuard/HyperGuard）限制内核操作
└─ 最佳策略: 减少暴露窗口 + 多层防御
```

---

## 参考链接

- [Ekko Sleep Obfuscation](https://github.com/Cracked5pider/Ekko)
- [Foliage - APC Sleep Obfuscation](https://github.com/SecIdiot/FOLIAGE)
- [ThreadStackSpoofer](https://github.com/mgeeky/ThreadStackSpoofer)
- [Module Stomping](https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/)
- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
