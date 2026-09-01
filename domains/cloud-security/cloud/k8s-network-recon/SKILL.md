---
name: k8s-network-recon
description: "Kubernetes 集群内网络侦察与服务发现。当已获得 Pod Shell、需要发现集群内其他服务、执行 K8s 内网扫描时使用。覆盖 DNS PTR 反查、SRV 记录枚举、AXFR 域传输、K8Spider 使用。任何在 Pod 中需要横向侦察、寻找隐藏服务、确定攻击目标的场景都应使用此技能，即使用户没有明确提到 DNS"
metadata:
  tags: "k8s,kubernetes,dns,recon,service-discovery,k8spider,cluster,内网侦察,服务发现"
  category: "cloud"
---

→ 读 [references/network-attacks.md](references/network-attacks.md)

# Kubernetes 集群内网络侦察

在 K8s 集群中横向移动的第一步是弄清楚还有哪些服务在运行。因为 K8s 用 DNS 做服务发现，每个 Service 和 Pod 都有可预测的 DNS 名称，这意味着通过 DNS 反查就能系统性地枚举整个集群。

## K8s DNS 命名规则

| 资源类型 | DNS 格式 | 示例 |
|---------|---------|------|
| Service | `<svc>.<ns>.svc.cluster.local` | `redis.default.svc.cluster.local` |
| Pod | `<pod-ip-dashed>.<ns>.pod.cluster.local` | `10-244-0-5.default.pod.cluster.local` |
| Headless Service | `<pod-name>.<svc>.<ns>.svc.cluster.local` | `web-0.nginx.default.svc.cluster.local` |

> **注意**: DNS 后缀不一定是 `cluster.local`，由集群配置决定。检查 `/etc/resolv.conf` 中的 `search` 行。

### SRV 记录

Service 的 SRV 记录暴露端口信息：
```bash
nslookup -type=srv <service>.<namespace>.svc.cluster.local
# 输出示例: service = 0 50 80 svc.ns.svc.cluster.local
# 即使没有 _proto 前缀，也能查到所有有效端口
```

---

## Phase 1: 确定扫描范围

DNS PTR 反查是逐 IP 的——/16 范围有 65535 个 IP，盲扫可能需要几十分钟。先花 30 秒确定 Service CIDR，能把扫描时间从分钟级降到秒级。

**先获取入口点信息（按可靠度从高到低）**
```bash
# 1. 环境变量（最快，几乎必有）
echo $KUBERNETES_SERVICE_HOST
env | grep -i service_host

# 2. DNS 配置（nameserver 地址通常在 Service CIDR 内）
cat /etc/resolv.conf

# 3. DNS 查询（返回的 API Server IP 暴露 CIDR 段）
nslookup kubernetes.default.svc.cluster.local

# 4. 路由表/ARP（辅助推断）
cat /etc/hosts && ip route && arp -a 2>/dev/null

# 5. 避免用 ip addr — sidecar 注入的虚拟网卡会干扰判断
```

从获取到的 IP 推断 Service CIDR。

### 子网范围选择策略
⚠️ **禁止用 /8 或更大范围** — 16M+ IP 永远扫不完，会浪费整轮时间。

推荐扫描粒度：
1. 先用上面获取的 `KUBERNETES_SERVICE_HOST` 确定 Service CIDR
2. 从 `/24` 开始（256 IP，秒级完成），无结果则扩到 `/16`（65K IP，分钟级）
3. 常见 Service CIDR：`10.96.0.0/16`、`10.100.0.0/16`、`10.43.0.0/16`（K3s）
4. 如果 `KUBERNETES_SERVICE_HOST` 是 `10.96.0.1`，扫 `10.96.0.0/16`

---

## Phase 2: DNS 批量扫描

### 使用 K8Spider（推荐）

```bash
# PTR 反查 + SRV 记录 + 多线程，一条命令完成全部扫描
k8spider scan -subnet 10.100.0.0/24

# 更大的范围
k8spider scan -subnet 10.96.0.0/12    # 默认 Service CIDR
k8spider scan -subnet 10.244.0.0/16   # Pod CIDR (Flannel 默认)
k8spider scan -subnet 10.42.0.0/16    # Pod CIDR (K3s 默认)
```

> **备选**: 部分 CTF 环境预装了 `dnscan`（用法: `dnscan -subnet <cidr>`），功能类似但不支持 SRV 记录枚举。优先用 K8Spider。

### 无工具时的手动方法

```bash
# PTR 反查 (逐个 IP)
for i in $(seq 1 254); do
  nslookup 10.100.0.$i 2>/dev/null | grep -v "NXDOMAIN" | grep "name =" &
done; wait

# AXFR 域传输（如果 CoreDNS 允许）
dig axfr cluster.local @$(grep nameserver /etc/resolv.conf | awk '{print $2}')

# Wildcard DNS（已被新版 CoreDNS 废弃，但老版本可能有效）
nslookup any.any.svc.cluster.local
```

---

## Phase 3: 服务利用

发现服务后，按攻击价值优先级排序：

1. **直接 flag/数据服务**（名称含 flag、secret、internal）→ 立即 curl 访问
2. **集群管控面**（API Server 6443、etcd 2379、kubelet 10250）→ 未授权访问 = 集群接管
3. **策略/Webhook 服务**（kyverno-svc、gatekeeper）→ 可提取注入的 Secret
4. **监控/运维**（prometheus 9090、grafana 3000、dashboard 8443）→ 信息泄露 + 凭据
5. **业务服务**（其他自定义服务）→ 根据名称和端口判断

```bash
# 访问发现的服务
curl <service>.<namespace>.svc.cluster.local
curl <service>.<namespace>.svc.cluster.local:<port>

# 对高价值目标尝试多个路径
curl -s http://<svc>:<port>/
curl -s http://<svc>:<port>/flag
curl -s http://<svc>:<port>/api/v1
curl -sk https://<svc>:<port>/
```

---

## 相关技能

发现服务后，根据目标类型加载对应技能：
- Istio/Envoy 相关服务 → `Skill(skill="k8s-istio-bypass")`
- Kyverno/OPA Webhook → `Skill(skill="k8s-webhook-abuse")`
- NFS/EFS 存储 → `Skill(skill="k8s-storage-exploit")`
- API Server/Kubelet → `Skill(skill="k8s-container-escape")`
- K8Spider 工具详细用法 → `Skill(skill="k8spider")`

## 工具速查

| 工具 | 用途 | 安装 |
|------|------|------|
| K8Spider | K8s DNS 批量扫描（PTR+SRV+AXFR+多线程） | `go install github.com/Esonhugh/k8spider@latest` |
| nslookup/dig | 手动 DNS 查询 | 系统自带 |
| CDK | 容器渗透工具集（含服务发现） | f8x 安装 |
