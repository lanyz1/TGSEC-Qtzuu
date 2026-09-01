# AdmissionReview 请求模板

## 最小可用模板（Kyverno）

将以下 JSON 保存为 `/tmp/admission.json` 后发送：

```json
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1",
  "request": {
    "uid": "test-uid-12345",
    "name": "test-pod",
    "namespace": "sensitive-ns",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "requestKind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "requestResource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "operation": "CREATE",
    "object": {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "test-pod",
        "namespace": "sensitive-ns"
      },
      "spec": {
        "containers": [{
          "name": "test",
          "image": "nginx"
        }]
      }
    },
    "oldObject": null,
    "options": null
  }
}
```

## 字段说明

| 字段 | 必须 | 说明 |
|------|------|------|
| `namespace` | ✅ | 必须匹配 Kyverno Policy 的 `match.resources.namespaces`，否则不触发 mutation |
| `kind` | ✅ | 必须填写，缺失导致 Kyverno panic（空指针解引用） |
| `requestKind` | ✅ | 同上，也必须填写 |
| `resource` / `requestResource` | ✅ | 同上 |
| `operation` | ✅ | 通常为 `CREATE`；`UPDATE` 也可以但需要 `oldObject` |
| `uid` | ✅ | 任意唯一字符串 |
| `object.kind` | ✅ | 必须为 `Pod`（与外层 kind 一致） |
| `object.spec.containers` | ✅ | 至少一个容器定义，Kyverno 的 mutate 规则通常以 `name: "*"` 匹配所有容器 |

## Kyverno 常见坑

1. **不要用 `--http1.1`** — Kyverno 的 Go HTTP/2 server 会断开 HTTP/1.1 连接
2. **必须有 `-H "Content-Type: application/json"`** — 否则返回 `invalid content-type`
3. **必须有 `-k`** — Webhook 使用自签名证书
4. **namespace 要对** — 策略的 `match` 条件决定了哪些 namespace 的请求会触发 mutation

## OPA Gatekeeper 模板

Gatekeeper 使用 Validating Webhook，同样的 AdmissionReview 格式，但端点不同：

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d @/tmp/admission.json \
  https://gatekeeper-webhook-service.gatekeeper-system.svc.cluster.local/v1/admit
```

Gatekeeper 的响应中虽然不会注入 Secret，但可能泄露策略规则细节（告诉你哪些操作被禁止）。
