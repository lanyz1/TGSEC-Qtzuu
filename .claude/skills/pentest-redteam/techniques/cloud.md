---
name: pentest-cloud
description: "云环境渗透：容器逃逸、K8s攻击链、IAM提权、Serverless利用——信号→动作速查表"
allowed-tools: Read,Grep,Glob,Bash,WebFetch
---

# Cloud Pentest

> 仅在根路由选择本目录后读取。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 目标运行在 AWS/Azure/GCP/阿里云或 K8s 环境。

## 领域决策直觉

1. 元数据服务（169.254.169.254）是云环境的第一个检查点——有访问就有角色凭证
2. IAM 权限枚举比传统端口扫描更有价值——知道"能做什么"比知道"开着什么"更直接
3. 容器逃逸不等于集群控制：先看 Pod 的 service account 权限再决定是否逃逸

---

## 云资产发现

### IMDS 元数据探测
- **信号**: 目标在 AWS/Azure/GCP 上运行（EC2/VM/GCE）
- **假设**: IMDS 可访问且返回临时凭证
- **验证**: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS) / `curl -H "Metadata:true" http://169.254.169.254/metadata/identity/oauth2/token` (Azure) / `curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"` (GCP)
- **证实**: 返回有效的 IAM 角色临时凭证
- **升级**: 凭证 → IAM 权限枚举 → 权限提升路径

### IAM 权限枚举
- **信号**: 拥有云 API 凭证（Access Key/Token/Service Account Key）
- **假设**: 当前身份可能有过度的、非预期或可链接的权限
- **验证**: AWS——`enumerate-iam` 全权限暴力枚举 / `pmapper` 图论分析权限链 / `cloudsplaining` 识别过度权限。Azure——`az ad signed-in-user show` + 资源提供商枚举。GCP——`gcloud projects get-iam-policy` + `gcloud services list` + `gcloud auth application-default print-access-token`
- **证实**: 发现低权限身份可链式提升到管理员权限
- **升级**: 权限提升 → 跨账户访问 → 数据窃取

### 云存储枚举
- **信号**: 发现任何域名或 JS 中引用云存储 URL
- **假设**: 存在公开或弱权限的存储桶/容器
- **验证**: AWS S3 `aws s3 ls s3://bucket-name --no-sign-request` → Azure Blob `https://account.blob.core.windows.net/container` → GCP Storage `gsutil ls gs://bucket-name` → 阿里云 OSS `https://bucket.oss-<region>.aliyuncs.com`
- **证实**: 可未认证读取/写入存储对象
- **升级**: 存储内容分析 → 敏感信息提取 → 凭据发现 → 横向移动

---

## 容器逃逸

### Copy Fail CVE-2026-31431（无特权逃逸）
- **信号**: 在容器中运行，无特权/无 capability，内核版本在受影响范围
- **假设**: Linux 内核 page-cache CoW 路径竞争条件可实现无特权容器逃逸
- **验证**: 三阶段——(1) AF_ALG + splice() 竞态污染内核 page cache 中的只读文件 (2) OverlayFS 共享层跨容器传播污染 (3) 特权 DaemonSet（kube-proxy 等）执行污染二进制 → 节点级代码执行。全程零权限/零 capability/磁盘取证免疫
- **证实**: 在宿主机节点上执行命令
- **升级**: 节点控制 → K8s 集群控制 → 云元数据访问

### 容器逃逸 11 种路径
- **信号**: 在容器内，需评估逃逸可能性
- **假设**: Docker socket/特权模式/挂载/cgroup 等配置提供逃逸路径
- **验证**: CDK 自动化评估——Docker socket 挂载 → Docker API → CVE-2019-5736 runC（/proc/self/exe 覆盖）→ CVE-2020-15257 containerd-shim → CVE-2022-0492 cgroup release_agent → procfs/设备挂载 → Copy-Fail CVE-2026 → LXCFS → Ptrace → CAP_DAC_READ_SEARCH 宿主机文件读取 → Cgroup 设备权限重写
- **证实**: 至少一种路径可用
- **升级**: 宿主机访问 → K8s 凭据窃取 → 集群控制

### badPods 五维风险分级
- **信号**: Pod 配置存在 privileged/hostPID/hostNetwork/hostIPC/hostPath 组合
- **假设**: 五维组合的风险等级直接对应攻击面
- **验证**: privileged + hostPID → nsenter -t 1 宿主机逃逸。hostPath kubelet 凭据 → /etc/kubernetes/admin.conf 窃取。hostNetwork → etcd/kubelet 流量嗅探
- **证实**: 成功获取宿主机 shell 或 kubelet 凭据
- **升级**: K8s 集群管理权限 → 所有 namespace 访问

---

## K8s 攻击链

### K8s 凭据与权限发现
- **信号**: 在 Pod 中获得 shell
- **假设**: ServiceAccount Token 挂载点可访问，权限可能超出预期
- **验证**: `cat /var/run/secrets/kubernetes.io/serviceaccount/token` → `kubectl auth can-i --list` → KubeHound 图论分析 SA/Role/ClusterRole/Secret 关系 → 寻找过度授权的 SA
- **证实**: Token 有超出当前 namespace 的权限
- **升级**: 跨 namespace 访问 → Secrets 窃取 → 集群管理

### Admission Webhook 后门
- **信号**: 已有 cluster-admin 或 MutatingWebhookConfiguration 创建权限
- **假设**: 可注入 Admission Webhook 使所有新建 Pod 自动携带后门
- **验证**: 创建 MutatingWebhookConfiguration → 规则匹配所有 Pod 创建 → 注入 Sidecar 容器（hostPath 挂载 + 特权）→ 所有新建 Pod 自动携带后门
- **证实**: 新创建的 Pod 自动包含后门容器
- **升级**: 集群级持久化 → 隐蔽长期访问

### etcd 直接访问 → RBAC 篡改
- **信号**: etcd 端口 2379 未授权或可凭据访问
- **假设**: 直接修改 etcd 中 RBAC 数据可完全绕过 API Server 审计
- **验证**: etcd 未授权访问 → etcdctl 直接读写 /registry/rbac/ → 修改 cluster-admin ClusterRoleBinding 添加攻击者 SA → API Server 完全无审计记录
- **证实**: SA 获得 cluster-admin 且 kubectl 审计日志为零
- **升级**: 集群完全控制 + 审计隐身

### Shadow API Server 持久化
- **信号**: 需要长期隐蔽的 K8s 集群控制
- **假设**: 可在集群内 MITM kube-api 流量
- **验证**: MITM ClusterIP 实现 Shadow API Server → 拦截并修改 kube-api 请求/响应 → 隐身代理
- **证实**: 正常 kubectl 流量被透明劫持且不触发告警
- **升级**: 长期集群控制 → 所有操作完全隐蔽

---

## 云持久化与后门

### AWS IAM 信任策略后门
- **信号**: 已获 AWS 高权限访问
- **假设**: 可创建或修改 IAM Role 信任策略，嵌入攻击者 AWS 账户 ARN
- **验证**: 创建合法 Role → 嵌入攻击者 AWS 账户 ARN 的 Trust Policy → 附加 AdministratorAccess → 创建 Access Key 导出 → 或修改现有 Role 信任策略注入
- **证实**: 从攻击者账户成功 sts:AssumeRole 获取管理员权限
- **升级**: 跨账户访问 → 持续数据窃取

### sts:GetFederationToken 密钥删除后存活
- **信号**: 使用 Access Key 访问。管理员可能轮换/删除 Key
- **假设**: GetFederationToken 生成的 Token 独立于原始 Key 生命周期
- **验证**: 在 Access Key 有效期内调用 GetFederationToken → 生成独立 Token 最长 36 小时 → 管理员删除/轮换原 Access Key 后 Token 仍有效 → 用存活 Token 建立新持久化入口
- **证实**: 原 Key 被删除后，Token 仍可执行 AWS API 调用
- **升级**: 应急持久化 → 创建新 IAM 用户或 Role 后门

### Lambda Serverless 后门
- **信号**: 目标使用 AWS Lambda
- **假设**: Lambda Extension 作为独立进程可持久化后门且不修改函数代码
- **验证**: 恶意 Extension 注入（独立进程，不修改函数代码）→ Lambda 运行时 API 劫持 → EventBridge 规则劫持 → Function URL 后门 AuthType NONE 直接 HTTPS 调用
- **证实**: Lambda 冷启动后 Extension 仍执行恶意逻辑
- **升级**: Serverless 持久化 → 事件驱动数据窃取

### Azure AD Connect 密码提取
- **信号**: 目标使用 Azure AD Connect 同步本地 AD 到 Azure
- **假设**: AAD Connect 服务器存储同步凭据
- **验证**: 从 AAD Connect 服务器提取同步凭据 → Kerberos 票据转向云资源 → Azure 资源访问 → 云环境持久化后门创建
- **证实**: 成功用同步凭据访问 Azure 资源
- **升级**: Azure 订阅控制 → 所有云资源访问
