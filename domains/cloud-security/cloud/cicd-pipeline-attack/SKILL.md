---
name: cicd-pipeline-attack
description: "CI/CD 流水线与供应链攻击方法论。当发现目标使用 GitHub Actions/Jenkins/GitLab CI/CircleCI/Terraform Cloud/Atlantis 等 CI/CD 系统、需要测试流水线安全性、或发现 .github/workflows/Jenkinsfile/.gitlab-ci.yml 等配置文件时使用。覆盖 PPE（Poisoned Pipeline Execution）三种攻击模式（D-PPE/I-PPE/3PE）、VCS 代码仓库攻击面（代码泄露/Webhook 滥用/分支保护绕过）、Pipeline Secrets 窃取与横向移动、以及从 CI/CD 到云环境的穿越路径"
metadata:
  tags: "cicd,pipeline,github-actions,jenkins,gitlab,terraform,atlantis,supply-chain,PPE,poisoned-pipeline,secrets,VCS,webhook,CI/CD攻击,供应链,流水线"
  category: "cloud"
---

# CI/CD 流水线与供应链攻击方法论

CI/CD 系统是现代软件工程的核心基础设施——它们拥有代码仓库的读写权限、持有云平台的部署凭据、能够直接修改生产环境。一旦攻陷流水线，攻击者可以同时获得代码控制权、Secrets 访问权和云环境穿透能力，其影响范围远超单台服务器的沦陷。

本技能以决策树形式组织 CI/CD 攻击方法论。各平台的详细技术手法请参阅对应的参考文档。

## 深入参考

识别到具体平台后，加载对应参考文档获取完整攻击技术细节：

- GitHub Actions 专项攻击手法 → 读 [references/github-actions-abuse.md](references/github-actions-abuse.md)
- Jenkins / Terraform / Atlantis / GitLab CI / Azure DevOps / CircleCI / Drone / Buildkite 等平台 → 读 [references/platform-specific.md](references/platform-specific.md)
- 跨平台构建文件注入（package.json、setup.py、Makefile、Bazel、Maven/Gradle、csproj）→ 读 [references/build-file-injection.md](references/build-file-injection.md)

## Phase 0: CI/CD 系统识别

在目标代码仓库或基础设施中发现以下标识文件时，可确定对应的 CI/CD 平台：

| 标识文件/特征 | CI/CD 平台 | 下一步 |
|---|---|---|
| `.github/workflows/*.yml` | GitHub Actions | → Phase 2 PPE + 参考 github-actions-abuse.md |
| `Jenkinsfile` 或 `/script` 控制台 | Jenkins | → Phase 4 Jenkins 专项 + 参考 platform-specific.md |
| `.gitlab-ci.yml` | GitLab CI | → Phase 2 PPE + 参考 platform-specific.md |
| `.circleci/config.yml` | CircleCI | → Phase 2 PPE + 参考 platform-specific.md |
| `azure-pipelines.yml` | Azure DevOps | → Phase 2 PPE + 服务连接 Secret 提取 |
| `.drone.yml` | Drone CI | → Phase 2 PPE + Self-hosted Runner 检查 |
| `.buildkite/*.yml` | Buildkite | → Phase 2 PPE + Agent 云/K8s 权限检查 |
| `atlantis.yaml` + Webhook | Atlantis | → Phase 4 Atlantis 专项 |
| `*.tf` + Terraform Cloud | Terraform Cloud | → Phase 4 Terraform 专项 |
| `serverless.yml` | Serverless Framework | → 参考 platform-specific.md |
| `docker-compose.yml` + CI 触发 | Docker Build | → 检查构建上下文泄露 |
| Airflow DAGs / Concourse pipeline | Airflow / Concourse | → 参考 platform-specific.md |

**快速识别技巧：**
- 克隆仓库后搜索配置文件：查找 `Jenkinsfile`、`.github/workflows`、`.gitlab-ci.yml`、`.circleci`、`atlantis.yaml`
- 检查 Webhook 配置：Webhook URL 暴露 CI/CD 服务类型和内网地址
- 枚举 CI/CD 服务端口：Jenkins 默认 8080，Atlantis 默认 4141，GitLab Runner 8093

## Phase 1: VCS 攻击面

在进入流水线攻击之前，VCS（版本控制系统）本身就是重要的攻击面。

### 1.1 代码泄露

代码仓库中常见的敏感信息来源：

- **Git 历史记录**：已删除的密钥/凭据可能仍在 commit 历史中（`git log -p` 搜索所有分支）
- **公开仓库**：使用 GitHub Dork 搜索组织名称 + 关键词（`password`、`secret`、`token`、`AWS_`）
- **已删除的 Fork 数据**：GitHub 上已删除的 fork 中的 commit 数据仍可通过 commit hash 访问
- **内部仓库暴露**：private 仓库变 public 前的 fork 数据可通过短 SHA-1 暴力枚举

### 1.2 分支保护绕过

分支保护是防止恶意代码合入的关键防线，但存在多种绕过方式：

| 绕过场景 | 条件 | 攻击方法 |
|---|---|---|
| 审批不足 | 控制多个账户 | 使用其他账户审批自己的 PR |
| GITHUB_TOKEN 自审批 | Actions 有写权限 | 通过 Actions 中的 GITHUB_TOKEN 审批 PR |
| 推送后审批未失效 | 未启用 "dismiss on push" | 先提交合法代码获得审批，再推送恶意代码 |
| CODEOWNERS 配置错误 | 文件格式有误 | GitHub 不报错但 CODEOWNERS 保护失效 |
| 新分支无保护 | 使用通配符 `*` 但有延迟 | 创建新分支时分支保护尚未生效，第一次 push 可触发 Actions |
| 管理员豁免 | 管理员未纳入规则 | 管理员可直接绕过所有分支保护 |
| PR 劫持 | 可修改他人 PR | 在他人的 PR 中注入恶意代码后自行审批合并 |

### 1.3 Webhook 滥用

- **无 Secret 验证**：攻击者可伪造 Webhook 请求触发流水线
- **Secret 暴露在 URL 中**：Secret 附在 URL 参数中，易被日志记录
- **IP 白名单绕过**：在 GitHub/GitLab 上创建账户配置 Webhook 即可向白名单内的 Jenkins/Atlantis 发送请求
- **Bitbucket Cloud**：不支持 Webhook Secret，只能依赖 IP 白名单

## Phase 2: PPE -- Poisoned Pipeline Execution

PPE 是 CI/CD 攻击的核心框架。攻击者通过修改 CI 配置文件或其依赖文件来"毒化"流水线，使其执行恶意命令。

### PPE 判定决策树

```
是否能写入/修改 CI 配置文件（workflow yml / Jenkinsfile / .gitlab-ci.yml）？
├── 是 → D-PPE（直接毒化）
│   ├── 能直接推送到触发分支 → 最简单路径
│   └── 需要 PR → 检查 PR 是否触发流水线
│
├── 否，但能修改 CI 配置依赖的文件？
│   ├── Makefile / build.sh / package.json / requirements.txt → I-PPE（间接毒化）
│   ├── Terraform .tf 文件 → I-PPE via external data source
│   └── Dockerfile → I-PPE via build context
│
└── 否，且无仓库写权限？
    └── 3PE（第三方毒化）
        ├── 能否提交外部 PR？ → pull_request 触发器
        ├── PR 标题/描述是否被注入到 shell 命令？ → Context Script Injection
        └── 能否通过 issue/comment 触发？ → issue_comment 触发器
```

### D-PPE（Direct PPE）

攻击者直接修改 CI 配置文件。这是最直接的攻击路径：

- **前提**：拥有仓库写权限，或能通过 PR 触发使用 PR 分支配置的流水线
- **目标文件**：`.github/workflows/*.yml`、`Jenkinsfile`、`.gitlab-ci.yml`、`.circleci/config.yml`
- **关键条件**：某些平台（如 GitHub Actions 的 `pull_request` 触发器）会使用 PR 提交者的 workflow 版本——这意味着攻击者的修改会被执行

### I-PPE（Indirect PPE）

攻击者不修改 CI 配置文件本身，而是修改 CI 配置所依赖的文件：

- **构建脚本**：`Makefile`、`build.sh`、`package.json` 的 `scripts` 字段
- **依赖文件**：`requirements.txt`、`package-lock.json`（供应链注入）
- **IaC 配置**：Terraform `.tf` 文件中的 `external` data source 或 `local-exec` provisioner
- **Docker 构建**：控制 Dockerfile 或构建上下文路径

I-PPE 的局限性在于攻击者只能访问流水线原本就加载的 Secrets，无法通过配置声明新的 Secret 引用。

### 3PE（Third-Party PPE / Public PPE）

无仓库写权限的外部攻击者通过以下方式触发流水线：

**Context Script Injection（最常见）：**

当 CI 配置使用 `${{ github.event.pull_request.title }}` 等用户可控表达式在 `run:` 步骤中拼接 shell 命令时，攻击者可通过 PR 标题注入命令。GitHub Actions 在执行前先渲染表达式，所以 shell 引号转义无法防御。

**危险触发器对比：**

| 触发器 | Secrets 访问 | 写权限 | 使用的代码版本 | 风险 |
|---|---|---|---|---|
| `pull_request` | 无（GITHUB_TOKEN 只读） | 无 | PR 分支 | 低（但可上传恶意 Artifact） |
| `pull_request_target` | 有 | 有 | 基础分支（默认安全） | 高（若 checkout PR 代码则极危险） |
| `workflow_run` | 有 | 有 | 取决于配置 | 高（常被链式利用） |
| `issue_comment` | 有 | 有 | 基础分支 | 高（结合 checkout PR ref 可 RCE） |

**`pull_request_target` 的致命误用：**

虽然 `pull_request_target` 在基础分支上下文运行（看似安全），但如果 workflow 中显式 checkout 了 PR 的代码（`ref: ${{ github.event.pull_request.head.sha }}`），则攻击者的代码会在拥有 Secrets 和写权限的环境中执行。

## Phase 3: Secrets 窃取与横向移动

成功毒化流水线后，核心目标是窃取 Secrets 并向外扩展。

### 3.1 Secrets 提取方法

**环境变量：**
- `env | base64` 导出所有环境变量（base64 编码可绕过 GitHub 的日志掩码）
- 双重 base64 编码进一步绕过掩码：`echo '${{ toJson(secrets) }}' | base64 -w0 | base64 -w0`

**文件系统：**
- 临时脚本文件：`/home/runner/work/_temp/*`（GitHub Actions 存储渲染后的脚本）
- 进程内存：`gcore` 或 `/proc/<pid>/mem` 读取 Runner.Worker/Runner.Listener 进程中的明文 Secrets

**无法直接外传时：**
- 使用 GITHUB_TOKEN 创建仓库/issue/comment 作为数据中转
- 将 Secrets 写入 Artifact 上传
- 写入 Actions 日志（注意掩码规则）

### 3.2 CI/CD 到云环境穿越

CI/CD Runner 通常拥有云平台凭据用于部署。这些凭据是从 CI/CD 穿越到云环境的桥梁：

| 凭据来源 | 位置 | 利用方式 |
|---|---|---|
| OIDC Token（GitHub → AWS/GCP/Azure） | `id-token: write` 权限 | 请求 OIDC Token → AssumeRoleWithWebIdentity |
| AWS 静态 AK/SK | 环境变量或 Secrets | 参考 `cloud-aksk-exploit` 技能 |
| GCP Service Account JSON | 文件或环境变量 | 参考 `gcp-pentesting` 技能 |
| Azure Service Principal | 环境变量 | 参考 `aws-pentesting` 技能中的 Azure 相关内容 |
| Terraform Cloud Runner 凭据 | `tfc-aws-*`/`tfc-gcp-*` 文件 | 直接使用 CLI 操作云资源 |
| Kubernetes kubeconfig | `~/.kube/config` 或挂载的 SA Token | 集群接管 |
| Docker Registry Token | `~/.docker/config.json` | 推送恶意镜像 |

**Self-hosted Runner 额外攻击面：**
- 云元数据服务（169.254.169.254）→ 获取实例绑定的 IAM 角色凭据
- 内网横向移动 → 访问内网其他服务
- Docker API（2375/tcp）→ 容器逃逸
- Kubernetes 集群访问 → DaemonSet 横向扩展

### 3.3 生产环境接管

如果流水线直接负责生产部署：

- **代码篡改**：在构建产物中注入后门代码
- **供应链攻击**：篡改 npm/PyPI 包发布流程（窃取 publish token → 发布恶意版本）
- **镜像投毒**：修改 Docker 镜像层注入恶意代码
- **IaC 篡改**：修改 Terraform/CloudFormation 配置创建后门资源

## Phase 4: 平台专项攻击

### 4.1 GitHub Actions

GitHub Actions 是最广泛使用的 CI/CD 平台之一，攻击面丰富：

- **Artifact Poisoning**：低权限 workflow 上传恶意 Artifact → 高权限 workflow 下载并执行
- **Cache Poisoning**：跨 workflow 共享的缓存无信任隔离 → 毒化缓存中的脚本/二进制文件
- **GITHUB_TOKEN 滥用**：合并 PR、审批 PR、创建 PR
- **Action Tag 劫持**：攻击者获取 Action 仓库写权限后 force-push 标签指向恶意 commit
- **AI Agent 注入**：CI 中的 LLM Agent（Gemini/Claude Code Action）可被 prompt injection 控制

→ 读 [references/github-actions-abuse.md](references/github-actions-abuse.md)

### 4.2 Jenkins

Jenkins 的高权限特性使其成为高价值目标：

- **Groovy Script Console**（`/script`）→ 直接 RCE
- **Pipeline 创建/修改** → 通过 Jenkinsfile 执行任意命令
- **凭据转储** → Groovy 脚本导出 credentials.xml 中的所有密钥
- **文件读取 → RCE** → 读取 `master.key` + `hudson.util.Secret` → 离线解密所有凭据 → 伪造 remember-me Cookie

→ 读 [references/platform-specific.md](references/platform-specific.md)

### 4.3 Terraform / Atlantis

IaC 工具的攻击核心在于代码即执行：

- **Terraform Plan RCE**：`external` data source 或恶意 Provider 在 `plan` 阶段即可执行代码
- **Terraform Apply RCE**：`local-exec` provisioner 在 `apply` 阶段执行
- **State 文件篡改**：写入 state 文件注入恶意 provider → 下次 plan/apply 触发 RCE
- **Atlantis Plan 注入**：PR 中修改 `.tf` 文件触发 `atlantis plan` → 在 Atlantis 服务器上 RCE
- **Atlantis Custom Workflow**：当 `allow_custom_workflows=true` 时，`atlantis.yaml` 可定义任意执行步骤
- **Terraform Cloud Speculative Plan**：窃取 TFC Token → 触发 speculative plan → 在 Runner 上执行代码 → 获取注入的云凭据

→ 读 [references/platform-specific.md](references/platform-specific.md)

### 4.4 其他平台速查

| 平台 | 关键攻击路径 | 详情 |
|---|---|---|
| GitLab CI | Runner Token 窃取、共享 Runner 逃逸、CI 变量注入 | → platform-specific.md |
| CircleCI | Context Secrets 窃取、SSH Rerun、项目变量导入 | → platform-specific.md |
| Azure DevOps | Service Connection Secret、变量/参数注入、Runner hijack | → platform-specific.md |
| Drone CI | `.drone.yml` commands 注入、Self-hosted Runner 云/K8s 权限 | → platform-specific.md |
| Buildkite | `.buildkite/*.yml` command 注入、Agent 所在云/K8s 权限 | → platform-specific.md |
| Serverless Framework | IAM Role 提权（默认 AdministratorAccess）、Plugin 投毒 | → platform-specific.md |
| CloudFlare | Workers 滥用、Zero Trust 绕过 | → platform-specific.md |
| Concourse / Airflow | 参考 platform-specific.md 快速参照表 | → platform-specific.md |

## 注意事项

**操作安全：**
- CI/CD 系统通常有完整的审计日志——PR 创建、workflow 执行、Secrets 访问都会被记录
- GitHub 上的 PR 即使删除账户后仍可能被 SIEM 捕获
- Self-hosted Runner 上的操作可能触发 EDR/HIDS 告警
- 在授权测试中应事先与客户确认 CI/CD 测试范围和影响

**Secrets 保护绕过：**
- GitHub Actions 日志掩码只保护渲染输出，进程内存中仍存在明文
- 使用 base64 编码或加密可绕过大多数自动掩码机制
- JWT 签名值等派生数据不会被掩码

**供应链攻击升级：**
- 窃取到 npm/PyPI publish token 后可发布恶意包版本
- npm 的 `preinstall`/`postinstall` hook 在安装时自动执行
- Python 的 `.pth` 文件在解释器启动时自动执行
- 单个 CI/CD 沦陷可能级联影响整个供应链（参考 tj-actions/Ultralytics 事件）
