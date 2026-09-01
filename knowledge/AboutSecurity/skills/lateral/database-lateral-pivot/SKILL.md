---
name: database-lateral-pivot
description: "数据库横向移动与跨库攻击。当已获取一个数据库权限（PostgreSQL/MySQL/MSSQL）需要横向到其他数据库或内网服务时使用。覆盖 PostgreSQL dblink 跨库连接、MSSQL Linked Server 横向、MySQL 联邦引擎跨库、数据库→SSRF→内网探测。当目标网络隔离但数据库可通信时（数据库通常有比应用服务器更宽松的网络策略），这是突破隔离的关键路径。发现任何数据库间通信需求、内网数据库横向、跨库查询场景都应使用此技能"
metadata:
  tags: "database,lateral,pivot,dblink,linked_server,postgresql,mssql,mysql,横向移动,跨库,内网,ssrf"
  category: "lateral"
---

# 数据库横向移动方法论

数据库是内网中天然的跳板——它们通常比应用服务器有更宽松的网络访问策略（需要连接多个服务），而且 PostgreSQL 的 dblink、MSSQL 的 Linked Server、MySQL 的 FEDERATED 引擎都提供了原生的跨主机查询能力。当应用层网络隔离严格时，通过数据库进行横向移动往往是唯一路径。

## ⛔ 深入参考（必读）

- dblink 连接、Linked Server 利用、SSRF 探测的完整命令和场景 → [references/dblink-lateral.md](references/dblink-lateral.md)

---

## Phase 1: 评估横向条件

在当前数据库中收集信息，判断横向移动的可能性：

```sql
-- PostgreSQL: 检查可用扩展
SELECT * FROM pg_available_extensions WHERE name IN ('dblink','postgres_fdw');

-- PostgreSQL: 已有的外部连接配置
SELECT * FROM pg_foreign_server;
SELECT * FROM pg_user_mapping;

-- MSSQL: 检查 Linked Servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;

-- MySQL: 检查 FEDERATED 引擎
SHOW ENGINES;
```

**横向条件清单**：
- 当前是 superuser/sa/root 吗？（非特权用户通常无法创建 dblink）
- 数据库配置中有没有其他主机的连接信息？
- 环境变量/配置文件中有没有其他数据库的凭据？

## Phase 2: 内网信息收集（通过数据库）

数据库本身就是信息金矿：

```sql
-- 搜索连接字符串
SELECT * FROM pg_settings WHERE name LIKE '%connection%';

-- 搜索包含密码的表/列
SELECT table_name, column_name FROM information_schema.columns
WHERE column_name LIKE '%pass%' OR column_name LIKE '%secret%' OR column_name LIKE '%token%';

-- 查找其他数据库主机（配置表中常有）
SELECT * FROM config WHERE key LIKE '%host%' OR key LIKE '%db%' OR value LIKE '%.%.%.%';
```

## Phase 3: 横向攻击决策树

```
已控制一个数据库？
├─ PostgreSQL → 
│   ├─ dblink（最灵活）→ 连接任意 PostgreSQL/支持的数据库
│   ├─ postgres_fdw（外部数据封装器）→ 透明跨库查询
│   └─ COPY TO PROGRAM + curl → SSRF 探测内网
├─ MSSQL →
│   ├─ Linked Server → 连接其他 MSSQL/任意 OLE DB 数据源
│   ├─ OPENROWSET → 即席跨库查询
│   └─ xp_cmdshell + curl → 内网探测
├─ MySQL →
│   ├─ FEDERATED 引擎 → 跨 MySQL 实例查询
│   └─ LOAD DATA LOCAL → 读取本地文件
└─ 通用 → 
    ├─ 通过命令执行进行端口扫描/服务发现
    └─ 利用数据库中存储的凭据连接其他服务
```

→ 各数据库横向的完整命令 → [references/dblink-lateral.md](references/dblink-lateral.md)

## Phase 4: 横向后利用

成功连接到新数据库后：

1. **提取数据** — 用户表、配置表、flag
2. **获取 RCE** — COPY FROM PROGRAM / xp_cmdshell / UDF
3. **继续横向** — 新数据库可能连接更多内网资源
4. **持久化** — 创建后门账号、触发器

## 注意事项

- dblink/Linked Server 查询产生的流量来自**数据库服务器 IP**，不是你的攻击机 IP
- 利用这一特性可以绕过基于 IP 的网络 ACL
- 数据库间通信通常是明文的，注意凭据安全
- 大量跨库查询会产生日志，注意操作节制
