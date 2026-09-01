---
name: php-injection-audit
description: |
  PHP 源码注入类漏洞审计。当在 PHP 白盒审计中需要检测注入类漏洞时触发。
  覆盖 6 种注入: SQL 注入(PDO/MySQLi/ORM)、NoSQL 注入(MongoDB)、
  命令注入(system/exec/passthru)、LDAP 注入、表达式注入(eval/preg_replace /e)、SSRF。
  需要 php-audit-pipeline 提供的数据流证据(EVID_*)作为审计输入。
metadata:
  tags: php injection, sql injection, command injection, nosql, ldap injection, ssrf, eval, preg_replace, 注入审计, 代码注入, php source audit
  category: code-audit
---

# PHP 注入类漏洞源码审计
本 skill 聚焦源码层面判断"注入是否成立"，核心是验证 Source→Sink 路径上的过滤是否充分。构造 payload、绕 WAF 等运行时利用技术属于对应黑盒 exploit skill 范畴。

## 深入参考

- 6 种注入的危险模式 / 安全模式代码对比 / EVID 证据示例 → [references/injection-patterns.md](references/injection-patterns.md)

---

## 6 种注入速查表

| 类型 | 典型 Sink | 危险模式 | 严重度 |
|------|-----------|----------|--------|
| SQL 注入 | `PDO::query`, `mysqli_query`, `DB::raw`, `whereRaw` | 字符串拼接进 SQL | Critical-High |
| 命令注入 | `exec`, `system`, `shell_exec`, `passthru`, `proc_open`, 反引号 | 用户输入拼入命令串 | Critical |
| SSRF | `curl_exec`, `file_get_contents`, `SoapClient` | 用户可控 URL 发起服务端请求 | High-Medium |
| 表达式注入 | `eval`, `assert`, `preg_replace(/e)`, `create_function` | 用户输入进入代码执行上下文 | Critical |
| NoSQL 注入 | MongoDB `find()`, `$where`, 操作符 `$ne/$gt/$regex` | 数组/对象参数绕过等值比较 | High |
| LDAP 注入 | `ldap_search`, `ldap_list`, `ldap_bind` | 用户输入拼入过滤器字符串 | High-Medium |

## 通用审计流程（4 步）

**Step 1 -- 确认 EVID 证据点**: 从 `php-audit-pipeline` Phase 3 产出的 EVID_* 证据中，筛选属于注入类的条目（EVID_SQL_*、EVID_CMD_*、EVID_SSRF_*、EVID_EXPR_*、EVID_LDAP_*）。没有 EVID 证据的 Sink 只能标"待验证"。

**Step 2 -- 判断过滤有效性**: 追踪 Source→Sink 路径上的每一步过滤/转义操作，评估其是否对当前注入类型有效。常见陷阱: `addslashes` 对 GBK 宽字节无效、`intval` 对数组参数无效、`escapeshellarg` 在特定 locale 下可绕过。

**Step 3 -- 评估绕过可能性**: 过滤存在但不充分时，分析具体绕过路径（编码差异、类型混淆、二次处理等）。能给出绕过思路则标"已确认"，否则标"待验证"并记录已知过滤方式。

**Step 4 -- 确定严重度**: 使用 `php-audit-pipeline` 的三维度评分公式 `Score = R*0.40 + I*0.35 + C*0.25`。注入类漏洞的 Impact 通常较高（命令/表达式注入 I=3, SQL 注入 I=2-3），但需结合可达性和利用复杂度综合判断。

## SQL 注入审计要点

- **PDO 预编译**: 确认 `prepare()` + `execute()` 的占位符绑定完整。`PDO::query($sql)` 和 `PDO::exec($sql)` 是直接执行，拼接即危险
- **ORM 陷阱**: `whereRaw`/`havingRaw`/`orderByRaw`/`selectRaw` 中的变量拼接不受 ORM 参数化保护
- **动态 ORDER BY / LIMIT**: 这两个子句无法使用参数化绑定，`intval()` 或白名单是唯一安全方案
- **sprintf %s 拼接**: `sprintf("SELECT * FROM t WHERE id='%s'", $input)` 本质仍是拼接
- **二次注入**: 数据入库时转义、出库时未转义再拼入新查询，追踪需跨越存储边界

## 命令注入审计要点

- **escapeshellarg 有效性**: 单独使用通常有效，但与 `escapeshellcmd` 同时使用反而会引入绕过（引号配对被破坏）
- **多参数拼接**: `exec("convert " . escapeshellarg($src) . " " . $dest)` — 如果 `$dest` 未转义则仍可注入
- **反引号**: 容易被忽视的命令执行方式，全局搜索反引号中的变量引用
- **proc_open 数组模式**: `proc_open([$cmd, $arg1, $arg2], ...)` 避免了 shell 解析，是安全的命令执行方式

## SSRF 审计要点

- **协议限制**: 检查是否限制了 `http/https` 以外的协议（`gopher://` 可打内网服务，`file://` 可读本地文件）
- **IP 黑名单绕过**: 十进制 `2130706433`、八进制 `0177.0.0.1`、IPv6 `[::1]`、DNS Rebinding 都能绕过简单的 IP 检查
- **重定向跟随**: `curl` 默认不跟随但 `CURLOPT_FOLLOWLOCATION=true` 时，可通过 302 跳转绕过 URL 白名单
- **DNS 解析时序**: 先解析检查再发起请求的模式存在 TOCTOU 竞争（DNS Rebinding 利用点）

## 表达式注入审计要点

- **eval/assert**: 任何用户可控数据进入 `eval()` 都是 Critical。`assert()` 在 PHP < 8.0 可执行字符串
- **preg_replace /e**: PHP 7.0 已移除，但遗留系统中仍可能存在。替代方案 `preg_replace_callback` 是安全的
- **create_function**: 本质是 `eval`，PHP 8.0 已移除但老项目常见
- **可控回调**: `array_map`/`usort`/`call_user_func` 的回调参数如果用户可控，等价于代码执行

## NoSQL / LDAP 审计要点（简要）

- **MongoDB 操作符注入**: PHP 数组参数 `$_GET['user'][$ne]=1` 可绕过等值匹配，检查是否对输入做了类型强制转换
- **$where 注入**: MongoDB 的 `$where` 接受 JavaScript 表达式，用户可控时等价于代码执行
- **LDAP 过滤器拼接**: `(&(uid=$input)(pass=$pass))` 中注入 `*)(uid=*))(|(uid=*` 可修改查询逻辑
- **ldap_escape 缺失**: PHP 5.6+ 提供 `ldap_escape()` 但很多项目未使用，检查 `(`, `)`, `*`, `\`, `NUL` 是否被转义

## 检测清单

- [ ] 所有注入类 EVID_* 证据点已逐一审查
- [ ] SQL 拼接点均已验证是否使用参数化/预编译
- [ ] ORM Raw 方法中的变量拼接已全部标记
- [ ] 命令执行函数的每个参数段都已检查转义
- [ ] SSRF Sink 的 URL 来源和协议限制已确认
- [ ] eval/assert/preg_replace /e 的参数可控性已追踪
- [ ] NoSQL 查询参数的类型强制已检查
- [ ] LDAP 过滤器的转义处理已确认
- [ ] 过滤不充分的点已给出具体绕过思路或标"待验证"
- [ ] 严重度评分使用了统一公式，与 pipeline 一致
