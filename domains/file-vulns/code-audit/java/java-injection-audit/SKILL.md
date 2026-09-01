---
name: java-injection-audit
description: |
  Java 源码注入类漏洞审计。当在 Java 白盒审计中需要检测注入类漏洞时触发。
  覆盖 6 种注入: SQL 注入(JDBC/MyBatis/Hibernate/JPA)、命令注入(Runtime.exec/ProcessBuilder)、
  SSRF(HttpURLConnection/OkHttp/RestTemplate)、LDAP 注入、SpEL/OGNL 表达式注入、NoSQL 注入(MongoDB)。
  需要 java-audit-pipeline 提供的数据流证据(EVID_*)作为审计输入。
metadata:
  tags: java injection, sql injection, command injection, ssrf, spel, ognl, ldap injection, mybatis, hibernate, jpa, nosql, 注入审计, java source audit
  category: code-audit
---

# Java 注入类漏洞源码审计
本 skill 聚焦源码层面判断"注入是否成立"，核心是验证 Source→Sink 路径上的过滤是否充分。构造 payload、绕 WAF 等运行时利用技术属于对应黑盒 exploit skill 范畴。

## 深入参考

- 6 种注入的危险模式 / 安全模式代码对比 / EVID 证据示例 → [references/injection-patterns.md](references/injection-patterns.md)

---

## 6 种注入速查表

| 类型 | 典型 Sink | 危险模式 | 严重度 |
|------|-----------|----------|--------|
| SQL 注入 | `Statement.execute`, `session.createQuery`, MyBatis `${}`, JPA `nativeQuery` | 字符串拼接进 SQL | Critical-High |
| 命令注入 | `Runtime.exec`, `ProcessBuilder.start`, `commons-exec` | 用户输入拼入命令串或经 `sh -c` 包装 | Critical |
| SSRF | `HttpURLConnection`, `OkHttpClient`, `RestTemplate`, `WebClient` | 用户可控 URL 发起服务端请求 | High-Medium |
| SpEL/OGNL 注入 | `ExpressionParser.parseExpression`, `ValueStack.findValue`, `@Value` | 用户输入进入表达式解析上下文 | Critical |
| LDAP 注入 | `DirContext.search`, `LdapTemplate.search` | 用户输入拼入过滤器字符串 | High-Medium |
| NoSQL 注入 | `MongoCollection.find`, `@Query`, `$where` | 字符串拼接进查询或操作符注入 | High |

## 通用审计流程（4 步）

**Step 1 -- 确认 EVID 证据点**: 从 `java-audit-pipeline` Phase 3 产出的 EVID_* 证据中，筛选注入类条目（EVID_SQL_*、EVID_CMD_*、EVID_SSRF_*、EVID_EXPR_*、EVID_LDAP_*、EVID_NOSQL_*）。没有 EVID 证据的 Sink 只能标"待验证"。

**Step 2 -- 判断过滤有效性**: 追踪 Source→Sink 路径上每一步过滤/转义操作，评估其对当前注入类型是否有效。常见陷阱: `PreparedStatement` 但 SQL 片段仍由拼接构造、MyBatis `${}` 被误用为 `#{}`、`escapeshellarg` 等 PHP 思维迁移到 Java 不适用。

**Step 3 -- 评估绕过可能性**: 过滤存在但不充分时，分析具体绕过路径（编码差异、类型混淆、二次处理等）。能给出绕过思路则标"已确认"，否则标"待验证"并记录已知过滤方式。

**Step 4 -- 确定严重度**: 使用 `java-audit-pipeline` 的三维度评分公式 `Score = R*0.40 + I*0.35 + C*0.25`。注入类漏洞 Impact 通常较高（命令/表达式注入 I=3, SQL 注入 I=2-3），但需结合可达性和利用复杂度综合判断。

## SQL 注入审计要点

- **JDBC PreparedStatement vs Statement**: `PreparedStatement` + `?` 占位符是安全的，`Statement.execute(sql)` 拼接即危险；注意 `PreparedStatement` 中仍可能存在拼接片段
- **MyBatis `#{}` vs `${}`**: `#{}` 参数绑定安全，`${}` 直接拼接危险；ORDER BY 场景常被迫用 `${}`，需白名单校验
- **Hibernate HQL 拼接**: `session.createQuery("from User where name='" + input + "'")` 虽然是 HQL 仍可注入
- **JPA @Query nativeQuery**: `@Query(value="...", nativeQuery=true)` 中 SpEL `#{#param}` 或字符串拼接均危险
- **动态排序 ORDER BY**: 标识符无法参数化，白名单是唯一安全方案；Spring Data 的 `Sort` 对象是安全的

## 命令注入审计要点

- **Runtime.exec(String) vs exec(String[])**: 单字符串形式按空白拆分为程序和参数，不会自动经 shell 解释；数组形式更明确，但两者都需注意 `-flag` 参数注入
- **ProcessBuilder**: 参数列表形式类似数组 exec，但通过 `sh -c "cmd"` 包装则退化为 shell 解释
- **反射调用**: 通过反射调用 `Runtime.getRuntime()` 或 `ProcessBuilder` 可绕过静态扫描
- **commons-exec CommandLine**: `CommandLine.parse(userInput)` 危险，`addArgument(input, false)` 安全

## SSRF 审计要点

- **HttpURLConnection**: `new URL(userInput).openConnection()` — 最基础的 SSRF 入口
- **OkHttp / Apache HttpClient / RestTemplate / WebClient**: 均需检查 URL 参数是否用户可控
- **协议限制**: 检查是否限制 `http/https`（`file://` 读文件、`jar://` SSRF、`netdoc://` 信息泄露）
- **DNS Rebinding**: 先解析校验再发起请求存在 TOCTOU 竞争
- **重定向跟随**: `HttpURLConnection` 默认跟随同协议重定向，需 `setInstanceFollowRedirects(false)`

## SpEL/OGNL 表达式注入审计要点

- **SpEL**: `new SpelExpressionParser().parseExpression(userInput).getValue()` — 直接 RCE
- **@Value / @PreAuthorize**: 注解中引用用户可控配置值时可触发 SpEL 解析
- **Thymeleaf SSTI**: `__${expr}__` 预处理语法触发 SpEL 执行
- **OGNL (Struts2)**: `ActionContext` / `ValueStack` 注入，历史漏洞众多
- **安全模式**: `SimpleEvaluationContext` 限制 SpEL 功能（禁用类型引用和构造器）

## LDAP 注入审计要点

- **过滤器拼接**: `"(uid=" + username + ")"` — 注入 `*)(uid=*))(|(uid=*` 可修改查询逻辑
- **安全模式**: 手动转义 `( ) * \ \0` 或使用 Spring LDAP 的 `LdapQueryBuilder` / `LdapEncoder`
- **DN 注入**: 与过滤器注入不同，需转义 `, + " \ < > ;` 等 DN 特殊字符

## NoSQL 注入审计要点

- **MongoDB Java Driver**: `BasicDBObject` / `Document` 构造时如果拼接 JSON 字符串则可注入操作符
- **Spring Data MongoDB**: `@Query("{'name': ?0}")` 参数化安全；字符串拼接构造查询危险
- **$where / $regex**: `$where` 接受 JavaScript 表达式，用户可控时等价于代码执行
- **Criteria API**: `Criteria.where("name").is(input)` 是安全的参数化查询方式

## 检测清单

- [ ] 所有注入类 EVID_* 证据点已逐一审查
- [ ] SQL 拼接点均已验证是否使用参数化/预编译，MyBatis `${}` 已全部标记
- [ ] 命令执行入口的每个参数来源和构造方式已检查
- [ ] SSRF Sink 的 URL 来源、协议限制、重定向策略已确认
- [ ] SpEL/OGNL 解析入口的表达式来源已追踪
- [ ] LDAP 过滤器和 DN 的转义处理已确认
- [ ] NoSQL 查询参数的构造方式已检查
- [ ] 过滤不充分的点已给出具体绕过思路或标"待验证"
- [ ] 严重度评分使用了统一公式，与 pipeline 一致
