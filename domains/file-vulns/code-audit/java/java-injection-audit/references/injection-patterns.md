# Java 注入类漏洞审计模式参考

6 种注入的危险代码 / 安全代码对比 + EVID_* 证据格式示例。

---

## 1. SQL 注入

### 1.1 JDBC 危险模式 vs 安全模式

```java
// 危险: Statement 拼接
stmt.executeQuery("SELECT * FROM users WHERE id=" + request.getParameter("id"));

// 危险: PreparedStatement 但仍拼接 SQL 片段
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name='" + name + "' ORDER BY " + sortColumn);

// 安全: 占位符绑定
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
ps.setInt(1, Integer.parseInt(request.getParameter("id")));

// ORDER BY 仍需白名单（标识符无法参数化）
List<String> allowed = Arrays.asList("id", "name", "created_at");
String sort = allowed.contains(sortColumn) ? sortColumn : "id";
```

### 1.2 MyBatis `${}` vs `#{}`

```xml
<!-- 危险: ${} 直接拼接 -->
<select id="findUser" resultType="User">
  SELECT * FROM users WHERE name = '${name}'
</select>
<!-- 危险: ORDER BY / LIKE 场景 -->
<select id="search" resultType="User">
  SELECT * FROM users WHERE name LIKE '%${keyword}%' ORDER BY ${orderColumn}
</select>

<!-- 安全: #{} 参数绑定 -->
<select id="findUser" resultType="User">
  SELECT * FROM users WHERE name = #{name}
</select>
<!-- 安全: LIKE 使用 CONCAT -->
<select id="search" resultType="User">
  SELECT * FROM users WHERE name LIKE CONCAT('%', #{keyword}, '%')
</select>
```

审计关键: 全局搜索 `${` 出现位置，逐一确认是否有白名单保护。ORDER BY / GROUP BY / 表名等标识符无法用 `#{}`，必须白名单。

### 1.3 Hibernate HQL 拼接

```java
// 危险: HQL 拼接（虽非原生 SQL 但仍可注入）
String hql = "from User where username='" + input + "'";
session.createQuery(hql).list();
// 危险: Criteria sqlRestriction 拼接
session.createCriteria(User.class).add(Restrictions.sqlRestriction("name='" + input + "'"));

// 安全: 命名参数绑定
session.createQuery("from User where username=:name").setParameter("name", input);
// 安全: Criteria API 参数化
session.createCriteria(User.class).add(Restrictions.eq("username", input));
```

### 1.4 JPA @Query 与 Spring Data JPA

```java
// 危险: 动态拼接原生 SQL
String sql = "SELECT * FROM users WHERE name LIKE '%" + keyword + "%'";
entityManager.createNativeQuery(sql, User.class).getResultList();

// 安全: JPQL 参数绑定
@Query("SELECT u FROM User u WHERE u.name = :name")
List<User> findByName(@Param("name") String name);
// 安全: Specification 动态查询（Criteria API 内部参数化）
Specification<User> spec = (root, query, cb) -> cb.like(root.get("name"), "%" + keyword + "%");
```

### 1.5 二次注入

```java
// 入库参数化安全，出库后被信任再拼入新查询
ps.setString(1, maliciousName); // 入库安全
String name = rs.getString("name"); // 出库
stmt.executeQuery("SELECT * FROM logs WHERE operator = '" + name + "'"); // 二次注入
```

### 1.6 SQL EVID 证据示例

```
[EVID_SQL_EXEC_POINT]       com/app/dao/OrderDao.java:87 | stmt.executeQuery(sql)
[EVID_SQL_STRING_CONSTRUCTION]  :83-86
  sql = "SELECT * FROM orders WHERE user_id=" + userId + " ORDER BY " + sortCol
[EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT]
  Source: OrderController.java:42 — userId=request.getParameter("uid")
  过滤: userId→Integer.parseInt(安全) | sortCol→无过滤(可注入)
```

---

## 2. 命令注入

### 2.1 Runtime.exec 字符串 vs 数组形式

```java
// 易错: 单字符串形式会按空白拆分为程序和参数，不会自动经 shell 解释
Runtime.getRuntime().exec("ping " + userInput);
// ; | & 通常不会被解释，但仍存在参数注入、额外参数拼接和平台差异风险

// 更安全: 数组形式，显式区分程序和参数
Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", userInput});
// 仍需防止 userInput 以 - 开头造成参数注入
```

### 2.2 ProcessBuilder 与 commons-exec

```java
// 危险: sh -c 包装退化为 shell 解释
new ProcessBuilder("sh", "-c", "ping " + userInput).start();
// 相对安全: 参数列表形式
new ProcessBuilder("ping", "-c", "1", userInput).start();

// commons-exec 危险: parse 按空格分割可注入额外参数
CommandLine.parse("convert " + userInput);
// commons-exec 安全: addArgument
CommandLine cmd = new CommandLine("convert");
cmd.addArgument(inputFile, false); // false=不处理引号
```

### 2.3 特殊场景

```java
// 反射调用绕过静态分析
Class<?> clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec", String.class).invoke(clazz.getMethod("getRuntime").invoke(null), userInput);

// ScriptEngine 间接执行
new ScriptEngineManager().getEngineByName("js")
    .eval("java.lang.Runtime.getRuntime().exec('" + userInput + "')");

// Windows vs Linux: cmd /c 和 sh -c 都启动 shell 解释
```

### 2.4 CMD EVID 证据示例

```
[EVID_CMD_EXEC_POINT]       com/app/service/FileService.java:156 | Runtime.getRuntime().exec(cmd)
[EVID_CMD_COMMAND_STRING_CONSTRUCTION]  :151-155
  cmd = "ffmpeg -i " + inputPath + " -o " + outputPath
  inputPath 来自用户上传文件名 | outputPath 服务端生成(安全)
[EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT]
  Source: FileController.java:78 — inputPath=file.getOriginalFilename() | 无过滤 → 可注入
```

---

## 3. SSRF

### 3.1 各 HTTP 客户端 SSRF 入口

```java
// HttpURLConnection
new URL(userInput).openConnection().getInputStream();
// OkHttp
new OkHttpClient().newCall(new Request.Builder().url(userInput).build()).execute();
// Apache HttpClient
HttpClients.createDefault().execute(new HttpGet(userInput));
// RestTemplate
restTemplate.getForObject(userInput, String.class);
// WebClient
webClient.get().uri(userInput).retrieve().bodyToMono(String.class);
```

### 3.2 协议与防御绕过

| 协议 | 风险 |
|------|------|
| `file://` | 读取本地文件 |
| `jar://` | `jar:http://evil.com/shell.jar!/` 下载解析 |
| `netdoc://` | 部分 JDK 支持，类似 `file://` |

```
DNS Rebinding: TTL=0 → 校验时外网 IP，请求时 127.0.0.1（TOCTOU）
302 重定向: HttpURLConnection 默认跟随 → setInstanceFollowRedirects(false)
URL 解析差异: http://evil.com@internal-server/ → 解析器取 host 不一致
IPv6/特殊编码: [::1], 2130706433, 0x7f000001 → 均指向 127.0.0.1
```

### 3.3 安全模式

```java
// URL 白名单 + DNS 解析后校验 + 禁止重定向 + 协议限制
URL url = new URL(input);
if (!Arrays.asList("http", "https").contains(url.getProtocol())) return false;
InetAddress addr = InetAddress.getByName(url.getHost());
if (addr.isLoopbackAddress() || addr.isSiteLocalAddress()) return false;
conn.setInstanceFollowRedirects(false);
```

### 3.4 SSRF EVID 证据示例

```
[EVID_SSRF_URL_NORMALIZATION]  com/app/service/WebhookService.java:45
  url = request.getParameter("callback_url")，无协议限制
[EVID_SSRF_FINAL_URL_HOST_PORT]  :52 | new URL(url).openConnection() — 完全可控
[EVID_SSRF_DNSIP_AND_INNER_BLOCK]  无内网 IP 校验 | followRedirects=true → 可 302 绕过
```

---

## 4. SpEL/OGNL 表达式注入

### 4.1 SpEL 直接解析

```java
// 危险: 用户输入直接进入 SpEL
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();
// userInput = "T(java.lang.Runtime).getRuntime().exec('calc')" → RCE

// StandardEvaluationContext 提供完整能力（类型引用、构造器、方法调用）
StandardEvaluationContext ctx = new StandardEvaluationContext();
parser.parseExpression(userInput).getValue(ctx); // 表达式可控即危险
```

### 4.2 SpEL 在注解与模板中

```java
// @Value 引用可被操控的配置 → RCE
@Value("#{${app.dynamic.expression}}")
private String dynamicValue;

// @PreAuthorize 中如果表达式来源可控（罕见但存在）
@PreAuthorize("hasRole(#{dynamicRole})")

// Thymeleaf SSTI: 控制器返回用户可控视图名
return "pages/" + lang + "/index";
// lang = "__${T(java.lang.Runtime).getRuntime().exec('calc')}__::.x"
// __${...}__ 预处理语法触发 SpEL
```

### 4.3 OGNL 注入 (Struts2) 与 EL 表达式

```java
// Struts2 OGNL 历史漏洞模式:
// URL 注入: /action?(%23context['xwork.MethodAccessor.denyMethodExecution']=false)
// Content-Type 注入: %{(#cmd='id')(#exec=...)}
// Struts2 < 2.5.30 需重点关注

// EL 表达式: 动态构造
ExpressionFactory factory = ExpressionFactory.newInstance();
factory.createValueExpression(elContext, "${" + userInput + "}", Object.class).getValue(elContext);
```

### 4.4 安全模式

```java
// SimpleEvaluationContext 禁用类型引用和构造器
EvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().withInstanceMethods().build();
parser.parseExpression(userInput).getValue(ctx);
// T(java.lang.Runtime) 会抛异常，但仍允许属性访问
```

### 4.5 EXPR EVID 证据示例

```
[EVID_EXPR_SPEL_PARSE]       com/app/service/RuleEngine.java:89
  parser.parseExpression(ruleExpr).getValue(ctx)
[EVID_EXPR_STRING_CONSTRUCTION]  :85-88 | ruleExpr 来自数据库 rule 表
[EVID_EXPR_USER_INPUT_INTO_EXPR]
  Source: RuleController.java:45 — 管理员可编辑规则表达式
  上下文: StandardEvaluationContext | 无沙箱 → Critical
```

---

## 5. LDAP 注入

### 5.1 过滤器拼接与通配符利用

```java
// 危险: 直接拼接
String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";
ctx.search(baseDN, filter, searchControls);
// username = "*)(uid=*))(|(uid=*" → 匹配所有用户
// username = "admin)(&)" → 截断密码条件
// 通配符枚举: * → 全部 | a* → 前缀匹配 → 逐字符枚举
```

### 5.2 安全模式

```java
// 手动转义 ( ) * \ \0
public static String ldapFilterEscape(String input) {
    return input.replace("\\","\\5c").replace("*","\\2a")
        .replace("(","\\28").replace(")","\\29").replace("\0","\\00");
}

// Spring LDAP LdapQueryBuilder（自动参数化）
LdapQuery query = LdapQueryBuilder.query().base("ou=users")
    .where("uid").is(username).and("userPassword").is(password);

// Spring LDAP LdapEncoder
"(&(uid=" + LdapEncoder.filterEncode(username) + ")(userPassword=" + LdapEncoder.filterEncode(password) + "))";
```

### 5.3 DN 注入

```java
// DN 特殊字符与过滤器不同: , + " \ < > ; = 空格(首尾) #(首位)
String dn = "uid=" + username + ",ou=users,dc=example,dc=com"; // 危险
String safeDn = "uid=" + LdapEncoder.nameEncode(username) + ",ou=users,dc=example,dc=com"; // 安全
```

### 5.4 LDAP EVID 证据示例

```
[EVID_LDAP_QUERY_CALL]  com/app/auth/LdapAuthService.java:67
  ctx.search(baseDN, filter, searchControls)
[EVID_LDAP_FILTER_CONSTRUCTION]  :62-66
  filter = "(&(uid=" + username + ")(userPassword=" + password + "))"
  两参数直接拼接，未调用 LdapEncoder
[EVID_LDAP_USER_INPUT_INTO_FILTER]
  Source: LoginController.java:34 — username=request.getParameter("user") | 无过滤 → 可注入
```

---

## 6. NoSQL 注入 (MongoDB)

### 6.1 Java Driver 字符串拼接

```java
// 危险: 拼接 JSON 字符串
String json = "{ 'username': '" + userInput + "' }";
collection.find(Document.parse(json));
// userInput = "admin', 'password': {'$ne': ''}, 'x':'" → 绕过密码

// 安全: 参数化构造（值不被解析为操作符）
collection.find(new Document("username", userInput));
```

### 6.2 Spring Data MongoDB

```java
// 危险: 运行时动态拼接查询
String json = "{'name': {'$regex': '" + keyword + "'}}";
mongoTemplate.find(new BasicQuery(json), User.class);
// keyword = ".*', '$where': 'sleep(5000)" → 注入 $where

// 安全: @Query 参数占位符
@Query("{'name': ?0}")
List<User> findByName(String name);
// 安全: Criteria API
mongoTemplate.find(new Query(Criteria.where("name").is(userInput)), User.class);
```

### 6.3 $where 与操作符注入

```java
// $where 接受 JavaScript 表达式
new Document("$where", "this.username == '" + userInput + "'");
// "'; sleep(5000); '" → 时间盲注 | "' || true || '" → 全量泄露

// 操作符注入: JSON body 直接解析为查询
Document query = Document.parse(requestBody);
// {"password": {"$ne": ""}} → 绕过认证
// {"password": {"$regex": "^a"}} → 逐字符盲注
```

### 6.4 安全模式

```java
// 类型校验 + Filters API
if (!(username instanceof String)) throw new IllegalArgumentException("Invalid type");
Bson filter = Filters.and(Filters.eq("username", username), Filters.eq("password", hashedPassword));
collection.find(filter).first();
```

### 6.5 NoSQL EVID 证据示例

```
[EVID_NOSQL_QUERY_POINT]  com/app/repo/TokenRepo.java:34 | collection.find(query)
[EVID_NOSQL_PARAM_CONSTRUCTION]  :30-33
  String json = "{'token': '" + token + "'}"; Document query = Document.parse(json);
[EVID_NOSQL_USER_INPUT_INTO_QUERY]
  Source: ApiFilter.java:22 — token=request.getHeader("X-Auth-Token")
  方式: 字符串拼接进 JSON → 可注入操作符或修改查询结构
```
