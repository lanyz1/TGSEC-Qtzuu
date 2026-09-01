# Java 危险函数分类速查表

按漏洞类型分类，列出 Java 中常见的 Sink 函数及其审计要点。审计时以此表为索引进行全局关键字扫描，快速定位潜在漏洞代码区域。

---

## SQL 注入（SQL）

**Sink 函数**: `Statement.executeQuery`, `Statement.executeUpdate`, `Statement.execute`, `Connection.prepareStatement`（拼接 SQL 时）, MyBatis `${}` 占位符, Hibernate `Session.createQuery` / `Session.createSQLQuery`（HQL/原生 SQL 拼接时）, JPA `@Query`（`nativeQuery=true` 且拼接参数时）, `EntityManager.createNativeQuery`, Spring `JdbcTemplate.query/update`（字符串拼接 SQL 时）

**危险模式**: 用户输入通过字符串拼接进入 SQL 语句。特别注意 MyBatis 的 `${}` — 开发者常误以为 MyBatis 天然安全，但 `${}` 是直接替换不做预编译；Hibernate HQL 拼接同样存在注入风险。`ORDER BY`、`LIMIT`、表名/列名等无法参数化的位置是高危区域。

**安全验证**: 是否使用 `PreparedStatement` 参数化绑定; MyBatis 是否使用 `#{}` 而非 `${}`; JPA `@Query` 是否使用命名参数; 动态排序字段是否走白名单校验。

**对应审计 skill**: `java-injection-audit`

---

## 命令注入（CMD）

**Sink 函数**: `Runtime.getRuntime().exec()`, `ProcessBuilder.command().start()`, `commons-exec: CommandLine / DefaultExecutor`

**危险模式**: 用户输入拼入命令字符串或命令参数数组。`Runtime.exec(String)` 会经过 `StringTokenizer` 分割，与 `Runtime.exec(String[])` 行为不同，可能影响注入方式。`ProcessBuilder` 使用数组参数时，各参数独立传递给 OS，shell 元字符注入难度增加但并非完全安全（参数本身可能被目标程序解释）。

**安全验证**: 命令和参数是否硬编码; 用户输入是否仅作为参数值（非命令本身）; 是否存在白名单校验; 是否使用数组形式传参避免 shell 解释。

**对应审计 skill**: `java-injection-audit`

---

## SSRF

**Sink 函数**: `java.net.URL.openConnection`, `HttpURLConnection.connect`, `OkHttpClient.newCall().execute`, `Apache HttpClient: CloseableHttpClient.execute`, `Spring RestTemplate.getForObject / exchange`, `Spring WebClient.get().retrieve`, `java.net.Socket` 直连

**危险模式**: 用户可控的 URL 被服务端发起请求。注意 `URL.openConnection` 支持 `file://`、`jar://`、`netdoc://` 等协议; HTTP 客户端默认跟随 302 重定向可能绕过 host 校验。

**安全验证**: URL 白名单/黑名单验证; 是否限制了协议（仅 http/https）; DNS Rebinding 防护（先解析 DNS 再校验 IP）; 是否禁用了重定向跟随; 内网地址段（10/172.16/192.168/127）是否被阻断。

**对应审计 skill**: `java-injection-audit`

---

## 文件读取（FILE）

**Sink 函数**: `FileInputStream`, `Files.readAllBytes / Files.readAllLines / Files.newInputStream`, `RandomAccessFile`, `ClassLoader.getResource / getResourceAsStream`, `java.nio.file.Path` + `Files.read*`, `new File().exists/length/lastModified`（路径探测）, `ServletContext.getResourceAsStream`

**危险模式**: 用户输入影响文件路径，可导致任意文件读取。Java NIO 的 `Path.resolve` 和 `Path.normalize` 行为需特别关注 — `../` 穿越在 `normalize` 后仍可能逃逸基准目录。`ClassLoader.getResource` 可被利用读取 classpath 下的敏感配置。

**安全验证**: 是否使用 `canonical path` 对比基准目录; `Path.normalize()` 后是否校验 `startsWith(baseDir)`; 是否存在双重编码绕过（%2e%2e%2f）; 文件名是否走白名单。

**对应审计 skill**: `java-file-audit`

---

## 文件上传（UPLOAD）

**Sink 函数**: `MultipartFile.transferTo()`, `Part.write()`, `Files.copy(inputStream, targetPath)`, `FileOutputStream.write`（配合上传流）

**危险模式**: 用户上传的文件被存储到 Web 可访问目录且保留了可执行扩展名。Java 应用通常不像 PHP 那样直接执行上传文件，但 JSP/JSPX 文件上传到 webapp 目录下会被容器编译执行。

**安全验证**: 扩展名白名单还是黑名单（黑名单需覆盖 `.jsp`, `.jspx`, `.jspf`, `.war`）; 存储目录是否在 webapp 根目录外; 是否使用随机文件名; 上传目录是否有容器解析 JSP 的配置; Content-Type 校验（可伪造但增加利用难度）。

**对应审计 skill**: `java-file-audit`

---

## XSS

**Sink 函数**: JSP `<%= expression %>` / `<% out.print() %>`, JSTL 缺少 `<c:out>` 或 `fn:escapeXml`, Thymeleaf `th:utext`（不转义）vs `th:text`（自动转义）, FreeMarker `${var?no_esc}` / `<#noescape>`, Velocity `$!{var}`

**危险模式**: 用户输入未经 HTML 编码直接输出到页面。JSP 中 `<%= %>` 默认不转义; JSTL 的 `${param.name}` 在 EL 表达式中直接输出也不转义; Thymeleaf 的 `th:utext` 明确跳过转义。

**安全验证**: JSP 是否使用 `<c:out value="">` 或 `fn:escapeXml()`; Thymeleaf 是否使用 `th:text` 而非 `th:utext`; FreeMarker 全局 `auto_escaping` 配置; JavaScript 上下文中是否做了 JS 编码而非仅 HTML 编码; 全局 XSS Filter 的实际覆盖范围。

**对应审计 skill**: `java-frontend-audit`

---

## XXE

**Sink 函数**: `DocumentBuilderFactory.newInstance().newDocumentBuilder().parse()`, `SAXParserFactory.newInstance().newSAXParser().parse()`, `XMLInputFactory.newInstance().createXMLStreamReader()`, `TransformerFactory.newInstance().newTransformer()`, `SchemaFactory.newInstance().newSchema()`, `XMLReader.parse()`, `Unmarshaller.unmarshal()`（JAXB）

**危险模式**: 用户提交的 XML 数据被解析且未禁用外部实体和 DTD 加载。Java 的 XML 解析器默认配置大多不安全（允许外部实体），需显式禁用。

**安全验证**: 是否设置了 `FEATURE_DISALLOW_DOCTYPE_DECL = true`; 是否设置了 `FEATURE_EXTERNAL_GENERAL_ENTITIES = false` 和 `FEATURE_EXTERNAL_PARAMETER_ENTITIES = false`; `XMLInputFactory` 是否设置了 `IS_SUPPORTING_EXTERNAL_ENTITIES = false` 和 `SUPPORT_DTD = false`; 使用的 XML 库版本是否存在已知绕过。

**对应审计 skill**: `java-serialization-audit`

---

## 反序列化（DESER）

**Sink 函数**: `ObjectInputStream.readObject()` / `readUnshared()`, `XMLDecoder.readObject()`, FastJSON `JSON.parseObject(str, Feature.SupportNonPublicField)` / `JSON.parse`（autoType 未禁用时）, Jackson `ObjectMapper.enableDefaultTyping()` / `@JsonTypeInfo`, Hessian `HessianInput.readObject()`, Kryo `kryo.readObject()`（无注册类限制时）, XStream `xstream.fromXML()`

**危险模式**: 用户可控数据进入反序列化入口。Java 原生反序列化（ObjectInputStream）是最经典的 RCE 入口; FastJSON autoType 开启时可实例化任意类; Jackson enableDefaultTyping 同理; XMLDecoder 直接将 XML 映射为任意方法调用。

**安全验证**: ObjectInputStream 是否配置了 `ObjectInputFilter`（JDK 9+）或使用了 SerialKiller / contrast-rO0 等防护库; FastJSON 版本及 autoType 白名单/黑名单配置; Jackson 是否禁用了 DefaultTyping; 项目 classpath 中是否存在已知 Gadget Chain（Commons Collections / BeanUtils / C3P0 / JDK7u21 等）。

**对应审计 skill**: `java-serialization-audit`

---

## 表达式注入（EXPR）

**Sink 函数**: Spring SpEL `ExpressionParser.parseExpression().getValue()`, OGNL `Ognl.getValue()` / `OgnlUtil.getValue()`（Struts2）, MVEL `MVEL.eval()`, EL 表达式 `ELProcessor.eval()` / `ExpressionFactory.createValueExpression()`, Groovy `GroovyShell.evaluate()` / `GroovyClassLoader.parseClass()`

**危险模式**: 用户输入被拼入表达式字符串并执行。SpEL 在 Spring 场景中极为常见（`@Value` 注解、Spring Security 表达式、Thymeleaf 预处理 `__${expr}__`）; Struts2 的 OGNL 注入是历史上最高频的 RCE 入口之一。

**安全验证**: SpEL 是否使用了 `SimpleEvaluationContext`（安全）而非 `StandardEvaluationContext`（可 RCE）; OGNL SecurityMemberAccess 配置; 表达式字符串是否硬编码; 用户输入是否仅作为表达式变量而非表达式本身。

**对应审计 skill**: `java-injection-audit`

---

## 重定向（REDIR）

**Sink 函数**: `HttpServletResponse.sendRedirect()`, Spring MVC `return "redirect:" + url`, `RedirectView`, `ModelAndView("redirect:" + url)`, `ResponseEntity.status(302).header("Location", url)`

**危险模式**: 用户输入控制重定向目标 URL，可用于钓鱼攻击（Open Redirect）。在 OAuth2 / CAS 等认证流程中，开放重定向可升级为 Token/Code 窃取。

**安全验证**: 是否仅允许相对路径重定向; 是否有域名白名单; 是否检查了 URL scheme（防止 `javascript:` 协议）; Spring Security 的 `SavedRequestAwareAuthenticationSuccessHandler` 是否限制了 targetUrl。

**对应审计 skill**: `java-frontend-audit`

---

## LDAP 注入（LDAP）

**Sink 函数**: `InitialDirContext.search()`, `SpringLdapTemplate.search()`, `DirContext.search(name, filter, controls)`

**危险模式**: 用户输入拼入 LDAP 过滤器字符串（如 `(&(uid={0})(userPassword={1}))`），通过注入 `*`、`)(` 等字符修改查询逻辑。LDAP 认证绑定场景中，空密码可能导致匿名绑定成功。

**安全验证**: 是否使用参数化查询（`SearchControls` + `filterArgs`）; 是否对 `(`, `)`, `*`, `\`, `NUL` 做了转义; Spring LDAP 的 `LdapQueryBuilder` 是否正确使用; `ldap_bind` 是否检查了空密码。

**对应审计 skill**: `java-injection-audit`
