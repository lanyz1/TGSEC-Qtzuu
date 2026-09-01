---
name: java-framework-audit
description: |
  Java 框架特定漏洞源码审计。当在 Java 白盒审计中需要检测框架层面的已知漏洞模式时触发。
  覆盖 5 大框架/组件: Spring 全家桶(SpEL/Actuator/参数绑定/Spring Cloud Gateway)、
  Struts2(OGNL/ActionMapping/Content-Type 解析)、Shiro(RememberMe 反序列化/URI 绕过)、
  FastJSON/Jackson/Gson(反序列化 autotype/polymorphic)、MyBatis(${} 注入/动态 SQL)。
  这些是 Java 生态中出现频率最高、影响面最广的框架级漏洞。
metadata:
  tags: spring, struts2, shiro, fastjson, jackson, mybatis, ognl, spel, actuator, rememberme, spring cloud, 框架漏洞, java source audit
  category: code-audit
---

# Java 框架特定漏洞源码审计
框架漏洞的本质分两类: **框架自身缺陷**（已知 CVE，升级即修）和**框架误用**（开发者对框架安全机制理解不足导致的配置/编码缺陷）。本 skill 关注的核心问题是: 被审计项目的代码如何触发这些已知的框架缺陷模式。

## 深入参考

- 5 大框架/组件漏洞模式详解 → [references/framework-vulns.md](references/framework-vulns.md)

---

## 5 大框架/组件速查表

| 框架/组件 | 核心风险 | 首要搜索关键字 | 典型严重度 |
|-----------|---------|---------------|-----------|
| Spring 全家桶 | SpEL 注入 / Actuator 暴露 / Mass Assignment | `@Value` `SpelExpression` `Actuator` `management.endpoints` | 高-严重 |
| Struts2 | OGNL 注入 / Content-Type 解析 | `struts.xml` `ActionSupport` `ValueStack` `ognl` | 严重 |
| Shiro | RememberMe 反序列化 / URI 绕过 | `setCipherKey` `rememberMe` `ShiroFilterChain` | 严重 |
| FastJSON/Jackson/Gson | 反序列化 autotype / polymorphic | `JSON.parseObject` `JSON.parse` `enableDefaultTyping` `@JsonTypeInfo` | 严重 |
| MyBatis | `${}` SQL 拼接注入 | `${` 在 Mapper XML / `@Select` `@Update` 注解 | 高 |

### Spring 全家桶审计要点

- **Spring MVC 参数绑定（Mass Assignment）**: `@ModelAttribute` 会自动将请求参数绑定到对象字段。若实体类含 `role`/`isAdmin`/`price` 等敏感字段且未使用 `@InitBinder` + `WebDataBinder.setAllowedFields()` 做白名单，攻击者可通过添加额外参数覆写敏感属性
- **Spring Boot Actuator**: 检查 `management.endpoints.web.exposure.include` 配置。高危端点: `/actuator/env`（泄露配置 + restart RCE）、`/actuator/jolokia`（JNDI 注入）、`/actuator/heapdump`（堆转储提取密钥/密码）、`/actuator/gateway/routes`（Gateway 路由注入）
- **SpEL 注入**: 5 种常见注入点 — `@Value("#{externInput}")`、`@Cacheable(key="#root.args[0]")` 拼接用户输入、`@PreAuthorize` / `@PostAuthorize` 表达式拼接、`ExpressionParser.parseExpression()` 直接解析外部输入、Spring Data `@Query` 中的 SpEL `?#{...}`
- **Spring Cloud Gateway**: CVE-2022-22947 类型漏洞，路由 Predicate/Filter 配置中嵌入 SpEL 表达式，通过 Actuator `/gateway/routes` 动态注册恶意路由
- **Spring Security 配置陷阱**: `antMatchers` 顺序错误（宽松规则在前覆盖严格规则）、`.permitAll()` 范围过大、路径匹配与 Servlet 路径不一致（如尾部斜杠 `/admin` vs `/admin/`）

### Struts2 审计要点

- **OGNL 注入**: 用户可控数据进入 OGNL 表达式求值。参数名/值通过 `ParametersInterceptor` 进入 `ValueStack`，若 `SecurityMemberAccess` 限制不严，可执行任意代码
- **Content-Type 解析**: Jakarta Multipart 解析器对异常 Content-Type 的错误处理导致 OGNL 执行（S2-045），Content-Disposition 的 filename 字段同理（S2-046）
- **ActionMapping 参数前缀**: `method:`（调用任意 Action 方法）、`redirect:`/`redirectAction:`（OGNL 注入）。检查 `struts.enable.DynamicMethodInvocation` 和 `struts.mapper.alwaysSelectFullNamespace`
- **版本 CVE 映射**: Struts 2.0.x~2.3.x 是高危区间，S2-001/005/009/012/013/015/016/019/032/033/037/045/046/048/052/053/057/059/061/062 均为远程代码执行级别

### Shiro 审计要点

- **RememberMe 反序列化**: Shiro 1.2.4 及之前版本使用硬编码 AES 密钥 `kPH+bIxk5D2deZiIxcaaaA==` 加密 RememberMe Cookie。即使升级后，若开发者使用自定义但可预测/泄露的密钥，风险依旧存在
- **URI 绕过**: 分号截断 `/admin/;.js` 绕 Shiro 但被 Spring 正常路由、`/..;/admin` 路径穿越、双重 URL 编码、大小写混合绕 Filter。核心原因是 Shiro 的 URL 匹配与后端框架（Spring/Servlet）的解析规则不一致
- **版本 CVE**: CVE-2016-4437（硬编码密钥）、CVE-2020-1957（`/toLogin;/../admin` 绕过）、CVE-2020-11989（双重编码）、CVE-2021-41303（路径标准化绕过）

### FastJSON/Jackson/Gson 审计要点

- **FastJSON**: `JSON.parseObject(input)` 或 `JSON.parse(input)` 默认支持 `@type` 字段指定反序列化类。autotype 黑名单随版本升级不断被绕过（1.2.24→1.2.47→1.2.68→1.2.80）。`Feature.SupportNonPublicField` 开启时可设置私有字段。1.2.83+ 引入 `safeMode` 彻底关闭 autotype
- **Jackson**: `ObjectMapper.enableDefaultTyping()` 或 `ObjectMapper.activateDefaultTyping()` 开启全局多态反序列化，等同于全局 RCE 入口。字段级 `@JsonTypeInfo(use=Id.CLASS)` 或 `@JsonTypeInfo(use=Id.MINIMAL_CLASS)` 同样危险
- **Gson**: 本身不支持多态反序列化，相对安全。但自定义 `TypeAdapter` / `JsonDeserializer` 中若使用 `Class.forName` 加载用户指定类名则引入风险
- **检测方法**: 搜索 `JSON.parseObject` / `JSON.parse`（FastJSON）、`enableDefaultTyping` / `activateDefaultTyping` / `@JsonTypeInfo`（Jackson）、自定义 `TypeAdapter`（Gson）

### MyBatis 审计要点

- **`${}` vs `#{}`**: `${}` 是字符串直接拼接（等同于 `String.format`），`#{}` 是预编译参数绑定。Mapper XML 和 `@Select`/`@Update`/`@Delete`/`@Insert` 注解中的 `${}` 均为 SQL 注入入口
- **动态 SQL 中的 `${}`**: `<if test="sort != null">ORDER BY ${sort}</if>`、`<where>` 和 `<foreach>` 标签内的 `${}` 使用同样危险
- **ORDER BY / LIKE / IN 安全写法**: ORDER BY 无法使用 `#{}` 预编译，应对列名做白名单校验; LIKE 应改写为 `LIKE CONCAT('%', #{keyword}, '%')`; IN 应使用 `<foreach collection="ids" item="id">#{id}</foreach>`
- **两种入口**: Mapper XML 文件（`*Mapper.xml`）和注解模式（`@Select("SELECT * FROM ${table}")`），两者都需要审计

## 检测清单

- [ ] 已确认项目使用的框架及精确版本号，已比对已知 CVE
- [ ] Spring Actuator 端点暴露范围已检查，敏感端点已确认是否需要认证
- [ ] SpEL 注入的 5 种场景已逐一搜索排查
- [ ] Spring MVC `@ModelAttribute` 绑定的实体是否有敏感字段未做白名单
- [ ] Struts2 项目已确认 OGNL 安全配置和 `SecurityMemberAccess` 设置
- [ ] Shiro `setCipherKey` 是否使用默认或弱密钥，Filter Chain 的 URI 匹配与实际路由是否一致
- [ ] FastJSON 版本及 autotype 配置已确认，Jackson 是否开启 `enableDefaultTyping`
- [ ] 所有 Mapper XML 和 `@Select` 注解中的 `${}` 使用已标记，不可避免的场景已确认有白名单防护
- [ ] 动态 SQL 标签（`<if>` / `<where>` / `<foreach>`）中的 `${}` 已检查
- [ ] 所有发现的框架漏洞均有 EVID_* 证据链（Source→Sink 路径 + 版本/配置证据）
