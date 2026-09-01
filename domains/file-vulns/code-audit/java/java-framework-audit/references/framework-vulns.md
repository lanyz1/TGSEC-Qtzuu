# Java 框架特定漏洞模式详解

本文档覆盖 Java 生态中 5 大高频框架/组件的漏洞模式，包含危险代码、安全代码对比及 CVE 参考。

---

## 1. Spring 全家桶

### 1.1 Mass Assignment（参数绑定漏洞）

**漏洞模式**: `@ModelAttribute` 自动将 HTTP 参数绑定到 Java 对象，若对象含 `role`/`isAdmin`/`price` 等敏感字段且无白名单限制，攻击者可覆写任意属性。

**危险代码**:
```java
@PostMapping("/register")
public String register(@ModelAttribute User user) {
    userService.save(user);  // User.role/isAdmin 被攻击者通过额外参数控制
    return "success";
}
```

**安全代码**:
```java
// 方案1: @InitBinder 白名单
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("username", "password", "email");
}
// 方案2: 使用 DTO 隔离，仅暴露安全字段
```

**EVID**: `@ModelAttribute` 绑定实体 → 实体含敏感字段 → 无 `setAllowedFields`/DTO 隔离。

### 1.2 SpEL 注入

用户可控数据进入 Spring Expression Language 解析 → 任意代码执行。5 种危险场景:

```java
// 场景1: @Value 引用外部化配置（需配置源可控）
@Value("#{${user.expression}}")  private String val;

// 场景2: @Cacheable key 拼接
@Cacheable(key = "#root.methodName + '_' + #userInput")
public Data getData(String userInput) { ... }

// 场景3: @PreAuthorize 动态表达式（从 DB 加载）
@PreAuthorize("#{permissionExpression}")  public void action() { ... }

// 场景4: ExpressionParser 直接解析外部输入（最常见）
Expression exp = new SpelExpressionParser().parseExpression(userInput);  // RCE
exp.getValue();

// 场景5: Spring Data @Query — ?#{principal.department} 需确认是否间接可控
```

**安全**: 使用 `SimpleEvaluationContext.forReadOnlyDataBinding()` 限制表达式能力，禁止方法调用和类型引用。

**EVID**: 搜索 `SpelExpressionParser`/`parseExpression` → 解析字符串含用户可控部分 → 未使用 `SimpleEvaluationContext`。

### 1.3 Actuator 利用链

| 端点 | 利用方式 | 前置条件 |
|------|---------|---------|
| `/actuator/env` + `/restart` | 修改 `spring.datasource.url` → 重启触发 JNDI | env 可写 + restart 存在 |
| `/actuator/jolokia` | JMX MBean `reloadByURL` 加载恶意配置 | Jolokia 依赖 |
| `/actuator/heapdump` | 堆转储提取密码/密钥/JWT Secret | heapdump 暴露 |
| `/actuator/gateway/routes` | POST 注册含 SpEL 的恶意路由 Filter | Gateway Actuator 暴露 |

**危险配置**: `management.endpoints.web.exposure.include: "*"` + `env`/`restart` enabled。
**安全配置**: `include: health,info`，敏感端点 disabled 或加认证。

**EVID**: `application.yml` 中 `exposure.include` 值 → 敏感端点是否需认证 → `SecurityFilterChain` 是否覆盖 `/actuator/**`。

### 1.4 Spring Cloud Gateway SpEL（CVE-2022-22947）

通过 Actuator `/gateway/routes` POST 注册恶意路由，Filter 的 `value` 字段嵌入 `#{T(Runtime).getRuntime().exec('cmd')}`。

**EVID**: 使用 Spring Cloud Gateway → Actuator gateway 端点暴露 → 允许未认证路由注册。

### 1.5 Spring 高频 CVE 简表

| CVE | 影响版本 | 类型 | 关键特征 |
|-----|---------|------|---------|
| CVE-2022-22947 | Cloud Gateway < 3.1.1 | SpEL RCE | Actuator 路由注入 |
| CVE-2022-22963 | Cloud Function < 3.1.7 | SpEL RCE | `routing-expression` Header |
| CVE-2022-22965 | Framework 5.3.0~5.3.17 | RCE | JDK9+ ClassLoader 参数绑定 |
| CVE-2018-1270 | Framework < 5.0.5 | SpEL RCE | Messaging STOMP |
| CVE-2017-8046 | Data REST < 2.6.9 | SpEL RCE | PATCH JSON Path |
| CVE-2020-5421 | Framework < 5.2.9 | RFD | 反射文件下载 |

---

## 2. Struts2

### 2.1 OGNL 注入原理

用户可控输入进入 OGNL 表达式求值。攻击路径: HTTP 参数/Header → `ParametersInterceptor` → OGNL `setValue()`/`getValue()` → 绕过 `SecurityMemberAccess` → `Runtime.exec()`。

**危险代码**:
```java
ValueStack stack = ActionContext.getContext().getValueStack();
Object result = stack.findValue(userControlledInput);  // OGNL 注入
```
```xml
<!-- struts.xml 危险配置 -->
<constant name="struts.ognl.allowStaticMethodAccess" value="true"/>
<constant name="struts.enable.DynamicMethodInvocation" value="true"/>
```

**安全配置**:
```xml
<constant name="struts.ognl.allowStaticMethodAccess" value="false"/>
<constant name="struts.enable.DynamicMethodInvocation" value="false"/>
<constant name="struts.mapper.alwaysSelectFullNamespace" value="true"/>
```

### 2.2 Content-Type 系列漏洞

- **S2-045（CVE-2017-5638）**: Jakarta Multipart 解析器对异常 Content-Type 的错误处理将值作为 OGNL 执行
- **S2-046（CVE-2017-5638）**: Content-Disposition 的 filename 字段触发同一解析漏洞

检测: `pom.xml` 中 struts2-core < 2.3.32 / < 2.5.10.1，且使用 Jakarta Multipart（默认）。

### 2.3 ActionMapping 参数前缀

- `method:` — 调用 Action 任意公开方法: `action?method:maliciousMethod`
- `redirect:` — 参数值作为 OGNL 求值后重定向
- `redirectAction:` — 同 `redirect:`，目标为 Action 名称

**EVID**: Struts2 版本 → `DynamicMethodInvocation` 配置 → `struts.xml` 通配符 `<action name="*">`。

### 2.4 Struts2 重点 CVE 表

| CVE/编号 | 影响版本 | 入口点 |
|----------|---------|--------|
| S2-001 (CVE-2007-4556) | 2.0.0~2.0.8 | 表单验证失败标签值二次 OGNL 解析 |
| S2-005 (CVE-2010-1870) | 2.0.0~2.1.8.1 | ParametersInterceptor 绕过 |
| S2-009 (CVE-2011-3923) | 2.0.0~2.3.1.1 | 参数名 OGNL 注入 |
| S2-012 (CVE-2013-1965) | 2.0.0~2.3.14.2 | redirect 结果类型 OGNL |
| S2-013 (CVE-2013-1966) | 2.0.0~2.3.14.1 | URL 标签 includeParams |
| S2-015 (CVE-2013-2134) | 2.0.0~2.3.14.2 | 通配符 Action 名称 OGNL |
| S2-016 (CVE-2013-2251) | 2.0.0~2.3.15 | redirect:/redirectAction: 前缀 |
| S2-032 (CVE-2016-3081) | 2.3.20~2.3.28 | DynamicMethodInvocation method: |
| S2-045 (CVE-2017-5638) | 2.3.5~2.3.31 | Content-Type Jakarta Multipart |
| S2-046 (CVE-2017-5638) | 2.3.5~2.3.31 | Content-Disposition filename |
| S2-048 (CVE-2017-9791) | 2.3.x Struts1 Plugin | ActionMessage 格式化 |
| S2-052 (CVE-2017-9805) | 2.1.2~2.3.33 | XStream REST 反序列化 |
| S2-053 (CVE-2017-12611) | 2.0.0~2.3.33 | Freemarker 标签 OGNL |
| S2-057 (CVE-2018-11776) | 2.3~2.3.34, 2.5~2.5.16 | namespace OGNL 注入 |
| S2-061 (CVE-2020-17530) | 2.0.0~2.5.25 | 标签属性强制二次 OGNL |
| S2-062 (CVE-2021-31805) | 2.0.0~2.5.29 | S2-061 补丁绕过 |

---

## 3. Shiro

### 3.1 RememberMe 反序列化

**链路**: Cookie → Base64 解码 → AES-CBC 解密 → `ObjectInputStream.readObject()`。

**危险代码**:
```java
// Shiro <= 1.2.4 硬编码密钥（CVE-2016-4437）
private static final byte[] DEFAULT_CIPHER_KEY_BYTES =
    Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");

// 自定义但常见的弱密钥
manager.setCipherKey(Base64.decode("4AvVhmFLUs0KTA3Kprsdag=="));
```

**安全代码**:
```java
byte[] key = new byte[16];
new SecureRandom().nextBytes(key);
manager.setCipherKey(key);
// 或升级 Shiro 1.4.2+ 使用 AES-GCM
```

**检测**: 搜索 `setCipherKey`/`Base64.decode` 附近硬编码字符串，比对已知 Shiro 密钥字典（100+ 常见密钥），检查 `pom.xml` 中 shiro 版本。

**EVID**: `setCipherKey` 调用 → 提取密钥值 → 是否为已知密钥 → classpath 是否存在可用 Gadget（commons-collections/commons-beanutils/c3p0）。

### 3.2 URI 绕过

Shiro URL 路径匹配与后端框架（Spring/Servlet）解析规则不一致 → 认证/授权绕过。

| 手法 | Payload 示例 | 原理 |
|------|-------------|------|
| 分号截断 | `/admin/page;.js` | Shiro 截断分号，后缀绕 Filter |
| 路径穿越 | `/toLogin;/../admin/page` | Shiro 匹配 `/toLogin`(anon)，Spring 路由 `/admin/page` |
| 双重编码 | `/admin/%25%32%65%25%32%65/page` | Shiro 未二次解码 |
| 尾部斜杠 | `/admin/` vs `/admin` | Filter 配置不匹配 |
| 大小写 | `/Admin/Page` | Shiro 默认大小写敏感 |

**EVID**: 提取 `ShiroFilterFactoryBean` URL-Filter 映射 → 对比 Spring 实际路由 → 构造绕过路径。

### 3.3 Shiro CVE 简表

| CVE | 影响版本 | 类型 | 关键特征 |
|-----|---------|------|---------|
| CVE-2016-4437 | <= 1.2.4 | 反序列化 RCE | 硬编码 AES 密钥 |
| CVE-2019-12422 | < 1.4.2 | Padding Oracle | CBC Padding Oracle → 密钥恢复 |
| CVE-2020-1957 | < 1.5.2 | 认证绕过 | 路径穿越 |
| CVE-2020-11989 | < 1.5.3 | 认证绕过 | 双重 URL 编码 |
| CVE-2020-13933 | < 1.6.0 | 认证绕过 | 分号编码截断 |
| CVE-2021-41303 | < 1.8.0 | 认证绕过 | 路径标准化不一致 |

---

## 4. FastJSON / Jackson / Gson

### 4.1 FastJSON 反序列化

`@type` 字段指定反序列化目标类，autotype 未关闭时可触发 Gadget Chain。

**危险代码**:
```java
JSONObject obj = JSON.parseObject(userInput);  // 默认支持 @type
Object obj = JSON.parseObject(userInput, Feature.SupportNonPublicField);  // 扩大攻击面
```

**安全代码**:
```java
ParserConfig.getGlobalInstance().setSafeMode(true);  // 1.2.83+ 彻底关闭 autotype
ParserConfig.getGlobalInstance().addAccept("com.mycompany.model.");  // 1.2.68+ 白名单
// 或迁移到 FastJSON2（默认关闭 autotype）
```

**autotype 绕过历史**:

| 版本 | 事件 |
|------|------|
| <= 1.2.24 | autotype 默认开启，无限制 |
| 1.2.25~1.2.41 | 默认关闭 + 黑名单，`L`/`;` 前后缀绕过 |
| 1.2.42 | 黑名单 hash 化，双写 `LL` 绕过 |
| 1.2.43~1.2.46 | `[` 符号 / MyBatis JndiDataSourceFactory 绕过 |
| 1.2.47 | `java.lang.Class` 缓存加载任意类 |
| 1.2.48~1.2.67 | 新 Gadget 不断加入黑名单 |
| 1.2.68 | `AutoCloseable`/`Throwable` expectClass 绕过 |
| 1.2.69~1.2.80 | 持续发现新绕过链 |
| 1.2.83+ | safeMode 彻底关闭 autotype |

**EVID**: `pom.xml` FastJSON 版本 → `JSON.parseObject`/`JSON.parse` 调用 → 是否解析不受信任输入 → `safeMode`/`autoTypeSupport` 配置。

### 4.2 Jackson 多态反序列化

**危险代码**:
```java
// 全局开启（等同全局 RCE 入口）
mapper.enableDefaultTyping();  // 已废弃
mapper.activateDefaultTyping(validator, DefaultTyping.NON_FINAL);

// 字段级
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)  private Object payload;    // 危险
@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)  private Object data;  // 同样危险
```

**安全代码**:
```java
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.mycompany.model.").build(),
    DefaultTyping.NON_FINAL);
// 字段级使用 @JsonTypeInfo(use=Id.NAME) + @JsonSubTypes 白名单
```

**EVID**: 搜索 `enableDefaultTyping`/`activateDefaultTyping` → `PolymorphicTypeValidator` 白名单 → `@JsonTypeInfo(use=Id.CLASS)` → 字段是否接受外部输入。

### 4.3 Gson 安全注意事项

Gson 不支持多态反序列化，相对安全。风险在自定义 `TypeAdapter`/`JsonDeserializer` 中若使用 `Class.forName(userInput)` 加载类。

**EVID**: 搜索自定义 `TypeAdapter`/`JsonDeserializer` → 是否有 `Class.forName` 加载用户指定类名。

### 4.4 常见反序列化 Gadget

| Gadget 类 | 来源 | 利用方式 |
|-----------|------|---------|
| `JdbcRowSetImpl` | JDK | JNDI（`setDataSourceName` → `lookup`） |
| `TemplatesImpl` | JDK | 恶意字节码（`_bytecodes`） |
| `ClassLoader`(BCEL) | JDK | BCEL 字节码执行 |
| `JndiDataSourceFactory` | MyBatis | JNDI 注入 |
| `PropertyPathFactoryBean` | Spring | 属性路径注入 |
| `JNDIConnectionSource` | Logback | JNDI 注入 |
| `FileUtils` | commons-io | 任意文件写入 |

---

## 5. MyBatis

### 5.1 `${}` 直接拼接 vs `#{}` 参数绑定

- `#{}` — PreparedStatement `?` 占位符，安全
- `${}` — 字符串直接拼接，等同 SQL 注入

**危险代码**:
```xml
<select id="findUser" resultType="User">
    SELECT * FROM users WHERE username = '${username}'
</select>
<select id="queryTable" resultType="Map">
    SELECT * FROM ${tableName} WHERE id = #{id}
</select>
```

**安全代码**:
```xml
<select id="findUser" resultType="User">
    SELECT * FROM users WHERE username = #{username}
</select>
```

### 5.2 ORDER BY / LIKE / IN 场景

**ORDER BY**（`#{}` 加引号致语法错误，`${}` 须配合白名单）:
```xml
<!-- 危险 -->
<select id="listUsers" resultType="User">
    SELECT * FROM users ORDER BY ${sortColumn} ${sortOrder}
</select>
<!-- 安全: Java 层白名单 Arrays.asList("id","name","create_time").contains(col) -->
```

**LIKE**:
```xml
<!-- 危险 -->  LIKE '%${keyword}%'
<!-- 安全 -->  LIKE CONCAT('%', #{keyword}, '%')
<!-- Oracle -->  LIKE '%' || #{keyword} || '%'
```

**IN**:
```xml
<!-- 危险 -->  IN (${ids})
<!-- 安全: foreach 标签 -->
<foreach collection="ids" item="id" open="(" separator="," close=")">#{id}</foreach>
```

### 5.3 动态 SQL 中的 `${}`

```xml
<!-- 危险: <if> + ${} -->
<if test="name != null">AND name = '${name}'</if>
<if test="sort != null">ORDER BY ${sort}</if>

<!-- 危险: <foreach> + ${} -->
<foreach collection="sqls" item="sql" separator=";">${sql}</foreach>
```

### 5.4 注解模式

```java
// 危险
@Select("SELECT * FROM ${tableName} WHERE id = #{id}")
User findById(@Param("tableName") String tableName, @Param("id") Long id);

@Select("<script>SELECT * FROM users <if test='sort != null'>ORDER BY ${sort}</if></script>")
List<User> listUsers(@Param("sort") String sort);

// 安全
@Select("SELECT * FROM users WHERE id = #{id}")
User findById(@Param("id") Long id);
```

### 5.5 Mapper 审计清单

| 检查项 | 搜索模式 | 风险 |
|--------|---------|------|
| Mapper XML `${}` | `*Mapper.xml` 中 `${` | 高 |
| 注解 `${}` | `@Select`/`@Update` 等注解内 `${` | 高 |
| ORDER BY 无白名单 | `ORDER BY ${` 且无校验 | 高 |
| LIKE 拼接 | `LIKE '%${` | 高 |
| IN 拼接 | `IN (${` | 高 |
| 动态表名/列名 | `FROM ${` / `SELECT ${` | 高 |
| foreach 中 `${}` | `<foreach>` 体内 `${` | 严重 |
| Provider 动态 SQL | `@SelectProvider` 引用类的字符串拼接 | 高 |

**EVID**: Mapper XML/注解中 `${}` → 反向追踪参数来源（Controller → Service → Mapper） → 确认是否用户输入 → 检查白名单/枚举校验 → 记录完整 Source→Sink 数据流。
