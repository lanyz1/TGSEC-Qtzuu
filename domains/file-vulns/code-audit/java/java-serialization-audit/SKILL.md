---
name: java-serialization-audit
description: |
  Java 源码序列化类漏洞审计。当在 Java 白盒审计中需要检测序列化/反序列化相关漏洞时触发。
  覆盖 3 类风险: Java 原生反序列化(ObjectInputStream/Gadget Chain/ysoserial)、
  XXE(DocumentBuilderFactory/SAXParser/XMLInputFactory/TransformerFactory/SchemaFactory 五种解析器)、
  模板注入 SSTI(Velocity/FreeMarker/Thymeleaf 模板引擎代码执行)。
  Java 反序列化是 Java 生态最具特色的高危漏洞类型，Gadget Chain 分析是核心难点。
metadata:
  tags: deserialization, xxe, ssti, objectinputstream, gadget chain, ysoserial, xml, velocity, freemarker, thymeleaf, 反序列化, 模板注入, java source audit
  category: code-audit
---

# Java 序列化类漏洞源码审计
本 skill 聚焦源码层面判断"反序列化/XXE/SSTI 是否成立"，核心工作是：白盒确认反序列化入口点、追踪数据来源、评估 classpath 中可用 Gadget 链、验证 XML 解析器安全配置、检查模板引擎渲染上下文。构造 exploit payload、远程利用链发送等运行时黑盒技术属于对应 exploit skill 范畴。

## 深入参考

- 3 类漏洞的危险模式 / 安全模式代码对比 / Gadget 依赖表 / EVID 证据示例 → [references/serialization-patterns.md](references/serialization-patterns.md)

---

## 3 类漏洞速查表

| 类型 | 典型 Sink | 利用条件 | 严重度 |
|------|-----------|----------|--------|
| Java 反序列化 | `ObjectInputStream.readObject()`, `XMLDecoder.readObject()` | 用户可控序列化流 + classpath 存在可用 Gadget Chain | Critical |
| XXE | `DocumentBuilderFactory`, `SAXParser`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` | 外部实体/DTD 未禁用 + 用户可控 XML 输入 | High-Critical |
| SSTI | `Velocity.evaluate`, `FreeMarker Template`, Thymeleaf 预处理表达式 | 用户输入直接进入模板编译/渲染上下文 | Critical |

## Java 反序列化审计要点

- **入口点识别**: `ObjectInputStream.readObject()`、`ObjectInputStream.readUnshared()`、`XMLDecoder.readObject()`、自定义 `readObject`/`readResolve`/`readExternal` 实现中的额外攻击面
- **数据来源追踪**: HTTP 请求 body（魔术字节 `AC ED 00 05` 或 Base64 编码 `rO0AB`）、RMI/JMX 远程调用、JMS 消息队列、Redis/Memcached 缓存反序列化、文件读取、ViewState、Cookie/Session 序列化存储
- **Gadget 可用性评估**: 检查 `pom.xml`/`build.gradle` 及 classpath 中是否存在已知 Gadget 链的依赖库（commons-collections 3.x/4.x、commons-beanutils、spring-core、Groovy、hibernate-core 等），版本是否在受影响范围内
- **防御机制验证**: JEP 290 `ObjectInputFilter` 是否配置、白名单 vs 黑名单策略、`SerialKiller`/`NotSoSerial` 等第三方防护库是否启用、`resolveClass` 是否被重写为白名单校验
- **readResolve/readObject 自定义逻辑**: 即使不存在通用 Gadget，自定义反序列化方法中的文件操作、网络请求、动态类加载等行为也构成攻击面

## XXE 审计要点

- **5 种 XML 解析器安全配置**:
  - `DocumentBuilderFactory`: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  - `SAXParserFactory`: 同上 + `setFeature("http://xml.org/sax/features/external-general-entities", false)` + `setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
  - `XMLInputFactory` (StAX): `setProperty(XMLInputFactory.SUPPORT_DTD, false)` + `setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`
  - `TransformerFactory`: `setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")` + `setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")`
  - `SchemaFactory`: `setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")` + `setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "")`
- **数据流分析**: XML 输入来源（HTTP 请求体、文件上传、SOAP 消息、SVG/Office 文件） → 进入解析器 → 解析结果回显（直接 XXE）或无回显（盲注/带外 OOB）
- **Java 特有协议**: `jar:` 协议可触发远程文件下载与解压、`netdoc:` 协议（旧版 JDK）等价于 `file://`

## 模板注入 SSTI 审计要点

- **Velocity**: `Velocity.evaluate(context, writer, tag, userTemplate)` — 若 `userTemplate` 参数用户可控则直接 RCE
- **FreeMarker**: `new Template("t", new StringReader(userInput), cfg).process(dataModel, writer)` — 用户输入作为模板源编译即危险
- **Thymeleaf**: 控制器返回值拼接导致 SSTI，`return "user/" + input` 时 input 可注入 `__${expr}__` 预处理表达式触发 SpEL → RCE
- **安全模式**: 模板名/路径白名单、FreeMarker 设置 `TemplateClassResolver.ALLOWS_NOTHING_RESOLVER` 禁用 `?new()` 内建函数、Velocity 使用 `SecureUberspector`、Thymeleaf 限制视图名不可拼接用户输入

## 检测清单

- [ ] 所有 `ObjectInputStream.readObject()`/`XMLDecoder.readObject()` 调用点已逐一审查
- [ ] 反序列化入口的数据来源（HTTP/RMI/JMS/缓存/文件）已追踪确认
- [ ] classpath 依赖已检查是否包含已知 Gadget Chain 库及其受影响版本
- [ ] JEP 290 ObjectInputFilter / SerialKiller / 白名单 resolveClass 等防御机制已验证
- [ ] 自定义 readObject/readResolve 方法中的额外攻击面已排查
- [ ] 5 种 XML 解析器的安全 Feature 配置已逐一确认
- [ ] XML 输入来源（请求体/上传/SOAP/SVG）及回显方式已分析
- [ ] Velocity/FreeMarker/Thymeleaf 模板渲染入口的用户输入可控性已检查
- [ ] 模板引擎安全模式（沙箱/白名单/禁用危险函数）已验证
- [ ] 严重度评分使用了统一公式，与 pipeline 一致
