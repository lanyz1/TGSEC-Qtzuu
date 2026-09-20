# Payload 生成工具方案

## 0. 一句话定位

一个**不接 AI、不执行、不验证、不自动提交**的确定性 Payload 生成工具。
它只做一件事：

> 根据用户本次启动后做出的选择，从内置规则库中过滤可用模板与绕过，拼接、编码、包装后，输出用户指定层级的可复制 Payload。

目标用户：Web 安全渗透测试工程师、CTF 解题者。
工具只负责生成，使用后果由用户负责。

------

## 1. 已确定原则

- 不允许接入 AI，包括本地模型和在线 API。
- 全自动化程序实现，规则、模板、版本、绕过均由编写时提供。
- 不执行、不验证、不自动提交、不扫描目标。
- 不保存历史，不推断注入上下文，只关心用户本次启动后的选择。
- 用户选择什么，工具就按什么生成；缺参数用用户输入，没输入用默认值或占位符。
- 正确性不由工具验证，用户自行验证。
- 工具只保证：语法完全正确，并符合用户选择的要求。
- 绕过由用户手动选择；工具只根据当前选择，显示“当前可生效”的绕过。
- 允许绕过组合或嵌套，但必须在规则库写明的可实现范围内。
- 版本数据由编写时提供，可存本地 JSON/YAML/SQLite；用户选择版本号后，工具据此过滤。
- 输出层、提交方式、最终内容类型均尽量越全越好，由用户选择。
- curl 属于系统命令输出的一部分。
- 有需要就允许离线 parser，用于语法校验，不接 AI。
- 存储和核心引擎用最快实现，初步优先内存加载 + JSON/YAML。
- GUI / WebUI / CLI 初步不设计，核心引擎先与 UI 解耦，后续再包。

------

## 2. 范围与非目标

### 做什么

- 生成 Payload。
- 按漏洞类型、组件、版本、最终内容类型、绕过、提交方式、输出层进行过滤。
- 支持组合、嵌套、编码、转义、包装。
- 输出原始 Payload、编码后 Payload、完整 URL、完整 HTTP 请求、curl 等。
- 支持用户导入自定义规则，后续可扩展。

### 不做什么

- 不接 AI。
- 不自动扫描。
- 不自动提交。
- 不执行系统命令。
- 不验证漏洞是否存在。
- 不保证权限足够、函数存在、WAF 可绕过、版本指纹准确。
- 不保证实际可利用，只保证语法与用户选择一致。

------

## 3. 核心概念

需要区分清楚：

| 概念         | 含义                                                         |
| ------------ | ------------------------------------------------------------ |
| 漏洞类型     | SQLi、SSTI、RCE、Python 安全、Node.js 安全、Java 安全、PHP 安全等 |
| 最终内容类型 | 系统命令、SQL 表达式、模板表达式、Python 语句、Node 语句、Java 语句、PHP 语句、文件路径、原始字符串等 |
| 提交方式     | Payload 放在 HTTP 请求的哪个位置，如 URL 参数、JSON body、Header、Cookie 等 |
| 输出层       | 最后复制走的东西长什么样，如原始 Payload、编码后、完整 URL、完整请求、curl |
| 绕过         | 手动选择的变换，如编码、语法变换、关键字替换、注释、大小写等 |
| 版本         | 目标组件版本，用于过滤模板和绕过                             |
| 占位符       | 用户未提供的变量，如 `{{host}}`、`{{path}}`、`{{cmd}}`       |

注意：
“最终内容类型 = 系统命令”和“输出格式 = curl”不是一回事。
用户选系统命令 + 输出 curl，生成的是 curl 命令；选系统命令 + 输出原始，生成的是纯命令。

------

## 4. 用户选择状态模型

用户本次启动后的所有选择构成一个 `GenerationState`，至少包括：

- 漏洞类型、子类型
- 最终内容类型
- 目标语言、框架、组件、版本
- 目标 OS、Shell、运行时
- 权限、回显方式
- 过滤条件、WAF、允许字符、长度限制
- 已选绕过、绕过顺序、嵌套深度
- 提交方式、HTTP 方法、Content-Type
- 输出层
- 占位符变量
- 默认值覆盖

状态变化后，工具重新计算：

- 可用模板
- 可用绕过
- 冲突项
- 失效项
- 最终输出

------

## 5. 规则库与数据模型

### 5.1 Payload 模板字段

- ID、名称、描述
- 适用漏洞类型
- 适用最终内容类型
- 适用组件、框架、语言
- 适用版本范围
- 适用 OS、Shell、运行时
- 前置条件：权限、函数、配置、回显方式
- 变量占位符
- 生成片段
- 依赖的编码层
- 冲突项、互斥项
- 顺序要求
- 是否可嵌套
- 来源、许可证
- 标签：CVE、ATT&CK、组件、语言、OS、权限、回显、WAF
- 测试状态：理论 / 黄金样本 / 靶场验证
- 风险等级、置信度
- 更新日期、作者

### 5.2 绕过字段

- ID、名称、类型：传输编码、语法、关键字、语义、WAF 特定
- 前置条件
- 影响层：语义层、语法层、传输层、输出层
- 效果
- 冲突项、依赖项
- 顺序要求
- 是否可嵌套
- 是否幂等
- 字符集影响
- 适用漏洞、组件、版本
- 是否可组合

### 5.3 版本数据字段

- 组件名、别名
- 版本范围语法
- 发行版、backport、补丁
- 多组件依赖
- 未知版本处理
- 来源、许可证

------

## 6. 漏洞类型与最终内容类型支持矩阵

完整矩阵由编写时内置，越全越好。用户选漏洞类型后，工具只显示该类型支持的最终内容类型。

简化示例：

| 漏洞类型                   | 系统命令 | SQL 表达式 | 模板表达式 | Python 语句 | Node 语句 | Java 语句 | PHP 语句 | 文件路径 | 原始字符串 | HTTP 请求 | curl |
| -------------------------- | -------- | ---------- | ---------- | ----------- | --------- | --------- | -------- | -------- | ---------- | --------- | ---- |
| SQL 注入                   | 部分     | 支持       | 不支持     | 不支持      | 不支持    | 不支持    | 不支持   | 部分     | 支持       | 支持      | 支持 |
| SSTI                       | 部分     | 不支持     | 支持       | 部分        | 部分      | 部分      | 部分     | 部分     | 支持       | 支持      | 支持 |
| RCE / 命令注入             | 支持     | 不支持     | 不支持     | 部分        | 部分      | 部分      | 部分     | 部分     | 支持       | 支持      | 支持 |
| 代码注入                   | 部分     | 不支持     | 部分       | 部分        | 部分      | 部分      | 部分     | 部分     | 支持       | 支持      | 支持 |
| 反序列化                   | 部分     | 不支持     | 不支持     | 部分        | 部分      | 部分      | 部分     | 部分     | 支持       | 支持      | 支持 |
| XXE                        | 部分     | 不支持     | 不支持     | 不支持      | 不支持    | 不支持    | 不支持   | 支持     | 支持       | 支持      | 支持 |
| SSRF                       | 部分     | 不支持     | 不支持     | 不支持      | 不支持    | 不支持    | 不支持   | 支持     | 支持       | 支持      | 支持 |
| 文件包含                   | 部分     | 不支持     | 不支持     | 部分        | 部分      | 部分      | 部分     | 支持     | 支持       | 支持      | 支持 |
| 文件上传                   | 部分     | 不支持     | 不支持     | 部分        | 部分      | 部分      | 部分     | 支持     | 支持       | 支持      | 支持 |
| 路径穿越                   | 不支持   | 不支持     | 不支持     | 不支持      | 不支持    | 不支持    | 不支持   | 支持     | 支持       | 支持      | 支持 |
| NoSQL 注入                 | 部分     | 部分       | 不支持     | 不支持      | 部分      | 不支持    | 不支持   | 不支持   | 支持       | 支持      | 支持 |
| ORM 注入                   | 部分     | 部分       | 不支持     | 部分        | 部分      | 部分      | 部分     | 不支持   | 支持       | 支持      | 支持 |
| JNDI / Log4j / Fastjson 等 | 部分     | 不支持     | 不支持     | 不支持      | 不支持    | 支持      | 不支持   | 不支持   | 支持       | 支持      | 支持 |
| 框架漏洞                   | 部分     | 部分       | 部分       | 部分        | 部分      | 部分      | 部分     | 部分     | 支持       | 支持      | 支持 |

具体到组件和版本，再由规则库细化。

------

## 7. 最终内容类型完整枚举

### 7.1 系统命令类

- Linux Shell：bash、sh、zsh、fish、dash、ksh、csh、tcsh
- Windows：cmd、批处理、PowerShell、WMI、VBScript、JScript
- 常用工具：curl、wget、nc、ncat、socat、telnet、ssh、scp、rsync、ftp、tftp、python、perl、ruby、php、node、java、go、gcc
- 反弹 Shell：Bash、Python、Perl、Ruby、PHP、Node、Java、PowerShell、nc、socat
- 下载并执行：curl|sh、wget|sh、PowerShell IEX、certutil、bitsadmin
- 文件操作、系统操作、计划任务、服务、注册表、用户、组、环境变量、进程、网络
- 命令拼接与分隔：`;`、`|`、`||`、`&`、`&&`、换行、`$()`、反引号
- 编码命令：Base64、Hex、URL、Unicode、HTML 实体、ROT13、Gzip、Zlib

### 7.2 SQL 表达式类

- 基本语句、联合查询、条件、注释、闭合
- 报错注入、布尔盲注、时间盲注、堆叠注入、带外
- 系统命令：xp_cmdshell、sp_OACreate、COPY PROGRAM、UDF 等
- MySQL、PostgreSQL、Oracle、MSSQL、SQLite、NoSQL、ORM
- LDAP、XPath、XQuery、GraphQL、OData

### 7.3 模板 / SSTI 表达式类

- Jinja2、Twig、Freemarker、Velocity、Smarty、Mako、Django、Tornado
- ERB、EJS、Pug、Handlebars、Mustache、Nunjucks、Liquid、Jade、DoT
- Thymeleaf、SpEL、OGNL、Groovy、Razor、Blade、Latte
- AngularJS、Vue、React、Svelte、Next.js、Nuxt、Astro、Remix
- Gradio、Streamlit、Dash、Shiny、Jupyter、Voila、Panel、Bokeh
- 表达式边界：`{{ }}`、`{% %}`、`${ }`、`#{ }`、`<%= %>`、`<% %>`、`[% %]`、`@{}`、`*{}`、`~{}`

### 7.4 Python 安全语句类

- eval、exec、compile、**import**、getattr、setattr、globals、locals、**builtins**
- pickle、cPickle、dill、joblib、marshal、shelve、jsonpickle
- yaml.load、yaml.unsafe_load、ruamel.yaml
- os.system、os.popen、subprocess、pty、commands、socket、requests、urllib
- **class**、**mro**、**subclasses**、**init**、**globals**、**code**、**reduce**、**reduce_ex**
- Flask、Django、Tornado、FastAPI、aiohttp、Jinja2、Mako、Werkzeug
- JWT、PyJWT、itsdangerous、cryptography、paramiko、ftplib、smtplib、telnetlib
- XML-RPC、SOAP、gRPC、protobuf、pickle 反序列化、yaml 反序列化

### 7.5 Node.js 安全语句类

- eval、Function、setTimeout、setInterval、vm、vm2
- child_process：exec、execSync、spawn、spawnSync、fork、execFile、execFileSync
- require、import、process、global、globalThis、module、exports
- **proto**、prototype、constructor、原型链污染
- Object.assign、lodash merge、defaultsDeep、set、setWith
- Express、Koa、Hapi、NestJS、Next.js、Nuxt、Electron
- node-serialize、serialize-to-js、funcster、cryo、js-yaml、yaml、json5
- jsonwebtoken、passport、oauth、saml、graphql、apollo、express-graphql
- mongoose、sequelize、knex、typeorm、prisma、sqlite3、mysql、pg、redis、mongodb

### 7.6 Java 安全语句类

- Runtime.exec、ProcessBuilder、ScriptEngineManager、GroovyShell
- SpEL、OGNL、MVEL、JEXL、EL、JSTL、JSP、Servlet、Filter、Listener
- JDBC、JNDI、LDAP、RMI、JMS、JMX、反序列化
- ObjectInputStream、readObject、readResolve、readExternal、writeObject
- XMLDecoder、XStream、Jackson、Fastjson、Gson、SnakeYAML
- Log4j、Log4j2、JNDI 注入、Spring、Spring Boot、Spring Cloud、Spring Security
- Struts2、Struts1、WebWork、Hibernate、MyBatis、iBatis、Shiro
- CommonsCollections、CommonsBeanutils、C3P0、Druid、HikariCP
- Tomcat、Jetty、Undertow、WebLogic、WebSphere、JBoss、WildFly、GlassFish

### 7.7 PHP 安全语句类

- eval、assert、system、exec、shell_exec、passthru、popen、proc_open、pcntl_exec、反引号
- include、require、include_once、require_once
- file_get_contents、file_put_contents、fopen、fwrite、readfile
- curl_exec、fsockopen、stream_socket_client、socket_create
- unserialize、serialize、json_decode、json_encode、yaml_parse
- simplexml_load_string、DOMDocument、XMLReader、XMLWriter、SoapClient
- PDO、mysqli、mysql_query、pg_query、sqlite_query、oci_parse、mssql_query
- LDAP、ldap_search、ldap_bind、mail、mb_send_mail、imap_open、ftp_connect、ssh2_connect
- phar、phar://、zip://、expect://、data://、php://input、php://filter、php://fd、php://memory、php://temp、glob://
- create_function、call_user_func、call_user_func_array、array_map、array_walk、usort、preg_replace_callback
- 魔术方法：__construct、__destruct、__wakeup、__sleep、__toString、__invoke、__call、__get、__set、__isset、__unset、__clone、__debugInfo、__set_state、__serialize、__unserialize

### 7.8 文件 / 路径类

- 绝对路径、相对路径、Windows 路径、Linux 路径、UNC 路径
- 路径穿越：`../`、`..\\`、`%2e%2e%2f`、`....//`、`..;/`
- 文件读取、文件写入、文件包含、LFI、RFI、phar、zip、data、php://filter

### 7.9 原始字符串 / 编码类

- 原始 Payload
- URL 编码、双重 URL 编码
- JSON 转义、XML 实体、HTML 实体
- Base64、Base32、Hex、Unicode、UTF-7、UTF-16
- Gzip、Zlib、ROT13、凯撒、异或
- Shell 转义、SQL 转义、模板转义

### 7.10 输出包装类

- 只给核心 Payload
- 给编码后的 Payload
- 给完整 URL
- 给完整 HTTP 请求
- 给 curl 命令
- 给 PowerShell 请求
- 给 Python requests 代码片段
- 给 Node fetch/axios 代码片段
- 给 Java HttpClient 代码片段
- 给 PHP curl 代码片段
- 给 Burp 可复制请求
- 给 Postman 可导入片段

### 7.11 其他语言 / 环境

- Ruby、Perl、Go、Rust、C/C++、.NET、PowerShell、Bash、cmd
- 数据库：MySQL、MSSQL、PostgreSQL、Oracle、SQLite、MongoDB、Redis
- 中间件：Tomcat、Nginx、Apache、IIS、WebLogic、JBoss、Jenkins、GitLab

------

## 8. 提交方式完整枚举

### 8.1 URL 相关

- scheme、host、port、path、query、fragment、userinfo、authority
- 参数名、参数值、重复参数、数组参数、对象参数
- 路径段、矩阵参数 `;param=value`
- 编码：URL 编码、双重 URL 编码、Unicode、UTF-7

### 8.2 HTTP 方法

- GET、POST、PUT、PATCH、DELETE、HEAD、OPTIONS、TRACE、CONNECT
- 自定义方法、方法覆盖：X-HTTP-Method-Override、X-Method-Override

### 8.3 Header

- 标准头：Host、Origin、Referer、User-Agent、Accept、Accept-Language、Accept-Encoding、Content-Type、Content-Length、Cookie、Authorization
- 代理头：X-Forwarded-For、X-Real-IP、X-Client-IP、X-Remote-IP、X-Remote-Addr、X-Originating-IP、X-Host、X-Forwarded-Host、X-Forwarded-Proto、X-Forwarded-Port、X-Forwarded-Server、X-Forwarded-Prefix
- 覆盖头：X-Original-URL、X-Rewrite-URL、X-HTTP-Method-Override、X-Method-Override、X-Override
- 自定义头、任意 Header 名、任意 Header 值

### 8.4 Cookie

- 单个 Cookie、多个 Cookie、Cookie 名、Cookie 值
- Cookie 属性、Set-Cookie、Session、JWT、Bearer、Basic、Digest、OAuth、SAML、OIDC

### 8.5 Body 类型

- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `application/json`
- `application/xml` / `text/xml`
- `text/plain`、`text/html`、`application/graphql`
- `application/x-httpd-php`、`application/x-java-serialized-object`、`application/x-php-serialized`、`application/x-python-pickle`、`application/x-node-serialized`
- `application/x-protobuf`、`application/msgpack`、`application/cbor`、`application/yaml`
- raw body、二进制、分块传输、chunked、trailer

### 8.6 文件上传

- 文件名、文件内容、Content-Type、Content-Disposition、boundary
- 路径、扩展名、MIME、魔术字节、多个文件、嵌套 multipart

### 8.7 WebSocket / SSE / gRPC / HTTP2 / HTTP3

- WebSocket：消息、帧、握手、子协议、扩展
- SSE：事件、数据、id、retry
- gRPC：消息、元数据、方法、流
- HTTP/2：帧、头、数据、优先级、服务器推送
- HTTP/3：帧、QUIC

### 8.8 其他协议

- DNS、SMTP、IMAP、POP3、FTP、SSH、Telnet、TCP、UDP、ICMP
- MQTT、CoAP、AMQP、STOMP、XMPP、SIP、WebRTC

### 8.9 路径 / 矩阵参数

- `/user/{id}`、`;param=value`、`.`、`..`、`%2e`、编码、路径穿越

### 8.10 重定向 / 回调参数

- url、next、redirect、return、callback、continue、dest、destination、redir、redirect_uri、return_url、success_url、failure_url、cancel_url、webhook、callback_url

### 8.11 模板 / 命令分隔符

- 模板：`{{ }}`、`{% %}`、`${ }`、`#{ }`、`<%= %>`、`<% %>`、`[% %]`、`@{}`、`*{}`、`~{}`
- 命令：`;`、`|`、`||`、`&`、`&&`、反引号、`$()`、`%0a`、`%0d`、换行、空格、Tab、`$IFS`、花括号、通配符、编码

------

## 9. 绕过系统

- 绕过由用户手动选择。
- 工具根据当前状态，只显示“当前可生效”的绕过。
- 允许组合、嵌套，但必须在规则库写明的可实现范围内。
- 每个绕过要有前置条件、冲突项、依赖项、顺序要求、是否幂等、影响层。
- 用户选择后重新计算可用绕过。
- 已选但失效的绕过要提示或移除。
- 组合顺序、嵌套深度、是否允许循环，由规则和用户选择共同决定，具体策略待定。

------

## 10. 编码 / 转义管线

建议分层，顺序固定或用户可调：

1. 目标语义编码：命令 base64、SQL 字符串转义
2. 语法适配：闭合引号、补括号、加注释
3. 绕过变换：大小写、注释、空白替代、关键字拆分
4. 传输编码：URL、JSON、XML、HTML
5. 输出包装：参数名、body、Header、Cookie、curl

每层定义：

- 输入输出类型
- 字符集
- 是否幂等
- 是否可跳过
- 与其他层的顺序约束
- 是否会产生双重编码

必须区分：

- 利用层编码
- 传输层编码

------

## 11. 输出层

输出层由用户选择，可多选。缺参数用默认值或占位符。

可选：

- 原始 Payload
- 利用层编码后 Payload
- 传输层编码后 Payload
- 完整 URL
- 完整 HTTP 请求
- curl 命令
- PowerShell 请求
- Python requests 片段
- Node fetch/axios 片段
- Java HttpClient 片段
- PHP curl 片段
- Burp 可复制请求
- Postman 可导入片段

curl 生成时注意 Shell 转义：bash、zsh、cmd、PowerShell 分别处理单引号、双引号、`$`、反引号、换行、空格。

------

## 12. 变量与默认值

- 占位符语法：`{{host}}`、`{{path}}`、`{{param}}`、`{{cmd}}`、`{{payload}}`
- 用户提供就用用户的。
- 没提供就用默认值或占位符。
- 默认值建议：host=[example.com](https://example.com/)、path=/、method=GET、param=id、cmd=whoami、shell=bash、os=linux。
- 变量作用域：全局、模板、阶段。
- 变量能否引用其他变量、编码后是否可复用，待定。

------

## 13. 语法正确性定义

工具只保证：

- 目标语言语法正确：SQL、模板、Shell、Python、Node、Java、PHP。
- 闭合正确：引号、括号、注释、标签。
- 转义正确：URL、JSON、XML、HTML、Shell。
- 传输格式合法：HTTP、form、JSON、XML。
- 符合用户勾选：版本、上下文、绕过、输出层、提交方式。

不保证：

- 目标函数存在。
- 权限足够。
- WAF 能绕过。
- 版本指纹准确。
- 语义一定可利用。
- 实际执行成功。

有需要就允许离线 parser：SQL、Shell、JSON、XML、模板、Python、Node、Java、PHP。
parser 失败时给出明确错误。

------

## 14. 版本数据

- 由编写时提供。
- 可存本地 JSON / YAML / SQLite。
- 用户选择版本号后，工具据此过滤模板和绕过。
- 支持版本范围语法、组件别名、多组件依赖、发行版、backport。
- 未知版本显示通用模板并标记条件。
- 来源：CVE、厂商文档、PayloadsAllTheThings、Seclists、Exploit-DB、GitHub。
- 许可证合规，手动导入更新，不自动在线更新。

------

## 15. 存储与性能

用最快的：

- MVP：启动时把 JSON / YAML 规则加载到内存。
- 查询、过滤、组合都在内存里做。
- 数据量大再换 SQLite。
- 建索引：漏洞、组件、版本、语言、OS、标签。
- 缓存常用过滤结果。
- 核心引擎本地函数调用，不做网络层。

------

## 16. 扩展性、测试、安全合规

### 扩展性

- 新漏洞、新组件、新模板、新绕过、新输出格式都通过数据文件加。
- 支持用户导入自定义 YAML / JSON。
- 热加载。
- 插件化：模板插件、绕过插件、输出适配器插件。
- 规则版本迁移。
- 核心引擎与 UI 解耦。

### 测试

- 黄金样本：输入状态 → 期望输出。
- 单元测试：模板、绕过、编码、输出。
- 集成测试：多选输出、嵌套、冲突。
- 回归测试。
- 语法校验测试。
- 错误提示测试。

### 安全合规

- 完全离线，不接 AI，不接在线 API。
- 不执行、不验证、不自动提交。
- 免责声明：用户对使用负责。
- 审计日志：可选。
- 来源和许可证标注。
- 无遥测。
- 工具自身不写敏感文件，不执行 payload。
- curl 生成不自动执行。

------

## 17. MVP 建议

先做小范围：

- 定义规则 DSL。
- 定义模板元数据 Schema。
- 定义绕过元数据 Schema。
- 定义用户选择状态 Schema。
- 定义编码管线。
- 定义输出适配器。
- 支持 2–3 个漏洞类型。
- 支持少量组件和版本。
- 支持原始、编码、完整请求、curl 四层输出。
- 用黄金样本测试。
- 不接 AI，不执行，不提交。

------

## 18. 未确定部分

以下内容目前尚未确定，需要后续拍板：

### 18.1 技术选型

- 用什么语言实现核心引擎。
- 用 JSON、YAML 还是 SQLite 作为主存储。
- 是否使用离线 parser，具体用哪些库。
- 打包方式：单文件、Docker、跨平台可执行。
- 核心引擎 API 契约。

### 18.2 规则与 Schema

- 规则 DSL 的具体语法。
- 模板元数据字段最终版。
- 绕过元数据字段最终版。
- 版本范围语法。
- 多组件依赖表达方式。
- 未知版本处理策略。
- 多模板匹配排序规则。
- 冲突处理策略：禁用、提示还是回滚。
- 绕过组合顺序：用户拖拽还是规则拓扑排序。
- 最大嵌套深度。
- 是否允许循环嵌套。
- 编码管线顺序是否允许用户调整。
- 是否允许双重编码及如何避免。

### 18.3 交互与输出

- GUI、WebUI、CLI 最终形态。
- 输出层是否任意多选，依赖如何处理。
- 占位符语法与默认值最终清单。
- 变量作用域与引用规则。
- 是否支持收藏、历史、配置导入导出。
- 是否支持快捷键、搜索、过滤、预览、复制。
- 是否支持中英文界面。
- 错误提示格式。

### 18.4 数据与版本

- 版本数据具体来源与更新方式。
- 是否内置 CVE、ATT&CK 标签。
- 是否处理发行版 backport。
- 是否允许用户导入自定义规则。
- 是否支持热加载。
- 规则版本迁移方案。
- 许可证合规细节。

### 18.5 质量与合规

- 黄金样本与测试用例标准。
- 语法校验测试范围。
- 审计日志是否默认开启。
- 免责声明文本。
- 是否提供贡献指南、用户手册、规则编写指南。
- 性能指标与缓存策略。

### 18.6 范围与优先级

- MVP 具体支持哪些漏洞类型、组件、版本。
- 高级提交方式是否进 MVP：WebSocket、SSE、gRPC、HTTP/2、HTTP/3、其他协议。
- Burp、Postman 片段是否进 MVP。
- 多阶段 Payload、OOB、反弹 Shell、文件写入/包含是否进 MVP。
- 是否处理无回显、权限提升、横向移动、持久化、清理痕迹。
- 是否处理文件上传、路径穿越、重定向回调参数。
- 是否处理模板/命令分隔符、编码命令。
- 是否处理所有数据库、中间件、框架。

------

## 19. 下一步最建议先定下来的五样

1. 规则 DSL：怎么写“什么条件下可用”。
2. 模板元数据 Schema。
3. 绕过元数据 Schema。
4. 用户选择状态 Schema。
5. 编码管线与输出适配器。