# XXE - XML 外部实体注入

> 来源：PortSwigger Academy / OWASP WSTG / 本地 lxml 靶场训练
> 条目前缀：KB-XXE | 覆盖：文件读取、SSRF、盲 XXE、OOB 数据渗透

---

### [KB-XXE-01] XXE 外部实体文件读取
- **类别**: XXE / 文件读取
- **信号**: 应用接受 XML 输入（Content-Type: application/xml 或 text/xml）；XML 解析结果部分回显在响应中；请求使用 SOAP、SVG、Office 文档（DOCX/XLSX）等 XML 格式；错误消息包含 XML 解析器特征（lxml/libxml2/Xerces）
- **原理**: 当 XML 解析器允许外部实体（External Entities）时，通过 DOCTYPE 声明引入外部资源，最常见是 `file://` 协议读取服务器本地文件。这是 XXE 最直接、危害最大的利用方式
- **检测**: 先建立正常 XML 基线 → 内联实体确认解析（`<!ENTITY test "hello">` → `&test;` 被替换）→ 外部实体读取文件（`file:///etc/passwd`）
- **利用**: 首选 `/etc/passwd`、`/etc/hostname`、`/proc/self/environ`（可能含凭据）；PHP 目标试 `php://filter` wrapper；Java 目标试 `file:///WEB-INF/web.xml`。Windows 调整路径分隔符 `file:///c:/windows/win.ini`
- **绕过与变体**: 实体未解析→测参数实体（%）；外部实体被禁止→测 XInclude；file:// 被过滤→测 php:// 或 jar://；无回显→转盲 XXE
- **修复**: 禁用 DTD 和外部实体（load_dtd=False, resolve_entities=False）；使用 defusedxml（Python）；拒绝含 DOCTYPE 的输入；JSON 替代 XML
- **相关技术卡**: `techniques/xxe/basic-file-read.yaml`、`techniques/xxe/blind-oob.yaml`
- **参考**: CWE-611 / PortSwigger: XXE / OWASP WSTG-INPV-07 / 本地 lxml 靶场训练 (2026-07-23)

### [KB-XXE-02] 盲 XXE 带外检测与数据渗透
- **类别**: XXE / 盲利用
- **信号**: 应用接受 XML 但返回统一响应（'OK'/HTTP 200 无差异）；XML 输入被解析但无内容回显；存在文件上传 + XML 解析（DOCX 处理、SVG 上传）
- **原理**: 当 XML 解析结果不回显时，通过侧信道确认漏洞存在：①OOB 回调（HTTP/DNS）最可靠但受解析器网络限制；②错误消息差异（存在/不存在资源返回不同错误）；③时间延迟（远程慢资源或死循环）
- **检测**: DNS 回调比 HTTP 回调更可靠（DNS 通常不被防火墙拦截）；lxml 6.x 默认禁止网络（no_network=False 不生效），HTTP OOB 被阻断但 file:// 仍可用
- **利用**: OOB 数据渗透链——恶意 DTD → 参数实体 → 文件内容 → URL 参数 → 攻击者服务器；本地 DTD 重新定义（利用系统已有 DTD 文件，无需外部网络）
- **绕过与变体**: DNS OOB > HTTP OOB；本地 DTD 技术突破网络隔离；错误消息渗透（文件内容嵌入必然报错路径）
- **修复**: 彻底禁用 DTD/外部实体；出站防火墙限制解析器网络；解析器沙箱/低权限运行；错误消息统一化
- **相关技术卡**: `techniques/xxe/blind-oob.yaml`、`techniques/xxe/basic-file-read.yaml`
- **参考**: CWE-611 / PortSwigger: Blind XXE / OWASP XXE Prevention Cheat Sheet / 本地 lxml 靶场训练 (2026-07-23)
