---
name: java-frontend-audit
description: |
  Java 源码前端安全类漏洞审计。当在 Java 白盒审计中需要检测前端安全漏洞时触发。
  覆盖 5 类风险: XSS(JSP/Thymeleaf/FreeMarker 输出转义)、CSRF(Spring Security/自定义 Token)、
  开放重定向(sendRedirect/forward)、CRLF 注入(Header/Cookie)、Session 管理(固定/超时/并发)。
  需要 java-audit-pipeline 提供的数据流证据。
metadata:
  tags: xss, csrf, open redirect, crlf injection, session, jsp, thymeleaf, freemarker, spring security, 前端安全, java source audit
  category: code-audit
---

# Java 前端安全类漏洞源码审计
本 skill 聚焦源码层面判断"前端安全漏洞是否成立"，核心是验证用户输入在输出到 HTTP 响应（HTML/Header/Cookie/重定向）过程中的过滤与转义是否充分。构造 payload、绕 WAF 等运行时利用技术属于对应黑盒 exploit skill 范畴。

## 深入参考

- 5 类前端漏洞的危险模式 / 安全模式代码对比 / EVID 证据示例 -> [references/frontend-vuln-patterns.md](references/frontend-vuln-patterns.md)

---

## 5 类前端安全漏洞速查表

| 类型 | 典型 Sink | 危险模式 | 严重度 |
|------|-----------|----------|--------|
| XSS | JSP `<%= %>`, `th:utext`, `${var?no_esc}`, `out.println()` | 用户输入未经转义直接输出到 HTML/JS 上下文 | High-Medium |
| CSRF | 状态变更 POST/PUT/DELETE 接口 | `csrf().disable()` 或缺少 Token 校验的写操作端点 | High-Medium |
| 开放重定向 | `sendRedirect()`, `return "redirect:" + url` | 用户可控 URL 直接传入重定向函数 | Medium |
| CRLF 注入 | `setHeader()`, `addHeader()`, `addCookie()` | 用户输入未过滤 `\r\n` 直接写入 HTTP 头 | Medium-High |
| Session 管理 | `getSession()`, `Cookie` 构造, `session-timeout` | 登录后未重建 Session / Cookie 缺少安全属性 | Medium-High |

## 通用审计流程（4 步）

**Step 1 -- 确认 EVID 证据点**: 从 `java-audit-pipeline` Phase 3 产出的 EVID_* 证据中，筛选前端安全类条目（EVID_XSS_*、EVID_CSRF_*、EVID_REDIR_*、EVID_CRLF_*、EVID_SESSION_*）。没有 EVID 证据的 Sink 只能标"待验证"。

**Step 2 -- 判断过滤有效性**: 追踪 Source->Sink 路径上每一步过滤/转义操作，评估其对当前漏洞类型是否有效。常见陷阱: `<c:out>` 安全但 `<%= %>` 不转义、`th:text` 安全但 `th:utext` 不转义、URL 白名单可被 `//evil.com` 绕过。

**Step 3 -- 评估绕过可能性**: 过滤存在但不充分时，分析具体绕过路径（上下文切换、编码差异、URL 解析差异等）。能给出绕过思路则标"已确认"，否则标"待验证"并记录已知过滤方式。

**Step 4 -- 确定严重度**: 使用 `java-audit-pipeline` 的三维度评分公式 `Score = R*0.40 + I*0.35 + C*0.25`。XSS 存储型 I=2-3，反射型 I=1-2；CSRF 取决于被保护操作的影响。

## XSS 审计要点

- **JSP 输出**: `<%= request.getParameter("x") %>` 和 `<% out.println(input); %>` 均不转义，直接输出到 HTML 即反射型 XSS；安全写法: `<c:out value="${param.x}"/>` 或 `${fn:escapeXml(param.x)}`，JSTL 默认转义 HTML 实体
- **Thymeleaf**: `th:utext="${userInput}"` 不转义（原始 HTML 输出）——危险；`th:text="${userInput}"` 自动 HTML 转义——安全
- **FreeMarker**: 全局配置 `output_format=HTMLOutputFormat` + `auto_escaping_policy=ENABLE_IF_SUPPORTED` 后默认转义；`${var?no_esc}` 显式跳过转义——危险；未配置全局转义时所有 `${}` 均危险
- **上下文差异**: HTML body 转义 `< > & " '` 即可；HTML attribute 需额外处理引号闭合；JavaScript 上下文需 JS 编码而非 HTML 转义；URL 参数需 URL 编码——不同上下文使用错误的转义函数等于无防御
- **DOM-based XSS**: 后端返回 JSON 被前端 `innerHTML` / `document.write()` / `eval()` 渲染，后端审计需确认 JSON 响应的 `Content-Type` 是否为 `application/json` 而非 `text/html`
- **存储型 XSS**: 数据从数据库取出后未转义直接输出——追踪入库点是否做了过滤，出库点是否做了转义
- **富文本场景**: 需使用白名单过滤库如 OWASP Java HTML Sanitizer (`PolicyFactory`) 或 `Jsoup.clean(html, Safelist.basic())`

## CSRF 审计要点

- **Spring Security 默认**: CSRF Token 默认开启，但 REST API 项目常见 `.csrf().disable()`（旧版）或 `http.csrf(csrf -> csrf.disable())`（Lambda DSL）——全局关闭后所有状态变更端点均暴露
- **自定义 Token**: 评估生成强度（`SecureRandom` 安全 vs `Math.random()` 可预测）、是否绑定 Session、校验时机（Controller 层 vs Filter 层）
- **Token 传递**: 表单用 `<input type="hidden" name="_csrf" value="..."/>`；AJAX 用 `X-CSRF-TOKEN` 请求头配合 `<meta name="_csrf">` 读取——缺失任一传递方式则该场景无防护
- **CORS 与 CSRF 的关系**: 宽松 CORS（`Access-Control-Allow-Origin: *` + `Allow-Credentials: true`）可被跨域 JS 读取响应中的 CSRF Token，间接绕过 CSRF 防护
- **GET 请求状态变更**: GET 执行写操作（如 `/deleteUser?id=1`）天然无 CSRF 防护——`<img src="">` 即可触发

## 开放重定向审计要点

- **Servlet 直接重定向**: `response.sendRedirect(request.getParameter("url"))` / `response.sendRedirect(request.getParameter("next"))` ——用户完全可控
- **Spring MVC**: `return "redirect:" + target` 或 `RedirectView(url)` 中 target 来自请求参数
- **绕过手法**: `//evil.com`（协议相对 URL）、`/\evil.com`（部分解析器视 `\` 为路径分隔符）、URL 编码 `%2F%2Fevil.com`、`@` 符号 `http://trusted.com@evil.com`、unicode 同形异义字
- **安全模式**: 白名单域名校验 + 限制仅相对路径（以 `/` 开头且不以 `//` 开头）；使用 `UriComponentsBuilder` 解析后校验 host

## CRLF 注入审计要点

- **HTTP Header 注入**: `response.setHeader("X-Custom", userInput)` 或 `response.addHeader("Location", "/path?lang=" + input)` ——注入 `\r\nSet-Cookie: admin=1` 可设置任意头
- **Servlet 容器差异**: Tomcat 7.0.67+ / Jetty 9.2.15+ 默认拒绝 Header 值中的 `\r\n`；旧版本或自定义 HTTP 框架（如 Netty 原始 API）可能无此保护——确认容器版本是关键
- **Cookie 值注入**: `new Cookie("lang", userInput)` ——注入 `\r\nSet-Cookie: session=evil` 可劫持 Session
- **安全模式**: 过滤或拒绝值中的 `\r`、`\n`、`\0` 控制字符；升级到较新版本 Servlet 容器

## Session 管理审计要点

- **Session 固定**: 登录前后 Session ID 不变——攻击者诱导受害者使用已知 Session ID；安全模式: 登录成功后 `request.getSession().invalidate()` + `request.getSession(true)` 重建；Spring Security `SessionFixationProtection.migrateSession` 默认启用
- **Cookie 属性**: `HttpOnly` 防 XSS 窃取 Cookie（`cookie.setHttpOnly(true)`）；`Secure` 限制仅 HTTPS 传输（`cookie.setSecure(true)`）；`SameSite=Lax/Strict` 防 CSRF（Servlet 4.0+ 或 Spring `server.servlet.session.cookie.same-site`）
- **超时配置**: `web.xml` 中 `<session-timeout>30</session-timeout>`（分钟）；Spring Boot `server.servlet.session.timeout=30m`；过长超时增加 Session 劫持窗口
- **并发登录控制**: Spring Security `sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true)` ——未配置时同一账户可多点登录，被盗凭据难以发现

## 检测清单

- [ ] 所有前端安全类 EVID_* 证据点已逐一审查
- [ ] JSP `<%= %>` / `out.println()` 输出点均已确认是否转义，Thymeleaf `th:utext` 已全部标记
- [ ] CSRF 保护状态已确认（是否 disable、Token 传递方式、GET 写操作）
- [ ] 重定向 Sink 的 URL 来源和白名单校验已确认
- [ ] HTTP Header/Cookie 写入点的用户输入过滤已检查，容器版本已记录
- [ ] Session 生命周期（固定/超时/并发/Cookie 属性）已审查
- [ ] 过滤不充分的点已给出具体绕过思路或标"待验证"
- [ ] 严重度评分使用了统一公式，与 pipeline 一致
