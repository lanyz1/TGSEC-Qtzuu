# Java 前端安全类漏洞审计模式参考

5 类前端安全漏洞的危险代码 / 安全代码对比 + EVID_* 证据格式示例。

---

## 1. XSS（跨站脚本）

### 1.1 JSP 反射型 XSS

```jsp
<%-- 危险: 表达式/Scriptlet 直接输出 --%>
<p>欢迎, <%= request.getParameter("name") %></p>
<% out.println("搜索: " + request.getParameter("keyword")); %>

<%-- 安全: JSTL c:out / fn:escapeXml --%>
<p>欢迎, <c:out value="${param.name}"/></p>
<p>搜索: ${fn:escapeXml(param.keyword)}</p>
```

审计关键: 全局搜索 `<%=` 和 `out.print`，逐一确认输出值来源。EL `${param.*}` 在 JSP 2.0+ 默认转义，显式禁用时仍危险。

### 1.2 Thymeleaf XSS

```html
<!-- 危险: th:utext 不转义 / [(${...})] 内联不转义 -->
<p th:utext="${userInput}">原始 HTML 输出</p>
<p>[(${userInput})]</p>

<!-- 安全: th:text 自动转义 / [[${...}]] 内联转义 -->
<p th:text="${userInput}">转义输出</p>
<p>[[${userInput}]]</p>
```

### 1.3 FreeMarker XSS

```ftl
<#-- 危险: 未配置全局转义时所有插值不转义 / 显式跳过 -->
<p>${username}</p>
<p>${content?no_esc}</p>

<#-- 安全: 全局配置 OutputFormat + 手动转义 -->
<#-- cfg.setOutputFormat(HTMLOutputFormat.INSTANCE) -->
<p>${username?html}</p>
<#ftl output_format="HTML">
```

审计关键: 检查 Configuration 的 OutputFormat 和 AutoEscapingPolicy。搜索 `?no_esc` 找显式跳过转义。

### 1.4 存储型 XSS 与 JSON 响应 XSS

```java
// 存储型: 入库参数化安全但 XSS payload 原样入库，出库 <%= comment %> 不转义
// 安全: 出库用 <c:out> 或入库时 Jsoup.clean(input, Safelist.basic())

// JSON XSS: Content-Type 误配为 text/html → 浏览器按 HTML 解析
response.setContentType("text/html"); // 危险
response.setContentType("application/json;charset=UTF-8"); // 安全
// Spring @ResponseBody 默认 application/json（安全）
// 加 X-Content-Type-Options: nosniff 防 MIME 嗅探
```

### 1.5 富文本安全过滤

```java
// OWASP Java HTML Sanitizer
PolicyFactory policy = new HtmlPolicyBuilder()
    .allowElements("p", "b", "i", "em", "strong", "a")
    .allowAttributes("href").onElements("a").allowUrlProtocols("http", "https").toFactory();
String safe = policy.sanitize(userInput);

// Jsoup.clean() — Safelist.basic() 允许基本格式标签，禁止 script/img/事件属性
String safe = Jsoup.clean(userInput, Safelist.basic());
```

### 1.6 XSS EVID 证据示例

```
[EVID_XSS_OUTPUT_POINT]   views/user/profile.jsp:45 | <%= user.getBio() %>
[EVID_XSS_DATA_FLOW]      UserController.java:89 → bio 来自数据库，入库无过滤
[EVID_XSS_CONTEXT]        HTML body | 模板未使用 c:out → 存储型 XSS 已确认

[EVID_XSS_OUTPUT_POINT]   templates/search.html:12 | th:utext="${keyword}"
[EVID_XSS_DATA_FLOW]      SearchController.java:34 → keyword=request.getParameter("q")
[EVID_XSS_CONTEXT]        HTML body | th:utext 不转义 → 反射型 XSS 已确认
```

---

## 2. CSRF（跨站请求伪造）

### 2.1 Spring Security CSRF Token

```java
// 默认启用: POST/PUT/DELETE/PATCH 需携带 Token
// 表单: <input type="hidden" name="_csrf" th:value="${_csrf.token}"/>
// AJAX: X-CSRF-TOKEN 请求头 + <meta name="_csrf"> 读取
```

### 2.2 CSRF 保护被关闭

```java
// 危险: 全局关闭（旧版 DSL / Lambda DSL）
http.csrf().disable();
http.csrf(csrf -> csrf.disable());

// 危险: 忽略范围过大
http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"));

// 安全: 仅忽略无状态回调 + CookieCsrfTokenRepository
http.csrf(csrf -> csrf
    .ignoringRequestMatchers("/api/webhook/**")
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

审计关键: 搜索 `csrf().disable()` 和 `csrf(csrf -> csrf.disable())`，评估影响范围。

### 2.3 自定义 Token 与绕过场景

```java
// 危险: Math.random() 可预测 / Token 未绑定 Session
// 安全: SecureRandom 32 字节 + 存入 Session + MessageDigest.isEqual() 校验

// 绕过 1: GET 执行状态变更（天然无 CSRF 保护）
@GetMapping("/deleteUser")  // <img src="..."> 即可触发
public String delete(@RequestParam Long id) { userService.delete(id); }

// 绕过 2: <form enctype="text/plain"> 发送类 JSON body（Content-Type 绕过）
// 绕过 3: 宽松 CORS 可跨域读取 CSRF Token
```

### 2.4 CSRF EVID 证据示例

```
[EVID_CSRF_GLOBAL_CONFIG]         SecurityConfig.java:35 | http.csrf(csrf -> csrf.disable())
[EVID_CSRF_STATE_CHANGE_ENDPOINT] UserController.java:67 | @PostMapping("/updateProfile") 无 Token 校验
[EVID_CSRF_GET_STATE_CHANGE]      AdminController.java:112 | @GetMapping("/admin/deleteLog") GET 执行删除
```

---

## 3. 开放重定向

### 3.1 Servlet 与 Spring MVC 重定向

```java
// 危险: 参数直接传入重定向
response.sendRedirect(request.getParameter("url"));
return "redirect:" + request.getParameter("target");
return new RedirectView(request.getParameter("url"));
return new ModelAndView("redirect:" + dest);
ResponseEntity.status(302).header("Location", userUrl).build();

// 危险: forward 到用户可控路径（信息泄露）
request.getRequestDispatcher(request.getParameter("page")).forward(request, response);
// page = "/WEB-INF/web.xml" → 读取配置
```

### 3.2 绕过白名单

```
//evil.com                     协议相对 URL
/\evil.com                     反斜线被视为路径分隔符
%2F%2Fevil.com                 URL 编码绕过
http://trusted.com@evil.com    @ 符号（trusted 变为 userinfo）
http://trusted.com.evil.com    子域名混淆
http://evil.com?trusted.com    查询参数混淆
```

### 3.3 安全模式

```java
// 白名单域名 + 相对路径限制
private static final Set<String> ALLOWED = Set.of("trusted.com", "sub.trusted.com");
public String safeRedirect(String url) {
    if (url.startsWith("//") || url.startsWith("/\\")) return "/default";
    if (url.startsWith("/") && !url.startsWith("//")) return url; // 相对路径
    try {
        String host = new URI(url).getHost();
        if (host != null && ALLOWED.contains(host.toLowerCase())) return url;
    } catch (URISyntaxException e) { /* 拒绝 */ }
    return "/default";
}
// Spring: UriComponentsBuilder.fromUriString(url).build().getHost() 校验白名单
```

### 3.4 开放重定向 EVID 证据示例

```
[EVID_REDIR_SINK]        AuthController.java:89 | response.sendRedirect(redirectUrl)
[EVID_REDIR_PARAM]       :85 | redirectUrl = request.getParameter("return_url") | 无白名单 → 已确认

[EVID_REDIR_SINK]        LoginController.java:56 | return "redirect:" + next
[EVID_REDIR_PARAM]       :52 | startsWith("/") 校验 → //evil.com 绕过 → 已确认
```

---

## 4. CRLF 注入

### 4.1 HTTP Header 与 Cookie 注入

```java
// 危险: Header 注入
response.setHeader("Content-Language", request.getParameter("lang"));
// lang = "zh\r\nSet-Cookie: admin=true" → 注入任意 Header

// 危险: Location Header → HTTP Response Splitting
response.addHeader("Location", "/app?lang=" + request.getParameter("path"));
// 注入 \r\n\r\n<script>... → 完整控制响应体

// 危险: Cookie 值注入
response.addCookie(new Cookie("theme", request.getParameter("theme")));
// 注入 \r\nSet-Cookie: session=hijacked → 劫持 Session
```

### 4.2 Servlet 容器防护差异

| 容器 | 版本 | CRLF 防护 |
|------|------|-----------|
| Tomcat | 7.0.67+ / 8.0.30+ | Header 值含 `\r\n` 抛 IllegalArgumentException |
| Jetty | 9.2.15+ | 拒绝 CR/LF |
| Undertow | 较新版本 | 默认过滤 |
| Tomcat 6.x / Jetty 8.x | 旧版 | 无防护，可直接利用 |
| Netty / Vert.x | 所有版本 | 原始 API 无自动过滤 |
| Spring Boot 内嵌 | 取决于内嵌容器版本 | 检查 pom.xml 版本号 |

### 4.3 安全模式

```java
// 过滤控制字符
String safe = value.replaceAll("[\\r\\n\\0]", "");
// 白名单校验
if (lang.matches("^[a-zA-Z\\-]{2,10}$")) response.setHeader("Content-Language", lang);
// URL 编码（适用于 Location）— URLEncoder 编码 \r\n 为 %0D%0A
response.sendRedirect("/app?lang=" + URLEncoder.encode(path, "UTF-8"));
```

### 4.4 CRLF EVID 证据示例

```
[EVID_CRLF_HEADER_WRITE] ApiController.java:45 | response.setHeader("X-User", username)
[EVID_CRLF_CONTAINER]    Tomcat 9.0.x → 内置防护 → 低风险

[EVID_CRLF_HEADER_WRITE] GatewayHandler.java:78 | ctx.response().putHeader("X-Trace", traceId)
[EVID_CRLF_CONTAINER]    Vert.x 4.x (Netty) → 无防护 → CRLF 注入已确认
```

---

## 5. Session 管理

### 5.1 Session 固定（Session Fixation）

```java
// 危险: 登录后未重建 Session
if (authService.authenticate(user, pass)) {
    request.getSession().setAttribute("user", user); // Session ID 不变
}
// 攻击: 诱导受害者携带已知 JSESSIONID 登录 → 共享 Session

// 安全: 销毁旧 Session + 创建新 Session
request.getSession().invalidate();
HttpSession s = request.getSession(true);
s.setAttribute("user", user);

// Spring Security 默认:
// sessionFixation().migrateSession()   迁移属性到新 Session（默认）
// sessionFixation().changeSessionId()  Servlet 3.1+ 仅改 ID（推荐）
// sessionFixation().none()             不处理（危险！）
```

### 5.2 Cookie 属性

```java
// 危险: 未设置安全属性 → XSS 窃取 / HTTP 明文截获 / CSRF 携带
Cookie c = new Cookie("JSESSIONID", sid);
response.addCookie(c);

// 安全: 完整设置
c.setHttpOnly(true); c.setSecure(true); c.setPath("/"); c.setMaxAge(-1);

// SameSite（Servlet 4.0+ 不原生支持）:
response.setHeader("Set-Cookie", "JSESSIONID=" + sid + "; Path=/; HttpOnly; Secure; SameSite=Lax");
// Spring Boot: server.servlet.session.cookie.same-site=lax
// Spring Session: DefaultCookieSerializer.setSameSite("Lax")
```

### 5.3 超时与并发控制

```xml
<!-- web.xml 超时配置 -->
<session-config>
    <session-timeout>30</session-timeout>  <!-- 分钟。危险: 480/-1 -->
    <tracking-mode>COOKIE</tracking-mode>  <!-- 缺失则可能支持 URL 重写 ;jsessionid=xxx -->
</session-config>
```

```java
// Spring Boot: server.servlet.session.timeout=30m
// 编程方式: request.getSession().setMaxInactiveInterval(1800);

// Spring Security 并发控制
http.sessionManagement(s -> s.maximumSessions(1).maxSessionsPreventsLogin(false));
// 需注册 HttpSessionEventPublisher Bean 否则不生效
// 未配置 → 同一账户无限并发登录 → 凭据泄露难以发现
```

### 5.4 Session EVID 证据示例

```
[EVID_SESSION_FIXATION]    LoginServlet.java:78 | 登录后未 invalidate() → Session Fixation 已确认
[EVID_SESSION_COOKIE]      web.xml 缺少 <cookie-config> | HttpOnly/Secure/SameSite 均未设置
[EVID_SESSION_TIMEOUT]     web.xml:15 | <session-timeout>480</session-timeout> → 8 小时窗口过大
[EVID_SESSION_CONCURRENT]  SecurityConfig.java 未配置 maximumSessions → 无并发控制
[EVID_SESSION_TRACKING]    web.xml 未配置 <tracking-mode>COOKIE → 可能支持 URL 重写
```
