# HTTP Request Smuggling & Cache Poisoning 知识库

> 条目前缀：KB-RS | 来源：PortSwigger Research / James Kettle / PortSwigger Web Security Academy
> 去重键：`类别 + 原理摘要` SHA-256 前 8 位

---

### [KB-RS-001] CL.TE Request Smuggling

- **类别**: HTTP Request Smuggling
- **信号**: 前端使用 Content-Length 定界，后端使用 Transfer-Encoding 分块。发送一个同时包含 `Content-Length` 和 `Transfer-Encoding: chunked` 的 POST 请求，若后端将第二个请求的前缀吞入前一个请求体，则存在 CL.TE 走私。
- **原理**: 前端代理/负载均衡器按 `Content-Length` 头计算请求体长度，将整个报文（含第二个请求）一并转发；后端按 `Transfer-Encoding: chunked` 解析，在第一个 `0\r\n\r\n` 处结束，剩余字节被当作下一个请求的前缀——第二个请求的起始部分被"走私"进前一个请求体。
- **最小PoC**:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

后端将 `G` 视为下一个请求的开头，若后续请求开头为 `GET /admin`，实际处理为 `GPOST /`（畸形），造成 400/超时，时间差或状态码差异即为信号。

- **绕过与变体**: 调整 `Content-Length` 值使走私前缀恰好覆盖下一个请求的方法行；使用 `Transfer-Encoding: chunked` 带 chunk 扩展（`chunked; x=y`）绕过 WAF。
- **修复**:
  - 统一前后端 HTTP 解析器或使用同一软件栈
  - 禁用 HTTP/1.1 后端复用连接（关闭 connection reuse）
  - 前端拒绝同时包含 `CL` 和 `TE` 的请求
  - 使用 HTTP/2 端到端避免降级解析歧义
- **参考**: CWE-444；PortSwigger Web Security Academy: "HTTP request smuggling, basic CL.TE vulnerability"

---

### [KB-RS-002] TE.CL Request Smuggling

- **类别**: HTTP Request Smuggling
- **信号**: 前端使用 Transfer-Encoding 分块解析，后端使用 Content-Length 定界。发送同时包含两头的请求，若后端将 chunked 尾部视为定长请求体的结束，剩余前缀污染下一个请求。
- **原理**: 前端按 `Transfer-Encoding: chunked` 解块后发送完整请求体；后端按 `Content-Length` 读取 N 字节，chunked 尾部（`0\r\n\r\n`）后的走私前缀被留在缓冲区，作为下一个请求的前缀被处理。
- **最小PoC**:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

x=1
0

```

后端读 4 字节（`5c\r\n`），剩余内容（`GPOST /...`）作为下一个请求。目标是让下一个真实请求的方法行被走私前缀覆盖，例如 `GET /search` 变成 `GPOST /search`，实际命中走私中的 `POST` 路径。

- **绕过与变体**: CL 值精确匹配 chunk size 行字节数（含 CRLF）；在 chunk size 后插入分号注释混淆中间件（`5c;ignore`）；使用 `\x0d\x0a` 裸 CRLF 替代 `\r\n`。
- **修复**: 同 KB-RS-001；两端一致解析；禁用后端连接复用；HTTP/2 端到端。
- **参考**: CWE-444；PortSwigger: "HTTP request smuggling, basic TE.CL vulnerability"

---

### [KB-RS-003] TE.TE Smuggling (Transfer-Encoding Obfuscation)

- **类别**: HTTP Request Smuggling
- **信号**: 前后端均支持 `Transfer-Encoding: chunked`，但一方可被 obfuscation 技法致使忽略该头，退化为定长或不解析 chunked。尝试 `Transfer-Encoding: xchunked`、`Transfer-Encoding : chunked`（空格变体）、`Transfer-Encoding: chunked\r\nTransfer-Encoding: x`（重复头）等变体。
- **原理**: 利用 HTTP 头解析差异：前端严格解析后忽略畸形的 TE 头，回退到 `Content-Length`；后端容错解析并仍然识别为 chunked。或反之。两类解析器对 TE 头的容错/严格度不一致导致走私。
- **最小PoC**:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
Content-Length: 11

x=1
0

```

- **绕过与变体**: `Transfer-Encoding: chunked` 的常见混淆列表（PortSwigger 27 种变体）：
  - `Transfer-Encoding : chunked`（冒号前空格）
  - `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity`（重复头）
  - `Transfer-Encoding:\tchunked`（tab 分隔）
  - `Transfer-encoding: chunked`（大小写混合）
  - `Transfer-Encoding: chunked; x=y`（参数化）
- **修复**: 拒绝任何非严格 `Transfer-Encoding: chunked` 的 TE 头；前后端同栈解析；HTTP/2 端到端。
- **参考**: CWE-444；James Kettle "HTTP Desync Attacks: Request Smuggling Reborn" (Black Hat USA 2019)；PortSwigger Research

---

### [KB-RS-004] HTTP/2 Downgrade Smuggling

- **类别**: HTTP Request Smuggling (H2↓)
- **信号**: 前端接受 HTTP/2，但将请求降级为 HTTP/1.1 转发给后端。通过注入 HTTP/2 伪头部或利用 H2 帧的特性构造等价于走私前缀的 HTTP/1.1 请求。使用 `curl --http2` 或 HTTP/2 客户端发送恶意请求，观察后端响应时序/异常。
- **原理**: HTTP/2 是二进制协议，无 `Content-Length`/`Transfer-Encoding` 歧义。但当前端将 H2 降级为 H1.1 时，前端的降级逻辑可能将 H2 的 stream 特性错误翻译，例如注入额外的 H1 请求前缀或产生请求拆分。常见路径：降级时代入的 `Transfer-Encoding: chunked` + 用户可控的 header 值含 `\r\n` 导致请求拆分。
- **最小PoC**（H2 降级时 header 注入请求拆分）:

```http
:method POST
:path /
:authority vulnerable-website.com
foo: bar\r\n\r\nGET /admin HTTP/1.1\r\nHost: vulnerable-website.com\r\n\r\n
```

前端降级时 header 值中的 `\r\n` 未转义，导致在 H1.1 中生成第二个完整请求。

- **绕过与变体**: 在 H2 pseudo-header (`:path`、`:authority`) 中注入 CRLF；用 H2 流优先级/依赖帧干扰降级顺序；利用 H2 的 `host` 头与 `:authority` 伪头不一致导致降级分裂。
- **修复**:
  - 端到端 HTTP/2（后端也支持 H2）
  - 降级时强制 strip/转义所有 header 中的 CRLF
  - 禁用 H2→H1.1 降级或在降级层做严格校验
- **参考**: James Kettle "HTTP/2: The Sequel is Always Worse" (Black Hat USA 2021)；PortSwigger Research；CWE-444

---

### [KB-RS-005] H2.CL Request Smuggling

- **类别**: HTTP Request Smuggling (H2↓)
- **信号**: 前端 HTTP/2 降级为 HTTP/1.1 时，未剥离或未校验 H2 请求中用户注入的 `content-length` 头。H2 本身用 `:method` + DATA 帧传输 body，`content-length` 头是多余的 — 但如果降级层信任用户提供的 CL 头，可造成与 CL.TE 等价的后端走私。
- **原理**: HTTP/2 规范中 `content-length` 头是不被框架层使用的（请求体由 DATA 帧流确定）。但降级层若原封不动地将 `content-length` 头写入 H1.1 请求，后端按该 CL 读取请求体。攻击者发送一个完整 H2 请求，同时携带一个虚假的小 `content-length`，使降级后的 H1.1 后端只读取部分 body，剩余字节（下一个 H2 stream 降级后的请求）被走私为下一个请求的前缀。
- **最小PoC**:

```http
:method POST
:path /
:authority vulnerable-website.com
content-length: 0

(HTTP/2 DATA frame with body "GET /admin HTTP/1.1\r\nHost: vulnerable-website.com\r\nFoo: bar")
```

降级层写 `Content-Length: 0` 到 H1.1，但 DATA 帧中携带的 body 被直接跟在后面，成为下一个请求。

- **绕过与变体**: `content-length` 使用不同大小写（`Content-length`、`CONTENT-LENGTH`）；注入多个 `content-length` 头（某些降级层只 strip 第一个）；与 TE 头结合注入。
- **修复**: 降级层必须从后端协议重新计算 `Content-Length`，完全忽略用户提交的该头；H2 端到端。
- **参考**: James Kettle "Browser-Powered Desync Attacks" (DEF CON 30 / Black Hat 2022)；PortSwigger Research

---

### [KB-RS-006] Response Queue Poisoning

- **类别**: HTTP Request Smuggling (Impact)
- **信号**: 走私成功且后端连接被复用。发出一个走私前缀请求 + 一个正常请求；走私前缀劫持下一个正常请求的响应并将其返回给攻击者。若观察到响应错乱（自己的请求收到别人的响应）、响应延迟或连接挂起，则队列被污染。
- **原理**: 请求走私成功后，走私前缀在连接上形成一个待处理的"半请求"。下一个通过同一条后端连接发送的真实用户的请求，其响应会被路由到走私前缀的发起方（攻击者）。从而攻击者可捕获其他用户的会话 Cookie、CSRF token 或敏感数据。持续投毒可长期捕获流量。
- **最小PoC**（基于 CL.TE 走私捕获随机用户请求的响应）:

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 80
Transfer-Encoding: chunked

0

GET /my-account HTTP/1.1
Host: vulnerable-website.com
X-Ignore: X
```

后端在 chunked 终止后，将 `GET /my-account...` 视为新请求处理，其响应返回给攻击者的连接。真实用户的后续请求可能被丢弃或超时。

- **绕过与变体**: 调整走私请求的路径以命中不同敏感端点；结合请求体调整 `Content-Length` 值批量捕获；通过异步请求（AJAX）触发更多后端连接复用。
- **修复**: 消除走私根因；禁用后端连接复用；对每个连接做请求计数与超时清理。
- **参考**: James Kettle "HTTP Desync Attacks" (2019)；PortSwigger: "Exploiting HTTP request smuggling to capture other users' requests"；CWE-444

---

### [KB-RS-007] Web Cache Poisoning (Basics)

- **类别**: Web Cache Poisoning
- **信号**: 响应包含 `X-Cache: hit` 或 `CF-Cache-Status: HIT` 等缓存头。测试未列入缓存键（unkeyed）的 HTTP 请求头（如 `X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-Original-URL` 等），若这些头影响响应内容（如生成 redirect URL、script src 或 CSP 头），则存在缓存投毒入口。
- **原理**: CDN/缓存服务器使用"缓存键"（通常为 HTTP method + path + query + Host 头）决定是否复用缓存响应。但许多请求头部不被纳入缓存键，却影响后端生成的响应内容。攻击者发送恶意值于 unkeyed header，使服务器生成带恶意内容的响应并被缓存，后续所有匹配缓存键的请求将获得该投毒响应。
- **最小PoC**:

```http
GET /?foo=bar HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: evil.com
```

若响应中包含 `<script src="https://evil.com/resource.js">`（源于 `X-Forwarded-Host`），且首次请求命中缓存，则后续所有访问 `/?foo=bar` 的用户均被加载恶意 JS。

- **绕过与变体**: 使用 `X-Forwarded-Port`、`X-Forwarded-Proto`、`Forwarded` 头；利用 `X-Original-URL` 或 `X-Rewrite-URL` 重写缓存键路径；利用 fat GET（带 body 的 GET 请求）绕过缓存键；利用参数污染（`?foo=bar&foo=baz`）触发不同的缓存键解析。
- **修复**:
  - 禁用不需要的 unkeyed header 处理
  - 避免在 unkeyed header 值直接拼接到 HTML/JS/redirect
  - 使用 `Vary` 头声明所有影响响应的 header
  - CDN 层做归一化与校验
- **参考**: James Kettle "Practical Web Cache Poisoning" (Black Hat 2018)；CWE-346；PortSwigger: "Web cache poisoning"

---

### [KB-RS-008] Web Cache Deception

- **类别**: Web Cache Deception
- **信号**: 应用程序对路径 `/account.php/nonexistent.css` 仍然返回 `/account.php` 的内容（敏感信息），但 CDN/缓存服务器因路径以 `.css` 结尾将其视为静态资源并缓存。探测类似路径是否返回相同敏感内容 + `X-Cache: hit`。
- **原理**: 应用服务器（如 Apache、Nginx + PHP-FPM）对路径的解析与 CDN/缓存服务器的缓存策略不一致。应用按"前缀匹配"执行脚本（`/account.php/anything` 仍执行 `account.php`），但 CDN 按文件扩展名（`.css`）分类为静态可缓存资源。攻击者诱骗受害者访问 `https://target.com/account.php/evil.css`，CDN 缓存了返回的敏感页面（含账户信息、CSRF token），攻击者再访问同一 URL 获取缓存内容。
- **最小PoC**:

```http
GET /my-account.php/nonexistent.css HTTP/1.1
Host: vulnerable-website.com
```

若响应为 `HTTP/1.1 200 OK` + 完整账户页面 HTML + `X-Cache: miss`（首次），再发一次同请求变为 `X-Cache: hit`，则存在 Web Cache Deception。

- **绕过与变体**: 使用 `;.css`、`%2F.css`、`..;.css` 路径后缀；利用 Nginx `merge_slashes` 配置（`//.css`）；目标动态语言扩展（`.php`、`.asp`、`.jsp`）与静态扩展结合（`account.php/.css`）。
- **修复**:
  - 配置应用服务器对不存在路径返回 404/302 而非透明执行
  - CDN 配置：仅缓存已知静态目录/扩展名，默认不缓存
  - 设置 `Cache-Control: no-store` 于敏感端点
  - 使用 `Vary: Cookie` 区分认证/未认证（但成本高）
- **参考**: Omer Gil "Web Cache Deception Attack" (Black Hat 2017)；CWE-524；PortSwigger Research

---

### [KB-RS-009] Unkeyed Query Cache Poisoning

- **类别**: Web Cache Poisoning
- **信号**: CDN/缓存的缓存键包含完整 query string，但某些 CDN 或中间件仅缓存路径不缓存（或忽略）部分 query 参数。GET 参数在应用中影响页面输出（如 `?lang=fr` 改变语言而输出反射），但该参数被错误地排除在缓存键之外。
- **原理**: CDN 或缓存层对 query string 的处理可能为：全部纳入缓存键（安全）、全部忽略（可投毒）、或只忽略某些参数（更隐蔽）。若后端根据未被缓存的 query 参数生成差异响应（如错误消息反射参数值、重定向目标等），攻击者可注入恶意 payload，使该 URL 下所有请求被投毒。
- **最小PoC**:

```http
GET /?utm_campaign=evil<script>alert(1)</script> HTTP/1.1
Host: vulnerable-website.com
```

若 CDN 忽略 `utm_*` 参数的缓存键（常见于营销跟踪参数），且应用将 `utm_campaign` 值反射到页面 DOM，则投毒后的 `/` 缓存返回给所有访客，触发 XSS。

- **绕过与变体**: 探测 CDN 对常见 track 参数（`utm_source`、`utm_medium`、`gclid`、`fbclid`、`mc_cid` 等）是否排除在缓存键外；利用参数分隔符差异（`?` vs `;` vs `&`）；利用内联 JSON/JS 反射而非 HTML；利用 fat GET + unkeyed query 结合。
- **修复**:
  - CDN 配置：默认全部 query 参数纳入缓存键，或显式列出排除参数的白名单
  - 后端避免在不纳入缓存键的 query 参数中产生内容差异
  - 使用 `Vary` 头覆盖影响输出的 query 参数
- **参考**: James Kettle "Web Cache Entanglement" (Black Hat 2020)；PortSwigger Research

---

### [KB-RS-010] Host Header Cache Poisoning

- **类别**: Web Cache Poisoning
- **信号**: 应用在响应中反射 `Host` 头值（如 password reset link、script src、absolute URL 等）。若 CDN/缓存将 `Host` 头排除在缓存键之外（常见于某些 CDN 的正常化处理），攻击者可注入恶意 Host 投毒全局缓存。
- **原理**: CDN 出于灵活性和路由需要，可能不将 `Host` 头纳入缓存键（尤其是非 TLS 环境下，Host 头可随意伪造）。若后端将 `Host` 头值用于生成响应内容——password reset email 中的链接、`<base>` 标签、`<script src>` 的 CDN 路径、CORS 头等——攻击者以恶意 Host 发起请求并使响应被缓存，所有后续访问者获取投毒页面。
- **最小PoC**:

```http
GET / HTTP/1.1
Host: evil.com
```

若后端返回 `<script src="//evil.com/resource.js"></script>` 或 `Location: http://evil.com/...` 且响应被缓存，则目标首页被投毒。

- **绕过与变体**: 使用 `X-Forwarded-Host`（优先级常高于 `Host`）；双重 Host 头（`Host: target.com, evil.com`）；`Host` 头存在但 `Host` 加入 `Vary`——测试 CDN 是否实际遵守 `Vary: Host`；使用绝对 URL 绕过路径限定的缓存键。
- **修复**:
  - 使用相对 URL 而非绝对 URL（避免依赖 Host 头生成资源路径）
  - CDN 将 `Host` 纳入缓存键
  - 后端校验 `Host` 头为合法域名白名单
  - 使用 `X-Forwarded-Host` 标准化，并在应用层使用该标准头而非原始 `Host`
- **参考**: James Kettle "Practical Web Cache Poisoning" (2018)；CWE-346；PortSwigger Research

---

## 附录：快速判别决策树

```
观察到 X-Cache / CF-Cache-Status 缓存头？
├── YES → 测试 unkeyed header 反射与差异响应 → Web Cache Poisoning (KB-RS-007/009/010)
│          └── 路径后缀静态扩展返回动态内容？→ Web Cache Deception (KB-RS-008)
└── NO → 前端代理/CDN/WAF 架构？
         └── YES → 检测 CL/TE 走私：
                   ├── 前端 CL, 后端 TE → KB-RS-001
                   ├── 前端 TE, 后端 CL → KB-RS-002
                   ├── TE obfuscation → KB-RS-003
                   ├── HTTP/2 降级 → KB-RS-004
                   └── H2 + CL 注入 → KB-RS-005
                       └── 走私成功 → 响应队列投毒 KB-RS-006
```
