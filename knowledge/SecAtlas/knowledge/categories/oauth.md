# OAuth 2.0 / OIDC 攻击技术

> 来源：PortSwigger Web Security Academy、OWASP、HackTricks
> 前缀：KB-OA

---

### [KB-OA01] CSRF on OAuth Authorization Endpoint
- **类别**: OAuth / CSRF
- **信号**: 授权端点未要求 `state` 参数或未验证其与用户会话的绑定；OAuth 流程中无 CSRF token 或 nonce 保护
- **原理**: 攻击者用自己的 OAuth 账号完成授权流程，截获 `authorization code` 后，诱使受害者访问攻击者构造的 `GET /authorize?response_type=code&client_id=...&redirect_uri=...`（绑定攻击者账户的 code），受害者完成授权后即绑定攻击者身份，后续可窃取受害者在客户端应用中产生的数据
- **最小PoC**: 1) 攻击者在客户端应用中用自己的账户发起 OAuth 流程，在 `redirect_uri` 回调处拦截请求，提取完整 URL（含 `code` 参数）；2) 丢弃 `code` 参数，保留其余参数构造 URL；3) 将 URL 发送给已登录客户端的受害者访问；4) 受害者点击后 CSRF 完成，受害者会话绑定至攻击者账户
- **绕过与变体**: 若 `state` 存在但未绑定用户会话（仅静态值或可预测值），同样存在 CSRF 风险；可结合 XSS 获取 session cookie 后伪造绑定
- **修复**: 必须使用不可预测的 `state` 参数并绑定到用户会话，在回调时严格校验；SameSite Cookie + CSRF token 纵深防御
- **参考**: PortSwigger - OAuth CSRF; CWE-352; OAuth 2.0 RFC 6749 §10.12

### [KB-OA02] redirect_uri Bypass — Open Redirect
- **类别**: OAuth / Open Redirect
- **信号**: 授权服务器对 `redirect_uri` 的校验存在模式匹配漏洞；回调后 `code`/`token` 被发送至外部域
- **原理**: 若授权服务器仅对 `redirect_uri` 做前缀匹配或模糊校验（如仅检查域名开头字符串），攻击者可通过注册相似域（如 `client.com.evil.com`）或将开放重定向漏洞链入已注册域，使 `code`/`token` 落入攻击者控制服务器
- **最小PoC**: 在靶场 OAuth 流程中将 `redirect_uri` 改为 `https://client-app.com.evil.net/callback`，观察授权服务器是否仍在 `evil.net` 上返回 `code`；或利用已注册域上的开放重定向：`https://client.com/callback?redirect=https://evil.com/steal`
- **绕过与变体**: 利用授权服务器自身域的开放重定向；URI scheme 篡改（`javascript:`, `file:` 等，取决于实现）；subdomain 通配符混淆（`*.client.com` 含 `attacker.client.com`）
- **修复**: 授权服务器必须对 `redirect_uri` 做精确匹配或严格的 allowlist 校验（完整 URI 比较）；客户端注册时锁定 `redirect_uri`
- **参考**: PortSwigger - OAuth redirect_uri bypass; OWASP - Open Redirect; CWE-601

### [KB-OA03] redirect_uri Bypass — Path Traversal
- **类别**: OAuth / Path Traversal
- **信号**: `redirect_uri` 中包含 `../`、`..;/`、`%2f`、`%252f` 或 `//` 等路径遍历/URL 混淆字符；授权服务器未规范化解码后的 URI
- **原理**: 授权服务器对 `redirect_uri` 做了基础域名校验，但未对 URL 路径做规范化处理。攻击者通过路径遍历（`/../`）将回调端点导向同域下其他可控路径，或利用参数污染将 `code` 泄露到可控日志/Referer
- **最小PoC**: 1) 修改 `redirect_uri` 为 `https://client.com/../evil-path/callback`；2) 若服务器规范化后依旧回调到 `client.com` 但路径变为可控页面，可在该页面注入 JS 读取 URL fragment/hash 中的 token；3) 也可通过 `https://client.com/callback?extra=/../attacker-path` 探索差异处理
- **绕过与变体**: 双编码 `%252f` 绕过 WAF；`..;` 绕过目录规范化；使用 `//evil.com@client.com` 格式滥用 URL 解析歧义；CRLF 注入构造额外请求头
- **修复**: URL 解析使用 RFC 3986 严格模式，先规范化再校验；不信任任何经过转换的 URI；在客户端注册时固定完整路径
- **参考**: PortSwigger - OAuth redirect_uri path traversal; OWASP - Path Traversal; CWE-22

### [KB-OA04] State Parameter Missing / Weak
- **类别**: OAuth / CSRF / Token Binding
- **信号**: 授权请求中无 `state` 参数，或 `state` 为固定值/可预测值；回调端点未校验 `state` 与用户会话的绑定
- **原理**: `state` 参数用于将 OAuth 授权请求与回调响应绑定，防止 CSRF。缺失时攻击者可完成「CSRF 绑定攻击」；若 `state` 弱（常量、递增 ID、时间戳），攻击者可预测并伪造有效的 `state`，同样绕过保护
- **最小PoC**: 1) 拦截 OAuth 流程，观察 `/authorize` 请求是否有 `state=...`；2) 若无，直接执行 KB-OA01 的 CSRF 攻击；3) 若有但为固定值（如 `state=12345`），构造含相同 `state` 的恶意授权请求绑攻击者账户
- **绕过与变体**: `state` 存在但回调时仅做存在性检查（`if state:`）而非绑定校验；`state` 使用可逆编码（如 base64 用户 ID）导致可伪造
- **修复**: 生成密码学安全的随机 `state`（≥128 位熵），在服务端存储并与用户会话绑定；回调时执行恒定时间比较
- **参考**: PortSwigger - OAuth state parameter; OAuth 2.0 RFC 6749 §10.12; CWE-352

### [KB-OA05] PKCE Downgrade Attack
- **类别**: OAuth / Authorization Code Interception / PKCE
- **信号**: 授权服务器支持 PKCE 但不强制；客户端不发送 `code_challenge` 时服务器仍返回授权码
- **原理**: Authorization Code + PKCE 流程中，攻击者若可拦截受害者的授权请求（如通过恶意 app 注册自定义 URI scheme、网络中间人），可在请求中删除 `code_challenge` 和 `code_challenge_method` 参数，使授权服务器降级为无 PKCE 保护模式，后续攻击者用自己的 `code_verifier` 兑换 `code`
- **最小PoC**: 1) 从受害者的授权请求中移除 `code_challenge` 及 `code_challenge_method` 参数；2) 发送修改后的请求；3) 观察授权服务器是否仍然返回 `code`；4) 若返回，用攻击者自选的 `code_verifier` 在 `/token` 端点兑换
- **绕过与变体**: 修改 `code_challenge_method` 为 `plain`（服务器若接受则降级为明文验证）；中间人截获 `code_verifier`；利用 mobile/native app 的 custom URI scheme 劫持回调
- **修复**: 授权服务器必须强制 PKCE（对 public client 不可协商）；客户端必须发送 PKCE 参数；不允许 `plain` 模式
- **参考**: PortSwigger - PKCE downgrade; OAuth 2.0 PKCE RFC 7636; OWASP Mobile Top 10 - M1

### [KB-OA06] Implicit Flow Token Leakage
- **类别**: OAuth / Token Exposure / Implicit Flow
- **信号**: `response_type=token` 使用隐式授权流；access token 出现在 URL fragment 或 Referer header 中
- **原理**: 隐式授权流（Implicit Grant）直接在前端返回 access token（通过 URL fragment），token 可能泄露于：浏览器历史记录、Referer header（若回调页含外链）、JavaScript 可读取 fragment、中间人攻击（非 HTTPS）。攻击者通过 URL 泄露点或 Referer 日志窃取 token
- **最小PoC**: 1) 在 OAuth 隐式流回调页面中查找外链/图片请求；2) 通过检查 Referer header 确认回调 URL 是否带 token fragment 暴露给第三方；3) 利用 `window.location.hash` 在 DOM XSS 中读取 token 并外传
- **绕过与变体**: 若回调页存在开放重定向，token 随 Referer 泄露至外部域；PostMessage 广播 token 至任意 origin（`*`）；前端日志/Sentry 等监控工具可能捕获完整 URL 含 token
- **修复**: 禁止使用隐式授权流，改用 Authorization Code + PKCE；使用 `response_mode=form_post`；严格 CSP 限制外链和 script-src
- **参考**: PortSwigger - OAuth implicit flow; OAuth 2.0 Security BCP; OWASP - OAuth implicit flow risks; CWE-598

### [KB-OA07] Authorization Code Replay
- **类别**: OAuth / Code Replay / Replay Attack
- **信号**: 同一 `authorization code` 可在 `/token` 端点多次兑换；code 有效期过长
- **原理**: 根据 OAuth 2.0 RFC 6749 §10.5，授权码必须一次性使用。若授权服务器未做 code 消费标记（短时间窗口内重放），攻击者通过中间人、Referer 泄露或客户端日志截获 code 后可在受害者之前抢先兑换 token，获得访问权限
- **最小PoC**: 1) 截获完整的 `/authorize` 回调 URL（含 `code` 参数）；2) 在攻击者设备上向 `/token` 端点发送同一 `code`（含 `grant_type=authorization_code`、`client_id`、`redirect_uri`）；3) 若服务器返回 `access_token`，重放成功
- **绕过与变体**: 结合 PKCE 降级（KB-OA05）时的 code 截获；利用 DNS rebinding 将回调导向攻击者；code 有效期过长（>60s）增加拦截窗口
- **修复**: 授权码一次性使用（数据库标记已消费）；code 有效期 ≤ 60 秒；TLS 1.3 + 证书绑定；PKCE 强制作为纵深防御
- **参考**: PortSwigger - OAuth code replay; OAuth 2.0 RFC 6749 §10.5; CWE-294

### [KB-OA08] Client Secret Extraction from Mobile / Native App
- **类别**: OAuth / Mobile Security / Client Secret
- **信号**: APK/IPA 文件反编译后可在 strings.xml、配置类、shared preference 或硬编码常量中发现 client secret
- **原理**: OAuth 2.0 的 `client_secret` 若嵌入在移动 app/native app 的二进制或配置中，攻击者通过逆向工程（APK 解包、反编译 smali/dex、strings 提取、IPA 解密）可恢复密钥。获得 `client_secret` 后即可在授权码流程中兑换 token（伪装为合法客户端）
- **最小PoC**: 1) 获取目标 app APK：`apktool d app.apk -o out/`；2) 搜索 secret：`grep -rni "client_secret\|client-id\|api_key" out/`；3) 对混淆代码使用 frida/Objection 运行时 hook，监控 HTTP 请求提取运行时 secret
- **绕过与变体**: 白盒加密/密钥存储（如 Android Keystore）可被 root 环境绕过；JNI/native 层硬编码可通过 `strings` 或动态链接库分析提取；Firebase remote config 动态下发密钥可通过网络抓包捕获
- **修复**: 移动/原生客户端不得使用 `client_secret`，应使用 PKCE 替代；OAuth 2.1 要求 public client 必须用 PKCE；对敏感 API 使用 DPoP（Demonstration of Proof-of-Possession）token 绑定
- **参考**: PortSwigger - mobile app OAuth; HackTricks - Android APK reversing; OWASP MASVS; OAuth 2.1 draft §8.1; CWE-798

### [KB-OA09] OIDC ID Token Confusion — iss/sub Bypass
- **类别**: OIDC / JWT / Token Confusion
- **信号**: RP (Relying Party) 校验 `id_token` 时仅验证签名有效性而未校验 `iss`（issuer）值；`sub` 声明在不同 issuer 间重复
- **原理**: 若多个 OIDC Provider 共享相同密钥（或 RP 接受多个 issuer），且校验逻辑未将 `iss` 与期望的 issuer 严格对比，攻击者可在另一 issuer 注册同 `sub` 账号，生成合法签名的 `id_token` 后用于目标 RP 的身份冒充
- **最小PoC**: 1) 在目标 RP 使用的 OIDC Provider A 上注册用户；2) 若 RP 同时接受 Provider B 的 token，在 Provider B 注册相同 `sub`（如邮箱前缀）；3) 修改 Provider B 的 `id_token` 中 `iss` 为 Provider A 的地址，`aud` 为目标 RP 的 `client_id`；4) 使用此 token 访问 RP，观察是否通过身份验证获得目标用户权限
- **绕过与变体**: `aud`（audience）未校验导致跨客户端 token 复用；`alg:none` 绕过签名校验；kid 注入/jku header 注入获取自选密钥签名
- **修复**: 严格校验 `iss` 必须等于已知 issuer URL（精确字符串比较）；同时校验 `aud`、`exp`、`iat`、`nonce`；使用 OpenID Connect Discovery 获取 provider 公钥而非信任客户端传入
- **参考**: PortSwigger - JWT/OIDC attacks; OIDC Core 1.0 §3.1.3.7; CWE-287

### [KB-OA10] OAuth Account Takeover via Scope Manipulation
- **类别**: OAuth / Privilege Escalation / Scope Injection
- **信号**: 攻击者可追加、修改或删除授权请求中的 `scope` 参数且授权服务器不重新验证；scope 提权未触发用户交互
- **原理**: OAuth 授权流程中若 scope 校验仅在首次注册时完成，而 `/authorize` 请求中 scope 参数可被客户端任意修改，攻击者可扩大权限范围（如追加 `admin`、`write` scope）或通过 scope 映射利用业务逻辑缺陷，实现权限提升或账户接管
- **最小PoC**: 1) 拦截 OAuth `/authorize` 请求；2) 在 `scope` 参数中追加高权限 scope（如 `scope=read write admin` 或 `scope=profile email account.manage`）；3) 若授权服务器直接颁发含追加 scope 的 token 且未要求额外用户同意，后续即可使用该 token 执行越权操作
- **绕过与变体**: scope 值注入（如 `scope=read%20write` 被后端误解析）；利用 scope 到 endpoint 的松映射关系；结合 client 注册时的宽松 scope 策略；`claims` 参数注入获取额外用户属性
- **修复**: 在授权服务器端对 scope 做固定 allowlist，拒绝不在客户端注册 scope 内的值；敏感 scope 触发强制用户交互（consent screen）；access token 使用 audience-restricted scope 绑定
- **参考**: PortSwigger - OAuth scope attacks; HackTricks - OAuth scope escalation; OAuth 2.0 RFC 6749 §3.3; CWE-862
