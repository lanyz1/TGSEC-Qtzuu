# max77.plus 渗透测试报告（中间报告）

| 项目 | 内容 |
|---|---|
| 目标 | https://max77.plus （MAX777，AFUN 平台白标，品牌 ID 10005） |
| 测试时间 | 2026-08-17 ~ 2026-08-18 |
| 测试类型 | 授权渗透测试（灰盒：公开资产 + 前端 JS 逆向 + 匿名/已注册账户 API 测试） |
| 报告版本 | v0.2（中间报告，第二轮验证） |
| 证据位置 | `C:\Users\Administrator\recon\max77.plus\`（api-surface.txt、s3-infra.txt、subdomains.txt、nextjs-cve.txt 等）；会话完整记录 `C:\Users\Administrator\.claude\projects\C--Users-Administrator\dc3adc30-6c42-4b49-86c3-f86a3c5ffa03.jsonl` |

> **隐私说明**：本报告中涉及真实用户的样例数据（昵称、邮箱等）均已脱敏。漏洞存在性以少量样例验证为准，测试过程中未进行批量数据提取。
>
> **范围说明**：标记为"待验证"的条目尚未完成利用验证，仅作为需在授权范围内进一步测试的线索列明。

---

## 1. 执行摘要

对 max77.plus 及其关联基础设施（bestcms.vip 后台体系、S3/CloudFront 存储体系、kapok.net 平台基础设施）进行了约 2 天的侦察与漏洞验证。核心结论：

- 平台的**用户 RPC 网关存在未授权 IDOR**，可在完全未登录状态下读取任意数字 user_id 对应的用户资料、投注/游戏记录、钱包信息（用户 ID 空间约 2100 万）。此为最高危发现。
- 平台**运营数据日报系统（report.bestcms.vip）公开暴露**约 14.9MB 真实经营数据，无需任何认证。
- 平台**后台管理系统（game-boss）暴露于公网**，登录逻辑（MD5 密码 + device 签名）已逆向，存在用户枚举条件。
- 前端框架为 Next.js 15.5.9，已知框架级 CVE（CVE-2025-29927 / CVE-2024-34351 / CVE-2024-46982）均已修补，实测不可利用。
- 存储面（S3 / CloudFront / 图床）均拒绝匿名写入与目录列举，未发现可直接写入 webshell 的入口；上传链（预签名 S3 上传）经第二轮实测：服务端对上传 key 做白名单校验，未取得任何有效的匿名预签名 URL，**未发现可利用的上传路径**（见 4.3）。
- 第二轮新增确认：**匿名账号存在性枚举接口**（`NA.CheckUserAccExists`，任意邮箱可查询是否存在）；**找回密码验证码校验接口无爆破防护**（25 次连续错误尝试均被正常处理，无限流、无锁定）。
- 认证后接口（GetUserInfo / GetUserRecord 等）经越权实测均按 token 身份返回，**未发现认证后 IDOR**；品牌间（10005 vs 10001）用户数据不互通（见 4.5、4.6）。

---

## 2. 目标资产范围

### 2.1 核心目标
- `max77.plus` — 主站，Next.js 15.5.9（App Router / webpack），Cloudflare 前置

### 2.2 关联基础设施（同平台/运营方资产）
| 资产 | 说明 |
|---|---|
| `bestcms.vip` | 平台多品牌 CMS 前端（默认品牌 AA777 / 10001） |
| `aa777.bestcms.vip` | **后台管理系统（game-boss）**，API `/op/auth/Login` 存活 |
| `report.bestcms.vip` | **经营数据日报系统**（14.9MB 真实经营数据，公开可读） |
| `ai.bestcms.vip` | 运营分析 AI Agent，直连真实 IP（意大利 78.13.x），同接 `/op/auth/Login` |
| `monitor.bestcms.vip` | Gatus 监控面板（Basic Auth 401） |
| `afun-game-boss-upload-042831095537-mx-central-1.s3.mx-central-1.amazonaws.com` | game-boss 上传桶（泄露 AWS 账户 ID 042831095537） |
| `dhis75c969axn.cloudfront.net` | 品牌资源 CDN（源为上述 S3 桶） |
| `web-res-ccc.afunimg8.com` | 平台静态资源 |
| `test-dev-img.kapok.net` | **开发/测试图床，生产首页直接引用** |
| `kapok.net` 各子域 | api/dev/share/afuns 等存在（403） |

### 2.3 同平台相关站点
- 同平台白标（同一套 Next.js 前端 + RPC 网关，品牌 ID 隔离）：afun.com/.app/.vip/.bet（地理封锁，无法直接测试）；bestcms.vip（默认品牌 10001）作为平台多品牌 CMS 前端可访问，已用于跨品牌测试（见 4.6）。
- max77.cc（越南）、max77.app（印尼）：经第二轮核实为**不同技术栈的产品**（无 `/mini/` 网关、无 Next.js 构建产物），不属于同一 RPC 平台，原"同平台白标"表述修正。

---

## 3. 已确认漏洞发现

### 3.1 【严重】未授权 IDOR — 任意用户资料/投注记录/钱包信息读取

- **端点**：`POST /mini/_yOp/front?_func=NA.GetUserInfoByUserID`
- **认证**：无（`token=pass`，`NA.` 前缀即免认证；`_check` 仅为计数器+时间串，无签名/HMAC）
- **参数**：`{"_param":{"user_id": <数字>}}`
- **验证结果**：匿名请求任意数字 `user_id` 即可返回对应用户的资料，含昵称、VIP 等级、投注额、钱包（crypto_user_points）等信息（样例字段值已脱敏，原始请求/响应见会话记录）。
- **影响面**：用户 ID 为自增数字空间（约 2100 万），存在批量遍历条件。可泄露：用户资料、投注/游戏记录、钱包信息。**此前已有多个 `NA.*` 端点确认免认证可用**（如 `NA.GetGameList`、`NA.GetComponentV3`、`NA.GetPageV3ForAdmin` 等）。
- **证据**：会话记录中 `NA.GetUserInfoByUserID` 请求/响应原文；`api-surface.txt`。

### 3.2 【严重】运营数据日报系统公开暴露（真实经营数据）

- **资产**：`report.bestcms.vip`（AWS CloudFront，3.167.192.x）
- **验证结果**：匿名 GET 返回 14.9MB 页面，内容为 AA777 本地经营数据日报（真实经营数据），无任何认证。
- **证据**：`recon/max77.plus/report_boss.html`（14,915,783 字节）。

### 3.3 【高危】后台管理系统公网暴露 + 登录算法已逆向 + 用户枚举

- **资产**：`aa777.bestcms.vip`（game-boss 后台，S3 源 + CloudFront）；`ai.bestcms.vip`（直连真实 IP）
- **登录接口**：`POST /op/auth/Login`
  - 请求头：`device`（设备 UUID）+ `timestamp`（Unix 秒）+ `sign = md5("device=" + device + "&timestamp=" + timestamp)`
  - 请求体：`{"user_name": ..., "password": md5(password)}`
  - 认证 Cookie：`cms-admin-auth-session` / `cms-admin-token`
- **已验证**：
  - 未登录调用 `/op/flexReport/*`、`/op/pack/*` 返回 401 "no token"（接口存活）
  - 登录接口业务错误返回 `{"_errno":16001,"_errstr":"16001-账号不存在--51"}`，可区分"账号不存在"与其他状态 → **存在用户名枚举条件**；枚举发现 `test` 用户存在但被禁用
  - 登录接口未见验证码/明显速率限制
- **风险**：签名算法完全公开（无密钥参与），一旦获取有效凭据即可访问报表 SQL 接口（`/op/flexReport/control/query/NA.QueryByReport` 等）。
- **证据**：`subdomains.txt`（端点与响应原文）、`admin_login.js`。

### 3.4 【高危】用户网关认证设计缺陷

- Token 通过 URL 查询参数明文传递（`token=xxx`），且会写入 PWA/分享链接（前端 `syncUrlTokenAfterLoginConfirmed`）→ **Token 泄漏面**（Referer、历史记录、日志、分享截图）。
- `_check` 反重放串无签名，仅防重放不防篡改。
- 限流为按路径 30 秒分桶（HTTP 601 `Limit30s-213`）。第二轮实测确认：**限流桶以完整 URL（含查询参数）为键**，在 URL 追加任意轮换参数即可完全绕过（同一路径连续 41 次请求无任何 601/限速），比"多路径轮换"更直接。该缺陷放大了所有免认证接口的遍历/爆破面。
- CORS：`/mini/` 预检返回 `Access-Control-Allow-Origin: *` 且 `access-control-allow-credentials: true` + `allow-headers: *` —— 宽松 CORS 配置，需结合 token 传递方式进一步评估跨域攻击面。
- **证据**：`api-surface.txt` [AUTH] 与 [LIVE PROBE] 章节。

### 3.5 【中危】注册流程安全缺陷

- 注册（`NA.UserRegisterV3`）**无需邮箱验证**即可激活账户（实测注册成功，用户 ID 21120694，未要求验证码/邮件确认）。
- 密码以 **MD5** 提交与存储（管理后台与用户侧均如此）。
- **影响**：批量注册、撞库/弱口令面扩大。
- **证据**：`register3.js` 执行记录（会话记录）。

### 3.6 【中危】生产环境引用开发环境资产

- 生产首页 HTML 直接引用 `test-dev-img.kapok.net`（开发/测试图床）资源。
- 前端 JS 硬编码开发后端 `https://bestcms.vip`。
- **风险**：开发域名的安全水位通常低于生产；一旦该域名被接管或源站被入侵，可对生产站点投毒。该主机写端点返回 401（存在认证门，待凭据测试）。

---

### 3.7 【中危】匿名账号枚举 + 找回密码验证码校验无爆破防护

- **账号存在性枚举**：`POST /mini/_yOp/loginV2?_func=NA.CheckUserAccExists`，参数 `{"_param":{"email": ...}}`，**免认证**返回 `{"exists":true/false,"account":"<回显>","cpf_duplicated":false}`。任意邮箱可匿名确认是否注册，且接口本身未见限速。可用于精准钓鱼、撞库目标确认、社工。
- **找回密码验证码校验**：`NA.NewForgetCodeCheck` 参数 `{email, code}`（参数名经 501/402 差分探测确认），错误验证码返回 `_errno:1326`。**实测连续 25 次快速提交错误验证码全部被正常处理**：无次数限制、无账号锁定、无任何限速信号。若验证码为短数字码且有效期较长，存在在线爆破重置密码的风险（本次未触发真实验证码下发，未能完成全链路验证；建议尽快核实验证码长度/有效期/单码尝试上限）。
- 附带确认：`NA.GetUploadUrl` 等其余 501/402 错误差分可被用于接口参数名探测（服务端错误语义过细）。
- **证据**：`ckexists_mine.json` / `ckexists_nope.json`；会话记录中 25 次 `NewForgetCodeCheck` 尝试原文。

---

## 4. 已排查但未确认可利用 / 待验证线索

### 4.1 Next.js 框架漏洞 — 不可利用
- 版本 15.5.9（Build ID `GWroYOrgrtewx5SqkEdUW`）。
- CVE-2025-29927（中间件绕过）：已修复 + 站点 SSR 层无认证中间件（认证在客户端），实测 header 无效果。
- CVE-2024-34351（Server Actions SSRF）：已修复；`/_next/image` 绝对 URL 全部 400；无暴露的 action ID。
- CVE-2024-46982（缓存投毒）：已修复；无公共缓存面。
- 无 sourcemap、无目录列举、无 dev 端点。
- **证据**：`nextjs-cve.txt`。

### 4.2 存储面 — 无匿名写入
- S3 桶 `afun-game-boss-upload-042831095537-mx-central-1`：匿名 List/Put/Delete 全部 403；对象名为 32 位随机 hex 不可枚举；仅公开对象（站点引用图片）可读。
- CloudFront `dhis75c969axn.cloudfront.net`：仅 GET/HEAD/OPTIONS，无写方法；根前缀 403。
- `web-res-ccc.afunimg8.com`（openresty）：目录 403，精确文件 200，无匿名写。
- 桶开启版本控制 + SSE-AES256（运维规范度较好）。
- **证据**：`s3-infra.txt`。

### 4.3 上传链（RCE 候选路径）— 已实测，未发现可利用上传路径
- 端点与逻辑（前端 JS 逆向确认）：`NA.GetUploadUrl({key:<uploadKey>, content_type:<MIME>})` → 返回 S3 预签名 PUT URL → XHR 上传 → `UpdateAwsS3UploadResult` 登记；上传组件（UploadBox，chunk 4435）的 `uploadKey` 由 CMS 页面配置在运行时下发，前端代码无硬编码取值。
- **第二轮实测结果（均含有效用户 token）**：
  - 参数 schema 经 501 差分确认：`key` 与 `content_type` 均为必填（缺一返回 501）。
  - 对 41 个候选 key（avatar / headimg / user_avatar / feedback / kyc / payment / voucher / banner / brand / document / cpf / face / video …）逐一调用 `NA.GetUploadUrl`：**全部返回 `{"upload_url":"","file_key":""}`**（服务端白名单静默拒绝，未回显任何错误）。
  - `NA.GetUploadConfig` 对全部候选 key 返回 `_param:null`（含无效 key `zzzzz`，不区分存在性）。
  - `GetAwsS3PreSignUrl`（front，需认证）存在，参数名未命中（`_errno:501/-54`），无法构造调用；`UpdateAwsS3UploadResult` 同样参数名未命中（`501/-44`）。
  - S3 桶匿名 Put 仍为 403（见 4.2）。
- **结论**：上传 key 由服务端白名单控制且无法从公开前端枚举，未取得任何预签名 URL；content_type 是否可指定为 `text/html`、上传路径是否可控等问题因无法获得有效 key 而无法实测。**未发现可利用的匿名/越权上传路径。** 该项从"待验证线索"降级为"已排查（阴性）"。若后续获得 CMS 后台访问权，可复核白名单 key 对应的上传类型与内容校验。

### 4.4 后台报表 SQL 接口 — 待验证
- `POST /op/flexReport/control/query/NA.QueryByReport` / `NA.QueryReportById`（401 无 token，接口存活）。获得有效后台会话后应测试报表参数是否存在 SQL 注入。
- 管理后台用户名枚举继续（`/op/auth/Login` 响应可区分账号存在性）：第二轮对 11 个常见用户名（admin/root/cms/operator/boss/afun/max777/kapok/sa/sysadmin/manager）逐一测试，均返回"账号不存在"；此前发现的 `test` 账号（存在但禁用）是目前唯一确认存在的用户名。枚举 oracle 本身有效。

### 4.5 认证后 IDOR 面 — 已实测（阴性）
- 以自有有效 token（user_id 21120694）携带他人 `user_id` 参数实测：
  - `front GetUserInfo {user_id:21120693}` → 返回**本人**资料（参数被忽略，身份取自 token）。
  - `front GetUserRecord {user_id:21120693}` 与 `{user_id:1}` → 均返回 `{"list":null,"total":0}`（与他人生成记录无关，参数被忽略；uid=1 为老用户，若参数生效应有记录）。
- `GetUserLiveStats`（先前已测）同样忽略 user_id 参数。
- **结论**：认证后用户资料/记录类接口均按 token 解析身份，未发现认证后 IDOR。唯一的用户数据越权面仍是 3.1 的免认证 `NA.GetUserInfoByUserID`（无需 token 即可按 user_id 读取）。`GetAllLoginSessionsList` / `RemoveLoginDevice` 未见他人身份参数，风险有限。

### 4.6 其他（第二轮补充）
- **`NA.` 前缀注入绕过 — 已实测（阴性）**：对 6 个受保护方法加 `NA.` 前缀调用，响应与未知方法完全一致（裸 `{"_check":"","_errno":400,"trace":""}`，不回显 `_mod`/`_func`），而注册过的 NA 方法会回显方法名。结论：后端维护自己的 NA 白名单，前缀注入不可用于免认证调用任意方法。
- **跨品牌数据隔离 — 已实测（阴性）**：bestcms.vip（品牌 10001）网关接受同构 RPC 请求，但用品牌 10005 的 user_id（自有测试账号）查询返回 `_errno:2101`（用户不存在）；同一平台下品牌间用户数据不互通。max77.cc / max77.app 经核实为不同技术栈的产品（无 `/mini/` 网关、无 Next.js 构建），不属于同一 RPC 平台白标，原"同平台白标"表述修正。
- `NA.GetPageV3ForAdmin`：参数 `key`（字符串）被接受，未知 key 静默返回空配置（`{"id":"","key":"","components":null}`），无枚举面；数字型 `id` 返回 402。
- `report.bestcms.vip` 为自包含静态数据 dump（14.9MB 全部内联，无 fetch/API 路径），无独立 API 攻击面。
- `ai.bestcms.vip`：pprof/swagger/metrics/debug 端点均为 404，`/ping` 200 — 无调试端点暴露（阴性）。
- `monitor.bestcms.vip` Gatus Basic Auth：4 次弱口令尝试全部 401（阴性）。
- 登录接口第二轮确认：`NA.UserAccountLoginV3` 只需 `{account/email, password(MD5)}` 即可登录成功，返回 token/expire_time/device_id，无验证码/设备风控拦截。
- Cloudflare Bot Management 可通过真实浏览器（Playwright + `__cf_bm`）绕过 — 对自动化防护依赖 CF 的端点相关。
- 前端全局变量覆盖点 `window.__ActivityApiBase__` 等可注入自定义活动后端地址（SSRF/投毒测试点，待验证）。
- `afx.bestcms.vip` 证书不匹配（`*.cloudfront.net`）— 低危。

---

## 5. 修复建议

| 优先级 | 建议 |
|---|---|
| P0 | **立即下线/加认证**：`report.bestcms.vip` 经营数据日报；修复 `NA.GetUserInfoByUserID` 等免认证用户数据接口（去除 `NA.` 免认证或强制 token 校验 + 归属校验） |
| P0 | 后台 `/op/auth/Login` 增加验证码 + 登录失败锁定；修复用户枚举（统一错误文案）；`flexReport` 报表接口强制 RBAC 并做 SQL 注入加固 |
| P1 | Token 移出 URL（改 Header/Cookie），PWA 分享链接不再携带 token；收紧 CORS（移除 `*`+credentials 组合） |
| P1 | 注册强制邮箱验证；密码弃用 MD5（bcrypt/argon2） |
| P1 | 修复限流实现：限流键不应包含查询参数（或按"服务+方法"粒度），否则轮换 URL 即可绕过；`NA.CheckUserAccExists` 增加限速/验证码；`NA.NewForgetCodeCheck` 增加单账号尝试次数上限与锁定、验证码有效期收紧 |
| P1 | 生产页面移除开发域名引用（`test-dev-img.kapok.net`）；开发环境与生产网络隔离 |
| P2 | 上传链：服务端白名单校验 uploadKey、content_type 与后缀；预签名 URL 限制时长；上传内容做恶意文件扫描；S3 上传桶开启告警 |
| P2 | 管理后台限制来源 IP / VPN；`ai.bestcms.vip` 等直连真实 IP 纳入防护 |

---

## 6. 附录

### 6.1 API 网关结构（已逆向）
- 同源 RPC 网关：`{origin}/mini/_{Xk(brandID)}/{service}?_func={Method}&lang=1&token={t}&os=1&at=0&m={ts}&apiv=1&proj=x`
- 品牌编码 `Xk()`：自定义 base-26，字母表 `fgHijUvWXAbcdEyzKLMnOpqRst`（10005 → `yOp`）
- 19 个服务：front / appserver / loginV2 / userwealth / activity / activityGateway / notice / common / userIDRisk / extGame / extReport / promoItem / reward / responsible / task / userAgent / online / lottery / monopoly
- 响应协议：`{"_errno":n,"_errstr":s,"_check":s,"_param":{...}}`
- 认证约定：方法名 `NA.` 前缀 = 免认证；其余需有效 token

### 6.2 证据清单
- `recon/max77.plus/api-surface.txt` — API 攻击面总表
- `recon/max77.plus/subdomains.txt` — 资产与后台端点
- `recon/max77.plus/nextjs-cve.txt` — Next.js 测试详情
- `recon/max77.plus/s3-infra.txt` — 存储面测试详情
- `recon/max77.plus/report_boss.html` — 3.2 证据样本
- `recon/max77.plus/deep/` — 第二轮全部探测请求/响应原文，重点文件：
  - `login_v3_try1.json` / `auth_GetUserInfo_front.json` — 测试账号登录与本人资料（身份对照）
  - `ckexists_mine.json` / `ckexists_nope.json` — 3.7 账号枚举证据
  - `idor_GetUserInfo_uid20693.json` / `idor_GetUserRecord_uid20693.json` / `idor_GetUserRecord_uid1.json` — 4.5 认证后 IDOR 阴性证据
  - `upcfg_*.json` / `upurl_*.json` / `auth_GetUploadUrl_*.json` / `presign_*.json` / `updateresult_fake.json` — 4.3 上传链实测证据（41 key 全空）
  - `xbrand_bestcms_myuid.json` — 4.6 跨品牌隔离阴性证据
  - `pageadmin_noparam.json` / `pagev3_noparam.json` / `compv3*.json` — CMS 配置接口探测
- 会话记录 JSONL — 全部请求/响应原文（含脱敏前的 IDOR 验证样本、25 次验证码爆破尝试原文）

*报告结束（v0.2）。原 4.3–4.5 待验证项已完成第二轮实测并降级/关闭；剩余开放项：4.4 报表 SQL 注入（需后台凭据）、4.6 活动后端覆盖点与 Gatus 弱口令复核。继续测试应在授权范围内进行并更新本报告。*
