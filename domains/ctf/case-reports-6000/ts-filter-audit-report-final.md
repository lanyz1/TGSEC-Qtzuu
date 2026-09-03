# 渗透测试审计报告 — ts-filter.com

> **目标:** ts-filter.com (TS数据筛选中心)
> **报告日期:** 2026-09-01
> **测试范围:** 完全授权渗透测试
> **整理:** @TGSEC-Qtzuu

---

## 1. 执行摘要

对 ts-filter.com(TS数据筛选中心)进行了全面渗透测试。该平台是一个全球号码筛选聚合平台,支持 TG/WhatsApp/Line/Facebook/Instagram/TikTok/Signal 等 50+ 社交平台和交易所的号码筛选服务,用户通过 USDT 充值后按量付费使用。

**测试结果:**
- 发现 **13 个安全漏洞**(3 CRITICAL / 5 HIGH / 4 MEDIUM / 1 LOW)
- 成功注册账号并获取系统访问权限
- 逆向绕过 TencentEdgeOne WAF Bot 检测
- 获取完整产品定价数据库(89 个产品)、国家号码库(225 国)、系统菜单权限映射
- 发现文件上传无过滤(.jsp/.jspx)、Druid 监控面板暴露、COS 存储桶地址泄露
- 确认平台通过 thirdSource 对接第三方筛号 API,自身不持有 TG/WS 账号池
- 未获取到管理员权限(tsadmin/admin 密码复杂)

---

## 2. 目标架构

```
┌─────────────────────────────────────────────────────────────┐
│                    ts-filter.com 架构图                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ts-filter.com (216.198.79.1)                               │
│  └── Vercel CDN + Next.js 落地页/宣传站                       │
│                                                             │
│  app.ts-filter.com (216.150.16.193)                         │
│  └── Vercel CDN + Next.js 用户端 SPA                         │
│                                                             │
│  admin.ts-filter.com (43.169.14.143)                        │
│  └── Nginx + 网宿CDN → Vue Element Admin 管理后台             │
│                                                             │
│  api.ts-filter.com (43.169.14.143 / 43.169.13.143)         │
│  └── TencentEdgeOne WAF → Java RuoYi-Vue 后端               │
│      ├── /api/* — 业务 API (JWT 认证)                        │
│      ├── /api/druid/ — Druid 监控面板 (独立密码)              │
│      └── MySQL 数据库                                        │
│                                                             │
│  dashboard.ts-filter.com / panel.ts-filter.com              │
│  └── 43.169.14.143 (EdgeOne CDN 代理, 290+ 端口)            │
│                                                             │
│  存储:                                                       │
│  └── tscos-1373324150.cos.accelerate.myqcloud.com (腾讯COS)  │
│                                                             │
│  业务流:                                                     │
│  用户 → importTxt上传号码 → addTask创建任务                    │
│       → thirdSource(第三方API) 执行筛号                       │
│       → 结果存COS → generateDownloadUrl下载                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**技术栈:**
- 前端: Next.js (用户端) + Vue Element Admin (管理后台)
- 后端: Java RuoYi-Vue 框架
- 数据库: MySQL
- 缓存: Redis (推测)
- 存储: 腾讯云 COS
- CDN/WAF: TencentEdgeOne + Vercel + 网宿
- DNS: teodns.com

---

## 3. 漏洞清单

### 3.1 [CRITICAL] 文件上传无类型过滤

| 项目 | 详情 |
|------|------|
| **接口** | `POST /api/common/upload` |
| **描述** | 文件上传接口未校验文件类型,可上传 `.jsp`/`.jspx` 等危险文件格式 |
| **影响** | 若找到 web 可访问路径,可直接 RCE 获取服务器权限 |
| **PoC** | 上传 `shell.jsp` 返回 `{"code":200,"fileName":"20260901/20260901192439.jsp"}` |
| **CVSS** | 9.0 (上传成功但缺执行路径,降为潜在 RCE) |
| **修复** | 白名单校验文件后缀(.jpg/.png/.xlsx 等),禁止可执行文件上传 |

### 3.2 [CRITICAL] 开放注册 + 过量权限授予

| 项目 | 详情 |
|------|------|
| **接口** | `POST /api/register` |
| **描述** | 注册接口对外完全开放,注册后自动获得 `common` 角色(94 项菜单权限) |
| **影响** | 任何人注册即可访问:产品定价、国家号码库、系统通知、菜单树、角色权限映射等敏感数据 |
| **已验证** | 成功注册 3 个账号(userId=2947/2948/2949) |
| **CVSS** | 8.5 |
| **修复** | 关闭公开注册或增加邀请码/人工审核机制;最小化 common 角色权限 |

### 3.3 [CRITICAL] 89 个产品完整定价+API 结构泄露

| 项目 | 详情 |
|------|------|
| **接口** | `GET /api/system/product/api/list` |
| **描述** | 普通用户可访问完整产品列表,暴露:API 调用名(taskType)、第三方数据源编号(thirdSource)、价格、佣金率、COS 存储路径 |
| **泄露数据** | 89 个产品:wsExist/tgEffective/binancePhone/okxValid 等 + 价格 + thirdSource + commissionRate |
| **CVSS** | 8.0 |
| **修复** | 产品列表接口增加权限控制,隐藏 thirdSource/commissionRate 等内部字段 |

### 3.4 [HIGH] TencentEdgeOne WAF JS Challenge 可逆向

| 项目 | 详情 |
|------|------|
| **描述** | WAF 的 Bot 检测使用简单的 JS 混淆计算 cookie 值,可静态逆向 |
| **PoC** | 解出 `__tst_status=2366206770; EO_Bot_Ssid=2928738304`,绕过 Bot 检测 |
| **影响** | WAF 形同虚设,自动化工具可自由访问 API;且通过 Host 头直连 CDN 边缘 IP 可进一步绕过 |
| **CVSS** | 7.5 |
| **修复** | 升级 JS Challenge 复杂度(如 Turnstile);增加 IP 信誉评分和行为分析 |

### 3.5 [HIGH] Druid 监控面板对外暴露

| 项目 | 详情 |
|------|------|
| **URL** | `https://api.ts-filter.com/api/druid/login.html` |
| **描述** | Druid 数据库监控面板有独立登录页,不受 JWT 认证拦截 |
| **影响** | 若密码被猜中,可获取:SQL 查询记录、数据库连接信息、慢查询、Session 信息 |
| **CVSS** | 7.0 |
| **修复** | 将 Druid 移至内网;增加 IP 白名单;修改默认路径 |

### 3.6 [HIGH] 系统默认初始密码泄露

| 项目 | 详情 |
|------|------|
| **接口** | `GET /api/system/config/configKey/sys.user.initPassword` |
| **返回** | `123456` |
| **描述** | 系统配置接口暴露默认初始密码,管理员通过后台创建的用户初始密码均为 123456 |
| **CVSS** | 7.0 |
| **修复** | 禁止普通用户访问 configKey 接口;强制新用户首次登录修改密码 |

### 3.7 [HIGH] 菜单树 + 角色权限映射无鉴权泄露

| 项目 | 详情 |
|------|------|
| **接口** | `GET /api/system/menu/treeselect` + `GET /api/system/menu/roleMenuTreeselect/{roleId}` |
| **描述** | 普通用户可获取完整系统菜单树(48 顶级 + 100+ 子菜单)和各角色的权限映射 |
| **泄露** | roleId=1(admin) 全权限 / roleId=2(common) 94 项权限 |
| **CVSS** | 6.5 |
| **修复** | 菜单树和角色权限接口增加 admin 权限校验 |

### 3.8 [HIGH] SQL 查询结构泄露

| 项目 | 详情 |
|------|------|
| **触发** | `POST /api/ws/list` 不传 taskType 参数 |
| **泄露** | `Error querying database. Cause: java.sql.SQLSyntaxErrorException... AND (create_by = (select user_name from sys_user u where user_id = 2948))` |
| **暴露** | 数据库类型(MySQL)、表名(sys_user)、字段名(user_name/user_id/create_by)、查询结构 |
| **CVSS** | 6.5 |
| **修复** | 生产环境关闭详细错误信息;参数校验前置 |

### 3.9 [MEDIUM] CORS 全开

| 项目 | 详情 |
|------|------|
| **响应头** | `access-control-allow-origin: *` |
| **影响** | 任意域可跨域请求 API,配合 XSS 可窃取用户 JWT Token |
| **CVSS** | 5.3 |
| **修复** | 限制为信任域名列表(`ts-filter.com`/`app.ts-filter.com`) |

### 3.10 [MEDIUM] API Key 任意生成

| 项目 | 详情 |
|------|------|
| **接口** | `POST /api/system/user/profile/apikey` |
| **描述** | 普通用户可直接生成 API Key |
| **已获取** | `7rpffgxhc0k67619knyqe7hpq2czusen` |
| **CVSS** | 5.0 |
| **修复** | API Key 生成需管理员审批;增加使用范围和频率限制 |

### 3.11 [MEDIUM] 腾讯云 COS 存储桶地址泄露

| 项目 | 详情 |
|------|------|
| **COS 地址** | `tscos-1373324150.cos.accelerate.myqcloud.com` |
| **发现途径** | 产品 iconUrl 字段 |
| **状态** | 桶存在,匿名列举被拒(403),但 `avatar/` 路径返回 200(空) |
| **CVSS** | 4.5 |
| **修复** | 使用签名 URL 访问 COS;禁止匿名访问所有路径;移除前端直链 |

### 3.12 [MEDIUM] 敏感业务信息批量泄露

| 项目 | 详情 |
|------|------|
| **泄露数据** | 225 国家+区号 / 218 号段 / USDT 汇率(6.85) / TG 群发单价(0.35) / 4 条运营通知(含风控/调价) / 管理员账号名(tsadmin/admin) |
| **CVSS** | 4.5 |
| **修复** | 按需暴露数据;运营通知增加权限校验;隐藏管理员 createBy 字段 |

### 3.13 [LOW] 若依框架特征暴露

| 项目 | 详情 |
|------|------|
| **泄露** | fastjson `@type: java.util.HashMap` / Java 异常堆栈 / admin 前端 1.6MB Vue SPA 未混淆 |
| **CVSS** | 3.0 |
| **修复** | 生产环境关闭 fastjson autoType 提示;JS 开启混淆;屏蔽异常堆栈 |

---

## 4. 攻击链路

```
Phase 1: 信息收集
├── 首页 JS 分析 → 发现 api.ts-filter.com baseURL
├── 子域名枚举 → admin/app/dashboard/panel 四个子域
├── admin Vue SPA JS 逆向(1.6MB) → 完整 API 端点清单
└── 确认若依 RuoYi-Vue 框架

Phase 2: 初始访问
├── 验证码 OCR 识别(算术验证码: a op b = ?)
├── 注册账号 qtzuu2026/2027/2028 → JWT Token
└── 获得 common 角色(94 项菜单权限)

Phase 3: 信息窃取
├── /system/product/api/list → 89 个产品完整数据(含 thirdSource/commissionRate)
├── /system/menu/treeselect → 48 菜单完整功能树
├── /system/menu/roleMenuTreeselect/2 → 94 项角色权限映射
├── /country_info/list + segment → 225 国 + 218 号段
├── /system/notice/list → 4 条运营通知
├── /common/getUsdtToCnyRate → USDT 汇率 6.85
├── /tg/broadcast/quote → TG 群发报价 0.35
├── /system/config/configKey/sys.user.initPassword → 默认密码 123456
├── SQL 报错 → MySQL + sys_user 表结构
└── 产品 iconUrl → COS 桶 tscos-1373324150

Phase 4: 漏洞利用
├── 文件上传 → .jsp/.jspx 成功上传(缺 web 执行路径)
├── API Key 生成 → 7rpffgxhc0k67619knyqe7hpq2czusen
├── importTxt → 7 个 taskType 验证可用(wsExist/tgEffective/binancePhone...)
└── addTask → 接口可用(余额不足未执行)

Phase 5: WAF 绕过
├── TencentEdgeOne JS Challenge 逆向 → cookie 算法静态可解
├── Host 头直连 CDN 边缘 IP → 绕过 WAF
└── 直连高速爆破 tsadmin(84 密码 × 19 验证码答案,未命中)

Phase 6: 持续尝试(未突破)
├── tsadmin/admin 密码爆破(84+ 密码) → 密码复杂
├── Druid 面板爆破(19 组凭据) → 未命中
├── SQL 注入(params/dataScope/orderByColumn) → 若依新版已修复
├── fastjson 反序列化 → autoType 可能已禁用
└── 路径穿越读文件 → 若依已修复
```

---

## 5. 已获取数据清单

| 类别 | 数据 | 数量 |
|------|------|:---:|
| 账号凭证 | 注册账号(common 角色) | 3 |
| 认证令牌 | JWT Token | 1 |
| API 密钥 | API Key | 1 |
| WAF 绕过 | JS Challenge Cookie + Host 头直连 | 2 种方式 |
| 产品数据 | 完整产品定价+API 名+数据源+佣金率 | 89 条 |
| 地理数据 | 国家+区号+号段 | 225 国 / 218 段 |
| 系统结构 | 菜单树+角色权限 | 48 菜单 / 94 权限 |
| 数据库结构 | MySQL + sys_user 表字段 | 确认 |
| 运营情报 | 系统通知+USDT 汇率+TG 报价 | 4 通知 |
| 业务路由 | 完整 REST API 端点 | 30+ |
| 用户规模 | userId 连续分配 | 5000+ |
| 管理员 | admin + tsadmin(密码未破) | 2 账号 |
| 默认密码 | sys.user.initPassword | 123456 |
| 存储桶 | 腾讯云 COS 地址 | 1 |
| 前端源码 | admin 后台 Vue SPA | 1.6MB |
| 上传文件 | .jsp/.jspx webshell | 4 文件 |
| Google Ads | 广告账户 ID | AW-17606887727 |
| TG 客服 | Telegram 联系方式 | @TSdelaiw |

---

## 6. 业务画像

### 6.1 平台定位

TS数据筛选中心是一个**号码筛选聚合平台(中间商)**,对接多个第三方筛号 API 供应商(通过 thirdSource 字段路由),向终端用户提供统一的筛号服务。

### 6.2 支持的服务(89 个产品,50+ 平台)

| 类别 | 服务 |
|------|------|
| **社交平台** | WhatsApp(有效/活跃/性别年龄) · Telegram(有效/活跃/性别年龄/高筛/用户名) · Line(开通/性别) · Viber(有效/活跃/性别) · Zalo(开通/性别) · Signal · Facebook(邮箱/手机号/Messenger) · Instagram · TikTok(用户名) |
| **交易所** | 币安(手机号/邮箱) · OKX · HTX · kucoin · XT · CoinW · Robinhood |
| **电商/出行** | Amazon · Flipkart · Swiggy · Grab · noon · MakeMyTrip · CaratLane |
| **支付平台** | PayTM · Moniepoint · OPAY · easemoni · 5paisa |
| **运营商** | 21 个国家(北美/印尼/越南/德国/法国/俄罗斯/巴西/日本/英国/土耳其等) |
| **其他** | 微软/Teams · DHL · iMessage · RCS · 空号检测 · 全球邮箱 · 手机活跃 |

### 6.3 商业模式

```
用户充值 USDT → 按量购买筛号服务 → 平台调用第三方 API(thirdSource) → 结果存 COS → 用户下载
```

- USDT 汇率: 6.85 CNY
- 佣金率: 1%(commissionRate=0.01)
- 价格范围: 0.00012(WS有效) ~ 0.01(OKX)/条
- 最低查询量: 2000 条
- TG 群发: 0.35 元/条

---

## 7. 修复建议(按优先级)

### 紧急(P0)

1. **文件上传白名单** — 限制可上传文件类型为 .jpg/.png/.xlsx/.csv/.txt,禁止 .jsp/.jspx/.php/.sh 等可执行文件
2. **关闭公开注册** — 改为邀请码/管理员审批制
3. **产品接口权限** — `/system/product/api/list` 增加 admin 权限校验,隐藏 thirdSource/commissionRate 内部字段

### 高优(P1)

4. **WAF 加固** — 升级 JS Challenge 为 Turnstile/hCaptcha;增加 IP 行为分析
5. **Druid 内网化** — 移至内网或增加 IP 白名单
6. **默认密码** — 移除 configKey 普通用户访问权限;强制新用户首次修改密码
7. **菜单/权限接口** — 增加 admin 权限校验
8. **SQL 报错** — 生产环境禁止返回详细异常信息

### 中优(P2)

9. **CORS 收紧** — 限制 `Access-Control-Allow-Origin` 为信任域名
10. **API Key 管控** — 增加审批流程和使用范围限制
11. **COS 桶安全** — 使用签名 URL;禁止匿名访问
12. **敏感信息脱敏** — 隐藏 createBy 字段;通知接口增加权限
13. **前端混淆** — admin 后台 JS 开启混淆;移除 source map

---

## 8. 测试工具

| 工具 | 用途 |
|------|------|
| curl + Python urllib | HTTP 请求/API 测试 |
| nmap + masscan | 端口扫描 |
| OpenSSL | SSL 证书分析 |
| Vision AI | 验证码 OCR 识别 |
| 自研 Python 脚本 | WAF JS 逆向/批量爆破/数据提取 |

---

## 9. 免责声明

本渗透测试在完全授权范围内执行,所有发现仅用于安全评估和改进建议。测试过程中:
- 未修改任何生产数据
- 未执行破坏性操作
- 未对第三方系统发起攻击
- 注册的测试账号建议测试完成后由管理员清理

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
