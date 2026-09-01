---
name: 401-403-bypass
description: "401/403 访问拒绝绕过与 Spring MVC .do 鉴权绕过方法论。当遇到管理后台、API 端点返回 401/403 Forbidden、Spring MVC .do 接口鉴权绕过、302 登录跳转（login_tologin.do）、越权注册（registersysuser、goedituser）等场景时使用。覆盖路径操纵、HTTP 方法篡改、Header 注入、协议降级、.do 后缀鉴权绕过、302 跳转绕过、组合攻击"
metadata:
  tags: "403,401,bypass,forbidden,绕过,路径操纵,method override,X-Original-URL,X-Forwarded-For,access control,权限绕过,spring,mvc,.do,鉴权,302,login_tologin,registersysuser,goedituser,越权,注册,鉴权绕过"
  category: "exploit"
---

# 401/403 绕过方法论

核心思路：反向代理/WAF 检查一种路径格式，但后端做了不同的路径规范化。

## 深入参考

- 路径操纵 Payload 完整列表 → [references/path-manipulation-payloads.md](references/path-manipulation-payloads.md)
- HTTP 方法/Header 绕过 → [references/method-header-bypass.md](references/method-header-bypass.md)
- 中间件特定绕过与组合攻击 → [references/middleware-combo-bypass.md](references/middleware-combo-bypass.md)

---

## 决策树

```
遇到 401/403？
├── 1. 路径操纵（成功率最高）
│   ├── /path/ → /PATH → /path%20 → /./path → //path
│   ├── /path;x → /path..;/ → /%2e/path → /path%00
│   └── 200？→ 绕过成功
├── 2. 方法绕过
│   ├── POST/PUT/PATCH/DELETE/OPTIONS/HEAD
│   ├── X-HTTP-Method-Override: PUT
│   └── PROPFIND/自定义方法
├── 3. Header 绕过
│   ├── X-Original-URL: /path（Nginx/IIS）
│   ├── X-Forwarded-For: 127.0.0.1（IP 白名单）
│   └── Referer/Origin/Host 伪造
├── 4. 协议绕过
│   └── HTTP/1.0
├── 5. 组合攻击
│   └── Method + Path + Header 三合一
├── 全部失败 → 其他思路
│   ├── 请求走私 → cache-poisoning-smuggling
│   ├── SSRF → ssrf-methodology
│   ├── IDOR → idor-methodology
│   └── 认证逻辑 → privilege-escalation-web
└── 自动化扫描 byp4xx / 403bypasser
```

---

## 快速参考 — 路径操纵要点

| 技巧 | 示例 |
|------|------|
| 尾部斜杠/点 | `/admin/`  `/admin/.` |
| 大小写 | `/Admin`  `/ADMIN` |
| URL 编码 | `/%61dmin`  `/admi%6e` |
| 双重编码 | `/%2561dmin` |
| Unicode 过长编码 | `/admi%C0%AE` |
| 点段/路径穿越 | `/./admin`  `//admin` |
| NULL 字节 | `/admin%00`  `/admin%00.json` |
| 路径参数 (Tomcat) | `/admin;foo`  `/;/admin` |
| 反斜杠 (IIS) | `/admin\` |

## 快速参考 — 方法/Header 要点

| 技巧 | 示例 |
|------|------|
| 方法切换 | `POST /admin`  `PUT /admin` |
| Method Override | `X-HTTP-Method-Override: PUT` |
| URL 重写 | `X-Original-URL: /admin` |
| IP 伪造 | `X-Forwarded-For: 127.0.0.1` |
| 协议降级 | `GET /admin HTTP/1.0` |

## 中间件速查

| 服务器 | 关键技巧 |
|---|---|
| **Apache** | `/admin/`(尾部斜杠), `/.admin`(点前缀) |
| **Nginx** | `/Admin`(大小写), `X-Original-URL` |
| **IIS/ASP.NET** | `/admin;.css`, `/admin\`, `/admin::$DATA` |
| **Tomcat/Java** | `/admin;foo`, `/admin..;/`, `/;/admin` |
| **Spring** | `/admin.anything`(旧版后缀匹配) |

> 完整 payload 列表见 references 文件

## Spring MVC `.do` 鉴权绕过与 302 登录跳转

Java 政务/企业系统常见 `*.do`（Spring MVC）接口，鉴权实现差异常导致绕过：

```
请求 .do 接口 → 302 跳转登录页 (login_tologin.do)
├── 1. 去掉 .do 后缀重试：/user.do → /user
├── 2. 加后缀绕过：/user.do → /user.do/、/user.do;.css、/user.do?x=
├── 3. 大小写/编码：/User.do、/%75ser.do
├── 4. 方法切换：GET → POST → PUT
├── 5. 直接带参数访问：login_tologin.do 类登录/注册入口无鉴权时
│   └── 尝试未授权调用 registersysuser / goedituser 类注册、改用户接口
├── 6. 302 响应分析：Location 中泄露内部路径/参数
└── 7. Cookie/Session 复用：登录接口 302 后 Set-Cookie 未校验
```

- `registersysuser`（注册用户）、`goedituser`（编辑用户）等接口名在生产环境中常见，若未鉴权即可未授权注册/修改用户（越权注册），测试时先确认接口存在再验证权限。
- 判断标准：不携带登录态访问受保护接口，若返回业务数据/成功操作而非 401/403/302，则鉴权失效。

## 国产/Java 系统鉴权绕过速查

| 场景 | 尝试 |
|------|------|
| Spring MVC `.do` 接口 | 去后缀、加后缀、大小写、方法切换 |
| 302 登录跳转 | 分析 Location、直接访问业务接口 |
| 注册/改用户接口 | registersysuser、goedituser 未鉴权调用 |
| 白名单路径 | `/api/health` 前缀 + 路径穿越 |

