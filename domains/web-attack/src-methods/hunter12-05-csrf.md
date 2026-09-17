---
source: test008008008008-glitch/web-security-skills
skill: 05-csrf
fused: 2026-09-17
method: 五步猎洞法
---

---
name: csrf
description: CSRF 跨站请求伪造实战手册。当目标存在无防重放校验的状态变更操作（改绑、转账、设置）时使用，覆盖 PoC 构造、SameSite/CORS 缺陷组合与绕过。
---

# 第五技 · CSRF —— 让用户的浏览器替你扣扳机

> 猎手视角：浏览器有一个诚实到危险的习惯——只要 Cookie 在，它就带。你要做的只是把"发射请求"这件事伪装得足够日常，让用户的点击替你完成。

**目标读者**：具备基础 Web 测试经验的安全工程师
**前置要求**：Cookie 工作机制、同源策略、HTML 表单与 fetch 基础

---

## 何时启用本技

- **状态变更类操作**：改密码/改邮箱（改完还能锁死原账号）、绑定手机、转账、下单、关注、授权
- 目标站**未带 CSRF Token**，或 Token 形同虚设（见对抗节）
- 目标 Cookie 无 `SameSite` 属性（现代浏览器默认 Lax，仍有豁免场景）
- 组合场景：XSS 拿不到 HttpOnly Cookie，但 CSRF 能**带着 Cookie 直接干活**

---

## 一、原理拆解

```
用户(已登录bank.com)          evil.example
   │                              │
   │◄── 用户点开 evil 页面 ───────┤
   │                              │
   ├─ evil 页里的 <img> 或自动提交表单
   │  发起: POST https://bank.com/transfer
   │  Cookie 自动附带（浏览器的"忠诚"）
   │─────────────────────────────→ bank.com
   │            转账完成，用户全程无感知
```

成立的三个条件：

1. 变更操作**仅凭 Cookie 鉴权**（无二次验证）
2. 请求参数**攻击者可完整构造**（转账金额、收款账号）
3. 攻击者能诱导用户的浏览器发出该请求（跨站表单/图片/链接）

---

## 二、五步猎洞法

### 第一步：识面 —— 盘点高危变更操作

把目标的"动作型 API"列全：`POST /api/password`、`/api/bindPhone`、`/pay/confirm`……按"影响资金、影响账号控制权、影响授权关系"排序。

### 第二步：定点 —— 检查请求里的"防重放指纹"

逐个请求检查：有无 `CSRF-Token` 头？Token 是否每次变化、是否服务端校验、是否与会话绑定？`Origin`/`Referer` 服务端是否校验？JSON 请求是否检查 `Content-Type`（跨站表单打不出 `application/json`）？

### 第三步：验证 —— 本地构造"不跨站"的最小复现

在**授权测试环境**，先自己模拟跨站条件：用本机另一端口页面发起目标请求，确认无 Token 拦截、服务端正常执行——证明请求"可被第三方伪造"。

### 第四步：利用 —— 构造真实 PoC

**自动触发型**（打开即中）：

```html
<form action="https://target.demo-example.com/api/bindEmail" method="POST">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit()</script>
```

**诱导点击型**（点击式游戏/按钮）：

```html
<img src="https://target.demo-example.com/api/follow?uid=8888" style="visibility:hidden">
```

GET 型变更接口（`?action=delete&id=`）属于设计级漏洞，一张图就够。

**JSON 接口的兼容打法**：表单 `enctype="text/plain"` 伪造报文体，配合后端宽松解析（老 Java/PHP 框架常见）。

### 第五步：收官 —— 影响评估

按操作性质分级：改绑类（账号接管）> 转账下单类（资金）> 关注点赞类（骚扰）。PoC 用自己的测试账号对测试账号演示，留录屏。

---

## 三、实战推演（虚构场景）

> 场景：授权测试虚构社区 `club.demo-example.com`，修改密码接口无 Token

1. **识面**：`POST /user/password` 参数仅 `newPassword`，无旧密码校验、无 Token
2. **定点**：抓包比对多账号会话，确认无会话绑定校验；Cookie 无 `SameSite` 标记
3. **验证**：本地起 evil 页面跨端口提交，密码修改成功
4. **利用**：PoC 改为改绑攻击者邮箱——受害账号可通过"忘记密码"被攻击者重置接管
5. **收官**：报告定级"CSRF → 账号接管"，修复建议：改密强制旧密码 + CSRF Token + SameSite=Lax 三层

---

## 四、对抗与绕过

| 防线 | 破解思路 |
|------|----------|
| Token 存在但不校验 | 删 Token 重放试试，大量框架"生成了但没验证" |
| Token 不绑定会话 | 用自己的 Token 配受害者的会话 |
| 校验 Referer | 删 Referer 头（部分配置空值放行）、子域 XSS 借道、`Referer: https://target.com.evil.example/` 拼接 |
| SameSite=Lax | **顶层导航的 GET 请求仍带 Cookie**——GET 型变更接口照样中；以及 2 分钟内的新会话豁免 |
| JSON + 严格 Content-Type | 找 XSS 组合；或 CORS 配置缺陷（`Access-Control-Allow-Origin` 反射任意 Origin + credentials）升级为跨域 fetch |
| CORS 反射 Origin | 直接 `fetch(url, {credentials:'include'})` 正大光明跨站 |

---

## 五、防御视角

1. **CSRF Token**：密码学随机、绑定会话、一次性、服务端强校验——四点缺一不可
2. Cookie `SameSite=Lax/Strict` + `Secure` + `HttpOnly`
3. 敏感操作**二次验证**（旧密码/短信码），Token 被偷也兜得住
4. 服务端校验 `Origin`（优先于 Referer，不可被隐私插件删除）
5. 变更接口一律 `POST/PUT`，拒绝 GET 改状态的设计

---

## 六、踩坑记录

- PoC 里目标地址写 `localhost` 本地测试没问题，交付报告时**换成目标域名**——忘了这一出，复现现场全场沉默
- `SameSite=Lax` 出来后很多人判"CSRF 死了"，但**顶层导航 GET 豁免**与**老浏览器存量**让 GET 型变更接口依然能打
- Token 在 Cookie 里（双提交模式）时，若整个站有 XSS，攻击者能读 Cookie 里的 Token——防御别只看一层
- 转账 PoC 金额写 `0.01`，别写 `9999`：授权测试的钱是真扣的
- 自动提交表单在 Chrome 有 PNA（私有网络访问）限制时，本地起 HTTPS 服务更稳

---

## 七、速查卡

```text
自动:   <form>+submit() 打POST | <img> 打GET变更
JSON:   enctype=text/plain 配宽松解析
绕过:   Token不校验 | 删Referer | SameSite的GET豁免
组合:   CORS反射Origin → fetch带credentials
判定:   改绑>资金>骚扰 分级写报告
防御:   Token(随机+绑定+一次性) + SameSite + 二次验证
```
