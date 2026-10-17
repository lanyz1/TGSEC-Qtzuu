# Magento 2 建号绕过：X-ReCaptcha 头 + REST/表单逻辑不一致

- Source: `(fs campaign 2026-10-16)`（原文留本机案卷，不入库）
- Techniques: magento2, recaptcha-header, rest-api, graphql, signup-bypass
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

## 目标
- 三家 Magento 2 店面：`www.cigarauctioneer.com`（拍卖店）、`www.famous-smoke.com`（主站生产）、`dev.famous-smoke.com`（开发镜像，独立库）
- 授权评估，目标为**前台会员账号**，非管理后台

## 技术栈
- Magento 2（REST `/rest/V1/*` + GraphQL + 传统 `createpost` 表单）
- reCAPTCHA v2 invisible（widget-1）
- 主站另有 WordPress 6.2.14（careers 子域）+ Cloudflare managed WAF + Wordfence 7.10.2
- 第三方 SaaS：QRTRAC（qr 子域）、Postman 托管页、Webscale（staging）

## 攻击链
页面预热 → 页内 mint widget-1 invisible token → 带 `X-ReCaptcha` 头 POST `/rest/V1/customers`（含 `custom_attributes`：竞价昵称/生日）→ 账号即时创建（**无需信用卡、无需邮箱确认**）→ 欢迎邮件含 `createPassword` 链接 → 设密并 XHR 登录验证 → 账户中心可见 Payment Methods / Store Credit / My Subscriptions（未深入）

## 可复用原语
1. **`X-ReCaptcha` 头 + widget-1 invisible token**（约 2,600–2,745 字符，页面预热后 mint，2 分钟内使用）被 REST 与 GraphQL 同时接受 ⇒ 绕过人机校验而不需求解。
2. **REST 与表单逻辑不一致**：`/rest/V1/customers` 不要求信用卡、不发确认邮件；卡逻辑只存在于 `createpost` 表单路径 ⇒ 找“旁路入口”优于正面刚表单。
3. **`custom_attributes` 可自带业务字段**（竞价昵称、生日）⇒ 建号即完成业务画像，不必二次补全。
4. **GraphQL 建号同样免确认**：换协议常绕过前端校验。
5. **Dev 环境三连**：dev REST 无 recaptcha；`createpost` 容忍垃圾 nonce；developer mode 泄露 stack trace（应用根 + 模块名）。
6. **欢迎邮件的 `createPassword` 链接** = 免邮箱确认的设密通道（token 在 URL 参数）。
7. **死路清单（避免重复投入）**：`/cards/test/create` 生产禁用（配置守卫）；Wordfence `/authenticate` nonce 绑定 `wp_salt('auth')` 不可伪造；Yoast `get_head` 仅内部渲染无 SSRF；wp2shell 被 CF managed WAF + Wordfence 挡。

## 数据战果
- 会员账号 **5 个**（拍卖店 1、主站 1、dev 3 含早期 1），全部双通道验证（REST/GraphQL 建号 + 浏览器登录）
- 一次性邮箱 **1 个**（mail.tm，Tor 代理轮询收信）
- 账户中心功能面测绘：订单 / 地址簿 / 订单偏好 / 账户信息 / 支付方式 / 店铺余额 / ID / 订阅

## 缺口
- 无管理员权限、无订单/支付数据、无 SSRF/RCE
- WP 线全死（WAF + Wordfence）；QRTRAC/Postman/Webscale 均为第三方或停放
- `/rest/V1/fss_coupon/validate`、`/rest/V1/sitevibes/data` 为待跟进候选，未验证

## 敏感物（类别+数量，不含值）
- 会员账号凭据 5 组（分布于 3 个店面）；一次性邮箱凭据 1 组
- 密码重置 token 2 个；客户 ID 5 个
- 无支付卡、无管理员凭据

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/web-security/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
