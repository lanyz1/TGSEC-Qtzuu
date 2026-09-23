# 案例课：2FA 逻辑绕过 13 条（learn365 / 微信译文补全）

> 本地原先散落在 `logic-flaw-patterns.md` §2、`security-arsenal` MFA Payloads、`src-hunter` `auth-2fa`。**本文补的是那些卡没有写成检查项的条目。** 不开新 Skill。

活靶碰到 OTP 闸：先跑本表，再决定要不要喷密。

## 本地已有（别重复蒸）

| # | 手法 | 已在 |
|---|---|---|
| 1 | `"success":false`→`true` | arsenal Pattern 3；src-hunter 响应篡改 |
| 2 | 4xx→200 | arsenal「401→200 / redirect」 |
| 3 | 响应回显 OTP | logic-flaw 2.2「响应泄露」 |
| 5 | 码复用跨会话 | arsenal Pattern 2；logic-flaw 令牌复用 |
| 6 | 4/6 位无限速 | arsenal Pattern 1；logic-flaw 2.5 |
| 7 | A 的码打 B | logic-flaw 跨账户 |
| 9 | 关 2FA CSRF | logic-flaw 2.6 CSRF/Clickjacking |
| 10 | 改密连带关 2FA | logic-flaw 2.4 |

## 本地原先缺 / 写得太浅（本课重点）

### 4. JS 写死测试码或生成逻辑

登录页 / `chunk-*.js` 搜：`otp` `verifyCode` `000000` `123456` `totp` `hardcode`。  
有的实现把测试码写进 `__DEV__` 分支但生产 bundle 没剥。拿到生成函数就本地算，别喷。

### 8. 空值 / `000000` / 固定值

OTP 口试：省略字段、`null`、`""`、`000000`、`123456`、`111111`。  
logic-flaw 只把空值写在 **CAPTCHA** 节，2FA 口要单独打。一次成功即停。

### 11. 备份码 = 重置通道，不只是爆破面

arsenal Pattern 5 只写「备份码空间小可喷」。还要测：

- 备份码用掉一次后能否再开「关闭 2FA / 换绑定」而**不再要 TOTP**
- `/api/mfa/backup` 是否未授权列举或 CORS 漏
- 备份码接口是否无 CSRF、无二次密码

### 12. 点击劫持关 2FA

logic-flaw 一句话带过。要真探：`X-Frame-Options` / `CSP frame-ancestors` 在 **关闭 2FA 的那一页**（常是 `/settings/security` 不是登录页）。登录页有框、设置页没框 = 可套 iframe。

### 13. 启用 2FA **不踢历史会话**（最容易漏）

本地三张 2FA 卡都没写这条。

```text
会话 A：密码过了、还没开 2FA → 拿 cookie
（XSS / 会话固定 / 共享电脑）
受害者之后才开启 2FA
会话 A 是否还活？心跳 / 轮询 / WS 保活能不能拖过 idle timeout？
```

要测：开 2FA 的接口成功后，**旧 cookie 打 `/api/me` 或业务写口**。还活 = 2FA 形同虚设。配合过宽的 session idle。

## 检查清单（OTP 闸）

- [ ] 响应 `success` / HTTP 码是否纯前端判
- [ ] JS 有没有测试码 / 生成函数
- [ ] 码是否绑 userId、是否一次性
- [ ] 空/`000000` 是否过
- [ ] 关 2FA 是否 CSRF + 二次确认 + 邮件
- [ ] 备份码能否当重置通道
- [ ] 设置页能否被 iframe
- [ ] **开 2FA 之后旧会话是否作废**

深手册：`domains/web-injection/web-method/business-logic-attack/references/logic-flaw-patterns.md` §2（已补 2.7）。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
