# 案例课：未授权发码 + forget 改密（xmnyme 家族）

> 脱敏。来源战报包 `REPORT_20260922_2007.md` / xmnyme·kaixinmi·memxexus。

## 模式

用户面两口无鉴权串起来就能接管任意邮箱号：

```text
POST /api/notify/send_email  type=2 + cookie 会话
→ 邮箱收到码（或自有邮箱可控）
→ POST /api/user/forget_password
   account / new_password / auth_code / secondary_password / type=email
→ 登录拿 token
```

后台另面：`POST /admin/admin/login`（username/password/auth_code 谷歌）常 **429**；禁喷密。Charge 页 `proofImg` 可种存储 XSS，等运营审充值才可能带 cookie。

## 指纹

`admin.<brand>/admin/admin/login`；`/api/notify/send_email`；`forget_password` + `secondary_password`。

## 检查清单

- [ ] `send_email` type=2 是否免登录？
- [ ] forget 是否只校验码、不校验旧密/登录态？
- [ ] 后台 429 后立刻停喷，转 forget/XSS
- [ ] XSS 是否真有运营审图（webhook 无 hit = 没开火）

## 修复

发码绑定登录态+图形闸+频控；forget 要二次确认登录后会话；后台独立限速按账号不是只按 IP。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
