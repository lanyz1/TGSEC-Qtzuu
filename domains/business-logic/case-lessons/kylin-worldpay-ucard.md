# 案例课：Kylin / WorldPay 麒麟黑卡 — 会员票 IDOR → 超管

> 脱敏。无卡面/助记词/口令。来源 `kylin-v1.2.0_完整报告_20260922.md`。

## 模式

企业签 iOS 客户端（壳 `worldpay.app`，Bundle 伪装系统服务）+ `/ucard/` API。**作业机禁止安装 IPA**（内嵌内核 exploit）。

业务链：

```text
邀请码 KYLIN / 888888
→ GET /ucard/appUser/sendEmailCode  未授权发码
→ 会员 JWT
→ 全站读：walletLog / 卡列表 / uid 余额 / USDT 址 / 渠道 2FA
→ POST /ucard/channelUser/updatePwd 任意 JWT 改他人渠道密
→ POST /ucard/user/findList 拖后台表（MD5 + TOTP 种子）
→ 超管常 user=pass + 表内谷歌码
```

### 资金真假

账本合计可到百万级，**热钱包常空**。客服手动转入 ≠ 可提。助记词在破核 C2 ZIP（`gagagagag.com`），不在发卡 API。

### 不要混

- 不是 `white-label-pay-admin` 的 worldpaypp 跑分台
- 不是 DarkSword/Coruna 投递面板（另一条 iOS 链）

## 检查清单

- [ ] `sendEmailCode` 免登录？
- [ ] 会员票能否 `user/findList`？
- [ ] `updatePwd` 跨 userId？
- [ ] 账本 vs 链上是否对过？

## 修复

发码要鉴权；列表接口按 uid 强制本人；改密要旧密+角色；超管密码≠用户名；TOTP 种子禁止 API 回显。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
