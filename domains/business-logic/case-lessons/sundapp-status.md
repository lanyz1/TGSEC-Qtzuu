# sundapp/usdc 渗透战报

- Source report: `STATUS.md`
- Full report: `domains/business-logic/case-reports/sundapp-status/sundapp-status.md`
- Techniques: wallet, payment, cred
- Fused: 2026-09-17

## Key findings (distilled)

- JWT: HS256, `type=user`
- 返回字段: `user` + **`jwt`** (HS512, `type=customer`) + `refreshToken`
- 常见弱口令未中
- JWT 常见 secret 伪造失败；none 算法失败

## When to reuse

- 同类标签命中：wallet, payment, cred
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
