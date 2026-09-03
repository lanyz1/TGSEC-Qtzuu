# 身份层 + 反逻辑 · 统一作战手册

把下列文档当**一套**用，不要拆开只读一半：

| 顺序 | 文档 | 作用 |
|------|------|------|
| 0 | `recon/true-false-separation-recon.md` | 真假分离，找真后台 |
| 1 | `auth-security/session-crypto-identity-layer.md` | 算力别砸错（身份层 ROI） |
| 2 | `redteam-framework/anti-logic-layout.md` | A1–A6 并行开缝 |
| 3 | `business-logic/payment-config-crown-surface.md` | Crown/支付验证面 |
| 4 | 正逻辑登录/权限链 | 与 2 并行，汇合 token/写权 |

## 一页流程

```text
真假分离侦察
    ├─ 诱饵面：降优先级
    └─ 真后台 / API / 支付面
         ├─ 身份层评估（secret/JWT/HMAC/session）
         ├─ 正逻辑：账号口令/验证码/权限提升
         └─ 反逻辑 A1–A6：旁门并行
              └─ 汇合 → 授权范围内 Crown 验证
```

## Hermes

`skill_view(pentest-execution)` → `references/anti-logic-and-identity-layer.md`



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
