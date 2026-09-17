# maojuid-cn 发卡/支付审计

- Source report: `AUDIT-REPORT.md`
- Full report: `domains/business-logic/case-reports/maojuid-cn-audit/AUDIT-REPORT.md`
- Techniques: payment, cred, waf
- Fused: 2026-09-17

## Key findings (distilled)

- 攻击者可对 maojuid.com **任意在售商品**伪造支付并提取卡密。
- 支付平台其它商户密钥同样处于可读风险（同 admin 列表接口）。
- 主站常见弱口令

## Repro snippets

```
总结果： 【完全打穿】← 伪造 Epay 回调成功，query/secret 回明文卡密；独享 SKU 库存已控空
一句话： trade.yaorinet.com admin/123456 → 商户 MD5 key → 主站 callback.Epay 伪造支付 → 出卡
目标达成： 是
最高权限： 支付网关平台管理员 + 主站库存发卡控制（无主站 admin / 无命令执行）
未知洞标签： 已知洞利用（弱口令 + 商户钥签回调）
[trade.yaorinet.com]  --admin/123456-->  平台后台
        | 读商户列表
        v
  pid=1541070142 key=qdKBJaNLqvYiN8B6Xnf4ucmxyvmZsN
        | MD5 签 Epay notify
        v
[maojuid.com callback.Epay] --> status=1 发货 --> query 出 secret
T+0   指纹：异次元 v3.4.8；支付 handle=Epay；无预选卡
T+1   验证码 OCR 下单 → 支付页泄露 pid=1541070142 + notify + MD5 sign
T+2   sign:true / 弱 key notify → 非法签名（主站回调旁路失败）
T+3   换面 trade.yaorinet.com；Geetest v4 自动解算
T+4   POST /api/admin/login  admin/123456 → JWT [已验证]
T+5   GET /api/admin/merchants?keyword=1541070142 → 商户 key 明文
T+6   MD5 校验与支付页 submit sign 一致
T+7   伪造 form notify → callback.Epay 返回 success；query 出卡
T+8   独享 SKU 按库存伪造支付清空；item12 为共享交付链（排除出交付清单）
```

## When to reuse

- 同类标签命中：payment, cred, waf
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
