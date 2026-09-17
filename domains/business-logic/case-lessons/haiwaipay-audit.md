# 海外严选 haiwaipay 审计

- Source report: `HAIWAIPAY_SECURITY_AUDIT_REPORT.md`
- Full report: `domains/business-logic/case-reports/haiwaipay-audit/HAIWAIPAY_SECURITY_AUDIT_REPORT.md`
- Techniques: sqli, auth, idor, cred
- Fused: 2026-09-17

## Key findings (distilled)

- 客服后台登录**（弱口令）
- 跨用户订单发货内容读取**（IDOR）
- 订单详情强制归属校验**（IDOR）。
- 密码存储改为 bcrypt/argon2；轮换 JWT/缓存密钥与 session 机制。
- 安全测试回归：登录 scene 矩阵、IDOR 矩阵、注入矩阵。
- 卡密以明文（或等价明文）存在业务表**，一旦 SQLi 即全资产沦陷。

## Repro snippets

```
[1] 侦察
    DNS/IP → 8.134.121.100
    指纹 likeadmin/likeshop + TP 6.1.4
    3306 暴露 / 后台子域发现

[2] 初始访问
    A. kefu01/888888 → kefuapi
    B. scene=3 → 任意注册用户 shop token

[3] 权限扩大 / 横向
    kefu 枚举 user_id → 手机/邮箱列表
    scene=3 批量接管高价值用户（余额、历史单）
    订单 IDOR → 他人 delivery_content

[4] 深度数据窃取
    shopapi goods/lists 列名注入
    → 库名/表/virtual 全量 HEX dump
    → admin 哈希、session、order 字段

[5] 影响
    未售库存 157 + 全库有内容卡密 2392 外泄
    用户 PII（手机邮箱）规模泄露
    业务核心资产（虚拟卡）失去保密性
```

## When to reuse

- 同类标签命中：sqli, auth, idor, cred
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
