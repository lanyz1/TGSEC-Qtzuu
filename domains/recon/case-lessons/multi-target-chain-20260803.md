# 多目标攻击链综合（08-03~04）

- Source report: `综合渗透测试报告-全目标.md`
- Full report: `domains/recon/case-reports/multi-target-chain-20260803/综合渗透测试报告-全目标.md`
- Techniques: ssrf, upload, payment
- Fused: 2026-09-17

## Key findings (distilled)

- ✅ **完整账号接管链确认**:公开注册 → 角色提权 → 越权读 15144 账号 → 会话导出
- ❌ 管理端 403(JWT 强密钥 + 角色校验)
- 精客云**:立即改 admin/admin;后台加限速/IP 白名单;修 PHP 上传;换 /admin 前缀

## Repro snippets

```
laravel-admin 默认口令 admin/admin → /admin 完整后台接管
→ 全量用户手机号 + 积分余额 + 真实金额订单
→ 管理员创建成功(提权/持久化)→ 已清理
→ PHP 文件上传接受(CVE-2020-11427,存储未公开)
```

## When to reuse

- 同类标签命中：ssrf, upload, payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
