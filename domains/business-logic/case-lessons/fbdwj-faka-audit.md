# FB 账号发卡站 fbdwj 评估

- Source report: `FBDWJ_安全评估报告.md`
- Full report: `domains/business-logic/case-reports/fbdwj-faka-audit/FBDWJ_安全评估报告.md`
- Techniques: payment, cred, auth
- Fused: 2026-09-17

## Key findings (distilled)

- 订单与卡密（secret）批量泄露**（前台查单接口未授权）
- 后台写操作未授权**（配置/分类/订单模块的 del、edit 类接口在无登录态下仍返回业务 JSON）
- 订单字段可被未授权篡改**（含 `secret` 等字段，已用无害标记验证读写闭环）
- 后台存在可枚举的管理员用户名（如 `admin` / `Admin` 返回「密码错误」类差异），存在口令攻击面（本轮常见弱口令未命中，**未取得后台会话**）
- 所有 `/admin/**` 写接口统一 **Session/JWT 鉴权 + 角色校验**；未登录一律 401/登录页，禁止业务 JSON。
- [ ] 支付回调验签、幂等与金额二次校验

## When to reuse

- 同类标签命中：payment, cred, auth
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
