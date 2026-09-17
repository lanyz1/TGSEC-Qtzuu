# 萝卜快测/灵动空号检测

- Source report: `萝卜快测平台渗透测试报告.md`
- Full report: `domains/api-security/case-reports/luobo-lingdong-konghao/萝卜快测平台渗透测试报告.md`
- Techniques: idor, upload
- Fused: 2026-09-17

## Key findings (distilled)

- 影响**: **严重 PII 泄露** — 约 2 万+ 条记录, 估算涉及数亿条手机号数据; 任意人可枚举 ID 批量下载客户检测的手机号文件。同时泄露服务器路径 `/home/ruoyi/uploadPath/` (确认 RuoYi 部署)。
- `datasource.json`: `jdbc:mysql://127.0.0.1:33306/number-check-mini` (用户 `root`)
- `sql.json`: 完整 SQL 历史 (RuoYi 全表结构: `sys_user`, `sys_oper_log`, `sys_job_log`, `sys_file`, `customer_chat_message`; 观察到 1594 次文件上传、13672 次定时任务执行)
- `GET /number-check/portal/selectContentList?pageSize=100` → 未鉴权返回 90 条内容记录 (含 `/profile/upload/YYYY/MM/DD/` 上传路径)
- 影响: 上传目录下文件可直接获取 (含可能的用户上传号码文件)
- 计费/支付: `t_recharge_log`(金额/token/订单), `t_self_recharge`, `t_expense_detail`
- C1 (紧急)**: `/system/screenlog/{id}` 及 ZIP 下载 (`/profile/upload/`) 必须强制鉴权 + 访问控制 (仅记录属主可读); 对 screenlog ID 枚举限速; 上传文件随机化路径并即时清理。**当前为可批量导出手机号数据的严重泄露**
- M3/M4**: 对 `/system/*`, `/portal/*` 增加鉴权; 上传文件随机化文件名

## Repro snippets

```
luobokuaice.com (8.145.48.174)  —— 静态营销站点, nginx catch-all 200, 全部路径返回首页
        │  首页 JS 将核心功能指向 ↓
lingdongdata.com (8.130.145.115) —— 主平台
        ├─ /number-check/   —— RuoYi-Vue 3.8.6 后台 API (Spring Boot, Tomcat 9.0.90, Java 1.8.0_152)
        │     ├─ /admin/    —— 管理控制台 (登录页)
        │     ├─ /druid/    —— Druid 监控控制台 ★
        │     ├─ /swagger-ui/, /v2/api-docs —— Swagger API 文档 ★
        │     ├─ /front/*   —— 客户前台 API (sendCode/login/userlogin, 需鉴权)
        │     └─ /portal/*, /system/*
```

## When to reuse

- 同类标签命中：idor, upload
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
