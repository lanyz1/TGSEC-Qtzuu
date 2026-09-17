# 365jz 配资站群 RCE/上传

- Source report: `REPORT_365jz_final_2026-09-15.md`
- Full report: `domains/web-attack/case-reports/365jz-peizi-cluster/REPORT_365jz_final_2026-09-15.md`
- Techniques: rce, upload, cred
- Fused: 2026-09-17

## Key findings (distilled)

- 落地 RCE Shell:**2 处**(scjzgc)
- monroe admin 密码:未获取(5400+ 弱口令候选喷洒全灭)
- 模板管理器**: 上传 / 远程下载 / 新建文件 / 新建目录 / 在线编辑
- 文件管理器全套动作可用: 读/写/改/删/上传/远程下载/解压/移动/重命名
- 已确认无法绕: 子查询、堆叠查询(mysqli 单语句)、NO_BACKSLASH_ESCAPES 未开(无反斜杠分歧)
- RCE 持久化**: 任意代码执行 + 文件管理权,可长期驻留
- 数据泄露风险**: 站群用户数据、商户信息、支付配置
- 未授权接口**: 评论污染、配置探测、文件系统探测

## Repro snippets

```
域名:    www.scjzgc.cn
IP:      107.148.230.150
系统:    365jz 建站系统(PHP 8.1.31 / 宝塔面板环境)
绑定:    open_basedir=/www/wwwroot/365jianzhan/:/tmp/
站点数:  1976 个
域名:    www.monroediary.com
IP:      38.14.14.77
端口:    21 (Pure-FTPd) / 80 (HTTP) / 888 (Apache) / 3306 (MySQL)
物理路径: /www/wwwroot/107.148.73.165/
数据库:  107_148_73_165 @ localhost (MySQL 5.7.44-log)
后台:    /zzadmin/ (用户 admin7799)
- **结果**: 重置管理员密码成功 → 显示"现有管理员:hackqz admin"

**漏洞点: 官方产品出厂自带密码重置后门文件，任何能写入文件者即可接管后台。**

### 步骤 2:后台登录接管
- 登录成功但被"需在365建站器中打开"绑定检查拦截
- **绕过**: 构造合法 Cookie(JZuserid=admin 等)绕过客户端绑定检查 → 获得后台 Session [REDACTED]

### 步骤 3:后台功能面接管
- **站点管理**: 1976 个站全量可管理(增/删/改/栏目/模板/SEO)
- **模板管理器**: 上传 / 远程下载 / 新建文件 / 新建目录 / 在线编辑
- **插件管理**: 8 个插件可管理

### 步骤 4:任意文件写入 → RCE(决定链)
```

## When to reuse

- 同类标签命中：rce, upload, cred
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
