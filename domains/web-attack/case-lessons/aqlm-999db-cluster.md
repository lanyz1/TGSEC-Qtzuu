# 案例课：aqlm / 999db 同运营者集群（TP 上传 RCE + TGBot webhook SQLi + PPay SSRF）

> 脱敏。来源 `漏洞汇总报告.md`。栈混杂，**不单开 Skill**：上传走 file-vulns；若依走 ruoyi 课；CF Access 走 `cf-hidden-origin-tracing`。

## 模式

同一运营者挂：卧龙 TG 后台、频道转发 Bot、WordPress 朝家、PPay 钱包、RuoYi-Plus 股票、ThinkPHP dms、Pritunl。

高 ROI 三刀：

```text
1) ThinkPHP dms  POST /index.php/api/images/upload  字段 file
   无登录、扩展名不校验 → /uploads/pz/<Ymd>/<md5>.php
   disable_functions 可能拦 shell_exec，mysqli/curl 仍能读 .env

2) TGBot  POST /forward/telegram/api/webhook?secret=<任意>
   secret 不校验；chat.title / from.username 时间盲注；伪造 /start 可写会员

3) PPay  notifyUrl SSRF（商户凭据）跟随 302 → 内网/云元数据
   回调无 timestamp/nonce → 重放；空值字段被签名剔除
```

旁路：RuoYi `admin/admin123` + Druid `ruoyi/123456`；WP 源站直连绕 Cloudflare Access；Jet 模板未授权读。

## 坑

- 字段名可能要爆破（本例 `file`，1035 组）
- 对方删 `/uploads` 树会把通道被动掐死，不代表洞修了
- 老 PPay 下线不等于新 `openapi.` 安全
- 弱口/验证码 OCR 不是开局首选；有未授权上传/SQLi 先打那些

## 检查清单

- [ ] `/api/images/upload` 免登录？扩展名？
- [ ] webhook secret 是否任意字符串？
- [ ] notifyUrl 是否跟随 302 / 内网？
- [ ] CF Access 是否源站 IP 直连就没了？

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
