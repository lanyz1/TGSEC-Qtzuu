# 85amz RCE/上传/支付

- Source report: `85amz_渗透测试报告.md`
- Full report: `domains/web-attack/case-reports/85amz-rce-upload/85amz_渗透测试报告.md`
- Techniques: rce, upload, payment
- Fused: 2026-09-17

## Key findings (distilled)

- 支付密钥**（支付宝 RSA 私钥、阿里云短信密钥、磨泽付支付网关密钥等）
- 支付宝 RSA 密钥对（重新生成公/私钥）
- 配置加密存储**：支付密钥不应明文存入数据库，改用加密存储 + 环境变量
- 部署 WAF**：拦截 `updatexml`、`extractvalue`、`0x7e` 等 SQLi 特征
- 日志审计**：检查攻击期间日志，确认是否有他人利用该漏洞

## Repro snippets

```
GET /index.php/jingdian/detail/index/id/{payload}.html
GET /index.php/jingdian/detail/index/lmid/{payload}.html
**PoC（错误型注入，无需空格，用括号替代）：**
响应中的泄露：
```

## When to reuse

- 同类标签命中：rce, upload, payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
