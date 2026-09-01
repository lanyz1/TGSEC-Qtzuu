---
name: skill-arsenal
description: "Use when needing pentest skills across 17 attack categories."
version: 1.0.0
---

# Skill Arsenal (local) — /www/wwwroot/skill

## Part 1: CDN溯源 + WAF检测方法论

| File | Lines | Description |
|---|---|---|
| `SKILL.md` | 1477 | CDN/WAF真实IP溯源手册 v4.0 — 26种溯源方法,组合拳,完整命令,厂商IP段 |
| `waf检测技能.md` | 117 | WAF检测验证方法论 — L0-L3四级风险,多信号指纹,证据闭环 |

### CDN溯源核心方法(26种,推荐组合拳: crt.sh→子域名→历史DNS→FOFA→Host头验证)

crt.sh证书查询(85%) · 子域名枚举(80%) · 历史DNS(75%) · FOFA/Shodan(70%) · CNAME追踪(70%) · CDN IP范围反查(65%) · SPF邮件(60%) · MX关联(55%) · Host头验证(55%) · 第三方ID(50%) · 网站功能泄露(50%) · ICP备案(45%) · XML-RPC Pingback(40%) · 邮件头(40%) · Favicon哈希(35%) · IPv6(25%) · 区域传送(15%) · AltDNS(45%) · 多DNS交叉验证(60%) · CSP/CORS泄露(40%) · 回源IP段(55%) · JS/API泄露(45%) · 被动DNS聚合(80%) · CA分析(50%) · HTTP重定向链(35%) · 批量Bypass字典(80+模板)

### WAF检测四级风险

L0=离线分析(不发包) · L1=低频基线(授权后) · L2=非破坏性规则验证 · L3=协议变体绕过(单变量)

## Part 2: 实战渗透报告(19份)

| Report | Vulns | Key Techniques |
|---|---|---|
| `独角BUG.md` | 支付伪造 | 独角数卡PHP签名=merchant_id,无IP白名单/重放保护,GET直接调 |
| `漏洞利用完整证明报告.md` | Werkzeug RCE | NoSQL注入触异常→弹出调试器→EVALEX代码执行→70万+数据泄露 |
| `Dujiao_Next_支付模块.md` | 1元购(三重缺陷) | ①回调不校验金额 ②钱包扣款幂等键静态 ③旧支付链接未作废 → 999元余额循环利用 |
| `HushChat-S3渗透测试报告.md` | S3存储桶泄露 | Cognito身份池硬编码→匿名获AWS凭据→11桶23.5万+用户对象 |
| `176.122.161.117-渗透审计报告.md` | 多漏洞 | RCE/CORS/CSRF/弱口令/注入/信息泄露 |
| `2026-07-23_VI钱包后台-完整控制报告.md` | JWT/密钥泄露 | 钱包后台完整控制链 |
| `507mx_vulnerability_report.md` | 多漏洞 | RCE/SSRF/注入/越权/信息泄露 |
| `711tock_审计报告.md` | IDOR/JWT/XSS | TG云控平台审计 |
| `715TG云控_全周期审计报告.md` | JWT/泄露 | 云控平台全周期审计 |
| `85amz_渗透测试报告.md` | RCE/支付 | 验证码绕过+支付逻辑 |
| `AUDIT-REPORT.md` | JWT/RCE/SSRF | 弱口令/默认口令链 |
| `BadHost_LiteLLM_报告.md` | LiteLLM | CORS/注入/LiteLLM漏洞 |
| `TG筛号平台-渗透测试报告.md` | 越权/泄露 | TG筛号平台审计 |
| `TG运营集群-综合渗透报告.md` | JWT/S3/SSRF | 运营集群多目标链 |
| `max77.plus-渗透测试报告.md` | 多漏洞 | RCE/SSRF/IDOR/越权/逻辑 |
| `peiioh_20260819_完整报告.md` | IDOR/JWT/RCE | 乐视会议分发链审计 |
| `渗透测试报告-183.179.252.26.md` | 多漏洞 | RCE/SSRF/支付/越权 |
| `综合渗透测试报告-全目标.md` | 多目标链 | JWT/LiteLLM/SSRF/文件上传 |
| `萝卜快测平台-渗透测试报告.md` | 多漏洞 | IDOR/RCE/未授权/支付 |

## Key Attack Techniques (from reports)

1. **Werkzeug RCE**: NoSQL注入触发`'dict' object has no attribute 'strip'` → 异常弹出Werkzeug调试器 → frame内eval执行 → 数据库/Credit窃取
2. **独角数卡支付伪造**: 签名密钥=merchant_id(公开) → 自算签名 → GET回调伪造(order_sn+payId+type+price+reallyPrice+merchant_id) → md5
3. **Dujiao-Next 1元购**: ①余额扣款幂等键静态(可重置) → ②切换渠道释放余额 → ③旧支付链接未作废 → 1元实付履约全额订单
4. **S3桶匿名访问**: 逆向APK/iOS获取Cognito身份池ID → 两步POST获AWS临时凭据 → List/Get/Put/Delete S3对象
5. **CDN溯源组合拳**: crt.sh证书查询→子域名枚举→历史DNS→FOFA/Shodan→Host头验证,成功率95%+

## Usage

```
# Load CDN溯源手册
read_file(/www/wwwroot/skill/SKILL.md)

# Load WAF检测方法论
read_file(/www/wwwroot/skill/waf检测技能.md)

# Load a pentest report for experience
read_file(/www/wwwroot/skill/<report-name>.md)
```

## Notes

- SKILL.md = CDN/WAF溯源手册(26方法, 1477行, 56KB)
- waf检测技能.md = WAF检测验证方法论
- Reports = 实战渗透测试经验,含攻击链+PoC+修复建议
