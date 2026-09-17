# 趣她&智信选伴完整测绘

- Source report: `完整测绘报告.md`
- Full report: `domains/recon/case-reports/quta-zhixin-mapping/完整测绘报告.md`
- Techniques: recon, idor, waf
- Fused: 2026-09-17

## Key findings (distilled)

- 发现 /v1/test/ 未授权端点
- 微信支付商户账单拉取
- 支付宝数据**：API 仅暴露微信支付商户配置，支付宝商户凭据未在任何端点泄漏

## Repro snippets

```
#### 2.1.3 `/v1/test/pay` — 微信支付商户全量凭据泄漏

每次请求随机返回一个商户配置（轮询方式），通过多次请求可提取全部商户：

| 商户名称 | 商户号 | AppID | API Key |
|---------|--------|-------|---------|
| 科轩2青汐恋 | 1740995963 | wxee3acc6d06398c50 | `m9CiGyyByv7rPkULQEHSef5tsJtTMUoV` |
| 科轩5幽爱 | 1742188993 | wxf47e9381e5352ec6 | `m9CiGyyByv7rPkULQEHSef5tsJtTMUoV` |
| 可轩3qt | 1108865395 | wx5c5c6bce31829c9c | `m9CiGyyByv7rPkULQEHSef5tsJtTMUoV` |
| 科轩1幽雅 | 1107788372 | wx4623ff1eb1381615 | `m9CiGyyByv7rPkULQEHSef5tsJtTMUoV` |
| wxgfsy1sy | 1114691046
### 4.2 全平台交易汇总

| 指标 | 数值 |
|------|------|
| 总成功交易 | **5,051 笔** |
| 总退款 | 17 笔（¥609.60） |
| 总成交金额 | **¥430,824.93** |
| 独立付费用户（OpenID） | **1,911 人** |
| 数据覆盖天数 | 11 天（2026-08-22 ~ 2026-09-01） |
| 日均交易笔数 | **459 笔** |
| 日均交易金额 | **¥39,166** |

### 4.3 交易类型分布

| 商品名称 | 说明 |
|---------|------|
| 首充 | 首次充值优惠套餐 |
| 金币充值 | 常规金币充值 |
| VIP | 会员订阅 |

### 4.4 充值套餐（从 `/v1/user/recharge/index` 提取）

| 套餐 ID | 价格(¥) | 金币数 | 折算 |
|---------|---------|--------|------|
| 57 | 28.80 | 2,016 | 70 币/¥ |
| 49 | 6
### 5.13 其他服务凭据

| 服务 | Key / ID | 用途 |
|------|----------|------|
| 极光推送 (JPush) | AppKey: `76c0f16de29a2e99bbc69b70` | 消息推送 |
| OpenInstall | AppKey: `u04kst` | 渠道归因 |
| 腾讯 IM SDK | App ID: `1600030942` | 即时通讯 |
| ZEGO SDK | App ID: `2077629466` | 音视频通话 |
| Apple App Store | ID: `6740605050` | iOS 应用 |

### 5.14 数据库结构（SQL 泄漏 + MySQL 直连）

已接管数据库：`yuanban_admin`（52 表）/ `yuanban_api`（454 表）/ `yuanban_agent_info` / `yuanban_organization`，共 **589 张表**。

核心表：

| 表名 | 已知字段 | 用途 |
|------|---------|
```

## When to reuse

- 同类标签命中：recon, idor, waf
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
