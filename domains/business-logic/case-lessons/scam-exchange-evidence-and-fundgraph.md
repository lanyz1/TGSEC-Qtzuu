# 杀猪盘/假交易所 归因与资金图谱四件套课（订单溯源 · 邮件头 · 钓鱼统计 · 链上图谱）

- Source report: 报告包 20261012（HA8 战役档案 ATTRIBUTION / EMAIL_INTEL / PHISHING_EMPIRE / FUNDER_GRAPH / REPORT_UPDATE；**值零入库**）
- Techniques: attribution-chain, email-header-origin, phishing-estate-stats, onchain-fundgraph, evidence-discipline
- Fused: 2026-10-12

## 定位
杀猪盘/假交易所结案定性「你是谁」+「钱在哪」的组合方法论：四路证据源交叉，收敛到运营者身份 + 资金去向 + 犯罪链闭环。

## 四件套
1. **订单平台溯源**：E2ESOFT 类订单/CRM 平台 → 真名/手机/支付方式（充值订单是身份 × 支付通道的交叉点，比用户库更接近「实名」）
2. **邮件头泄源站**：邮件头的 Received/源 IP 线索 → 反查真实服务器（CF/WAF 正面硬时，邮件系统是侧门）
3. **钓鱼邮件全量统计**：品牌/地区/TOP 目标统计 → 「庞大钓鱼资产 + 定向目标」的量化呈现（黑产情报统计口径）
4. **链上枢纽→奖池图谱**：枢纽地址 → 转账图谱（50 tx 采样；`sum_out / sum_in` 口径）→ 资金流向 + 吞没率佐证

## 证据纪律（高频踩雷点）
- **「不转账、只固定证据」**：链上首触只做读取与快照，不做任何转移操作
- **缓存 vs 链上双重校验**：平台 API 余额可能是陈旧缓存 → 链上复核后多处奖池地址为 0/已搬空（口径差必须两源对齐）
- **资金卡点分层矩阵**：控制面 / 链路（归集服务）/ 签名机 / 私钥 四层分开列结论，禁止笼统宣称「资金面已失陷」
- 数字引用带文件名 + 日期（多稿口径不一致时不可跨稿合并）

## 对照
- `osint-methodology`（人员/组织面）· `xiaolanben-equity`（股权穿透）· `scam-exchange-platform-pentest`（**控制面 ≠ 私钥层** 铁律）

## When to reuse
杀猪盘/假交易所结案定性、黑产情报输出、资金面分层评估时，按四件套 + 三条纪律执行。

@TGSEC社区 · @TGSEC-Qtzuu 整理
