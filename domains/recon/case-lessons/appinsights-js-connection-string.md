---
title: "Azure App Insights 连接串 JS 泄漏（recon + 遥测滥用链）"
type: case-lesson
tags: [recon, javascript, azure, appinsights, secrets, telemetry]
date_created: 2026-10-06
sources: ["https://x.com/luckyhacker43/status/2073424121426288714", "https://thedailyscout.com", "https://learn.microsoft.com/azure/azure-monitor/app/connection-strings"]
---

# Azure Application Insights 连接串 JS 泄漏

> 来源：@luckyhacker43（2026-07-04 演示，三步链）· thedailyscout 报道 · MS 官方文档定性。
> 本质：客户端 JS 里的 `connectionString`（InstrumentationKey + IngestionEndpoint + ApplicationId）**按设计就是公开的**；
> 但"不是密钥"≠"无风险"—— 它是**遥测管线地图 + 可写入端点**。

## 发现手法

```bash
# 任意前端 JS / bundle 里找
grep -rE "InstrumentationKey|IngestionEndpoint|connectionString" js/
# 常见形态
"connectionString": "InstrumentationKey=xxxxxxxx-...;IngestionEndpoint=https://westus2-2.in.applicationinsights.azure.com/"
```

配合全站 JS 扫描（jsowl / SourceDetector / jsluice 等）可批量面。命中 = 资源标识 + 接入端点全暴露。

## 滥用链（luckyhacker43 三步）

1. **探测**：以泄漏连接串构造 ingestion 端点请求，测试资源是否接受**未认证遥测**。
2. **批量写入/提取**：向 ingestion 端点发送自定义 trace/event/metric → **污染监控、投喂假数据**（对 SOC 是投毒面）；若周边控制薄弱，可进一步借 ApplicationId / REST API 枚举资源数据（报道称 "telemetry-linked data pulls"，未独立复现）。
3. **出报告**：生成 JSON 报告（受影响资源 + 证据）→ 通知厂家。

## MS 官方立场（定级关键）

- ikey **不是安全令牌**；连接串设计上会嵌在客户端 → "泄漏"本身不判高危。
- 官方防护 = **Entra ID 认证遥测摄入**（authenticated ingestion）+ 浏览器遥测资源与服务端敏感资源**分离**。
- 即：允许的滥用面（伪造遥测 / 资源测绘）靠**架构收敛**，不靠"藏 key"。

## 判据 / 定级建议

- 找到 connectionString = recon 价值（资源测绘）→ 单条信息泄露一般不够 High。
- 证明能**写入遥测**（污染监控）→ 讲"监控投毒 + 供应链信任"故事提影响。
- 反面教材：不要按"密钥泄露"报 —— 会被 MS 按 by-design 关闭。

## 反制

- Entra 认证摄入；资源隔离；前端资源不放敏感遥测；定期扫自家 bundle 去重。
