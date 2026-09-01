---
id: TECH-2026-5403
title: "AXFR/IXFR 区域传送边界"
kind: technique
track:
  - 授权渗透测试
platform:
  - 网络与协议安全
techniques:
  - DNS
  - DNSSEC
lifecycle:
  - 侦察
  - 验证
  - 复测
standards:
  - RFC-1995
  - RFC-5936
  - RFC-7766
  - RFC-9103
  - RFC-8945
source_id:
  - SRC-2026-5404
  - SRC-2026-5408
  - SRC-2026-5410
  - SRC-2026-5415
  - SRC-2026-5407
authorization: owned-authorized
confidence: verified
sensitivity: public
license: CC BY-SA 4.0
---

# AXFR/IXFR 区域传送边界

## 目标

用一次授权 TCP 请求验证区域传送是否只向预期二级权威开放。

## 授权范围

- 只测试书面授权列出的 zone 与权威地址。
- 每台权威最多一次 AXFR；IXFR 仅在已知合法 serial 时一次。
- 不得向第三方公开、复用或长期保存完整区内容。

## 前置条件

- 确认目标确为该区权威
- 记录测试源地址
- 确认是否预期 TSIG/mTLS/ACL

## 被动优先步骤

- 优先审阅 allow-transfer、TSIG、XoT/mTLS 和二级权威清单。
- 查看既有传送日志是否存在未知源或明文跨不可信网络。
- 确认测试源是否本来就被设计为授权二级权威。

## 最小主动验证

```bash
dig +tcp @"$AUTH" "$ZONE" AXFR
# 仅隔离实验或明确授权且已知 serial：dig +tcp @"$AUTH" "$ZONE" IXFR="$SERIAL"
```

**硬上限**：每台权威 AXFR 1 次；可选 IXFR 1 次；无重试、无并发。

## 必备证据

- TCP 会话与 RCODE
- 是否返回起止 SOA 及区数据
- 服务端传送审计日志
- 调用方身份

## 证据 Oracle

- REFUSED/NOTAUTH/认证失败支持边界有效，但仍需配置证据确认预期。
- 向未授权测试源返回完整区才构成暴露证据。
- TSIG 只提供认证与完整性；机密性需 XoT 或受信网络。

## 常见误报

- 测试源本就是授权二级权威
- 分裂视图区仅含公开记录
- 负载均衡节点策略未同步

## 停止点

返回第一份完整区、出现连接异常、数据包含未预期敏感记录或授权身份不明确时立即停止。

## 清理

加密保存最小证据，删除完整区副本；不导入任何记录到其它系统。

## 修复

- 默认拒绝传送
- 仅允许明确二级权威并使用 TSIG
- 跨不可信网络使用 XoT
- 监控未知传送源

## 复测

- 从同一未授权源重复一次
- 预期 REFUSED 或认证失败
- 确认授权二级权威同步仍正常

## 结论模板

- 观察事实：
- 支持的假设：
- 被排除的解释：
- 尚缺证据：
- 风险与影响：
- 已触发停止点：
- 修复后复测结果：
