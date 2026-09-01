---
id: TECH-2026-4440
title: "HTTP 请求走私与 Desync：攻击面与测试思路"
kind: technique
track: [代码审计, 授权渗透测试]
platform: [Web与API]
techniques: [HTTP请求走私, HTTP-Desync, 协议解析差异]
lifecycle: [检测, 修复, 复测]
standards: [CWE-444, RFC-9112, RFC-9113, RFC-9114, RFC-9931, WSTG-INPV-16]
authorization: authorized-only
source_url: "multiple; see 公开来源索引.md"
source_date: "2005-06/2026-03"
collected_at: "2026-07-20"
language: zh-CN
confidence: verified
sensitivity: public
license: "原创整理文本；外部来源权利见来源索引"
source_id: [SRC-2026-4440]
---

# HTTP 请求走私与 Desync

本专题用于学习 HTTP 消息边界和连接状态分歧：哪里可能产生解析差异、如何选择最低影响检查、需要什么证据、何时停止，以及如何修复和复测。

## 决策循环

`scope → topology/boundary → observation → hypothesis → single-variable minimal_check → evidence → stop → remediation → retest`

评估记录应包含：

- 已确认的授权范围与逐跳协议边界。
- 观察事实与单一可证伪假设。
- 最低影响、单变量检查及预期安全行为。
- 证据、结论强度和停止原因。
- 根因修复与同样本复测条件。

不输出自由展开的私有思维链，也不生成可复用攻击报文。

## 结论门槛

- 版本命中、入口支持 H2/H3、单个错误码、超时或断连：仅是线索。
- 能证明相邻组件的 `message_end`、消费量、请求计数或错误后连接状态不同：才是解析或状态分歧证据。
- 观察到首次分歧、残留状态、异常计数或业务副作用：立即停止，不继续证明跨用户影响。
- 修复后必须用同一抽象样本证明逐跳一致处理、异常状态不复用，并补一个合法控制样本。

## 内容入口

1. [公开来源索引](公开来源索引.md)：16 个当前规范、官方分类、公开研究与厂商案例。

## 主动验证边界

主动检查仅限书面授权的 `loopback`、隔离容器、官方实验室或无真实数据且连接池专用的预生产。生产、共享租户、共享缓存、共享后端队列和授权不明目标只做被动审计。

禁止：

- 完整请求走私载荷、原始 HTTP 报文或扫描命令。
- 真实目标、凭据、对象枚举、并发、压力或 DoS。
- 向共享后端队列注入第二条业务请求。
- 为扩大影响而验证缓存、认证、他人请求或跨用户后果。
