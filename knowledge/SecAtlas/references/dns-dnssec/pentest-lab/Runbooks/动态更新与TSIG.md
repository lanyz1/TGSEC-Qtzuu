---
id: TECH-2026-5404
title: "RFC 2136 动态更新与 TSIG"
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
  - RFC-2136
  - RFC-8945
  - RFC-3833
source_id:
  - SRC-2026-5406
  - SRC-2026-5407
  - SRC-2026-5439
  - SRC-2026-5423
authorization: owned-authorized
confidence: verified
sensitivity: public
license: CC BY-SA 4.0
---

# RFC 2136 动态更新与 TSIG

## 目标

验证动态更新入口是否有事务认证、细粒度更新策略、审计与可回滚边界。

## 授权范围

- 生产目标只做配置、日志和拒绝路径审查。
- 可成功的 UPDATE 只在一次性 .test 实验区执行，且使用临时 TSIG 与空更新。
- 不得写入真实业务 RR、DNSSEC 密钥材料或持久化后门记录。

## 前置条件

- 确认 primary 角色
- 取得更新策略和授权 principal 清单
- 准备可丢弃实验 zone

## 被动优先步骤

- 检查 allow-update 是否使用宽泛地址段。
- 优先检查 update-policy 的名称、类型和 principal 限制。
- 核对 TSIG 算法、密钥分发、轮换和日志脱敏。
- 确认更新与签名、通知、二级同步的事务边界。

## 最小主动验证

```bash
# 只在隔离实验区：nsupdate -v -k "$EPHEMERAL_TSIG_KEY"
server $LAB_AUTH
zone signed.test
show
send  # 不包含 add/delete，形成一次空更新边界检查
```

**硬上限**：生产成功路径 0 次；隔离实验空更新 1 次；失败不重试。

## 必备证据

- UPDATE RCODE
- TSIG 验证结果
- update-policy 命中规则
- 变更日志与 SOA serial 是否保持

## 证据 Oracle

- 未认证请求被 REFUSED/NOTAUTH 支持安全边界。
- 有 TSIG 不等于有权限；必须同时命中最小更新策略。
- 空更新成功只证明认证路径，不证明任意记录可写。

## 常见误报

- 本地主机 update-policy local
- DHCP 专用更新 principal
- 测试命中错误 view

## 停止点

发现任何真实 RR 变化、serial 异常推进、密钥来源不明或日志泄露密钥材料时停止。

## 清理

销毁临时 TSIG 文件和一次性 zone；确认无 RR/serial 变化。

## 修复

- 用 TSIG principal 加细粒度 update-policy
- 禁止仅靠源 IP 的宽泛更新
- 分离密钥并建立轮换和审计

## 复测

- 未认证空更新应失败
- 越权名称/类型应失败
- 授权实验 principal 只可修改允许范围

## 结论模板

- 观察事实：
- 支持的假设：
- 被排除的解释：
- 尚缺证据：
- 风险与影响：
- 已触发停止点：
- 修复后复测结果：
