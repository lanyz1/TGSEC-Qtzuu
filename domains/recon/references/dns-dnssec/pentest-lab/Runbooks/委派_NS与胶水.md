---
id: TECH-2026-5402
title: "委派、NS 与胶水一致性"
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
  - RFC-1034
  - RFC-1035
  - RFC-4034
  - RFC-9975
source_id:
  - SRC-2026-5402
  - SRC-2026-5403
  - SRC-2026-5304
  - SRC-2026-5322
authorization: owned-authorized
confidence: verified
sensitivity: public
license: CC BY-SA 4.0
---

# 委派、NS 与胶水一致性

## 目标

判断父区委派、胶水、子区权威和 DNSSEC DS 是否形成一致且可解释的授权链。

## 授权范围

- 只向已识别的父区或授权权威发起非递归查询。
- 不对未授权地址进行端口扫描或版本探测。
- 多签名者和多提供商场景必须按设计文档解释。

## 前置条件

- 已完成被动枚举
- 已识别父区权威与子区权威
- 知道计划轮换或迁移窗口

## 被动优先步骤

- 比较父区 NS 和子区 apex NS。
- 仅对 bailiwick 内 NS 检查必要胶水 A/AAAA。
- 比较各权威 SOA serial、DNSKEY、CDS/CDNSKEY 和关键 RRset。
- 把缓存 TTL 与轮换窗口纳入时间线。

## 最小主动验证

```bash
dig +norecurse @"$PARENT_AUTH" "$ZONE" NS
dig +norecurse @"$CHILD_AUTH" "$ZONE" SOA
dig +dnssec +norecurse @"$PARENT_AUTH" "$ZONE" DS
```

**硬上限**：每个父/子权威每种记录 1 次，整区最多 12 次查询。

## 必备证据

- 父区授权答案
- 子区 apex 答案
- SOA serial
- DS/DNSKEY/CDS 一致性快照

## 证据 Oracle

- 胶水仅用于到达权威，不等于权威区内 A/AAAA 的最终真实性。
- 所有权威在稳定窗口持续给出冲突关键数据才可判为发布不一致。
- 计划轮换中同时存在新旧密钥可为正常状态，需按时序裁决。

## 常见误报

- 缓存尚未过期
- DNSSEC 双签窗口
- Anycast 节点短暂不同步
- 分裂视图

## 停止点

发现超出授权的权威、节点开始限流、或无法取得变更窗口信息时停止并标记待补证。

## 清理

无远端状态；删除临时解析缓存并保留时间戳。

## 修复

- 统一父子区 NS
- 修正缺失或陈旧胶水
- 让所有权威在自动变更前达到合理一致

## 复测

- 等待相关 TTL 后重复同一组查询
- 确认所有权威 serial 与关键 RRset 符合设计

## 结论模板

- 观察事实：
- 支持的假设：
- 被排除的解释：
- 尚缺证据：
- 风险与影响：
- 已触发停止点：
- 修复后复测结果：
