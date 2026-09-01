---
id: TECH-2026-5406
title: "DNSSEC 验证状态与父子错配"
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
  - RFC-4033
  - RFC-4034
  - RFC-4035
  - RFC-8914
  - RFC-9904
source_id:
  - SRC-2026-5303
  - SRC-2026-5304
  - SRC-2026-5305
  - SRC-2026-5413
  - SRC-2026-5318
authorization: owned-authorized
confidence: verified
sensitivity: public
license: CC BY-SA 4.0
---

# DNSSEC 验证状态与父子错配

## 目标

沿信任链区分 Secure、Insecure、Bogus 与 Indeterminate，并定位 DS、DNSKEY、RRSIG 或信任锚问题。

## 授权范围

- 只读取公开记录或隔离实验区。
- 不把 dig +dnssec 当成本地验证完成。
- 算法和根信任锚状态在实施前重新查 IANA。

## 前置条件

- 可信时钟
- 已知验证器和信任锚
- 父区与子区权威清单

## 被动优先步骤

- 分别采集父区 DS、子区 DNSKEY/RRSIG 和目标 RRset。
- 记录签名 inception/expiration、key tag、算法与摘要类型。
- 比较验证解析器、非验证解析器和权威直接查询。
- 读取验证器详细原因或 Extended DNS Error。

## 最小主动验证

```bash
dig +dnssec +noall +answer "$ZONE" DS
dig +dnssec +noall +answer "$ZONE" DNSKEY
delv "$NAME" A
```

**硬上限**：每记录类型每权威 1 次，整条验证链最多 10 次查询。

## 必备证据

- DS/DNSKEY 摘要关系
- RRSIG 时间窗
- 验证器状态与原因
- 信任锚版本
- 多权威一致性

## 证据 Oracle

- Secure 需要从信任锚到目标 RRset 的完整成功验证。
- Insecure 需要已验证的无 DS 证明，不是随意缺少签名。
- Bogus 需要先证明该分支应受保护，再给出具体失败原因。
- 无适用信任锚时为 Indeterminate，不能强行归类。

## 常见误报

- 验证器时钟错误
- 签名/密钥计划轮换
- 缓存旧 DS
- 算法实现不一致
- MTU/TCP 回退故障

## 停止点

已定位到单一可复现链条断点、来源开始限流或无法证明信任锚时停止。

## 清理

无远端状态；保留脱敏链条和时间戳，不保存私钥。

## 修复

- 按 TTL 时序修正 DS/DNSKEY/RRSIG
- 恢复可靠时间和 TCP 回退
- 更新验证器与信任锚

## 复测

- 验证器得到预期四态之一
- 多权威关键 RRset 一致
- 修复后正常与不存在名称都可正确验证

## 结论模板

- 观察事实：
- 支持的假设：
- 被排除的解释：
- 尚缺证据：
- 风险与影响：
- 已触发停止点：
- 修复后复测结果：
