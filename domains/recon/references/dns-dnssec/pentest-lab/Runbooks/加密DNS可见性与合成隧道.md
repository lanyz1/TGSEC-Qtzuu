---
id: TECH-2026-5410
title: "加密 DNS 可见性与合成隧道检测"
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
  - RFC-9076
  - RFC-7858
  - RFC-8484
  - RFC-9250
  - ATT&CK-T1071.004
source_id:
  - SRC-2026-5310
  - SRC-2026-5312
  - SRC-2026-5313
  - SRC-2026-5314
  - SRC-2026-5330
  - SRC-2026-5429
  - SRC-2026-5430
authorization: owned-authorized
confidence: verified
sensitivity: public
license: CC BY-SA 4.0
---

# 加密 DNS 可见性与合成隧道检测

## 目标

理解 DoT/DoH/DoQ 对旁路观测的影响，并用无数据外传的合成流量验证多信号隧道检测。

## 授权范围

- 只在批准解析器、端点或隔离网络采集。
- 合成标签不编码真实文件、凭据、设备标识或个人数据。
- 不阻断生产加密 DNS，不把未知端点自动判为恶意。

## 前置条件

- 批准解析器清单
- 资产与进程上下文
- 基线时段
- 无公网出口 .test 权威

## 被动优先步骤

- 区分明文 DNS、DoT、DoH 和 DoQ 的可见字段。
- 在批准解析器记录查询类型、响应、策略与客户端标识的最小必要集合。
- 将标签长度、熵、查询频率、类型比例和目的权威与端点进程关联。
- 建立 CDN、服务发现、遥测和安全产品的良性允许列表。

## 最小主动验证

```bash
dig @"$LAB_RESOLVER" release-2026-07-20-build-artifact.cdn.test TXT
dig @"$LAB_RESOLVER" mfrggzdfmztwq2lk-nbswy3dpeb3w64tmmq.tunnel.test TXT
```

**硬上限**：每个合成对照 1 次；不编码真实数据、不循环、不发送到公网权威。

## 必备证据

- PCAP 端点与尺寸
- 批准解析器查询日志
- Zeek/Suricata 事件
- 端点进程与资产角色

## 证据 Oracle

- 加密会话旁路只能证明端点、时序和大小，不应声称看到 QNAME。
- 长标签或高熵必须与频率、端点进程和目的权威共同成立。
- 良性对照与疑似样本无法稳定分离时，正确结论是补证而非告警升级。

## 常见误报

- CDN 缓存键
- 软件更新与服务发现
- EDR/遥测
- DNSSEC 大响应
- 批准的隐私解析器

## 停止点

需要解密未授权流量、收集真实内容、制造持续信道或影响生产解析时停止。

## 清理

删除合成 resolver 日志中的临时客户端标识；销毁 .test 区和隔离 VM。

## 修复

- 强制使用批准解析器
- 在解析器与端点关联检测
- 按多信号和资产角色调优
- 保留最小必要日志

## 复测

- 合成疑似样本触发且良性对照不触发
- 批准 DoH/DoT 正常
- 旁路监控不再声称可见明文查询

## 结论模板

- 观察事实：
- 支持的假设：
- 被排除的解释：
- 尚缺证据：
- 风险与影响：
- 已触发停止点：
- 修复后复测结果：
