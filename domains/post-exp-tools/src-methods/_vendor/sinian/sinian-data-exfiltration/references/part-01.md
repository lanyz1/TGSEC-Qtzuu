## 概述

本手册是面向红队行动与安全研究的综合性数据外泄技术参考，涵盖从传统网络隧道到2026年最新的前沿外泄方法。手册以实战为导向，提供可立即投入使用的代码示例、检测规避策略与攻击链整合方案。

### 核心设计原则

1. **纵深防御突破**: 每一层外泄技术均考虑多层DLP/NDR/EDR的检测能力
2. **加密优先**: 所有外泄通道默认启用强加密，防止中间设备审计
3. **协议伪装**: 外泄流量深度伪装为正常业务流量，规避流量特征分析
4. **分段传输**: 大文件自动分片并重新组装，支持断点续传
5. **自适应降级**: 主通道被阻断时自动切换到备用通道

### 目标DLP/NDR产品覆盖

| 厂商 | 产品 | 检测重点 | 绕过难度 |
|------|------|----------|----------|
| Symantec | DLP 16.x | 内容指纹、正则匹配、文件指纹 | 高 |
| Forcepoint | DLP 9.x | 行为分析、异常流量、数据分类 | 高 |
| Digital Guardian | DLP 8.x | 端点审计、内核级监控、API Hook | 极高 |
| Microsoft | Purview DLP | 云原生、敏感信息类型、AI分类器 | 中高 |
| Broadcom | DLP 15.x | 网络监控、邮件扫描、指纹识别 | 高 |
| Trellix | DLP 11.x | 端点与网络融合、ML检测 | 中高 |
| Zscaler | DLP Cloud | CASB、SSL检查、内联代理 | 中 |
| Netskope | DLP NG-SWG | 云访问安全、API控制 | 中 |

### 实战环境约定

```bash
# 攻击者服务器 (C2/LISTENER)
ATTACKER_IP="10.0.0.100"
ATTACKER_DOMAIN="evil-c2.example.com"
ATTACKER_PORT="443"

# 受害者内网环境
VICTIM_LAN="192.168.1.0/24"
VICTIM_HOST="192.168.1.50"
EXFILTRATION_TARGET="/data/sensitive/"

# 外泄数据标记
TARGET_DATA="customer_db.sql"
TARGET_SIZE="2.4GB"
```

---

