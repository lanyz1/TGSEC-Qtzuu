---
name: black-cat-redteam
description: "Use for hypothesis state-machine redteam flow."
---

# Black Cat Redteam

假设驱动的状态机渗透测试框架。来源: https://github.com/0rangec3t/Black-cat

## 安装位置
`/root/Black-cat/`

## 核心设计
- **状态机模型**: RECON ⇄ ENUMERATE ⇄ VALIDATE → EXPLOIT → POST-EXPLOIT → REPORT
- **假设驱动**: 信号→假设→验证/证伪,证伪产生新假设
- **JSONL Ledger**: 单一真相源,hypothesis/evidence/verdict追踪
- **证据链**: observation → reproduction → impact 三角色闭环

## 技术目录路由
| 信号 | 读取 |
|------|------|
| 域名/前端/Web/API/GraphQL | `techniques/web.md` |
| 信息收集/CDN/DNS/ASN/子域 | `techniques/recon.md` + Hermes `cdn-origin-tracing` |
| AWS/Azure/GCP/K8s/容器 | `techniques/cloud.md` |
| 数据库端口/连接串 | `techniques/database.md` |
| APK/IPA/EXE/固件 | `techniques/reversing.md` |
| AD/内网/凭据 | `techniques/ad.md` |
| EDR/免杀/OPSEC | `techniques/evasion.md` |

## 使用方式
加载完整SKILL.md:
```
cat /root/Black-cat/skills/pentest-redteam/SKILL.md
```
加载技术目录(按需):
```
cat /root/Black-cat/skills/pentest-redteam/techniques/web.md
cat /root/Black-cat/skills/pentest-redteam/techniques/recon.md
```
Ledger工具:
```
python3 /root/Black-cat/tests/test_case_ledger.py
```
