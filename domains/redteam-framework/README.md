# 红队执行框架

@TGSEC社区 · @TGSEC-Qtzuu 整理

## Black Cat — 假设驱动状态机渗透框架

核心设计:
- **状态机模型**: RECON ⇄ ENUMERATE ⇄ VALIDATE → EXPLOIT → POST-EXPLOIT → REPORT
- **假设驱动**: 信号→假设→验证/证伪,证伪产生新假设
- **JSONL Ledger**: 单一真相源,hypothesis/evidence/verdict追踪
- **证据链**: observation → reproduction → impact 三角色闭环

### 技术目录
| 信号 | 文件 |
|------|------|
| Web/API/GraphQL | `black-cat/techniques/web.md` |
| 信息收集/CDN/DNS | `black-cat/techniques/recon.md` |
| AWS/Azure/GCP/K8s | `black-cat/techniques/cloud.md` |
| 数据库 | `black-cat/techniques/database.md` |
| 逆向(APK/IPA/EXE) | `black-cat/techniques/reversing.md` |
| AD/内网 | `black-cat/techniques/ad.md` |
| EDR/免杀 | `black-cat/techniques/evasion.md` |

来源: https://github.com/0rangec3t/Black-cat
