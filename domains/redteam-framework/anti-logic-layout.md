# Anti-Logic — 逆向思维 / 反逻辑布局

原则：对手按「你会怎么走」布防；你走「他不会想」的缝。

## 六轴

| 轴 | 名 | 做法 |
|----|----|------|
| A1 | 反目标 | 不夺权，先碰支付/配置写接口 |
| A2 | 反路径 | setup/register/reports/export |
| A3 | 反协议 | 空 init_data / phone-only / 内网 persona |
| A4 | 反顺序 | 先 user 链再测 admin 越权 |
| A5 | 反身份 | 客服/cron UA，降噪声 |
| A6 | 反入口 | chat / socket.io / 回调 SSRF 面 |

与正逻辑 Kill Chain **并行**；汇合点 = token 或写权限。

相关：`auth-security/session-crypto-identity-layer.md` · `business-logic/payment-config-crown-surface.md`



---
@TGSEC社区 · @TGSEC-Qtzuu 整理
