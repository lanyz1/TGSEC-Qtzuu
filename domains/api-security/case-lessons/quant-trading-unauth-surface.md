# 量化/交易平台无鉴权面清单 — okbot/开单大师案

**目标**: okbot/weboot 生态 (5 服务器 12 服务: 开单大师 kaidan-rust / BigShort-Go / 开单君 FastAPI / GFast / 1Panel / C2)

## 命中面 (逐条可复用)
- **开单大师**: 14 个业务 API 全免鉴权 → 698KB 真实交易数据 (60+ alpha 因子 / 策略完整表达式 / webhook 回执中文账户名)
- **RabbitMQ 默认凭据**: admin/123456 + guest/guest → administrator 接管; 16 队列 8273 消息 (审批队列含 isAdmin 待批账号 + 后门账号)
- **开单君 OpenAPI**: 27 路径全暴露 (策略/订单/日志/回测; 写面被服务端开关锁死)
- **BigShort-Go**: 开放注册 + 验证码免鉴权 + ddddocr 全自动 → JWT; HS256 secret 爆 rockyou 1434 万未命中
- **C2 /cmd/poll**: 未授权读命令队列 (无写端点)
- **1Panel**: 明文 HTTP + 算术验证码可自动解 (1132 候选密码全废)
- GFast: 注册待审核 + Gin validator 泄露 struct 字段名

## 教训
- 交易类 SaaS 先测"无鉴权数据面" (因子/策略/订单/回测) — 常整套裸奔
- RabbitMQ 默认凭据是高频命中点 (admin/123456 尤甚)
- HS256 secret 爆到 rockyou 级未命中 = 强 secret, 即停
