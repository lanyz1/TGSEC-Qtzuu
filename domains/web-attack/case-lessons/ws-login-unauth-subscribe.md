# WebSocket 登录免鉴权订阅 + 订单号即凭证 (SKYSCRM/AFBpay 案)

## WS 免鉴权订阅 (核心)
- `wss://jump.afbpay.com/wsp_5556/subscribe` 无认证
- 发 `{"method":"login","uid":"2"}` 即实时收全平台 C2C 订单推送
- 规模: 2 分钟 22 笔 ¥9527 → 估算 5000+ 码商
- **手法**: WS 先抓帧看 method 集合; login/join 类 method 直接重放 + 降 uid/空 token

## 支付网关面
- `paymentGetState` IDOR: **order_no 即凭证** (无 session 查任意订单全详情)
- `paymentSubmit` 绕过天御验证码直接 "操作成功"
- `X-Forwarded-For: 127.0.0.1` 绕 nginx IP 白名单 (403→404 对比判)
- `/adminApi/getAll` 未授权泄露 117 条后台 API/权限树; 审计日志未授权可读

## 教训
- WS 协议是"影子 HTTP": 同 endpoint 的鉴权常被开发忽略
- "订单号即凭证"模式 (短信链接式) 在支付网关高频出现
