# 独角数卡 0 元购 — "通道归属不校验"全家桶 (apple-giftcards 案)

**目标**: apple-giftcards.com (独角数卡 dujiaoka + dcat-admin 2.0.24-beta + epusdt :8000)

## V1 0 元购全链 (CRITICAL)
- `PayController::loadGateWay()` **只按 URL {payway} 加载通道、不校验通道归属**; pay_id 可被落库改写 → 任意订单 0 元支付

## 密钥泄露 + 回调伪造
- GET `/pay/{yipay|paysapi|vpay}/epusdt/{SN}` → **merchant_id + sign 直接进 URL** (md5 可复算验证)
- 伪造回调 `POST /pay/epusdt/notify_url` (签名 = md5(排序参数串+merchant_id)) → 订单"已完成" + **自动发货** (卡密写单+标记售出+邮件); 实测 2 单成功

## 其他面
- search-order-by-email 任意邮箱查单 / detail-order-sn / check-order-status 零鉴权; 模板无条件渲染卡密字段
- epusdt create-transaction = 签名预言机; checkout-counter / check-status 无鉴权; TRC20 收款地址泄露
- 后台 /appleadmin: bcrypt 耗时时序枚举用户名 (0.9s vs 0.6s); aaPanel :34205 静态可读 + 8 位随机入口爆破无果

## 教训
- 发卡站三查: ①通道归属校验 ②epusdt 密钥是否进 URL ③notify 签名算法可复现性
- dujiaoka 家族: `payway` 路由参数 = 攻击面核心
