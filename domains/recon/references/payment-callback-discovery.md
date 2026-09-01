# 支付回调端点发现与利用
id: "KB-PAY-001"
name: "支付回调端点发现与利用"
category: "Web与API安全"
subcategory: "支付逻辑"
severity: "high"

description: |
  在线支付系统中，支付网关（如支付宝/微信/PayPal/Shayu）完成支付后会通过回调 URL
  通知商户服务器更新订单状态。如果回调端点的签名验证可绕过，攻击者可以伪造支付
  成功通知，无需实际付款即可获取商品/服务。

discovery_methods:
  - method: "支付页面 HTML 表单分析"
    detail: |
      访问支付页面（如 /pay.{trade_no}），搜索表单中的 notify_url 字段。
      回调 URL 通常包含内部 IP/端口/路径，绕过前端代理直接到达后端服务。
      
      在本案例中：notify_url = http://203.0.113.14:8912/pay/async.{trade_no}
      该端口不在公网 nmap 扫描结果中，仅通过表单泄露。

  - method: "JS 逆向支付流程"
    detail: |
      分析 checkout.js 等支付相关 JS 文件，查找：
      - pay.timer() 的轮询逻辑（状态轮询 → 回调完成）
      - pay.getPayOrder() 的状态码定义（status=2 表示已支付）
      - 支付成功后的跳转 URL（如 /pay/sync.{trade_no}）

  - method: "端口扫描 + 路径枚举"
    detail: |
      对目标 IP 进行全端口扫描，发现非标准 HTTP 端口后，
      尝试常见支付回调路径：/pay/callback、/pay/notify、/pay/async、/pay/return

attack_vectors:
  - name: "签名密钥破解"
    detail: |
      大多数支付回调使用 MD5/SHA256 签名验证。常见签名格式：
      - MD5(params_sorted + "&key=" + secret)
      - MD5(values_concatenated + secret)
      - MD5(params + timestamp + secret)
      
      密钥可能来源：
      - 商户后台配置（需卖家权限）
      - JS 源码硬编码（Base.js/util.js 中搜索）
      - PHP 配置文件（通过 LFI/文件读取获取）

  - name: "参数注入"
    detail: |
      测试回调端点的参数处理：
      - 缺少签名时是否仍接受
      - 数组参数（param[]）是否绕过类型检查
      - 特殊字符注入（\0、\n、SQL 关键字）
      - 超大值/负值是否触发异常

  - name: "时间窗口利用"
    detail: |
      如果签名包含时间戳，枚举时间窗口（±5s）逐个尝试。

  - name: "回调 URL 切换"
    detail: |
      如果攻击者能控制 notify_url（如通过修改请求参数），
      可将回调指向自己控制的服务器，捕获真实支付通知并重放。

defense:
  - "回调签名密钥使用强随机值，长度 ≥ 32 字符"
  - "服务端验证回调来源 IP（仅允许支付网关 IP）"
  - "回调 URL 不得包含内网地址，使用 HTTPS 公网域名"
  - "订单状态机不允许从'已支付'回退到'未支付'"
  - "设置回调超时时间，过期订单自动取消"

tools:
  - "curl / requests"
  - "nmap（全端口扫描）"
  - "Burp Suite（拦截支付页面、修改回调参数）"

sources:
  - agent: "黑骡 v1.1.0"
    date: "2026-07-21"
  - ref: "授权渗透测试案例"
  - ref: "技术卡: api-bypass-aes-cbc-timestamp-signature"
