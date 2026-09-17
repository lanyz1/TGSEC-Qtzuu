# 独角 BUG 笔记

- Source report: `独角BUG.md`
- Full report: `domains/business-logic/case-reports/dujiao-bug-notes/独角BUG.md`
- Techniques: payment
- Fused: 2026-09-17

## Key findings (distilled)

- 代码都扒出来了。这个漏洞确实经典，整理清楚：
- ---
- 🐛 独角数卡 · PHP 伪造支付漏洞
- 漏洞本质
- 支付回调接口签名算法可逆向，攻击者能自己算签名 → 伪造支付成功通知 → 订单状态变为「已支付」→ 无需真实付款即可获得商品。
- 受影响版本
- dujiaoka ≤ 2.0.4（含）所有版本。项目已归档，不会修复。
- 漏洞根因
- 以 V免签 (Vpay) 为例——最易利用的一个：
- // app/Http/Controllers/Pay/VpayController.php
- public function notifyUrl(Request $request)  // ← GET 请求！
- {

## When to reuse

- 同类标签命中：payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
