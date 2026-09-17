# 独角 Next 1元购/打折支付 PoC

- Source report: `Dujiao_Next_支付模块_1_元购_打折支付漏洞_—_完整漏洞报告与_PoC_.md`
- Full report: `domains/business-logic/case-reports/dujiao-next-1yuan-pay/Dujiao_Next_支付模块_1_元购_打折支付漏洞_—_完整漏洞报告与_PoC_.md`
- Techniques: payment, idor
- Fused: 2026-09-17

## Key findings (distilled)

- 缺陷① 履约不校验金额**：支付回调处理（`applyPaymentUpdate`）在将订单标记为已支付前，只检查"订单当前不是 Paid"，**从不比较这笔支付的金额是否覆盖订单当前的在线应付额**。回调前的事实校验（`validateCallbackPaymentFacts`）只验证"回调金额 == 这笔支付记录自身的金额"，形成"支付记录金额可以很小"的合规缺口。
- 缺陷② 钱包扣款幂等键静态**：余额扣款流水的幂等键恒为 `order:<订单ID>:order_pay`。订单在"用余额 → 改在线（余额退回）→ 再用余额"之间来回切换时，第二次扣款命中第一轮**已被退回的旧流水**，`ApplyOrderBalance` 直接返回旧金额而**不执行扣款**；订单侧桥接代码却无条件信任该返回值并写入 `wallet_paid_amount=999`——**订单
- 缺陷③ 旧支付链接无网关侧作废**：v1.4.3 中创建新支付时对同订单其他 pending 支付**零处理**（supersede 机制尚不存在），且同渠道重复创建会**直接复用旧支付记录及其网关链接**（`reusedPending`）。全库不存在任何网关侧关单 API，被"本地作废"（或从未作废）的小额链接在支付网关侧持续可付，攻击者仍可在其上付款并触发合法验签回调。
- 创建第二笔支付（换渠道）**不会**改动第一笔支付（`SupersedePendingByOrderID` 函数在该版本不存在——`git grep SupersedePendingByOrderID v1.4.3` 为空，该函数由 ab60e138 于 2026-08-11 引入）；
- 全库**不存在**任何网关侧 close/关单 API（alipay/epay/okpay/bepusdt/wechat 网关包均无实现），第一笔 1 元支付的网关链接在网关侧持续有效；
- I:H：任意订单支付完整性被破坏、账目伪造；
- 业务定级 **Critical**（直接资损、100% 成功率、可自动化、无并发条件）。
- `online_paid_amount` 被写成全额，**财务对账无法从账面发现**，只能通过"支付渠道实际流水 < 订单 online_paid_amount"专项稽核暴露；

## Repro snippets

```
回调前的 `validateCallbackPaymentFacts`（同文件）只校验：
`markOrderPaid` 内部虽然通过 `IsTransitionAllowed` 限制了 `PendingPayment → Paid` 的迁移（排除了已取消/已退款订单被重放履约的可能），但对**合法处于 PendingPayment 的订单**，任何成功回调都会触发履约与发货（`ConsumeManualStockByItems` + 自动交付）。

> 修复版对照（f57247b4）：
>
### 2.2 缺陷②：钱包扣款幂等键静态，"退回后再用余额"不再扣款

**文件**：`internal/modules/wallet/application/order_balance.go`（v1.4.3）→ `ApplyOrderBalance`
```

## When to reuse

- 同类标签命中：payment, idor
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
