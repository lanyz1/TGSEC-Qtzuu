# 区块链充值对账安全 (Blockchain Deposit Reconciliation)

> 来源: TRC20/ERC20 标准、TronGrid API 文档、授权事故复盘
> 条目数: 3 | 分类: 区块链 (Blockchain)

---

### [KB-BLK-01] USDT approve 伪装充值（链上对账事件类型混淆）
- **信号**: 平台提供 TRC20/ERC20 地址充值自动上分；对账接口返回含 Approval 事件；充值确认仅校验 solidity 回执 SUCCESS；用户未转账但账户余额增加、充值地址链上无入账
- **原理**: `approve(spender, amount)` 是授权声明（允许 spender 最多划走 amount），不转移资金。TronGrid `/v1/accounts/{addr}/transactions/trc20?only_to=true` 会同时返回 Transfer 与 Approval，且 Approval 的 spender 位于 to 字段，导致充值地址命中；对账若未过滤事件类型，会把授权额度误写为充值金额。`solidity SUCCESS` 对 approve 同样成立，无法作为到账依据
- **最小PoC**: 对平台充值地址发起 `approve(充值地址, 1000 USDT)`（方法选择器 `095ea7b3`），观察平台是否上分而链上无 Transfer（topic `ddf252ad…`）；正常转账应为 `a9059cbb` + Transfer 事件（topic `8c5be1e5…` 为 Approval）
- **绕过与变体**: 多次 approve 放大金额；ERC20 同构（EVM 链同样适用）；对账轮询窗口内批量提交
- **修复**: 落库只认 `type=Transfer`；上分前校验 solidity + 本地址等额 USDT Transfer 事件；事件类型按 topic0 白名单；异常单标记 invalid + 告警；提现侧交叉验证链上真实入账
- **参考**: TRC20 标准（Tron Improvement Proposal）、TronGrid API docs、CWE-20（输入验证不当）

### [KB-BLK-02] TRON 交易构造与签名（txID=SHA256、能量租赁闭环）
- **信号**: 需要链上构造 TRC20 调用（approve/transfer）或本地签名广播；账户无 TRX 但可租能量
- **原理**: TRON 交易签名消息是 `SHA-256(raw_data_hex)`（**不是 Keccak**，与地址推导不同）；TronGrid `triggersmartcontract` 返回交易对象（txID/raw_data/raw_data_hex），本地对 raw_data_hex 做 SHA256 后 secp256k1 签名（65 字节 r‖s‖v，v=recid+27），`broadcasttransaction` 广播。TRC20 调用需能量：可通过能量租赁服务（如 trxfee，签名=HMAC-SHA256(secret, timestamp&sort_json)）租 1H 能量到目标地址，订单完成后即可广播，无需账户持有 TRX
- **最小PoC**: `triggersmartcontract(owner, USDT合约, "approve(address,uint256)", param)` → 签名 → `broadcasttransaction`；验证 `allowance(owner,spender)` 常量调用确认授权生效（ABI 参数：address 左填充 32 字节）
- **绕过与变体**: 地址推导用 Keccak-256(pub[1:])[-20:]+Base58Check(0x41)，签名用 SHA256——混用会导致 SIGERROR（恢复出的签名者不是 owner）；`auto_activation` 可自动激活未激活地址；能量订单约 10 秒完成
- **修复**: 无（链上正常机制）；对账侧需区分 transfer/approve（见 KB-BLK-01）
- **参考**: TRON Developer Hub（triggersmartcontract / broadcasttransaction / gettransactionbyid）、TronGrid API

### [KB-BLK-03] 链上测绘：approve 伪装充值目标平台反查
- **信号**: 需要定位"支持 USDT 充值上分且对账不过滤事件类型"的平台；web 侧测绘（FOFA）命中率低
- **原理**: approve 攻击痕迹永久留链：同一 owner 对同一 spender 多次 approve（正常 DeFi 授权仅一次）、只 approve 不转账、金额为整数充值档位（10/100/500/1000/5000/15000）。从 USDT 合约 Approval 事件流（TronGrid events API 分页）统计 (owner,spender) 频次即可反查候选地址
- **最小PoC**: `GET /v1/contracts/{USDT}/events?event_name=Approval&limit=200` 翻页 → 统计组合频次≥2 → 对候选查 `transactions/trc20?only_to=true` 判别（Transfer≈0 + 档位金额 + 非合约）→ 交叉扩散同一批 owner 的 approve 集合 = 站群清单
- **绕过与变体**: 反例排除——交易所/跨链桥（海量 owner 各 1 次、大额流水）、OTC 钱包（approve 伴随大量 Transfer）；drainer 钓鱼站（approve 含 max uint256 无限授权）；日期金额（20260805）标记自动化测试批次
- **修复**: 无（公开链上数据）；研究用途仅被动读取；平台侧防御见 KB-BLK-01
- **参考**: TronGrid events API、实战测绘 2026-08-06（3 个高置信地址）

---
