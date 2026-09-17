# farmtg 农场游戏越级购买

- Source report: `农场游戏越级购买.md`
- Full report: `domains/business-logic/case-reports/farmtg-tier-bypass/农场游戏越级购买.md`
- Techniques: idor, telegram, rce
- Fused: 2026-09-17

## Key findings (distilled)

- 后台越权边界**：玩家 token 访问 `/api/admin/*` 返回 404（资源隐藏）；匿名返回 401
- JWT 防伪造**：`alg:none`、空密钥、弱密钥猜测均被 401 拒绝
- 泄露完整经济参数、`plot_unlock_coins/upgrade_costs`、**TON 充值包与精确 nano-TON 价格**、运营者 TG 联系方式、前端 Vercel 地址。
- TON 充值 `recharge/ton/create + confirm` 真实性**：若 `confirm` 不校验链上到账/签名，可**凭空造点券**（资金级漏洞）。**本次刻意未触发**——需你明确授权（且确认能承受"若成功则点券真被造出、需手工清零"的后果）后再测。
- Mail 领取 IDOR/重放**：当前账号无邮件，需先触发一封邮件。
- 结论：作物增改属后台/DB 管理面，玩家会话不可达；未发现从玩家 token 提权到该面的路径（JWT 伪造、alg:none、空密钥均已试，全部 401）
- 资金面**基础防御成立**。未做真实小额支付测试（涉及真实 TON 支出），因此"金额/备注匹配是否可被弱化"（如付 0.001 TON 冒领）**未验证**——如需彻底确认，建议运营侧用真实小额自测并核对 memo+金额校验逻辑。
- 单号自测批**（需新鲜 Bearer，其它客户端关闭）：`visit expected_coin_cost=0`、`sell_fruits` 越界（现有 4 白萝卜+1 小麦库存）、`mails` 列表+IDOR 尝试、任务列表找可完成项后并发 claim、`all-players` 枚举规模、risk-score 自查、`human-verify/challenge` provider 判定。

## Repro snippets

```
4. 实测结果（Lv.1 账号）：返回 `ok`，金币 −576，库存「普通小麦 ×1」。服务端只扣了钱，没有校验 Lv.1 < Lv.13。
5. 附带（F2）：`count=-5 / 0 / 1.5` 被静默钳为「买 1」，超大量返回笼统 `请求处理失败`，说明 `count` 无显式白名单校验。

> 用户等级服务端可信（WS `plots.user.level`），作物定义也在服务端目录（`GET /api/crops`），因此等级校验完全可以在服务端完成，不依赖任何客户端输入。

### 5.3 根因

`unlock_level` 被当作**纯展示字段**：授权判断（能否购买/能否种）放到了前端按钮层，后端 `buy_seed` handler 只执行 `coins >= price*count` 就放行。SPA bundle 公开，任何人可绕过 UI 直接构造动作帧。

### 5.4 修复方案（Go 伪码，防御纵深）

核心原则：**所有授权判断放服务端，且购买与发放在同一事务/同一把锁内**；人机验证（gocaptcha/Turnstile）只当反自动化层，**不得充
**(2) `plant` 同样必须校验（真正的伤害点）**——种子允许"低等级持有、升级后播种"，但播种瞬间以**当前等级**为准：
**(3) `transfer_seed` 不需按等级拦**（好友送高级种子是设计功能），封堵落在播种方（plant 的收货人等级校验）。若要更严，可在 transfer 时附加提醒，但**不要**禁转。

**(4) 同类入口一次排查**：`buy_pet / buy_tool` 加同样断言；新增**统一辅助函数**避免遗漏：
```

## When to reuse

- 同类标签命中：idor, telegram, rce
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
