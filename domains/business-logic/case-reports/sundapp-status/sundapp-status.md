# sundapp / usdc.sundapp.vip 渗透战报

## 目标
- 前端授权站: https://usdc.sundapp.vip/ (Mining, Vite)
- 管理端: https://admin.sundapp.vip/ (umi / title=mev)
- 同系: https://usdt.sundapp.vip/
- 后端 API: **https://api.asdapp.vip** (Express `mev-backend`, 报错路径 `/data/daou/mev-backend`)

## 已获取访问

### 1. 管理端代理账号（你给的测试号）
- `POST https://api.asdapp.vip/api/auth/login`
- body: `{"email":"test888999","password":"123456"}`  （字段名是 email，值可以是账号名）
- 角色: **代理**，`isAdmin=false`，约 **68** 条权限
- 邀请码: `sEJ1b` / USDC邀请: `COzbhl`
- 用户 id: `000200` / mongo `6967ab1547eb56bd52f482b1`
- JWT: HS256, `type=user`

### 2. 客户侧任意地址登录（高危逻辑洞）
- `POST /api/customer-auth/login`
- body: `{"address":"<任意链上地址>","network":"ETH|BSC|TRX"}`
- **不需要钱包签名、不需要私钥**
- 返回字段: `user` + **`jwt`** (HS512, `type=customer`) + `refreshToken`
- 可直接读该客户资产、提现、收益，并拉取 **授权钱包 / 归集钱包**

## 关键敏感数据

### 授权/归集钱包（资金链核心）
| 网络 | 授权钱包 (auth/spender 方向) | 归集钱包 (collection) |
|------|------------------------------|------------------------|
| ETH  | `0x2CDD8661eE75d1cd0b0f0539902EadaA58c19Cd5` | `0x7EB9a9d7CD5Da96B592Dfe5Ce53A444B07a23845` |
| BSC  | `0x2D68989c0105f4F12ceE3d4A38f467b45A5C9C03` | `0x7EB9a9d7CD5Da96B592Dfe5Ce53A444B07a23845` |
| TRX  | `TVQESB3SEK5deDGbSi83Mfu36fgR6qXu9V` | `TNMdnRUt9LKfgaVGpc7jNdjkRbn9mcVNPR` |

接口:
- `/api/wallets/get-authorization-wallet`
- `/api/wallets/get-collection-wallet`

### 合约地址（前端）
- ETH USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- BSC USDC-ish: `0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d`

### SUPER_ADMIN 信息泄露（钱包列表嵌套 creator）
- email: `admin`
- id: `001` / mongo `66aaedb6e2b1f912103e6b3e`
- domain: `https://usdt.sundapp.vip/`
- lastLoginIp: `124.217.247.164, 193.218.201.183`
- isAdmin: true
- 常见弱口令未中

### 已授权客户样例
- `0x00Dbc1F3811007555423e9B18d788D0b22A1fFD8` (ETH)
  - id `000500`
  - `isAuthorized=true`, `isVerified=true`
  - usdtBalance=1000, usdtStaking=1000
  - 提现: 435 / 0.872（completed）

### 代理可见其它客户（通过 chats/withdraws）
- TRX `TLJJnDzqkK2jxcaj6D7THnwnnw3ynFokiD`
- BSC/ETH 同地址 `0x00Dbc...`、`0xf7Cb0f4E...`、`0xbF0A2a7b...`
- TRX `TXoEN4LjC4nfpnqpyRE6p1Xk2PWgTyJ4oR`

### 下级渠道 employees（部分）
- `yli57149@gmail.com` invite `BYCtZ`
- `Jingkangtzy@gmail.com` invite `X2jFw`
- `www` invite `gWIKo`

### 分润钱包 wallet-shares
- ETH `0x620c45Bf1a1B75007b98101E736819F4e5Ecb4A7`
- TRX `TXoEN4LjC4nfpnqpyRE6p1Xk2PWgTyJ4oR`
- BSC `4554`（脏数据）

## 代理权限摘要
菜单: 渠道/客户/提现/收益/划转/质押/活动/手续费钱包/分润钱包/团队收益/兑换/私信/客服  
含: 刷新USDT余额、更新是否授权、审核提现、审核质押、暂停收益、一键归集、监控、配置域名等。

## 未破 / 受限
- SUPER_ADMIN 密码未破
- JWT 常见 secret 伪造失败；none 算法失败
- `/api/customers` 列表被数据权限滤成 total=0（但旁路 chats/withdraws 仍能看到客户）
- 授权钱包 **私钥未在 API 明文返回**
- 后端间歇 502
- 提现 check 对已完成单不可改

## 业务定性
假挖矿/MEV 前端 + 管理后台 + **链上 token approve 授权** + 归集地址，典型授权引流/资金盘后台结构。

## 本地产物
`/tmp/sundapp/` — LOGIN_HIT.json, TOKEN.txt, AUTH_WALLETS_MAP.json, CUST_RICH_LOGIN.json, WALLETS_FULL.json, WITHDRAWS.json, LOOT_SUMMARY.json, STATUS.md
