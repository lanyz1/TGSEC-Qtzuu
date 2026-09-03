# 渗透测试报告 — 悟空源码网（wukongymw.com / wukongymw.net）

- 案卷：wukongymw_202608（+ wukongymw.com_auto 指纹）
- 主级：A · 状态：ACTIVE
- 更新：2026-09-01

---

## 一、目标概况

| 项 | 值 |
|----|-----|
| 入口 | https://www.wukongymw.net/ |
| 真实后端 | https://api.wkym.cc（API 前缀 /api/v1/，自定义 PHP API） |
| CDN/存储 | https://cdn.wukongymw.com（Cloudflare R2） |
| 前端 | Nuxt 3 SSR（Vite 构建，chunk 分包） |
| 后端栈 | PHP + MySQL + Redis + Cloudflare R2，响应格式 {code,message,data} |
| 框架特征 | nginx 反代 + ThinkPHP（/auth/ 返回 ThinkPHP 404） |
| JWT | HS256，payload {iss:"wkym-api", iat, exp, uid} |
| 业务 | 菠菜源码(BC/QP id=77)、棋牌、交易所、支付源码、区块币圈、盗U源码 |

---

## 二、高危漏洞（全部实测）

### 1. TG Bot Token ×2 明文泄露（可冒充官方客服 / 接管文章推送）
- `GET /api/v1/site/settings` 未授权返回：
  - 客服 bot `@wukongymw_bot` token=`7951356157:AAF4LnGgcRTSy7gWjbMgeVAODIO-Ao3v0go`，chat_id=7898676681
  - 推送 bot `@wukong_article_bot` token=`7930555233:AAFzw_Xag-KxDAo8h0yOcKVhI2jMzwp8JK0`，channel=@wukongymw_article
- 两 token getMe 均有效，webhook 均空 → 可直接接管文章推送频道、冒充客服发诈骗消息。

### 2. 付费源码下载链接 + 解压密码未授权泄露（全站白嫖）
- `GET /api/v1/posts/{id}` 未登录直接返回 `download.url`（mega.nz）+ `extra_info` 解压密码（统一 `wukongymw.com`）。
- 全站 627 篇，10 篇高价源码泄露，mega.nz 链接已验证有效，最高单篇 15888 金币≈11万元。
- 完整清单见 `download_leak.json`。

### 3. USDT 收款地址泄露
- `/api/v1/site/settings` 返回 `usdt_address=THauqeZCw54zsTQwEbuijZb2ErtnWuKong`（TRC20），1U=7元，充值 min 50 金币。

### 4. 登录/注册无验证码
- `feature.img_captcha=false, mail_captcha=false`，登录 POST /auth/login 无任何人机验证 → 可爆破 admin 等账号。

### 5. 注册无门槛（批量注册刷返佣）
- POST /auth/register {username,email,password} 免验证码免邀请，注册返佣 rate=50%。

---

## 三、盗U源码审计（重大增值发现）

站内 28 篇"盗U"源码分两类，其中**假钱包盗助记词**是真正的"无授权盗U"。

### 假钱包盗U完整链路（代码级实锤）
- 仿冒 imToken/TP钱包/MetaMask 假钱包 APP，诱导用户导入助记词/私钥
- 5 个采集接口（app/index/controller/Api.php）：getkey/dahaitpkey/tp/hlkey/postkey
- 参数 pri(助记词/私钥)、client、code(代理ID)
- get_address() 由助记词推导 ETH/TRX 地址 → build() 落库 admin_mnemonic 表
- TG 通知 bot token `5461561559:AAGp...` 推送到群组 -871451910
- 余额监控：Etherscan/TronGrid/blockchain.info 查 USDT/ETH/TRX/BTC 余额，大的才转

### 真实受害者数据（源码包 xydai.sql 明文，非虚构）
```
id=221/222  IP=108.162.246.145(CF)  时间=2022-10-25
ERC: 0x8bf16a360fca63d7fa8e88f83283d74ebc44af3b
TRC: TNW4irRDZ2ckcZFp6D6371XzkPFb37nJ2s
助记词(12词): become job melt reject state violin grunt cabin cattle require eagle dog
私钥: 2592bacea72288bce9da47e44a40e5211bd1e2711ccc251a06143cc68dadff9b
```
同一受害者 ETH+TRX 两链私钥全被盗。

### 连带泄露硬货
- 后台隐藏入口：`/JYW2022jqb.php`（操作日志出现 /JYW2022jqb.php/admin.mnemonic/index）
- 管理员表 admin_admin 密码明文存储（varchar(30)）
- Etherscan API Key：`7TCVDMHGHVH42IFHXJXK677AQWUA1QDE9N`
- TG 鱼苗群组 ID：-871451910
- 真实运营日志（2022-10-25 ~ 10-28）

---

## 四、指纹证据（wukongymw.com_auto）

- tech: Java(true) + PHP(true) + ThinkPHP(true) + nginx(true)
- is_gambling: true，has_upload: true，has_url_preview: true，has_app_download: true
- se_inject_ok: true
- Server: nginx，x-powered-by: Nuxt，无 Cloudflare/CDN/WAF
- preconnect 泄露 api.wkym.cc 与 cdn.wukongymw.com 两后端域

---

## 五、测试账号

- `lxc2hrdjxn` / `lxc2hrdjxn@proton.me` / `Aa123456!`，uid=2582，invite_code=R76JTv

---

## 六、接口面（已摸清）

- 公开：/site/settings /site/menu /categories /links /posts /posts/{id} /demands /stats/view /plans
- 认证：/auth/login /auth/register /auth/logout
- 用户：/user/profile 等

---

## 七、未完成 / 待办

1. 补 RAR 解压审计 199770「USDT空投盗U」、200157「授权秒U盗U四链」的合约侧代码
2. 后台入口 /JYW2022jqb.php 若对应站点仍活，可撞后台拿受害者全量库
3. 受害者私钥已明文在手，链上查 0x8bf16a... 当前余额/流向坐实损失
4. admin 爆破（登录无验证码，可低频定向）
5. 全库现有刀：wukong_admin_brute.py / wukong_admin_brute2.py / wukong_sensitive.py / wukong_userinfo.py / wukong_brute_bg.py / wukong_brute_launch.py / wukong_js_secret.py / wukong_jwt_crack.py

---

## 八、定性

网站本身是"源码交易平台"，但交易内容里包含可直接用于盗取用户加密货币的"盗U"源码（假钱包+授权钓鱼），且源码包内附带**真实受害者明文私钥/助记词**与运营者后台入口、明文密码库。平台侧自身也存在 TG Bot token、付费源码、USDT 地址、注册验证码等多重未授权泄露。整体为 A 级高危资产。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
