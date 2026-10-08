# CASE-INDEX — 实战报告总目录（AI 强制入口）

> **渗透中途必查。** 命中资产类型后：先本表 → `case-lessons/<slug>.md`（课）。全文卷已撤库（原文存本机案卷）。
> 不要只读通用 playbook 就开打；同面有 case 时必须至少打开 1 篇相关课。

- 课（case-lessons）：**95**（全量实计；含 web-security / web-injection / crypto-attacks 域）
- 域覆盖：api-security, auth-security, business-logic, cloud-security, gambling-pentest, llm-ai-security, recon, redteam-framework, reverse-engineering, web-attack, web-security, web-injection, crypto-attacks
- 生成：2026-09-20（闭环优化后）

## 怎么用（Hermes / 任意 AI）

```text
1. skill_view(pentest-execution) + skill_view(tgsec-suite)
2. 命中私有资产 → skill_view(对应私有技能)（白标/发卡/盗U/假交易所/LLM网关…）
3. read_file domains/<面>/README.md
4. read_file domains/CASE-INDEX.md（本文件）定位 slug
5. read_file domains/<面>/case-lessons/<slug>.md
6. 需要证据 → 开本机案卷（原文已撤库，不在仓内）
```

## 关键词速查

| 信号 | 优先打开 |
|------|----------|
| 实战报告 / 同类案 / Evidence | 本文件 + `recon/case-lessons/README.md` |
| 发卡 / 卡密 / 独角 / ACG / FBDWJ / 卡商 | `card-merchant-platform-pentest` + business-logic 课 |
| 自研单入口 JSON 路由（`?action=` 分发）/ 未知操作 / 参数错误 | api-security 课 `zhangduozhe-api-router-and-weakadmin` |
| 付费产品安装包泄露在 `/uploads/`（备份文件猎捕胜过硬爆）/ 后台目录中文业务词枚举 / 上传强制扩展名 / 易语言客户端逆向 | web-security 课 `zd-leaked-product-package-and-cn-wordlist` |
| **若依(RuoYi)框架识别 / 默认账号 ry|admin123 / /dev-api 前缀坑 / BFLA 漏注解脱库 / 验证码打码 / bcrypt 快破** | web-security 课 `ruoyi-default-creds-and-bfla-mass-dump` |
| **自建静态服务器上的盗U站: `/server.js` 源码直读 + `?soladmin=1` 前端参数即管理员入口 + 管理API未鉴权** | web-security 课 `drainer-static-server-three-killshots` |
| 钱包 / 收款 / TRC20 / 支付回调 | business-logic payment/vi-wallet/haiwaipay/fllqb |
| TG云控 / export / 库存 BOLA | api-security 711tock/715tg/tg-filter/tg-ops |
| TG Mini App 钱包 | `tg-miniapp-wallet-pentest` |
| 博彩 / 代收 / 代理 | `gambling-platform-pentest` + gambling 课 |
| 白标大厅 WSS / 712 / 777club | `white-label-hall-wss-pentest` + `712win3-partial-users` |
| 空投盗U / drainer | `crypto-drainer-farm-pentest` |
| 假交易所 / 杀猪盘 | `scam-exchange-platform-pentest` |
| **杀猪盘 SaaS / 代理面板 / 审核流 CSRF / 密码预言机** | gambling 课 `sunnic-agent-portal-csrf` · `kachiho-password-oracle-ato` |
| **Docker API / 容器逃逸 / host_root / 持久化矩阵** | web-attack 课 `r4z-billionmail-root-escape` |
| **云账号接管 / GVA / EC2 Instance Connect / Rancher** | cloud 课 `gva-to-aws-account-takeover` |
| **单 IP 多系统农场 / TG 监听 / 端口→应用矩阵** | recon 课 `143-tg-farm-takeover` |
| WAF / EdgeOne / 开放注册上传 | `waf-fronted-login-attack` / web-attack 课 |
| RuoYi / DataScope / 列表越权 | auth-security ruoyi-datascope |
| MCP / DCR / OAuth 客户端 | auth-security cloudflare-mcp / okx-mcp |
| LLM / LiteLLM 网关 | `llm-gateway-pentest` + badhost-litellm |

## `api-security`（15）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `711tock-tg-cloud` | - Source report: 711tock_审计报告.md | `domains/api-security/case-lessons/711tock-tg-cloud.md` | 已撤库 |
| `715tg-cloud-fullcycle` | - Source report: 715TG云控_全周期审计报告.md | `domains/api-security/case-lessons/715tg-cloud-fullcycle.md` | 已撤库 |
| `luobo-lingdong-konghao` | - Source report: 萝卜快测平台渗透测试报告.md | `domains/api-security/case-lessons/luobo-lingdong-konghao.md` | 已撤库 |
| `session-progress-20260908` | - Source report: session-progress-2026-09-08.md | `domains/api-security/case-lessons/session-progress-20260908.md` | 已撤库 |
| `tg-cloud-export-bola` | 平台：Telegram 云控 / 筛号 / 账号库存（Go/Gin 或同类 + Vue SPA + CDN）。 | `domains/api-security/case-lessons/tg-cloud-export-bola.md` | — |
| `tg-filter-platform` | - Source report: TG筛号平台-渗透测试报告.md | `domains/api-security/case-lessons/tg-filter-platform.md` | 已撤库 |
| `tg-ops-cluster-alanyhq` | - Source report: TG运营集群-综合渗透报告.md | `domains/api-security/case-lessons/tg-ops-cluster-alanyhq.md` | 已撤库 |
| `uu-im-8089-multiface` | UU钱包/iM/8089注单：未授权upload+download/resource XSS；WebWS设备表；accounts SSRF；群管OpenAPI | `domains/api-security/case-lessons/uu-im-8089-multiface.md` | — |
| `darksword-coruna-c2` | 同机 ThinkPHP刷单+DarkSword+Coruna：phar/FPM/PwnKit 或 payload %2f LFI；JackApple 数据面密钥；+2026-10 farm 深挖（WAF 重放语义测穿） | `domains/api-security/case-lessons/darksword-coruna-c2.md` | 已撤库 |
| `bms-pc28-console` | BMS/PC28：算法.py沙箱逃逸→root；占位session伪造；OKPAY回调 | `domains/api-security/case-lessons/bms-pc28-console.md` | — |
| `chatnet-lsky-cloudreve-ugc` | Lsky is_admin + ChatNet未授权建管 + OSS根AK→云助手root | `domains/api-security/case-lessons/chatnet-lsky-cloudreve-ugc.md` | — |
| `okbot-quant-cluster` | 量化集群：14+27 API 免鉴权 + RabbitMQ admin/123456 + dddocr | `domains/api-security/case-lessons/quant-trading-unauth-surface.md` | 已撤库 |
| `kt8899-tg-cloud` | TG群控：SVG 验证码明文 + roleIdList:[] 绕过后门账号 + TG session 收割 | `domains/api-security/case-lessons/kt8899-tg-cloud-multisurface.md` | 已撤库 |
| `fina-icu-audit` | fina.icu 非破坏审计：_app.config.js RSA 私钥内联 + 测试面板暴露 | `domains/api-security/case-lessons/fina-ruoyi-nondestructive-audit.md` | 已撤库 |
| `openim-default-jwt-and-intel` | OpenIM 默认密钥 openIM123 伪造 imAdmin；「星环」指挥平台裸奔情报 | `domains/api-security/case-lessons/openim-default-jwt-and-intel.md` | — |

## `auth-security`（6）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `cloudflare-mcp-dcr` | - Source report: Cloudflare_DCR_漏洞报告.md | `domains/auth-security/case-lessons/cloudflare-mcp-dcr.md` | 已撤库 |
| `okx-mcp-dcr` | - Source report: OKX_DCR_漏洞报告.md | `domains/auth-security/case-lessons/okx-mcp-dcr.md` | 已撤库 |
| `ruoyi-datascope-list-bola` | - 登录角色 charge/业务客户，权限点很多但 system/ 管理面 403 | `domains/auth-security/case-lessons/ruoyi-datascope-list-bola.md` | — |
| `ruoyi-plus-anonymous-gettoken` | RuoYi-Vue-Plus 匿名/getToken发固定会员会话→批量PII | `domains/auth-security/case-lessons/ruoyi-plus-anonymous-gettoken.md` | — |
| `xmnyme-forget-unauth-code` | 未授权 send_email type=2 + forget_password 改密接管邮箱号；后台 429 禁喷 | `domains/auth-security/case-lessons/xmnyme-forget-unauth-code.md` | — |
| `2fa-logic-bypass-13` | 2FA 逻辑绕过 13 条（响应篡改/码复用/关 2FA CSRF/不踢旧会话） | `domains/auth-security/case-lessons/2fa-logic-bypass-13.md` | — |

## `business-logic`（17）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `acg-faka-mass-hunt` | - Source report: acg_mass_hunt_report.md | `domains/business-logic/case-lessons/acg-faka-mass-hunt.md` | 已撤库 |
| `dujiao-bug-notes` | - Source report: 独角BUG.md | `domains/business-logic/case-lessons/dujiao-bug-notes.md` | 已撤库 |
| `dujiao-next-1yuan-pay` | - Source report: Dujiao_Next_支付模块_1_元购_打折支付漏洞_—_完整漏洞报告与_PoC_.md | `domains/business-logic/case-lessons/dujiao-next-1yuan-pay.md` | 已撤库 |
| `farmtg-tier-bypass` | - Source report: 农场游戏越级购买.md | `domains/business-logic/case-lessons/farmtg-tier-bypass.md` | 已撤库 |
| `fbdwj-faka-audit` | - Source report: FBDWJ_安全评估报告.md | `domains/business-logic/case-lessons/fbdwj-faka-audit.md` | 已撤库 |
| `fllqb-wallet-dump` | - Source report: fllqb_福利来钱包_完整数据.md | `domains/business-logic/case-lessons/fllqb-wallet-dump.md` | 已撤库 |
| `haiwaipay-audit` | - Source report: HAIWAIPAY_SECURITY_AUDIT_REPORT.md | `domains/business-logic/case-lessons/haiwaipay-audit.md` | 已撤库 |
| `kashang-admin-takeover` | - Source report: kashang_takeover.md | `domains/business-logic/case-lessons/kashang-admin-takeover.md` | 已撤库 |
| `maojuid-cn-audit` | - Source report: AUDIT-REPORT.md | `domains/business-logic/case-lessons/maojuid-cn-audit.md` | 已撤库 |
| `payment-callback-forge-card-leak` | text | `domains/business-logic/case-lessons/payment-callback-forge-card-leak.md` | — |
| `snddapp-admin-audit` | - Source report: AUDIT_REPORT_admin_snddapp_2026-09-11.md | `domains/business-logic/case-lessons/snddapp-admin-audit.md` | 已撤库 |
| `sundapp-status` | - Source report: STATUS.md | `domains/business-logic/case-lessons/sundapp-status.md` | 已撤库 |
| `sundapp-status-continued` | - Source report: STATUS (2).md | `domains/business-logic/case-lessons/sundapp-status-continued.md` | 已撤库 |
| `vi-wallet-admin-takeover` | - Source report: 2026-07-23_VI钱包后台-完整控制报告.md | `domains/business-logic/case-lessons/vi-wallet-admin-takeover.md` | 已撤库 |
| `kylin-worldpay-ucard` | Kylin/麒麟黑卡 /ucard：未授权发码→会员票全站 IDOR→超管 user=pass+TOTP | `domains/business-logic/case-lessons/kylin-worldpay-ucard.md` | — |
| `apple-giftcards-dujiaoka` | 独角数卡 0 元购（通道归属不校验）+ epusdt 密钥进 URL + 回调伪造发货 | `domains/business-logic/case-lessons/dujiaoka-channel-ownership-0yuan.md` | 已撤库 |
| `kuaipao-merchant-api` | hou.kuaipao.us 商户 API 文档（HMAC-SHA256 签名规范） | `domains/business-logic/case-lessons/kuaipao-merchant-signing-notes.md` | 已撤库 |

## `cloud-security`（2）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `hushchat-s3` | - Source report: HushChat-S3渗透测试报告.md | `domains/cloud-security/case-lessons/hushchat-s3.md` | 已撤库 |
| `gva-aws-takeover` | GVA 配置泄露→AWS AdministratorAccess→EC2 Instance Connect ×28→Rancher→GitLab 全源码 | `domains/cloud-security/case-lessons/gva-to-aws-account-takeover.md` | 已撤库 |

## `gambling-pentest`（9）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `712win3-partial-users` | 玩家态可扩 部分用户（排行榜 11326 + BindThird 占用预言机 + FB 弱密）；全站用户表卡在 admin JWT（cache 桶）/ 外网 MSSQL ACL。 | `domains/gambling-pentest/case-lessons/712win3-partial-users.md` | 已撤库 |
| `dygy-bytedream-scam` | - Source report: 抖音公益平台.txt | `domains/gambling-pentest/case-lessons/dygy-bytedream-scam.md` | 已撤库 |
| `goodluck777-20260915` | - Source report: REP-GOODLUCK777-2026-0915 .md | `domains/gambling-pentest/case-lessons/goodluck777-20260915.md` | 已撤库 |
| `macau-live-6app` | - Source report: 高危漏洞.md | `domains/gambling-pentest/case-lessons/macau-live-6app.md` | 已撤库 |
| `tongbao-game-audit` | - Source report: AUDIT_REPORT.md | `domains/gambling-pentest/case-lessons/tongbao-game-audit.md` | 已撤库 |
| `vvgzrvtt-kaiyun28` | - Source report: FULL_REPORT.md | `domains/gambling-pentest/case-lessons/vvgzrvtt-kaiyun28.md` | 已撤库 |
| `82vip-ll-center` | 82vip/LL.VIP：Nacos Host 绕 CF Access → /ll/center AES 未授权调账（XFF） | `domains/gambling-pentest/case-lessons/82vip-ll-center.md` | — |
| `sunnic-agent-saas` | 杀猪盘 SaaS：agent 弱口令 + 审核流 CSRF/SSRF + 万能密码后门 | `domains/gambling-pentest/case-lessons/sunnic-agent-portal-csrf.md` | 已撤库 |
| `kachiho-fxgz` | 密码预言机批量 ATO（655→62）+ PAD SPACE 锁窗绕过 + 40+ RCE 排除矩阵 | `domains/gambling-pentest/case-lessons/kachiho-password-oracle-ato.md` | 已撤库 |

## `llm-ai-security`（1）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `badhost-litellm` | - Source report: BadHost_LiteLLM_报告.md | `domains/llm-ai-security/case-lessons/badhost-litellm.md` | 已撤库 |

## `recon`（8）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `176-122-161-117-audit` | - Source report: 176.122.161.117-渗透审计报告.md | `domains/recon/case-lessons/176-122-161-117-audit.md` | 已撤库 |
| `multi-target-chain-20260803` | - Source report: 综合渗透测试报告-全目标.md | `domains/recon/case-lessons/multi-target-chain-20260803.md` | 已撤库 |
| `quta-zhixin-mapping` | - Source report: 完整测绘报告.md | `domains/recon/case-lessons/quta-zhixin-mapping.md` | 已撤库 |
| `recent-targets-digest-20260913` | - Source report: 审计报告_近期目标合集_20260913 (2).md | `domains/recon/case-lessons/recent-targets-digest-20260913.md` | 已撤库 |
| `report-evidence-finding-path` | 1. 目标画像：栈、CDN、角色、API 前缀 | `domains/recon/case-lessons/report-evidence-finding-path.md` | — |
| `unauth-settings-bot-token-download` | - Bot Token 有效 + webhook 空 → 可劫持推送/假客服（报告只写风险，不教诈骗话术） | `domains/recon/case-lessons/unauth-settings-bot-token-download.md` | — |
| `vuln-batch-export-20260901` | - Source report: vulnerability-report-conversation-20260901-013932.md | `domains/recon/case-lessons/vuln-batch-export-20260901.md` | 已撤库 |
| `143-tg-farm` | 单 IP 36-40 套系统：TG 监听三件套 + 策略平台 + 假投注；端口→应用矩阵 | `domains/recon/case-lessons/143-tg-farm-takeover.md` | 已撤库 |

## `redteam-framework`（2）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `redteam-chain-reasoning-matrix` | - Source report: CLAUDE.md | `domains/redteam-framework/case-lessons/redteam-chain-reasoning-matrix.md` | 已撤库 |
| `fleet-master-20261002` | 舰队 50+ 目标聚合战报（以单报告为准） | — | 已撤库 |

## `reverse-engineering`（3）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `jjpc28-frontend-malware` | - Source report: jjpc28-static-malware-analysis.md | `domains/reverse-engineering/case-lessons/jjpc28-frontend-malware.md` | 已撤库 |
| `qingmeng-fake-detector-botnet` | - Source report: 情梦后门 rar | `domains/reverse-engineering/case-lessons/qingmeng-fake-detector-botnet.md` | 已撤库 |
| `electron-jsc-signature-oracle` | Electron jsc 字节码 → V8 签名 Oracle 重建 | `domains/reverse-engineering/case-lessons/electron-jsc-signature-oracle.md` | — |

## `web-attack`（17）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `183-179-252-26` | - Source report: 渗透测试报告-183.179.252.26.md | `domains/web-attack/case-lessons/183-179-252-26.md` | 已撤库 |
| `365jz-peizi-cluster` | - Source report: REPORT_365jz_final_2026-09-15.md | `domains/web-attack/case-lessons/365jz-peizi-cluster.md` | 已撤库 |
| `507mx-waf-idor` | - Source report: 507mx_vulnerability_report.md | `domains/web-attack/case-lessons/507mx-waf-idor.md` | 已撤库 |
| `85amz-rce-upload` | - Source report: 85amz_渗透测试报告.md | `domains/web-attack/case-lessons/85amz-rce-upload.md` | 已撤库 |
| `edgeone-waf-open-register-upload` | text | `domains/web-attack/case-lessons/edgeone-waf-open-register-upload.md` | — |
| `max77-plus` | - Source report: max77.plus-渗透测试报告.md | `domains/web-attack/case-lessons/max77-plus.md` | 已撤库 |
| `peiioh-leshi-meeting` | - Source report: peiioh_20260819_完整报告.md | `domains/web-attack/case-lessons/peiioh-leshi-meeting.md` | 已撤库 |
| `tgt-a-example-redacted` | - Source report: report.md | `domains/web-attack/case-lessons/tgt-a-example-redacted.md` | 已撤库 |
| `werkzeug-rce-proof` | - Source report: 漏洞利用完整证明报告.md | `domains/web-attack/case-lessons/werkzeug-rce-proof.md` | 已撤库 |
| `aqlm-999db-cluster` | aqlm/999db：TP 上传 RCE + TGBot webhook SQLi + PPay notifyUrl SSRF | `domains/web-attack/case-lessons/aqlm-999db-cluster.md` | — |
| `waf-glob-rce-bypass` | Linux glob `?` 绕 Sucuri/CRS PL1–3 拦 RCE（theMiddle） | `domains/web-attack/case-lessons/waf-glob-rce-bypass.md` | — |
| `r4z-crime-empire` | BillionMail Docker API→iptables 注入→chroot host_root 逃逸→宿主机 ROOT（126 webshell 持久化） | `domains/web-attack/case-lessons/r4z-billionmail-root-escape.md` | 已撤库 |
| `primetools-takedown` | CF 绕过→WP REST→CyberPanel→SSH；EIP-7702 Vault（见 crypto 课） | `domains/web-attack/case-lessons/cyberpanel-source-ssh-chain.md` | 已撤库 |
| `skyscrm-afbpay` | WS 登录免鉴权订阅（全量订单）+ 订单号即凭证 IDOR + jsc 签名 Oracle | `domains/web-attack/case-lessons/ws-login-unauth-subscribe.md` | 已撤库 |
| `onechat-chat` | Gitea diffpatch **apply 两次**暗门 + 容器逃逸失败条件清单 | `domains/web-attack/case-lessons/gitea-diffpatch-apply-twice.md` | 已撤库 |
| `tingyu28-qunkong` | 群控三件套：开放注册→workspace IDOR→导出 API（86.7万条） | `domains/web-attack/case-lessons/qunkong-console-trio.md` | 已撤库 |
| `guoqiang-jinpan` | /install 重入 + rogue MySQL 写配置；FCGI sock 0666 + sendmail 绕 disable_functions | `domains/web-attack/case-lessons/install-reentry-rogue-mysql.md` | 已撤库 |

## `web-security`（5）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `drainer-static-server-three-killshots` | 自建静态服务器盗U站：/server.js 源码直读 + ?soladmin=1 + 管理API未鉴权 | `domains/web-security/case-lessons/drainer-static-server-three-killshots.md` | — |
| `ruoyi-default-creds-and-bfla-mass-dump` | 若依默认口令 ry|admin123 + /dev-api 前缀坑 + BFLA 脱库 | `domains/web-security/case-lessons/ruoyi-default-creds-and-bfla-mass-dump.md` | — |
| `zd-leaked-product-package-and-cn-wordlist` | 付费安装包泄露 /uploads/ + 后台中文业务词枚举 | `domains/web-security/case-lessons/zd-leaked-product-package-and-cn-wordlist.md` | — |
| `mtdgs52-drainer-chain` | 盗U站群：INSERT 多行闭合 + extractvalue；授权钓鱼 + 链上追踪 | `domains/web-security/case-lessons/mtdgs52-drainer-chain.md` | 已撤库 |
| `majanito-drainer-audit` | Drainer 集群审计：`....//` 遍历 + 引擎五段式 + SELFDESTRUCT 证据固化 | `domains/web-security/case-lessons/majanito-drainer-audit.md` | — |

## `web-injection`（4）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `sqli-minimal-probe-to-ato` | SQLi 三步探型（200→500→200）→ ATO | `domains/web-injection/case-lessons/sqli-minimal-probe-to-ato.md` | — |
| `codeigniter-empty-where-bypass` | CodeIgniter 空 where `{}` 认证绕过 + JSON 键名 SQLi | `domains/web-injection/case-lessons/codeigniter-empty-where-bypass.md` | — |
| `blind-rce-char-oracle` | 盲 RCE 自适应 sleep 字符预言机 | `domains/web-injection/case-lessons/blind-rce-char-oracle.md` | — |
| `passive-xss-audit-zero-write` | 零写入被动审计（等效路径验证 + CSRF AB 对比） | `domains/web-injection/case-lessons/passive-xss-audit-zero-write.md` | 已撤库 |

## `crypto-attacks`（1）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `eip7702-vault-key-search` | EIP-7702/ERC-4337 Vault 识别 + 私钥穷尽搜查 12 面 | `domains/crypto-attacks/case-lessons/eip7702-vault-key-search.md` | — |

## 纪律

- 活靶开打 / 「继续深挖」：伞形技能 + **同面 case-lessons ≥1** + 命中则 load 私有专项技能。
- `src-methods/_vendor/sinian/` 默认不遍历。
- 禁止把案卷（原文本机）里的 Token/session/助记词写进对话落盘；更禁止入库。
- 新案子：只写 `case-lessons/<slug>.md`（提炼 + 脱敏硬门）；原文存本机案卷，不建 case-reports。

@TGSEC社区 · @TGSEC-Qtzuu 整理
