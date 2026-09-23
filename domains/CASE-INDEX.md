# CASE-INDEX — 实战报告总目录（AI 强制入口）

> **渗透中途必查。** 命中资产类型后：先本表 → `case-lessons/<slug>.md`（课）→ `case-reports/<slug>/`（全文）。
> 不要只读通用 playbook 就开打；同面有 case 时必须至少打开 1 篇相关课。

- 课（case-lessons）：**62**
- 域覆盖：api-security, auth-security, business-logic, cloud-security, gambling-pentest, llm-ai-security, recon, redteam-framework, reverse-engineering, web-attack
- 生成：2026-09-20（闭环优化后）

## 怎么用（Hermes / 任意 AI）

```text
1. skill_view(pentest-execution) + skill_view(tgsec-suite)
2. 命中私有资产 → skill_view(对应私有技能)（白标/发卡/盗U/假交易所/LLM网关…）
3. read_file domains/<面>/README.md
4. read_file domains/CASE-INDEX.md（本文件）定位 slug
5. read_file domains/<面>/case-lessons/<slug>.md
6. 需要证据再进 case-reports/<slug>/
```

## 关键词速查

| 信号 | 优先打开 |
|------|----------|
| 实战报告 / 同类案 / Evidence | 本文件 + `recon/case-lessons/README.md` |
| 发卡 / 卡密 / 独角 / ACG / FBDWJ / 卡商 | `card-merchant-platform-pentest` + business-logic 课 |
| 钱包 / 收款 / TRC20 / 支付回调 | business-logic payment/vi-wallet/haiwaipay/fllqb |
| TG云控 / export / 库存 BOLA | api-security 711tock/715tg/tg-filter/tg-ops |
| TG Mini App 钱包 | `tg-miniapp-wallet-pentest` |
| 博彩 / 代收 / 代理 | `gambling-platform-pentest` + gambling 课 |
| 白标大厅 WSS / 712 / 777club | `white-label-hall-wss-pentest` + `712win3-partial-users` |
| 空投盗U / drainer | `crypto-drainer-farm-pentest` |
| 假交易所 / 杀猪盘 | `scam-exchange-platform-pentest` |
| WAF / EdgeOne / 开放注册上传 | `waf-fronted-login-attack` / web-attack 课 |
| RuoYi / DataScope / 列表越权 | auth-security ruoyi-datascope |
| MCP / DCR / OAuth 客户端 | auth-security cloudflare-mcp / okx-mcp |
| LLM / LiteLLM 网关 | `llm-gateway-pentest` + badhost-litellm |

## `api-security`（11）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `711tock-tg-cloud` | - Source report: 711tock_审计报告.md | `domains/api-security/case-lessons/711tock-tg-cloud.md` | `domains/api-security/case-reports/711tock-tg-cloud/` |
| `715tg-cloud-fullcycle` | - Source report: 715TG云控_全周期审计报告.md | `domains/api-security/case-lessons/715tg-cloud-fullcycle.md` | `domains/api-security/case-reports/715tg-cloud-fullcycle/` |
| `luobo-lingdong-konghao` | - Source report: 萝卜快测平台渗透测试报告.md | `domains/api-security/case-lessons/luobo-lingdong-konghao.md` | `domains/api-security/case-reports/luobo-lingdong-konghao/` |
| `session-progress-20260908` | - Source report: session-progress-2026-09-08.md | `domains/api-security/case-lessons/session-progress-20260908.md` | `domains/api-security/case-reports/session-progress-20260908/` |
| `tg-cloud-export-bola` | 平台：Telegram 云控 / 筛号 / 账号库存（Go/Gin 或同类 + Vue SPA + CDN）。 | `domains/api-security/case-lessons/tg-cloud-export-bola.md` | — |
| `tg-filter-platform` | - Source report: TG筛号平台-渗透测试报告.md | `domains/api-security/case-lessons/tg-filter-platform.md` | `domains/api-security/case-reports/tg-filter-platform/` |
| `tg-ops-cluster-alanyhq` | - Source report: TG运营集群-综合渗透报告.md | `domains/api-security/case-lessons/tg-ops-cluster-alanyhq.md` | `domains/api-security/case-reports/tg-ops-cluster-alanyhq/` |
| `uu-im-8089-multiface` | UU钱包/iM/8089注单：未授权upload+download/resource XSS；WebWS设备表；accounts SSRF；群管OpenAPI | `domains/api-security/case-lessons/uu-im-8089-multiface.md` | — |
| `darksword-coruna-c2` | 同机 ThinkPHP刷单+DarkSword+Coruna：phar/FPM/PwnKit 或 payload %2f LFI；JackApple 数据面密钥 | `domains/api-security/case-lessons/darksword-coruna-c2.md` | — |
| `bms-pc28-console` | BMS/PC28：算法.py沙箱逃逸→root；占位session伪造；OKPAY回调 | `domains/api-security/case-lessons/bms-pc28-console.md` | — |
| `chatnet-lsky-cloudreve-ugc` | Lsky is_admin + ChatNet未授权建管 + OSS根AK→云助手root | `domains/api-security/case-lessons/chatnet-lsky-cloudreve-ugc.md` | — |

## `auth-security`（6）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `cloudflare-mcp-dcr` | - Source report: Cloudflare_DCR_漏洞报告.md | `domains/auth-security/case-lessons/cloudflare-mcp-dcr.md` | `domains/auth-security/case-reports/cloudflare-mcp-dcr/` |
| `okx-mcp-dcr` | - Source report: OKX_DCR_漏洞报告.md | `domains/auth-security/case-lessons/okx-mcp-dcr.md` | `domains/auth-security/case-reports/okx-mcp-dcr/` |
| `ruoyi-datascope-list-bola` | - 登录角色 charge/业务客户，权限点很多但 system/ 管理面 403 | `domains/auth-security/case-lessons/ruoyi-datascope-list-bola.md` | — |
| `ruoyi-plus-anonymous-gettoken` | RuoYi-Vue-Plus 匿名/getToken发固定会员会话→批量PII | `domains/auth-security/case-lessons/ruoyi-plus-anonymous-gettoken.md` | — |
| `xmnyme-forget-unauth-code` | 未授权 send_email type=2 + forget_password 改密接管邮箱号；后台 429 禁喷 | `domains/auth-security/case-lessons/xmnyme-forget-unauth-code.md` | — |
| `2fa-logic-bypass-13` | 2FA 逻辑绕过 13 条（响应篡改/码复用/关 2FA CSRF/不踢旧会话） | `domains/auth-security/case-lessons/2fa-logic-bypass-13.md` | — |

## `business-logic`（15）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `acg-faka-mass-hunt` | - Source report: acg_mass_hunt_report.md | `domains/business-logic/case-lessons/acg-faka-mass-hunt.md` | `domains/business-logic/case-reports/acg-faka-mass-hunt/` |
| `dujiao-bug-notes` | - Source report: 独角BUG.md | `domains/business-logic/case-lessons/dujiao-bug-notes.md` | `domains/business-logic/case-reports/dujiao-bug-notes/` |
| `dujiao-next-1yuan-pay` | - Source report: Dujiao_Next_支付模块_1_元购_打折支付漏洞_—_完整漏洞报告与_PoC_.md | `domains/business-logic/case-lessons/dujiao-next-1yuan-pay.md` | `domains/business-logic/case-reports/dujiao-next-1yuan-pay/` |
| `farmtg-tier-bypass` | - Source report: 农场游戏越级购买.md | `domains/business-logic/case-lessons/farmtg-tier-bypass.md` | `domains/business-logic/case-reports/farmtg-tier-bypass/` |
| `fbdwj-faka-audit` | - Source report: FBDWJ_安全评估报告.md | `domains/business-logic/case-lessons/fbdwj-faka-audit.md` | `domains/business-logic/case-reports/fbdwj-faka-audit/` |
| `fllqb-wallet-dump` | - Source report: fllqb_福利来钱包_完整数据.md | `domains/business-logic/case-lessons/fllqb-wallet-dump.md` | `domains/business-logic/case-reports/fllqb-wallet-dump/` |
| `haiwaipay-audit` | - Source report: HAIWAIPAY_SECURITY_AUDIT_REPORT.md | `domains/business-logic/case-lessons/haiwaipay-audit.md` | `domains/business-logic/case-reports/haiwaipay-audit/` |
| `kashang-admin-takeover` | - Source report: kashang_takeover.md | `domains/business-logic/case-lessons/kashang-admin-takeover.md` | `domains/business-logic/case-reports/kashang-admin-takeover/` |
| `maojuid-cn-audit` | - Source report: AUDIT-REPORT.md | `domains/business-logic/case-lessons/maojuid-cn-audit.md` | `domains/business-logic/case-reports/maojuid-cn-audit/` |
| `payment-callback-forge-card-leak` | text | `domains/business-logic/case-lessons/payment-callback-forge-card-leak.md` | — |
| `snddapp-admin-audit` | - Source report: AUDIT_REPORT_admin_snddapp_2026-09-11.md | `domains/business-logic/case-lessons/snddapp-admin-audit.md` | `domains/business-logic/case-reports/snddapp-admin-audit/` |
| `sundapp-status` | - Source report: STATUS.md | `domains/business-logic/case-lessons/sundapp-status.md` | `domains/business-logic/case-reports/sundapp-status/` |
| `sundapp-status-continued` | - Source report: STATUS (2).md | `domains/business-logic/case-lessons/sundapp-status-continued.md` | `domains/business-logic/case-reports/sundapp-status-continued/` |
| `vi-wallet-admin-takeover` | - Source report: 2026-07-23_VI钱包后台-完整控制报告.md | `domains/business-logic/case-lessons/vi-wallet-admin-takeover.md` | `domains/business-logic/case-reports/vi-wallet-admin-takeover/` |
| `kylin-worldpay-ucard` | Kylin/麒麟黑卡 /ucard：未授权发码→会员票全站 IDOR→超管 user=pass+TOTP | `domains/business-logic/case-lessons/kylin-worldpay-ucard.md` | — |

## `cloud-security`（1）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `hushchat-s3` | - Source report: HushChat-S3渗透测试报告.md | `domains/cloud-security/case-lessons/hushchat-s3.md` | `domains/cloud-security/case-reports/hushchat-s3/` |

## `gambling-pentest`（7）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `712win3-partial-users` | 玩家态可扩 部分用户（排行榜 11326 + BindThird 占用预言机 + FB 弱密）；全站用户表卡在 admin JWT（cache 桶）/ 外网 MSSQL ACL。 | `domains/gambling-pentest/case-lessons/712win3-partial-users.md` | `domains/gambling-pentest/case-reports/712win3-partial-users/` |
| `dygy-bytedream-scam` | - Source report: 抖音公益平台.txt | `domains/gambling-pentest/case-lessons/dygy-bytedream-scam.md` | `domains/gambling-pentest/case-reports/dygy-bytedream-scam/` |
| `goodluck777-20260915` | - Source report: REP-GOODLUCK777-2026-0915 .md | `domains/gambling-pentest/case-lessons/goodluck777-20260915.md` | `domains/gambling-pentest/case-reports/goodluck777-20260915/` |
| `macau-live-6app` | - Source report: 高危漏洞.md | `domains/gambling-pentest/case-lessons/macau-live-6app.md` | `domains/gambling-pentest/case-reports/macau-live-6app/` |
| `tongbao-game-audit` | - Source report: AUDIT_REPORT.md | `domains/gambling-pentest/case-lessons/tongbao-game-audit.md` | `domains/gambling-pentest/case-reports/tongbao-game-audit/` |
| `vvgzrvtt-kaiyun28` | - Source report: FULL_REPORT.md | `domains/gambling-pentest/case-lessons/vvgzrvtt-kaiyun28.md` | `domains/gambling-pentest/case-reports/vvgzrvtt-kaiyun28/` |
| `82vip-ll-center` | 82vip/LL.VIP：Nacos Host 绕 CF Access → /ll/center AES 未授权调账（XFF） | `domains/gambling-pentest/case-lessons/82vip-ll-center.md` | — |

## `llm-ai-security`（1）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `badhost-litellm` | - Source report: BadHost_LiteLLM_报告.md | `domains/llm-ai-security/case-lessons/badhost-litellm.md` | `domains/llm-ai-security/case-reports/badhost-litellm/` |

## `recon`（7）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `176-122-161-117-audit` | - Source report: 176.122.161.117-渗透审计报告.md | `domains/recon/case-lessons/176-122-161-117-audit.md` | `domains/recon/case-reports/176-122-161-117-audit/` |
| `multi-target-chain-20260803` | - Source report: 综合渗透测试报告-全目标.md | `domains/recon/case-lessons/multi-target-chain-20260803.md` | `domains/recon/case-reports/multi-target-chain-20260803/` |
| `quta-zhixin-mapping` | - Source report: 完整测绘报告.md | `domains/recon/case-lessons/quta-zhixin-mapping.md` | `domains/recon/case-reports/quta-zhixin-mapping/` |
| `recent-targets-digest-20260913` | - Source report: 审计报告_近期目标合集_20260913 (2).md | `domains/recon/case-lessons/recent-targets-digest-20260913.md` | `domains/recon/case-reports/recent-targets-digest-20260913/` |
| `report-evidence-finding-path` | 1. 目标画像：栈、CDN、角色、API 前缀 | `domains/recon/case-lessons/report-evidence-finding-path.md` | — |
| `unauth-settings-bot-token-download` | - Bot Token 有效 + webhook 空 → 可劫持推送/假客服（报告只写风险，不教诈骗话术） | `domains/recon/case-lessons/unauth-settings-bot-token-download.md` | — |
| `vuln-batch-export-20260901` | - Source report: vulnerability-report-conversation-20260901-013932.md | `domains/recon/case-lessons/vuln-batch-export-20260901.md` | `domains/recon/case-reports/vuln-batch-export-20260901/` |

## `redteam-framework`（1）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `redteam-chain-reasoning-matrix` | - Source report: CLAUDE.md | `domains/redteam-framework/case-lessons/redteam-chain-reasoning-matrix.md` | `domains/redteam-framework/case-reports/redteam-chain-reasoning-matrix/` |

## `reverse-engineering`（2）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `jjpc28-frontend-malware` | - Source report: jjpc28-static-malware-analysis.md | `domains/reverse-engineering/case-lessons/jjpc28-frontend-malware.md` | `domains/reverse-engineering/case-reports/jjpc28-frontend-malware/` |
| `qingmeng-fake-detector-botnet` | - Source report: 情梦后门 rar | `domains/reverse-engineering/case-lessons/qingmeng-fake-detector-botnet.md` | `domains/reverse-engineering/case-reports/qingmeng-fake-detector-botnet/` |

## `web-attack`（11）

| slug | 一句话 | 课 | 全文 |
|------|--------|----|------|
| `183-179-252-26` | - Source report: 渗透测试报告-183.179.252.26.md | `domains/web-attack/case-lessons/183-179-252-26.md` | `domains/web-attack/case-reports/183-179-252-26/` |
| `365jz-peizi-cluster` | - Source report: REPORT_365jz_final_2026-09-15.md | `domains/web-attack/case-lessons/365jz-peizi-cluster.md` | `domains/web-attack/case-reports/365jz-peizi-cluster/` |
| `507mx-waf-idor` | - Source report: 507mx_vulnerability_report.md | `domains/web-attack/case-lessons/507mx-waf-idor.md` | `domains/web-attack/case-reports/507mx-waf-idor/` |
| `85amz-rce-upload` | - Source report: 85amz_渗透测试报告.md | `domains/web-attack/case-lessons/85amz-rce-upload.md` | `domains/web-attack/case-reports/85amz-rce-upload/` |
| `edgeone-waf-open-register-upload` | text | `domains/web-attack/case-lessons/edgeone-waf-open-register-upload.md` | — |
| `max77-plus` | - Source report: max77.plus-渗透测试报告.md | `domains/web-attack/case-lessons/max77-plus.md` | `domains/web-attack/case-reports/max77-plus/` |
| `peiioh-leshi-meeting` | - Source report: peiioh_20260819_完整报告.md | `domains/web-attack/case-lessons/peiioh-leshi-meeting.md` | `domains/web-attack/case-reports/peiioh-leshi-meeting/` |
| `tgt-a-example-redacted` | - Source report: report.md | `domains/web-attack/case-lessons/tgt-a-example-redacted.md` | `domains/web-attack/case-reports/tgt-a-example-redacted/` |
| `werkzeug-rce-proof` | - Source report: 漏洞利用完整证明报告.md | `domains/web-attack/case-lessons/werkzeug-rce-proof.md` | `domains/web-attack/case-reports/werkzeug-rce-proof/` |
| `aqlm-999db-cluster` | aqlm/999db：TP 上传 RCE + TGBot webhook SQLi + PPay notifyUrl SSRF | `domains/web-attack/case-lessons/aqlm-999db-cluster.md` | — |
| `waf-glob-rce-bypass` | Linux glob `?` 绕 Sucuri/CRS PL1–3 拦 RCE（theMiddle） | `domains/web-attack/case-lessons/waf-glob-rce-bypass.md` | — |

## 纪律

- 活靶开打 / 「继续深挖」：伞形技能 + **同面 case-lessons ≥1** + 命中则 load 私有专项技能。
- `src-methods/_vendor/sinian/` 默认不遍历。
- 禁止把 case-reports 里的 Token/session/助记词写进对话落盘。
- 新案子：`case-reports/<slug>/` + `case-lessons/<slug>.md` + 更新本表。

@TGSEC社区 · @TGSEC-Qtzuu 整理
