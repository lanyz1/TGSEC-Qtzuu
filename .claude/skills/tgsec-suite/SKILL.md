---
name: tgsec-suite
description: "Use for attack-surface domain knowledge matrix."
version: 1.3.0
---

# 安全知识库 · TGSEC 一体化导航

按攻击面组织的安全知识矩阵。  
包根：含 `MASTER.md` + `domains/` + `scripts/bootstrap.sh` 的目录（常见 `~/security-suite`）。  
总入口：`MASTER.md` · 关键词表：`ROUTING.md` · 小白：`START.md`  
**实战报告总入口（强制）：`domains/CASE-INDEX.md`**  
融合索引：`domains/FUSION-6000.md` · `domains/FUSION-20260920-absorb.md`

**规模（约）：** 25 域 · domains 18700+ 文件 · 14 伞形技能 · 实战课 50 篇。

## 开打前强制（技能用全）

1. `skill_view(pentest-execution)` — 活靶纪律 / 覆盖矩阵 / 验证门 / OOB  
2. `skill_view(tgsec-suite)` — 本文件定攻击面  
3. 按下表 **补 load 专项伞形**（匹配到的必须 load，禁止跳过）  
4. `read_file domains/<面>/README.md`  
5. **`read_file domains/CASE-INDEX.md`** → 同面至少 `read_file` 1 篇 `case-lessons/<slug>.md`（无命中则在推进日志写「本面无 case」）  
6. 同面优先：`case-lessons/` → `playbook-6000/` → `hunter-6000/` → `src-methods/` → `torch-*` → 其它  
7. APK/IPA/逆向：`reverse-skill` + 本机 `master-route.sh --hint "…"`（有则用）

> 「只 load 技能、从不打开 CASE-INDEX/case-lessons」= **调用失败**。知识堆在 domains 不算用上。

## 伞形技能全表（渗透时按需全开）

| skill_view | 触发词 / 场景 | 接着读 |
|------------|---------------|--------|
| `pentest-execution` | 任意活靶、继续深挖、平台链、反逻辑 | `hermes-skills/pentest-execution/references/` |
| `tgsec-suite` | 定域、知识库总路由、实战课入口 | `MASTER.md` `ROUTING.md` `domains/CASE-INDEX.md` |
| `cdn-origin-tracing` | CDN/WAF/Cloudflare/源站 IP | skill scripts + recon |
| `hack-skills` | Web/API/SQLi/XSS/AD 深手册 | domains 对应面 + CASE-INDEX |
| `web-sec` | EXP/VUL 三层 Web | web-injection / web-attack |
| `about-security` | 结构化 payload/字典 | Payload/Dic · domains 镜像 |
| `0day-exploit-library` | 产品名+版本 RCE | `domains/0day-exploits/` · `EXPLOITARIUM-INDEX.md` |
| `reverse-skill` | APK/IPA/Frida/DEX/砸壳/IL2CPP/IDA/pwn | `panda-rev/` · master-route |
| `gambling-platform-pentest` | 博彩/代收/代理 BFLA/白标大厅 | `domains/gambling-pentest/` + CASE-INDEX |
| `black-cat-redteam` | 假设驱动状态机 | `redteam-framework/black-cat/` |
| `stopen` | OODA 自动渗透代理 | skill 内 |
| `claude-bughunter` | BB 狩猎技能卡 | 与 src-methods 交叉 |
| `secatlas` | YAML 技术卡片 | SecAtlas 树 |
| `security-kb-ingest` | 外仓吸收进 domains | skill 纪律 |

> 本机私有伞形（如 `white-label-hall-wss-pentest` / `defi-authorize-drain`）以 `~/.hermes/skills/security/` 实存为准，命中资产必须 load。

## 实战课调用（中途闸门）

| 资产信号 | skill_view（私有优先） | CASE-INDEX / 课 |
|----------|------------------------|-----------------|
| 发卡/独角/卡密/号商 | `card-merchant-platform-pentest` → `usdt-faka-filter-saas` | business-logic：dujiao / acg / fbdwj / kashang |
| 钱包/支付回调 | （business 面） | payment-callback / vi-wallet / haiwaipay / fllqb |
| TG云控/export | （api 面） | 711tock / 715tg / tg-filter / tg-ops |
| TG Mini App 钱包 | `tg-miniapp-wallet-pentest` | mobile / api |
| 博彩/代收 | `gambling-platform-pentest` | tongbao / goodluck777 / kaiyun28 |
| 白标大厅 WSS（712/777） | `white-label-hall-wss-pentest` | gambling · `712win3-partial-users` |
| 白标支付后台 | `white-label-pay-admin` | business-logic |
| 空投盗U/drainer | `crypto-drainer-farm-pentest` | crypto / business |
| DeFi 授权挖矿 | `defi-authorize-drain` | crypto-web-campaign-patterns |
| 杀猪盘/假交易所 | `scam-exchange-platform-pentest` | gambling / business |
| WAF/EdgeOne/上传 | `waf-fronted-login-attack` / `cdn-origin-tracing` | web-attack：edgeone / 507mx / 85amz |
| CF 真源 / 自建面板 | `cf-hidden-origin-tracing` / `self-hosted-panel-takeover` | recon |
| RuoYi 列表越权 | （auth 面） | ruoyi-datascope |
| RuoYi-Plus 匿名 getToken / 固定 App 会话 | （auth 面） | `ruoyi-plus-anonymous-gettoken` |
| DarkSword / Coruna / iOS C2 / payload entry | `darksword-coruna-c2-pentest` | `darksword-coruna-c2` |
| BMS / PC28 / 算法.py 上传沙箱 | `bms-pc28-console-pentest` | `bms-pc28-console` |
| ChatNet / LskyPro / Cloudreve UGC | `chatnet-lsky-cloudreve-ugc` | `chatnet-lsky-cloudreve-ugc` |
| 82vip / LL.VIP / `/ll/center` 调账 | `82vip-ll-center-pentest` | `82vip-ll-center` |
| Kylin / 麒麟黑卡 /ucard | `kylin-worldpay-ucard-pentest` | `kylin-worldpay-ucard` |
| xmnyme 未授权发码 forget | （auth 面） | `xmnyme-forget-unauth-code` |
| MCP/DCR | （auth 面） | cloudflare-mcp / okx-mcp |
| LLM 网关中转 | `llm-gateway-pentest` | badhost-litellm |

继续深挖 / 换向量前：**再扫一眼 CASE-INDEX**，并 load 上表命中的私有技能；避免只用通用 SQLi/爆破空转。

`src-methods/_vendor/sinian/` = 补充读物，默认不整目录遍历。

## 主题域速查

| 域 | 何时 | 约文件 |
|----|------|--------|
| recon | 子域/端口/组件情报/OSINT | 1100+ |
| web-injection | SQLi/XSS/SSRF/XXE/反序列化 | 1200+ |
| web-attack | CSRF/走私/WAF/竞态 | 170+ |
| auth-security | IDOR/JWT/OAuth/身份层 | 110+ |
| file-vulns | 上传/LFI/白盒审计 | 410+ |
| api-security | GraphQL/API/BOLA | 80+ |
| business-logic | 支付/逻辑/发卡钱包案 | 70+ |
| mobile-security | APK/IPA/Frida/iOS CVE | 80+ |
| reverse-engineering | IDA/Ghidra/panda-rev | 360+ |
| cloud-security | 云/K8s/CI-CD | 290+ |
| binary-pwn | fuzz/shellcode | 60+ |
| ad-attack / windows-post / linux-post | 域与后渗 | 见 MASTER |
| redteam-framework | 状态机/Anti-Logic/torch | 530+ |
| 0day-exploits | 产品 RCE + exploitarium | 11000+ |
| llm-ai-security | Prompt/RAG/MCP | 110+ |
| gambling-pentest | 博彩/代收 | 18+ |
| wireless | WiFi/BLE/Zigbee | 29 |
| post-exp-tools / malware-dfir / ctf / … | 后渗/取证/靶场 | 见 MASTER |

## 5 步路由

1. 定阶段 2. 定域 3. load 伞形 4. **CASE-INDEX + case-lessons≥1** 5. playbook/hunter/src/torch

## 工具链

```bash
bash scripts/check-tools.sh
bash scripts/install-tools.sh
bash scripts/sync-hermes-skills.sh   # pull 后必跑
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
