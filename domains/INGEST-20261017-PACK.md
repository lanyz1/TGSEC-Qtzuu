# INGEST-20261017-PACK — 外部分享包全量吸收

> 来源：gofile `gyRM3T07` → `报告.zip`（123,871,182 B，MD5 `3ef1a742…`，2026-10-17 落地）
> 性质：另一台 Hermes 作战库的分享脱敏包（同源血统；多处与本仓、本机技能库一字不差）
> 纪律：原文留本机案卷（`/root/cases/_absorb/pack_20261017/`），**原文不入库**；本文件只记动作与结果。

## 一、技能库（本机 `~/.hermes/skills`）

| 动作 | 数量 | 说明 |
|------|------|------|
| 净新胖卡导入（export） | **382** | 302 安全 + 80 其它；跳过 74 stub / 10 薄卡 |
| 净新实战卡导入（tar） | **564** | CJK 全量（≥2K）；tar 库共 2,022 卡，与 export 零 md5 重叠 |
| 升级段合并（同名 pack 更厚） | **88** | 仅追加包版独有 H2 段（384 KB），**不覆盖本机增量** |
| 百科全书 router | **1** | `security-encyclopedia`：930 张英文参考卡压成 `references/*.md`，避免 system prompt 爆炸 |
| 前栅修复 | 4 | 裸冒号描述加引号（`supply-chain` / `web-ssrf` / `privilege-escalation` / `jwt-attack-methodology`） |
| 库规模 | **1,211 → 2,158** | 零重名、零嵌套 SKILL.md 污染 |

- 重复件识别：`pool_manual` 矿池手册早存在于 `mining-pool-pentest/references`（8 文件全同，删新增副本）；`gpu-root-persistence-pack-v1.1`、`phoenix_forge_v1` 已入过，入 `_skipped/`。
- `卡网skill.txt`（ACG 回调绕过 57 KB）并入 `acg-faka-pentest/references/`，不占技能位。
- 安检：全文扫提示注入 / 真凭据 / 压缩炸弹 → 0 真凭据；AKIA 3 处为 AWS 文档示例、PEM 4 处为字面量、t.me 20 处为目标情报非推广。

## 二、战报 → case-lessons（本仓）

新增 **12 课**（原文仅本机）：

| 域 | slug |
|----|------|
| web-security | `laravel-livewire-callback-root-chain` · `okx-icu-darkword-c2-panel` · `magento-recaptcha-header-signup` |
| gambling-pentest | `olympus-tm99s-filament-rce-ddl` · `r64-grey-card-ledger-desens` |
| redteam-framework | `gameseal-b3w1443-not-landed` · `session-20261012-three-chains` |
| reverse-engineering | `c17-captured-arsenal-persistence` · `hyrz-il2cpp-privacy-audit` |
| crypto-attacks | `tgdemo61-usdt-staking-fastadmin-root` |
| gpu-ai-security | `gpu-vps-cve-shortlist-2026q4` |
| recon | `email-archive-extraction-assessment` |

增量追加 **2 课**：`711tock-tg-cloud`（WASM oracle / 明文口令面 / 363 会话 / 限流指纹）· `nbgame-agent-console-takeover`（operlog 权限地图 / logininfor 白名单 oracle）。

CASE-INDEX：课数按实盘同步 **113 → 127**（旧表少计 4 课一并校正）；域计数同步。

## 三、纯数据 / 源码（不入库）

- `vcchomes_full_export_20261014.tar.xz`（36 MB）+ `vcchomes_profiles.csv.gz`（11 MB）→ `/root/loot_archive/vcchomes_20261017/`
- 源码/工具：`chatgpt_reg_src.zip`、`regbot_sanitized_20261015`、`http80_fixed.zip`、`sysd_kit_20261014_clean.tar.gz` → `/root/cases/_absorb/pack_20261017/src/`
- 情报 PDF：`rce-in-2026-tg@gitbook_s.pdf`、`top-43.tg@gitbook_s.pdf` → 同目录 `intel/`
- 技能库归档：`skills-export-脱敏版.zip`、`hermes_skills_share.tar.gz` → `skill-archives/`

## 四、未吸收

- export 侧 74 张 <1.5 K stub + 10 张非 CJK 薄卡（无战术增量）
- tar 侧 418 张 <2 K / 纯薄卡（已并入 router 可检索范围外）
- `hermes_skills_说明.md`（59 K 分类说明）仅作索引参考，未入仓
