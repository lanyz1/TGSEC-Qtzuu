# 仓库保留 / 可删对照

> 删之前先看依赖。技能伞形在 `hermes-skills/`，正文在 `domains/`。

## 建议保留（主链路）

| 路径 | 原因 |
|------|------|
| `domains/*` 各攻击面正文 | 主知识库 |
| `domains/*/playbook-6000` | 6000 方法论 |
| `domains/*/hunter-6000` | offensive 手册 |
| `domains/*/src-methods` | SRC 方法 |
| `hermes-skills/` | 旧机器覆盖安装 Hermes 技能 |
| `scripts/sync-hermes-skills.sh` | 技能同步 |
| `scripts/reinstall-tgsec.sh` | 一键重装 |
| `MASTER.md` / `AGENTS.md` / `ai-config/` | 入口与多 AI 配置 |
| `scripts/check-tools.sh` `install-tools.sh` | 工具链 |

## 可删（不影响主路由，仅占空间/重复）

| 路径 | 说明 | 风险 |
|------|------|------|
| `hermes-config/` | 与 `ai-config/hermes/` **内容重复** | 低；删前确认只用 ai-config |
| `domains/integration-report.json` | 旧融合统计 | 无 |
| `domains/integration-report-6000.json` | 6000 融合过程 JSON | 无（有 FUSION-6000.md 即可） |
| `domains/ctf/case-reports-6000/` | 别人的渗透报告样例，非通用方法 | 低；仅少参考文风 |
| `domains/other/playbook-6000/cyberstrike-eino-demo/` | demo 壳，价值低 | 无 |
| `domains/malware-dfir/vuln-hunter-memory/vuln_memory_data/` | 空数据目录（若又出现） | 无 |
| 根目录重复人格 | 只留 `ai-config/hermes` | 低 |

## 不要删（除非你知道自己在干啥）

- `domains/0day-exploits/` — 产品 exploit 库
- `domains/web-injection/` 等大域
- `hermes-skills/pentest-execution` `tgsec-suite` `reverse-skill`
- `ai-config/universal/`

## 机器上的旁路目录（不在本 git 仓内）

这些是历史 clone，**suite 已融过该融的**；磁盘紧可归档/删，但对应 Hermes 伞形若仍指向原路径会断：

| 路径 | 约大小 | Hermes 技能仍可能引用 |
|------|--------|------------------------|
| `/root/AboutSecurity` | ~68M | `about-security` |
| `/root/reverse-skill` | ~29M | `reverse-skill`（路由引擎，建议留） |
| `/root/Stopen` | ~12M | `stopen` |
| `/root/Claude-BugHunter` | ~7M | `claude-bughunter` |
| `/root/hack-skills` | ~7M | `hack-skills` |
| `/root/SecAtlas` | ~3.6M | `secatlas` |
| `/root/web-sec` | ~2.9M | `web-sec` |
| `/root/Black-cat` | ~0.8M | `black-cat-redteam` |
| `/www/wwwroot/skill` | 空 | `skill-arsenal`（内容已空，技能近废） |

`reverse-skill` **建议保留**（master-route 依赖）。其它镜像若只当只读库且磁盘紧，可 `tar` 归档后再删；删前改技能内路径或改为只用 `domains/`。

@TGSEC社区 · @TGSEC-Qtzuu 整理
