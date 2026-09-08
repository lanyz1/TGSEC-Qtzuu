---
name: tgsec-suite
description: "Use for attack-surface domain knowledge matrix."
version: 1.2.0
---

# 安全知识库 · TGSEC 一体化导航

按攻击面组织的安全知识矩阵。  
包根：含 `MASTER.md` + `domains/` + `scripts/bootstrap.sh` 的目录（常见 `~/security-suite`）。  
总入口：`MASTER.md` · 关键词表：`ROUTING.md` · 小白：`START.md`  
融合索引：`domains/FUSION-6000.md` · `domains/FUSION-20260908.md`

**规模（约）：** 24 域 · domains 5200+ 文件 · 14 伞形技能。

## 开打前强制（技能用全）

1. `skill_view(pentest-execution)` — 活靶纪律 / 覆盖矩阵 / 验证门 / OOB  
2. `skill_view(tgsec-suite)` — 本文件定攻击面  
3. 按下表 **补 load 专项伞形**（匹配到的必须 load，禁止跳过）  
4. `read_file domains/<面>/README.md`  
5. 同面优先：`playbook-6000/` → `hunter-6000/` → `src-methods/` → `torch-hunt/` → `torch-wiki/` → `case-lessons/` → 其它  
6. APK/IPA/逆向：`reverse-skill` + 本机 `master-route.sh --hint "…"`（有则用）

## 伞形技能全表（渗透时按需全开）

| skill_view | 触发词 / 场景 | 接着读 |
|------------|---------------|--------|
| `pentest-execution` | 任意活靶、继续深挖、平台链、反逻辑 | `hermes-skills/pentest-execution/references/` |
| `tgsec-suite` | 定域、知识库总路由 | `MASTER.md` `domains/` |
| `cdn-origin-tracing` | CDN/WAF/Cloudflare/源站 IP | skill scripts + recon |
| `hack-skills` | Web/API/SQLi/XSS/AD 深手册 | `/root/hack-skills` 或 domains 对应面 |
| `web-sec` | EXP/VUL 三层 Web | `/root/web-sec` + web-injection |
| `about-security` | 结构化 payload/字典 | Payload/Dic · domains 镜像 |
| `0day-exploit-library` | 产品名+版本 RCE | `domains/0day-exploits/` · `EXPLOITARIUM-INDEX.md` |
| `reverse-skill` | APK/IPA/Frida/DEX/砸壳/IL2CPP/IDA/pwn | `panda-rev/` · master-route |
| `gambling-platform-pentest` | 博彩/代收/代理 BFLA | `domains/gambling-pentest/` |
| `black-cat-redteam` | 假设驱动状态机 | `redteam-framework/black-cat/` |
| `stopen` | OODA 自动渗透代理 | skill 内 |
| `claude-bughunter` | BB 狩猎技能卡 | 与 src-methods 交叉 |
| `secatlas` | YAML 技术卡片 | SecAtlas 树 |
| `security-kb-ingest` | 外仓吸收进 domains | skill 纪律 |

> 本机私有伞形（如 `defi-authorize-drain`）不在公开仓 sync 列表时，以 `~/.hermes/skills/security/` 实存为准，活靶涉及 DeFi 授权盘再 load。

## 主题域速查

| 域 | 何时 | 约文件 |
|----|------|--------|
| recon | 子域/端口/组件情报/OSINT/TORCH tools | 1000+ |
| web-injection | SQLi/XSS/SSRF/XXE/反序列化/torch-hunt/orwa 字典 | 1100+ |
| web-attack | CSRF/走私/WAF/竞态/开放重定向 | 120+ |
| auth-security | IDOR/JWT/OAuth/401-403/身份层 | 70+ |
| file-vulns | 上传/LFI/白盒审计 | 390+ |
| api-security | GraphQL/API 网关/BOLA | 50+ |
| business-logic | 支付/逻辑/Crown | 20+ |
| mobile-security | APK/IPA/Frida/panda-rev/iOS CVE | 80+ |
| reverse-engineering | IDA/Ghidra/panda-rev 符号结构体 | 60+ |
| cloud-security | 云/K8s/CI-CD/容器 | 180+ |
| binary-pwn | fuzz/shellcode/exploit dev | 50+ |
| ad-attack / windows-post / linux-post | 域与后渗 | 见 MASTER |
| redteam-framework | 状态机/Anti-Logic/torch campaign | 160+ |
| 0day-exploits | 产品 RCE + exploitarium | 650+ |
| llm-ai-security | Prompt/RAG/MCP | 50+ |
| post-exp-tools / malware-dfir / ctf / gambling-pentest / … | 后渗/取证/靶场/博彩 | 见 MASTER |

## 2026-09-08 增量路径

- `domains/**/torch-wiki|torch-hunt|torch-workflow` — TORCH  
- `domains/redteam-framework/torch-scripts/` — campaign/next_move/coverage  
- `domains/mobile-security/panda-rev/` · `reverse-engineering/panda-rev/`  
- `domains/web-injection/Payload/sqli/*orwa*`  
- `domains/0day-exploits/EXPLOITARIUM-INDEX.md`

## 5 步路由

1. 定阶段 2. 定域 3. load 伞形 4. 读 README 5. 进 playbook/hunter/src/torch/case

## 工具链

```bash
bash scripts/check-tools.sh
bash scripts/install-tools.sh
bash scripts/sync-hermes-skills.sh   # pull 后必跑
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
