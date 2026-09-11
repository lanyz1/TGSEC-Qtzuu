# TGSEC-Qtzuu · 安全知识聚合库

> **@TGSEC社区 · @TGSEC-Qtzuu 整理**  
> 面向 **AI + 人** 的授权安全知识库：渗透测试、挖洞、红队方法论，按**攻击面**组织，可直接丢给 Grok Build / Claude / Cursor / Hermes / Codex 等使用。

**仓库地址：** https://github.com/lanyz1/TGSEC-Qtzuu  

**👉 完全零基础：只看 [`START.md`](START.md)（3 步）**  
**👉 AI 查「说了啥去哪个目录」：[`ROUTING.md`](ROUTING.md)**  
**👉 全部主题地图：[`MASTER.md`](MASTER.md)**

---

## 一、这是什么

本仓库不是「按上游项目名堆一堆文件夹」，而是把多份技能包、手册、PoC、字典、实战报告**拆开后，按攻击面重新融合**进 `domains/`，让 AI 和人都能按「我现在测的是登录 / 支付 / 注入…」找到对应资料，并在授权范围内**直接跑工具与 PoC**。

| 它是 | 它不是 |
|------|--------|
| 授权渗透 / 挖洞 / 评估用的**知识 + 路由 + 可执行资产** | 未授权攻击教程或自动「输入域名就授权」 |
| 给**多种 AI** 共用的同一套路径（不绑死 Hermes） | 必须安装某一种 AI 才能用 |
| 初学可从 `START.md` 进，熟手可从 `MASTER`/`domains` 深挖 | 只有黑盒脚本、没有说明 |
| **文档 + 工具链入口 + PoC/字典/战役脚本**一体 | 「只能读 md、真跑全靠宿主瞎猜」 |

**规模（以本机 `domains/` 实计，2026-09-10 融合后）：**

- **24** 个主题域
- **约 14000+** 文件（`domains/` 正文；含 poc-catalog 全量；以 `find domains -type f | wc -l` 为准）
- **14** 个伞形技能入口（`hermes-skills/` → 可 sync 到 Claude/Cursor/Hermes/…）
- **80+** 工具清单（`scripts/tools-manifest.json` + `check-tools.sh` / `install-tools.sh`）

> 旧文案里的「2879 / 3800+ / 5200+」是历史口径；**以本 README 与本地实计为准**。

---

## 二、30 秒上手（所有人）

### 1）下载

**Windows（PowerShell 一行，需 [Git for Windows](https://git-scm.com/download/win)）：**
```powershell
irm https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-windows.ps1 | iex
```

**Linux / macOS / WSL：**
```bash
curl -fsSL https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-linux.sh | bash
```

或手动：
```bash
git clone https://github.com/lanyz1/TGSEC-Qtzuu.git security-suite
cd security-suite
bash scripts/bootstrap.sh   # 写各 AI 入口 + 同步伞形技能
```

默认目录：`~/security-suite`（Windows 多为 `C:\Users\<用户名>\security-suite`）。

### 2）用 AI 打开整个文件夹

| AI | 做法 |
|----|------|
| Grok Build | 打开文件夹 → 选 `security-suite` |
| Claude CLI | 进入该目录再运行 `claude` |
| Cursor | Open Folder → `security-suite` |
| Hermes | 新会话，工作目录尽量指到该文件夹；再 `bash scripts/sync-hermes-skills.sh` |
| Codex / Aider | 以该目录为项目根 |

### 3）复制发给 AI（渗透 / 挖洞）

```text
请先读 START.md、AGENTS.md、ROUTING.md、MASTER.md。
我做的是【已授权】渗透测试和挖洞（侦察、找漏洞、可复现验证、出报告）。
按 ROUTING.md 去 domains/ 找资料；开打前按「技能加载矩阵」把对应伞形技能全部 load 齐。
用简单中文一步步带我做，给可复现命令，不要只讲概念。
目标与授权说明：……（填域名/范围，并写明已授权）
```

---

## 三、核心设计：全 AI 同一套路径

不依赖 Hermes 的 `skill_view`，任何能读仓库文件的 AI 都能用：

```text
AGENTS.md  →  AI 总规则（何时路由、授权边界、完成清单）
ROUTING.md →  人话关键词 → domains/ 下具体路径
MASTER.md  →  24 域导航 + 渗透阶段
domains/   →  全部知识正文 + PoC + 字典 + 战役脚本
scripts/   →  工具安装/检查/技能同步（可执行工具链入口）
```

**同主题推荐阅读顺序：**

```text
domains/<面>/README.md
  → playbook-6000/     （系统测试手册）
  → hunter-6000/       （进攻向专题）
  → src-methods/       （SRC 挖洞方法）
  → torch-hunt/ / torch-wiki/   （TORCH 猎杀手册 + 技术页，2026-09-08）
  → case-lessons/      （实战报告提炼，脱敏）
  → 其它专项 md / Payload / exploit
```

`hermes-skills/` 是 **伞形路由器**（约 14 个入口），sync 后加速定位；**细粮永远在 `domains/`**。

---

## 四、文档 + 可执行，不是「只能看」

别的模型如果说「只有文档、真跑靠宿主」——本仓的定位是：

| 层 | 你在本仓得到什么 | 怎么跑 |
|----|------------------|--------|
| 路由 | `ROUTING` / `MASTER` / 伞形 SKILL | AI 打开即用 |
| 方法论 | playbook / hunter / src-methods / torch-hunt | 逐步照做 |
| 字典 / Payload | `domains/**/Payload`、`sql-wordlist-orwa.txt`、AboutSecurity-Dic | ffuf/sqlmap/自定义脚本直接喂 |
| 产品 PoC | `domains/0day-exploits/**`（含 exploitarium 批次） | 授权实验室按 README 复现 |
| 战役状态机 | `pentest-execution` + `redteam-framework/torch-scripts/` | coverage / Deadend / next-move |
| 逆向专项 | `panda-rev`（Frida/DEX dump/砸壳/IL2CPP/IDAPython/Unicorn） | 本机 ADB/Frida/IDA 环境执行 |
| 宿主工具 | `scripts/tools-manifest.json`（80+） | `bash scripts/check-tools.sh` → `install-tools.sh` |

**边界说清楚：** 本仓**不**内嵌完整 C2 商业马、不替你装 Kali 全家桶；它提供的是「测什么 → 去哪读 → 用哪条命令/PoC/字典」的可执行闭环。工具二进制由 `install-tools` 按清单装到宿主——这是刻意设计，不是缺失。

---

## 五、目录结构

```text
START.md                 小白 3 步
INSTALL.md               安装速查
README.md                本说明（详细自述）
AGENTS.md                任意 AI 第一指令 / 完整路由规则
ROUTING.md               全 AI 关键词 → 路径表（不绑 Hermes）
MASTER.md                主题域矩阵 + 5 步路由 + 融合说明
CLAUDE.md / .cursorrules / .github/copilot/  各客户端薄入口
RULES.md                 通用短规则
ai-config/               Claude/Cursor/Codex/Grok/Aider/Hermes/universal 源配置
hermes-skills/           伞形技能源（14 入口，含 cdn-origin-tracing / 0day / reverse…）
scripts/
  install-windows.ps1 / install-linux.sh
  bootstrap.sh           写各 AI 入口 + 同步技能
  sync-agent-skills.sh   Claude/Cursor/Codex/Gemini/agents/Hermes 一键技能
  sync-hermes-skills.sh  仅 Hermes
  check-tools.sh / install-tools.sh / tools-manifest.json
domains/                 ★ 知识正文（按攻击面，~5200+ 文件）
  recon/ web-injection/ web-attack/ api-security/ auth-security/
  file-vulns/ business-logic/ ad-attack/ windows-post/ linux-post/
  cloud-security/ mobile-security/ binary-pwn/ reverse-engineering/
  crypto-attacks/ llm-ai-security/ post-exp-tools/ malware-dfir/
  social-eng/ ctf/ 0day-exploits/ redteam-framework/ gambling-pentest/ other/
  FUSION-6000.md / FUSION-20260908.md / FUSION-REPORT-20260908.md / FUSION-20260910-wechat4.md
```

---

## 六、主题域规模（约数，融合后会变）

| 域 | 约文件数 | 覆盖摘要 |
|----|----------|----------|
| `web-injection` | 1100+ | SQLi/XSS/SSRF/XXE/反序列化/Fastjson/Shiro/Log4j + torch-hunt/wiki + orwa 字典 |
| `recon` | 1050+ | 子域/端口/OSINT/FOFA/组件情报/TORCH tools·cheatsheets/Dic |
| `0day-exploits` | 650+ | 产品 RCE 库 + **exploitarium** 批次索引 |
| `file-vulns` | 390+ | 上传/LFI/白盒 PHP·Java 审计 |
| `ctf` | 330+ | 靶场/题解/torch CTF workflow |
| `ad-attack` | 190+ | Kerberos/ACL/ADCS/BloodHound + torch AD |
| `cloud-security` | 180+ | AWS/Azure/K8s/CI-CD + torch cloud |
| `redteam-framework` | 160+ | 状态机/Anti-Logic/torch campaign 脚本 |
| `post-exp-tools` | 150+ | C2/隧道/Webshell/凭据 |
| `web-attack` | 120+ | CSRF/WAF/走私/缓存/竞态 |
| `windows-post` / `linux-post` | 100+ / 40+ | 提权/横移/凭证 |
| `mobile-security` | 80+ | APK/iOS/Frida + **panda-rev**（DEX/砸壳/IL2CPP） |
| `reverse-engineering` | 60+ | IDA/Ghidra + **panda-rev** 符号/结构体/Unicorn |
| `auth` / `api` / `llm` / … | 见 MASTER | 认证、API、AI/MCP、密码学、博彩面等 |

数字以仓库内统计为准，融合后会变。

---

## 七、渗透时「技能必须用全」——加载矩阵

开打**任意**授权目标时，AI / 操作者按资产类型 **load 对应伞形**，再进 `domains/`。  
**禁止**不 load 技能就空手写临时脚本开喷。

| 场景 | 必 load（伞形） | domains 落点（再读） |
|------|-----------------|----------------------|
| 每次活靶开局 | `pentest-execution` + `tgsec-suite` | `redteam-framework/` · coverage / Deadend |
| 长任务失忆/原地循环/凑链 | （开局）+ `cyberstrike-progress-gates` · `capability-primitives` | `redteam-framework/cyberstrike-methodology/` |
| CDN/WAF/找源站 IP | `cdn-origin-tracing` | `recon/` · handbook |
| Web 注入/API/JWT/IDOR | `hack-skills` → `web-sec` | `web-injection` `web-attack` `auth` `api` · `torch-hunt` |
| SQLi 字典 fuzz | （同上） | `web-injection/Payload/sqli/*orwa*` |
| 组件/版本已识别 | （+ component intel） | `recon/component-vuln-intel/` · `0day-exploits/` · `POC-PLATFORM-INDEX.md` |
| 产品已知 RCE | `0day-exploit-library` | `0day-exploits/<product>/` · `EXPLOITARIUM-INDEX.md` |
| n8n / Form 工作流 | （+ 0day） | `web-injection/Vuln/middleware/n8n/`（含 fullchain + exploit） |
| 内网 AD / Kerberos 反射 | （开局） | `ad-attack/cve-2026-26128-kerberos-unicode-reflection/` |
| K8s/容器逃逸（Copy-Fail） | （开局） | `cloud-security/container-escape-techniques/cve-2026-31431-copyfail-k8s.md` |
| CTF / Payload 速查 | （开局） | `ctf/payloads/` · `ctf-solver-routing.md` · `depth-articles/` |
| AI Agent/MCP/RAG 运行时 · SOC 研判门禁 | （开局） | `llm-ai-security/ai-security-engineering/` |
| APK/IPA/Frida/DEX/砸壳/IL2CPP/二进制 | `reverse-skill`（+ master-route） | `mobile-security/panda-rev` · `reverse-engineering/panda-rev` |
| 博彩/代收/代理 BFLA | `gambling-platform-pentest` | `gambling-pentest/` |
| 假设驱动状态机 | `black-cat-redteam` | `redteam-framework/black-cat/` |
| OODA 自动化代理 | `stopen` | （技能内流程） |
| Bug bounty 狩猎卡 | `claude-bughunter` | 与 `src-methods` 交叉 |
| 结构化 payload/字典库 | `about-security` | `Payload/` `Dic/` 及 domains 镜像 |
| YAML 技术卡片 | `secatlas` | SecAtlas 本地树 |
| 吸收外部安全仓 | `security-kb-ingest` | 本 README 融合纪律 |
| 业务身份层/反逻辑/支付 | `pentest-execution` refs | `auth-security` · `business-logic` · `anti-logic-*` |

Hermes：`skill_view(<name>)`。  
Claude/Cursor 等：项目内 `.claude/skills/<name>/` 或先 `bash scripts/sync-agent-skills.sh`。  
**全 AI 兜底：** 不会 skill 系统 → 直接 `ROUTING.md` → `domains/`。

活靶纪律（覆盖矩阵、验证门、OOB、禁止「已到极限」）在 `hermes-skills/pentest-execution/`。

---

## 八、特色方法论（熟手）

| 主题 | 路径 |
|------|------|
| 真假分离侦察 | `domains/recon/true-false-separation-recon.md` |
| 业务系统身份层 ROI | `domains/auth-security/session-crypto-identity-layer.md` |
| Anti-Logic A1–A6 | `domains/redteam-framework/anti-logic-layout.md` |
| 身份层 + 反逻辑手册 | `domains/redteam-framework/identity-antilogic-playbook.md` |
| 支付/Crown 配置面 | `domains/business-logic/payment-config-crown-surface.md` |
| TORCH 战役层（wiki/hunt/campaign） | `domains/**/torch-*` · `redteam-framework/torch-methodology-delta-20260908.md` |
| 能力原语凑链 + 长任务进度闸 | `domains/redteam-framework/cyberstrike-methodology/` · `pentest-execution/references/*` |
| AI 安全工程（宪法/门禁/研判） | `domains/llm-ai-security/ai-security-engineering/` |
| exploitarium 产品 PoC 索引 | `domains/0day-exploits/EXPLOITARIUM-INDEX.md` |
| 本地 POC 库查询（不灌 Skill） | `domains/0day-exploits/POC-PLATFORM-INDEX.md` |
| 实战脱敏课 | `domains/*/case-lessons/` |

**思路：** 强身份业务优先 session/JWT/HMAC/无 auth 写接口与旁门；与正逻辑 Kill Chain **并行**。

---

## 九、一键装到 Claude / Cursor / Hermes 等

```bash
cd security-suite
bash scripts/sync-agent-skills.sh          # Linux/Mac
# Windows:
# powershell -ExecutionPolicy Bypass -File .\scripts\sync-agent-skills.ps1
```

| 装到哪 | 路径 |
|--------|------|
| Claude Code 项目内 | `.claude/skills/<name>/SKILL.md` |
| Claude 用户级 | `~/.claude/skills/` |
| Cursor | `.cursor/skills/` 与 `~/.cursor/skills/` |
| 通用 | `.agents/skills/` |
| Codex / Gemini | `.codex/skills/` · `.gemini/skills/` |
| Hermes | `~/.hermes/skills/security/` |

`bootstrap.sh` / 一键 install **会自动调用**。装完请**新开会话**。

```bash
bash scripts/sync-hermes-skills.sh   # 仅 Hermes
bash scripts/check-tools.sh          # 看缺什么工具
bash scripts/install-tools.sh        # 按清单补工具
```

`git pull` **不会**自动更新 `~/.hermes/skills`，需要再 sync。

---

## 十、融合批次

### 2026-09-11

- 补全专项技能全文：不设限 / 钓鱼社工初始访问 / OPSEC（`skills-full` + `skills-restricted`）
- 平台参考：roles、agents、docs、tools 配置树
- AI 安全工程剩余 stub Agent、graph、原文副本
- 失败拉取记录：`0day-exploits/FAILED-CVE-FETCHES.md`（cPanel/KiviCare 上游 404）

### 2026-09-10

- 红队运行时：长任务进度闸、能力原语凑链、验证/改动台账、ControlIntent 闭环 → `cyberstrike-methodology/` + `pentest-execution` Runtime Gates  
- AI 安全工程：宪法门禁、公式速查、运行时信任、SOC 研判 → `llm-ai-security/ai-security-engineering/`  
- n8n 未授权全链 + 可运行 exploit；AD Kerberos Unicode 反射；K8s/宿主机 Copy-Fail 多实现；Apache H2 / Office / npm-tar 等单洞  
- CTF：Payload、深度文、脚本、路由、靶场 WP、工具手册、大赛 WP meta  
- **POC/0day 全量目录** → `0day-exploits/poc-catalog/`（sec-fork / eeee / vuln-wiki / awesome-md / from-poc-db）；总索引 `POC-CATALOG-INDEX.md`；CVE 卡 800+；4393 摘要 JSONL  
- recon：`cyberstrike-recon-skills`（攻击面 / 组件情报 / 源码狩猎）  
- 手法 skill 全文 → `cyberstrike-methodology/skills-full/`

### 2026-09-08

- TORCH wiki/hunt/workflow → 各域 `torch-*`  
- 移动/逆向 panda-rev（DEX/砸壳/IL2CPP 等）  
- SQLi orwa 字典、exploitarium 产品 PoC 索引、Dic/Vuln 增量

---

## 十一、和 reverse-skill 的关系

吸收了 reverse-skill 的：**关键词路由、先读规则再动手、工具路径不瞎猜、完成清单**。  
正文仍在 `domains/` 攻击面融合；本机若有 reverse-skill 包，可 `master-route`。  
2026-09 另融 **panda-rev**（DEX dump 二进制、Frida 现代 API、砸壳、IL2CPP、符号/结构体、Unicorn）。

---

## 十二、更新

```bash
cd ~/security-suite && git pull
bash scripts/bootstrap.sh --force    # 或 sync-agent-skills / sync-hermes-skills
```

---

## 十三、常见问题

**Q：技能是不是变少了？**  
A：伞形入口十几个是**路由器**；内容在 `domains/`（五千级文件）。渗透时按第七节矩阵 load，再下钻 domains。

**Q：只有文档不能跑？**  
A：见第四节。字典/PoC/战役脚本/工具清单都在仓内；二进制工具用 `install-tools` 装到宿主。

**Q：必须 Hermes 吗？**  
A：不必。Grok/Claude/Cursor 打开文件夹读 `START`→`ROUTING`→`domains` 即可。

**Q：能否未授权打公网？**  
A：不能。口令里的「已授权」指 SRC/客户书面授权/自有资产/CTF 等。

**Q：文件数和 README 对不上？**  
A：以 `find domains -type f | wc -l` 与本节「实计」为准；融合后会涨。

---

## 十四、声明

本套件仅供**合法授权**的安全测试、CTF 训练、学术研究与防护研究使用。使用者须遵守所在地法律法规，对未授权行为自行承担责任。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
