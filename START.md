# 小白从这里开始（3 步）

- 2026-09-23：82vip/Kylin · 微信 · src-6k 锁面 · **CVE 23b–23g（cvebird：Solr/Netlogon/ActiveMQ/vB/cPanel/Next-Win）**

仓库：https://github.com/lanyz1/TGSEC-Qtzuu

这是 **TGSEC 安全知识聚合库**：按攻击面整理的授权渗透 / 挖洞资料 + 伞形技能路由 + 工具/PoC/字典入口。  
给 **AI 和人**一起用（Grok / Claude / Cursor / Hermes / Codex…）。

**规模体感：** 24 个主题域 · `domains/` 约 **14000+** 文件 · 14 个伞形技能 · **62** 实战课 · 80+ 工具清单。

**本轮更新（2026-09-28）：**  
**0day C 批（xishou 全量技能蒸馏，908 个新 skill）** — 三波融合：Wave1 乱码测绘引擎 skills(673) + Wave2 Pentest-Skills-Merged 差量(235) + Wave3 72stack-sec(3192 文件/45MB/2836 H1 报告/88636 WooYun/19 playbook/305+176 payload)。**技能库 113→1022（security 类 958）**。新增 `hunt-*`(70+)·`offensive-*`(60+)·专项渗透(200+)·基础能力(150+)·侦察报告(40+)。  
**0day A 批（murrez 独立仓）** — 7 CVE 全 MISS 全融：Citrix NetScaler **88772**（DTLS 内存溢出，**已在野利用**）· Joomla UP **97163/97160/97161** · AcyMailing **94132** · WP Ultra Addons CF7 **82901** · WP Bookly **93399**。**Joomla 产品线全新**。  
**0day B 批（最优吸收，60 URL → 17 目标，全 MISS）** — **网络设备线全新**：F5 BIG-IP **94127** · Citrix NetScaler **8452 + 8451 + 19490**（19490 未授权 SAML 会话伪造，**厂商无 workaround**）· Check Point **50751** · Splunk **20253** · Ivanti Sentry **10520+10523** · Progress ShareFile **2699+2701**。**容器/VM 逃逸线**：`container-escape/` **52910+80521** · `kvm/` 补 arm64 **46316 ITScape**（三部曲齐全）。**MikroTrick 86060+67279+67277**（RouterOS 未授权完全接管，**2026-09-02 起在野**，IoC `login failure for user -2`）。另：Cisco IOS XE 20272 · Artifactory 82329 · WP Give-Tributes 19658 · macOS SMBFS 84543 · ZoneMinder 76060 · JWT 5430。错放修正：Ivanti 10520 从 `sharepoint/` 搬入 `ivanti-sentry/`。  
完整说明 → [`INGEST-20260928-INDEX.md`](domains/0day-exploits/INGEST-20260928-INDEX.md) · [`INGEST-20260928B-INDEX.md`](domains/0day-exploits/INGEST-20260928B-INDEX.md) · [`INGEST-20260928C-INDEX.md`](domains/0day-exploits/INGEST-20260928C-INDEX.md)

**D 批（fastjson2 ≤2.0.62 RCE）** — FNV-1a 哈希碰撞绕 AutoType 白名单 → `jar:http://` 远程类加载 → RCE。默认配置可利用，全 JDK。修复 2.0.63。exploit.py + collision_finder(C/Python) + Docker lab + 27 条多层检测规则。落位 `fastjson2/CVE-2026-fastjson2-PR7695/`。  
**E 批（AI-Infra-Guard 腾讯朱雀实验室）** — 151 AI 产品指纹 + 132 产品漏洞规则库 + 15 MCP 安全规则 + 17 Prompt 安全评测集 + Research（SkillJack/RogueHandoff20/forge_bench）。27MB/4971 文件。落位 `domains/ai-infra-security/AI-Infra-Guard-Tencent/`。  
**F 批（GPU 猎杀包 + SD WebUI RCE）** — 5 GPU 猎杀 skill（gpu-hunter/venom-root/venom-hydra/immortal-pact/undying-persist）+ stable-diffusion-webui-rce skill → `.hermes/skills/security/`。思路文档 → `domains/gpu-ai-security/`。**技能库最终 1028**。  

**上一轮（2026-09-23，commit `1d12151c` 起）：**  
**0day** — V8 可跑 harness；独立仓 23b–e（WP Core / Zabbix / RustyTux / Forminator / macOS LPE / copyfail-rs PAM…）；**@cvebird 对照 1.3 万仓后只融 9 条真缺口**（Solr / Netlogon / ActiveMQ / vBulletin / cPanel parking / Next-Win / OpenClaw / Docker 2375 / XWiki）。SecureWithUmer stub **整仓不吸**。  
**锁面（禁止自动打同网段不相干站）** — 点名 URL 的 **A 记录 IP** 才算同机；同 /24 另一 IP **不是同机**，不能当主线。旁端口同 IP 可以打。用户没说「打邻机 / 横向」禁止自己切站。写在 `pentest-execution` §0。  
**微信 / 报告.zip** — 2FA+glob 补旧卡；82vip / Kylin 课。loot 不入库。  
完整说明 → [`UPDATE-2026-09-23.md`](UPDATE-2026-09-23.md) · 融合批次见 README **第十节**。

---

## 第 1 步：下载到电脑

**Windows（PowerShell 复制一行）：**
```powershell
irm https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-windows.ps1 | iex
```
需要先装 [Git for Windows](https://git-scm.com/download/win)。

**不行就两行：**
```powershell
git clone https://github.com/lanyz1/TGSEC-Qtzuu.git $HOME\security-suite
cd $HOME\security-suite
```

**Linux / Mac：**
```bash
curl -fsSL https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-linux.sh | bash
```

装好后文件夹一般在：`C:\Users\你的用户名\security-suite` 或 `~/security-suite`

---

## 第 2 步：用 AI 打开这个文件夹

| 你用的 AI | 怎么做 |
|-----------|--------|
| **Grok Build** | 打开文件夹 → 选 `security-suite` |
| **Claude Code** | 进入该文件夹再运行 `claude`，然后 `/skill pentest-redteam` |
| **Cursor** | File → Open Folder → `security-suite` |
| **Hermes** | 新开对话（工作目录指到该文件夹更好） |

**一定要打开整个 security-suite 文件夹**，不要只开里面某一个文件。

建议再跑一次（装技能 + 入口文件）：

```bash
cd ~/security-suite && bash scripts/bootstrap.sh --force
```

Windows：

```powershell
cd $HOME\security-suite
powershell -ExecutionPolicy Bypass -File .\scripts\sync-agent-skills.ps1
```

### Claude Code 本机没有 `claude`？

```bash
npm install -g @anthropic-ai/claude-code
cd ~/security-suite && bash scripts/ensure-claude-pentest.sh
claude
```

然后输入：`/skill pentest-redteam`

---

## 第 3 步：复制这句话发给 AI

```text
加载 pentest-redteam。我做【已授权】渗透测试（书面授权/SRC/自有/CTF）。
授权范围：……（域名/网段/深度）。
按假设驱动状态机直接打：信号→technique→observation/reproduction/impact；
弹药用 domains/ 与 0day-exploits/poc-catalog；需要时再用 pentest-execution 纪律。
不要只给建议清单，授权已声明就开打。
```

然后补上你的目标，例如：

- `目标 https://xxx.com，客户已书面授权，只测该域名，要挖洞并出 PoC 步骤`
- `已授权，先做信息收集和登录/越权面`
- `JWT / 支付回调 / TG export 这类经验课在哪，按这个测`
- `CDN / Cloudflare 找源站真实 IP`
- `PHP/Java 白盒审计从哪开始`
- `APK 加固 / Frida / DEX dump / 砸壳`
- `某产品版本 RCE，先查 0day-exploits / EXPLOITARIUM-INDEX`

---

## （推荐）把技能装进 Claude / Cursor / Hermes

在 `security-suite` 里：

**Windows：**
```powershell
cd $HOME\security-suite
powershell -ExecutionPolicy Bypass -File .\scripts\sync-agent-skills.ps1
```

**Linux / Mac：**
```bash
cd ~/security-suite && bash scripts/sync-agent-skills.sh
# Hermes 还可：
bash scripts/sync-hermes-skills.sh
```

会装到例如：

- 项目内 `.claude/skills/`（Claude Code 在本文件夹启动即加载）
- 用户级 `~/.claude/skills/`、`~/.cursor/skills/`、`~/.hermes/skills/security/` 等

然后**新开**会话。skills 是**路由器**；细手册/PoC/字典在 `domains/`。

### 渗透时技能别漏（极简）

| 你在干什么 | 先让 AI load / 去哪 |
|------------|----------------|
| 任意开打（Claude Code） | `/skill pentest-redteam`（状态机）+ TGSEC `domains/` |
| 任意开打（Hermes 等） | `pentest-execution` + `tgsec-suite` |
| 长任务卡死/乱循环/要凑链 | 同上 + `cyberstrike-progress-gates` / `capability-primitives` |
| 找源站 / CDN | `cdn-origin-tracing` |
| Web 注入/越权/API | `hack-skills` → `web-sec` |
| 产品 RCE / 本地 POC 库 | `0day-exploit-library` · `POC-PLATFORM-INDEX` |
| n8n / 内网 AD / K8s 逃逸 | `domains/` 下 n8n、`cve-2026-26128-*`、`copyfail-k8s` |
| CTF / Payload 速查 | `ctf/ctf-solver-routing` · `ctf/payloads/` |
| AI Agent/MCP 安全 | `llm-ai-security/ai-security-engineering/` |
| APK/IPA/逆向 | `reverse-skill` |
| 博彩/代收 | `gambling-platform-pentest` |

完整表见 [`README.md`](README.md) 第七节。  

### 最近融了啥

**2026-09-28：** A 批 murrez 7 CVE — **Joomla 产品线全新**。B 批 60 URL → 17 目标（网络设备线/容器逃逸/MikroTrick 在野）。C 批 xishou 908 skill（技能库 113→1022）。D 批 fastjson2 ≤2.0.62 RCE（FNV-1a 碰撞绕 AutoType）。E 批 AI-Infra-Guard 腾讯朱雀（151 指纹+132 漏洞规则+15 MCP+17 eval）。F 批 GPU 猎杀包 5 skill + SD WebUI RCE skill。**技能库最终 1028，0day 库 258 产品/264 CVE**。  
**2026-09-23：** CVE 独立仓 23b–g + @cvebird 最优 9 harness + src-6k 锁面 + 微信/报告.zip 课。USBPrint 搬出 ghost-cms。聚合仓 stub 不吸。  
**2026-09-22：** 报告吸收硬门 · UU/DarkSword/BMS/ChatNet 课。  
**2026-09-20：** CASE-INDEX 闸门 · sinian 114 迁 `_vendor` · 712win3 课。  
**2026-09-11：** 专项技能（不设限/钓鱼/OPSEC）· Claude Code=`pentest-redteam` 开打。  
**2026-09-10：** 运行时闸门 · n8n/AD/K8s/Copy-Fail · **POC 全量目录**。  
详见 `README.md` **第十节（融合批次）** · [`UPDATE-2026-09-23.md`](UPDATE-2026-09-23.md)。

### 工具不够？

```bash
bash scripts/check-tools.sh
bash scripts/install-tools.sh
```

---

## 以后更新仓库

```powershell
cd $HOME\security-suite
git pull
powershell -ExecutionPolicy Bypass -File .\scripts\sync-agent-skills.ps1
```

```bash
cd ~/security-suite && git pull && bash scripts/sync-agent-skills.sh
```

看「这次更新了啥」：打开根目录最新的 `UPDATE-*.md`（现在是 [`UPDATE-2026-09-23.md`](UPDATE-2026-09-23.md)）。

---

## 还是懵？只记四件事

1. **资料都在 `domains/`**（按攻击类型分好了，约 5500+ 文件）  
2. **地图是 `MASTER.md` 和 `ROUTING.md`**  
3. **先让 AI 读这几个 md，再按技能矩阵 load，再动手**  
4. **要跑工具：`scripts/check-tools.sh`；要 PoC：`0day-exploits/`**

进阶：`AGENTS.md`（完整规则）、`README.md`（自述全文）、`hermes-skills/`（伞形入口）。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
