# TGSEC-Qtzuu · 安全知识聚合库

> **@TGSEC社区 · @TGSEC-Qtzuu 整理**  
> 面向 **AI + 人** 的授权安全知识库：渗透测试、挖洞、红队方法论、按**攻击面**组织，可直接丢给 Grok Build / Claude / Cursor / Hermes / Codex 等使用。

**仓库地址：** https://github.com/lanyz1/TGSEC-Qtzuu  

**👉 完全零基础：只看 [`START.md`](START.md)（3 步）**  
**👉 AI 查「说了啥去哪个目录」：[`ROUTING.md`](ROUTING.md)**  
**👉 全部主题地图：[`MASTER.md`](MASTER.md)**

---

## 一、这是什么

本仓库不是「按上游项目名堆一堆文件夹」，而是把多份技能包、手册、实战报告**拆开后，按攻击面重新融合**进 `domains/`，让 AI 和人都能按「我现在测的是登录 / 支付 / 注入…」找到对应资料。

| 它是 | 它不是 |
|------|--------|
| 授权渗透 / 挖洞 / 评估用的**知识与路由** | 未授权攻击教程或自动「输入域名就授权」 |
| 给**多种 AI** 共用的同一套路径（不绑死 Hermes） | 必须安装某一种 AI 才能用 |
| 初学可从 `START.md` 进，熟手可从 `MASTER`/`domains` 深挖 | 只有黑盒脚本、没有说明 |

**规模（约）：** 24 个主题域 · **2800+** 文件（以 `MASTER.md` / 本地 `domains/` 为准）。

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
bash scripts/bootstrap.sh   # 可选：写各 AI 入口文件
```

默认目录：`~/security-suite`（Windows 多为 `C:\Users\<用户名>\security-suite`）。

### 2）用 AI 打开整个文件夹

| AI | 做法 |
|----|------|
| Grok Build | 打开文件夹 → 选 `security-suite` |
| Claude CLI | 进入该目录再运行 `claude` |
| Cursor | Open Folder → `security-suite` |
| Hermes | 新会话，工作目录尽量指到该文件夹 |
| Codex / Aider | 以该目录为项目根 |

### 3）复制发给 AI（渗透 / 挖洞）

```text
请先读 START.md、AGENTS.md、ROUTING.md、MASTER.md。
我做的是【已授权】渗透测试和挖洞（侦察、找漏洞、可复现验证、出报告）。
按 ROUTING.md 去 domains/ 找资料，用简单中文一步步带我做。
目标与授权说明：……（填域名/范围，并写明已授权）
```

---

## 三、核心设计：全 AI 同一套路径

不依赖 Hermes 的 `skill_view`，任何能读仓库文件的 AI 都能用：

```text
AGENTS.md  →  AI 总规则（何时路由、授权边界、完成清单）
ROUTING.md →  人话关键词 → domains/ 下具体路径
MASTER.md  →  24 域导航 + 渗透阶段
domains/   →  全部知识正文
```

**同主题推荐阅读顺序：**

```text
domains/<面>/README.md
  → playbook-6000/     （系统测试手册）
  → hunter-6000/       （进攻向专题）
  → src-methods/       （SRC 挖洞方法）
  → case-lessons/      （实战报告提炼，脱敏）
  → 其它专项 md
```

`hermes-skills/` 仅在 **Hermes** 上作可选加速（同步到 `~/.hermes/skills/security/`），**不是**使用本库的门槛。

---

## 四、目录结构

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
hermes-skills/           Hermes 伞形技能源（约 13 个入口）
scripts/
  install-windows.ps1    Win 一键
  install-linux.sh       Linux 一键
  bootstrap.sh           写各 AI 入口 + 可选同步 Hermes 技能
  sync-hermes-skills.sh  仅覆盖 Hermes 技能
  check-tools.sh / install-tools.sh
domains/                 ★ 知识正文（按攻击面）
  recon/ web-injection/ web-attack/ api-security/ auth-security/
  file-vulns/ business-logic/ ad-attack/ windows-post/ linux-post/
  cloud-security/ mobile-security/ binary-pwn/ reverse-engineering/
  crypto-attacks/ llm-ai-security/ post-exp-tools/ malware-dfir/
  social-eng/ ctf/ 0day-exploits/ redteam-framework/ gambling-pentest/ other/
  FUSION-6000.md         6000 包融合索引
```

---

## 五、主题域一览（详见 MASTER.md）

| 域 | 覆盖内容（摘要） |
|----|------------------|
| `recon` | 子域/端口/OSINT/FOFA/真假分离侦察/组件情报/报告课 |
| `web-injection` | SQLi/XSS/SSRF/XXE/反序列化/Fastjson/Shiro/Log4j/Spring… |
| `web-attack` | CSRF/WAF/走私/竞态/重定向/EdgeOne 等 |
| `api-security` | GraphQL/JWT/OAuth/IDOR·BOLA/export 越权课 |
| `auth-security` | 登录绕过/越权/Session 身份层 ROI/RuoYi DataScope 课 |
| `file-vulns` | 上传/LFI/路径穿越/SCM |
| `business-logic` | 支付/Crown 收款面/回调伪造课 |
| `ad-attack` / `windows-post` / `linux-post` | 域与后渗 |
| `cloud-security` | 云/K8s/容器/CI-CD |
| `mobile-security` | APK/iOS/Frida/iOS 内核 CVE 研判 |
| `binary-pwn` / `reverse-engineering` | Pwn 与逆向 |
| `crypto-attacks` / `llm-ai-security` | 密码学 / AI 安全 |
| `post-exp-tools` / `malware-dfir` | 后渗工具 / 样本取证 |
| `0day-exploits` | 产品向 RCE/PoC 索引 |
| `redteam-framework` | 状态机、lyan 工作流、**Anti-Logic A1–A6** |
| `gambling-pentest` | 博彩/代收类业务面 |
| `ctf` / `social-eng` / `other` | 靶场、社工、杂项 |

数字以仓库内 `MASTER.md` 为准（会随融合更新）。

---

## 六、特色方法论（建议熟手必读）

| 主题 | 路径 |
|------|------|
| 真假分离侦察（诱饵面 vs 真后台） | `domains/recon/true-false-separation-recon.md` |
| 业务系统 ≠ CMS：身份层 ROI | `domains/auth-security/session-crypto-identity-layer.md` |
| Anti-Logic 反逻辑 A1–A6 | `domains/redteam-framework/anti-logic-layout.md` |
| 身份层 + 反逻辑统一手册 | `domains/redteam-framework/identity-antilogic-playbook.md` |
| 支付/QR/Crown 配置面 | `domains/business-logic/payment-config-crown-surface.md` |
| 实战报告脱敏课（BOLA/支付回调/RuoYi/EdgeOne…） | `domains/*/case-lessons/` · 索引 `domains/recon/case-lessons/README.md` |

**思路：** 强身份业务优先 session/JWT/HMAC/无 auth 写接口与旁门；与正逻辑 Kill Chain **并行**，不是二选一。

---

## 七、知识从哪融合来（不按上游名堆叠）

| 来源类型 | 在仓库中的形态 |
|----------|----------------|
| Skills20260809 等 playbook | 各域 `playbook-6000/` |
| hunter offensive skills | 各域 `hunter-6000/` |
| SRC 方法论 | 各域 `src-methods/` |
| 工作流 / vuln-memory / 组件情报 | `redteam-framework/pentest-lyan-workflow`、`malware-dfir/vuln-hunter-memory`、`recon/component-vuln-intel` 等 |
| 授权实战报告 | **只提炼**进 `case-lessons/`（无真实 Token/session/助记词） |
| reverse-skill 路由思想 | `AGENTS.md` / `ROUTING.md` 方法论；完整引擎可本机自备，非必须 |

索引：`domains/FUSION-6000.md`。

**刻意不进仓：** 越狱「永不拒绝」类 ds.txt、无通用价值的 demo 壳、含密钥的原始报告全文。

---

## 八、Hermes 用户（可选）

```bash
cd security-suite
bash scripts/bootstrap.sh --force    # 含技能同步
# 或仅技能：
bash scripts/sync-hermes-skills.sh
```

然后**新开 Hermes 会话**。常用伞形：`tgsec-suite`、`pentest-execution`、`reverse-skill`、`hack-skills`、`web-sec`、`0day-exploit-library`、`gambling-platform-pentest` 等。  

`git pull` **不会**自动更新 `~/.hermes/skills`，需要再跑 sync/bootstrap。

细文档仍以 **`domains/`** 为准；伞形技能多是路由器。

---

## 九、和 reverse-skill 的关系

参考了 [reverse-skill](https://github.com/zhaoxuya520/reverse-skill) 的：**关键词路由、先读规则再动手、工具路径不瞎猜、完成清单**。  

**没有**把该仓整库再堆进本仓；本仓正文是 `domains/` 攻击面融合。本机若自备 reverse-skill，可在 AGENTS 指引下可选调用 `master-route`。

---

## 十、更新

```powershell
cd $HOME\security-suite
git pull
```

```bash
cd ~/security-suite && git pull
```

安装脚本变更后可再执行一次对应 `install-*.ps1` / `install-linux.sh` 或 `bootstrap.sh --force`。

---

## 十一、常见问题

**Q：技能是不是变少了？**  
A：Hermes **入口**只有十几个伞形；**内容**在 `domains/`（含上百份 playbook/hunter/方法）。Win 上请走 `ROUTING.md`，不要只依赖文档里写的 Linux 路径 `/root/xxx`。

**Q：必须 Hermes 吗？**  
A：不必。Grok/Claude/Cursor 打开文件夹读 `START`→`ROUTING`→`domains` 即可。

**Q：能否未授权打公网？**  
A：不能。口令里的「已授权」指 SRC/客户书面授权/自有资产/CTF 等；不是自动盖章。

**Q：小白和熟手怎么选文件？**  
A：小白 `START.md`；熟手 `MASTER.md` + `domains/<面>/`；给 AI 规则看 `AGENTS.md`。

---

## 十二、声明

本套件仅供**合法授权**的安全测试、CTF 训练、学术研究与防护研究使用。使用者须遵守所在地法律法规，对未授权行为自行承担责任。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
