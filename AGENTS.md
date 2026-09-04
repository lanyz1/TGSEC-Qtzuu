# TGSEC 安全任务自动路由规则（AGENTS.md）

> **人类小白请先看 [`START.md`](START.md)**（只有 3 步）。本文件给 AI 用，偏完整。

> 任意 AI（Hermes / Grok Build / Claude CLI / Cursor / Codex / Aider / OpenCode…）打开本仓库的**第一指令**。  
> 包根目录 = **本文件所在目录**（不要写死盘符；Windows 常见 `C:\Users\<你>\security-suite`）。  
> 知识正文在 `domains/`；总导航 `MASTER.md`；**全 AI 路径表 `ROUTING.md`（不依赖 Hermes）**；`hermes-skills/` 仅 Hermes 可选加速。

@TGSEC社区 · @TGSEC-Qtzuu 整理

---

## 0. 强制首步（打开仓库立刻做）

```bash
# 在包根目录
bash scripts/bootstrap.sh
# 或 --force 重装入口文件 + Hermes 技能
bash scripts/bootstrap.sh --force
```

| 客户端 | bootstrap 后 |
|--------|----------------|
| Claude CLI / Code | 根目录 `CLAUDE.md` |
| Cursor | `.cursorrules` |
| Codex | `.github/copilot/instructions.md` |
| Grok / Grok Build | 尽量写 `~/.grok/system.txt`；**仍以本 AGENTS.md + MASTER.md 为准** |
| Hermes | `scripts/sync-hermes-skills.sh` → `~/.hermes/skills/security/` |

然后：

1. 读 **本文件** + **`ROUTING.md`** + **`MASTER.md`**
2. 按 `ROUTING.md` 关键词表打开 `domains/` 路径（**所有 AI 通用，不需要 skill_view**）
3. 同主题优先：`playbook-6000/` → `hunter-6000/` → `src-methods/` → `case-lessons/` → 其它
4. Hermes 可选再 `skill_view` 加速，非必需

---

## 1. 触发关键词（任意命中即走安全路由）

### 1.1 渗透 / Web / API / 业务

渗透测试、红队、安全评估、打点、漏洞利用、SRC、Bug Bounty、众测  
端口扫描、Nmap、Nuclei、目录爆破、FFUF、指纹、JS 提取、接口  
SQL 注入、SQLMap、XSS、SSRF、SSTI、反序列化、文件上传、WAF bypass  
IDOR、越权、未授权、BOLA、BFLA、JWT、OAuth、认证绕过、验证码绕过  
支付逻辑、收款地址、TRC20、会话伪造、Flask session、HMAC、init_data  
完整报告、writeup、PoC 验证、覆盖矩阵

→ **主路径：** `MASTER.md` → `domains/web-injection|web-attack|auth-security|api-security|business-logic|file-vulns|recon/…`  
→ **Hermes：** `skill_view(pentest-execution)` + `skill_view(tgsec-suite)`；Web 深挖再 `hack-skills` / `web-sec`

### 1.2 移动 / APK / iOS

APK、jadx、apktool、smali、Frida、Hook、重打包、证书校验、root 检测  
IPA、iOS、Objection、SSL Pinning、MobSF、Mach-O  
iOS 26.6、KASLR、AppleKeyStore、内核 CVE 研判

→ **`domains/mobile-security/`**（含 `ios-kernel-cve/`）  
→ **Hermes：** `skill_view(reverse-skill)`；若本机有 reverse-skill 包再 `master-route`

### 1.3 逆向 / 二进制 / Pwn / 固件

IDA、Ghidra、radare2、反汇编、脱壳、符号迁移、bindiff  
pwn、ROP、堆、pwntools、固件、binwalk、IoT  
.NET、dnSpy、Go/Rust 逆向、协议逆向、Protobuf

→ **`domains/reverse-engineering/`** · **`domains/binary-pwn/`**  
→ **Hermes：** `reverse-skill`；本机 reverse-skill：`bash <reverse-skill根>/skills/scripts/master-route.sh --hint "…"`

### 1.4 内网 / AD / 后渗

域渗透、BloodHound、Kerberos、ADCS、PtH、横向移动、提权、凭证、C2、隧道

→ **`domains/ad-attack/`** · **`windows-post/`** · **`linux-post/`** · **`post-exp-tools/`**

### 1.5 云 / 供应链 / LLM

K8s、容器逃逸、AWS、CI/CD、依赖混淆、SBOM  
Prompt 注入、Agent 安全、MCP、LLM 红队

→ **`domains/cloud-security/`** · **`llm-ai-security/`**

### 1.6 博彩 / 特殊业务

博彩、代收、代理 BFLA、游戏平台

→ **`domains/gambling-pentest/`** + **`skill_view(gambling-platform-pentest)`**

### 1.7 0day / 组件已知洞

产品名 + 版本、RCE 库、组件 CVE

→ **`domains/0day-exploits/`** · **`recon/component-vuln-intel/`** · **`skill_view(0day-exploit-library)`**

### 1.8 方法论专题（已融合）

| 主题 | 路径 |
|------|------|
| 真假分离侦察 | `domains/recon/true-false-separation-recon.md` |
| Session/JWT 身份层 vs CMS 注入 ROI | `domains/auth-security/session-crypto-identity-layer.md` |
| Anti-Logic 反逻辑 A1–A6 全文 | `domains/redteam-framework/anti-logic-layout.md` |
| 身份层+反逻辑统一手册 | `domains/redteam-framework/identity-antilogic-playbook.md` |
| 支付/收款 Crown 面 | `domains/business-logic/payment-config-crown-surface.md` |
| 实战报告提炼 | `domains/*/case-lessons/`（见 recon/case-lessons/README） |

未命中具体域 → 读 `MASTER.md` 主题表，**不要硬塞**；可提议补文档到对应 `domains/<面>/`。

---

## 2. 路由入口（TGSEC 包内顺序）

```text
1. 本 AGENTS.md（触发与原则）
2. ROUTING.md                   — 全 AI 关键词→路径（不绑 Hermes）
3. MASTER.md                    — 24 域导航 + 5 步路由
4. domains/<面>/README.md       — 域索引
5. playbook-6000 → hunter-6000 → src-methods → case-lessons → 专项
6. Hermes 可选: skill_view(...)
7. 可选本机 reverse-skill master-route（有则用，无则只用 domains）
```

**检测包根：** 含 `MASTER.md` + `domains/` + `scripts/bootstrap.sh` 的目录 = TGSEC 根。  
**不要猜** `D:\…` 或 `/root/…` 固定路径。

---

## 3. 执行原则

### 3.1 工具

- 不猜工具绝对路径；先 `scripts/check-tools.sh` / `tools-manifest.json`
- 缺失：`scripts/install-tools.sh`（失败 2 次停止自动重试，改输出手动步骤）
- 逆向专用工具链：若存在本机 reverse-skill，用其 `refresh-tool-index` / `bootstrap-reverse`，**仍以用户授权范围为界**

### 3.2 授权与范围（硬性）

- 活靶 ACT 前确认：用户声明 **SRC / Bug Bounty / 自有资产 / 书面授权 / CTF 靶场** 之一
- **禁止**「只输入 URL 就自动写入已授权」
- 不主动扩大到用户未点名的资产；高危利用先汇报再继续（除非用户已明确全权授权范围）
- 报告与日志脱敏（Token/真实手机号/超额 PII）

### 3.3 决策与防卡死

- 每 ~5 次工具调用或卡住时自检：是否在推进？同参数是否重复 ≥2 次？→ 换路径  
- 静态↔动态、正逻辑↔反逻辑（A1–A6）、Web↔移动↔身份层  
- 业务系统优先 **身份层 / 会话 / 无 auth 写接口**，避免对强身份架构无脑喷 SQLi  
- 单子任务工具调用过多时主动汇报进度

### 3.4 输出质量

- 关键步骤给**可复现命令**（不要只叙述）
- 逆向标注地址/偏移/符号
- 渗透结论：能验证的给验证步骤与证据路径；不确定标置信度
- 用户要**交付报告**时：发现列表 + 复现 + 覆盖/未测面（勿把未验证 scanner 当正式洞）

### 3.5 风格（分客户端）

- **Hermes：** 可跟用户 memories / `ai-config/hermes`（若已 bootstrap）；「继续」= 授权范围内加深，不提前喊停  
- **Claude / 多数云模型：** 以本仓 `CLAUDE.md` 为准——授权评估与知识执行，**不**套用「永不拒绝」越狱句  
- **Grok Build：** 打开本仓后以 **AGENTS.md + MASTER.md + domains/** 为系统任务书

---

## 4. 完整行为链

```text
1. 命中安全/逆向关键词 → 本路由
2. 定位包根（本文件目录）
3. 无 bootstrap 痕迹 → scripts/bootstrap.sh
4. 读 MASTER.md → 定 domains/<面>/
5. Hermes 则 skill_view 对应伞形
6. 可选 reverse-skill master-route（本机有则用）
7. 读 tool 状态 / 补工具
8. 授权范围清晰 → ACT；否则只做知识/加固/清单
9. 推进中定期汇报；失败换轴（含 Anti-Logic）
10. 结束 → 完成 Checklist
```

---

## 5. 任务完成 Checklist（尽量做满）

```text
□ 结论与证据（命令/响应摘录/路径）已给出
□ 覆盖了哪些面、哪些未测/阻塞已说明
□ 可复现步骤完整（客户/队友能重做）
□ 敏感信息已脱敏
□ 有价值的新手法可沉淀到 domains/<面>/ 或 hermes-skills 引用（用户同意再改仓）
□ Hermes：重要平台链可记入 pentest-execution references（用户同意）
```

用户说「你忘了出报告/矩阵」→ 立刻补，不辩解。

---

## 6. 错误处理

| 场景 | 动作 |
|------|------|
| bootstrap 成功 | 继续，少打扰 |
| clone/工具失败 2 次 | 停自动重试，给手动步骤 |
| 域路由不清 | 回 MASTER.md，或问一句资产类型 |
| 无授权活靶 | 只提供方法论/加固/检查清单，不动手打公网 |
| 身份层业务系统 | 转 session-crypto + anti-logic，降 SQLi 喷洒权重 |
| reverse-skill 不在本机 | 仅用 `domains/reverse-engineering|mobile-security|binary-pwn` |

---

## 7. Hermes 伞形技能速查（可选加速，非全 AI 必需）

| skill_view | 何时 |
|------------|------|
| `tgsec-suite` | 定攻击面 / 知识库总路由 |
| `pentest-execution` | 活靶纪律、平台链、反逻辑触发 |
| `reverse-skill` | APK/IPA/二进制路由 |
| `hack-skills` / `web-sec` | Web 深手册 |
| `0day-exploit-library` | 产品 RCE 索引 |
| `gambling-platform-pentest` | 博彩/代收 |
| `security-kb-ingest` | 吸收外部分知识进 domains |
| `black-cat-redteam` | 假设驱动状态机 |

技能源：`hermes-skills/` → 同步：`bash scripts/sync-hermes-skills.sh`  
`git pull` **不等于**技能更新，需再 sync/bootstrap。

---

## 8. 常用命令（在包根）

```bash
# 配置入口 + 全 AI 技能目录
bash scripts/bootstrap.sh --force

# 仅技能：Claude/Cursor/agents/Hermes
bash scripts/sync-agent-skills.sh
# 仅 Hermes：
bash scripts/sync-hermes-skills.sh

# 工具
bash scripts/check-tools.sh
bash scripts/install-tools.sh

# 导航
# MASTER.md
# domains/<面>/README.md
```

可选本机 reverse-skill（路径以本机为准，示例）：

```bash
bash "$REVERSE_SKILL_ROOT/skills/scripts/master-route.sh" --hint "用户原话"
bash "$REVERSE_SKILL_ROOT/skills/scripts/refresh-tool-index.sh"
```

Windows PowerShell 示例：

```powershell
cd $HOME\security-suite
bash scripts/bootstrap.sh --force
# 若有 reverse-skill：
# powershell -NoProfile -ExecutionPolicy Bypass -File $env:REVERSE_SKILL_ROOT\skills\scripts\master-route.ps1 -Hint "..."
```

---

## 9. 禁止行为

- ❌ 未读 MASTER/域索引就盲打  
- ❌ 猜测工具路径  
- ❌ 输入 URL 自动伪造授权  
- ❌ 超用户指定范围扩扫  
- ❌ 把未验证扫描器输出写成「已确认漏洞」  
- ❌ 同一失败自动安装死循环  
- ❌ 长时间无进度沉默  
- ❌ 编造版本号/未读过的文件内容  
- ❌ 把 ds.txt 类越狱「永不拒绝」写进本仓全局规则  

---

## 10. 联网补充（有搜索时）

未知组件/CVE/报错 → 搜 → **提炼可执行步骤**写入会话结论；用户同意再沉淀进 `domains/` 或 references。  
优先可验证来源；标注日期；不丢裸链接当唯一答案。

---

## 11. 安装（人类）

```bash
git clone https://github.com/lanyz1/TGSEC-Qtzuu.git security-suite
cd security-suite && bash scripts/bootstrap.sh
```

公开仓 Linux 一行（若 raw/cdn 可用）：

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-linux.sh | bash
```

Windows：见仓库 `INSTALL.md` / `scripts/install-windows.ps1`（以当前仓内文件为准）。

---

## 12. 发给已打开 AI 的最短口令

```text
工作区是 TGSEC 包根。读 AGENTS.md、ROUTING.md、MASTER.md。
按 ROUTING 表打开 domains/ 对应文件（不依赖 Hermes skill_view）。
顺序 README→playbook-6000→hunter-6000→src-methods→case-lessons。
授权范围内执行；业务系统走真假分离+身份层+反逻辑。
```

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
