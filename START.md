# 小白从这里开始（3 步）

仓库：https://github.com/lanyz1/TGSEC-Qtzuu

这是 **TGSEC 安全知识聚合库**：按攻击面整理的授权渗透 / 挖洞资料 + 伞形技能路由 + 工具/PoC/字典入口。  
给 **AI 和人**一起用（Grok / Claude / Cursor / Hermes / Codex…）。

**规模体感：** 24 个主题域 · `domains/` 约 **5200+** 文件 · 14 个伞形技能 · 80+ 工具清单。

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
| **Claude** | 进入该文件夹再运行 `claude` |
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

---

## 第 3 步：复制这句话发给 AI

```text
请先读 START.md、AGENTS.md、ROUTING.md、MASTER.md。
我做的是【已授权】渗透测试和挖洞（侦察、找漏洞、可复现验证、出报告）。
按 ROUTING.md 去 domains/ 找资料；开打前按 README「技能加载矩阵」把相关伞形技能 load 齐，再给可复现命令。
用简单中文一步步带我做。
目标与授权说明：……（填域名/范围，并写明已授权）
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

| 你在干什么 | 先让 AI load |
|------------|----------------|
| 任意开打 | `pentest-execution` + `tgsec-suite` |
| 找源站 / CDN | `cdn-origin-tracing` |
| Web 注入/越权/API | `hack-skills` → `web-sec` |
| 产品 RCE | `0day-exploit-library` |
| APK/IPA/逆向 | `reverse-skill` |
| 博彩/代收 | `gambling-platform-pentest` |

完整表见 [`README.md`](README.md) 第七节。

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

---

## 还是懵？只记四件事

1. **资料都在 `domains/`**（按攻击类型分好了，五千级文件）  
2. **地图是 `MASTER.md` 和 `ROUTING.md`**  
3. **先让 AI 读这几个 md，再按技能矩阵 load，再动手**  
4. **要跑工具：`scripts/check-tools.sh`；要 PoC：`0day-exploits/`**

进阶：`AGENTS.md`（完整规则）、`README.md`（自述全文）、`hermes-skills/`（伞形入口）。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
