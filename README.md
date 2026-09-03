# TGSEC 学习渗透套件 · 安全知识聚合库

> **TGSEC社区** 学习渗透套件组合 — 按攻击面组织的渗透测试全链路知识库,可直接喂给 AI Agent 使用
>
> 📌 整理作者: **@TGSEC-Qtzuu**

---

## 这是什么

一套**面向 AI Agent 的渗透测试知识套件**。它把渗透测试、逆向工程、漏洞利用、红队攻击链的全链路知识,按**攻击面**组织成 24 个主题域、2700+ 个文件,并配备:

- **主入口 `MASTER.md`** — 24 主题导航矩阵 + 5 步路由
- **主题索引** — 每个 `domains/<主题>/` 下有 README 索引 + 技能文件
- **AI 自适应引导** — `AGENTS.md`,AI 拿到仓库即自动配置
- **多AI工具支持** — Hermes / Claude Code / Codex / Grok / Cursor / Aider 一键配置
- **0day漏洞库** — 77个产品91个RCE漏洞(含PoC和自动化exploit)
- **SRC方法论** — 49种漏洞测试方法论,已融合到对应主题域
- **工具自动管理** — 缺什么装什么,渗透途中自动补工具

---

## 24 个主题域

| 主题域 | 覆盖范围 | 文件数 |
|--------|---------|--------|
| `recon` | 侦察情报 — 子域枚举/端口扫描/指纹识别/OSINT/资产测绘/FOFA工具/SRC挖掘规则 | 398 |
| `web-injection` | Web注入 — SQLi/XSS/SSRF/SSTI/XXE/CMDi/EL注入/JNDI/反序列化/原型链污染 + SRC方法论 | 964 |
| `web-attack` | Web攻击 — CSRF/CORS/HTTP走私/缓存投毒/WAF绕过/WebSocket/竞态条件 + SRC方法论 | 89 |
| `api-security` | API安全 — GraphQL/JWT/OAuth/IDOR·BOLA/API网关 + SRC方法论 | 42 |
| `auth-security` | 认证授权 — 认证绕过/IDOR越权/OAuth-JWT/401-403绕过 + SRC方法论 | 49 |
| `file-vulns` | 文件漏洞 — 上传/目录遍历/LFI/源码管理泄露 + SRC方法论 | 53 |
| `business-logic` | 业务逻辑 — 支付绕过/越权/竞态/类型混淆 + SRC方法论 | 16 |
| `ad-attack` | AD域攻击 — Kerberos/ACL滥用/ADCS/NTLM中继/票据/BloodHound | 87 |
| `windows-post` | Windows后渗透 — 提权/横向移动/持久化/凭证/免杀/LOLBins | 53 |
| `linux-post` | Linux后渗透 — 提权大全/隧道代理/持久化/凭据收集/内网横移 | 18 |
| `cloud-security` | 云安全 — AWS/Azure/GCP/K8s/容器逃逸/云IDE RCE/依赖混淆 + SRC方法论 | 100 |
| `mobile-security` | 移动端 — Android/iOS/APK逆向/Frida/SSL Pinning | 48 |
| `binary-pwn` | 二进制Pwn — 栈溢出/堆利用/ROP/格式化字符串/内核 | 31 |
| `reverse-engineering` | 逆向工程 — PE/ELF/脱壳/动态调试/固件/协议逆向 | 37 |
| `crypto-attacks` | 密码学攻击 — RSA/对称/格子/哈希/区块链/智能合约 | 17 |
| `llm-ai-security` | AI/LLM安全 — Prompt注入/RAG投毒/Agent攻击面/MCP权限 + SRC方法论 | 29 |
| `post-exp-tools` | 后渗透工具 — C2/隧道/代理/MSF/Webshell/凭据提取/数据渗出 | 141 |
| `malware-dfir` | 恶意样本与取证 — YARA/内存取证/流量分析/恶意样本分析 | 29 |
| `social-eng` | 社会工程 — 钓鱼模板/社工技术/C2框架/水坑攻击/物理渗透 | 10 |
| `ctf` | CTF与靶场 — Web/Pwn/Crypto/Reverse/取证/攻击链复盘 | 214 |
| `0day-exploits` | 0day漏洞库 — 77个产品91个RCE漏洞(含PoC+自动化exploit) | 298 |
| `redteam-framework` | 红队框架 — Black Cat假设驱动红队方法论 | 11 |
| `gambling-pentest` | 赌博平台渗透 — BFLA/支付逻辑/代理系统/实战案例 | 3 |
| `other` | 其他 — ASP.NET/Laravel/Node.js/Next.js/验证码专项 | 7 |

---

## 渗透闭环

```
信息收集(recon) → 漏洞发现(web-injection/web-attack/auth-security/...)
→ 漏洞利用(0day-exploits) → 后渗透(linux-post/windows-post)
→ 内网横移(lateral-movement) → 凭据收集(credential-harvest)
→ 数据提取 → 持久化(persistence) → 报告输出
```

全链路 2700+ 文件,零薄弱环节。

---

## AI Agent 一键配置

支持 **6种主流AI工具**,clone后一条命令变红队执行引擎:

| AI工具 | 配置命令 |
|--------|---------|
| **Hermes Agent** | `cd ai-config/hermes && bash setup.sh` |
| **Claude Code** | `cp ai-config/claude/CLAUDE.md ./CLAUDE.md` |
| **OpenAI Codex** | `cp ai-config/codex/instructions.md .github/copilot/` |
| **Grok CLI** | `cp ai-config/grok/system.txt ~/.grok/` |
| **Cursor** | `cp ai-config/cursor/.cursorrules ./` |
| **Aider** | `cp ai-config/aider/.aider.conf.yml ./` |

配置后AI会:
- 收到渗透指令直接执行
- 自动按攻击面优先级规划
- 遇到对应系统自动调用0day库
- 限速时自动切换攻击面

---

## 直接丢给 AI 使用

**任何 AI Agent 拿到这个仓库地址,读 `AGENTS.md` 即可自动完成:**
1. 克隆仓库
2. 根据AI工具类型自动配置红队人格
3. 检测本机工具链,缺失自动安装
4. 注册技能/知识库
5. 渗透途中发现缺工具 → 自动补装再用

### 示例

```
帮我安装 https://github.com/lanyz1/TGSEC-Qtzuu
```

AI 会自动:克隆 → 配置 → 开测 → 缺工具自动装。

---

## 本地使用

```bash
git clone https://github.com/lanyz1/TGSEC-Qtzuu.git
cd TGSEC-Qtzuu
bash scripts/check-tools.sh        # 检测工具链
bash scripts/install-tools.sh      # 自动安装缺失工具
cat MASTER.md                      # 导航入口
```

---

## 最近更新

| 日期 | 更新内容 |
|------|---------|
| 2026-09-02 | 补强Linux后渗透(提权/隧道/持久化/凭据/横移) + 社工(钓鱼/C2) + 赌博平台渗透大全 |
| 2026-09-02 | SRC漏洞挖掘方法论(49种)融合到9个已有主题域 |
| 2026-09-02 | RuoYi-Vue-Plus tenant_id SQL注入POC(当日0day) |
| 2026-09-02 | 多AI工具红队配置(Hermes/Claude/Codex/Grok/Cursor/Aider) |
| 2026-09-02 | Redis CVE-2026-81934 RCE exploit(CVSS 9.8) |
| 2026-09-01 | 0day漏洞库(77产品91个RCE) + Black Cat红队框架 + 赌博平台渗透经验 |
| 2026-09-01 | 仓库创建,21个主题域整合 |

---

## 声明

本套件仅供合法授权的安全测试、CTF 训练、学术研究与防护研究使用。使用者需遵守所在地法律法规,对任何未经授权的行为自行承担责任。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理

## 知识融合

- 域索引: `MASTER.md`
- 6000RMB skills 融合: `domains/FUSION-6000.md`
- iOS 内核 CVE 研判: `domains/mobile-security/ios-kernel-cve/`

@TGSEC社区 · @TGSEC-Qtzuu 整理
