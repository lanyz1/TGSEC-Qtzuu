# TGSEC 全 AI 通用路由（不绑 Hermes）

> **所有客户端同一套：只认仓库相对路径。**  
> 不要求 `skill_view`、不要求 MCP、不要求 reverse-skill 本机包。  
> Hermes 若存在，可在读完路径后再 `skill_view` 作加速，**不是必需。**

包根 = 含本文件 + `MASTER.md` + `domains/` 的目录。

@TGSEC社区 · @TGSEC-Qtzuu 整理

---

## 0. 任何 AI 打开仓库后固定 4 步

```text
1) 读 AGENTS.md
2) 读本文件 ROUTING.md（或 MASTER.md 主题表）
3) 按用户任务关键词打开下表「必读路径」
4) 同主题深入顺序：
   domains/<面>/README.md
   → playbook-6000/（若有）
   → hunter-6000/（若有）
   → src-methods/（若有）
   → case-lessons/（若有）
   → 其它子目录
```

可选：`bash scripts/bootstrap.sh`（写各 IDE 入口文件；无 bash 可跳过，直接读 md）。

---

## 1. 关键词 → 必读路径（通用）

| 用户话里的信号 | 先读这些路径（相对包根） |
|----------------|--------------------------|
| 渗透、打点、审计、漏洞、SRC、报告 | `MASTER.md` + 本表继续往下 |
| 侦察、子域、端口、指纹、FOFA、信息收集 | `domains/recon/README.md` |
| 真假后台、诱饵、矛盾点 | `domains/recon/true-false-separation-recon.md` |
| SQLi、XSS、SSRF、SSTI、反序列化、Fastjson、Shiro、Log4j、Spring | `domains/web-injection/README.md` |
| CSRF、WAF、走私、竞态、开放重定向、EdgeOne | `domains/web-attack/README.md` |
| 上传、LFI、路径穿越 | `domains/file-vulns/README.md` |
| API、GraphQL、Swagger、导出 export、BOLA | `domains/api-security/README.md` |
| 登录、JWT、OAuth、越权、IDOR、session、Flask、HMAC、Telegram 登录 | `domains/auth-security/README.md` |
| 身份层、业务系统不是 CMS、算力别砸错 | `domains/auth-security/session-crypto-identity-layer.md` |
| 支付、TRC20、收款、QR、回调伪造、卡密、Crown | `domains/business-logic/README.md` + `payment-config-crown-surface.md` + `case-lessons/payment-callback-forge-card-leak.md` |
| 反逻辑、A1–A6、旁门、不爆 admin | `domains/redteam-framework/anti-logic-layout.md` + `identity-antilogic-playbook.md` |
| 博彩、代收、代理 | `domains/gambling-pentest/README.md` |
| APK、Frida、jadx、iOS、IPA | `domains/mobile-security/README.md` |
| iOS 26.6、KASLR、内核 CVE | `domains/mobile-security/ios-kernel-cve/ANALYSIS.md` |
| 逆向、IDA、Ghidra、pwn、固件 | `domains/reverse-engineering/README.md` + `domains/binary-pwn/README.md` |
| 域、AD、BloodHound、横向 | `domains/ad-attack/README.md` + `windows-post` / `linux-post` |
| 云、K8s、容器、CI/CD | `domains/cloud-security/README.md` |
| LLM、Prompt、Agent | `domains/llm-ai-security/README.md` |
| 产品名+版本、0day、RCE 库 | `domains/0day-exploits/README.md` + `domains/recon/component-vuln-intel/SKILL.md` |
| 实战报告怎么写、Evidence | `domains/recon/case-lessons/README.md` |
| TG 云控 export 越权 | `domains/api-security/case-lessons/tg-cloud-export-bola.md` |
| RuoYi 列表大数据 | `domains/auth-security/case-lessons/ruoyi-datascope-list-bola.md` |
| EdgeOne + 注册 + 上传 | `domains/web-attack/case-lessons/edgeone-waf-open-register-upload.md` |
| settings/Bot/付费下载未授权 | `domains/recon/case-lessons/unauth-settings-bot-token-download.md` |

未命中：打开 `MASTER.md` 主题矩阵，选最接近的 `domains/<面>/`，**不要猜。**

---

## 2. 业务系统默认作战序（全 AI）

```text
A. domains/recon/true-false-separation-recon.md
B. domains/auth-security/session-crypto-identity-layer.md
C. 正逻辑登录/权限  ∥  domains/redteam-framework/anti-logic-layout.md
D. domains/business-logic/payment-config-crown-surface.md（若涉支付）
E. 对应 web/api/auth playbook-6000 与 case-lessons
```

---

## 3. 客户端差异（只有入口不同，知识相同）

| 客户端 | 如何挂上本路由 |
|--------|----------------|
| **Grok Build** | 打开包根文件夹；系统/首条：`读 AGENTS.md 与 ROUTING.md` |
| **Claude CLI/Code** | 包根启动；已有 `CLAUDE.md` 指向 AGENTS/MASTER/ROUTING |
| **Cursor** | 打开包根；`.cursorrules` 指向同上 |
| **Codex/Copilot** | `.github/copilot/instructions.md` |
| **Aider** | `.aider.conf.yml` read 列表含 AGENTS/ROUTING/MASTER |
| **Hermes** | 同上读文件；**额外可选** `skill_view(tgsec-suite)` 等加速 |
| **其它** | 任意能读仓库文件的 AI：先 AGENTS + ROUTING |

**禁止把 Hermes skill 名当成唯一入口**——无 skill_view 时路径表仍然完整可用。

---

## 4. 最短口令（复制给任何 AI）

```text
工作区是 TGSEC 包根。先读 AGENTS.md 和 ROUTING.md，再读 MASTER.md。
按 ROUTING 关键词表打开 domains/ 下对应文件；
顺序 README → playbook-6000 → hunter-6000 → src-methods → case-lessons。
不要依赖 Hermes skill_view；有则可选。
授权范围内执行；业务系统走真假分离+身份层+反逻辑。
```

---

## 5. 与 hermes-skills/ 的关系

`hermes-skills/` = Hermes 机器上的**可选加速器**（同步到 `~/.hermes/skills`）。  
知识真理源永远是 **`domains/` + 本 ROUTING.md`**。  
其它 AI **不必、也不该**安装 Hermes 才能渗透路由。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
