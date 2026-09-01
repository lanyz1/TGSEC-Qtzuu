# TGSEC 学习渗透套件 · 安全知识聚合库

> **TGSEC社区** 学习渗透套件组合 — 按攻击面组织的渗透测试全链路知识库,可直接喂给 AI Agent 使用
>
> 📌 整理作者: **@TGSEC-Qtzuu**

---

## 这是什么

一套**面向 AI Agent 的渗透测试知识套件**。它把渗透测试、逆向工程、漏洞利用、红队攻击链的全链路知识,按**攻击面**组织成 21 个主题域、2300+ 个文件,并配备:

- **主入口 `MASTER.md`** — 21 主题导航矩阵 + 5 步路由
- **主题索引** — 每个 `domains/<主题>/` 下有 README 索引 + 技能文件
- **AI 自适应引导** — `AGENTS.md`,AI 拿到仓库即自动配置
- **工具自动管理** — 缺什么装什么,渗透途中自动补工具

---

## 21 个主题域

| 主题域 | 覆盖范围 |
|--------|---------|
| `recon` | 侦察情报 — 子域枚举/端口扫描/指纹识别/OSINT/资产测绘/证书日志 |
| `web-injection` | Web注入 — SQLi/XSS/SSRF/SSTI/XXE/CMDi/NoSQL/表达式注入/原型链污染 |
| `web-attack` | Web攻击 — CSRF/CORS/CRLF/请求走私/缓存投毒/WAF绕过/域名接管/WebSocket |
| `api-security` | API安全 — GraphQL/JWT/OAuth/IDOR·BOLA/反序列化/未授权访问/参数注入 |
| `auth-security` | 认证授权 — 认证绕过/会话/SSO/OAuth-OIDC/SAML/验证码绕过/ATO |
| `file-vulns` | 文件漏洞 — 上传/包含LFI-RFI/任意文件读写/路径穿越/代码审计 |
| `business-logic` | 业务逻辑 — 支付绕过/越权/竞态/类型混淆/逻辑缺陷 |
| `ad-attack` | AD域攻击 — Kerberos/ACL滥用/ADCS/NTLM中继/票据/域渗透/BloodHound |
| `windows-post` | Windows后渗透 — 提权/横向移动/持久化/凭证/免杀/AV规避/LOLBins |
| `linux-post` | Linux后渗透 — 提权/SUID/sudo/内核/横向/隧道/反弹shell |
| `cloud-security` | 云安全 — AWS/Azure/GCP/IAM/K8s/容器逃逸/私服/Serverless/CICD投毒 |
| `mobile-security` | 移动端 — Android/iOS/APK逆向/Frida/SSL Pinning/App动态调试 |
| `binary-pwn` | 二进制Pwn — 栈溢出/堆利用/ROP/格式化字符串/内核/Symbolic/浏览器VM |
| `reverse-engineering` | 逆向工程 — PE/ELF/脱壳/动态调试/固件/混淆还原/协议逆向 |
| `crypto-attacks` | 密码学攻击 — RSA/对称/格子/哈希/区块链/智能合约/USDT |
| `llm-ai-security` | AI/LLM安全 — Prompt注入/RAG投毒/Agent攻击面/MCP权限/OWASP LLM |
| `post-exp-tools` | 后渗透工具 — C2/隧道/代理/MSF/Webshell/凭据提取/数据渗出 |
| `malware-dfir` | 恶意样本与取证 — YARA/内存取证/流量分析/恶意样本分析/反取证 |
| `social-eng` | 社工与硬件 — 钓鱼/水坑/硬件安全/物理访问 |
| `ctf` | CTF与靶场 — Web/Pwn/Crypto/Reverse/取证/完整攻击链复盘 |
| `other` | 其他 — ASP.NET/Laravel/Node.js/Next.js/验证码专项 |

---

## 直接丢给 AI 使用

**任何 AI Agent 拿到这个仓库地址,读 `AGENTS.md` 即可自动完成:**
1. 克隆仓库
2. 检测本机工具链(哪些有、哪些没有)
3. 缺失工具自动下载安装(apt/pip/npx/go 多通道)
4. 渗透途中发现缺工具 → 自动补装再用

### 示例

```
把 https://github.com/lanyz1/security-suite 克隆到本地,读 AGENTS.md 初始化。
然后对授权目标 X 进行渗透测试。
```

AI 会自动:克隆 → 配置 → 开测 → 缺工具自动装。

---

## 本地使用

```bash
git clone https://github.com/lanyz1/security-suite.git
cd security-suite
bash scripts/check-tools.sh        # 检测工具链
bash scripts/install-tools.sh      # 自动安装缺失工具
cat MASTER.md                      # 导航入口
```

---

## 声明

本套件仅供合法授权的安全测试、CTF 训练、学术研究与防护研究使用。使用者需遵守所在地法律法规,对任何未经授权的行为自行承担责任。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理
