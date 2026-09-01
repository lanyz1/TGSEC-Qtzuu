# Security Suite

安全技能聚合知识库 — 覆盖渗透测试、逆向工程、漏洞利用、红队攻击链全链路

## 内容结构

| 模块 | 内容 | 说明 |
|------|------|------|
| `MASTER.md` | 总入口 | 21 主题域导航矩阵,5 步路由 |
| `domains/` | 21 个主题域 | 按攻击面组织的知识体系 |
| `skills/` | 7 个技能入口 | Hermes 技能系统,skill_view 按需加载 |

## 主题域一览

| 主题域 | 覆盖 |
|--------|------|
| `recon` | 侦察情报 — 子域枚举/端口扫描/指纹/OSINT/资产测绘 |
| `web-injection` | Web注入 — SQLi/XSS/SSRF/SSTI/XXE/CMDi/NoSQL |
| `web-attack` | Web攻击 — CSRF/CORS/走私/缓存投毒/WAF绕过 |
| `api-security` | API安全 — GraphQL/JWT/IDOR/BOLA/反序列化 |
| `auth-security` | 认证授权 — 认证绕过/会话/SSO/SAML/验证码 |
| `file-vulns` | 文件漏洞 — 上传/包含/任意文件读写/路径穿越 |
| `business-logic` | 业务逻辑 — 支付绕过/越权/竞态/逻辑缺陷 |
| `ad-attack` | AD域攻击 — Kerberos/ACL/ADCS/NTLM中继/票据 |
| `windows-post` | Windows后渗透 — 提权/横向/持久化/免杀 |
| `linux-post` | Linux后渗透 — 提权/SUID/横向/隧道 |
| `cloud-security` | 云安全 — AWS/Azure/K8s/容器逃逸/IAM |
| `mobile-security` | 移动端 — Android/iOS/APK逆向/Frida |
| `binary-pwn` | 二进制Pwn — 栈/堆/ROP/格式化/内核 |
| `reverse-engineering` | 逆向工程 — PE/ELF/脱壳/固件/混淆还原 |
| `crypto-attacks` | 密码学攻击 — RSA/对称/格子/区块链 |
| `llm-ai-security` | AI/LLM安全 — Prompt注入/RAG投毒/MCP权限 |
| `post-exp-tools` | 后渗透工具 — C2/隧道/MSF/Webshell/渗出 |
| `malware-dfir` | 恶意样本与取证 — YARA/内存/流量分析 |
| `social-eng` | 社工与硬件 — 钓鱼/水坑/硬件安全 |
| `ctf` | CTF与靶场 — Web/Pwn/Crypto/Reverse比赛题 |
| `other` | 其他 — ASP.NET/Laravel/Node.js专项 |

## 使用方式

```
MASTER.md          → 总入口,主题导航
domains/<主题>/    → 主题内容(每个域有 README.md 索引)
skills/<入口>/     → Hermes 技能加载
```

@TGSEC社区 ·擎天柱整理
