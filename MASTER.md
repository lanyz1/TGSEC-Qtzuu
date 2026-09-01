---
name: tgsec-suite
description: "Use when needing unified security knowledge by attack surface."
---

# 安全知识库 · TGSEC 一体化导航

按攻击面组织的安全知识矩阵 —— 21 个主题域、21 个入口,一个目录直达。

## 使用方式

从 `domains/<主题>/` 进入,每个主题有 README.md 索引 + 各子目录/技能文件。

## 主题矩阵

| 主题域 | 覆盖 |
|--------|------|
| `recon` | 侦察情报 — 子域枚举/端口扫描/指纹识别/OSINT/资产测绘/证书日志 |
| `web-injection` | Web注入 — SQLi/XSS/SSRF/SSTI/XXE/CMDi/NoSQL/表达式注入/原型链污染 |
| `web-attack` | Web攻击 — CSRF/CORS/CRLF/请求走私/缓存投毒/WAF绕过/域名接管/WebSocket |
| `api-security` | API安全 — GraphQL/JWT/OAuth/IDOR·BOLA/反序列化/未授权访问/参数注入 |
| `auth-security` | 认证授权 — 认证绕过/会话/SSO/OAuth-OIDC/SAML/验证码绕过/ATO |
| `file-vulns` | 文件漏洞 — 上传/包含LFI-RFI/任意文件读写/路径穿越/代码审计 |
| `business-logic` | 业务逻辑 — 支付绕过/越权/竞态/类型混淆/奖励逻辑缺陷 |
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
| `ctf` | CTF与靶场 — Web/Pwn/Crypto/Reverse/取证比赛题+完整攻击链复盘 |
| `other` | 其他 — 特定框架/服务专项(ASP.NET/Laravel/Node.js/Next.js/验证码) |


## 5 步路由

1. **定阶段**: 侦察 → 注入/绕过 → 提权 → 后渗透/横向 → 报告
2. **定攻击面**: 选上方主题域
3. **读索引**: `domains/<主题>/README.md`
4. **入子目录**: 按具体漏洞/技术载入
5. **交叉引用**: 同一技术各角度文档并存,取所需

@TGSEC社区 ·擎天柱整理
