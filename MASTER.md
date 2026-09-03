---
name: tgsec-suite
description: "Use when needing unified security knowledge by attack surface."
---

# 安全知识库 · TGSEC 一体化导航

按攻击面组织的安全知识矩阵 —— 24 个主题域、2700+ 文件,一个目录直达。

## 使用方式

从 `domains/<主题>/` 进入,每个主题有 README.md 索引 + 各子目录/技能文件。
带 `src-methods/` 子目录的域包含SRC漏洞挖掘方法论(49种漏洞测试方法已融合)。

## 主题矩阵

| 主题域 | 覆盖 | 文件 |
|--------|------|------|
| `recon` | 侦察情报 — 子域枚举/端口扫描/OSINT/JS逆向/FOFA工具/SRC挖掘规则/打穿短表 | 408 |
| `web-injection` | Web注入 — SQLi/XSS/SSRF/XXE/EL注入/JNDI/反序列化/原型链污染/类型混淆 | 983 |
| `web-attack` | Web攻击 — CSRF/CORS/HTTP走私/缓存投毒/WAF绕过/WebSocket/竞态/GraphQL | 97 |
| `api-security` | API安全 — GraphQL/JWT/OAuth/IDOR·BOLA/API网关/反序列化/未授权 | 44 |
| `auth-security` | 认证授权 — 认证绕过/IDOR越权/OAuth-JWT/401-403绕过/SSO/SAML | 53 |
| `file-vulns` | 文件漏洞 — 上传/目录遍历/LFI-RFI/路径穿越/源码管理泄露 | 55 |
| `business-logic` | 业务逻辑 — 支付绕过/越权/竞态/类型混淆/逻辑缺陷 | 17 |
| `ad-attack` | AD域攻击 — Kerberos/ACL/ADCS/NTLM中继/票据/BloodHound | 87 |
| `windows-post` | Windows后渗透 — 提权/横移/持久化/凭证/免杀/LOLBins | 57 |
| `linux-post` | Linux后渗透 — 提权大全/隧道代理/持久化/凭据收集/内网横移 | 19 |
| `cloud-security` | 云安全 — AWS/Azure/GCP/K8s/容器逃逸/云IDE RCE/依赖混淆 | 103 |
| `mobile-security` | 移动端 — Android/iOS/APK逆向/Frida/SSL Pinning/iOS26.6内核CVE研判 | 53 |
| `binary-pwn` | 二进制Pwn — 栈溢出/堆利用/ROP/格式化字符串/内核 | 37 |
| `reverse-engineering` | 逆向工程 — PE/ELF/脱壳/动态调试/固件/协议逆向 | 37 |
| `crypto-attacks` | 密码学攻击 — RSA/对称/格子/哈希/区块链/智能合约 | 17 |
| `llm-ai-security` | AI/LLM安全 — Prompt注入/RAG投毒/Agent攻击面/MCP | 30 |
| `post-exp-tools` | 后渗透工具 — C2/隧道/代理/MSF/Webshell/凭据/数据渗出 | 142 |
| `malware-dfir` | 恶意样本与取证 — YARA/内存取证/流量分析/反取证 | 47 |
| `social-eng` | 社会工程 — 钓鱼模板/社工技术/C2框架/水坑/物理渗透 | 11 |
| `ctf` | CTF与靶场 — Web/Pwn/Crypto/Reverse/取证/攻击链复盘 | 219 |
| `0day-exploits` | 0day漏洞库 — 77产品91个RCE漏洞(含PoC+自动exploit) | 298 |
| `redteam-framework` | 红队框架 — Black Cat假设驱动红队方法论 | 58 |
| `gambling-pentest` | 赌博平台 — BFLA/支付逻辑/代理系统/WebSocket/实战案例 | 3 |
| `other` | 其他 — 特定框架/服务专项 | 18 |

## 渗透闭环

```
侦察(recon) → 漏洞发现(web-*/auth-*/file-*/api-*) → 漏洞利用(0day-exploits)
→ 后渗透(linux-post/windows-post) → 横移(lateral-movement) → 凭据收集
→ 数据提取 → 持久化 → 报告
```

## 5 步路由

1. **定阶段**: 侦察 → 注入/绕过 → 提权 → 后渗透/横向 → 报告
2. **定攻击面**: 选上方主题域
3. **读索引**: `domains/<主题>/README.md`
4. **入子目录**: 按具体漏洞/技术载入(含 `src-methods/` SRC方法论)
5. **交叉引用**: 同一技术各角度文档并存,取所需


## 6000RMB Skills 包融合（2026-09-03）

来源 zip 已**按攻击面拆入 domains/**，禁止再按仓库名单独堆叠：

| 来源块 | 融合位置 |
|--------|----------|
| Skills20260809（30 playbook） | 各域 `playbook-6000/<name>/` |
| hunter-skills（37 offensive） | 各域 `hunter-6000/<name>/` |
| skill1 渗透工作流 | `redteam-framework/pentest-lyan-workflow/` |
| vuln-hunter | `malware-dfir/vuln-hunter-memory/` |
| component-vuln-intel | `recon/component-vuln-intel/` |
| 实战报告样例 | `ctf/case-reports-6000/` |
| clown 知识库 | 已有 `src-methods/` 哈希去重（重复跳过） |

**Hermes 路由:** `tgsec-suite` → 定域 → `playbook-6000`/`hunter-6000`/`src-methods`；活靶开打仍先 `pentest-execution`。

## 技能路由（Hermes）

开打必须 `skill_view`，不要靠目录虚词碰运气：

| 场景 | skill |
|------|-------|
| 活靶渗透/深挖/攻击链 | `pentest-execution` |
| APK/IPA/JS/二进制逆向 | `reverse-skill` → master-route.sh |
| Web注入/API | `hack-skills` + `web-sec` |
| 攻击面知识库 | `tgsec-suite`（本仓库） |
| iOS26.6/65343/KASLR/盗U边界 | `domains/mobile-security/ios-kernel-cve/ANALYSIS.md` |

## AI工具配置

```
ai-config/hermes/   — Hermes Agent一键配置
ai-config/claude/   — Claude Code (CLAUDE.md)
ai-config/codex/    — OpenAI Codex
ai-config/grok/     — Grok CLI
ai-config/cursor/   — Cursor (.cursorrules)
ai-config/aider/    — Aider
ai-config/universal/ — 通用配置(任何AI工具可用)
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
