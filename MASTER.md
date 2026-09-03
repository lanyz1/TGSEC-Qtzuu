---
name: tgsec-suite
description: "Use for attack-surface domain knowledge matrix."
---

# 安全知识库 · TGSEC 一体化导航

> **任意 AI 打开本仓：先 `bash scripts/bootstrap.sh`，再读 AGENTS.md。**


按攻击面组织的安全知识矩阵 — **24 个主题域、2866 个文件**，一个目录直达。

本地路径: `/root/security-suite`  
融合索引: `domains/FUSION-6000.md`

## 使用方式

1. 活靶先 `skill_view(pentest-execution)` + `tgsec-suite`
2. 定攻击面 → 读 `domains/<主题>/README.md`
3. 同面优先: `playbook-6000/` → `hunter-6000/` → `src-methods/` → 其它子目录
4. APK/IPA/二进制逆向 → `reverse-skill` + `master-route.sh`
5. 组件/版本已识别 → `domains/recon/component-vuln-intel/`

## 主题矩阵

| 主题域 | 覆盖 | 文件 |
|--------|------|------|
| `recon` | 侦察情报 — 子域/端口/OSINT/组件CVE情报/FOFA/SRC规则/playbook | 408 |
| `web-injection` | Web注入 — SQLi/XSS/SSRF/XXE/反序列化/Fastjson/Shiro/Log4j/Spring | 983 |
| `web-attack` | Web攻击 — CSRF/CORS/走私/缓存投毒/WAF/竞态/重定向 | 97 |
| `api-security` | API安全 — GraphQL/JWT/OAuth/IDOR·BOLA/网关/未授权 | 44 |
| `auth-security` | 认证授权 — 认证绕过/IDOR/OAuth-JWT/401-403/SSO | 53 |
| `file-vulns` | 文件漏洞 — 上传/LFI-RFI/路径穿越/SCM泄露 | 55 |
| `business-logic` | 业务逻辑 — 支付绕过/越权/竞态/威胁建模 | 17 |
| `ad-attack` | AD域攻击 — Kerberos/ACL/ADCS/NTLM/BloodHound | 87 |
| `windows-post` | Windows后渗透 — 提权/横移/凭证/免杀/EDR | 57 |
| `linux-post` | Linux后渗透 — 提权/隧道/持久化/内网横移 | 19 |
| `cloud-security` | 云安全 — AWS/Azure/GCP/K8s/容器/CI-CD | 103 |
| `mobile-security` | 移动端 — Android/iOS/APK/Frida/iOS26.6内核CVE | 53 |
| `binary-pwn` | 二进制Pwn — 栈堆/ROP/fuzz/shellcode/exploit dev | 37 |
| `reverse-engineering` | 逆向工程 — PE/ELF/脱壳/调试/固件/协议 | 37 |
| `crypto-attacks` | 密码学攻击 — RSA/对称/格子/哈希/链上 | 17 |
| `llm-ai-security` | AI/LLM安全 — Prompt注入/RAG/Agent/MCP | 30 |
| `post-exp-tools` | 后渗透工具 — C2/隧道/代理/Webshell/凭据 | 142 |
| `malware-dfir` | 恶意样本与取证 — YARA/IR/内存/vuln-memory | 47 |
| `social-eng` | 社会工程 — 钓鱼/水坑/意识培训/物理 | 11 |
| `ctf` | CTF与靶场 — Web/Pwn/Crypto/Reverse/报告样例 | 219 |
| `0day-exploits` | 0day漏洞库 — 产品RCE PoC/自动利用 | 298 |
| `redteam-framework` | 红队框架 — 状态机/多阶段/lyan工作流 | 42 |
| `gambling-pentest` | 赌博平台 — BFLA/支付/代理/WebSocket | 3 |
| `other` | 其他 — 框架专项/自动化/代码审计 | 18 |

## 渗透闭环

```
侦察(recon) → 漏洞发现(web-*/auth-*/file-*/api-*) → 漏洞利用(0day-exploits)
→ 后渗透(linux-post/windows-post) → 横移 → 凭据收集 → 数据提取 → 报告
```

## 5 步路由

1. **定阶段**: 侦察 → 注入/绕过 → 提权 → 后渗透/横向 → 报告
2. **定攻击面**: 选上方主题域
3. **读索引**: `domains/<主题>/README.md`
4. **入子目录**: playbook-6000 / hunter-6000 / src-methods / 专项
5. **交叉引用**: 同技术多角度并存，取所需

## 6000RMB Skills 包融合

来源 zip **按攻击面拆入 domains/**（禁止按仓库名堆叠）：

| 来源块 | 融合位置 |
|--------|----------|
| Skills20260809（30 playbook） | 各域 `playbook-6000/<name>/` |
| hunter-skills（37 offensive） | 各域 `hunter-6000/<name>/` |
| skill1 渗透工作流 | `redteam-framework/pentest-lyan-workflow/` |
| vuln-hunter | `malware-dfir/vuln-hunter-memory/` |
| component-vuln-intel | `recon/component-vuln-intel/` |
| 实战报告样例 | `ctf/case-reports-6000/` |
| clown 知识库 | 已有 `src-methods/` 哈希去重 |

## 技能路由（Hermes）

| 场景 | skill |
|------|-------|
| 活靶渗透/深挖/攻击链 | `pentest-execution` |
| 攻击面知识库 | `tgsec-suite`（本仓库） |
| APK/IPA/JS/二进制逆向 | `reverse-skill` |
| Web 注入/API playbook | `hack-skills` + `web-sec` |
| 产品 0day RCE | `0day-exploit-library` |
| iOS26.6/65343/KASLR 研判 | `mobile-security/ios-kernel-cve/ANALYSIS.md` |

## 打开即配置 / 旧机器覆盖

```bash
bash scripts/bootstrap.sh            # 任意 AI/人类：配齐 Claude/Cursor/Codex/Aider/Grok/Hermes
bash scripts/bootstrap.sh --force --pull
bash scripts/reinstall-tgsec.sh      # clone/pull + bootstrap 一条龙
```

## AI 工具配置

```
ai-config/hermes/    — Hermes 一键配置
ai-config/claude/    — Claude Code
ai-config/codex/     — OpenAI Codex
ai-config/grok/      — Grok CLI
ai-config/cursor/    — Cursor
ai-config/aider/     — Aider
ai-config/universal/ — 通用 PERSONA/MEMORY/RULES
```

## 更新日志

- 2026-09-03: iOS 26.6 内核 CVE 研判卡融入 mobile-security
- 2026-09-03: 6000RMB skills 按攻击面融合；MASTER/README 校准；空目录清理；lyan 双结构压平

---
@TGSEC社区 · @TGSEC-Qtzuu 整理
