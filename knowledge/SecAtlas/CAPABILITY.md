# SecAtlas 能力索引

> 最后更新: 2026-08-16 | 单一真源

## 总览

| 资产 | 数量 | 位置 |
|------|------|------|
| Hermes Skill | 126 个（安全分类；含历史归档） | `/root/.hermes/skills/security/` |
| 技术卡 (YAML) | 46 | `techniques/` — 23 个分类 |
| 知识条目 (MD) | 18 类 136 条 | `knowledge/categories/` + `knowledge/frameworks/` |
| 实战工具 | 18 | `tools/` — Python/Go/Shell |
| 案例 | 17 | `cases/` — 授权/CTF/Lab/PWN |
| 深度专题 | 62 篇 | `references/` — 11 个专题 |
| 镜像备份 | 3 | `mirrors/` — keysmith 系列 |

---

## 技术卡 × Skill 对照

| 分类 | 技术卡 | 对应 Skill |
|------|--------|-----------|
| **sql-injection** | 3 (万能密码/布尔盲注/嵌套引号) | `web-api-ops` |
| **xss** | 2 (反射存储/DOM盲打) | `web-api-ops` |
| **ssrf** | 3 (云元数据/过滤绕过/Scheme绕过) | `web-api-ops` |
| **ssti** | 2 (Jinja2 RCE/引擎识别) | `web-api-ops` |
| **jwt** | 3 (alg:none/RS→HS/kid注入) | `web-api-ops` |
| **cmd-injection** | 3 (OOB盲注/WAF绕过/参数注入) | `web-api-ops` |
| **idor** | 3 (RESTful枚举/API越权/批量探测) | `web-api-ops` |
| **request-smuggling** | 2 (CL.TE/H2降级) | `web-api-ops` |
| **deserialization** | 2 (Java URLDNS/PHP POP) | `binary-exploitation` |
| **xxe** | 2 (文件读取/盲OOB) | `web-api-ops` |
| **cache-poisoning** | 1 (Unkeyed Header) | `poison-ops` P1 |
| **log-poisoning** | 1 (LFI→RCE) | `poison-ops` P2 |
| **network-poisoning** | 1 (ARP欺骗) | `poison-ops` P3 |
| **cicd-poisoning** | 1 (依赖混淆) | `poison-ops` P4 |
| **data-poisoning** | 1 (Redis SSH Key) | `poison-ops` P6 |
| **code-audit** | 1 (Agent驱动CVE) | `pentest-orchestrator` |
| **api-bypass** | 3 (AES绕过/汇率操纵/Ruoyi配置) | `chain-ops` |
| **auth** | 2 (JS凭证/验证码绕过) | `cred-hunt` |
| **payment-bypass** | 1 (dujiaoka 回调伪造) | `chain-ops` |
| **blockchain** | 3 (approve伪装充值/平台测绘对账/链上反查) | `chain-ops` |
| **recon** | 2 (JS控制器枚举/平台发现) | `recon-entry-ops` |
| **waf-bypass** | 1 (内联注释) | `chain-ops` |
| **pwn** | 3 (PHP off-by-one/堆off-by-one/UAF检测) | `binary-exploitation` |

---

## 工具矩阵

### Python 工具

| 工具 | 用途 | 用法 |
|------|------|------|
| `jwt-analyzer.py` | JWT 解码 + alg:none/RS→HS/KID 注入/弱密钥爆破 | `python3 jwt-analyzer.py <token> --test-none` |
| `js-extractor.py` | JS 敏感信息提取（25 种正则：API Key/端点/密码/JWT/Firebase） | `python3 js-extractor.py https://target.com/app.js -r` |
| `redis-exploit.py` | Redis 未授权利用（check/ssh-key/crontab/webshell/extract） | `python3 redis-exploit.py -H 10.0.0.5 ssh-key` |

### Go 工具

| 工具 | 用途 | 用法 |
|------|------|------|
| `cache-poison-detector.go` | 缓存投毒探测器（14 个 unkeyed 头并发探测 + 双阶段验证） | `go run cache-poison-detector.go -url https://target.com` |

### Shell 脚本（维护用）

| 脚本 | 用途 |
|------|------|
| `mule-auto-learn.sh` | 自动学习新知识入库 |
| `mule-auto-maintain.sh` | 仓库自动维护 |
| `mule-review-prs.sh` | PR 自动审查 |
| `mule-merge-pr.sh` | PR 自动合并 |
| `mule-comment-pr.sh` | PR 评论 |
| `mule-tempmail.sh` | 临时邮箱工具 |

---

## Skill 分类索引

### 编排与治理 (13)

| Skill | 版本 | 描述 |
|-------|------|------|
| `pentest-orchestrator` | 0.7.1 | 跨测绘→验证→证据→修复→复测编排 |
| `engagement-scope` | 0.4.1 | 授权/范围/禁区/预算管理 |
| `finding-verification` | 0.4.1 | 候选漏洞正反例裁决 |
| `evidence-contract` | 1.0.0 | 统一证据合同模板 |
| `chain-ops` | 0.4.4 | 指纹/CVE/403 组合推断 |
| `ecc-ops` | 0.1.1 | 会话目标锁定与防串 |
| `pentagi-lessons` | 0.7.2 | 长任务卡死恢复与多Agent交接 |
| `pentest-cases` | 1.0.0 | 案例库与战术指纹匹配 |
| `shannon-pipeline` | 1.0.0 | Shannon 五阶段渗透方法论 |
| `target-playbooks` | 0.5.3 | T01-T17 攻击角度卡 |
| `hexstrike-matrix` | 0.4.1 | Kali 工具按阶段/风险/证据选型 |
| `acs-playbooks` | - | ACS 精选手册网关 |
| `bug-bounty-methodology` | - | 赏金猎人完整工作流 |

### 侦察与信息收集 (6)

| Skill | 描述 |
|-------|------|
| `recon-entry-ops` | 子域枚举/DNS/端口/httpx/爬虫/指纹 |
| `recon-apis` | FOFA/uncover/GoFOFA/2captcha |
| `osint-operations` | 开源情报收集 |
| `blackbox-artifacts` | JS/source map/APK/镜像/SBOM分析 |
| `telegram-query-ops` | Telegram 公共元数据查询 |
| `temp-email` | 临时邮箱自动化 |

### Web与API安全 (4)

| Skill | 描述 |
|-------|------|
| `web-api-ops` | SQLi/XSS/SSRF/SSTI/IDOR/JWT/OAuth/GraphQL |
| `web-runtime-security` | Next/Nuxt SSR/RSC/WebSocket授权 |
| `telegram-platform-security` | Webhook/Mini App/MTProto/Bot安全 |
| `gambling-platform-attack-surface` | 博彩平台攻击面测绘 |

### 投毒作战 (1)

| Skill | 描述 |
|-------|------|
| `poison-ops` | 6 链: 缓存/日志/DNS-ARP/CI-CD/Session/数据层 |

### AD与内网渗透 (2)

| Skill | 描述 |
|-------|------|
| `ad-internal-ops` | LDAP/Kerberos/SMB/BloodHound/AD CS |
| `ad-attack-defense` | AD 攻防综合(含防御) |

### 二进制与逆向 (3)

| Skill | 描述 |
|-------|------|
| `binary-exploitation` | PWN/栈溢出/堆/UAF/ROP/GDB |
| `reverse-pcap-ops` | Frida/PCAP/私有协议逆向 |
| `malware-analysis` | 恶意软件静态/动态分析 |

### 云与容器 (3) | LLM与AI (3) | 取证 (3) | 威胁建模 (1) | 凭据与供应链 (2) | 移动安全 (1) | 工具与辅助 (5)

完整 47 Skill（2026-07-23 历史快照）见 [`SKILL_INDEX.md`](./SKILL_INDEX.md)；当前环境实际加载 126 个安全 Skill（`/root/.hermes/skills/security/`），含思念派大星全能技能包与既有 4 个授权渗透 Skill：`authorized-web-pentest` / `ruoyi-biz-pentest` / `web-app-pentest` / `web-pentest`。

---

## 知识条目索引

| 类别 | 文件 | 条目 |
|------|------|------|
| SQL 注入 | `knowledge/categories/sqli.md` | 15 |
| XSS | `knowledge/categories/xss.md` | 10 |
| SSRF | `knowledge/categories/ssrf.md` | 10 |
| 文件包含 | `knowledge/categories/file-inclusion.md` | 10 |
| 命令注入 | `knowledge/categories/command-injection.md` | 10 |
| 反序列化 | `knowledge/categories/deserialization.md` | 10 |
| SSTI | `knowledge/categories/ssti.md` | 10 |
| JWT | `knowledge/categories/jwt.md` | 10 |
| OAuth/OIDC | `knowledge/categories/oauth.md` | 10 |
| 请求走私 | `knowledge/categories/request-smuggling.md` | 10 |
| ACL | `knowledge/categories/acl.md` | 5 |
| IDOR | `knowledge/categories/idor.md` | 3 |
| PWN | `knowledge/categories/pwn.md` | 5 |
| 综合技巧 | `knowledge/categories/misc.md` | 12 |
| 区块链 | `knowledge/categories/blockchain.md` | 3 |
| XXE | `knowledge/categories/xxe.md` | 2 |
| AI Agent/MCP | `knowledge/categories/agentic-ai.md` | 1 |
| 工具清单 | `knowledge/categories/tool-checklist-9phase.md` | 9 阶段 |

---

## 深度专题 (references/)

| 专题 | 文件数 | 内容 |
|------|--------|------|
| SQL注入 | 9 | 原理/形态/检测/审计/修复/盲注/来源 |
| SBOM供应链 | 7 | SBOM边界/组件身份/签名/SLSA/VEX |
| DNS与DNSSEC | 17 | 技术卡/Runbooks/攻击矩阵/防守核查 |
| WebSocket-SSE | 4 | 攻击面/测试思路/授权验证 |
| 云元数据 | 4 | 攻击面/低影响验证/证据 |
| OAuth/OIDC | 1 | RFC 9700 授权码流安全 |
| Passkey/WebAuthn | 4 | 依赖方安全基线/审计清单 |
| TLS/0-RTT | 3 | TLS1.3 0RTT 重放防护 |
| 请求走私 | 2 | H2/Desync |
| AI Agent/MCP | 4 | 攻击面与控制对/来源取舍/证据复测清单 |
| iOS水坑平台 | 5 | 架构/C2契约/桥接降级链/收割路径/检测IoC |

---

## 镜像备份 (mirrors/)

| 仓库 | Stars | 用途 |
|------|-------|------|
| codex-keysmith | 1437 | Codex CLI 全局指令注入 + gpt-unrestricted.md |
| claude-keysmith | 278 | Claude Code CLAUDE.md 注入 |
| zcode-keysmith | 43 | ZCode AGENTS.md 注入 |
