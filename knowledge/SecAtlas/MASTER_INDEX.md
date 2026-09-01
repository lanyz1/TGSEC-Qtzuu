# 骡子渗透知识库

> 来源：公开靶场、OWASP、PortSwigger、HackTricks、PayloadsAllTheThings 与公开规范
> 最后更新：2026-08-16

## 内容入口

- [`knowledge/categories/`](./knowledge/categories/)：按漏洞类型整理的深度知识条目（18类 136 条目，另含 4 个框架漏洞库，含 AI Agent/MCP）。
- [`techniques/`](./techniques/)：可复用技术卡（23类 46 张）。
- [`cases/`](./cases/)：靶场、CTF 与授权实战案例（17 个）。
- [`references/`](./references/)：深度专题文档（SQL注入/WebSocket/云元数据/SBOM供应链/DNS/TLS/OAuth/Passkey/请求走私/AI Agent/iOS水坑平台，共 11 个专题、62 篇文档）。
- [`mirrors/`](./mirrors/)：外部仓库镜像备份（codex-keysmith/claude-keysmith/zcode-keysmith）。
- [`SKILL_INDEX.md`](./SKILL_INDEX.md)：骡子安全 Skill 索引（47 个历史快照 / 4 个当前活跃）。

## 快速导航

| 你想做什么 | 去哪里 |
|-----------|--------|
| 查具体漏洞怎么打 | `techniques/<类别>/` — 含触发信号、payload、判据 |
| 理解漏洞原理和知识来源 | `knowledge/categories/<类别>.md` — PortSwigger/OWASP 蒸馏 |
| 复盘实战案例 | `cases/<authorized\|ctf\|lab\|pwn>/` |
| 读专题深度文档 | `references/<专题>/` — SQL注入9篇/SBOM供应链5篇等 |
| 查 Skill 能力清单 | `SKILL_INDEX.md` |

## 技术卡目录

| 类别 | 数量 | 技术卡 |
| --- | ---: | --- |
| SQLi | 3 | 万能密码、布尔盲注、嵌套引号 |
| XSS | 2 | 反射/存储、DOM/盲XSS |
| SSRF | 3 | Cloud Metadata、Scheme绕过、过滤绕过 |
| SSTI | 2 | Jinja2 RCE、引擎识别 |
| JWT | 3 | alg:none、RS→HS混淆、kid注入 |
| 命令注入 | 3 | OOB盲注、WAF绕过、参数注入 |
| IDOR | 3 | RESTful枚举、API越权、批量探测 |
| 请求走私 | 2 | CL.TE、H2降级 |
| 反序列化 | 2 | Java URLDNS、PHP POP链 |
| API绕过 | 3 | AES-CBC绕过、汇率操纵、Ruoyi配置 |
| 认证 | 2 | JS硬编码凭证、验证码绕过 |
| 支付绕过 | 1 | dujiaoka 支付回调伪造 |
| 区块链 | 3 | approve伪装充值、平台测绘对账判定、链上approve目标反查 |
| PWN | 3 | PHP off-by-one 堆溢出、堆 off-by-one 基础、UAF 检测 |
| 侦察 | 2 | JS控制器枚举、平台发现方法论 |
| WAF绕过 | 1 | 内联注释 |
| 缓存投毒 | 1 | Unkeyed Header |
| CI/CD投毒 | 1 | 依赖混淆 |
| 日志投毒 | 1 | LFI→RCE |
| 网络投毒 | 1 | ARP欺骗 |
| 数据层投毒 | 1 | Redis SSH Key |
| 代码审计 | 1 | Agent驱动CVE |
| XXE | 2 | 基础文件读取、盲OOB |
