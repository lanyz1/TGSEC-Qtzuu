<div align="center">
  <img src="./assets/brand/secatlas-cover.svg" alt="SecAtlas 网络渗透知识库" width="100%" />

  <p><strong>结构化中文网络渗透知识库：技术卡、专题、案例与多 Agent 协作维护</strong></p>

  <p>
    <a href="#项目概览">项目概览</a>
    <span>&nbsp;·&nbsp;</span>
    <a href="#多agent协作">多Agent协作</a>
    <span>&nbsp;·&nbsp;</span>
    <a href="#内容全景">内容全景</a>
    <span>&nbsp;·&nbsp;</span>
    <a href="#精选入口">精选入口</a>
    <span>&nbsp;·&nbsp;</span>
    <a href="#工具集">工具集</a>
    <span>&nbsp;·&nbsp;</span>
    <a href="#内容标准">内容标准</a>
  </p>

  <p>
    <a href="https://github.com/shuaiqideyu/SecAtlas/stargazers">
      <img alt="GitHub Stars" src="https://img.shields.io/github/stars/shuaiqideyu/SecAtlas?style=for-the-badge&logo=github&label=Stars&color=D7B468&labelColor=07131F" />
    </a>
    <a href="https://github.com/shuaiqideyu/SecAtlas/forks">
      <img alt="GitHub Forks" src="https://img.shields.io/github/forks/shuaiqideyu/SecAtlas?style=for-the-badge&logo=github&label=Forks&color=35C9DC&labelColor=07131F" />
    </a>
    <img alt="Author @yuuu" src="https://img.shields.io/badge/AUTHOR-@yuuu-D7B468?style=flat-square&labelColor=07131F" />
    <img alt="AI Collaborative" src="https://img.shields.io/badge/AI_COLLABORATIVE-✓-35C9DC?style=flat-square&labelColor=07131F" />
  </p>

  <p><strong>作者</strong>：<a href="https://t.me/yuuu">Telegram @yuuu</a></p>
</div>

## 项目概览

**SecAtlas** 把网络渗透知识整理成可检索、可复核、可持续维护的体系：技术卡、深度专题、案例复盘与工具脚本统一入库，并支持多个 AI Agent 共同学习、共同维护。

每个专题围绕一条完整闭环展开：

`漏洞原理 → 攻击面 → 最低影响验证 → 证据判断 → 修复建议 → 回归复测`

### 当前内容规模

| 技术卡 | 知识条目 | 案例 | 专题 | 工具 | Skill | 镜像 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **46** | **136** | **17** | **62篇/11专题** | **18** | **126** | **3** |

📊 [CAPABILITY.md](./CAPABILITY.md) — 完整能力索引

## 多 Agent 协作

SecAtlas 是**首个面向多 AI Agent 协作**的结构化安全知识库。

### 对你的 Agent 说

将以下内容告诉你的 Agent，它就能参与共建：

```
去 https://github.com/shuaiqideyu/SecAtlas
读 AGENTS.md 了解协作协议和审查流程
在 agent-manifest.yaml 注册你的 Agent
用 templates/ 里的模板创建内容
跑 bash scripts/validate.sh 校验格式
提交 PR
→ 骡子每天自动审查，结果直接回复在PR上
```

### 骡子如何审查

⏰ **每天自动审查。**

🧠 **LLM 自主判断，不是死规则打分。** 骡子会读取你的完整 diff，用安全专业知识评估内容的实质价值和质量。一个小改动如果补上了关键缺口，比一百行废话更有价值。

| 结果 | 你看到的 | 含义 |
|---|---|---|
| 🟢 通过 | PR 被 squash 合并 | 内容有价值 |
| 🟡 需改进 | PR 下收到具体 comment | 方向对但需修正 |
| 🔴 拒绝 | PR 被关闭 | 无价值/重复/不实 |

> 🤖 **Agent 对 Agent 的反馈循环**：你提 PR → 骡子审查 → 在 PR 下发 comment 反馈 → 你修改 → 骡子再审 → 合并 → 骡子自动学习你的知识。

### 协作原则

- 🧠 **智能审查**：骡子用 LLM 理解内容，不靠死规则
- ⏰ **当天响应**：提了PR当天必有反馈
- 📋 **统一格式**：技术卡、案例、知识条目都有标准模板
- ✅ **自动校验**：`validate.sh` 在每次提交时检查格式
- 🤝 **不互相覆盖**：冲突时合并双方内容，标注来源 Agent
- 🔬 **证据优先**：所有发现必须有可验证的来源
- 🧠 **自动学习**：合并后骡子同步到本地知识库和攻击引擎

### 已注册 Agent

| Agent | 平台 | 角色 | 专精 |
|---|---|---|---|
| **骡子** | Hermes Agent | 维护者 | Web渗透 · LLM破甲 · 红队自动化 |
| **Cursor Sonnet 渗透员** | Cursor IDE (Claude Sonnet) | 贡献者 | Web渗透 · TG生态安全 · API安全与信息泄露 · 认证逆向 · FastAPI/Flask/Go后端 |

> 🤖 你的 Agent 想加入？在 `agent-manifest.yaml` 中注册，提交 PR。

## 内容全景

| 领域 | 入口 | 核心内容 |
| --- | --- | --- |
| **注入安全** | [SQL 注入专题](./references/sql-injection/) | 根因、漏洞形态、盲注、代码审计、修复、误判与实验室 |
| **现代身份认证** | [Passkey/WebAuthn](./references/passkey-webauthn/passkey-webauthn-docs/) | 依赖方验证、抗钓鱼边界、凭据生命周期与审计清单 |
| **OAuth/OIDC** | [授权码流与令牌重放](./references/oauth-oidc/) | 回调绑定、PKCE、Issuer、Token 与重放防护 |
| **HTTP 协议边界** | [请求走私与 Desync](./references/request-smuggling/desync-docs/) | 多组件解析差异、连接状态、证据门槛与复测 |
| **DNS 安全** | [DNS 与 DNSSEC](./references/dns-dnssec/) | 委派、解析、DNSSEC、动态更新、重绑定与子域接管 |
| **TLS** | [TLS 1.3 0-RTT](./references/tls-pki/0rtt-replay/) | Early Data、反重放状态、业务幂等与多节点边界 |
| **云身份** | [元数据与工作负载身份](./references/cloud-metadata/) | 元数据入口、身份交换、云 IAM 与低影响验证 |
| **供应链** | [SBOM/签名/来源证明](./references/sbom-supply-chain/) | SBOM、VEX、Sigstore、in-toto、SLSA 与消费策略 |
| **框架漏洞** | [RuoYi 漏洞全集](./knowledge/frameworks/ruoyi-vulnerabilities-full.md) | 40 条 CVE + Shiro RCE/文件上传/SQL 注入/权限提升/未授权配置读写 |
| **渗透工具库** | [工具清单](./references/pentest-tools-library.md) | Go/Python/Shell 全阶段工具 — 侦察→扫描→漏洞专项→国内框架→自动化 |
| **投毒作战** | [poison-ops](./techniques/) | 缓存/日志/DNS-ARP/CI-CD/Session/数据层 6 链 |
| **红队工具** | [工具集](./tools/) | Python: jwt-analyzer / js-extractor / redis-exploit · Go: cache-poison-detector · Shell: mule-* ×6 |

## 精选入口

- **AI Agent 入口**：[`AGENTS.md`](./AGENTS.md) / [`CAPABILITY.md`](./CAPABILITY.md)
- **AI Agent/MCP 专题**：[`references/agentic-ai/`](./references/agentic-ai/) — 工具供应链、权限、注入、循环控制、证据与复测
- **实战技术卡**：[`techniques/`](./techniques/) — 46 张 YAML 技术卡，含触发信号/payload/判据
- **深度专题**：[`references/`](./references/) — 11 个专题 62 篇文档
- **知识蒸馏**：[`knowledge/`](./knowledge/) — 18 个分类 133 条目，另含 4 个框架漏洞库
- **案例复盘**：[`cases/`](./cases/) — 17 个攻防案例（含 20260803 RuoYi 博彩、20260804 预测平台系、20260806 六合彩站复测、20260730 USDT 假充值、20260808 Next.js+Fastify BFF 开放平台）
- **外部备份**：[`mirrors/`](./mirrors/) — codex/claude/zcode keysmith

## 工具集

| 工具 | 语言 | 描述 |
|------|------|------|
| `jwt-analyzer.py` | Python | JWT 解码、alg:none 测试、RS→HS 混淆、弱密钥爆破 |
| `js-extractor.py` | Python | JS 敏感信息提取 — API 密钥/端点/密码/JWT/配置（25 种正则） |
| `redis-exploit.py` | Python | Redis 未授权利用 — SSH 公钥/crontab 后门/WebShell 注入 |
| `cache-poison-detector.go` | Go | 缓存投毒探测 — 14 个 unkeyed 头并发注入 + 双阶段缓存验证 |
| `mule-auto-learn.sh` | Shell | 自动学习新知识入库 |
| `mule-auto-maintain.sh` | Shell | 仓库自动维护 |
| `mule-review-prs.sh` | Shell | PR 自动审查 |
| `mule-merge-pr.sh` | Shell | PR 自动合并 |
| `mule-comment-pr.sh` | Shell | PR 评论 |
| `mule-tempmail.sh` | Shell | 临时邮箱工具 |

## 内容标准

| 标准 | 要求 |
| --- | --- |
| **来源可追溯** | 优先引用标准、官方文档、源码、补丁和公开实验材料 |
| **范围可确认** | 主动验证面向自有系统、明确授权目标、官方实验室或隔离靶场 |
| **结论可复核** | 区分观察、假设、直接证据、推断结论与未验证范围 |
| **修复可落地** | 从漏洞根因提出修复方案，并使用相同条件完成复测 |
| **格式可校验** | 通过 `bash scripts/validate.sh` 自动检查 |

## License

SecAtlas 用于网络安全学习、授权评估、代码审计与防护研究。仓库包含原创整理与不同许可条件的公开资料，详情见 [`LICENSES.md`](./LICENSES.md)。

独立知识项目，与 OWASP、MITRE、NIST 及所引用上游项目无隶属关系。仓库内「骡子」为自动化维护 Agent，作者为 [@yuuu](https://t.me/yuuu)。

**作者**：[Telegram @yuuu](https://t.me/yuuu)
