# AI 安全工程 V4.1

> **主轴不是 SOC Agent，而是一套统一的 AI 安全工程：既让 AI 做安全，也让 AI 自己可控。**

V4.1 以 V3 为唯一母版：保留 V3 的平铺 `agents/`、`graph/`、`skills/` 目录、证据链规则、公式体系和统一编排方式；Security for AI 只作为新增 Agent 平铺进入 `agents/`，不另起一套目录和规则。

## 一张图看懂主轴

```text
AI for Security：攻击面治理 Agent → 安全验证 Agent → 检测 Agent → 调查研判 Agent → 响应处置 Agent → 复盘进化 Agent

Security for AI：输入与上下文安全 Agent → 身份与权限安全 Agent → 工具与MCP安全 Agent → RAG与记忆安全 Agent → 动作策略安全 Agent → 数据防泄漏 Agent → AI供应链安全 Agent → AI红队评估 Agent

                           ↓
                  Control + Evidence
                           ↓
                 可追溯 / 可授权 / 可审计
```

> **对攻击，沿证据链走；对自己，在权限笼子里跑。**

## 目录规则

```text
AI安全工程-V4.1/
├── 智能体宪法.md
├── 使用说明.md
├── 公式与金句速查.md
├── 技术校准说明.md
├── agents/          # 所有 Agent 同级平铺，延续 V3
├── graph/           # 攻击路径、盲区、实体和关系
└── skills/          # 可复用运行时 Skill
```

没有 `ai-for-security/`、`security-for-ai/` 二级 Agent 目录。**目录只表示运行资产类型，不表示安全领域边界。**

## 总公式

```text
实体解析 + 基线偏离 + 权限/不变量违反 + 跨源证据 + 因果连续 − 良性解释
= 可解释的安全结论

可解释的安全结论 + 业务影响 + Control Policy
= 可执行的响应动作

可信 AI 执行
= 身份可信 × 上下文可信 × 最小权限 × Tool控制 × 数据边界 × 审计能力
```

公式表达组合关系和门槛，不代表行业通用固定权重。

## 使用方式

1. 启动先读 `智能体宪法.md`。
2. 再读 `agents/统一编排Agent.md` 与 `agents/运行速查Agent.md`。
3. 根据任务类型调用对应宏观 Agent，再由宏观 Agent 调用专项 Agent。
4. 所有安全结论保留 provenance；所有高风险执行动作额外经过身份、权限、Policy、人审/可逆性门禁。
5. `graph/` 中的攻击路径是调查与验证参考，不是攻击已发生的事实证明；盲区只进入调查优先级，不进入事实置信度。

> **特征负责提问，证据负责定性；风险负责排序，策略负责动作。**
