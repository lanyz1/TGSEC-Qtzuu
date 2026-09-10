# AI 安全工程（吸收包）

主轴：**既让 AI 做安全，也让 AI 自己可控。**

```
AI for Security：攻击面治理 → 安全验证 → 检测 → 调查研判 → 响应处置 → 复盘进化
Security for AI：输入/身份/工具MCP/RAG记忆/动作策略/防泄漏/供应链/红队评估
                 ↓
            Control + Evidence（可追溯/可授权/可审计）
```

| 文件 | 用途 |
|---|---|
| `constitution-and-gates.md` | 宪法、五道门禁、provenance、高严重度门槛 |
| `formulas-cheatsheet.md` | 公式与金句速查 |
| `runtime-trust-skill.md` | Model/Agent/RAG/Tool/MCP 运行时信任 |
| `soc-triage-skill.md` | 多源 SOC 研判蒸馏 |
| `agents/` | 非空壳 Agent 原文（中性目录名） |

目录规则：不按领域二级堆叠；与 `llm-ai-security` 现有 prompt-injection/mcp-security 等交叉引用，不另起平行宇宙。


@TGSEC社区 · @TGSEC-Qtzuu 整理 · 2026-09-10
