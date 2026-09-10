# AI 红队运行时方法论（吸收自开源 Agent 平台改造实践 + 公开 Skill 套件）

> **不整仓吸收平台代码。** 只提炼可迁移到 TGSEC/Hermes 的运行时纪律，并映射到现有 `engagement-state` / `campaign-loop` / `validation-gates`。

## 吸收了什么

| 主题 | 本目录文件 | Hermes 挂载 |
|---|---|---|
| 能力原语凑链 | `capability-primitive-search.md` | `pentest-execution/references/capability-primitives.md` |
| 黑板 + 无进展闸 | `blackboard-and-progress-gates.md` | `.../cyberstrike-progress-gates.md` |
| 验证铁律 + 改动台账 | `verification-and-output.md` | （上）交叉引用 |
| 防御 ControlIntent 闭环 | `control-intent-loop.md` | 可选读 |
| 选吸片段 | `delta-snippets.md` | 组件情报/源码狩猎/LLM 应用 |

## 明确跳过

- Go 平台本体、MCP 联邦、Web UI、100+ tools YAML
- 默认全开高风险 Skill（无限扩域/钓鱼/OPSEC 整包）
- 产品私有 SQLite API 名（映射为 TGSEC 战役文件，不假装 Hermes 有 `upsert_project_fact`）

## 与现有体系关系

```
engagement-state (scope/state/loot/Deadends/Approach/Killchain)
        ↑ 写入节奏与字段语义
campaign-loop (init→board→next→done)
        ↑ 无进展 / 指纹 / replan 闸
validation-gates + confirmation-gate
        ↑ confirmed 证据门槛
capability-primitives
        ↑ 无单点 RCE 时的凑链搜索
```

来源批次：微信 CyberStrikeAI 改造文 + 公开 skills/ +（另包）AI安全工程 V4.1 见 `domains/llm-ai-security/ai-security-engineering/`。


@TGSEC社区 · @TGSEC-Qtzuu 整理 · 2026-09-10
