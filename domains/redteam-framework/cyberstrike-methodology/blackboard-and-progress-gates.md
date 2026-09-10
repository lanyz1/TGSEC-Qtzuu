# 战役黑板 + 长任务无进展闸

## 映射（禁止假装有上游 SQLite API）

| 上游概念 | TGSEC/Hermes 落点 |
|---|---|
| Fact / confidence | `loot.md` + `state.md`（标 confirmed/tentative/deprecated） |
| 负结果 | `Deadends.md`（方法+排除原因） |
| 关系边 / 攻击路径 | `Killchain.md` |
| 任务账本 / open row | `Approach.md` + campaign `board` |
| 决策日志 | `state.md` 决策段 |

## 强制节奏：边打边记

1. 每确认新认知（端口/版本/入口/认证态/攻击面变化）→ **立即**写入 loot/state  
2. 每验证可复现洞 → 写入 Vuln-index + 证据路径；同步 confirmation-gate  
3. 上下文压缩/跨天/多代理前：先落盘再继续  
4. 子任务返回新认知：协调者负责写入，不假定子代理已记

## confidence 铁律

- **搜索结果 / 公开 PoC 线索 ≠ confirmed**  
- confirmed 必须附：命令输出 / HTTP 响应 / 文件内容 / OOB HIT  
- 禁止“可能/疑似”当结论；要么 confirmed+证据，要么 tentative，要么不报  
- 验证失败 → 负结果落 Deadends，防重复打点

## action_fingerprint（防原地循环）

```
fingerprint = target + tool + normalized_args + credential_context + intent
```

- 已成功 → 不得同参重复  
- 已失败且前置条件无变化 → 不得重复  
- 正在运行 → 只查状态，禁止当失败重启同动作

## 无进展退出（不是错误次数）

| 事件 | 动作 |
|---|---|
| 同一工具同一错误 | 最多重试 1 次；第二次必须改参/换工具/换假设 |
| 连续 2 步无新增事实/证据/关系/状态 | 停分支，重读 state/loot，replan |
| 连续 2 次 replan 仍无进展 | 任务 **blocked**：写清缺什么、试过什么、要人工补什么 |
| 工具长时间无输出 | 按超时终止/查状态，不重启相同动作 |
| 上下文压缩 | 压缩前写入；压缩后先重载范围、关键事实、负面结果、账本、最近决策 |

用户说「继续」= 跑 campaign `next`，不是写总结；blocked 时上报缺口而不是空转。

## Role 最小权限（概念）

拆成：只读验证 / 防御建议（只产 ControlIntent）/ 变更执行（仅 Workflow+HITL）。  
Hermes 侧：高风险工具默认不在常规角色；生产策略变更禁止 Agent 直接下发。


@TGSEC社区 · @TGSEC-Qtzuu 整理 · 2026-09-10
