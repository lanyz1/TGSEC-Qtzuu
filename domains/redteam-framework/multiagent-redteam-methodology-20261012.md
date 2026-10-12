# 多智能体红队框架 — 方法论提炼 (2026-10-12)

- 定位: 多智能体红队框架工程参考；**不整仓入库**，三个可移植设计点 + 一个术语表如下。

## 1. 闭环验证层 verify_chain —— "验准"轴承（最高价值）

- 立意：红队最贵的不是"挖到"，是"验准"——未验准的发现拉去实战会翻车。
- 五算子：`timing` / `boolean` / `echo` / `sqlishape` / `score`。
  - **timing**：先对照组多次采样基线 → 取中位数 + 抖动幅度（max−min）扣除，再测 payload 延迟——防网络抖动误判。
  - **score**：证据汇总打 0-100 置信度 → **<40 不成立 / 40-70 存疑 / ≥70 成立**；未证实项不计分，绝不吹"成立"。
- 已持久化：`verification-scripts/verify_chain.py`（无依赖，urllib 实现；op=timing/boolean/echo/score/sqlishape）。
- 本地对账：已有 evidence-gate / 闭环纪律；**增量点 = 可执行的抖动扣除采样器 + 三段阈值化打分** —— 打站验证环节可直接调用该脚本。

## 2. 确定性 DAG 调度 + resolved 台账

- 原则：**LLM 只做战略决策，调度器只做确定性计算**。
- 四算子：`graph`（建任务 DAG 算就绪）/ `wave`（按优先级选一波派发，带 resolved 台账**防重复打死路**）/ `ledger`（标记向量死路）/ `status`（汇总全貌）。
- 增量点：resolved 台账防"同向量重复打"；wave 并发上限（默认 3）。

## 3. 经验蒸馏 AtkMeta（winning / losing 剧本库）

- **成功链去特化**：剥 IP/端口/路径，只留类型战术骨架链（如 `entry → vuln(lfi) → cred → foothold → goal`）。
- 剧本库 `winning_chains.json` 按 target_fp 分桶；同类合并强化置信度：
  `conf = min(0.95, 0.4 + 0.12*wins − 0.05*fails)`。
- 失败链进 `losing:` 桶 → 回灌时输出「避免: xxx(已失败N次)」。
- **证据门槛**：无证据发现不得计入成功路径。
- 增量点 vs 本地 ops-review：losing 桶反向提示 + 去特化骨架链表达法。

## 4. 编排层术语表（参考）

- `subagent`（独立上下文只回收结论）/ `team`（多角色+流程锁定）/ `workflow`（tasks+stages 流水线）/ `ralph`（每轮全新上下文，防钻牛角尖）/ `goal`（钉会话多轮）。
- 队友黑板：同批子代理共享黑板，`SAY:` 广播发现与"已排除方向"。
- 自进化：执行经验沉淀为可检索条目（factdb + 触发词机制）。

## 取用

- 持久件：`verification-scripts/verify_chain.py`（本域目录）。

@TGSEC社区 · @TGSEC-Qtzuu 整理

## 5. AtkMeta 集成点（10-12B 补）

- 命令面：开场回放 `atkmeta lessons/avoid`（避开已败向量）· 胜利蒸馏 `atkmeta save`（证据门槛：无证据发现不计入成功路径）· 败簿 `atkmeta fail`
- 存储：`winning_chains.json` 按 target_fp 分桶；losing 桶回灌输出「避免: xxx(已失败N次)」
- 置信公式：`conf = min(0.95, 0.4 + 0.12*wins − 0.05*fails)`
- 本机适配：机制并入 ops-review 沉淀流程（技能名 atk-meta-library 为来源机器实现）
