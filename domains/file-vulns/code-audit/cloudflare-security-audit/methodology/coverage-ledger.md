# Coverage Ledger（确定性覆盖账本）— 提炼

> 来源：cloudflare/security-audit-skill `RECONNAISSANCE.md` / `HUNTING.md`（MIT）

## 为什么需要

单次审计**从不**等于穷尽。先建 `coverage-ledger.json`，每个 unit 有稳定 `coverage_id`，hunter/verifier 结果回写状态，下一轮读 prior ledger 做增量而不是重开盲盒。

## Unit 最小字段（校验见 schema/validate-coverage-ledger.cjs）

- `coverage_id`
- `canonical_refs`
- `surface` / `boundary` / `subsystem` / `attack_class`
- `starting_paths`
- `ordinary_attack_class_block`
- `selected_companion_blocks`
- 状态机：`planned` → `candidate` → `covered` / `deferred` / `blocked` / `out_of_scope` …
- 每条 check：`agent_id`、`reviewed_paths`、`method`=`source|local`、`artifact`

## Prior-run 规则（摘要）

1. 仅凭 prior source ref **不能**证明路径未变——要对比相关源码
2. prior `confirmed` 且源未变 → 可带入当前 candidate，但仍走终核
3. 源已变 → 新建 revalidation unit，不进 hunter 排除表冒充已覆盖
4. `needs_validation` / `deferred` / `blocked` **永不**压制当前 unit
5. `quick`/scoped prior **不得**暗示“其余都没事”

## Critic 波次

Hunt 后跑 coverage-critic：找 ledger 空洞与弱覆盖，决定补 hunter 还是 `deferred`。

机器校验：

```bash
node schema/validate-coverage-ledger.cjs /path/to/coverage-ledger.json
node schema/validate-findings.cjs /path/to/findings.json
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
