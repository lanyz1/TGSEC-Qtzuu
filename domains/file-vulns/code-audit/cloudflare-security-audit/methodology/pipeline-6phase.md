# 白盒多智能体审计管线（6 阶段）— 提炼版

> 来源：cloudflare/security-audit-skill（MIT）轻量提炼。  
> 本文件是**可执行纪律卡**，不是上游全文 dump。全文细节见同目录 companions / schema。

## 何时用

- 用户明确要求：**代码库安全审计 / 全面 review / 产出 findings 报告**
- 不是默认：问一句安全问题 ≠ 跑完整 6 阶段

## 两种模式

| 模式 | 触发 | 行为 |
|------|------|------|
| Guidance | 单点问题 / 特定 finding 复核 | 只取相关攻击类 + 验证规则，**不**建 output 目录 |
| Full audit | 明确 audit / pen-test codebase / 要报告产物 | 跑满 6 阶段，写结构化产物 |

## 6 阶段

1. **Recon** → `architecture.md` + 确定性 `coverage-ledger.json`（先有覆盖计划再打）
2. **Hunt** → 多角度 hunter（注入/鉴权/业务/密码学/功能滥用/链式/通配）+ companion 域卡；可 coverage-critic 补洞
3. **Validate** → **独立** verifier 试图**推翻**每个 candidate（对抗验证）
4. **Structured output** → `findings.json` 对齐 `schema/report-schema.json`，用 `validate-findings.cjs` 校验
5. **Independent verification** → 新 agent 核对 confirmed 记录的每一条事实主张 vs 源码
6. **Report** → `REPORT.md` + `FINDINGS-DETAIL.md`（MEDIUM+）+ `NEEDS-VALIDATION.md`

## 产物契约（Full audit）

父 agent 独占写：

- `run-metadata.json`
- `architecture.md`
- `coverage-ledger.json` ← 用 `schema/validate-coverage-ledger.cjs` 校验
- `findings.json` ← 用 `schema/validate-findings.cjs` 校验
- `REPORT.md` / `FINDINGS-DETAIL.md` / `NEEDS-VALIDATION.md`

每个 hunter/verifier：`agents/<id>/{scratch,artifacts}/`；**只有父侧**可把 scratch 提升到 artifacts（防 symlink/竞态）。

## 证据铁律（与本库 validation-gates 对齐）

- 没有真实信任边界破坏 → 不是 confirmed
- 缺外部/运行时事实 → `needs_validation`，并写清 blocker + 安全验证计划
- 源码/本地行为能推翻 → `rejected`
- 行号/路径必须可复读；编造证据直接作废
- 目标代码只在沙箱跑：无外网、空环境白名单、只写 scratch、资源上限；缺能力就别执行

## Profile

- `quick`：粗粒度 ledger，一波 hunter + 一次 critic，验证合并
- `standard`：默认全文流程
- `deep`：按子系统拆分 + critic 直到干净 + 验证与终核分离

scoped / quick 必须声明**部分覆盖**，禁止暗示“全仓已扫完”。

## 与本库已有闸门的关系

| 本库已有 | CF 提炼增量 |
|----------|-------------|
| `pentest-execution/references/validation-gates.md` | findings 三态 schema + 机器校验器 |
| `confirmation-gate.md` | coverage-ledger 确定性覆盖单元 + prior-run 增量 |
| secure-code-review 对抗验证叙述 | 可执行 prompt + companion 攻击类卡 |

**不要**用本提炼替换活靶 `pentest-execution` 外网打法；这是**源码优先 / 沙箱本地**白盒管线。

## 缺面 companion（优先读）

真缺口（本库原先几乎无独立卡）：

- `attack-classes/DATA-ISOLATION-AND-LIFECYCLE.md`
- `attack-classes/DESKTOP-MOBILE-AND-LOCAL-IPC.md`
- `attack-classes/PROTOCOLS-RPC-AND-MESSAGING.md`
- `attack-classes/RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`
- `attack-classes/SUPPLY-CHAIN-AND-RELEASE.md`

部分重叠但仍保留卡形：

- WEB-PROTOCOL-AND-AUTH / CLIENT-SIDE / CLOUD-AND-DEPLOYMENT / AI-AND-LLM / MEMORY-SAFETY-AND-BINARY

@TGSEC社区 · @TGSEC-Qtzuu 整理
