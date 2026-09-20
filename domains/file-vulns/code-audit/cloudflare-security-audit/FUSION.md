# FUSION · cloudflare/security-audit-skill · 2026-09-20

## 决策

用户选 **轻量提炼**：只融缺口，不新建独立 Hermes 技能，不整仓堆叠。

## 上游

- repo: https://github.com/cloudflare/security-audit-skill
- license: MIT
- local clone (transient): `/tmp/cf-security-audit-skill`

## 已存在（故不重吸）

- 名称引用已在 `playbook-6000/secure-code-review` / sinian secure-code-review
- 活靶验证门：`pentest-execution/references/validation-gates.md` + `confirmation-gate.md`
- CF 边车：`cdn-origin-tracing` / `cloudflare-turnstile-bypass` / `cf-hidden-origin-tracing`（不同问题域）

## 本次增量

- `methodology/*` 纪律卡（pipeline / ledger / verdicts / anti-patterns）
- `attack-classes/` 缺面 + 高信号 companion
- `schema/` report-schema + 两个 validator + tests

## 刻意跳过

- 上游全文 SKILL/HUNTING/RECON/VALIDATION 原文件（改提炼）
- Hermes `security-audit` 伞形技能
- 与活靶外网攻击链混写

@TGSEC社区 · @TGSEC-Qtzuu 整理
