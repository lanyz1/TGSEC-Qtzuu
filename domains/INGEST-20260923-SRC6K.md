# INGEST — src-6k-skill.zip 2026-09-23

- 文件: `src-6k-skill.zip` sha256 `1ef595e2a1e7e880ddc9f8844ccd82ebb60242ebcfb2a2fb07b368f3911cc341` (1.56MB / 112 files)
- 根: `clown-src-6k-skill/`（49 方法卡 + 11 rules + FOFA MCP + Grok 用户指南）
- 旧融: 方法卡已在 `domains/*/src-methods/`，rules 已在 `domains/recon/src-rules/`（含 `dig-scope-workflow.md`）

## 差分

| 类 | 结论 |
| --- | --- |
| 49 方法卡 | 42 SAME；7 DIFF 全是套件把 GitHub 打成 `[upstream-repo]`（branding 纪律），**不回写** |
| 11 rules | 全部 SAME（含 64KB `dig-scope-workflow.md`） |
| FOFA MCP / Grok docs | 工具壳，SKIP |

## 真缺口（执行层，不是再堆卡）

`dig-scope-workflow` 锁面写在 suite `src-rules/`，**活靶入口 `pentest-execution` 没当开局硬门**。
冲突条款仍是「hard blocker → pivot NEW TARGET」+「主站铁桶 → 兄弟 IP」。

2026-09-23 实证：用户锁死 `https://pc28zd.com/customer/login`，执行层把 FOCUS 切到邻段 `thjcoin.cc`。

## 本轮动作

1. `pentest-execution` 文首加 **§0 开局先判锁面**（7 条硬门；锁面赢过邻机 pivot）
2. 删「hit hard blocker → NEW TARGET immediately」；改成锁面不换站
3. `hardened-front-sibling-pivot.md` 已有锁死提示，保持
4. 套件镜像 `hermes-skills/pentest-execution/` 已 `cp` 对齐
5. 方法卡不重融、GitHub 链接不还原

用户点名 URL = 锁面。邻机只 recon。
