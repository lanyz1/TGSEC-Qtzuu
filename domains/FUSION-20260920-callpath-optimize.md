# 本地调用闭环优化 — 2026-09-20

## 目标
渗透过程中技能/实战课可自动调到，而不是堆文件调不到。

## 已落地

### P0 调用硬伤
- 迁走并清空 `~/.hermes/skills/security.bak.*`（曾导致 `skill_view` Ambiguous）
- 修改 `scripts/sync-hermes-skills.sh`：备份改到 `~/.hermes/skill-backups/`，保留最近 3 份；自动迁出树内 legacy bak

### P1 私有技能进强制矩阵
- `pentest-execution` FULL MATRIX 增加：白标大厅/支付、发卡、USDT faka、TG MiniApp、盗U/drainer、假交易所、LLM 网关、WAF 登录、CF 源站、自建面板等
- `tgsec-suite` 实战课表增加 skill_view 列

### P2 噪声与实战入口
- 114 个 `sinian-*` 迁入各域 `src-methods/_vendor/sinian/`，并写 README「默认不遍历」
- 新增 `gambling-pentest/case-lessons/712win3-partial-users.md` + case-reports 指针；CASE-INDEX 现 **51** 课
- ROUTING/MASTER 继续以 CASE-INDEX 为中途强制入口

### P3 触发描述
- 过长 description 截到 ≤57 且可读

## 校验
- 裸名 `pentest-execution` / `tgsec-suite` / `hack-skills` / 私有技能：**matches=1**
- 树内 bak：**0**
- vendor sinian：**114**；顶层 sinian：**0**
- CASE-INDEX 含 `712win3-partial-users`

## 闭环调用序
```text
开打/继续深挖
→ skill_view(pentest-execution)+skill_view(tgsec-suite)
→ 命中资产则 skill_view(私有专项)
→ read_file domains/CASE-INDEX.md
→ case-lessons≥1
→ playbook/hunter/非vendor src
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
