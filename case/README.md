# TGSEC × Black-cat 案件目录

- `ledger.jsonl` — 唯一机器真相源（hypothesis/evidence/verdict）
- `evidence-validation.md` — 自动生成可视化报告（勿手改）
- `artifacts/` — 原始响应/日志/截图

命令（在包根）：

```bash
python3 -X utf8 .claude/skills/pentest-redteam/scripts/case_ledger.py context case
python3 -X utf8 .claude/skills/pentest-redteam/scripts/case_ledger.py render case
python3 -X utf8 .claude/skills/pentest-redteam/scripts/case_ledger.py verify --report case
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
