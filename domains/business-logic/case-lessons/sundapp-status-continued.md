# sundapp 继续深挖战报

- Source report: `STATUS (2).md`
- Full report: `domains/business-logic/case-reports/sundapp-status-continued/sundapp-status-continued.md`
- Techniques: wallet, payment
- Fused: 2026-09-17

## Key findings (distilled)

- 可上传：`.php` / `.phtml` / `.html` / `.svg` / `.jsp` / `.aspx` / `.txt`
- partnerships 里已有历史 payload：`logoUrl=.../javascript:require("child_process").execSync("id")`（像前人打过，当前未形成可利用 RCE）
- JWT secret 伪造
- 上传 RCE（文件能传，PHP 不执行）

## Repro snippets

```
GET /api/customers?employee=<任意ObjectId>&current=1&pageSize=100
```

## When to reuse

- 同类标签命中：wallet, payment
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
