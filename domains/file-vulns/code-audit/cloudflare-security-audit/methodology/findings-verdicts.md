# findings.json 三态 — 速查

机器源：`../schema/report-schema.json`

| verdict | 含义 | 进报告？ |
|---------|------|----------|
| `confirmed` | 源码可追溯 + 本地可复现边界破坏 + 修复建议匹配证据 | 是 |
| `needs_validation` | 源码 trace 成立，但缺部署/运行时决定性事实；必须写清 blocker + 安全验证计划 | 是（单独 NEEDS-VALIDATION） |
| `rejected` | 源码/本地行为/可见控制/无实质影响 推翻 | 不作为漏洞 |

未经验证的 candidate **只留在 ledger**，不得塞进 `findings.json`。

```bash
node ../schema/validate-findings.cjs findings.json
```

@TGSEC社区 · @TGSEC-Qtzuu 整理
