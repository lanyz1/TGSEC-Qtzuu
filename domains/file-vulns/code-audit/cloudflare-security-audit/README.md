# Cloudflare security-audit-skill · 轻量提炼

**不是**整仓 vendor，**不是**新建 Hermes 伞形技能。  
落点：白盒审计方法论增量 → `domains/file-vulns/code-audit/`。

上游：<https://github.com/cloudflare/security-audit-skill>（MIT）  
账本：[`FUSION.md`](FUSION.md)

## 目录

| 路径 | 内容 |
|------|------|
| `methodology/pipeline-6phase.md` | 6 阶段纪律 + 与本库闸门对齐 |
| `methodology/coverage-ledger.md` | 确定性覆盖账本 / prior-run |
| `methodology/findings-verdicts.md` | confirmed / needs_validation / rejected |
| `methodology/anti-patterns.md` | 审计反模式 |
| `attack-classes/` | companion 攻击类（优先缺面 5 张 + 部分重叠保留） |
| `schema/` | `report-schema.json` + `validate-*.cjs`（含 test） |

## 怎么用（人 / AI）

1. 活靶外网渗透 → 继续 `pentest-execution`，**别**拿这套当外网剧本  
2. 明确要**源码审计报告** → 读 `methodology/pipeline-6phase.md`  
3. 按架构选 companion：`attack-classes/*.md`（缺面优先）  
4. 产出后跑：

```bash
node domains/file-vulns/code-audit/cloudflare-security-audit/schema/validate-coverage-ledger.cjs coverage-ledger.json
node domains/file-vulns/code-audit/cloudflare-security-audit/schema/validate-findings.cjs findings.json
```

## 吸了什么 / 没吸什么

**吸（缺口）：** coverage-ledger 概念+校验器、findings schema+校验器、数据隔离/本地IPC/RPC消息/资源耗尽/供应链 companion、6 阶段对抗验证纪律。

**不吸：** 整份上游 SKILL/HUNTING/RECON/VALIDATION 原文堆叠；不新建 `skill_view(security-audit)`；不覆盖本库已有 Turnstile/CDN/活靶链。

@TGSEC社区 · @TGSEC-Qtzuu 整理
