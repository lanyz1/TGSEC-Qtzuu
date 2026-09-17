# TG/会话进度备忘 2026-09-08

- Source report: `session-progress-2026-09-08.md`
- Full report: `domains/api-security/case-reports/session-progress-20260908/session-progress-2026-09-08.md`
- Techniques: telegram, auth
- Fused: 2026-09-17

## Key findings (distilled)

- **Saved at:** 2026-09-08 17:01 UTC
- **Channel:** Telegram DM with 擎天柱
- **Status:** PAUSED (no offensive work on live target)
- ---
- | Item | Result |
- |------|--------|
- | Request | Install https://github.com/lanyz1/TGSEC-Qtzuu, overwrite existing |
- | Path | `/root/security-suite` |
- | Method | `bash scripts/reinstall-tgsec.sh /root/security-suite` |
- | Git | `origin/master` @ `fc7e2aa` — up to date |
- | domains/ | ~2879 files, 24 attack-surface domains |
- | Hermes skills | 13 umbrellas → `~/.hermes/skills/security/` (overwrite) |

## Repro snippets

```
/root/security-suite/                 # TGSEC-Qtzuu
/root/security-suite/domains/         # knowledge body
/root/security-suite/AGENTS.md
/root/security-suite/MASTER.md
/root/security-suite/ROUTING.md
/root/.hermes/skills/security/        # active Hermes umbrellas
/root/.hermes/skill-backups/          # old skill bak trees
/root/session-progress-2026-09-08.md  # this file
```

## When to reuse

- 同类标签命中：telegram, auth
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
