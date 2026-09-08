# TORCH methodology delta (2026-09-08 full absorb)

Prior absorb (2026-09-05) already put into `pentest-execution` references:
engagement-state, coverage-classes, campaign-loop, confirmation-gate, oob-callbacks.

This pass additionally fused:

- **wiki/** (~500 pages) → `domains/*/torch-wiki/` by attack surface
- **hunt-*** skills → `domains/*/torch-hunt/`
- **workflow** (pt/bb/ctf/coverage/triage/evidence/wiki-recon/...) → domains
- **scripts** subset (campaign.py, next_move.py, playbook.json, wordlists, ...)
  → `domains/redteam-framework/torch-scripts/`
- **docs** workflows/conventions/auto-triggers → `torch-docs/`

## Skipped (on purpose)

- Claude Code hooks / `~/.claude` bootstrap
- Obsidian vault wiring / qmd MCP installer
- `targets/` client data
- Full `setup/bootstrap.sh` host mutation

## How to use

1. Live engagement discipline: still `skill_view(pentest-execution)` + existing gates
2. Technique lookup: `domains/<surface>/torch-wiki/` or `search_files` under domains
3. Hunt playbook: `domains/<surface>/torch-hunt/hunt-<class>/SKILL.md`
4. Campaign driver reference: `domains/redteam-framework/torch-scripts/campaign.py`



@TGSEC社区 · @TGSEC-Qtzuu 整理
