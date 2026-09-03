# Hermes security skills（可覆盖安装）

这些是 TGSEC 在 Hermes 上的**伞形技能入口**（`~/.hermes/skills/security/`）。

知识正文在仓库 `domains/`，这里只放路由/纪律/触发 description。

## 安装/覆盖（旧机器）

```bash
cd ~/security-suite   # 或你的 clone 路径
git pull
bash scripts/sync-hermes-skills.sh
# 或一条龙:
bash scripts/reinstall-tgsec.sh
```

装完**开新会话**，技能目录才会稳刷新。

## 清单

见各子目录 `SKILL.md` 的 `description:`（系统目录只展示约 57 字，必须是实词触发）。

@TGSEC社区 · @TGSEC-Qtzuu 整理
