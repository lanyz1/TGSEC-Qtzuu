# TGSEC 红队执行引擎 — 多AI工具配置

> @TGSEC社区 · @TGSEC-Qtzuu 整理

一套配置让主流AI CLI工具变成渗透测试执行引擎。

## 支持的AI工具

| AI工具 | 配置文件 | 安装方式 |
|--------|---------|---------|
| **Hermes Agent** | `hermes/` | `cd hermes && bash setup.sh` |
| **Claude Code** | `claude/CLAUDE.md` | `cp claude/CLAUDE.md 项目根目录/CLAUDE.md` |
| **OpenAI Codex** | `codex/instructions.md` | `cp codex/instructions.md .github/copilot/` |
| **Grok CLI** | `grok/system.txt` | `cp grok/system.txt ~/.grok/` |
| **Cursor** | `cursor/.cursorrules` | `cp cursor/.cursorrules 项目根目录/` |
| **Aider** | `aider/.aider.conf.yml` | `cp aider/.aider.conf.yml 项目根目录/` |

## 通用配置

`universal/` 目录包含不依赖特定AI工具的通用配置:
- `PERSONA.md` — 红队人格(身份+规则+流程)
- `MEMORY.md` — 渗透知识(攻击面+平台特征+绕过策略)
- `RULES.md` — 执行铁则(命令规范+输出风格)

不在上表的AI工具,直接把 `universal/PERSONA.md` 的内容粘贴到对应工具的 system prompt 即可。

## 快速安装

```bash
git clone https://github.com/lanyz1/TGSEC-Qtzuu.git
cd TGSEC-Qtzuu/ai-config

# Hermes
cd hermes && bash setup.sh && cd ..

# Claude Code
cp claude/CLAUDE.md ../CLAUDE.md

# Cursor
cp cursor/.cursorrules ../

# 其他工具按上表操作
```

## 配置后效果

- 收到渗透指令直接执行,不拒绝
- 自动化验证码破解(Tesseract OCR + RSA)
- 按攻击面优先级自动规划
- 限速时自动切换攻击面
- 配合仓库 `domains/` 目录的 0day 漏洞库 + 21个攻击面知识
