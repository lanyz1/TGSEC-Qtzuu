# Hermes Agent 红队配置

> @TGSEC社区 · @TGSEC-Qtzuu 整理

## 这是什么

将 [Hermes Agent](https://hermes-agent.nousresearch.com/) 配置为**红队渗透测试执行引擎**的预设配置文件。

安装后 Hermes 会：
- 收到渗透指令直接调工具执行，不拒绝不犹豫
- 使用疯狂天才黑客风格交互
- 自动化验证码破解（Tesseract OCR + RSA逆向）
- 按攻击面优先级自动规划渗透路径
- 限速时自动切换攻击面，不浪费等待时间
- 持续进攻直到用户说停

## 文件说明

| 文件 | 说明 |
|------|------|
| `USER.md` | 用户画像 — 定义交互风格、执行规则、渗透方法论 |
| `MEMORY.md` | Agent记忆 — 攻击面优先级、平台特征、绕过策略 |
| `setup-hermes.sh` | 一键安装脚本 |

## 快速安装

```bash
cd hermes-config
bash setup-hermes.sh
```

## 手动安装

```bash
# 1. 找到Hermes memories目录
ls ~/.hermes/memories/

# 2. 复制配置(会自动提取代码块中的实际内容)
bash setup-hermes.sh

# 或手动复制代码块内容到:
#   ~/.hermes/memories/USER.md
#   ~/.hermes/memories/MEMORY.md
```

## 配合技能库使用

本仓库的安全技能已注册为 Hermes 技能，安装后可直接调用：

```
0day-exploit-library  — 76产品90个RCE漏洞exploit
hack-skills           — 102个渗透技能
black-cat-redteam     — 假设驱动红队框架
pentest-execution     — 渗透执行攻击链
gambling-platform-pentest — 赌博平台渗透
```

## 注意事项

- 仅用于**已授权**的安全评估/红队演练/CTF
- 安装前会自动备份原有配置（`.bak.时间戳`）
- 如需还原，用备份文件覆盖即可
