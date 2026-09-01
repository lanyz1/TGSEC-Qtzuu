# AGENTS.md — AI Agent 引导文件

> 🤖 你(Agent)拿到本仓库后,请按以下流程自动初始化。本仓库是 @TGSEC-Qtzuu 整理的 TGSEC社区 学习渗透套件。

## 第 1 步:环境自检

```bash
# 检测常用工具链
bash scripts/check-tools.sh
```

输出每项工具的状态:`[OK]` 已安装 / `[MISS]` 缺失 / `[N/A]` 不适用。

## 第 2 步:补装缺失工具

```bash
# 自动安装缺失工具(apt/pip/npx/go 多通道探测)
bash scripts/install-tools.sh
```

如果目标场景需要专用工具(如 CTF 逆向需要 radare2、内网需要 impacket),而当前不在「必备清单」里,安装前先查 `scripts/tools-manifest.json`——那里有 80+ 工具的分类、安装方式、装到哪。

## 第 3 步:选择知识入口

| 场景 | 入口 |
|------|------|
| 不知道从哪开始 | `MASTER.md`(21主题导航 + 5步路由) |
| 指定攻击面 | `domains/<主题>/README.md` |
| 具体漏洞技术 | `domains/<主题>/<子目录或文件>` |

## 渗透中缺工具怎么办

**规则:缺什么装什么,装完继续,不要中断任务。**

1. 先查 `scripts/tools-manifest.json` 里是否有该工具(有→按 manifest 安装方式装)
2. 没有 → 按工具类型选安装通道:
   - apt/pip/npm/go install 常规通道
   - GitHub release 下载(解压到 `~/tools/` 并加入 PATH)
   - 便携脚本(单文件 python/bash,直接运行)
3. 装完立即验证 `command -v <工具>` 确认可用
4. 如果 manifest 里没有,把新工具补进 manifest(名称/类型/安装方式),方便下次自动装

## 目录结构

```text
MASTER.md        # 总入口:21主题导航 + 5步路由
README.md        # 项目简介
AGENTS.md        # 你正在读的引导文件
scripts/
  check-tools.sh          # 工具检测
  install-tools.sh        # 自动安装缺失工具
  tools-manifest.json     # 80+ 工具清单(名称/分类/安装方式)
domains/         # 21 个主题域知识库
  <主题>/
    README.md    # 主题索引
    ...          # 技能/文档
skills/          # Hermes 技能入口
```

## 行为准则

- 仅对**合法授权**的目标执行测试,遵守 scope/authorization
- 所有操作记录证据链(时间/命令/结果),报告可复核
- 同一技术有多个文档时,融合多来源后给出结论
- 工具不可用/不支持时,先装,再测,不要跳过

@TGSEC社区 · @TGSEC-Qtzuu 整理
