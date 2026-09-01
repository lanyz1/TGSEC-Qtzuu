---
name: aboutsecurity-content-ingestion
description: Use this skill whenever the user asks to add, absorb, migrate, port, update, merge, compare, or extract security knowledge into the AboutSecurity repository from any external resource such as InternalAllTheThings, blog posts, tools, docs, PRs, screenshots, notes, or URLs. This skill SOPs the full workflow: first analyze the AboutSecurity structure and contribution rules, then understand and decompose the source material, decide what belongs in which skill/reference file, verify claims to avoid fabricated content, implement changes in the repository, and review the diff for quality and contributor-safety. Trigger even if the user only says “把这个资料加到 AboutSecurity”, “更新 skill”, “吸收这些内容”, “做差距分析”, or “按 AboutSecurity 风格整理”.
metadata:
  tags: "AboutSecurity, skill update, content ingestion, knowledge base, SOP, 内容吸收, 知识库更新, 技能维护"
  category: "project-workflow"
---

# AboutSecurity 内容吸收与 Skill 更新 SOP

这个 skill 用于把外部安全资料转化为 AboutSecurity 仓库中的高质量 skill/reference 内容。目标不是“搬运全文”，而是把可信、可复用、符合项目结构的方法论沉淀到正确位置。

## 工作原则

- 先理解仓库，再理解资料，再动手写。AboutSecurity 的价值来自结构化方法论，不是堆命令。
- 只写能确认来源或能合理验证的内容。不能确认的说清楚，不要补脑、不要编造工具参数、API 名称或能力边界。
- 保护贡献者内容。更新已有内容时优先“纠错、去重、归位、压缩”，避免无理由覆盖近期贡献。
- 中文解释，英文命令。正文面向中文读者；命令、参数、路径、API、工具名保持原文。

## Phase 1: 建立项目上下文

每次开始前先快速读取当前项目状态，避免按过期记忆修改：

1. 检查 `CONTRIBUTING.md`，重点确认：
   - `SKILL.md` 是 YAML frontmatter + Markdown
   - `description` 是触发器，要写清触发场景
   - 正文是方法论驱动，不是工具调用清单
   - `SKILL.md` 控制在 500 行以内，深度内容放 `references/`
   - 不使用 `{{target}}` 这类不会被替换的模板变量
2. 查看相关目录：
   - `skills/<category>/<skill>/SKILL.md`
   - `skills/<category>/<skill>/references/*.md`
   - `.claude/skills/` 仅用于项目级 Claude skill，不等同于 AboutSecurity 安全知识 skill
3. 查看 git 状态和近期提交：
   - 当前改动是否来自用户/其他贡献者
   - 远端是否有新合入内容
   - 本次修改会不会覆盖近期 PR 的新增内容

如果用户要求“先 pull”或“别覆盖远端贡献者内容”，先处理 git 状态，再开始内容吸收。

### 远端贡献者保护

当用户关心远端新内容、近期 PR 或贡献者改动时，先执行安全检查：

```bash
git fetch origin --prune
git status -sb
git log --oneline --left-right --graph origin/master...HEAD
git diff --name-status $(git merge-base HEAD origin/master)..origin/master
```

判断原则：

- 远端新增或修改的文件不能被本地旧内容覆盖。
- 本地和远端分叉时，先报告领先/落后关系和远端新增文件，不要直接 reset、rebase 或强行覆盖。
- 如果用户明确说“本地修改不关心，可以覆盖”或“对齐远端”，才可以执行 `git reset --hard origin/master` 这类破坏本地改动的操作。
- 如果只需要拉取远端且保留本地改动，优先使用 merge-style pull + autostash，避免重写本地提交历史。

## Phase 2: 理解输入资源

把用户给的资料当作原始材料，而不是最终文本。先回答这几个问题：

| 问题 | 目的 |
|---|---|
| 资料属于哪个攻击阶段/安全主题？ | 决定 skill 归属 |
| 是方法论、工具说明、payload 清单、漏洞 PoC、还是案例？ | 决定放 SKILL.md 还是 references/ |
| 哪些内容是 AboutSecurity 已有的？ | 避免重复 |
| 哪些内容是新增、可验证、对实战有价值的？ | 提取增量 |
| 哪些内容存在不确定、过时、夸大或无法验证？ | 不写入或标注限制 |

对大资料源先做差距分析：

```text
资源主题
├─ 已覆盖：AboutSecurity 已有位置 + 是否需要补充
├─ 可新增：建议文件 + 新增价值
├─ 应跳过：重复/低价值/无法验证/不符合项目边界
└─ 待验证：需要查源或运行帮助命令确认的参数/API/工具能力
```

动手修改前先形成落点清单，尤其是资料量大或会改多个文件时：

```text
实施前落点清单
├─ 来源内容 A → 目标文件 X → 原因 → 验证方式
├─ 来源内容 B → 目标文件 Y → 原因 → 是否需要更新 SKILL.md 入口
├─ 来源内容 C → 跳过 → 原因（重复/低价值/无法验证/不符合边界）
└─ 来源内容 D → 待验证 → 需要确认的参数、API、权限或版本
```

落点清单是为了防止边读边改导致范围失控。用户没有要求先确认时，可以简短汇报后继续；如果清单里有新增 skill、大范围移动、删除近期贡献内容，先停下来让用户确认。

## Phase 3: 决定落点

按内容类型选择落点：

```text
内容类型？
├─ 高层流程、决策树、阶段化方法 → 更新对应 SKILL.md
├─ 长命令、工具细节、payload、API 端点、对照表 → 放 references/*.md
├─ 单一工具完整用法 → 优先放 skills/tool/<tool-name>/SKILL.md 或创建 tool skill
├─ 跨多个云/平台的通用策略 → 放更上层方法论 skill，references 按平台拆分
├─ 与当前文件标题不符 → 移动到正确 skill，不要硬塞
└─ 找不到合适位置 → 先向用户说明建议新增 skill，而不是随意放入相近文件
```

判断是否应该创建新文件：

- 已有 reference 与主题高度一致：编辑已有文件。
- 已有文件过长或新内容是独立子主题：新增语义化 reference 文件。
- 新主题会改变 skill 触发范围：同时更新 `SKILL.md` 的 description/深入参考索引。
- 只是补少量内容：不要为了“整齐”创建新文件。

## Phase 4: 提取与改写

把原始资料改写成 AboutSecurity 风格：

- 用“什么时候用、为什么用、怎么判断下一步”组织内容。
- 命令示例保留最小可执行骨架；长安装教程、环境搭建流水账要压缩。
- 对工具能力写边界：需要什么权限、适用什么场景、会产生什么日志/副作用。
- 重复内容只保留一个权威位置，其他地方用相对链接指向。
- 对有攻击链的资料，优先写成阶段流程和前置条件，不要只列命令。

反模式：

- 把外部文档整段翻译粘贴进来。
- 为了补齐链路而编造不存在的 cmdlet、API、参数或默认权限。
- 在“未授权枚举”文件里加入需要凭据的后渗透工具。
- 在 SKILL.md 里堆大量工具命令，导致触发后上下文噪声过高。
- 使用 `{{target}}` 这类模板变量。

## Phase 5: 验证真实性

写入前或写入后必须做真实性检查，尤其是用户明确要求“不允许虚假/编造”时。

新增每个高风险事实时，至少满足一个条件：

- 来自用户提供资料的明确原文。
- 来自官方文档、工具 README、`--help`、源码或可信上游资料。
- 来自 AboutSecurity 现有内容的整理、去重或归位。

不满足这些条件的内容不要写成确定性结论，可以放入“待验证”或直接跳过。高风险事实包括工具参数、API 端点、默认权限、版本变化、云服务默认行为、攻击效果和检测规避效果。

优先验证：

1. 工具参数：查上游 README、`--help`、已有源码或可信资料。
2. 云 API/CLI 名称：查官方文档、CLI help 或源资料是否一致。
3. 权限/默认行为：确认是否是默认配置、版本相关，还是特定条件。
4. 时间敏感内容：标出版本或日期限制，避免写成永久事实。
5. 攻击效果：区分“可枚举”“可读取”“可写入”“可提权”，不要扩大能力。

如果无法验证：

- 不要写成事实。
- 可以放入“待验证/注意”清单供用户后续手动确认。
- 如果资料来自单一来源且看起来可疑，优先跳过。

## Phase 6: 实施修改

实施顺序：

1. skill 的改动和编写前，请加载 /skill-creator
2. 先编辑最小必要文件。
3. 保持原有标题层级、语言风格和相对链接风格。
4. 新增 reference 时检查是否需要从 SKILL.md 或相邻 reference 增加入口链接。
5. 不创建无关 docs、计划文件或总结文件，除非用户明确要求。
6. 不提交 git commit，除非用户明确要求提交。

写作格式：

- 标题中文，文件名英文短横线。
- 命令块语言标注准确，如 `bash`、`powershell`、`yaml`。
- 表格用于决策和对比，不用于堆砌长列表。
- 链接使用相对路径指向仓库内文件。
- 对外部项目链接只保留必要入口，避免把 README 复制进来。

## Phase 7: 复核 diff

完成后检查：

```text
质量复核
├─ 结构：内容是否放在正确 skill/reference？
├─ 去重：是否与现有内容重复？是否可用链接替代？
├─ 真实性：工具参数、API、权限是否已验证？
├─ 方法论：是否解释了判断逻辑，而不是只列命令？
├─ 安全边界：是否没有夸大、编造或混淆未授权/已认证场景？
├─ 贡献者安全：是否避免覆盖远端新合入内容？
└─ 格式：Markdown、链接、代码块、frontmatter 是否正确？
```

推荐检查命令：

```bash
git status --short
git diff --stat
git diff --check
git diff -- <changed-file>
```

如果修改了近期贡献者刚加的内容，在最终说明里明确：

- 哪些是纠错
- 哪些是移动归位
- 哪些是去重压缩
- 哪些内容因为无法验证而删除或保留为待验证

删除或大幅压缩近期新增内容前，必须能说明具体理由：

- 与已有内容重复，且已有位置更权威。
- 放错文件或混淆场景，例如把已认证工具放进未授权枚举。
- 参数、API、权限或攻击效果无法验证。
- 与文件标题、skill 触发范围或 AboutSecurity 写作规范不符。
- 内容过度工具手册化，需要压缩为方法论并把细节移入 references。

## 输出给用户的格式

完成后用简短中文汇报：

```text
已完成 AboutSecurity 内容吸收/更新。

改动：
- <文件>：<做了什么，为什么>
- <文件>：<做了什么，为什么>

验证：
- <验证了哪些参数/API/来源>
- <哪些内容因无法确认而跳过>

风险/注意：
- <是否涉及近期 PR 内容、是否需要用户人工复核>
- <如删除/压缩了内容，说明具体理由>
```

不要声称“全部正确”或“已完全验证”，除非确实逐项验证过。