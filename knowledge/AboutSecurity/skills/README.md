# 安全 SKills

## 快速开始

```bash
# 列出所有 skills
ls skills/

# 查看特定 skills
cat skills/general/judge-pentest/SKILL.md

# 运行 Benchmark (需要本地配置好 claude code 使用)
python scripts/bench-skill.py --skill sql-injection-methodology
```

## skills 格式

```
sql-injection-methodology/
├── SKILL.md           # 决策树（触发条件 → 执行流程）
├── references/        # 详细内容（payload + 脚本）
└── evals/             # A/B 测试评估
```

SKILL.md 定义 AI Agent 的行为约束（NEVER/ALWAYS），references/ 目录按需加载详细内容。

---

## 分类架构说明

### 三级路径 vs 二级路径

本仓库的 skill 存储采用**三级路径**（按维护者视角分类）：

```
skills/<category>/<skill-name>/SKILL.md    # 维护者视角：按攻击阶段分类
```

而 AI Agent 实际消费时使用**二级路径**（扁平结构）：

```
.claude/skills/<skill-name>/SKILL.md       # Agent 视角：所有 skill 平铺
```

通过 `sync-skills.sh` 脚本将三级路径软链接/复制为二级路径。这意味着：
- **维护者**按分类组织，便于管理和查找
- **Agent** 使用时所有 skill 在同一层级，不存在"跨分类跳转"问题
- 脚本支持多源合并（如私有仓库 + 本仓库），先到先得

### 为什么 `tool/` 是独立分类

工具类 skill（如 nuclei、sqlmap）独立于方法论 skill，原因：

1. **多用途工具避免重复**：nuclei 可用于指纹扫描、漏洞扫描、DAST、本地文件扫描，若在每个引用它的 skill 中重复写使用方法，维护成本极高
2. **模型不了解新工具**：AI 模型训练数据有截止日期，对新版本工具的参数和用法不了解，需要专门的 skill 文档补充
3. **运行时无影响**：sync-skills.sh 将 tool/ 下的 skill 和其他分类一起扁平化，Agent 在使用时按 description 匹配触发，不感知分类层级

---

## skills Benchmark

`python scripts/bench-skill.py --all` 量化 skills 对 Agent 效果的提升，结果记录在 `benchmarks/` 目录。
