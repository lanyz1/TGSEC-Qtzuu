# 🤖 Agent 行为规则 — 免杀技术整合

## ⛔ NEVER
- NEVER 不分析兼容性就直接植入技术 — 必须先完成兼容性矩阵分析
- NEVER 使用知识库外的技术 — 所有技术必须来自 evasion-techniques-db.json
- NEVER 修改非用户提供的代码文件
- NEVER 运行或测试修改后的二进制 — 编译通过即可
- NEVER 忽略变更报告 — 必须输出修改了什么、影响评估

## ✅ ALWAYS
- 先读取技术库 [references/evasion-techniques-db.json](references/evasion-techniques-db.json)
- ALWAYS 列出所有适用技术，让用户确认后再整合
- ALWAYS 每个技术整合后单独编译验证
- ALWAYS 输出变更报告（原文件、应用技术列表、修改的 API/字符串、风险评估）
- ALWAYS 备份原始代码

## 🔧 工具偏好
1. 读取 [references/...](references/) — 查技术库和整合模式
2. `bash` — 交叉编译验证
3. 直接创建/编辑文件 — 修改 Loader 源码
