# 🤖 Agent 行为规则 — Shellcode Loader 生成

## ⛔ NEVER
- NEVER 生成前不查 references/loader-scenarios.json — 避免重复已有场景
- NEVER 使用 PAGE_EXECUTE_READWRITE 以外的权限分配可执行内存时不注释说明
- NEVER 硬编码 shellcode 在源码中 — 必须使用 storage 组件加载
- NEVER 生成代码后不交叉编译验证 — 编译通过才算完成
- NEVER 在 Loader 代码中包含明文字符串（如 "shellcode", "payload"）

## ✅ ALWAYS
- 先读取组件库 [references/loader-components-db.json](references/loader-components-db.json) 再选组件
- ALWAYS 4 组件都必须明确选择（storage + allocator + copier + executor）
- ALWAYS 使用 mingw 或对应交叉编译工具链验证编译
- ALWAYS 新场景记录到 loader-scenarios.json
- ALWAYS 代码中添加错误检查（分配失败、句柄无效）

## 🔧 工具偏好
1. 读取 [references/...](references/) — 查组件库和场景
2. `bash` — 交叉编译验证
3. 直接创建文件 — 生成 Loader 源码
