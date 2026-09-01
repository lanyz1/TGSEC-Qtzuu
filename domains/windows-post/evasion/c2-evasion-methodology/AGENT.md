# 🤖 Agent 行为规则 — C2 免杀

## ⛔ NEVER
- NEVER 跳过任何一条 YARA/Sigma 规则 — 每条规则都必须有分析和免杀方案
- NEVER 不分析检测规则就直接修改源码 — 必须先完成 Phase 2-3 再进入 Phase 4
- NEVER 直接修改二进制文件 — 只修改源码，通过重新编译产生新二进制
- NEVER 忽略 Hex pattern — 必须分析 references/hex-analysis.md
- NEVER 忽略二进制资产（shellcode/资源文件/配置文件）
- NEVER 运行或测试修改后的二进制文件 — 编译成功即可

## ✅ ALWAYS
- ALWAYS 编译器标志优先 — 最低成本最高收益（-O2, -fomit-frame-pointer, -fno-stack-protector）
- ALWAYS 检查 Makefile/CMakeLists/Cargo.toml 中的免杀机会
- ALWAYS 逐规则分析：解析 pattern → 定位源码 → 制定策略 → 实施 → 验证
- ALWAYS 验证修改后 pattern 已消除（grep 确认）
- ALWAYS 生成 modifications_summary.md 文档化所有修改
- ALWAYS 每个 Phase 开始前读取对应的 references 文档

## 🔧 工具偏好
1. `grep`/`find` — 搜索源码中的检测特征
2. `bash` — 编译验证
3. 读取 [references/...](references/) — 每个 Phase 的详细步骤
4. `http_request` — 搜索在线 YARA/Sigma 规则库
