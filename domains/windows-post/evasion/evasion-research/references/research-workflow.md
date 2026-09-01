# 研究流程详细参考

> 提取自 Evasion-SubAgents/research.md，供 [references/research-workflow.md](references/research-workflow.md) 引用。

## Step 1: GitHub 搜索

使用 `gh` CLI 搜索。先宽后窄。

```bash
# 搜索仓库
gh search repos "shellcode loader language:C stars:>20" --limit 20
gh search repos "AMSI bypass" --limit 15
gh search repos "syscall direct" --language c --limit 15

# 搜索代码模式
gh search code "VirtualAlloc PAGE_EXECUTE_READWRITE" --language c --limit 30
```

## Step 2: 仓库分析

对有价值的仓库，获取关键文件：

```bash
# 查看仓库信息
gh repo view owner/repo

# 列出文件
gh api repos/owner/repo/contents

# 获取文件内容
gh api repos/owner/repo/contents/path/to/file.c --jq '.content' | base64 -d
```

## Step 3: 模式提取

按以下类别分类提取的技术：

| 类别 | 关键词 |
|------|--------|
| **内存分配** | VirtualAlloc, HeapCreate, NtAllocateVirtualMemory, MappedFile |
| **代码执行** | CreateThread, EnumWindows, APC, Fiber, callback |
| **API 混淆** | API hashing, PEB walk, GetProcAddress, dynamic resolve |
| **字符串混淆** | XOR, AES, stack strings, compile-time encryption |
| **反分析** | IsDebuggerPresent, CheckRemoteDebugger, anti-VM, sandbox |
| **Syscall** | direct syscall, indirect syscall, SSN, Hell's Gate |

## Step 4: 去重检查

入库前必须去重：

| 条件 | 操作 |
|------|------|
| 完全同名 | SKIP — 重复 |
| 同技术不同名 | SKIP — 重复 |
| 同目标不同实现 | ADD — 两者都有价值 |
| 不同目标类似 API | ADD — 不同用途 |
| 同源码同方法 | SKIP — 重复 |
| 同源码不同方法 | ADD — 变体 |

## Step 5: 输出总结

研究完成后提供：

1. **发现的技术**: 列表 + 简述
2. **复杂度评估**: simple / medium / complex
3. **知识库状态**: NEW / DUPLICATE / VARIATION
4. **参考链接**: GitHub URL

## Bash 命令规范

✅ **正确**:
```bash
gh search repos "shellcode loader"
```

❌ **错误**:
```bash
gh search repos "query" 2>/dev/null      # 不要重定向
cd "/some/path" && gh search repos ...    # 不要 cd 组合
```
