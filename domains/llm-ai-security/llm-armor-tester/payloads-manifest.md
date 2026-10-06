# payloads/ 载荷库清单 — llm-armor-tester

> 源仓库 `Limcrence/llm-armor-tester` 的 `payloads/` 目录共 3 个 JSONL 文件（**未随本卡复制**：
> 合计 1.7MB+ 超出单卡体积限制，按规范改为清单说明）。JSONL 每行一条载荷记录，
> 字段结构（id/name/category/severity/objective/tags/payload/leak_markers/canary/
> system_prompt_override/follow_up/parent_id/source/notes）见本卡 README「payload 库结构」。

| 文件 | 记录数 | 大小 | 说明 |
|---|---|---|---|
| `payloads/payloads.jsonl` | 50 | 24K | 内置基础载荷（P001 起；category 如 prompt_leak / roleplay_dan / direct_override / hypothetical / encoding / fake_system / splitting / few_shot 等） |
| `payloads/payloads_advanced.jsonl` | 20 | 12K | 进阶载荷（P101 起；组件栈新范式 category：semantic_disguise / protocol_adoption / reasoning_hijack / phantom_authority / ontology_reframe / fixture_normalization / context_presupposition / format_hijack） |
| `payloads/payloads_mutated.jsonl` | 600 | 1.7M | `expand` 变异增殖产物（M0001 起，`source: mutate:...`，23 种变异算子：rot13 / homoglyph / zwsp / b64_nested / unicode_escape 等，确定性可复现、带 parent_id 血缘） |

已随本卡复制的内容：`chains/attack_chains.jsonl` —— 6 条多轮攻击链
（C001 密语触发 / C002 渐进服从登门槛 / C003 记忆污染 / C004 角色渐变 / C005 分心掩护 / C006 跨轮编码重组）。

载荷总量对账（README 原文）：二代载荷库共 713 条 = 内置 50 + 外部词库引入 43 + 变异增殖 600；
其中「外部词库引入 43 条」来自使用者本地引入的第三方词库，源仓库不携带其文本，故不在上表。

重新生成 / 扩充方式（README 原始命令）：

```powershell
# 查看内置库统计
python -m armor_tester payloads stats

# 变异增殖：库扩到 600+
python -m armor_tester expand --target 600 --out payloads/payloads_mutated.jsonl

# 引入外部词库（逐行测试题 / 整篇越狱大文本 / 人设越狱词自动识别）
python -m armor_tester import-goods --goods-root <外部词库目录> --out payloads/payloads_ref.jsonl
```

往 `payloads/` 追加任意 `*.jsonl` 即可扩库，id 全局唯一自动校验（README）。
