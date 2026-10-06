---
title: "GraphQL sort_query → Elasticsearch Painless 注入（H1 #3694007）"
type: case-lesson
tags: [api-security, graphql, elasticsearch, painless, code-injection, hackerone]
date_created: 2026-10-06
sources: ["https://hackerone.com/reports/3694007", "https://x.com/luckyhacker43"]
---

# GraphQL `sort_query` → ES Painless 注入

> 来源：HackerOne #3694007（**brumbelow**，Code Injection / High 8.8 / **$7,000**，2026-06-17 披露）· 经 @luckyhacker43 转播吸收。
> 目标：`hackerone.com/graphql` —— `Query.search(sort_query: String)` 未校验直通 ES `sort`。

## 机制

GraphQL 暴露 `sort_query: String` 参数，服务端原样塞进 Elasticsearch 搜索体的 `sort` 字段（无 schema 校验/白名单/脚本拒绝）：

```json
{"sort": [{"_script": {"type": "number", "script": {"source": "…Painless…"}}}]}
```

ES 在**逐文档**打分/排序阶段编译并执行 Painless。脚本可读 `doc[...]` 字段及 `_seq_no` 等元数据（受 ES 沙箱限制，但足够做布尔预言机）。

## 判定链（报告原法）

1. 同一查询发两次，**只改 `script.source`** → 返回文档顺序不同。
2. 请求 A：常量排序键；请求 B：以每文档 `_seq_no` 作为排序键 → B 的序 = 已知 `_seq_no` 升序基线。
3. 两组前若干位**零重叠** → 证明脚本逐文档编译执行（只有这个能解释）。

## 影响

- 布尔预言机 → **系统性枚举跨项目敏感元数据**（program handle、severity、资产标识、CWE ID、子状态等）。
- 资源消耗型脚本 → 共享 ES 集群 **DoS**。
- 平台判定：未能确认越权读取正文；元数据枚举 + DoS 已足够 High（8.8）。

## 检测 / 狩猎

- 找任何**把用户输入拼进 ES query body** 的字段：`sort` / `script` / `fields` / `runtime_mappings`。
- GraphQL 侧重点：String 型 `sort_query` / `sort` / `order_by` 直通。
- 无害打点验证执行：`{"_script":{"script":"doc['_id'].value.length()"}}`（仅授权环境）。

## 反制

- sort **白名单化**（字段名 + 方向枚举）；任何 script / 嵌套对象一律拒绝。
- ES 侧：禁用 inline scripting、专用只读账号、请求缓存隔离、针对异常脚本的审计。

## 关联

- `hunt-graphql` / `hunt-nosqli`；API 参数直通数据层的通类问题（同族思路：ORM 注入 / NoSQL 操作符注入）。
