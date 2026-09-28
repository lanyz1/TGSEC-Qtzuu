# AI-Infra-Guard — 腾讯朱雀实验室 AI 红队扫描平台（数据提炼）

- **来源:** https://github.com/Tencent/AI-Infra-Guard
- **性质:** AI 基础设施安全扫描平台（Go+Python），Black Hat EU 2025 Arsenal
- **提炼内容:** 指纹库 + 漏洞规则库 + MCP 安全规则 + Prompt 安全评测集 + Research 论文

## 提炼明细

| 层 | 内容 | 数量 |
|----|------|------|
| **fingerprints/** | AI 产品指纹（YAML，含路径/Header/Body 匹配规则） | 151 个产品 |
| **vuln/** | 中文漏洞规则（按产品分目录，含 CVE/CVSS/修复建议/版本匹配） | 132 个产品 |
| **vuln_en/** | 英文漏洞规则（同上） | 132 个产品 |
| **mcp/** | MCP 协议安全扫描规则（命令注入/凭据泄露/路径遍历/反序列化/权限过大等） | 15 条 |
| **eval/** | Prompt 安全评测集（越狱/CBRN/有害行为/版权/工具滥用等） | 17 个 |
| **Research/** | SkillJack · RogueHandoff20 · forge_bench · deepseek-harness | 253 文件 |
| **aig-skills/** | AIG Agent 红队 skill（dispatcher/profiler/aggregator + report 模板） | 190 文件 |

## 覆盖产品（151 个指纹，精选）

ComfyUI · Ollama · Ray · vLLM · SGLang · LiteLLM · Dify · n8n · LangFlow · LangFuse ·
FastGPT · OpenWebUI · Jupyter (Lab/Notebook/Server) · Gradio · AnythingLLM ·
AutoGPT · CrewAI · BentoML · Triton · TensorRT-LLM · LLaMA.cpp · LocalAI ·
PrivateGPT · LibreChat · LobeCat · MLflow · KubeFlow · KubeAI · Flowise ·
HuggingFace TGI/ChatUI · Chroma · Qdrant · Milvus · Weaviate · ClickHouse ·
FastChat · H2OGPT · InstructLab · LLaMA-Factory · Text-Generation-WebUI ·
GPT-SoVITS · F5-TTS · Crawl4AI · MCP Server · MCPHub · Context7 ...

## 用法

```bash
# 查某产品指纹
cat fingerprints/comfyui.yaml

# 查某产品全部 CVE
ls vuln/ollama/

# 查 MCP 协议安全规则
ls mcp/

# 配合 gpu-hunter skill: 测绘识别产品 → 查漏洞规则 → 打
```

## SKIP

Go 源码 · frontend · Docker 配置 · go.mod/go.sum · CI/CD · PDF（>2MB × 3）

## 状态

**DATA_FUSED** — 提炼数据层 27MB/4970 文件。融合日 2026-09-28。

@TGSEC社区 · @TGSEC-Qtzuu 整理
