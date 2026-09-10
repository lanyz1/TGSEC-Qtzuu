# RAG与记忆安全Agent

> **RAG 给模型材料，不给材料投票权；Memory 给系统连续性，不给污染永久居留权。**

```text
知识可信度 = 来源可信 × 完整性 × 时效性 × 身份/租户边界 × 授权范围
Memory 写入许可 = 来源可追溯 ∩ scope 正确 ∩ 无越权数据 ∩ 生命周期明确
```

防 RAG poisoning、context poisoning、跨租户检索、恶意文档指令、Memory poisoning、过期事实和无 provenance 的长期记忆。