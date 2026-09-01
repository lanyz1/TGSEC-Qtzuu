---
name: ctf-ai-ml
description: "CTF AI/ML 攻击技术。当挑战涉及 AI 模型攻击、对抗样本生成、模型提取、Prompt 注入/越狱、LoRA 权重操纵、LLM Token 走私、成员推理攻击、训练数据投毒、神经网络分析时使用。覆盖 FGSM/PGD/C&W 对抗攻击、模型反演、模型权重扰动还原、LLM 工具链劫持、上下文窗口操纵等 AI 安全全链路攻防技术"
metadata:
  tags: "ai,ml,machine learning,adversarial,FGSM,PGD,model extraction,model inversion,prompt injection,jailbreak,token smuggling,LoRA,safetensors,pytorch,transformers,membership inference,data poisoning,backdoor detection,neural network,LLM,GPT,classifier,evasion,adversarial patch"
  category: "ctf"
---

# CTF AI/ML Attack Techniques

## When to Use
- Challenge involves ML model files (.pt, .pth, .safetensors, .onnx, .h5)
- Target is an AI chatbot, LLM-based application, or ML classifier
- Need to craft adversarial examples to fool image/text classifiers
- Challenge provides model weights for analysis or manipulation
- AI/ML platform security testing (model extraction, membership inference)

## Quick Start
```bash
pip install torch transformers numpy scipy Pillow safetensors scikit-learn
file model.*
python3 -c "import torch; m=torch.load('model.pt'); print(type(m), m.keys() if hasattr(m,'keys') else '')"
```

## Decision Tree
1. **Model weight file** (.pt/.safetensors) → [model-attacks.md](references/model-attacks.md)
   - Weight perturbation negation, model inversion, LoRA merging, encoder collision
2. **Image classifier to fool** → [adversarial-ml.md](references/adversarial-ml.md)
   - FGSM, PGD, C&W attacks, adversarial patches, evasion, data poisoning
3. **LLM/chatbot target** → [llm-attacks.md](references/llm-attacks.md)
   - Prompt injection, jailbreaking, token smuggling, tool use exploitation
4. **Pure math/crypto inside ML** → Switch to `ctf-crypto`
5. **Compiled model binary** → Switch to `ctf-reverse`
6. **Python jail wrapped in chatbot** → Switch to `ctf-misc`

## Pivot Signals
- If challenge is pure cryptography/number theory with no ML → `/ctf-crypto`
- If reverse engineering compiled inference binary → `/ctf-reverse`
- If Python sandbox escape inside chatbot wrapper → `/ctf-misc`
- If web app with AI features (prompt injection via web) → `/ai-security/prompt-injection`
