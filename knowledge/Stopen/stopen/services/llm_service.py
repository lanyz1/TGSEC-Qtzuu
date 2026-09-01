"""LLM 统一调用封装 —— 渗透专用提示词"""
import json, re
from pathlib import Path
from typing import AsyncGenerator, Optional
from services.llm_client import completion, acompletion
from app_config.encryption import ConfigEncryption
from app_config.providers import PROVIDERS
from app_config.settings import CONFIG_DIR

_encryption = ConfigEncryption(CONFIG_DIR)
MAX_CONTEXT_CHARS = 32000
MAX_HISTORY_MESSAGES = 20
SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "SYSTEM_PROMPT.md"


def _get_model_string(provider_key: str, model_name: str) -> str:
    provider = PROVIDERS.get(provider_key)
    if not provider:
        raise ValueError(f"未知提供商: {provider_key}")
    prefix = provider["api_prefix"]
    return model_name if model_name.startswith(prefix) else f"{prefix}{model_name}"


def _get_llm_kwargs(provider_key: str) -> dict:
    config = _encryption.load_config()
    saved = config.get(provider_key, {})
    kwargs = {"api_key": saved.get("api_key", "")}
    info = PROVIDERS.get(provider_key, {})
    if info.get("base_url") and not info.get("is_native", True):
        kwargs["api_base"] = saved.get("base_url") or info["base_url"]
    return kwargs


def _truncate_history(messages: list, max_chars: int = MAX_CONTEXT_CHARS,
                      max_msgs: int = MAX_HISTORY_MESSAGES) -> list:
    if not messages:
        return messages
    trimmed = messages[-max_msgs:] if len(messages) > max_msgs else list(messages)
    total = sum(len(str(m.get("content", ""))) for m in trimmed)
    while total > max_chars and len(trimmed) > 2:
        removed = trimmed.pop(0)
        total -= len(str(removed.get("content", "")))
    return trimmed


def _build_system_prompt(task_type: str = "pentest", custom: str = "") -> str:
    """根据任务类型构建渗透专用系统提示词"""
    if custom:
        return custom

    prompt = f"""你是 Stopen，自动化渗透测试 Agent。

# 工作方式
使用 OODA 循环 + 黑板（Blackboard）追踪渗透进度：
- **Observe**: 读取黑板 Facts/Intents，分析当前状态
- **Orient**: 判断目标是否达成、下一步方向
- **Decide**: 决定执行哪个 Intent（或产生新 Intent）
- **Act**: 调用工具执行，结果写回黑板

# 核心规则
1. **反幻觉**: 所有"发现"必须有工具输出原文佐证。无证据的声称视为不存在。
2. **工具优先**: 能用工具做的事情不让 LLM 猜。拿不准就扫一下。
3. **记录进度**: 每个发现写回黑板 Facts，每个待办事项写回 Intents。
4. **安全第一**: 仅用于授权测试，提问后才执行破坏性操作。"""

    if task_type == "ctf":
        prompt += """

# CTF 模式
目标：找到 flag。
策略：
- Web 题目：扫端口 → 扫目录 → 找注入/上传/RCE
- Crypto 题目：识别加密类型 → 应用对应的解码/解密
- Reverse 题目：分析文件 → 找关键逻辑 → 逆向 flag
- 找到 flag 后立即报告，格式：FLAG{{...}}"""

    prompt += """

# 可用工具
调用合适的工具完成当前步骤。工具会返回执行结果，根据结果决定下一步。

# 输出规范
- 第 1 行输出你正在做的事情（中文，一句话）
- 然后可以调用工具
- 工具结果返回后分析结果
- 不要输出长篇大论的解释"""
    return prompt


def test_connection(provider_key: str, api_key: str, base_url=None, model=None) -> tuple:
    info = PROVIDERS.get(provider_key)
    if not info:
        return False, f"未知提供商: {provider_key}"
    test_model = model or (info["models"][0] if info.get("models") else "gpt-4o-mini")
    model_str = _get_model_string(provider_key, test_model)
    kwargs = {"api_key": api_key, "timeout": 10}
    if not info.get("is_native", True) and (base_url or info.get("base_url")):
        kwargs["api_base"] = base_url or info["base_url"]
    try:
        resp = completion(model=model_str, messages=[{"role": "user", "content": "Hi"}], max_tokens=5, **kwargs)
        return True, f"连接成功！模型响应: {resp.choices[0].message.content[:50]}"
    except Exception as e:
        return False, f"连接失败: {str(e)}"


async def chat_stream(messages, model, provider_key, task_type="pentest",
                      tools=None, model_params=None, cancel_event=None,
                      custom_prompt="") -> AsyncGenerator[str, None]:
    truncated = _truncate_history(messages)
    system = _build_system_prompt(task_type, custom_prompt)
    full_msgs = [{"role": "system", "content": system}] + truncated
    kwargs = _get_llm_kwargs(provider_key)
    if not kwargs.get("api_key"):
        yield "\n[错误] 请先配置 API Key"
        return
    if model_params:
        for k in ("temperature", "top_p", "max_tokens", "presence_penalty", "frequency_penalty"):
            if model_params.get(k) is not None:
                kwargs[k] = model_params[k]
    try:
        resp = await acompletion(
            model=model, messages=full_msgs, stream=True,
            **(dict(tools=tools) if tools else {}), **kwargs)
        async for chunk in resp:
            if cancel_event and cancel_event.is_set():
                break
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta and delta.content:
                yield delta.content
    except Exception as e:
        yield f"\n[错误] {str(e)}"
