"""对话引擎 —— 流式输出 + 思考过程 + 工具调用循环

与 OODA Agent 的区别：面向自然语言问答，模型自主决定是否调用工具，
支持推理模型（DeepSeek-R1/GLM-Thinking 等）的 reasoning_content 透传。
事件类型：
    reasoning    思考过程增量
    token        正文增量
    tool_call    模型发起工具调用
    tool_result  工具执行结果
    error        错误
    done         结束（含最终 content/reasoning）
"""
import json
from typing import AsyncGenerator

from services.llm_client import acompletion
from services.tool_registry import tool_registry
from app_config.logging_config import get_logger

log = get_logger(__name__)

MAX_TOOL_ROUNDS = 8

CHAT_SYSTEM_PROMPT = """你是 Stopen 对话助手，帮助用户进行渗透测试与网络安全分析。
- 回复简洁专业，使用中文
- 需要实时数据（端口、Web 内容、CVE、编码转换等）时调用工具获取，不要凭空编造
- 引用工具结果时注明是工具输出
- 仅协助授权范围内的安全测试"""


def _merge_tool_call_fragments(acc: dict, frags) -> None:
    """按 index 聚合流式 tool_calls 增量分片"""
    for f in frags:
        slot = acc.setdefault(f.index, {"id": "", "name": "", "arguments": ""})
        if getattr(f, "id", None):
            slot["id"] = f.id
        if getattr(f, "name", None):
            slot["name"] = f.name
        if getattr(f, "arguments", None):
            slot["arguments"] += f.arguments


async def chat_agent_stream(messages: list, model: str, api_key: str,
                            api_base: str = None, use_tools: bool = True,
                            cancel_event=None) -> AsyncGenerator[dict, None]:
    """流式对话主循环，yield 事件 dict"""
    msgs = list(messages)
    tools = tool_registry.list_openai_tools() if use_tools else None
    kwargs = {"api_key": api_key}
    if api_base:
        kwargs["api_base"] = api_base

    for _round in range(MAX_TOOL_ROUNDS + 1):
        acc_content = ""
        acc_reasoning = ""
        tool_acc: dict[int, dict] = {}

        try:
            resp = await acompletion(model=model, messages=msgs, stream=True,
                                     tools=tools, **kwargs)
            async for chunk in resp:
                if cancel_event and cancel_event.is_set():
                    yield {"type": "done", "content": acc_content,
                           "reasoning": acc_reasoning, "reason": "cancelled"}
                    return
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                rc = getattr(delta, "reasoning_content", None)
                if rc:
                    acc_reasoning += rc
                    yield {"type": "reasoning", "text": rc}
                if delta.content:
                    acc_content += delta.content
                    yield {"type": "token", "text": delta.content}
                frags = getattr(delta, "tool_calls", None)
                if frags:
                    _merge_tool_call_fragments(tool_acc, frags)
        except Exception as e:
            log.error(f"chat stream error: {e}")
            yield {"type": "error", "text": str(e)}
            yield {"type": "done", "content": acc_content, "reasoning": acc_reasoning}
            return

        if not tool_acc:
            yield {"type": "done", "content": acc_content, "reasoning": acc_reasoning}
            return

        # 聚合完成，构造带 tool_calls 的助手消息入上下文
        ordered = [tool_acc[i] for i in sorted(tool_acc)]
        tc_list = []
        for n, slot in enumerate(ordered):
            tc_list.append({
                "id": slot["id"] or f"call_{n}",
                "type": "function",
                "function": {"name": slot["name"], "arguments": slot["arguments"] or "{}"},
            })
        msgs.append({"role": "assistant", "content": acc_content or None,
                     "tool_calls": tc_list})

        for slot, tc in zip(ordered, tc_list):
            name = slot["name"]
            try:
                args = json.loads(slot["arguments"] or "{}")
            except json.JSONDecodeError:
                args = {}
            yield {"type": "tool_call", "name": name, "arguments": args}
            result = await tool_registry.execute(name, args)
            output = result.output if result.success else (result.error or "执行失败")
            yield {"type": "tool_result", "name": name,
                   "output": output[:4000], "success": result.success}
            msgs.append({"role": "tool", "tool_call_id": tc["id"],
                         "content": (output or result.error)[:8000]})

    yield {"type": "error", "text": f"工具调用轮次超过上限 ({MAX_TOOL_ROUNDS})"}
    yield {"type": "done", "content": "", "reasoning": ""}
