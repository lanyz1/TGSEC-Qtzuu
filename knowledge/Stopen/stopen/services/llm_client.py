"""Lightweight LLM client - pure httpx"""
import json
import httpx
from typing import AsyncGenerator
from types import SimpleNamespace

_sync_client = httpx.Client(timeout=120)
_async_client = httpx.AsyncClient(timeout=120)

_DEFAULT_URLS = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    "deepseek": "https://api.deepseek.com/v1/chat/completions",
    "kimi": "https://api.moonshot.cn/v1/chat/completions",
}


def _ns(**kw):
    return SimpleNamespace(**kw)


def _split_model(model: str):
    if "/" in model:
        provider, name = model.split("/", 1)
        return provider, name
    return "openai", model


def _get_url(provider: str, custom_url: str = None) -> str:
    if custom_url:
        if "/chat/completions" not in custom_url:
            return custom_url.rstrip("/") + "/chat/completions"
        return custom_url
    return _DEFAULT_URLS.get(provider, "")


def _build_payload(model_name: str, messages: list, stream: bool = False,
                   tools: list = None, tool_choice: str = None, **kwargs) -> dict:
    payload = {"model": model_name, "messages": messages, "stream": stream}
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = tool_choice or "auto"
    for k in ("temperature", "top_p", "max_tokens", "presence_penalty", "frequency_penalty"):
        if k in kwargs and kwargs[k] is not None:
            payload[k] = kwargs[k]
    return payload


def _build_message(msg_data: dict):
    tool_calls = []
    for tc in msg_data.get("tool_calls") or []:
        tool_calls.append(_ns(
            id=tc.get("id", ""),
            type=tc.get("type", "function"),
            function=_ns(
                name=tc.get("function", {}).get("name", ""),
                arguments=tc.get("function", {}).get("arguments", "{}"),
            ),
        ))
    return _ns(
        content=msg_data.get("content"),
        role=msg_data.get("role", "assistant"),
        tool_calls=tool_calls if tool_calls else None,
    )


def _build_response(data: dict):
    choices = []
    for c in data.get("choices", []):
        msg_data = c.get("message", {})
        choices.append(_ns(
            index=c.get("index", 0),
            message=_build_message(msg_data),
            delta=_ns(content=None, role=None),
        ))
    return _ns(id=data.get("id", ""), choices=choices)


async def _stream_openai(resp: httpx.Response) -> AsyncGenerator:
    """OpenAI 兼容流式解析。

    delta 透传 content / role / reasoning_content（思考模型）/ tool_calls 增量分片，
    供上层做思考过程展示与工具调用聚合。
    """
    async for line in resp.aiter_lines():
        if not line.startswith("data: "):
            continue
        data = line[6:]
        if data == "[DONE]":
            break
        try:
            chunk = json.loads(data)
            choices = chunk.get("choices") or []
            if not choices:
                continue
            raw_delta = choices[0].get("delta") or {}
            tc_frags = []
            for tc in raw_delta.get("tool_calls") or []:
                func = tc.get("function") or {}
                tc_frags.append(_ns(
                    index=tc.get("index", 0),
                    id=tc.get("id"),
                    name=func.get("name"),
                    arguments=func.get("arguments"),
                ))
            yield _ns(choices=[_ns(
                index=0,
                delta=_ns(
                    content=raw_delta.get("content"),
                    role=raw_delta.get("role"),
                    reasoning_content=raw_delta.get("reasoning_content") or raw_delta.get("reasoning"),
                    tool_calls=tc_frags or None,
                ),
                message=_ns(content=None, role=None, tool_calls=None),
            )])
        except (json.JSONDecodeError, IndexError, KeyError):
            continue


# Anthropic helpers
def _anthropic_headers(api_key: str):
    return {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }


def _to_anthropic_messages(messages: list):
    result = []
    for m in messages:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role == "system":
            continue
        if isinstance(content, list):
            result.append({"role": role, "content": [
                {"type": "text", "text": p.get("text", "")} if p.get("type") == "text"
                else {"type": "text", "text": "[image]"}
                for p in content
            ]})
        else:
            result.append({"role": role, "content": content})
    return result


def _to_anthropic_tools(tools: list):
    result = []
    for t in tools or []:
        if t.get("type") == "function":
            func = t.get("function", {})
            result.append({
                "name": func.get("name", ""),
                "description": func.get("description", ""),
                "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
            })
    return result


def _from_anthropic_response(data: dict):
    blocks = data.get("content", [])
    text_parts = []
    tool_calls = []
    for block in blocks:
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append(_ns(
                id=block.get("id", ""),
                type="function",
                function=_ns(
                    name=block.get("name", ""),
                    arguments=json.dumps(block.get("input", {})),
                ),
            ))
    return _ns(choices=[_ns(
        index=0,
        message=_ns(
            content="".join(text_parts) if text_parts else None,
            role="assistant",
            tool_calls=tool_calls if tool_calls else None,
        ),
        delta=_ns(content=None, role=None),
    )])


async def _anthropic_completion(model: str, messages: list, tools: list = None, **kwargs):
    api_key = kwargs.get("api_key", "")
    base = kwargs.get("api_base", "https://api.anthropic.com")
    url = base.rstrip("/") + "/v1/messages"
    system = ""
    anthropic_msgs = []
    for m in messages:
        if m.get("role") == "system":
            system = str(m.get("content", ""))
        else:
            anthropic_msgs.append(m)
    payload = {
        "model": model,
        "messages": _to_anthropic_messages(anthropic_msgs),
        "max_tokens": kwargs.get("max_tokens", 4096),
    }
    if system:
        payload["system"] = system
    if tools:
        payload["tools"] = _to_anthropic_tools(tools)
        payload["tool_choice"] = {"type": "auto"}
    for k in ("temperature", "top_p"):
        if k in kwargs and kwargs[k] is not None:
            payload[k] = kwargs[k]
    resp = await _async_client.post(url, headers=_anthropic_headers(api_key), json=payload)
    resp.raise_for_status()
    return _from_anthropic_response(resp.json())


async def _anthropic_stream(model: str, messages: list, tools: list = None, **kwargs):
    resp = await _anthropic_completion(model, messages, tools, **kwargs)
    msg = resp.choices[0].message
    text = msg.content or ""
    for char in text:
        yield _ns(choices=[_ns(
            index=0,
            delta=_ns(content=char, role="assistant"),
            message=_ns(content=None, role=None, tool_calls=None),
        )])


async def acompletion(model: str, messages: list, stream: bool = False,
                      tools: list = None, tool_choice: str = None, **kwargs):
    provider, model_name = _split_model(model)
    api_key = kwargs.get("api_key", "")
    base_url = kwargs.get("api_base", "")
    if provider == "anthropic" or "anthropic.com" in base_url:
        if stream:
            return _anthropic_stream(model_name, messages, tools, **kwargs)
        return await _anthropic_completion(model_name, messages, tools, **kwargs)
    url = _get_url(provider, base_url)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = _build_payload(model_name, messages, stream=stream, tools=tools,
                             tool_choice=tool_choice, **kwargs)
    if stream:
        resp = await _async_client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        return _stream_openai(resp)
    resp = await _async_client.post(url, headers=headers, json=payload)
    resp.raise_for_status()
    return _build_response(resp.json())


def completion(model: str, messages: list, **kwargs):
    provider, model_name = _split_model(model)
    api_key = kwargs.get("api_key", "")
    base_url = kwargs.get("api_base", "")
    if provider == "anthropic" or "anthropic.com" in base_url:
        import asyncio
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop:
            raise RuntimeError("Anthropic sync completion not supported inside async context.")
        return asyncio.run(_anthropic_completion(model_name, messages, **kwargs))
    url = _get_url(provider, base_url)
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = _build_payload(model_name, messages, **kwargs)
    resp = _sync_client.post(url, headers=headers, json=payload)
    resp.raise_for_status()
    return _build_response(resp.json())
