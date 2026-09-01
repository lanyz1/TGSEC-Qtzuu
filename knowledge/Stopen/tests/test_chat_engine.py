"""对话引擎测试：流式事件、reasoning 透传、工具调用循环"""
import json
from types import SimpleNamespace as ns

import pytest

from services import chat_engine
from services.llm_client import _stream_openai


# ── llm_client 流式解析 ──

class FakeResp:
    def __init__(self, lines):
        self._lines = lines

    async def aiter_lines(self):
        for l in self._lines:
            yield l


def _sse(obj):
    return "data: " + json.dumps(obj)


@pytest.mark.asyncio
async def test_stream_openai_parses_reasoning_and_tool_calls():
    lines = [
        _sse({"choices": [{"delta": {"role": "assistant", "reasoning_content": "让我想想"}}]}),
        _sse({"choices": [{"delta": {"content": "端口"}}]}),
        _sse({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "id": "c1", "function": {"name": "port_scan", "arguments": "{\"tar"}}]}}]}),
        _sse({"choices": [{"delta": {"tool_calls": [
            {"index": 0, "function": {"arguments": "get\": \"1.2.3.4\"}"}}]}}]}),
        "data: [DONE]",
    ]
    deltas = [c.choices[0].delta async for c in _stream_openai(FakeResp(lines))]

    assert deltas[0].reasoning_content == "让我想想"
    assert deltas[1].content == "端口"
    assert deltas[2].tool_calls[0].name == "port_scan"
    # 分片参数拼接
    assert deltas[2].tool_calls[0].arguments == '{"tar'
    assert deltas[3].tool_calls[0].arguments == 'get": "1.2.3.4"}'
    assert deltas[3].tool_calls[0].id is None  # 后续分片无 id


@pytest.mark.asyncio
async def test_stream_openai_skips_malformed():
    lines = ["data: not-json", "", _sse({"choices": [{"delta": {"content": "ok"}}]})]
    deltas = [c.choices[0].delta async for c in _stream_openai(FakeResp(lines))]
    assert [d.content for d in deltas if d.content] == ["ok"]


# ── chat_engine 工具循环 ──

def _chunk(content=None, reasoning=None, tool_calls=None):
    return ns(choices=[ns(delta=ns(content=content, role="assistant",
                                   reasoning_content=reasoning, tool_calls=tool_calls))])


def _frag(index=0, id=None, name=None, arguments=None):
    return ns(index=index, id=id, name=name, arguments=arguments)


@pytest.fixture
def fake_tools(monkeypatch):
    calls = []

    async def fake_execute(name, args):
        calls.append((name, args))
        from services.tool_base import ToolResult
        return ToolResult.ok("22/tcp open  ssh")

    monkeypatch.setattr(chat_engine.tool_registry, "execute", fake_execute)
    monkeypatch.setattr(chat_engine.tool_registry, "list_openai_tools", lambda: [])
    return calls


@pytest.mark.asyncio
async def test_chat_stream_plain_answer(fake_tools, monkeypatch):
    async def fake_completion(**kw):
        async def gen():
            yield _chunk(content="你好")
            yield _chunk(content="，世界")
        return gen()
    monkeypatch.setattr(chat_engine, "acompletion", fake_completion)

    events = [ev async for ev in chat_engine.chat_agent_stream(
        [{"role": "user", "content": "hi"}], "openai/gpt-4o", api_key="k")]

    types = [e["type"] for e in events]
    assert types == ["token", "token", "done"]
    assert events[-1]["content"] == "你好，世界"
    assert fake_tools == []


@pytest.mark.asyncio
async def test_chat_stream_tool_loop(fake_tools, monkeypatch):
    rounds = {"n": 0}

    async def fake_completion(**kw):
        async def gen():
            if rounds["n"] == 0:
                rounds["n"] += 1
                yield _chunk(reasoning="需要先扫端口")
                yield _chunk(tool_calls=[_frag(id="c1", name="port_scan", arguments='{"target": "1.2.3.4"}')])
            else:
                yield _chunk(content="发现 22 端口开放")
        return gen()
    monkeypatch.setattr(chat_engine, "acompletion", fake_completion)

    events = [ev async for ev in chat_engine.chat_agent_stream(
        [{"role": "user", "content": "扫一下 1.2.3.4"}], "openai/gpt-4o", api_key="k")]

    types = [e["type"] for e in events]
    assert types == ["reasoning", "tool_call", "tool_result", "token", "done"]
    assert events[2]["output"] == "22/tcp open  ssh"
    assert fake_tools == [("port_scan", {"target": "1.2.3.4"})]
    assert events[-1]["content"] == "发现 22 端口开放"


@pytest.mark.asyncio
async def test_chat_stream_llm_error(fake_tools, monkeypatch):
    async def fake_completion(**kw):
        async def gen():
            raise RuntimeError("api down")
            yield  # pragma: no cover
        return gen()
    monkeypatch.setattr(chat_engine, "acompletion", fake_completion)

    events = [ev async for ev in chat_engine.chat_agent_stream(
        [{"role": "user", "content": "hi"}], "openai/gpt-4o", api_key="k")]

    assert events[0]["type"] == "error"
    assert events[-1]["type"] == "done"
