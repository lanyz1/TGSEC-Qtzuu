"""LLM 客户端纯函数测试"""
from services.llm_client import _build_message, _build_payload, _get_url, _split_model


def test_split_model_with_provider():
    assert _split_model("deepseek/deepseek-chat") == ("deepseek", "deepseek-chat")


def test_split_model_default_openai():
    assert _split_model("gpt-4o") == ("openai", "gpt-4o")


def test_get_url_default():
    assert _get_url("openai") == "https://api.openai.com/v1/chat/completions"
    assert _get_url("unknown-provider") == ""


def test_get_url_custom_appends_suffix():
    assert _get_url("x", "https://a.com/v1") == "https://a.com/v1/chat/completions"


def test_get_url_custom_keeps_full_endpoint():
    assert _get_url("x", "https://a.com/v1/chat/completions") == "https://a.com/v1/chat/completions"


def test_build_payload_basic():
    p = _build_payload("m1", [{"role": "user", "content": "hi"}], stream=True)
    assert p["model"] == "m1" and p["stream"] is True and "tools" not in p


def test_build_payload_with_tools():
    p = _build_payload("m1", [], tools=[{"type": "function"}])
    assert p["tool_choice"] == "auto"


def test_build_payload_ignores_none_kwargs():
    p = _build_payload("m1", [], temperature=None, max_tokens=100)
    assert "temperature" not in p and p["max_tokens"] == 100


def test_build_message_tool_calls():
    msg = _build_message({"role": "assistant", "content": "",
                          "tool_calls": [{"id": "1", "type": "function",
                                          "function": {"name": "scan", "arguments": "{}"}}]})
    assert msg.tool_calls[0].function.name == "scan"
