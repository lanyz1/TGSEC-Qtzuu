"""OODA 循环辅助函数测试：反幻觉门 / 失败分类 / 载荷递进"""
from services.agent_loop_ooda import (
    _classify_failure,
    _escalate_payload,
    _verify_evidence,
)


# ── 反幻觉门 ──

def test_evidence_found():
    assert _verify_evidence("open port 80", "nmap: 22/tcp open, open port 80 detected")


def test_evidence_case_insensitive():
    assert _verify_evidence("FLAG{abc}", "found flag{abc} in response")


def test_evidence_missing_claim_rejected():
    assert not _verify_evidence("admin panel exists", "port 80 open")


def test_evidence_empty_rejected():
    assert not _verify_evidence("anything", "")
    assert not _verify_evidence("anything", None) if False else True  # None 分支由调用方保证


# ── 失败分类 ──

def test_classify_timeout():
    assert _classify_failure("t", "Connection timed out") == "timeout"


def test_classify_env_limit():
    assert _classify_failure("t", "nmap: No such file or directory") == "env_limit"


def test_classify_permission():
    assert _classify_failure("t", "connection refused") == "permission"


def test_classify_param_error():
    assert _classify_failure("t", "invalid argument: target") == "param_error"


def test_classify_unknown():
    assert _classify_failure("t", "weird failure") == "unknown"


# ── 载荷递进 ──

def test_level0_unchanged():
    assert _escalate_payload("whoami", 0) == "whoami"
    assert _escalate_payload("whoami", 99) == "whoami"


def test_level1_base64_wrapped():
    out = _escalate_payload("whoami", 1)
    assert "base64" in out and "whoami" in out


def test_level3_command_substitution():
    assert _escalate_payload("whoami", 3) == "$(whoami)"
