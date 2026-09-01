"""报告与 PoC 生成测试"""
from services import report_service


def test_markdown_report(tmp_path, monkeypatch):
    monkeypatch.setattr(report_service, "STORAGE_DIR", tmp_path)
    findings = [
        {"type": "port", "value": "80/tcp", "source": "nmap", "evidence": "open"},
        {"type": "port", "value": "443/tcp", "source": "nmap", "evidence": "open"},
    ]
    result = report_service.generate_report(task_id="t1", target="10.0.0.1", findings=findings)
    assert result["findings_count"] == 2
    assert "10.0.0.1" in result["content"]
    assert (tmp_path / "reports" / "report_t1.md").exists()


def test_flag_report_section(tmp_path, monkeypatch):
    monkeypatch.setattr(report_service, "STORAGE_DIR", tmp_path)
    result = report_service.generate_report(
        task_id="t2", target="x", task_type="ctf",
        findings=[{"type": "flag", "value": "flag{test}", "evidence": "cmd output"}])
    assert "flag{test}" in result["content"]
    assert "Flag 结果" in result["content"]


def test_html_report(tmp_path, monkeypatch):
    monkeypatch.setattr(report_service, "STORAGE_DIR", tmp_path)
    result = report_service.generate_html_report(task_id="t3", target="10.0.0.2",
                                                 findings=[{"type": "port", "value": "22", "source": "nmap"}])
    assert "<table>" in result["content"] and "22" in result["content"]


def test_poc_script_contains_target_and_title(tmp_path, monkeypatch):
    monkeypatch.setattr(report_service, "STORAGE_DIR", tmp_path)
    script = report_service.generate_poc_script({
        "title": "SQL Injection", "target": "http://10.0.0.1/",
        "vuln_type": "sqli", "description": "union based", "evidence": "error based"})
    assert 'TARGET = "http://10.0.0.1/"' in script
    assert "SQL Injection" in script
    result = report_service.generate_poc_file({
        "title": "SQL Injection", "target": "http://10.0.0.1/"})
    assert result["path"].endswith(".py")
