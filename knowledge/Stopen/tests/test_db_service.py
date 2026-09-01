"""Database 测试：CRUD、WebShell 密码加密存储、多线程并发"""
import sqlite3
import threading

import pytest

from services.db_service import Database


@pytest.fixture
def db(tmp_path):
    return Database(db_path=tmp_path / "unit.db")


def test_conversation_roundtrip(db):
    conv = db.create_conversation(title="测试", model="glm-4")
    fetched = db.get_conversation(conv["id"])
    assert fetched["title"] == "测试"
    db.add_message(conv["id"], "user", "你好")
    msgs = db.get_messages(conv["id"])
    assert len(msgs) == 1 and msgs[0]["content"] == "你好"


def test_webshell_password_encrypted_at_rest(db):
    """密码落库必须是密文，读取时透明解密"""
    db.create_webshell(name="shell1", url="http://t/shell.php", password="hunter2")
    raw = sqlite3.connect(str(db.db_path)).execute(
        "SELECT password FROM webshells").fetchone()[0]
    assert raw != "hunter2"
    assert raw.startswith("gAAAAA")  # Fernet token 前缀
    rows = db.list_webshells()
    assert rows[0]["password"] == "hunter2"


def test_webshell_legacy_plaintext_still_readable(db):
    """旧库里的明文密码应兼容读取"""
    db.create_webshell(name="legacy", url="http://t/x.php", password="plain-pass")
    # 手工改回明文，模拟历史数据
    conn = sqlite3.connect(str(db.db_path))
    conn.execute("UPDATE webshells SET password='plain-pass'")
    conn.commit()
    rows = db.list_webshells()
    assert rows[0]["password"] == "plain-pass"


def test_webshell_update_password_reencrypts(db):
    db.create_webshell(name="s", url="http://t", password="old")
    wid = db.list_webshells()[0]["id"]
    db.update_webshell(wid, password="new-pass")
    assert db.list_webshells()[0]["password"] == "new-pass"


def test_listener_create_and_update(db):
    l = db.create_listener(name="l1", port=4444)
    assert l["secret"]
    db.update_listener(l["id"], port=5555)
    assert db.list_listeners()[0]["port"] == 5555


def test_vulnerability_stats(db):
    db.create_vulnerability(title="SQLi", severity="high")
    db.create_vulnerability(title="XSS", severity="low")
    db.create_vulnerability(title="RCE", severity="high")
    stats = db.vulnerability_stats()
    assert stats["total"] == 3
    assert stats["by_severity"]["high"] == 2


def test_yaml_tool_crud(db):
    db.create_yaml_tool(name="nmap_scan", command='["nmap"]')
    rows = db.list_yaml_tools()
    assert rows[0]["name"] == "nmap_scan"
    db.update_yaml_tool(rows[0]["id"], description="端口扫描")
    assert db.get_yaml_tool(rows[0]["id"])["description"] == "端口扫描"
    db.delete_yaml_tool(rows[0]["id"])
    assert db.list_yaml_tools() == []


def test_multithread_concurrent_writes(db):
    """多线程并发写不应出现游标竞争 / 数据丢失"""
    errors = []

    def worker(i):
        try:
            for j in range(20):
                db.create_conversation(title=f"t{i}-{j}")
                db.list_conversations()
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, f"并发写失败: {errors}"
    assert db.vulnerability_stats  # sanity: db still usable
    assert len(db.list_conversations()) == 160
