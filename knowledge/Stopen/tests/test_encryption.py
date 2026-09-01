"""配置加密模块测试"""
from app_config.encryption import ConfigEncryption


def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("STOPEN_KEY_PATH", str(tmp_path / "k.key"))
    enc = ConfigEncryption(tmp_path)
    assert not enc.config_exists()
    enc.save_config({"openai": {"api_key": "sk-secret"}})
    assert enc.config_exists()
    # 新实例（模拟重启后重新加载）
    enc2 = ConfigEncryption(tmp_path)
    assert enc2.load_config() == {"openai": {"api_key": "sk-secret"}}


def test_empty_config(tmp_path, monkeypatch):
    monkeypatch.setenv("STOPEN_KEY_PATH", str(tmp_path / "k.key"))
    enc = ConfigEncryption(tmp_path)
    assert enc.load_config() == {}


def test_ciphertext_not_plaintext(tmp_path, monkeypatch):
    monkeypatch.setenv("STOPEN_KEY_PATH", str(tmp_path / "k.key"))
    enc = ConfigEncryption(tmp_path)
    enc.save_config({"k": "secret-value"})
    assert b"secret-value" not in enc.config_path.read_bytes()
