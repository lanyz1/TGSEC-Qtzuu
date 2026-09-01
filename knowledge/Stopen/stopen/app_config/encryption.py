"""配置加密模块：Fernet 加密"""
import json, os, time
from pathlib import Path
from cryptography.fernet import Fernet


class ConfigEncryption:
    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        key_path_env = os.environ.get("STOPEN_KEY_PATH", "")
        self.key_path = Path(key_path_env) if key_path_env else (self.storage_dir / "keyfile.key")
        self.config_path = self.storage_dir / "config.enc"
        self._fernet = self._load_or_create_key()
        self._cache = None
        self._cache_time = 0.0

    def _load_or_create_key(self) -> Fernet:
        if self.key_path.exists():
            return Fernet(self.key_path.read_bytes())
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        return Fernet(key)

    def save_config(self, config: dict) -> None:
        plaintext = json.dumps(config, ensure_ascii=False).encode("utf-8")
        self.config_path.write_bytes(self._fernet.encrypt(plaintext))
        self._cache = config
        self._cache_time = time.time()

    def load_config(self) -> dict:
        if self._cache is not None and (time.time() - self._cache_time) < 5.0:
            return self._cache
        if not self.config_path.exists():
            return {}
        self._cache = json.loads(self._fernet.decrypt(self.config_path.read_bytes()))
        self._cache_time = time.time()
        return self._cache

    def config_exists(self) -> bool:
        return self.config_path.exists()
