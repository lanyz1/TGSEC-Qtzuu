"""Reusable on-disk sessions (target, assembled hash, bypass state)."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


GATEX_HOME = Path.home() / ".gatex"
SESSION_DIR = GATEX_HOME / "sessions"
ACTIVE_PATH = GATEX_HOME / "active.json"

DEFAULT_TARGET = "files/7350FH.zip"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def remember_last_session(name: str) -> None:
    GATEX_HOME.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"session": name, "updated_at": now_iso()})
    tmp = ACTIVE_PATH.with_suffix(".tmp")
    tmp.write_text(payload + "\n", encoding="utf-8")
    tmp.replace(ACTIVE_PATH)
    try:
        ACTIVE_PATH.chmod(0o600)
    except OSError:
        pass


def last_session_name(default: str = "default") -> str:
    try:
        data = json.loads(ACTIVE_PATH.read_text(encoding="utf-8"))
        name = str(data.get("session") or "").strip()
        if name:
            return name
    except (OSError, json.JSONDecodeError, TypeError):
        pass
    return default


def resolve_target(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        cwd_hit = (Path.cwd() / path).resolve()
        if cwd_hit.exists():
            return cwd_hit
        proj_hit = (PROJECT_ROOT / path).resolve()
        if proj_hit.exists():
            return proj_hit
        return cwd_hit
    return path.resolve()


@dataclass
class TargetRecord:
    target_path: str
    hash_phc: str | None = None
    engine_state: str = "idle"
    cage_timeout: float = 45.0
    cage_argv: list[str] = field(default_factory=list)
    bypassed: bool = False
    bypass_password: str | None = None
    notes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetRecord:
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**fields)


@dataclass
class Session:
    name: str = "default"
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    target_path: str = ""
    hash_phc: str | None = None
    engine_state: str = "idle"
    cage_timeout: float = 45.0
    cage_argv: list[str] = field(default_factory=list)
    bypassed: bool = False
    bypass_password: str | None = None
    notes: list[str] = field(default_factory=list)
    targets: dict[str, TargetRecord] = field(default_factory=dict)
    last_target_id: str = ""
    kdf_salt_b64: str = ""
    kdf_info_b64: str = ""
    core_aad: str = ""

    def __post_init__(self) -> None:
        if not self.target_path:
            self.target_path = str(resolve_target(DEFAULT_TARGET))

    @property
    def path(self) -> Path:
        return SESSION_DIR / f"{self.name}.json"

    def target_key(self) -> str:
        return str(Path(self.target_path).resolve()) if self.target_path else ""

    def active(self) -> TargetRecord:
        self._ensure_active_target()
        return self.targets[self.last_target_id]

    def _ensure_active_target(self) -> None:
        tid = self.last_target_id or self.target_key() or self.target_path
        if tid not in self.targets:
            self.targets[tid] = TargetRecord(
                target_path=self.target_path,
                hash_phc=self.hash_phc,
                engine_state=self.engine_state,
                cage_timeout=self.cage_timeout,
                cage_argv=list(self.cage_argv),
                bypassed=self.bypassed,
                bypass_password=self.bypass_password,
            )
        self.last_target_id = tid
        self._pull_active()

    def _pull_active(self) -> None:
        job = self.targets[self.last_target_id]
        self.target_path = job.target_path
        self.hash_phc = job.hash_phc
        self.engine_state = job.engine_state
        self.cage_timeout = job.cage_timeout
        self.cage_argv = job.cage_argv
        self.bypassed = job.bypassed
        self.bypass_password = job.bypass_password

    def _push_active(self) -> None:
        if not self.last_target_id:
            return
        job = self.targets.get(self.last_target_id)
        if job is None:
            return
        job.target_path = self.target_path
        job.hash_phc = self.hash_phc
        job.engine_state = self.engine_state
        job.cage_timeout = self.cage_timeout
        job.cage_argv = self.cage_argv
        job.bypassed = self.bypassed
        job.bypass_password = self.bypass_password

    def to_dict(self) -> dict[str, Any]:
        self._push_active()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        raw_targets = data.get("targets") or {}
        targets: dict[str, TargetRecord] = {}
        if isinstance(raw_targets, dict):
            for key, value in raw_targets.items():
                if isinstance(value, dict):
                    targets[str(key)] = TargetRecord.from_dict(value)
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        fields["targets"] = targets
        session = cls(**fields)
        if not session.targets:
            tid = session.target_key() or session.target_path
            session.targets[tid] = TargetRecord(
                target_path=session.target_path,
                hash_phc=session.hash_phc,
                engine_state=session.engine_state,
                cage_timeout=session.cage_timeout,
                cage_argv=list(session.cage_argv),
                bypassed=session.bypassed,
                bypass_password=session.bypass_password,
            )
            session.last_target_id = tid
        session._ensure_active_target()
        return session

    def save(self) -> Path:
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self._push_active()
        self.updated_at = now_iso()
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=False)
        fd, tmp = tempfile.mkstemp(prefix=f".{self.name}.", suffix=".json", dir=SESSION_DIR)
        tmp_path = Path(tmp)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
            tmp_path.replace(self.path)
        except Exception:
            try:
                tmp_path.unlink()
            except OSError:
                pass
            raise
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        remember_last_session(self.name)
        return self.path

    @classmethod
    def load(cls, name: str) -> Session:
        path = SESSION_DIR / f"{name}.json"
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        session = cls.from_dict(data)
        session.name = name
        remember_last_session(session.name)
        return session

    @classmethod
    def load_or_create(cls, name: str) -> Session:
        path = SESSION_DIR / f"{name}.json"
        if path.exists():
            return cls.load(name)
        session = cls(name=name)
        session._ensure_active_target()
        session.save()
        return session

    @classmethod
    def list_names(cls) -> list[str]:
        if not SESSION_DIR.exists():
            return []
        return sorted(p.stem for p in SESSION_DIR.glob("*.json") if not p.name.startswith("."))

    def set_target(self, value: str) -> TargetRecord:
        path = resolve_target(value)
        self._push_active()
        tid = str(path)
        if tid not in self.targets:
            self.targets[tid] = TargetRecord(
                target_path=tid,
                cage_timeout=self.cage_timeout,
                cage_argv=list(self.cage_argv),
            )
        self.last_target_id = tid
        self._pull_active()
        return self.active()
