"""Reusable on-disk sessions (account token, per-target jobs, wordlist offsets).

A session file is the crash-safe checkpoint. Switching GoFile IDs keeps
progress for every previous id. The last-used session name is stored in
~/.gofilex/active.json so a bare `python -m gofilex` resumes it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .ratelimit import DEFAULT_INTERVALS, FLOOR_INTERVALS

APP_DIR = Path.home() / ".gofilex"
LEGACY_APP_DIRS = (Path.home() / ".onefilex",)


def _migrate_legacy_app_dir() -> None:
    if APP_DIR.exists():
        return
    for legacy in LEGACY_APP_DIRS:
        if not legacy.exists():
            continue
        try:
            legacy.rename(APP_DIR)
            return
        except OSError:
            try:
                shutil.copytree(legacy, APP_DIR)
            except OSError:
                continue
            return


_migrate_legacy_app_dir()
SESSION_DIR = APP_DIR / "sessions"
ACTIVE_PATH = APP_DIR / "active.json"
SHARE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?gofile\.io/(?:d|w)/([A-Za-z0-9]+)",
    re.IGNORECASE,
)
CONTENT_ID_RE = re.compile(r"[A-Za-z0-9-]{6,64}")


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_content_id(value: str) -> str:
    value = (value or "").strip()
    match = SHARE_RE.search(value)
    if match:
        return match.group(1)
    if CONTENT_ID_RE.fullmatch(value):
        return value
    raise ValueError(f"not a GoFile share URL or content id: {value!r}")


def share_url(content_id: str) -> str:
    return f"https://gofile.io/d/{content_id}"


def remember_last_session(name: str) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
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


@dataclass
class AccountRecord:
    id: str = ""
    token: str = ""
    email: str = ""
    tier: str = ""
    root_folder: str = ""
    stats_current: dict[str, Any] = field(default_factory=dict)
    ip_traffic: dict[str, Any] | int | None = None
    synced_at: str = ""


@dataclass
class WordlistRecord:
    path: str
    line: int = 0  # lines already consumed; next read starts here
    offset: int = 0  # byte offset of the next line
    total_lines: int | None = None
    tried: int = 0
    skipped: int = 0
    exhausted: bool = False


def _wordlist_from_dict(item: dict[str, Any]) -> WordlistRecord:
    allowed = WordlistRecord.__dataclass_fields__
    return WordlistRecord(**{k: v for k, v in item.items() if k in allowed})


def _clone_wordlist_paths(records: list[WordlistRecord]) -> list[WordlistRecord]:
    return [WordlistRecord(path=item.path) for item in records]


@dataclass
class TargetRecord:
    content_id: str
    target_url: str = ""
    wordlists: list[WordlistRecord] = field(default_factory=list)
    found_password: str | None = None
    found_at: str | None = None
    listing: dict[str, Any] | None = None
    engine_state: str = "idle"
    last_password: str | None = None
    last_wordlist: str | None = None
    last_line: int = 0

    def __post_init__(self) -> None:
        if not self.target_url and self.content_id:
            self.target_url = share_url(self.content_id)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TargetRecord:
        wordlists = [_wordlist_from_dict(item) for item in data.get("wordlists") or []]
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        fields["wordlists"] = wordlists
        return cls(**fields)


@dataclass
class Session:
    name: str = "default"
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    target_url: str = ""
    content_id: str = ""
    account: AccountRecord = field(default_factory=AccountRecord)
    wordlists: list[WordlistRecord] = field(default_factory=list)
    found_password: str | None = None
    found_at: str | None = None
    listing: dict[str, Any] | None = None
    download_dir: str = ""
    contents_interval: float = 3.0
    engine_state: str = "idle"
    notes: list[str] = field(default_factory=list)
    targets: dict[str, TargetRecord] = field(default_factory=dict)
    last_target_id: str = ""

    @property
    def path(self) -> Path:
        return SESSION_DIR / f"{self.name}.json"

    def active(self) -> TargetRecord:
        self._ensure_active_target()
        if self.last_target_id and self.last_target_id in self.targets:
            return self.targets[self.last_target_id]
        return TargetRecord(content_id=self.content_id, target_url=self.target_url)

    def _ensure_active_target(self) -> None:
        tid = self.last_target_id or self.content_id
        if not tid:
            return
        if tid not in self.targets:
            self.targets[tid] = TargetRecord(
                content_id=tid,
                target_url=share_url(tid),
                wordlists=self.wordlists,
                found_password=self.found_password,
                found_at=self.found_at,
                listing=self.listing,
                engine_state=self.engine_state,
            )
        self.last_target_id = tid
        self._pull_active()

    def _pull_active(self) -> None:
        job = self.targets[self.last_target_id]
        self.content_id = job.content_id
        self.target_url = job.target_url or share_url(job.content_id)
        self.wordlists = job.wordlists
        self.found_password = job.found_password
        self.found_at = job.found_at
        self.listing = job.listing
        self.engine_state = job.engine_state

    def _push_active(self) -> None:
        if not self.last_target_id:
            return
        job = self.targets.get(self.last_target_id)
        if job is None:
            return
        job.content_id = self.content_id
        job.target_url = self.target_url
        job.wordlists = self.wordlists
        job.found_password = self.found_password
        job.found_at = self.found_at
        job.listing = self.listing
        job.engine_state = self.engine_state

    def to_dict(self) -> dict[str, Any]:
        self._push_active()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        account = data.get("account") or {}
        wordlists = [_wordlist_from_dict(item) for item in data.get("wordlists") or []]
        raw_targets = data.get("targets") or {}
        targets: dict[str, TargetRecord] = {}
        if isinstance(raw_targets, dict):
            for key, value in raw_targets.items():
                if isinstance(value, dict):
                    job = TargetRecord.from_dict(value)
                    targets[str(key)] = job
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        fields["account"] = AccountRecord(
            **{k: v for k, v in account.items() if k in AccountRecord.__dataclass_fields__}
        )
        fields["wordlists"] = wordlists
        fields["targets"] = targets
        session = cls(**fields)
        if not session.targets:
            tid = session.content_id
            if tid:
                session.targets[tid] = TargetRecord(
                    content_id=tid,
                    target_url=session.target_url or share_url(tid),
                    wordlists=session.wordlists,
                    found_password=session.found_password,
                    found_at=session.found_at,
                    listing=session.listing,
                    engine_state=session.engine_state,
                )
                session.last_target_id = tid
        session._ensure_active_target()
        return session

    def save(self) -> Path:
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self._push_active()
        self.updated_at = now_iso()
        payload = json.dumps(self.to_dict(), indent=2, sort_keys=False)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.name}.",
            suffix=".json",
            dir=SESSION_DIR,
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
            tmp_path.replace(self.path)
        except OSError:
            try:
                tmp_path.unlink(missing_ok=True)
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
        before = session.contents_interval
        session.clamp_rate()
        migrated = not (data.get("targets") or {})
        if session.contents_interval != before or migrated:
            session.save()
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

    def clamp_rate(self) -> None:
        if self.contents_interval < FLOOR_INTERVALS["contents"]:
            self.contents_interval = DEFAULT_INTERVALS["contents"]
        # Previous cautious default was 15–45s; speed those sessions back up.
        elif self.contents_interval >= 14.0:
            self.contents_interval = DEFAULT_INTERVALS["contents"]

    def set_target(self, value: str) -> TargetRecord:
        """Switch to a GoFile id. Existing jobs keep their wordlist offsets."""
        content_id = parse_content_id(value)
        self._push_active()
        created = content_id not in self.targets
        if created:
            self.targets[content_id] = TargetRecord(
                content_id=content_id,
                target_url=share_url(content_id),
                wordlists=_clone_wordlist_paths(self.wordlists),
            )
        self.last_target_id = content_id
        self._pull_active()
        return self.active()

    def add_wordlist(self, path: str | Path) -> WordlistRecord:
        self._ensure_active_target()
        resolved = str(Path(path).expanduser().resolve())
        for existing in self.wordlists:
            if existing.path == resolved:
                return existing
        record = WordlistRecord(path=resolved)
        self.wordlists.append(record)
        return record

    def current_wordlist(self) -> WordlistRecord | None:
        for record in self.wordlists:
            if not record.exhausted:
                return record
        return None

    def total_progress(self) -> tuple[int, int | None]:
        tried = sum(item.tried for item in self.wordlists)
        totals = [item.total_lines for item in self.wordlists]
        if any(t is None for t in totals):
            return tried, None
        return tried, sum(int(t or 0) for t in totals)

    def mark_attempt(self, wordlist: str, line: int, password: str) -> None:
        job = self.active()
        job.last_wordlist = wordlist
        job.last_line = line
        job.last_password = password
        self._push_active()
