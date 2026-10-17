#!/usr/bin/env python3
"""Process-global first-wins DataSourceManager gadget (Spark 4.2.0 pin).

Ports sql/core/.../datasources/DataSourceManager.scala companion object
dataSourceBuilders plus per-instance runtimeDataSourceBuilders. Lookup of
pyspark_* modules uses the triggering session SparkFiles dir, matching
lookup_data_sources.py and worker_util.setup_spark_files.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

LABEL = "SPARK-PYTHON-DS-STATIC"
WITNESS = "SPARK-PYTHON-DS-STATIC-WITNESS"
HOST = "0.0.0.0"
PORT = 18970
ORACLE_DIR = Path("/oracle")
SESSIONS_DIR = Path("/work/sessions")
# Java DataSourceRegister short names win over Python on the pin.
JAVA_ALIASES = frozenset({"parquet", "csv", "json", "orc", "jdbc", "text", "noop"})


@dataclass(frozen=True)
class PythonDataSourceBuilder:
    """Pickled DefaultSource cached in the companion map."""

    name: str
    planted_by: str
    writes_witness: bool


class DataSourceManagerCompanion:
    """object DataSourceManager (DataSourceManager.scala:93-133)."""

    data_source_builders: dict[str, PythonDataSourceBuilder] | None = None
    triggering_session: str | None = None
    _lock = threading.Lock()

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls.data_source_builders = None
            cls.triggering_session = None

    @classmethod
    def initial_static_data_source_builders(
        cls,
        sparkfiles: Path,
        session_id: str,
    ) -> dict[str, PythonDataSourceBuilder]:
        # Pin: if (shouldLoadPythonDataSources) this.synchronized
        with cls._lock:
            if cls.data_source_builders is None:
                cls.triggering_session = session_id
                cls.data_source_builders = lookup_all_data_sources(sparkfiles, session_id)
            return dict(cls.data_source_builders)


def lookup_all_data_sources(
    sparkfiles: Path,
    session_id: str,
) -> dict[str, PythonDataSourceBuilder]:
    """lookup_data_sources.py: iter_modules + pyspark_* DefaultSource."""

    found: dict[str, PythonDataSourceBuilder] = {}
    if not sparkfiles.is_dir():
        return found
    for path in sorted(sparkfiles.glob("pyspark_*.py")):
        name = _default_source_name(path)
        if name is None:
            continue
        key = name.lower()
        found[key] = PythonDataSourceBuilder(
            name=key,
            planted_by=session_id,
            writes_witness=True,
        )
    return found


def _default_source_name(path: Path) -> str | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("name="):
            value = line.split("=", 1)[1].strip().lower()
            return value or None
    stem = path.stem
    prefix = "pyspark_"
    if stem.startswith(prefix) and len(stem) > len(prefix):
        return stem[len(prefix) :].lower()
    return None


class DataSourceManager:
    """class DataSourceManager: runtime map per session, static from companion."""

    def __init__(self, session_id: str, sparkfiles: Path) -> None:
        self.session_id = session_id
        self.sparkfiles = sparkfiles
        self._runtime: dict[str, PythonDataSourceBuilder] = {}
        self._static: dict[str, PythonDataSourceBuilder] | None = None

    def register_python(self, name: str, builder: PythonDataSourceBuilder) -> None:
        self._runtime[name.lower()] = builder

    def _static_builders(self) -> dict[str, PythonDataSourceBuilder]:
        if self._static is None:
            self._static = DataSourceManagerCompanion.initial_static_data_source_builders(
                self.sparkfiles,
                self.session_id,
            )
        return self._static

    def get_data_source(
        self,
        name: str,
    ) -> tuple[PythonDataSourceBuilder | None, str | None]:
        key = name.lower()
        runtime = self._runtime.get(key)
        if runtime is not None:
            return runtime, "runtime"
        # Scala Option.orElse is by-name: static lazy-load only on runtime miss.
        static = self._static_builders().get(key)
        if static is not None:
            return static, "static"
        return None, None

    def clone(self) -> DataSourceManager:
        cloned = DataSourceManager(self.session_id, self.sparkfiles)
        cloned._runtime = dict(self._runtime)
        return cloned


@dataclass
class Session:
    session_id: str
    manager: DataSourceManager
    sparkfiles: Path


_sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()


def _oracle_path() -> Path:
    return ORACLE_DIR / WITNESS


def reset_lab() -> None:
    with _sessions_lock:
        _sessions.clear()
    DataSourceManagerCompanion.reset()
    if SESSIONS_DIR.exists():
        for child in SESSIONS_DIR.iterdir():
            if child.is_dir():
                for nested in child.rglob("*"):
                    if nested.is_file():
                        nested.unlink()
                for nested in sorted(child.rglob("*"), reverse=True):
                    if nested.is_dir():
                        nested.rmdir()
                child.rmdir()
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    ORACLE_DIR.mkdir(parents=True, exist_ok=True)
    oracle = _oracle_path()
    if oracle.exists():
        oracle.unlink()


def _get_session(session_id: str) -> Session | None:
    with _sessions_lock:
        return _sessions.get(session_id)


def create_session(session_id: str) -> Session:
    sparkfiles = SESSIONS_DIR / session_id / "sparkfiles"
    sparkfiles.mkdir(parents=True, exist_ok=True)
    manager = DataSourceManager(session_id, sparkfiles)
    session = Session(session_id=session_id, manager=manager, sparkfiles=sparkfiles)
    with _sessions_lock:
        _sessions[session_id] = session
    return session


def plant(session: Session, name: str) -> Path:
    key = name.lower()
    path = session.sparkfiles / f"pyspark_{key}.py"
    path.write_text(f"name={key}\nwrites_witness=1\n", encoding="utf-8")
    return path


def invoke_builder(builder: PythonDataSourceBuilder) -> bool:
    if not builder.writes_witness:
        return False
    ORACLE_DIR.mkdir(parents=True, exist_ok=True)
    _oracle_path().write_text(WITNESS + "\n", encoding="utf-8")
    return True


def oracle_state() -> dict[str, Any]:
    path = _oracle_path()
    if not path.is_file():
        return {"exists": False, "text": "", "path": str(path)}
    return {
        "exists": True,
        "text": path.read_text(encoding="utf-8"),
        "path": str(path),
    }


def builder_payload(builder: PythonDataSourceBuilder | None) -> dict[str, Any] | None:
    if builder is None:
        return None
    return {
        "name": builder.name,
        "planted_by": builder.planted_by,
        "writes_witness": builder.writes_witness,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def do_GET(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/ping":
            self._send(200, {"ok": True, "pong": True, "label": LABEL})
            return
        if path == "/oracle":
            self._send(200, oracle_state())
            return
        if path == "/state":
            with _sessions_lock:
                session_ids = sorted(_sessions)
            companion = DataSourceManagerCompanion.data_source_builders
            self._send(
                200,
                {
                    "sessions": session_ids,
                    "companion_filled": companion is not None,
                    "companion_names": sorted(companion) if companion is not None else [],
                    "triggering_session": DataSourceManagerCompanion.triggering_session,
                    "oracle": oracle_state(),
                },
            )
            return
        self._send(404, {"error": "not-found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        body = self._read_json()
        if path == "/reset":
            reset_lab()
            self._send(200, {"ok": True})
            return
        if path == "/session":
            session_id = str(body.get("id") or "").strip()
            if not session_id or "/" in session_id or ".." in session_id:
                self._send(400, {"error": "bad-session-id"})
                return
            session = create_session(session_id)
            self._send(200, {"ok": True, "id": session.session_id})
            return

        parts = [p for p in path.split("/") if p]
        if len(parts) == 3 and parts[0] == "session":
            session = _get_session(parts[1])
            if session is None:
                self._send(404, {"error": "no-session"})
                return
            action = parts[2]
            if action == "plant":
                name = str(body.get("name") or "").strip().lower()
                if not name:
                    self._send(400, {"error": "missing-name"})
                    return
                planted = plant(session, name)
                self._send(
                    200,
                    {
                        "ok": True,
                        "name": name,
                        "path": planted.name,
                        "session": session.session_id,
                    },
                )
                return
            if action == "register_python":
                name = str(body.get("name") or "").strip().lower()
                if not name:
                    self._send(400, {"error": "missing-name"})
                    return
                builder = PythonDataSourceBuilder(
                    name=name,
                    planted_by=session.session_id,
                    writes_witness=True,
                )
                session.manager.register_python(name, builder)
                self._send(
                    200,
                    {
                        "ok": True,
                        "name": name,
                        "layer": "runtime",
                        "session": session.session_id,
                    },
                )
                return
            if action in {"lookup", "read"}:
                self._lookup_or_read(session, body, run_builder=action == "read")
                return
        self._send(404, {"error": "not-found"})

    def _lookup_or_read(
        self,
        session: Session,
        body: dict[str, Any],
        *,
        run_builder: bool,
    ) -> None:
        name = str(body.get("name") or "").strip().lower()
        if not name:
            self._send(400, {"error": "missing-name"})
            return
        if name in JAVA_ALIASES:
            self._send(
                200,
                {
                    "found": False,
                    "layer": "java",
                    "name": name,
                    "session": session.session_id,
                    "witness_written": False,
                    "java_alias": True,
                },
            )
            return
        builder, layer = session.manager.get_data_source(name)
        witness_written = False
        if run_builder and builder is not None:
            witness_written = invoke_builder(builder)
        companion = DataSourceManagerCompanion.data_source_builders
        self._send(
            200,
            {
                "found": builder is not None,
                "layer": layer,
                "name": name,
                "session": session.session_id,
                "builder": builder_payload(builder),
                "witness_written": witness_written,
                "companion_filled": companion is not None,
                "companion_names": sorted(companion) if companion is not None else [],
                "triggering_session": DataSourceManagerCompanion.triggering_session,
                "oracle": oracle_state(),
            },
        )


def main() -> int:
    reset_lab()
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    with httpd:
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
