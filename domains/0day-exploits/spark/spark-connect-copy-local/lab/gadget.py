#!/usr/bin/env python3
"""Spark 4.2.0 Connect copyFromLocalToFs session-conf gate gadget.

Pin: tag v4.2.0 commit 32f7299601108917fb01920a54e084595b7b3bf8.
SQLConf.ARTIFACT_COPY_FROM_LOCAL_TO_FS_ALLOW_DEST_LOCAL is still buildConf
(session-settable) at sql/catalyst/.../SQLConf.scala ~7047-7059. ArtifactManager
uploadArtifactToFs (sql/core/.../artifact/ArtifactManager.scala ~491-524) blocks
LocalFileSystem dest unless that session conf is true. 4.3.0 moved the key to
StaticSQLConf (SPARK-58531). This process does not compile Spark; it copies the
session-conf gate and the LocalFileSystem dest copy.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

FORWARD_TO_FS_PREFIX = "forward_to_fs"
ARTIFACT_KEY = "spark.sql.artifact.copyFromLocalToFs.allowDestLocal"
STATIC_KEY = "spark.connect.copyFromLocalToFs.allowDestLocal"
ARTIFACT_ROOT = Path("/opt/spark/work/artifacts")
LISTEN_HOST = os.environ.get("GADGET_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("GADGET_PORT", "18920"))
PIN_COMMIT = "32f7299601108917fb01920a54e084595b7b3bf8"
PIN_TAG = "v4.2.0"


class SparkUnsupportedOperationError(Exception):
    """SparkUnsupportedOperationException("_LEGACY_ERROR_TEMP_3161")."""

    def __init__(self, condition: str) -> None:
        super().__init__(condition)
        self.condition = condition


class CannotModifyStaticConfigError(Exception):
    """QueryCompilationErrors.cannotModifyValueOfStaticConfigError."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Cannot modify the value of the static Spark config: {key}.")
        self.key = key
        self.error_class = "CANNOT_MODIFY_STATIC_CONFIG"


class LocalFileSystem:
    """Hadoop org.apache.hadoop.fs.LocalFileSystem dest."""

    def copy_from_local_file(
        self,
        del_src: bool,
        overwrite: bool,
        src: Path,
        dest: Path,
    ) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and not overwrite:
            raise FileExistsError(str(dest))
        shutil.copyfile(src, dest)
        if del_src:
            src.unlink()


class RemoteFileSystem:
    """Non-local dest. Documented copyFromLocalToFs path; not this leftover."""

    def copy_from_local_file(
        self,
        del_src: bool,
        overwrite: bool,
        src: Path,
        dest: Path,
    ) -> None:
        raise SparkUnsupportedOperationError("REMOTE_FS_NOT_IN_LAB")


def is_local_file_system(dest: Path) -> bool:
    text = str(dest)
    if text.startswith(("hdfs://", "s3a://", "abfs://", "gs://")):
        return False
    return True


def get_file_system(dest: Path) -> LocalFileSystem | RemoteFileSystem:
    if is_local_file_system(dest):
        return LocalFileSystem()
    return RemoteFileSystem()


def normalize_path(path: Path) -> Path:
    # ArtifactManager.normalizePath: system separators then Path.normalize().
    normalized = str(path).replace("/", os.sep).replace("\\", os.sep)
    return Path(os.path.normpath(normalized))


def concatenate_paths(base_path: Path, other_path: Path) -> Path:
    # ArtifactUtils.concatenatePaths: string join, not Path.resolve, then normalize.
    if other_path.is_absolute():
        raise ValueError("INVALID_ARTIFACT_PATH")
    concatenated = Path(str(base_path) + "/" + str(other_path))
    normalized = Path(os.path.normpath(str(concatenated)))
    base_prefix = str(base_path) + "/"
    if normalized == base_path or not str(normalized).startswith(base_prefix):
        raise ValueError("INVALID_ARTIFACT_PATH")
    return normalized


class Session:
    """One Connect session: RuntimeConfig.set plus ArtifactManager.uploadArtifactToFs."""

    def __init__(self) -> None:
        self.session_uuid = str(uuid.uuid4())
        self.session_conf: dict[str, str] = {}
        self.static_conf: dict[str, str] = {STATIC_KEY: "false"}
        self.static_keys = {STATIC_KEY}
        self.sql_keys = {ARTIFACT_KEY}
        self.artifact_path = ARTIFACT_ROOT / self.session_uuid
        self.staging_dir = self.artifact_path / "staging"
        self.artifact_path.mkdir(parents=True, exist_ok=True)
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()

    def is_static_config_key(self, key: str) -> bool:
        return key in self.static_keys

    def is_modifiable(self, key: str) -> bool:
        # SQLConf.isModifiable: registered and not static. Internal buildConf is settable.
        return key in self.sql_keys and not self.is_static_config_key(key)

    def require_non_static_conf(self, key: str) -> None:
        # RuntimeConfig.requireNonStaticConf (classic RuntimeConfig.scala ~106-123).
        if self.is_static_config_key(key):
            raise CannotModifyStaticConfigError(key)

    def set(self, key: str, value: str) -> None:
        self.require_non_static_conf(key)
        self.session_conf[key] = value

    def conf_get(self, key: str) -> str:
        if key in self.session_conf:
            return self.session_conf[key]
        if key in self.static_conf:
            return self.static_conf[key]
        raise KeyError(key)

    def get_conf_optional_bool(self, key: str) -> bool | None:
        # SQLConf.getConf(OptionalConfigEntry) - createOptional, unset is None.
        if key not in self.session_conf:
            return None
        return self.session_conf[key].lower() == "true"

    def upload_artifact_to_fs(self, remote_relative_path: Path, staging_path: Path) -> Path:
        # ArtifactManager.uploadArtifactToFs ~491-524.
        normalized = normalize_path(remote_relative_path)
        prefix = FORWARD_TO_FS_PREFIX + os.sep
        if not str(normalized).startswith(prefix):
            raise AssertionError("forward_to_fs prefix required")
        remainder = Path(*normalized.parts[1:])
        dest = Path(os.sep) / remainder
        fs = get_file_system(dest)
        if isinstance(fs, LocalFileSystem):
            allow_dest_local = self.get_conf_optional_bool(ARTIFACT_KEY)
            if allow_dest_local is None:
                allow_dest_local = "true" in self.conf_get(STATIC_KEY)
            if not allow_dest_local:
                # Default: do not upload to a local dest; otherwise a user overwrites
                # an arbitrary file on the Spark driver.
                raise SparkUnsupportedOperationError("_LEGACY_ERROR_TEMP_3161")
        fs.copy_from_local_file(False, True, staging_path, dest)
        return dest

    def copy_from_local_to_fs(self, dest_path: str, content: str) -> Path:
        # PySpark: artifact name is FORWARD_TO_FS_PREFIX + absolute dest (no os.path.join).
        dest = Path(dest_path)
        if not dest.is_absolute():
            raise ValueError("destination FS path must be an absolute path")
        name = FORWARD_TO_FS_PREFIX + dest_path
        remote = Path(name)
        staged = concatenate_paths(self.staging_dir, remote)
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_text(content, encoding="utf-8")
        try:
            return self.upload_artifact_to_fs(remote, staged)
        finally:
            if staged.exists():
                staged.unlink()


SESSION = Session()


def json_bytes(payload: dict[str, Any], status: int = 200) -> tuple[int, bytes]:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    return status, body


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"gadget {self.address_string()} {fmt % args}", flush=True)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("json object required")
        return data

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        status, body = json_bytes(payload, status)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, {"ok": True, "pin": PIN_TAG, "commit": PIN_COMMIT})
            return
        if parsed.path == "/whoami":
            self._send(
                200,
                {
                    "artifact_root": str(SESSION.artifact_path),
                    "gid": os.getgid(),
                    "pin": PIN_TAG,
                    "commit": PIN_COMMIT,
                    "session_uuid": SESSION.session_uuid,
                    "uid": os.getuid(),
                },
            )
            return
        if parsed.path == "/stat":
            query = parse_qs(parsed.query)
            path_s = (query.get("path") or [""])[0]
            target = Path(path_s)
            if not target.exists() or not target.is_file():
                self._send(200, {"exists": False, "path": path_s})
                return
            st = target.stat()
            self._send(
                200,
                {
                    "content": target.read_text(encoding="utf-8"),
                    "exists": True,
                    "gid": st.st_gid,
                    "path": str(target),
                    "size": st.st_size,
                    "uid": st.st_uid,
                },
            )
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            data = self._read_json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        with SESSION.lock:
            if parsed.path == "/config/set":
                key = str(data.get("key", ""))
                value = str(data.get("value", ""))
                try:
                    SESSION.set(key, value)
                except CannotModifyStaticConfigError as exc:
                    self._send(
                        400,
                        {
                            "error": str(exc),
                            "error_class": exc.error_class,
                            "key": exc.key,
                        },
                    )
                    return
                self._send(
                    200,
                    {
                        "key": key,
                        "modifiable": SESSION.is_modifiable(key),
                        "ok": True,
                        "value": value,
                    },
                )
                return
            if parsed.path == "/copyFromLocalToFs":
                dest_path = str(data.get("dest_path", ""))
                content = str(data.get("content", ""))
                try:
                    dest = SESSION.copy_from_local_to_fs(dest_path, content)
                except SparkUnsupportedOperationError as exc:
                    self._send(
                        400,
                        {
                            "condition": exc.condition,
                            "error": (
                                "Uploading artifact file to local file system "
                                "destination path is not supported."
                            ),
                            "error_class": "SparkUnsupportedOperationException",
                        },
                    )
                    return
                except ValueError as exc:
                    self._send(400, {"error": str(exc)})
                    return
                st = dest.stat()
                self._send(
                    200,
                    {
                        "dest": str(dest),
                        "ok": True,
                        "uid": st.st_uid,
                    },
                )
                return
        self._send(404, {"error": "not found"})


def main() -> int:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(
        f"gadget listen={LISTEN_HOST}:{LISTEN_PORT} uid={os.getuid()} "
        f"artifact_root={SESSION.artifact_path} pin={PIN_TAG}",
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
