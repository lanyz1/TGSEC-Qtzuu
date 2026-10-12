"""X-Website-Token generation, matching gofile.io/js/wt.obf.js.

The official web client signs listing requests as:

    sha256(f"{userAgent}::{language}::{accountToken}::{window}::{salt}")

where ``window = floor(unix_time / 14400)`` (4-hour buckets). The salt is
embedded in the obfuscated generator and rotated server-side; we keep a
known-good default and refresh it from wt.obf.js when possible.
"""

from __future__ import annotations

import hashlib
import re
import time
from codecs import decode as codecs_decode

DEFAULT_SALT = "12af056dacea0b"
WT_SCRIPT_URL = "https://gofile.io/js/wt.obf.js"
WINDOW_SECONDS = 14400
_SALT_HEX_RE = re.compile(r"[0-9a-f]{10,16}")
_OBF_STRING_RE = re.compile(r"'(?:\\x[0-9a-fA-F]{2})+'")


def time_window(now: float | None = None, offset: int = 0) -> int:
    ts = int(now if now is not None else time.time())
    return ts // WINDOW_SECONDS + offset


def generate_wt(
    account_token: str,
    user_agent: str,
    language: str = "en-US",
    salt: str = DEFAULT_SALT,
    now: float | None = None,
    window_offset: int = 0,
) -> str:
    window = time_window(now, window_offset)
    raw = f"{user_agent}::{language}::{account_token}::{window}::{salt}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def extract_salts_from_obf(js: str) -> list[str]:
    """Pull hex-looking secrets out of the obfuscated generator script."""
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value not in seen and _SALT_HEX_RE.fullmatch(value):
            seen.add(value)
            found.append(value)

    for chunk in _OBF_STRING_RE.findall(js):
        try:
            decoded = codecs_decode(chunk[1:-1], "unicode_escape")
        except (UnicodeDecodeError, ValueError, LookupError):
            continue
        add(decoded)

    for match in _SALT_HEX_RE.findall(js):
        add(match)

    # Prefer the current default first if it is still present.
    found.sort(key=lambda s: (s != DEFAULT_SALT, len(s), s))
    return found
