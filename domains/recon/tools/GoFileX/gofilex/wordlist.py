"""Wordlist walking with resume offsets and GoFile password-length filters."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .session import WordlistRecord

# Documented when *setting* a folder password: 4–100 characters.
# Trying outside that range wastes rate-limited listing calls.
MIN_PASSWORD_LEN = 4
MAX_PASSWORD_LEN = 100
LINE_ENCODINGS = ("utf-8", "latin-1")


def sha256_hex(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def count_lines(path: str | Path) -> int:
    total = 0
    with Path(path).open("rb") as handle:
        for _ in handle:
            total += 1
    return total


def decode_line(raw: bytes) -> str:
    for encoding in LINE_ENCODINGS:
        try:
            return raw.decode(encoding).rstrip("\r\n")
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace").rstrip("\r\n")


def usable_password(value: str) -> bool:
    if not value:
        return False
    n = len(value)
    return MIN_PASSWORD_LEN <= n <= MAX_PASSWORD_LEN


@dataclass
class Candidate:
    password: str
    digest: str
    wordlist: str
    line: int  # 1-based display
    skipped: bool = False
    skip_reason: str = ""


class WordlistQueue:
    def __init__(self, records: list[WordlistRecord]) -> None:
        self.records = records

    def ensure_totals(self) -> None:
        for record in self.records:
            if record.total_lines is None and Path(record.path).is_file():
                record.total_lines = count_lines(record.path)

    def rewind(self, record: WordlistRecord, candidate: Candidate) -> None:
        """Put the last non-skipped candidate back (429 / network)."""
        if record.exhausted:
            record.exhausted = False
        record.line = max(0, candidate.line - 1)
        # byte offset is unknown after a rewind from line number; next read
        # falls back to skipping record.line lines from the start once.
        record.offset = -1 if record.line else 0

    def next_candidate(self) -> Candidate | None:
        """Advance one physical line. Skipped lines are returned flagged, so
        the engine can log them without spending an API call."""
        for record in self.records:
            if record.exhausted:
                continue
            path = Path(record.path)
            if not path.is_file():
                record.exhausted = True
                continue
            with path.open("rb") as handle:
                if record.offset > 0:
                    handle.seek(record.offset)
                elif record.line > 0:
                    # rewind or a session that only stored the line number
                    for _ in range(record.line):
                        if not handle.readline():
                            record.exhausted = True
                            return None
                    record.offset = handle.tell()
                while True:
                    raw = handle.readline()
                    if not raw:
                        record.exhausted = True
                        break
                    record.line += 1
                    record.offset = handle.tell()
                    password = decode_line(raw)
                    name = path.name
                    if not usable_password(password):
                        record.skipped += 1
                        reason = "empty" if not password else f"len={len(password)} (need 4-100)"
                        return Candidate(
                            password=password,
                            digest="",
                            wordlist=name,
                            line=record.line,
                            skipped=True,
                            skip_reason=reason,
                        )
                    return Candidate(
                        password=password,
                        digest=sha256_hex(password),
                        wordlist=name,
                        line=record.line,
                    )
        return None


# Packaged lists live next to the gofilex package: ../wordlists/
WORDLIST_ROOT = Path(__file__).resolve().parent.parent / "wordlists"

# Custom / high-signal first, then small public tops, then larger breach lists.
BUNDLED_ORDER: list[str] = [
    "custom/tesox2-clues.txt",
    "public/nordpass-2025-top200.txt",
    "public/2025-199_most_used_passwords.txt",
    "public/2024-top-used.txt",
    "public/2023-top-used.txt",
    "public/2020-top-used.txt",
    "public/huntress-2026-top20.txt",
    "public/500-worst-passwords.txt",
    "public/top-passwords-shortlist.txt",
    "public/worst-2017-top100.txt",
    "public/10k-most-common.txt",
    "public/probable-v2_top-12000.txt",
    "public/xato-top-10000.txt",
    "public/rockyou-75.txt",
    "public/100k-most-used-passwords-NCSC.txt",
    "public/xato-top-100000.txt",
]


def bundled_wordlists() -> list[Path]:
    """Every shipped .txt list, custom first, then remaining public files."""
    found: list[Path] = []
    seen: set[Path] = set()
    for rel in BUNDLED_ORDER:
        path = (WORDLIST_ROOT / rel).resolve()
        if path.is_file() and path not in seen:
            seen.add(path)
            found.append(path)
    for folder in (WORDLIST_ROOT / "custom", WORDLIST_ROOT / "public"):
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.txt")):
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(resolved)
    return found
