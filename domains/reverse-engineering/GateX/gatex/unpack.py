"""Static unpack of the 7350FH Nuitka onefile. Never executes the ELF.

The outer binary is a Nuitka onefile bootstrap: .rodata starts with magic
``KAY`` + a zstd stream of packed files. The first file is ``7350FH.bin``,
the compiled slim_launcher. Gate constants sit in that inner image as
XOR-scrambled base64 blobs immediately before ``cfh-slim-hardened-v2``.
"""

from __future__ import annotations

import struct
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

import zstandard

from .gate import GateError, GateSecrets, assemble_hash, xunmask

KAY = b"KAY"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
AAD_MARK = b"cfh-slim-hardened-v2"
B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


class _Readable(Protocol):
    def read(self, n: int) -> bytes: ...


def _looks_b64(value: str) -> bool:
    if len(value) < 16 or len(value) > 256:
        return False
    if any(ch not in B64_CHARS for ch in value):
        return False
    body = value.rstrip("=")
    return bool(body) and "=" not in body


def load_outer_elf(path: Path) -> bytes:
    """Read the ELF from a zip member or a raw file. Zip-slip rejected."""
    path = path.expanduser().resolve()
    if not path.is_file():
        raise GateError(f"not a file: {path}")
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            elf_name: str | None = None
            for info in zf.infolist():
                name = info.filename
                dest = (Path("/safe") / name).resolve()
                if not str(dest).startswith("/safe"):
                    raise GateError(f"zip-slip rejected: {name}")
                base = Path(name).name
                if info.is_dir():
                    continue
                if base.lower().endswith(".md") or base.lower().endswith(".txt"):
                    continue
                if elf_name is None or info.file_size > zf.getinfo(elf_name).file_size:
                    elf_name = name
            if not elf_name:
                raise GateError("zip contains no candidate ELF")
            data = zf.read(elf_name)
    else:
        data = path.read_bytes()
    if not data.startswith(b"\x7fELF"):
        raise GateError(f"{path} is not an ELF (and zip had no ELF member)")
    return data


def find_payload(elf: bytes) -> bytes:
    idx = elf.find(KAY + ZSTD_MAGIC)
    if idx < 0:
        idx = elf.find(KAY)
        if idx < 0 or elf[idx + 3 : idx + 7] != ZSTD_MAGIC:
            raise GateError("Nuitka onefile payload (KAY + zstd) not found")
    return elf[idx + 3 :]


def _read_packed_file(stream: _Readable) -> tuple[str, int, bytes] | None:
    """One Nuitka packed-file record: name\\0, flags u8, size u64le, data."""
    name_buf = bytearray()
    while True:
        ch = stream.read(1)
        if not ch:
            return None
        if ch == b"\x00":
            break
        name_buf += ch
        if len(name_buf) > 4096:
            raise GateError("packed filename too long")
    if not name_buf:
        return None
    name = bytes(name_buf).decode("utf-8", "replace")
    flags = stream.read(1)
    size_b = stream.read(8)
    if len(flags) != 1 or len(size_b) != 8:
        raise GateError(f"truncated packed header for {name!r}")
    size = struct.unpack("<Q", size_b)[0]
    if size > 500_000_000:
        raise GateError(f"packed file {name!r} implausibly large ({size})")
    data = stream.read(size)
    if len(data) != size:
        raise GateError(f"truncated packed file {name!r}: {len(data)}/{size}")
    return name, flags[0], data


class _Reader:
    """Minimal read() wrapper so packed-file parsing does not need BufferedReader."""

    def __init__(self, raw: _Readable) -> None:
        self._raw = raw

    def read(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self._raw.read(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return bytes(buf)


def extract_inner_elf(payload_zstd: bytes) -> bytes:
    dctx = zstandard.ZstdDecompressor()
    reader = _Reader(dctx.stream_reader(payload_zstd))
    while True:
        rec = _read_packed_file(reader)
        if rec is None:
            raise GateError("payload ended before 7350FH.bin")
        name, _flags, data = rec
        if name.endswith(".bin") or name in {"7350FH.bin", "7350FH"}:
            if data[:4] != b"\x7fELF":
                raise GateError(f"{name} is not an ELF")
            return data


def extract_scramble_blobs(inner: bytes) -> list[str]:
    """Fourteen XOR-scrambled base64 blobs immediately before the AAD marker."""
    idx = inner.find(AAD_MARK)
    if idx < 0:
        raise GateError("core AAD marker cfh-slim-hardened-v2 not found")
    region = inner[:idx]
    parts = region.split(b"\x00")
    blobs: list[str] = []
    for raw in reversed(parts):
        if not raw:
            continue
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        value = text[1:] if text[:1] == "u" and _looks_b64(text[1:]) else text
        if _looks_b64(value):
            blobs.append(value)
            if len(blobs) >= 14:
                break
    blobs.reverse()
    if len(blobs) < 14:
        raise GateError(f"expected 14 scramble blobs before AAD, found {len(blobs)}")
    return blobs[:14]


def parse_secrets(inner: bytes, source: str = "") -> GateSecrets:
    blobs = extract_scramble_blobs(inner)
    (
        a_ct,
        a_key,
        b_ct,
        b_key,
        c_ct,
        c_key,
        salt_ct,
        salt_key,
        info_ct,
        info_key,
        _nonce_ct,
        _nonce_key,
        _core_ct,
        _core_key,
    ) = blobs[:14]
    hash_phc = assemble_hash(a_ct, a_key, b_ct, b_key, c_ct, c_key)
    return GateSecrets(
        hash_phc=hash_phc,
        kdf_salt_b64=xunmask(salt_ct, salt_key),
        kdf_info_b64=xunmask(info_ct, info_key),
        core_aad=AAD_MARK.decode("ascii"),
        source=source,
    )


def extract_gate(path: str | Path) -> GateSecrets:
    path = Path(path)
    elf = load_outer_elf(path)
    payload = find_payload(elf)
    inner = extract_inner_elf(payload)
    return parse_secrets(inner, source=str(path))


def iter_packed_files(payload_zstd: bytes) -> Iterator[tuple[str, int, bytes]]:
    dctx = zstandard.ZstdDecompressor()
    reader = _Reader(dctx.stream_reader(payload_zstd))
    while True:
        rec = _read_packed_file(reader)
        if rec is None:
            return
        yield rec


def extract_payload_tree(path: str | Path, dest: Path) -> Path:
    """Write every Nuitka packed file under dest. No ELF execution."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    elf = load_outer_elf(Path(path))
    payload = find_payload(elf)
    written = 0
    for name, flags, data in iter_packed_files(payload):
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts:
            raise GateError(f"refusing packed path {name!r}")
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        mode = 0o700 if flags & 1 else 0o600
        out.chmod(mode)
        written += 1
    if written == 0:
        raise GateError("payload contained no files")
    inner = dest / "7350FH.bin"
    if not inner.is_file():
        raise GateError("payload tree missing 7350FH.bin")
    inner.chmod(0o700)
    return inner
