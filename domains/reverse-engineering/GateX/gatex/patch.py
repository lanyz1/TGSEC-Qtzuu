"""Re-key the XOR-scrambled Argon2 hash and AES-GCM banner.

The inner ELF never stores the passphrase. It stores scramble blobs that
_assemble_hash / _decrypt_core consume. Replacing those blobs with ones
derived from a password we know is a data patch, not an instruction NOP:
the original gate still runs, but it now accepts BYPASS_PASSWORD.

Nothing here executes the ELF.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from itertools import cycle
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .gate import GateError, b64decode, xunmask
from .unpack import extract_scramble_blobs

BYPASS_PASSWORD = "gatex"
# Nuitka blob tag 'c' (bytes) + payload. The AES-GCM AAD is the bytes value,
# not the file needle "c"+"fh-slim-hardened-v2".
GCM_AAD = b"fh-slim-hardened-v2"
# AES-GCM ciphertext in this build is 95 bytes = 79-byte banner + 16-byte tag.
BANNER = (b"GATEX BYPASS -- core banner replaced. plugins compiled in.\n" + b" " * 16)[:79]


@dataclass(frozen=True)
class PatchResult:
    password: str
    hash_phc: str
    replacements: int
    inner_path: Path


def _b64(data: bytes, length: int) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    if len(encoded) == length:
        return encoded
    stripped = encoded.rstrip("=")
    if len(stripped) == length:
        return stripped
    padded = encoded + ("=" * (length - len(encoded)))
    if len(padded) == length:
        return padded
    raise GateError(f"b64 length {len(encoded)} cannot match original {length}")


def xmask(plaintext: str, key_b64: str, ct_len: int) -> str:
    key = b64decode(key_b64)
    raw = plaintext.encode("utf-8")
    xored = bytes(a ^ b for a, b in zip(raw, cycle(key)))
    return _b64(xored, ct_len)


def _new_hash(password: str) -> str:
    hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    phc = hasher.hash(password)
    if len(phc) != 97:
        raise GateError(f"new PHC length {len(phc)} != 97")
    return phc


def _derive_key(password: str, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(password.encode("utf-8"))


def patch_inner_bytes(inner: bytes, password: str = BYPASS_PASSWORD) -> tuple[bytes, str, int]:
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
        nonce_ct,
        nonce_key,
        core_ct,
        core_key,
    ) = blobs

    phc = _new_hash(password)
    a_pt, b_pt, c_pt = phc[:32], phc[32:64], phc[64:]
    if (len(a_pt), len(b_pt), len(c_pt)) != (
        len(xunmask(a_ct, a_key)),
        len(xunmask(b_ct, b_key)),
        len(xunmask(c_ct, c_key)),
    ):
        raise GateError("new hash does not split like the original fragments")

    new_a = xmask(a_pt, a_key, len(a_ct))
    new_b = xmask(b_pt, b_key, len(b_ct))
    new_c = xmask(c_pt, c_key, len(c_ct))

    salt = b64decode(xunmask(salt_ct, salt_key))
    info = b64decode(xunmask(info_ct, info_key))
    nonce = b64decode(xunmask(nonce_ct, nonce_key))
    old_ct_b64 = xunmask(core_ct, core_key)
    aes_len = len(b64decode(old_ct_b64))
    banner = BANNER[: max(1, aes_len - 16)]
    if len(banner) + 16 != aes_len:
        banner = banner.ljust(aes_len - 16, b".")[: aes_len - 16]

    key = _derive_key(password, salt, info)
    aes_ct = AESGCM(key).encrypt(nonce, banner, GCM_AAD)
    if len(aes_ct) != aes_len:
        raise GateError(f"AES-GCM size {len(aes_ct)} != {aes_len}")
    new_core_plain = base64.b64encode(aes_ct).decode("ascii")
    # original xunmask output is 128 chars; std b64 of 95 bytes is 128 with padding
    new_core = xmask(new_core_plain, core_key, len(core_ct))

    replacements = 0
    patched = inner
    for old, new in ((a_ct, new_a), (b_ct, new_b), (c_ct, new_c), (core_ct, new_core)):
        if old == new:
            continue
        count = patched.count(old.encode("ascii"))
        if count == 0:
            raise GateError(f"blob not found in inner ELF: {old[:24]}…")
        patched = patched.replace(old.encode("ascii"), new.encode("ascii"))
        replacements += count

    if patched == inner:
        raise GateError("patch produced no replacements")
    return patched, phc, replacements


def patch_inner_file(inner_path: Path, password: str = BYPASS_PASSWORD) -> PatchResult:
    inner_path = Path(inner_path)
    raw = inner_path.read_bytes()
    patched, phc, n = patch_inner_bytes(raw, password)
    inner_path.write_bytes(patched)
    inner_path.chmod(0o700)
    return PatchResult(password=password, hash_phc=phc, replacements=n, inner_path=inner_path)


def cache_dir_for(target: Path) -> Path:
    digest = hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:16]
    return Path.home() / ".gatex" / "cache" / digest
