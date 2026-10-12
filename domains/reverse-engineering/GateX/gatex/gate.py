"""Argon2id verify + the build-time XOR unmask used by 7350FH.

The gated Nuitka binary (slim_launcher.py) stores the PHC hash as three
XOR-scrambled fragments. Reversing that is data recovery, not executing
the ELF: plaintext = base64(ct) XOR cycle(base64(key)).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from itertools import cycle
from typing import Literal

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

PHC_RE = re.compile(
    r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$"
)

# argon2-cffi README doctest hash — present in the binary, NOT the gate.
DECOY_PHC = (
    "$argon2id$v=19$m=65536,t=3,p=4$"
    "MIIRqgvgQbgj220jfp0MPA$"
    "YfwJSVjtjSU0zzV/P3S9nnQ/USre2wvJMjfCIjrTQbg"
)

DENIED_MARKERS = ("[!] access denied",)
NO_PASS_MARKERS = ("[!] no passphrase provided",)
INTEGRITY_MARKERS = ("[!] core integrity check failed",)
PROMPT_MARKERS = ("Fortinet Hunter passphrase:",)

GateKind = Literal["denied", "nopass", "integrity", "error", "hit", "unknown"]


class GateError(Exception):
    pass


def b64decode(value: str) -> bytes:
    pad = (-len(value)) % 4
    return base64.b64decode(value + ("=" * pad))


def xunmask(ct: str, key: str) -> str:
    """Reverse the build-time XOR scramble: base64(ct) XOR key -> plaintext."""
    data = b64decode(ct)
    key_bytes = b64decode(key)
    if not data or not key_bytes:
        raise GateError("empty scramble inputs")
    return bytes(a ^ b for a, b in zip(data, cycle(key_bytes))).decode("utf-8")


def assemble_hash(
    a_ct: str,
    a_key: str,
    b_ct: str,
    b_key: str,
    c_ct: str,
    c_key: str,
) -> str:
    assembled = xunmask(a_ct, a_key) + xunmask(b_ct, b_key) + xunmask(c_ct, c_key)
    if not PHC_RE.match(assembled):
        raise GateError(f"assembled hash is not a PHC argon2id string: {assembled!r}")
    if assembled == DECOY_PHC:
        raise GateError("assembled the argon2-cffi doctest decoy, not the gate hash")
    return assembled


@dataclass(frozen=True)
class GateSecrets:
    hash_phc: str
    kdf_salt_b64: str = ""
    kdf_info_b64: str = ""
    core_aad: str = ""
    source: str = ""

    @property
    def params(self) -> str:
        # $argon2id$v=19$m=65536,t=3,p=4$...
        parts = self.hash_phc.split("$")
        if len(parts) >= 4:
            return f"{parts[1]} {parts[2]} {parts[3]}"
        return "?"


_HASHER = PasswordHasher()


def verify_password(hash_phc: str, password: str) -> bool:
    """True on match. False on mismatch. Raises GateError if the hash is junk."""
    try:
        _HASHER.verify(hash_phc, password)
        return True
    except VerifyMismatchError:
        return False
    except InvalidHash as exc:
        raise GateError(f"invalid argon2 hash: {exc}") from exc
    except VerificationError as exc:
        raise GateError(f"argon2 verify failed: {exc}") from exc


_LOADER_ERRORS = (
    "not found (required by",
    "error while loading shared libraries",
    "cannot execute",
    "exec format error",
    "no such file or directory",
    "qemu:",
    "version `glibc",
    "segmentation fault",
    "aborted",
)


def classify_output(stdout: str, stderr: str, returncode: int) -> GateKind:
    """Map cage stdout/stderr to a gate result.

    Loader failures must never count as a password hit. The only success
    signal is a clean run that did not print a gate-deny line.
    """
    blob = f"{stdout}\n{stderr}"
    low = blob.lower()
    if any(marker.lower() in low for marker in DENIED_MARKERS):
        return "denied"
    if any(marker.lower() in low for marker in NO_PASS_MARKERS):
        return "nopass"
    if any(marker.lower() in low for marker in INTEGRITY_MARKERS):
        return "integrity"
    if any(bit in low for bit in _LOADER_ERRORS):
        return "error"
    if returncode == 0:
        return "hit"
    return "unknown"
