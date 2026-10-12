from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from gatex.gate import (
    DECOY_PHC,
    PHC_RE,
    assemble_hash,
    b64decode,
    classify_output,
    verify_password,
    xunmask,
)
from gatex.patch import BYPASS_PASSWORD, GCM_AAD, patch_inner_bytes, xmask
from gatex.session import Session
from gatex.unpack import (
    extract_gate,
    extract_inner_elf,
    extract_scramble_blobs,
    find_payload,
    load_outer_elf,
    parse_secrets,
)

if TYPE_CHECKING:
    import pytest

HASH_A_CT = "Y+VgUrts8jyM+kxPAQ9mRhPq/+RVDKpIGatMzLj+kjM="
HASH_A_KEY = "R4QSNdQCwFXo3jpyMDZCKy7cytFmOoY8JJhgvIXKthg="
HASH_B_CT = "z2owaiQnu5a/x8XEdM7O88raMUMjRdcpadif/HyOKdI="
HASH_B_KEY = "pAwCPEEfi6X8opWWAIGFgq7tZhZyYe4YDY2uyBq8R4s="
HASH_C_CT = "wCqYgfkR4AQWWtODeKRG/T6UJ5j+QxaOa5QtB7vbsx7a"
HASH_C_KEY = "g3zX15BBgWBaNfz7KNACqXzwTO+Qc1PILL9DauK/wnk="

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ZIP_PATH = _REPO_ROOT / "files" / "7350FH.zip"
_STATIC_INNER = Path("/tmp/ctf-7350fh-static/7350FH.bin")


def _inner_elf() -> bytes | None:
    if _STATIC_INNER.is_file():
        return _STATIC_INNER.read_bytes()
    if _ZIP_PATH.is_file():
        return extract_inner_elf(find_payload(load_outer_elf(_ZIP_PATH)))
    return None


def test_xunmask_hash_a_prefix() -> None:
    text = xunmask(HASH_A_CT, HASH_A_KEY)
    assert text.startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_assemble_hash_is_phc_not_decoy() -> None:
    assembled = assemble_hash(HASH_A_CT, HASH_A_KEY, HASH_B_CT, HASH_B_KEY, HASH_C_CT, HASH_C_KEY)
    assert PHC_RE.match(assembled)
    assert assembled != DECOY_PHC
    assert assembled.startswith("$argon2id$")
    assert verify_password(assembled, "this-is-not-the-password") is False


def test_session_multi_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from gatex import session as session_mod

    monkeypatch.setattr(session_mod, "SESSION_DIR", tmp_path)
    monkeypatch.setattr(session_mod, "GATEX_HOME", tmp_path)
    monkeypatch.setattr(session_mod, "ACTIVE_PATH", tmp_path / "active.json")

    s = Session(name="hunt")
    s.hash_phc = "$argon2id$placeholder"
    s.save()

    other = tmp_path / "other.bin"
    other.write_bytes(b"\x7fELF")
    s.set_target(str(other))
    assert Path(s.target_path).name == "other.bin"
    assert s.hash_phc is None
    s.bypassed = True
    s.bypass_password = "gatex"
    s.save()

    reloaded = Session.load("hunt")
    assert Path(reloaded.target_path).name == "other.bin"
    assert reloaded.bypassed is True
    assert reloaded.bypass_password == "gatex"


def test_classify_output() -> None:
    assert classify_output("", "[!] access denied\n", 1) == "denied"
    assert classify_output("", "[!] no passphrase provided\n", 1) == "nopass"
    assert classify_output("usage: 7350FH list\n", "", 0) == "hit"
    assert (
        classify_output("", "/tmp/7350FH: version `GLIBC_2.38' not found (required by /tmp/7350FH)", 1)
        == "error"
    )
    assert classify_output("boom", "something else", 1) == "unknown"


def test_xmask_roundtrip() -> None:
    ct = HASH_A_CT
    key = HASH_A_KEY
    plain = xunmask(ct, key)
    rebuilt = xmask(plain, key, len(ct))
    assert xunmask(rebuilt, key) == plain


def test_patch_inner_rekeys_hash_and_banner() -> None:
    inner = _inner_elf()
    if inner is None:
        return

    patched, phc, n = patch_inner_bytes(inner, BYPASS_PASSWORD)
    assert n >= 4
    assert verify_password(phc, BYPASS_PASSWORD)
    secrets = parse_secrets(patched)
    assert secrets.hash_phc == phc
    blobs = extract_scramble_blobs(patched)
    nonce = b64decode(xunmask(blobs[10], blobs[11]))
    aes_ct = b64decode(xunmask(blobs[12], blobs[13]))
    salt = b64decode(secrets.kdf_salt_b64)
    info = b64decode(secrets.kdf_info_b64)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(
        BYPASS_PASSWORD.encode("utf-8")
    )
    banner = AESGCM(key).decrypt(nonce, aes_ct, GCM_AAD)
    assert banner.startswith(b"GATEX BYPASS")


def test_extract_gate_from_zip() -> None:
    if not _ZIP_PATH.is_file():
        return
    secrets = extract_gate(_ZIP_PATH)
    assert secrets.hash_phc.startswith("$argon2id$")
    assert secrets.hash_phc != DECOY_PHC
    assert secrets.core_aad == "cfh-slim-hardened-v2"
    assert PHC_RE.match(secrets.hash_phc)
