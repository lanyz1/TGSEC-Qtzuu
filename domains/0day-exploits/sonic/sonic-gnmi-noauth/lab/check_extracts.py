#!/usr/bin/env python3
"""SHA256-check lab extracts against copied sonic-gnmi pin files. Fail the image build on drift."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIN = ROOT / "pin"
LAB = ROOT / "lab"

UNSET_BLOCK = (
    '\tif *telemetryCfg.CaCert == "" && telemetryCfg.UserAuth.Enabled("cert") {\n'
    '\t\ttelemetryCfg.UserAuth.Unset("cert")\n'
    '\t\tlog.V(2).Info("client_auth mode cert requires ca_crt option. Disabling cert mode authentication.")\n'
    "\t}"
)

FAIL_CLOSED = """USER_AUTH=$(extract_field "$GNMI" '.user_auth')
# Fail-closed default: if user_auth is unset (missing GNMI CONFIG_DB entry or
# missing field), force cert mode. Without this, --client_auth is omitted and
# authentication ends up disabled entirely.
if [ -z "$USER_AUTH" ] || [ "$USER_AUTH" == "null" ]; then
    USER_AUTH="cert"
fi"""

USERAUTH_COPY = "\t\t\tcfg.UserAuth = telemetryCfg.UserAuth"

AUTHENTICATE_SIG = (
    "func authenticate(config *Config, ctx context.Context, target string, "
    "writeAccess bool) (context.Context, error) {"
)
UNIX_PEER_SIG = "func isUnixPeer(ctx context.Context) bool {"
AUTH_ANY_SIG = "func (i AuthTypes) Any() bool {"
AUTH_ENABLED_SIG = "func (i AuthTypes) Enabled(mode string) bool {"
AUTH_UNSET_SIG = "func (i AuthTypes) Unset(mode string) error {"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_func(src: str, sig: str) -> str:
    i = src.find(sig)
    if i < 0:
        raise SystemExit(f"missing signature: {sig}")
    brace = src.find("{", i)
    if brace < 0:
        raise SystemExit(f"missing brace after {sig}")
    depth = 0
    for j in range(brace, len(src)):
        ch = src[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise SystemExit(f"unclosed {sig}")


def extract_between_ok(src: str, blob: str) -> str:
    if blob not in src:
        raise SystemExit("FAIL extract-drift blob missing")
    return blob


def require_contains(path: Path, blob: str, name: str) -> None:
    text = path.read_text(encoding="utf-8")
    if blob not in text:
        raise SystemExit(f"FAIL extract-drift {name} not in {path}")
    digest = sha256_bytes(blob.encode("utf-8"))
    print(f"IOC extract-ok name={name} sha256={digest} path={path.name}")


def require_func(pin_src: str, lab_src: str, sig: str, name: str) -> None:
    pin_fn = extract_func(pin_src, sig)
    lab_fn = extract_func(lab_src, sig)
    pin_h = sha256_bytes(pin_fn.encode("utf-8"))
    lab_h = sha256_bytes(lab_fn.encode("utf-8"))
    if pin_h != lab_h:
        raise SystemExit(f"FAIL extract-drift {name} pin={pin_h} lab={lab_h}")
    print(f"IOC extract-ok name={name} sha256={pin_h}")


def require_file(pin_path: Path, lab_path: Path, name: str) -> None:
    pin_b = pin_path.read_bytes()
    lab_b = lab_path.read_bytes()
    pin_h = sha256_bytes(pin_b)
    lab_h = sha256_bytes(lab_b)
    if pin_h != lab_h:
        raise SystemExit(f"FAIL extract-drift {name} pin={pin_h} lab={lab_h}")
    print(f"IOC extract-ok name={name} sha256={pin_h} bytes={len(pin_b)}")


def main() -> int:
    pin_server = (PIN / "gnmi_server" / "server.go").read_text(encoding="utf-8")
    lab_auth = (LAB / "gnmi_server" / "authenticate.go").read_text(encoding="utf-8")
    lab_types = (LAB / "gnmi_server" / "authtypes.go").read_text(encoding="utf-8")
    pin_tel = (PIN / "telemetry" / "telemetry.go").read_text(encoding="utf-8")
    lab_tel = (LAB / "telemetry" / "setupflags.go").read_text(encoding="utf-8")
    pin_sh = (PIN / "gnmi-native.sh").read_text(encoding="utf-8")

    require_func(pin_server, lab_auth, AUTHENTICATE_SIG, "authenticate")
    require_func(pin_server, lab_auth, UNIX_PEER_SIG, "isUnixPeer")
    require_func(pin_server, lab_types, AUTH_ANY_SIG, "AuthTypes.Any")
    require_func(pin_server, lab_types, AUTH_ENABLED_SIG, "AuthTypes.Enabled")
    require_func(pin_server, lab_types, AUTH_UNSET_SIG, "AuthTypes.Unset")

    require_contains(PIN / "telemetry" / "telemetry.go", UNSET_BLOCK, "setupFlags-cert-unset-pin")
    require_contains(LAB / "telemetry" / "setupflags.go", UNSET_BLOCK, "setupFlags-cert-unset-lab")
    if sha256_bytes(UNSET_BLOCK.encode("utf-8")) != sha256_bytes(
        extract_between_ok(pin_tel, UNSET_BLOCK).encode("utf-8")
    ):
        raise SystemExit("FAIL extract-drift setupFlags-cert-unset hash")
    if UNSET_BLOCK not in lab_tel:
        raise SystemExit("FAIL extract-drift setupFlags-cert-unset missing from lab")
    print(
        f"IOC extract-ok name=setupFlags-cert-unset sha256={sha256_bytes(UNSET_BLOCK.encode('utf-8'))}"
    )

    require_contains(PIN / "telemetry" / "telemetry.go", USERAUTH_COPY, "cfg.UserAuth-copy-tls-branch")
    if "cfg.UserAuth = telemetryCfg.UserAuth" not in lab_tel:
        raise SystemExit("FAIL extract-drift UserAuth TLS-branch copy missing from lab")
    print("IOC extract-ok name=cfg.UserAuth-copy-modeled")

    require_contains(PIN / "gnmi-native.sh", FAIL_CLOSED, "gnmi-native-fail-closed")
    if "--client_auth" not in pin_sh or 'USER_AUTH="cert"' not in pin_sh:
        raise SystemExit("FAIL extract-drift gnmi-native.sh client_auth cert default")

    require_file(
        PIN / "gnmi_server" / "constants_native_write.go",
        LAB / "gnmi_server" / "constants_native_write.go",
        "constants_native_write.go",
    )
    require_file(
        PIN / "gnmi_server" / "constants_translib_write.go",
        LAB / "gnmi_server" / "constants_translib_write.go",
        "constants_translib_write.go",
    )

    native = (LAB / "gnmi_server" / "constants_native_write.go").read_text(encoding="utf-8")
    if "ENABLE_NATIVE_WRITE = true" not in native or "gnmi_native_write" not in native:
        raise SystemExit("FAIL extract-drift ENABLE_NATIVE_WRITE not true")
    print("IOC extract-ok name=ENABLE_NATIVE_WRITE")
    print("IOC pin-fingerprint-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
