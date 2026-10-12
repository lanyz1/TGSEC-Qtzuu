"""Probe the Nuitka gate and re-key it. Never walks a wordlist."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .gate import classify_output
from .patch import BYPASS_PASSWORD, cache_dir_for, patch_inner_file
from .sandbox import (
    IMAGE,
    CageError,
    CageResult,
    bypass_container_name,
    build_image,
    container_name,
    destroy as cage_destroy,
    ensure_bypass_cage,
    image_exists,
    start_docker_desktop,
    try_patched,
)
from .session import Session
from .unpack import extract_gate, extract_payload_tree

LogFn = Callable[[str, str], None]


@dataclass
class EngineState:
    cage_ready: bool = False
    found: str | None = None


class Engine:
    def __init__(self, session: Session, log: LogFn) -> None:
        self.session = session
        self.log = log
        self.state = EngineState()
        if session.bypass_password:
            self.state.found = session.bypass_password

    def _emit(self, kind: str, message: str) -> None:
        self.log(kind, message)

    async def probe(self) -> bool:
        """Static unpack + hash assemble. Does not execute the ELF."""
        target = Path(self.session.target_path)
        if not target.is_file():
            self._emit("err", f"target missing: {target}")
            return False
        self._emit("sys", f"probe  static unpack {target.name}  (no exec)")
        try:
            secrets = await asyncio.to_thread(extract_gate, target)
        except Exception as exc:
            self._emit("err", f"unpack failed: {type(exc).__name__}: {exc}")
            return False
        self.session.hash_phc = secrets.hash_phc
        self.session.kdf_salt_b64 = secrets.kdf_salt_b64
        self.session.kdf_info_b64 = secrets.kdf_info_b64
        self.session.core_aad = secrets.core_aad
        self.session.save()
        shown = secrets.hash_phc
        if len(shown) > 72:
            shown = shown[:32] + "…" + shown[-24:]
        self._emit("ok", f"gate hash  {shown}")
        self._emit("sys", f"argon2  {secrets.params}  aad={secrets.core_aad}")
        self._emit(
            "sys",
            "the PHC is a velvet rope. plugins are compiled into the inner ELF. "
            "/bypass re-keys the blobs.",
        )
        return True

    async def bypass(self, password: str | None = None, argv: list[str] | None = None) -> bool:
        """Re-key the inner ELF to a known password and exec it in the cage."""
        password = password or BYPASS_PASSWORD
        target = Path(self.session.target_path)
        if not target.is_file():
            self._emit("err", f"target missing: {target}")
            return False
        dest = cache_dir_for(target) / "payload"
        cache_hint = dest.parent.name
        self._emit(
            "sys",
            f"bypass  static unpack → ~/.gatex/cache/{cache_hint}/payload  (no exec)",
        )
        try:
            inner = await asyncio.to_thread(extract_payload_tree, target, dest)
        except Exception as exc:
            self._emit("err", f"unpack tree failed: {type(exc).__name__}: {exc}")
            return False
        orig = dest / "7350FH.bin.orig"
        if not orig.is_file():
            orig.write_bytes(inner.read_bytes())
            orig.chmod(0o400)
        else:
            inner.write_bytes(orig.read_bytes())
            inner.chmod(0o700)
        self._emit("sys", f"re-keying gate blobs to FH_PASS={password!r}")
        try:
            result = await asyncio.to_thread(patch_inner_file, inner, password)
        except Exception as exc:
            self._emit("err", f"patch failed: {type(exc).__name__}: {exc}")
            return False
        self._emit("ok", f"patched {result.inner_path.name}  replacements={result.replacements}")
        argv = list(argv if argv is not None else (self.session.cage_argv or ["list"]))
        try:
            name = await asyncio.to_thread(
                ensure_bypass_cage, self.session.name, target, dest, self._emit
            )
        except CageError as exc:
            self._emit("err", f"bypass cage: {exc}")
            return False
        self.state.cage_ready = True
        self._emit("sys", f"exec patched inner  argv={argv}  (qemu linux/amd64, may take a minute)")
        try:
            cage = await asyncio.to_thread(
                try_patched,
                name,
                password,
                argv,
                max(self.session.cage_timeout, 300.0),
            )
        except CageError as exc:
            self._emit("err", f"bypass exec: {exc}")
            return False
        return self._finish_cage_run(cage, password, argv)

    async def run_cmd(self, argv: list[str]) -> bool:
        """Exec argv against the already-patched inner ELF in the cage."""
        password = self.session.bypass_password or BYPASS_PASSWORD
        if not self.session.bypassed:
            self._emit("err", "not bypassed yet — /bypass first")
            return False
        target = Path(self.session.target_path)
        dest = cache_dir_for(target) / "payload"
        inner = dest / "7350FH.bin"
        if not inner.is_file():
            self._emit("err", f"patched inner missing: {inner}  — /bypass again")
            return False
        try:
            name = await asyncio.to_thread(
                ensure_bypass_cage, self.session.name, target, dest, self._emit
            )
        except CageError as exc:
            self._emit("err", f"bypass cage: {exc}")
            return False
        self.state.cage_ready = True
        self._emit("sys", f"exec patched inner  argv={argv}")
        try:
            cage = await asyncio.to_thread(
                try_patched,
                name,
                password,
                argv,
                max(self.session.cage_timeout, 300.0),
            )
        except CageError as exc:
            self._emit("err", f"exec: {exc}")
            return False
        return self._finish_cage_run(cage, password, argv)

    def _finish_cage_run(self, cage: CageResult, password: str, argv: list[str]) -> bool:
        kind = classify_output(cage.stdout, cage.stderr, cage.returncode)
        preview = (cage.stdout or cage.stderr or "").strip().replace("\n", " ")
        if len(preview) > 240:
            preview = preview[:237] + "..."
        if cage.timed_out:
            self._emit("err", f"timeout after {cage.duration:.1f}s  {preview}")
            return False
        if kind == "denied":
            self._emit("err", f"argon2 still denied  rc={cage.returncode}  {preview}")
            return False
        if kind == "integrity":
            self.session.bypassed = False
            self.session.bypass_password = password
            self.session.save()
            self._emit(
                "warn",
                f"argon2 accepted {password!r} but _decrypt_core failed  "
                f"({cage.duration:.1f}s). "
                "AAD is the Nuitka bytes value fh-slim-hardened-v2, "
                "not the on-disk cfh-… needle.",
            )
            if preview:
                self._emit("sys", preview)
            return False
        if kind in {"nopass", "error"}:
            self._emit("err", f"{kind}  rc={cage.returncode}  {preview}")
            return False
        self.session.bypassed = True
        self.session.bypass_password = password
        self.session.engine_state = "bypassed"
        self.session.cage_argv = list(argv)
        self.session.save()
        self.state.found = password
        self._emit(
            "ok",
            f"BYPASS OK  FH_PASS={password!r}  argv={argv}  "
            f"rc={cage.returncode}  {cage.duration:.1f}s",
        )
        if preview:
            self._emit("sys", preview)
        return True

    async def ensure_cage(self) -> bool:
        """Build the cage image and confirm Docker is up. Does not exec the ELF."""
        try:
            await asyncio.to_thread(start_docker_desktop)
            if not await asyncio.to_thread(image_exists):
                self._emit("sys", f"building {IMAGE} (linux/amd64, first time)")
                await asyncio.to_thread(build_image)
        except CageError as exc:
            self._emit("err", f"cage: {exc}")
            return False
        except Exception as exc:
            self._emit("err", f"cage: {type(exc).__name__}: {exc}")
            return False
        self._emit("ok", "docker up  image ready  linux/amd64  net=none  cap-drop=ALL")
        return True

    def stop(self) -> None:
        self.session.save()

    async def drop_cage(self) -> None:
        name = container_name(self.session.name)
        await asyncio.to_thread(cage_destroy, name)
        await asyncio.to_thread(cage_destroy, bypass_container_name(self.session.name))
        self.state.cage_ready = False
        self._emit("sys", f"destroyed {name} and bypass cage")
