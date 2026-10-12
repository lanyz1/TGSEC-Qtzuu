"""Late-90s IRC-style TUI for GateX."""

from __future__ import annotations

import shlex
from collections.abc import Awaitable, Callable
from datetime import datetime
from pathlib import Path

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Input, RichLog, Static

from . import __github__, __twitter__, __url__, __version__, __writeup__
from .engine import Engine
from .sandbox import docker_running, image_exists
from .session import Session, resolve_target

AUTHOR = ""
TWITTER = __twitter__
BLOG = __url__
GITHUB = __github__
WRITEUP = __writeup__

LOGO_GLYPHS = [
    r"   ██████╗  █████╗ ████████╗███████╗██╗  ██╗",
    r"  ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝",
    r"  ██║  ███╗███████║   ██║   █████╗   ╚███╔╝ ",
    r"  ██║   ██║██╔══██║   ██║   ██╔══╝   ██╔██╗ ",
    r"  ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗",
    r"   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
]
LOGO_COLORS = [
    "#00ff00",
    "#00ee44",
    "#00dd88",
    "#00ccee",
    "#00aaff",
    "#0088ff",
]

HELP = """
[bold cyan]***[/] commands  (IRC-style; leading slash required)
[cyan]/help[/]                      this list
[cyan]/session[/] [name]            load or create a named reusable session
[cyan]/sessions[/]                  list saved sessions in ~/.gatex/sessions
[cyan]/target[/] <zip|elf>          switch binary/zip
[cyan]/targets[/]                   list every target in this session
[cyan]/probe[/]                     static unpack + assemble the Argon2id hash (no exec)
[cyan]/bypass[/] [password]         re-key the gate (default gatex) and exec in the cage
[cyan]/cmd[/] [args…]               argv passed to the patched ELF in the cage
[cyan]/timeout[/] <seconds>         cage exec timeout (default 45)
[cyan]/sandbox[/]                   docker / image / cage status
[cyan]/sandbox up[/]                start Docker Desktop, build image
[cyan]/sandbox down[/]              destroy cage containers
[cyan]/quit[/]                      write session and leave
"""

CSS = """
Screen {
    background: #000010;
    color: #00c000;
}

#titlebar {
    dock: top;
    height: 1;
    background: #00007a;
    color: #ffffff;
    text-style: bold;
    padding: 0 1;
}

#body {
    height: 1fr;
}

#channel {
    background: #000000;
    color: #00e000;
    border: solid #000055;
    padding: 0 1;
    scrollbar-background: #000020;
    scrollbar-color: #0000aa;
}

#side {
    width: 38;
    min-width: 30;
}

#acct {
    height: 1fr;
    background: #000018;
    border: solid #000055;
    color: #00cccc;
    padding: 0 1;
    overflow-y: auto;
}

#progress {
    height: 1;
    background: #000030;
    color: #ffff00;
    padding: 0 1;
}

#statusbar {
    height: 1;
    background: #00007a;
    color: #ffff00;
    padding: 0 1;
}

#cmdline {
    dock: bottom;
    background: #000000;
    color: #00ff00;
    border: none;
    padding: 0 1;
}

Input {
    background: #000000;
    color: #00ff00;
    border: none;
}

Footer {
    background: #00004a;
    color: #aaaaaa;
}
"""

CommandFn = Callable[[list[str]], Awaitable[None]]

def clock() -> str:
    return datetime.now().strftime("%H:%M:%S")

def short(value: str, n: int = 12) -> str:
    value = value or "-"
    return value if len(value) <= n else value[: n - 1] + "…"

class SidePanel(Static):
    pass

class GateXApp(App):
    CSS = CSS
    TITLE = "GateX"
    BINDINGS = [
        Binding("f1", "show_help", "Help", priority=True),
        Binding("ctrl+c", "quit_app", "Quit", priority=True),
    ]

    def __init__(self, session_name: str = "default") -> None:
        super().__init__()
        self.session = Session.load_or_create(session_name)
        self.engine = Engine(self.session, self._on_log)
        self._pending_logs: list[tuple[str, str]] = []

    def compose(self) -> ComposeResult:
        yield Static(id="titlebar")
        with Horizontal(id="body"):
            yield RichLog(id="channel", highlight=False, markup=True, wrap=True)
            with Vertical(id="side"):
                yield SidePanel(id="acct")
        yield Static(id="progress")
        yield Static(id="statusbar")
        yield Input(placeholder="[GateX]  /help   /probe   /bypass   /sandbox", id="cmdline")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#cmdline", Input).focus()
        self.set_interval(0.4, self._refresh_chrome)
        self._print_banner()
        self._refresh_chrome()
        self.run_worker(self._boot(), exclusive=True, name="boot")

    def on_unmount(self) -> None:
        self.engine.stop()
        self.session.save()

    def _print_banner(self) -> None:
        log = self.query_one("#channel", RichLog)
        log.write("")
        log.write("[bold #ff00ff]  ░▒▓█  n o   c a r r i e r   █▓▒░[/]     [bold #ffff00]*** ELITE HACKER EDITION ***[/]")
        log.write("[#003300]  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·[/]")
        for glyph, color in zip(LOGO_GLYPHS, LOGO_COLORS):
            log.write(f"[bold {color}]{glyph}[/]")
        log.write("[#003300]  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·[/]")
        log.write(
            f"[bold #ffff00]  ▓▓[/] [bold #00ff00]7350FH gate client[/]  "
            f"[#808080]::{escape(' late-90s TUI')}[/]  "
            f"[bold #00ffff]v{escape(__version__)}[/]  "
            f"[bold #ffff00]▓▓[/]"
        )
        log.write(
            f"[bold #00ffff]  author[/] [#808080]....[/] [bold #ff00ff]{escape(AUTHOR)}[/]     "
            f"[#808080]all rites reversed / 1999-2026[/]"
        )
        log.write(
            f"[bold #00ffff]  x[/] [#808080].........[/] [bold #00ff00 underline]{escape(TWITTER)}[/]"
        )
        log.write(
            f"[bold #00ffff]  blog[/] [#808080]......[/] [bold #00ff00 underline]{escape(BLOG)}[/]"
        )
        log.write(
            f"[bold #00ffff]  github[/] [#808080]....[/] [bold #00ff00 underline]{escape(GITHUB)}[/]"
        )
        log.write(
            f"[bold #00ffff]  writeup[/] [#808080]...[/] [bold #00ff00 underline]{escape(WRITEUP)}[/]"
        )
        log.write(
            "[#808080]  never execs the ELF on the host  ·  cage is linux/amd64 Docker  ·  net=none[/]"
        )
        log.write("[bold #00ff00]  ░▒▓████████████████████████████████████████████████████████▓▒░[/]")
        log.write("")
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] session [white]{escape(self.session.name)}[/]  "
            f"~/.gatex/sessions/{escape(self.session.name)}.json"
        )
        target = Path(self.session.target_path)
        shown_target = target.name if target.name else str(target)
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] target [white]{escape(shown_target)}[/]  "
            f"timeout={self.session.cage_timeout:.0f}s"
        )
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] /probe unpacks the Nuitka payload in-process (zstd, no exec) "
            f"and reassembles the XOR-fragmented Argon2id hash."
        )
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] /bypass re-keys Argon2 + AES-GCM to a known pass "
            f"and execs the inner ELF in the Docker cage."
        )
        self._print_resume()

    def _print_resume(self) -> None:
        log = self.query_one("#channel", RichLog)
        session = self.session
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] resume  jobs={len(session.targets)}  "
            f"hash={'yes' if session.hash_phc else 'no'}  "
            f"state={session.engine_state}  "
            f"bypassed={'yes' if session.bypassed else 'no'}"
        )
        if session.bypassed:
            log.write(
                f"[bold green]\\[{clock()}\\] +ok+[/] gate re-keyed  "
                f"FH_PASS={escape(session.bypass_password or 'gatex')!r}  — /cmd list"
            )
        else:
            log.write(f"[cyan]\\[{clock()}\\] ***[/] not bypassed — /probe then /bypass")

    def _on_log(self, kind: str, message: str) -> None:
        self._pending_logs.append((kind, message))

    def _flush_logs(self) -> None:
        if not self._pending_logs:
            return
        log = self.query_one("#channel", RichLog)
        styles = {
            "sys": ("cyan", "***"),
            "ok": ("bright_green", "+ok+"),
            "fail": ("#808080", "-fail-"),
            "warn": ("yellow", "-!-"),
            "err": ("bright_red", "-err-"),
        }
        while self._pending_logs:
            kind, message = self._pending_logs.pop(0)
            color, tag = styles.get(kind, ("white", kind))
            log.write(f"[{color}]\\[{clock()}\\] {tag}[/] {escape(message)}")

    def _refresh_chrome(self) -> None:
        self._flush_logs()
        session = self.session
        running = "BYPASS" if session.bypassed else "IDLE"
        target_name = Path(session.target_path).name or "-"
        title = (
            f" GateX {__version__}  ::  {AUTHOR}  ::  {session.name}  "
            f"{target_name}  [{running}]  {clock()} "
        )
        self.query_one("#titlebar", Static).update(title)

        if session.bypassed:
            prog = (
                f" re-keyed  FH_PASS={session.bypass_password!r}  "
                f"argv={session.cage_argv or ['list']}"
            )
        elif session.hash_phc:
            prog = " hash assembled  — /bypass to re-key the gate"
        else:
            prog = " no hash yet  — /probe then /bypass"
        self.query_one("#progress", Static).update(prog)

        status = (
            f" [1] {datetime.now().strftime('%H:%M')}  {short(session.name, 16)}  "
            f"{short(target_name, 18)}  "
            f"{'bypassed' if session.bypassed else 'locked'}  [{running}]"
        )
        self.query_one("#statusbar", Static).update(status)
        self.query_one("#acct", SidePanel).update(self._acct_text())

    def _acct_text(self) -> str:
        s = self.session
        phc = s.hash_phc or ""
        shown = phc if len(phc) <= 28 else phc[:12] + "…" + phc[-10:]
        lines = [
            "[bold #00ffff] GATE / CAGE[/]",
            "",
            f" hash  {escape(shown or '(probe first)')}",
            f" aad   {escape(s.core_aad or '-')}",
            f" cage  to={s.cage_timeout:.0f}s  argv={escape(' '.join(s.cage_argv) or 'list')}",
            f" ready {('yes' if self.engine.state.cage_ready else 'no')}",
            f" bypass {('yes' if s.bypassed else 'no')}",
            "",
            "[bold #00ffff] CONTACT[/]",
            "",
            f" {escape(TWITTER)}",
            f" {escape(BLOG)}",
            f" {escape(GITHUB)}",
        ]
        if s.bypassed:
            lines += [
                "",
                f"[bold green] PASS {escape(s.bypass_password or 'gatex')}[/]",
                " [bold yellow]re-key[/]",
            ]
        return "\n".join(lines)

    def action_show_help(self) -> None:
        self.run_worker(self._cmd_help([]), name="help")

    def action_quit_app(self) -> None:
        self.engine.stop()
        self.session.save()
        self.exit()

    async def _boot(self) -> None:
        target = Path(self.session.target_path)
        if target.is_file():
            self._on_log("sys", f"target on disk  {target.name}")
        else:
            self._on_log("warn", f"target not found  {target}  — /target files/7350FH.zip")
        if self.session.hash_phc:
            self._on_log("sys", "reusing assembled argon2id hash from session")
        else:
            self._on_log("sys", "no hash yet — /probe")
        if self.session.bypassed:
            self._on_log("ok", "session already bypassed — /cmd list")

    def _say(self, kind: str, message: str) -> None:
        self._on_log(kind, message)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        event.input.value = ""
        if not raw:
            return
        self._say("sys", f"> {raw}")
        await self._dispatch(raw)

    async def _dispatch(self, raw: str) -> None:
        if not raw.startswith("/"):
            self._say("warn", "commands start with /  —  /help")
            return
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            self._say("err", f"parse: {exc}")
            return
        cmd = parts[0].lower().lstrip("/")
        args = parts[1:]
        handler = self._commands().get(cmd)
        if handler is None:
            self._say("err", f"unknown command /{cmd}  —  /help")
            return
        await handler(args)

    def _commands(self) -> dict[str, CommandFn]:
        return {
            "help": self._cmd_help,
            "?": self._cmd_help,
            "quit": self._cmd_quit,
            "exit": self._cmd_quit,
            "q": self._cmd_quit,
            "session": self._cmd_session,
            "sessions": self._cmd_sessions,
            "target": self._cmd_target,
            "targets": self._cmd_targets,
            "probe": self._cmd_probe,
            "heartbeat": self._cmd_probe,
            "bypass": self._cmd_bypass,
            "rekey": self._cmd_bypass,
            "timeout": self._cmd_timeout,
            "cmd": self._cmd_argv,
            "sandbox": self._cmd_sandbox,
            "cage": self._cmd_sandbox,
        }

    async def _cmd_help(self, _args: list[str]) -> None:
        log = self.query_one("#channel", RichLog)
        for line in HELP.strip("\n").splitlines():
            log.write(line)

    async def _cmd_quit(self, _args: list[str]) -> None:
        self.action_quit_app()

    async def _cmd_sessions(self, _args: list[str]) -> None:
        names = Session.list_names() or ["(none)"]
        self._say("sys", f"sessions in ~/.gatex/sessions: {', '.join(names)}")

    async def _cmd_session(self, args: list[str]) -> None:
        if not args:
            self._say("sys", f"current session {self.session.name}")
            return
        self.engine.stop()
        self.session.save()
        self.session = Session.load_or_create(args[0])
        self.engine = Engine(self.session, self._on_log)
        self._say("sys", f"loaded session {self.session.name}")
        self._print_resume()

    async def _cmd_targets(self, _args: list[str]) -> None:
        self.session._ensure_active_target()
        if not self.session.targets:
            self._say("sys", "no targets yet — /target files/7350FH.zip")
            return
        for tid, job in self.session.targets.items():
            mark = ">" if tid == self.session.last_target_id else " "
            flag = "  BYPASSED" if job.bypassed else ""
            self._say("sys", f"{mark} {Path(tid).name}  {job.engine_state}{flag}")

    async def _cmd_target(self, args: list[str]) -> None:
        if not args:
            self._say("sys", f"target {self.session.target_path}")
            await self._cmd_targets([])
            return
        previous = self.session.target_path
        path = resolve_target(args[0])
        if not path.exists():
            self._say("warn", f"path does not exist yet: {path}")
        job = self.session.set_target(str(path))
        self.engine.state.found = job.bypass_password
        self.engine.state.cage_ready = False
        self.session.save()
        if job.target_path == previous:
            self._say("sys", f"already on {Path(job.target_path).name}")
            return
        if job.bypassed:
            self._say("ok", f"switched to {Path(job.target_path).name}  already bypassed")
        else:
            self._say("ok", f"switched to {Path(job.target_path).name}  — /probe then /bypass")

    async def _cmd_probe(self, _args: list[str]) -> None:
        await self.engine.probe()

    async def _cmd_bypass(self, args: list[str]) -> None:
        password = args[0] if args else None
        await self.engine.bypass(password)

    async def _cmd_timeout(self, args: list[str]) -> None:
        if not args:
            self._say("sys", f"cage timeout {self.session.cage_timeout:.0f}s")
            return
        try:
            seconds = float(args[0])
        except ValueError:
            self._say("err", "need a number of seconds")
            return
        self.session.cage_timeout = max(5.0, seconds)
        self.session.save()
        self._say("sys", f"cage timeout set to {self.session.cage_timeout:.0f}s")

    async def _cmd_argv(self, args: list[str]) -> None:
        if not args:
            self._say("sys", f"cage argv {self.session.cage_argv or ['list']}")
            return
        self.session.cage_argv = list(args)
        self.session.save()
        await self.engine.run_cmd(list(args))

    async def _cmd_sandbox(self, args: list[str]) -> None:
        sub = args[0].lower() if args else "status"
        if sub in {"status", "info"}:
            docker = "up" if docker_running() else "down"
            image = "yes" if docker == "up" and image_exists() else "no"
            self._say(
                "sys",
                f"docker={docker}  image={image}  cage_ready={self.engine.state.cage_ready}  "
                f"target={Path(self.session.target_path).name}",
            )
            return
        if sub in {"up", "start", "build"}:
            ok = await self.engine.ensure_cage()
            if ok:
                self._say("ok", "sandbox up")
            return
        if sub in {"down", "destroy", "rm"}:
            await self.engine.drop_cage()
            return
        self._say("err", "/sandbox  |  /sandbox up  |  /sandbox down")
