"""Late-90s IRC-style TUI for GoFileX."""

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

from . import __version__
from .api import GofileClient
from .engine import Engine
from .ratelimit import RateLimiter
from .session import SESSION_DIR, Session
from .wordlist import MAX_PASSWORD_LEN, MIN_PASSWORD_LEN, WORDLIST_ROOT, bundled_wordlists

CmdHandler = Callable[[list[str]], Awaitable[None]]

AUTHOR = ""
HANDLE = ""
HANDLE_URL = ""
BLOG = ""
GITHUB = ""
EMAIL = ""

# Late-90s ANSI boot art. Colors are Rich markup, not raw ANSI,
# so they survive inside RichLog. Box-drawing only — no [ ] in the glyph
# lines (those would be parsed as tags).
LOGO_GLYPHS = [
    r" ██████╗  ██████╗ ███████╗██╗██╗     ███████╗██╗  ██╗",
    r"██╔════╝ ██╔═══██╗██╔════╝██║██║     ██╔════╝╚██╗██╔╝",
    r"██║  ███╗██║   ██║█████╗  ██║██║     █████╗   ╚███╔╝ ",
    r"██║   ██║██║   ██║██╔══╝  ██║██║     ██╔══╝   ██╔██╗ ",
    r"╚██████╔╝╚██████╔╝██║     ██║███████╗███████╗██╔╝ ██╗",
    r" ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝",
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
[bold cyan]***[/] commands  (IRC-style; leading slash required except for this list)
[cyan]/help[/]                      this list
[cyan]/session[/] [name]            load or create a named reusable session
[cyan]/sessions[/]                  list saved sessions in ~/.gofilex/sessions
[cyan]/target[/] <url|id>           switch GoFile share (progress kept per id)
[cyan]/targets[/]                   list every GoFile id in this session
[cyan]/token[/] <api-token>         use an existing token (Premium recommended)
[cyan]/guest[/]                     POST /accounts if this session has no token
[cyan]/wl add[/] <path> [...]       queue one or more wordlists (run in order)
[cyan]/wl all[/]                    queue every bundled wordlist (custom first)
[cyan]/wl[/]                        show the queue + offsets
[cyan]/wl drop[/] <n>               remove wordlist number n
[cyan]/heartbeat[/]                 one GET /contents (counts toward the listing budget)
[cyan]/probe[/]                     alias of /heartbeat
[cyan]/start[/]                     walk the wordlist queue
[cyan]/pause[/]  [cyan]/resume[/]  [cyan]/stop[/]
[cyan]/try[/] <password>            a single listing attempt
[cyan]/rate[/] <seconds>            listing interval (floor 1.5s, default 3s)
[cyan]/stats[/]                     GET /accounts/{id} usage snapshot
[cyan]/dl[/] [dir]                  download unlocked files
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

#lists, #acct {
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

def clock() -> str:
    return datetime.now().strftime("%H:%M:%S")

def short(value: str, n: int = 12) -> str:
    value = value or "-"
    return value if len(value) <= n else value[: n - 1] + "…"

def fmt_bytes(n: int | None) -> str:
    if not n:
        return "0"
    units = ["B", "KB", "MB", "GB", "TB"]
    x = float(n)
    for unit in units:
        if x < 1024 or unit == units[-1]:
            return f"{x:.1f}{unit}" if unit != "B" else f"{int(x)}B"
        x /= 1024
    return f"{n}B"

class SidePanel(Static):
    pass

class GoFileXApp(App):
    CSS = CSS
    TITLE = "GoFileX"
    BINDINGS = [
        Binding("f1", "show_help", "Help", priority=True),
        Binding("ctrl+p", "pause_run", "Pause"),
        Binding("ctrl+s", "start_run", "Start"),
        Binding("ctrl+c", "quit_app", "Quit", priority=True),
    ]

    def __init__(self, session_name: str = "default") -> None:
        super().__init__()
        self.session = Session.load_or_create(session_name)
        self.limiter = RateLimiter(contents_interval=self.session.contents_interval)
        self.client = GofileClient(token=self.session.account.token, limiter=self.limiter)
        self.engine = Engine(self.session, self.client, self._on_log)
        self._pending_logs: list[tuple[str, str]] = []

    def compose(self) -> ComposeResult:
        yield Static(id="titlebar")
        with Horizontal(id="body"):
            yield RichLog(id="channel", highlight=False, markup=True, wrap=True)
            with Vertical(id="side"):
                yield SidePanel(id="lists")
                yield SidePanel(id="acct")
        yield Static(id="progress")
        yield Static(id="statusbar")
        yield Input(placeholder="[GoFileX]  /help   /heartbeat   /wl all   /start", id="cmdline")
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
            f"[bold #ffff00]  ▓▓[/] [bold #00ff00]wordlist client[/]  "
            f"[#808080]::{escape(' late-90s TUI')}[/]  "
            f"[bold #00ffff]v{escape(__version__)}[/]  "
            f"[bold #ffff00]▓▓[/]"
        )
        log.write(
            f"[bold #00ffff]  author[/] [#808080]....[/] [bold #ff00ff]{escape(AUTHOR)}[/]  "
            f"[bold #00ffff]{escape(HANDLE)}[/]     "
            f"[#808080]all rites reversed / 1999-2026[/]"
        )
        log.write(
            f"[bold #00ffff]  x[/] [#808080].........[/] [bold #00ffff]{escape(HANDLE)}[/]  [bold #00ff00 underline]{escape(HANDLE_URL)}[/]"
        )
        log.write(
            f"[bold #00ffff]  github[/] [#808080]....[/] [bold #00ff00 underline]{escape(GITHUB)}[/]"
        )
        log.write(
            f"[bold #00ffff]  blog[/] [#808080]......[/] [bold #00ff00 underline]{escape(BLOG)}[/]"
        )
        log.write(
            f"[bold #00ffff]  email[/] [#808080].....[/] [bold #00ff00]{escape(EMAIL)}[/]"
        )
        log.write(
            "[#808080]  documented GoFile API  ·  rate limits are law  ·  429s pause the run[/]"
        )
        log.write("[bold #00ff00]  ░▒▓████████████████████████████████████████████████████████▓▒░[/]")
        log.write("")
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] session [white]{escape(self.session.name)}[/]  "
            f"{escape(str(self.session.path))}"
        )
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] target [white]{escape(self.session.target_url)}[/]  "
            f"interval={self.limiter.contents_interval:.1f}s  "
            f"password-len={MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN}"
        )
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] cruise {self.limiter.contents_interval:.1f}s between listing calls, "
            f"1s global gap. 429 backs off 15s, 30s, 60s…  Pause after 3 consecutive 429s."
        )
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] /heartbeat sends one listing request when the slot is free. "
            f"That call counts; the next guess waits the cruise interval. No GoFile traffic until then."
        )
        self._print_resume()

    def _print_resume(self) -> None:
        log = self.query_one("#channel", RichLog)
        session = self.session
        jobs = len(session.targets)
        rec = session.current_wordlist()
        log.write(
            f"[cyan]\\[{clock()}\\] ***[/] resume  jobs={jobs}  "
            f"active=[white]{escape(session.content_id)}[/]  "
            f"token={'yes' if session.account.token else 'no'}  "
            f"state={session.engine_state}"
        )
        if rec:
            name = Path(rec.path).name
            log.write(
                f"[cyan]\\[{clock()}\\] ***[/] wordlist [white]{escape(name)}[/]  "
                f"line {rec.line}/{rec.total_lines or '?'}  tried={rec.tried}"
            )
        elif session.wordlists:
            log.write(f"[cyan]\\[{clock()}\\] ***[/] wordlist queue exhausted for this target")
        else:
            log.write(f"[cyan]\\[{clock()}\\] ***[/] no wordlists queued — /wl all")
        job = session.active()
        if job.last_wordlist:
            shown = job.last_password or ""
            if len(shown) > 40:
                shown = shown[:37] + "..."
            log.write(
                f"[cyan]\\[{clock()}\\] ***[/] last attempt  {escape(job.last_wordlist)}:{job.last_line}  "
                f"{escape(shown)!r}"
            )
        if session.found_password:
            log.write(
                f"[bold green]\\[{clock()}\\] +ok+[/] already unlocked  "
                f"{escape(session.found_password)!r}  — /dl to download"
            )
        elif session.engine_state in {"running", "paused"}:
            log.write(
                f"[yellow]\\[{clock()}\\] -!-[/] previous run was [white]{session.engine_state}[/]  "
                f"— /start to continue from the saved line"
            )

    def _on_log(self, kind: str, message: str) -> None:
        # Engine may log from the worker thread/task; queue for the UI.
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
        account = session.account
        limiter = self.limiter
        snap = limiter.snapshot()
        contents = snap["endpoints"].get("contents") or {}
        running = self._run_label()
        title = (
            f" GoFileX {__version__}  ::  {HANDLE}  ::  {session.name}  "
            f"{session.content_id}  {account.tier or 'no-acct'}  [{running}]  {clock()} "
        )
        self.query_one("#titlebar", Static).update(title)

        tried, total = session.total_progress()
        if total:
            pct = 100.0 * tried / total
            bar_w = 24
            fill = int(bar_w * tried / total)
            bar = "#" * fill + "-" * (bar_w - fill)
            prog = f" [{bar}] {tried}/{total}  {pct:.3f}%"
        else:
            prog = f" [{tried} tried]  (line-count pending)"
        if session.found_password:
            prog += f"   FOUND {session.found_password!r}"
        self.query_one("#progress", Static).update(prog)

        next_s = contents.get("next_s") or 0.0
        lag = f"{next_s:.1f}s" if next_s else "ready"
        status = (
            f" [1] {datetime.now().strftime('%H:%M')}  {HANDLE}  "
            f"#{session.content_id}  +{account.tier or '-'}  "
            f"GET/contents {contents.get('requests', 0)}  429:{contents.get('rate_limits', 0)}  "
            f"next {lag}  [{running}]"
        )
        self.query_one("#statusbar", Static).update(status)

        self.query_one("#lists", SidePanel).update(self._lists_text())
        self.query_one("#acct", SidePanel).update(self._acct_text())

    def _run_label(self) -> str:
        if self.engine.state.running and not self.engine.state.paused:
            return "RUN"
        if self.engine.state.paused or self.limiter.paused:
            return "PAUSE"
        if self.session.found_password:
            return "FOUND"
        return "IDLE"

    def _lists_text(self) -> str:
        lines = ["[bold #00ffff] WORDLISTS[/]", ""]
        if not self.session.wordlists:
            lines.append("[#808080]  (empty — /wl add FILE)[/]")
        current = self.session.current_wordlist()
        for i, rec in enumerate(self.session.wordlists, 1):
            mark = ">" if rec is current else " "
            name = Path(rec.path).name
            tot = rec.total_lines if rec.total_lines is not None else "?"
            flag = " done" if rec.exhausted else ""
            lines.append(f" {mark}{i}. {escape(name)}{flag}")
            lines.append(f"     line {rec.line}/{tot}  try {rec.tried}  skip {rec.skipped}")
        lines += ["", "[bold #00ffff] FILES[/]", ""]
        listing = self.session.listing or {}
        children = listing.get("children") or []
        if self.session.found_password:
            lines.append(f" [green]unlocked[/]  {escape(str(listing.get('name') or ''))}")
            if not children:
                lines.append(" [#808080]  (no children in snapshot)[/]")
            for child in children[:12]:
                kind = child.get("type") or "?"
                lines.append(f"  {kind[0].upper()} {escape(str(child.get('name') or child.get('id')))}")
        else:
            lines.append("[#808080]  locked until a password hits[/]")
        return "\n".join(lines)

    def _acct_text(self) -> str:
        a = self.session.account
        snap = self.limiter.snapshot()
        contents = snap["endpoints"].get("contents") or {}
        accounts = snap["endpoints"].get("accounts") or {}
        stats = a.stats_current or {}
        traffic = stats.get("trafficWebDownloaded") or stats.get("trafficDirectGenerated")
        lines = [
            "[bold #00ffff] ACCOUNT / LIMITS[/]",
            "",
            f" id    {escape(short(a.id, 28))}",
            f" x     {escape(HANDLE)}",
            f" tier  {escape(a.tier or '-')}",
            f" token {escape(short(a.token, 10)+('…' if a.token else ''))}",
            "",
            f" GET /contents",
            (
                f"   req {contents.get('requests', 0)}  ok {contents.get('ok', 0)}  "
                f"429 {contents.get('rate_limits', 0)}"
            ),
            f"   interval {self.limiter.contents_interval:.1f}s",
            f"   next {contents.get('next_s', 0):.1f}s  cd {contents.get('cooldown_s', 0):.0f}s",
            f" GET /accounts",
            f"   req {accounts.get('requests', 0)}  429 {accounts.get('rate_limits', 0)}",
            "",
            f" storage {fmt_bytes(stats.get('storage'))}",
            f" files   {stats.get('fileCount', '-')}",
            f" traffic {fmt_bytes(traffic) if isinstance(traffic, int) else '-'}",
        ]
        if snap["paused"]:
            lines += ["", f"[bold red] PAUSED[/]", f" {escape(snap['pause_reason'])}"]
        if self.session.found_password:
            lines += ["", f"[bold green] PASS {escape(self.session.found_password)}[/]"]
        return "\n".join(lines)

    def action_show_help(self) -> None:
        self.run_worker(self._cmd_help([]), name="help")

    def action_pause_run(self) -> None:
        self.engine.pause()

    def action_start_run(self) -> None:
        self.run_worker(self.engine.start(), name="engine-start")

    def action_quit_app(self) -> None:
        self.engine.stop()
        self.session.save()
        self.exit()

    async def _boot(self) -> None:
        if self.session.account.token:
            self.client.token = self.session.account.token
            self._on_log(
                "sys",
                f"reusing token {self.session.account.token[:8]}…  "
                f"{HANDLE}  tier={self.session.account.tier or '?'}",
            )
        else:
            self._on_log("sys", "no token in session yet — /guest or /token")

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
        handlers: dict[str, CmdHandler] = {
            "help": self._cmd_help,
            "?": self._cmd_help,
            "quit": self._cmd_quit,
            "exit": self._cmd_quit,
            "q": self._cmd_quit,
            "session": self._cmd_session,
            "sessions": self._cmd_sessions,
            "target": self._cmd_target,
            "targets": self._cmd_targets,
            "token": self._cmd_token,
            "guest": self._cmd_guest,
            "wl": self._cmd_wl,
            "wordlist": self._cmd_wl,
            "probe": self._cmd_heartbeat,
            "heartbeat": self._cmd_heartbeat,
            "hb": self._cmd_heartbeat,
            "ping": self._cmd_heartbeat,
            "start": self._cmd_start,
            "pause": self._cmd_pause,
            "resume": self._cmd_resume,
            "stop": self._cmd_stop,
            "try": self._cmd_try,
            "rate": self._cmd_rate,
            "stats": self._cmd_stats,
            "dl": self._cmd_dl,
            "download": self._cmd_dl,
        }
        handler = handlers.get(cmd)
        if handler is None:
            self._say("err", f"unknown command /{cmd}  —  /help")
            return
        await handler(args)

    async def _cmd_help(self, _args: list[str]) -> None:
        log = self.query_one("#channel", RichLog)
        for line in HELP.strip("\n").splitlines():
            log.write(line)

    async def _cmd_quit(self, _args: list[str]) -> None:
        self.action_quit_app()

    async def _cmd_sessions(self, _args: list[str]) -> None:
        names = Session.list_names() or ["(none)"]
        self._say("sys", f"sessions in {SESSION_DIR}: {', '.join(names)}")

    async def _cmd_session(self, args: list[str]) -> None:
        if not args:
            self._say("sys", f"current session {self.session.name}  {self.session.path}")
            return
        self.engine.stop()
        self.session.save()
        self.session = Session.load_or_create(args[0])
        self.limiter = RateLimiter(contents_interval=self.session.contents_interval)
        await self.client.aclose()
        self.client = GofileClient(token=self.session.account.token, limiter=self.limiter)
        self.engine = Engine(self.session, self.client, self._on_log)
        self._say("sys", f"loaded session {self.session.name}")
        self._print_resume()

    async def _cmd_targets(self, _args: list[str]) -> None:
        self.session._ensure_active_target()
        if not self.session.targets:
            self._say("sys", "no targets yet — /target <gofile id or url>")
            return
        for tid, job in self.session.targets.items():
            mark = ">" if tid == self.session.last_target_id else " "
            rec = None
            for item in job.wordlists:
                if not item.exhausted:
                    rec = item
                    break
            if rec:
                wl = f"{Path(rec.path).name}:{rec.line}"
            elif job.wordlists:
                wl = "done"
            else:
                wl = "no-lists"
            found = f"  FOUND {job.found_password}" if job.found_password else ""
            self._say("sys", f"{mark} {tid}  {wl}  {job.engine_state}{found}")

    async def _cmd_target(self, args: list[str]) -> None:
        if not args:
            self._say("sys", f"target {self.session.target_url}")
            await self._cmd_targets([])
            return
        previous = self.session.content_id
        try:
            job = self.session.set_target(args[0])
        except ValueError as exc:
            self._say("err", str(exc))
            return
        if self.engine.is_alive():
            self.engine.stop()
        self.engine.state.found = self.session.found_password
        self.engine.state.last_listing = None
        self.session.save()
        if job.content_id == previous:
            self._say("sys", f"already on {job.target_url}")
            return
        rec = self.session.current_wordlist()
        if rec and rec.line:
            self._say(
                "ok",
                f"switched to {job.target_url}  resuming {Path(rec.path).name} line {rec.line}",
            )
        elif job.found_password:
            self._say("ok", f"switched to {job.target_url}  already unlocked")
        else:
            n = len(job.wordlists)
            if n:
                extra = f"new job, copied {n} wordlist path(s), progress 0"
            else:
                extra = "new job — /wl all"
            self._say("ok", f"switched to {job.target_url}  {extra}")

    async def _cmd_token(self, args: list[str]) -> None:
        if not args:
            tok = self.session.account.token
            shown = f"{tok[:8]}…" if tok else "(none)"
            self._say("sys", f"token {shown}")
            return
        token = args[0].strip()
        self.session.account.token = token
        self.client.token = token
        ident = await self.client.get_id()
        if ident.ok:
            self.session.account.id = str(ident.data.get("id") or "")
            self.session.account.email = str(ident.data.get("email") or "")
            self.session.account.tier = str(ident.data.get("tier") or "")
            self._say("ok", f"token accepted  {HANDLE}  tier={self.session.account.tier}")
        else:
            self._say("warn", f"token stored but /accounts/getid → {ident.api_status}")
        self.session.save()

    async def _cmd_guest(self, _args: list[str]) -> None:
        await self.engine.ensure_account()

    async def _cmd_wl(self, args: list[str]) -> None:
        if not args:
            if not self.session.wordlists:
                self._say("sys", "wordlist queue empty")
            for i, rec in enumerate(self.session.wordlists, 1):
                self._say(
                    "sys",
                    f"[{i}] {rec.path}  line={rec.line}/{rec.total_lines or '?'}  "
                    f"tried={rec.tried}  skipped={rec.skipped}"
                    + ("  EXHAUSTED" if rec.exhausted else ""),
                )
            return
        sub = args[0].lower()
        if sub == "add":
            if len(args) < 2:
                self._say("err", "/wl add <path> [path...]")
                return
            for spec in args[1:]:
                path = Path(spec).expanduser()
                if not path.is_file():
                    self._say("err", f"not a file: {path}")
                    continue
                rec = self.session.add_wordlist(path)
                self._say("ok", f"queued {rec.path}")
            self.session.save()
            return
        if sub in {"all", "import"}:
            paths = bundled_wordlists()
            if not paths:
                self._say("err", f"no bundled lists found under {WORDLIST_ROOT}")
                return
            added = 0
            for path in paths:
                before = len(self.session.wordlists)
                self.session.add_wordlist(path)
                if len(self.session.wordlists) > before:
                    added += 1
                self._say("ok", f"queued {path.name}")
            self.session.save()
            n_lists = len(self.session.wordlists)
            self._say("sys", f"imported {added} new list(s), queue now {n_lists} — custom first")
            return
        if sub in {"drop", "rm", "remove"}:
            if len(args) < 2 or not args[1].isdigit():
                self._say("err", "/wl drop <n>")
                return
            idx = int(args[1]) - 1
            if idx < 0 or idx >= len(self.session.wordlists):
                self._say("err", "no such wordlist")
                return
            rec = self.session.wordlists.pop(idx)
            self.session.save()
            self._say("sys", f"dropped {rec.path}")
            return
        self._say("err", "/wl  |  /wl add FILE…  |  /wl all  |  /wl drop N")

    async def _cmd_heartbeat(self, _args: list[str]) -> None:
        await self.engine.heartbeat()

    async def _cmd_start(self, _args: list[str]) -> None:
        await self.engine.start()

    async def _cmd_pause(self, _args: list[str]) -> None:
        self.engine.pause()

    async def _cmd_resume(self, _args: list[str]) -> None:
        self.engine.resume()
        if not self.engine.is_alive():
            await self.engine.start()

    async def _cmd_stop(self, _args: list[str]) -> None:
        self.engine.stop()

    async def _cmd_try(self, args: list[str]) -> None:
        if not args:
            self._say("err", "/try <password>")
            return
        await self.engine.try_password(" ".join(args))

    async def _cmd_rate(self, args: list[str]) -> None:
        if not args:
            self._say(
                "sys",
                f"contents interval {self.limiter.contents_interval:.1f}s  (floor 1.5, default 3)",
            )
            return
        try:
            seconds = float(args[0])
        except ValueError:
            self._say("err", "need a number of seconds")
            return
        applied = self.limiter.set_contents_interval(seconds)
        self.session.contents_interval = applied
        self.session.save()
        self._say("sys", f"contents interval set to {applied:.1f}s")

    async def _cmd_stats(self, _args: list[str]) -> None:
        if not await self.engine.ensure_account():
            return
        await self.engine.refresh_account_stats()

    async def _cmd_dl(self, args: list[str]) -> None:
        dest = args[0] if args else None
        await self.engine.download_all(dest)
