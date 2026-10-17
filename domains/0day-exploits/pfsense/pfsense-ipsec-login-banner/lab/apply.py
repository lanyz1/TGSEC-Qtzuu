#!/usr/bin/env python3
"""Load a PHP-generated strongswan.conf: try charon, else lexer-fallback popen."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

WITNESS_NAME = "PFSENSE-IPSEC-LOGIN-BANNER-WITNESS"
ORACLE_DIR = Path("/oracle")
WRITER = ORACLE_DIR / "w.sh"
WITNESS = ORACLE_DIR / WITNESS_NAME
CHARON_CANDIDATES = (
    "/usr/libexec/ipsec/charon",
    "/usr/lib/ipsec/charon",
    "/usr/sbin/charon",
)
CHARON_TIMEOUT_S = 12.0


class ParseError(Exception):
    """strongSwan settings parse failed."""


@dataclass
class Section:
    values: dict[str, str] = field(default_factory=dict)
    sections: dict[str, "Section"] = field(default_factory=dict)

    def merge_section(self, name: str, child: "Section") -> None:
        existing = self.sections.get(name)
        if existing is None:
            self.sections[name] = child
            return
        existing.values.update(child.values)
        for sub_name, sub in child.sections.items():
            existing.merge_section(sub_name, sub)


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    pos: int


class Lexer:
    """Port of strongSwan settings_lexer.l default + <val> rules."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.i = 0

    def _peek(self) -> str:
        return self.text[self.i] if self.i < self.n else ""

    def _advance(self) -> str:
        ch = self._peek()
        if ch:
            self.i += 1
        return ch

    def _eat_default_noise(self) -> None:
        while self.i < self.n:
            start = self.i
            while self.i < self.n and self.text[self.i] in " \t\r":
                self.i += 1
            if self.i < self.n and self.text[self.i] == "#":
                while self.i < self.n and self.text[self.i] not in "\r\n":
                    self.i += 1
            if self.i < self.n and self.text[self.i] == "\n":
                self.i += 1
                continue
            if self.i == start:
                break

    def tokenize(self) -> list[Token]:
        tokens: list[Token] = []
        while True:
            self._eat_default_noise()
            if self.i >= self.n:
                tokens.append(Token("EOF", "", self.i))
                return tokens
            pos = self.i
            ch = self._peek()
            if ch in "{}":
                self._advance()
                tokens.append(Token(ch, ch, pos))
                continue
            if ch == ".":
                self._advance()
                tokens.append(Token("DOT", ".", pos))
                continue
            if ch == ",":
                self._advance()
                tokens.append(Token("COMMA", ",", pos))
                continue
            if ch == ":":
                self._advance()
                tokens.append(Token("COLON", ":", pos))
                continue
            if ch == "=":
                self._advance()
                tokens.append(Token("=", "=", pos))
                tokens.extend(self._scan_val())
                continue
            if ch == '"':
                raise ParseError(f"unexpected string at {pos}")
            if self._at_include():
                self._skip_include()
                continue
            name = self._scan_name()
            if not name:
                raise ParseError(
                    f"unexpected {self.text[pos:pos + 20]!r} at {pos}"
                )
            tokens.append(Token("NAME", name, pos))

    def _at_include(self) -> bool:
        rest = self.text[self.i :]
        if not rest.startswith("include"):
            return False
        after = rest[7:]
        if not after or after[0] not in " \t":
            return False
        j = 0
        while j < len(after) and after[j] in " \t":
            j += 1
        return j < len(after) and after[j] != "="

    def _skip_include(self) -> None:
        self.i += 7
        while self.i < self.n and self.text[self.i] in " \t":
            self.i += 1
        while self.i < self.n and self.text[self.i] not in "#}\n":
            if self.text[self.i] == "\r":
                self.i += 1
                continue
            self.i += 1

    def _scan_name(self) -> str:
        start = self.i
        while self.i < self.n:
            ch = self.text[self.i]
            if ch in '#{}:.,=" \r\n\t':
                break
            self.i += 1
        return self.text[start : self.i]

    def _scan_val(self) -> list[Token]:
        tokens: list[Token] = []
        while True:
            while self.i < self.n and self.text[self.i] in " \t\r":
                self.i += 1
            if self.i >= self.n:
                tokens.append(Token("NEWLINE", "", self.i))
                return tokens
            ch = self.text[self.i]
            if ch in "#}\n":
                tokens.append(Token("NEWLINE", "", self.i))
                return tokens
            if ch == '"':
                pos = self.i
                tokens.append(Token("STRING", self._scan_string(), pos))
                continue
            pos = self.i
            start = self.i
            while self.i < self.n and self.text[self.i] not in '#}" \r\n\t':
                self.i += 1
            if self.i == start:
                tokens.append(Token("NEWLINE", "", self.i))
                return tokens
            tokens.append(Token("NAME", self.text[start : self.i], pos))

    def _scan_string(self) -> str:
        self._advance()
        out: list[str] = []
        while self.i < self.n:
            ch = self._advance()
            if ch == '"':
                return "".join(out)
            if ch == "\\" and self.i < self.n:
                nxt = self._advance()
                mapping = {"n": "\n", "r": "\r", "t": "\t"}
                out.append(mapping.get(nxt, nxt))
                continue
            out.append(ch)
        raise ParseError("unterminated string")


class Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.i = 0

    def _peek(self) -> Token:
        return self.tokens[self.i]

    def _kind(self) -> str:
        return self._peek().kind

    def _advance(self) -> Token:
        tok = self._peek()
        if tok.kind != "EOF":
            self.i += 1
        return tok

    def _skip_newlines(self) -> None:
        while self._kind() == "NEWLINE":
            self._advance()

    def parse(self) -> Section:
        root = Section()
        self._parse_statements(root)
        self._skip_newlines()
        if self._kind() != "EOF":
            tok = self._peek()
            raise ParseError(f"trailing token {tok.kind} {tok.value!r}")
        return root

    def _parse_statements(self, section: Section) -> None:
        while True:
            self._skip_newlines()
            kind = self._kind()
            if kind in ("EOF", "}"):
                return
            self._parse_statement(section)

    def _parse_statement(self, section: Section) -> None:
        tok = self._advance()
        if tok.kind != "NAME":
            raise ParseError(f"expected NAME, got {tok.kind} {tok.value!r}")
        name = tok.value
        self._skip_newlines()
        kind = self._kind()
        if kind == "{":
            self._advance()
            child = Section()
            self._parse_statements(child)
            self._skip_newlines()
            closer = self._advance()
            if closer.kind != "}":
                raise ParseError(
                    f"unclosed section {name!r}, got {closer.kind}"
                )
            section.merge_section(name, child)
            return
        if kind == "=":
            self._advance()
            section.values[name] = self._parse_value()
            return
        raise ParseError(
            f"expected {{ or = after {name!r}, got {kind} {self._peek().value!r}"
        )

    def _parse_value(self) -> str:
        parts: list[str] = []
        while self._kind() in ("NAME", "STRING"):
            parts.append(self._advance().value)
        if self._kind() == "NEWLINE":
            self._advance()
        return " ".join(parts)


def parse_settings(text: str) -> Section:
    return Parser(Lexer(text).tokenize()).parse()


def lookup(section: Section, path: str) -> Section | None:
    cur = section
    for part in path.split("."):
        if part not in cur.sections:
            return None
        cur = cur.sections[part]
    return cur


def attr_28672(root: Section) -> str | None:
    attr = lookup(root, "charon.plugins.attr")
    if attr is None:
        return None
    return attr.values.get("28672")


def start_script_path(root: Section) -> str | None:
    scripts = lookup(root, "charon.start-scripts")
    if scripts is None or not scripts.values:
        return None
    if "w" in scripts.values:
        return scripts.values["w"]
    return next(iter(scripts.values.values()))


def ensure_writer() -> None:
    ORACLE_DIR.mkdir(parents=True, exist_ok=True)
    WRITER.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' '{WITNESS_NAME}' > {WITNESS}\n"
    )
    WRITER.chmod(0o755)


def clear_witness() -> None:
    if WITNESS.exists():
        WITNESS.unlink()


def witness_ok() -> bool:
    if not WITNESS.is_file():
        return False
    return WITNESS_NAME in WITNESS.read_text(errors="replace")


def find_charon() -> str | None:
    for path in CHARON_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def try_charon(conf_path: str) -> tuple[bool, str]:
    binary = find_charon()
    if binary is None:
        return False, "charon-binary-missing"
    Path("/etc").mkdir(parents=True, exist_ok=True)
    Path("/run").mkdir(parents=True, exist_ok=True)
    Path("/var/run").mkdir(parents=True, exist_ok=True)
    Path("/etc/strongswan.conf").write_text(Path(conf_path).read_text())
    env = os.environ.copy()
    env["STRONGSWAN_CONF"] = conf_path
    clear_witness()
    try:
        proc = subprocess.Popen(
            [binary],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        return False, f"charon-spawn-failed:{exc}"
    deadline = time.time() + CHARON_TIMEOUT_S
    log_blob = ""
    try:
        while time.time() < deadline:
            if witness_ok():
                proc.send_signal(signal.SIGTERM)
                try:
                    out, _err = proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, _err = proc.communicate(timeout=2)
                return True, (out or "")[-1200:]
            if proc.poll() is not None:
                out, _err = proc.communicate()
                log_blob = out or ""
                break
            time.sleep(0.1)
        else:
            proc.send_signal(signal.SIGTERM)
            try:
                out, _err = proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, _err = proc.communicate(timeout=2)
            log_blob = out or ""
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    if witness_ok():
        return True, log_blob[-1200:]
    return False, log_blob[-1200:]


def popen_script(path: str) -> None:
    with os.popen(path) as pipe:
        pipe.read()


def self_test() -> None:
    sample = (
        "starter {\n"
        "\tload_warning = no\n"
        "}\n"
        "charon {\n"
        "\tthreads = 16\n"
        "\tplugins {\n"
        "\t\tunity {\n"
        "\t\t\tload = no\n"
        "\t\t}\n"
        "\t\tattr {\n"
        "\t\t\t# Login Banner\n"
        "\t\t\t28672 = x} } start-scripts { w = /oracle/w.sh } } "
        "dummy1 { dummy2 { dummy3 {\n"
        "\t\t}\n"
        "\t}\n"
        "}\n"
    )
    root = parse_settings(sample)
    if attr_28672(root) != "x":
        raise ParseError(f"self-test attr {attr_28672(root)!r}")
    if start_script_path(root) != "/oracle/w.sh":
        raise ParseError(f"self-test scripts {start_script_path(root)!r}")
    control = (
        "charon {\n"
        "\tplugins {\n"
        "\t\tattr {\n"
        "\t\t\t28672 = Welcome\n"
        "\t\t}\n"
        "\t}\n"
        "}\n"
    )
    ctl = parse_settings(control)
    if attr_28672(ctl) != "Welcome":
        raise ParseError("self-test control attr")
    if start_script_path(ctl) is not None:
        raise ParseError("self-test control scripts")


def conf_excerpt(text: str) -> str:
    lines = text.splitlines()
    tail = lines[-24:] if len(lines) > 24 else lines
    return "\n".join(tail)


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "--self-test":
        self_test()
        print("self-test-ok", flush=True)
        return 0
    if len(sys.argv) < 3:
        print("usage: apply.py CONF_PATH control|trigger", file=sys.stderr)
        return 2
    conf_path = sys.argv[1]
    mode = sys.argv[2]
    ensure_writer()
    self_test()
    text = Path(conf_path).read_text()
    result: dict[str, object] = {
        "mode": mode,
        "parse_ok": False,
        "attr_28672": None,
        "start_scripts": False,
        "script_path": None,
        "loader": None,
        "witness": False,
        "charon_log": "",
        "excerpt": conf_excerpt(text),
        "error": "",
    }
    try:
        root = parse_settings(text)
    except ParseError as exc:
        result["error"] = str(exc)
        print(json.dumps(result), flush=True)
        return 1
    result["parse_ok"] = True
    result["attr_28672"] = attr_28672(root)
    path = start_script_path(root)
    result["script_path"] = path
    result["start_scripts"] = path is not None
    if mode == "control":
        clear_witness()
        result["witness"] = witness_ok()
        result["loader"] = "none"
        print(json.dumps(result), flush=True)
        return 0
    if path is None:
        result["error"] = "no-start-scripts"
        print(json.dumps(result), flush=True)
        return 1
    charon_ok, charon_log = try_charon(conf_path)
    result["charon_log"] = charon_log[-800:]
    if charon_ok and witness_ok():
        result["loader"] = "charon"
        result["witness"] = True
        print(json.dumps(result), flush=True)
        return 0
    clear_witness()
    popen_script(path)
    result["witness"] = witness_ok()
    result["loader"] = "lexer-fallback"
    if not result["witness"]:
        result["error"] = "popen-no-witness"
        print(json.dumps(result), flush=True)
        return 1
    print(json.dumps(result), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
