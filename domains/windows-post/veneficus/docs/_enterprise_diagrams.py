#!/usr/bin/env python3
"""Cabinet-projection architecture boards for VENEFICUS_MINI_v3_DEEP_ANALYSIS.md.

Cards are extruded 3D tiles on platforms (not full-width 2D bars). Render with:
  python3 docs/_enterprise_diagrams.py
"""
from __future__ import annotations

import math
import subprocess
from pathlib import Path

OUT = Path(__file__).resolve().parent
RSVG = "/opt/homebrew/bin/rsvg-convert"

BG = "#07090d"
INK = "#f2f6fb"
MUTED = "#c5cdd8"
DIM = "#7d8796"
LINE = "#1c2533"
LIVE = "#3dff9a"
PARTIAL = "#f5c542"
BROKEN = "#ff5d6c"
CONTROL = "#5b8cff"
GHOST = "#6b7380"
CYAN = "#7ee7ff"

STATUS = {
    "live": {
        "accent": LIVE,
        "top": "#145c3a",
        "side": "#0b2418",
        "front0": "#12301f",
        "front1": "#0b1412",
        "chip": "LIVE",
    },
    "partial": {
        "accent": PARTIAL,
        "top": "#5a4310",
        "side": "#2a1f08",
        "front0": "#2c220f",
        "front1": "#12100c",
        "chip": "PARTIAL",
    },
    "broken": {
        "accent": BROKEN,
        "top": "#5a1822",
        "side": "#2a0c12",
        "front0": "#30141c",
        "front1": "#14090c",
        "chip": "BROKEN",
    },
    "control": {
        "accent": CONTROL,
        "top": "#16345c",
        "side": "#0c1a30",
        "front0": "#122238",
        "front1": "#0a1018",
        "chip": "CONTROL",
    },
    "ghost": {
        "accent": GHOST,
        "top": "#2a3140",
        "side": "#161a22",
        "front0": "#1a1e26",
        "front1": "#0c0e12",
        "chip": "DEAD",
    },
}

FONT = "Helvetica Neue, Helvetica, Arial, sans-serif"
MONO = "Menlo, SF Mono, ui-monospace, monospace"


def esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def tspans(text: str, x: float, dy: float, fill: str, size: float, weight: int = 400) -> str:
    lines = str(text).split("\n")
    parts = []
    for i, line in enumerate(lines):
        extra = f' dy="{dy}"' if i else ""
        parts.append(
            f'<tspan x="{x}"{extra} fill="{fill}" font-size="{size}" '
            f'font-weight="{weight}" font-family="{FONT}">{esc(line)}</tspan>'
        )
    return "".join(parts)


class Board:
    def __init__(self, w: int, h: int, fig: str, title: str, subtitle: str):
        self.w = w
        self.h = h
        self.fig = fig
        self.title = title
        self.subtitle = subtitle
        self.gradients: list[str] = []
        self.plat: list[str] = []
        self.pipes: list[str] = []
        self.cards: list[str] = []
        self.over: list[str] = []
        self.fx = 0

    def _fid(self, name: str) -> str:
        self.fx += 1
        return f"{name}{self.fx}"

    def defs(self) -> str:
        return f"""
  <defs>
    <linearGradient id="hdr" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{LIVE}"/>
      <stop offset="0.55" stop-color="{CYAN}"/>
      <stop offset="1" stop-color="{CONTROL}"/>
    </linearGradient>
    <radialGradient id="vignette" cx="50%" cy="16%" r="80%">
      <stop offset="0" stop-color="#101820" stop-opacity="1"/>
      <stop offset="1" stop-color="{BG}" stop-opacity="1"/>
    </radialGradient>
    <pattern id="scan" width="6" height="6" patternUnits="userSpaceOnUse">
      <rect width="6" height="1" fill="{LIVE}" opacity="0.035"/>
    </pattern>
    <pattern id="iso" width="56" height="32" patternUnits="userSpaceOnUse">
      <path d="M0 16 L28 0 L56 16 L28 32 Z" fill="none" stroke="#14301f" stroke-width="0.7" opacity="0.35"/>
    </pattern>
    <filter id="shadow" x="-25%" y="-25%" width="160%" height="170%">
      <feGaussianBlur in="SourceAlpha" stdDeviation="6"/>
      <feOffset dx="4" dy="10" result="off"/>
      <feFlood flood-color="#000" flood-opacity="0.55"/>
      <feComposite in2="off" operator="in"/>
      <feMerge>
        <feMergeNode/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="2.6" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    {''.join(self.gradients)}
  </defs>"""

    def background(self) -> str:
        return f"""
  <rect width="{self.w}" height="{self.h}" fill="url(#vignette)"/>
  <rect width="{self.w}" height="{self.h}" fill="url(#iso)" opacity="0.55"/>
  <rect width="{self.w}" height="{self.h}" fill="url(#scan)"/>
  <rect x="0" y="0" width="{self.w}" height="4" fill="url(#hdr)"/>
  <rect x="0" y="4" width="{self.w}" height="78" fill="#0a0e14" opacity="0.72"/>"""

    def chrome(self) -> str:
        return f"""
  <text x="36" y="26" fill="{LIVE}" font-size="11" font-weight="700" font-family="{MONO}" letter-spacing="2.4">{esc(self.fig)}</text>
  <text x="{self.w - 36}" y="26" fill="{DIM}" font-size="11" font-weight="600" font-family="{MONO}" text-anchor="end" letter-spacing="1.6">TLP:CLEAR · EDUCATIONAL</text>
  <text x="36" y="58" fill="{INK}" font-size="28" font-weight="700" font-family="{FONT}">{esc(self.title)}</text>
  <text x="36" y="80" fill="{DIM}" font-size="13" font-weight="400" font-family="{FONT}">{esc(self.subtitle)}</text>
"""

    def legend(self, x: float, y: float, items: list[tuple[str, str]] | None = None) -> None:
        items = items or [
            ("live", "LIVE"),
            ("partial", "PARTIAL"),
            ("broken", "BROKEN"),
            ("control", "CONTROL"),
        ]
        cx = x
        bits = []
        for key, label in items:
            st = STATUS[key]
            bits.append(
                f'<g transform="translate({cx},{y})">'
                f'<rect x="0" y="0" rx="9" ry="9" width="{18 + 7.2 * len(label)}" height="18" fill="#0c1218" stroke="{st["accent"]}" stroke-width="1.2"/>'
                f'<circle cx="10" cy="9" r="3.2" fill="{st["accent"]}"/>'
                f'<text x="18" y="12.5" fill="{st["accent"]}" font-size="10" font-weight="700" font-family="{MONO}">{esc(label)}</text>'
                f"</g>"
            )
            cx += 22 + 7.2 * len(label) + 14
        self.over.append("".join(bits))

    def platform(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        title: str,
        accent: str = LIVE,
        depth: int = 22,
    ) -> None:
        dx, dy = depth, int(depth * 0.52)
        top = f"M{x},{y} L{x + dx},{y - dy} L{x + w + dx},{y - dy} L{x + w},{y} Z"
        side = f"M{x + w},{y} L{x + w + dx},{y - dy} L{x + w + dx},{y + h - dy} L{x + w},{y + h} Z"
        self.plat.append(
            f"""
  <g filter="url(#shadow)">
    <path d="{side}" fill="#0a1016" stroke="{LINE}" stroke-width="1"/>
    <path d="{top}" fill="#101820" stroke="{LINE}" stroke-width="1"/>
    <path d="M{x},{y} L{x + dx},{y - dy}" stroke="{accent}" stroke-width="1.4" opacity="0.7"/>
    <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" ry="10" fill="#0b1118" stroke="{LINE}" stroke-width="1.2" opacity="0.96"/>
    <rect x="{x}" y="{y}" width="6" height="{h}" rx="2" fill="{accent}" opacity="0.95"/>
    <text x="{x + 22}" y="{y + 22}" fill="{accent}" font-size="11" font-weight="700" font-family="{MONO}" letter-spacing="2.2">{esc(title)}</text>
  </g>"""
        )

    def card(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        *,
        status: str = "live",
        kicker: str = "",
        title: str = "",
        body: str = "",
        depth: int = 18,
        chip: str | None = None,
        hollow: bool = False,
    ) -> dict:
        st = STATUS[status]
        dx, dy = depth, int(depth * 0.55)
        chip = chip if chip is not None else st["chip"]
        top = f"M{x},{y} L{x + dx},{y - dy} L{x + w + dx},{y - dy} L{x + w},{y} Z"
        side = f"M{x + w},{y} L{x + w + dx},{y - dy} L{x + w + dx},{y + h - dy} L{x + w},{y + h} Z"
        gid = self._fid("cg")
        self.gradients.append(
            f"""
    <linearGradient id="{gid}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="{st["front0"]}"/>
      <stop offset="1" stop-color="{st["front1"]}"/>
    </linearGradient>"""
        )
        dash = 'stroke-dasharray="6 4"' if hollow else ""
        front_op = "0.45" if hollow else "1"
        top_fill = st["top"] if not hollow else "#12161c"
        crack = ""
        if status == "broken" and not hollow:
            crack = (
                f'<path d="M{x + w * 0.74},{y + 10} L{x + w * 0.66},{y + h * 0.46} '
                f'L{x + w * 0.76},{y + h * 0.56} L{x + w * 0.68},{y + h - 12}" '
                f'fill="none" stroke="{BROKEN}" stroke-width="1.15" opacity="0.32"/>'
            )
        chip_w = 18 + 7.4 * len(chip)
        self.cards.append(
            f"""
  <g filter="url(#shadow)">
    <path d="{side}" fill="{st["side"]}" stroke="{st["accent"]}" stroke-width="0.85" opacity="0.95"/>
    <path d="{top}" fill="{top_fill}" stroke="{st["accent"]}" stroke-width="0.95" opacity="0.95"/>
    <path d="M{x},{y} L{x + dx},{y - dy}" stroke="#ffffff" stroke-width="1.1" opacity="0.18"/>
    <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" ry="12" fill="url(#{gid})" stroke="{st["accent"]}" stroke-width="1.4" {dash} opacity="{front_op}"/>
    <rect x="{x}" y="{y}" width="5" height="{h}" rx="2" fill="{st["accent"]}"/>
    <circle cx="{x + 22}" cy="{y + 22}" r="4.2" fill="{st["accent"]}" filter="url(#glow)"/>
    <text x="{x + 34}" y="{y + 26}" fill="{st["accent"]}" font-size="10.5" font-weight="700" font-family="{MONO}" letter-spacing="1.8">{esc(kicker)}</text>
    <rect x="{x + w - chip_w - 14}" y="{y + 13}" rx="9" ry="9" width="{chip_w}" height="18" fill="#05070a" stroke="{st["accent"]}" stroke-width="1"/>
    <text x="{x + w - 14 - chip_w / 2}" y="{y + 26}" text-anchor="middle" fill="{st["accent"]}" font-size="10" font-weight="700" font-family="{MONO}">{esc(chip)}</text>
    <text x="{x + 20}" y="{y + 52}" fill="{INK}" font-size="16" font-weight="700" font-family="{FONT}">{esc(title)}</text>
    <text x="{x + 20}" y="{y + 76}">{tspans(body, x + 20, 16, MUTED, 12.5, 400)}</text>
    {crack}
  </g>"""
        )
        return {
            "x": x,
            "y": y,
            "w": w,
            "h": h,
            "n": (x + w / 2, y),
            "s": (x + w / 2, y + h),
            "e": (x + w, y + h / 2),
            "wpt": (x, y + h / 2),
            "status": status,
        }

    def pipe(self, *points, color: str = LIVE, broken: bool = False, arrow: bool = True) -> None:
        pts = [(float(p[0]), float(p[1])) for p in points]
        if len(pts) < 2:
            return
        x1, y1 = pts[-2]
        x2, y2 = pts[-1]
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy) or 1.0
        inset = 9.0
        x2s = x2 - dx / dist * inset
        y2s = y2 - dy / dist * inset
        pts[-1] = (x2s, y2s)
        d = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
        dash = 'stroke-dasharray="7 6"' if broken else ""
        col = BROKEN if broken else color
        self.pipes.append(
            f"""
  <polyline points="{d}" fill="none" stroke="#05070a" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
  <polyline points="{d}" fill="none" stroke="{col}" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round" {dash} opacity="0.95" filter="url(#glow)"/>"""
        )
        if arrow:
            ux, uy = dx / dist, dy / dist
            px, py = -uy, ux
            p, w = 9.0, 5.5
            ax, ay = x2s, y2s
            self.over.append(
                f'<polygon points="{ax:.1f},{ay:.1f} {ax - ux * p + px * w:.1f},{ay - uy * p + py * w:.1f} {ax - ux * p - px * w:.1f},{ay - uy * p - py * w:.1f}" fill="{col}"/>'
            )

    def junction(self, x: float, y: float, color: str = LIVE) -> None:
        self.over.append(
            f'<rect x="{x - 5}" y="{y - 5}" width="10" height="10" rx="1" transform="rotate(45 {x} {y})" fill="{color}" stroke="#05070a" stroke-width="1"/>'
        )

    def note(self, x: float, y: float, text: str, color: str = DIM) -> None:
        self.over.append(
            f'<text x="{x}" y="{y}" fill="{color}" font-size="11" font-weight="600" font-family="{MONO}" letter-spacing="1.1">{esc(text)}</text>'
        )

    def tostring(self) -> str:
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
            f'viewBox="0 0 {self.w} {self.h}">\n'
            + self.defs()
            + self.background()
            + "\n".join(self.plat)
            + "\n".join(self.pipes)
            + "\n".join(self.cards)
            + "\n".join(self.over)
            + self.chrome()
            + "\n</svg>\n"
        )

    def save(self, name: str) -> Path:
        svg = OUT / f"{name}.svg"
        png = OUT / f"{name}.png"
        svg.write_text(self.tostring(), encoding="utf-8")
        subprocess.check_call(
            [RSVG, "-w", str(self.w * 2), "-h", str(self.h * 2), "-o", str(png), str(svg)]
        )
        return png


def architecture() -> Board:
    b = Board(1000, 1320, "FIG 01  ·  CONTROL PLANE", "Kit architecture", "Intended path — stager, implant, Worker, Telegram")
    b.legend(36, 96)

    b.platform(40, 150, 920, 250, "VICTIM HOST", LIVE, depth=24)
    a = b.card(70, 188, 270, 180, status="partial", kicker="01  STAGER", title="loader.ps1",
               body="AMSI reflection bypass\nGET /beacon  →  drop PE\nMicrosoftEdgeUpdate.exe", depth=20)
    c = b.card(365, 188, 270, 180, status="live", kicker="02  IMPLANT", title="veneficus_mini.exe",
               body="Sandbox score 0–100\nStealth + BYOVD gate\nTheft · persist · SOCKS", depth=20)
    d = b.card(660, 188, 270, 180, status="live", kicker="03  THREADS", title="payload cluster",
               body="payload · persist · proxy\nHVNC · clipper\nSpawned only if score ≤ 60", depth=20)

    b.platform(40, 450, 440, 790, "OPERATOR", CONTROL, depth=22)
    p1 = b.card(68, 490, 384, 200, status="control", kicker="CONTROL", title="X-Admin-Key API",
                body="/admin  /register  /set_config\n/listing  /unregister\nWorker-side, UUID gated", depth=18)
    p2 = b.card(68, 720, 384, 200, status="partial", kicker="RELAY", title="Cloudflare Worker",
                body="UUID gate · command queue\nconfig KV\nNo /beacon in this tree", depth=18)
    p3 = b.card(68, 950, 384, 230, status="broken", kicker="NOTIFY", title="Telegram bot",
                body="sendMessage of truncated ct\nct.slice(0, 60) only\nDumps never reconstruct", depth=18)

    b.platform(520, 450, 440, 790, "C2 CHANNEL", LIVE, depth=22)
    q1 = b.card(548, 490, 384, 280, status="live", kicker="HTTPS", title="Implant → Worker",
                body="POST /exfil  {uuid, tag, ct,\nnonce, hmac}\nPOST /commands  ·  /config\nAES-256-GCM keyed from UUID", depth=18)
    q2 = b.card(548, 820, 384, 360, status="broken", kicker="LOSS", title="Exfil does not survive",
                body="Worker forwards ct.slice(0, 60)\nto Telegram. Ciphertext is not\nstored in KV.\nFull dump / creds / cookies\nnever reach the operator.", depth=18)

    b.pipe(a["e"], c["wpt"], color=LIVE)
    b.pipe(c["e"], d["wpt"], color=LIVE)
    b.pipe(p1["s"], p2["n"], color=CONTROL)
    b.pipe(p2["s"], p3["n"], color=BROKEN, broken=True)
    b.pipe(q1["s"], q2["n"], color=BROKEN, broken=True)
    # operator control → C2 https (straight horizontal into the card)
    b.pipe((p1["e"][0], p1["e"][1]), (q1["x"], p1["e"][1]), color=CONTROL)
    # implant threads → C2 (beacon / poll)
    rail = 430
    b.pipe(d["s"], (d["s"][0], rail), (q1["n"][0], rail), q1["n"], color=LIVE)
    b.note(848, 424, "beacon / poll", CYAN)
    return b


def boot_phases() -> Board:
    b = Board(1000, 1460, "FIG 02  ·  BOOT", "Boot sequence", "main.rs score gates — Phase 5 is unreachable")
    b.legend(36, 96)

    s = b.card(300, 150, 400, 120, status="control", kicker="START", title="main() + IMPLANT_UUID",
               body="UUID baked by build.rs — identity and AES seed", depth=18)
    sc = b.card(260, 310, 480, 140, status="live", kicker="SCORE", title="assess_environment()  0–100",
                body="Debugger / VM / RAM / idle / CPUID / Google GET", depth=18)

    k1 = b.card(40, 520, 280, 170, status="broken", kicker="> 80", title="Self-destruct",
                body="Wipe + wevtutil\nNo beacon. Process exits.", depth=18)
    k2 = b.card(360, 520, 280, 170, status="partial", kicker="> 60", title="Safe mode",
                body="Fingerprint thread only\nNo BYOVD / workers", depth=18)
    k3 = b.card(680, 520, 280, 170, status="live", kicker="≤ 60", title="Full stack",
                body="Stealth + BYOVD\nThen payload workers", depth=18)

    st = b.card(260, 780, 480, 140, status="partial", kicker="STEALTH", title="initialize() + EDR name list",
                body="Always returns true — DKOM / syscalls are stubs", depth=18)
    wk = b.card(260, 960, 480, 140, status="live", kicker="WORKERS", title="payload · persist · SOCKS · HVNC · clipper",
                body="Not started on a safe-mode boot", depth=18)
    lp = b.card(260, 1140, 480, 140, status="broken", kicker="C2 LOOP", title="run_command_loop()  →  !",
                body="Never returns. /sleep /status /self_destruct", depth=18)
    ph = b.card(260, 1320, 480, 100, status="ghost", kicker="PHASE 5", title="Join threads + wipe",
                body="Dead code after the diverging C2 loop", depth=18, hollow=True, chip="UNREACHABLE")

    b.pipe(s["s"], sc["n"], color=LIVE)

    rail = (sc["s"][1] + k2["n"][1]) / 2
    b.pipe(sc["s"], (sc["s"][0], rail), (k1["n"][0], rail), k1["n"], color=BROKEN)
    b.pipe((sc["s"][0], rail), k2["n"], color=PARTIAL)
    b.pipe((sc["s"][0], rail), (k3["n"][0], rail), k3["n"], color=LIVE)
    b.junction(sc["s"][0], rail, LIVE)

    rail2 = (k3["s"][1] + st["n"][1]) / 2
    b.pipe(k3["s"], (k3["s"][0], rail2), (st["n"][0], rail2), st["n"], color=LIVE)

    b.pipe(st["s"], wk["n"], color=LIVE)
    b.pipe(wk["s"], lp["n"], color=BROKEN, broken=True)
    b.pipe(lp["s"], ph["n"], color=GHOST, broken=True)
    return b


def c2_path() -> Board:
    b = Board(1000, 1280, "FIG 03  ·  C2 PATH", "Command-and-control path", "What is supposed to happen vs where it dies")
    b.legend(36, 96)

    a = b.card(220, 150, 560, 150, status="live", kicker="01  CRYPTO", title="GoldenGhost AES-256-GCM + HMAC",
               body="Key = SHA-256(IMPLANT_UUID). Encrypt + sign plaintext.", depth=20)
    r = b.card(220, 340, 560, 160, status="broken", kicker="02  RELAY URL", title="relay_url()",
               body="RELAY_URL_BYTES is read then discarded.\nAlways falls back to http://RELAY_URL_NOT_SET", depth=20)

    e = b.card(40, 560, 280, 180, status="live", kicker="EXFIL", title="POST /exfil",
               body="tag + ct + nonce\n+ hmac", depth=18)
    m = b.card(360, 560, 280, 180, status="partial", kicker="CMDS", title="POST /commands",
               body="Plaintext verb list\nNo HMAC check", depth=18)
    g = b.card(680, 560, 280, 180, status="live", kicker="CFG", title="POST /config",
               body="clipper_addresses\nreinfect_url", depth=18)

    w = b.card(220, 800, 560, 170, status="partial", kicker="03  WORKER", title="Cloudflare Worker",
               body="env.* used in service-worker scope → likely crash on load.\nNo wrangler.toml. No /beacon route.", depth=20)
    t = b.card(220, 1020, 560, 190, status="broken", kicker="04  TELEGRAM", title="sendMessage",
               body="Only ct.slice(0, 60) is forwarded. Ciphertext is not\nstored in KV. Credentials, dumps, and beacons\nare unrecoverable.", depth=20)

    b.pipe(a["s"], r["n"], color=LIVE)
    rail = (r["s"][1] + m["n"][1]) / 2
    b.pipe(r["s"], (r["s"][0], rail), color=PARTIAL, arrow=False)
    b.pipe((r["s"][0], rail), (e["n"][0], rail), e["n"], color=LIVE)
    b.pipe((r["s"][0], rail), m["n"], color=PARTIAL)
    b.pipe((r["s"][0], rail), (g["n"][0], rail), g["n"], color=LIVE)
    b.junction(r["s"][0], rail, PARTIAL)
    b.pipe(m["s"], w["n"], color=PARTIAL)
    b.pipe(w["s"], t["n"], color=BROKEN, broken=True)
    return b


def byovd_chain() -> Board:
    b = Board(1000, 1320, "FIG 04  ·  BYOVD", "BYOVD driver pool", "Named n-days vs what this tree actually ships")
    b.legend(36, 96)

    b.card(80, 145, 840, 125, status="partial", kicker="INPUT", title="get_pids_by_name(EDR list)",
           body="Exact image-name match. CrowdStrike.exe is often wrong.", depth=18)

    tiles = [
        (40, 300, "partial", "1  K7", "K7RKScan.sys", "CVE-2025-1055 / 52915\nIOCTL 0x830020C4\nPoCs often use 0x222018"),
        (360, 300, "partial", "2  BD", "BdApiUtil64.sys", "Bitdefender-family helper\nIOCTL 0x9C402440\nFile not in drivers/"),
        (680, 300, "partial", "3  TS", "truesight.sys", "TrueSight process-kill\nIOCTL 0x22E084\nCopy-pasted onto 3 drivers"),
        (40, 540, "partial", "4  TB", "ThrottleBlood.sys", "CVE-2025-7771 ThrottleStop\nPID-only body\nPhysmem R/W not implemented"),
        (360, 540, "broken", "5  ST", "STProcessMonitor.sys", "CVE-2025-70795 Safetica\nKit 0x22E084\nPublic 0xB822200C"),
        (680, 540, "partial", "6  WS", "wsftprm.sys", "Monitor helper\nSame IOCTL as TrueSight\nFile missing"),
        (40, 780, "broken", "7  RT", "RTCore64", "LOLDrivers classic\nGenericDriver String temps\nLikely compile error"),
        (360, 780, "broken", "8  CC", "capcom.sys", "Execute user fn in kernel\nNot a PID-kill interface\nSame IOCTL as RTCore64"),
        (680, 780, "ghost", "9  —", "empty slot", "No ninth driver\nin the pool"),
    ]
    for i, (x, y, st, k, title, body) in enumerate(tiles):
        b.card(x, y, 280, 205, status=st, kicker=k, title=title, body=body, depth=18, hollow=(i == 8))

    b.card(80, 1045, 840, 200, status="broken", kicker="TREE", title="drivers/ is empty",
           body="load_driver_bytes always returns None in this drop.\nEvery terminator above is unreachable without a packed .sys.", depth=18)
    b.note(80, 1030, "FALLBACK ORDER IS TOP → BOTTOM, LEFT → RIGHT", DIM)
    return b


def lsass_chain() -> Board:
    b = Board(1000, 1540, "FIG 05  ·  LSASS", "LSASS dump chain", "Fallback as written in lsass.rs — descending 3D stair")
    b.legend(36, 96)

    steps = [
        (180, 145, "partial", "1", "MiniDumpWriteDump", "Native dbghelp. Needs SeDebugPrivilege.\nCargo.toml missing dbghelp feature.\nPPL blocks on modern Win."),
        (260, 365, "broken", "2", "WDigest + procdump", "NativeBypassCredGuard.dll + procdump.exe\ntools/ empty → skip"),
        (180, 585, "broken", "3", "lsawhisper.exe", "tools/ empty → skip"),
        (260, 805, "broken", "4", "dumpguard_bof.exe", "tools/ empty → skip"),
        (180, 1025, "broken", "5", "RTCore64 then dump", "IOCTL process-kill is not a PPL bypass.\nWould crash the host if it worked."),
        (220, 1265, "broken", "THEN", "send_data(lsass_dump)", "Even a successful dump is truncated\nat the Worker. Operator never sees it."),
    ]
    prev = None
    for x, y, st, k, title, body in steps:
        h = 180 if k == "THEN" else 150
        card = b.card(x, y, 560, h, status=st, kicker=k, title=title, body=body, depth=20)
        if prev:
            mid = (prev["s"][1] + card["n"][1]) / 2
            b.pipe(prev["s"], (prev["s"][0], mid), (card["n"][0], mid), card["n"],
                   color=BROKEN if st != "partial" else PARTIAL,
                   broken=st != "partial")
        prev = card
    return b


def steal_pipeline() -> Board:
    b = Board(1000, 1180, "FIG 06  ·  THEFT", "Credential pipeline", "payload::run() — one shot, then C2")
    b.legend(36, 96)

    a = b.card(80, 155, 400, 210, status="live", kicker="A", title="Device fingerprint",
               body="hostname, OS, RAM,\nMachineGuid, user, UUID\n→ tag fingerprint", depth=20)
    bb = b.card(520, 155, 400, 210, status="partial", kicker="B", title="Browser passwords",
                body="Chrome/Edge/Brave/Opera/\nVivaldi Login Data + DPAPI.\nBroken on Chromium v80+\n(v10 AES-GCM).", depth=20)
    c = b.card(80, 430, 400, 210, status="broken", kicker="C", title="steal_all_browser_cookies()",
               body="Function exists.\nNever called from run().\nDead code in steal.rs.", depth=20)
    d = b.card(520, 430, 400, 210, status="partial", kicker="D", title="LSASS dump → base64",
               body="Temp ~xxxxxxxx.tmp\nthen tag lsass_dump\nSee FIG 05 for fallbacks.", depth=20)
    e = b.card(200, 720, 600, 230, status="broken", kicker="E", title="c2::send_data",
               body="Encrypts the full blob. Worker keeps 60 characters.\nOperator cannot reconstruct fingerprint, passwords,\ncookies, or the LSASS dump.", depth=20)

    b.pipe(a["e"], bb["wpt"], color=PARTIAL)
    b.pipe(a["s"], c["n"], color=BROKEN, broken=True)
    b.pipe(bb["s"], d["n"], color=PARTIAL)
    junc = (e["n"][0], e["n"][1] - 30)
    b.pipe(c["s"], (c["s"][0], junc[1]), junc, color=BROKEN, broken=True, arrow=False)
    b.pipe(d["s"], (d["s"][0], junc[1]), junc, color=BROKEN, broken=True, arrow=False)
    b.pipe(junc, e["n"], color=BROKEN, broken=True)
    b.junction(*junc, BROKEN)
    b.note(200, 980, "COOKIES ARE IMPLEMENTED AND NEVER WIRED. EXFIL IS ENCRYPTED THEN DISCARDED.", BROKEN)
    return b


def module_map() -> Board:
    b = Board(1000, 1280, "FIG 07  ·  MODULES", "Module map", "What is real code versus a stub in this drop")
    b.legend(36, 96, [("live", "LIVE"), ("partial", "PARTIAL"), ("broken", "STUB")])

    b.platform(40, 145, 440, 1070, "IMPLEMENTED ENOUGH TO READ", LIVE, depth=22)
    live = [
        (68, 185, "live", "CORE", "main · c2 · crypto · utils", "Boot, AES-GCM, HTTPS client,\nsandbox score, DPAPI helpers"),
        (68, 385, "partial", "THEFT", "steal · clipper · lsass attempt", "Passwords DPAPI-only.\nLSASS fallbacks mostly skip."),
        (68, 585, "live", "HOST", "persistence · proxy · self_destruct", "WMI / schtask / Run key.\nSOCKS5 CONNECT, localhost."),
        (68, 785, "live", "STEALTH", "stomp AMSI/ETW (real bytes)", "AmsiScanBuffer + EtwEventWrite\npatches. amsi.dll often unloaded."),
        (68, 985, "partial", "RELAY", "worker.js route shapes", "Routes exist. env.* likely\ncrashes the isolate on load."),
    ]
    for x, y, st, k, title, body in live:
        b.card(x, y, 384, 170, status=st, kicker=k, title=title, body=body, depth=16)

    b.platform(520, 145, 440, 1070, "STUB / UNUSED / EMPTY", BROKEN, depth=22)
    dead = [
        (548, 185, "broken", "SYSCALLS", "Tartarus / Halo TODO", "All inits return true.\nAllocators return null."),
        (548, 385, "broken", "DKOM", "All methods return false", "Needs kernel R/W this\nBYOVD path does not export."),
        (548, 585, "broken", "HVNC", "RFB handshake, no desktop", "Listens. Never paints a\nhidden framebuffer."),
        (548, 785, "broken", "NTLM", "Never called from main", "CVE-2025-33073 mislabeled\nas EFS. python3 on Windows."),
        (548, 985, "broken", "PAYLOADS", "drivers/ and tools/ empty", "BYOVD and LSASS fallbacks\nhave nothing to load."),
    ]
    for x, y, st, k, title, body in dead:
        b.card(x, y, 384, 170, status=st, kicker=k, title=title, body=body, depth=16)
    return b


def main() -> None:
    boards = {
        "architecture": architecture,
        "boot_phases": boot_phases,
        "c2_path": c2_path,
        "byovd_chain": byovd_chain,
        "lsass_chain": lsass_chain,
        "steal_pipeline": steal_pipeline,
        "module_map": module_map,
    }
    for name, fn in boards.items():
        png = fn().save(name)
        print(f"wrote {png.name}  {png.stat().st_size} bytes")


if __name__ == "__main__":
    main()
