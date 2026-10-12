#!/usr/bin/env python3

# +--------------------------------------------------------------------------+
# |                                                                          |
# |                       Veneficus Mini Worm Toolkit                        |
# |                                                                          |
# +--------------------------------------------------------------------------+

"""Build REVIEW.html + REVIEW.pdf from the obfuscated pseudo-code tree."""
from __future__ import annotations

import html
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MINI = ROOT / "Veneficus_Mini"
HTML_OUT = ROOT / "REVIEW.html"
PDF_OUT = ROOT / "REVIEW.pdf"

ORDER = [
    "NOTICE.txt",
    "project.toml",
    "build_id.pseudo",
    "notes/build.txt",
    "dropper/stage.pseudo",
    "relay/edge_relay.pseudo",
    "src/entry.pseudo",
    "src/host_profile.pseudo",
    "src/channel_crypto.pseudo",
    "src/control.pseudo",
    "src/driver_assist.pseudo",
    "src/stay.pseudo",
    "src/local_relay.pseudo",
    "src/retire.pseudo",
    "src/payload/mod.pseudo",
    "src/payload/harvest.pseudo",
    "src/payload/paste_swap.pseudo",
    "src/payload/secret_store_dump.pseudo",
    "src/stealth/mod.pseudo",
    "src/stealth/native_call.pseudo",
    "src/stealth/stack_cover.pseudo",
    "src/stealth/kernel_hide.pseudo",
    "src/stealth/inproc_patch.pseudo",
    "src/backdoor/mod.pseudo",
    "src/backdoor/hidden_view.pseudo",
    "src/lateral/mod.pseudo",
    "src/lateral/coerce.pseudo",
    "driver_pool/README.txt",
    "helpers/README.txt",
]

CSS = r"""
:root {
  --bg:#0c1018; --raised:#141b27; --panel:#1a2332; --border:#2a3a52;
  --text:#e8edf4; --muted:#8b9bb0; --accent:#e85d48; --cyan:#50bedc;
  --amber:#f5b446; --green:#48be82; --code:#0e1520;
  --font:"Segoe UI",-apple-system,BlinkMacSystemFont,sans-serif;
  --mono:ui-monospace,Menlo,Consolas,monospace;
}
* { box-sizing:border-box; }
html,body { margin:0; background:var(--bg); color:var(--text); font-family:var(--font); line-height:1.6; }
header.bar { padding:18px 28px; border-bottom:3px solid var(--accent); background:#121826; }
header.bar h1 { margin:0; font-size:1.35rem; }
header.bar .meta { color:var(--muted); font-size:13px; margin-top:4px; }
header.bar a { color:var(--cyan); text-decoration:none; }
main { max-width:980px; margin:0 auto; padding:28px 28px 80px; }
h2 { border-bottom:1px solid var(--border); padding-bottom:.35em; margin-top:2em; }
h3 { color:var(--cyan); }
h4 { color:var(--amber); margin-bottom:.3em; }
a { color:var(--cyan); }
.banner { width:100%; height:auto; border:1px solid var(--border); border-radius:8px; margin:12px 0 24px; }
.call { border-left:3px solid var(--accent); background:var(--raised); padding:.2em 1em; margin:1em 0; color:var(--muted); }
table { width:100%; border-collapse:collapse; font-size:.92em; background:var(--raised); margin:1em 0; }
th,td { border:1px solid var(--border); padding:8px 10px; text-align:left; vertical-align:top; }
th { background:#1e2a3d; color:var(--cyan); }
code,pre { font-family:var(--mono); font-size:.84em; }
:not(pre)>code { background:var(--code); border:1px solid var(--border); border-radius:4px; padding:0 .35em; color:#f0d4a8; }
pre { background:var(--code); border:1px solid var(--border); border-radius:10px; padding:14px 16px; overflow:auto; white-space:pre-wrap; word-break:break-word; }
.file { margin:1.6em 0 2em; }
.file h4 { font-family:var(--mono); }
.pill { display:inline-block; font-size:11px; padding:2px 8px; border-radius:999px; border:1px solid var(--border); color:var(--muted); margin-left:8px; }
.ok { color:var(--green); border-color:var(--green); }
.warn { color:var(--amber); border-color:var(--amber); }
.bad { color:var(--accent); border-color:var(--accent); }
nav.toc ul { columns:2; padding-left:1.2em; }
@media print {
  html,body { background:#0c1018; color:#e8edf4; font-size:10.5pt; }
  header.bar { position:static; }
  a { color:#7ec8e3; text-decoration:none; }
  pre,table,img { break-inside:avoid; }
}
@page {
  size:A4;
  margin:14mm 12mm 16mm 12mm;
  background:#0c1018;
  @bottom-center {
    content:"Veneficus Mini review  ·  " counter(page);
    color:#8b9bb0; font-size:8pt;
    font-family:"Segoe UI",Helvetica,Arial,sans-serif;
  }
}
"""

INTRO = r"""
<p class="call"><strong>Review packet — not a blog post.</strong> Veneficus Mini is
<strong>Full kill-chain malware 0day: Exploit, LPE, Pivot, C2, Persistence</strong>.
This directory is an obfuscated pseudo-code clone. Nothing here compiles or runs.
Identifiers that would make a useful YARA rule (function names, host artifacts,
relay paths, driver filenames, device paths, control codes, XOR keys, drop names)
have been replaced with aliases. Public CVE numbers are kept; vendor and
exploit nicknames are not.</p>

<h2 id="overview">What this is</h2>
<p>Veneficus Mini is <strong>Full kill-chain malware 0day: Exploit, LPE, Pivot, C2, Persistence</strong>
 — a Windows x64 kit sketched as a modular
agent: host scoring, concealment, a signed-driver helper pool, harvest,
three persistence paths, a loopback SOCKS-like relay, a blank remote-view
listener, and an HTTPS edge relay that forwards sealed blobs to a chat API.
This packet documents the <em>design</em>, including defects, without
reproducing the private implementation.</p>

<h2 id="arch">Intended flow</h2>
<ol>
<li><strong>Dropper</strong> — quiet the script engine, GET <code>/payload</code>,
write a throwaway-named image under the user temp directory, start it hidden.</li>
<li><strong>Score</strong> — debugger / hypervisor / hardware / idle / timing /
outbound checks. High → wipe and exit. Medium → quiet mode (card only).
Low → full.</li>
<li><strong>Conceal</strong> — native-call path (stub), stack-cover (imported,
unused), kernel hide (stub), in-process script-scan and telemetry patches
(real intent, bytes omitted).</li>
<li><strong>Driver pool</strong> — try signed-but-vulnerable kernel images as
a process-kill helper. Needs admin. Images are not in this packet.</li>
<li><strong>Harvest</strong> — host card, browser logins, OS secret-store dump,
clipboard swap. Cookie harvest exists and is never called.</li>
<li><strong>Hold</strong> — WMI pulse / on-logon task / machine Run key,
loopback relay, blank view listener, control poll with jitter.</li>
</ol>

<h2 id="cves">CVE references (vendor names withheld)</h2>
<table>
<tr><th>CVE</th><th>Role in the pool (alias)</th><th>Note</th></tr>
<tr><td>CVE-2025-1055 / CVE-2025-52915</td><td>AV kernel scanner</td><td>Process-kill control code</td></tr>
<tr><td>CVE-2024-51324</td><td>Third-party AV utility driver</td><td>Process-kill control code</td></tr>
<tr><td>CVE-2025-7771</td><td>CPU-tuning driver</td><td>Real primitive is physmem R/W, not pid-kill</td></tr>
<tr><td>CVE-2025-70795</td><td>DLP process-monitor driver</td><td>Process-kill control code</td></tr>
<tr><td>CVE-2019-16098</td><td>GPU overlay driver</td><td>Virtual R/W; private tree used the wrong code</td></tr>
<tr><td>CVE-2025-33073</td><td>SMB client (lateral sketch)</td><td>Cited, not implemented; dead code</td></tr>
</table>

<h2 id="status">Module status (as designed)</h2>
<table>
<tr><th>Module</th><th>File</th><th>Status</th></tr>
<tr><td>In-process patches</td><td>stealth/inproc_patch.pseudo</td><td><span class="pill ok">intent real</span></td></tr>
<tr><td>Host scoring</td><td>host_profile.pseudo</td><td><span class="pill ok">intent real</span></td></tr>
<tr><td>Persistence</td><td>stay.pseudo</td><td><span class="pill ok">intent real</span></td></tr>
<tr><td>SOCKS-like relay</td><td>local_relay.pseudo</td><td><span class="pill warn">loopback / gated</span></td></tr>
<tr><td>Channel crypto</td><td>channel_crypto.pseudo</td><td><span class="pill warn">AEAD ok, keying weak</span></td></tr>
<tr><td>Browser harvest</td><td>payload/harvest.pseudo</td><td><span class="pill warn">misses modern wrapping</span></td></tr>
<tr><td>Secret-store dump</td><td>payload/secret_store_dump.pseudo</td><td><span class="pill warn">PPL blocks native path</span></td></tr>
<tr><td>Clipboard swap</td><td>payload/paste_swap.pseudo</td><td><span class="pill warn">patterns too broad</span></td></tr>
<tr><td>Edge relay</td><td>relay/edge_relay.pseudo</td><td><span class="pill bad">would not load as written</span></td></tr>
<tr><td>URL embedding</td><td>control.pseudo</td><td><span class="pill bad">decoder defect</span></td></tr>
<tr><td>Native-call chain</td><td>stealth/native_call.pseudo</td><td><span class="pill bad">empty stubs</span></td></tr>
<tr><td>Kernel hide</td><td>stealth/kernel_hide.pseudo</td><td><span class="pill bad">always false</span></td></tr>
<tr><td>Hidden view</td><td>backdoor/hidden_view.pseudo</td><td><span class="pill bad">handshake only</span></td></tr>
<tr><td>Auth coerce</td><td>lateral/coerce.pseudo</td><td><span class="pill bad">dead code</span></td></tr>
<tr><td>Driver pool</td><td>driver_assist.pseudo</td><td><span class="pill bad">images absent; several slots wrong primitive</span></td></tr>
</table>

<h2 id="aliases">Alias surface (what a detector should not see here)</h2>
<ul>
<li>No private function names, env-var names, or type names.</li>
<li>No host artifacts (drop filename, task name, Run value, WMI filter names) from the private tree.</li>
<li>No relay path strings from the private tree; public paths are <code>/payload /inbox /queue /profile /ops /enroll /revoke /roster</code>.</li>
<li>No driver basenames, device paths, or control-code integers.</li>
<li>No XOR key, no patch bytes, no regexes.</li>
<li>Product name retained: <strong>Veneficus</strong>.</li>
</ul>

<h2 id="tree">Tree</h2>
<pre>
Veneficus_Mini/
├── NOTICE.txt
├── project.toml
├── build_id.pseudo
├── notes/build.txt
├── dropper/stage.pseudo
├── relay/edge_relay.pseudo
├── driver_pool/          (empty)
├── helpers/              (empty)
└── src/
    ├── entry.pseudo
    ├── host_profile.pseudo
    ├── channel_crypto.pseudo
    ├── control.pseudo
    ├── driver_assist.pseudo
    ├── stay.pseudo
    ├── local_relay.pseudo
    ├── retire.pseudo
    ├── payload/{mod,harvest,paste_swap,secret_store_dump}.pseudo
    ├── stealth/{mod,native_call,stack_cover,kernel_hide,inproc_patch}.pseudo
    ├── backdoor/{mod,hidden_view}.pseudo
    └── lateral/{mod,coerce}.pseudo
</pre>

<h2 id="files">Pseudo-code files</h2>
"""

def banner_data_uri() -> str:
    return ""

def collect_files() -> list[tuple[str, str]]:
    out = []
    seen = set()
    for rel in ORDER:
        p = MINI / rel
        if p.is_file():
            out.append((rel, p.read_text()))
            seen.add(rel)
    for p in sorted(MINI.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(MINI))
        if rel in seen:
            continue
        out.append((rel, p.read_text(errors="replace")))
    return out

def build_html() -> str:
    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'/>",
        "<title>Veneficus Mini - Full kill-chain malware 0day: Exploit, LPE, Pivot, C2, Persistence</title>",
        f"<style>{CSS}</style></head><body>",
        "<header class='bar'><h1>Veneficus Mini - Full kill-chain malware 0day: Exploit, LPE, Pivot, C2, Persistence</h1>",
        "public technical outline · not executable · 2026-09-03</div></header><main>",
        banner_data_uri(),
        INTRO,
        "<nav class='toc'><h3>Files</h3><ul>",
    ]
    files = collect_files()
    for rel, _ in files:
        anchor = rel.replace("/", "-").replace(".", "-")
        parts.append(f"<li><a href='#f-{html.escape(anchor)}'>{html.escape(rel)}</a></li>")
    parts.append("</ul></nav>")
    for rel, text in files:
        anchor = rel.replace("/", "-").replace(".", "-")
        parts.append(f"<section class='file' id='f-{html.escape(anchor)}'>")
        parts.append(f"<h4>{html.escape(rel)}</h4>")
        parts.append(f"<pre>{html.escape(text)}</pre></section>")
    parts.append(
        "<p class='call'>End of review packet. No blog post. No private identifiers.</p>"
    )
    parts.append("</main></body></html>")
    return "\n".join(parts)

def strip_pdf(path: Path) -> None:
    from pypdf import PdfReader, PdfWriter

    reader = PdfReader(str(path))
    writer = PdfWriter()
    writer.append(reader)
    try:
        writer.metadata = None
    except Exception:
        pass
    writer.add_metadata(
        {
            "/Title": "Veneficus Mini - Full kill-chain malware 0day: Exploit, LPE, Pivot, C2, Persistence",
            "/Author": "",
            "/Subject": "Public technical outline. Not executable.",
            "/Keywords": "",
            "/Creator": "",
        }
    )
    tmp = path.with_suffix(".stripped.pdf")
    with tmp.open("wb") as f:
        writer.write(f)
    tmp.replace(path)
    subprocess.run(["xattr", "-c", str(path)], check=False)

def main() -> None:
    html_doc = build_html()
    HTML_OUT.write_text(html_doc)
    print("wrote", HTML_OUT, "bytes", HTML_OUT.stat().st_size)
    subprocess.run(["weasyprint", str(HTML_OUT), str(PDF_OUT)], check=True)
    strip_pdf(PDF_OUT)
    print("wrote", PDF_OUT, "bytes", PDF_OUT.stat().st_size)

if __name__ == "__main__":
    main()
