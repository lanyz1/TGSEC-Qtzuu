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

// stealth/lacuna.rs — stack spoofing via the lacuna-rs crate.
//
// Thin wrappers around a third-party git dependency. init() only logs.
//
// BROKEN as a stealth engine: resolve_syscall_number / get_export_address /
// scan_ghost_regions are never called from the rest of the implant, so
// nothing is actually spoofed. Build depends on github.com/Karkas66/lacuna-rs
// remaining available.

use lacuna_rs::{nt::resolve_ssn, pe::pe_export, scan::scan_ghosts};
use log::info;

/// Log only. Does not install hooks or rewrite return addresses.
pub fn init() {
    info!("Lacuna stack-spoofing engine initialised.");
}

/// Resolve the syscall number for a native API by name. UNUSED.
pub fn resolve_syscall_number(name: &str) -> Option<u16> {
    resolve_ssn(name)
}

/// Get the virtual address of a DLL export. UNUSED.
pub fn get_export_address(dll: &str, function: &str) -> Option<*mut std::ffi::c_void> {
    pe_export(dll, function)
}

/// Scan `dll` for ghost (unbacked) memory regions that can host shellcode
/// without appearing as private memory to memory-scanning EDRs. UNUSED.
pub fn scan_ghost_regions(dll: &str) -> Vec<(usize, usize)> {
    scan_ghosts(dll)
        .into_iter()
        .map(|g| (g.start as usize, g.end as usize))
        .collect()
}
