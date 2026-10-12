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

// stealth/syscalls.rs — direct/indirect syscall bypass chain.
//
// Intended: pick a method at init, then allocate memory via that path.
//
// BROKEN:
//   - All four bypass inits are `/* TODO */ true`. First one "wins" (Tartarus).
//   - allocate_* for those methods return null; only allocate_std is real.
//   - direct_allocate() is never called from the rest of the crate.
//   - callghost crate is in Cargo.toml but unused here.

use log::{info, warn};
use std::sync::atomic::{AtomicU8, Ordering};
use std::ffi::c_void;

// ── Syscall method discriminant ──────────────────────────────────────────────
const M_NONE:     u8 = 0;
const M_TARTARUS: u8 = 1;
const M_HALOS:    u8 = 2;
const M_UNHOOK:   u8 = 3;
const M_INDIRECT: u8 = 4;
const M_STD:      u8 = 5;

static SYSCALL_METHOD: AtomicU8 = AtomicU8::new(M_NONE);

fn method() -> u8 { SYSCALL_METHOD.load(Ordering::Acquire) }

/// Probe bypasses in order; store the first that returns true.
/// Because stubs return true, this always stores Tartarus and returns.
pub fn init() {
    info!("Initialising syscall fallback chain…");
    if init_tartarus_gate()  { SYSCALL_METHOD.store(M_TARTARUS, Ordering::Release); info!("Tartarus Gate active."); return; }
    if init_halos_gate()     { SYSCALL_METHOD.store(M_HALOS,    Ordering::Release); info!("Halo's Gate active."); return; }
    if init_ntdll_unhook()   { SYSCALL_METHOD.store(M_UNHOOK,   Ordering::Release); info!("ntdll unhook active."); return; }
    if init_indirect()       { SYSCALL_METHOD.store(M_INDIRECT,  Ordering::Release); info!("Indirect syscalls active."); return; }
    SYSCALL_METHOD.store(M_STD, Ordering::Release);
    warn!("All syscall bypasses failed — using standard WinAPI.");
}

// ── Bypass initialisers ──────────────────────────────────────────────────────
// Each returns true on success.  In a full implementation these would:
//   Tartarus: walk ntdll exports, detect hooks by comparing first bytes,
//             use adjacent unhookable stub.
//   Halos:    same but scan neighbouring exports when local stub is also
//             hooked.
//   Unhook:   map a clean ntdll from disk, overwrite .text in memory.
//   Indirect: find `syscall; ret` gadget inside ntdll .text.
//
// STUBS: all return true without doing that work.

fn init_tartarus_gate()  -> bool { /* TODO: real impl */ true }
fn init_halos_gate()     -> bool { /* TODO: real impl */ true }
fn init_ntdll_unhook()   -> bool { /* TODO: real impl */ true }
fn init_indirect()       -> bool { /* TODO: real impl */ true }

// ── Memory allocation via selected syscall path ───────────────────────────────

/// Dispatch VirtualAlloc-equivalent by stored method. UNUSED by callers.
pub fn direct_allocate(size: usize) -> *mut c_void {
    match method() {
        M_TARTARUS => allocate_tartarus(size),
        M_HALOS    => allocate_halos(size),
        M_UNHOOK   => allocate_unhook(size),
        M_INDIRECT => allocate_indirect(size),
        _          => allocate_std(size),
    }
}

fn allocate_tartarus(_size: usize) -> *mut c_void { std::ptr::null_mut() /* TODO */ }
fn allocate_halos(_size: usize)    -> *mut c_void { std::ptr::null_mut() /* TODO */ }
fn allocate_unhook(_size: usize)   -> *mut c_void { std::ptr::null_mut() /* TODO */ }
fn allocate_indirect(_size: usize) -> *mut c_void { std::ptr::null_mut() /* TODO */ }

/// Real path: VirtualAlloc COMMIT|RESERVE, PAGE_READWRITE (not RX).
fn allocate_std(size: usize) -> *mut c_void {
    unsafe {
        winapi::um::memoryapi::VirtualAlloc(
            std::ptr::null_mut(), size,
            0x3000,  // MEM_COMMIT | MEM_RESERVE
            0x04,    // PAGE_READWRITE
        )
    }
}
