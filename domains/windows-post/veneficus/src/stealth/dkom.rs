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

// stealth/dkom.rs — DKOM (Direct Kernel Object Manipulation) process hiding.
//
// Intended: unlink this PID from EPROCESS lists / unregister EDR callbacks.
// All of that needs a kernel read/write primitive. BYOVD in this tree only
// sends a "kill PID" IOCTL and does not export R/W.
//
// BROKEN: every method logs and returns false. hide_process always fails.
// External tools HollowGhost.exe / STFUEDR.exe mentioned in comments are
// not in the tree and are not invoked.

use log::{info, error};

/// Hide `pid` from user-mode process enumeration via DKOM fallback chain.
/// Always returns false in this tree.
pub fn hide_process(pid: u32) -> bool {
    info!("Hiding PID {} via DKOM fallback chain…", pid);
    if hide_via_eprocess_unlink(pid) { return true; }
    if hide_via_pspchained_enumeration(pid) { return true; }
    if manipulate_edr_callbacks() { return hide_via_eprocess_unlink(pid); }
    error!("All DKOM methods failed for PID {}.", pid);
    false
}

/// EPROCESS doubly-linked list unlink — requires kernel write primitive.
/// STUB: returns false until kernel write capability is confirmed available.
fn hide_via_eprocess_unlink(pid: u32) -> bool {
    info!("EPROCESS unlink for PID {}.", pid);
    // Stub: real impl writes to EPROCESS.ActiveProcessLinks via kernel primitive.
    // Returns false until kernel write capability is confirmed available.
    false
}

/// PspChainedenumeration hiding — alternative DKOM path. STUB.
fn hide_via_pspchained_enumeration(pid: u32) -> bool {
    info!("PspChained enumeration patch for PID {}.", pid);
    false
}

/// Unregister EDR kernel callbacks (PsSetCreateProcessNotifyRoutine, etc.)
/// so the EDR stops receiving create/terminate events. STUB.
fn manipulate_edr_callbacks() -> bool {
    info!("Attempting EDR callback unregistration…");
    // Real impl: enumerate PspCreateProcessNotifyRoutine array, null out
    // entries belonging to the EDR driver.  Requires kernel R/W.
    false
}
