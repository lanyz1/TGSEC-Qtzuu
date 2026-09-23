use crate::detect::output::{scan_human, OUT_BUF};
use crate::detect::scan::run_scan;
use crate::Error;
use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, Ordering};
use heapless::String;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = core::mem::zeroed();
        sa.sa_sigaction = handle_sigterm as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, core::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, core::ptr::null_mut());
    }
}

pub fn run_watch(paths: &[&CStr], interval_secs: u32) -> Result<(), Error> {
    install_signal_handlers();
    write_stderr(b"copyfail-rs --watch started (SIGTERM to stop)\n");

    while !STOP.load(Ordering::SeqCst) {
        let report = run_scan(paths)?;
        let mut buf: String<OUT_BUF> = String::new();
        scan_human(&report, &mut buf);
        write_stderr(buf.as_bytes());
        if report.any_tampered() {
            write_stderr(b"!!! TAMPERING DETECTED -- see entries above\n");
        }

        let mut remaining = interval_secs;
        while remaining > 0 && !STOP.load(Ordering::SeqCst) {
            unsafe {
                libc::sleep(1);
            }
            remaining -= 1;
        }
    }

    write_stderr(b"copyfail-rs --watch shutting down cleanly\n");
    Ok(())
}

fn write_stderr(b: &[u8]) {
    unsafe {
        libc::write(2, b.as_ptr() as *const _, b.len());
    }
}
