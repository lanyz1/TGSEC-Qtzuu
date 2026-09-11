use copyfail_rs::detect::scan::{run_scan, FileVerdict, FsKind};
use copyfail_rs::{check_kernel, CopyFail};
use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

fn target_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    let _ = fs::create_dir_all(&p);
    p
}

fn skip_if_not_vulnerable() -> bool {
    match check_kernel() {
        Ok(s) => {
            if !s.authencesn_template {
                eprintln!("SKIP: authencesn template not present in /proc/crypto");
                return true;
            }
            false
        }
        Err(_) => {
            eprintln!("SKIP: could not read /proc/crypto");
            true
        }
    }
}

#[test]
fn scan_clean_file_reports_clean() {
    if cfg!(not(target_os = "linux")) {
        return;
    }

    let path = target_dir().join("scan-clean.bin");
    fs::write(&path, vec![b'X'; 4096]).unwrap();

    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let paths: [&core::ffi::CStr; 1] = [cpath.as_c_str()];
    let report = run_scan(&paths).unwrap();

    assert_eq!(report.entries.len(), 1);
    let e = &report.entries[0];
    assert_eq!(e.verdict, FileVerdict::Clean, "note: {}", e.note.as_str());
    let _ = fs::remove_file(&path);
}

#[test]
fn scan_detects_cache_mutation() {
    if cfg!(not(target_os = "linux")) {
        return;
    }
    if skip_if_not_vulnerable() {
        return;
    }

    let path = target_dir().join("scan-tampered.bin");
    fs::write(&path, vec![b'A'; 4096]).unwrap();
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    f.sync_all().unwrap();
    drop(f);

    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: CopyFail::new failed: {:?}", e);
            return;
        }
    };

    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let target_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
    assert!(target_fd >= 0);

    let payload: Vec<u8> = b"BBBBCCCC".to_vec();
    if let Err(e) = prim.write_buffer(target_fd, &payload) {
        unsafe {
            libc::close(target_fd);
        }
        eprintln!(
            "SKIP: write_buffer returned {:?} (likely patched kernel)",
            e
        );
        let _ = fs::remove_file(&path);
        return;
    }
    unsafe {
        libc::close(target_fd);
    }

    let paths: [&core::ffi::CStr; 1] = [cpath.as_c_str()];
    let report = run_scan(&paths).unwrap();

    assert_eq!(report.entries.len(), 1);
    let e = &report.entries[0];
    assert_eq!(
        e.verdict,
        FileVerdict::Tampered,
        "expected Tampered after page-cache mutation, got {:?} (note: {})",
        e.verdict,
        e.note.as_str()
    );
    assert_ne!(e.cache_hash, e.disk_hash, "hashes should differ");

    let _ = fs::remove_file(&path);
}

#[test]
fn scan_unreadable_file_reports_error() {
    if cfg!(not(target_os = "linux")) {
        return;
    }

    let cpath = CString::new("/nonexistent/path/to/file").unwrap();
    let paths: [&core::ffi::CStr; 1] = [cpath.as_c_str()];
    let report = run_scan(&paths).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].verdict, FileVerdict::Error);
}

#[test]
fn scan_tmpfs_skips_with_note() {
    if cfg!(not(target_os = "linux")) {
        return;
    }

    // /run is tmpfs on most systems
    if !std::path::Path::new("/run").exists() {
        eprintln!("SKIP: /run not present");
        return;
    }

    let path = std::path::PathBuf::from("/run/copyfail-scan-test.bin");
    if fs::write(&path, b"test").is_err() {
        eprintln!("SKIP: cannot write to /run (no permission)");
        return;
    }

    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let paths: [&core::ffi::CStr; 1] = [cpath.as_c_str()];
    let report = run_scan(&paths).unwrap();

    assert_eq!(report.entries.len(), 1);
    let e = &report.entries[0];
    assert_eq!(e.fs, FsKind::Tmpfs);
    assert_eq!(e.verdict, FileVerdict::Skipped);

    let _ = fs::remove_file(&path);
}
