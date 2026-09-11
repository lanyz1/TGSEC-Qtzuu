use copyfail_rs::detect::baseline::{diff_baseline, write_baseline};
use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

fn target_dir(sub: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    p.push("test-baseline");
    p.push(sub);
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn baseline_roundtrip_clean_no_diff() {
    if cfg!(not(target_os = "linux")) {
        return;
    }
    let dir = target_dir("clean_roundtrip");
    let f1 = dir.join("a.bin");
    let f2 = dir.join("b.bin");
    fs::write(&f1, vec![b'A'; 1024]).unwrap();
    fs::write(&f2, vec![b'B'; 1024]).unwrap();
    let baseline = dir.join("baseline.dat");

    let cf1 = CString::new(f1.as_os_str().as_encoded_bytes()).unwrap();
    let cf2 = CString::new(f2.as_os_str().as_encoded_bytes()).unwrap();
    let cb = CString::new(baseline.as_os_str().as_encoded_bytes()).unwrap();
    let paths: [&core::ffi::CStr; 2] = [cf1.as_c_str(), cf2.as_c_str()];

    let n = write_baseline(cb.as_c_str(), &paths).expect("write_baseline");
    assert_eq!(n, 2);
    assert!(baseline.exists(), "baseline file must be created");

    let diffs = diff_baseline(cb.as_c_str()).expect("diff");
    assert_eq!(diffs.len(), 0, "no diff expected on unchanged files");
}

#[test]
fn baseline_detects_disk_change() {
    if cfg!(not(target_os = "linux")) {
        return;
    }
    let dir = target_dir("disk_change");
    let f = dir.join("file.bin");
    fs::write(&f, vec![b'X'; 1024]).unwrap();
    let baseline = dir.join("baseline.dat");
    let cf = CString::new(f.as_os_str().as_encoded_bytes()).unwrap();
    let cb = CString::new(baseline.as_os_str().as_encoded_bytes()).unwrap();
    let paths: [&core::ffi::CStr; 1] = [cf.as_c_str()];

    write_baseline(cb.as_c_str(), &paths).unwrap();

    // Mutate on disk
    fs::write(&f, vec![b'Y'; 1024]).unwrap();
    // Sync + drop cache so disk read sees fresh content
    let fd = std::fs::File::open(&f).unwrap();
    fd.sync_all().unwrap();
    drop(fd);

    let diffs = diff_baseline(cb.as_c_str()).expect("diff");
    assert_eq!(diffs.len(), 1, "expected one tampered entry");
}
