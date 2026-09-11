use crate::cache::read_pair;
use crate::detect::scan::FsKind;
use crate::syscall::close_fd;
use crate::Error;
use core::ffi::CStr;
use core::mem::MaybeUninit;
use heapless::{String, Vec};

pub const MAX_BASELINE_ENTRIES: usize = 256;
pub const MAX_PATH_LEN: usize = 256;
const READ_BUF: usize = 96 * 1024;

#[derive(Clone)]
pub struct BaselineEntry {
    pub path: String<MAX_PATH_LEN>,
    pub disk_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    DiskTampered,
    CacheTampered,
    BothChanged,
    Missing,
    SkippedTmpfs,
}

pub struct DiffEntry {
    pub path: String<MAX_PATH_LEN>,
    pub kind: DiffKind,
    pub baseline_disk_hash: [u8; 32],
    pub current_disk_hash: [u8; 32],
    pub current_cache_hash: [u8; 32],
}

pub fn write_baseline(out: &CStr, paths: &[&CStr]) -> Result<usize, Error> {
    unsafe {
        let fd = libc::open(
            out.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            return Err(Error::OpenFailed);
        }
        let mut count = 0usize;
        for p in paths.iter().take(MAX_BASELINE_ENTRIES) {
            let hp = match read_pair(p) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let mut line: heapless::Vec<u8, 384> = heapless::Vec::new();
            for byte in hp.disk.iter() {
                let _ = line.push(hex_high(*byte));
                let _ = line.push(hex_low(*byte));
            }
            let _ = line.push(b' ');
            let _ = line.extend_from_slice(p.to_bytes());
            let _ = line.push(b'\n');
            let n = libc::write(fd, line.as_ptr() as *const _, line.len());
            if n < 0 {
                close_fd(fd);
                return Err(Error::Io);
            }
            count += 1;
        }
        close_fd(fd);
        Ok(count)
    }
}

pub fn read_baseline(path: &CStr) -> Result<Vec<BaselineEntry, MAX_BASELINE_ENTRIES>, Error> {
    let mut buf = [0u8; READ_BUF];
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return Err(Error::OpenFailed);
        }
        let mut total = 0usize;
        loop {
            if total >= buf.len() {
                break;
            }
            let n = libc::read(fd, buf.as_mut_ptr().add(total) as *mut _, buf.len() - total);
            if n <= 0 {
                break;
            }
            total += n as usize;
        }
        close_fd(fd);

        let mut out: Vec<BaselineEntry, MAX_BASELINE_ENTRIES> = Vec::new();
        for line in buf[..total].split(|&b| b == b'\n') {
            if line.len() < 65 {
                continue;
            }
            // First 64 = hex, 65th must be space
            let hex_part = &line[..64];
            if line[64] != b' ' {
                continue;
            }
            let path_part = &line[65..];
            let mut entry = BaselineEntry {
                path: String::new(),
                disk_hash: [0u8; 32],
            };
            // Hex parse: any non-hex byte rejects the entire line. Silently
            // zeroing rejected bytes would forge a bogus hash that always
            // looks tampered.
            let mut hex_ok = true;
            for i in 0..32 {
                let hi = match unhex(hex_part[i * 2]) {
                    Some(v) => v,
                    None => {
                        hex_ok = false;
                        break;
                    }
                };
                let lo = match unhex(hex_part[i * 2 + 1]) {
                    Some(v) => v,
                    None => {
                        hex_ok = false;
                        break;
                    }
                };
                entry.disk_hash[i] = (hi << 4) | lo;
            }
            if !hex_ok {
                continue;
            }
            if let Ok(s) = core::str::from_utf8(path_part) {
                let _ = entry.path.push_str(s);
            } else {
                continue;
            }
            if out.push(entry).is_err() {
                break;
            }
        }
        Ok(out)
    }
}

pub fn diff_baseline(path: &CStr) -> Result<Vec<DiffEntry, MAX_BASELINE_ENTRIES>, Error> {
    let entries = read_baseline(path)?;
    let mut out: Vec<DiffEntry, MAX_BASELINE_ENTRIES> = Vec::new();
    for e in entries.iter() {
        let mut nul: heapless::Vec<u8, 257> = heapless::Vec::new();
        if nul.extend_from_slice(e.path.as_bytes()).is_err() {
            continue;
        }
        if nul.push(0).is_err() {
            continue;
        }
        let cstr = match CStr::from_bytes_until_nul(&nul) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut d = DiffEntry {
            path: String::new(),
            kind: DiffKind::Missing,
            baseline_disk_hash: e.disk_hash,
            current_disk_hash: [0u8; 32],
            current_cache_hash: [0u8; 32],
        };
        let _ = d.path.push_str(e.path.as_str());

        // tmpfs has no on-disk view: read_pair would return identical cache
        // and "disk" hashes (same buffered bytes), so cache mutation cannot
        // be detected. Skip with a labeled entry rather than silently report
        // Clean.
        if matches!(fs_kind(cstr), Some(FsKind::Tmpfs)) {
            d.kind = DiffKind::SkippedTmpfs;
            if out.push(d).is_err() {
                break;
            }
            continue;
        }
        match read_pair(cstr) {
            Ok(hp) => {
                d.current_disk_hash = hp.disk;
                d.current_cache_hash = hp.cache;
                let disk_diff = hp.disk != e.disk_hash;
                let cache_diff = hp.cache != e.disk_hash;
                match (disk_diff, cache_diff) {
                    (false, false) => continue,
                    (true, true) => d.kind = DiffKind::BothChanged,
                    (true, false) => d.kind = DiffKind::DiskTampered,
                    (false, true) => d.kind = DiffKind::CacheTampered,
                }
            }
            Err(_) => {
                d.kind = DiffKind::Missing;
            }
        }
        if out.push(d).is_err() {
            break;
        }
    }
    Ok(out)
}

fn fs_kind(path: &CStr) -> Option<FsKind> {
    unsafe {
        let mut sb: MaybeUninit<libc::statfs> = MaybeUninit::uninit();
        if libc::statfs(path.as_ptr(), sb.as_mut_ptr()) != 0 {
            return None;
        }
        let sb = sb.assume_init();
        #[allow(clippy::unnecessary_cast)]
        let m = sb.f_type as i64;
        const TMPFS_MAGIC: i64 = 0x0102_1994;
        Some(if m == TMPFS_MAGIC {
            FsKind::Tmpfs
        } else {
            FsKind::Other
        })
    }
}

fn hex_high(b: u8) -> u8 {
    hex_digit(b >> 4)
}
fn hex_low(b: u8) -> u8 {
    hex_digit(b & 0x0F)
}
fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}
fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
