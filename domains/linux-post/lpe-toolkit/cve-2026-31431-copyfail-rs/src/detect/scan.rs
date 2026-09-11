use crate::cache::read_pair;
use crate::Error;
use core::ffi::CStr;
use core::mem::MaybeUninit;
use heapless::{String, Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsKind {
    Ext4,
    Xfs,
    Btrfs,
    Overlayfs,
    Tmpfs,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileVerdict {
    Clean,
    Tampered,
    Skipped,
    Error,
}

pub const MAX_PATHS: usize = 64;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_NOTE: usize = 96;

pub struct ScanEntry {
    pub path: String<MAX_PATH_LEN>,
    pub fs: FsKind,
    pub verdict: FileVerdict,
    pub cache_hash: [u8; 32],
    pub disk_hash: [u8; 32],
    pub note: String<MAX_NOTE>,
}

pub struct ScanReport {
    pub entries: Vec<ScanEntry, MAX_PATHS>,
    pub elapsed_ms: u32,
}

impl ScanReport {
    pub fn count(&self, v: FileVerdict) -> usize {
        self.entries.iter().filter(|e| e.verdict == v).count()
    }
    pub fn any_tampered(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.verdict == FileVerdict::Tampered)
    }
}

pub fn default_paths() -> [&'static CStr; 20] {
    [
        c"/usr/bin/su",
        c"/usr/bin/sudo",
        c"/usr/bin/passwd",
        c"/usr/bin/mount",
        c"/usr/bin/umount",
        c"/usr/bin/chsh",
        c"/usr/bin/chfn",
        c"/usr/bin/newgrp",
        c"/usr/bin/gpasswd",
        c"/etc/passwd",
        c"/etc/group",
        c"/etc/sudoers",
        c"/etc/nsswitch.conf",
        c"/etc/pam.d/sudo",
        c"/etc/pam.d/su",
        c"/etc/pam.d/login",
        c"/etc/pam.d/common-auth",
        c"/etc/pam.d/system-auth",
        c"/etc/ld.so.preload",
        c"/etc/ssh/sshd_config",
    ]
}

// FS magic numbers per kernel uapi/linux/magic.h. Cast to i64 covers both
// glibc (signed __fsword_t) and musl (unsigned u64) statfs.f_type widths.
const EXT_MAGIC: i64 = 0xEF53;
const XFS_MAGIC: i64 = 0x5846_5342;
const BTRFS_MAGIC: i64 = 0x9123_683E;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const OVERLAYFS_MAGIC: i64 = 0x794C_7630;

fn classify(magic: i64) -> FsKind {
    match magic {
        EXT_MAGIC => FsKind::Ext4,
        XFS_MAGIC => FsKind::Xfs,
        BTRFS_MAGIC => FsKind::Btrfs,
        TMPFS_MAGIC => FsKind::Tmpfs,
        OVERLAYFS_MAGIC => FsKind::Overlayfs,
        _ => FsKind::Other,
    }
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
        Some(classify(m))
    }
}

pub fn run_scan(paths: &[&CStr]) -> Result<ScanReport, Error> {
    let mut entries: Vec<ScanEntry, MAX_PATHS> = Vec::new();

    for p in paths.iter().take(MAX_PATHS) {
        let mut entry = ScanEntry {
            path: String::new(),
            fs: FsKind::Other,
            verdict: FileVerdict::Error,
            cache_hash: [0u8; 32],
            disk_hash: [0u8; 32],
            note: String::new(),
        };
        let path_bytes = p.to_bytes();
        let take = core::cmp::min(path_bytes.len(), MAX_PATH_LEN - 1);
        if let Ok(s) = core::str::from_utf8(&path_bytes[..take]) {
            let _ = entry.path.push_str(s);
        }

        match fs_kind(p) {
            Some(kind) => {
                entry.fs = kind;
                match kind {
                    FsKind::Tmpfs => {
                        entry.verdict = FileVerdict::Skipped;
                        let _ = entry.note.push_str("tmpfs (no on-disk view)");
                    }
                    FsKind::Overlayfs => {
                        let _ = entry.note.push_str("overlayfs (best-effort fallback)");
                        match read_pair(p) {
                            Ok(hp) => {
                                entry.cache_hash = hp.cache;
                                entry.disk_hash = hp.disk;
                                entry.verdict = if hp.differ() {
                                    FileVerdict::Tampered
                                } else {
                                    FileVerdict::Clean
                                };
                            }
                            Err(_) => {
                                entry.verdict = FileVerdict::Error;
                                let _ = entry.note.push_str(" / read failed");
                            }
                        }
                    }
                    _ => match read_pair(p) {
                        Ok(hp) => {
                            entry.cache_hash = hp.cache;
                            entry.disk_hash = hp.disk;
                            entry.verdict = if hp.differ() {
                                FileVerdict::Tampered
                            } else {
                                FileVerdict::Clean
                            };
                        }
                        Err(_) => {
                            entry.verdict = FileVerdict::Error;
                            let _ = entry.note.push_str("read failed");
                        }
                    },
                }
            }
            None => {
                entry.verdict = FileVerdict::Error;
                let _ = entry
                    .note
                    .push_str("statfs failed (missing or no permission)");
            }
        }

        if entries.push(entry).is_err() {
            break;
        }
    }

    Ok(ScanReport {
        entries,
        elapsed_ms: 0,
    })
}
