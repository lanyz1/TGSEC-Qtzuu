use crate::syscall::{close_fd, errno, last};
use crate::Error;
use core::ffi::CStr;
use sha2::{Digest, Sha256};

#[repr(C, align(4096))]
struct AlignedBuf([u8; 4096]);

pub struct HashPair {
    pub cache: [u8; 32],
    pub disk: [u8; 32],
}

impl HashPair {
    pub fn differ(&self) -> bool {
        self.cache != self.disk
    }
}

pub fn read_pair(path: &CStr) -> Result<HashPair, Error> {
    let cache = hash_via_cache(path)?;
    let disk = hash_via_disk(path)?;
    Ok(HashPair { cache, disk })
}

fn hash_via_cache(path: &CStr) -> Result<[u8; 32], Error> {
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return Err(Error::OpenFailed);
        }
        let h = stream_hash(fd)?;
        close_fd(fd);
        Ok(h)
    }
}

fn hash_via_disk(path: &CStr) -> Result<[u8; 32], Error> {
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECT);
        if fd >= 0 {
            let h = stream_hash_aligned(fd)?;
            close_fd(fd);
            return Ok(h);
        }
        if errno() != libc::EINVAL {
            return Err(Error::OpenFailed);
        }
        let fd2 = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd2 < 0 {
            return Err(Error::OpenFailed);
        }
        let _ = libc::posix_fadvise(fd2, 0, 0, libc::POSIX_FADV_DONTNEED);
        let h = stream_hash(fd2)?;
        close_fd(fd2);
        Ok(h)
    }
}

unsafe fn stream_hash(fd: i32) -> Result<[u8; 32], Error> {
    let mut buf = [0u8; 4096];
    let mut hasher = Sha256::new();
    loop {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len());
        if n < 0 {
            return Err(last());
        }
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n as usize]);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    Ok(arr)
}

unsafe fn stream_hash_aligned(fd: i32) -> Result<[u8; 32], Error> {
    let mut buf = AlignedBuf([0u8; 4096]);
    let mut hasher = Sha256::new();
    loop {
        let n = libc::read(fd, buf.0.as_mut_ptr() as *mut _, buf.0.len());
        if n < 0 {
            return Err(last());
        }
        if n == 0 {
            break;
        }
        hasher.update(&buf.0[..n as usize]);
    }
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    Ok(arr)
}
