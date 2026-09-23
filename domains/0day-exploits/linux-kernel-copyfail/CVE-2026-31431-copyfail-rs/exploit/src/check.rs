use crate::syscall::close_fd;
use crate::Error;

const OSRELEASE_MAX: usize = 64;
const PROC_BUF: usize = 8192;

pub struct KernelStatus {
    pub osrelease: [u8; OSRELEASE_MAX],
    pub osrelease_len: usize,
    pub algif_aead_module: bool,
    pub authencesn_template: bool,
}

impl KernelStatus {
    pub fn osrelease_str(&self) -> &str {
        core::str::from_utf8(&self.osrelease[..self.osrelease_len]).unwrap_or("?")
    }
}

pub fn check_kernel() -> Result<KernelStatus, Error> {
    let mut status = KernelStatus {
        osrelease: [0u8; OSRELEASE_MAX],
        osrelease_len: 0,
        algif_aead_module: false,
        authencesn_template: false,
    };

    let or_bytes = read_proc_file(b"/proc/sys/kernel/osrelease\0")?;
    let or_trim = trim(&or_bytes);
    let n = core::cmp::min(or_trim.len(), OSRELEASE_MAX);
    status.osrelease[..n].copy_from_slice(&or_trim[..n]);
    status.osrelease_len = n;

    if let Ok(modules) = read_proc_file(b"/proc/modules\0") {
        status.algif_aead_module = contains(&modules, b"algif_aead");
    }

    if let Ok(crypto) = read_proc_file(b"/proc/crypto\0") {
        status.authencesn_template = contains(&crypto, b"authencesn(hmac(sha256),cbc(aes))");
    }

    Ok(status)
}

fn read_proc_file(path_nul: &[u8]) -> Result<[u8; PROC_BUF], Error> {
    let mut buf = [0u8; PROC_BUF];
    unsafe {
        let fd = libc::open(path_nul.as_ptr() as *const _, libc::O_RDONLY);
        if fd < 0 {
            return Err(Error::OpenFailed);
        }
        let mut total: usize = 0;
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
    }
    Ok(buf)
}

fn trim(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 {
        let c = s[end - 1];
        if c == 0 || c == b'\n' || c == b'\r' || c == b' ' {
            end -= 1;
        } else {
            break;
        }
    }
    &s[..end]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let last = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}
