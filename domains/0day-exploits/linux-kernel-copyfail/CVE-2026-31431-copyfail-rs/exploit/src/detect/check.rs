use crate::syscall::close_fd;
use crate::Error;
use core::ffi::CStr;
use heapless::String;

const READ_BUF: usize = 16 * 1024;
const KERNEL_MAX: usize = 64;
const MITIGATION_FILE_MAX: usize = 128;

pub struct CheckSources<'a> {
    pub proc_modules: &'a CStr,
    pub proc_crypto: &'a CStr,
    pub boot_config: &'a CStr,
    pub modprobe_d_dir: &'a CStr,
    pub osrelease: &'a CStr,
}

impl CheckSources<'static> {
    pub fn real() -> Self {
        CheckSources {
            proc_modules: c"/proc/modules",
            proc_crypto: c"/proc/crypto",
            boot_config: c"",
            modprobe_d_dir: c"/etc/modprobe.d",
            osrelease: c"/proc/sys/kernel/osrelease",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigState {
    Builtin,
    Module,
    NotInKernel,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Vulnerable,
    Mitigated,
    NotExploitable,
    Unknown,
}

pub struct CheckReport {
    pub kernel_release: String<KERNEL_MAX>,
    pub algif_aead_loaded: bool,
    pub authencesn_template: bool,
    pub config_aead: ConfigState,
    pub mitigation_present: bool,
    pub mitigation_file: String<MITIGATION_FILE_MAX>,
    pub verdict: Verdict,
    pub recommendation: &'static str,
    pub config_y_warning: bool,
}

pub fn run_check() -> Result<CheckReport, Error> {
    let real = CheckSources::real();
    let kernel_release = read_trimmed::<KERNEL_MAX>(real.osrelease)?;
    let mut boot_config_buf: String<256> = String::new();
    let _ = boot_config_buf.push_str("/boot/config-");
    let _ = boot_config_buf.push_str(kernel_release.as_str());
    let mut nul_buf = [0u8; 257];
    let bytes = boot_config_buf.as_bytes();
    if bytes.len() >= nul_buf.len() {
        return Err(Error::BufferFull);
    }
    nul_buf[..bytes.len()].copy_from_slice(bytes);
    let boot_config_cstr = match CStr::from_bytes_until_nul(&nul_buf) {
        Ok(c) => c,
        Err(_) => return Err(Error::ParseError),
    };
    let sources = CheckSources {
        proc_modules: real.proc_modules,
        proc_crypto: real.proc_crypto,
        boot_config: boot_config_cstr,
        modprobe_d_dir: real.modprobe_d_dir,
        osrelease: real.osrelease,
    };
    run_check_with_sources(&sources)
}

pub fn run_check_with_sources(sources: &CheckSources<'_>) -> Result<CheckReport, Error> {
    let mut report = CheckReport {
        kernel_release: String::new(),
        algif_aead_loaded: false,
        authencesn_template: false,
        config_aead: ConfigState::Unknown,
        mitigation_present: false,
        mitigation_file: String::new(),
        verdict: Verdict::Unknown,
        recommendation: "",
        config_y_warning: false,
    };

    if let Ok(s) = read_trimmed::<KERNEL_MAX>(sources.osrelease) {
        report.kernel_release = s;
    }

    let modules = read_file_buf(sources.proc_modules).unwrap_or(([0u8; READ_BUF], 0));
    report.algif_aead_loaded = scan_loaded_module(&modules.0[..modules.1]);

    let crypto = read_file_buf(sources.proc_crypto).unwrap_or(([0u8; READ_BUF], 0));
    report.authencesn_template = contains(&crypto.0[..crypto.1], b"authencesn(");

    report.config_aead = grep_config_streaming(sources.boot_config);

    let (mitig_present, mitig_file) = scan_modprobe_d(sources.modprobe_d_dir)?;
    report.mitigation_present = mitig_present;
    report.mitigation_file = mitig_file;

    let (verdict, warning, recommendation) = decide_verdict(&report);
    report.verdict = verdict;
    report.config_y_warning = warning;
    report.recommendation = recommendation;

    Ok(report)
}

fn decide_verdict(r: &CheckReport) -> (Verdict, bool, &'static str) {
    match r.config_aead {
        ConfigState::Builtin => {
            (Verdict::Vulnerable, true,
             "rebuild kernel with =m, apply seccomp filter, or update to a kernel including mainline commit a664bf3d603d")
        }
        ConfigState::NotInKernel => {
            (Verdict::NotExploitable, false,
             "kernel built without CRYPTO_USER_API_AEAD; this attack path is not present")
        }
        ConfigState::Module => {
            match (r.mitigation_present, r.algif_aead_loaded) {
                (true, false) => (Verdict::Mitigated, false,
                    "modprobe blacklist effective; algif_aead unloaded"),
                (true, true) => (Verdict::Vulnerable, false,
                    "blacklist installed but module still loaded; run `sudo rmmod algif_aead`"),
                (false, _) => (Verdict::Vulnerable, false,
                    "echo \"install algif_aead /bin/false\" > /etc/modprobe.d/disable-algif.conf && rmmod algif_aead"),
            }
        }
        ConfigState::Unknown => {
            // Conservative: if module is loaded or template present, treat as vuln.
            if r.algif_aead_loaded {
                (Verdict::Vulnerable, false,
                 "kernel config unreadable but algif_aead is loaded; apply mitigation")
            } else {
                (Verdict::Unknown, false,
                 "kernel config unreadable (try `grep CRYPTO_USER_API_AEAD /boot/config-$(uname -r)`)")
            }
        }
    }
}

fn scan_loaded_module(buf: &[u8]) -> bool {
    // /proc/modules format: "<name> <size> <use_count> ..."
    for line in buf.split(|&b| b == b'\n') {
        let mut parts = line.split(|&b| b == b' ');
        if let Some(name) = parts.next() {
            if name == b"algif_aead" {
                return true;
            }
        }
    }
    false
}

fn parse_config_line(line: &[u8]) -> Option<ConfigState> {
    let trimmed = trim_ws(line);
    if trimmed.starts_with(b"CONFIG_CRYPTO_USER_API_AEAD=") {
        let val = &trimmed[b"CONFIG_CRYPTO_USER_API_AEAD=".len()..];
        return Some(match val {
            b"y" => ConfigState::Builtin,
            b"m" => ConfigState::Module,
            b"n" => ConfigState::NotInKernel,
            _ => ConfigState::Unknown,
        });
    }
    if trimmed.starts_with(b"# CONFIG_CRYPTO_USER_API_AEAD is not set") {
        return Some(ConfigState::NotInKernel);
    }
    None
}

fn grep_config_streaming(path: &CStr) -> ConfigState {
    if path.to_bytes().is_empty() {
        return ConfigState::Unknown;
    }
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return ConfigState::Unknown;
        }
        let mut chunk = [0u8; 4096];
        let mut line_buf: heapless::Vec<u8, 256> = heapless::Vec::new();
        let mut found = ConfigState::Unknown;
        loop {
            let n = libc::read(fd, chunk.as_mut_ptr() as *mut _, chunk.len());
            if n <= 0 {
                break;
            }
            for &byte in &chunk[..n as usize] {
                if byte == b'\n' {
                    if let Some(cs) = parse_config_line(&line_buf) {
                        found = cs;
                        line_buf.clear();
                        // Found — short-circuit
                        close_fd(fd);
                        return found;
                    }
                    line_buf.clear();
                } else if line_buf.push(byte).is_err() {
                    line_buf.clear();
                }
            }
        }
        if let Some(cs) = parse_config_line(&line_buf) {
            found = cs;
        }
        close_fd(fd);
        found
    }
}

fn scan_modprobe_d(dir: &CStr) -> Result<(bool, String<MITIGATION_FILE_MAX>), Error> {
    let mut empty: String<MITIGATION_FILE_MAX> = String::new();
    unsafe {
        let dirp = libc::opendir(dir.as_ptr());
        if dirp.is_null() {
            return Ok((false, empty));
        }
        loop {
            let ent = libc::readdir(dirp);
            if ent.is_null() {
                break;
            }
            let name_ptr = (*ent).d_name.as_ptr();
            let name_cstr = CStr::from_ptr(name_ptr);
            let name = name_cstr.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            // Build full path: dir + "/" + name
            let dir_bytes = dir.to_bytes();
            let mut path: heapless::Vec<u8, 512> = heapless::Vec::new();
            if path.extend_from_slice(dir_bytes).is_err() {
                continue;
            }
            if path.push(b'/').is_err() {
                continue;
            }
            if path.extend_from_slice(name).is_err() {
                continue;
            }
            if path.push(0).is_err() {
                continue;
            }
            let cpath = match CStr::from_bytes_until_nul(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if let Ok((buf, len)) = read_file_buf(cpath) {
                if file_blacklists_algif(&buf[..len]) {
                    let _ = empty.push_str(core::str::from_utf8(name).unwrap_or(""));
                    libc::closedir(dirp);
                    return Ok((true, empty));
                }
            }
        }
        libc::closedir(dirp);
    }
    Ok((false, empty))
}

fn file_blacklists_algif(buf: &[u8]) -> bool {
    for line in buf.split(|&b| b == b'\n') {
        let trimmed = trim_ws(line);
        if trimmed.is_empty() || trimmed[0] == b'#' {
            continue;
        }
        // Match: "blacklist algif_aead" or "install algif_aead /bin/false" (or any install with algif_aead)
        if line_matches_token(trimmed, b"blacklist", b"algif_aead") {
            return true;
        }
        if line_matches_token(trimmed, b"install", b"algif_aead") {
            return true;
        }
    }
    false
}

fn line_matches_token(line: &[u8], directive: &[u8], target: &[u8]) -> bool {
    let mut parts = line.split(|&b| b == b' ' || b == b'\t');
    let p1 = match parts.next() {
        Some(s) => s,
        None => return false,
    };
    if p1 != directive {
        return false;
    }
    // Skip empty splits from multiple spaces
    for p in parts {
        if p.is_empty() {
            continue;
        }
        return p == target;
    }
    false
}

pub(crate) fn read_file_buf(path: &CStr) -> Result<([u8; READ_BUF], usize), Error> {
    if path.to_bytes().is_empty() {
        return Err(Error::OpenFailed);
    }
    let mut buf = [0u8; READ_BUF];
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY);
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
        Ok((buf, total))
    }
}

fn read_trimmed<const N: usize>(path: &CStr) -> Result<String<N>, Error> {
    let (buf, len) = read_file_buf(path)?;
    let mut out: String<N> = String::new();
    let trimmed = trim_ws(&buf[..len]);
    let s = core::str::from_utf8(trimmed).map_err(|_| Error::ParseError)?;
    out.push_str(s).map_err(|_| Error::BufferFull)?;
    Ok(out)
}

fn trim_ws(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end {
        let c = s[start];
        if c == b' ' || c == b'\t' {
            start += 1;
        } else {
            break;
        }
    }
    while end > start {
        let c = s[end - 1];
        if c == 0 || c == b'\n' || c == b'\r' || c == b' ' || c == b'\t' {
            end -= 1;
        } else {
            break;
        }
    }
    &s[start..end]
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
