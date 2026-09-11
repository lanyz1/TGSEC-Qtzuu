use crate::detect::check::read_file_buf;
use crate::syscall::close_fd;
use crate::Error;
use core::ffi::CStr;

const MAX_HOSTS: usize = 256;
const MAX_HOST_LEN: usize = 128;

pub fn run_hunt(hosts_file: &CStr) -> Result<(), Error> {
    let (buf, len) = read_file_buf(hosts_file)?;
    let mut total_hosts = 0usize;
    let mut vuln = 0usize;
    let mut mit = 0usize;
    let mut unk = 0usize;
    let mut errs = 0usize;

    write_stderr(b"copyfail-rs --hunt started\n");
    for line in buf[..len].split(|&b| b == b'\n').take(MAX_HOSTS) {
        let trimmed = trim_ws(line);
        if trimmed.is_empty() || trimmed[0] == b'#' {
            continue;
        }
        if trimmed.len() >= MAX_HOST_LEN {
            continue;
        }
        // Refuse hosts starting with '-': prevents ssh from interpreting the
        // host string as a flag (e.g. `-oProxyCommand=...`).
        if trimmed[0] == b'-' {
            write_stderr(b"--- ");
            write_stderr(trimmed);
            write_stderr(b" --- rejected: host begins with '-'\n");
            errs += 1;
            continue;
        }
        total_hosts += 1;

        let mut host_nul: heapless::Vec<u8, { MAX_HOST_LEN + 1 }> = heapless::Vec::new();
        if host_nul.extend_from_slice(trimmed).is_err() {
            continue;
        }
        if host_nul.push(0).is_err() {
            continue;
        }

        let mut output_buf = [0u8; 4096];
        match ssh_check(&host_nul, &mut output_buf) {
            Ok(out_len) => {
                let out = &output_buf[..out_len];
                write_stderr(b"--- ");
                write_stderr(trimmed);
                write_stderr(b" ---\n");
                write_stderr(out);
                if !out.ends_with(b"\n") {
                    write_stderr(b"\n");
                }
                if contains(out, b"\"verdict\":\"vulnerable\"") {
                    vuln += 1;
                } else if contains(out, b"\"verdict\":\"mitigated\"") {
                    mit += 1;
                } else {
                    unk += 1;
                }
            }
            Err(_) => {
                errs += 1;
                write_stderr(b"--- ");
                write_stderr(trimmed);
                write_stderr(b" --- ssh failed\n");
            }
        }
    }

    write_stderr(b"\n=== Hunt summary ===\n");
    write_num(b"  hosts:      ", total_hosts);
    write_num(b"  vulnerable: ", vuln);
    write_num(b"  mitigated:  ", mit);
    write_num(b"  unknown:    ", unk);
    write_num(b"  errors:     ", errs);
    Ok(())
}

fn ssh_check(host_nul: &[u8], output_buf: &mut [u8]) -> Result<usize, Error> {
    unsafe {
        let mut pipefd: [i32; 2] = [-1, -1];
        if libc::pipe(pipefd.as_mut_ptr()) < 0 {
            return Err(Error::Io);
        }

        let pid = libc::fork();
        if pid < 0 {
            close_fd(pipefd[0]);
            close_fd(pipefd[1]);
            return Err(Error::Io);
        }

        if pid == 0 {
            // Child: redirect stdout to write end of pipe; close other ends
            libc::close(pipefd[0]);
            libc::dup2(pipefd[1], 1);
            libc::close(pipefd[1]);

            // Build argv: ssh -o BatchMode=yes -o ConnectTimeout=10 <host> copyfail --mode detect --check --json
            let prog = c"ssh";
            let opt1 = c"-o";
            let opt1v = c"BatchMode=yes";
            let opt2 = c"-o";
            let opt2v = c"ConnectTimeout=10";
            let cmd1 = c"copyfail";
            let cmd2 = c"--mode";
            let cmd3 = c"detect";
            let cmd4 = c"--check";
            let cmd5 = c"--json";

            // `--` ends ssh option parsing; host is the next positional arg.
            // Combined with the leading-`-` rejection in run_hunt, this
            // prevents an attacker-controlled hosts file from injecting ssh
            // flags (e.g. `-oProxyCommand=...`) via the host field.
            let opt_end = c"--";
            let argv_full: [*const libc::c_char; 13] = [
                prog.as_ptr(),
                opt1.as_ptr(),
                opt1v.as_ptr(),
                opt2.as_ptr(),
                opt2v.as_ptr(),
                opt_end.as_ptr(),
                host_nul.as_ptr() as *const libc::c_char,
                cmd1.as_ptr(),
                cmd2.as_ptr(),
                cmd3.as_ptr(),
                cmd4.as_ptr(),
                cmd5.as_ptr(),
                core::ptr::null(),
            ];
            libc::execvp(prog.as_ptr(), argv_full.as_ptr());
            libc::_exit(127);
        }

        // Parent
        libc::close(pipefd[1]);
        let mut total = 0usize;
        loop {
            if total >= output_buf.len() {
                break;
            }
            let n = libc::read(
                pipefd[0],
                output_buf.as_mut_ptr().add(total) as *mut _,
                output_buf.len() - total,
            );
            if n <= 0 {
                break;
            }
            total += n as usize;
        }
        libc::close(pipefd[0]);
        let mut status: i32 = 0;
        libc::waitpid(pid, &mut status, 0);
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(Error::Io);
        }
        Ok(total)
    }
}

fn trim_ws(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
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

fn write_stderr(b: &[u8]) {
    unsafe {
        libc::write(2, b.as_ptr() as *const _, b.len());
    }
}

fn write_num(prefix: &[u8], n: usize) {
    write_stderr(prefix);
    let mut buf = [0u8; 32];
    let mut i = buf.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    write_stderr(&buf[i..]);
    write_stderr(b"\n");
}
