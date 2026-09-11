// S5: --i-have-authorization gate removed; --vector defaults to auto on --mode exploit.
//
// Integration tests that spawn the compiled binary. They prove three contracts:
//
//   1. `--mode exploit` with no other flags is accepted (vector defaulted to auto).
//      We use `--dry-run` to short-circuit before any real execution path so the
//      test is host-independent: dry-run returns 0 when vector resolves to a
//      concrete choice, and 2 when vector is None (the pre-S5 behavior).
//
//   2. `--help` output contains no mention of the retired authorization flag.
//
//   3. `--mode exploit --vector list` does not refuse for missing authorization
//      (regression guard against the pre-S5 exit 2 path being re-introduced).

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_copyfail")
}

#[test]
fn exploit_mode_with_no_vector_flag_defaults_to_auto() {
    // --dry-run path is reached only if vector != None. Pre-S5 this would have
    // hit "REFUSED" (exit 2) before dry-run, AND parse would have set vector
    // to None, also forcing exit 2 from the "requires --vector" branch.
    let out = Command::new(bin())
        .args(["--mode", "exploit", "--dry-run"])
        .output()
        .expect("spawn copyfail");
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 (dry-run executed because vector defaulted to auto). \
         stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn help_output_omits_retired_authorization_flag() {
    let out = Command::new(bin())
        .arg("--help")
        .output()
        .expect("spawn copyfail");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("i-have-authorization"),
        "--help still mentions the retired --i-have-authorization flag:\n{combined}"
    );
}

#[test]
fn help_wins_regardless_of_argument_order() {
    // Regression guard: pre-fix, `--help --mode exploit` would set Cmd::Help
    // then Cmd::Exploit, the post-loop tail would default --vector to auto,
    // and dispatch would run the exploit path instead of printing help.
    let out = Command::new(bin())
        .args(["--help", "--mode", "exploit"])
        .output()
        .expect("spawn copyfail");
    assert_eq!(out.status.code(), Some(0));
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("Usage:"),
        "expected help banner, got:\n{combined}"
    );
}

#[test]
fn vector_list_does_not_refuse_for_missing_authorization() {
    let out = Command::new(bin())
        .args(["--mode", "exploit", "--vector", "list"])
        .output()
        .expect("spawn copyfail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("REFUSED"),
        "--vector list path emitted REFUSED (auth gate must be gone):\n{stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "--vector list should always exit 0. stderr: {stderr}"
    );
}
