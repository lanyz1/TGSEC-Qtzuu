use copyfail_rs::vectors::passwd::{find_uid_offset, find_username_for_uid, format_uid_4ascii};

#[test]
fn format_uid_4digit() {
    assert_eq!(format_uid_4ascii(1000), Some(*b"1000"));
    assert_eq!(format_uid_4ascii(1234), Some(*b"1234"));
    assert_eq!(format_uid_4ascii(9999), Some(*b"9999"));
}

#[test]
fn format_uid_rejects_out_of_range() {
    assert_eq!(format_uid_4ascii(0), None);
    assert_eq!(format_uid_4ascii(999), None);
    assert_eq!(format_uid_4ascii(10_000), None);
    assert_eq!(format_uid_4ascii(u32::MAX), None);
}

#[test]
fn passwd_offset_first_line() {
    let body = b"alice:x:1234:1234:Alice:/home/alice:/bin/bash\n";
    assert_eq!(find_uid_offset(body, b"alice"), Some(8));
}

#[test]
fn passwd_offset_no_trailing_newline() {
    let body = b"alice:x:1234:1234:Alice:/home/alice:/bin/bash";
    assert_eq!(find_uid_offset(body, b"alice"), Some(8));
}

#[test]
fn passwd_offset_user_in_middle() {
    let prefix = b"root:x:0:0:root:/root:/bin/bash\n";
    let body = b"root:x:0:0:root:/root:/bin/bash\nalice:x:1234:1234:Alice:/home/alice:/bin/bash\n";
    assert_eq!(find_uid_offset(body, b"alice"), Some(prefix.len() + 8));
}

#[test]
fn passwd_offset_user_not_found() {
    let body = b"root:x:0:0:root:/root:/bin/bash\n";
    assert_eq!(find_uid_offset(body, b"alice"), None);
}

#[test]
fn passwd_offset_username_prefix_must_not_match() {
    // searching for "alice" should NOT match "alicia"
    let alicia_line = b"alicia:x:1235:1235:Alicia:/home/alicia:/bin/bash\n";
    let mut body = Vec::new();
    body.extend_from_slice(alicia_line);
    body.extend_from_slice(b"alice:x:1234:1234:Alice:/home/alice:/bin/bash\n");
    assert_eq!(
        find_uid_offset(&body, b"alice"),
        Some(alicia_line.len() + 8)
    );
}

#[test]
fn passwd_offset_empty_username_rejected() {
    let body = b"alice:x:1234:1234:Alice:/home/alice:/bin/bash\n";
    assert_eq!(find_uid_offset(body, b""), None);
}

#[test]
fn lookup_username_by_uid() {
    let body = b"root:x:0:0:root:/root:/bin/bash\nalice:x:1234:1234:Alice:/home/alice:/bin/bash\n";
    assert_eq!(find_username_for_uid(body, 1234), Some(&b"alice"[..]));
}

#[test]
fn lookup_username_uid_not_found() {
    let body = b"alice:x:1234:1234:Alice:/home/alice:/bin/bash\n";
    assert_eq!(find_username_for_uid(body, 5555), None);
}

#[test]
fn lookup_username_rejects_3digit_uid() {
    let body = b"old:x:999:999:old:/home/old:/bin/bash\n";
    assert_eq!(find_username_for_uid(body, 999), None);
}
