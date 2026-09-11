use copyfail_rs::vectors::payload::PAYLOAD;

#[test]
fn payload_is_present() {
    // PAYLOAD is empty until the Makefile builds payloads/<arch>.bin and the
    // build pulls it in. This test fails on the empty stub and passes once
    // a real ELF is embedded.
    if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        assert!(
            !PAYLOAD.is_empty(),
            "payload not embedded — build payloads/<arch>.bin first"
        );
    }
}

#[test]
fn payload_starts_with_elf_magic() {
    if PAYLOAD.is_empty() {
        return; // covered by payload_is_present
    }
    assert_eq!(
        &PAYLOAD[..4],
        b"\x7fELF",
        "payload must start with ELF magic to be execve()-able"
    );
}

#[test]
fn payload_fits_splice_window() {
    // The splice primitive's MAX_BUF is the cap for one write_buffer call.
    // Payload must fit within it (current cap: 65536 bytes).
    if PAYLOAD.is_empty() {
        return;
    }
    assert!(
        PAYLOAD.len() <= 65536,
        "payload {} bytes exceeds splice window 65536",
        PAYLOAD.len()
    );
}

#[test]
fn payload_length_is_4byte_aligned() {
    if PAYLOAD.is_empty() {
        return;
    }
    assert_eq!(
        PAYLOAD.len() % 4,
        0,
        "payload {} bytes is not 4-byte aligned — pad payload-<arch>.S",
        PAYLOAD.len()
    );
}
