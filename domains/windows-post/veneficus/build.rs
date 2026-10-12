/*
** *********************************************************************
** *********************************************************************
**
**                              DISCLAIMER
**       For educational purposes only. 2026 All rights reversed.
**
** *********************************************************************
** *********************************************************************
*/

// build.rs — compile-time UUID baking.
// Each build produces a fresh random UUID so every binary is individually
// fingerprinted.  The UUID is embedded via env!("IMPLANT_UUID") and is the
// primary authentication token used by the Cloudflare Worker.
//
// It is also the AES-GCM key seed (SHA-256 of this UTF-8 string in c2.rs).
// Recoverable from the PE with strings — not a secret once the binary ships.
//
// BROKEN relative to C2: this script does NOT emit RELAY_URL_BYTES. c2.rs
// still would ignore that env var even if cargo set it.

fn main() {
    // Pull in random bytes via getrandom (available in build scripts without
    // adding it as a [dependencies] entry because build scripts run on the
    // host).
    let mut uuid = [0u8; 16];
    // Use /dev/urandom on Linux / CryptGenRandom on Windows.
    getrandom::getrandom(&mut uuid).expect("Failed to generate UUID bytes");
    // Format as hyphenated UUID v4.
    let uuid_str = format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes(uuid[0..4].try_into().unwrap()),
        u16::from_be_bytes(uuid[4..6].try_into().unwrap()),
        // Set version 4 bits
        (u16::from_be_bytes(uuid[6..8].try_into().unwrap()) & 0x0FFF) | 0x4000,
        // Set variant bits (10xx)
        (u16::from_be_bytes(uuid[8..10].try_into().unwrap()) & 0x3FFF) | 0x8000,
        {
            let mut n = 0u64;
            for b in &uuid[10..16] {
                n = (n << 8) | (*b as u64);
            }
            n
        }
    );

    println!("cargo:rustc-env=IMPLANT_UUID={}", uuid_str);
    println!("cargo:rerun-if-changed=build.rs");
}
