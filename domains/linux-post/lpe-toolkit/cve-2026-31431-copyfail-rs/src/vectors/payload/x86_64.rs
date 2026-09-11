// Pre-built static ELF payload (see payloads/Makefile, payloads/payload-x86_64.S).
// Rebuild: `make -C payloads x86_64.bin`.
pub const PAYLOAD: &[u8] = include_bytes!("../../../payloads/x86_64.bin");
