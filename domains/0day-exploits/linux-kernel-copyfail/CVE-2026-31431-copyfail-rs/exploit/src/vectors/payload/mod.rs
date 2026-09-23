#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::PAYLOAD;

#[cfg(target_arch = "aarch64")]
pub use aarch64::PAYLOAD;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const PAYLOAD: &[u8] = &[];
