#![no_std]
#![allow(clippy::missing_safety_doc)]

pub mod alg;
pub mod cache;
pub mod check;
pub mod detect;
pub mod orchestrator;
pub mod post_exploit;
pub mod splice;
pub mod syscall;
pub mod vectors;

pub use cache::{read_pair, HashPair};
pub use check::{check_kernel, KernelStatus};
pub use splice::CopyFail;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Syscall(i32),
    AlgUnavailable,
    KernelNotVulnerable,
    ParseError,
    NotImplemented,
    InvalidArgument(&'static str),
    OpenFailed,
    Io,
    BufferFull,
}

#[derive(Debug, Clone, Copy)]
pub enum DetectionResult {
    Clean,
    Tampered {
        cache_hash: [u8; 32],
        disk_hash: [u8; 32],
    },
    Vulnerable {
        reason: VulnReason,
    },
    Mitigated {
        method: MitigationMethod,
    },
    Unknown {
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum VulnReason {
    KernelInRange,
    ModuleAvailable,
    ConfigBuiltIn,
    TemplateRegistered,
}

#[derive(Debug, Clone, Copy)]
pub enum MitigationMethod {
    ModprobeBlacklist,
    KernelPatch,
    SeccompFilter,
    ApparmorProfile,
}

pub trait Vector {
    fn name(&self) -> &'static str;
    fn applicable(&self) -> Result<bool, Error>;
    fn execute(&self, primitive: &mut CopyFail) -> Result<(), Error>;
}

pub trait Detector {
    fn name(&self) -> &'static str;
    fn check(&self) -> Result<DetectionResult, Error>;
}
