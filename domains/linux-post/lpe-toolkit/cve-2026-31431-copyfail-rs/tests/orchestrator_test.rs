// TDD: tests written before src/orchestrator.rs.
//
// Pure-logic coverage: ranking, plan building, selection, fallback chain,
// exit-code mapping. Mock Vector impls panic on execute() via trait so we
// catch any code path that bypasses the closure-based runner.

use copyfail_rs::orchestrator::{self, AttemptOutcome, Confidence, RunReport, VectorMeta};
use copyfail_rs::{CopyFail, Error, Vector};
use core::cell::Cell;

// ----- Mocks --------------------------------------------------------------

struct MockVector {
    name: &'static str,
    applicable: Result<bool, Error>,
}

impl Vector for MockVector {
    fn name(&self) -> &'static str {
        self.name
    }
    fn applicable(&self) -> Result<bool, Error> {
        self.applicable
    }
    fn execute(&self, _: &mut CopyFail) -> Result<(), Error> {
        panic!(
            "MockVector::execute called via trait — orchestrator must use the closure-based runner"
        )
    }
}

fn mk(name: &'static str, applicable: Result<bool, Error>) -> MockVector {
    MockVector { name, applicable }
}

// ----- Static metadata ----------------------------------------------------

#[test]
fn stealth_ranks_match_spec() {
    assert_eq!(orchestrator::stealth_of("pam"), 3);
    assert_eq!(orchestrator::stealth_of("su"), 2);
    assert_eq!(orchestrator::stealth_of("passwd"), 1);
    assert_eq!(orchestrator::stealth_of("nonsense"), 0);
}

#[test]
fn confidence_labels_match_spec() {
    assert_eq!(orchestrator::confidence_of("pam"), Confidence::High);
    assert_eq!(orchestrator::confidence_of("su"), Confidence::High);
    assert_eq!(orchestrator::confidence_of("passwd"), Confidence::Medium);
}

#[test]
fn meta_for_known_vectors() {
    let m: VectorMeta = orchestrator::meta_for("pam").unwrap();
    assert_eq!(m.name, "pam");
    assert_eq!(m.stealth, 3);
    assert_eq!(m.confidence, Confidence::High);
    assert!(orchestrator::meta_for("nope").is_none());
}

// ----- Plan building (--vector list) --------------------------------------

#[test]
fn build_plan_reports_applicability_per_vector() {
    let pam = mk("pam", Ok(true));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(false));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];

    let plan = orchestrator::build_plan(vectors);
    assert_eq!(plan.len(), 3);

    // Plan rows are ordered by stealth DESC.
    assert_eq!(plan[0].name, "pam");
    assert_eq!(plan[1].name, "su");
    assert_eq!(plan[2].name, "passwd");

    assert!(plan[0].applicable);
    assert!(plan[1].applicable);
    assert!(!plan[2].applicable);
}

#[test]
fn build_plan_does_not_call_execute() {
    // MockVector panics on execute — this proves build_plan never invokes it.
    let pam = mk("pam", Ok(true));
    let su = mk("su", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su];
    let _ = orchestrator::build_plan(vectors);
}

#[test]
fn build_plan_marks_probe_errors_as_inapplicable() {
    let pam = mk("pam", Err(Error::Io));
    let vectors: &[&dyn Vector] = &[&pam];
    let plan = orchestrator::build_plan(vectors);
    assert!(!plan[0].applicable);
    assert!(plan[0].probe_error);
}

// ----- select_vector (--vector auto) --------------------------------------

#[test]
fn select_picks_pam_when_all_applicable() {
    let pam = mk("pam", Ok(true));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(true));
    let vectors: &[&dyn Vector] = &[&pw, &su, &pam]; // input order shuffled
    let chosen = orchestrator::select_vector(vectors).unwrap();
    assert_eq!(vectors[chosen].name(), "pam");
}

#[test]
fn select_picks_su_when_pam_not_applicable() {
    let pam = mk("pam", Ok(false));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];
    let chosen = orchestrator::select_vector(vectors).unwrap();
    assert_eq!(vectors[chosen].name(), "su");
}

#[test]
fn select_picks_passwd_when_pam_and_su_not_applicable() {
    let pam = mk("pam", Ok(false));
    let su = mk("su", Ok(false));
    let pw = mk("passwd", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];
    let chosen = orchestrator::select_vector(vectors).unwrap();
    assert_eq!(vectors[chosen].name(), "passwd");
}

#[test]
fn select_returns_none_when_nothing_applicable() {
    let pam = mk("pam", Ok(false));
    let su = mk("su", Ok(false));
    let pw = mk("passwd", Ok(false));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];
    assert!(orchestrator::select_vector(vectors).is_none());
}

#[test]
fn select_skips_probe_errors() {
    let pam = mk("pam", Err(Error::Io));
    let su = mk("su", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su];
    let chosen = orchestrator::select_vector(vectors).unwrap();
    assert_eq!(vectors[chosen].name(), "su");
}

// ----- try_all (--vector all) ---------------------------------------------

#[test]
fn try_all_stops_at_first_success() {
    let pam = mk("pam", Ok(true));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(true));
    let vectors: &[&dyn Vector] = &[&pw, &pam, &su]; // shuffled

    let log: Cell<u32> = Cell::new(0);
    let report: RunReport = orchestrator::try_all_with(vectors, |v| {
        log.set(log.get() + 1);
        if v.name() == "pam" {
            Ok(())
        } else {
            Err(Error::Io)
        }
    });
    assert_eq!(log.get(), 1, "execute should be called exactly once (pam)");
    assert_eq!(report.success, Some("pam"));
    assert_eq!(report.attempts.len(), 1);
    assert!(matches!(
        report.attempts[0].outcome,
        AttemptOutcome::ExecuteOk
    ));
}

#[test]
fn try_all_falls_through_when_first_execute_fails() {
    let pam = mk("pam", Ok(true));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];

    let report = orchestrator::try_all_with(vectors, |v| {
        if v.name() == "su" {
            Ok(())
        } else {
            Err(Error::Io)
        }
    });
    assert_eq!(report.success, Some("su"));
    assert_eq!(report.attempts.len(), 2);
    assert_eq!(report.attempts[0].name, "pam");
    assert!(matches!(
        report.attempts[0].outcome,
        AttemptOutcome::ExecuteErr
    ));
    assert_eq!(report.attempts[1].name, "su");
    assert!(matches!(
        report.attempts[1].outcome,
        AttemptOutcome::ExecuteOk
    ));
}

#[test]
fn try_all_returns_failure_when_all_execute_fail() {
    let pam = mk("pam", Ok(true));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];

    let report = orchestrator::try_all_with(vectors, |_| Err(Error::Io));
    assert!(report.success.is_none());
    assert_eq!(report.attempts.len(), 3);
    for a in report.attempts.iter() {
        assert!(matches!(a.outcome, AttemptOutcome::ExecuteErr));
    }
}

#[test]
fn try_all_skips_inapplicable_vectors() {
    let pam = mk("pam", Ok(false));
    let su = mk("su", Ok(true));
    let pw = mk("passwd", Ok(false));
    let vectors: &[&dyn Vector] = &[&pam, &su, &pw];

    let names: std::cell::RefCell<Vec<&'static str>> = std::cell::RefCell::new(Vec::new());
    let report = orchestrator::try_all_with(vectors, |v| {
        names.borrow_mut().push(v.name());
        Ok(())
    });
    assert_eq!(*names.borrow(), vec!["su"]);
    assert_eq!(report.success, Some("su"));
    // Skipped vectors are still recorded in attempts for the JSON chain.
    let skipped: Vec<&str> = report
        .attempts
        .iter()
        .filter(|a| matches!(a.outcome, AttemptOutcome::Skipped))
        .map(|a| a.name)
        .collect();
    assert!(skipped.contains(&"pam"));
}

#[test]
fn try_all_records_probe_errors_as_skipped() {
    let pam = mk("pam", Err(Error::Io));
    let su = mk("su", Ok(true));
    let vectors: &[&dyn Vector] = &[&pam, &su];

    let report = orchestrator::try_all_with(vectors, |_| Ok(()));
    assert_eq!(report.success, Some("su"));
    assert!(report
        .attempts
        .iter()
        .any(|a| a.name == "pam" && matches!(a.outcome, AttemptOutcome::ProbeError)));
}

#[test]
fn try_all_with_no_applicable_returns_none() {
    let pam = mk("pam", Ok(false));
    let su = mk("su", Ok(false));
    let vectors: &[&dyn Vector] = &[&pam, &su];

    let report = orchestrator::try_all_with(vectors, |_| {
        panic!("execute closure must not be called when nothing is applicable")
    });
    assert!(report.success.is_none());
}

// ----- Exit code mapping --------------------------------------------------

#[test]
fn exit_code_success_is_zero() {
    let report = RunReport {
        success: Some("pam"),
        attempts: heapless_vec(&[("pam", AttemptOutcome::ExecuteOk)]),
    };
    assert_eq!(orchestrator::exit_code_for(&report, false), 0);
}

#[test]
fn exit_code_all_failed_is_four() {
    let report = RunReport {
        success: None,
        attempts: heapless_vec(&[
            ("pam", AttemptOutcome::ExecuteErr),
            ("su", AttemptOutcome::ExecuteErr),
        ]),
    };
    assert_eq!(orchestrator::exit_code_for(&report, false), 4);
}

#[test]
fn exit_code_strict_with_prior_failure_is_partial() {
    let report = RunReport {
        success: Some("su"),
        attempts: heapless_vec(&[
            ("pam", AttemptOutcome::ExecuteErr),
            ("su", AttemptOutcome::ExecuteOk),
        ]),
    };
    assert_eq!(orchestrator::exit_code_for(&report, true), 5);
    // Without strict, success wins.
    assert_eq!(orchestrator::exit_code_for(&report, false), 0);
}

#[test]
fn exit_code_strict_with_no_failures_is_zero() {
    let report = RunReport {
        success: Some("pam"),
        attempts: heapless_vec(&[("pam", AttemptOutcome::ExecuteOk)]),
    };
    assert_eq!(orchestrator::exit_code_for(&report, true), 0);
}

#[test]
fn exit_code_inapplicable_only_is_four() {
    let report = RunReport {
        success: None,
        attempts: heapless_vec(&[("pam", AttemptOutcome::Skipped)]),
    };
    assert_eq!(orchestrator::exit_code_for(&report, false), 4);
}

// ----- helpers ------------------------------------------------------------

fn heapless_vec(
    rows: &[(&'static str, AttemptOutcome)],
) -> heapless::Vec<orchestrator::Attempt, 8> {
    let mut v = heapless::Vec::new();
    for (name, outcome) in rows {
        v.push(orchestrator::Attempt {
            name,
            outcome: *outcome,
        })
        .unwrap();
    }
    v
}
