#![deny(
    unused_imports,
    unused_variables,
    unused_mut,
    unused_assignments,
    unused_parens,
    unused_unsafe,
    unused_macros,
    unused_attributes,
    unused_doc_comments,
    unused_must_use,
    unreachable_patterns,
    duplicate_macro_attributes
)]
// #17190: mechanical rustc lints are denied crate-wide; dead_code and
// private_interfaces remain ratcheted by userspace-dp/lint-baseline.tsv
// (make lint-rust-baseline) until their burn-down completes.

//! `fairness-eval` — consume iperf3 JSON + per-binding active flow count
//! samples, compute the contract gates from `docs/fairness-regimes.md`,
//! emit a verdict JSON. Used by `test/incus/fairness-harness.sh`.
//!
//! CLI shell only; the evaluator orchestration lives in `fairness_eval`.

use std::process::ExitCode;

#[path = "../fairness.rs"]
pub(crate) mod fairness;

#[path = "../fairness_eval/mod.rs"]
mod fairness_eval;

fn main() -> ExitCode {
    let args = fairness_eval::args::parse_args();
    let inputs = match fairness_eval::inputs::load(&args) {
        Ok(inputs) => inputs,
        Err(e) => {
            eprintln!("fairness-eval: {e}");
            return ExitCode::from(2);
        }
    };
    let report = match fairness_eval::run_evaluation(&args, inputs) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("fairness-eval: {e}");
            return ExitCode::from(2);
        }
    };
    fairness_eval::report::emit(&report, &args);
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
