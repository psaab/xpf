//! CoS doc/code drift guard (#1205).
//!
//! Fails if known-stale scheduler policy references reappear in
//! active CoS source. Each entry in `STALE_PATTERNS` carries a
//! one-line rationale describing why that exact substring is wrong
//! against the current code state.
//!
//! Add a new entry only when a fairness/MQFQ change makes a prior
//! assertion stale; never silence by suppressing the check.
//!
//! Whitelist: lines marked `// drift-check: historical` are tolerated
//! verbatim (e.g., intentional retrospective text comparing pre- and
//! post-refactor state).
//!
//! Companion of #1210 (which scrubbed the existing drift). This test
//! must pass on master once #1210 has merged; until then the test
//! will report violations that #1210 will remove.
//!
//! Reviewed PLAN-READY (Codex round-2 task-mou73ban-paip6b
//! PLAN-NEEDS-MINOR addressed in v3; Gemini round-2
//! task-mou73zm2-ikjmii PLAN-READY in v2).

use std::fs;
use std::path::{Path, PathBuf};

/// Substring patterns that must NOT appear on a non-historical line
/// in any file under `SCAN_DIRS`. Each entry is `(pattern, rationale)`.
///
/// Why these specific phrases:
/// - `COS_FLOW_FAIR_BUCKETS = 1024`: the constant has been 4096 since
///   #785 Phase 3.
/// - `flow_fair = queue.exact && !shared_exact`: the policy gate was
///   lifted in #785 Phase 3; current code is `flow_fair = queue.exact`
///   for both owner-local AND shared_exact.
/// - `shared_exact queues are NOT on the flow-fair path`: stale claim
///   that contradicts current promotion in `admission.rs:478-486`.
/// - `single-FIFO-per-worker drain`: stale; shared_exact runs MQFQ
///   with cross-worker V_min sync (#917).
/// - `1024-bucket bookkeeping` / `all 1024 SFQ buckets` /
///   `bounded by 1024 worst case` / `1024 active buckets`: prose
///   variants of the bucket-count drift.
const STALE_PATTERNS: &[(&str, &str)] = &[
    ("COS_FLOW_FAIR_BUCKETS = 1024", "value is 4096 since #785 Phase 3"),
    (
        "flow_fair = queue.exact && !shared_exact",
        "policy is `flow_fair = queue.exact` since #785 Phase 3",
    ),
    (
        "shared_exact queues are NOT on the flow-fair path",
        "shared_exact runs flow_fair with cross-worker V_min sync (#917) since #785 Phase 3",
    ),
    (
        "single-FIFO-per-worker drain",
        "shared_exact uses MQFQ, not FIFO, since #785 Phase 3",
    ),
    ("1024-bucket bookkeeping", "value is 4096 since #785 Phase 3"),
    ("all 1024 SFQ buckets", "value is 4096 since #785 Phase 3"),
    ("bounded by 1024 worst case", "value is 4096 since #785 Phase 3"),
    ("1024 active buckets", "value is 4096 since #785 Phase 3"),
];

/// `tx.rs:` followed by an ASCII digit — old line-number breadcrumbs
/// stale across the tx.rs decomposition (#956+). Module/function
/// anchors like `tx.rs::transmit_batch` are accepted (only digits
/// trigger the violation).
const TX_LINE_REF_PATTERN: &str = "tx.rs:";
const TX_LINE_REF_RATIONALE: &str =
    "stale tx.rs:NNN line breadcrumb across the tx.rs decomposition (#956+); use module/function anchor instead";

const SCAN_DIRS: &[&str] = &[
    // Recursive scan covers cos/, types/, worker/cos.rs,
    // tx/cos_classify.rs, coordinator/cos_state.rs, etc.
    "src/afxdp",
    "src/session",
];

const ALLOW_MARKER: &str = "drift-check: historical";

#[test]
fn cos_doc_drift_guard() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut violations: Vec<Violation> = Vec::new();

    for dir in SCAN_DIRS {
        let p = Path::new(manifest_dir).join(dir);
        scan_dir(&p, &mut violations);
    }

    if !violations.is_empty() {
        let report: Vec<String> = violations
            .iter()
            .map(|v| {
                format!(
                    "  {}:{}: {:?} ({})",
                    v.path.display(),
                    v.line,
                    v.pattern,
                    v.rationale
                )
            })
            .collect();
        panic!(
            "CoS doc/code drift detected (#1205): {} violation(s)\n{}\n\n\
             If a violation flags an intentional historical retrospective \
             (e.g., explicit before/after comparison text), add the \
             allow-marker `// {}` on the same line.\n\n\
             If a stale phrase has reappeared in real code/comments, \
             rewrite the phrase to reflect current code state. Do NOT \
             silence by suppressing the test. See \
             docs/pr/1205-cos-drift-check/plan.md for context.",
            violations.len(),
            report.join("\n"),
            ALLOW_MARKER,
        );
    }
}

struct Violation {
    path: PathBuf,
    line: usize,
    pattern: String,
    rationale: &'static str,
}

fn scan_dir(dir: &Path, violations: &mut Vec<Violation>) {
    // Per Codex round-1 finding #7: panic loudly if a configured scan
    // root is missing. Silent return on read_dir error converted
    // refactor-induced path moves into false passes.
    let entries = fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "scan_dir({}): {} — fix SCAN_DIRS in tests/cos_doc_drift.rs \
             or your tree is broken",
            dir.display(),
            e
        )
    });
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_dir(&path, violations);
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        // Skip the drift-check test file itself: it must contain the
        // stale strings as part of its blocklist, but those occurrences
        // are not real drift.
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|n| n == "cos_doc_drift.rs")
            .unwrap_or(false)
        {
            continue;
        }
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        scan_content(&path, &content, violations);
    }
}

fn scan_content(path: &Path, content: &str, violations: &mut Vec<Violation>) {
    for (lineno, line) in content.lines().enumerate() {
        if line.contains(ALLOW_MARKER) {
            continue;
        }
        for (pattern, rationale) in STALE_PATTERNS {
            if line.contains(pattern) {
                violations.push(Violation {
                    path: path.to_path_buf(),
                    line: lineno + 1,
                    pattern: (*pattern).to_string(),
                    rationale,
                });
            }
        }
        // tx.rs:N — digit-suffix breadcrumb. Module/function anchors
        // like `tx.rs::transmit_batch` are acceptable (only digits
        // trigger the violation).
        //
        // Iterate ALL occurrences (Codex+Gemini r2 PR review): a line
        // like `// tx.rs::transmit_batch and tx.rs:262` would only
        // have `find()` see the first `tx.rs::` (next char `:`), miss
        // the digit-suffix later. `match_indices` catches every match.
        for (idx, _) in line.match_indices(TX_LINE_REF_PATTERN) {
            let next = line.as_bytes().get(idx + TX_LINE_REF_PATTERN.len()).copied();
            if next.map(|c| c.is_ascii_digit()).unwrap_or(false) {
                violations.push(Violation {
                    path: path.to_path_buf(),
                    line: lineno + 1,
                    pattern: TX_LINE_REF_PATTERN.to_string(),
                    rationale: TX_LINE_REF_RATIONALE,
                });
            }
        }
    }
}

// --- self-tests on the in-memory scan logic -------------------------------

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn detects_stale_bucket_count() {
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "// COS_FLOW_FAIR_BUCKETS = 1024 today\n",
            &mut v,
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allow_marker_suppresses() {
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "// COS_FLOW_FAIR_BUCKETS = 1024 was the old value // drift-check: historical\n",
            &mut v,
        );
        assert!(v.is_empty(), "marker should suppress violation");
    }

    #[test]
    fn detects_tx_rs_line_ref() {
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "    // ref tx.rs:262 here\n    // tx.rs::transmit_batch is fine\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "only the digit-suffix one should fire");
    }

    #[test]
    fn detects_tx_rs_line_ref_after_module_anchor_on_same_line() {
        // Codex+Gemini r2 PR review: line.find() saw only the first
        // `tx.rs::` and missed the digit-suffix later. match_indices
        // fixes this.
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "// see tx.rs::transmit_batch and tx.rs:262 for context\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "must catch tx.rs:NNN even if a tx.rs::module anchor precedes it");
    }

    #[test]
    fn previous_line_allow_marker_does_not_suppress() {
        // Allow marker is same-line only. A marker on the line BEFORE
        // a stale phrase must NOT silence it.
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "// drift-check: historical\n// COS_FLOW_FAIR_BUCKETS = 1024\n",
            &mut v,
        );
        assert_eq!(v.len(), 1, "previous-line allow marker must NOT suppress next-line stale phrase");
    }

    #[test]
    fn detects_stale_policy_phrase() {
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "/// flow_fair = queue.exact && !shared_exact, per #785\n",
            &mut v,
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn no_false_positive_on_unrelated_text() {
        let mut v = Vec::new();
        scan_content(
            Path::new("test.rs"),
            "/// 4096 buckets gives ~1.6% birthday collision at N=12\n\
             /// flow_fair = queue.exact for shared_exact since #785\n",
            &mut v,
        );
        assert!(v.is_empty(), "unexpected violation: {:?}", v.iter().map(|x| &x.pattern).collect::<Vec<_>>());
    }
}
