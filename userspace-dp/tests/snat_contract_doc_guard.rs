//! SNAT pool contract/doc drift guard for #1377.
//!
//! The contract: every runtime source-NAT decision fails CLOSED. A matched
//! pool-mode rule that cannot produce a usable translation drops the packet
//! before session creation or forwarding; it never forwards untranslated.
//!
//! Where the decision lives (#19132). #17021 moved the new-session and
//! missing-neighbor-seed SNAT decision out of `poll_descriptor/mod.rs` into ONE
//! composer, `session_glue::compose_outbound_source_nat` (forward_commit.rs),
//! which returns the failure as `NatFailure::SourceNat`. Both of its callers,
//! in `poll_descriptor/mod.rs`, record that failure and recycle the frame. The
//! old guard counted `source_nat_decision_for_flow(` inside mod.rs only, read 0
//! after the move, and stopped before checking anything else. This guard
//! follows the decision to where it is:
//!   - a crate-wide census of runtime `source_nat_decision_for_flow(` calls:
//!     exactly the composer and the flowless-fragment retry (frag_assoc.rs);
//!   - the composer propagates a failure as `NatFailure::SourceNat`;
//!   - the flowless-fragment retry drops on any failure;
//!   - exactly two composer callers, both in poll_descriptor/mod.rs, each
//!     recording a `NatFailure::SourceNat` with `record_source_nat_failure`;
//!   - no legacy Option helper and no `unwrap_or_default` fail-open on the
//!     decision path;
//!   - the plan and capability docs describe this layout.
//! Every check runs and every failure is reported together, so one stale
//! check cannot hide the rest.

use std::fs;
use std::path::{Path, PathBuf};

const DECISION_CALL: &str = "source_nat_decision_for_flow(";
const COMPOSER_CALL: &str = "compose_outbound_source_nat(";
const COMPOSER: &str = "userspace-dp/src/afxdp/session_glue/forward_commit.rs";
const FRAG_RETRY: &str = "userspace-dp/src/afxdp/poll_descriptor/frag_assoc.rs";
const POLL: &str = "userspace-dp/src/afxdp/poll_descriptor/mod.rs";
const DECISION_PATH_FILES: [&str; 4] = [
    POLL,
    COMPOSER,
    FRAG_RETRY,
    "userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs",
];

fn read(root: &Path, rel: &str) -> String {
    let path = root.join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e))
}

/// A unit-test file inside src/ (`tests.rs`, `*_tests.rs`, `tests_*.rs`, or
/// anything under a `tests/` directory): not runtime code.
fn is_test_file(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    rel.contains("/tests/")
        || name == "tests.rs"
        || name.ends_with("_tests.rs")
        || name.starts_with("tests_")
}

/// Every runtime .rs file under userspace-dp/src, as repo-relative paths.
fn runtime_sources(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![root.join("userspace-dp/src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot list {}: {}", dir.display(), e)) {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let rel = path.strip_prefix(root).expect("under the repo root").display().to_string();
                if !is_test_file(&rel) {
                    out.push(rel);
                }
            }
        }
    }
    out.sort();
    out
}

/// 1-based lines of `source` that call `call` (not its definition, not a
/// comment).
fn call_lines(source: &str, call: &str) -> Vec<usize> {
    let name = call.trim_end_matches('(');
    source
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let code = line.trim_start();
            (line.contains(call) && !line.contains(&format!("fn {name}")) && !code.starts_with("//"))
                .then_some(idx + 1)
        })
        .collect()
}

/// The `len` lines starting at 1-based `line`.
fn window(source: &str, line: usize, len: usize) -> Vec<&str> {
    source.lines().skip(line - 1).take(len).collect()
}

#[test]
fn snat_contract_documents_current_fail_closed_runtime() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root: PathBuf = manifest_dir
        .parent()
        .expect("userspace-dp should live directly under the repo root")
        .to_path_buf();
    let mut problems: Vec<String> = Vec::new();

    // 1. Crate-wide census of runtime source-NAT decisions.
    let mut decision_sites: Vec<(String, usize)> = Vec::new();
    let mut composer_sites: Vec<(String, usize)> = Vec::new();
    for rel in runtime_sources(&repo_root) {
        let source = read(&repo_root, &rel);
        for line in call_lines(&source, DECISION_CALL) {
            decision_sites.push((rel.clone(), line));
        }
        for line in call_lines(&source, COMPOSER_CALL) {
            composer_sites.push((rel.clone(), line));
        }
    }
    let decision_files: Vec<&str> = decision_sites.iter().map(|(f, _)| f.as_str()).collect();
    if decision_files != [FRAG_RETRY, COMPOSER] {
        problems.push(format!(
            "runtime {DECISION_CALL} calls should be exactly one in {COMPOSER} and one in {FRAG_RETRY}; \
             found {decision_sites:?}. A new or moved decision site needs its fail-closed handling \
             checked here and the #1377 contract updated"
        ));
    }

    // 2. The composer hands a failed decision back as NatFailure::SourceNat.
    let composer = read(&repo_root, COMPOSER);
    for (file, line) in decision_sites.iter().filter(|(f, _)| f == COMPOSER) {
        let w = window(&composer, *line, 40).join("\n");
        if !w.contains("Err(failure) => Err(NatFailure::SourceNat(failure))") {
            problems.push(format!(
                "{file}:{line}: a failed source-NAT decision must come back as Err(NatFailure::SourceNat(failure)), \
                 not be swallowed (fail-open)"
            ));
        }
    }

    // 3. The flowless-fragment retry drops on any failure.
    let frag = read(&repo_root, FRAG_RETRY);
    for (file, line) in decision_sites.iter().filter(|(f, _)| f == FRAG_RETRY) {
        let w = window(&frag, *line, 40).join("\n");
        if !w.contains("_ => RetryFlowlessFragmentNat::Drop") {
            problems.push(format!(
                "{file}:{line}: the flowless-fragment source-NAT retry must drop when the decision fails"
            ));
        }
    }

    // 4. Exactly two composer callers, both in poll_descriptor/mod.rs (the
    //    normal new-session path and the missing-neighbor seed), each recording
    //    a NatFailure::SourceNat before the frame is recycled.
    let poll = read(&repo_root, POLL);
    let composer_in_poll = composer_sites.iter().filter(|(f, _)| f == POLL).count();
    if composer_sites.len() != 2 || composer_in_poll != 2 {
        problems.push(format!(
            "{COMPOSER_CALL} should have exactly two runtime callers, both in {POLL}; found {composer_sites:?}"
        ));
    }
    for (file, line) in composer_sites.iter().filter(|(f, _)| f == POLL) {
        let w = window(&poll, *line, 60);
        let records = w
            .iter()
            .position(|l| l.contains("NatFailure::SourceNat("))
            .is_some_and(|arm| w[arm..].iter().take(15).any(|l| l.contains("record_source_nat_failure(")));
        if !records {
            problems.push(format!(
                "{file}:{line}: the NatFailure::SourceNat arm must call record_source_nat_failure before the frame is recycled"
            ));
        }
    }

    // 5. No legacy Option helper and no unwrap_or_default fail-open on the
    //    decision path.
    for rel in DECISION_PATH_FILES {
        let source = read(&repo_root, rel);
        if !call_lines(&source, "match_source_nat_for_flow(").is_empty() {
            problems.push(format!("{rel} must not use the legacy Option source-NAT helper"));
        }
        if source.contains("match_source_nat_for_flow(...).unwrap_or_default()") {
            problems.push(format!(
                "{rel} must not document or retain source-NAT unwrap_or_default fail-open handling"
            ));
        }
    }

    // 6. The plan doc describes the current runtime boundary.
    let plan_rel = "docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md";
    let plan = read(&repo_root, plan_rel);
    for required in [
        "## Current Fail-Closed Runtime Boundary",
        "match_source_nat_for_flow_result",
        "normal new-session path",
        "pending-neighbor/session-build retry path",
        "flowless-fragment",
        "fail-closed",
        "record_source_nat_failure",
        "compose_outbound_source_nat",
        "NatFailure::SourceNat",
        "session_glue/forward_commit.rs",
        "poll_descriptor/mod.rs",
        "poll_descriptor/frag_assoc.rs",
        "source_nat_pool_missing",
        "source_nat_pool_empty",
        "source_nat_pool_invalid_port_range",
    ] {
        if !plan.contains(required) {
            problems.push(format!(
                "{plan_rel} must mention {required:?} so the #1377 contract tracks current runtime behavior"
            ));
        }
    }

    // 7. The capability docs.
    for rel in ["docs/userspace-dataplane-architecture.md", "docs/userspace-dataplane-gaps.md"] {
        check_capability_doc(&mut problems, rel, &read(&repo_root, rel));
    }

    assert!(problems.is_empty(), "#1377 SNAT contract drift:\n  {}", problems.join("\n  "));
}

fn check_capability_doc(problems: &mut Vec<String>, rel: &str, doc: &str) {
    // Accept either `poll_descriptor.rs` (flat layout) or
    // `poll_descriptor/mod.rs` (directory layout post-#1327 Step 1).
    let poll_path_alternatives = ["poll_descriptor.rs", "poll_descriptor/mod.rs"];
    if !poll_path_alternatives.iter().any(|tok| doc.contains(tok)) {
        problems.push(format!(
            "{rel} must mention at least one of {poll_path_alternatives:?} so current capability docs match the #1377 runtime contract"
        ));
    }
    for required in [
        "Source NAT",
        "pool",
        "fail-closed",
        "source-NAT call sites",
        "missing pools",
        "empty pools",
        "invalid port",
        "persistent-nat",
        "exhaustion counters",
    ] {
        if !doc.contains(required) {
            problems.push(format!(
                "{rel} must mention {required:?} so current capability docs match the #1377 runtime contract"
            ));
        }
    }
    for stale in [
        "runtime remains fail-open",
        "source-NAT call sites can fall through",
        "forward without SNAT",
        "claim userspace pool-mode SNAT is fail-closed",
    ] {
        if doc.contains(stale) {
            problems.push(format!("{rel} still contains stale SNAT pool fail-closed wording: {stale:?}"));
        }
    }
}
