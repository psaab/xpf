//! SNAT pool contract/doc drift guard for #1377.

use std::fs;
use std::path::Path;

#[test]
fn snat_contract_documents_current_fail_closed_runtime() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .expect("userspace-dp should live directly under the repo root");
    let plan_path = repo_root.join("docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md");
    let architecture_path = repo_root.join("docs/userspace-dataplane-architecture.md");
    let gaps_path = repo_root.join("docs/userspace-dataplane-gaps.md");
    let poll_path = manifest_dir.join("src/afxdp/poll_descriptor.rs");

    let plan = fs::read_to_string(&plan_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", plan_path.display(), e));
    let architecture = fs::read_to_string(&architecture_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", architecture_path.display(), e));
    let gaps = fs::read_to_string(&gaps_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", gaps_path.display(), e));
    let poll = fs::read_to_string(&poll_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {}", poll_path.display(), e));

    let call_lines = source_nat_decision_call_lines(&poll);
    assert_eq!(
        call_lines.len(),
        4,
        "update the #1377 SNAT contract when poll_descriptor.rs no longer has exactly four source-NAT runtime decision call sites: {call_lines:?}"
    );
    assert!(
        !poll.contains("match_source_nat_for_flow(\n"),
        "poll_descriptor.rs must not use the legacy Option source-NAT helper"
    );
    assert!(
        !poll.contains("match_source_nat_for_flow(...).unwrap_or_default()"),
        "poll_descriptor.rs must not document or retain source-NAT unwrap_or_default fail-open handling"
    );
    assert_each_source_nat_call_records_failure(&poll, &call_lines);

    for required in [
        "## Current Fail-Closed Runtime Boundary",
        "match_source_nat_for_flow_result",
        "userspace-dp/src/afxdp/poll_descriptor.rs",
        "normal new-session path",
        "pending-neighbor/session-build retry path",
        "fail-closed",
        "record_source_nat_failure",
        "source_nat_pool_missing",
        "source_nat_pool_empty",
        "source_nat_pool_invalid_port_range",
    ] {
        assert!(
            plan.contains(required),
            "{} must mention {:?} so the #1377 contract tracks current runtime behavior",
            plan_path.display(),
            required
        );
    }

    let documented_call_count = plan.matches("poll_descriptor.rs:").count();
    assert_eq!(
        documented_call_count,
        call_lines.len(),
        "{} should enumerate the same number of poll_descriptor.rs source-NAT call sites as the code ({call_lines:?})",
        plan_path.display()
    );

    assert_current_capability_doc_matches_fail_closed_contract(&architecture_path, &architecture);
    assert_current_capability_doc_matches_fail_closed_contract(&gaps_path, &gaps);
}

fn source_nat_decision_call_lines(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            (line.contains("source_nat_decision_for_flow(")
                && !line.contains("fn source_nat_decision_for_flow"))
            .then_some(idx + 1)
        })
        .collect()
}

fn assert_each_source_nat_call_records_failure(source: &str, call_lines: &[usize]) {
    let lines: Vec<&str> = source.lines().collect();
    for &line_no in call_lines {
        let start = line_no - 1;
        let end = usize::min(start + 32, lines.len());
        let window = lines[start..end].join("\n");
        assert!(
            window.contains("Err(failure)") && window.contains("record_source_nat_failure("),
            "source-NAT call at poll_descriptor.rs:{line_no} must record fail-closed failures before forwarding/session creation"
        );
    }
}

fn assert_current_capability_doc_matches_fail_closed_contract(path: &Path, doc: &str) {
    for required in [
        "Source NAT",
        "pool",
        "fail-closed",
        "poll_descriptor.rs",
        "source-NAT call sites",
        "missing pools",
        "empty pools",
        "invalid port",
        "persistent-nat",
        "exhaustion counters",
    ] {
        assert!(
            doc.contains(required),
            "{} must mention {:?} so current capability docs match the #1377 runtime contract",
            path.display(),
            required
        );
    }

    for stale in [
        "runtime remains fail-open",
        "source-NAT call sites can fall through",
        "forward without SNAT",
        "claim userspace pool-mode SNAT is fail-closed",
    ] {
        assert!(
            !doc.contains(stale),
            "{} still contains stale SNAT pool fail-closed wording: {:?}",
            path.display(),
            stale
        );
    }
}
