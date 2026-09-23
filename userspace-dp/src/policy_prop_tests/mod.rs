//! #10587 — generated policy-config/packet agreement harness.
//!
//! The committed rows are the reviewable seed boundary.  Proptest explores
//! packet dimensions around those seeds in-process, while the Rust oracle is
//! the production `PolicyState` parser/evaluator.  Set `XPF_EMIT_POLICY_ROWS`
//! to a directory to emit Rust-computed rows for the Go consumer.
//!
//! Normal CI uses bounded property counts.  `PROPTEST_CASES=1000` is the
//! supported deep soak: P2/P4/P7 each accept only 2 of 48 seed rows, so the
//! default 65,536 local-reject budget reaches roughly 2,500 cases.  A
//! 100,000-case run would exceed that reject budget unless proptest's config
//! is deliberately raised.  Record the effective case count, generated row
//! count, and disagreement count.  A disagreement is a bug, never an
//! allowlist entry.  `proptest-regressions/` is committed and replayed first.

use super::*;
use proptest::prelude::*;

mod oracle;
mod strategy;

use oracle::{
    GeneratedRow, GeneratedVerdict, assert_row_oracle, divergence_ids, emit_generated_rows,
    emit_seed_rows, evaluate_row, manifest_ids, restamp_rows,
};
use strategy::{generated_config_strategy, query_strategy, row_named, seed_row_strategy};
fn cfg(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(cases),
        max_shrink_iters: 4096,
        ..ProptestConfig::default()
    }
}

fn assert_seed_rows_are_fresh(rows: &[GeneratedRow]) {
    assert_eq!(
        rows.len(),
        48,
        "generated policy seed contract changed (want exactly 48 rows)"
    );
    let expected_ids = manifest_ids();
    assert_eq!(
        expected_ids.len(),
        48,
        "seed_manifest.json must contain exactly 48 IDs"
    );
    let actual_ids: Vec<_> = rows.iter().map(|row| row.id.clone()).collect();
    assert_eq!(
        actual_ids, expected_ids,
        "generated policy seed IDs/order differ from seed_manifest.json"
    );
    assert!(
        divergence_ids().is_empty(),
        "known_divergences.json must be empty at land"
    );
    for row in rows {
        assert_eq!(
            row.schema_version, 1,
            "row {} has unsupported schema",
            row.id
        );
        assert_row_oracle(row);
    }
}

#[test]
fn policy_generated_seed_rows_are_fresh_and_emittable_10587() {
    let rows = oracle::seed_rows();
    assert_seed_rows_are_fresh(&rows);
    if let Ok(dir) = std::env::var("XPF_EMIT_POLICY_ROWS") {
        let path = std::path::Path::new(&dir);
        emit_seed_rows(path);
        let cases = std::env::var("XPF_EMIT_POLICY_CASES")
            .or_else(|_| std::env::var("PROPTEST_CASES"))
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(32);
        emit_generated_rows(path, cases.max(1));
    }
    if let Ok(dir) = std::env::var("XPF_RESTAMP_POLICY_ROWS") {
        restamp_rows(std::path::Path::new(&dir));
    }
}

// P1 — determinism / totality.  The arbitrary packet is deliberately allowed
// to be outside the row's original tuple; it still must never panic, and two
// evaluations over the same immutable PolicyState must be byte-identical.
proptest! {
    #![proptest_config(cfg(32))]
    #[test]
    fn p1_determinism_totality_10587(row in seed_row_strategy(), query in query_strategy()) {
        let mut candidate = row.clone();
        candidate.query = query;
        let first = evaluate_row(&candidate);
        let second = evaluate_row(&candidate);
        prop_assert_eq!(first, second);
    }

    // The real configuration generator: 1–3 zones, 0–6 rules, weighted tier
    // shapes, address terms, application terms, and boundary packet fields.
    // Its direct snapshot is fed through the production parser, so arbitrary
    // generated configurations exercise the enforcer rather than a toy model.
    #[test]
    fn p1_generated_config_totality_10587(config in generated_config_strategy()) {
        let mut row = GeneratedRow {
            schema_version: 1,
            id: "generated-in-process".to_string(),
            source_case: "generated".to_string(),
            config_set_lines: config.set_lines,
            query: config.query,
            go_verdict: None,
            rust_verdict: GeneratedVerdict::default(),
            snapshot: Some(config.snapshot),
            emitter_seed: None,
        };
        let first = evaluate_row(&row);
        row.rust_verdict = first.clone();
        let second = evaluate_row(&row);
        prop_assert_eq!(first, second);
    }

    // P2 — first-match-wins. Swapping two overlapping exact-pair rules changes
    // only the winner, not the packet or the evaluator's tier.
    #[test]
    fn p2_first_match_wins_10587(row in seed_row_strategy().prop_filter("exact overlap", |r| {
        r.source_case == "first-match-wins-within-a-pair" && r.query.dst_port == 22
    })) {
        let original = evaluate_row(&row);
        prop_assert_eq!(original.policy_name, "p-deny-ssh");
        let mut swapped = row.clone();
        let snapshot = swapped.snapshot.as_mut().expect("seed snapshot");
        let deny = snapshot.rules.iter().position(|r| r.name == "p-deny-ssh").expect("deny rule");
        let permit = snapshot.rules.iter().position(|r| r.name == "p-allow").expect("permit rule");
        snapshot.rules.swap(deny, permit);
        let reversed = evaluate_row(&swapped);
        prop_assert_eq!(reversed.action, "permit");
        prop_assert_eq!(reversed.policy_name, "p-allow");
    }

    // P3 — exact pair / wildcard / global tier precedence is represented by
    // the committed tier-collision rows and re-evaluated by the generated side.
    #[test]
    fn p3_tier_precedence_10587(row in seed_row_strategy().prop_filter("tier collision", |r| {
        matches!(r.source_case.as_str(),
            "exact-pair-outranks-scoped-global" |
            "single-wildcard-tier-deny-first" |
            "single-wildcard-tier-permit-first" |
            "zone-pair-wildcards")
    })) {
        assert_row_oracle(&row);
    }

    // P4 — scoped globals apply iff both scope sets contain the flow zones.
    #[test]
    fn p4_scope_soundness_10587(row in seed_row_strategy().prop_filter("scope", |r| {
        r.source_case == "scoped-global-applies-only-in-scope"
    })) {
        assert_row_oracle(&row);
    }

    // P5 — address books, exclusions, IPv6, and mapped IPv6 are concrete
    // differential rows; nil/unspecified addresses remain a Go-only contract.
    #[test]
    fn p5_address_families_exclusions_10587(row in seed_row_strategy().prop_filter("address", |r| {
        matches!(r.source_case.as_str(), "source-address-scoping" | "excluded-source-address-scoping")
            || r.id == "mapped-v6-source"
    })) {
        assert_row_oracle(&row);
    }

    // P6 — boundary ports, ICMP type/code, and no-L4 fragment gating.
    #[test]
    fn p6_application_port_icmp_frag_10587(row in seed_row_strategy().prop_filter("app dimensions", |r| {
        matches!(r.source_case.as_str(),
            "first-match-wins-within-a-pair" |
            "icmp-unknown-application" |
            "junos-host-fragment-associated-deny")
            || r.id.starts_with("boundary-port-")
    })) {
        assert_row_oracle(&row);
    }

    // P7 — the two host fragment rows pin skipped deny attribution and the
    // non-overlapping control row.
    #[test]
    fn p7_fragment_associated_deny_10587(row in seed_row_strategy().prop_filter("frag", |r| {
        r.source_case == "junos-host-fragment-associated-deny" && r.query.frag
    })) {
        assert_row_oracle(&row);
        prop_assert!(row.rust_verdict.policy_name == "block-host-ssh" || row.rust_verdict.policy_name == "permit-host-all");
    }

    // P8 — unknown ingress is an unattributed deny; unknown egress falls to
    // the configured default. These are evaluated from a generated copy of a
    // committed permit-all state, not from an authored expected verdict.
    #[test]
    fn p8_unknown_zone_gates_10587(_row in seed_row_strategy()) {
        let mut ingress = row_named("default-policy-permit-all-01");
        ingress.query.from_zone = "missing-ingress".to_string();
        let ingress_verdict = evaluate_row(&ingress);
        prop_assert_eq!(ingress_verdict.action, "deny");
        prop_assert!(!ingress_verdict.default_used);
        prop_assert!(!ingress_verdict.matched);

        let mut egress = row_named("default-policy-permit-all-01");
        egress.query.to_zone = "missing-egress".to_string();
        let egress_verdict = evaluate_row(&egress);
        prop_assert_eq!(egress_verdict.action, "permit");
        prop_assert!(egress_verdict.default_used);
        prop_assert!(!egress_verdict.matched);
    }

    // P9 — changing only the default posture changes only a fall-through row.
    #[test]
    fn p9_default_posture_independence_10587(_row in seed_row_strategy()) {
        let mut deny = row_named("empty-policy-deny-all");
        let deny_v = evaluate_row(&deny);
        prop_assert_eq!(deny_v.action, "deny");
        prop_assert!(deny_v.default_used);
        prop_assert!(!deny_v.matched);

        deny.snapshot.as_mut().expect("seed snapshot").default_policy = "permit".to_string();
        let permit_v = evaluate_row(&deny);
        prop_assert_eq!(permit_v.action, "permit");
        prop_assert!(permit_v.default_used);
        prop_assert!(!permit_v.matched);
    }

    // P11 — every matched seed row carries the runtime policy identity from
    // Rust's PolicyRuleSnapshot, and the Go side checks the same ID.
    #[test]
    fn p11_policy_id_agreement_10587(row in seed_row_strategy()) {
        let got = evaluate_row(&row);
        if got.matched {
            prop_assert!(!got.policy_name.is_empty());
            prop_assert_eq!(got.policy_id, row.rust_verdict.policy_id);
            prop_assert_eq!(got.policy_name, row.rust_verdict.policy_name);
        } else {
            prop_assert_eq!(got.policy_id, 0);
            prop_assert!(got.policy_name.is_empty());
        }
    }
}

// P10 is intentionally a Rust-side refusal pin for an address-axis snapshot
// sentinel. The Go package has a separate application-axis refusal pin; the
// inputs and parser layers differ, so they are not claimed as a differential
// agreement test.
#[test]
fn p10_content_reject_refusal_10587() {
    let mut row = row_named("exact-zone-pair-permit-01");
    let snapshot = row.snapshot.as_mut().expect("seed snapshot");
    snapshot.rules[0].source_literals = vec![UNREPRESENTABLE_ADDRESS_SENTINEL.to_string()];
    let zones = zone_name_to_id_from_snapshot(&snapshot.zones);
    let parse = parse_policy_state_with_counters(
        &snapshot.default_policy,
        &snapshot.rules,
        &zones,
        &snapshot.address_books,
        &PolicyCounterStore::default(),
    );
    let error = match parse {
        Ok(_) => panic!("unrepresentable generated content must be refused"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("unrepresentable address"),
        "address refusal lost its error kind: {error}"
    );
}
