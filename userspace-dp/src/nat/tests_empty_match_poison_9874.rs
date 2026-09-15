// #9874: an authored-but-empty source-NAT `match` ships as an UNCONSTRAINED
// catch-all on the tolerant path.
//
// The Go #8430 gate rejects such a rule at strict commit but downgrades to a
// warning on lenient load / peer-sync, and the snapshot carried NO marker — so
// the rule installed with `source_constrained = false` and `nets_match_v4`
// returned true for every flow in scope (source/mod.rs:1287,1527-1528). The
// typed rule now carries `LenientMatchDropped`, the snapshot carries
// `lenient_match_dropped`, and the source-NAT table fails such a rule CLOSED:
// a matched flow gets `Unavailable` (drop + count) instead of a translation,
// including for `off` rules (whose exemption short-circuit runs before the
// pool_failure check and would otherwise exempt every flow in scope).
//
// The unmarked shape is untouched: a scope-only rule (no `match` at all) still
// installs unconstrained and still translates — that is the legitimate
// catch-all, and conflating it with the poisoned one is the over-reject this
// file's first cell pins against.
#![allow(unused_imports)]

use super::allocator::{port_allocator_build_count, reset_port_allocator_build_count, NatHolder};
use super::destination::PROTO_TCP;
use super::*;
use crate::{NatPortRangeWire, SourceNATRuleSnapshot};

/// No-over-reject pin AND the STEP-0 execution proof: an UNMARKED rule with an
/// empty match set installs unconstrained and translates — on base this is the
/// catch-all the defect ships; post-fix it is the legitimate scope-only shape
/// (the Go compiler leaves `LenientMatchDropped` false when no `match` was
/// authored). Must stay Matched whatever the poison does.
#[test]
fn unmarked_empty_match_rule_still_translates_scope_only_9874() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "scope-only".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // No source_addresses: the scope-only shape. Deliberately NO
        // lenient_match_dropped marker.
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(rules.len(), 1);
    assert!(
        !rules[0].source_constrained,
        "an unmarked empty match set installs unconstrained (scope-only)"
    );
    let lookup = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.11.12.13".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    match lookup {
        SourceNatLookup::Matched(decision) => {
            assert_eq!(
                decision.rewrite_src,
                Some("172.16.80.8".parse().expect("snat"))
            );
        }
        other => panic!(
            "unmarked scope-only rule must still translate, got {other:?} (#9874 over-reject)"
        ),
    }
}
/// THE point of #9874: a marked pool-mode rule with an empty match set claims
/// the flow and fails CLOSED (drop + count) instead of installing the catch-all
/// translator. RED-on-revert: drop the `lenient_match_dropped` check in the
/// match loop and this translates.
#[test]
fn poisoned_pool_rule_fails_closed_9874() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "poisoned-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Empty match set + the poison marker.
        pool_name: "p1".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 40000,
        port_high: 40000,
        lenient_match_dropped: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(rules.len(), 1);
    assert!(
        rules[0].lenient_match_dropped,
        "parse must carry the snapshot marker onto the rule"
    );
    let lookup = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.11.12.13".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(
                f,
                SourceNatFailure {
                    rule_name: "poisoned-pool".to_string(),
                    pool_name: "p1".to_string(),
                    reason: SourceNatFailureReason::AuthoredMatchEmpty,
                }
            );
            assert_eq!(f.exception_reason(), "source_nat_authored_match_empty");
        }
        other => panic!("poisoned rule must drop, got {other:?} (#9874 fail-open)"),
    }
}

/// The placement cell: the poison check runs BEFORE the `off` short-circuit
/// (match_rules.rs), so a poisoned exemption DROPS instead of exempting every
/// flow in scope. A check ordered after `off` (or keyed on `pool_failure`,
/// which the `off` arm never consults) returns Matched-default here and this
/// reds.
#[test]
fn poisoned_off_rule_does_not_exempt_9874() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "poisoned-off".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        off: true,
        lenient_match_dropped: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let lookup = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.11.12.13".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::AuthoredMatchEmpty);
        }
        other => panic!(
            "poisoned `off` rule must drop, got {other:?} — a Matched-default \
             here exempts every flow in scope (#9874)"
        ),
    }
}

/// Interface-mode poison: the interface return runs before the pool_failure
/// check, so only the pre-`off` poison check catches it. Same Unavailable.
#[test]
fn poisoned_interface_rule_fails_closed_9874() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "poisoned-iface".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        interface_mode: true,
        lenient_match_dropped: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let lookup = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.11.12.13".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::AuthoredMatchEmpty);
        }
        other => panic!("poisoned interface rule must drop, got {other:?} (#9874)"),
    }
}

/// Ordering + scope in one table. A poisoned first rule STOPS evaluation (the
/// in-scope flow drops; it must NOT fall through to the healthy second rule
/// and translate under it), while a flow outside the poisoned rule's scope
/// still reaches the second rule (the poison claims only what the rule's
/// scope covers — no over-claim).
#[test]
fn poisoned_first_rule_stops_evaluation_but_scope_still_applies_9874() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "poisoned-first".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            pool_name: "p1".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            lenient_match_dropped: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "healthy-second".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    // In the poisoned rule's scope: claimed and dropped, no fall-through.
    let in_scope = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.11.12.13".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    match in_scope {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::AuthoredMatchEmpty);
            assert_eq!(f.rule_name, "poisoned-first");
        }
        other => panic!(
            "in-scope flow must drop at the poisoned first rule, got {other:?} \
             (fall-through would translate under the wrong rule or forward \
             untranslated, #9874)"
        ),
    }
    // Outside it: the poisoned rule is skipped by scope and the healthy rule
    // translates.
    let out_of_scope = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "dmz",
        "wan",
        "10.11.12.13".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    match out_of_scope {
        SourceNatLookup::Matched(decision) => {
            assert_eq!(
                decision.rewrite_src,
                Some("172.16.80.8".parse().expect("snat"))
            );
        }
        other => panic!(
            "out-of-scope flow must still translate via the healthy rule, got \
             {other:?} (#9874 over-claim)"
        ),
    }
}

/// A poisoned pool-mode rule builds NO allocator: no bitmap, no #6812 budget
/// charge, no reuse key — like a failed pool. The unpoisoned twin keeps its
/// key. The build-count leg is load-bearing, not belt: `allocator_key()` has
/// its own marker check, so a key-only assertion stays green if the parse-loop
/// pending guard is removed — only the constructor count sees the bitmap that
/// would then be built, charged, and fought over by the budget walk (#6812 F3).
#[test]
fn poisoned_rule_builds_no_allocator_9874() {
    reset_port_allocator_build_count();
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "poisoned".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            pool_name: "p1".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            lenient_match_dropped: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "healthy".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "p2".to_string(),
            pool_addresses: vec!["203.0.113.11".to_string()],
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].allocator_key(),
        None,
        "poisoned rule must report no allocator key"
    );
    assert!(
        rules[1].allocator_key().is_some(),
        "healthy twin must keep its allocator key"
    );
    assert_eq!(
        port_allocator_build_count(),
        1,
        "only the healthy twin may construct a PortAllocator: the poisoned rule \
         must build nothing (a build-then-discard behind the key gate shows up \
         here as 2)"
    );
}

/// Pool snapshot for the generation tests: 11 ports so repeated refreshes
/// carrying one live allocator never trip range exhaustion (each generation
/// below mints once on the carried allocator).
fn pool_snap_9874(
    name: &str,
    to_zone: &str,
    match_addrs: &[&str],
    pool: &str,
    poisoned: bool,
) -> SourceNATRuleSnapshot {
    SourceNATRuleSnapshot {
        name: name.to_string(),
        from_zone: "lan".to_string(),
        to_zone: to_zone.to_string(),
        source_addresses: match_addrs.iter().map(|a| a.to_string()).collect(),
        pool_name: pool.to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 40000,
        port_high: 40010,
        lenient_match_dropped: poisoned,
        ..SourceNATRuleSnapshot::default()
    }
}

/// Tuple-path admit for the generation tests: TCP, so a pool-mode rule
/// exercises the real `allocate_translation` path (the proto-0 wrapper is
/// address-only and would never touch the allocator under test).
fn admit_tcp_9874(
    reg: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    from_zone: &str,
    to_zone: &str,
    src: &str,
    src_port: u16,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        reg,
        rules,
        &NatScopeCtx::default(),
        from_zone,
        to_zone,
        src.parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some(PROTO_TCP),
        src_port,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

/// Poisoned→healthy recovery across generations: correcting the empty match
/// while retaining pool identity must restore pool SNAT. The poisoned
/// generation holds only the never-built default allocator, which the
/// previous-generation collection must NOT publish under the live pool key —
/// otherwise the recovered rule reuses a max_tracked_flows == 0 placeholder
/// and every mint fails AllocatorExhausted. RED pre-fix on all three legs
/// (build count 0, status capacity 0, e2e Unavailable).
#[test]
fn poisoned_to_healthy_recovery_builds_fresh_allocator_9874() {
    // Generation 1: the rule is poisoned — it drops, and builds nothing.
    let gen1 = parse_source_nat_rules(&[pool_snap_9874("r1", "wan", &[], "p1", true)]);
    assert_eq!(gen1.len(), 1);
    let reg = InterfaceNatAllocators::default();
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen1, "lan", "wan", "10.0.0.1", 5555),
            SourceNatLookup::Unavailable(_)
        ),
        "setup: the poisoned generation must drop, not translate"
    );

    // Generation 2: the operator corrects the match; pool identity unchanged.
    reset_port_allocator_build_count();
    let gen2 = parse_source_nat_rules_with_previous(
        &[pool_snap_9874("r1", "wan", &["0.0.0.0/0"], "p1", false)],
        Some(&gen1),
        &NatCounterStore::default(),
        0,
    );
    assert_eq!(gen2.len(), 1);
    assert!(
        gen2[0].pool_failure.is_none(),
        "recovery must not fail the pool"
    );
    assert_eq!(
        port_allocator_build_count(),
        1,
        "recovery must build a FRESH allocator: the poisoned generation held only \
         the never-built default, so there is nothing to reuse — a 0 here means the \
         placeholder was published under the pool key and reused"
    );
    let statuses = source_nat_pool_statuses(&gen2);
    assert_eq!(statuses.len(), 1);
    assert!(
        statuses[0].max_tracked_flows > 0,
        "the recovered rule must report real allocator capacity, not the placeholder's 0"
    );
    match admit_tcp_9874(&reg, &gen2, "lan", "wan", "10.0.0.2", 5556) {
        SourceNatLookup::Matched(d) => {
            assert_eq!(d.rewrite_src, Some("203.0.113.10".parse().expect("snat")));
            assert!(
                d.rewrite_src_port.is_some(),
                "TCP recovery must allocate a pool port"
            );
        }
        other => panic!("recovered rule must translate, got {other:?}"),
    }
}

/// A poisoned rule must not displace a shared pool's real allocator on
/// refresh — with the poisoned rule FIRST, so the pre-fix or_insert
/// (first-wins) publishes the placeholder. The healthy sibling lives in
/// another zone scope but references the SAME pool (allocator keys carry no
/// scope), so its flows skip the poisoned rule on scope and still exercise
/// the shared allocator end to end. Covers the repeated-refresh half: gen2
/// AND gen3 must keep translating. The build-count leg pins the other
/// direction: gen2 must REUSE (0 builds), proving the fix does not over-skip
/// and drop real state.
#[test]
fn poisoned_sibling_does_not_displace_shared_pool_allocator_9874() {
    let snaps = vec![
        pool_snap_9874("poisoned", "wan", &[], "p1", true),
        pool_snap_9874("healthy", "dmz", &["0.0.0.0/0"], "p1", false),
    ];
    let reg = InterfaceNatAllocators::default();
    let gen1 = parse_source_nat_rules(&snaps);
    assert_eq!(gen1.len(), 2);
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen1, "lan", "wan", "10.0.0.1", 5555),
            SourceNatLookup::Unavailable(_)
        ),
        "setup: the poisoned rule must drop its own scope"
    );
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen1, "lan", "dmz", "10.0.0.2", 5556),
            SourceNatLookup::Matched(_)
        ),
        "setup: the healthy sibling must translate"
    );

    reset_port_allocator_build_count();
    let gen2 =
        parse_source_nat_rules_with_previous(&snaps, Some(&gen1), &NatCounterStore::default(), 0);
    assert_eq!(
        port_allocator_build_count(),
        0,
        "the shared key is live: gen2 must REUSE the healthy sibling's allocator, \
         not rebuild — a build here means the fix over-skips and drops real state"
    );
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen2, "lan", "dmz", "10.0.0.3", 5557),
            SourceNatLookup::Matched(_)
        ),
        "shared-pool sibling must keep translating after refresh (pre-fix: the \
         placeholder displaces the real allocator and every mint fails \
         AllocatorExhausted)"
    );
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen2, "lan", "wan", "10.0.0.1", 5555),
            SourceNatLookup::Unavailable(_)
        ),
        "the poison persists across refresh"
    );

    let gen3 =
        parse_source_nat_rules_with_previous(&snaps, Some(&gen2), &NatCounterStore::default(), 0);
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen3, "lan", "dmz", "10.0.0.4", 5558),
            SourceNatLookup::Matched(_)
        ),
        "repeated refreshes must stay healthy, not just the first"
    );
}

/// Live-ownership guard for the collection skip: a poisoned DRAINING rule
/// still contributes its carried allocator. Greens with and without the fix —
/// it binds the fix against over-correction (skipping every poisoned rule
/// would strand the live flows the #7717 drain exists to release; the gen3
/// leg is the load-bearing one). New flows still drop as AuthoredMatchEmpty:
/// the poison wins for admission while live state drains.
#[test]
fn poisoned_draining_rule_still_retains_live_allocator_9874() {
    let gen1 = parse_source_nat_rules(&[pool_snap_9874("r1", "wan", &["0.0.0.0/0"], "p1", false)]);
    let reg = InterfaceNatAllocators::default();
    assert!(
        matches!(
            admit_tcp_9874(&reg, &gen1, "lan", "wan", "10.0.0.1", 5555),
            SourceNatLookup::Matched(_)
        ),
        "setup: the healthy pool must translate"
    );
    assert_eq!(
        gen1[0].pool_allocator.live_flow_count(),
        1,
        "setup: the pool must hold one live flow"
    );

    let mut quarantined = pool_snap_9874("r1", "wan", &[], "p1", true);
    quarantined.pool_unusable = true;
    quarantined.pool_unusable_reason = "iface_snat_egress_overlap".to_string();
    let snaps = vec![quarantined];
    let gen2 =
        parse_source_nat_rules_with_previous(&snaps, Some(&gen1), &NatCounterStore::default(), 0);
    assert_eq!(
        gen2[0].pool_allocator.live_flow_count(),
        1,
        "#7717 retention must survive poisoning: the draining rule carries live \
         flows and needs the state that releases them"
    );
    match admit_tcp_9874(&reg, &gen2, "lan", "wan", "10.0.0.2", 5556) {
        SourceNatLookup::Unavailable(f) => assert_eq!(
            f.reason,
            SourceNatFailureReason::AuthoredMatchEmpty,
            "new flows drop as poisoned even when the rule is also draining"
        ),
        other => panic!("poisoned+draining rule must drop new flows, got {other:?}"),
    }

    let gen3 =
        parse_source_nat_rules_with_previous(&snaps, Some(&gen2), &NatCounterStore::default(), 0);
    assert_eq!(
        gen3[0].pool_allocator.live_flow_count(),
        1,
        "retention must survive repeated poisoned+draining snapshots, not just the first"
    );
}
