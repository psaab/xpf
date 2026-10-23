//! #16021 (ZP-07): a `NoRoute` frame must adjudicate the egress-unconstrained
//! policy tiers before the implicit default policy decides.
//!
//! Before this, `evaluate_policy_result_l3_aware_unresolved_egress` skipped the
//! whole tier walk for `to_id == 0`, so under `default-policy permit-all` a
//! NoRoute packet was delegated to the kernel FIB — whose route the userspace
//! FIB did not have (flap / FIB-not-loaded / capped learned-route import) —
//! and an explicit deny the packet's ingress + L3/L4 identity matched was
//! never evaluated. These cells drive `noroute_policy_denial` with
//! `egress_ifindex == 0`, the base NoRoute shape the arm adjudicates.
//!
//! Eligible on NoRoute: `from-zone <from> to-zone any`, `from-zone any
//! to-zone any`, and `junos-global` with an `Any` to-zone scope (from-zone
//! scope still applies). Ineligible: the exact pair, `from-zone any
//! to-zone <z>`, and `junos-global` with a concrete to-zone scope — each
//! names an egress zone the flow does not have.

use super::noroute_policy_denial;
use crate::policy::{PolicyAction, PolicyState, parse_policy_state};
use crate::{PolicyApplicationSnapshot, PolicyRuleSnapshot};
use rustc_hash::FxHashMap;
use std::net::IpAddr;

const LAN: u16 = 11;
const WAN: u16 = 12;
const UNZONED: u16 = 0;

fn zones() -> FxHashMap<String, u16> {
    let mut m = FxHashMap::default();
    m.insert("lan".to_string(), LAN);
    m.insert("wan".to_string(), WAN);
    m
}

fn src() -> IpAddr {
    "10.0.61.100".parse().expect("src")
}
fn dst() -> IpAddr {
    "172.16.80.200".parse().expect("dst")
}

fn rule(name: &str, from_zone: &str, to_zone: &str, action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: from_zone.to_string(),
        to_zone: to_zone.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: action.to_string(),
        ..Default::default()
    }
}

fn global_rule(name: &str, match_from: &str, match_to: &str, action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        match_from_zone: match_from.to_string(),
        match_to_zone: match_to.to_string(),
        ..rule(name, "junos-global", "junos-global", action)
    }
}

fn verdict(state: &PolicyState) -> Option<crate::policy::PolicyEvaluationResult> {
    noroute_policy_denial(
        state,
        LAN,
        UNZONED,
        0,
        src(),
        dst(),
        6,
        Some((40000, 443)),
        None,
        64,
    )
}

/// THE DECISIVE CELL (#16021): userspace route withdrawn, kernel route
/// retained, default permit-all + an explicit egress-unconstrained deny.
///
/// FAIL-ON-REVERT: restoring the `to_id == 0` tier-gate skip makes every
/// deny below return the default PERMIT, so `verdict` is `None` (kernel
/// delegation) and this reds — the explicit deny bypassed to the kernel FIB.
#[test]
fn noroute_explicit_deny_beats_default_permit_16021() {
    // `from-zone lan to-zone any deny` — egress unconstrained.
    let state = parse_policy_state(
        "permit",
        &[rule("deny-lan-any", "lan", "any", "deny")],
        &zones(),
    );
    let v = verdict(&state).expect("to-zone any deny must deny the NoRoute frame");
    assert_eq!(v.action, PolicyAction::Deny);
    assert_eq!(v.policy_id, state.rules[0].policy_id);

    // `from-zone any to-zone any deny` — both sides unconstrained.
    let state = parse_policy_state(
        "permit",
        &[rule("deny-any-any", "any", "any", "deny")],
        &zones(),
    );
    let v = verdict(&state).expect("both-any deny must deny the NoRoute frame");
    assert_eq!(v.action, PolicyAction::Deny);

    // Unscoped `junos-global deny`.
    let state = parse_policy_state(
        "permit",
        &[rule("deny-global", "junos-global", "junos-global", "deny")],
        &zones(),
    );
    let v = verdict(&state).expect("unscoped global deny must deny the NoRoute frame");
    assert_eq!(v.action, PolicyAction::Deny);

    // `junos-global` scoped only on the from side (`match from-zone lan`).
    let state = parse_policy_state(
        "permit",
        &[global_rule("deny-global-lan", "lan", "", "deny")],
        &zones(),
    );
    let v = verdict(&state).expect("from-scoped global deny must deny the NoRoute frame");
    assert_eq!(v.action, PolicyAction::Deny);

    // REJECT is a denial too: it must not delegate.
    let state = parse_policy_state(
        "permit",
        &[rule("reject-lan-any", "lan", "any", "reject")],
        &zones(),
    );
    let v = verdict(&state).expect("to-zone any reject must deny the NoRoute frame");
    assert_eq!(v.action, PolicyAction::Reject);
}

/// The egress-constrained tiers stay ineligible without an egress zone: a
/// rule that names the (unknown) egress must not decide the flow, in either
/// direction — a scoped deny must not drop, a scoped permit must not rescue
/// a default-deny box.
#[test]
fn noroute_egress_constrained_rules_stay_ineligible_16021() {
    // Exact pair deny does not fire; default permit delegates.
    let state = parse_policy_state(
        "permit",
        &[rule("deny-lan-wan", "lan", "wan", "deny")],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "an exact-pair deny names an egress the NoRoute flow does not have"
    );

    // `from-zone any to-zone wan deny` does not fire.
    let state = parse_policy_state(
        "permit",
        &[rule("deny-any-wan", "any", "wan", "deny")],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "a from-any/to-zone<wan> deny is egress-constrained and stays ineligible"
    );

    // `junos-global` with a concrete to-zone scope does not fire.
    let state = parse_policy_state(
        "permit",
        &[global_rule("deny-global-wan", "", "wan", "deny")],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "a to-scoped global deny is egress-constrained and stays ineligible"
    );

    // A from-scoped global for a DIFFERENT ingress does not fire.
    let state = parse_policy_state(
        "permit",
        &[global_rule("deny-global-wan-in", "wan", "", "deny")],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "a global scoped to another from-zone must not match this ingress"
    );

    // An eligible PERMIT decides the flow under default-deny (delegation).
    let state = parse_policy_state(
        "deny",
        &[rule("permit-lan-any", "lan", "any", "permit")],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "an egress-unconstrained permit must still delegate under default-deny"
    );

    // No eligible rule at all: the default still decides (permit delegates,
    // deny drops) — availability on a fresh boot / uncapped miss is intact.
    let state = parse_policy_state("permit", &[], &zones());
    assert!(
        verdict(&state).is_none(),
        "unmatched NoRoute keeps default-permit delegation"
    );
    let state = parse_policy_state("deny", &[], &zones());
    assert!(
        verdict(&state).is_some(),
        "unmatched NoRoute keeps default-deny drop"
    );
}

/// First-match precedence among the eligible tiers is the normal one:
/// single-wildcard before both-any before global, config order within a tier.
#[test]
fn noroute_eligible_tiers_keep_normal_precedence_16021() {
    // to-any permit configured AFTER a both-any deny still wins (tier order).
    let state = parse_policy_state(
        "permit",
        &[
            rule("deny-any-any", "any", "any", "deny"),
            rule("permit-lan-any", "lan", "any", "permit"),
        ],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "the single-wildcard tier must beat both-any regardless of config order"
    );

    // Both-any deny beats a later global permit.
    let state = parse_policy_state(
        "deny",
        &[
            rule("permit-global", "junos-global", "junos-global", "permit"),
            rule("deny-any-any", "any", "any", "deny"),
        ],
        &zones(),
    );
    let v = verdict(&state).expect("both-any deny must beat the global permit");
    assert_eq!(v.action, PolicyAction::Deny);
    assert_eq!(v.policy_id, state.rules[1].policy_id);

    // Within the to-any tier the first matching rule in config order wins.
    let state = parse_policy_state(
        "deny",
        &[
            rule("permit-lan-any", "lan", "any", "permit"),
            rule("deny-lan-any", "lan", "any", "deny"),
        ],
        &zones(),
    );
    assert!(
        verdict(&state).is_none(),
        "the first to-any rule in config order must win"
    );
}

/// The L3/L4 identity still gates eligible rules: an address- or
/// port-mismatched deny must not fire, and a flowless packet fails closed
/// against a port-bearing eligible deny (#4569 association).
#[test]
fn noroute_eligible_deny_still_requires_l3_l4_match_16021() {
    // Destination-scoped deny for a different destination: no match.
    let mut scoped = rule("deny-other-dst", "lan", "any", "deny");
    scoped.destination_addresses = vec!["203.0.113.0/24".to_string()];
    let state = parse_policy_state("permit", &[scoped], &zones());
    assert!(
        verdict(&state).is_none(),
        "an eligible deny whose destination does not match must not fire"
    );

    // Port-bearing deny: flow-backed 443 matches, flow-backed 22 does not,
    // flowless fails closed via the fragment-association override.
    let mut port_deny = rule("deny-https", "lan", "any", "deny");
    port_deny.application_terms = vec![PolicyApplicationSnapshot {
        name: "tcp-443".to_string(),
        protocol: "tcp".to_string(),
        source_port: String::new(),
        destination_port: "443".to_string(),
        icmp_type: None,
        icmp_code: None,
        inactivity_timeout: None,
    }];
    let state = parse_policy_state("permit", &[port_deny], &zones());
    assert!(
        verdict(&state).is_some(),
        "443 must hit the port-bearing deny"
    );
    let v22 = noroute_policy_denial(
        &state,
        LAN,
        UNZONED,
        0,
        src(),
        dst(),
        6,
        Some((40000, 22)),
        None,
        64,
    );
    assert!(v22.is_none(), "port 22 must not hit the 443 deny");
    let flowless = noroute_policy_denial(&state, LAN, UNZONED, 0, src(), dst(), 6, None, None, 64);
    assert!(
        flowless.is_some(),
        "a flowless packet must fail closed against the port-bearing eligible deny"
    );
}
