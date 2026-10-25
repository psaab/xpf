// #16831 — a Junos functional zone (`security zones functional-zone
// management`) is host-only: traffic entering it does not match policies
// and cannot transit to another interface. Loaded from policy.rs as a
// `#[cfg(test)]` sibling.
//
// Before #16831 the zone compiled into an ordinary transit zone, so a
// global permit (or a leniently-loaded management->trust permit)
// forwarded management<->data traffic. RED-on-revert: dropping the
// functional denial in evaluate_policy_result_counted (or the
// functional exclusion from concrete_zone_ids) makes the transit cells
// below return Permit.

use super::*;
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv4Addr};

const MGMT_ZONE_ID: u32 = 4242;

fn zones_16831() -> FxHashMap<String, u32> {
    let mut m = FxHashMap::default();
    m.insert("management".to_string(), MGMT_ZONE_ID);
    m.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    m.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    m
}

fn functional_16831() -> FxHashSet<u32> {
    let mut s = FxHashSet::default();
    s.insert(MGMT_ZONE_ID);
    s
}

fn any_rule_16831(name: &str, from_zone: &str, to_zone: &str, action: &str) -> PolicyRuleSnapshot {
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

fn eval_16831(state: &PolicyState, from_id: u32, to_id: u32) -> PolicyAction {
    evaluate_policy(
        state,
        from_id,
        to_id,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        6,
        12345,
        22,
    )
}

/// Transit into/out of the functional zone is denied under a global
/// permit AND under default-permit; the ordinary twin pair still
/// forwards under the same global permit (control).
#[test]
fn functional_transit_denied_under_global_and_default_permit_16831() {
    let zones = zones_16831();
    let functional = functional_16831();
    let global = [any_rule_16831("g1", "junos-global", "junos-global", "permit")];

    let state = parse_policy_state_with_functional("deny", &global, &zones, &functional);
    assert_eq!(eval_16831(&state, MGMT_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval_16831(&state, TEST_TRUST_ZONE_ID, MGMT_ZONE_ID), PolicyAction::Deny);
    // Control: ordinary pair still permitted by the same global rule.
    assert_eq!(eval_16831(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);

    // Default-permit cannot rescue functional transit either.
    let state = parse_policy_state_with_functional("permit", &[], &zones, &functional);
    assert_eq!(eval_16831(&state, MGMT_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval_16831(&state, TEST_TRUST_ZONE_ID, MGMT_ZONE_ID), PolicyAction::Deny);
    assert_eq!(eval_16831(&state, TEST_TRUST_ZONE_ID, TEST_UNTRUST_ZONE_ID), PolicyAction::Permit);
}

/// A leniently-loaded zone-pair permit naming the functional zone stays
/// indexed (strict commit rejects it, tolerant load only warns) but can
/// never fire. The twin without the functional mark forwards (control).
#[test]
fn functional_zone_pair_permit_never_fires_16831() {
    let zones = zones_16831();
    let rules = [any_rule_16831("p1", "management", "trust", "permit")];

    let state = parse_policy_state_with_functional("deny", &rules, &zones, &functional_16831());
    assert_eq!(eval_16831(&state, MGMT_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Deny);

    let twin = parse_policy_state_with_functional("deny", &rules, &zones, &FxHashSet::default());
    assert_eq!(eval_16831(&twin, MGMT_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
}

/// Host-inbound is the functional zone's legitimate traffic: a
/// `to-zone junos-host` permit from the functional zone still matches on
/// the host path (ssh to the interface address), while the same flow as
/// transit is denied above.
#[test]
fn functional_host_inbound_still_admitted_16831() {
    let zones = zones_16831();
    let rules = [any_rule_16831("host-ssh", "management", "junos-host", "permit")];
    let state = parse_policy_state_with_functional("deny", &rules, &zones, &functional_16831());
    let host = evaluate_junos_host_policy(
        &state,
        MGMT_ZONE_ID,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
        6,
        12345,
        22,
        None,
        60,
    );
    assert_eq!(host.map(|r| r.action), Some(PolicyAction::Permit));
}

/// The wire helper derives the functional id set from ZoneSnapshot rows
/// marked `functional`, skipping unaddressable rows.
#[test]
fn functional_ids_from_snapshot_16831() {
    let zones = vec![
        ZoneSnapshot { name: "management".into(), id: MGMT_ZONE_ID, functional: true, ..Default::default() },
        ZoneSnapshot { name: "trust".into(), id: TEST_TRUST_ZONE_ID, ..Default::default() },
        ZoneSnapshot { name: "ghost".into(), id: 0, functional: true, ..Default::default() },
    ];
    let set = functional_zone_ids_from_snapshot(&zones);
    assert!(set.contains(&MGMT_ZONE_ID));
    assert!(!set.contains(&TEST_TRUST_ZONE_ID));
    assert_eq!(set.len(), 1);
}
