// #9570 — a policy rule is GLOBAL only when BOTH structural sides carry the
// `junos-global` sentinel. Loaded from policy.rs as a `#[cfg(test)]` sibling.
//
// Before #9570 the classifier was `from_zone == "junos-global" || to_zone ==
// "junos-global"`, so a leniently-loaded zone-pair stanza naming the sentinel on
// ONE side was indexed into the global tier with an `Any` scope and enforced for
// every zone pair (measured at 1b5b4c291: `from junos-global to trust ... permit`
// under default deny gave lan->wan=Permit, untrust->lan=Permit). The Go #9410
// mirror, which already used `&&`, reported that snapshot refused.

use super::*;
use crate::test_zone_ids::*;

fn zones_9570() -> FxHashMap<String, u16> {
    let mut m = FxHashMap::default();
    m.insert("lan".to_string(), TEST_LAN_ZONE_ID);
    m.insert("wan".to_string(), TEST_WAN_ZONE_ID);
    m.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    m.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    m
}

fn any_rule_9570(name: &str, from_zone: &str, to_zone: &str, action: &str) -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: name.to_string(),
        from_zone: from_zone.to_string(),
        to_zone: to_zone.to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: action.to_string(),
        ..Default::default()
    }
}

fn parse_9570(
    default_policy: &str,
    rules: &[PolicyRuleSnapshot],
    zones: &FxHashMap<String, u16>,
) -> Result<PolicyState, SnapshotIntegrityError> {
    let store = PolicyCounterStore::default();
    parse_policy_state_with_counters(default_policy, rules, zones, &[], &store)
}

fn eval_9570(state: &PolicyState, from_id: u16, to_id: u16) -> PolicyAction {
    evaluate_policy(
        state,
        from_id,
        to_id,
        "10.0.0.1".parse().expect("src"),
        "10.0.0.2".parse().expect("dst"),
        PROTO_TCP,
        12345,
        443,
    )
}

/// Every HALF-sentinel spelling, in both action directions. Each must be refused
/// as an unresolvable zone, naming `junos-global`, which is the reason the Go
/// mirror reports for the same decoded rule.
#[test]
fn half_sentinel_zone_pair_rule_is_refused_not_promoted_to_global_9570() {
    let zones = zones_9570();
    for (from, to) in [
        ("junos-global", "trust"),
        ("trust", "junos-global"),
        ("any", "junos-global"),
        ("junos-global", "any"),
    ] {
        for (action, default_policy) in [("permit", "deny"), ("deny", "permit")] {
            let rules = [any_rule_9570("p1", from, to, action)];
            match parse_9570(default_policy, &rules, &zones) {
                Err(SnapshotIntegrityError::UnresolvableZoneReference { zone, .. }) => {
                    assert_eq!(zone, "junos-global", "{from}->{to}: refusal names the wrong zone");
                }
                Ok(state) => panic!(
                    "#9570: {from}->{to} {action} (default {default_policy}) was ACCEPTED and enforced: \
                     lan->wan={:?} untrust->lan={:?}",
                    eval_9570(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
                    eval_9570(&state, TEST_UNTRUST_ZONE_ID, TEST_LAN_ZONE_ID),
                ),
                Err(other) => panic!("#9570: {from}->{to}: refused for the wrong reason: {other:?}"),
            }
        }
    }
}

/// The accepting control. A both-sided rule is what the Go builder emits for a
/// real `security policies global` rule, so it must stay in the global tier with
/// its precedence unchanged: below an exact zone-pair rule, above the default.
#[test]
fn both_sided_sentinel_rule_is_still_the_global_tier_9570() {
    let zones = zones_9570();
    let state = parse_9570(
        "deny",
        &[any_rule_9570("g1", "junos-global", "junos-global", "permit")],
        &zones,
    )
    .expect("a real global rule must be accepted");
    assert_eq!(eval_9570(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID), PolicyAction::Permit);
    assert_eq!(eval_9570(&state, TEST_UNTRUST_ZONE_ID, TEST_LAN_ZONE_ID), PolicyAction::Permit);

    let state = parse_9570(
        "deny",
        &[
            any_rule_9570("g1", "junos-global", "junos-global", "permit"),
            any_rule_9570("zp", "lan", "wan", "deny"),
        ],
        &zones,
    )
    .expect("a zone-pair rule beside a global rule must be accepted");
    assert_eq!(
        eval_9570(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
        PolicyAction::Deny,
        "an exact zone-pair rule must still win over the global tier"
    );
    assert_eq!(eval_9570(&state, TEST_UNTRUST_ZONE_ID, TEST_LAN_ZONE_ID), PolicyAction::Permit);
}

/// The Go builder poisons a ZONE-PAIR stanza that names the sentinel with the
/// `__unsupported__` application term, because the both-sided spelling is
/// wire-identical to a real global rule. This pins that the helper refuses that
/// poison on a both-sided rule, which is the only spelling where the helper's
/// own predicate cannot help.
#[test]
fn builder_poison_on_a_both_sided_rule_refuses_the_snapshot_9570() {
    let mut rule = any_rule_9570("zp1", "junos-global", "junos-global", "permit");
    rule.application_terms = vec![PolicyApplicationSnapshot {
        name: "__unsupported__".to_string(),
        protocol: "__unsupported__".to_string(),
        ..Default::default()
    }];
    match parse_9570("deny", &[rule], &zones_9570()) {
        Err(SnapshotIntegrityError::UnrepresentableApplicationProtocol { .. }) => {}
        Ok(state) => panic!(
            "#9570: the builder's poison was accepted; lan->wan={:?}",
            eval_9570(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID)
        ),
        Err(other) => panic!("#9570: refused for the wrong reason: {other:?}"),
    }
}

/// A zone DEFINED as `junos-global` survives the tolerant compile with a warning
/// (#3055). A half-sentinel rule naming it then resolves as an ordinary zone
/// pair on that zone, and must NOT be enforced for unrelated pairs. Under the
/// old `||` it was a device-wide global rule even though the name resolved.
#[test]
fn half_sentinel_rule_against_a_zone_named_junos_global_is_scoped_to_that_zone_9570() {
    let mut zones = zones_9570();
    zones.insert("junos-global".to_string(), TEST_SFMIX_ZONE_ID);
    let state = parse_9570(
        "deny",
        &[any_rule_9570("p1", "junos-global", "trust", "permit")],
        &zones,
    )
    .expect("the name resolves, so the rule is an ordinary zone-pair rule");
    assert_eq!(eval_9570(&state, TEST_SFMIX_ZONE_ID, TEST_TRUST_ZONE_ID), PolicyAction::Permit);
    assert_eq!(
        eval_9570(&state, TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID),
        PolicyAction::Deny,
        "#9570: a rule scoped to one zone pair was enforced for an unrelated pair"
    );
    assert_eq!(eval_9570(&state, TEST_UNTRUST_ZONE_ID, TEST_LAN_ZONE_ID), PolicyAction::Deny);
}
