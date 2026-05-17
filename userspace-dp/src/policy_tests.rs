// Tests for policy.rs — relocated from inline
// `#[cfg(test)] mod tests` to keep policy.rs under the modularity-discipline
// LOC threshold. Loaded as a sibling submodule via
// `#[path = "policy_tests.rs"]` from policy.rs.

use super::*;
use crate::test_zone_ids::*;

fn test_zone_name_to_id() -> FxHashMap<String, u16> {
    let mut m = FxHashMap::default();
    m.insert("lan".to_string(), TEST_LAN_ZONE_ID);
    m.insert("wan".to_string(), TEST_WAN_ZONE_ID);
    m.insert("trust".to_string(), TEST_TRUST_ZONE_ID);
    m.insert("untrust".to_string(), TEST_UNTRUST_ZONE_ID);
    m.insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    m
}

#[test]
fn allow_all_matches_zone_pair() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-all".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn default_deny_applies_without_match() {
    let state = parse_policy_state("deny", &[], &test_zone_name_to_id());
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn evaluate_policy_skips_inactive_rules() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            rule_id: "security-policy:lan:wan:inactive-allow".to_string(),
            name: "inactive-allow".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            scheduler_name: "workhours".to_string(),
            inactive: true,
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );

    assert_eq!(
        state.rules[0].rule_id,
        "security-policy:lan:wan:inactive-allow"
    );
    assert_eq!(state.rules[0].scheduler_name, "workhours");
    assert!(state.rules[0].inactive);
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Deny
    );
    assert_eq!(
        state.rules[0]
            .hit_count
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
fn inactive_rule_falls_through_to_next_match() {
    let state = parse_policy_state(
        "deny",
        &[
            PolicyRuleSnapshot {
                name: "inactive-deny".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                scheduler_name: "offhours".to_string(),
                inactive: true,
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "deny".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                rule_id: "security-policy:lan:wan:active-allow".to_string(),
                name: "active-allow".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                action: "permit".to_string(),
                ..Default::default()
            },
        ],
        &test_zone_name_to_id(),
    );

    assert_eq!(state.rules[0].rule_id, "lan->wan/inactive-deny");
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        state.rules[0]
            .hit_count
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        state.rules[1]
            .hit_count
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn cidr_matches_ipv6() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-v6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["2001:559:8585:ef00::/64".to_string()],
            destination_addresses: vec!["2001:559:8585:80::/64".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "2001:559:8585:ef00::100".parse().expect("src"),
            "2001:559:8585:80::200".parse().expect("dst"),
            PROTO_TCP,
            12345,
            5201,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn named_application_matches_protocol_and_port() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-http".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["junos-http".to_string()],
            application_terms: vec![PolicyApplicationSnapshot {
                name: "junos-http".to_string(),
                protocol: "tcp".to_string(),
                source_port: String::new(),
                destination_port: "80".to_string(),
            }],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            80,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            443,
        ),
        PolicyAction::Deny
    );
}

#[test]
fn application_set_matches_any_expanded_term() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "allow-web".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["web".to_string()],
            application_terms: vec![
                PolicyApplicationSnapshot {
                    name: "junos-http".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "80".to_string(),
                },
                PolicyApplicationSnapshot {
                    name: "junos-https".to_string(),
                    protocol: "tcp".to_string(),
                    source_port: String::new(),
                    destination_port: "443".to_string(),
                },
            ],
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.61.100".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            PROTO_TCP,
            40000,
            443,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn global_policy_matches_any_zone_pair() {
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "global-allow".to_string(),
            from_zone: "junos-global".to_string(),
            to_zone: "junos-global".to_string(),
            source_addresses: vec!["any".to_string()],
            destination_addresses: vec!["any".to_string()],
            applications: vec!["any".to_string()],
            application_terms: Vec::new(),
            action: "permit".to_string(),
            ..Default::default()
        }],
        &test_zone_name_to_id(),
    );
    // Should match any zone pair
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_TRUST_ZONE_ID,
            TEST_UNTRUST_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            443,
        ),
        PolicyAction::Permit
    );
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_DMZ_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "192.168.1.1".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_UDP,
            5555,
            53,
        ),
        PolicyAction::Permit
    );
}

#[test]
fn global_policy_evaluated_after_zone_specific() {
    let state = parse_policy_state(
        "deny",
        &[
            PolicyRuleSnapshot {
                name: "deny-trust-to-untrust".to_string(),
                from_zone: "trust".to_string(),
                to_zone: "untrust".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "deny".to_string(),
                ..Default::default()
            },
            PolicyRuleSnapshot {
                name: "global-allow".to_string(),
                from_zone: "junos-global".to_string(),
                to_zone: "junos-global".to_string(),
                source_addresses: vec!["any".to_string()],
                destination_addresses: vec!["any".to_string()],
                applications: vec!["any".to_string()],
                application_terms: Vec::new(),
                action: "permit".to_string(),
                ..Default::default()
            },
        ],
        &test_zone_name_to_id(),
    );
    // Zone-specific deny should take precedence (evaluated first)
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_TRUST_ZONE_ID,
            TEST_UNTRUST_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
    // Different zone pair should hit the global permit
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_SFMIX_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
}

/// #919/#922: snapshot rules whose zone names are absent from
/// `zone_name_to_id` are dropped by `parse_policy_state` (logged
/// and not indexed). A real `LAN→WAN` lookup therefore finds
/// nothing and falls through to the default action.
#[test]
fn evaluate_policy_unknown_zone_pair_returns_default_action() {
    let zones = test_zone_name_to_id();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "rule".into(),
            from_zone: "ghost-from".into(),
            to_zone: "ghost-to".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
    );
    // Unknown-zone rule was not indexed; LAN→WAN lookup finds nothing → default deny.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "10.0.0.1".parse().expect("src"),
            "8.8.8.8".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Deny
    );
}

/// #923: legacy permissive parse — addresses that fail to parse
/// are silently dropped by `parse_address`. If ALL configured
/// addresses are malformed the resulting Vec is empty, which
/// `PrefixSet::from_prefixes(Vec::new())` collapses to
/// `MatchAny` — preserving the legacy `Vec::is_empty()` =
/// match-all behavior. This is intentional; a strict-parse
/// follow-up issue tracks fixing the silent-drop.
#[test]
fn malformed_only_input_yields_match_all_via_evaluate_policy() {
    let zones = test_zone_name_to_id();
    let state = parse_policy_state(
        "deny",
        &[PolicyRuleSnapshot {
            name: "permit-with-typo".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec![
                "totally-bogus".into(),
                "192.18.1/24".into(), // invalid (missing octet)
            ],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            application_terms: Vec::new(),
            action: "permit".into(),
            ..Default::default()
        }],
        &zones,
    );
    // The malformed source becomes MatchAny; an arbitrary src
    // hits the rule and returns Permit.
    assert_eq!(
        evaluate_policy(
            &state,
            TEST_LAN_ZONE_ID,
            TEST_WAN_ZONE_ID,
            "8.8.8.8".parse().expect("src"),
            "1.1.1.1".parse().expect("dst"),
            PROTO_TCP,
            12345,
            80,
        ),
        PolicyAction::Permit
    );
}
