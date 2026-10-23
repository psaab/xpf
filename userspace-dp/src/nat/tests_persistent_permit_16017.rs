// #16017: persistent-NAT permit tightening does not revoke stored grants.
//
// Mint an any-remote-host lease, rebuild the same pool with a tightened
// permit (same pool name/addresses/ports, so the allocator is reused),
// then probe `persistent_inbound_lookup_for_rule` from a non-target
// remote — it must be Denied post-fix (today Permitted). An
// unchanged-permit rebuild must preserve the grant.

use super::*;
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::PROTO_TCP;
use std::net::IpAddr;

const POOL_PORT: u16 = 20_000;
const POOL_PORT_HIGH: u16 = 20_001;

fn rules_with_permit(permit: &str) -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "wan".to_string(),
        from_zone: "trust".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.0/24".to_string()],
        pool_name: "shared".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: POOL_PORT,
        port_high: POOL_PORT_HIGH,
        persistent_nat: true,
        persistent_nat_permit: permit.to_string(),
        persistent_nat_inactivity_timeout: 300,
        ..SourceNATRuleSnapshot::default()
    }])
}

fn outbound(
    rules: &[SourceNatRule],
    dst_ip: IpAddr,
    dst_port: u16,
    now_ns: u64,
) -> TranslatedTuple {
    let mut counter = None;
    match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &NatScopeCtx::default(),
        "trust",
        "wan",
        "10.0.0.5".parse().expect("src"),
        dst_ip,
        Some(PROTO_TCP),
        40_000,
        dst_port,
        None,
        None,
        now_ns,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    ) {
        SourceNatLookup::Matched(decision) => TranslatedTuple {
            ip: decision.rewrite_src.expect("pool rewrite"),
            port: decision.rewrite_src_port.expect("pool port rewrite"),
        },
        other => panic!("outbound must translate, got {other:?}"),
    }
}

fn inbound(
    rule: &SourceNatRule,
    translated: TranslatedTuple,
    remote_ip: IpAddr,
    remote_port: u16,
    now_ns: u64,
) -> PersistentInbound {
    rule.pool_allocator.persistent_inbound_lookup_for_rule(
        PROTO_TCP,
        translated.ip,
        translated.port,
        remote_ip,
        remote_port,
        now_ns,
        rule,
        "wan",
        &rule.from_zone,
        "wan",
        &NatScopeCtx::default(),
    )
}

#[test]
fn persistent_permit_tightening_revokes_any_remote_grant_16017() {
    let target: IpAddr = "198.51.100.20".parse().unwrap();
    let non_target: IpAddr = "203.0.113.99".parse().unwrap();
    let now = 1_000u64;

    let rules1 = rules_with_permit("any-remote-host");
    let translated = outbound(&rules1, target, 443, now);
    // Control: any-remote admits the non-target before tightening.
    assert!(
        matches!(
            inbound(&rules1[0], translated, non_target, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "fixture: any-remote-host must admit arbitrary remote before rebuild"
    );

    // Rebuild same pool + tightened permit; allocator must be reused.
    let rules2 = crate::nat::parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "wan".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "target-host-port".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        }],
        Some(&rules1),
        &NatCounterStore::default(),
        now,
    );
    assert!(
        rules1[0]
            .pool_allocator
            .same_allocator(&rules2[0].pool_allocator),
        "fixture: same pool must reuse the allocator"
    );
    // Decisive check: non-target remote must be denied post-fix.
    assert_eq!(
        inbound(&rules2[0], translated, non_target, 9_999, now),
        PersistentInbound::Denied,
        "#16017: tightened permit must revoke the stored any-remote grant"
    );
    // The original target's exact (host,port) grant remains permitted:
    // outbound under any-remote recorded no exact remote, so target is
    // also denied — tightening to target-host-port grants nothing retroactively.
    // (This asserts fail-closed, not a widening.)
    assert_eq!(
        inbound(&rules2[0], translated, target, 443, now),
        PersistentInbound::Denied,
        "#16017: tightening must not invent an exact grant that was never recorded under the new permit"
    );
}

#[test]
fn persistent_permit_unchanged_preserves_any_remote_grant_16017() {
    let target: IpAddr = "198.51.100.20".parse().unwrap();
    let non_target: IpAddr = "203.0.113.99".parse().unwrap();
    let now = 1_000u64;

    let rules1 = rules_with_permit("any-remote-host");
    let translated = outbound(&rules1, target, 443, now);

    let rules2 = crate::nat::parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "wan".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        }],
        Some(&rules1),
        &NatCounterStore::default(),
        now,
    );
    assert!(
        rules1[0]
            .pool_allocator
            .same_allocator(&rules2[0].pool_allocator),
        "fixture: same pool must reuse the allocator"
    );
    assert!(
        matches!(
            inbound(&rules2[0], translated, non_target, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "#16017 control: unchanged any-remote permit must preserve the grant across reuse"
    );
}

#[test]
fn persistent_permit_tightening_to_target_host_revokes_any_remote_16017() {
    let target: IpAddr = "198.51.100.20".parse().unwrap();
    let non_target: IpAddr = "203.0.113.99".parse().unwrap();
    let now = 1_000u64;

    let rules1 = rules_with_permit("any-remote-host");
    let translated = outbound(&rules1, target, 443, now);

    let rules2 = crate::nat::parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "wan".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "target-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        }],
        Some(&rules1),
        &NatCounterStore::default(),
        now,
    );
    assert_eq!(
        inbound(&rules2[0], translated, non_target, 9_999, now),
        PersistentInbound::Denied,
        "#16017: tightening to target-host must revoke any-remote grant"
    );
}
