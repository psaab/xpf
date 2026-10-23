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

#[test]
fn imported_any_remote_grant_is_revoked_on_tightening_16017() {
    use super::idle_lease_sync_8121::IdleLeaseImport;

    let target: IpAddr = "198.51.100.20".parse().unwrap();
    let non_target: IpAddr = "203.0.113.99".parse().unwrap();
    let now = 1_000u64;
    let rules1 = rules_with_permit("any-remote-host");
    let translated = outbound(&rules1, target, 443, now);
    let rule1 = &rules1[0];
    assert!(rule1.pool_allocator.release_flow(
        crate::nat::SourceNatFlowKey {
            protocol: PROTO_TCP,
            src_ip: "10.0.0.5".parse().unwrap(),
            dst_ip: target,
            src_port: 40_000,
            dst_port: 443,
            routing_scope: 0,
        },
        translated,
        now,
        NatHolder::Untracked,
    ));
    let exported = rule1.pool_allocator.export_idle_leases(now + 1);
    assert_eq!(exported.len(), 1, "fixture: idle any-remote lease exports");

    // Fresh allocator models the standby importing the grant before the
    // permit change reaches it.
    let standby_rules = rules_with_permit("any-remote-host");
    let standby = &standby_rules[0];
    let pool_addrs = vec![translated.ip];
    assert_eq!(
        standby.pool_allocator.import_idle_lease(
            &exported[0],
            &pool_addrs,
            300_000_000_000,
            now + 2
        ),
        IdleLeaseImport::Installed
    );
    assert!(
        matches!(
            inbound(standby, translated, non_target, 9_999, now + 2),
            PersistentInbound::Permitted { .. }
        ),
        "fixture: imported any-remote grant admits before tightening"
    );

    // Reusing this allocator for the tightened generation must revoke the
    // imported (version-0) grant, not treat version 0 as always current.
    let tightened = crate::nat::parse_source_nat_rules_with_previous(
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
        Some(&standby_rules),
        &NatCounterStore::default(),
        now + 3,
    );
    assert!(
        standby
            .pool_allocator
            .same_allocator(&tightened[0].pool_allocator)
    );
    assert_eq!(
        inbound(&tightened[0], translated, non_target, 9_999, now + 3),
        PersistentInbound::Denied,
        "#16017 fold: imported version-0 any-remote grant must be revoked on tightening"
    );
}

#[test]
fn stale_generation_writer_cannot_reauthorize_after_sync_16017() {
    // Fold 2 interleaving: capture the old generation, sync the tightened
    // generation (epoch bump + demotion), then replay the OLD writer.
    // Its AnyRemoteHost record must be demoted, not reauthorize the grant.
    let target: IpAddr = "198.51.100.20".parse().unwrap();
    let non_target: IpAddr = "203.0.113.99".parse().unwrap();
    let now = 1_000u64;
    let old_rules = rules_with_permit("any-remote-host");
    let translated = outbound(&old_rules, target, 443, now);
    let old_rule = old_rules[0].clone();
    let old_epoch = old_rule.persistent_permit_epoch;

    let tightened = crate::nat::parse_source_nat_rules_with_previous(
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
        Some(&old_rules),
        &NatCounterStore::default(),
        now,
    );
    assert!(
        tightened[0].persistent_permit_epoch > old_epoch,
        "fixture: permit-change sync must bump the epoch (old {old_epoch}, new {})",
        tightened[0].persistent_permit_epoch
    );
    assert_eq!(
        inbound(&tightened[0], translated, non_target, 9_999, now),
        PersistentInbound::Denied,
        "fixture: sync demotes the old any-remote grant"
    );

    // Replay the old-generation writer after the sync: same flow, old
    // epoch, AnyRemoteHost. This is the in-flight mint/synced record an
    // old ForwardingState could still issue against the shared allocator.
    let flow = crate::nat::SourceNatFlowKey {
        protocol: PROTO_TCP,
        src_ip: "10.0.0.5".parse().unwrap(),
        dst_ip: target,
        src_port: 40_000,
        dst_port: 443,
        routing_scope: 0,
    };
    tightened[0]
        .pool_allocator
        .record_synced_persistent_permission_with_zones(
            flow,
            PersistentNatPermit::AnyRemoteHost,
            tightened[0].persistent_rule_scope("trust", "wan", "wan", &NatScopeCtx::default()),
            Some("trust"),
            old_epoch,
        );
    assert_eq!(
        inbound(&tightened[0], translated, non_target, 9_999, now),
        PersistentInbound::Denied,
        "#16017 fold 2: stale-generation writer must not reauthorize after permit-change sync"
    );
}

#[test]
fn validated_import_after_tightening_stays_demoted_16017() {
    // Fold 3: a generation-validated HA import arriving AFTER the local
    // rule tightened must not stamp current epoch + any_remote=true.
    // Generation validation proves record provenance, not local consent.
    use super::idle_lease_sync_8121::IdleLeaseImport;

    let target: IpAddr = "198.51.100.20".parse().unwrap();
    let non_target: IpAddr = "203.0.113.99".parse().unwrap();
    let now = 1_000u64;
    let rules1 = rules_with_permit("any-remote-host");
    let translated = outbound(&rules1, target, 443, now);
    assert!(rules1[0].pool_allocator.release_flow(
        crate::nat::SourceNatFlowKey {
            protocol: PROTO_TCP,
            src_ip: "10.0.0.5".parse().unwrap(),
            dst_ip: target,
            src_port: 40_000,
            dst_port: 443,
            routing_scope: 0,
        },
        translated,
        now,
        NatHolder::Untracked,
    ));
    let exported = rules1[0].pool_allocator.export_idle_leases(now + 1);
    assert_eq!(exported.len(), 1, "fixture: idle any-remote lease exports");
    assert!(
        exported[0].permit_any_remote,
        "fixture: record carries wildcard"
    );

    // Standby generation tightens first, then the validated import lands.
    let standby_rules = rules_with_permit("any-remote-host");
    let tightened = crate::nat::parse_source_nat_rules_with_previous(
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
        Some(&standby_rules),
        &NatCounterStore::default(),
        now + 2,
    );
    let pool_addrs = vec![translated.ip];
    // This is the coordinator's tightened branch: after_generation without
    // local AnyRemoteHost authorization.
    assert_eq!(
        tightened[0].pool_allocator.import_idle_lease_at_after_generation(
            &exported[0],
            Some(0),
            300_000_000_000,
            now + 3,
        ),
        IdleLeaseImport::Installed,
        "validated import still installs the lease (demoted, not refused)"
    );
    assert_eq!(
        inbound(&tightened[0], translated, non_target, 9_999, now + 3),
        PersistentInbound::Denied,
        "#16017 fold 3: generation-validated import must not re-authorize wildcard under tightened rule"
    );
}
