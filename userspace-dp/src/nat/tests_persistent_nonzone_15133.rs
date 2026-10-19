// #15133 (A91-07, #14322 residual): persistent-NAT inbound lookups for
// interface-, routing-instance- or global-scoped source-NAT rule-sets pass
// an empty `rule.from_zone`, which the allocator treats as UNSCOPED, so a
// `target-host-port` persistent mapping is widened to `any-remote-host`
// inbound when a sibling non-zone rule-set shares the pool with a
// permissive mode.
//
// Two rules naming one pool share one PortAllocator and one
// endpoint-independent lease for the same internal source (#9389). Rule A
// is scoped only by interface (ge-0/0/0.0), so from_zone is empty; it
// permits any-remote-host. Rule B is scoped only by interface
// (ge-0/0/1.0), also from_zone empty; it permits only target-host-port to
// 198.51.100.20:443. Before the fix both mints used the packet zones
// (trust->wan), so BOTH grants landed in ONE bucket on the shared lease,
// and the inbound lookup recomputed ("", ingress) -> UNSCOPED (any
// bucket admits), so the arbitrary remote was Permitted on B's strict
// binding.
//
// The fix keys grants and lookups by the ADMITTING RULE's normalized
// effective scope (its authored scope fields, empty zones replaced by
// the packet's resolved zones), so A's any-remote grant can never
// authorize B's binding even though both rule-sets have empty from_zone.

use super::*;
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::PROTO_TCP;
use std::net::IpAddr;

// Two port slots: persistent lease reuse is checked after the tracked-flow
// capacity gate, and a one-port pool caps that gate at a single live flow.
const POOL_PORT: u16 = 20_000;
const POOL_PORT_HIGH: u16 = 20_001;

fn nonzone_shared_pool_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "iface-any".to_string(),
            from_zone: String::new(),
            to_zone: String::new(),
            from_interface: "ge-0/0/0.0".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "iface-strict".to_string(),
            from_zone: String::new(),
            to_zone: String::new(),
            from_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "target-host-port".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
    ])
}

fn outbound(
    rules: &[SourceNatRule],
    ingress_ifname: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    now_ns: u64,
) -> TranslatedTuple {
    let mut counter = None;
    let scope = NatScopeCtx {
        ingress_ifname,
        ..NatScopeCtx::default()
    };
    match match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        rules,
        &scope,
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
        other => panic!("outbound via {ingress_ifname} must translate, got {other:?}"),
    }
}

fn inbound(
    rule: &SourceNatRule,
    translated: TranslatedTuple,
    remote_ip: IpAddr,
    remote_port: u16,
    now_ns: u64,
) -> PersistentInbound {
    // Packet pair = the original flow's (trust ingress, wan arrival),
    // matching the outbound mint's (trust, wan).
    rule.pool_allocator.persistent_inbound_lookup_for_rule(
        PROTO_TCP,
        translated.ip,
        translated.port,
        remote_ip,
        remote_port,
        now_ns,
        rule,
        "wan",
        "trust",
        "wan",
        &NatScopeCtx::default(),
    )
}
/// THE CELL: sibling interface-scoped rule-sets share one pool. The
/// permissive rule's any-remote-host grant must not widen the strict
/// rule's target-host-port binding, even though both rules carry empty
/// from_zone/to_zone.
///
/// RED pre-fix (probe): the strict rule's inbound lookup returns Permitted
/// for the arbitrary remote, because both grants share one bucket and the
/// empty-from_zone lookup is UNSCOPED (any bucket admits).
#[test]
fn nonzone_shared_pool_permissions_do_not_merge_15133() {
    let rules = nonzone_shared_pool_rules();
    assert_eq!(rules.len(), 2, "fixture: both rules must parse");
    assert!(
        rules[0]
            .pool_allocator
            .same_allocator(&rules[1].pool_allocator),
        "fixture: rules naming one pool must share one allocator"
    );
    assert!(rules[0].from_zone.is_empty() && rules[1].from_zone.is_empty(), "fixture: non-zone rule-sets");
    let strict_dst: IpAddr = "198.51.100.20".parse().expect("strict dst");
    let permissive_dst: IpAddr = "198.51.100.30".parse().expect("permissive dst");
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary remote");
    let now = 1_000;
    // Permissive rule mints first (any-remote-host), honoured on its OWN
    // rule's arrival scope only.
    let permissive_translated = outbound(&rules, "ge-0/0/0.0", permissive_dst, 443, now);
    let strict_translated = outbound(&rules, "ge-0/0/1.0", strict_dst, 443, now);
    assert_eq!(
        strict_translated, permissive_translated,
        "shared lease must keep one translated tuple (#9389)"
    );
    assert!(
        matches!(
            inbound(&rules[0], permissive_translated, arbitrary, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "the permissive rule keeps its any-remote-host grant on its own scope (#15133 control)"
    );
    assert!(
        matches!(
            inbound(&rules[1], strict_translated, strict_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "the strict rule's own target-host-port grant must still admit (#15133 control)"
    );
    assert_eq!(
        inbound(&rules[1], strict_translated, permissive_dst, 443, now),
        PersistentInbound::Denied,
        "the permissive rule's flow destination must not become a strict-rule grant (#15133)"
    );
    assert_eq!(
        inbound(&rules[1], strict_translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "any-remote-host minted via an interface-scoped sibling must not authorize inbound on the strict rule (#15133)"
    );
}


/// Global (fully unscoped) sibling: a rule-set with NO scope at all shares
/// the pool with a strict interface-scoped rule. Its any-remote-host grant
/// must not widen the strict rule either, and the global rule keeps its
/// own grant.
#[test]
fn global_shared_pool_permissions_do_not_merge_into_strict_15133() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "global-any".to_string(),
            from_interface: "ge-0/0/9.0".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "iface-strict".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "target-host-port".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    assert_eq!(rules.len(), 2, "fixture: both rules must parse");
    let strict_dst: IpAddr = "198.51.100.20".parse().expect("strict dst");
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary remote");
    let now = 1_000;
    // Global rule matches any ingress interface (empty scope).
    let global_translated = outbound(&rules, "ge-0/0/9.0", "198.51.100.30".parse().expect("global dst"), 443, now);
    let strict_translated = outbound(&rules, "ge-0/0/1.0", strict_dst, 443, now);
    assert_eq!(global_translated, strict_translated, "shared lease keeps one tuple");
    assert!(
        matches!(
            inbound(&rules[0], global_translated, arbitrary, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "the global rule keeps its any-remote-host grant (#15133 control)"
    );
    assert_eq!(
        inbound(&rules[1], strict_translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "a global any-remote-host grant must not widen the strict sibling (#15133)"
    );
    assert!(
        matches!(
            inbound(&rules[1], strict_translated, strict_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "the strict rule's own grant still admits (#15133 control)"
    );
}

/// Routing-instance-scoped sibling, same mechanism on the RI axis.
#[test]
fn ri_shared_pool_permissions_do_not_merge_15133() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "ri-any".to_string(),
            from_routing_instance: "ri-a".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "ri-strict".to_string(),
            from_routing_instance: "ri-b".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: POOL_PORT,
            port_high: POOL_PORT_HIGH,
            persistent_nat: true,
            persistent_nat_permit: "target-host-port".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    assert_eq!(rules.len(), 2, "fixture: both rules must parse");
    let strict_dst: IpAddr = "198.51.100.20".parse().expect("strict dst");
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary remote");
    let now = 1_000;
    let mut counter = None;
    let mut mint = |ri: &str, dst: IpAddr| -> TranslatedTuple {
        let scope = NatScopeCtx {
            ingress_routing_instance: ri,
            ..NatScopeCtx::default()
        };
        match match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            &rules,
            &scope,
            "trust",
            "wan",
            "10.0.0.5".parse().expect("src"),
            dst,
            Some(PROTO_TCP),
            40_000,
            443,
            None,
            None,
            now,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        ) {
            SourceNatLookup::Matched(d) => TranslatedTuple {
                ip: d.rewrite_src.expect("rewrite"),
                port: d.rewrite_src_port.expect("port"),
            },
            other => panic!("outbound via {ri} must translate, got {other:?}"),
        }
    };
    let any_t = mint("ri-a", "198.51.100.30".parse().expect("any dst"));
    let strict_t = mint("ri-b", strict_dst);
    assert_eq!(any_t, strict_t, "shared lease keeps one tuple");
    assert_eq!(
        inbound(&rules[1], strict_t, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "an RI-scoped any-remote-host grant must not widen the strict RI sibling (#15133)"
    );
    assert!(
        matches!(
            inbound(&rules[1], strict_t, strict_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "the strict RI rule's own grant still admits (#15133 control)"
    );
}



