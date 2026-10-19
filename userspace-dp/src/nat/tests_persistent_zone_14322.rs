// #14322: persistent-NAT permissions must not leak across egress zones when
// two source-NAT rules share one pool allocator.
//
// Two rules naming one pool share one PortAllocator and one
// endpoint-independent lease for the same internal source — deliberately,
// because the pool is one shared resource of (translated_ip, port) wire
// identities (#9389). SourceNatRule matching selects outbound rules by
// their (from_zone, to_zone) pair, so the same internal (src_ip, src_port)
// can egress via trust->dmz under `permit any-remote-host` and via
// trust->wan under `permit target-host-port`. Before the fix both flows
// recorded permits into one flat grant set on the shared lease, so the dmz
// rule's any_remote grant authorized arbitrary remotes inbound on the
// wan-side reflexive binding.
//
// The fix buckets grants by the admitting rule's folded egress scope on the
// SHARED lease: the lease identity and translated tuple stay shared, but an
// inbound lookup admits only grants recorded under the packet's
// (from, ingress) scope (or legacy unscoped grants).

use super::*;
use crate::SourceNATRuleSnapshot;
use crate::ip_proto::PROTO_TCP;
use std::net::IpAddr;

// Two port slots: persistent lease reuse is checked after the tracked-flow
// capacity gate, and a one-port pool caps that gate at a single live flow.
// Both test flows still share the first lease's translated tuple.
const POOL_PORT: u16 = 20_000;
const POOL_PORT_HIGH: u16 = 20_001;

fn shared_pool_rules() -> Vec<SourceNatRule> {
    parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "dmz-any".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "dmz".to_string(),
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
            name: "wan-strict".to_string(),
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
        },
    ])
}

fn outbound(
    rules: &[SourceNatRule],
    to_zone: &str,
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
        to_zone,
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
        other => panic!("outbound via {to_zone} must translate, got {other:?}"),
    }
}

fn inbound(
    rule: &SourceNatRule,
    ingress_zone: &str,
    translated: TranslatedTuple,
    remote_ip: IpAddr,
    remote_port: u16,
    now_ns: u64,
) -> PersistentInbound {
    // #15133: production admission keys the lookup by the admitting rule's
    // normalized scope. The packet pair is the ORIGINAL flow's
    // (internal ingress zone, arrival zone on the egress fabric): the
    // internal side is the rule's `from_zone` for a zone-authored rule,
    // the external side is where this unsolicited packet arrived.
    rule.pool_allocator.persistent_inbound_lookup_for_rule(
        PROTO_TCP,
        translated.ip,
        translated.port,
        remote_ip,
        remote_port,
        now_ns,
        rule,
        ingress_zone,
        &rule.from_zone,
        ingress_zone,
        &NatScopeCtx::default(),
    )
}

/// THE CELL (permissive first). Both outbound flows share ONE lease and ONE
/// translated tuple (endpoint-independent NAT is preserved), but the dmz
/// grant must not authorize arbitrary remotes on the wan side.
///
/// RED pre-fix: grants were one flat set, so the wan lookup below returns
/// Permitted for the arbitrary remote.
#[test]
fn shared_pool_persistent_permissions_do_not_leak_across_egress_zones_14322() {
    let rules = shared_pool_rules();
    assert_eq!(rules.len(), 2, "fixture: both rules must parse");
    assert!(
        rules[0]
            .pool_allocator
            .same_allocator(&rules[1].pool_allocator),
        "fixture: rules naming one pool must share one allocator"
    );
    let wan_dst: IpAddr = "198.51.100.20".parse().expect("wan dst");
    let dmz_dst: IpAddr = "198.51.100.30".parse().expect("dmz dst");
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary remote");
    let now = 1_000;
    let dmz_translated = outbound(&rules, "dmz", dmz_dst, 443, now);
    let wan_translated = outbound(&rules, "wan", wan_dst, 443, now);
    assert_eq!(
        wan_translated, dmz_translated,
        "shared lease must keep one translated tuple across egress zones"
    );
    assert!(
        matches!(
            inbound(&rules[0], "dmz", dmz_translated, arbitrary, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "the admitting zone keeps its any-remote-host grant"
    );
    assert_eq!(
        inbound(&rules[1], "wan", dmz_translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "any-remote-host minted via trust->dmz must not authorize inbound via trust->wan (#14322)"
    );
    assert!(
        matches!(
            inbound(&rules[1], "wan", dmz_translated, wan_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "the wan rule's own target-host-port grant must still admit"
    );
    assert_eq!(
        inbound(&rules[1], "wan", dmz_translated, dmz_dst, 443, now),
        PersistentInbound::Denied,
        "the dmz target grant must not become a wan grant"
    );
}

/// Reverse order: the strict rule mints first. Its target-host-port grant
/// must authorize only that exact remote on the wan side, and the later
/// permissive flow must not widen it (it still widens the DMZ side only).
#[test]
fn shared_pool_strict_first_then_permissive_does_not_widen_14322() {
    let rules = shared_pool_rules();
    let wan_dst: IpAddr = "198.51.100.20".parse().expect("wan dst");
    let dmz_dst: IpAddr = "198.51.100.30".parse().expect("dmz dst");
    let arbitrary: IpAddr = "203.0.113.99".parse().expect("arbitrary remote");
    let now = 1_000;
    let wan_translated = outbound(&rules, "wan", wan_dst, 443, now);
    assert!(
        matches!(
            inbound(&rules[1], "wan", wan_translated, wan_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "target-host-port admits its recorded remote"
    );
    assert_eq!(
        inbound(&rules[1], "wan", wan_translated, wan_dst, 8443, now),
        PersistentInbound::Denied,
        "target-host-port must not admit a different port on the target host"
    );
    assert_eq!(
        inbound(&rules[1], "wan", wan_translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "no grant exists for an arbitrary remote on the wan side"
    );
    let dmz_translated = outbound(&rules, "dmz", dmz_dst, 443, now);
    assert_eq!(
        dmz_translated, wan_translated,
        "shared lease keeps one tuple"
    );
    assert_eq!(
        inbound(&rules[1], "wan", wan_translated, arbitrary, 9_999, now),
        PersistentInbound::Denied,
        "the dmz any-remote-host flow must not widen the wan binding"
    );
    assert!(
        matches!(
            inbound(&rules[0], "dmz", wan_translated, arbitrary, 9_999, now),
            PersistentInbound::Permitted { .. }
        ),
        "the dmz side does gain its own any-remote grant"
    );
    assert!(
        matches!(
            inbound(&rules[1], "wan", wan_translated, wan_dst, 443, now),
            PersistentInbound::Permitted { .. }
        ),
        "the wan target-host-port grant survives the dmz flow"
    );
}
