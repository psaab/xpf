// NAT interface / routing-instance scoping tests (source, static,
// destination) for the nat/ module.
//
// Split out of nat/tests.rs (#4409) as a sibling `#[path]` test module
// loaded from nat/mod.rs. Pure code motion: every #[test] fn and
// test-local helper is moved verbatim.
#![allow(unused_imports)]

use super::allocator::{
    ALLOCATION_GC_BUDGET, NS_PER_SEC, PersistentLease, PersistentSourceKey, PoolAddressFamily,
    TranslatedTuple, sticky_pool_index,
};
use super::source::{PersistentNatPermit, SOURCE_NAT_PROTO_ANY, SourceNatFlowKey};
use super::destination::{PROTO_ANY, PROTO_TCP, PROTO_UDP};
use super::*;
use crate::ip_proto::{PROTO_ESP, PROTO_GRE, PROTO_ICMP, PROTO_ICMPV6};
use crate::{
    DestinationNATRuleSnapshot, NatAppTermWire, NatPortRangeWire, SourceNATRuleSnapshot,
    StaticNATRuleSnapshot,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Source NAT scoped by `from interface`: matches a flow ingressing the named
// interface, NOT another. Fail-on-revert: dropping the `scope_matches` gate in
// SourceNatRule::matches makes the second assertion (wrong-interface) match and
// so RED.
#[test]
fn source_nat_from_interface_scope_matches_only_named_iface() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_interface: "ge-0/0/1.0".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());

    // Ingress on the named interface -> matches.
    let on_iface = NatScopeCtx {
        ingress_ifname: "ge-0/0/1.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &on_iface,
            "",
            "",
            src,
            dst,
            egress_v4,
            None
        )
        .is_some(),
        "from-interface-scoped SNAT must match traffic ingressing the named interface"
    );

    // Ingress on a DIFFERENT interface -> no match.
    let other_iface = NatScopeCtx {
        ingress_ifname: "ge-0/0/2.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &other_iface,
            "",
            "",
            src,
            dst,
            egress_v4,
            None
        )
        .is_none(),
        "from-interface-scoped SNAT must NOT match traffic ingressing another interface"
    );
}

// Source NAT scoped by `from routing-instance`: matches only the named VRF.
#[test]
fn source_nat_from_routing_instance_scope_matches_only_named_vrf() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_routing_instance: "VR1".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());

    let in_vr1 = NatScopeCtx {
        ingress_routing_instance: "VR1",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &in_vr1,
            "",
            "",
            src,
            dst,
            egress_v4,
            None
        )
        .is_some(),
        "from-routing-instance-scoped SNAT must match traffic in the named VRF"
    );

    let in_vr2 = NatScopeCtx {
        ingress_routing_instance: "VR2",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &in_vr2,
            "",
            "",
            src,
            dst,
            egress_v4,
            None
        )
        .is_none(),
        "from-routing-instance-scoped SNAT must NOT match traffic in another VRF"
    );
}

// Source NAT scoped by `to interface`: matches only the named egress interface.
#[test]
fn source_nat_to_interface_scope_matches_only_named_egress() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        to_interface: "ge-0/0/2.0".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());

    let to_named = NatScopeCtx {
        egress_ifname: "ge-0/0/2.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &to_named,
            "",
            "",
            src,
            dst,
            egress_v4,
            None
        )
        .is_some(),
        "to-interface-scoped SNAT must match traffic egressing the named interface"
    );
    let to_other = NatScopeCtx {
        egress_ifname: "ge-0/0/9.0",
        ..NatScopeCtx::default()
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &to_other,
            "",
            "",
            src,
            dst,
            egress_v4,
            None
        )
        .is_none(),
        "to-interface-scoped SNAT must NOT match traffic egressing another interface"
    );
}

// A zone-scoped source NAT rule is unaffected by the #3096 scope plumbing
// (no-regression): empty interface/RI scope = wildcard, so any interface/VRF
// in the matching zone pair still matches.
#[test]
fn source_nat_zone_scope_unaffected_by_interface_plumbing() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let src: IpAddr = "10.0.61.102".parse().unwrap();
    let dst: IpAddr = "172.16.80.200".parse().unwrap();
    let egress_v4 = Some("172.16.80.8".parse().unwrap());
    // Arbitrary interface names in the scope ctx must not affect a zone rule.
    let scope = NatScopeCtx {
        ingress_ifname: "ge-0/0/7.0",
        egress_ifname: "ge-0/0/8.0",
        ingress_routing_instance: "whatever",
        egress_routing_instance: "whatever",
        routing_domain: 0,
    };
    assert!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &scope,
            "lan",
            "wan",
            src,
            dst,
            egress_v4,
            None
        )
        .is_some(),
        "zone-scoped SNAT must still match regardless of interface/RI ctx"
    );
}

// Static NAT (DNAT direction) scoped by `from interface`: the inbound
// translation fires only when the packet ingresses the named interface.
// Fail-on-revert: dropping the interface gate in match_dnat_with_counter_scoped
// makes the wrong-interface assertion fire and so RED.
#[test]
fn static_nat_dnat_from_interface_scope_matches_only_named_iface() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            name: "stat".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    // On the named interface -> DNAT applies.
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, None, "", "ge-0/0/1.0", "")
            .is_some(),
        "interface-scoped static DNAT must match on the named ingress interface"
    );
    // On a different interface -> no DNAT.
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, None, "", "ge-0/0/2.0", "")
            .is_none(),
        "interface-scoped static DNAT must NOT match on another ingress interface"
    );
}

// Static NAT (SNAT/reverse direction) scoped by `from interface`: the reverse
// source translation fires only when the packet egresses the named interface.
#[test]
fn static_nat_snat_from_interface_scope_matches_only_named_egress() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            source_addresses: Vec::new(),
            name: "stat".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let int: IpAddr = "192.168.1.10".parse().unwrap();
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, None, "", "ge-0/0/1.0", "")
            .is_some(),
        "interface-scoped static SNAT must match on the named egress interface"
    );
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, None, "", "ge-0/0/2.0", "")
            .is_none(),
        "interface-scoped static SNAT must NOT match on another egress interface"
    );
}

// #3435 (H01): static-NAT `match source-address` must gate the inbound DNAT
// translation on the packet SOURCE. Before #3435 the constraint was dropped at
// the snapshot boundary, installing an all-source mapping that exposed the
// internal host to ANY source. Fail-on-revert: dropping the `source_ok` gate
// makes the out-of-scope-source assertion (which expects None) match and so RED.
#[test]
fn static_nat_dnat_source_address_gates_inbound() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["198.51.100.0/24".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    let in_scope: IpAddr = "198.51.100.7".parse().unwrap();
    let out_scope: IpAddr = "203.0.113.99".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(in_scope), "", "", "")
            .is_some(),
        "static DNAT must fire for a source inside `match source-address`"
    );
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(out_scope), "", "", "")
            .is_none(),
        "static DNAT must NOT fire for a source outside `match source-address` (the #3435 fail-open)"
    );
}

// #3435 (M02): a bracket / repeated source-address list must honor EVERY prefix
// (the multi-value scalar loss). Fail-on-revert: if the compiler/snapshot drops
// every entry after the first, the second-prefix source goes unmatched and the
// loop assertion RED.
#[test]
fn static_nat_dnat_source_address_bracket_list() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec![
                "198.51.100.0/24".to_string(),
                "203.0.113.200".to_string(),
            ],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    for src in ["198.51.100.7", "203.0.113.200"] {
        let s: IpAddr = src.parse().unwrap();
        assert!(
            table
                .match_dnat_with_counter_scoped(ext, 0, Some(s), "", "", "")
                .is_some(),
            "static DNAT must fire for source {src} in the bracket list"
        );
    }
    let out: IpAddr = "10.0.0.1".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(out), "", "", "")
            .is_none(),
        "static DNAT must NOT fire for a source outside the bracket list"
    );
}

// #3435: the reverse (SNAT) direction gates on the packet DESTINATION (the
// original client), symmetric with the inbound source gate. Fail-on-revert:
// dropping the source gate lets an out-of-scope destination match.
#[test]
fn static_nat_snat_source_address_gates_reverse() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["198.51.100.0/24".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let int: IpAddr = "192.168.1.10".parse().unwrap();
    let in_scope: IpAddr = "198.51.100.7".parse().unwrap();
    let out_scope: IpAddr = "203.0.113.99".parse().unwrap();
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, Some(in_scope), "", "", "")
            .is_some(),
        "reverse static SNAT must fire toward a client inside `match source-address`"
    );
    assert!(
        table
            .match_snat_with_counter_scoped(int, 0, Some(out_scope), "", "", "")
            .is_none(),
        "reverse static SNAT must NOT fire toward a client outside `match source-address`"
    );
}

// #3435: a source-constrained rule whose source list parses to NOTHING (every
// entry malformed) must match NO source — fail CLOSED, never revert to
// match-any (the #2394/#3435 fail-open guard). Fail-on-revert: collapsing the
// unparseable list to "unconstrained" makes the assertion (expecting None) RED.
#[test]
fn static_nat_dnat_source_address_unparseable_fails_closed() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            source_addresses: vec!["not-an-ip".to_string()],
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    let any: IpAddr = "198.51.100.7".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(any), "", "", "")
            .is_none(),
        "a source-scoped rule with no parseable prefix must match nothing (fail closed)"
    );
}

// #3435: guard against over-gating — an UNscoped static-NAT rule (no `match
// source-address`) must still translate every source.
#[test]
fn static_nat_dnat_no_source_constraint_matches_any() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[StaticNATRuleSnapshot {
            name: "stat".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "192.168.1.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        }],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    let any: IpAddr = "10.9.8.7".parse().unwrap();
    assert!(
        table
            .match_dnat_with_counter_scoped(ext, 0, Some(any), "", "", "")
            .is_some(),
        "an unscoped static DNAT must match any source"
    );
}

// === #3605: zone/scope-differentiated static-NAT rules must COEXIST ===

// Split-horizon static DNAT: two rules share the same `(external_ip,
// match-port)` key but differ by `from zone`, translating the same public
// address to a DIFFERENT internal host per ingress zone. Both must be
// installed and matched by scope.
//
// Fail-on-revert: with the pre-#3605 single-entry map the second rule
// OVERWRITES the first (last-write-wins), so the untrust packet — whose only
// surviving entry is the dmz-scoped rule — fails `zone_ok` and returns None
// (a silent UNtranslated leak). The untrust assertion below then RED.
#[test]
fn static_nat_dnat_scope_differentiated_rules_coexist_3605() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                name: "from-untrust".to_string(),
                from_zone: "untrust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            StaticNATRuleSnapshot {
                name: "from-dmz".to_string(),
                from_zone: "dmz".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "10.0.0.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    // Packet ingressing untrust -> the untrust rule (192.168.1.10). This is the
    // rule OVERWRITTEN pre-#3605, so this assertion is the fail-on-revert.
    let via_untrust = table
        .match_dnat_with_counter_scoped(ext, 0, None, "untrust", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_untrust,
        Some(Some("192.168.1.10".parse().unwrap())),
        "untrust-scoped static DNAT must survive alongside the dmz-scoped rule (#3605 overwrite)"
    );
    // Packet ingressing dmz -> the dmz rule (10.0.0.10).
    let via_dmz = table
        .match_dnat_with_counter_scoped(ext, 0, None, "dmz", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_dmz,
        Some(Some("10.0.0.10".parse().unwrap())),
        "dmz-scoped static DNAT must translate to its own internal host"
    );
}

// Reverse (SNAT) direction of the same #3605 overwrite: two rules map DIFFERENT
// external addresses to the SAME internal host, scoped by different egress
// zones. The SNAT map keys on `(internal_ip, snat_port)`, so both rules collide
// on one key and the pre-#3605 map kept only the last -> the trust-egress
// return packet un-NATs to the wrong (or no) external address.
//
// Fail-on-revert: the trust assertion RED because its rule was overwritten by
// the wan-scoped rule.
#[test]
fn static_nat_snat_scope_differentiated_rules_coexist_3605() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                name: "egress-trust".to_string(),
                from_zone: "trust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            StaticNATRuleSnapshot {
                name: "egress-wan".to_string(),
                from_zone: "wan".to_string(),
                external_ip: "203.0.113.20".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    let int: IpAddr = "192.168.1.10".parse().unwrap();
    // Return packet egressing trust -> un-NAT to 203.0.113.10 (overwritten rule).
    let via_trust = table
        .match_snat_with_counter_scoped(int, 0, None, "trust", "", "")
        .map(|(d, _)| d.rewrite_src);
    assert_eq!(
        via_trust,
        Some(Some("203.0.113.10".parse().unwrap())),
        "trust-egress static SNAT must survive alongside the wan-scoped rule (#3605 overwrite)"
    );
    // Return packet egressing wan -> un-NAT to 203.0.113.20.
    let via_wan = table
        .match_snat_with_counter_scoped(int, 0, None, "wan", "", "")
        .map(|(d, _)| d.rewrite_src);
    assert_eq!(
        via_wan,
        Some(Some("203.0.113.20".parse().unwrap())),
        "wan-egress static SNAT must un-NAT to its own external address"
    );
}

// #3605 specificity tiering: a zone-SCOPED rule and a zone-WILDCARD rule share
// the same `(external_ip, match-port)` key. A packet matching the scoped zone
// must hit the SPECIFIC rule, not the wildcard — regardless of config order
// (the wildcard is authored FIRST here, the adversarial order). Traffic in any
// other zone falls through to the wildcard.
//
// Fail-on-revert: with the single-entry map the scoped rule (authored second)
// overwrites the wildcard, so the "other zone" packet — whose only entry is now
// the trust-scoped rule — returns None instead of the wildcard translation, so
// the other-zone assertion RED.
#[test]
fn static_nat_dnat_scoped_rule_wins_over_coexisting_wildcard_3605() {
    let counters = NatCounterStore::default();
    let table = StaticNatTable::from_snapshots(
        &[
            StaticNATRuleSnapshot {
                name: "wildcard".to_string(),
                from_zone: String::new(), // any zone
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "10.0.0.99".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
            StaticNATRuleSnapshot {
                name: "trust-specific".to_string(),
                from_zone: "trust".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "192.168.1.10".to_string(),
                ..StaticNATRuleSnapshot::default()
            },
        ],
        &counters,
    );
    let ext: IpAddr = "203.0.113.10".parse().unwrap();
    // trust ingress -> the SPECIFIC rule wins over the wildcard.
    let via_trust = table
        .match_dnat_with_counter_scoped(ext, 0, None, "trust", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_trust,
        Some(Some("192.168.1.10".parse().unwrap())),
        "the zone-specific rule must win over a coexisting wildcard regardless of order (#3605)"
    );
    // any other zone -> the wildcard catch-all (fail-on-revert: overwritten).
    let via_other = table
        .match_dnat_with_counter_scoped(ext, 0, None, "untrust", "", "")
        .map(|(d, _)| d.rewrite_dst);
    assert_eq!(
        via_other,
        Some(Some("10.0.0.99".parse().unwrap())),
        "an unmatched zone must fall through to the coexisting wildcard rule (#3605 overwrite)"
    );
}

// Destination NAT scoped by `from interface`: the DNAT entry fires only for the
// named ingress interface. Fail-on-revert: dropping the scope_ok gate in
// match_entries makes the wrong-interface assertion fire and so RED.
#[test]
fn destination_nat_from_interface_scope_matches_only_named_iface() {
    let counters = NatCounterStore::default();
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "dnat".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            destination_address: "203.0.113.10".to_string(),
            pool_address: "10.0.0.5".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &counters,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "ge-0/0/1.0", "", None)
            .is_some(),
        "interface-scoped DNAT must match on the named ingress interface"
    );
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "ge-0/0/2.0", "", None)
            .is_none(),
        "interface-scoped DNAT must NOT match on another ingress interface"
    );
}

// Destination NAT scoped by `from routing-instance`.
#[test]
fn destination_nat_from_routing_instance_scope_matches_only_named_vrf() {
    let counters = NatCounterStore::default();
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "dnat".to_string(),
            from_routing_instance: "VR1".to_string(),
            destination_address: "203.0.113.10".to_string(),
            pool_address: "10.0.0.5".to_string(),
            ..DestinationNATRuleSnapshot::default()
        }],
        &counters,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "", "VR1", None)
            .is_some(),
        "RI-scoped DNAT must match in the named VRF"
    );
    assert!(
        table
            .lookup_with_counter_scoped(PROTO_TCP, src, dst, 0, 443, "", "", "VR2", None)
            .is_none(),
        "RI-scoped DNAT must NOT match in another VRF"
    );
}

// === #3429: source-NAT `match destination-port` / `match application`
// enforcement. Before the fix these match fields were parsed and compiled but
// never carried to the dataplane, so a port/app-scoped source-NAT rule
// (including a `then source-nat off` exemption) silently widened to every
// port/protocol. Reverting the l4_matches gate makes the wrong-port / wrong-app
// lookups translate, turning the NoMatch assertions RED. ===


// #9062: two rule-sets scoped to DIFFERENT routing instances that reference the
// SAME pool shared one flow-identity space and one PortAllocator, so an
// identical 5-tuple in two VRFs collided.
//
// `live_by_flow.get(&flow)` then handed the second tenant's flow the FIRST's
// translated tuple. #7160 cannot recover it: the reverse index is inserted and
// probed with routing_domain 0, and the two-pass domain PREFERENCE it uses has
// nothing to prefer once both forward sessions carry the same reverse identity.
#[test]
fn source_nat_flow_key_separates_routing_domains_9062() {
    let a = SourceNatFlowKey {
        protocol: 6,
        src_ip: "10.0.0.1".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 1234,
        dst_port: 443,
        routing_scope: 1,
    };
    let b = SourceNatFlowKey {
        routing_scope: 2,
        ..a
    };
    assert_ne!(
        a, b,
        "an identical 5-tuple in two routing domains must be two flow \
         identities; sharing one is the cross-tenant reply misdelivery"
    );

    // REFERENCE ARM: the SAME domain must still be the same flow, or every
    // repeat packet of one flow mints a new translation and the pool drains.
    let a2 = SourceNatFlowKey { ..a };
    assert_eq!(a, a2, "the same flow in the same domain must be one identity");

    // The unscoped default is 0, so a deployment with no routing instances
    // keys exactly as it did before this change.
    let unscoped = SourceNatFlowKey {
        routing_scope: 0,
        ..a
    };
    assert_ne!(unscoped, a, "domain 0 and domain 1 are different scopes");
}

// #9389 INVERTED THIS CELL. It asserted the opposite, and it was wrong.
//
// The comment it replaces read: "Keying only the flow would still leave both
// tenants drawing ports from ONE PortAllocator, so a port handed to one is
// unavailable to the other -- a quieter defect than the collision."
//
// THAT IS NOT A DEFECT. It is a shared pool working correctly. A pool is a
// finite set of wire identities, and one `(address, port)` backs exactly one
// flow whatever routing instance its traffic came from. "Unavailable to the
// other" is what a shared resource means.
//
// #9062's real defect was the OTHER half of that sentence -- two tenants with
// identical 5-tuples resolving to one `live_by_flow` record and being handed
// the SAME translation -- and `SourceNatFlowKey::routing_scope` closes it
// alone. With distinct flow keys the two tenants hold two records and draw two
// DIFFERENT ports from the one allocator, which is the correct outcome.
//
// Splitting the allocator as well produced two pointer-distinct `PortAllocator`s
// over identical addresses, either of which could mint the same `(addr, port)`
// for a different tenant. The #6979/#8115 overlap guard correctly refused that
// (`same_allocator` is `Arc::ptr_eq`), so mints came back
// `PoolPeerAddressOverlap` and were dropped -- measured at five consecutive
// refusals on a pool with free capacity. The guard was right; the split was
// wrong.
//
// Note what the split did NOT buy: `pool_addresses_v4`/`_v6` are already in the
// key, so two genuinely different pools sharing a NAME across instances were
// always discriminated by their addresses. The routing instance added no
// discrimination that was not already there.
//
// See `two_instances_naming_one_pool_are_not_peers_9389` for the behavioural
// half; this cell pins the key itself.
#[test]
fn source_nat_allocator_key_ignores_routing_instances_9389() {
    let mk = |ri: &str| SourceNATRuleSnapshot {
        name: format!("snat-{ri}"),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        from_routing_instance: ri.to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "shared-pool".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        ..SourceNATRuleSnapshot::default()
    };
    let vrf_a = parse_source_nat_rules(&[mk("tenant-a")]);
    let vrf_b = parse_source_nat_rules(&[mk("tenant-b")]);
    let same = parse_source_nat_rules(&[mk("tenant-a")]);

    let key = |rs: &[crate::nat::SourceNatRule]| rs[0].allocator_key();
    assert_eq!(
        key(&vrf_a),
        key(&vrf_b),
        "two rule-sets naming ONE pool from different routing instances must share \
         ONE PortAllocator. A pool is one set of wire identities; splitting it \
         gives two allocators that can each mint the same (addr, port), which the \
         #6979 overlap guard then refuses -- dropping mints while the pool has \
         free capacity (#9389)"
    );
    // REFERENCE ARM: the same instance must still share, or every apply mints a
    // fresh allocator and every in-flight translation is forgotten.
    assert_eq!(
        key(&vrf_a),
        key(&same),
        "the same rule in the same instance must select the same allocator"
    );
}
// #11351: DNAT and static-NAT rule-set scopes use the same Junos
// interface > zone > routing-instance > unscoped hierarchy as source NAT.
// Keeping both scopes eligible in each probe proves precedence rather than
// only checking the individual scope gates.
#[derive(Clone, Copy)]
struct NatScopePrecedenceRule11351 {
    name: &'static str,
    from_zone: &'static str,
    from_interface: &'static str,
    from_routing_instance: &'static str,
    translation: &'static str,
}

const NAT_SCOPE_IFACE_11351: NatScopePrecedenceRule11351 = NatScopePrecedenceRule11351 {
    name: "interface",
    from_zone: "",
    from_interface: "ge-0/0/1.0",
    from_routing_instance: "",
    translation: "10.0.0.1",
};
const NAT_SCOPE_ZONE_11351: NatScopePrecedenceRule11351 = NatScopePrecedenceRule11351 {
    name: "zone",
    from_zone: "trust",
    from_interface: "",
    from_routing_instance: "",
    translation: "10.0.0.2",
};
const NAT_SCOPE_RI_11351: NatScopePrecedenceRule11351 = NatScopePrecedenceRule11351 {
    name: "routing-instance",
    from_zone: "",
    from_interface: "",
    from_routing_instance: "VR1",
    translation: "10.0.0.3",
};
const NAT_SCOPE_ANY_11351: NatScopePrecedenceRule11351 = NatScopePrecedenceRule11351 {
    name: "unscoped",
    from_zone: "",
    from_interface: "",
    from_routing_instance: "",
    translation: "10.0.0.4",
};

fn dnat_scope_precedence_snapshot_11351(
    scope: NatScopePrecedenceRule11351,
    destination_address: &str,
    destination_prefix: &str,
) -> DestinationNATRuleSnapshot {
    DestinationNATRuleSnapshot {
        name: scope.name.to_string(),
        from_zone: scope.from_zone.to_string(),
        from_interface: scope.from_interface.to_string(),
        from_routing_instance: scope.from_routing_instance.to_string(),
        destination_address: destination_address.to_string(),
        destination_prefix: destination_prefix.to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: scope.translation.to_string(),
        ..DestinationNATRuleSnapshot::default()
    }
}

fn static_scope_precedence_snapshot_11351(
    scope: NatScopePrecedenceRule11351,
    external_ip: &str,
    internal_ip: &str,
) -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        name: scope.name.to_string(),
        from_zone: scope.from_zone.to_string(),
        from_interface: scope.from_interface.to_string(),
        from_routing_instance: scope.from_routing_instance.to_string(),
        external_ip: external_ip.to_string(),
        internal_ip: internal_ip.to_string(),
        ..StaticNATRuleSnapshot::default()
    }
}

#[test]
fn destination_nat_context_precedence_all_pairs_both_orders_11351() {
    let scopes = [
        NAT_SCOPE_IFACE_11351,
        NAT_SCOPE_ZONE_11351,
        NAT_SCOPE_RI_11351,
        NAT_SCOPE_ANY_11351,
    ];
    let pairs = [
        (&scopes[0], &scopes[1]),
        (&scopes[0], &scopes[2]),
        (&scopes[0], &scopes[3]),
        (&scopes[1], &scopes[2]),
        (&scopes[1], &scopes[3]),
        (&scopes[2], &scopes[3]),
    ];
    let counters = NatCounterStore::default();
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    for (preferred, broader) in pairs {
        for reversed in [false, true] {
            let ordered = if reversed {
                vec![*broader, *preferred]
            } else {
                vec![*preferred, *broader]
            };
            let snapshots: Vec<_> = ordered
                .into_iter()
                .map(|scope| dnat_scope_precedence_snapshot_11351(scope, "203.0.113.10", ""))
                .collect();
            let table = DnatTable::from_snapshots(&snapshots, &counters);
            let got = table
                .lookup_with_counter_scoped(
                    PROTO_TCP,
                    src,
                    dst,
                    0,
                    443,
                    "trust",
                    "ge-0/0/1.0",
                    "VR1",
                    None,
                )
                .map(|(decision, _)| decision.rewrite_dst);
            assert_eq!(
                got,
                Some(Some(preferred.translation.parse().unwrap())),
                "DNAT {} must beat {} (reversed config order: {reversed})",
                preferred.name,
                broader.name
            );
        }
    }
}

#[test]
fn destination_nat_prefix_context_precedence_is_scope_first_11351() {
    for reversed in [false, true] {
        let ordered = if reversed {
            [NAT_SCOPE_ZONE_11351, NAT_SCOPE_IFACE_11351]
        } else {
            [NAT_SCOPE_IFACE_11351, NAT_SCOPE_ZONE_11351]
        };
        let snapshots: Vec<_> = ordered
            .into_iter()
            .map(|scope| {
                dnat_scope_precedence_snapshot_11351(scope, "203.0.113.0", "203.0.113.0/24")
            })
            .collect();
        let table = DnatTable::from_snapshots(&snapshots, &NatCounterStore::default());
        let got = table
            .lookup_with_counter_scoped(
                PROTO_TCP,
                "198.51.100.1".parse().unwrap(),
                "203.0.113.10".parse().unwrap(),
                0,
                443,
                "trust",
                "ge-0/0/1.0",
                "VR1",
                None,
            )
            .map(|(decision, _)| decision.rewrite_dst);
        assert_eq!(
            got,
            Some(Some(NAT_SCOPE_IFACE_11351.translation.parse().unwrap())),
            "an interface-scoped DNAT prefix must beat a zone-scoped prefix (reversed config order: {reversed})"
        );
    }
}

#[test]
fn static_nat_context_precedence_all_pairs_both_orders_11351() {
    let scopes = [
        NAT_SCOPE_IFACE_11351,
        NAT_SCOPE_ZONE_11351,
        NAT_SCOPE_RI_11351,
        NAT_SCOPE_ANY_11351,
    ];
    let pairs = [
        (&scopes[0], &scopes[1]),
        (&scopes[0], &scopes[2]),
        (&scopes[0], &scopes[3]),
        (&scopes[1], &scopes[2]),
        (&scopes[1], &scopes[3]),
        (&scopes[2], &scopes[3]),
    ];
    let counters = NatCounterStore::default();
    let external: IpAddr = "203.0.113.10".parse().unwrap();
    for (preferred, broader) in pairs {
        for reversed in [false, true] {
            let ordered = if reversed {
                vec![*broader, *preferred]
            } else {
                vec![*preferred, *broader]
            };
            let snapshots: Vec<_> = ordered
                .into_iter()
                .map(|scope| static_scope_precedence_snapshot_11351(scope, "203.0.113.10", scope.translation))
                .collect();
            let table = StaticNatTable::from_snapshots(&snapshots, &counters);
            let got = table
                .match_dnat_with_counter_scoped(external, 0, None, "trust", "ge-0/0/1.0", "VR1")
                .map(|(decision, _)| decision.rewrite_dst);
            assert_eq!(
                got,
                Some(Some(preferred.translation.parse().unwrap())),
                "static DNAT {} must beat {} (reversed config order: {reversed})",
                preferred.name,
                broader.name
            );
        }
    }
}

#[test]
fn static_nat_block_context_precedence_is_scope_first_11351() {
    let interface = NatScopePrecedenceRule11351 {
        translation: "10.1.0.0/24",
        ..NAT_SCOPE_IFACE_11351
    };
    let zone = NatScopePrecedenceRule11351 {
        translation: "192.0.2.0/24",
        ..NAT_SCOPE_ZONE_11351
    };
    for reversed in [false, true] {
        let ordered = if reversed {
            [zone, interface]
        } else {
            [interface, zone]
        };
        let snapshots: Vec<_> = ordered
            .into_iter()
            .map(|scope| {
                static_scope_precedence_snapshot_11351(
                    scope,
                    "198.51.100.0/24",
                    scope.translation,
                )
            })
            .collect();
        let table = StaticNatTable::from_snapshots(&snapshots, &NatCounterStore::default());
        let got = table
            .match_dnat_with_counter_scoped(
                "198.51.100.42".parse().unwrap(),
                0,
                None,
                "trust",
                "ge-0/0/1.0",
                "VR1",
            )
            .map(|(decision, _)| decision.rewrite_dst);
        assert_eq!(
            got,
            Some(Some("10.1.0.42".parse().unwrap())),
            "interface-scoped static block must beat zone-scoped block (reversed config order: {reversed})"
        );
    }
}

#[test]
fn static_nat_reverse_block_context_precedence_is_interface_first_11351() {
    for reversed in [false, true] {
        let interface = StaticNATRuleSnapshot {
            name: "interface".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            external_ip: "203.0.113.0/24".to_string(),
            internal_ip: "10.0.0.0/24".to_string(),
            ..StaticNATRuleSnapshot::default()
        };
        let zone = StaticNATRuleSnapshot {
            name: "zone".to_string(),
            from_zone: "trust".to_string(),
            external_ip: "198.51.100.0/24".to_string(),
            internal_ip: "10.0.0.0/24".to_string(),
            ..StaticNATRuleSnapshot::default()
        };
        let snapshots = if reversed {
            vec![zone, interface]
        } else {
            vec![interface, zone]
        };
        let table = StaticNatTable::from_snapshots(&snapshots, &NatCounterStore::default());
        let got = table
            .match_snat_with_counter_scoped(
                "10.0.0.42".parse().unwrap(),
                0,
                None,
                "trust",
                "ge-0/0/1.0",
                "VR1",
            )
            .map(|(decision, _)| decision.rewrite_src);
        assert_eq!(
            got,
            Some(Some("203.0.113.42".parse().unwrap())),
            "interface-scoped static reverse block must beat zone scope (reversed config order: {reversed})"
        );
    }
}


#[test]
fn static_nat_reverse_context_precedence_is_interface_first_11351() {
    for reversed in [false, true] {
        let interface = StaticNATRuleSnapshot {
            name: "interface".to_string(),
            from_interface: "ge-0/0/1.0".to_string(),
            external_ip: "203.0.113.1".to_string(),
            internal_ip: "10.0.0.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        };
        let zone = StaticNATRuleSnapshot {
            name: "zone".to_string(),
            from_zone: "trust".to_string(),
            external_ip: "203.0.113.2".to_string(),
            internal_ip: "10.0.0.10".to_string(),
            ..StaticNATRuleSnapshot::default()
        };
        let snapshots = if reversed {
            vec![zone, interface]
        } else {
            vec![interface, zone]
        };
        let table = StaticNatTable::from_snapshots(&snapshots, &NatCounterStore::default());
        let got = table
            .match_snat_with_counter_scoped(
                "10.0.0.10".parse().unwrap(),
                0,
                None,
                "trust",
                "ge-0/0/1.0",
                "VR1",
            )
            .map(|(decision, _)| decision.rewrite_src);
        assert_eq!(
            got,
            Some(Some("203.0.113.1".parse().unwrap())),
            "interface-scoped static reverse NAT must beat zone scope (reversed config order: {reversed})"
        );
    }
}
