// NAT L4 (application / port) match-constraint tests (source and
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

#[test]
fn source_nat_match_destination_port_constrains_flow_3429() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        // `match destination-port 20000 to 20003`.
        match_destination_ports: vec![NatPortRangeWire {
            low: 20000,
            high: 20003,
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let mut counter = None;
    // In-range destination port -> translated.
    let hit = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        Some(PROTO_TCP),
        12345,
        20001,
        egress_v4,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert!(
        matches!(hit, SourceNatLookup::Matched(_)),
        "in-range dst port must match: {:?}",
        hit
    );
    // Out-of-range destination port -> NO match (pre-fix this over-matched).
    let miss = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        Some(PROTO_TCP),
        12345,
        80,
        egress_v4,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert_eq!(
        miss,
        SourceNatLookup::NoMatch,
        "out-of-range dst port must NOT match"
    );
}

#[test]
fn source_nat_match_destination_port_constrains_off_exemption_3429() {
    // `then source-nat off` scoped to a destination port must exempt ONLY that
    // port. Pre-fix the exemption widened to every port, so a flow on a
    // different port was wrongly left untranslated (Matched(default)).
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "no-nat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        off: true,
        match_destination_ports: vec![NatPortRangeWire { low: 53, high: 53 }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let mut counter = None;
    // Exempt port -> matched as a no-op (off) rule.
    let on_port = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        Some(PROTO_UDP),
        40000,
        53,
        egress_v4,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert!(
        matches!(on_port, SourceNatLookup::Matched(_)),
        "exempt port must match the off rule: {:?}",
        on_port
    );
    // Different port -> the off rule must NOT swallow it.
    let other_port = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        Some(PROTO_UDP),
        40000,
        443,
        egress_v4,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert_eq!(
        other_port,
        SourceNatLookup::NoMatch,
        "a port-scoped `source-nat off` must NOT exempt other ports"
    );
}

#[test]
fn source_nat_fragment_sentinel_does_not_bypass_later_rule_for_scoped_off_10675() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "off-udp-53".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            off: true,
            match_applications: vec![NatAppTermWire {
                protocol: PROTO_UDP as u16,
                ports: vec![NatPortRangeWire { low: 53, high: 53 }],
                src_ports: vec![],
            }],
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat-tcp-443".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            match_applications: vec![NatAppTermWire {
                protocol: PROTO_TCP as u16,
                ports: vec![NatPortRangeWire { low: 443, high: 443 }],
                src_ports: vec![],
            }],
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    let mut counter = None;
    let lookup = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(crate::session::SHIM_PROTO_FRAGMENT_NO_L4),
        0,
        0,
        Some("172.16.80.8".parse().unwrap()),
        None,
        0,
        true,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert!(
        matches!(lookup, SourceNatLookup::Matched(decision) if decision.rewrite_src.is_some()),
        "an ambiguous L4-scoped off rule must not hide a later possible SNAT rule: {lookup:?}"
    );
}

#[test]
fn source_nat_match_application_constrains_protocol_and_port_3429() {
    // `match application` pre-expanded to (proto=TCP, ports=[443]).
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_TCP as u16,
            ports: vec![NatPortRangeWire {
                low: 443,
                high: 443,
            }],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let lookup = |proto: u8, dport: u16| {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            Some(proto),
            12345,
            dport,
            egress_v4,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        )
    };
    // Right proto + right port -> match.
    assert!(
        matches!(lookup(PROTO_TCP, 443), SourceNatLookup::Matched(_)),
        "tcp/443 must match the app-scoped rule"
    );
    // Right proto, wrong port -> no match.
    assert_eq!(
        lookup(PROTO_TCP, 80),
        SourceNatLookup::NoMatch,
        "tcp/80 must NOT match an app scoped to tcp/443"
    );
    // Wrong proto (UDP) on the same port -> no match.
    assert_eq!(
        lookup(PROTO_UDP, 443),
        SourceNatLookup::NoMatch,
        "udp/443 must NOT match an app scoped to tcp/443"
    );
}

#[test]
fn source_nat_match_application_constrains_source_port_3491() {
    // #3491: `match application` pre-expanded to (proto=TCP, dst=443, src=12345).
    // The application carried a source-port constraint; before #3491 it was
    // dropped and the rule matched any source port (fail-open). Reverting the
    // l4_matches src_port gate (or the SrcPorts wire) makes the wrong-source-port
    // assertion below match -> RED.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_TCP as u16,
            ports: vec![NatPortRangeWire {
                low: 443,
                high: 443,
            }],
            src_ports: vec![NatPortRangeWire {
                low: 12345,
                high: 12345,
            }],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let lookup = |sport: u16, dport: u16| {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            Some(PROTO_TCP),
            sport,
            dport,
            egress_v4,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        )
    };
    // Right source port + right dest port -> match.
    assert!(
        matches!(lookup(12345, 443), SourceNatLookup::Matched(_)),
        "tcp src=12345 dst=443 must match the app-scoped rule"
    );
    // Right dest port, WRONG source port -> no match (the #3491 fail-open).
    assert_eq!(
        lookup(55555, 443),
        SourceNatLookup::NoMatch,
        "tcp src=55555 dst=443 must NOT match an app scoped to source-port 12345"
    );
}

#[test]
fn source_nat_app_source_port_never_match_sentinel_3491() {
    // #3491: the Go builder emits a low>high never-match range when an
    // application's source-port spec coalesces to nothing. The Rust matcher must
    // preserve it (port_in_ranges can never satisfy low>high) so the term matches
    // NO source port rather than widening to any source port.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_TCP as u16,
            ports: vec![],
            src_ports: vec![NatPortRangeWire { low: 1, high: 0 }],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let mut counter = None;
    let lookup = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(PROTO_TCP),
        12345,
        443,
        egress_v4,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert_eq!(
        lookup,
        SourceNatLookup::NoMatch,
        "a never-match source-port sentinel must match NO source port"
    );
}

#[test]
fn source_nat_real_proto_255_is_not_unknown_fragment_10674() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "udp-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: PROTO_UDP as u16,
            ports: vec![],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut counter = None;
    let lookup = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(crate::session::SHIM_PROTO_FRAGMENT_NO_L4),
        12345,
        443,
        Some("172.16.80.8".parse().unwrap()),
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );

    assert_eq!(
        lookup,
        SourceNatLookup::NoMatch,
        "a real protocol-255 packet must not match a UDP-only NAT rule"
    );
}

#[test]
fn source_nat_unconstrained_rule_still_matches_any_l4_3429() {
    // A rule with NO L4 match fields keeps the pre-#3429 match-any behavior,
    // including for the address-only (`None`) tuple-unknown caller.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let d = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        egress_v4,
        None,
    );
    assert!(
        d.is_some(),
        "an unconstrained SNAT rule must still match (proto-unknown caller)"
    );
}

#[test]
fn source_nat_l4_constrained_rule_fails_closed_on_unknown_tuple_3429() {
    // The address-only (`None`) caller cannot supply a port/protocol, so an
    // L4-constrained rule fails closed (does not fire) rather than over-match.
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_destination_ports: vec![NatPortRangeWire {
            low: 443,
            high: 443,
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let d = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        egress_v4,
        None,
    );
    assert!(
        d.is_none(),
        "an L4-scoped SNAT rule must NOT fire for an unknown (proto=0) tuple"
    );
}

// #3471 fold: a destination-port constraint that is purely an impossible
// (low > high) range — the natNeverMatchPortRange fail-closed sentinel the Go
// builder emits when every configured port is out of range — must match
// NOTHING, NOT collapse to "unconstrained". The Rust parser keeps a low > high
// range verbatim; dropping it (the pre-fold revert) empties match_dst_ports and
// l4_matches then treats the rule as port-unconstrained = match-all (fail-open).
#[test]
fn source_nat_never_match_port_sentinel_matches_nothing_3429() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        // natNeverMatchPortRange = {low:1, high:0} — impossible, never matches.
        match_destination_ports: vec![NatPortRangeWire { low: 1, high: 0 }],
        ..SourceNATRuleSnapshot::default()
    }]);
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    for dport in [1u16, 80, 443, 20001, 65535] {
        let mut counter = None;
        let r = match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            Some(PROTO_TCP),
            12345,
            dport,
            egress_v4,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        );
        assert_eq!(
            r,
            SourceNatLookup::NoMatch,
            "never-match port sentinel must reject dst port {}",
            dport
        );
    }
}

// #3471 fold: an app term whose protocol is the never-match sentinel (0xFFFF,
// what the Go builder emits for an empty/unresolvable app protocol) must match
// NOTHING, while a genuinely-any term (SOURCE_NAT_PROTO_ANY = 256) still matches
// every protocol. This locks the distinction the Codex finding turned on:
// returning natProtoAny for an unresolvable protocol (the revert) would make the
// never term behave like the any term — fail-open.
#[test]
fn source_nat_app_protocol_never_vs_any_3429() {
    let egress_v4 = Some("172.16.80.8".parse::<Ipv4Addr>().unwrap());
    let src: IpAddr = "10.0.1.100".parse().unwrap();
    let dst: IpAddr = "8.8.8.8".parse().unwrap();
    let lookup = |rules: &[_], proto: u8| {
        let mut counter = None;
        match_source_nat_result_for_tuple(
            &InterfaceNatAllocators::default(),
            rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            Some(proto),
            12345,
            443,
            egress_v4,
            None,
            0,
            false,
            false,
            NatHolder::Untracked,
            &mut counter,
        )
    };

    // Never-match protocol sentinel (0xFFFF): no protocol satisfies the term.
    let never = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: 0xFFFF,
            ports: vec![],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_GRE] {
        assert_eq!(
            lookup(&never, proto),
            SourceNatLookup::NoMatch,
            "never-match app protocol must reject protocol {}",
            proto
        );
    }

    // Genuinely-any protocol (256): every protocol matches the term.
    let any = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        match_applications: vec![NatAppTermWire {
            protocol: SOURCE_NAT_PROTO_ANY,
            ports: vec![],
            src_ports: vec![],
        }],
        ..SourceNATRuleSnapshot::default()
    }]);
    for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_GRE] {
        assert!(
            matches!(lookup(&any, proto), SourceNatLookup::Matched(_)),
            "any-protocol app term must match protocol {}",
            proto
        );
    }
}

// ===========================================================================
// #3437: DNAT `match application` source-port (H10) + ICMP type/code (H11)
// enforcement. Before #3437 the DNAT builder reduced an application to
// protocol + destination-port only, so the published VIP matched any source
// port and every ICMP type — a fail-open NAT widening. These tests pin the
// dataplane gate and are RED when the `l4_extra_matches` source-port / ICMP
// checks are reverted.
// ===========================================================================

/// Helper: a single-rule DNAT table whose entry carries the given L4 match
/// constraints. Destination 203.0.113.10, pool 192.168.1.10, unscoped zone.
fn dnat_table_with_l4(
    protocol: &str,
    destination_port: u16,
    match_source_ports: Vec<NatPortRangeWire>,
    match_icmp_type: Option<u8>,
    match_icmp_code: Option<u8>,
) -> DnatTable {
    DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "app-scoped".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port,
            protocol: protocol.to_string(),
            pool_address: "192.168.1.10".to_string(),
            match_source_ports,
            match_icmp_type,
            match_icmp_code,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    )
}

#[test]
fn dnat_match_application_constrains_source_port_3437() {
    // `match application <app>` with source-port 12345 -> only a flow whose
    // SOURCE port is 12345 (hitting dest port 80) is DNAT'd.
    let table = dnat_table_with_l4(
        "tcp",
        80,
        vec![NatPortRangeWire {
            low: 12345,
            high: 12345,
        }],
        None,
        None,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();

    // In-range source port: translated.
    let hit = table
        .lookup_with_counter(PROTO_TCP, src, dst, 12345, 80, "", None)
        .map(|(d, _)| d);
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "DNAT must fire for the application's source port"
    );

    // Out-of-range source port: NOT translated (RED on revert of the
    // source-port gate in l4_extra_matches — without it this is Some).
    let miss = table
        .lookup_with_counter(PROTO_TCP, src, dst, 55555, 80, "", None)
        .map(|(d, _)| d);
    assert_eq!(
        miss, None,
        "DNAT must NOT fire for a source port outside the application's range"
    );
}

#[test]
fn dnat_match_application_source_port_never_match_sentinel_3437() {
    // A configured source-port that coalesced to nothing -> never-match
    // sentinel ({low:1, high:0}). The entry must match NO source port (fail
    // closed), not widen to any.
    let table = dnat_table_with_l4(
        "tcp",
        80,
        vec![NatPortRangeWire { low: 1, high: 0 }],
        None,
        None,
    );
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    for sp in [0u16, 1, 80, 12345, 65535] {
        assert!(
            table
                .lookup_with_counter(PROTO_TCP, src, dst, sp, 80, "", None)
                .is_none(),
            "never-match source-port sentinel must reject source port {sp}"
        );
    }
}

#[test]
fn dnat_match_application_constrains_icmp_type_3437() {
    // `match application junos-ping` = ICMP echo-request (type 8). Only ICMP
    // type 8 to the VIP is DNAT'd; an echo-reply (type 0), a destination-
    // unreachable (type 3), and a non-ICMP flow must NOT be translated.
    let table = dnat_table_with_l4("icmp", 0, vec![], Some(8), None);
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();

    // Echo-request: translated.
    let hit = table
        .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((8, 0)))
        .map(|(d, _)| d);
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_dst: Some("192.168.1.10".parse().unwrap()),
            ..NatDecision::default()
        }),
        "DNAT must fire for the application's ICMP type (echo-request)"
    );

    // Echo-reply (type 0): NOT translated (RED on revert of the ICMP gate —
    // without it this is Some).
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((0, 0)))
            .is_none(),
        "DNAT must NOT fire for a different ICMP type (echo-reply)"
    );

    // Destination-unreachable (type 3): NOT translated.
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((3, 1)))
            .is_none(),
        "DNAT must NOT fire for an ICMP error type"
    );

    // Non-ICMP flow (no packet_icmp supplied): fail closed.
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", None)
            .is_none(),
        "an ICMP-type-constrained entry must fail closed when the packet has no ICMP (type, code)"
    );
}

#[test]
fn dnat_match_application_constrains_icmp_type_and_code_3437() {
    // type 3 + code 1 (host-unreachable). Right type, wrong code must NOT match.
    let table = dnat_table_with_l4("icmp", 0, vec![], Some(3), Some(1));
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((3, 1)))
            .is_some(),
        "DNAT must fire for the exact (type, code)"
    );
    assert!(
        table
            .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((3, 0)))
            .is_none(),
        "DNAT must NOT fire for the right type but wrong code"
    );
}

#[test]
fn dnat_unconstrained_application_still_matches_any_l4_3437() {
    // Regression guard: an entry with NO source-port and NO ICMP constraint
    // (the common case) still matches any source port / any ICMP type — the
    // fix must not narrow the unconstrained path.
    let table = dnat_table_with_l4("tcp", 80, vec![], None, None);
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();
    for sp in [0u16, 1, 1024, 65535] {
        assert!(
            table
                .lookup_with_counter(PROTO_TCP, src, dst, sp, 80, "", None)
                .is_some(),
            "unconstrained DNAT must match any source port (got miss at {sp})"
        );
    }

    let icmp_any = dnat_table_with_l4("icmp", 0, vec![], None, None);
    for t in [0u8, 3, 8, 11] {
        assert!(
            icmp_any
                .lookup_with_counter(PROTO_ICMP, src, dst, 0, 0, "", Some((t, 0)))
                .is_some(),
            "unconstrained ICMP DNAT must match any ICMP type (got miss at type {t})"
        );
    }
}

// #3434 (Codex audit 095 H07/H08): a DNAT rule whose `match application` names
// an UNDEFINED application or a defined-but-EMPTY application-set resolves to
// zero application terms. Before the fix the Go builder fell through to its
// explicit-match fallback and emitted protocol="" + destination_port=0 — a
// PROTO_ANY wildcard entry that translated EVERY flow to the destination (a
// fail-open wildcard VIP). The fix instead emits that same wildcard shape but
// with the #3437 source-port never-match sentinel ({low:1, high:0}), so the
// installed entry can never satisfy l4_extra_matches and translates NOTHING.
//
// This test pins the exact snapshot shape the Go builder now emits for an
// undefined/empty NAT app reference and proves it fails CLOSED across every L4
// protocol and port. The first table is the pre-fix fail-open (no sentinel) —
// it translates everything — and is the contrast that proves the sentinel is
// what closes the hole.
#[test]
fn dnat_undefined_application_never_match_sentinel_fails_closed_3434() {
    let src: IpAddr = "198.51.100.1".parse().unwrap();
    let dst: IpAddr = "203.0.113.10".parse().unwrap();

    // Pre-fix shape: an IP-only wildcard entry (protocol="" + dst_port=0 =>
    // PROTO_ANY) with NO L4 constraint translates ANY protocol/port — the
    // H07/H08 fail-open the explicit-match fallback produced.
    let fail_open = dnat_table_with_l4("", 0, vec![], None, None);
    assert!(
        fail_open
            .lookup_with_counter(PROTO_TCP, src, dst, 40000, 443, "", None)
            .is_some(),
        "control: an unconstrained PROTO_ANY DNAT entry translates any flow (the pre-fix fail-open)"
    );

    // Post-fix shape: the same wildcard entry carrying the never-match
    // source-port sentinel matches NOTHING, for every protocol and port.
    let fail_closed = dnat_table_with_l4("", 0, vec![NatPortRangeWire { low: 1, high: 0 }], None, None);
    for &(proto, sp, dp) in &[
        (PROTO_TCP, 0u16, 0u16),
        (PROTO_TCP, 40000, 443),
        (PROTO_UDP, 1, 53),
        (PROTO_ICMP, 0, 0),
        (PROTO_TCP, 65535, 65535),
    ] {
        let icmp = if proto == PROTO_ICMP {
            Some((8u8, 0u8))
        } else {
            None
        };
        assert!(
            fail_closed
                .lookup_with_counter(proto, src, dst, sp, dp, "", icmp)
                .is_none(),
            "undefined-app never-match sentinel must reject proto={proto} sport={sp} dport={dp}"
        );
    }
}

// #3449: a DNAT `match destination-port low to high` range rides ONE
// wildcard-port entry (destination_port=0) carrying a match_destination_ports
// range, instead of one exact-port entry per port. The lookup must translate a
// flow whose destination port falls in the range and miss one outside it. A
// pool_port of 0 preserves the destination port (the range maps each port to
// itself). RED-on-revert: drop the match_dst_ports check in l4_extra_matches
// and the out-of-range port is wrongly translated (the wildcard entry widens to
// match-any-port).
#[test]
fn dnat_destination_port_range_3449() {
    let table = DnatTable::from_snapshots(
        &[DestinationNATRuleSnapshot {
            name: "range".to_string(),
            from_zone: "untrust".to_string(),
            destination_address: "203.0.113.10".to_string(),
            destination_port: 0,
            match_destination_ports: vec![NatPortRangeWire {
                low: 20000,
                high: 30000,
            }],
            protocol: "tcp".to_string(),
            pool_address: "192.168.1.10".to_string(),
            pool_port: 0,
            ..DestinationNATRuleSnapshot::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    let src: std::net::IpAddr = "198.51.100.1".parse().unwrap();
    let dst: std::net::IpAddr = "203.0.113.10".parse().unwrap();

    // In-range ports translate the destination (port preserved, pool_port=0).
    for port in [20000u16, 25000, 30000] {
        let decision = table.lookup(PROTO_TCP, src, dst, port, "untrust");
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_dst: Some("192.168.1.10".parse().unwrap()),
                ..NatDecision::default()
            }),
            "in-range dport {port} must DNAT to the pool"
        );
    }

    // Out-of-range ports must NOT match (the range entry is not a match-any
    // wildcard).
    for port in [19999u16, 30001, 80] {
        assert!(
            table.lookup(PROTO_TCP, src, dst, port, "untrust").is_none(),
            "out-of-range dport {port} must NOT match the [20000,30000] range entry"
        );
    }
}

