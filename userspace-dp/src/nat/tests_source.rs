// Source (interface/address-match) NAT tests for the nat/ module.
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
fn interface_source_nat_matches_v4_rule() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn interface_source_nat_matches_v6_rule() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

// === #5688: interface SNAT with no same-family egress address must fail CLOSED ===

/// #5688 fail-on-revert: interface-mode SNAT translates the source to the egress
/// interface's OWN address of the PACKET's family. When a v4 packet's egress
/// interface has NO v4 address (only a v6 address here), there is nothing to
/// translate to. Before the fix this returned `Matched` with a `None` rewrite,
/// so the packet was forwarded with its private/internal source UNTRANSLATED —
/// the leak. The fix fails CLOSED: `Unavailable(InterfaceNoEgressAddress)`, which
/// funnels through the same drop / `nat_alloc_fail` disposition a pool-mode
/// allocation failure takes. Reverting to `Matched`-with-`None` makes this panic
/// (the returned lookup is no longer `Unavailable`). Passing a v6 egress address
/// that must NOT be used also proves the RIGHT family is resolved.
#[test]
fn interface_source_nat_no_v4_egress_addr_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let lookup = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        None, // egress interface has NO v4 address
        // a v6 address is present but must NOT be used to translate a v4 packet
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::InterfaceNoEgressAddress);
        }
        other => panic!(
            "expected Unavailable (fail-closed drop), got {other:?} — a \
             Matched-with-None-rewrite forwards the private source UNTRANSLATED (#5688 leak)"
        ),
    }
}

/// #5688 symmetric v6: a v6 packet whose egress interface has NO v6 address
/// (only a v4 address present, which must NOT be used) fails closed the same
/// way. Independent of the v4 branch — the dual-stack family check is per-packet.
#[test]
fn interface_source_nat_no_v6_egress_addr_fails_closed() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/0".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let lookup = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        // a v4 address is present but must NOT be used to translate a v6 packet
        Some("172.16.80.8".parse().expect("egress v4")),
        None, // egress interface has NO v6 address
    );
    match lookup {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(f.reason, SourceNatFailureReason::InterfaceNoEgressAddress);
        }
        other => panic!(
            "expected Unavailable (fail-closed drop), got {other:?} — a \
             Matched-with-None-rewrite forwards the private source UNTRANSLATED (#5688 leak)"
        ),
    }
}

/// #5688 no-regression / dual-stack independence: the SAME lookup that fails
/// closed for a family with no egress address still TRANSLATES when the egress
/// interface HAS the packet's family address. A v6 packet is translated to the
/// egress v6 address even though there is ALSO a v4 address present (which is
/// irrelevant to a v6 packet), and vice versa — proving the working case is
/// preserved and the families are resolved independently.
#[test]
fn interface_source_nat_translates_when_same_family_egress_addr_present() {
    let rules = parse_source_nat_rules(&[
        SourceNATRuleSnapshot {
            name: "snat4".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        },
        SourceNATRuleSnapshot {
            name: "snat6".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["::/0".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    // v4 packet -> egress v4 address (v6 also present but unused).
    let v4 = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress v4")),
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    );
    assert_eq!(
        v4,
        SourceNatLookup::Matched(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat v4")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
    // v6 packet -> egress v6 address (v4 also present but unused).
    let v6 = match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress v4")),
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    );
    assert_eq!(
        v6,
        SourceNatLookup::Matched(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat v6")),
            rewrite_dst: None,
            ..NatDecision::default()
        })
    );
}

#[test]
fn off_rule_short_circuits_translation() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "no-nat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        off: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision::default())
    );
}

// === #2398: SNAT all-malformed match prefixes must fail CLOSED, not match-any ===

/// #2398 fail-on-revert: a SNAT rule whose configured source match set is
/// non-empty but whose entries ALL fail to parse must match NOTHING. Before
/// #2398 the empty parsed list collapsed to "match any source", so the SNAT
/// silently translated all traffic in the zone pair (fail-open broadening).
/// This test FAILS (SNAT fires) if the constrained flag / fail-closed path is
/// reverted to `nets.is_empty() || ...`.
#[test]
fn snat_all_malformed_source_match_fails_closed_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-typo".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Every prefix is garbage / unparseable — operator typo.
        source_addresses: vec!["not-an-ip".to_string(), "10.0.0.0/99".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT source match must NOT translate (fail closed) — \
         got a translation, which is the #2398 match-any fail-open"
    );
}

/// #2398 fail-on-revert (v6): same as above for an IPv6 SNAT rule.
#[test]
fn snat_all_malformed_source_match_fails_closed_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat6-typo".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["::/999".to_string(), "garbage".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT v6 source match must fail closed (#2398)"
    );
}

/// #2398: a malformed DESTINATION match set (non-empty, all-garbage) must also
/// fail closed — the destination side gets the same constrained-flag treatment.
#[test]
fn snat_all_malformed_destination_match_fails_closed_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-dst-typo".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Source is valid (match any in zone), destination is all garbage.
        source_addresses: vec!["0.0.0.0/0".to_string()],
        destination_addresses: vec!["bogus".to_string(), "1.2.3.4/40".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT destination match must fail closed (#2398)"
    );
}

/// #2398 (v6 destination): a SNAT rule with a non-empty but ALL-malformed v6
/// destination match set must match NOTHING. The fail-closed logic
/// (`destination_constrained` + shared `crate::prefix::nets_match` with
/// explicit `except == false`, #16128) is identical to the v4 destination
/// path, so without this test a v6-destination-only regression
/// (e.g. the shared empty arm reverted to empty=match-any) would slip through. This
/// test FAILS (SNAT fires) if the v6 destination fail-closed path reverts.
#[test]
fn snat_all_malformed_destination_match_fails_closed_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-dst-typo6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // Source is valid (match any in zone), v6 destination is all garbage.
        source_addresses: vec!["::/0".to_string()],
        destination_addresses: vec!["bogus6".to_string(), "2001:db8::/999".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        decision, None,
        "all-malformed SNAT v6 destination match must fail closed (#2398)"
    );
}

/// #16128: the NAT arm of the shared `crate::prefix::nets_match` — explicit
/// `except == false` — must keep ALL-malformed (constrained-but-empty) sets
/// fail-closed on BOTH axes and families after the dedup. FAIL-ON-REVERT:
/// pass the filter's empty-except arm (or `except = constrained`) at the NAT
/// call site and every cell below translates (fail-open). The four #2398
/// cells above pin source/destination separately; this cell pins a rule
/// malformed on BOTH axes at once, v4 and v6.
#[test]
fn nat_shared_nets_match_explicit_false_16128() {
    for (name, src_addrs, dst_addrs, src, dst, egress_v4, egress_v6) in [
        (
            "both-malformed-v4",
            vec!["not-an-ip".to_string()],
            vec!["also-bogus".to_string()],
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        (
            "both-malformed-v6",
            vec!["garbage".to_string()],
            vec!["::/999".to_string()],
            "2001:559:8585:ef00::100".parse().expect("src"),
            "2001:559:8585:80::200".parse().expect("dst"),
            None,
            Some("2001:559:8585:80::8".parse().expect("egress")),
        ),
    ] {
        let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
            name: name.to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: src_addrs,
            destination_addresses: dst_addrs,
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }]);
        let decision = match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            egress_v4,
            egress_v6,
        );
        assert_eq!(
            decision, None,
            "{name}: NAT shared nets_match with explicit except=false must fail closed (#16128/#2398)"
        );
    }
}

/// #2398: a bare host v4 destination match IP (no `/prefix`) correctly scopes
/// the SNAT on the DESTINATION path — symmetric with the source bare-IP
/// fallback. Only traffic to the configured destination host is translated.
#[test]
fn snat_bare_host_destination_match_scopes_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare-dst".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        destination_addresses: vec!["172.16.80.200".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Traffic to the configured destination host is translated.
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host SNAT destination must translate traffic to the configured host (#2398)"
    );
    // Traffic to a different destination is NOT translated (scope held).
    let miss = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.201".parse().expect("other dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        miss, None,
        "bare-host SNAT destination must NOT translate traffic to a different host"
    );
}

/// #2398 (v6): bare host v6 destination match scopes the SNAT on the
/// destination path.
#[test]
fn snat_bare_host_destination_match_scopes_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare-dst6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        destination_addresses: vec!["2001:559:8585:80::200".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host v6 SNAT destination must translate traffic to the configured host (#2398)"
    );
    let miss = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::201".parse().expect("other dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        miss, None,
        "bare-host v6 SNAT destination must NOT translate traffic to a different host"
    );
}

/// #2398: a bare host match IP (no `/prefix`) correctly scopes the SNAT. Junos
/// carries `match source-address 10.0.61.102` verbatim; `IpNet::from_str`
/// rejects a bare IP, so without the bare-IP /32 fallback this rule would have
/// an empty parsed list and (after the fail-closed fix) match NOTHING. With the
/// fallback it matches exactly the host and only the host.
#[test]
fn snat_bare_host_source_match_scopes_v4() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.102".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Configured host is translated.
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host SNAT source must translate the configured host (#2398 fallback)"
    );
    // A different host is NOT translated (scope held, not match-any).
    let miss = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.200".parse().expect("other src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        miss, None,
        "bare-host SNAT must NOT translate a different source (no over-broadening)"
    );
}

/// #2398 (v6): bare host IPv6 match scopes the SNAT.
#[test]
fn snat_bare_host_source_match_scopes_v6() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-bare6".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["2001:559:8585:ef00::100".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(
        hit,
        Some(NatDecision {
            rewrite_src: Some("2001:559:8585:80::8".parse().expect("snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "bare-host v6 SNAT source must translate the configured host (#2398)"
    );
    let miss = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::200".parse().expect("other src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress")),
    );
    assert_eq!(miss, None, "bare-host v6 SNAT must not translate a different source");
}

/// #2398 anti-over-restrict: a valid UNSCOPED SNAT (empty match set) still
/// translates all sources. This is the behavior we must NOT break while making
/// the all-malformed case fail closed.
#[test]
fn snat_unscoped_still_translates_all_sources() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-any".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        // No source/destination match prefixes — unconstrained.
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    for src in ["10.0.61.5", "192.0.2.7", "10.0.99.250"] {
        let decision = match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            src.parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        );
        assert_eq!(
            decision,
            Some(NatDecision {
                rewrite_src: Some("172.16.80.8".parse().expect("snat")),
                rewrite_dst: None,
                ..NatDecision::default()
            }),
            "unscoped SNAT must translate every source (anti-over-restrict, #2398) — {src}"
        );
    }
}

/// #2398 anti-over-restrict: a valid SCOPED SNAT translates only matching
/// traffic — the configured subnet is translated, an out-of-subnet source is
/// not.
#[test]
fn snat_valid_scoped_translates_only_matching() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-scoped".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.50".parse().expect("in-subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert!(hit.is_some(), "in-subnet source must be translated");
    let miss = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.62.50".parse().expect("out-of-subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(miss, None, "out-of-subnet source must NOT be translated");
}

/// #2398: a MIXED valid+malformed source match set keeps the valid entries and
/// drops only the garbage — the match narrows to the valid prefix rather than
/// failing closed entirely or broadening to match-any.
#[test]
fn snat_mixed_valid_and_malformed_keeps_valid() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "snat-mixed".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![
            "garbage".to_string(),
            "10.0.61.0/24".to_string(),
            "10.0.0.0/99".to_string(),
        ],
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    // Valid prefix still matches.
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.7".parse().expect("in valid subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert!(
        hit.is_some(),
        "mixed match set must keep the valid prefix and translate it (#2398)"
    );
    // Out-of-prefix source is not translated (no match-any leak from the garbage).
    let miss = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.62.7".parse().expect("out of valid subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        miss, None,
        "mixed match set must NOT broaden to match-any from the dropped garbage (#2398)"
    );
}

#[test]
fn reverse_decision_turns_snat_into_reply_dnat() {
    let decision = NatDecision {
        rewrite_src: Some("172.16.80.8".parse().expect("snat")),
        rewrite_dst: None,
        ..NatDecision::default()
    };
    assert_eq!(
        decision.reverse(
            "10.0.61.102".parse().expect("orig src"),
            "172.16.80.200".parse().expect("orig dst"),
            12345,
            443,
        ),
        NatDecision {
            rewrite_src: None,
            rewrite_dst: Some("10.0.61.102".parse().expect("orig src")),
            ..NatDecision::default()
        }
    );
}

// #4718 FAIL-ON-REVERT: a source-NAT rule whose match set contains an
// UNPARSEABLE prefix must (1) still translate via its VALID prefixes and (2)
// SURFACE the dropped prefix via the NatCounterStore parse-error counter,
// instead of the pre-#4718 silent `Err(_) => {}`. Reverting
// `record_parse_error` back to the empty arm leaves `parse_errors() == 0` →
// surfacing assertion RED, while the translation still succeeds (the fix does
// not change the fail-closed match-set behaviour, only makes the drop
// observable).
#[test]
fn source_nat_unparseable_match_prefix_surfaces_and_keeps_valid() {
    let counters = crate::nat::NatCounterStore::default();
    let rules = parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "snat-mixed".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec![
                "garbage".to_string(),      // unparseable — surfaced drop
                "10.0.61.0/24".to_string(), // valid — must still translate
            ],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }],
        None,
        &counters,
        0,
    );
    // (1) The valid prefix still translates its source.
    let hit = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.7".parse().expect("in valid subnet"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert!(
        hit.is_some(),
        "valid source-NAT prefix must translate despite a malformed sibling"
    );
    // (2) The malformed prefix was surfaced — RED on the silent-skip revert.
    assert_eq!(
        counters.parse_errors(),
        1,
        "an unparseable source-NAT match prefix must bump the parse-error counter"
    );
}

// #4718 guard: an all-valid source-NAT match set reports ZERO parse errors —
// no false positive from the surfacing path.
#[test]
fn source_nat_all_valid_reports_no_parse_errors() {
    let counters = crate::nat::NatCounterStore::default();
    let _rules = parse_source_nat_rules_with_previous(
        &[SourceNATRuleSnapshot {
            name: "snat-clean".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.61.0/24".to_string(), "10.0.62.5".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        }],
        None,
        &counters,
        0,
    );
    assert_eq!(
        counters.parse_errors(),
        0,
        "an all-valid match set must report zero parse errors"
    );
}

// === #5717 / #5628 tolerant-load parity: `off` PRECEDENCE over a contradictory
// terminal action ===
//
// The #5628 commit gate hard-rejects a NAT rule whose `then` block carries two
// mutually-exclusive terminal actions; the tolerant load / peer-sync path only
// WARNS (#1960 no-brick), so a pre-#5628 persisted config — or a peer-synced
// one — still reaches this matcher with BOTH fields set (the Go compiler's
// independent-`if` setters record every action it finds, and the Go snapshot
// builder forwards `off` + `interface_mode` / `pool_*` verbatim; see
// pkg/dataplane/userspace/nat_source.go).
//
// The gate's contract comment states the resulting behavior is safe because
// "the Rust dataplane's off-precedence governs (off wins -> exempt)". That is
// the ONLY thing standing between a leniently-loaded contradictory rule and
// publishing an authored EXEMPTION as a TRANSLATION — the exact inversion the
// gate exists to prevent — and until #5717 nothing bound it.
//
// `off_rule_short_circuits_translation` above does NOT bind it: its rule sets
// `off` ALONE, so it stays green under a mutation that moves the `rule.off`
// check BELOW the `rule.interface_mode` block (a clean off rule has
// interface_mode == false and pool_mode == false, so it still reaches the
// relocated check). These two tests bind the precedence itself.

/// #5717 fail-on-revert: a leniently-loaded rule carrying BOTH `off` and
/// `interface` must resolve to the EXEMPTION. Moving the `rule.off` early
/// return in `match_source_nat_result` below the `rule.interface_mode` block
/// makes this rewrite the source to the egress address — the authored
/// exemption published as a translation.
#[test]
fn off_wins_over_contradictory_interface_action_5717() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "contradictory-off-interface".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        // Both terminal actions set — what the tolerant path publishes for
        // `then { source-nat { interface; off; } }`.
        off: true,
        interface_mode: true,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision::default()),
        "a contradictory `off` + `interface` rule must resolve to the EXEMPTION \
         (no rewrite); a rewrite means the authored exemption published as a \
         translation — the #5628 inversion the tolerant path relies on \
         off-precedence to prevent"
    );
}

/// #5717 fail-on-revert: a leniently-loaded rule carrying BOTH `off` and a
/// usable `pool` must resolve to the EXEMPTION and allocate nothing. Moving the
/// `rule.off` early return below the pool block makes this take a pool
/// allocation and rewrite the source.
#[test]
fn off_wins_over_contradictory_pool_action_5717() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "contradictory-off-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        // Both terminal actions set — what the tolerant path publishes for
        // `then { source-nat { off; pool p1; } }`. The Go builder resolves and
        // forwards the pool (probe-verified: PoolAddresses is populated), so
        // the rule is genuinely pool-capable here.
        off: true,
        pool_name: "p1".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision::default()),
        "a contradictory `off` + `pool` rule must resolve to the EXEMPTION (no \
         rewrite, no pool allocation); a rewrite means the authored exemption \
         published as a translation"
    );
}

/// #5717: pin the ACTUAL tolerant-load behavior of a ZERO-action rule so the
/// #5628 contract comment cannot drift back to calling it harmless.
///
/// A leniently-loaded actionless rule is NOT inert. The Go snapshot builder
/// EMITS it (probe-verified: `Off=false Iface=false Pool=""`), it MATCHES here,
/// and the `else` arm below the pool_mode check clears the tentative counter
/// and `continue`s — so matching traffic falls through to the next, BROADER
/// rule and is translated by it. That is the fail-open the strict gate's own
/// rejection text names ("matching traffic falls through — translated by a
/// later broader rule if one matches"). This fixture supplies that later rule;
/// the sibling `actionless_rule_with_no_later_rule_passes_untranslated_5717`
/// covers the other half of that sentence (#6820).
///
/// This test asserts the DECIDED contract (#6823: an actionless rule is
/// NON-TERMINAL), not merely today's behavior. Making one TERMINAL would newly
/// exempt traffic that deployed configs currently translate — the leaking
/// direction, contra #5688 a few lines above the `continue` this exercises.
/// The decision, the rejected alternatives and the criterion that would REOPEN
/// the terminal option are in docs/config-schema.md; any such change must
/// consciously update that section AND this test.
#[test]
fn actionless_rule_falls_through_to_later_broader_rule_5717() {
    let rules = parse_source_nat_rules(&[
        // Narrow, ACTIONLESS rule first — the shape a pre-#5628 config can
        // still carry through a tolerant load.
        SourceNATRuleSnapshot {
            name: "actionless-narrow".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.61.0/24".to_string()],
            ..SourceNATRuleSnapshot::default()
        },
        // Broader translating rule second.
        SourceNATRuleSnapshot {
            name: "broad-interface".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/8".to_string()],
            interface_mode: true,
            ..SourceNATRuleSnapshot::default()
        },
    ]);
    let decision = match_source_nat(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress")),
        None,
    );
    assert_eq!(
        decision,
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("snat v4")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "an actionless rule must fall THROUGH to the later broader rule (today's \
         behavior). If this now reports an exemption, the actionless disposition \
         was changed to terminal — reversing the #6823 decision, a \
         migration-contract change that must be argued in \
         docs/config-schema.md, not landed silently"
    );
}

/// #5717 (#6820 re-gate): the actionless rule with NO later rule to fall into.
///
/// The gate comment said the matched traffic "FALLS THROUGH to a later, broader
/// rule and is translated by it". The first half is right; the second half
/// presumes a later rule EXISTS. The matcher reaches the actionless `else` arm,
/// `continue`s, runs out of rules, and reports `NoMatch` — the packet is
/// FORWARDED, untranslated. The disposition then coincides with the intended
/// exemption, so nothing is observably wrong on the wire today; what is wrong is
/// the RULE, which is non-terminal, so adding any later broader rule turns the
/// same config into the sibling's case and the packet IS translated against the
/// operator's intent. Calling this outcome itself "a fail-open" (an earlier
/// revision did) conflates a live wrong disposition with a latent one, and
/// contradicts the corrected gate wording at
/// compiler_validate_strict_nat.go's ZERO-actions bullet.
///
/// One rule in the slice, deliberately: adding a later rule is exactly what the
/// sibling does, and it is the presence of that rule that the old wording
/// silently assumed.
///
/// ASSERTED ON `SourceNatLookup`, NOT ON THE `Option` WRAPPER (#6820 re-gate).
/// The wrapper `match_source_nat` folds `NoMatch | Unavailable(_) => None`
/// (source.rs), so an `assert_eq!(..., None)` is satisfied by BOTH — the exact
/// distinction this test's name makes. Production splits them oppositely:
/// `NoMatch => Ok(NatDecision::default())` forwards the packet untranslated,
/// while `Unavailable(failure) => Err(failure)`
/// (afxdp/poll_descriptor/nat_exception.rs) funnels into
/// `record_source_nat_failure` + `scratch_recycle.push` + `continue` in
/// afxdp/poll_descriptor/mod.rs — the packet is DROPPED. The wrapper is also
/// reachable in production only through `match_source_nat_for_flow`, which is
/// `#[cfg_attr(not(test), allow(dead_code))]`; the live entry point is
/// `match_source_nat_result_for_tuple`, which is what this calls, with a real
/// TCP tuple rather than the address-only `protocol: None` sentinel.
#[test]
fn actionless_rule_with_no_later_rule_passes_untranslated_5717() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "actionless-only".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        // No off, no interface_mode, no pool — the actionless shape.
        ..SourceNATRuleSnapshot::default()
    }]);
    let mut counter = None;
    let lookup = match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        Some(PROTO_TCP),
        44444,
        443,
        Some("172.16.80.8".parse().expect("egress")),
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    match lookup {
        SourceNatLookup::NoMatch => {}
        SourceNatLookup::Unavailable(f) => panic!(
            "actionless rule with NO later rule reported Unavailable({:?}) — production \
             maps Unavailable to Err and DROPS the packet (nat_exception.rs -> \
             record_source_nat_failure + continue). The rule names no terminal action \
             at all; turning that into a drop is a fail-CLOSED regression that the \
             `Option`-returning wrapper cannot see, because it folds NoMatch and \
             Unavailable to the same None",
            f.reason
        ),
        SourceNatLookup::Matched(d) => panic!(
            "actionless rule with NO later rule reported Matched({d:?}) — a rewrite \
             means the actionless arm started translating on a rule that names no \
             terminal action; a default (no-rewrite) decision means the actionless \
             disposition became TERMINAL, reversing the #6823 decision — a \
             migration-contract change that must be argued in \
             docs/config-schema.md, not landed silently"
        ),
    }
}

/// #5717 (#6820 gate): a contradictory rule WITHOUT `off` — source NAT
/// `interface` + `pool` — resolves to INTERFACE TRANSLATION, not to an
/// exemption.
///
/// This is the case that let a false safety claim survive review. The gate's
/// replacement wording said a contradiction "resolves to the EXEMPTION", which
/// is true only when the contradiction contains `off`. Here there is no `off`,
/// the matcher checks off -> interface_mode -> pool_mode in that order, and
/// interface SNAT wins while the authored pool is silently discarded.
///
/// Asserting today's behaviour, not endorsing it: the rule is malformed and the
/// strict commit gate rejects it. The point is that nothing previously bound
/// what the tolerant path does with it, so prose could claim anything.
#[test]
fn interface_wins_over_pool_without_off_5717() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "contradictory-interface-pool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        // No `off` — the two remaining terminal actions only.
        interface_mode: true,
        pool_name: "p1".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision {
            rewrite_src: Some("172.16.80.8".parse().expect("egress snat")),
            rewrite_dst: None,
            ..NatDecision::default()
        }),
        "an `interface` + `pool` contradiction carries no `off`, so it must resolve \
         to INTERFACE translation (the egress address) — NOT to an exemption, and \
         NOT to the pool address. If this now reports an exemption or a pool \
         rewrite, the precedence changed and every comment claiming \
         off-precedence needs re-reading"
    );
}

/// #5717 (#6820 re-gate): the OTHER half of the `interface` + `pool`
/// precedence claim — the one where interface mode has nothing to translate to.
///
/// `interface_wins_over_pool_without_off_5717` above supplies a same-family
/// egress address, so it exercises only the branch where interface translation
/// SUCCEEDS. The claim it is cited for is two-sided: interface mode wins, and
/// when the egress interface has no same-family address the rule takes the
/// #5688 fail-closed belt (`Unavailable(InterfaceNoEgressAddress)`) instead of
/// falling back to the authored pool. Nothing bound that second side.
/// Mutation-measured: letting the no-egress arm fall through to the pool block
/// when `rule.pool_mode` is set leaves every `5717` test AND both
/// `interface_source_nat_no_v{4,6}_egress_addr_fails_closed` tests GREEN —
/// those two carry NO pool, so there is no fallback for them to reach and they
/// cannot see the interaction.
///
/// The difference is a security boundary. The belt exists because a
/// `Matched`-with-`None`-rewrite forwarded the private source untranslated
/// (#5688); falling through to the pool does not leak, but it silently
/// translates onto a DIFFERENT public address than the rule's own terminal
/// action names, resurrecting the discarded `pool` of a rule the strict gate
/// rejects — a translation decision made by a fallback no operator authored.
/// Fail closed and let the flow take the `nat_alloc_fail` drop.
///
/// Both families, because the belt resolves the egress address per PACKET
/// family: the pool carries a usable address of each family, so the mutated
/// fallback has somewhere real to land in both directions and a RED here is
/// not an artifact of an unusable pool.
#[test]
fn interface_with_pool_no_egress_fails_closed_5717() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "contradictory-interface-pool-no-egress".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec![
            "10.0.61.0/24".to_string(),
            "2001:559:8585:ef00::/64".to_string(),
        ],
        // No `off`: `interface` + `pool`, the same shape as the test above.
        interface_mode: true,
        pool_name: "p1".to_string(),
        // A usable address of BOTH families — the fallback the mutation would
        // take is genuinely available in either direction.
        pool_addresses: vec!["203.0.113.10".to_string(), "2001:db8:cafe::10".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);

    // v4 packet, egress interface has NO v4 address. The v6 address present
    // must not be used to translate a v4 packet, and the v4 POOL address must
    // not be used either.
    match match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().expect("src"),
        "172.16.80.200".parse().expect("dst"),
        None,
        Some("2001:559:8585:80::8".parse().expect("egress v6")),
    ) {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(
                f.reason,
                SourceNatFailureReason::InterfaceNoEgressAddress,
                "the no-egress arm must report the #5688 belt's own reason; a \
                 different reason means the flow took some other failure path"
            );
        }
        other => panic!(
            "expected Unavailable(InterfaceNoEgressAddress), got {other:?} — an \
             `interface` + `pool` rule with no same-family egress address must \
             take the #5688 fail-closed belt, NOT fall back to the pool. A \
             Matched-with-a-pool-rewrite here means the discarded `pool` action \
             quietly became the translation for a rule the operator authored as \
             interface-mode"
        ),
    }

    // v6 packet, egress interface has NO v6 address — symmetric, and equally
    // pool-capable (the pool carries 2001:db8:cafe::10).
    match match_source_nat_result(
        &InterfaceNatAllocators::default(),
        &rules,
        &NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:559:8585:ef00::100".parse().expect("src"),
        "2001:559:8585:80::200".parse().expect("dst"),
        Some("172.16.80.8".parse().expect("egress v4")),
        None,
    ) {
        SourceNatLookup::Unavailable(f) => {
            assert_eq!(
                f.reason,
                SourceNatFailureReason::InterfaceNoEgressAddress,
                "the v6 no-egress arm must report the #5688 belt's own reason"
            );
        }
        other => panic!(
            "expected Unavailable(InterfaceNoEgressAddress), got {other:?} — the \
             v6 half of the belt must fail closed too; the family resolution is \
             per-packet, so a v4-only egress cannot rescue a v6 packet and the \
             v6 pool address must not be substituted"
        ),
    }
}

/// #5717 (#6820 gate): `off` precedence over BOTH other actions at once.
///
/// The two pairwise tests above (`off` + `interface`, `off` + `pool`) do not
/// discharge a claim quantified over "2+ actions": both survive a predicate
/// that mishandles only the three-action shape — e.g. `off && !(interface_mode
/// && pool_mode)`, which is correct for every pair and wrong for the triple.
/// Pairwise fixtures test pairs; ordering among three has to be bound directly.
#[test]
fn off_wins_over_all_three_actions_5717() {
    let rules = parse_source_nat_rules(&[SourceNATRuleSnapshot {
        name: "contradictory-all-three".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.61.0/24".to_string()],
        // Every terminal action a source-NAT rule can carry, at once.
        off: true,
        interface_mode: true,
        pool_name: "p1".to_string(),
        pool_addresses: vec!["203.0.113.10".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..SourceNATRuleSnapshot::default()
    }]);
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            "10.0.61.102".parse().expect("src"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        Some(NatDecision::default()),
        "with all three terminal actions set, `off` must still win — the exemption \
         is the safe resolution and the one every gate comment relies on. A rewrite \
         here means the authored exemption published as a translation on a shape \
         the pairwise tests cannot see"
    );

    // NON-MATCHING controls. Without them, a triple-action early return placed
    // ABOVE `rule.matches(...)` would satisfy the assertion above while
    // exempting traffic the rule never covered — an exemption is a no-translate
    // decision, so widening one silently un-NATs those sources.
    //
    // TWO controls, because `rule.matches` is a conjunction over several axes
    // and a control that varies only ONE of them is scoped narrower than the
    // claim. The out-of-prefix control alone still passes an early exemption
    // hoisted to just after the source-prefix check but before the zone /
    // destination / L4 checks — a real shape, since the source prefix is the
    // first thing a reader reaches for. The wrong-zone-inside-the-prefix
    // control is what closes that: it holds the source prefix satisfied and
    // varies only the zone, so it can only pass if the handling is inside the
    // FULL match gate.
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            "lan",
            "wan",
            // Outside 10.0.61.0/24.
            "10.0.99.7".parse().expect("src outside match"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        None,
        "a source OUTSIDE the rule's match prefix must not match at all — if this \
         reports an exemption, the three-action handling was hoisted above the \
         match gate and now un-NATs traffic the rule never covered"
    );
    assert_eq!(
        match_source_nat(
            &InterfaceNatAllocators::default(),
            &rules,
            &NatScopeCtx::default(),
            // Wrong ingress zone; the rule is scoped lan -> wan.
            "dmz",
            "wan",
            // INSIDE 10.0.61.0/24 — only the zone disqualifies this packet.
            "10.0.61.102".parse().expect("src inside match prefix"),
            "172.16.80.200".parse().expect("dst"),
            Some("172.16.80.8".parse().expect("egress")),
            None,
        ),
        None,
        "a packet from the WRONG zone must not match even though its source is \
         inside the rule's prefix — if this reports an exemption, the \
         three-action handling sits after the source-prefix check but before \
         the zone check, and now un-NATs a whole zone the rule never covered"
    );
}
