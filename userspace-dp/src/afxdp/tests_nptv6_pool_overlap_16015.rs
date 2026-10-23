// #16015 — pool/interface mint inside an NPTv6 external prefix backstop.
//
// The strict Go gate rejects the config at commit. These cells cover
// the tolerated population that still reaches the dataplane (lenient
// load / peer-sync / handcrafted snapshot): a pool mint landing inside
// an installed NPTv6 external prefix must be refused, never published
// as a duplicate wire tuple (NPTv6 preserves the port statelessly, so
// prefix membership at ANY port collides at that same port).
//
// Every reject cell goes through `build_forwarding_state` so the
// wiring pass (`wire_nptv6_overlap_peers`) is exercised: deleting that
// call, or the mint-side NPTv6 check, reds them. Controls pin that
// pools outside the prefix, and prefixes scoped to a disjoint zone,
// still mint.

use super::forwarding_build::build_forwarding_state;
use super::test_fixtures::nat_snapshot;
use super::ForwardingState;
use crate::nat::{InterfaceNatAllocators, NatHolder, SourceNatFailureReason, SourceNatLookup};
use crate::protocol::{ConfigSnapshot, Nptv6RuleSnapshot, SourceNATRuleSnapshot};
use std::net::{IpAddr, Ipv6Addr};

const INSIDE: &str = "2001:db8:1::10";
const OUTSIDE: &str = "2001:db8:2::10";
const PORT: u16 = 20000;

fn base_snapshot(pool_addr: &str) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.static_nat_rules = Vec::new();
    snapshot.nat64_rules = Vec::new();
    snapshot.nptv6_rules = Vec::new();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "spool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["2001:db8:ffff::/48".to_string()],
        pool_name: "sp".to_string(),
        pool_addresses: vec![format!("{pool_addr}/128")],
        port_low: PORT,
        port_high: PORT,
        ..Default::default()
    }];
    snapshot
}

fn nptv6_rule(from_zone: &str) -> Nptv6RuleSnapshot {
    Nptv6RuleSnapshot {
        name: "npt1".to_string(),
        from_zone: from_zone.to_string(),
        // Checksum-neutral pair (same ones-complement word sum, words
        // swapped): adjustment is zero, so the published address is a
        // pure prefix swap and the claimant below is exact.
        internal_prefix: "0db8:2001:1::/48".to_string(),
        external_prefix: "2001:db8:1::/48".to_string(),
    }
}
fn snat_mint_v6(state: &ForwardingState) -> SourceNatLookup {
    let mut counter = None;
    crate::nat::match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:db8:ffff::7".parse().expect("src"),
        "2001:db8:aa::8".parse().expect("dst"),
        Some(6),
        33333,
        443,
        None,
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

fn snat_identity(lookup: &SourceNatLookup) -> Option<(IpAddr, Option<u16>)> {
    match lookup {
        SourceNatLookup::Matched(d) => d.rewrite_src.map(|ip| (ip, d.rewrite_src_port)),
        _ => None,
    }
}

fn snat_reason(lookup: &SourceNatLookup) -> Option<SourceNatFailureReason> {
    match lookup {
        SourceNatLookup::Unavailable(f) => Some(f.reason),
        _ => None,
    }
}

#[test]
fn pool_mint_inside_nptv6_external_is_refused_16015() {
    let mut snapshot = base_snapshot(INSIDE);
    snapshot.nptv6_rules = vec![nptv6_rule("wan")];
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.source_nat_rules[0].nptv6_externals.is_some(),
        "fixture: the pool touches an NPTv6 external prefix and must hold the view"
    );
    // Reverse claimant: the NPTv6-generated tuple for the same host
    // keeps the source port unchanged — verify the prefix really
    // publishes the pool address at the minted port.
    let mut npt_src: Ipv6Addr = "0db8:2001:1::10".parse().expect("internal");
    assert!(
        state.nptv6.translate_outbound(&mut npt_src, "wan"),
        "fixture: NPTv6 must translate the internal host"
    );
    assert_eq!(
        npt_src,
        INSIDE.parse::<Ipv6Addr>().unwrap(),
        "NPTv6 publishes the pool address itself (port preserved on the wire)"
    );
    let mint = snat_mint_v6(&state);
    assert_eq!(
        snat_identity(&mint),
        None,
        "a pool mint inside an NPTv6 external prefix must not publish"
    );
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the refusal must carry the peer-overlap reason"
    );
}

#[test]
fn pool_mint_outside_nptv6_external_still_mints_16015() {
    let mut snapshot = base_snapshot(OUTSIDE);
    snapshot.nptv6_rules = vec![nptv6_rule("wan")];
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.source_nat_rules[0].nptv6_externals.is_none(),
        "fixture: a disjoint pool must leave the fast path untouched"
    );
    let mint = snat_mint_v6(&state);
    assert_eq!(
        snat_identity(&mint),
        Some((OUTSIDE.parse::<IpAddr>().unwrap(), Some(PORT))),
        "control: a pool address no NPTv6 prefix covers must still mint"
    );
}

#[test]
fn pool_mint_nptv6_disjoint_zone_still_mints_16015() {
    // NPTv6 scoped to zone-b; the pool flow egresses wan. Split-horizon:
    // no packet's egress zone matches both, so no collision.
    let mut snapshot = base_snapshot(INSIDE);
    snapshot.nptv6_rules = vec![nptv6_rule("zone-b")];
    let state = build_forwarding_state(&snapshot);
    let mint = snat_mint_v6(&state);
    assert_eq!(
        snat_identity(&mint),
        Some((INSIDE.parse::<IpAddr>().unwrap(), Some(PORT))),
        "control: NPTv6 in a disjoint zone must not refuse the mint"
    );
}

#[test]
fn pool_mint_no_nptv6_still_mints_16015() {
    let snapshot = base_snapshot(INSIDE);
    let state = build_forwarding_state(&snapshot);
    assert!(state.source_nat_rules[0].nptv6_externals.is_none());
    let mint = snat_mint_v6(&state);
    assert_eq!(
        snat_identity(&mint),
        Some((INSIDE.parse::<IpAddr>().unwrap(), Some(PORT))),
        "control: with no NPTv6 rules the pool must mint normally"
    );
}

// --- Fold: interface-only SNAT carries its own NPTv6 view ---

fn iface_only_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.static_nat_rules = Vec::new();
    snapshot.nat64_rules = Vec::new();
    snapshot.nptv6_rules = vec![nptv6_rule("wan")];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "iface-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["2001:db8:ffff::/48".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    snapshot
}

fn iface_mint_v6(state: &ForwardingState, egress: Ipv6Addr) -> SourceNatLookup {
    let mut counter = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:db8:ffff::7".parse().expect("src"),
        "2001:db8:aa::8".parse().expect("dst"),
        Some(6),
        33333,
        443,
        None,
        Some(egress),
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    )
}

#[test]
fn iface_only_mint_inside_nptv6_external_is_refused_16015() {
    let state = build_forwarding_state(&iface_only_snapshot());
    assert!(
        state.source_nat_rules[0].interface_mode,
        "fixture: interface-only rule"
    );
    assert!(
        state.source_nat_rules[0].nptv6_externals.is_some(),
        "fold fixture: interface-only rule must carry the NPTv6 view itself"
    );
    let mint = iface_mint_v6(&state, INSIDE.parse().expect("egress"));
    assert_eq!(
        snat_identity(&mint),
        None,
        "interface-only mint inside an NPTv6 external prefix must not publish"
    );
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::InterfaceIdentityExhausted),
        "interface refusal must carry the interface-exhausted reason"
    );
}

#[test]
fn iface_only_mint_outside_nptv6_external_still_mints_16015() {
    let state = build_forwarding_state(&iface_only_snapshot());
    let mint = iface_mint_v6(&state, OUTSIDE.parse().expect("egress"));
    assert_eq!(
        snat_identity(&mint),
        Some((OUTSIDE.parse::<IpAddr>().unwrap(), None)),
        "control: interface egress outside the prefix must still mint (port preserved)"
    );
}

// --- Fold: HA import must not succeed before the NPTv6 overlap check ---

fn ha_key() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: 6,
        src_ip: "2001:db8:ffff::7".parse().expect("src"),
        dst_ip: "2001:db8:aa::8".parse().expect("dst"),
        src_port: 33333,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

#[test]
fn ha_import_inside_nptv6_external_is_refused_before_success_16015() {
    // Pool rule (INSIDE, one port) + NPTv6 wan. A dynamic synced import
    // naming the pool tuple must refuse, not return success via the
    // early no-reservation / PASS success returns.
    let mut snapshot = base_snapshot(INSIDE);
    snapshot.nptv6_rules = vec![nptv6_rule("wan")];
    let state = build_forwarding_state(&snapshot);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(INSIDE.parse().expect("rewrite")),
        rewrite_src_port: Some(PORT),
        ..Default::default()
    };
    let ok = crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &ha_key(),
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static: Some(false),
            static_externals: None,
            nptv6_external_prefixes: &[],
        },
    );
    assert!(
        !ok,
        "HA import inside an NPTv6 external prefix must refuse before any success return"
    );
}

#[test]
fn ha_import_outside_nptv6_external_still_reserves_16015() {
    let mut snapshot = base_snapshot(OUTSIDE);
    snapshot.nptv6_rules = vec![nptv6_rule("wan")];
    let state = build_forwarding_state(&snapshot);
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(OUTSIDE.parse().expect("rewrite")),
        rewrite_src_port: Some(PORT),
        ..Default::default()
    };
    let ok = crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &ha_key(),
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static: Some(false),
            static_externals: None,
            nptv6_external_prefixes: &[],
        },
    );
    assert!(
        ok,
        "control: HA import outside the prefix must still reserve"
    );
}

#[test]
fn ha_iface_import_inside_nptv6_external_is_refused_16015() {
    // Interface-only: no pool owns the address, so PASS falls to the
    // interface domain — which must refuse inside the prefix instead
    // of booking and returning success.
    let state = build_forwarding_state(&iface_only_snapshot());
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(INSIDE.parse().expect("rewrite")),
        ..Default::default()
    };
    let ok = crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &ha_key(),
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static: Some(false),
            static_externals: None,
            nptv6_external_prefixes: &[],
        },
    );
    assert!(
        !ok,
        "HA interface import inside an NPTv6 external prefix must refuse, not book success"
    );
}
