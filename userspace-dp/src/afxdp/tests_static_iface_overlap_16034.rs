// #16034 — interface-SNAT mint vs static-NAT external backstop (A2-C8).
//
// The strict Go gate already pairs static externals against interface
// egress owners (validateStaticNATPoolOverlapStrict / #15258), and the
// #16015 runtime work covered the NPTv6 leg for interface mints. What
// was missing: the interface mint arms consulted only pool/NAT64 peer
// owners — never static_owns_wire_identity — so on a tolerated install
// (lenient load / peer-sync / handcrafted snapshot) an interface mint
// could publish the exact (egress, port) a static external publishes
// unconditionally, and the reverse index could not attribute replies.
//
// Every reject cell goes through `build_forwarding_state` so the wiring
// pass (`wire_static_overlap_peers` interface wiring) is exercised:
// deleting that wiring, or the mint-side static check, reds them.
// Controls pin that statics on other addresses, and port-mapped statics
// at other ports, still mint (PAT arm PATs around a mapped port).

use super::forwarding_build::build_forwarding_state;
use super::test_fixtures::nat_snapshot;
use super::ForwardingState;
use crate::nat::{NatHolder, SourceNatFailureReason, SourceNatLookup};
use crate::protocol::{ConfigSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const EGRESS: &str = "203.0.113.10";
const OTHER: &str = "203.0.113.11";
const SRC_PORT: u16 = 33333;

fn iface_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.static_nat_rules = Vec::new();
    snapshot.nat64_rules = Vec::new();
    snapshot.nptv6_rules = Vec::new();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "iface-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.0/24".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    snapshot
}

fn static_rule(external: &str, match_port: u16, mapped_port: u16) -> StaticNATRuleSnapshot {
    StaticNATRuleSnapshot {
        name: "static-web".to_string(),
        from_zone: "wan".to_string(),
        external_ip: external.to_string(),
        internal_ip: "10.0.30.100".to_string(),
        match_destination_port: match_port,
        mapped_port,
        ..Default::default()
    }
}

fn iface_mint(
    state: &ForwardingState,
    egress: &str,
    protocol: u8,
    src_port: u16,
) -> SourceNatLookup {
    let mut counter = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.0.7".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
        Some(protocol),
        src_port,
        443,
        Some(egress.parse::<Ipv4Addr>().expect("egress v4")),
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
fn iface_mint_on_whole_address_static_external_is_refused_16034() {
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.source_nat_rules[0].interface_mode,
        "fixture: interface-only rule"
    );
    assert!(
        state.source_nat_rules[0].static_externals.is_some(),
        "fixture: interface-only rule must carry the static view itself"
    );
    let mint = iface_mint(&state, EGRESS, 6, SRC_PORT);
    assert_eq!(
        snat_identity(&mint),
        None,
        "an interface mint on a whole-address static external must not publish"
    );
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::InterfaceIdentityExhausted),
        "the refusal must carry the interface-exhausted reason"
    );
}

#[test]
fn iface_mint_after_pat_on_whole_address_static_is_refused_16034() {
    // Decisive cell per the issue: the PAT path must not publish either.
    // A first flow preserves SRC_PORT; a second flow from a different
    // internal host with the same source port forces the allocator to
    // PAT — every candidate port is static-owned, so it must refuse.
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    let first = iface_mint(&state, EGRESS, 6, SRC_PORT);
    assert_eq!(
        snat_identity(&first),
        None,
        "first mint must already refuse"
    );
    // Second, distinct internal host (different flow key) — same refusal.
    let mut counter = None;
    let second = crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.0.9".parse().expect("src2"),
        "8.8.8.8".parse().expect("dst"),
        Some(6),
        SRC_PORT,
        443,
        Some(EGRESS.parse::<Ipv4Addr>().expect("egress v4")),
        None,
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert_eq!(
        snat_reason(&second),
        Some(SourceNatFailureReason::InterfaceIdentityExhausted),
        "PAT-attempted mint on a whole-address static must refuse, not PAT around it"
    );
}

#[test]
fn iface_address_only_mint_on_static_external_is_refused_16034() {
    // GRE (no L4 ports) takes the address-only arm.
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    let mint = iface_mint(&state, EGRESS, 47, 0);
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::InterfaceIdentityExhausted),
        "address-only interface mint on a static external must refuse"
    );
}

#[test]
fn iface_mint_never_lands_on_port_mapped_static_port_16034() {
    // The preserved port collides with the port-mapped static's fixed
    // external port, so the mint must PAT — and the PAT candidate set
    // excludes that port, so it can never land on the static's tuple.
    // (For a whole-address static every candidate is excluded and the
    // mint refuses instead — the cells above.)
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, SRC_PORT, 8443)];
    let state = build_forwarding_state(&snapshot);
    let mint = iface_mint(&state, EGRESS, 6, SRC_PORT);
    assert_ne!(
        snat_identity(&mint),
        Some((EGRESS.parse::<IpAddr>().unwrap(), None)),
        "interface mint must not publish the preserved tuple on a port-mapped static port"
    );
    if let Some((ip, port)) = snat_identity(&mint) {
        assert_eq!(ip, EGRESS.parse::<IpAddr>().unwrap());
        assert_ne!(
            port,
            Some(SRC_PORT),
            "a PAT'd mint must not land on the static's fixed port"
        );
    }
}

#[test]
fn iface_mint_pats_around_port_mapped_static_16034() {
    // Control: source port differs from the mapped port — the static
    // owns only its fixed port, so the mint preserves its own port.
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, 20000, 8443)];
    let state = build_forwarding_state(&snapshot);
    let mint = iface_mint(&state, EGRESS, 6, SRC_PORT);
    assert_eq!(
        snat_identity(&mint),
        Some((EGRESS.parse::<IpAddr>().unwrap(), None)),
        "control: mint at a port the port-mapped static does not own must publish (port preserved)"
    );
}

#[test]
fn iface_mint_outside_static_external_still_mints_16034() {
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(OTHER, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    let mint = iface_mint(&state, EGRESS, 6, SRC_PORT);
    assert_eq!(
        snat_identity(&mint),
        Some((EGRESS.parse::<IpAddr>().unwrap(), None)),
        "control: egress no static covers must still mint (port preserved)"
    );
}

#[test]
fn iface_mint_no_static_still_mints_16034() {
    let snapshot = iface_snapshot();
    let state = build_forwarding_state(&snapshot);
    assert!(state.source_nat_rules[0].static_externals.is_none());
    let mint = iface_mint(&state, EGRESS, 6, SRC_PORT);
    assert_eq!(
        snat_identity(&mint),
        Some((EGRESS.parse::<IpAddr>().unwrap(), None)),
        "control: with no static rules the interface mint must proceed normally"
    );
}

#[test]
fn iface_mint_v6_on_v6_static_external_is_refused_16034() {
    let mut snapshot = iface_snapshot();
    snapshot.source_nat_rules[0].source_addresses = vec!["2001:db8:ffff::/48".to_string()];
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "static6".to_string(),
        from_zone: "wan".to_string(),
        external_ip: "2001:db8:1::10".to_string(),
        internal_ip: "2001:db8:ffff::100".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let mut counter = None;
    let mint = crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "2001:db8:ffff::7".parse().expect("src6"),
        "2001:db8:aa::8".parse().expect("dst6"),
        Some(6),
        SRC_PORT,
        443,
        None,
        Some("2001:db8:1::10".parse::<Ipv6Addr>().expect("egress v6")),
        0,
        false,
        false,
        NatHolder::Untracked,
        &mut counter,
    );
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::InterfaceIdentityExhausted),
        "v6 interface mint on a v6 static external must refuse"
    );
}

// --- HA import: dynamic interface rewrite on a static external ---

fn ha_key_v4() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.0.7".parse().expect("src"),
        dst_ip: "8.8.8.8".parse().expect("dst"),
        src_port: SRC_PORT,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

#[test]
fn ha_iface_import_on_static_external_is_refused_16034() {
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    let statics = state.static_nat.external_identities();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(EGRESS.parse().expect("rewrite")),
        ..Default::default()
    };
    let ok = crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &ha_key_v4(),
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static: Some(false),
            static_externals: Some(&statics),
            nptv6_external_prefixes: &[],
        },
    );
    assert!(
        !ok,
        "dynamic HA interface import on a static external must refuse, not book success"
    );
}

#[test]
fn ha_iface_import_outside_static_still_reserves_16034() {
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(OTHER, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    let statics = state.static_nat.external_identities();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(EGRESS.parse().expect("rewrite")),
        ..Default::default()
    };
    let ok = crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &ha_key_v4(),
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static: Some(false),
            static_externals: Some(&statics),
            nptv6_external_prefixes: &[],
        },
    );
    assert!(
        ok,
        "control: HA interface import no static owns must still reserve"
    );
}

#[test]
fn ha_genuine_static_import_still_succeeds_16034() {
    // Control: a static-provenance import IS the static publish — it
    // keeps the #15191 no-reservation success, never booked/refused here.
    let mut snapshot = iface_snapshot();
    snapshot.static_nat_rules = vec![static_rule(EGRESS, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    let statics = state.static_nat.external_identities();
    let nat = crate::nat::NatDecision {
        rewrite_src: Some(EGRESS.parse().expect("rewrite")),
        ..Default::default()
    };
    let ok = crate::nat::reserve_synced_source_nat_allocation_untracked(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &ha_key_v4(),
        nat,
        false,
        Some(("lan", "wan")),
        0,
        crate::nat::SyncedSourceNatDomains {
            source_nat_static: Some(true),
            static_externals: Some(&statics),
            nptv6_external_prefixes: &[],
        },
    );
    assert!(
        ok,
        "control: genuine static import must keep no-reservation success"
    );
}
