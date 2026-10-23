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
