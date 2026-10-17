// #14368 — static-NAT external vs source-pool / NAT64-pool mint backstop.
//
// The strict Go gate rejects a static external inside a referenced pool at
// commit. These cells cover the tolerated population that still reaches the
// dataplane (lenient load / peer-sync / handcrafted snapshot): a pool or
// NAT64 mint landing on an external the static table publishes must be
// refused, never published as a duplicate wire tuple.
//
// Every cell goes through `build_forwarding_state` so the wiring pass
// (`wire_static_overlap_peers`) is exercised: deleting that call, or the
// mint-side static check, reds the reject cells. Controls pin that statics
// outside the pool and pool addresses outside every static external still
// mint, and that static-vs-static behaviour is unchanged.

use super::forwarding_build::build_forwarding_state;
use super::ForwardingState;
use super::test_fixtures::nat_snapshot;
use crate::nat::{InterfaceNatAllocators, NatHolder, SourceNatFailureReason, SourceNatLookup};
use crate::protocol::{ConfigSnapshot, NAT64RuleSnapshot, SourceNATRuleSnapshot, StaticNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const SHARED: &str = "203.0.113.10";
const OUTSIDE: &str = "203.0.113.11";
const PORT: u16 = 20000;

fn base_snapshot() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.static_nat_rules = Vec::new();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "spool".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.0/24".to_string()],
        pool_name: "sp".to_string(),
        pool_addresses: vec![format!("{SHARED}/32")],
        port_low: PORT,
        port_high: PORT,
        ..Default::default()
    }];
    snapshot.nat64_rules = Vec::new();
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

fn snat_mint(state: &ForwardingState) -> SourceNatLookup {
    let mut counter = None;
    crate::nat::match_source_nat_result_for_tuple(
        &InterfaceNatAllocators::default(),
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.0.7".parse().expect("src"),
        "8.8.8.8".parse().expect("dst"),
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
fn pool_mint_on_whole_address_static_external_is_refused_14368() {
    let mut snapshot = base_snapshot();
    snapshot.static_nat_rules = vec![static_rule(SHARED, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.source_nat_rules[0].static_externals.is_some(),
        "fixture: the pool touches a static external and must hold the view"
    );
    let mint = snat_mint(&state);
    assert_eq!(
        snat_identity(&mint),
        None,
        "a pool mint on a whole-address static external must not publish"
    );
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "the refusal must carry the peer-overlap reason"
    );
}

#[test]
fn pool_mint_outside_static_external_still_mints_14368() {
    let mut snapshot = base_snapshot();
    snapshot.static_nat_rules = vec![static_rule(OUTSIDE, 0, 0)];
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.source_nat_rules[0].static_externals.is_none(),
        "fixture: a disjoint static external must leave the fast path untouched"
    );
    let mint = snat_mint(&state);
    assert_eq!(
        snat_identity(&mint),
        Some((SHARED.parse::<IpAddr>().unwrap(), Some(PORT))),
        "control: a pool address no static covers must still mint"
    );
}

#[test]
fn pool_mint_on_port_mapped_static_port_is_refused_14368() {
    let mut snapshot = base_snapshot();
    // The static emits external port 20000 (match port); the pool's one-port
    // range is exactly that port.
    snapshot.static_nat_rules = vec![static_rule(SHARED, PORT, 8443)];
    let state = build_forwarding_state(&snapshot);
    let mint = snat_mint(&state);
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "a port-mapped static must refuse a mint of its fixed external port"
    );
}

#[test]
fn pool_mint_on_block_static_external_is_refused_14368() {
    let mut snapshot = base_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        name: "static-block".to_string(),
        from_zone: "wan".to_string(),
        external_ip: "203.0.113.0/24".to_string(),
        internal_ip: "10.0.30.0/24".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let mint = snat_mint(&state);
    assert_eq!(
        snat_reason(&mint),
        Some(SourceNatFailureReason::PoolPeerAddressOverlap),
        "a block static external containing the pool address must refuse the mint"
    );
}

#[test]
fn nat64_mint_on_static_external_is_refused_14368() {
    let mut snapshot = base_snapshot();
    snapshot.source_nat_rules = Vec::new();
    snapshot.static_nat_rules = vec![static_rule(SHARED, 0, 0)];
    snapshot.nat64_rules = vec![NAT64RuleSnapshot {
        name: "n64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![SHARED.to_string()],
        ..Default::default()
    }];
    // NAT64 mints from the bottom of its own range; pin the static check by
    // using a whole-address static, which covers every minted port.
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.nat64.prefixes[0].static_externals.is_some(),
        "fixture: the NAT64 pool touches a static external"
    );
    let mint = state.nat64.allocate_source_for_worker(
        0,
        6,
        "2001:db8::7".parse::<Ipv6Addr>().expect("v6 src"),
        "8.8.8.8".parse::<Ipv4Addr>().expect("v4 dst"),
        40000,
        443,
        0,
        0,
        &[],
        0,
        None,
    );
    assert_eq!(
        mint,
        Err(SourceNatFailureReason::PoolPeerAddressOverlap),
        "a NAT64 mint on a static external must roll back and refuse"
    );
}

#[test]
fn nat64_mint_outside_static_external_still_mints_14368() {
    let mut snapshot = base_snapshot();
    snapshot.source_nat_rules = Vec::new();
    snapshot.static_nat_rules = vec![static_rule(OUTSIDE, 0, 0)];
    snapshot.nat64_rules = vec![NAT64RuleSnapshot {
        name: "n64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec![SHARED.to_string()],
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);
    let mint = state.nat64.allocate_source_for_worker(
        0,
        6,
        "2001:db8::7".parse::<Ipv6Addr>().expect("v6 src"),
        "8.8.8.8".parse::<Ipv4Addr>().expect("v4 dst"),
        40000,
        443,
        0,
        0,
        &[],
        0,
        None,
    );
    assert!(
        mint.is_ok(),
        "control: a NAT64 pool no static covers must still mint, got {mint:?}"
    );
}
