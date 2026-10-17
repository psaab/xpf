// #14367 — interface-mode SNAT had no runtime mint guard against NAT64 /
// prefix-spelled SNAT pools sharing its egress address.
//
// Colliders share egress E=203.0.113.1. Tests drive the production mint paths
// through build_forwarding_state so the combined overlap index is built the
// way production builds it.

use super::forwarding_build::build_forwarding_state;
use super::ForwardingState;
use super::test_fixtures::nat_snapshot;
use crate::nat::{InterfaceNatAllocators, NatHolder, SourceNatFailureReason, SourceNatLookup};
use crate::protocol::{ConfigSnapshot, NAT64RuleSnapshot, SourceNATRuleSnapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const E: &str = "172.16.80.8";
const SRV: &str = "93.184.216.34";
const TCP: u8 = 6;

fn snap_iface_pool(pool_addr: &str) -> ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.source_nat_rules = vec![
        SourceNATRuleSnapshot {
            name: "iface-snat".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["10.0.0.0/24".into()],
            interface_mode: true,
            ..Default::default()
        },
        SourceNATRuleSnapshot {
            name: "pool-snat".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["10.1.0.0/24".into()],
            pool_name: "P".into(),
            pool_addresses: vec![pool_addr.to_string()],
            port_low: 40000,
            port_high: 40000,
            ..Default::default()
        },
    ];
    snap
}

fn snap_iface_nat64(pool_addr: &str) -> ConfigSnapshot {
    let mut snap = nat_snapshot();
    snap.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "iface-snat".into(),
        from_zone: "lan".into(),
        to_zone: "wan".into(),
        source_addresses: vec!["0.0.0.0/0".into()],
        interface_mode: true,
        ..Default::default()
    }];
    snap.nat64_rules = vec![NAT64RuleSnapshot {
        name: "n64".into(),
        prefix: "64:ff9b::/96".into(),
        pool_addresses: vec![pool_addr.to_string()],
        ..Default::default()
    }];
    snap
}

fn iface_admit(state: &ForwardingState, src: &str, src_port: u16, dst: &str) -> SourceNatLookup {
    let mut c = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().unwrap(),
        dst.parse().unwrap(),
        Some(TCP),
        src_port,
        443,
        Some(E.parse::<Ipv4Addr>().unwrap()),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut c,
    )
}

fn pool_admit(state: &ForwardingState, src: &str, src_port: u16) -> SourceNatLookup {
    let mut c = None;
    crate::nat::match_source_nat_result_for_tuple(
        &state.iface_nat_allocators,
        &state.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src.parse().unwrap(),
        SRV.parse().unwrap(),
        Some(TCP),
        src_port,
        443,
        Some(E.parse::<Ipv4Addr>().unwrap()),
        None,
        1_000,
        false,
        false,
        NatHolder::Untracked,
        &mut c,
    )
}

fn nat64_mint(state: &ForwardingState, src_port: u16) -> Result<(Ipv4Addr, u16), SourceNatFailureReason> {
    state.nat64.allocate_source_for_worker(
        0,
        TCP,
        "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
        SRV.parse::<Ipv4Addr>().unwrap(),
        src_port,
        443,
        1_000,
        0,
        &state.source_nat_rules,
        0,
        Some(&state.iface_nat_allocators),
    )
}

#[test]
fn nat64_then_interface_does_not_duplicate_14367() {
    let state = build_forwarding_state(&snap_iface_nat64(E));
    let (ip, pt) = nat64_mint(&state, 40000).expect("NAT64 mint");
    assert_eq!(ip.to_string(), E);
    match iface_admit(&state, "10.0.0.2", pt, SRV) {
        SourceNatLookup::Matched(d) => {
            assert_eq!(d.rewrite_src, Some(E.parse::<IpAddr>().unwrap()));
            assert_ne!(d.rewrite_src_port.unwrap_or(pt), pt, "#14367: interface preserved NAT64-owned ({E},{pt}) toward same remote");
        }
        SourceNatLookup::Unavailable(f) => assert_eq!(f.reason, SourceNatFailureReason::InterfaceIdentityExhausted),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn interface_then_nat64_is_refused_14367() {
    let state = build_forwarding_state(&snap_iface_nat64(E));
    match iface_admit(&state, "10.0.0.2", 40000, SRV) {
        SourceNatLookup::Matched(d) => assert_eq!(d.rewrite_src_port, None, "first iface preserves"),
        other => panic!("iface mint {other:?}"),
    }
    // NAT64 allocator will choose its own port (1024..), not necessarily 40000.
    // To force collision we need NAT64 to mint 40000: its BIB reuses per
    // (proto,src_v6,src_port) — allocate_translation picks next port from
    // cursor, not src_port. So this order cannot deterministically collide
    // via allocate_source_for_worker alone. Instead mint interface at the
    // port NAT64 WOULD pick: first NAT64 mint on a fresh state picks 1024.
    // Rebuild fresh and preserve 1024 first.
    let state2 = build_forwarding_state(&snap_iface_nat64(E));
    match iface_admit(&state2, "10.0.0.2", 1024, SRV) {
        SourceNatLookup::Matched(d) => assert_eq!(d.rewrite_src_port, None),
        other => panic!("iface mint2 {other:?}"),
    }
    assert_eq!(
        nat64_mint(&state2, 40000),
        Err(SourceNatFailureReason::PoolPeerAddressOverlap),
        "#14367: NAT64 must refuse interface-owned (E,1024) toward SRV"
    );
    let _ = state;
}

#[test]
fn pool_then_interface_does_not_duplicate_14367() {
    let state = build_forwarding_state(&snap_iface_pool(&format!("{E}/32")));
    let pt = match pool_admit(&state, "10.1.0.7", 33333) {
        SourceNatLookup::Matched(d) => d.rewrite_src_port.expect("pool PAT port"),
        other => panic!("pool mint {other:?}"),
    };
    assert_eq!(pt, 40000);
    match iface_admit(&state, "10.0.0.2", pt, SRV) {
        SourceNatLookup::Matched(d) => assert_ne!(d.rewrite_src_port.unwrap_or(pt), pt, "#14367 pool->iface duplicate"),
        SourceNatLookup::Unavailable(f) => assert_eq!(f.reason, SourceNatFailureReason::InterfaceIdentityExhausted),
        other => panic!("{other:?}"),
    }
}

#[test]
fn interface_then_pool_is_refused_14367() {
    let state = build_forwarding_state(&snap_iface_pool(&format!("{E}/32")));
    match iface_admit(&state, "10.0.0.2", 40000, SRV) {
        SourceNatLookup::Matched(_) => {}
        other => panic!("iface {other:?}"),
    }
    match pool_admit(&state, "10.1.0.7", 33333) {
        SourceNatLookup::Unavailable(f) => assert_eq!(f.reason, SourceNatFailureReason::PoolPeerAddressOverlap, "#14367 iface->pool must refuse"),
        other => panic!("pool must refuse interface-owned identity, got {other:?}"),
    }
}

#[test]
fn prefix_pool_interface_registration_14367() {
    // Prefix-spelled pool 203.0.113.0/24 contains E. After expansion the pool
    // contains E, so a pool mint that lands on E must be guarded. Deterministic
    // landing on E is not guaranteed with many addresses, so assert the
    // combined index registers E as shared between pool and interface egress.
    // We check via behaviour with a /32-equivalent prefix: 203.0.113.1/32 is
    // host prefix; the /24 case is covered by Go detector. Here use /24 and
    // mint many pool flows: one must land on E:40000 (only port), then iface
    // must not duplicate that exact identity if it was minted toward SRV.
    // Pool source is 10.1.0.0/24 distinct hosts.
    let state = build_forwarding_state(&snap_iface_pool("172.16.80.0/24"));
    let mut saw_e = false;
    for i in 0..300u16 {
        let src = format!("10.1.0.{}", (i % 250) + 1);
        // Distinct src_port to get distinct flows? Pool PAT port is fixed 40000
        // per address, each address can mint once toward SRV.
        match pool_admit(&state, &src, 30000 + i) {
            SourceNatLookup::Matched(d) => {
                if d.rewrite_src == Some(E.parse::<IpAddr>().unwrap()) {
                    saw_e = true;
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(saw_e, "fixture: pool /24 must eventually mint on E");
    match iface_admit(&state, "10.0.0.2", 40000, SRV) {
        SourceNatLookup::Matched(d) => assert_ne!(d.rewrite_src_port.unwrap_or(40000), 40000, "#14367 prefix pool->iface duplicate"),
        SourceNatLookup::Unavailable(f) => assert_eq!(f.reason, SourceNatFailureReason::InterfaceIdentityExhausted),
        other => panic!("{other:?}"),
    }
}

#[test]
fn disjoint_pool_does_not_block_interface_14367() {
    let state = build_forwarding_state(&snap_iface_pool("198.51.100.7/32"));
    match iface_admit(&state, "10.0.0.2", 40000, SRV) {
        SourceNatLookup::Matched(d) => assert_eq!(d.rewrite_src_port, None, "disjoint preserve"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn interface_different_remote_translates_14367() {
    // NAT64 PAT bitmap is remote-agnostic: same (E,port) toward a different
    // remote may be PAT'd to a distinct port, but must translate (not refuse
    // as exhausted when PAT space is free).
    let state = build_forwarding_state(&snap_iface_nat64(E));
    let (_ip, pt) = nat64_mint(&state, 40000).expect("nat64");
    let l = iface_admit(&state, "10.0.0.2", pt, "9.9.9.9");
    assert!(matches!(l, SourceNatLookup::Matched(_)), "different remote must translate (PAT ok), got {l:?}");
    let _ = InterfaceNatAllocators::default();
}
