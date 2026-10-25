//! #16619: the poll-path inbound-hold gate must take the hold for an
//! inbound persistent session whose composed decision also carries a
//! source rewrite (inbound SNAT of the remote).
//!
//! These tests drive `acquire_persistent_inbound_hold` directly — the
//! exact function the poll loop calls at every anchoring install site —
//! with a `ForwardingState` carrying a real persistent pool rule whose
//! lease was minted outbound by the internal host and then released to
//! idle. Pre-fix the gate returned `false` whenever
//! `rewrite_src.is_some()`, so `acquire_took_hold` was false and the
//! binding expired under the live inbound session (the #15111 defect
//! surviving through its own exemption).

use super::*;
use crate::nat::PersistentNatPermit;

/// Build a forwarding state with one persistent pool rule and mint the
/// internal host's lease (10.0.1.100:12345 -> 203.0.113.10), releasing
/// the outbound flow so the lease is idle. Returns (forwarding, lease_key).
fn forwarding_with_idle_persistent_lease_16619() -> (ForwardingState, crate::nat::PersistentSourceKey) {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
            name: "persistent-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "persistent-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40010,
            persistent_nat: true,
            persistent_nat_permit_any_remote_host: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 1,
            ..crate::SourceNATRuleSnapshot::default()
        }]);
    // Mint X's lease outbound at t=1s, then release it to idle.
    let mut counter = None;
    let minted = match crate::nat::match_source_nat_result_for_tuple(
        &crate::nat::InterfaceNatAllocators::default(),
        &forwarding.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        Some(6),
        12345,
        53,
        None,
        None,
        1_000_000_000,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut counter,
    ) {
        crate::nat::SourceNatLookup::Matched(d) => d,
        other => panic!("fixture: outbound mint must match, got {other:?}"),
    };
    let outbound_key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.1.100".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 12345,
        dst_port: 53,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    crate::nat::release_source_nat_allocation_for_worker(
        &crate::nat::InterfaceNatAllocators::default(),
        &forwarding.source_nat_rules,
        &outbound_key,
        minted,
        false,
        1_000_000_001,
        0,
    );
    let lease_key = crate::nat::PersistentSourceKey {
        protocol: 6,
        src_ip: "10.0.1.100".parse().unwrap(),
        src_port: 12345,
        routing_scope: 0,
        remote: None,
    };
    (forwarding, lease_key)
}

fn inbound_flows_16619(forwarding: &ForwardingState) -> Option<u32> {
    forwarding.source_nat_rules[0]
        .pool_allocator
        .debug_persistent_lease_for_flow(
            &crate::nat::SourceNatFlowKey {
                protocol: 6,
                src_ip: "10.0.1.100".parse().unwrap(),
                dst_ip: "8.8.8.8".parse().unwrap(),
                src_port: 12345,
                dst_port: 53,
                routing_scope: 0,
            },
            PersistentNatPermit::AnyRemoteHost,
        )
        .map(|l| l.inbound_flows)
}

/// #16619 acceptance arm: composed decision = persistent DNAT
/// (rewrite_dst=X) + inbound SNAT of the remote (rewrite_src set).
/// `acquire_took_hold` must be true and the lease must carry the hold.
#[test]
fn acquire_persistent_inbound_hold_with_snat_takes_hold_16619() {
    let (forwarding, lease_key) = forwarding_with_idle_persistent_lease_16619();
    assert_eq!(inbound_flows_16619(&forwarding), Some(0), "fixture: idle lease, no hold");

    let composed = crate::nat::NatDecision {
        rewrite_src: Some("198.51.100.1".parse().unwrap()),
        rewrite_src_port: Some(50000),
        rewrite_dst: Some("10.0.1.100".parse().unwrap()),
        rewrite_dst_port: Some(12345),
        ..crate::nat::NatDecision::default()
    };
    let took = acquire_persistent_inbound_hold(&forwarding, Some(lease_key), composed, 1_500_000_000);
    assert!(
        took,
        "#16619: acquire_took_hold must be true for an inbound persistent session that is also source-NATed"
    );
    assert_eq!(
        inbound_flows_16619(&forwarding),
        Some(1),
        "#16619: the internal host's lease must carry the inbound hold"
    );

    // DNAT-only control still takes the hold (unchanged #15111 behavior).
    let (forwarding2, lease_key2) = forwarding_with_idle_persistent_lease_16619();
    let dnat_only = crate::nat::NatDecision {
        rewrite_dst: Some("10.0.1.100".parse().unwrap()),
        rewrite_dst_port: Some(12345),
        ..crate::nat::NatDecision::default()
    };
    assert!(
        acquire_persistent_inbound_hold(&forwarding2, Some(lease_key2), dnat_only, 1_500_000_000),
        "#15111 control: DNAT-only inbound must still take the hold"
    );
    assert_eq!(inbound_flows_16619(&forwarding2), Some(1));
}

/// #16619: NAT64/NPTv6 exemptions are unchanged, and a decision that no
/// longer carries the persistent `rewrite_dst` (or no stored key) takes
/// no hold.
#[test]
fn acquire_persistent_inbound_hold_exemptions_unchanged_16619() {
    let (forwarding, lease_key) = forwarding_with_idle_persistent_lease_16619();
    let base = crate::nat::NatDecision {
        rewrite_src: Some("198.51.100.1".parse().unwrap()),
        rewrite_dst: Some("10.0.1.100".parse().unwrap()),
        rewrite_dst_port: Some(12345),
        ..crate::nat::NatDecision::default()
    };
    assert!(
        !acquire_persistent_inbound_hold(
            &forwarding,
            Some(lease_key),
            crate::nat::NatDecision { nat64: true, ..base },
            1_500_000_000
        ),
        "NAT64 exemption must stay exempt"
    );
    assert!(
        !acquire_persistent_inbound_hold(
            &forwarding,
            Some(lease_key),
            crate::nat::NatDecision { nptv6: true, ..base },
            1_500_000_000
        ),
        "NPTv6 exemption must stay exempt"
    );
    assert!(
        !acquire_persistent_inbound_hold(
            &forwarding,
            Some(lease_key),
            crate::nat::NatDecision {
                rewrite_dst: None,
                rewrite_dst_port: None,
                ..base
            },
            1_500_000_000
        ),
        "no rewrite_dst => no persistent lease to hold"
    );
    assert!(
        !acquire_persistent_inbound_hold(&forwarding, None, base, 1_500_000_000),
        "no stored lease key => no hold"
    );
    assert_eq!(
        inbound_flows_16619(&forwarding),
        Some(0),
        "exempt/refused acquires must not touch the lease"
    );
}
