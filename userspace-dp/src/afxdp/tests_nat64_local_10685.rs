//! #10685: a NAT64 destination embedding a firewall-owned IPv4 address must
//! not resolve to helper LocalDelivery. The kernel owns no synthetic NAT64
//! address, so reinjecting the original IPv6 frame would bypass the v4-keyed
//! host policy and leave the packet untranslated; LocalMiss would also mint
//! state for a packet that was not translated.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::PolicyRuleSnapshot;
use crate::test_zone_ids::*;
use std::net::{IpAddr, Ipv6Addr};

const INGRESS_IFINDEX: u32 = 24;
const CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0559, 0x8585, 0xef00, 0, 0, 0, 0x102);
const PREF64_LOCAL_V4: Ipv6Addr = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0a00, 0x3d01);
const PREF64_PUBLIC_V4: Ipv6Addr = Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808);

fn nat64_snapshot_10685() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.nat64_rules = vec![crate::protocol::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["172.16.80.50".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }];
    snapshot
}

fn run_nat64_miss_10685(
    forwarding: &ForwardingState,
    dst: Ipv6Addr,
) -> (usize, DebugPollCounters, BatchCounters) {
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, INGRESS_IFINDEX as i32, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(16);
    let frame = build_txn_tcp_syn_frame_v6(
        CLIENT,
        dst,
        54321,
        443,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let meta = txn_meta_v6(INGRESS_IFINDEX, frame.len());
    let (batch, debug) = txn_run_descriptor_checked(
        &mut binding,
        &mut sessions,
        forwarding,
        &ha_state,
        &frame,
        meta,
        true,
    );
    (sessions.len(), debug, batch)
}

#[test]
fn nat64_localdelivery_with_v4_junos_host_deny_does_not_reinject_or_mint_10685() {
    let mut snapshot = nat64_snapshot_10685();
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "deny-nat64-firewall-v4".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["10.0.61.1/32".to_string()],
        applications: vec!["any".to_string()],
        action: "deny".to_string(),
        ..Default::default()
    });
    let forwarding = build_forwarding_state(&snapshot);
    assert_eq!(
        lookup_forwarding_resolution(&forwarding, IpAddr::V4("10.0.61.1".parse().unwrap()))
            .disposition,
        ForwardingDisposition::LocalDelivery,
        "fixture must resolve the embedded IPv4 destination to the firewall"
    );

    let (sessions, debug, batch) = run_nat64_miss_10685(&forwarding, PREF64_LOCAL_V4);
    assert_eq!(
        sessions, 0,
        "#10685: NAT64-to-LocalDelivery must not mint a LocalMiss session, even when the \
         configuration has a v4-keyed junos-host deny"
    );
    assert_eq!(
        batch.session_creates, 0,
        "no local or reverse session may be installed"
    );
    assert_eq!(
        debug.local, 0,
        "#10685: untranslated NAT64 must not reach LocalDelivery reinjection \
         (local={}, policy_deny={}, host_inbound_deny={}, session_create={})",
        debug.local, debug.policy_deny, debug.host_inbound_deny, debug.session_create,
    );
}

#[test]
fn nat64_localdelivery_without_policy_does_not_mint_or_reinject_10685() {
    let forwarding = build_forwarding_state(&nat64_snapshot_10685());
    let (sessions, debug, batch) = run_nat64_miss_10685(&forwarding, PREF64_LOCAL_V4);
    assert_eq!(
        sessions, 0,
        "NAT64-to-LocalDelivery must not mint a LocalMiss session"
    );
    assert_eq!(
        batch.session_creates, 0,
        "no helper session may be installed"
    );
    assert_eq!(
        debug.local, 0,
        "NAT64-to-LocalDelivery must not reinject when no policy denies the packet"
    );
}

#[test]
fn nat64_nonlocal_ipv4_destination_still_translates_and_forwards_10685() {
    let forwarding = build_forwarding_state(&nat64_snapshot_10685());
    let (sessions, debug, batch) = run_nat64_miss_10685(&forwarding, PREF64_PUBLIC_V4);
    assert_eq!(debug.tx, 1, "ordinary NAT64 transit must still forward");
    assert_eq!(
        batch.nat64_translations, 1,
        "ordinary NAT64 transit must translate"
    );
    assert_eq!(
        sessions, 2,
        "ordinary NAT64 transit retains its forward/reverse pair"
    );
}
