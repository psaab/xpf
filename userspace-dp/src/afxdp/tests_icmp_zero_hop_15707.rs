// #16841 (correcting #15707): `system internet-options
// no-ipv6-reject-zero-hop-limit` governs ONLY IPv6 packets addressed to
// the local host. By default (knob unset) a hop-limit-0 packet to a
// local address is dropped at local delivery; with the knob set it is
// admitted. Transit packets are still dropped with an ICMPv6 Time
// Exceeded (RFC 4443 §3.3) regardless of the knob — the #15707
// suppression of that error was the wrong contract and is removed.
//
// Split out as a sibling `#[path]` test module loaded from afxdp/mod.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::xsk_ffi::IfInfo;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    DestinationNATRuleSnapshot, FirewallFilterSnapshot, FirewallTermSnapshot,
    InterfaceAddressSnapshot, NeighborSnapshot, PolicyRuleSnapshot, RouteSnapshot,
    SourceNATRuleSnapshot, StaticNATRuleSnapshot, ThreeColorPolicerSnapshot, ZoneSnapshot,
};

fn v6_meta() -> UserspaceDpMeta {
    UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    }
}

/// The local fixture address on ifindex 5's v6 primary in
/// `icmp_suppress_forwarding` is not used here; the local-delivery
/// cells build their state from `nat_snapshot`, whose reth1.0 owns
/// 2001:559:8585:ef00::1 and reth0.80 owns 2001:559:8585:80::8.
fn local_v6() -> Ipv6Addr {
    "2001:559:8585:ef00::1".parse().unwrap()
}

fn transit_v6() -> Ipv6Addr {
    "2001:db8:1::1".parse().unwrap()
}

#[test]
fn zero_hop_limit_local_dropped_by_default_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, local_v6(), 0, TEST_LAN_MAC);
    let fwd = build_forwarding_state(&nat_snapshot());
    let dst_is_local = matches!(
        lookup_forwarding_resolution(&fwd, IpAddr::V6(local_v6()))
            .resolution
            .disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert!(dst_is_local, "fixture destination must resolve LocalDelivery");
    assert!(
        zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), dst_is_local),
        "hop-limit=0 to a local address must drop with the knob unset (Junos default)"
    );
}

#[test]
fn zero_hop_limit_local_admitted_when_no_reject_set_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, local_v6(), 0, TEST_LAN_MAC);
    let mut snapshot = nat_snapshot();
    snapshot.no_ipv6_reject_zero_hop_limit = true;
    let fwd = build_forwarding_state(&snapshot);
    assert!(
        !zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), true),
        "hop-limit=0 to a local address must be admitted with no-ipv6-reject-zero-hop-limit set"
    );
}

#[test]
fn zero_hop_limit_transit_not_local_dropped_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, transit_v6(), 0, TEST_LAN_MAC);
    let fwd = build_forwarding_state(&nat_snapshot());
    let dst_is_local = matches!(
        lookup_forwarding_resolution(&fwd, IpAddr::V6(transit_v6()))
            .resolution
            .disposition,
        ForwardingDisposition::LocalDelivery
    );
    assert!(!dst_is_local, "transit destination must not resolve LocalDelivery");
    assert!(
        !zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), dst_is_local),
        "hop-limit=0 transit must not take the local drop (it draws Time Exceeded instead)"
    );
}

#[test]
fn hop_limit_one_local_not_dropped_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, local_v6(), 1, TEST_LAN_MAC);
    let fwd = build_forwarding_state(&nat_snapshot());
    assert!(
        !zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), true),
        "hop-limit=1 to a local address is ordinary local delivery, never the zero-hop drop"
    );
}

#[test]
fn zero_hop_limit_te_sent_when_no_reject_set_16841() {
    // RED on the #15707 code: the knob suppressed this builder.
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let server: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, server, 0, TEST_LAN_MAC);
    let mut fwd = icmp_suppress_forwarding();
    fwd.no_ipv6_reject_zero_hop_limit = true;
    assert!(
        build_local_time_exceeded_v6(&frame, v6_meta(), 5, &fwd).is_some(),
        "transit hop-limit=0 must still originate ICMPv6 Time Exceeded with the knob set (RFC 4443 §3.3)"
    );
}

#[test]
fn zero_hop_limit_te_sent_when_no_reject_unset_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let server: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, server, 0, TEST_LAN_MAC);
    let fwd = icmp_suppress_forwarding();
    assert!(
        build_local_time_exceeded_v6(&frame, v6_meta(), 5, &fwd).is_some(),
        "control: hop-limit=0 without the knob still originates ICMPv6 Time Exceeded"
    );
}

#[test]
fn hop_limit_one_te_still_sent_when_no_reject_set_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let server: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, server, 1, TEST_LAN_MAC);
    let mut fwd = icmp_suppress_forwarding();
    fwd.no_ipv6_reject_zero_hop_limit = true;
    assert!(
        build_local_time_exceeded_v6(&frame, v6_meta(), 5, &fwd).is_some(),
        "hop-limit=1 expires after decrement and must still draw Time Exceeded even with the knob set"
    );
}

#[test]
fn snapshot_flag_reaches_forwarding_state_16841() {
    let mut snapshot = nat_snapshot();
    assert!(!build_forwarding_state(&snapshot).no_ipv6_reject_zero_hop_limit);
    snapshot.no_ipv6_reject_zero_hop_limit = true;
    assert!(build_forwarding_state(&snapshot).no_ipv6_reject_zero_hop_limit);
}
