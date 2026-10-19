// #15707: `system internet-options no-ipv6-reject-zero-hop-limit` must
// suppress the locally-originated ICMPv6 Time Exceeded for a packet that
// arrived with hop limit 0, while a hop-limit=1 packet (expires after the
// forwarding decrement) still draws one, and IPv4 is unaffected.
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

#[test]
fn zero_hop_limit_te_suppressed_when_no_reject_set_15707() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let server: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, server, 0, TEST_LAN_MAC);
    let mut fwd = icmp_suppress_forwarding();
    fwd.no_ipv6_reject_zero_hop_limit = true;
    assert!(
        build_local_time_exceeded_v6(&frame, v6_meta(), 5, &fwd).is_none(),
        "hop-limit=0 with no-ipv6-reject-zero-hop-limit must not originate ICMPv6 Time Exceeded"
    );
}

#[test]
fn zero_hop_limit_te_sent_when_no_reject_unset_15707() {
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
fn hop_limit_one_te_still_sent_when_no_reject_set_15707() {
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
fn snapshot_flag_reaches_forwarding_state_15707() {
    let mut snapshot = nat_snapshot();
    assert!(!build_forwarding_state(&snapshot).no_ipv6_reject_zero_hop_limit);
    snapshot.no_ipv6_reject_zero_hop_limit = true;
    assert!(build_forwarding_state(&snapshot).no_ipv6_reject_zero_hop_limit);
}
