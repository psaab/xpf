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
        zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), || dst_is_local),
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
        !zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), || true),
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
        !zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), || dst_is_local),
        "hop-limit=0 transit must not take the local drop (it draws Time Exceeded instead)"
    );
}

#[test]
fn hop_limit_one_local_not_dropped_16841() {
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client, local_v6(), 1, TEST_LAN_MAC);
    let fwd = build_forwarding_state(&nat_snapshot());
    assert!(
        !zero_hop_limit_local_drop(&fwd, &frame, v6_meta(), || true),
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

/// #18533: the locality verdict — a full FIB walk at the poll-loop call
/// site — is resolved only for a hop-limit-0 IPv6 packet with the knob
/// unset. IPv4, an ordinary IPv6 hop limit, and the knob-set case never
/// pay it. FAIL-ON-REVERT: evaluating `dst_is_local` before the cheap
/// conjuncts (the #16841 eager shape) counts a call on every row.
#[test]
fn zero_hop_gate_resolves_locality_only_for_ipv6_hop_limit_zero_18533() {
    let fwd = build_forwarding_state(&nat_snapshot());
    let mut knob_snapshot = nat_snapshot();
    knob_snapshot.no_ipv6_reject_zero_hop_limit = true;
    let fwd_knob = build_forwarding_state(&knob_snapshot);
    let client: Ipv6Addr = "2001:db8::102".parse().unwrap();
    let v4_frame = build_icmp_echo_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(172, 16, 80, 200),
        64,
        TEST_LAN_MAC,
    );
    let v4_meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let hop_64 = build_icmp_echo_frame_v6(client, local_v6(), 64, TEST_LAN_MAC);
    let hop_0 = build_icmp_echo_frame_v6(client, local_v6(), 0, TEST_LAN_MAC);
    let calls = std::cell::Cell::new(0u32);
    let locality = || {
        calls.set(calls.get() + 1);
        true
    };
    assert!(!zero_hop_limit_local_drop(&fwd, &v4_frame, v4_meta, locality));
    assert!(!zero_hop_limit_local_drop(&fwd, &hop_64, v6_meta(), locality));
    assert!(!zero_hop_limit_local_drop(&fwd_knob, &hop_0, v6_meta(), locality));
    assert_eq!(
        calls.get(),
        0,
        "IPv4, hop limit 64 and the knob-set case must not resolve locality"
    );
    // Transition control: the one shape the verdict can change still
    // resolves it, and drops a local destination.
    assert!(zero_hop_limit_local_drop(&fwd, &hop_0, v6_meta(), locality));
    assert_eq!(calls.get(), 1, "hop-limit-0 IPv6 must resolve locality once");
}
