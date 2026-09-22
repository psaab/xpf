// ICMP-error classification, TTL-expiry, and locally-generated time-exceeded.
//
// Split out of afxdp/tests.rs (#4840) as a sibling `#[path]` test module
// loaded from afxdp/mod.rs. Pure code motion: every #[test] fn is moved
// verbatim; shared test-support helpers live in afxdp/tests_support.rs.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::worker::WorkerTxPipeline;
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
use super::tests_support::*;

#[test]
fn is_icmp_error_identifies_v4_types() {
    // ICMPv4 error types that quote the offending datagram (RFC 792).
    assert!(is_icmp_error(PROTO_ICMP, 3)); // Destination Unreachable
    // #2393: Source Quench (4) and Redirect (5) also quote an inner IP
    // header + 8 bytes at l4+8 and must have their embedded inner
    // translated on NAT44 transit, matching the reject/netfilter set.
    assert!(is_icmp_error(PROTO_ICMP, 4)); // Source Quench (deprecated, RFC 6633)
    assert!(is_icmp_error(PROTO_ICMP, 5)); // Redirect
    assert!(is_icmp_error(PROTO_ICMP, 11)); // Time Exceeded
    assert!(is_icmp_error(PROTO_ICMP, 12)); // Parameter Problem
    // Non-error (query) types
    assert!(!is_icmp_error(PROTO_ICMP, 0)); // Echo Reply
    assert!(!is_icmp_error(PROTO_ICMP, 8)); // Echo Request
    assert!(!is_icmp_error(PROTO_ICMP, 13)); // Timestamp Request
}


#[test]
fn is_icmp_error_identifies_v6_types() {
    // ICMPv6 error types
    assert!(is_icmp_error(PROTO_ICMPV6, 1)); // Destination Unreachable
    assert!(is_icmp_error(PROTO_ICMPV6, 2)); // Packet Too Big
    assert!(is_icmp_error(PROTO_ICMPV6, 3)); // Time Exceeded
    assert!(is_icmp_error(PROTO_ICMPV6, 4)); // Parameter Problem
    // Non-error types
    assert!(!is_icmp_error(PROTO_ICMPV6, 128)); // Echo Request
    assert!(!is_icmp_error(PROTO_ICMPV6, 129)); // Echo Reply
}


#[test]
fn is_icmp_error_rejects_non_icmp_protocols() {
    assert!(!is_icmp_error(PROTO_TCP, 3));
    assert!(!is_icmp_error(PROTO_UDP, 3));
}


#[test]
fn forwarding_state_includes_session_timeouts() {
    let snapshot = nat_snapshot();
    let state = build_forwarding_state(&snapshot);
    // Default timeouts when snapshot has 0 values
    assert_eq!(state.session_timeouts.tcp_established_ns, 300_000_000_000);
    assert_eq!(state.session_timeouts.udp_ns, 60_000_000_000);
    assert_eq!(state.session_timeouts.icmp_ns, 60_000_000_000);
}


#[test]
fn forwarding_state_custom_session_timeouts() {
    let mut snapshot = nat_snapshot();
    snapshot.flow.tcp_session_timeout = 120;
    snapshot.flow.udp_session_timeout = 30;
    snapshot.flow.icmp_session_timeout = 5;
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.session_timeouts.tcp_established_ns, 120_000_000_000);
    assert_eq!(state.session_timeouts.udp_ns, 30_000_000_000);
    assert_eq!(state.session_timeouts.icmp_ns, 5_000_000_000);
}


#[test]
fn forwarding_state_allow_embedded_icmp_wired() {
    let mut snapshot = nat_snapshot();
    assert!(!build_forwarding_state(&snapshot).allow_embedded_icmp);
    snapshot.flow.allow_embedded_icmp = true;
    assert!(build_forwarding_state(&snapshot).allow_embedded_icmp);
}


#[test]
fn packet_ttl_would_expire_identifies_v4_and_v6() {
    let frame_v4 = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 1, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta_v4 = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(packet_ttl_would_expire(&frame_v4, meta_v4), Some(true));

    let frame_v6 = build_icmp_echo_frame_v6(
        "2001:559:8585:ef00::102".parse().unwrap(),
        "2606:4700:4700::1111".parse().unwrap(),
        2,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let meta_v6 = UserspaceDpMeta {
        l3_offset: 14,
        addr_family: libc::AF_INET6 as u8,
        ..UserspaceDpMeta::default()
    };
    assert_eq!(packet_ttl_would_expire(&frame_v6, meta_v6), Some(false));
}


#[test]
fn build_local_time_exceeded_request_returns_prebuilt_forward_for_ttl_expiry() {
    // #5567: this emission test depends on a non-empty TimeExceeded bucket;
    // serialise with the drainer tests over the shared global bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 1,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    )
    .expect("ttl-expiring session/flow-cache hit should enqueue local TE");

    assert_eq!(request.target_ifindex, 5);
    assert_eq!(request.ingress_queue_id, ingress_ident.queue_id);
    assert_eq!(request.desc.addr, desc.addr);
    assert_eq!(request.flow_key.as_ref(), Some(&flow.forward_key));
    assert!(request.cos_tx_selection_resolved);
    assert!(matches!(request.frame, PendingForwardFrame::Prebuilt(_)));
}


/// #2238: the generated ICMP Time Exceeded is classified by its OWN egress
/// tuple, so an OUTPUT firewall filter + three-color policer on the egress
/// interface (matching `protocol icmp`) drops it — and the drop lands on the
/// dedicated `time_exceeded_output_filter_drops` counter, not the trigger's
/// ingress input policer. Pre-#2238 the trigger's tuple was used, so an
/// *input* policer on the ingress interface keyed off the TCP/UDP trigger;
/// that is exactly the bug this fixes (the reply's own egress treatment was
/// never consulted).
#[test]
fn build_local_time_exceeded_request_classifies_generated_icmp_on_egress() {
    // #5567 needed a non-empty bucket here because the token was consumed
    // BEFORE the output-filter classify. #7174 M04 reversed that — the token is
    // consumed last, only for a reply that will actually be sent — so this test
    // no longer depends on bucket state. The lock stays because the fallback
    // bucket is a shared static and these tests must not race.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    // The TRIGGER is a UDP flow (proto 17) — proving the egress filter keys
    // off the GENERATED ICMP reply, not the UDP trigger.
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 128,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = icmp_suppress_flow_v4(client_ip, dst_ip);
    // OUTPUT filter on the egress interface (ifindex 5) with a terminal
    // `discard` for `protocol icmp`. The term only fires for the GENERATED
    // ICMP reply (the trigger is UDP), proving classify-by-generated-tuple.
    let filter_state = build_output_filter_state(
        "drop-icmp-out",
        FirewallTermSnapshot {
            name: "drop-icmp".into(),
            action: "discard".into(),
            protocols: vec!["icmp".into()],
            ..Default::default()
        },
    );
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    // #7174 M04: give this zone its OWN bucket so the token observation below is
    // isolated from the shared static fallback (and from every other test).
    // Key the bucket on the zone the code will ACTUALLY resolve. `from_zone_id`
    // comes from `forwarding.ifindex_to_zone_id[ingress_ident.ifindex]`, so
    // binding it here is what makes the bucket reachable — inserting under a
    // zone the lookup never produces leaves the code on the shared static
    // fallback and both assertions below pass vacuously. The control cell caught
    // exactly that on its first run.
    forwarding.ifindex_to_zone_id.insert(5, TEST_LAN_ZONE_ID);
    let te_bucket = std::sync::Arc::new(crate::afxdp::icmp_ratelimit::ZoneLimiter::new());
    forwarding
        .time_exceeded_buckets
        .insert(TEST_LAN_ZONE_ID, te_bucket.clone());
    let arrival_before = te_bucket.aggregate_arrival_ns();

    let mut counters = BatchCounters::default();
    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );

    assert!(
        request.is_none(),
        "egress output-filter `then discard` (protocol icmp) must reject the generated ICMP reply"
    );
    // #7174 M04: and it must not have COST anything. The budget bounds what this
    // box emits; a reply the filter discards emits nothing, so charging for it
    // lets a filtered stream starve the errors that would have gone out — and
    // does it invisibly, because the drop is attributed to the filter counter
    // while the missing errors are attributed to the limiter.
    assert_eq!(
        te_bucket.aggregate_arrival_ns(),
        arrival_before,
        "a filter-DROPPED ICMP Time Exceeded must not spend a rate-limit token \
         (#7174 M04); the bucket state moved, so it did"
    );
    assert_eq!(
        counters.time_exceeded_output_filter_drops, 1,
        "the output-filter drop must land on the dedicated TE counter"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}


/// #2238: an output filter matching the INBOUND UDP trigger tuple does NOT
/// drop the generated ICMP error — the discriminating test proving the reply
/// is classified by its OWN (ICMP) tuple, not the trigger's (UDP).
#[test]
fn build_local_time_exceeded_request_ignores_trigger_matching_output_filter() {
    // #5567: asserts the reply IS built (Some) — needs a non-empty bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client_ip, dst_ip, 1);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 128,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let flow = icmp_suppress_flow_v4(client_ip, dst_ip);
    // Output filter discards UDP — but the generated reply is ICMP, so it
    // must NOT be dropped.
    let filter_state = build_output_filter_state(
        "drop-udp-out",
        FirewallTermSnapshot {
            name: "drop-udp".into(),
            action: "discard".into(),
            protocols: vec!["udp".into()],
            ..Default::default()
        },
    );
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    // #7174 M04 CONTROL. The sibling drop-path cell asserts a filtered reply
    // spends NO token; that assertion is only meaningful if a reply which IS
    // sent DOES spend one. Without this, "the bucket did not move" would be
    // satisfied by a bucket nothing ever consults.
    // Key the bucket on the zone the code will ACTUALLY resolve. `from_zone_id`
    // comes from `forwarding.ifindex_to_zone_id[ingress_ident.ifindex]`, so
    // binding it here is what makes the bucket reachable — inserting under a
    // zone the lookup never produces leaves the code on the shared static
    // fallback and both assertions below pass vacuously. The control cell caught
    // exactly that on its first run.
    forwarding.ifindex_to_zone_id.insert(5, TEST_LAN_ZONE_ID);
    let te_bucket = std::sync::Arc::new(crate::afxdp::icmp_ratelimit::ZoneLimiter::new());
    forwarding
        .time_exceeded_buckets
        .insert(TEST_LAN_ZONE_ID, te_bucket.clone());
    let arrival_before = te_bucket.aggregate_arrival_ns();

    let mut counters = BatchCounters::default();
    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );

    assert_ne!(
        te_bucket.aggregate_arrival_ns(),
        arrival_before,
        "a reply that IS sent must spend a rate-limit token — otherwise the \
         drop-path cell's 'no token spent' assertion proves nothing (#7174 M04)"
    );
    assert!(
        request.is_some(),
        "an output filter matching the UDP trigger must NOT drop the generated ICMP reply"
    );
    assert_eq!(counters.time_exceeded_output_filter_drops, 0);
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}


/// #3026 LITERAL fail-on-revert. Drives the real
/// #6102 fail-on-revert (production-reachable rebuild of the vacuous #3026
/// test): `build_local_time_exceeded_request` on a real VLAN sub-interface.
/// The ingress AF_XDP binding is the PHYSICAL parent port (ifindex 11) — the
/// value `ingress_ident.ifindex` genuinely holds in production (#6046) — while
/// the tagged unit reth0.80 is the LOGICAL unit (ifindex 12) that keys
/// `forwarding.egress` and the output filter. The daemon's
/// `ingress_logical_ifindex` map resolves `(physical 11, vlan 80) -> logical
/// 12`. The unit (12) carries an output `then discard protocol icmp` filter;
/// the physical parent (11) carries NONE and has NO egress entry.
///
/// The fix resolves the logical unit ONCE (`resolve_ingress_logical_ifindex`)
/// and feeds it to the egress lookup, the reply builders, and
/// `classify_generated_reply`. The double assertion catches every partial and
/// full revert to the physical `ingress_ident.ifindex`:
///   - revert the CLASSIFY only  -> build on 12 (Some), classify on physical 11
///     (no filter) -> reply ADMITTED -> `request.is_none()` FAILS RED.
///   - revert the EGRESS LOOKUP or a BUILDER only -> `egress.get(11)` = None ->
///     builder `?`-drops -> `request` is None but the drop is a BUILD-fail, not
///     a filter drop -> `time_exceeded_output_filter_drops == 0` FAILS RED.
///   - full revert to physical -> same build-fail drop -> counter 0 FAILS RED.
/// The counter assertion is what distinguishes a filter drop (fix working) from
/// a build-fail drop (a reverted egress/builder), so `is_none()` alone can
/// never pass vacuously.
#[test]
fn build_local_time_exceeded_request_resolves_logical_ingress_for_classify_6102() {
    // #5567 needed a non-empty bucket here because the token was consumed
    // BEFORE the output-filter classify. #7174 M04 reversed that — the token is
    // consumed last, only for a reply that will actually be sent — so this test
    // no longer depends on bucket state. The lock stays because the fallback
    // bucket is a shared static and these tests must not race.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    // TRIGGER is a UDP flow; the generated reply is ICMP (proven elsewhere).
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client_ip, dst_ip, 1);
    // PHYSICAL ingress bind port 11, tagged VLAN 80 — exactly what the shim
    // reports for a frame arriving on reth0.80 (`ingress_vlan_id` = 80).
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 11,
        ingress_vlan_id: 80,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        pkt_len: 128,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    // The AF_XDP binding is the PHYSICAL parent (ifindex 11) — the fixed
    // per-binding socket-bind port. The logical unit (12) is NOT this value;
    // the fix must resolve it from `(11, 80)` before keying egress/classify.
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("reth0"),
        ifindex: 11,
    };
    let flow = icmp_suppress_flow_v4(client_ip, dst_ip);
    // OUTPUT filter on the LOGICAL VLAN unit (ifindex 12) with a terminal
    // `discard` for `protocol icmp`. The PHYSICAL parent (ifindex 11) is given
    // NO output filter — so a physical-keyed classification would miss it.
    let filter_state = crate::filter::parse_filter_state(
        &[FirewallFilterSnapshot {
            name: "drop-icmp-out".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-icmp".into(),
                action: "discard".into(),
                protocols: vec!["icmp".into()],
                ..Default::default()
            }],
        }],
        &[],
        &[crate::InterfaceSnapshot {
            name: "reth0.80".into(),
            ifindex: 12,
            parent_ifindex: 11,
            vlan_id: 80,
            filter_output_v4: "drop-icmp-out".into(),
            ..Default::default()
        }],
        "",
        "",
    )
    .expect("filter state compiles");
    let mut forwarding = ForwardingState {
        filter_state,
        tx_selection_enabled_v4: true,
        ..ForwardingState::default()
    };
    // Egress keyed by the LOGICAL ifindex 12 ONLY; bind_ifindex 11 is the
    // physical parent (= target_ifindex, the XSK transmit device). There is NO
    // egress entry for the physical parent 11, so a physical-keyed egress
    // lookup (a reverted fix) misses and the builder `?`-drops.
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 80,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: TEST_WAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
            primary_v6: None,
        },
    );
    // The daemon-built `(physical bind, vlan) -> logical unit` map
    // (interfaces.rs:291-301). This is the SSOT the fix resolves through.
    forwarding.ingress_logical_ifindex.insert((11, 80), 12);

    let mut counters = BatchCounters::default();
    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );

    assert!(
        request.is_none(),
        "the VLAN unit's OWN output filter (on logical ifindex 12) must drop \
         the generated ICMP reply (#6102); classifying on the physical parent \
         (ingress_ident.ifindex 11, no filter) would wrongly admit it"
    );
    assert_eq!(
        counters.time_exceeded_output_filter_drops, 1,
        "the logical-egress output-filter drop must land on the TE counter — a \
         value of 0 means the egress lookup/builder was keyed on the physical \
         parent 11 (no egress entry) and the reply was BUILD-dropped, not \
         filter-dropped (a reverted #6102 fix)"
    );
    assert_eq!(counters.generated_reply_classify_parse_errors, 0);
}


#[test]
fn build_local_time_exceeded_request_skips_fabric_ingress_packets() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1, crate::afxdp::tests_support::TEST_FABRIC_MAC);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        meta_flags: FABRIC_INGRESS_FLAG,
        ..UserspaceDpMeta::default()
    };
    let desc = XdpDesc {
        addr: 8192,
        len: frame.len() as u32,
        options: 0,
    };
    let ingress_ident = BindingIdentity {
        slot: 0,
        queue_id: 7,
        worker_id: 0,
        interface: Arc::<str>::from("fab0"),
        ifindex: 5,
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(client_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port: 0x1234,
            dst_port: 1,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_FABRIC_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );

    let request = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &ingress_ident,
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    );

    assert!(
        request.is_none(),
        "fabric-ingress packets should not enqueue local Time Exceeded"
    );
}


#[test]
fn build_local_time_exceeded_v4_quotes_original_packet() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 1, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let out =
        build_local_time_exceeded_v4(&frame, meta, 5, &forwarding).expect("build local IPv4 TE");
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(
        Ipv4Addr::new(out[26], out[27], out[28], out[29]),
        Ipv4Addr::new(10, 0, 61, 1)
    );
    assert_eq!(Ipv4Addr::new(out[30], out[31], out[32], out[33]), client_ip);
    assert_eq!(out[34], 11);
    assert_eq!(out[35], 0);
    let quoted_ip_start = 42;
    assert_eq!(
        Ipv4Addr::new(
            out[quoted_ip_start + 12],
            out[quoted_ip_start + 13],
            out[quoted_ip_start + 14],
            out[quoted_ip_start + 15]
        ),
        client_ip
    );
    assert_eq!(
        Ipv4Addr::new(
            out[quoted_ip_start + 16],
            out[quoted_ip_start + 17],
            out[quoted_ip_start + 18],
            out[quoted_ip_start + 19]
        ),
        dst_ip
    );
    assert_eq!(out[quoted_ip_start + 8], 1);
}


#[test]
fn build_local_time_exceeded_v6_quotes_original_packet() {
    let client_ip: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let dst_ip: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(client_ip, dst_ip, 1, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    let mut forwarding = ForwardingState::default();
    forwarding.egress.insert(
        5,
        EgressInterface {
            bind_ifindex: 5,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: None,
            primary_v6: Some("2001:559:8585:ef00::1".parse().unwrap()),
        },
    );
    let out =
        build_local_time_exceeded_v6(&frame, meta, 5, &forwarding).expect("build local IPv6 TE");
    assert_eq!(&out[0..6], &[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x86dd);
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[22..38]).unwrap()),
        "2001:559:8585:ef00::1".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&out[38..54]).unwrap()),
        client_ip
    );
    assert_eq!(out[54], 3);
    assert_eq!(out[55], 0);
    let quoted_ip_start = 62;
    assert_eq!(
        Ipv6Addr::from(
            <[u8; 16]>::try_from(&out[quoted_ip_start + 8..quoted_ip_start + 24]).unwrap()
        ),
        client_ip
    );
    assert_eq!(
        Ipv6Addr::from(
            <[u8; 16]>::try_from(&out[quoted_ip_start + 24..quoted_ip_start + 40]).unwrap()
        ),
        dst_ip
    );
    assert_eq!(out[quoted_ip_start + 7], 1);
}

// --- #2237 ICMP error-generation suppression gate tests ---


/// The emission case: a normal unicast UDP packet with TTL 1 DOES draw a
/// locally generated Time Exceeded (the suppression gate must NOT fire).
#[test]
fn time_exceeded_emitted_for_unicast_udp() {
    // #5567: asserts the reply IS built (Some) — needs a non-empty bucket.
    let _g = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    let meta = ttl_meta_v4();
    let fwd = icmp_suppress_forwarding();
    assert!(can_generate_icmp_error_reply(&frame, meta, &fwd));
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let req = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &icmp_suppress_flow_v4(client, server),
        &fwd,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    );
    assert!(
        req.is_some(),
        "unicast UDP with TTL 1 must draw a Time Exceeded"
    );
}


/// The emission case for TCP — confirms the gate is protocol-agnostic for
/// non-ICMP transports.
#[test]
fn time_exceeded_emitted_for_unicast_tcp() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame =
        build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    // Flip the IP protocol byte (l3 + 9 = byte 23) to TCP and recompute
    // the IPv4 header checksum.
    frame[23] = PROTO_TCP;
    frame[24..26].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&csum.to_be_bytes());
    let mut meta = ttl_meta_v4();
    meta.protocol = PROTO_TCP;
    assert!(
        can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "unicast TCP TTL 1 must be allowed"
    );
}


/// Suppression (a): a low-TTL inbound ICMPv4 *error* (type 11) must NOT
/// draw a fresh Time Exceeded — classic error loop / amplification.
#[test]
fn time_exceeded_suppressed_for_inbound_icmp_error_v4() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame =
        build_icmp_echo_frame_v4(client, server, 1, crate::afxdp::tests_support::TEST_DMZ_MAC);
    frame[34] = 11; // ICMP type Time Exceeded (an error)
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 34,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let fwd = icmp_suppress_forwarding();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to an inbound ICMP error"
    );
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    let req = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &icmp_suppress_flow_v4(client, server),
        &fwd,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut BatchCounters::default(),
    );
    assert!(req.is_none(), "no Time Exceeded for an inbound ICMP error");
    // An echo *request* (a query, type 8) is NOT suppressed.
    let mut echo =
        build_icmp_echo_frame_v4(client, server, 1, crate::afxdp::tests_support::TEST_DMZ_MAC);
    echo[34] = 8;
    assert!(
        can_generate_icmp_error_reply(&echo, meta, &ForwardingState::default()),
        "inbound ICMP echo request (query) must still draw an error"
    );
}


/// Suppression (a) for ICMPv6: any inbound ICMPv6 error (type < 128).
#[test]
fn time_exceeded_suppressed_for_inbound_icmp_error_v6() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut frame =
        build_icmp_echo_frame_v6(client, server, 1, crate::afxdp::tests_support::TEST_DMZ_MAC);
    frame[54] = 3; // ICMPv6 Time Exceeded (error, < 128)
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to an inbound ICMPv6 error"
    );
    // ICMPv6 echo request (type 128, a query) is NOT suppressed.
    let echo =
        build_icmp_echo_frame_v6(client, server, 1, crate::afxdp::tests_support::TEST_DMZ_MAC); // type 128
    assert!(
        can_generate_icmp_error_reply(&echo, meta, &ForwardingState::default()),
        "inbound ICMPv6 echo request must still draw an error"
    );
}


/// Suppression (b): a non-first IPv4 fragment (TTL 1) must NOT draw a
/// Time Exceeded — it carries no transport header.
#[test]
fn time_exceeded_suppressed_for_non_first_fragment_v4() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let mut frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    // Set a non-zero fragment offset (frag_off field at l3 + 6..8 = bytes
    // 20..22). Offset 0x0001 => non-first fragment.
    frame[20..22].copy_from_slice(&0x0001u16.to_be_bytes());
    frame[24..26].copy_from_slice(&[0, 0]);
    let csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&csum.to_be_bytes());
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to a non-first IPv4 fragment"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a non-first IPv4 fragment"
    );
}


/// Suppression (b) for IPv6: a non-first fragment behind a fragment
/// extension header must NOT draw a Time Exceeded.
#[test]
fn time_exceeded_suppressed_for_non_first_fragment_v6() {
    let client: Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
    let server: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x00, 0x25, 0x90, 0x12, 0x34, 0x56]); // dst mac
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&[0x86, 0xdd]);
    // IPv6 base header, next-header = 44 (Fragment), hop_limit 1.
    frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00, 0x00, 0x10, 44, 1]);
    frame.extend_from_slice(&client.octets());
    frame.extend_from_slice(&server.octets());
    // Fragment header (8 bytes): next-header UDP, reserved, frag-offset
    // 0x0008 (non-first: offset bits non-zero), then id.
    frame.extend_from_slice(&[PROTO_UDP, 0, 0x00, 0x08, 0xDE, 0xAD, 0xBE, 0xEF]);
    // 8 bytes of "payload" where the UDP header would be on the first frag.
    frame.extend_from_slice(&[0; 8]);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 0,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to a non-first IPv6 fragment"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a non-first IPv6 fragment"
    );
}


/// Suppression (c): an IPv4 multicast destination must NOT draw a reply.
#[test]
fn time_exceeded_suppressed_for_multicast_dest_v4() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let mcast = Ipv4Addr::new(224, 0, 0, 251); // mDNS group
    let frame = build_udp_frame_v4_full([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb], client, mcast, 1);
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to a multicast destination"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a multicast destination"
    );
}


/// Suppression (c): an L2 broadcast destination MAC must NOT draw a reply
/// even if the L3 destination looks unicast.
#[test]
fn time_exceeded_suppressed_for_l2_broadcast_dest() {
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(10, 0, 61, 1);
    let frame = build_udp_frame_v4_full([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], client, server, 1);
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to an L2 broadcast frame"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress an L2 broadcast frame"
    );
}


/// Suppression (d): a bogus IPv4 source (loopback) must NOT draw a reply.
#[test]
fn time_exceeded_suppressed_for_bad_source_v4() {
    let bad_src = Ipv4Addr::new(127, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 61, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], bad_src, server, 1);
    let meta = ttl_meta_v4();
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to a loopback source"
    );
    // Unspecified 0.0.0.0 source is also suppressed.
    let zero_src =
        build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], Ipv4Addr::UNSPECIFIED, server, 1);
    assert!(
        !can_generate_icmp_error_reply(&zero_src, meta, &ForwardingState::default()),
        "gate must suppress reply to a 0.0.0.0 source"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a loopback source"
    );
}


/// Suppression (d) for IPv6: a multicast source must NOT draw a reply.
#[test]
fn time_exceeded_suppressed_for_bad_source_v6() {
    let bad_src: Ipv6Addr = "ff02::1".parse().unwrap(); // multicast
    let server: Ipv6Addr = "2001:559:8585:ef00::1".parse().unwrap();
    let frame = build_icmp_echo_frame_v6(bad_src, server, 1, crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta = UserspaceDpMeta {
        l3_offset: 14,
        l4_offset: 54,
        ingress_ifindex: 5,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };
    assert!(
        !can_generate_icmp_error_reply(&frame, meta, &ForwardingState::default()),
        "gate must suppress reply to a multicast IPv6 source"
    );
    assert!(
        !te_request_built(&frame, meta),
        "TE call site must suppress a multicast IPv6 source"
    );
}


// --- #5567 token-after-feasibility tests ---

/// #5567 HEADLINE fail-on-revert: a flood of reply-ELIGIBLE-but-UNBUILDABLE
/// Time Exceeded triggers (a valid TTL=1 unicast frame whose ingress ifindex
/// has NO egress object, so the reply cannot be built) must NOT consume a
/// TimeExceeded rate-limit token. Pre-#5567 the token was spent BEFORE the
/// egress lookup + build, so each unbuildable attempt drained the shared
/// per-reason bucket — starving a buildable PMTUD/traceroute reply on ANOTHER
/// interface (the cross-interface false-deny DoS).
///
/// Proof shape (mirrors the reject path's #3656 H11
/// `unreplyable_reject_does_not_drain_bucket`): pin the TimeExceeded bucket
/// EMPTY at a far-future epoch so the call site's smaller real
/// `monotonic_nanos()` yields zero refill and the bucket stays empty across
/// the calls, then drive N unbuildable attempts. On the fixed code the build
/// returns None BEFORE `allow_generated_error`, so the empty bucket is never
/// touched and its rate-limited counter does not move. On a revert (token
/// before feasibility) each attempt denies against the empty bucket and bumps
/// the counter → RED. Each attempt also returns None (drop) — the trigger
/// disposition is unchanged.
#[test]
fn te_unbuildable_missing_egress_does_not_drain_token_5567() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, far_future);
    while allow_generated_error_at(GeneratedErrorReason::TimeExceeded, far_future, 1000, 1000) {}
    let before = rate_limited_count(GeneratedErrorReason::TimeExceeded);

    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    let meta = ttl_meta_v4();
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    // `ForwardingState::default()` has NO egress for the ingress ifindex (5),
    // so the v4 builder returns None: the reply is reply-eligible (it passes
    // the RFC suppression gate + the TTL check) but UNBUILDABLE.
    let forwarding = ForwardingState::default();
    let flow = icmp_suppress_flow_v4(client, server);
    for _ in 0..16 {
        let mut counters = BatchCounters::default();
        let req = build_local_time_exceeded_request(
            &frame,
            desc,
            meta,
            &icmp_suppress_ident(),
            &flow,
            &forwarding,
            &Arc::new(ShardedNeighborMap::new()),
            &BTreeMap::new(),
            0,
            &mut counters,
        );
        assert!(
            req.is_none(),
            "an unbuildable TE (no egress for the ingress ifindex) must drop the trigger"
        );
    }
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::TimeExceeded),
        before,
        "unbuildable TE attempts must NOT touch the shared TimeExceeded token \
         bucket (pre-#5567 they drained it and starved buildable replies)"
    );
    // Restore a full bucket so sibling emission tests are unaffected.
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, 0);
}


/// #5567: a BUILDABLE Time Exceeded is still rate-limited when the token is
/// exhausted (rate-limiting preserved), and a normal buildable reply under a
/// full bucket is emitted while consuming a token (the rate-limited counter
/// does not move on success). Together with
/// `te_unbuildable_missing_egress_does_not_drain_token_5567` this pins the
/// full disposition matrix: unbuildable → drop (no token), buildable+deny →
/// drop (token consumed), buildable+allow → reply (token consumed).
#[test]
fn te_buildable_respects_and_consumes_token_5567() {
    use crate::afxdp::icmp_ratelimit::{
        GeneratedErrorReason, allow_generated_error_at, global_bucket_test_lock,
        rate_limited_count, reset_bucket_for_test,
    };
    let _g = global_bucket_test_lock();
    let client = Ipv4Addr::new(10, 0, 61, 102);
    let server = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_udp_frame_v4_full([0x00, 0x25, 0x90, 0x12, 0x34, 0x56], client, server, 1);
    let meta = ttl_meta_v4();
    let desc = XdpDesc {
        addr: 4096,
        len: frame.len() as u32,
        options: 0,
    };
    // Egress present for the ingress ifindex (5) → the reply is buildable.
    let forwarding = icmp_suppress_forwarding();
    let flow = icmp_suppress_flow_v4(client, server);

    // (1) Exhausted bucket: a BUILDABLE reply is suppressed (rate-limited), the
    // trigger is dropped, and the observable rate-limited counter advances.
    let far_future = u64::MAX / 2;
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, far_future);
    while allow_generated_error_at(GeneratedErrorReason::TimeExceeded, far_future, 1000, 1000) {}
    let before_rl = rate_limited_count(GeneratedErrorReason::TimeExceeded);
    let mut counters = BatchCounters::default();
    let req = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );
    assert!(
        req.is_none(),
        "a buildable TE must still be suppressed when the token is exhausted (rate-limiting preserved)"
    );
    assert!(
        rate_limited_count(GeneratedErrorReason::TimeExceeded) > before_rl,
        "a rate-limited (buildable) TE must bump the observable TimeExceeded counter"
    );

    // (2) Full bucket: the buildable reply is emitted and consumes a token —
    // the rate-limited counter does NOT move on a successful emission.
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, 0);
    let before_rl = rate_limited_count(GeneratedErrorReason::TimeExceeded);
    let mut counters = BatchCounters::default();
    let req = build_local_time_exceeded_request(
        &frame,
        desc,
        meta,
        &icmp_suppress_ident(),
        &flow,
        &forwarding,
        &Arc::new(ShardedNeighborMap::new()),
        &BTreeMap::new(),
        0,
        &mut counters,
    );
    assert!(
        req.is_some(),
        "a buildable TE under a full bucket must be emitted"
    );
    assert_eq!(
        rate_limited_count(GeneratedErrorReason::TimeExceeded),
        before_rl,
        "a successful TE consumes a token but must not bump the rate-limited counter"
    );
    reset_bucket_for_test(GeneratedErrorReason::TimeExceeded, 0);
}

