// slow-path reinjection, forward-build-failure handling, and disposition/screen/syn-cookie counters.
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
fn maybe_reinject_slow_path_ignores_forward_candidate_disposition() {
    let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    let binding = BindingIdentity {
        slot: 3,
        queue_id: 2,
        worker_id: 1,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 6,
        tx_ifindex: 6,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };

    maybe_reinject_slow_path(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        decision,
        false,
        &recent_exceptions,
        &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().expect("exceptions").is_empty());
}


// #1913: the slow-path eligibility predicate is the single source of
// truth for which dispositions may be reinjected to the kernel slow
// path. PolicyDenied / HAInactive / DiscardRoute (and the
// forward/fabric dispositions) MUST be rejected so a zone-policy DENY is
// not silently bypassed on the cold path.
#[test]
fn slow_path_eligibility_predicate_allow_list() {
    use ForwardingDisposition::*;
    // Eligible: terminate locally or defer to the kernel FIB.
    assert!(LocalDelivery.is_slow_path_eligible());
    assert!(NoRoute.is_slow_path_eligible());
    assert!(MissingNeighbor.is_slow_path_eligible());
    // NOT eligible: must drop, never reinject.
    assert!(!PolicyDenied.is_slow_path_eligible());
    assert!(!HAInactive.is_slow_path_eligible());
    assert!(!DiscardRoute.is_slow_path_eligible());
    // #6664: NextTableUnsupported left the allow-list. Unlike NoRoute it is
    // NOT transient -- no FIB refresh resolves an over-deep or cyclic
    // next-table chain -- so reinjecting it was a STANDING zone-policy bypass
    // for that config rather than a window, and the #7409 "do not black-hole a
    // destination the kernel can still reach" argument does not reach it.
    assert!(!NextTableUnsupported.is_slow_path_eligible());
    // Forward/fabric dispositions never reach the generic slow path.
    assert!(!ForwardCandidate.is_slow_path_eligible());
    assert!(!FabricRedirect.is_slow_path_eligible());
}


// #1913: the filtered wrapper must drop (no enqueue, no exception,
// no drop-counter bump) for every should-drop disposition. Exercises
// the shared predicate via maybe_reinject_slow_path with a valid frame
// so the only thing keeping the packet out of the slow path is the
// disposition filter.
#[test]
fn maybe_reinject_slow_path_drops_ineligible_dispositions() {
    for disposition in [
        ForwardingDisposition::PolicyDenied,
        ForwardingDisposition::HAInactive,
        ForwardingDisposition::DiscardRoute,
    ] {
        let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

        let binding = BindingIdentity {
            slot: 3,
            queue_id: 2,
            worker_id: 1,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision { resolution: ForwardingResolution {
            disposition,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };

        maybe_reinject_slow_path(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            decision,
            false,
            &recent_exceptions,
            &ForwardingState::default(),
        );

        assert_eq!(
            live.slow_path_packets.load(Ordering::Relaxed),
            0,
            "{disposition:?} must not be enqueued to the slow path",
        );
        assert_eq!(
            live.slow_path_drops.load(Ordering::Relaxed),
            0,
            "{disposition:?} is filtered before any drop accounting",
        );
        assert!(
            recent_exceptions.lock().expect("exceptions").is_empty(),
            "{disposition:?} filtered cleanly with no exception",
        );
    }
}


#[test]
fn maybe_reinject_slow_path_records_extract_failure_for_invalid_desc() {
    let area = MmapArea::new(128).expect("mmap");
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let binding = BindingIdentity {
        slot: 3,
        queue_id: 2,
        worker_id: 1,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 5,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };

    // Addr beyond the registered UMEM length forces an extract failure.
    maybe_reinject_slow_path(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &area,
        XdpDesc {
            addr: 512,
            len: 96,
            options: 0,
        },
        meta,
        decision,
        false,
        &recent_exceptions,
        &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let exceptions = recent_exceptions.lock().expect("exceptions");
    let last = exceptions.back().expect("exception recorded");
    assert_eq!(last.reason, "slow_path_extract_failed");
    assert_eq!(last.packet_length, 96);
}


#[test]
fn maybe_reinject_slow_path_from_frame_records_unavailable() {
    let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };

    maybe_reinject_slow_path_from_frame(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &frame,
        meta,
        decision,
        false,
        &recent_exceptions,
        "forward_build_slow_path",
        &ForwardingState::default(),
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let exceptions = recent_exceptions.lock().expect("exceptions");
    let last = exceptions.back().expect("exception recorded");
    assert_eq!(last.reason, "slow_path_unavailable");
    assert_eq!(last.ifindex, 6);
}


#[test]
fn handle_forward_build_failure_records_build_and_slow_path_failures() {
    let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        6,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "slow_path_unavailable"]
    );
}


#[test]
fn handle_forward_build_failure_without_fallback_only_records_build_failure() {
    let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        false,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(reasons, vec!["forward_build_failed"]);
}


/// #1946: a FabricRedirect frame whose forward-frame build/enqueue failed
/// must NOT be raw-reinjected to the local kernel slow path (a
/// cross-chassis L2 redirect is not kernel-FIB routable — wrong-path /
/// conntrack-poison hazard). It is dropped fail-closed and counted on the
/// shared `fabric_redirect_unsendable_drops` counter with a distinct
/// `fabric_redirect_build_failed` exception, even when
/// `fallback_to_slow_path == true`.
#[test]
fn handle_forward_build_failure_drops_fabric_redirect_fail_closed() {
    let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    // `slow_path = None` would make even an eligible disposition record a
    // `slow_path_unavailable` drop; pass None so that, if the gate were
    // ever removed, the reasons vector would differ from the expected
    // fail-closed sequence and the test would catch the regression.
    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    assert_eq!(
        live.fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        1
    );
    // Fail-closed: no slow-path reinjection of any kind.
    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 0);
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 0);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "fabric_redirect_build_failed"]
    );
}


/// #1946 regression guard: the FabricRedirect gate in
/// `handle_forward_build_failure` must be disposition-specific.
/// `ForwardCandidate` IS a route the kernel FIB may legitimately serve,
/// so it must STILL reinject (not be caught by the fabric gate). With
/// `slow_path = None` the reinject lands on `slow_path_unavailable`,
/// proving the gate let it through.
#[test]
fn handle_forward_build_failure_still_reinjects_forward_candidate() {
    let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
    let binding = BindingIdentity {
        slot: 7,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 6,
    };
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 34,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };
    let mut dbg = DebugPollCounters::default();
    let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

    handle_forward_build_failure(
        &binding,
        &live,
        None,
        &local_tunnel_reinjectors,
        &recent_exceptions,
        &mut dbg,
        12,
        frame.len() as u32,
        &frame,
        meta,
        decision,
        true,
        &ForwardingState::default(),
    );

    assert_eq!(dbg.build_fail, 1);
    // The fabric gate must NOT have caught a ForwardCandidate.
    assert_eq!(
        live.fabric_redirect_unsendable_drops
            .load(Ordering::Relaxed),
        0
    );
    // It reinjected (and dropped only because slow_path is None).
    assert_eq!(live.slow_path_drops.load(Ordering::Relaxed), 1);
    let reasons: Vec<String> = recent_exceptions
        .lock()
        .expect("exceptions")
        .iter()
        .map(|entry| entry.reason().to_string())
        .collect();
    assert_eq!(
        reasons,
        vec!["forward_build_failed", "slow_path_unavailable"]
    );
}


#[test]
fn slow_path_accept_is_categorized_by_reason_and_disposition() {
    let live = BindingLiveState::new();

    live.record_slow_path_accept(ForwardingDisposition::MissingNeighbor, "slow_path", 128);
    live.record_slow_path_accept(
        ForwardingDisposition::NoRoute,
        "forward_build_slow_path",
        64,
    );

    assert_eq!(live.slow_path_packets.load(Ordering::Relaxed), 2);
    assert_eq!(live.slow_path_bytes.load(Ordering::Relaxed), 192);
    assert_eq!(
        live.slow_path_missing_neighbor_packets
            .load(Ordering::Relaxed),
        1
    );
}

// #1187: regression tests for DispositionCounters hot/cold accounting modes.
// Hot callers must accumulate in BatchCounters and only write to
// BindingLiveState on flush(). Cold callers must write immediately.


#[test]
fn disposition_counters_hot_accumulates_in_batch_not_live() {
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };
    let mut counters = BatchCounters::default();

    // Before any calls: live counter must be 0, batch must be clean.
    assert_eq!(live.policy_denied_packets.load(Ordering::Relaxed), 0);
    assert!(!counters.touched);

    // Hot call — should land in batch, not in live.
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Hot(&mut counters),
        ForwardingResolution {
            disposition: ForwardingDisposition::PolicyDenied,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        64,
        None,
        None,
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );

    assert_eq!(
        counters.policy_denied_packets, 1,
        "batch should hold the count"
    );
    assert_eq!(
        live.policy_denied_packets.load(Ordering::Relaxed),
        0,
        "live must not be updated before flush"
    );
    assert!(counters.touched, "touched flag must be set after hot bump");

    // After flush: batch clears, live receives the accumulated count.
    counters.flush(&live);
    assert_eq!(
        counters.policy_denied_packets, 0,
        "batch must be zero after flush"
    );
    assert_eq!(
        live.policy_denied_packets.load(Ordering::Relaxed),
        1,
        "live must receive count after flush"
    );
    assert!(!counters.touched, "touched flag must clear after flush");
}


#[test]
fn disposition_counters_cold_writes_live_immediately() {
    let live = BindingLiveState::new();
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let binding = BindingIdentity {
        slot: 1,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-0"),
        ifindex: 3,
    };

    // Before any calls: live counter must be 0.
    assert_eq!(live.route_miss_packets.load(Ordering::Relaxed), 0);

    // Cold call — should write to live immediately, no batch involved.
    record_forwarding_disposition(
        &binding,
        DispositionCounters::Cold(&live),
        ForwardingResolution {
            disposition: ForwardingDisposition::NoRoute,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        64,
        None,
        None,
        &recent_exceptions,
        &Arc::new(Mutex::new(None)),
        &ForwardingState::default(),
    );

    assert_eq!(
        live.route_miss_packets.load(Ordering::Relaxed),
        1,
        "cold path must update live immediately"
    );
}


#[test]
fn noroute_martian_dst_bumps_both_route_miss_and_martian() {
    let mut counters = BatchCounters::default();
    // IPv4 multicast destination that missed the FIB -> NoRoute.
    record_noroute_with_dst(&mut counters, IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)));
    assert_eq!(counters.route_miss_packets, 1, "NoRoute must bump route_miss");
    assert_eq!(
        counters.martian_dropped, 1,
        "a martian destination must ALSO bump martian_dropped"
    );

    // IPv6 multicast is martian too.
    let mut counters6 = BatchCounters::default();
    record_noroute_with_dst(
        &mut counters6,
        IpAddr::V6(std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
    );
    assert_eq!(counters6.martian_dropped, 1);
}


#[test]
fn noroute_nonmartian_dst_bumps_route_miss_only() {
    let mut counters = BatchCounters::default();
    // Ordinary unicast destination -> route miss, NOT martian.
    record_noroute_with_dst(&mut counters, IpAddr::V4(Ipv4Addr::new(10, 0, 2, 5)));
    assert_eq!(counters.route_miss_packets, 1);
    assert_eq!(
        counters.martian_dropped, 0,
        "an ordinary route miss must not be classified as martian"
    );
}


#[test]
fn is_martian_dst_classifies_all_families() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let m = crate::afxdp::disposition::is_martian_dst;
    // IPv4 martians.
    assert!(m(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))), "v4 multicast");
    assert!(m(IpAddr::V4(Ipv4Addr::BROADCAST)), "v4 broadcast");
    assert!(m(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), "v4 unspecified");
    assert!(m(IpAddr::V4(Ipv4Addr::LOCALHOST)), "v4 loopback");
    assert!(!m(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 5))), "v4 unicast");
    // IPv6 martians (no broadcast in v6).
    assert!(m(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), "v6 unspecified");
    assert!(m(IpAddr::V6(Ipv6Addr::LOCALHOST)), "v6 loopback");
    assert!(
        m(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))),
        "v6 multicast"
    );
    assert!(
        !m(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        "v6 unicast"
    );
}


#[test]
fn disposition_counters_hot_screen_drops_accumulate_in_batch() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    // Simulate the screen-check fast path directly (3 drops).
    for _ in 0..3 {
        counters.touched = true;
        counters.screen_drops += 1;
    }

    assert_eq!(counters.screen_drops, 3);
    assert_eq!(
        live.screen_drops.load(Ordering::Relaxed),
        0,
        "live must be 0 before flush"
    );

    counters.flush(&live);
    assert_eq!(counters.screen_drops, 0, "batch must clear after flush");
    assert_eq!(
        live.screen_drops.load(Ordering::Relaxed),
        3,
        "live must receive count after flush"
    );
}


// #4477: source-NAT allocation failures accumulate in the per-poll batch, flush
// into the live atomic, and surface through snapshot() so the Go control plane
// can bridge them into GlobalCtrNATAllocFail / GlobalCtrDrops. FAIL-ON-REVERT:
// dropping the nat_alloc_fail flush block (or the snapshot field) leaves the
// live atomic / snapshot at 0 and the dead-counter observability lie returns.
#[test]
fn nat_alloc_fail_flushes_and_snapshots() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    for _ in 0..4 {
        counters.touched = true;
        counters.nat_alloc_fail += 1;
    }
    assert_eq!(counters.nat_alloc_fail, 4);
    assert_eq!(
        live.nat_alloc_fail.load(Ordering::Relaxed),
        0,
        "live must be 0 before flush"
    );

    counters.flush(&live);
    assert_eq!(counters.nat_alloc_fail, 0, "batch must clear after flush");
    assert_eq!(
        live.nat_alloc_fail.load(Ordering::Relaxed),
        4,
        "live must receive the count after flush"
    );

    // snapshot() must surface the live value so refresh_bindings can copy it
    // onto the wire BindingStatus.
    assert_eq!(
        live.snapshot().nat_alloc_fail,
        4,
        "snapshot must surface nat_alloc_fail for the wire bridge"
    );
}


// #3343: record_screen_drop bumps BOTH the aggregate and the matching
// per-reason ordinal, and the per-reason slots flush element-wise into the
// live atomics + snapshot. FAIL-ON-REVERT: dropping the per-reason bump in
// record_screen_drop (or the per-reason flush loop) leaves the asserted
// ordinals at 0.
#[test]
fn record_screen_drop_populates_per_reason_counters() {
    use crate::afxdp::flood_counters::FloodCounterSlotMap;
    use crate::screen::screen_reason_drop_index;
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();
    // #3651 added the per-zone flood arguments. An EMPTY slot map (every zone
    // resolves to slot 0) keeps this test scoped to the aggregate + per-reason
    // tallies it was written for, so it stays a clean over-reach guard for them.
    let no_zones = FloodCounterSlotMap::empty();

    counters.record_screen_drop("syn-flood", 7, &no_zones);
    counters.record_screen_drop("syn-flood", 7, &no_zones);
    counters.record_screen_drop("port-scan", 7, &no_zones);
    counters.record_screen_drop("session-limit-src", 7, &no_zones);
    counters.record_screen_drop("session-limit-dst", 7, &no_zones);
    // A reason with no published ordinal bumps only the aggregate.
    counters.record_screen_drop("syn-cookie", 7, &no_zones);

    let syn_flood = screen_reason_drop_index("syn-flood").unwrap();
    let port_scan = screen_reason_drop_index("port-scan").unwrap();
    let session_limit = screen_reason_drop_index("session-limit-src").unwrap();
    assert_eq!(
        screen_reason_drop_index("session-limit-dst").unwrap(),
        session_limit,
        "both session-limit reasons fold onto one ordinal"
    );
    assert!(screen_reason_drop_index("syn-cookie").is_none());

    assert_eq!(counters.screen_drops, 6, "aggregate counts every drop");
    assert_eq!(counters.screen_reason_drops[syn_flood], 2);
    assert_eq!(counters.screen_reason_drops[port_scan], 1);
    assert_eq!(counters.screen_reason_drops[session_limit], 2);

    counters.flush(&live);
    assert_eq!(
        counters.screen_reason_drops[syn_flood], 0,
        "batch per-reason slot clears after flush"
    );
    assert_eq!(live.screen_reason_drops[syn_flood].load(Ordering::Relaxed), 2);
    assert_eq!(live.screen_reason_drops[port_scan].load(Ordering::Relaxed), 1);
    assert_eq!(
        live.screen_reason_drops[session_limit].load(Ordering::Relaxed),
        2
    );
    assert_eq!(live.screen_drops.load(Ordering::Relaxed), 6);

    let snap = live.snapshot();
    assert_eq!(snap.screen_reason_drops[syn_flood], 2);
    assert_eq!(snap.screen_reason_drops[session_limit], 2);
}

// #3651: the SAME `record_screen_drop` call that bumps the aggregate must also
// attribute the three FLOOD reasons to the packet's ingress zone. This binds
// the production wiring, not the flood module in isolation: the per-zone tally
// has to be reachable from the one method every screen drop site calls.
//
// FAIL-ON-REVERT: delete the `record_zone_flood_drop` line from
// `BatchCounters::record_screen_drop` and both zones' asserted counts stay 0.
#[test]
fn record_screen_drop_attributes_flood_reasons_to_the_ingress_zone() {
    use crate::afxdp::flood_counters::{
        flush_recorded_flood_counters, FloodCounterSlotMap, FloodCounterStore,
    };
    const TRUST: u16 = 50675; // config::StableZoneID("trust")
    const UNTRUST: u16 = 12345;

    let store = FloodCounterStore::default();
    let slots = FloodCounterSlotMap::build(&[TRUST, UNTRUST], &store);
    let mut counters = BatchCounters::default();

    counters.record_screen_drop("syn-flood", TRUST, &slots);
    counters.record_screen_drop("syn-flood", TRUST, &slots);
    counters.record_screen_drop("icmp-flood", TRUST, &slots);
    counters.record_screen_drop("udp-flood", UNTRUST, &slots);
    // Non-flood screen drops still bump the aggregate but must NOT land in any
    // per-zone flood family — otherwise "SYN flood events" would silently
    // include port scans.
    counters.record_screen_drop("port-scan", TRUST, &slots);
    counters.record_screen_drop("strict-syn-check", TRUST, &slots);
    flush_recorded_flood_counters(&store, &slots);

    let snap = store.snapshot();
    let trust = snap
        .iter()
        .find(|s| s.zone_id == TRUST)
        .expect("trust zone must have per-zone flood counts after record_screen_drop");
    assert_eq!(
        trust.syn_flood_events, 2,
        "record_screen_drop must attribute syn-flood drops to the ingress zone"
    );
    assert_eq!(trust.icmp_flood_events, 1);
    assert_eq!(
        trust.udp_flood_events, 0,
        "udp-flood happened on a different zone"
    );

    let untrust = snap
        .iter()
        .find(|s| s.zone_id == UNTRUST)
        .expect("untrust zone must have per-zone flood counts");
    assert_eq!(untrust.udp_flood_events, 1);
    assert_eq!(untrust.syn_flood_events, 0);

    // The aggregate is unchanged by the per-zone work: all six drops counted.
    assert_eq!(counters.screen_drops, 6);
}

#[test]
fn syn_cookie_counters_hot_path_accumulate_in_batch() {
    let live = BindingLiveState::new();
    let mut counters = BatchCounters::default();

    counters.touched = true;
    counters.syn_cookie_challenges = 2;
    counters.syn_cookie_secret_unavailable = 3;
    counters.syn_cookie_syn_ack_sent = 5;
    counters.syn_cookie_ack_rst_sent = 7;
    counters.syn_cookie_reply_budget_drops = 11;
    counters.syn_cookie_ack_valid = 13;
    counters.syn_cookie_ack_invalid = 17;
    counters.syn_cookie_bypass = 19;

    counters.flush(&live);

    assert_eq!(counters.syn_cookie_challenges, 0);
    assert_eq!(counters.syn_cookie_secret_unavailable, 0);
    assert_eq!(counters.syn_cookie_syn_ack_sent, 0);
    assert_eq!(counters.syn_cookie_ack_rst_sent, 0);
    assert_eq!(counters.syn_cookie_reply_budget_drops, 0);
    assert_eq!(counters.syn_cookie_ack_valid, 0);
    assert_eq!(counters.syn_cookie_ack_invalid, 0);
    assert_eq!(counters.syn_cookie_bypass, 0);
    assert_eq!(live.syn_cookie_challenges.load(Ordering::Relaxed), 2);
    assert_eq!(
        live.syn_cookie_secret_unavailable.load(Ordering::Relaxed),
        3
    );
    assert_eq!(live.syn_cookie_syn_ack_sent.load(Ordering::Relaxed), 5);
    assert_eq!(live.syn_cookie_ack_rst_sent.load(Ordering::Relaxed), 7);
    assert_eq!(
        live.syn_cookie_reply_budget_drops.load(Ordering::Relaxed),
        11
    );
    assert_eq!(live.syn_cookie_ack_valid.load(Ordering::Relaxed), 13);
    assert_eq!(live.syn_cookie_ack_invalid.load(Ordering::Relaxed), 17);
    assert_eq!(live.syn_cookie_bypass.load(Ordering::Relaxed), 19);
}

// ── #1861: transactional forward+reverse install — interleaving pins ──
//
// Deterministic at-cap pins for every interleaving in
// docs/research/1861-install-txn/plan.md §4 that the fix targets:
// I1/I2 (refusal drops the trigger packet, rolls back SNAT, caches
// nothing), I3 (reverse never attempted without forward), I4 boundary
// (pair admitted at cap-2, refused at cap-1), I5 (failed reply repair
// still forwards, is NOT flow-cached, and self-heals below cap), I6
// (refused seed is recycled, not buffered), I14 (NAT64 refusal drops).



// #6664: NextTableUnsupported is DROPPED by the filtered wrapper and counted,
// while a NoRoute whose policy result is Permit still DELEGATES. Both halves
// are asserted in one test against the same harness because the failure this
// guards against is not "the deny does not work" -- it is "the deny was
// applied to the wrong disposition", and only the pair can see that. A change
// that denied both would satisfy a deny-only test.
//
// The two dispositions produce OPPOSITE counter signatures, which is what
// makes the assertions mutation-sensitive:
//   - filtered at the top   -> slow_path_drops == 0, no exception,
//                              next_table_unsupported_drops == 1
//   - proceeds past the top -> slow_path_drops == 1, an exception recorded
//                              (there is no reinjector in this harness),
//                              next_table_unsupported_drops == 0
// Restoring NextTableUnsupported to the allow-list flips it onto the second
// signature and reds on an assertion rather than on a build error.
#[test]
fn next_table_unsupported_is_dropped_and_counted_permit_no_route_still_delegates_6664() {
    struct Case {
        disposition: ForwardingDisposition,
        filtered: bool,
    }
    for case in [
        Case {
            disposition: ForwardingDisposition::NextTableUnsupported,
            filtered: true,
        },
        Case {
            disposition: ForwardingDisposition::NoRoute,
            filtered: false,
        },
    ] {
        let disposition = case.disposition;
        let frame = build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64, crate::afxdp::tests_support::TEST_LAN_MAC);
        let mut area = MmapArea::new(4096).expect("mmap");
        area.slice_mut(0, frame.len())
            .expect("slice")
            .copy_from_slice(&frame);
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));

        let binding = BindingIdentity {
            slot: 3,
            queue_id: 2,
            worker_id: 1,
            interface: Arc::<str>::from("ge-0-0-1"),
            ifindex: 5,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };
        // egress_ifindex 0 mirrors what the FIB actually builds for both of
        // these dispositions (there is no egress interface), so the harness
        // is not quietly kinder to them than production is.
        let decision = SessionDecision { resolution: ForwardingResolution {
            disposition,
            local_ifindex: 0,
            egress_ifindex: 0,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        }, nat: NatDecision::default(), install_table_domain: 0, install_table_check: 0 };

        maybe_reinject_slow_path(
            &binding,
            &live,
            None,
            &local_tunnel_reinjectors,
            &area,
            XdpDesc {
                addr: 0,
                len: frame.len() as u32,
                options: 0,
            },
            meta,
            decision,
            false,
            &recent_exceptions,
            &ForwardingState::default(),
        );

        let drops = live.next_table_unsupported_drops.load(Ordering::Relaxed);
        let slow_path_drops = live.slow_path_drops.load(Ordering::Relaxed);
        let exception_seen = !recent_exceptions.lock().expect("exceptions").is_empty();

        if case.filtered {
            assert_eq!(
                drops, 1,
                "{disposition:?} must be counted as a fail-closed drop so the signal \
                 moves to next_table_unsupported_drops instead of vanishing with the \
                 accept-path counter it used to bump",
            );
            assert_eq!(
                slow_path_drops, 0,
                "{disposition:?} is filtered by the allow-list before any slow-path \
                 drop accounting",
            );
            assert!(
                !exception_seen,
                "{disposition:?} is filtered cleanly, with no slow-path exception",
            );
        } else {
            assert_eq!(
                drops, 0,
                "{disposition:?} must NOT be counted as a next-table drop -- the #6664 \
                 deny is scoped to one disposition, not to the slow path generally",
            );
            assert_eq!(
                slow_path_drops, 1,
                "{disposition:?} must still DELEGATE: it is a permit-result NoRoute \
                 and proceeds past the allow-list, then is only dropped here because \
                 this harness has no reinjector. If this is 0 the packet was filtered \
                 out, i.e. an uncapped/permit NoRoute stopped being slow-path eligible \
                 -- the #7409 black-hole regression.",
            );
            assert!(
                exception_seen,
                "{disposition:?} proceeded into the slow-path body, which records an \
                 exception when no reinjector is configured",
            );
        }
    }
}

// #9637/#10522 operator narrowing: only a LocalDelivery packet with a
// per-packet host-inbound gate proof may select the trusted outlet. Every
// disposition, including the current TableUnavailable arm, is delegated when
// the proof is absent; the positive LocalDelivery control remains trusted.
// Explicitly NOT an M1 killer: this mapper-only cell never calls the
// host-inbound gate, so an M1 gate mutation cannot change its inputs.
#[test]
fn reinject_host_authorized_maps_only_gated_local_delivery_to_trusted() {
    use super::tx::dispatch::reinject_host_authorized;
    use ForwardingDisposition::*;
    let all = [
        LocalDelivery,
        ForwardCandidate,
        FabricRedirect,
        HAInactive,
        PolicyDenied,
        NoRoute,
        MissingNeighbor,
        DiscardRoute,
        NextTableUnsupported,
        TableUnavailable,
    ];
    for disposition in all {
        assert!(
            !reinject_host_authorized(disposition, false),
            "{disposition:?} must delegate without a per-packet gate proof"
        );
    }
    assert!(
        reinject_host_authorized(LocalDelivery, true),
        "a gate-proven LocalDelivery must select Trusted"
    );
    for disposition in all {
        if !matches!(disposition, LocalDelivery) {
            assert!(
                !reinject_host_authorized(disposition, true),
                "{disposition:?} must remain delegated even with a gate proof"
            );
        }
    }
}

/// #10522 Cell 1 (M1 killer): drive a denied TCP/443 LocalDelivery MISS
/// through the real poll loop, host-inbound gate, and trailing reinject
/// chokepoint. The explicit lo0 ACCEPT term means an M1 admit-all mutant
/// reaches the outlet instead of being masked by a lo0 reject terminal.
#[test]
fn host_inbound_gate_to_reinject_chokepoint_is_end_to_end_10522() {
    use crate::slowpath::SlowPathReinjector;
    let mut snapshot = nat_snapshot();
    let lan = snapshot
        .zones
        .iter_mut()
        .find(|zone| zone.name == "lan")
        .expect("nat fixture lan zone");
    lan.host_inbound_system_services.clear();
    lan.host_inbound_protocols.clear();
    snapshot.flow.lo0_filter_input_v4 = "lo0-accept".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "lo0-accept".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "accept-web".to_string(),
            protocols: vec!["tcp".to_string()],
            destination_ports: vec!["443".to_string()],
            action: "accept".to_string(),
            ..Default::default()
        }],
    }];
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = build_txn_tcp_syn_frame_v4(
        Ipv4Addr::new(10, 0, 61, 102),
        Ipv4Addr::new(10, 0, 61, 1),
        40000,
        443,
        TCP_FLAG_SYN,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
    let reinjector = Arc::new(SlowPathReinjector::new_without_worker(1500));
    // Force deterministic outlet-local refusals after the real chokepoint
    // selects an outlet. The clean denied packet never calls either enqueue
    // path; an M1-admitted packet is refused by whichever outlet it reaches.
    reinjector.force_mtu_state_for_test(1500, 32, false);
    reinjector.force_delegated_mtu_state_for_test(32, false);

    let (batch, dbg) = txn_run_descriptor_with_reinjector(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &reinjector,
    );

    assert_eq!(
        reinjector.status().dropped_packets,
        0,
        "a host-inbound-denied packet must never reach Trusted",
    );
    assert_eq!(
        reinjector.delegated_status().dropped_packets,
        0,
        "a host-inbound-denied packet must never reach Delegated",
    );
    assert_eq!(dbg.local, 1, "probe must resolve through LocalDelivery");
    assert_eq!(
        batch.host_inbound_denied_packets, 1,
        "DENY_ZONE TCP/443 must be stopped by host-inbound H2",
    );
}

// #9637 operator narrowing: the enqueue lands on the selected outlet's
// status object. Uses a worker-less reinjector (both channels disconnected)
// so the drop is recorded deterministically without CAP_NET_ADMIN: a
// trusted enqueue must bump the trusted status and leave the delegated one
// at zero, and vice versa. If outlet selection ever crossed, this reds.
#[test]
fn reinject_outlet_selection_records_on_matching_status() {
    use crate::slowpath::{EnqueueOutcome, SlowPathReinjector};
    // Worker-less reinjector: both channels are buffered-but-undrained, so
    // early enqueues ACCEPT invisibly. Fill each outlet to QueueFull (bounded
    // 2× capacity: the forgotten receiver never drains, so full is
    // guaranteed) — the terminal QueueFull (and any rate-limited extras)
    // must land on THAT outlet's status only. If outlet selection ever
    // crossed, the other status would move.
    let r = SlowPathReinjector::new_without_worker(1500);
    let mut trusted_full = false;
    for _ in 0..32770 {
        if matches!(r.enqueue(vec![0u8; 64]), Ok(EnqueueOutcome::QueueFull)) {
            trusted_full = true;
            break;
        }
    }
    assert!(trusted_full, "trusted outlet never reported QueueFull");
    assert!(r.status().dropped_packets >= 1);
    assert_eq!(r.delegated_status().dropped_packets, 0);
    let trusted_drops = r.status().dropped_packets;
    let mut delegated_full = false;
    for _ in 0..32770 {
        if matches!(
            r.enqueue_delegated(vec![0u8; 64]),
            Ok(EnqueueOutcome::QueueFull)
        ) {
            delegated_full = true;
            break;
        }
    }
    assert!(delegated_full, "delegated outlet never reported QueueFull");
    assert!(r.delegated_status().dropped_packets >= 1);
    assert_eq!(r.status().dropped_packets, trusted_drops);
}

// #9637/#10391 operator narrowing: the ForwardCandidate fallback must remain
// explicitly delegated, while the filtered chokepoint derives Trusted only
// after host-inbound gating. Stage 11 is covered by behavioral poll-loop cells
// below and intentionally no longer pins an Adjudicated literal.
#[test]
fn reinject_outlet_declared_per_production_site_9637() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).expect("read reinject call site")
    };
    let fc_src = read("src/afxdp/tx/dispatch/slow_path.rs");
    let fc_start = fc_src
        .find("if fallback_to_slow_path {")
        .expect("ForwardCandidate fallback marker");
    let fc = &fc_src[fc_start..std::cmp::min(fc_start + 1200, fc_src.len())];
    assert!(
        fc.contains("false,"),
        "FC fallback must pass literal false as host_authorized"
    );
    assert!(
        !fc.contains("reinject_host_authorized("),
        "FC fallback must not infer authorization from disposition"
    );

    let src = read("src/afxdp/poll_descriptor/mod.rs");
    let i = src
        .find("if slow_path_admit(&binding.live, decision.resolution.disposition) {")
        .expect("filtered chokepoint marker");
    let choke = &src[i..std::cmp::min(i + 2200, src.len())];
    assert!(
        choke.contains("reinject_host_authorized("),
        "filtered chokepoint must derive Trusted from the disposition mapping"
    );
    assert!(
        choke.contains("host_inbound_gate_proof"),
        "filtered chokepoint must consume the per-packet gate proof"
    );
    // Cell 3 split: the runtime unit covers helper→mapper behavior. This
    // production pin covers the owner predicate and the exempt HIT arm's
    // proof assignment; the existing #10038 family covers lo0/TTL/input
    // semantics for the exemption.
    let exempt_start = src
        .find("let solicited_exempt = foreign_arrival_zone.is_none()")
        .expect("owner-only solicited exemption marker");
    let gated_start = src
        .find("let gated = if solicited_exempt {")
        .expect("solicited gated branch marker");
    let owner_predicate = &src[exempt_start..gated_start];
    assert!(
        owner_predicate.contains("foreign_arrival_zone.is_none()")
            && owner_predicate.contains("resolved.metadata.is_reverse")
            && owner_predicate.contains("tun_origin_reverse_exempt("),
        "solicited exemption must retain the owner/reverse/TUN-origin predicate"
    );
    let branch_len = src[gated_start..]
        .find("} else {")
        .expect("ordinary HIT gated branch marker");
    let exempt_branch = &src[gated_start..gated_start + branch_len];
    assert!(
        exempt_branch.contains("host_inbound_gate_proof = true")
            && exempt_branch.contains("Some(lo0_action_for_solicited_reply("),
        "solicited exemption must produce proof in its own HIT arm"
    );
}

// #9637 F1 (operator narrowing + GPT-1): per-path outlet cells through the
// REAL primitive (`maybe_reinject_slow_path_from_frame` with a worker-less
// reinjector), not the mapping function. Each row drives one reinject class
// with the flag its production site passes and asserts the drop lands on
// THAT outlet's status — the kernel-observable fork (trusted counter vs
// destination-deny counter) starts here. Observability comes from the MTU
// admission gate (no CAP_NET_ADMIN needed): oversized-for-that-outlet
// frames refuse with MtuExceeded on exactly one status object.
//
// Rows: gated LocalDelivery → trusted (the authorized ACCEPT control);
// NoRoute (common-skew + capped + D2 tunnel-forced shape — all resolve
// NoRoute at the outlet) → delegated; transit MissingNeighbor (D4a) →
// delegated; ForwardCandidate (D4b build-failure class) → delegated;
// synthetic LocalDelivery with authorized=false (NAT-T shape) → delegated.
// A row whose outlet ever crosses reds here, not in a mapping unit test.
#[test]
fn reinject_primitive_routes_each_path_to_its_outlet_9637() {
    use crate::slowpath::SlowPathReinjector;
    use ForwardingDisposition::*;
    struct Case {
        name: &'static str,
        disposition: ForwardingDisposition,
        authorized: bool,
        frame_len: usize,
        force_trusted_live: Option<i32>,
        expect_trusted: bool,
    }
    let cases = [
        Case { name: "gated-LocalDelivery-trusted-ACCEPT-control", disposition: LocalDelivery, authorized: true, frame_len: 96, force_trusted_live: Some(64), expect_trusted: true },
        Case { name: "NoRoute-delegated", disposition: NoRoute, authorized: false, frame_len: 2048, force_trusted_live: None, expect_trusted: false },
        Case { name: "MissingNeighbor-delegated-D4a", disposition: MissingNeighbor, authorized: false, frame_len: 2048, force_trusted_live: None, expect_trusted: false },
        Case { name: "ForwardCandidate-delegated-D4b", disposition: ForwardCandidate, authorized: false, frame_len: 2048, force_trusted_live: None, expect_trusted: false },
        Case { name: "synthetic-LocalDelivery-delegated-NAT-T", disposition: LocalDelivery, authorized: false, frame_len: 2048, force_trusted_live: None, expect_trusted: false },
    ];
    for c in cases {
        let r = std::sync::Arc::new(SlowPathReinjector::new_without_worker(1500));
        if let Some(live) = c.force_trusted_live {
            r.force_mtu_state_for_test(1500, live, false);
        }
        let mut frame = build_icmp_echo_frame_v4(
            Ipv4Addr::new(10, 0, 61, 102),
            Ipv4Addr::new(172, 16, 80, 8),
            64,
            crate::afxdp::tests_support::TEST_LAN_MAC,
        );
        frame.resize(c.frame_len, 0);
        let local_tunnel_reinjectors = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
        let binding = BindingIdentity {
            slot: 7,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 6,
        };
        let live = BindingLiveState::new();
        let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
        let meta = UserspaceDpMeta {
            magic: USERSPACE_META_MAGIC,
            version: USERSPACE_META_VERSION,
            length: std::mem::size_of::<UserspaceDpMeta>() as u16,
            l3_offset: 14,
            l4_offset: 34,
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            ..UserspaceDpMeta::default()
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: c.disposition,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        };
        maybe_reinject_slow_path_from_frame(
            &binding,
            &live,
            Some(&r),
            &local_tunnel_reinjectors,
            &frame,
            meta,
            decision,
            c.authorized,
            &recent_exceptions,
            "path-cell-9637",
            &ForwardingState::default(),
        );
        let (got_trusted, got_delegated) = (
            r.status().dropped_packets,
            r.delegated_status().dropped_packets,
        );
        if c.expect_trusted {
            assert_eq!(got_trusted, 1, "{}: trusted outlet must record the refusal", c.name);
            assert_eq!(got_delegated, 0, "{}: delegated outlet must stay quiet", c.name);
        } else {
            assert_eq!(got_delegated, 1, "{}: delegated outlet must record the refusal", c.name);
            assert_eq!(got_trusted, 0, "{}: trusted outlet must stay quiet", c.name);
        }
    }
}

/// Build a local-destination NAT-T frame with an ESP SPI immediately after
/// the UDP header. The frame is deliberately ordinary Ethernet/IPv4/UDP so
/// the production descriptor parser can derive the same flow key as the SA
/// gate.
fn build_stage11_esp_udp_frame_10516(spi: u32) -> Vec<u8> {
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(10, 0, 61, 1);
    let mut frame = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // fixture destination filled below
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // peer source
        0x08, 0x00, // IPv4
        0x45, 0x00, 0x00, 0x00, // total length filled below
        0x00, 0x01, 0x40, 0x00, 64, PROTO_UDP, 0x00, 0x00,
    ];
    frame[..6].copy_from_slice(&crate::afxdp::tests_support::TEST_LAN_MAC);
    let payload = [
        spi.to_be_bytes().as_slice(),
        &[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03],
    ]
    .concat();
    let total_len = 20 + 8 + payload.len();
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame[24..26].fill(0);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&40_000u16.to_be_bytes());
    frame.extend_from_slice(&4500u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // UDP checksum is optional for IPv4.
    frame.extend_from_slice(&payload);
    frame
}
fn build_stage11_udp_v4_frame_10516(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    dst_mac: [u8; 6],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut frame = vec![
        0u8, 0, 0, 0, 0, 0, // destination MAC
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // peer source MAC
        0x08, 0x00, // IPv4
        0x45, 0x00, 0x00, 0x00, // total length filled below
        0x00, 0x01, 0x40, 0x00, 64, PROTO_UDP, 0x00, 0x00,
    ];
    frame[..6].copy_from_slice(&dst_mac);
    frame[16..18].copy_from_slice(&(total_len as u16).to_be_bytes());
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame[24..26].fill(0);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

fn stage11_ipv4_udp_meta_10516(
    frame: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ingress_ifindex: u32,
    src_port: u16,
    dst_port: u16,
) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&src.octets());
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&dst.octets());
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        flow_src_port: src_port,
        flow_dst_port: dst_port,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}
fn build_stage11_ike_v4_frame_10516(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    initiator_spi: u64,
    responder_spi: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(if dst_port == 4500 { 20 } else { 16 });
    if dst_port == 4500 {
        payload.extend_from_slice(&[0, 0, 0, 0]);
    }
    payload.extend_from_slice(&initiator_spi.to_be_bytes());
    payload.extend_from_slice(&responder_spi.to_be_bytes());
    payload.extend_from_slice(&[0; 8]);
    build_stage11_udp_v4_frame_10516(
        src,
        dst,
        src_port,
        dst_port,
        &payload,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    )
}
fn stage11_esp_udp_meta_10516(frame: &[u8]) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        flow_src_port: 40_000,
        flow_dst_port: 4500,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn build_stage11_esp_udp_v6_frame_10516(spi: u32) -> Vec<u8> {
    let src = "2001:559:8585:ef00::102"
        .parse::<Ipv6Addr>()
        .expect("v6 source fixture");
    let dst = "2001:559:8585:ef00::1"
        .parse::<Ipv6Addr>()
        .expect("v6 local fixture");
    let mut frame = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // destination filled below
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // peer source
        0x86, 0xdd, // IPv6
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x14, // UDP header + 12-byte ESP-in-UDP payload
        PROTO_UDP,
        64,
    ];
    frame[..6].copy_from_slice(&crate::afxdp::tests_support::TEST_LAN_MAC);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&40_000u16.to_be_bytes());
    frame.extend_from_slice(&4500u16.to_be_bytes());
    frame.extend_from_slice(&20u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&spi.to_be_bytes());
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]);
    frame
}

fn stage11_esp_udp_v6_meta_10516(frame: &[u8]) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(
        &"2001:559:8585:ef00::102"
            .parse::<Ipv6Addr>()
            .expect("v6 source fixture")
            .octets(),
    );
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(
        &"2001:559:8585:ef00::1"
            .parse::<Ipv6Addr>()
            .expect("v6 local fixture")
            .octets(),
    );
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 62,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        flow_src_port: 40_000,
        flow_dst_port: 4500,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn run_stage11_frame_poll_with_options_10516(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sa_key: Option<crate::afxdp::forwarding::IpsecSaKey>,
    stale: bool,
    remove_after_seed: bool,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    run_stage11_frame_poll_on_snapshot_with_options_10516(
        &nat_snapshot(),
        frame,
        meta,
        sa_key,
        stale,
        remove_after_seed,
    )
}
fn run_stage11_frame_poll_on_snapshot_with_options_10516(
    snapshot: &ConfigSnapshot,
    frame: &[u8],
    meta: UserspaceDpMeta,
    sa_key: Option<crate::afxdp::forwarding::IpsecSaKey>,
    stale: bool,
    remove_after_seed: bool,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    let mut forwarding = build_forwarding_state(snapshot);
    forwarding.ipsec_sa.publish_empty_dump_for_test();
    if let Some(sa_key) = sa_key {
        forwarding.ipsec_sa.upsert(sa_key);
        if remove_after_seed {
            assert_eq!(
                forwarding
                    .ipsec_sa
                    .remove_dst_spi(sa_key.family, sa_key.dst, sa_key.spi),
                1,
                "DELSA fixture must remove the seeded destination/SPI"
            );
        }
    }
    let reinjector = Arc::new(crate::slowpath::SlowPathReinjector::new_without_worker(1500));
    if stale {
        forwarding.ipsec_sa.mark_stale();
    }
    let mut binding =
        BindingWorker::new_for_mirror_test(0, 0, meta.ingress_ifindex as i32, 0);
    binding.interface = Arc::<str>::from(match meta.ingress_ifindex {
        6 => "ge-0-0-1",
        12 => "reth0.80",
        _ => "ge-0-0-1",
    });
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    txn_run_descriptor_inner_with_slow_path(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
        None,
        Some(&reinjector),
    );
    (
        reinjector.status(),
        reinjector.delegated_status(),
        forwarding.ipsec_sa.counters.snapshot(),
        binding.scratch.scratch_recycle.len(),
        reinjector.test_enqueued_delegated(),
    )
}
fn run_stage11_frame_poll_with_seeded_ike_10516(
    snapshot: &ConfigSnapshot,
    frame: &[u8],
    meta: UserspaceDpMeta,
    stale: bool,
    ike_key: crate::afxdp::forwarding::IkeExchangeKey,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    let mut forwarding = build_forwarding_state(snapshot);
    forwarding.ipsec_sa.publish_empty_dump_for_test();
    if stale {
        forwarding.ipsec_sa.mark_stale();
    }
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    ike_exchanges.seed(ike_key, 123_000_000_000);
    let reinjector = Arc::new(crate::slowpath::SlowPathReinjector::new_without_worker(1500));
    let mut binding =
        BindingWorker::new_for_mirror_test(0, 0, meta.ingress_ifindex as i32, 0);
    binding.interface = Arc::<str>::from(match meta.ingress_ifindex {
        6 => "ge-0-0-1",
        12 => "reth0.80",
        _ => "ge-0-0-1",
    });
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    txn_run_descriptor_inner_with_slow_path_and_ike(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
        None,
        Some(&reinjector),
        &ike_exchanges,
    );
    (
        reinjector.status(),
        reinjector.delegated_status(),
        forwarding.ipsec_sa.counters.snapshot(),
        binding.scratch.scratch_recycle.len(),
        reinjector.test_enqueued_delegated(),
    )
}

fn run_stage11_frame_poll_10516(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sa_key: Option<crate::afxdp::forwarding::IpsecSaKey>,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    run_stage11_frame_poll_with_options_10516(frame, meta, sa_key, false, false)
}

fn run_stage11_frame_poll_stale_10516(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sa_key: crate::afxdp::forwarding::IpsecSaKey,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    run_stage11_frame_poll_with_options_10516(frame, meta, Some(sa_key), true, false)
}
fn run_stage11_frame_poll_removed_10516(
    frame: &[u8],
    meta: UserspaceDpMeta,
    sa_key: crate::afxdp::forwarding::IpsecSaKey,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    run_stage11_frame_poll_with_options_10516(frame, meta, Some(sa_key), false, true)
}

fn run_stage11_esp_udp_poll_10516(with_sa: bool) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    crate::afxdp::forwarding::IpsecSaCounterSnapshot,
    usize,
    Vec<bool>,
) {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    let spi = 0x1122_3344;
    let frame = build_stage11_esp_udp_frame_10516(spi);
    let meta = stage11_esp_udp_meta_10516(&frame);
    let sa_key = ipsec_sa_key(dst, spi, src).expect("same-family SA fixture");
    run_stage11_frame_poll_10516(&frame, meta, with_sa.then_some(sa_key))
}

fn build_stage11_raw_v4_frame_10516(protocol: u8) -> Vec<u8> {
    let mut frame = build_stage11_esp_udp_frame_10516(0x1122_3344);
    frame[23] = protocol;
    frame[24..26].fill(0);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    frame
}

fn build_stage11_raw_v6_frame_10516(protocol: u8) -> Vec<u8> {
    let mut frame = vec![
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // destination filled below
        0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5, // peer source MAC
        0x86, 0xdd, // IPv6
    ];
    let mut ip = [0u8; 40];
    ip[0] = 0x60;
    ip[6] = protocol;
    ip[7] = 64;
    ip[8..24].copy_from_slice(
        &"2001:559:8585:ef00::102"
            .parse::<Ipv6Addr>()
            .expect("v6 source fixture")
            .octets(),
    );
    ip[24..40].copy_from_slice(
        &"2001:559:8585:ef00::1"
            .parse::<Ipv6Addr>()
            .expect("v6 local fixture")
            .octets(),
    );
    let payload = [0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1];
    ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    frame[..6].copy_from_slice(&crate::afxdp::tests_support::TEST_LAN_MAC);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&payload);
    frame
}

fn raw_v4_meta_10516(frame: &[u8], protocol: u8) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr[..4].copy_from_slice(&[10, 0, 61, 102]);
    let mut dst_addr = [0u8; 16];
    dst_addr[..4].copy_from_slice(&[10, 0, 61, 1]);
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 34,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn raw_v6_meta_10516(frame: &[u8], protocol: u8) -> UserspaceDpMeta {
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(
        &"2001:559:8585:ef00::102"
            .parse::<Ipv6Addr>()
            .expect("v6 source fixture")
            .octets(),
    );
    let mut dst_addr = [0u8; 16];
    dst_addr.copy_from_slice(
        &"2001:559:8585:ef00::1"
            .parse::<Ipv6Addr>()
            .expect("v6 local fixture")
            .octets(),
    );
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol,
        flow_src_addr: src_addr,
        flow_dst_addr: dst_addr,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

fn raw_v4_non_first_meta_10516(frame: &[u8]) -> UserspaceDpMeta {
    let mut meta = frag_test_meta(14);
    meta.protocol = 255;
    meta.l4_offset = 34;
    meta.pkt_len = frame.len() as u16;
    meta.config_generation = 7;
    meta.fib_generation = 9;
    meta
}
fn build_stage11_raw_v4_non_first_frame_10516(protocol: u8) -> Vec<u8> {
    let mut frame = eth_ipv4_frag_frame(
        0x0001,
        &[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1],
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    frame[23] = protocol;
    frame
}

fn build_stage11_raw_v6_non_first_frame_10516(protocol: u8) -> Vec<u8> {
    let mut frame = eth_ipv6_frag_frame(0x0008, &[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1]);
    frame[14 + 40] = protocol;
    frame
}

fn raw_v6_non_first_meta_10516(frame: &[u8]) -> UserspaceDpMeta {
    let mut meta = raw_v6_meta_10516(frame, 255);
    meta.l4_offset = 14 + 40 + 8;
    meta.payload_offset = meta.l4_offset;
    meta
}

#[test]
fn stage11_raw_protocol_arm_is_fail_closed_10516() {
    assert!(super::poll_descriptor::stage11_raw_protocol_requires_drop(
        PROTO_ESP
    ));
    assert!(super::poll_descriptor::stage11_raw_protocol_requires_drop(
        PROTO_AH
    ));
    assert!(!super::poll_descriptor::stage11_raw_protocol_requires_drop(
        PROTO_UDP
    ));
}

/// Raw ESP/AH and non-first fragments are flowless before Stage 11. Exercise
/// those shapes through the real descriptor poll to pin the §6.1 cell-7
/// NotClaimed verdict, no SA telemetry, and exactly one recycle. Flowless
/// transit may still use an unrelated slow-path outlet after Stage 11 falls
/// through; the SA counters are the observable proof that Stage 11 did not
/// claim the packet.
#[test]
fn stage11_raw_ipsec_is_not_claimed_on_real_poll_10516() {
    let v4_esp = build_stage11_raw_v4_frame_10516(PROTO_ESP);
    let v4_ah = build_stage11_raw_v4_frame_10516(PROTO_AH);
    let v6_esp = build_stage11_raw_v6_frame_10516(PROTO_ESP);
    let v4_esp_fragment = build_stage11_raw_v4_non_first_frame_10516(PROTO_ESP);
    let v4_ah_fragment = build_stage11_raw_v4_non_first_frame_10516(PROTO_AH);
    let v6_esp_fragment = build_stage11_raw_v6_non_first_frame_10516(PROTO_ESP);
    let cases = [
        (
            "v4 ESP",
            v4_esp,
            raw_v4_meta_10516(
                &build_stage11_raw_v4_frame_10516(PROTO_ESP),
                PROTO_ESP,
            ),
        ),
        (
            "v4 AH",
            v4_ah,
            raw_v4_meta_10516(
                &build_stage11_raw_v4_frame_10516(PROTO_AH),
                PROTO_AH,
            ),
        ),
        (
            "v6 ESP",
            v6_esp,
            raw_v6_meta_10516(
                &build_stage11_raw_v6_frame_10516(PROTO_ESP),
                PROTO_ESP,
            ),
        ),
        (
            "v4 ESP non-first fragment",
            v4_esp_fragment,
            raw_v4_non_first_meta_10516(
                &build_stage11_raw_v4_non_first_frame_10516(PROTO_ESP),
            ),
        ),
        (
            "v4 AH non-first fragment",
            v4_ah_fragment,
            raw_v4_non_first_meta_10516(
                &build_stage11_raw_v4_non_first_frame_10516(PROTO_AH),
            ),
        ),
        (
            "v6 ESP non-first fragment",
            v6_esp_fragment,
            raw_v6_non_first_meta_10516(
                &build_stage11_raw_v6_non_first_frame_10516(PROTO_ESP),
            ),
        ),
    ];
    for (label, frame, meta) in cases {
        assert!(
            parse_session_flow_from_bytes(&frame, meta).is_none(),
            "{label}: raw IPsec must remain flowless"
        );
        let (_trusted, delegated, counters, recycled, _queues) =
            run_stage11_frame_poll_10516(&frame, meta, None);
        assert_eq!(delegated.queued_packets, 0, "{label}: raw packet minted q1");
        assert_eq!(counters.sa_miss_dropped_packets, 0, "{label}: SA gate consulted");
        assert_eq!(counters.sa_snapshot_stale_deny, 0, "{label}: stale gate consulted");
        assert_eq!(recycled, 1, "{label}: descriptor was not recycled exactly once");
    }
}


/// The Stage-11 SA decision must be observable through the actual descriptor
/// poll arm: a NAT-T packet with no matching SA is recycled without queueing,
/// while the same packet with a positive SA snapshot reaches only the
/// delegated outlet. This is intentionally not a direct stage/helper call.
#[test]
fn stage11_esp_udp_sa_gate_runs_poll_loop_10516() {
    let (trusted_miss, delegated_miss, miss_counters, miss_recycled, miss_queues) =
        run_stage11_esp_udp_poll_10516(false);
    assert_eq!(trusted_miss.queued_packets, 0);
    assert_eq!(delegated_miss.queued_packets, 0);
    assert_eq!(miss_recycled, 1);
    assert_eq!(miss_counters.sa_miss_dropped_packets, 1);
    assert_eq!(miss_counters.sa_miss_no_sa, 1);
    assert!(miss_queues.is_empty());

    let (trusted_hit, delegated_hit, hit_counters, hit_recycled, hit_queues) =
        run_stage11_esp_udp_poll_10516(true);
    assert_eq!(trusted_hit.queued_packets, 0);
    assert_eq!(delegated_hit.queued_packets, 1);
    assert_eq!(hit_recycled, 1);
    assert_eq!(hit_counters.sa_miss_dropped_packets, 0);
    assert_eq!(hit_queues, vec![true]);
}
#[test]
fn stage11_ike_new_and_established_bypass_stale_sa_gate_10516() {
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(10, 0, 61, 1);
    let initiator_spi = 0x1122_3344_5566_7788;

    let new_frame = build_stage11_ike_v4_frame_10516(
        src,
        dst,
        40_000,
        500,
        initiator_spi,
        0,
    );
    let new_meta = stage11_ipv4_udp_meta_10516(&new_frame, src, dst, 24, 40_000, 500);
    let (_, new_delegated, new_counters, new_recycled, new_queues) =
        run_stage11_frame_poll_with_options_10516(&new_frame, new_meta, None, true, false);
    assert_eq!(new_delegated.queued_packets, 1, "admitted NEW-IKE must delegate");
    assert_eq!(new_counters.sa_miss_dropped_packets, 0);
    assert_eq!(new_counters.sa_snapshot_stale_deny, 0);
    assert_eq!(new_recycled, 1);
    assert_eq!(new_queues, vec![true]);

    let established_frame = build_stage11_ike_v4_frame_10516(
        src,
        dst,
        40_000,
        4500,
        initiator_spi,
        0x8877_6655_4433_2211,
    );
    let established_meta =
        stage11_ipv4_udp_meta_10516(&established_frame, src, dst, 24, 40_000, 4500);
    let ike_key = crate::afxdp::forwarding::IkeExchangeKey::new(
        initiator_spi,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );
    let (_, established_delegated, established_counters, established_recycled, established_queues) =
        run_stage11_frame_poll_with_seeded_ike_10516(
            &nat_snapshot(),
            &established_frame,
            established_meta,
            true,
            ike_key,
        );
    assert_eq!(
        established_delegated.queued_packets, 1,
        "seeded established-IKE must delegate"
    );
    assert_eq!(established_counters.sa_miss_dropped_packets, 0);
    assert_eq!(established_counters.sa_snapshot_stale_deny, 0);
    assert_eq!(established_recycled, 1);
    assert_eq!(established_queues, vec![true]);
}

#[test]
fn stage11_unseeded_established_ike_is_denied_before_stale_sa_gate_10516() {
    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(10, 0, 61, 1);
    let frame = build_stage11_ike_v4_frame_10516(
        src,
        dst,
        40_000,
        4500,
        0x1122_3344_5566_7788,
        0x8877_6655_4433_2211,
    );
    let meta = stage11_ipv4_udp_meta_10516(&frame, src, dst, 24, 40_000, 4500);
    let mut denied_snapshot = nat_snapshot();
    for zone in &mut denied_snapshot.zones {
        zone.host_inbound_system_services.clear();
    }
    let (trusted, delegated, counters, recycled, queues) =
        run_stage11_frame_poll_on_snapshot_with_options_10516(
            &denied_snapshot,
            &frame,
            meta,
            None,
            true,
            false,
        );
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(delegated.queued_packets, 0);
    assert_eq!(queues, Vec::<bool>::new());
    assert_eq!(counters.sa_miss_dropped_packets, 0);
    assert_eq!(counters.sa_snapshot_stale_deny, 0);
    assert_eq!(recycled, 1);
}

#[test]
fn stage11_declared_end_rejects_v4_spi_slack_10516() {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    let spi = 0x1122_3344;
    let mut frame = build_stage11_esp_udp_frame_10516(spi);
    // Declare only the IPv4 header plus UDP header while retaining the
    // complete UDP length and matching SPI in backing UMEM slack.
    frame[16..18].copy_from_slice(&28u16.to_be_bytes());
    frame[24..26].fill(0);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let meta = stage11_esp_udp_meta_10516(&frame);
    let key = ipsec_sa_key(dst, spi, src).expect("same-family SA fixture");
    let (trusted, delegated, counters, recycled, queues) =
        run_stage11_frame_poll_10516(&frame, meta, Some(key));
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(delegated.queued_packets, 0);
    assert_eq!(queues, Vec::<bool>::new());
    assert_eq!(counters.sa_miss_dropped_packets, 1);
    assert_eq!(counters.sa_miss_truncated, 1);
    assert_eq!(recycled, 1);
}
#[test]
fn stage11_static_dnat_external_sa_miss_and_hit_10516() {
    let src = Ipv4Addr::new(198, 51, 100, 10);
    let dst = Ipv4Addr::new(203, 0, 113, 10);
    let spi: u32 = 0x2233_4455;
    let payload = [
        spi.to_be_bytes().as_slice(),
        &[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3],
    ]
    .concat();
    let frame = build_stage11_udp_v4_frame_10516(
        src,
        dst,
        40_000,
        4500,
        &payload,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let meta = stage11_ipv4_udp_meta_10516(&frame, src, dst, 6, 40_000, 4500);
    let ownership = build_forwarding_state(&static_nat_snapshot());
    assert!(ownership.owns_configured_ip(IpAddr::V4(dst)));
    assert!(parse_session_flow_from_bytes(&frame, meta).is_some());
    let (_, miss_delegated, miss_counters, miss_recycled, miss_queues) =
        run_stage11_frame_poll_on_snapshot_with_options_10516(
            &static_nat_snapshot(),
            &frame,
            meta,
            None,
            false,
            false,
        );
    assert_eq!(miss_delegated.queued_packets, 0);
    assert_eq!(miss_counters.sa_miss_dropped_packets, 1);
    assert_eq!(miss_counters.sa_miss_no_sa, 1);
    assert_eq!(miss_recycled, 1);
    assert!(miss_queues.is_empty());

    let key = ipsec_sa_key(IpAddr::V4(dst), spi, IpAddr::V4(src))
        .expect("same-family external SA fixture");
    let (_, hit_delegated, hit_counters, hit_recycled, hit_queues) =
        run_stage11_frame_poll_on_snapshot_with_options_10516(
            &static_nat_snapshot(),
            &frame,
            meta,
            Some(key),
            false,
            false,
        );
    assert_eq!(hit_delegated.queued_packets, 1);
    assert_eq!(hit_counters.sa_miss_dropped_packets, 0);
    assert_eq!(hit_recycled, 1);
    assert_eq!(hit_queues, vec![true]);
}
#[test]
fn stage11_positive_cells_never_mint_adjudicated_q0_10516() {
    let (local_trusted, local_delegated, _, _, local_queues) =
        run_stage11_esp_udp_poll_10516(true);

    let src = Ipv4Addr::new(10, 0, 61, 102);
    let dst = Ipv4Addr::new(10, 0, 61, 1);
    let initiator_spi: u64 = 0x1122_3344_5566_7788;
    let new_frame =
        build_stage11_ike_v4_frame_10516(src, dst, 40_000, 500, initiator_spi, 0);
    let new_meta = stage11_ipv4_udp_meta_10516(&new_frame, src, dst, 24, 40_000, 500);
    let (new_trusted, new_delegated, _, _, new_queues) =
        run_stage11_frame_poll_with_options_10516(&new_frame, new_meta, None, true, false);

    let established_frame = build_stage11_ike_v4_frame_10516(
        src,
        dst,
        40_000,
        4500,
        initiator_spi,
        0x8877_6655_4433_2211,
    );
    let established_meta =
        stage11_ipv4_udp_meta_10516(&established_frame, src, dst, 24, 40_000, 4500);
    let established_key = crate::afxdp::forwarding::IkeExchangeKey::new(
        initiator_spi,
        IpAddr::V4(src),
        IpAddr::V4(dst),
    );
    let (
        established_trusted,
        established_delegated,
        _,
        _,
        established_queues,
    ) = run_stage11_frame_poll_with_seeded_ike_10516(
        &nat_snapshot(),
        &established_frame,
        established_meta,
        true,
        established_key,
    );

    let external_src = Ipv4Addr::new(198, 51, 100, 10);
    let external_dst = Ipv4Addr::new(203, 0, 113, 10);
    let external_spi: u32 = 0x2233_4455;
    let external_payload = [
        external_spi.to_be_bytes().as_slice(),
        &[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3],
    ]
    .concat();
    let external_frame = build_stage11_udp_v4_frame_10516(
        external_src,
        external_dst,
        40_000,
        4500,
        &external_payload,
        crate::afxdp::tests_support::TEST_LAN_MAC,
    );
    let external_meta =
        stage11_ipv4_udp_meta_10516(&external_frame, external_src, external_dst, 6, 40_000, 4500);
    let external_key =
        ipsec_sa_key(IpAddr::V4(external_dst), external_spi, IpAddr::V4(external_src))
            .expect("same-family external SA fixture");
    let (external_trusted, external_delegated, _, _, external_queues) =
        run_stage11_frame_poll_on_snapshot_with_options_10516(
            &static_nat_snapshot(),
            &external_frame,
            external_meta,
            Some(external_key),
            false,
            false,
        );

    for (label, trusted, delegated, queues) in [
        ("SA hit", local_trusted, local_delegated, local_queues),
        ("NEW-IKE", new_trusted, new_delegated, new_queues),
        (
            "established-IKE",
            established_trusted,
            established_delegated,
            established_queues,
        ),
        (
            "external DNAT SA hit",
            external_trusted,
            external_delegated,
            external_queues,
        ),
    ] {
        assert_eq!(trusted.queued_packets, 0, "{label}: positive cell minted q0");
        assert_eq!(delegated.queued_packets, 1, "{label}: positive cell did not delegate");
        assert!(
            !queues.is_empty() && queues.iter().all(|delegated| *delegated),
            "{label}: positive cell minted an adjudicated q0 outlet: {queues:?}"
        );
    }
}
#[test]
fn stage11_declared_end_rejects_v6_spi_slack_10516() {
    let src = "2001:559:8585:ef00::102"
        .parse::<IpAddr>()
        .expect("v6 source fixture");
    let dst = "2001:559:8585:ef00::1"
        .parse::<IpAddr>()
        .expect("v6 local fixture");
    let spi = 0x1122_3344;
    let mut frame = build_stage11_esp_udp_v6_frame_10516(spi);
    // IPv6 payload length declares only the UDP header; the matching SPI
    // remains in backing UMEM slack after the authoritative IP end.
    frame[18..20].copy_from_slice(&8u16.to_be_bytes());
    let meta = stage11_esp_udp_v6_meta_10516(&frame);
    let key = ipsec_sa_key(dst, spi, src).expect("same-family SA fixture");
    let (trusted, delegated, counters, recycled, queues) =
        run_stage11_frame_poll_10516(&frame, meta, Some(key));
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(delegated.queued_packets, 0);
    assert_eq!(queues, Vec::<bool>::new());
    assert_eq!(counters.sa_miss_dropped_packets, 1);
    assert_eq!(counters.sa_miss_truncated, 1);
    assert_eq!(recycled, 1);
}
#[test]
fn stage11_keepalive_and_tiny_first_fragment_drop_10516() {
    let spi = 0x1122_3344;

    let mut keepalive = build_stage11_esp_udp_frame_10516(spi);
    keepalive[16..18].copy_from_slice(&29u16.to_be_bytes());
    keepalive[42] = 0xff;
    keepalive[38..40].copy_from_slice(&9u16.to_be_bytes());
    keepalive[24..26].fill(0);
    let ip_csum = checksum16(&keepalive[14..34]);
    keepalive[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let keepalive_meta = stage11_esp_udp_meta_10516(&keepalive);
    let (_, keepalive_delegated, keepalive_counters, keepalive_recycled, queues) =
        run_stage11_frame_poll_10516(&keepalive, keepalive_meta, None);
    assert_eq!(keepalive_delegated.queued_packets, 0);
    assert_eq!(keepalive_counters.sa_miss_dropped_packets, 1);
    assert_eq!(keepalive_counters.sa_miss_keepalive, 1);
    assert_eq!(keepalive_recycled, 1);
    assert!(queues.is_empty());

    let mut tiny = build_stage11_esp_udp_frame_10516(spi);
    tiny[16..18].copy_from_slice(&30u16.to_be_bytes());
    tiny[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    // UDP declares the full payload, but the first fragment's IP end exposes
    // only two payload bytes; the remaining SPI word is backing slack.
    tiny[38..40].copy_from_slice(&20u16.to_be_bytes());
    tiny[24..26].fill(0);
    let ip_csum = checksum16(&tiny[14..34]);
    tiny[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let tiny_meta = stage11_esp_udp_meta_10516(&tiny);
    let (_, tiny_delegated, tiny_counters, tiny_recycled, tiny_queues) =
        run_stage11_frame_poll_10516(&tiny, tiny_meta, None);
    assert_eq!(tiny_delegated.queued_packets, 0);
    assert_eq!(tiny_counters.sa_miss_dropped_packets, 1);
    assert_eq!(tiny_counters.sa_miss_truncated, 1);
    assert_eq!(tiny_recycled, 1);
    assert!(tiny_queues.is_empty());
}

#[test]
fn stage11_observed_spi_wrong_source_drops_10516() {
    let spi = 0x1122_3344;
    let mut frame = build_stage11_esp_udp_frame_10516(spi);
    frame[26..30].copy_from_slice(&[10, 0, 61, 103]);
    frame[24..26].fill(0);
    let ip_csum = checksum16(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    let mut meta = stage11_esp_udp_meta_10516(&frame);
    meta.flow_src_addr[..4].copy_from_slice(&[10, 0, 61, 103]);
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    let observed_src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let key = ipsec_sa_key(dst, spi, observed_src).expect("same-family SA fixture");
    let (_, delegated, counters, recycled, queues) =
        run_stage11_frame_poll_10516(&frame, meta, Some(key));
    assert_eq!(delegated.queued_packets, 0);
    assert_eq!(counters.sa_miss_dropped_packets, 1);
    assert_eq!(counters.sa_miss_no_sa, 1);
    assert_eq!(recycled, 1);
    assert!(queues.is_empty());
}
#[test]
fn stage11_delsa_removed_spi_drops_10516() {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    let spi = 0x1122_3344;
    let frame = build_stage11_esp_udp_frame_10516(spi);
    let meta = stage11_esp_udp_meta_10516(&frame);
    let key = ipsec_sa_key(dst, spi, src).expect("same-family SA fixture");
    let (_, delegated, counters, recycled, queues) =
        run_stage11_frame_poll_removed_10516(&frame, meta, key);
    assert_eq!(delegated.queued_packets, 0);
    assert_eq!(counters.sa_miss_dropped_packets, 1);
    assert_eq!(counters.sa_miss_no_sa, 1);
    assert_eq!(counters.sa_snapshot_stale_deny, 0);
    assert_eq!(recycled, 1);
    assert!(queues.is_empty());
}
#[test]
fn stage11_stale_spi_drops_10516() {
    let src = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1));
    let spi = 0x1122_3344;
    let frame = build_stage11_esp_udp_frame_10516(spi);
    let meta = stage11_esp_udp_meta_10516(&frame);
    let key = ipsec_sa_key(dst, spi, src).expect("same-family SA fixture");
    let (_, delegated, counters, recycled, queues) =
        run_stage11_frame_poll_stale_10516(&frame, meta, key);
    assert_eq!(delegated.queued_packets, 0);
    assert_eq!(counters.sa_miss_dropped_packets, 1);
    assert_eq!(counters.sa_miss_no_sa, 0);
    assert_eq!(counters.sa_snapshot_stale_deny, 1);
    assert_eq!(recycled, 1);
    assert!(queues.is_empty());
}

// #10311: neighbor MISS with a pending source translation parks the frame
// AND (pre-fix) hands a copy to the kernel slow path. The parked entry
// carries `pending_decision` (SNAT/NPTv6 merged in the MISS arm), but the
// trailing chokepoint reinjects with the ORIGINAL `decision`, whose
// `decision.nat` omits the pending translation — so the first packet(s) of
// an SNAT'd flow egress the kernel with the ORIGINAL source (SNAT bypass +
// internal-address disclosure) plus double delivery (kernel copy + later
// translated replay).
//
// The coherent disposition: a buffered frame is held for translated replay
// and must NOT also be slow-path-copied. These cells drive one SYN of an
// SNAT'd flow with an unresolved next-hop through the REAL
// `poll_binding_process_descriptor` and pin: parked exactly once,
// translated (case's source NAT), session seeded translated, no immediate
// forward, and NO slow-path copy (the txn harness wires `slow_path: None`,
// so any reinject attempt lands on `slow_path_drops` as
// `slow_path_unavailable` — pre-fix the drops assert below is 1, RED).
//
// Fail-on-revert: restore the fall-through reinject for buffered frames
// and `slow_path_drops` goes 0 -> 1 while `pending_neigh` still holds the
// sole translated replay representative; this cell goes RED.
#[derive(Clone, Copy, Debug)]
enum NeighMissNat10311 {
    /// Interface-mode SNAT (the `nat_snapshot` default rule):
    /// 10.0.61.102 -> 172.16.80.8 (egress reth0.80 address).
    InterfaceSnat,
    /// Static-NAT reverse SNAT: 10.0.61.102 -> 203.0.113.10.
    StaticSnat,
    /// NPTv6 outbound: 2001:559:8585:ef00::102 -> 2001:559:8585:80::/64.
    Nptv6,
}

fn drive_neigh_miss_10311(case: NeighMissNat10311) {
    let case_name = match case {
        NeighMissNat10311::InterfaceSnat => "iface-snat",
        NeighMissNat10311::StaticSnat => "static-snat",
        NeighMissNat10311::Nptv6 => "nptv6",
    };
    let mut snapshot = nat_snapshot();
    // Unresolved next-hop: the default routes exist but no neighbor does,
    // so resolution yields MissingNeighbor (the MISS seed path).
    snapshot.neighbors.clear();
    let v6 = matches!(case, NeighMissNat10311::Nptv6);
    match case {
        NeighMissNat10311::InterfaceSnat => {}
        NeighMissNat10311::StaticSnat => {
            // Static SNAT is the ONLY source translation: drop the
            // interface/pool rules so the parked rewrite can only come
            // from the static reverse match below.
            snapshot.source_nat_rules.clear();
            snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
                name: "static-10311".to_string(),
                from_zone: "wan".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "10.0.61.102".to_string(),
                ..Default::default()
            }];
        }
        NeighMissNat10311::Nptv6 => {
            snapshot.nptv6_rules = vec![crate::Nptv6RuleSnapshot {
                name: "nptv6-10311".to_string(),
                from_zone: String::new(),
                internal_prefix: "2001:559:8585:ef00::/64".to_string(),
                external_prefix: "2001:559:8585:80::/64".to_string(),
            }];
        }
    }
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();

    let (frame, meta) = if v6 {
        let client: std::net::Ipv6Addr = "2001:559:8585:ef00::102".parse().unwrap();
        let server: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let frame = build_txn_tcp_syn_frame_v6(client, server, 12345, 80, crate::afxdp::tests_support::TEST_LAN_MAC);
        let meta = txn_meta_v6(24, frame.len());
        (frame, meta)
    } else {
        let frame = build_txn_tcp_syn_frame_v4(
            Ipv4Addr::new(10, 0, 61, 102),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            443,
            TCP_FLAG_SYN,
            crate::afxdp::tests_support::TEST_LAN_MAC,
        );
        let meta = txn_meta_v4(24, TCP_FLAG_SYN, frame.len() as u16);
        (frame, meta)
    };
    let (_batch, dbg, published) = txn_run_descriptor_capturing_shared(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
    );

    // ── Fixture: the MISS arm fired, seeded, and parked. ──
    assert!(
        dbg.missing_neigh >= 1,
        "{case_name}: FIXTURE must take the MissingNeighbor arm"
    );
    assert_eq!(sessions.len(), 1, "{case_name}: permitted MISS flow seeds one session");
    assert_eq!(
        binding.pending_neigh.len(),
        1,
        "{case_name}: the MISS frame parks exactly once"
    );
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "{case_name}: a parked frame queues no immediate forward"
    );
    assert!(
        binding.scratch.scratch_recycle.is_empty(),
        "{case_name}: a parked frame is held for replay, not recycled"
    );
    // ── THE #10311 pin: no slow-path copy while parked. ──
    assert_eq!(
        binding.live.slow_path_packets.load(Ordering::Relaxed),
        0,
        "{case_name}: no slow-path accept while parked (#10311 double delivery)"
    );
    assert_eq!(
        binding.live.slow_path_drops.load(Ordering::Relaxed),
        0,
        "{case_name}: no slow-path copy while parked (#10311 untranslated egress)"
    );
    // ── The parked copy and the seed carry the pending translation. ──
    let parked = binding
        .pending_neigh
        .values()
        .next()
        .expect("parked entry");
    let nat = &parked.decision.nat;
    assert_eq!(nat.rewrite_dst, None, "{case_name}: no DNAT in this flow");
    match case {
        NeighMissNat10311::InterfaceSnat => {
            assert_eq!(
                nat.rewrite_src,
                Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                "{case_name}: parked decision carries the interface-SNAT source"
            );
        }
        NeighMissNat10311::StaticSnat => {
            assert_eq!(
                nat.rewrite_src,
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
                "{case_name}: parked decision carries the static-SNAT source"
            );
        }
        NeighMissNat10311::Nptv6 => {
            assert!(nat.nptv6, "{case_name}: parked decision is NPTv6-marked");
            match nat.rewrite_src {
                Some(IpAddr::V6(translated)) => {
                    // RFC 6296 adjusts the IID, so only the /64 prefix
                    // swap is pinned, not the full address.
                    assert_eq!(
                        translated.segments()[..4],
                        [0x2001, 0x0559, 0x8585, 0x0080],
                        "{case_name}: parked source is in the NPTv6 external /64"
                    );
                    assert_ne!(
                        translated,
                        "2001:559:8585:ef00::102".parse::<std::net::Ipv6Addr>().unwrap(),
                        "{case_name}: parked source differs from the original"
                    );
                }
                other => panic!("{case_name}: expected an NPTv6 v6 rewrite, got {other:?}"),
            }
        }
    }
    let seeds: Vec<_> = published
        .iter()
        .filter(|e| e.origin == SessionOrigin::MissingNeighborSeed)
        .collect();
    assert_eq!(seeds.len(), 1, "{case_name}: exactly one MissingNeighborSeed publish");
    assert_eq!(
        seeds[0].decision.nat, parked.decision.nat,
        "{case_name}: the seed carries the same pending translation"
    );
    let pending_key = *binding.pending_neigh.keys().next().expect("pending key");
    assert_eq!(
        pending_key.1,
        if v6 {
            IpAddr::V6(
                "2001:559:8585:80::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap(),
            )
        } else {
            IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))
        },
        "{case_name}: parked key uses the configured gateway"
    );
    // ── Resolve the hop and replay the parked frame through the real
    // `retry_pending_neigh` path. The egress binding deliberately owns a
    // different UMEM, so production's cross-UMEM pending_tx_local copy path
    // is exercised rather than a prepared offset alias.
    let next_hop = if v6 {
        IpAddr::V6(
            "2001:559:8585:80::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap(),
        )
    } else {
        IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))
    };
    assert_eq!(
        pending_key.0,
        12,
        "{case_name}: pending key uses the route's egress ifindex"
    );
    let mut bindings = vec![
        binding,
        BindingWorker::new_for_mirror_test(1, 0, 11, 0),
    ];
    bindings[1].interface = Arc::<str>::from("ge-0-0-0.80");
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        12,
        80,
        next_hop,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let binding_lookup = WorkerBindingLookup::from_bindings(&bindings);
    let mirror_targets = MirrorTargetMap::default();
    let mut shared_recycles = Vec::new();
    let area = bindings[0].umem.area() as *const MmapArea;
    let (left, rest) = bindings.split_at_mut(0);
    let (ingress, right) = rest.split_first_mut().expect("ingress binding");
    assert!(
        dynamic_neighbors.get(&pending_key).is_some(),
        "{case_name}: resolved neighbor must be visible under the pending key"
    );
    retry_pending_neigh(
        ingress,
        left,
        0,
        right,
        &binding_lookup,
        &mirror_targets,
        &forwarding,
        &dynamic_neighbors,
        None,
        123_000_000_100,
        // SAFETY: `area` points into bindings[0]'s UMEM, which outlives this
        // single-threaded retry call; the split borrows cover disjoint worker
        // state while the UMEM allocation itself is reference-counted.
        unsafe { &*area },
        &mut shared_recycles,
        None,
        &mut BatchCounters::default(),
    );
    assert!(
        bindings[0].pending_neigh.is_empty(),
        "{case_name}: neighbor resolution drains the parked representative"
    );
    assert_eq!(
        bindings[1].tx_pipeline.pending_tx_prepared.len(),
        0,
        "{case_name}: separate UMEMs must not receive a prepared offset"
    );
    assert_eq!(
        bindings[1].tx_pipeline.pending_tx_local.len(),
        1,
        "{case_name}: exactly one translated replay reaches the egress queue \
         (prepared={}, fill={}, table_unavailable={}, tx_submit_errors={}, cross_umem={})",
        bindings[1].tx_pipeline.pending_tx_prepared.len(),
        bindings[1].live.debug_pending_fill_frames.load(Ordering::Relaxed),
        bindings[1].live.table_unavailable_packets.load(Ordering::Relaxed),
        bindings[1].live.tx_submit_error_drops.load(Ordering::Relaxed),
        bindings[1].tx_counters.neighbor_retry_cross_umem_copies
    );
    assert_eq!(
        bindings[1].tx_counters.neighbor_retry_cross_umem_copies,
        1,
        "{case_name}: replay uses exactly one cross-UMEM copy"
    );
    let replay = bindings[1]
        .tx_pipeline
        .pending_tx_local
        .front()
        .expect("translated replay request");
    assert_eq!(
        replay.bytes.len(),
        frame.len() + 4,
        "{case_name}: replay preserves the egress VLAN tag and frame payload"
    );
    if v6 {
        let expected_prefix = [0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0x00, 0x80];
        assert_eq!(
            &replay.bytes[26..34],
            &expected_prefix,
            "{case_name}: replay source carries the NPTv6 external /64"
        );
        assert_ne!(
            &replay.bytes[26..34],
            &[0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0xef, 0x00],
            "{case_name}: replay does not carry the original NPTv6 source prefix"
        );
    } else {
        let expected_source = match case {
            NeighMissNat10311::InterfaceSnat => [172, 16, 80, 8],
            NeighMissNat10311::StaticSnat => [203, 0, 113, 10],
            NeighMissNat10311::Nptv6 => unreachable!(),
        };
        assert_eq!(
            &replay.bytes[30..34],
            &expected_source,
            "{case_name}: replay source is translated, never the original LAN address"
        );
        assert_ne!(
            &replay.bytes[30..34],
            &[10, 0, 61, 102],
            "{case_name}: replay cannot egress with the original source"
        );
    }
}

#[test]
fn neigh_miss_iface_snat_suppresses_slow_path_copy_while_parked_10311() {
    drive_neigh_miss_10311(NeighMissNat10311::InterfaceSnat);
}

#[test]
fn neigh_miss_static_snat_suppresses_slow_path_copy_while_parked_10311() {
    drive_neigh_miss_10311(NeighMissNat10311::StaticSnat);
}

#[test]
fn neigh_miss_nptv6_suppresses_slow_path_copy_while_parked_10311() {
    drive_neigh_miss_10311(NeighMissNat10311::Nptv6);
}
// #10525: DNAT-to-self IKE must pass the userspace fine gates (lo0 + to-zone
// junos-host) before Stage-11 reinject, and must seed the live-exchange table
// only AFTER those gates pass. The VIP 203.0.113.9:500/udp DNATs to the
// firewall's own 10.0.61.1:500; Stage 11 claims it pre-NAT via
// `owns_configured_ip` (DNAT destinations are members of `local_v*`) and the
// reinject carries the wire tuple (`NatDecision::default`, no translation), so
// both fine gates judge the external tuple.
const IKE_10525_SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const IKE_10525_VIP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const IKE_10525_SPI: u64 = 0x1122_3344_5566_7788;
const IKE_10525_RESPONDER_SPI: u64 = 0x8877_6655_4433_2211;
const IKE_10525_IFINDEX: u32 = 12;

fn dnat_to_self_snapshot_10525() -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        name: "vip-to-self-ike".to_string(),
        from_zone: "wan".to_string(),
        destination_address: "203.0.113.9".to_string(),
        destination_port: 500,
        protocol: "udp".to_string(),
        pool_address: "10.0.61.1".to_string(),
        pool_port: 500,
        ..Default::default()
    }];
    snapshot
}

fn junos_host_ike_deny_10525() -> PolicyRuleSnapshot {
    PolicyRuleSnapshot {
        name: "no-ike-to-vip".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "junos-host".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["203.0.113.9/32".to_string()],
        applications: vec!["ike-500".to_string()],
        application_terms: vec![crate::protocol::PolicyApplicationSnapshot {
            name: "ike-500".to_string(),
            protocol: "udp".to_string(),
            source_port: String::new(),
            destination_port: "500".to_string(),
            icmp_type: None,
            icmp_code: None,
            inactivity_timeout: None,
        }],
        action: "deny".to_string(),
        ..Default::default()
    }
}

fn lo0_ike_discard_snapshot_10525() -> ConfigSnapshot {
    let mut snapshot = dnat_to_self_snapshot_10525();
    snapshot.flow.lo0_filter_input_v4 = "protect-re".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "protect-re".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-ike".to_string(),
            destination_addresses: vec!["203.0.113.9/32".to_string()],
            protocols: vec!["udp".to_string()],
            destination_ports: vec!["500".to_string()],
            action: "discard".to_string(),
            ..Default::default()
        }],
    }];
    snapshot
}

fn new_ike_frame_10525() -> Vec<u8> {
    let mut frame = build_stage11_ike_v4_frame_10516(
        IKE_10525_SRC,
        IKE_10525_VIP,
        40_000,
        500,
        IKE_10525_SPI,
        0,
    );
    frame[..6].copy_from_slice(&crate::afxdp::tests_support::TEST_WAN_MAC);
    frame
}

fn followup_ike_frame_10525() -> Vec<u8> {
    let mut frame = build_stage11_ike_v4_frame_10516(
        IKE_10525_SRC,
        IKE_10525_VIP,
        40_000,
        500,
        IKE_10525_SPI,
        IKE_10525_RESPONDER_SPI,
    );
    frame[..6].copy_from_slice(&crate::afxdp::tests_support::TEST_WAN_MAC);
    frame
}

fn ike_meta_10525(frame: &[u8]) -> UserspaceDpMeta {
    stage11_ipv4_udp_meta_10516(
        frame,
        IKE_10525_SRC,
        IKE_10525_VIP,
        IKE_10525_IFINDEX,
        40_000,
        500,
    )
}

fn ike_key_10525() -> crate::afxdp::forwarding::IkeExchangeKey {
    crate::afxdp::forwarding::IkeExchangeKey::new(
        IKE_10525_SPI,
        IpAddr::V4(IKE_10525_SRC),
        IpAddr::V4(IKE_10525_VIP),
    )
}

fn run_stage11_ike_poll_10525(
    snapshot: &ConfigSnapshot,
    frame: &[u8],
    meta: UserspaceDpMeta,
    ike_exchanges: &Arc<crate::afxdp::forwarding::IkeExchangeTable>,
) -> (
    crate::slowpath::SlowPathStatus,
    crate::slowpath::SlowPathStatus,
    usize,
    Vec<bool>,
    BatchCounters,
    DebugPollCounters,
) {
    let forwarding = build_forwarding_state(snapshot);
    assert!(
        forwarding.owns_configured_ip(IpAddr::V4(IKE_10525_VIP)),
        "premise: the DNAT VIP must be firewall-owned so Stage 11 claims the IKE pre-NAT"
    );
    forwarding.ipsec_sa.publish_empty_dump_for_test();
    let reinjector = Arc::new(crate::slowpath::SlowPathReinjector::new_without_worker(1500));
    let mut binding =
        BindingWorker::new_for_mirror_test(0, 0, meta.ingress_ifindex as i32, 0);
    binding.interface = Arc::<str>::from(match meta.ingress_ifindex {
        6 => "ge-0-0-1",
        12 => "reth0.80",
        _ => "ge-0-0-1",
    });
    let mut sessions = SessionTable::new();
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let (batch, dbg) = txn_run_descriptor_inner_with_slow_path_and_ike(
        &mut binding,
        &mut sessions,
        &forwarding,
        &txn_ha_state(),
        frame,
        meta,
        &local_tunnel_deliveries,
        &shared_sessions,
        None,
        Some(&reinjector),
        ike_exchanges,
    );
    (
        reinjector.status(),
        reinjector.delegated_status(),
        binding.scratch.scratch_recycle.len(),
        reinjector.test_enqueued_delegated(),
        batch,
        dbg,
    )
}

#[test]
// R1 / RED-on-revert: removing the pre-reinject fine gate restores delegated
// reinject + seed; moving the seed before gates restores the table entry.
fn r1_dnat_to_self_ike_fine_deny_drops_without_seed_or_reinject_10525() {
    let mut snapshot = dnat_to_self_snapshot_10525();
    snapshot.policies.push(junos_host_ike_deny_10525());
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let frame = new_ike_frame_10525();
    let meta = ike_meta_10525(&frame);
    let (trusted, delegated, recycled, queues, batch, dbg) =
        run_stage11_ike_poll_10525(&snapshot, &frame, meta, &ike_exchanges);
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(
        delegated.queued_packets, 0,
        "a to-zone junos-host DENY covering the DNAT-to-self IKE must drop it before \
         Stage-11 reinject (#10525 confirmed bypass)"
    );
    assert!(queues.is_empty());
    assert_eq!(recycled, 1);
    assert_eq!(
        ike_exchanges.len(),
        0,
        "a fine-denied IKE must NEVER seed the live-exchange table (#10525 seed discipline)"
    );
    assert_eq!(dbg.local, 1);
    assert_eq!(dbg.policy_deny, 1);
    assert_eq!(
        batch.host_inbound_denied_packets, 0,
        "a fine deny is a policy deny, not a host-inbound deny"
    );
}

#[test]
// R2 / RED-on-revert: removing the pre-reinject lo0 gate restores delegated
// reinject + seed; moving the seed before gates restores the table entry.
fn r2_dnat_to_self_ike_lo0_discard_drops_without_seed_10525() {
    let snapshot = lo0_ike_discard_snapshot_10525();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let frame = new_ike_frame_10525();
    let meta = ike_meta_10525(&frame);
    let (trusted, delegated, recycled, queues, batch, dbg) =
        run_stage11_ike_poll_10525(&snapshot, &frame, meta, &ike_exchanges);
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(
        delegated.queued_packets, 0,
        "an lo0 filter-input discard covering the DNAT-to-self IKE must drop it before \
         Stage-11 reinject (#10525 skipped userspace lo0 eval)"
    );
    assert!(queues.is_empty());
    assert_eq!(recycled, 1);
    assert_eq!(
        ike_exchanges.len(),
        0,
        "an lo0-denied IKE must NEVER seed the live-exchange table (#10525 seed discipline)"
    );
    assert_eq!(dbg.local, 1);
    assert_eq!(dbg.policy_deny, 1);
    assert_eq!(batch.host_inbound_denied_packets, 0);
}

#[test]
// R3 / RED-on-revert: established Stage-11 IKE must not bypass a late fine
// deny; removing the per-packet gate admits the seeded follow-up.
fn r3_seeded_ike_followup_late_fine_deny_drops_10525() {
    let mut snapshot = dnat_to_self_snapshot_10525();
    snapshot.policies.push(junos_host_ike_deny_10525());
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    ike_exchanges.seed(ike_key_10525(), 123_000_000_000);
    let frame = followup_ike_frame_10525();
    let meta = ike_meta_10525(&frame);
    let (trusted, delegated, recycled, queues, _batch, dbg) =
        run_stage11_ike_poll_10525(&snapshot, &frame, meta, &ike_exchanges);
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(
        delegated.queued_packets, 0,
        "an established IKE follow-up must be re-gated per packet: a late fine deny drops \
         it (#10525 session-HIT parity)"
    );
    assert!(queues.is_empty());
    assert_eq!(recycled, 1);
    assert_eq!(dbg.local, 1);
    assert_eq!(dbg.policy_deny, 1);
    assert_eq!(
        ike_exchanges.len(),
        1,
        "the drop is per-packet re-eval without teardown: the seed stays and every follow-up \
         is re-gated until it idles out"
    );
}

#[test]
// C1 / control: coarse-admitted IKE with no fine/lo0 match remains delegated,
// and the caller seeds only after the gates pass.
fn c1_dnat_to_self_ike_admits_and_seeds_delegated_10525() {
    let snapshot = dnat_to_self_snapshot_10525();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let frame = new_ike_frame_10525();
    let meta = ike_meta_10525(&frame);
    let (trusted, delegated, recycled, queues, batch, dbg) =
        run_stage11_ike_poll_10525(&snapshot, &frame, meta, &ike_exchanges);
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(
        delegated.queued_packets, 1,
        "control: coarse-admitted IKE with no fine/lo0 deny must still delegate byte-identically"
    );
    assert_eq!(queues, vec![true]);
    assert_eq!(recycled, 1);
    assert_eq!(
        ike_exchanges.len(),
        1,
        "control: an admitted NEW IKE must seed exactly once"
    );
    assert!(
        ike_exchanges.matches(&ike_key_10525(), 123_000_000_000),
        "control: the seed must be keyed (initiator SPI, peer, local)"
    );
    assert_eq!(dbg.policy_deny, 0);
    assert_eq!(dbg.host_inbound_deny, 0);
    assert_eq!(batch.host_inbound_denied_packets, 0);
}

#[test]
// C2 / control: the existing coarse host-inbound deny remains first and never
// seeds or reinjects.
fn c2_dnat_to_self_ike_coarse_deny_drops_without_seed_10525() {
    let mut snapshot = dnat_to_self_snapshot_10525();
    for zone in snapshot.zones.iter_mut() {
        zone.host_inbound_system_services.clear();
    }
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let frame = new_ike_frame_10525();
    let meta = ike_meta_10525(&frame);
    let (trusted, delegated, recycled, queues, batch, _dbg) =
        run_stage11_ike_poll_10525(&snapshot, &frame, meta, &ike_exchanges);
    assert_eq!(trusted.queued_packets, 0);
    assert_eq!(
        delegated.queued_packets, 0,
        "control: a zone omitting `ike` must deny (coarse gate)"
    );
    assert!(queues.is_empty());
    assert_eq!(recycled, 1);
    assert_eq!(
        ike_exchanges.len(),
        0,
        "control: a coarse-denied IKE must never seed (#6471)"
    );
    assert_eq!(batch.host_inbound_denied_packets, 1);
}
