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
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
    let frame =
        build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
// and NoRoute still DELEGATES. Both halves are asserted in one test against
// the same harness because the failure this guards against is not "the deny
// does not work" -- it is "the deny was applied to the wrong disposition", and
// only the pair can see that. A change that denied both would satisfy a
// deny-only test.
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
fn next_table_unsupported_is_dropped_and_counted_no_route_still_delegates_6664() {
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
        let frame =
            build_icmp_echo_frame_v4(Ipv4Addr::new(10, 0, 61, 102), Ipv4Addr::new(1, 1, 1, 1), 64);
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
                "{disposition:?} must still DELEGATE: it proceeds past the allow-list \
                 and is only dropped here because this harness has no reinjector. If \
                 this is 0 the packet was filtered out, i.e. NoRoute stopped being \
                 slow-path eligible -- the #7409 black-hole regression.",
            );
            assert!(
                exception_seen,
                "{disposition:?} proceeded into the slow-path body, which records an \
                 exception when no reinjector is configured",
            );
        }
    }
}

// #9637 operator narrowing: the outlet mapping is exhaustive — exactly the
// gate-passed LocalDelivery takes the trusted TUN; every other disposition
// (including every other SLOW-PATH-ELIGIBLE one: NoRoute and MissingNeighbor
// delegate) takes the delegated TUN. A new disposition variant fails this
// test until its outlet is classified here.
#[test]
fn reinject_host_authorized_maps_only_gated_local_delivery_to_trusted() {
    use super::tx::dispatch::reinject_host_authorized;
    use ForwardingDisposition::*;
    assert!(reinject_host_authorized(LocalDelivery));
    for d in [
        ForwardCandidate,
        FabricRedirect,
        HAInactive,
        PolicyDenied,
        NoRoute,
        MissingNeighbor,
        DiscardRoute,
        NextTableUnsupported,
    ] {
        assert!(
            !reinject_host_authorized(d),
            "{d:?} must take the delegated outlet (destination-judged)"
        );
    }
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

// #9637 operator narrowing: every production reinject site declares its
// outlet, and only the filtered chokepoint may derive it from the
// disposition. The two unfiltered sites (ForwardCandidate fallback,
// synthetic IPsec passthrough) must pass a literal `false`: their classes
// never passed a host gate, so inferring from disposition there would be
// wrong the day a gated class shares the site. The chokepoint must pass
// `reinject_host_authorized(...)` (not a literal): it serves all
// dispositions that survive the allow-list. A site that stops declaring
// (or starts inferring) reds here; the mapping's own exhaustiveness is
// pinned by reinject_host_authorized_maps_only_gated_local_delivery_to_trusted.
#[test]
fn reinject_outlet_declared_per_production_site_9637() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).expect("read reinject call site")
    };
    let after_call = |src: &str, marker: &str, window: usize| -> String {
        let i = src
            .find(marker)
            .unwrap_or_else(|| panic!("call site marker not found: {marker}"));
        src[i..std::cmp::min(i + window, src.len())].to_string()
    };
    // ForwardCandidate fallback: literal false (forward disposition, never
    // gate-passed).
    let fc = after_call(
        &read("src/afxdp/tx/dispatch/slow_path.rs"),
        "if fallback_to_slow_path {",
        1200,
    );
    assert!(
        fc.contains("false,"),
        "FC fallback must pass literal false as host_authorized"
    );
    assert!(
        !fc.contains("reinject_host_authorized("),
        "FC fallback must not infer authorization from disposition"
    );
    // Synthetic IPsec passthrough: literal false (exempt classes never
    // gate-passed; IKE-new is destination-judged on identical tokens).
    let ipsec = after_call(
        &read("src/afxdp/poll_stages.rs"),
        "let ipsec_decision = ipsec_passthrough_decision();",
        1400,
    );
    assert!(
        ipsec.contains("false,"),
        "IPsec passthrough must pass literal false as host_authorized"
    );
    assert!(
        !ipsec.contains("reinject_host_authorized("),
        "IPsec passthrough must not infer authorization from disposition"
    );
    // Filtered chokepoint: the mapping function (serves every surviving
    // disposition; only gated LocalDelivery maps trusted).
    let choke = after_call(
        &read("src/afxdp/poll_descriptor/mod.rs"),
        "if slow_path_admit(&binding.live, decision.resolution.disposition) {",
        1400,
    );
    assert!(
        choke.contains("reinject_host_authorized(decision.resolution.disposition)"),
        "filtered chokepoint must derive host_authorized from the disposition mapping"
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
