// bind-strategy, fabric-redirect, worker-binding, forward-request/output-filter, session-replica/resolution, forwarded-frame, and static-NAT.
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
fn mlx5_keeps_umem_owner_bind_strategy() {
    assert_eq!(
        bind_strategy_for_driver(Some("mlx5_core")),
        AfXdpBindStrategy::UmemOwnerSocket
    );
    assert_eq!(
        alternate_bind_strategy(Some("mlx5_core"), AfXdpBindStrategy::UmemOwnerSocket),
        None
    );
}


#[test]
fn virtio_uses_auto_mode_umem_owner_strategy() {
    assert_eq!(
        bind_strategy_for_driver(Some("virtio_net")),
        AfXdpBindStrategy::UmemOwnerSocket
    );
    assert_eq!(
        alternate_bind_strategy(Some("virtio_net"), AfXdpBindStrategy::UmemOwnerSocket,),
        None
    );
    assert_eq!(
        binder_for_strategy(AfXdpBindStrategy::UmemOwnerSocket),
        AfXdpBinder::Umem
    );
    assert_eq!(bind_flag_candidates_for_driver(Some("virtio_net")), &[0]);
    assert_eq!(
        bind_flag_candidates_for_driver(Some("mlx5_core")),
        &[XSK_BIND_FLAGS_ZEROCOPY, XSK_BIND_FLAGS_COPY]
    );
}


#[test]
fn shared_umem_socket_roles_use_kernel_legal_bind_flags() {
    let mut info = IfInfo::invalid();
    info.set_queue(0);

    assert_eq!(
        bind_flag_candidates_for_socket_role(&info, Some("mlx5_core"), XskSocketRole::SharedOwner),
        &[XSK_BIND_FLAGS_ZEROCOPY]
    );

    let secondary = bind_flag_candidates_for_socket_role(
        &info,
        Some("mlx5_core"),
        XskSocketRole::SharedSecondary,
    );
    assert_eq!(secondary, &[SocketConfig::XDP_BIND_SHARED_UMEM]);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_COPY, 0);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_ZEROCOPY, 0);
    assert_eq!(secondary[0] & SocketConfig::XDP_BIND_NEED_WAKEUP, 0);
    assert_eq!(describe_bind_flags(secondary[0]), "shared-umem");
}


#[test]
fn shared_umem_group_key_is_same_device_mlx5_only() {
    assert_eq!(
        shared_umem_group_key_for_device(
            Some("mlx5_core"),
            Some("/sys/devices/pci0000:00/0000:08:00.0")
        ),
        Some("mlx5:/sys/devices/pci0000:00/0000:08:00.0".to_string())
    );
    assert_eq!(
        shared_umem_group_key_for_device(
            Some("virtio_net"),
            Some("/sys/devices/pci0000:00/0000:00:07.0")
        ),
        None
    );
    assert_eq!(
        shared_umem_group_key_for_device(Some("mlx5_core"), None),
        None
    );
}


#[test]
fn split_owner_fabric_redirect_skips_local_reverse_placeholder() {
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };

    assert!(!should_install_local_reverse_session(decision, true));
    assert!(!should_install_local_reverse_session(decision, false));
}


#[test]
fn fabric_redirect_reply_from_real_fabric_ingress_keeps_local_reverse() {
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            ..NatDecision::default()
        },
    };

    assert!(should_install_local_reverse_session(decision, true));
    assert!(!should_install_local_reverse_session(decision, false));
}


#[test]
fn cloned_worker_umem_shares_allocation_identity() {
    let shared = match WorkerUmem::new(64) {
        Ok(shared) => shared,
        Err(err) => {
            eprintln!("skipping UMEM identity test: {err}");
            return;
        }
    };
    let shared_clone = shared.clone();
    let private = match WorkerUmem::new(64) {
        Ok(private) => private,
        Err(err) => {
            eprintln!("skipping UMEM identity test: {err}");
            return;
        }
    };
    assert!(shared.shares_allocation_with(&shared_clone));
    assert!(!shared.shares_allocation_with(&private));
}


#[test]
fn worker_binding_lookup_prefers_same_queue_binding() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_if_queue.insert((5, 0), 0);
    lookup.by_if_queue.insert((5, 1), 1);
    lookup.first_by_if.insert(5, 0);
    lookup.all_by_if.insert(5, vec![0, 1]);

    assert_eq!(lookup.target_index(2, 7, 1, 5), Some(1));
    assert_eq!(lookup.target_index(2, 7, 3, 5), Some(0));
    assert_eq!(lookup.target_index(2, 5, 1, 5), Some(2));
}


#[test]
fn worker_binding_lookup_hashes_fabric_target_across_queues() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.all_by_if.insert(5, vec![10, 11, 12, 13]);

    let indices = [
        lookup.fabric_target_index(5, 0),
        lookup.fabric_target_index(5, 1),
        lookup.fabric_target_index(5, 2),
        lookup.fabric_target_index(5, 3),
    ];
    assert_eq!(indices, [Some(10), Some(11), Some(12), Some(13)]);
}


#[test]
fn worker_binding_lookup_resolves_slot_index() {
    let mut lookup = WorkerBindingLookup::default();
    lookup.by_slot.insert(11, 3);
    assert_eq!(lookup.slot_index(11), Some(3));
    assert_eq!(lookup.slot_index(99), None);
}


#[test]
fn build_live_forward_request_from_frame_uses_precomputed_hints() {
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let desc = XdpDesc {
        addr: 0,
        len: 0,
        options: 0,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let hints = PendingForwardHints {
        expected_ports: Some((12345, 5201)),
        target_binding_index: Some(9),
    };

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        desc,
        &[],
        meta,
        &decision,
        &ForwardingState::default(),
        None,
        None,
        false,
        0,
        None,
        Some(hints),
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    )
    .expect("request");

    assert_eq!(req.expected_ports, hints.expected_ports);
    assert_eq!(req.target_binding_index, hints.target_binding_index);
    assert_eq!(req.target_ifindex, 11);
}

// #5606: a NAT64 reverse (v4->v6) reply is forwarded through
// `build_live_forward_request_from_frame`. The matched reverse-companion
// session's `SessionMetadata` carries the original v6 src/dst
// (`Nat64ReverseInfo`); the poll loop threads it into the builder's
// `nat64_reverse` parameter, which the builder packs onto
// `PendingForwardRequest.nat64_reverse`. The TX dispatcher's
// `build_nat64_forwarded_frame` AF_INET (v4->v6) branch hard-requires that
// field to translate the reply back to IPv6 — with `None` it returns `None`
// and the reply is dropped. This pins that the builder carries the threaded
// value through, and that a non-NAT64 flow keeps `None`.
//
// RED on revert: restoring the constructor's hard-coded `nat64_reverse: None`
// (ignoring the new parameter) makes the `Some(reverse_info)` assertion fail.
#[test]
fn build_live_forward_request_threads_nat64_reverse_info_5606() {
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 10,
    };
    let desc = XdpDesc {
        addr: 0,
        len: 0,
        options: 0,
    };
    // The reverse reply arrives as IPv4 (server -> pool address).
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        ..UserspaceDpMeta::default()
    };
    let orig_client: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let orig_server: Ipv6Addr = "64:ff9b::0808:0808".parse().unwrap();
    // NAT64 reverse decision (nat64 = true): the reply is translated v4 -> v6.
    // `NatDecision::reverse` restores the original v6 src/dst; here we assemble
    // the equivalent decision directly.
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(orig_client)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(orig_server)),
            rewrite_dst: Some(IpAddr::V6(orig_client)),
            rewrite_src_port: None,
            rewrite_dst_port: Some(5000),
            nat64: true,
            nptv6: false,
        },
    };
    let reverse_info = Nat64ReverseInfo {
        orig_src_v6: orig_client,
        orig_dst_v6: orig_server,
    };

    // Threaded: the built request carries the reverse info verbatim.
    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        desc,
        &[],
        meta,
        &decision,
        &ForwardingState::default(),
        None,
        None,
        false,
        0,
        None,
        None,
        None,
        None,
        Some(reverse_info),
    )
    .expect("request");
    assert_eq!(
        req.nat64_reverse,
        Some(reverse_info),
        "#5606: the builder must thread the NAT64 reverse info (original v6 \
         src/dst) onto the request so the v4->v6 reply can be translated"
    );

    // Control: a non-NAT64 flow (no reverse info) keeps `nat64_reverse: None`.
    let plain_decision = SessionDecision {
        resolution: decision.resolution,
        nat: NatDecision::default(),
    };
    let plain = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        desc,
        &[],
        meta,
        &plain_decision,
        &ForwardingState::default(),
        None,
        None,
        false,
        0,
        None,
        None,
        None,
        None,
        None,
    )
    .expect("request");
    assert!(
        plain.nat64_reverse.is_none(),
        "#5606: a non-NAT64 request must keep nat64_reverse == None (the common \
         IPv4/IPv6 same-family path is unchanged)"
    );
}


#[test]
fn build_live_forward_request_from_frame_drops_logged_output_filter_discard() {
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        },
    };
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "discard".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    assert!(req.is_none(), "terminal output filter must not forward");
    let event = event_rx
        .try_recv()
        .expect("output filter-log frame")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.action, 0, "discard must encode RT_FLOW deny");
    assert_eq!(
        event.reason,
        FilterLogSource::Output.wire_reason(),
        "live output filter source must not be mislabeled",
    );
}


/// #3608 RED-on-revert: an OUTPUT firewall-filter `then reject` on the transit
/// forward path must synthesize an ACTIVE reject reply (a TCP RST here), NOT the
/// historical silent drop. On revert (the `CoSTxSelection.reject` flag or the
/// `build_live_forward_request_from_frame` synthesis wiring removed) the reject
/// collapses back to a silent discard: no RST is enqueued, `filter_reject_sent`
/// stays 0, and the filter-log downgrades REJECT->DENY — every assertion below
/// flips. `then discard` (the sibling test above) is unaffected.
#[test]
fn build_live_forward_request_from_frame_output_filter_reject_sends_rst_3608() {
    // #2472/#2955: the reject reply is gated by the PROCESS-GLOBAL Reject GCRA
    // token bucket, whose TAT advances monotonically across the whole test
    // binary. Hold the shared global-bucket test lock for the entire
    // reset→drive→assert window and reset the Reject bucket to full, exactly as
    // the reject_reply.rs success-path siblings do (e.g.
    // `reject_tcp_with_egress_enqueues_rst`). Without this a parallel test can
    // drain the bucket out from under us (this assertion would flake to
    // `filter_reject_sent == 0`) AND the resulting rate-limit denial would bump
    // the global rate_limited_count and break a concurrent lock-test's
    // before==after invariant.
    let _bucket_guard = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let src_ip = Ipv4Addr::new(10, 0, 61, 100);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let src_port = 12345u16;
    let dst_port = 443u16;
    // A minimal, valid Ethernet/IPv4/TCP SYN so the RST builder + the generated-
    // reply re-classify have real bytes to reflect. Unicast L2 addresses (a
    // group/broadcast source would be suppressed by build_reject_rst_frame).
    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, // dst MAC (unicast)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
        0x08, 0x00, // ethertype IPv4
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 64, PROTO_TCP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, 0xfa, 0xf0, // data offset / SYN / window
        0x00, 0x00, 0x00, 0x00, // checksum + urgent
    ]);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x02,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port,
            dst_port,
        },
    };
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-web".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["443".into()],
                action: "reject".into(),
                log: true,
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    // Size the pipeline above the SYN-cookie-shared TX-frame reserve so the
    // reject reply's budget gate admits it (the reject path reuses that gate).
    let mut tx_pipeline = WorkerTxPipeline {
        free_tx_frames: (0..256u64).collect(),
        pending_tx_prepared: std::collections::VecDeque::new(),
        pending_tx_local: std::collections::VecDeque::new(),
        max_pending_tx: 256,
        outstanding_tx: 0,
        pending_fill_frames: std::collections::VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    };
    let mut counters = BatchCounters::default();

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        Some(ForwardRejectReply {
            tx_pipeline: &mut tx_pipeline,
            counters: &mut counters,
        }),
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );

    assert!(
        req.is_none(),
        "a `then reject` output term must NOT forward the original packet"
    );
    assert_eq!(
        counters.filter_reject_sent, 1,
        "#3608: output-filter `then reject` must enqueue exactly one active reply (RED on revert: silent drop leaves this 0)"
    );
    assert_eq!(
        tx_pipeline.pending_tx_local.len(),
        1,
        "the reflected TCP RST must be queued on the ingress TX pipeline"
    );
    let event = event_rx
        .try_recv()
        .expect("output filter-log frame")
        .decode_dataplane_event()
        .expect("filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(
        event.action, 2,
        "#3608/#3615: an output `then reject` whose reply WAS sent must log RT_FLOW REJECT (2), not DENY (0)"
    );
}

/// #6854 (review finding): the OUTPUT-filter reject path must carry the term's
/// `then reject <message-type>` into the ICMP code on the wire.
///
/// The sibling above proves the output path synthesizes a reply at all, using
/// TCP so the reply is a RST. A RST carries no ICMP code, so it cannot see this
/// property at all. UDP here is what makes the ICMP builder run.
///
/// Why it exists: hostile review hardcoded `RejectMessage::ADMIN_PROHIBITED` at
/// each of the four hops carrying the message from the filter result to the
/// builder, and ALL FOUR SURVIVED the full suite. The wires were present and the
/// assertions were not -- the end-to-end cell in `icmp_tests.rs` reads the code
/// byte on the input/lo0 path only, which holds every other path harmless by
/// construction. That is the "complete at both ends, connected by nothing" shape
/// this whole issue is about, so a structural argument that the hop is wired is
/// not enough; the byte has to be read off the reply.
#[test]
fn output_filter_reject_carries_the_configured_icmp_code_6854() {
    let _bucket_guard = crate::afxdp::icmp_ratelimit::global_bucket_test_lock();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let lookup = WorkerBindingLookup::default();
    let ingress_ident = BindingIdentity {
        slot: 7,
        queue_id: 3,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-1"),
        ifindex: 10,
    };
    let src_ip = Ipv4Addr::new(10, 0, 61, 100);
    let dst_ip = Ipv4Addr::new(172, 16, 80, 200);
    let src_port = 12345u16;
    let dst_port = 443u16;

    let mut frame = Vec::new();
    frame.extend_from_slice(&[
        0x02, 0xbf, 0x72, 0x00, 0x80, 0x08, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
    ]);
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x40, 0x00, 64, PROTO_UDP, 0x00, 0x00,
    ]);
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x08, 0x00, 0x00]);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_UDP,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(dst_ip)),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_UDP,
            src_ip: IpAddr::V4(src_ip),
            dst_ip: IpAddr::V4(dst_ip),
            src_port,
            dst_port,
        },
    };
    let mut forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-reject".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-reject".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "reject-web".into(),
                protocols: vec!["udp".into()],
                destination_ports: vec!["443".into()],
                action: "reject".into(),
                reject_message_type: "host-unreachable".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    // The ICMP reply is sourced from the INGRESS interface's primary address, so
    // without one `can_generate_icmp_error_reply` declines and nothing is built.
    // The premise assertion below turns that into a named failure rather than a
    // cell that reads an absent frame.
    forwarding.egress.insert(
        10,
        crate::afxdp::types::EgressInterface {
            bind_ifindex: 0,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
            zone_id: 0,
            redundancy_group: 0,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    let mut tx_pipeline = WorkerTxPipeline {
        free_tx_frames: (0..256u64).collect(),
        pending_tx_prepared: std::collections::VecDeque::new(),
        pending_tx_local: std::collections::VecDeque::new(),
        max_pending_tx: 256,
        outstanding_tx: 0,
        pending_fill_frames: std::collections::VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    };
    let mut counters = BatchCounters::default();

    let req = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        None,
        None,
        None,
        Some(ForwardRejectReply {
            tx_pipeline: &mut tx_pipeline,
            counters: &mut counters,
        }),
        None,
    );

    assert!(
        req.is_none(),
        "a `then reject` output term must NOT forward the original packet"
    );
    assert_eq!(
        counters.filter_reject_sent, 1,
        "#6854 PREMISE: the output-filter reject must enqueue exactly one reply. If this \
         is 0 the assertion below reads a frame that was never built and proves nothing"
    );
    let reply = tx_pipeline
        .pending_tx_local
        .front()
        .expect("#6854: the ICMP reject reply must be queued on the ingress TX pipeline");
    let (ty, code) = icmp_type_code_v4_6854(&reply.bytes);
    assert_eq!(
        (ty, code),
        (3, 1),
        "#6854: the OUTPUT-filter path must carry the term's message-type onto the wire -- \
         `host-unreachable` is ICMPv4 type 3 code 1. Code 13 means the hop from \
         CoSTxSelection.reject_message to the builder carries the default, which the whole \
         suite otherwise cannot see"
    );

    // PRECOMPUTED arm — the flow-cache FALLBACK path, a different hop.
    //
    // The call above passes `precomputed_tx_selection: None`, so the selection is
    // resolved fresh. When a cached descriptor IS supplied, the message-type is
    // carried across a separate assignment, and the mutation matrix showed that
    // one still free with the fresh path bound. Covering one arm and calling the
    // path tested is the exact mistake this cell exists to correct.
    let precomputed = crate::afxdp::tx::resolve_cached_cos_tx_selection(
        &forwarding,
        12,
        meta,
        Some(&flow.forward_key),
    );
    assert!(
        precomputed.reject,
        "#6854 PREMISE: the precomputed descriptor must classify as a reject, or the arm \
         below never reaches the reject-reply branch"
    );
    let mut tx_pipeline2 = WorkerTxPipeline {
        free_tx_frames: (0..256u64).collect(),
        pending_tx_prepared: std::collections::VecDeque::new(),
        pending_tx_local: std::collections::VecDeque::new(),
        max_pending_tx: 256,
        outstanding_tx: 0,
        pending_fill_frames: std::collections::VecDeque::new(),
        in_flight_prepared_recycles: FastMap::default(),
        tx_submit_ns: Vec::new().into_boxed_slice(),
    };
    let mut counters2 = BatchCounters::default();
    crate::afxdp::icmp_ratelimit::reset_bucket_for_test(
        crate::afxdp::icmp_ratelimit::GeneratedErrorReason::Reject,
        0,
    );
    let req2 = build_live_forward_request_from_frame(
        &lookup,
        2,
        &ingress_ident,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        &frame,
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        None,
        None,
        Some(&precomputed),
        Some(ForwardRejectReply {
            tx_pipeline: &mut tx_pipeline2,
            counters: &mut counters2,
        }),
        None,
    );
    assert!(
        req2.is_none(),
        "the precomputed reject must not forward the original packet either"
    );
    assert_eq!(
        counters2.filter_reject_sent, 1,
        "#6854 PREMISE: the precomputed arm must enqueue exactly one reply"
    );
    let reply2 = tx_pipeline2
        .pending_tx_local
        .front()
        .expect("#6854: the precomputed ICMP reject reply must be queued");
    assert_eq!(
        icmp_type_code_v4_6854(&reply2.bytes),
        (3, 1),
        "#6854: the PRECOMPUTED (flow-cache fallback) path must carry the message-type too. \
         Code 13 here means a flow-cache fallback silently downgrades an operator's \
         `then reject host-unreachable` to administratively-prohibited"
    );
}

/// Read (type, code) from the ICMPv4 payload of a built reply frame.
///
/// Walks the L2/L3 headers rather than indexing a fixed offset, so a VLAN tag or
/// an IP options change cannot silently make this read the wrong bytes.
fn icmp_type_code_v4_6854(frame: &[u8]) -> (u8, u8) {
    let mut off = 14usize;
    if frame.len() > 13 && u16::from_be_bytes([frame[12], frame[13]]) == 0x8100 {
        off += 4;
    }
    assert!(frame.len() > off, "frame too short for an IPv4 header");
    let ihl = usize::from(frame[off] & 0x0f) * 4;
    let icmp = off + ihl;
    assert!(
        frame.len() > icmp + 1,
        "frame too short for an ICMP type/code at offset {icmp}"
    );
    (frame[icmp], frame[icmp + 1])
}

/// #3642 forward leg: a SNAT'd transit flow's egress `filter output` must match
/// the TRANSLATED (post-NAT) SOURCE address, because Junos applies output
/// filters AFTER NAT. The filter discards TCP `from source-address 172.16.80.8`
/// (the SNAT pool address); the pre-NAT source is 10.0.61.100. With the fix,
/// `build_live_forward_request_from_frame` evaluates the output filter against
/// the post-NAT wire key (`forward_wire_key`, src 172.16.80.8) so the discard
/// term matches and the packet is dropped (`req` None). On revert the eval uses
/// the pre-NAT tuple (src 10.0.61.100), which the term does NOT match -> the
/// packet forwards -> `req` Some -> RED.
#[test]
fn output_filter_matches_post_snat_source_forward_leg_3642() {
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        // SNAT: source rewritten to the pool address on the wire.
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 443,
        },
    };
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth0.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "wan-drop-src".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-drop-src".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-snat-src".into(),
                protocols: vec!["tcp".into()],
                source_addresses: vec!["172.16.80.8/32".into()],
                source_constrained: true,
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    // Counter-factual: the PRE-NAT source key does NOT match the discard term.
    let pre_nat = resolve_cos_tx_selection_at(
        &forwarding,
        12,
        meta,
        Some(&flow.forward_key),
        crate::filter::TermMatchExtra::default(),
        123,
    );
    assert!(
        !pre_nat.drop,
        "pre-NAT src 10.0.61.100 must NOT match `source-address 172.16.80.8/32` \
         (documents the #3642 bug the fix removes)"
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &frag_test_ingress_ident(),
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );
    assert!(
        req.is_none(),
        "SNAT'd flow: the output filter matching the TRANSLATED src 172.16.80.8 \
         must discard the packet; forwarding means it matched the pre-NAT tuple \
         (#3642)"
    );
}


/// #3642 reverse leg: for the SNAT reply the flow's `forward_key` is the reply's
/// own ingress tuple (src = responder, dst = the SNAT address). The reverse
/// `decision.nat` restores the original client address (rewrite_dst =
/// 10.0.61.100), and `apply_nat_ipv4` writes that to the frame — so
/// `forward_wire_key` yields the egress reply tuple (dst 10.0.61.100). An egress
/// (LAN-side) output filter `from destination-address 10.0.61.100` must match
/// the restored destination. On revert the eval sees the pre-de-NAT dst
/// (172.16.80.8) and does NOT match -> forwards -> RED. Proves the fix is
/// direction-correct (no separate reverse_wire_key needed).
#[test]
fn output_filter_matches_post_snat_dest_reverse_leg_3642() {
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 61,
        },
        // Reverse of the SNAT: restore the original client as the wire dst.
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100))),
            ..NatDecision::default()
        },
    };
    // Reply ingress tuple: responder -> the SNAT pool address.
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 443,
            dst_port: 12345,
        },
    };
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "lan-drop-dst".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "lan-drop-dst".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-client-dst".into(),
                protocols: vec!["tcp".into()],
                destination_addresses: vec!["10.0.61.100/32".into()],
                destination_constrained: true,
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let pre_nat = resolve_cos_tx_selection_at(
        &forwarding,
        12,
        meta,
        Some(&flow.forward_key),
        crate::filter::TermMatchExtra::default(),
        123,
    );
    assert!(
        !pre_nat.drop,
        "pre-de-NAT dst 172.16.80.8 must NOT match `destination-address \
         10.0.61.100/32` (documents the reverse-leg #3642 bug)"
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &frag_test_ingress_ident(),
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );
    assert!(
        req.is_none(),
        "SNAT reply: the LAN output filter matching the RESTORED dst 10.0.61.100 \
         must discard; forwarding means it matched the pre-de-NAT dst (#3642 \
         reverse leg)"
    );
}


/// #3642 DNAT: a DNAT'd flow's egress `filter output` must match the TRANSLATED
/// (post-DNAT) DESTINATION. The filter discards TCP `to destination-address
/// 10.0.61.50` (the internal server); the pre-NAT dst is the public VIP
/// 203.0.113.5. With the fix the output filter sees the post-DNAT wire dst
/// (10.0.61.50) and discards; on revert it sees 203.0.113.5 and forwards -> RED.
#[test]
fn output_filter_matches_post_dnat_dest_3642() {
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 10,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        pkt_len: 60,
        ..UserspaceDpMeta::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 11,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50))),
            neighbor_mac: Some([0xba, 0x86, 0xe9, 0xf6, 0x4b, 0xd5]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 61,
        },
        // DNAT: destination rewritten to the internal server on the wire.
        nat: NatDecision {
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 50))),
            ..NatDecision::default()
        },
    };
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            src_port: 40000,
            dst_port: 443,
        },
    };
    let forwarding = build_forwarding_state(&ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "reth1.0".into(),
            ifindex: 12,
            hardware_addr: "02:bf:72:00:80:08".into(),
            filter_output_v4: "lan-drop-dnat".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "lan-drop-dnat".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "drop-internal-dst".into(),
                protocols: vec!["tcp".into()],
                destination_addresses: vec!["10.0.61.50/32".into()],
                destination_constrained: true,
                action: "discard".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    });
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );

    let pre_nat = resolve_cos_tx_selection_at(
        &forwarding,
        12,
        meta,
        Some(&flow.forward_key),
        crate::filter::TermMatchExtra::default(),
        123,
    );
    assert!(
        !pre_nat.drop,
        "pre-DNAT dst 203.0.113.5 must NOT match `destination-address \
         10.0.61.50/32` (documents the DNAT #3642 bug)"
    );

    let req = build_live_forward_request_from_frame(
        &WorkerBindingLookup::default(),
        2,
        &frag_test_ingress_ident(),
        XdpDesc {
            addr: 0,
            len: 0,
            options: 0,
        },
        &[],
        meta,
        &decision,
        &forwarding,
        Some(&flow),
        None,
        false,
        123,
        Some(&event_handle),
        None,
        None,
        None,
        // #5606: non-NAT64 test flow — no reverse info.
        None,
    );
    assert!(
        req.is_none(),
        "DNAT'd flow: the output filter matching the TRANSLATED dst 10.0.61.50 \
         must discard; forwarding means it matched the pre-NAT VIP (#3642)"
    );
}


#[test]
fn icmp_reverse_key_keeps_identifier_position() {
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_ICMP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let reverse = flow.reverse_key_with_nat(NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        ..NatDecision::default()
    });
    assert_eq!(reverse.src_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)));
    assert_eq!(reverse.dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)));
    assert_eq!(reverse.src_port, 0x1234);
    assert_eq!(reverse.dst_port, 0);
}


#[test]
fn synced_replica_entry_keeps_peer_synced_entries_promotable() {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };
    let replica = synced_replica_entry(&entry);
    assert!(replica.origin.is_peer_synced());
    assert!(replica.origin.is_promotable_synced());
    assert_eq!(replica.key, entry.key);
    assert_eq!(replica.decision, entry.decision);
}


#[test]
fn synced_replica_entry_marks_local_entries_worker_local() {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };
    let replica = synced_replica_entry(&entry);
    assert_eq!(replica.origin, SessionOrigin::WorkerLocalImport);
    assert!(replica.origin.is_peer_synced());
    assert!(!replica.origin.is_promotable_synced());
    assert_eq!(replica.key, entry.key);
    assert_eq!(replica.decision, entry.decision);
}


#[test]
fn reconcile_stop_preserves_shared_synced_sessions() {
    let mut coordinator = Coordinator::new();
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };
    publish_shared_session(
        &coordinator.sessions.synced,
        &coordinator.sessions.nat,
        &coordinator.sessions.forward_wire,
        &coordinator.sessions.owner_rg_indexes,
        &entry,
    );

    coordinator.stop_inner(false);

    let preserved = coordinator.snapshot_shared_session_entries();
    assert_eq!(preserved.len(), 1);
    assert_eq!(preserved[0].key, entry.key);
    assert_eq!(preserved[0].decision, entry.decision);

    coordinator.stop();
    assert!(coordinator.snapshot_shared_session_entries().is_empty());
}


#[test]
fn replay_synced_sessions_requeues_preserved_entries_for_new_workers() {
    let coordinator = Coordinator::new();
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
        decision: SessionDecision {
            resolution: lookup_forwarding_resolution(
                &build_forwarding_state(&nat_snapshot()),
                IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            ),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
    };
    let worker_command_queues = BTreeMap::from([
        (0u32, Arc::new(Mutex::new(VecDeque::new()))),
        (1u32, Arc::new(Mutex::new(VecDeque::new()))),
    ]);

    let replayed = coordinator.replay_synced_sessions(&[entry.clone()], &worker_command_queues, -1);
    assert_eq!(replayed, 1);

    for commands in worker_command_queues.values() {
        let pending = commands.lock().expect("worker command queue");
        assert_eq!(pending.len(), 1);
        match pending.front().expect("queued command") {
            WorkerCommand::UpsertSynced(replayed_entry) => {
                assert_eq!(replayed_entry.key, entry.key);
                assert!(replayed_entry.origin.is_peer_synced());
            }
            other => panic!("unexpected command queued during replay: {other:?}"),
        }
    }
}


#[test]
fn resolution_target_uses_rewritten_destination_for_reverse_dnat() {
    let flow = SessionFlow {
        src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
        dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6("2001:559:8585:80::200".parse().expect("src")),
            dst_ip: IpAddr::V6("2001:559:8585:80::8".parse().expect("dst")),
            src_port: 0x1234,
            dst_port: 0,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 5,
            tx_ifindex: 5,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V6(
                "2001:559:8585:ef00::100".parse().expect("next hop"),
            )),
            neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision {
            rewrite_src: None,
            rewrite_dst: Some(IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))),
            ..NatDecision::default()
        },
    };
    assert_eq!(
        resolution_target_for_session(&flow, decision),
        IpAddr::V6("2001:559:8585:ef00::100".parse().expect("lan"))
    );
}


#[test]
fn session_resolution_falls_back_to_cached_neighbor_on_miss() {
    let mut state = build_forwarding_state(&nat_snapshot());
    state.neighbors.clear();
    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 12345,
            dst_port: 5201,
        },
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 0,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &Arc::new(ShardedNeighborMap::new()),
        &flow,
        decision,
    );
    let expected_src = state
        .egress
        .get(&12)
        .map(|egress| egress.src_mac)
        .expect("egress src mac");
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 12);
    assert_eq!(resolved.tx_ifindex, 11);
    assert_eq!(resolved.neighbor_mac, decision.resolution.neighbor_mac);
    assert_eq!(resolved.src_mac, Some(expected_src));
    assert_eq!(resolved.tx_vlan_id, 80);
}


#[test]
fn build_forwarded_frame_rewrites_l2_and_decrements_ttl() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );

    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8, 8,
        0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    let out = build_forwarded_frame(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution,
            nat: NatDecision::default(),
        },
        &state,
        None,
    )
    .expect("forwarded frame");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(out[22], 63);
}


#[test]
fn rewrite_forwarded_frame_in_place_reuses_rx_frame() {
    let state = build_forwarding_state(&forwarding_snapshot(true));
    let resolution = lookup_forwarding_resolution(&state, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 192, 0, 2, 10, 8, 8, 8, 8, 8,
        0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    let rewrite_result = rewrite_forwarded_frame_in_place(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution,
            nat: NatDecision::default(),
        },
        false,
        None,
    )
    .expect("in-place forward");
    let out = area
        .slice(rewrite_result.offset as usize, rewrite_result.len as usize)
        .expect("rewritten frame");
    assert_eq!(&out[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]);
    assert_eq!(u16::from_be_bytes([out[12], out[13]]), 0x0800);
    assert_eq!(out[22], 63);
}


#[test]
fn build_forwarded_frame_uses_fabric_header_without_nat() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let mut frame = Vec::new();
    write_eth_header(
        &mut frame,
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0x00, 0x25, 0x90, 0x12, 0x34, 0x56],
        0,
        0x0800,
    );
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 1, 0, 0, 10, 0, 61, 100, 172, 16, 80,
        200, 8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01,
    ]);
    let sum = checksum16(&frame[14..34]);
    frame[24] = (sum >> 8) as u8;
    frame[25] = sum as u8;

    let mut area = MmapArea::new(4096).expect("mmap");
    area.slice_mut(0, frame.len())
        .expect("slice")
        .copy_from_slice(&frame);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        addr_family: libc::AF_INET as u8,
        ..UserspaceDpMeta::default()
    };
    let out = build_forwarded_frame(
        &area,
        XdpDesc {
            addr: 0,
            len: frame.len() as u32,
            options: 0,
        },
        meta,
        &SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        },
        &state,
        None,
    )
    .expect("fabric frame");
    assert_eq!(&out[0..6], &[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!(&out[6..12], &[0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]);
    assert_eq!(&out[26..30], &[10, 0, 61, 100]);
    assert_eq!(out[22], 63);
}

// --- Static NAT integration tests ---


#[test]
fn static_nat_external_ip_recognized_as_local() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // The external IP 203.0.113.10 should be in local_v4 so traffic
    // destined to it is recognized by the firewall.
    assert!(
        state
            .local_v4
            .contains(&"203.0.113.10".parse::<Ipv4Addr>().unwrap()),
        "static NAT external IP must be in local_v4"
    );
}


#[test]
fn static_nat_dnat_routes_to_internal_ip() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // Simulate inbound: packet from 198.51.100.1 -> 203.0.113.10
    // The static NAT DNAT should match and the resolution should route
    // to the internal host 192.168.1.10 (on trust interface ifindex=5).
    let dnat = state
        .static_nat
        .match_dnat("203.0.113.10".parse().unwrap(), "untrust");
    assert!(dnat.is_some(), "DNAT must match external IP from untrust");
    let dnat = dnat.unwrap();
    assert_eq!(
        dnat.rewrite_dst,
        Some("192.168.1.10".parse::<IpAddr>().unwrap())
    );

    // After DNAT translation, resolution target is internal IP
    let internal_ip: IpAddr = "192.168.1.10".parse().unwrap();
    let resolution =
        lookup_forwarding_resolution_with_dynamic(&state, &Default::default(), internal_ip);
    // Should resolve to trust interface (ifindex 5) via connected route
    assert_eq!(resolution.egress_ifindex, 5);
}


#[test]
fn static_nat_snat_rewrites_outbound_source() {
    let state = build_forwarding_state(&static_nat_snapshot());
    // Simulate outbound: packet from 192.168.1.10 -> 198.51.100.1
    // egressing TOWARD the rule's external `from zone` (untrust). Static NAT
    // SNAT should rewrite src to external IP 203.0.113.10.
    // #2871: the SNAT match is gated on the EGRESS (destination) zone equalling
    // the rule's external `from zone` ("untrust" in static_nat_snapshot()).
    let snat = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "untrust");
    assert!(
        snat.is_some(),
        "SNAT should match internal IP when egressing toward the external zone"
    );
    assert_eq!(
        snat.unwrap().rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
}


#[test]
fn static_nat_snat_matches_when_zone_is_empty() {
    // Create a snapshot where from_zone is empty (matches any zone)
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "web-server".to_string(),
        from_zone: String::new(), // matches any zone
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }];
    let state = build_forwarding_state(&snapshot);

    // Now SNAT should match from any zone
    let snat = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(snat.is_some());
    let snat = snat.unwrap();
    assert_eq!(
        snat.rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
    assert!(snat.rewrite_dst.is_none());
}


#[test]
fn static_nat_takes_priority_over_interface_snat() {
    // Create snapshot with both static NAT and interface SNAT
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "static-web".to_string(),
        from_zone: String::new(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: "203.0.113.10".to_string(),
        internal_ip: "192.168.1.10".to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }];
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "interface-snat".to_string(),
        from_zone: "trust".to_string(),
        to_zone: "untrust".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snapshot);

    // For src=192.168.1.10, static NAT should match first
    let static_match = state
        .static_nat
        .match_snat("192.168.1.10".parse().unwrap(), "trust");
    assert!(
        static_match.is_some(),
        "static NAT should match internal IP"
    );
    assert_eq!(
        static_match.unwrap().rewrite_src,
        Some("203.0.113.10".parse::<IpAddr>().unwrap())
    );
}


#[test]
fn static_nat_v6_dnat_and_snat() {
    let mut snapshot = static_nat_snapshot();
    snapshot.static_nat_rules = vec![StaticNATRuleSnapshot {
        source_addresses: Vec::new(),
        counter_id: 0,
        name: "v6-server".to_string(),
        from_zone: String::new(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        external_ip: "2001:db8::10".to_string(),
        internal_ip: "fd00::10".to_string(),
        match_destination_port: 0,
        mapped_port: 0,
    }];
    // Add v6 addresses to interfaces
    snapshot.interfaces[0]
        .addresses
        .push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "fd00::1/64".to_string(),
            scope: 0,
        });
    snapshot.interfaces[1]
        .addresses
        .push(InterfaceAddressSnapshot {
            family: "inet6".to_string(),
            address: "2001:db8::1/64".to_string(),
            scope: 0,
        });
    let state = build_forwarding_state(&snapshot);

    // External v6 IP should be in local_v6
    assert!(
        state
            .local_v6
            .contains(&"2001:db8::10".parse::<Ipv6Addr>().unwrap())
    );

    // DNAT match
    let dnat = state
        .static_nat
        .match_dnat("2001:db8::10".parse().unwrap(), "any-zone");
    assert!(dnat.is_some());
    assert_eq!(
        dnat.unwrap().rewrite_dst,
        Some("fd00::10".parse::<IpAddr>().unwrap())
    );

    // SNAT match
    let snat = state
        .static_nat
        .match_snat("fd00::10".parse().unwrap(), "trust");
    assert!(snat.is_some());
    assert_eq!(
        snat.unwrap().rewrite_src,
        Some("2001:db8::10".parse::<IpAddr>().unwrap())
    );
}


#[test]
fn post_dnat_source_nat_matches_translated_destination() {
    let mut snapshot = nat_snapshot();
    snapshot.source_nat_rules = vec![SourceNATRuleSnapshot {
        name: "twice-snat".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        destination_addresses: vec!["10.0.61.102/32".to_string()],
        interface_mode: true,
        ..Default::default()
    }];
    snapshot.destination_nat_rules = vec![DestinationNATRuleSnapshot {
        counter_id: 0,
        name: "web-dnat".to_string(),
        from_zone: "wan".to_string(),
        from_interface: String::new(),
        from_routing_instance: String::new(),
        source_addresses: vec![],
        destination_address: "172.16.80.8".to_string(),
        destination_prefix: String::new(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.61.102".to_string(),
        pool_port: 8443,
        match_source_ports: vec![],
        match_destination_ports: vec![],
        match_icmp_type: None,
        match_icmp_code: None,
        off: false,
    }];
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "allow-inbound".to_string(),
        from_zone: "wan".to_string(),
        to_zone: "lan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "permit".to_string(),
        ..Default::default()
    });

    let state = build_forwarding_state(&snapshot);
    assert!(
        state
            .local_v4
            .contains(&"172.16.80.8".parse::<Ipv4Addr>().unwrap())
    );

    let flow = SessionFlow {
        src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)),
            src_port: 54321,
            dst_port: 443,
        },
    };
    let dnat = state
        .dnat_table
        .lookup(PROTO_TCP, flow.src_ip, flow.dst_ip, 443, "wan")
        .expect("dnat");
    assert_eq!(
        dnat.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(dnat.rewrite_dst_port, Some(8443));

    let translated_flow = flow.with_destination(dnat.rewrite_dst.unwrap());
    let snat = match_source_nat_for_flow(&state, 0, "wan", "lan", 24, &translated_flow)
        .expect("snat after dnat");
    assert_eq!(
        snat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)))
    );

    let merged = dnat.merge(snat);
    assert_eq!(
        merged.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)))
    );
    assert_eq!(
        merged.rewrite_dst,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(merged.rewrite_dst_port, Some(8443));
}

