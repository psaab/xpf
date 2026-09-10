// embedded-ICMP NAT matching and poll-descriptor policy/input-filter paths.
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
use crate::session::TunnelDiscriminator;

#[test]
fn no_match_embedded_icmp_returns_none() {
    // An ICMP error with no matching session should return None
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, 40000, 80, PROTO_TCP);

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

    let mut sessions = SessionTable::new();
    // Don't install any sessions
    let result = try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 1_000_000, 0);
    assert!(
        result.is_none(),
        "should return None when no session matches"
    );
}


#[test]
fn embedded_icmp_nat_match_uses_shared_nat_session_for_ipv4() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
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

    let mut sessions = SessionTable::new();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        tcp_close_class: 0,
    };
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("shared NAT session should match embedded ICMP");

    assert_eq!(icmp_match.original_src, IpAddr::V4(client_ip));
    assert_eq!(icmp_match.original_src_port, client_port);
    assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V4(snat_ip)));
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(icmp_match.resolution.tx_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}


/// #2393: a NAT44-transit ICMPv4 Redirect (type 5) — like Time Exceeded
/// (11) / Dest Unreachable (3) — quotes the offending datagram and MUST
/// have its embedded inner addresses translated back to the pre-NAT
/// tuple. Before #2393 the embedded-NAT `is_icmp_error` arm omitted 5, so
/// the match returned None and the quoted inner kept the post-SNAT
/// address (mismatched at the host). This test installs the SNAT session,
/// flips an otherwise-identical TE frame to a Redirect, and asserts the
/// match + reversed-frame build rewrite the embedded src to the client.
#[test]
fn embedded_icmp_nat_match_translates_redirect_v4() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    // ICMPv4 Redirect (5) carrying the SNAT'd inner tuple, then flip from
    // the shared type-11 builder to type 5. Unlike Time Exceeded (whose
    // bytes 4..8 are an unused word), a Redirect carries the better-gateway
    // address there; set a distinctive non-zero sentinel so the test
    // exercises a realistic Redirect AND can prove the embedded-NAT rewrite
    // (at l4+8) leaves the gateway field (l4+4..8) untouched. Set the
    // gateway BEFORE `rewrite_outer_icmpv4_type`, which recomputes the ICMP
    // checksum over the whole header so the frame stays valid.
    const REDIRECT_GATEWAY: [u8; 4] = [192, 0, 2, 1]; // RFC 5737 TEST-NET-1
    let mut frame =
        build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
    frame[38..42].copy_from_slice(&REDIRECT_GATEWAY); // ICMP bytes 4..8 = gateway
    rewrite_outer_icmpv4_type(&mut frame, 34, 5);
    assert_eq!(frame[34], 5, "outer ICMP type must be Redirect");
    assert_eq!(&frame[38..42], &REDIRECT_GATEWAY, "gateway set in input frame");

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

    let mut sessions = SessionTable::new();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    // Forward-NAT session: client:port -> server:80, SNAT to snat_ip:snat_port.
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(client_ip)),
                neighbor_mac: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 0,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        1_000_000,
        PROTO_TCP,
        0,
    ));

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("#2393: NAT44 Redirect must match the embedded session for reversal");

    assert_eq!(icmp_match.original_src, IpAddr::V4(client_ip));
    assert_eq!(icmp_match.original_src_port, client_port);

    // Build the reversed frame and confirm BOTH the outer dst and the
    // embedded inner src are translated back to the pre-NAT client.
    let result = build_nat_reversed_icmp_error_v4(&frame, meta, &icmp_match)
        .expect("#2393: reversed Redirect frame must build");
    assert_eq!(result[34], 5, "reversed frame stays a Redirect");
    let outer_dst = Ipv4Addr::new(result[30], result[31], result[32], result[33]);
    assert_eq!(outer_dst, client_ip, "outer dst restored to client");
    // Embedded IP starts at eth(14) + outer IP(20) + ICMP(8) = 42; src at +12.
    let embedded_src = Ipv4Addr::new(result[54], result[55], result[56], result[57]);
    assert_eq!(
        embedded_src, client_ip,
        "embedded inner src must be translated from SNAT addr back to client"
    );
    // The Redirect-specific invariant: the gateway-address field (ICMP
    // bytes 4..8 = frame offset 38..42, before the quoted IP at l4+8=42)
    // must survive the embedded-NAT rewrite byte-for-byte. The rewrite
    // touches only the quoted inner packet at l4+8 and the outer IP — never
    // the type-specific header word. This assertion FAILS if the rewrite is
    // ever changed to write into l4+4..8.
    assert_eq!(
        &result[38..42],
        &REDIRECT_GATEWAY,
        "Redirect gateway address must be preserved through embedded-NAT rewrite"
    );
}


#[test]
fn embedded_icmp_nat_match_ignores_non_error_echo() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
    let frame = build_icmp_echo_frame_v4(client_ip, dst_ip, 64);

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

    let mut sessions = SessionTable::new();
    let forwarding = ForwardingState::default();
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let result = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    );
    assert!(
        result.is_none(),
        "non-error ICMP echo should not trigger embedded NAT reversal"
    );
}

/// #5690 LITERAL fail-on-revert: drive an inbound NAT44 SNAT ICMP error
/// (Time Exceeded, addressed to the firewall's SNAT address) through the REAL
/// `poll_binding_process_descriptor` control flow — NOT the helper fn — and
/// prove the inner quoted packet is reverse-translated back to the pre-NAT
/// client on the production path.
///
/// The error is a non-query ICMP type, so `parse_session_flow_from_bytes`
/// (#3290) returns None and the packet is FLOWLESS: it never enters the
/// flow-backed session-miss arm where the generic embedded-ICMP NAT reversal
/// historically lived. Before #5690 that made the reversal unreachable in
/// production (helper-tested but dead). This test drives the flowless arm and
/// asserts the reversed error is queued as a prebuilt forward toward the
/// client with BOTH the outer destination and the embedded inner source
/// translated from the SNAT address back to the real client.
///
/// Fail-on-revert: remove the `try_reverse_embedded_icmp_error` call from the
/// flowless arm and the error takes normal flowless enforcement (LocalDelivery
/// reinject) — no prebuilt reversed forward is queued, so `scratch_forwards`
/// is empty and this test goes RED.
#[test]
fn poll_descriptor_embedded_icmp_reversal_reachable_on_flowless_path_5690() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    // Outer: router -> snat_ip; embedded quoted: snat_ip:snat_port -> server:80.
    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    // allow_embedded_icmp gates the poll-path reversal — enable it.
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    let forwarding = build_forwarding_state(&snapshot);

    // The error ingresses on the WAN (reth0.80, ifindex 12) since it is
    // addressed to the SNAT address; the reversal resolves egress toward the
    // client on the LAN (reth1.0, ifindex 24), so learn the client neighbor.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");

    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    // Neighbor toward the client on the LAN unit so the reversed error resolves
    // a tx interface + MAC (egress ifindex 24).
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Install the forward NAT session (client:client_port -> server:80 SNAT'd
    // to snat_ip:snat_port) so the embedded reversal can recover the client.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let sessions_before = sessions.len();

    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    // The load-bearing #5690 assertion: the ICMP error was reverse-translated on
    // the REAL poll path and queued as a prebuilt forward toward the client.
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "embedded-ICMP NAT reversal must queue exactly one reversed forward on \
         the flowless poll path (RED on revert: no forward is queued)"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let reversed = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("embedded-ICMP reversal must queue a PREBUILT reversed frame"),
    };
    assert_eq!(reversed[34], 11, "reversed frame stays an ICMP Time Exceeded");
    let outer_dst = Ipv4Addr::new(reversed[30], reversed[31], reversed[32], reversed[33]);
    assert_eq!(
        outer_dst, client_ip,
        "outer destination must be restored from the SNAT address to the client"
    );
    // Embedded IP at eth(14)+outerIP(20)+ICMP(8)=42; inner src at +12 = 54.
    let embedded_src = Ipv4Addr::new(reversed[54], reversed[55], reversed[56], reversed[57]);
    assert_eq!(
        embedded_src, client_ip,
        "embedded inner source must be reverse-translated from SNAT addr to client"
    );
    // Inner TCP source port at 42+20 = 62 restored to the pre-NAT client port.
    let embedded_src_port = u16::from_be_bytes([reversed[62], reversed[63]]);
    assert_eq!(
        embedded_src_port, client_port,
        "embedded inner source port must be reverse-translated to the client port"
    );
    // #5690: the non-query error must NOT become a session/cache authority.
    assert!(
        fwd.flow_key.is_none(),
        "reversed ICMP error must carry flow_key=None (never seeds a session)"
    );
    // Egress resolves toward the client on the LAN unit (ifindex 24).
    assert_eq!(fwd.target_ifindex, 24, "reversed error egresses toward the client");
    // The error is stateless: it seeds no new session and is not recycled here.
    assert_eq!(
        sessions.len(),
        sessions_before,
        "the ICMP error must not seed a new session"
    );
    assert!(
        binding.scratch.scratch_recycle.is_empty(),
        "a queued prebuilt forward owns the descriptor; no recycle"
    );
}

// ---------------------------------------------------------------------------
// #6472: NAT64 (cross-family) ICMP error translation on the flowless arm.
// ---------------------------------------------------------------------------

/// The IPv6 client, v4 server, NAT64 pool address, and translated port the
/// #6472 fixtures share. The synthetic destination is `64:ff9b::808:808`
/// (Pref64 ∷ 8.8.8.8) from the shared `nat64_snapshot` fixture.
const N6472_CLIENT_PORT: u16 = 12345;
const N6472_XLATED_PORT: u16 = 40000;
const N6472_SERVER_PORT: u16 = 443;

fn n6472_client_v6() -> Ipv6Addr {
    "2001:559:8585:ef00::102".parse().expect("client v6")
}
fn n6472_pref64_server() -> Ipv6Addr {
    "64:ff9b::808:808".parse().expect("Pref64::8.8.8.8")
}
fn n6472_server_v4() -> Ipv4Addr {
    Ipv4Addr::new(8, 8, 8, 8)
}
fn n6472_pool_v4() -> Ipv4Addr {
    Ipv4Addr::new(172, 16, 80, 50)
}
const N6472_CLIENT_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
const N6472_LAN_SRC_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x01, 0x00, 0x01];
const N6472_WAN_SRC_MAC: [u8; 6] = [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08];
const N6472_WAN_GW_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

/// Install the NAT64 forward session + its v4 reverse companion exactly as
/// the production cold path installs them (#4381/#5606): the forward key is
/// the original v6 5-tuple with the NAT64 forward decision; the reverse
/// companion is keyed on the v4 reply tuple `(server:port → pool:xlated)`
/// with `is_reverse = true`; BOTH halves carry `nat64_reverse`.
fn n6472_install_sessions(sessions: &mut SessionTable, now_ns: u64) {
    n6472_install_sessions_in_domain(sessions, now_ns, 0);
}

/// #9162: the same two halves, installed in routing domain `domain`. The
/// production cold path stamps `SessionKey.routing_domain` from the ingress
/// interface (`poll_descriptor/mod.rs`, the #7160 stamp site) and — since
/// #9033/#9271 — carries that same domain onto the NAT64 v4 reverse
/// companion, so a fixture that hardcodes 0 while the forwarding state has a
/// routing-instance membership no longer describes any real deployment.
fn n6472_install_sessions_in_domain(sessions: &mut SessionTable, now_ns: u64, domain: u32) {
    let fwd_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(n6472_pool_v4())),
        rewrite_dst: Some(IpAddr::V4(n6472_server_v4())),
        rewrite_src_port: Some(N6472_XLATED_PORT),
        rewrite_dst_port: None,
        nat64: true,
        nptv6: false,
    };
    let reverse_info = Nat64ReverseInfo {
        orig_src_v6: n6472_client_v6(),
        orig_dst_v6: n6472_pref64_server(),
    };
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(n6472_client_v6()),
            dst_ip: IpAddr::V6(n6472_pref64_server()),
            src_port: N6472_CLIENT_PORT,
            dst_port: N6472_SERVER_PORT,
                    discriminator: Default::default(),
                    routing_domain: domain,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some(N6472_WAN_GW_MAC),
                src_mac: Some(N6472_WAN_SRC_MAC),
                tx_vlan_id: 80,
            },
            nat: fwd_nat,
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: Some(reverse_info),
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        now_ns,
        PROTO_TCP,
        0x18,
    ));
    // The v4 reverse companion: keyed on the reply wire tuple, resolution
    // toward the v6 client on the LAN unit (reth1.0, ifindex 24).
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(n6472_server_v4()),
            dst_ip: IpAddr::V4(n6472_pool_v4()),
            src_port: N6472_SERVER_PORT,
            dst_port: N6472_XLATED_PORT,
                    discriminator: Default::default(),
                    routing_domain: domain,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 24,
                tx_ifindex: 24,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V6(n6472_client_v6())),
                neighbor_mac: Some(N6472_CLIENT_MAC),
                src_mac: Some(N6472_LAN_SRC_MAC),
                tx_vlan_id: 0,
            },
            nat: fwd_nat.reverse(
                IpAddr::V6(n6472_client_v6()),
                IpAddr::V6(n6472_pref64_server()),
                N6472_CLIENT_PORT,
                N6472_SERVER_PORT,
            ),
        },
        SessionMetadata {
            ingress_zone: TEST_WAN_ZONE_ID,
            egress_zone: TEST_LAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: Some(reverse_info),
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        now_ns,
        PROTO_TCP,
        0x18,
    ));
}

/// Flip the shared type-11 v4 fixture into a Packet-Too-Big-class
/// Fragmentation-Needed error (type 3 / code 4) carrying next-hop MTU 1400.
fn n6472_patch_ptb(frame: &mut [u8], l4_offset: usize) {
    frame[l4_offset] = 3;
    frame[l4_offset + 1] = 4;
    // RFC 1191 rest-of-header: [unused(2)][next-hop MTU(2)].
    frame[l4_offset + 4..l4_offset + 8].copy_from_slice(&[0, 0, 0x05, 0x78]);
    frame[l4_offset + 2] = 0;
    frame[l4_offset + 3] = 0;
    let csum = checksum16(&frame[l4_offset..]);
    frame[l4_offset + 2..l4_offset + 4].copy_from_slice(&csum.to_be_bytes());
}

/// #6472 FAIL-ON-REVERT (v4→v6, RFC 7915 §4.2): an ICMPv4 PTB from a v4 hop
/// addressed to the NAT64 pool address — quoting the session's FORWARD wire
/// packet `(pool:40000 → 8.8.8.8:443)` — must be translated on the REAL
/// flowless poll path into an ICMPv6 Packet-Too-Big toward the v6 client:
/// outer src = `64:ff9b::172.16.80.1` (Pref64 mapping of the error sender),
/// outer dst = the client, MTU = 1400 + 20, and the embedded quote reading
/// back as the ORIGINAL v6 forward packet `(client:12345 →
/// 64:ff9b::808:808:443)` — the source port RESTORED from the translated
/// pool value or the client cannot associate the error (PMTUD).
///
/// The reversal runs WITHOUT `allow_embedded_icmp` (left false here): NAT64
/// error translation for the translator's own sessions is core RFC 7915
/// behavior, not the optional same-family passthrough that flag gates.
///
/// Fail-on-revert: remove the `try_translate_nat64_icmp_error` call from
/// the flowless arm and the error takes normal flowless enforcement — no
/// prebuilt forward is queued (the pool address is not a local v4 socket),
/// so `scratch_forwards` is empty and the test goes RED.
#[test]
fn poll_descriptor_nat64_icmp_error_v4_to_v6_translated_on_flowless_path_6472() {
    let router_ip = Ipv4Addr::new(172, 16, 80, 1);
    let mut frame = build_icmp_te_frame_v4(
        router_ip,
        n6472_pool_v4(),
        n6472_server_v4(),
        N6472_XLATED_PORT,
        N6472_SERVER_PORT,
        PROTO_TCP,
    );
    n6472_patch_ptb(&mut frame, 34);

    // allow_embedded_icmp deliberately NOT set: the NAT64 arm is ungated.
    let forwarding = build_forwarding_state(&nat64_snapshot(lan_to_wan_permit(
        "8.8.8.8/32",
        "permit-nat64-v4",
    )));
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    n6472_install_sessions(&mut sessions, 123_000_000_000);
    let sessions_before = sessions.len();

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the NAT64 v4->v6 ICMP error translation must queue exactly one prebuilt \
         forward on the flowless poll path (RED on revert: no forward is queued)"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the NAT64 error translation must queue a PREBUILT frame"),
    };
    // L2: toward the client on the LAN unit (untagged, ethertype IPv6).
    assert_eq!(&out[0..6], &N6472_CLIENT_MAC, "eth dst = client MAC");
    assert_eq!(&out[6..12], &N6472_LAN_SRC_MAC, "eth src = LAN unit MAC");
    assert_eq!(&out[12..14], &[0x86, 0xdd], "ethertype IPv6");
    // Outer IPv6: src = Pref64::router (172.16.80.1 = ac10:5001), dst = client.
    let expect_router_v6: Ipv6Addr = "64:ff9b::ac10:5001".parse().expect("Pref64::router");
    assert_eq!(&out[14 + 8..14 + 24], &expect_router_v6.octets(), "outer src = Pref64::router");
    assert_eq!(
        &out[14 + 24..14 + 40],
        &n6472_client_v6().octets(),
        "outer dst = v6 client"
    );
    assert_eq!(out[14 + 6], PROTO_ICMPV6, "next header ICMPv6");
    assert_eq!(out[14 + 7], 63, "hop limit decremented once");
    // ICMPv6 PTB: type 2, code 0, MTU = 1400 + 20 = 1420.
    let icmp6 = &out[14 + 40..];
    assert_eq!(icmp6[0], 2, "ICMPv6 Packet Too Big type");
    assert_eq!(icmp6[1], 0, "PTB code 0");
    let mtu = u32::from_be_bytes([icmp6[4], icmp6[5], icmp6[6], icmp6[7]]);
    assert_eq!(mtu, 1420, "PTB MTU = v4 next-hop MTU + NAT64 header delta");
    // ICMPv6 checksum oracle over the translated message.
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&out[14 + 8..14 + 24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&out[14 + 24..14 + 40]).unwrap());
    assert_eq!(
        checksum16_ipv6(s6, d6, PROTO_ICMPV6, icmp6),
        0,
        "outer ICMPv6 checksum must verify"
    );
    // Embedded quote: the ORIGINAL v6 forward packet — client:12345 ->
    // Pref64::server:443. The quote's source port is RESTORED from the
    // translated pool port (40000) to the client's original (12345).
    let emb = &icmp6[8..];
    assert_eq!(&emb[8..24], &n6472_client_v6().octets(), "embedded src = client");
    assert_eq!(
        &emb[24..40],
        &n6472_pref64_server().octets(),
        "embedded dst = Pref64::server"
    );
    assert_eq!(
        &emb[40..42],
        &N6472_CLIENT_PORT.to_be_bytes(),
        "embedded src port restored to the ORIGINAL client port"
    );
    assert_eq!(
        &emb[42..44],
        &N6472_SERVER_PORT.to_be_bytes(),
        "embedded dst port untouched"
    );
    assert_eq!(fwd.target_ifindex, 24, "translated error egresses toward the client");
    assert!(fwd.flow_key.is_none(), "the error never seeds a session/flow-cache entry");
    assert_eq!(sessions.len(), sessions_before, "no new session minted");
    assert!(
        binding.scratch.scratch_recycle.is_empty(),
        "a queued prebuilt forward owns the descriptor; no recycle"
    );
}

/// #6472 FAIL-ON-REVERT (v6→v4, RFC 7915 §5.2): an ICMPv6 Time-Exceeded
/// from a v6 hop about the session's translated REPLY packet — addressed to
/// the synthetic `64:ff9b::808:808` and quoting `(64:ff9b::808:808:443 →
/// client:12345)` — must be translated on the flowless poll path into an
/// ICMPv4 Time-Exceeded toward the v4 server: outer src = the pool address
/// (the translator's own v4 identity for this session; the v6 hop has no
/// v4 mapping), outer dst = 8.8.8.8, and the embedded quote reading back as
/// the v4 reply the server sent `(8.8.8.8:443 → pool:40000)` — the
/// DESTINATION port RESTORED to the translated value or the server cannot
/// associate the error.
///
/// Fail-on-revert: remove the arm and the error is flowless-forwarded
/// UNTRANSLATED toward the IPv6 default route (ethertype stays 0x86dd and
/// the synthetic destination is on the wire) — every translated-content
/// assertion below goes RED.
#[test]
fn poll_descriptor_nat64_icmp_error_v6_to_v4_translated_on_flowless_path_6472() {
    let lan_router: Ipv6Addr = "2001:559:8585:ef00::fe".parse().expect("lan v6 router");
    let frame = build_icmpv6_te_frame(
        lan_router,
        n6472_pref64_server(),
        n6472_client_v6(),
        N6472_SERVER_PORT,
        N6472_CLIENT_PORT,
        PROTO_TCP,
    );

    let forwarding = build_forwarding_state(&nat64_snapshot(lan_to_wan_permit(
        "8.8.8.8/32",
        "permit-nat64-v4",
    )));
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    n6472_install_sessions(&mut sessions, 123_000_000_000);
    let sessions_before = sessions.len();

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 62,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the NAT64 v6->v4 ICMP error translation must queue exactly one prebuilt forward"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the NAT64 error translation must queue a PREBUILT frame"),
    };
    // L2: toward the WAN gateway, VLAN 80 tagged (18-byte eth header).
    assert_eq!(&out[0..6], &N6472_WAN_GW_MAC, "eth dst = WAN gateway MAC");
    assert_eq!(&out[6..12], &N6472_WAN_SRC_MAC, "eth src = WAN unit MAC");
    assert_eq!(&out[12..14], &[0x81, 0x00], "802.1Q tag present (VLAN 80)");
    assert_eq!(&out[16..18], &[0x08, 0x00], "ethertype IPv4 after the tag");
    let ip = &out[18..];
    // Outer IPv4: src = pool (translator identity), dst = server, TTL 63.
    assert_eq!(&ip[12..16], &n6472_pool_v4().octets(), "outer src = pool address");
    assert_eq!(&ip[16..20], &n6472_server_v4().octets(), "outer dst = v4 server");
    assert_eq!(ip[8], 63, "TTL decremented once");
    assert_eq!(ip[9], PROTO_ICMP, "protocol ICMPv4");
    assert_eq!(checksum16(&ip[..20]), 0, "outer IPv4 header checksum verifies");
    // ICMPv4 Time-Exceeded: type 11, code 0.
    let icmp = &ip[20..];
    assert_eq!(icmp[0], 11, "ICMPv4 Time Exceeded type");
    assert_eq!(icmp[1], 0, "code 0");
    // Embedded quote: the v4 reply the server sent — 8.8.8.8:443 ->
    // pool:40000. The quote's DESTINATION port is RESTORED to the translated
    // value (the server never saw the client's original 12345).
    let emb = &icmp[8..];
    assert_eq!(&emb[12..16], &n6472_server_v4().octets(), "embedded src = server");
    assert_eq!(&emb[16..20], &n6472_pool_v4().octets(), "embedded dst = pool");
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum verifies");
    assert_eq!(
        &emb[20..22],
        &N6472_SERVER_PORT.to_be_bytes(),
        "embedded src port untouched"
    );
    assert_eq!(
        &emb[22..24],
        &N6472_XLATED_PORT.to_be_bytes(),
        "embedded dst port restored to the TRANSLATED pool port"
    );
    assert_eq!(fwd.target_ifindex, 12, "translated error egresses toward the server");
    assert!(fwd.flow_key.is_none());
    assert_eq!(sessions.len(), sessions_before, "no new session minted");
    assert!(binding.scratch.scratch_recycle.is_empty());
}

// ---------------------------------------------------------------------------
// #9162: the SAME two NAT64 ICMP-error translations, in a NON-DEFAULT routing
// instance.
//
// The two `_6472` cells above run on a snapshot with no routing-instance
// membership, so `ingress_routing_domain` resolves 0 on both sides and every
// key in the path agrees at 0 by accident. That is the blind spot #9033's own
// commit message recorded ("no cell in the tree combines NAT64 with an ICMP
// error AND routing domains"), and it is why the V4->V6 arm could regress
// under #9271 with the whole suite green.
//
// The cells below are the SAME drivers with one variable changed — the routing
// domain — so a red at domain 7 beside a green at domain 0 is attributable to
// the domain and to nothing else.
// ---------------------------------------------------------------------------

/// `nat64_snapshot` with every interface a member of routing instance
/// `domain`. Domain 0 reproduces `nat64_snapshot` exactly (the field's
/// default), which is what makes the reference arm below a true control
/// rather than a different fixture.
fn n9162_nat64_snapshot_in_domain(policy: PolicyRuleSnapshot, domain: u32) -> ConfigSnapshot {
    let mut snapshot = nat64_snapshot(policy);
    for iface in snapshot.interfaces.iter_mut() {
        iface.routing_domain = domain;
    }
    snapshot
}

/// What the flowless arm produced, reduced to the facts both directions'
/// assertions read. Captured rather than asserted inside the driver so the
/// domain-0 reference arm and the domain-7 arm share one assertion body.
struct N9162Outcome {
    forwards: usize,
    prebuilt: Option<Vec<u8>>,
    target_ifindex: i32,
    flow_key_none: bool,
    sessions_delta: i64,
    recycles: usize,
}

/// Drive the v4->v6 (RFC 7915 4.2) arm with everything in routing instance
/// `domain`. Asserts the FIXTURE precondition — that the domain the poll loop
/// would stamp really is `domain` — because a fixture whose interfaces carry a
/// routing instance the forwarding build dropped would make every cell below
/// vacuous in exactly the way #9033's were.
fn n9162_run_v4_to_v6(domain: u32) -> N9162Outcome {
    let router_ip = Ipv4Addr::new(172, 16, 80, 1);
    let mut frame = build_icmp_te_frame_v4(
        router_ip,
        n6472_pool_v4(),
        n6472_server_v4(),
        N6472_XLATED_PORT,
        N6472_SERVER_PORT,
        PROTO_TCP,
    );
    n6472_patch_ptb(&mut frame, 34);

    let forwarding = build_forwarding_state(&n9162_nat64_snapshot_in_domain(
        lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"),
        domain,
    ));
    assert_eq!(
        crate::afxdp::forwarding::ingress_routing_domain(&forwarding, 12, 0, None),
        domain,
        "fixture precondition: the ICMPv4 error ingresses on reth0.80 (ifindex 12), \
         and the domain the poll loop stamps from that interface must be the domain \
         this cell is parameterised on — otherwise the cell measures nothing"
    );
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    n6472_install_sessions_in_domain(&mut sessions, 123_000_000_000, domain);
    let sessions_before = sessions.len();

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    n9162_capture(&binding, sessions.len() as i64 - sessions_before as i64)
}

/// Drive the v6->v4 (RFC 7915 5.2) arm with everything in routing instance
/// `domain`.
fn n9162_run_v6_to_v4(domain: u32) -> N9162Outcome {
    let lan_router: Ipv6Addr = "2001:559:8585:ef00::fe".parse().expect("lan v6 router");
    let frame = build_icmpv6_te_frame(
        lan_router,
        n6472_pref64_server(),
        n6472_client_v6(),
        N6472_SERVER_PORT,
        N6472_CLIENT_PORT,
        PROTO_TCP,
    );

    let forwarding = build_forwarding_state(&n9162_nat64_snapshot_in_domain(
        lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"),
        domain,
    ));
    assert_eq!(
        crate::afxdp::forwarding::ingress_routing_domain(&forwarding, 24, 0, None),
        domain,
        "fixture precondition: the ICMPv6 error ingresses on reth1.0 (ifindex 24), \
         and the domain the poll loop stamps from that interface must be the domain \
         this cell is parameterised on"
    );
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    n6472_install_sessions_in_domain(&mut sessions, 123_000_000_000, domain);
    let sessions_before = sessions.len();

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 54,
        payload_offset: 62,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    n9162_capture(&binding, sessions.len() as i64 - sessions_before as i64)
}

fn n9162_capture(binding: &BindingWorker, sessions_delta: i64) -> N9162Outcome {
    let forwards = binding.scratch.scratch_forwards.len();
    let (prebuilt, target_ifindex, flow_key_none) = match binding.scratch.scratch_forwards.first() {
        Some(fwd) => (
            match &fwd.frame {
                PendingForwardFrame::Prebuilt(bytes) => Some(bytes.clone()),
                _ => None,
            },
            fwd.target_ifindex,
            fwd.flow_key.is_none(),
        ),
        None => (None, 0, false),
    };
    N9162Outcome {
        forwards,
        prebuilt,
        target_ifindex,
        flow_key_none,
        sessions_delta,
        recycles: binding.scratch.scratch_recycle.len(),
    }
}

/// The v4->v6 translated-content assertions, byte-for-byte the `_6472` cell's,
/// applied to whatever domain the driver ran in.
fn n9162_assert_v4_to_v6(out: &N9162Outcome, domain: u32) {
    assert_eq!(
        out.forwards, 1,
        "the NAT64 v4->v6 ICMP error translation must queue exactly one prebuilt \
         forward in routing domain {domain}. 0 forwards means the quote's reply key \
         missed the installed v4 reverse companion and the error was DROPPED by \
         flowless enforcement -- PMTUD dead toward the client (#9162)"
    );
    let outb = out
        .prebuilt
        .as_ref()
        .expect("the NAT64 error translation must queue a PREBUILT frame");
    let o = outb.as_slice();
    assert_eq!(&o[0..6], &N6472_CLIENT_MAC, "eth dst = client MAC");
    assert_eq!(&o[6..12], &N6472_LAN_SRC_MAC, "eth src = LAN unit MAC");
    assert_eq!(&o[12..14], &[0x86, 0xdd], "ethertype IPv6");
    let expect_router_v6: Ipv6Addr = "64:ff9b::ac10:5001".parse().expect("Pref64::router");
    assert_eq!(
        &o[14 + 8..14 + 24],
        &expect_router_v6.octets(),
        "outer src = Pref64::router"
    );
    assert_eq!(
        &o[14 + 24..14 + 40],
        &n6472_client_v6().octets(),
        "outer dst = v6 client"
    );
    assert_eq!(o[14 + 6], PROTO_ICMPV6, "next header ICMPv6");
    let icmp6 = &o[14 + 40..];
    assert_eq!(icmp6[0], 2, "ICMPv6 Packet Too Big type");
    let mtu = u32::from_be_bytes([icmp6[4], icmp6[5], icmp6[6], icmp6[7]]);
    assert_eq!(mtu, 1420, "PTB MTU = v4 next-hop MTU + NAT64 header delta");
    let emb = &icmp6[8..];
    assert_eq!(&emb[8..24], &n6472_client_v6().octets(), "embedded src = client");
    assert_eq!(
        &emb[24..40],
        &n6472_pref64_server().octets(),
        "embedded dst = Pref64::server"
    );
    assert_eq!(
        &emb[40..42],
        &N6472_CLIENT_PORT.to_be_bytes(),
        "embedded src port restored to the ORIGINAL client port"
    );
    assert_eq!(
        out.target_ifindex, 24,
        "translated error egresses toward the client"
    );
    assert!(out.flow_key_none, "the error never seeds a session/flow-cache entry");
    assert_eq!(out.sessions_delta, 0, "no new session minted");
    assert_eq!(out.recycles, 0, "a queued prebuilt forward owns the descriptor");
}

/// The v6->v4 translated-content assertions, byte-for-byte the `_6472` cell's.
fn n9162_assert_v6_to_v4(out: &N9162Outcome, domain: u32) {
    assert_eq!(
        out.forwards, 1,
        "the NAT64 v6->v4 ICMP error translation must queue exactly one prebuilt \
         forward in routing domain {domain}. 0 forwards means the quote's reply key \
         missed the installed FORWARD session and the error was dropped -- PMTUD dead \
         toward the server (#9162)"
    );
    let outb = out
        .prebuilt
        .as_ref()
        .expect("the NAT64 error translation must queue a PREBUILT frame");
    let o = outb.as_slice();
    assert_eq!(&o[0..6], &N6472_WAN_GW_MAC, "eth dst = WAN gateway MAC");
    assert_eq!(&o[6..12], &N6472_WAN_SRC_MAC, "eth src = WAN unit MAC");
    assert_eq!(&o[12..14], &[0x81, 0x00], "802.1Q tag present (VLAN 80)");
    assert_eq!(&o[16..18], &[0x08, 0x00], "ethertype IPv4 after the tag");
    let ip = &o[18..];
    assert_eq!(&ip[12..16], &n6472_pool_v4().octets(), "outer src = pool address");
    assert_eq!(&ip[16..20], &n6472_server_v4().octets(), "outer dst = v4 server");
    assert_eq!(ip[9], PROTO_ICMP, "protocol ICMPv4");
    let icmp = &ip[20..];
    assert_eq!(icmp[0], 11, "ICMPv4 Time Exceeded type");
    let emb = &icmp[8..];
    assert_eq!(&emb[12..16], &n6472_server_v4().octets(), "embedded src = server");
    assert_eq!(&emb[16..20], &n6472_pool_v4().octets(), "embedded dst = pool");
    assert_eq!(
        &emb[22..24],
        &N6472_XLATED_PORT.to_be_bytes(),
        "embedded dst port restored to the TRANSLATED pool port"
    );
    assert_eq!(
        out.target_ifindex, 12,
        "translated error egresses toward the server"
    );
    assert!(out.flow_key_none, "the error never seeds a session/flow-cache entry");
    assert_eq!(out.sessions_delta, 0, "no new session minted");
    assert_eq!(out.recycles, 0, "a queued prebuilt forward owns the descriptor");
}

/// #9162 REFERENCE ARM (domain 0 — the default instance). Runs the exact
/// drivers the two domain-7 cells run, with the one variable set to 0.
///
/// It is not redundant with the `_6472` cells: those pin the ORIGINAL fixture,
/// this pins the PARAMETERISED one, so a fix that repairs domain 7 by breaking
/// domain 0 — trading one tenant for another — reds here rather than passing
/// two single-direction assertions.
#[test]
fn poll_descriptor_nat64_icmp_error_both_arms_default_instance_9162() {
    n9162_assert_v4_to_v6(&n9162_run_v4_to_v6(0), 0);
    n9162_assert_v6_to_v4(&n9162_run_v6_to_v4(0), 0);
}

/// #9162 (v4->v6, RFC 7915 4.2) IN A ROUTING INSTANCE. The ICMPv4 error's
/// quote resolves the installed v4 REVERSE companion, which since #9033/#9271
/// carries the forward flow's routing domain. `embedded_reply_key` hardcoded
/// `routing_domain: 0`, and `lookup_session_across_scopes` is exact on all
/// four of its indexes (`key_to_handle`, `forward_wire_index`, and the two
/// shared maps are every one domain-PRESERVING), so a domain-0 probe could not
/// reach a domain-7 companion and the error was dropped.
///
/// This arm is the REGRESSION half: it passed before #9271 only because the
/// companion was installed at 0 too — probe and entry agreed on a value that
/// was wrong on both sides.
///
/// Fail-on-revert: restore `routing_domain: 0` in `embedded_reply_key` and
/// this cell reds with `forwards == 0` while the reference arm above stays
/// green.
#[test]
fn poll_descriptor_nat64_icmp_error_v4_to_v6_in_routing_instance_9162() {
    n9162_assert_v4_to_v6(&n9162_run_v4_to_v6(7), 7);
}

/// #9162 (v6->v4, RFC 7915 5.2) IN A ROUTING INSTANCE — the issue's original
/// subject. The ICMPv6 error's quote resolves the installed FORWARD session,
/// whose key has ALWAYS been domain-stamped at the #7160 stamp site, so this
/// arm has been broken since #7160 rather than since #9271.
///
/// `nat64_match.rs` carried ZERO `routing_domain` references while its
/// same-family siblings `nat_match_v4.rs` / `nat_match_v6.rs` both derive one
/// via `ingress_routing_domain` — that asymmetry is the issue's own positive
/// control, and this cell is what makes it observable.
///
/// Fail-on-revert: drop the `ingress_routing_domain` stamp in `nat64_match.rs`
/// and this cell reds with `forwards == 0`.
#[test]
fn poll_descriptor_nat64_icmp_error_v6_to_v4_in_routing_instance_9162() {
    n9162_assert_v6_to_v4(&n9162_run_v6_to_v4(7), 7);
}

/// #6472 negative (fail-closed anti-spoof gate): an ICMPv4 error whose
/// OUTER destination is NOT the quote's source is not about this session's
/// wire packet (RFC 792: an error is addressed to the offending packet's
/// source) and MUST be declined to normal flowless enforcement — never
/// translated on the strength of a fabricated quote.
#[test]
fn poll_descriptor_nat64_icmp_error_outer_dst_mismatch_declined_6472() {
    let router_ip = Ipv4Addr::new(172, 16, 80, 1);
    // Outer dst = 172.16.80.51, but the quote's source stays 172.16.80.50
    // (the pool address): the RFC 792 consistency gate rejects the match.
    let frame = build_icmp_te_frame_v4(
        router_ip,
        Ipv4Addr::new(172, 16, 80, 51),
        n6472_server_v4(),
        N6472_XLATED_PORT,
        N6472_SERVER_PORT,
        PROTO_TCP,
    );
    // Patch the embedded quote's source back to the pool address so ONLY the
    // outer dst differs (the fixture ties them together by construction).
    // Embedded IP starts at eth(14)+outer IP(20)+ICMP(8)=42; src at +12=54.
    let mut frame = frame;
    frame[54..58].copy_from_slice(&n6472_pool_v4().octets());
    // Fix the embedded IP header checksum after the byte surgery.
    frame[52] = 0;
    frame[53] = 0;
    let emb_csum = checksum16(&frame[42..62]);
    frame[52..54].copy_from_slice(&emb_csum.to_be_bytes());
    // Fix the outer ICMP checksum to keep the message well-formed.
    frame[36] = 0;
    frame[37] = 0;
    let icmp_csum = checksum16(&frame[34..]);
    frame[36..38].copy_from_slice(&icmp_csum.to_be_bytes());

    let forwarding = build_forwarding_state(&nat64_snapshot(lan_to_wan_permit(
        "8.8.8.8/32",
        "permit-nat64-v4",
    )));
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    n6472_install_sessions(&mut sessions, 123_000_000_000);

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "an error not addressed to the quote's source must NOT be translated"
    );
}

/// #6472 control (no-steal): with a NAT64 prefix configured, a same-family
/// NAT44 session's ICMP error STILL takes the #5690 same-family reversal —
/// the NAT64 arm declines it (no `nat64_reverse` on the matched half), and
/// nothing about the #5690 path changes.
#[test]
fn poll_descriptor_same_family_reversal_not_stolen_by_nat64_arm_6472() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    // NAT64 prefix configured AND allow_embedded_icmp set: both arms are
    // eligible — the NAT64 arm must decline (the NAT44 half carries no
    // `nat64_reverse`) and the #5690 reversal must fire unchanged.
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"));
    snapshot.flow.allow_embedded_icmp = true;
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some(N6472_WAN_GW_MAC),
                src_mac: Some(N6472_WAN_SRC_MAC),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));

    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    // The #5690 return-path resolution resolves the client's MAC via the
    // dynamic neighbor table (the connected LAN route + learned entry), so
    // learn it here exactly like the #5690 test.
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    txn_run_descriptor_with_neighbors(
        &mut binding,
        &mut sessions,
        &forwarding,
        &ha_state,
        &frame,
        meta,
        &dynamic_neighbors,
    );

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the same-family #5690 reversal must still queue the reversed error"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let reversed = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("same-family reversal must queue a PREBUILT frame"),
    };
    // Same-family (NAT44) outcome: v4 in, v4 out — the outer dst and the
    // embedded src restored to the v4 CLIENT, never family-translated.
    assert_eq!(&reversed[12..14], &[0x08, 0x00], "same-family stays IPv4");
    let outer_dst = Ipv4Addr::new(reversed[30], reversed[31], reversed[32], reversed[33]);
    assert_eq!(outer_dst, client_ip, "outer dst restored to the v4 client");
    let embedded_src = Ipv4Addr::new(reversed[54], reversed[55], reversed[56], reversed[57]);
    assert_eq!(embedded_src, client_ip, "embedded src restored to the v4 client");
    assert_eq!(fwd.target_ifindex, 24);
}

// ---------------------------------------------------------------------------
// #6474: OUTBOUND ICMP error through source NAT — re-NAT the outer source
// and the embedded quote to the session's external identity (RFC 5508 §4).
// ---------------------------------------------------------------------------

/// Install the outbound SNAT forward session the #6474 fixtures share:
/// `client:12345 -> server:80` source-NAT'd to `snat:40000`. The session's
/// own decision resolution is irrelevant to the error path (the return
/// resolution toward the server is re-derived), so it points WAN.
fn n6474_install_snat_session(
    sessions: &mut SessionTable,
    client_ip: IpAddr,
    server_ip: IpAddr,
    snat_ip: IpAddr,
    addr_family: u8,
    // #9162: the routing domain the production stamp site would put on this
    // forward key. 0 for every pre-existing cell (no routing-instance
    // membership); non-zero for the VRF twins below.
    routing_domain: u32,
) {
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family,
            protocol: PROTO_TCP,
            src_ip: client_ip,
            dst_ip: server_ip,
            src_port: 12345,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: Some(N6472_WAN_GW_MAC),
                src_mac: Some(N6472_WAN_SRC_MAC),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(snat_ip),
                rewrite_dst: None,
                rewrite_src_port: Some(40000),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
}

fn n6474_meta(ingress_ifindex: u32, addr_family: u8, protocol: u8, frame_len: usize) -> UserspaceDpMeta {
    let (l4, payload) = if addr_family == libc::AF_INET6 as u8 {
        (54u16, 62u16)
    } else {
        (34u16, 42u16)
    };
    UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex,
        l3_offset: 14,
        l4_offset: l4,
        payload_offset: payload,
        pkt_len: (frame_len - 14) as u16,
        addr_family,
        protocol,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    }
}

/// #6474 FAIL-ON-REVERT (v4, RFC 5508 §4): an internal host behind SNAT
/// emits an ICMP Destination-Unreachable about the session's reply — outer
/// `10.0.61.102 -> 1.1.1.1`, quote `(1.1.1.1:80 -> 10.0.61.102:12345)`.
/// Before #6474 the #5690 flowless reversal consumed the descriptor with an
/// identity rewrite: the wire showed the INTERNAL (pre-NAT) source and a
/// quote in pre-NAT form the server cannot associate (its socket knows only
/// `172.16.80.8:40000`). Now the outbound arm re-NATs it: outer source →
/// the SNAT address, quote destination address → the SNAT address, quote
/// destination port → the translated 40000, every affected checksum
/// recomputed. RED on revert: every external-identity assertion below
/// fails (the old frame keeps the internal source + pre-NAT quote).
#[test]
fn poll_descriptor_snat_outbound_icmp_error_renat_v4_6474() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);

    // Outer (client -> server); embedded quote (server:80 -> client:12345).
    let mut frame = build_icmp_te_frame_v4(client_ip, server_ip, client_ip, 80, 12345, PROTO_TCP);
    // Destination Unreachable / port-unreachable (3/3): the natural error a
    // host emits about a reply it cannot handle.
    frame[34] = 3;
    frame[35] = 3;
    frame[36] = 0;
    frame[37] = 0;
    let icmp_csum = checksum16(&frame[34..]);
    frame[36..38].copy_from_slice(&icmp_csum.to_be_bytes());

    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    n6474_install_snat_session(
        &mut sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
        IpAddr::V4(snat_ip),
        libc::AF_INET as u8,
        0,
    );
    let sessions_before = sessions.len();

    let meta = n6474_meta(24, libc::AF_INET as u8, PROTO_ICMP, frame.len());
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the outbound SNAT ICMP error must be re-NAT'd and queued as one prebuilt forward"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the outbound re-NAT must queue a PREBUILT frame"),
    };
    // L2 toward the WAN gateway (default route), VLAN 80 tagged.
    assert_eq!(&out[0..6], &N6472_WAN_GW_MAC, "eth dst = WAN gateway");
    assert_eq!(&out[16..18], &[0x08, 0x00], "ethertype IPv4 after the VLAN tag");
    let ip = &out[18..];
    // THE defect fix: the outer source is the EXTERNAL SNAT address, never
    // the internal client address (the pre-#6474 leak).
    assert_eq!(&ip[12..16], &snat_ip.octets(), "outer src re-NAT'd to the SNAT address");
    assert_eq!(&ip[16..20], &server_ip.octets(), "outer dst untouched (the remote)");
    assert_eq!(checksum16(&ip[..20]), 0, "outer IPv4 header checksum verifies");
    // ICMP header: type/code preserved, checksum valid.
    let icmp = &ip[20..];
    assert_eq!(icmp[0], 3, "stays Destination Unreachable");
    assert_eq!(icmp[1], 3, "stays port-unreachable");
    assert_eq!(checksum16(icmp), 0, "outer ICMP checksum verifies");
    // Embedded quote: destination address + port re-NAT'd to the external
    // identity the server associates; source (the server) untouched.
    let emb = &icmp[8..];
    assert_eq!(&emb[12..16], &server_ip.octets(), "embedded src untouched (server)");
    assert_eq!(
        &emb[16..20],
        &snat_ip.octets(),
        "embedded dst re-NAT'd to the SNAT address"
    );
    assert_eq!(checksum16(&emb[..20]), 0, "embedded IPv4 header checksum verifies");
    assert_eq!(&emb[20..22], &80u16.to_be_bytes(), "embedded src port untouched");
    assert_eq!(
        &emb[22..24],
        &40000u16.to_be_bytes(),
        "embedded dst port re-NAT'd to the translated value"
    );
    assert!(
        matches!(fwd.target_ifindex, 11 | 12),
        "re-NAT'd error egresses toward the server (WAN unit reth0.80 / its parent)"
    );
    assert!(fwd.flow_key.is_none());
    assert_eq!(sessions.len(), sessions_before, "no new session minted");
}

/// #6474 FAIL-ON-REVERT (v6): the SNAT66 twin — an internal v6 host emits
/// an ICMPv6 Destination-Unreachable about the session's reply; the wire
/// must carry the translated external source and the quote the v6 server
/// associates (RFC 5508 §4 via the same session machinery).
#[test]
fn poll_descriptor_snat_outbound_icmp_error_renat_v6_6474() {
    let client_v6: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("client v6");
    let server_v6: Ipv6Addr = "2001:db8::1".parse().expect("server v6");
    let snat_v6: Ipv6Addr = "2001:559:8585:80::8".parse().expect("snat v6 (reth0.80)");

    // Outer (client -> server); embedded quote (server:80 -> client:12345).
    let mut frame = build_icmpv6_te_frame(client_v6, server_v6, client_v6, 80, 12345, PROTO_TCP);
    // Destination Unreachable / port-unreachable (1/4).
    let l4 = 54;
    frame[l4] = 1;
    frame[l4 + 1] = 4;
    frame[l4 + 2] = 0;
    frame[l4 + 3] = 0;
    let icmp6_csum = checksum16_ipv6(client_v6, server_v6, PROTO_ICMPV6, &frame[l4..]);
    frame[l4 + 2..l4 + 4].copy_from_slice(&icmp6_csum.to_be_bytes());

    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    n6474_install_snat_session(
        &mut sessions,
        IpAddr::V6(client_v6),
        IpAddr::V6(server_v6),
        IpAddr::V6(snat_v6),
        libc::AF_INET6 as u8,
        0,
    );

    let meta = n6474_meta(24, libc::AF_INET6 as u8, PROTO_ICMPV6, frame.len());
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the outbound SNAT66 ICMPv6 error must be re-NAT'd and queued as one prebuilt forward"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the outbound re-NAT must queue a PREBUILT frame"),
    };
    assert_eq!(&out[12..14], &[0x81, 0x00], "VLAN tag (reth0.80) present");
    assert_eq!(&out[16..18], &[0x86, 0xdd], "ethertype IPv6 after the tag");
    let ip = &out[18..];
    assert_eq!(&ip[8..24], &snat_v6.octets(), "outer src re-NAT'd to the SNAT66 address");
    assert_eq!(&ip[24..40], &server_v6.octets(), "outer dst untouched (the remote)");
    let icmp = &ip[40..];
    assert_eq!(icmp[0], 1, "stays Destination Unreachable");
    assert_eq!(icmp[1], 4, "stays port-unreachable");
    // Embedded quote: dst addr + dst port re-NAT'd; ICMPv6 checksum verifies.
    let emb = &icmp[8..];
    assert_eq!(&emb[8..24], &server_v6.octets(), "embedded src untouched (server)");
    assert_eq!(
        &emb[24..40],
        &snat_v6.octets(),
        "embedded dst re-NAT'd to the SNAT66 address"
    );
    assert_eq!(&emb[40..42], &80u16.to_be_bytes(), "embedded src port untouched");
    assert_eq!(
        &emb[42..44],
        &40000u16.to_be_bytes(),
        "embedded dst port re-NAT'd to the translated value"
    );
    let s6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap());
    let d6 = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap());
    assert_eq!(
        checksum16_ipv6(s6, d6, PROTO_ICMPV6, icmp),
        0,
        "outer ICMPv6 checksum verifies"
    );
    assert!(
        matches!(fwd.target_ifindex, 11 | 12),
        "re-NAT'd error egresses toward the server (WAN unit reth0.80 / its parent)"
    );
    assert!(fwd.flow_key.is_none());
}

// ---------------------------------------------------------------------------
// #9162: the SAME-FAMILY embedded-ICMP reply key in a NON-DEFAULT routing
// instance.
//
// `embedded_reply_key` is shared by the NAT64 arm and by the two same-family
// arms, so threading the domain into it changes `nat_match_v4` /
// `nat_match_v6` too. Nothing in the tree could SEE that change: every
// same-family embedded-ICMP cell also runs at domain 0. These two cells make
// it observable, so the same-family half of the fix is measured rather than
// argued.
//
// The #6474 outbound-SNAT shape is the right vehicle because it is the arm
// that depends on the reply key reaching an EXACT
// `lookup_session_across_scopes` — the quote's reply key IS the forward
// session's primary key. (The inbound #5690 shape resolves through
// `lookup_forward_nat_across_scopes`, which zeroes its own probe and so cannot
// distinguish the two values.)
// ---------------------------------------------------------------------------

/// `nat_snapshot` with `allow_embedded_icmp` and every interface in routing
/// instance `domain`.
fn n9162_snat_snapshot_in_domain(domain: u32) -> ConfigSnapshot {
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    for iface in snapshot.interfaces.iter_mut() {
        iface.routing_domain = domain;
    }
    snapshot
}

/// #9162 (same-family v4, the #6474 outbound-SNAT shape) IN A ROUTING
/// INSTANCE. The internal host's ICMP error quotes the session's reply, so
/// the quote's REPLY key is the forward session's primary key — an exact
/// lookup against a domain-stamped installed session.
///
/// Fail-on-revert: pass `0` instead of `embedded_routing_domain` at the
/// `embedded_reply_key` call in `nat_match_v4::match_outer_v4` (or restore the
/// hardcoded literal in `embedded_reply_key`) and this cell reds — the reply
/// key misses, no outbound-SNAT match is marked, and the #5690 identity
/// reversal leaks the INTERNAL source instead.
#[test]
fn poll_descriptor_snat_outbound_icmp_error_renat_v4_in_routing_instance_9162() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);

    let mut frame = build_icmp_te_frame_v4(client_ip, server_ip, client_ip, 80, 12345, PROTO_TCP);
    frame[34] = 3;
    frame[35] = 3;
    frame[36] = 0;
    frame[37] = 0;
    let icmp_csum = checksum16(&frame[34..]);
    frame[36..38].copy_from_slice(&icmp_csum.to_be_bytes());

    let forwarding = build_forwarding_state(&n9162_snat_snapshot_in_domain(7));
    assert_eq!(
        crate::afxdp::forwarding::ingress_routing_domain(&forwarding, 24, 0, None),
        7,
        "fixture precondition: the error ingresses on reth1.0 (ifindex 24) and the \
         domain stamped from it must be 7, or this cell measures nothing"
    );
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    n6474_install_snat_session(
        &mut sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
        IpAddr::V4(snat_ip),
        libc::AF_INET as u8,
        7,
    );

    let meta = n6474_meta(24, libc::AF_INET as u8, PROTO_ICMP, frame.len());
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the outbound SNAT ICMP error must still be re-NAT'd and queued in a \
         routing instance"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the outbound re-NAT must queue a PREBUILT frame"),
    };
    let ip = &out[18..];
    assert_eq!(
        &ip[12..16],
        &snat_ip.octets(),
        "#9162: outer src re-NAT'd to the SNAT address. A domain-0 reply key \
         misses the domain-7 session, the outbound-SNAT mark never fires, and \
         the #5690 reversal puts the INTERNAL client address on the wire"
    );
    let icmp = &ip[20..];
    let emb = &icmp[8..];
    assert_eq!(
        &emb[16..20],
        &snat_ip.octets(),
        "#9162: embedded quote dst re-NAT'd to the external identity"
    );
    assert_eq!(
        &emb[22..24],
        &40000u16.to_be_bytes(),
        "#9162: embedded quote dst port re-NAT'd to the translated value"
    );
}

/// #9162 (same-family v6 / SNAT66) IN A ROUTING INSTANCE — the twin of the
/// cell above, covering the SECOND `embedded_reply_key` call in
/// `nat_match_v6::match_outer_v6` (the `shared_reverse_key`, built from the
/// NPTv6-translated source), which is a distinct call site from the first.
///
/// Fail-on-revert: pass `0` at that call and this cell reds while the v4 twin
/// stays green — the two same-family arms are scored separately on purpose.
#[test]
fn poll_descriptor_snat_outbound_icmp_error_renat_v6_in_routing_instance_9162() {
    let client_v6: Ipv6Addr = "2001:559:8585:ef00::102".parse().expect("client v6");
    let server_v6: Ipv6Addr = "2001:db8::1".parse().expect("server v6");
    let snat_v6: Ipv6Addr = "2001:559:8585:80::8".parse().expect("snat v6 (reth0.80)");

    let mut frame = build_icmpv6_te_frame(client_v6, server_v6, client_v6, 80, 12345, PROTO_TCP);
    let l4 = 54;
    frame[l4] = 1;
    frame[l4 + 1] = 4;
    frame[l4 + 2] = 0;
    frame[l4 + 3] = 0;
    let icmp6_csum = checksum16_ipv6(client_v6, server_v6, PROTO_ICMPV6, &frame[l4..]);
    frame[l4 + 2..l4 + 4].copy_from_slice(&icmp6_csum.to_be_bytes());

    let forwarding = build_forwarding_state(&n9162_snat_snapshot_in_domain(7));
    assert_eq!(
        crate::afxdp::forwarding::ingress_routing_domain(&forwarding, 24, 0, None),
        7,
        "fixture precondition: the domain stamped from reth1.0 must be 7"
    );
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    n6474_install_snat_session(
        &mut sessions,
        IpAddr::V6(client_v6),
        IpAddr::V6(server_v6),
        IpAddr::V6(snat_v6),
        libc::AF_INET6 as u8,
        7,
    );

    let meta = n6474_meta(24, libc::AF_INET6 as u8, PROTO_ICMPV6, frame.len());
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "the outbound SNAT66 ICMPv6 error must still be re-NAT'd and queued in a \
         routing instance"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the outbound re-NAT must queue a PREBUILT frame"),
    };
    let ip = &out[18..];
    assert_eq!(
        &ip[8..24],
        &snat_v6.octets(),
        "#9162: outer src re-NAT'd to the SNAT66 address. With a domain-0 reply \
         key the domain-7 session is unreachable and the internal source leaks"
    );
    let icmp = &ip[40..];
    let emb = &icmp[8..];
    assert_eq!(
        &emb[24..40],
        &snat_v6.octets(),
        "#9162: embedded quote dst re-NAT'd to the external identity"
    );
    assert_eq!(
        &emb[42..44],
        &40000u16.to_be_bytes(),
        "#9162: embedded quote dst port re-NAT'd to the translated value"
    );
}

/// #6474 marker pin (match level): the OUTBOUND mark fires ONLY for a pure
/// source-NAT flow (rewrite_src set, no dst NAT) matched via the quote's
/// reply key. A DNAT-only flow's outbound-direction error keeps the
/// pre-#6474 identity (`outbound_snat == false`), and the #5690 inbound
/// matches never carry the mark.
#[test]
fn embedded_icmp_outbound_snat_marker_scoping_6474() {
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let meta = icmp_err_meta_v4();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    // (a) pure SNAT: outbound error marks true.
    let mut sessions = SessionTable::new();
    n6474_install_snat_session(
        &mut sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
        IpAddr::V4(snat_ip),
        libc::AF_INET as u8,
        0,
    );
    let frame = build_icmp_te_frame_v4(client_ip, server_ip, client_ip, 80, 12345, PROTO_TCP);
    let m = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("outbound error matches the forward SNAT session");
    assert!(m.outbound_snat, "pure-SNAT outbound error must carry the re-NAT mark");

    // (b) DNAT-only: the mark stays off (pre-#6474 behavior preserved).
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: 12345,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: Some(N6472_WAN_GW_MAC),
                src_mac: Some(N6472_WAN_SRC_MAC),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 30, 50))),
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let m = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("outbound-direction error still matches");
    assert!(
        !m.outbound_snat,
        "a DNAT-carrying flow must NOT take the outbound re-NAT mark"
    );

    // (c) the INBOUND error (quote = the forward wire packet) never marks.
    let mut sessions = SessionTable::new();
    n6474_install_snat_session(
        &mut sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
        IpAddr::V4(snat_ip),
        libc::AF_INET as u8,
        0,
    );
    let inbound_frame = build_icmp_te_frame_v4(
        Ipv4Addr::new(172, 16, 80, 1),
        snat_ip,
        server_ip,
        40000,
        80,
        PROTO_TCP,
    );
    let m = try_embedded_icmp_nat_match_from_frame(
        &inbound_frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect("inbound error matches via the forward-NAT reverse arm");
    assert!(!m.outbound_snat, "inbound #5690 matches never carry the mark");
}




#[test]
fn poll_descriptor_policy_deny_path_emits_rt_flow_event() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    snapshot.neighbors = vec![NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let frame = build_policy_deny_tcp_syn_frame();
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event from poll descriptor")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event.ingress_ifindex, 24);
    assert_eq!(event.src_port, 12345);
    assert_eq!(event.dst_port, 5201);
    // #2470: the poll path stamps the dataplane DECISION instant (wall-clock
    // Unix ns) at emit time instead of 0, so the Go decoder reports decision
    // time rather than receive time. This end-to-end check (a real
    // CLOCK_MONOTONIC now_ns flows through the worker poll path) fails if the
    // emitter is reverted to `timestamp_ns: 0`.
    assert!(
        event.timestamp_ns > 0,
        "policy-deny event from the poll path must carry a real wall-clock \
         timestamp, got 0"
    );
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
    assert!(telemetry.dbg.policy_deny >= 1);
}


/// #3021 LITERAL fail-on-revert. Drives the real
/// `poll_binding_process_descriptor` deny path with the ingress on a VLAN
/// SUB-INTERFACE whose LOGICAL unit (ifindex 13, zone `lan`) is in a
/// DIFFERENT zone than its physical parent (ifindex 11, zone `wan` — the
/// parent inherits its FIRST sub-interface reth0.80's wan zone). The emitted
/// PolicyDeny event's `ingress_zone_id` is the from-zone the zone-pair
/// lookup resolves. The #3021 fix resolves the logical ifindex 13 -> `lan`,
/// so the event reports lan. If the production site is reverted to
/// `meta.ingress_ifindex` (physical 11), the lookup resolves the parent's
/// `wan` zone and the `ingress_zone_id == TEST_LAN_ZONE_ID` assert fails RED.
/// (Both lan->wan and wan->wan are denied by the deny default — only dmz->wan
/// is permitted — so the deny event fires either way; only the reported
/// ingress zone distinguishes the fix from the bug.)
#[test]
fn poll_descriptor_policy_deny_keys_logical_ingress_zone_3021() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: TEST_DMZ_ZONE_ID,
            ..Default::default()
        },
    ];
    // Add a SECOND VLAN sub-interface (logical ifindex 13, VID 50) on the
    // SAME physical parent (ifindex 11) as reth0.80, but in zone `lan`. The
    // parent ifindex 11 keeps reth0.80's wan zone (first sub-interface),
    // so the logical (13->lan) and physical (11->wan) ingress zones diverge.
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth0.50".to_string(),
        zone: "lan".to_string(),
        linux_name: "ge-0-0-0.50".to_string(),
        ifindex: 13,
        parent_ifindex: 11,
        vlan_id: 50,
        hardware_addr: "02:bf:72:00:50:08".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "172.16.50.8/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.neighbors = vec![NeighborSnapshot {
        interface: "ge-0-0-0.80".to_string(),
        ifindex: 12,
        family: "inet".to_string(),
        ip: "172.16.80.200".to_string(),
        mac: "00:aa:bb:cc:dd:ee".to_string(),
        state: "reachable".to_string(),
        router: false,
        link_local: false,
    }];

    let forwarding = build_forwarding_state(&snapshot);
    // Sanity: the fixture really maps (parent 11, VID 50) -> logical 13 (lan)
    // while the physical parent 11 resolves to wan.
    assert_eq!(
        crate::afxdp::forwarding::resolve_ingress_logical_ifindex(&forwarding, 11, 50),
        Some(13),
        "fixture must map parent 11 / VLAN 50 -> logical ifindex 13"
    );
    assert_eq!(
        forwarding.ifindex_to_zone_id.get(&13).copied(),
        Some(TEST_LAN_ZONE_ID),
        "logical ifindex 13 (reth0.50) is zone lan"
    );
    // #7509 RETARGET, and the re-expressed form is STRICTLY STRONGER. This
    // asserted the parent inherited reth0.80's `wan`, so that a physical-keyed
    // lookup would report a zone DIFFERENT from the unit's `lan` and the cell
    // could tell the fix from the bug.
    //
    // A contested parent now carries no zone. The contrast the cell needs is
    // preserved and sharpened: a reverted, physical-keyed implementation would
    // report 0 rather than `wan`, which is distinguishable from `lan` and from
    // every other real zone -- the old form only distinguished it from `lan`.
    // The subject assertion below (`event.ingress_zone_id == TEST_LAN_ZONE_ID`)
    // is unchanged and still carries the cell.
    assert_eq!(
        forwarding.ifindex_to_zone_id.get(&11).copied().unwrap_or(0),
        0,
        "physical parent ifindex 11 carries units in DIFFERENT zones (wan on \
         reth0.80, lan on reth0.50), so it resolves to NO zone (#7509)"
    );

    // The physical port the VLAN sub-interface rides on is ifindex 11.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 11, 0);
    binding.interface = Arc::<str>::from("ge-0-0-0");
    let frame = build_policy_deny_tcp_syn_frame();
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        // Physical parent + out-of-band VID (the shim strips the tag and
        // conveys the VID in meta; the frame stays untagged so l3 is at 14).
        ingress_ifindex: 11,
        ingress_vlan_id: 50,
        ingress_vlan_present: 0,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("policy-deny event from poll descriptor")
        .decode_dataplane_event()
        .expect("policy-deny payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::PolicyDeny
    );
    // The load-bearing assert: the deny event's ingress zone is the LOGICAL
    // sub-interface zone (lan, ifindex 13), NOT the physical parent's wan
    // (ifindex 11). Reverting the production site to meta.ingress_ifindex
    // makes this report wan and the test fails RED.
    assert_eq!(
        event.ingress_zone_id, TEST_LAN_ZONE_ID,
        "the VLAN sub-interface's OWN logical ingress zone (lan) must drive \
         the zone-pair policy (#3021); a physical-keyed lookup reports wan"
    );
    assert_ne!(
        event.ingress_zone_id, TEST_WAN_ZONE_ID,
        "the physical parent's wan zone must NOT be used for the VLAN unit"
    );
    assert_eq!(event.egress_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(event.ingress_ifindex, 11);
    assert_eq!(event_handle.dataplane_event_stats().policy_deny.sent, 1);
}


#[test]
fn poll_descriptor_input_filter_log_path_emits_rt_flow_event() {
    // Default session cap: the ForwardCandidate flow installs a session.
    let (event_handle, event_rx) = run_input_filter_accept_log_poll(None);
    assert_input_filter_accept_log_event(&event_handle, &event_rx);
}


#[test]
fn poll_descriptor_input_filter_accept_log_emits_on_install_refused_miss() {
    // #2617 fail-on-revert guard. With the session table capped at 0 the
    // ForwardCandidate install is REFUSED (admission cap) and the miss
    // packet is dropped via `continue` BEFORE the former per-install emit
    // site. The accepted `then log` term must still emit its RT_FLOW audit
    // record on this first/only packet, otherwise a cache-declined or
    // short-lived permitted flow logs nothing at all. Before the fix moved
    // the emit to the single early accept-fall-through site, this asserted
    // `try_recv()` found NO event and `filter_log.sent == 0` — reverting the
    // fix turns this test RED.
    let (event_handle, event_rx) = run_input_filter_accept_log_poll(Some(0));
    assert_input_filter_accept_log_event(&event_handle, &event_rx);
}


#[test]
fn poll_descriptor_input_filter_discard_drops_and_logs() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
    ];
    snapshot.interfaces[0].filter_input_v4 = "drop-input".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-input".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    frame[47] = 0x10;
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("discard input filter-log event from poll descriptor")
        .decode_dataplane_event()
        .expect("discard filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.action, 0);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}


#[test]
fn poll_descriptor_session_hit_rechecks_dscp_input_filter() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            ..Default::default()
        },
    ];
    snapshot.interfaces[0].filter_input_v4 = "drop-ef-input".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "drop-ef-input".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-ef-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            dscp_values: vec![46],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    frame[47] = 0x10;
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        dscp: 46,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let flow_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: Some([0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
            tx_vlan_id: 80,
        },
        nat: NatDecision::default(),
    };
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key.clone(),
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        123_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("DSCP input filter-log event from session hit")
        .decode_dataplane_event()
        .expect("DSCP input filter-log payload");
    assert_eq!(event.reason, FilterLogSource::Input.wire_reason());
    assert_eq!(event.action, 0);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 1, "per-packet input drop keeps session");
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}


#[test]
fn poll_descriptor_lo0_filter_discard_drops_without_reinject() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    // #3705: host-inbound runs BEFORE the lo0 filter, so the host-bound packet
    // must be admitted for the lo0 filter to run. Every known zone is now
    // enforcing, so declare the packet-wide admit explicitly (pre-#3705 this
    // relied on the configured=false admit-all default). #3226: that token is
    // `any-service` — `all` now expands to the named system-service union.
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            host_inbound_configured: true,
            host_inbound_system_services: vec!["any-service".to_string()],
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            host_inbound_configured: true,
            host_inbound_system_services: vec!["any-service".to_string()],
            ..Default::default()
        },
    ];
    snapshot.interfaces[0].addresses = vec![InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: "10.0.61.1/24".to_string(),
        scope: 0,
    }];
    snapshot.flow.lo0_filter_input_v4 = "protect-re".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "protect-re".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    set_ipv4_dst(&mut frame, Ipv4Addr::new(10, 0, 61, 1));
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("lo0 filter-log event from poll descriptor")
        .decode_dataplane_event()
        .expect("lo0 filter-log payload");
    assert_eq!(
        event.kind,
        crate::event_stream::codec::DataplaneEventKind::FilterLog
    );
    assert_eq!(event.reason, FilterLogSource::Lo0.wire_reason());
    assert_eq!(event.action, 0);
    assert_eq!(event.ingress_zone_id, TEST_LAN_ZONE_ID);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
    assert_eq!(binding.live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().unwrap().is_empty());
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}


#[test]
fn poll_descriptor_lo0_filter_drops_cached_local_delivery_session_hit() {
    let mut snapshot = policy_deny_snapshot();
    snapshot.default_policy = "permit".to_string();
    snapshot.policies.clear();
    // #3705: host-inbound runs BEFORE the lo0 filter, so the host-bound packet
    // must be admitted for the lo0 filter to run. Every known zone is now
    // enforcing, so declare the packet-wide admit explicitly (pre-#3705 this
    // relied on the configured=false admit-all default). #3226: that token is
    // `any-service` — `all` now expands to the named system-service union.
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: TEST_LAN_ZONE_ID,
            host_inbound_configured: true,
            host_inbound_system_services: vec!["any-service".to_string()],
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: TEST_WAN_ZONE_ID,
            host_inbound_configured: true,
            host_inbound_system_services: vec!["any-service".to_string()],
            ..Default::default()
        },
    ];
    snapshot.interfaces[0].addresses = vec![InterfaceAddressSnapshot {
        family: "inet".to_string(),
        address: "10.0.61.1/24".to_string(),
        scope: 0,
    }];
    snapshot.flow.lo0_filter_input_v4 = "protect-re".to_string();
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "protect-re".to_string(),
        family: "inet".to_string(),
        terms: vec![FirewallTermSnapshot {
            name: "drop-web".to_string(),
            action: "discard".to_string(),
            destination_ports: vec!["5201".to_string()],
            log: true,
            ..Default::default()
        }],
    }];

    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut frame = build_policy_deny_tcp_syn_frame();
    set_ipv4_dst(&mut frame, Ipv4Addr::new(10, 0, 61, 1));
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 24,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };
    let mut sessions = SessionTable::new();
    let flow_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let local_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 24,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    };
    let local_metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_LAN_ZONE_ID,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    };
    assert!(sessions.install_with_protocol_with_origin(
        flow_key.clone(),
        local_decision,
        local_metadata.clone(),
        SessionOrigin::LocalMiss,
        123_000_000_000,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));
    let shared_entry = SyncedSessionEntry {
        key: flow_key.clone(),
        decision: local_decision,
        metadata: local_metadata,
        origin: SessionOrigin::LocalMiss,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &shared_entry,
    );
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let event = event_rx
        .try_recv()
        .expect("lo0 filter-log event from cached local session hit")
        .decode_dataplane_event()
        .expect("lo0 filter-log payload");
    assert_eq!(event.reason, FilterLogSource::Lo0.wire_reason());
    assert_eq!(event.action, 0);
    assert!(binding.scratch.scratch_forwards.is_empty());
    assert_eq!(sessions.len(), 0);
    assert!(shared_sessions.lock().expect("shared sessions").is_empty());
    assert!(shared_nat_sessions.lock().expect("shared nat").is_empty());
    assert!(
        shared_forward_wire_sessions
            .lock()
            .expect("shared forward wire")
            .is_empty()
    );
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, flow_key);
    assert_eq!(binding.live.slow_path_drops.load(Ordering::Relaxed), 0);
    assert!(recent_exceptions.lock().unwrap().is_empty());
    assert_eq!(event_handle.dataplane_event_stats().filter_log.sent, 1);
}



/// #7359: the flowless embedded-ICMP NAT reversal used to forward to the
/// client BEFORE the interface input filter ran, so a `filter input` attached
/// to the ingress interface never saw a reverse-translated ICMP error.
///
/// This is the SAME fixture as the #5690 reachability test above — same NAT
/// session, same frame, same ingress — with one difference: a `discard` input
/// filter on the ingress unit. That is deliberate. The sibling test asserts
/// the reversal DOES queue a forward with this fixture, so the pair shows the
/// filter is what changed the outcome and not something about the setup.
///
/// Fail-on-revert: move the input-filter evaluation back below the
/// `is_embedded_icmp_error` branch in poll_descriptor/mod.rs and the reversal
/// queues its forward before the filter runs, so `scratch_forwards` is
/// non-empty and this test goes RED.
#[test]
fn input_filter_discard_drops_the_embedded_icmp_reversal_7359() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    // Outer: router -> snat_ip; embedded quoted: snat_ip:snat_port -> server:80.
    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    // allow_embedded_icmp gates the poll-path reversal — enable it.
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    // #7359: attach `filter input` with a bare `discard` term to the WAN unit
    // the error ingresses on. Nothing about the filter is ICMP-specific — a
    // term with no match criteria matches every packet arriving there, which
    // is exactly the operator expectation this path violated.
    snapshot.filters.push(crate::protocol::FirewallFilterSnapshot {
        name: "block-all-in".to_string(),
        family: "inet".to_string(),
        terms: vec![crate::protocol::FirewallTermSnapshot {
            name: "t-discard".to_string(),
            action: "discard".to_string(),
            ..Default::default()
        }],
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == 12 {
            iface.filter_input_v4 = "block-all-in".to_string();
        }
    }
    let forwarding = build_forwarding_state(&snapshot);

    // The error ingresses on the WAN (reth0.80, ifindex 12) since it is
    // addressed to the SNAT address; the reversal resolves egress toward the
    // client on the LAN (reth1.0, ifindex 24), so learn the client neighbor.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");

    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        // #7359: the shim stamps the L3 identity into the meta, and
        // `l3_session_flow_from_meta` returns None for an UNSPECIFIED address
        // (the #7055 reachable leg). Leaving these zero makes l3_ctx None, the
        // input-filter block is skipped on EVERY path, and the test then
        // "passes" against a broken implementation for the wrong reason.
        flow_src_addr: {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&router_ip.octets());
            a
        },
        flow_dst_addr: {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&snat_ip.octets());
            a
        },
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    // Neighbor toward the client on the LAN unit so the reversed error resolves
    // a tx interface + MAC (egress ifindex 24).
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Install the forward NAT session (client:client_port -> server:80 SNAT'd
    // to snat_ip:snat_port) so the embedded reversal can recover the client.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let sessions_before = sessions.len();

    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    // The filter runs BEFORE the reversal now, so the error is dropped and no
    // prebuilt reversed forward is ever queued.
    assert!(
        binding.scratch.scratch_forwards.is_empty(),
        "an interface input filter with a `discard` term must drop a \
         reverse-translated embedded-ICMP error, but {} prebuilt forward(s) \
         were queued toward the client. Before #7359 the reversal ran first \
         and `continue`d past the filter entirely, so a configured discard \
         term never saw the packet, its counters never advanced, and a \
         policer never metered it.",
        binding.scratch.scratch_forwards.len()
    );
    // A flowless deny is a SILENT drop — no reject — and the descriptor is
    // recycled rather than owned by a queued forward.
    assert_eq!(
        binding.scratch.scratch_recycle.len(),
        1,
        "the dropped error must recycle its descriptor"
    );
    assert_eq!(
        sessions.len(),
        sessions_before,
        "a filtered ICMP error must not seed a session"
    );
}

/// #7359 acceptance criterion 2: a `filter input` COUNT term advances for a
/// reverse-translated embedded-ICMP error.
///
/// The sibling `input_filter_discard_drops_the_embedded_icmp_reversal_7359`
/// covers criterion 1 by asserting an ABSENCE — no queued forward. This one
/// asserts a PRESENCE on the same ordering, and the two fail for different
/// reasons: a fix that evaluated the filter but discarded unconditionally
/// would satisfy the discard cell and red this one.
///
/// Fail-on-revert: move the input-filter evaluation back below the
/// `is_embedded_icmp_error` branch in poll_descriptor/mod.rs and the reversal
/// queues its forward before the filter runs, so the count term never sees the
/// packet and `packets` stays 0.
#[test]
fn input_filter_count_term_advances_for_the_embedded_icmp_reversal_7359() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    // Outer: router -> snat_ip; embedded quoted: snat_ip:snat_port -> server:80.
    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);

    // allow_embedded_icmp gates the poll-path reversal — enable it.
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    // #7359 criterion 2: attach `filter input` whose first term COUNTS and
    // falls through to an accept.
    //
    // Two terms, not a single `count; discard;`, and the difference is the
    // point. With a discard the counter could advance on a path that also
    // drops the packet, and the sibling test already covers dropping — a
    // count+discard cell would re-measure the drop and infer the count. Here
    // the filter is NON-terminating, so the reversal must still queue its
    // forward: the assertions below require the counter to advance AND the
    // packet to survive, which together say "the filter SAW this packet"
    // rather than "the filter blocked this packet".
    //
    // `next_term: true` with no terminating action is the #2544 fall-through
    // shape: a modifier-only term applies its modifiers and continues.
    snapshot.filters.push(crate::protocol::FirewallFilterSnapshot {
        name: "count-all-in".to_string(),
        family: "inet".to_string(),
        terms: vec![
            crate::protocol::FirewallTermSnapshot {
                name: "t-count".to_string(),
                count: "in-embedded-icmp".to_string(),
                next_term: true,
                ..Default::default()
            },
            crate::protocol::FirewallTermSnapshot {
                name: "t-accept".to_string(),
                action: "accept".to_string(),
                ..Default::default()
            },
        ],
    });
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == 12 {
            iface.filter_input_v4 = "count-all-in".to_string();
        }
    }
    let forwarding = build_forwarding_state(&snapshot);

    // The error ingresses on the WAN (reth0.80, ifindex 12) since it is
    // addressed to the SNAT address; the reversal resolves egress toward the
    // client on the LAN (reth1.0, ifindex 24), so learn the client neighbor.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");

    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        // #7359: the shim stamps the L3 identity into the meta, and
        // `l3_session_flow_from_meta` returns None for an UNSPECIFIED address
        // (the #7055 reachable leg). Leaving these zero makes l3_ctx None, the
        // input-filter block is skipped on EVERY path, and the test then
        // "passes" against a broken implementation for the wrong reason.
        flow_src_addr: {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&router_ip.octets());
            a
        },
        flow_dst_addr: {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&snat_ip.octets());
            a
        },
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    // Neighbor toward the client on the LAN unit so the reversed error resolves
    // a tx interface + MAC (egress ifindex 24).
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Install the forward NAT session (client:client_port -> server:80 SNAT'd
    // to snat_ip:snat_port) so the embedded reversal can recover the client.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let sessions_before = sessions.len();

    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    let filter = forwarding
        .filter_state
        .iface_filter_v4_fast
        .get(&12)
        .expect(
            "the count filter did not attach to ifindex 12; the assertions below \
             would read a counter nothing was ever asked to increment",
        );

    // The criterion: the count term advanced for this packet.
    //
    // Under cfg(test) record_filter_counter writes through to the counter
    // immediately (filter/mod.rs) and flush_recorded_filter_counters is a
    // no-op, so there is no 64-packet batching window to wait out and a zero
    // here is a real zero rather than an unflushed one.
    assert_eq!(
        filter.terms[0].counter.packets.load(Ordering::Relaxed),
        1,
        "an interface `filter input` count term must advance for a \
         reverse-translated embedded-ICMP error. Before #7359 the reversal \
         forwarded to the client and `continue`d past the filter entirely, so \
         the term never saw the packet and its counter stayed 0 — an operator \
         reading `show firewall` was told nothing had arrived."
    );
    // Bytes as well as packets. A counter that increments packets but not
    // bytes is a real defect, and a packets-only assertion cannot see it.
    // 70 bytes here is the full frame; asserting frame.len() rather than a
    // literal keeps it true if the fixture frame is ever rebuilt.
    assert_eq!(
        filter.terms[0].counter.bytes.load(Ordering::Relaxed),
        frame.len() as u64,
        "the count term recorded a packet but the wrong byte total"
    );

    // The filter is NON-terminating, so the reversal must still reach the
    // client. Without this the cell cannot distinguish "the filter saw the
    // packet" from "the filter dropped the packet" — and a fix that ran the
    // filter first but then swallowed every reversal would satisfy the counter
    // assertion above while breaking embedded-ICMP delivery outright.
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "a count-only (fall-through) input filter must not stop the reversal; \
         {} prebuilt forward(s) were queued, want exactly 1",
        binding.scratch.scratch_forwards.len()
    );
}

/// Fixture guard for the #7359 ordering test: does the discard filter actually
/// ATTACH to ifindex 12 in the BUILT forwarding state?
///
/// Kept as a permanent cell rather than deleted after use, because the sibling
/// test asserts an ABSENCE — no queued forward — and an absence assertion is
/// satisfied just as well by a fixture that configures nothing. If the filter
/// silently stopped attaching (a renamed snapshot field, a changed family
/// string, an ifindex that moved), the ordering test would keep passing while
/// measuring nothing at all. This cell is what makes that impossible.
#[test]
fn the_7359_fixture_actually_attaches_its_input_filter() {
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    snapshot.filters.push(crate::protocol::FirewallFilterSnapshot {
        name: "block-all-in".to_string(),
        family: "inet".to_string(),
        terms: vec![crate::protocol::FirewallTermSnapshot {
            name: "t-discard".to_string(),
            action: "discard".to_string(),
            ..Default::default()
        }],
    });
    let mut attached = 0;
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == 12 {
            iface.filter_input_v4 = "block-all-in".to_string();
            attached += 1;
        }
    }
    assert_eq!(attached, 1, "expected exactly one ifindex-12 interface in nat_snapshot");
    let forwarding = build_forwarding_state(&snapshot);
    let has = forwarding.filter_state.iface_filter_v4_fast.contains_key(&12);
    assert!(
        has,
        "the discard filter did not attach to ifindex 12 in the built forwarding state; \
         keys present: {:?}",
        forwarding.filter_state.iface_filter_v4_fast.keys().collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// #8271: two ICMP-error arms paired the DECAPPED inner meta with the
// UN-DECAPPED outer frame.
//
// `poll_binding_process_descriptor` substitutes an owned, decapped inner frame
// for the raw UMEM frame at `stage_native_gre_decap` and rebinds `meta` to
// describe that inner packet. The NAT64 ICMP-error arm and the embedded-ICMP
// reversal arm both CLASSIFIED on `packet_frame` (correctly, at the inner
// `meta.l4_offset`) and then handed the helper `raw_frame` + `desc` -- the
// still-encapsulated outer frame -- together with the INNER meta. The helper
// then parsed outer bytes at inner offsets.
//
// This is the #1885/#1902 class. Two OTHER arms of the same function were fixed
// for exactly this pairing and carry comments saying so; these two were not,
// and they are reachable on the same input those fixes were about: a
// GRE-decapped ICMP error.
//
// THE FIXTURE USES A VLAN-TAGGED UNDERLAY DELIBERATELY. #1885's experience is
// that the failure mode is not guessable from the shape: on an UNTAGGED
// underlay the mis-paired read lands on the outer L3 header, which has a valid
// version nibble, so the parse can proceed and fail as a miss. The 4-byte
// dot1q tag is what turns the same defect into a misaligned slice. A fixture
// built on an untagged underlay would pass under the defect for the wrong
// reason, which is why the issue asks for the tagged shape by name.
// ---------------------------------------------------------------------------

#[test]
fn gre_decapped_embedded_icmp_reversal_reads_the_inner_frame_8271() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;

    // The SAME ICMP error the #5690 cell drives -- outer router -> snat_ip,
    // embedded quoted snat_ip:snat_port -> server:80 -- but carried as the GRE
    // payload rather than presented directly. `build_icmp_te_frame_v4` returns
    // an Ethernet frame; the GRE payload is the IP packet, so the 14-byte L2
    // header is stripped.
    let inner_l2 = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
    let inner = inner_l2[14..].to_vec();
    // vlan 80 = the live reth0.80 shape. See the header note on why tagged.
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);

    // allow_embedded_icmp gates the poll-path reversal — enable it.
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    // #8271: and a GRE tunnel terminating on this node, so the outer frame is
    // DECAPPED before the embedded-ICMP arm classifies. Without this the frame
    // never reaches `stage_native_gre_decap`, `packet_frame` stays equal to
    // `raw_frame`, and the cell cannot tell the fixed code from the broken code
    // -- which is exactly why all 5224 existing cells passed against both.
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "gr-0/0/0.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        tunnel: true,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.255.0.1/30".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
        id: 824,
        interface: "gr-0/0/0.0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        zone: "wan".to_string(),
        mode: "gre".to_string(),
        outer_family: "inet".to_string(),
        source: "172.16.80.8".to_string(),
        destination: "203.0.113.9".to_string(),
        transport_table: "inet.0".to_string(),
        ttl: 64,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);

    // The error ingresses on the WAN (reth0.80, ifindex 12) since it is
    // addressed to the SNAT address; the reversal resolves egress toward the
    // client on the LAN (reth1.0, ifindex 24), so learn the client neighbor.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");

    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    // The shim-contract meta for the OUTER GRE frame on a TAGGED underlay:
    // L3 at 18, protocol GRE. `stage_native_gre_decap` rebinds this to describe
    // the inner packet; the arms under test then run on the rebound meta, which
    // is the whole point of the issue.
    let mut meta = gre_to_self_outer_meta(80, frame.len());
    meta.ingress_ifindex = 12;
    meta.config_generation = 7;
    meta.fib_generation = 9;
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    // Neighbor toward the client on the LAN unit so the reversed error resolves
    // a tx interface + MAC (egress ifindex 24).
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Install the forward NAT session (client:client_port -> server:80 SNAT'd
    // to snat_ip:snat_port) so the embedded reversal can recover the client.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let sessions_before = sessions.len();

    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    // THE LOAD-BEARING #8271 ASSERTION. Under the defect the helper receives
    // the outer GRE frame while `meta` describes the inner packet, so the
    // parse reads GRE/outer-IP bytes at inner offsets, finds no ICMP error it
    // recognises, and queues nothing. RED on revert: length 0, not 1.
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "a GRE-DECAPPED embedded-ICMP error must reverse exactly as the \
         un-encapsulated one does. Queueing nothing means the helper parsed \
         the un-decapped OUTER frame at the INNER meta's offsets (#8271)."
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let reversed = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("embedded-ICMP reversal must queue a PREBUILT reversed frame"),
    };
    assert_eq!(
        reversed[34], 11,
        "the reversed frame must still be an ICMP Time Exceeded built from the \
         INNER packet's bytes"
    );
    let outer_dst = Ipv4Addr::new(reversed[30], reversed[31], reversed[32], reversed[33]);
    assert_eq!(
        outer_dst, client_ip,
        "outer destination must be restored from the SNAT address to the client"
    );
    // Embedded IP at eth(14)+outerIP(20)+ICMP(8)=42; inner src at +12 = 54.
    let embedded_src = Ipv4Addr::new(reversed[54], reversed[55], reversed[56], reversed[57]);
    assert_eq!(
        embedded_src, client_ip,
        "embedded inner source must be reverse-translated from SNAT addr to client"
    );
    // Inner TCP source port at 42+20 = 62 restored to the pre-NAT client port.
    let embedded_src_port = u16::from_be_bytes([reversed[62], reversed[63]]);
    assert_eq!(
        embedded_src_port, client_port,
        "embedded inner source port must be reverse-translated to the client port"
    );
    // #5690: the non-query error must NOT become a session/cache authority.
    assert!(
        fwd.flow_key.is_none(),
        "reversed ICMP error must carry flow_key=None (never seeds a session)"
    );
    // Egress resolves toward the client on the LAN unit (ifindex 24).
    assert_eq!(fwd.target_ifindex, 24, "reversed error egresses toward the client");
    // The error is stateless: it seeds no new session and is not recycled here.
    assert_eq!(
        sessions.len(),
        sessions_before,
        "the ICMP error must not seed a new session"
    );
    assert!(
        binding.scratch.scratch_recycle.is_empty(),
        "a queued prebuilt forward owns the descriptor; no recycle"
    );
}


/// #8271 arm 1: the NAT64 ICMP-error arm, GRE-decapped.
///
/// The sibling of `gre_decapped_embedded_icmp_reversal_reads_the_inner_frame_8271`
/// for the OTHER arm the issue names. It is a separate cell because it is a
/// separate defect: reverting arm 1 alone left the whole 5230-cell suite green,
/// including that sibling. Two arms were broken; one cell proves one arm.
///
/// Same construction and the same reason for the tagged underlay -- see the
/// header note above the embedded-ICMP cell.
///
/// Note this arm is UNGATED (`allow_embedded_icmp` is deliberately not set on
/// the #6472 original either): it needs only a configured NAT64 prefix, so its
/// reachability is strictly wider than arm 2's.
#[test]
fn gre_decapped_nat64_icmp_error_reads_the_inner_frame_8271() {
    let router_ip = Ipv4Addr::new(172, 16, 80, 1);
    let mut inner_l2 = build_icmp_te_frame_v4(
        router_ip,
        n6472_pool_v4(),
        n6472_server_v4(),
        N6472_XLATED_PORT,
        N6472_SERVER_PORT,
        PROTO_TCP,
    );
    n6472_patch_ptb(&mut inner_l2, 34);
    // The GRE payload is the IP packet, so drop the 14-byte L2 header.
    let inner = inner_l2[14..].to_vec();
    let frame = build_gre_to_self_outer_frame_v4(80, &inner);

    let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"));
    // The GRE tunnel that makes `packet_frame` differ from `raw_frame`. Its
    // source must be the outer destination the fixture frame carries
    // (172.16.80.8) or `stage_native_gre_decap` never fires and the cell
    // silently degrades into a duplicate of the #6472 original.
    snapshot.interfaces.push(InterfaceSnapshot {
        name: "gr-0/0/0.0".to_string(),
        zone: "wan".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        tunnel: true,
        addresses: vec![InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.255.0.1/30".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
        id: 824,
        interface: "gr-0/0/0.0".to_string(),
        linux_name: "gr-0-0-0".to_string(),
        ifindex: 77,
        zone: "wan".to_string(),
        mode: "gre".to_string(),
        outer_family: "inet".to_string(),
        source: "172.16.80.8".to_string(),
        destination: "203.0.113.9".to_string(),
        transport_table: "inet.0".to_string(),
        ttl: 64,
        ..Default::default()
    }];
    let forwarding = build_forwarding_state(&snapshot);

    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    n6472_install_sessions(&mut sessions, 123_000_000_000);

    let mut meta = gre_to_self_outer_meta(80, frame.len());
    meta.ingress_ifindex = 12;
    meta.config_generation = 7;
    meta.fib_generation = 9;
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);

    // RED on revert: under the defect the helper parses the un-decapped outer
    // GRE frame at the inner meta's offsets, recognises no ICMP error, and
    // queues nothing.
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "a GRE-DECAPPED NAT64 ICMP error must translate exactly as the \
         un-encapsulated one does. Queueing nothing means the helper parsed \
         the un-decapped OUTER frame at the INNER meta's offsets (#8271)."
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let out = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("the NAT64 ICMP error translation must queue a PREBUILT frame"),
    };
    // The cross-family translation is the payload of the fix: these bytes can
    // only be right if the INNER packet was the one parsed.
    assert_eq!(&out[12..14], &[0x86, 0xdd], "translated to IPv6");
    assert_eq!(out[14 + 6], PROTO_ICMPV6, "next header ICMPv6");
    let icmp6 = &out[14 + 40..];
    assert_eq!(icmp6[0], 2, "ICMPv6 Packet Too Big type");
    let mtu = u32::from_be_bytes([icmp6[4], icmp6[5], icmp6[6], icmp6[7]]);
    assert_eq!(
        mtu, 1420,
        "the PTB MTU is read out of the INNER ICMP error's own bytes, so it is \
         wrong or absent if the outer frame was parsed"
    );
}

/// #9030: a PURE-DNAT flow must reach the embedded-ICMP NAT reversal.
///
/// Closed #3112 landed the destination-side reversal builders, their struct
/// fields and their regression tests, and the production caller could not
/// reach any of it: the gate in `try_reverse_embedded_icmp_error` tested
/// `rewrite_src.is_none()`, and a pure-DNAT decision is
/// `rewrite_dst: Some(_), rewrite_src: None`. The existing #3112 cells call the
/// builders DIRECTLY, so they stayed green over an unreachable path -- which is
/// why this cell drives `poll_binding_process_descriptor`, the real call site.
///
/// Fail-on-revert: restore the gate to `rewrite_src.is_none()` and nothing is
/// queued, so `scratch_forwards` is empty and this test goes RED.
#[test]
fn poll_descriptor_embedded_icmp_reversal_reachable_for_pure_dnat_9030() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let vip_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let client_port: u16 = 12345;

    // Outer: router -> CLIENT (an ICMP error travels back to the original
    // source); embedded quoted: client:client_port -> server:80, i.e. the
    // POST-DNAT tuple as it appeared on the wire toward the real server.
    let frame = build_icmp_te_frame_v4(router_ip, client_ip, server_ip, client_port, 80, PROTO_TCP);

    // allow_embedded_icmp gates the poll-path reversal — enable it.
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    let forwarding = build_forwarding_state(&snapshot);

    // The error ingresses on the WAN (reth0.80, ifindex 12) since it is
    // addressed to the SNAT address; the reversal resolves egress toward the
    // client on the LAN (reth1.0, ifindex 24), so learn the client neighbor.
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");

    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        tcp_flags: 0,
        dscp: 0,
        config_generation: 7,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let meta_bytes = unsafe {
        std::slice::from_raw_parts((&meta as *const UserspaceDpMeta).cast::<u8>(), meta_len)
    };
    unsafe {
        binding
            .umem
            .area()
            .slice_mut_unchecked(meta_offset, meta_len)
            .expect("meta slice")
            .copy_from_slice(meta_bytes);
        binding
            .umem
            .area()
            .slice_mut_unchecked(frame_offset, frame.len())
            .expect("frame slice")
            .copy_from_slice(&frame);
    }
    binding.xsk.rx.push_for_test(XdpDesc {
        addr: frame_offset as u64,
        len: frame.len() as u32,
        options: 0,
    });

    let ident = binding.identity();
    let binding_lookup = WorkerBindingLookup::from_bindings(std::slice::from_ref(&binding));
    let mirror_targets = MirrorTargetMap::default();
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    // Neighbor toward the client on the LAN unit so the reversed error resolves
    // a tx interface + MAC (egress ifindex 24).
    learn_dynamic_neighbor(
        &forwarding,
        &dynamic_neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let ike_exchanges = Arc::new(crate::afxdp::forwarding::IkeExchangeTable::new());
    let local_tunnel_deliveries = Arc::new(ArcSwap::from_pointee(BTreeMap::new()));
    let recent_exceptions = Arc::new(Mutex::new(ExceptionEventRing::new()));
    let last_resolution = Arc::new(Mutex::new(None));
    let peer_worker_commands = Vec::new();
    let dnat_fds = DnatTableFds::default();
    let rg_epochs = std::array::from_fn(|_| AtomicU32::new(0));
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let __pptp_control_7699 = std::sync::Arc::new(crate::session::pptp_control::PptpControlInbox::default());
    let worker_ctx = WorkerContext {
        pptp_control: &__pptp_control_7699,
        ident: &ident,
        binding_lookup: &binding_lookup,
        mirror_targets: &mirror_targets,
        forwarding: &forwarding,
        ha_state: &ha_state,
        dynamic_neighbors: &dynamic_neighbors,
        neighbor_resolver: None,
        shared_sessions: &shared_sessions,
        shared_nat_sessions: &shared_nat_sessions,
        shared_forward_wire_sessions: &shared_forward_wire_sessions,
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
        slow_path: None,
        event_stream: Some(&event_handle),
        local_tunnel_deliveries: &local_tunnel_deliveries,
        recent_exceptions: &recent_exceptions,
        last_resolution: &last_resolution,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: crate::afxdp::empty_worker_commands_by_id(),
        dnat_fds: &dnat_fds,
        rg_epochs: &rg_epochs,
        cold_path_sample_mask: 0xff,
    };

    // Install the forward NAT session (client:client_port -> server:80 SNAT'd
    // to snat_ip:snat_port) so the embedded reversal can recover the client.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(vip_ip),
            src_port: client_port,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                // PURE DNAT: no source rewrite at all. This is the decision
                // shape the #9030 gate declined.
                rewrite_src: None,
                rewrite_dst: Some(IpAddr::V4(server_ip)),
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let sessions_before = sessions.len();

    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    let area_ptr = binding.umem.area() as *const MmapArea;

    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: 7,
            fib_generation: 9,
        },
        123_000_000_000,
        123,
        0,
        0,
        -1,
        -1,
        &worker_ctx,
        &mut telemetry,
    );

    // The load-bearing #9030 assertion: a PURE-DNAT flow reaches the reversal at
    // all. Before the gate was widened, `rewrite_src.is_none()` returned
    // NotHandled here and nothing was queued.
    assert_eq!(
        binding.scratch.scratch_forwards.len(),
        1,
        "a pure-DNAT flow must reach the embedded-ICMP reversal on the real poll \
         path -- the SNAT-only gate declined it, which made every builder #3112 \
         landed unreachable from production (#9030)"
    );
    let fwd = &binding.scratch.scratch_forwards[0];
    let reversed = match &fwd.frame {
        PendingForwardFrame::Prebuilt(bytes) => bytes,
        _ => panic!("embedded-ICMP reversal must queue a PREBUILT reversed frame"),
    };
    assert_eq!(reversed[34], 11, "reversed frame stays an ICMP Time Exceeded");
    let outer_dst = Ipv4Addr::new(reversed[30], reversed[31], reversed[32], reversed[33]);
    assert_eq!(outer_dst, client_ip, "the error still travels to the client");
    // Embedded IP at eth(14)+outerIP(20)+ICMP(8)=42; inner DST at +16 = 58.
    // THIS is what #3112 built and #9030 makes reachable: the client's PMTUD
    // matches on the quote, so the quoted destination must be the VIP it
    // actually addressed, not the internal server it was DNAT'd to.
    let embedded_dst = Ipv4Addr::new(reversed[58], reversed[59], reversed[60], reversed[61]);
    assert_eq!(
        embedded_dst, vip_ip,
        "embedded inner DESTINATION must be reverse-translated from the internal \
         server back to the VIP the client addressed -- otherwise the client sees \
         an error quoting a packet it never sent and PMTUD to the VIP is broken"
    );
    // The inner SOURCE is the client and was never translated: it must be left
    // alone. A reversal that rewrote it would corrupt the quote.
    let embedded_src = Ipv4Addr::new(reversed[54], reversed[55], reversed[56], reversed[57]);
    assert_eq!(
        embedded_src, client_ip,
        "a pure-DNAT flow has no source translation; the inner source must be untouched"
    );
    assert!(
        fwd.flow_key.is_none(),
        "reversed ICMP error must carry flow_key=None (never seeds a session)"
    );
    assert_eq!(
        sessions.len(),
        sessions_before,
        "the ICMP error must not seed a new session"
    );
}

/// #9031 END-TO-END: an ICMP error quoting a TRANSLATED GRE tunnel must resolve
/// against the live session — through the real
/// `try_embedded_icmp_nat_match_from_frame` path, not a key comparison.
///
/// This is the cell the parser-level ones cannot be: the four forward-key
/// constructors in `nat_match_v4`/`nat_match_v6`/`session_match` are simple
/// pass-throughs of `hdr.discriminator`, so reverting any one of them to
/// `Default::default()` leaves every parser cell GREEN. Only a lookup that
/// actually goes through a constructor can red them, which is why #9031's
/// acceptance asks for a rewritten-frame observation rather than a key hit.
///
/// The session is published as a SYNC IMPORT, so this is also the HA-imported
/// row: synchronization correctly preserves the discriminator, so an imported
/// GRE session inherited exactly the same mismatch.
#[test]
fn embedded_icmp_resolves_a_translated_gre_tunnel_9031() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    // GRE has no L4 ports, so this slot carries the RFC 2890 KEY. It is the
    // whole identity of the tunnel and the only thing separating two tunnels
    // between the same pair of addresses.
    let gre_key: u16 = 40000;

    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, gre_key, 0, PROTO_GRE);
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

    let mut sessions = SessionTable::new();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_GRE,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: 0,
            dst_port: 0,
            // The live session carries the tunnel's real identity. Before
            // #9031 the embedded lookup key hard-coded None, and SessionKey's
            // Eq includes this field, so the probe could never equal this.
            discriminator: TunnelDiscriminator::Keyed(gre_key as u32),
            routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                // ADDRESS-ONLY source NAT: `match_rules.rs` routes a protocol
                // with no L4 ports to `reserve_address_only`, which is how GRE
                // genuinely reaches same-family SNAT and is what makes this
                // reachable at all.
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        protocol: PROTO_GRE,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect(
        "#9031: the ICMP error quoting a translated GRE tunnel found NO session. \
         Every embedded lookup key hard-coded discriminator: None while the live \
         session carries Keyed(k), and SessionKey's Eq includes that field, so \
         every exact index probe missed. The outer destination and quoted source \
         cannot be restored and no usable signal reaches the endpoint — PMTUD and \
         unreachable/traceroute signalling are deterministically suppressed for \
         the tunnel",
    );

    // THE REWRITTEN FRAME, not just a key hit: the original (pre-translation)
    // source must be recovered, which is the thing the endpoint needs.
    assert_eq!(
        icmp_match.original_src,
        IpAddr::V4(client_ip),
        "#9031: the quoted source must be un-translated back to the client"
    );
    assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V4(snat_ip)));
    assert_eq!(icmp_match.resolution.egress_ifindex, 24);
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

/// CONTROL: a quote naming a DIFFERENT tunnel key must NOT resolve against this
/// session. Without this, a "fix" that wildcarded the discriminator would pass
/// the cell above while letting one tunnel's ICMP error resolve against
/// another's session — the fail-open direction.
#[test]
fn embedded_icmp_does_not_resolve_a_different_gre_tunnel_9031() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let session_key_value: u16 = 40000;
    let quoted_key_value: u16 = 40001; // a DIFFERENT tunnel

    let frame =
        build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, quoted_key_value, 0, PROTO_GRE);
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

    let mut sessions = SessionTable::new();
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    let mut entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_GRE,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: 0,
            dst_port: 0,
            discriminator: TunnelDiscriminator::Keyed(session_key_value as u32),
            routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        protocol: PROTO_GRE,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    entry.key.discriminator = TunnelDiscriminator::Keyed(session_key_value as u32);
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(
        try_embedded_icmp_nat_match_from_frame(
            &frame,
            meta,
            &mut sessions,
            &forwarding,
            &neighbors,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            1_000_000,
        )
        .is_none(),
        "#9031: an ICMP error quoting tunnel key {quoted_key_value} resolved \
         against the session for tunnel key {session_key_value}. GRE has no L4 \
         ports, so the discriminator is the ONLY thing separating two tunnels \
         between the same pair of addresses — a wildcarding fix would satisfy the \
         positive cell and cross tunnels here"
    );
}

/// #9031: the FORWARD `embedded_key` — the quote looked up AS-IS — must carry
/// the discriminator too.
///
/// The two cells above resolve through the reply key
/// (`lookup_forward_nat_across_scopes`), so reverting the four FORWARD-key
/// constructors to `Default::default()` left them green. That is the mutant
/// #9031's acceptance names, and it needed a fixture where the SESSION-FALLBACK
/// path is the one that hits: a session whose key IS the quoted tuple, which is
/// how an untranslated (or already-wire-form) GRE flow is matched.
///
/// Without this, a fix could wire the reply key alone and every GRE ICMP error
/// for a non-forward-NAT session would still miss.
#[test]
fn the_as_is_embedded_key_carries_the_discriminator_9031() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let tunnel_src = Ipv4Addr::new(172, 16, 80, 8);
    let tunnel_dst = Ipv4Addr::new(1, 1, 1, 1);
    let gre_key: u16 = 40000;

    // The quote names tunnel_src -> tunnel_dst with this GRE key.
    let frame = build_icmp_te_frame_v4(router_ip, tunnel_src, tunnel_dst, gre_key, 0, PROTO_GRE);
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

    // A session keyed EXACTLY on the quoted tuple, carrying the tunnel's real
    // identity — so only the as-is `embedded_key` can find it.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_GRE,
            src_ip: IpAddr::V4(tunnel_src),
            dst_ip: IpAddr::V4(tunnel_dst),
            src_port: 0,
            dst_port: 0,
            discriminator: TunnelDiscriminator::Keyed(gre_key as u32),
            routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: None,
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_GRE,
        0,
    ));

    assert!(
        try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 123_100_000_000, 0)
            .is_some(),
        "#9031: the as-is embedded key found no session for a quoted GRE tunnel \
         whose session is keyed on exactly that tuple. SessionKey's Eq includes \
         the discriminator, so a forward key built with None can never equal a \
         session carrying Keyed({gre_key})"
    );
}

/// CONTROL for the cell above: the same lookup must MISS when the quoted key
/// names a different tunnel, so the assertion there is attributable to the
/// discriminator matching rather than to the tuple alone.
#[test]
fn the_as_is_embedded_key_does_not_cross_tunnels_9031() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let tunnel_src = Ipv4Addr::new(172, 16, 80, 8);
    let tunnel_dst = Ipv4Addr::new(1, 1, 1, 1);

    let frame = build_icmp_te_frame_v4(router_ip, tunnel_src, tunnel_dst, 40001, 0, PROTO_GRE);
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

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_GRE,
            src_ip: IpAddr::V4(tunnel_src),
            dst_ip: IpAddr::V4(tunnel_dst),
            src_port: 0,
            dst_port: 0,
            discriminator: TunnelDiscriminator::Keyed(40000),
            routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: None,
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_GRE,
        0,
    ));

    assert!(
        try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 123_100_000_000, 0)
            .is_none(),
        "#9031: a quote naming tunnel key 40001 matched the session for tunnel \
         key 40000. GRE has no L4 ports, so without the discriminator the two \
         tunnels are indistinguishable and one tunnel's error resolves against \
         the other's session"
    );
}


// ---------------------------------------------------------------------------
// #9298 END-TO-END: an ICMP error quoting a PPTP data packet must resolve
// against the live call's session, through the real production arms.
//
// WHY THESE EXIST ON TOP OF THE UNIT CELLS. The five
// `pptp_embedded_9298` cells in `icmp_embed/mod.rs` pin
// `resolve_quoted_pptp_discriminator` itself. They cannot see the WIRING: the
// three key constructors (`nat_match_v4`, `nat_match_v6`, `session_match`) each
// call the resolver and drop the result into `SessionKey.discriminator`, and
// reverting a call site back to `hdr.discriminator` leaves every unit cell
// green — the function still behaves, nobody asks it.
//
// WHAT THESE CATCH, AS MEASURED BY MUTATION (not as hoped): a revert of the
// resolver's ARGUMENTS or of a REPLY key reds the v4/v6 cells. A revert of a
// FORWARD key alone does NOT — `nat_reverse_index` holds every forward entry's
// reverse wire key, so the reply key reaches the session first and a broken
// forward key has no match/no-match signal. Those three reverts are caught by
// the structural guard `every_same_family_forward_key_carries_the_resolved_quote_9298`
// in `icmp_embed/parse.rs`, which explains the index rule in full.
//
// Each cell below therefore drives `try_embedded_icmp_nat_match_from_frame` and
// asserts on the RECOVERED PRE-NAT SOURCE, which is the thing the endpoint
// needs and the thing that is unavailable when the probe misses.
// ---------------------------------------------------------------------------

/// A PPTP association plus a live GRE session carrying its handle.
///
/// The call ids are deliberately DIFFERENT per direction (RFC 2637 §4.1: each
/// side allocates its own id naming the peer it sends to), so a fixture that
/// accidentally worked by reading the wire value would only work in one
/// direction.
const PPTP_9298_CLIENT_CALL_ID: u16 = 0x0101;
const PPTP_9298_SERVER_CALL_ID: u16 = 0x0202;

fn install_pptp_association_9298(
    sessions: &mut SessionTable,
    client: IpAddr,
    server: IpAddr,
) -> u32 {
    let call = crate::session::pptp::PptpCall::new(
        client,
        PPTP_9298_CLIENT_CALL_ID,
        server,
        PPTP_9298_SERVER_CALL_ID,
    );
    let control = crate::session::pptp::ControlChannelId::new(client, 49_152, server, 1723);
    sessions
        .pptp_mut()
        .install(call, control, 1_000)
        .expect("fixture: the PPTP association must install")
}

#[allow(clippy::too_many_arguments)]
fn publish_pptp_gre_session_9298(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    client: IpAddr,
    server: IpAddr,
    snat: IpAddr,
    handle: u32,
    egress_ifindex: i32,
) {
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: if client.is_ipv4() {
                libc::AF_INET as u8
            } else {
                libc::AF_INET6 as u8
            },
            protocol: PROTO_GRE,
            src_ip: client,
            dst_ip: server,
            src_port: 0,
            dst_port: 0,
            // The live PPTP session carries the LOCALLY DERIVED handle
            // (#7188 decision 6 / #7699), never a wire call id — the two
            // directions of one call carry different wire values.
            discriminator: TunnelDiscriminator::Pptp(handle),
            routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex,
                tx_ifindex: egress_ifindex,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x50, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                // ADDRESS-ONLY source NAT: `match_rules.rs` routes a protocol
                // with no L4 ports to `reserve_address_only`, which is how GRE
                // genuinely reaches same-family SNAT.
                rewrite_src: Some(snat),
                rewrite_dst: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        metadata: SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        protocol: PROTO_GRE,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
}

/// FAIL-ON-REVERT (IPv4 arm): reds if `nat_match_v4`'s REPLY key goes back to
/// the raw quote, or if the resolver is asked about the wrong peer. The quote
/// then carries `Unparseable`, the live session carries `Pptp(handle)`,
/// `SessionKey`'s Eq includes the field (#7188), and the forward-NAT probe
/// misses. (A FORWARD-key-only revert is invisible here; see the section
/// header.)
#[test]
fn embedded_icmp_resolves_a_pptp_call_v4_9298() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    // The quote is of a packet the firewall SENT to the server, so it carries
    // the call id the SERVER allocated.
    let frame = build_icmp_te_frame_v4_pptp(router_ip, snat_ip, server_ip, PPTP_9298_SERVER_CALL_ID);
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

    let mut sessions = SessionTable::new();
    let handle = install_pptp_association_9298(
        &mut sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
    );
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    learn_dynamic_neighbor(
        &forwarding,
        &neighbors,
        24,
        0,
        IpAddr::V4(client_ip),
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    publish_pptp_gre_session_9298(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
        IpAddr::V4(snat_ip),
        handle,
        12,
    );

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect(
        "#9298: the ICMP error quoting a PPTP data packet found NO session. \
         `gre_transit_discriminator` returns Unparseable for EVERY version-1 \
         header, so without resolving the quoted Call ID against the \
         association table the probe carries a discriminator that equals no \
         live session — PMTUD and unreachable signalling stay suppressed for \
         every PPTP tunnel, which is the half #9031 left open",
    );

    // THE RECOVERED TUPLE, not just a key hit.
    assert_eq!(
        icmp_match.original_src,
        IpAddr::V4(client_ip),
        "#9298: the quoted source must be un-translated back to the client"
    );
    assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V4(snat_ip)));
    assert_eq!(icmp_match.embedded_proto, PROTO_GRE);
    assert_eq!(
        icmp_match.resolution.egress_ifindex, 24,
        "the error must be returned toward the client's ingress interface"
    );
    assert_eq!(
        icmp_match.resolution.neighbor_mac,
        Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    );
}

/// FAIL-ON-REVERT (IPv6 arm). `nat_match_v6` is a SEPARATE key constructor; a
/// v4-only cell leaves it free to be reverted with every test still green.
/// Reds on a revert of either v6 REPLY key (the fallback path builds a second).
#[test]
fn embedded_icmp_resolves_a_pptp_call_v6_9298() {
    let router_v6: Ipv6Addr = "2001:559:8585:ef00::fe".parse().expect("router v6");
    let snat_v6: Ipv6Addr = "2001:559:8585:80::8".parse().expect("snat v6");
    let client_v6: Ipv6Addr = "2001:559:8585:bf01::102".parse().expect("client v6");
    let server_v6: Ipv6Addr = "2606:4700:4700::1111".parse().expect("server v6");

    let frame =
        build_icmpv6_te_frame_pptp(router_v6, snat_v6, server_v6, PPTP_9298_SERVER_CALL_ID);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l3_offset: 14,
        l4_offset: 54,
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        ..UserspaceDpMeta::default()
    };

    let mut sessions = SessionTable::new();
    let handle = install_pptp_association_9298(
        &mut sessions,
        IpAddr::V6(client_v6),
        IpAddr::V6(server_v6),
    );
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    publish_pptp_gre_session_9298(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        IpAddr::V6(client_v6),
        IpAddr::V6(server_v6),
        IpAddr::V6(snat_v6),
        handle,
        12,
    );

    let icmp_match = try_embedded_icmp_nat_match_from_frame(
        &frame,
        meta,
        &mut sessions,
        &forwarding,
        &neighbors,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        1_000_000,
    )
    .expect(
        "#9298: the IPv6 arm must resolve a quoted PPTP Call ID too. PPTP over \
         IPv6 is the same enhanced-GRE header; leaving `nat_match_v6` on \
         `hdr.discriminator` makes it miss for exactly the same reason the v4 \
         arm did",
    );
    assert_eq!(
        icmp_match.original_src,
        IpAddr::V6(client_v6),
        "#9298: the quoted source must be un-translated back to the client"
    );
    assert_eq!(icmp_match.nat.rewrite_src, Some(IpAddr::V6(snat_v6)));
    assert_eq!(icmp_match.embedded_proto, PROTO_GRE);
}

/// FAIL-OPEN GUARD: a quote naming a DIFFERENT call must NOT resolve against
/// this session.
///
/// This one does NOT distinguish fixed from broken — it returns `None` before
/// and after — and it is not here to. It guards the direction a careless remedy
/// takes: wildcarding the discriminator, or resolving an unknown Call ID to
/// "whatever association is around", would satisfy the two cells above while
/// attributing one call's ICMP error to another call's session. PPTP tunnels
/// between one address pair are distinguished by nothing else.
#[test]
fn embedded_icmp_does_not_cross_pptp_calls_9298() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);

    // A call id the association table has never seen.
    let frame = build_icmp_te_frame_v4_pptp(router_ip, snat_ip, server_ip, 0x0999);
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

    let mut sessions = SessionTable::new();
    let handle = install_pptp_association_9298(
        &mut sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
    );
    let forwarding = build_forwarding_state(&nat_snapshot());
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    publish_pptp_gre_session_9298(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        IpAddr::V4(client_ip),
        IpAddr::V4(server_ip),
        IpAddr::V4(snat_ip),
        handle,
        12,
    );

    assert!(
        try_embedded_icmp_nat_match_from_frame(
            &frame,
            meta,
            &mut sessions,
            &forwarding,
            &neighbors,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            1_000_000,
        )
        .is_none(),
        "#9298: an ICMP error quoting an UNKNOWN PPTP Call ID must not resolve \
         against a live call. Attributing it would rewrite the error to the \
         wrong endpoint"
    );
}

/// THE THIRD CALL SITE. `session_match` is the same-family plain-lookup arm.
///
/// It has no non-test caller today (`afxdp/mod.rs` imports its wrapper under
/// `#[cfg(test)]`), so a mutant at its call site would be INERT in production.
/// The resolve is there so whoever wires this path does not inherit one that
/// silently misses every PPTP quote.
///
/// What this cell does and does NOT bind, as measured: it pins that a PPTP
/// quote REACHES the session through this module. It does NOT red when the
/// module's FORWARD keys revert to the raw quote — an earlier draft of this
/// comment claimed it did, and the mutation matrix refuted that. With the reply
/// key wired, `find_forward_nat_match` (the third fallback) still finds the
/// session. The forward keys are bound by the structural guard
/// `every_same_family_forward_key_carries_the_resolved_quote_9298` instead.
#[test]
fn embedded_icmp_session_match_resolves_a_pptp_call_9298() {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let tunnel_src = Ipv4Addr::new(172, 16, 80, 8);
    let tunnel_dst = Ipv4Addr::new(1, 1, 1, 1);

    let frame =
        build_icmp_te_frame_v4_pptp(router_ip, tunnel_src, tunnel_dst, PPTP_9298_SERVER_CALL_ID);
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

    let mut sessions = SessionTable::new();
    let handle = install_pptp_association_9298(
        &mut sessions,
        IpAddr::V4(tunnel_src),
        IpAddr::V4(tunnel_dst),
    );
    // Keyed EXACTLY on the quoted tuple, so only the as-is `embedded_key` — the
    // forward constructor under test — can find it.
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_GRE,
            src_ip: IpAddr::V4(tunnel_src),
            dst_ip: IpAddr::V4(tunnel_dst),
            src_port: 0,
            dst_port: 0,
            discriminator: TunnelDiscriminator::Pptp(handle),
            routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision::default(),
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_GRE,
        0,
    ));

    assert!(
        try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 123_100_000_000, 0)
            .is_some(),
        "#9298: the as-is embedded key found no session for a quoted PPTP data \
         packet whose session is keyed on exactly that tuple. SessionKey's Eq \
         includes the discriminator, so a forward key left on the quote's \
         `Unparseable` can never equal a session carrying Pptp(handle)"
    );
}

// #9528: the two flowless ICMP-error arms (#6472 NAT64 translation, #5690
// same-family reversal) `continue` with the descriptor consumed. The #6472 arm
// ran before the interface input filter, and both ran before the PBR verdict,
// so a `discard` term did not drop the error and its counter did not advance.
// Each drop cell carries a no-filter control in the SAME harness that must
// still forward, so a harness that never translated cannot pass the drop cell.

const G9528_FILTER: &str = "wan-in-9528";

fn g9528_attach(snapshot: &mut ConfigSnapshot, on_wan: bool, term: FirewallTermSnapshot) {
    snapshot.filters.push(FirewallFilterSnapshot {
        name: G9528_FILTER.to_string(),
        family: "inet".to_string(),
        terms: vec![term],
    });
    for iface in snapshot.interfaces.iter_mut() {
        if (on_wan && iface.ifindex == 12) || (!on_wan && iface.ifindex == 24) {
            iface.filter_input_v4 = G9528_FILTER.to_string();
        }
    }
}

fn g9528_term(action: &str, routing_instance: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: "t-9528".to_string(),
        action: action.to_string(),
        routing_instance: routing_instance.to_string(),
        count: "hits-9528".to_string(),
        ..Default::default()
    }
}

fn g9528_packets(forwarding: &ForwardingState) -> u64 {
    let filter = forwarding
        .filter_state
        .filters
        .get(&format!("inet:{G9528_FILTER}"))
        .expect("the input filter compiled");
    filter.terms[0].counter.packets.load(Ordering::Relaxed)
}

fn g9528_v4(ip: Ipv4Addr) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&ip.octets());
    a
}

/// Runs a v4 PTB quoting the live NAT64 session's forward wire packet through
/// the flowless arm. Returns (forwards queued, descriptors recycled, the filter
/// term's packet count or None without a filter).
fn g9528_run_nat64(term: Option<FirewallTermSnapshot>) -> (usize, usize, Option<u64>) {
    let router_ip = Ipv4Addr::new(172, 16, 80, 1);
    let mut frame = build_icmp_te_frame_v4(
        router_ip,
        n6472_pool_v4(),
        n6472_server_v4(),
        N6472_XLATED_PORT,
        N6472_SERVER_PORT,
        PROTO_TCP,
    );
    n6472_patch_ptb(&mut frame, 34);
    let mut snapshot = nat64_snapshot(lan_to_wan_permit("8.8.8.8/32", "permit-nat64-v4"));
    let with_filter = term.is_some();
    if let Some(term) = term {
        g9528_attach(&mut snapshot, true, term);
    }
    let forwarding = build_forwarding_state(&snapshot);
    let ha_state = txn_ha_state();
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    n6472_install_sessions(&mut sessions, 123_000_000_000);
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        config_generation: 7,
        fib_generation: 9,
        // The L3 identity the shim stamps. Left zero, the enforcement context is
        // None and the filter and PBR are skipped on EVERY path, so every drop
        // cell below would pass against a broken order (the #7359 warning).
        flow_src_addr: g9528_v4(router_ip),
        flow_dst_addr: g9528_v4(n6472_pool_v4()),
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &ha_state, &frame, meta);
    let count = with_filter.then(|| g9528_packets(&forwarding));
    (
        binding.scratch.scratch_forwards.len(),
        binding.scratch.scratch_recycle.len(),
        count,
    )
}

/// Runs a v4 Time-Exceeded quoting a live SNAT session through the #5690
/// same-family reversal (allow-embedded-icmp on). Same return as above.
fn g9528_run_same_family(term: Option<FirewallTermSnapshot>) -> (usize, usize, Option<u64>) {
    let router_ip = Ipv4Addr::new(10, 0, 0, 1);
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);
    let client_ip = Ipv4Addr::new(10, 0, 61, 102);
    let server_ip = Ipv4Addr::new(1, 1, 1, 1);
    let snat_port: u16 = 40000;
    let client_port: u16 = 12345;
    let frame = build_icmp_te_frame_v4(router_ip, snat_ip, server_ip, snat_port, 80, PROTO_TCP);
    let mut snapshot = nat_snapshot();
    snapshot.flow.allow_embedded_icmp = true;
    // The reversed error egresses toward the client on the LAN unit.
    // `..Default::default()`, not an exhaustive literal: NeighborSnapshot is an
    // additive wire struct (the #7689 ratchet).
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-1".to_string(),
        ifindex: 24,
        family: "inet".to_string(),
        ip: client_ip.to_string(),
        mac: "aa:bb:cc:dd:ee:ff".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    let with_filter = term.is_some();
    if let Some(term) = term {
        g9528_attach(&mut snapshot, true, term);
    }
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 12, 0);
    binding.interface = Arc::<str>::from("reth0.80");
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(client_ip),
            dst_ip: IpAddr::V4(server_ip),
            src_port: client_port,
            dst_port: 80,
            discriminator: Default::default(),
            routing_domain: 0,
        },
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
                neighbor_mac: Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                tx_vlan_id: 80,
            },
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_dst: None,
                rewrite_src_port: Some(snat_port),
                rewrite_dst_port: None,
                nat64: false,
                nptv6: false,
            },
        },
        SessionMetadata {
            ingress_zone: TEST_LAN_ZONE_ID,
            egress_zone: TEST_WAN_ZONE_ID,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 0,
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
        123_000_000_000,
        PROTO_TCP,
        0x18,
    ));
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        ingress_ifindex: 12,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 42,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_ICMP,
        config_generation: 7,
        fib_generation: 9,
        flow_src_addr: g9528_v4(router_ip),
        flow_dst_addr: g9528_v4(snat_ip),
        ..UserspaceDpMeta::default()
    };
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &BTreeMap::new(), &frame, meta);
    let count = with_filter.then(|| g9528_packets(&forwarding));
    (
        binding.scratch.scratch_forwards.len(),
        binding.scratch.scratch_recycle.len(),
        count,
    )
}

#[test]
fn nat64_icmp_error_is_dropped_by_an_input_filter_discard_9528() {
    assert_eq!(
        g9528_run_nat64(None).0,
        1,
        "control: with no filter the NAT64 error must be translated and queued, \
         or the drop below proves nothing"
    );
    let (forwards, recycled, count) = g9528_run_nat64(Some(g9528_term("discard", "")));
    assert_eq!(
        forwards, 0,
        "an input `discard` must drop a NAT64-translated ICMP error; the #6472 arm \
         ran before the input filter and queued it (#9528)"
    );
    assert_eq!(recycled, 1, "the dropped descriptor is recycled");
    assert_eq!(count, Some(1), "the discard term's counter advances exactly once");
}

#[test]
fn nat64_icmp_error_is_dropped_by_a_pbr_discard_9528() {
    let (forwards, recycled, count) = g9528_run_nat64(Some(g9528_term("discard", "scrub")));
    assert_eq!(
        forwards, 0,
        "a `then {{ routing-instance scrub; discard; }}` term must drop a NAT64-translated \
         ICMP error; its verdict lives only in the PBR evaluator the arm skipped (#9528)"
    );
    assert_eq!(recycled, 1, "the dropped descriptor is recycled");
    assert_eq!(count, Some(1), "the PBR term's counter advances exactly once");
}

#[test]
fn same_family_reversal_is_dropped_by_a_pbr_discard_9528() {
    assert_eq!(
        g9528_run_same_family(None).0,
        1,
        "control: with no filter the #5690 reversal must queue the reversed error, \
         or the drop below proves nothing"
    );
    let (forwards, recycled, count) =
        g9528_run_same_family(Some(g9528_term("discard", "scrub")));
    assert_eq!(
        forwards, 0,
        "a PBR `discard` must drop an embedded-ICMP reversal; the #5690 arm ran \
         before the PBR verdict and queued it (#9528)"
    );
    assert_eq!(recycled, 1, "the dropped descriptor is recycled");
    assert_eq!(count, Some(1), "the PBR term's counter advances exactly once");
}

/// Hoisted, not duplicated: a term that ACCEPTS (or only steers) still counts
/// exactly once, and the error is still delivered. A steer is not applied to an
/// error an arm queues; it goes to the quoted session's owner.
#[test]
fn icmp_error_arms_count_a_matching_term_exactly_once_9528() {
    for (what, run) in [
        ("NAT64", g9528_run_nat64 as fn(Option<FirewallTermSnapshot>) -> (usize, usize, Option<u64>)),
        ("same-family", g9528_run_same_family),
    ] {
        let (forwards, _, count) = run(Some(g9528_term("accept", "")));
        assert_eq!(forwards, 1, "{what}: an accepting input term must not stop the error");
        assert_eq!(count, Some(1), "{what}: an accepting input term counts exactly once");
        let (forwards, _, count) = run(Some(g9528_term("", "scrub")));
        assert_eq!(forwards, 1, "{what}: a PBR steer must not stop or redirect the error");
        assert_eq!(count, Some(1), "{what}: a PBR steer term counts exactly once");
    }
}

/// The hoist moved the PBR verdict above the ICMP-error arms, and the flowless
/// transit path below consumes it. A non-first fragment on that path must still
/// evaluate the PBR term exactly once, not once at the hoisted site and again
/// at the old one.
#[test]
fn flowless_fragment_evaluates_pbr_exactly_once_9528() {
    let mut snapshot = nat_snapshot();
    snapshot.neighbors.push(frag_transit_wan_neighbor());
    g9528_attach(&mut snapshot, false, g9528_term("", "scrub"));
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, 24, 0);
    binding.interface = Arc::<str>::from("reth1.0");
    let mut sessions = SessionTable::new();
    let frame = frag_v4_transit_frame();
    let mut meta = frag_v4_transit_meta();
    meta.pkt_len = frame.len() as u16;
    txn_run_descriptor(&mut binding, &mut sessions, &forwarding, &BTreeMap::new(), &frame, meta);
    assert_eq!(
        g9528_packets(&forwarding),
        1,
        "the flowless path must evaluate the PBR term exactly once"
    );
}
