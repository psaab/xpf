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
    let result = try_embedded_icmp_session_match_from_frame(&frame, meta, &mut sessions, 1_000_000);
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
    let worker_ctx = WorkerContext {
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
) {
    assert!(sessions.install_with_protocol(
        SessionKey {
            addr_family,
            protocol: PROTO_TCP,
            src_ip: client_ip,
            dst_ip: server_ip,
            src_port: 12345,
            dst_port: 80,
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
    let worker_ctx = WorkerContext {
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
    assert_eq!(
        forwarding.ifindex_to_zone_id.get(&11).copied(),
        Some(TEST_WAN_ZONE_ID),
        "physical parent ifindex 11 inherits reth0.80's wan zone"
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
    let worker_ctx = WorkerContext {
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
    let worker_ctx = WorkerContext {
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
    let worker_ctx = WorkerContext {
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
    let worker_ctx = WorkerContext {
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
    let worker_ctx = WorkerContext {
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

