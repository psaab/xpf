// #7212 END-TO-END: a static interface INPUT filter attached or tightened after
// a session was established revokes that session on its next packet, driven
// through the real `poll_binding_process_descriptor`.
//
// The helper-level cells in `poll_descriptor/filter_revalidation_7212_tests.rs`
// pin the VERDICT. These pin the CALLER: the pair teardown, the flow-cache
// eviction hand-off, and — the acceptance case the whole mechanism was chosen
// for — that a session the same interface's filter still PERMITS survives with
// its SNAT translated port intact.
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_support::*;
use super::*;
use crate::test_zone_ids::*;
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot,
    PolicyRuleSnapshot,
};
use crate::slowpath::SlowPathReinjector;
use std::sync::atomic::Ordering;

/// The generation the sessions below are STAMPED under: the config the operator
/// had before editing the filter.
const STAMPED_GENERATION: u64 = 6;
/// The generation the poll pass runs under: the commit that attached the filter.
const LIVE_GENERATION: u64 = 7;
/// `reth1.0`, the LAN ingress of the shared topology and of the driven frame.
const LAN_IFINDEX: i32 = 24;
/// The driven frame's tuple: 10.0.61.102:12345 -> 172.16.80.200:5201.
const FLOW_SRC_PORT: u16 = 12345;
const FLOW_DST_PORT: u16 = 5201;
/// A SIBLING flow on the SAME interface that the filter still permits, carrying
/// a source-NAT translation. Never packeted — its survival is what distinguishes
/// per-tuple revalidation from an interface-keyed family purge, which would drop
/// it with no packet at all.
const SIBLING_DST_PORT: u16 = 443;
const SIBLING_SNAT_PORT: u16 = 40001;

fn flow_key(dst_port: u16) -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: FLOW_SRC_PORT,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn revocation_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ingress_ifindex: LAN_IFINDEX as u32,
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
    }
}

fn revocation_decision(snat_port: Option<u16>) -> SessionDecision {
    SessionDecision { resolution: ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
        tx_vlan_id: 80,
    }, nat: NatDecision {
        rewrite_src: snat_port.map(|_| IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: snat_port,
        ..NatDecision::default()
    }, install_table_domain: 0, install_table_check: 0 }
}

/// Build the shared LAN->WAN topology with `terms` as `reth1.0`'s inet INPUT
/// filter.
fn revocation_snapshot(terms: Vec<FirewallTermSnapshot>) -> ConfigSnapshot {
    let mut snapshot = policy_deny_snapshot();
    snapshot.generation = LIVE_GENERATION;
    snapshot.fib_generation = 9;
    snapshot.filters = vec![FirewallFilterSnapshot {
        name: "edge-in".into(),
        family: "inet".into(),
        terms,
    }];
    for iface in snapshot.interfaces.iter_mut() {
        if iface.ifindex == LAN_IFINDEX {
            iface.filter_input_v4 = "edge-in".into();
        }
    }
    // PBR cells need a live `blue` table identity while leaving the tested
    // destination unrouted there. The address creates connected-table
    // presence, but no route covers 172.16.80.200.
    if snapshot.filters[0]
        .terms
        .iter()
        .any(|term| !term.routing_instance.is_empty())
    {
        snapshot.interfaces.push(InterfaceSnapshot {
            name: "blue0".into(),
            zone: "lan".into(),
            routing_instance: "blue".into(),
            linux_name: "blue0".into(),
            ifindex: 101,
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.250.0.1/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        });
        // The second packet is a new flow after pair teardown. Keep the
        // policy layer permissive so its unresolved explicit RI route remains
        // the observable NoRoute verdict rather than being downgraded to a
        // zone-policy deny because NoRoute has no egress zone.
        snapshot.default_policy = "permit".into();
    }
    // A lan->wan permit so the session under test is a flow the POLICY would
    // still admit. Without it a revocation could be mistaken for a policy deny.
    snapshot.policies.push(PolicyRuleSnapshot {
        name: "allow-lan-wan".into(),
        from_zone: "lan".into(),

        to_zone: "wan".into(),
        source_addresses: vec!["any".into()],
        destination_addresses: vec!["any".into()],
        applications: vec!["any".into()],
        application_terms: Vec::new(),
        action: "permit".into(),
        ..Default::default()
    });
    // #10554: the control keeps distinct per-row MACs. The LAN row regressing
    // to the WAN alias (02:bf:72:00:80:08) would silently reintroduce the
    // tripwire this repair removed — every driver below builds a LAN-dst frame.
    let lan_mac = snapshot
        .interfaces
        .iter()
        .find(|iface| iface.ifindex == LAN_IFINDEX)
        .expect("LAN row")
        .hardware_addr
        .clone();
    assert_eq!(
        lan_mac, "02:bf:72:01:00:01",
        "control LAN row must carry the LAN MAC, not the WAN alias (#10554)"
    );
    snapshot
}

fn term(name: &str, dport: &str, action: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: name.into(),
        protocols: vec!["tcp".into()],
        destination_ports: vec![dport.into()],
        action: action.into(),
        syslog: false,
        reject_message_type: String::new(),
        ..Default::default()
    }
}

fn pbr_term(name: &str, dport: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: name.into(),
        protocols: vec!["tcp".into()],
        destination_ports: vec![dport.into()],
        routing_instance: "blue".into(),
        action: "accept".into(),
        syslog: false,
        reject_message_type: String::new(),
        ..Default::default()
    }
}

fn per_packet_pbr_term(name: &str, dport: &str) -> FirewallTermSnapshot {
    let mut term = pbr_term(name, dport);
    term.tcp_flags = Some(TCP_FLAG_SYN);
    term
}

struct PollOutcome {
    sessions: SessionTable,
    revoked_scratch: Vec<crate::session::SessionKey>,
    revoked_count: u64,
    slow_path_packets: u64,
    no_route: u64,
    policy_deny: u64,
    session_miss: u64,
}

/// Pre-install the driven flow and its permitted SNAT sibling under
/// `STAMPED_GENERATION`, then drive ONE packet of the driven flow through the
/// real poll path under `LIVE_GENERATION`.
fn drive_one_packet(terms: Vec<FirewallTermSnapshot>) -> PollOutcome {
    drive_packets(terms, false, false)
}

fn drive_packets(
    terms: Vec<FirewallTermSnapshot>,
    second_packet: bool,
    fresh_hit: bool,
) -> PollOutcome {
    let snapshot = revocation_snapshot(terms);
    let forwarding = build_forwarding_state(&snapshot);
    let mut binding = BindingWorker::new_for_mirror_test(0, 0, LAN_IFINDEX, 0);
    binding.interface = Arc::<str>::from("reth1.0");

    let frame = build_policy_deny_tcp_syn_frame(crate::afxdp::tests_support::TEST_LAN_MAC);
    let meta_len = std::mem::size_of::<UserspaceDpMeta>();
    let frame_offset = 128;
    let meta_offset = frame_offset - meta_len;
    let meta = UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: meta_len as u16,
        ingress_ifindex: LAN_IFINDEX as u32,
        l3_offset: 14,
        l4_offset: 34,
        payload_offset: 54,
        pkt_len: frame.len() as u16,
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_SYN,
        config_generation: LIVE_GENERATION,
        fib_generation: 9,
        ..UserspaceDpMeta::default()
    };
    let push_packet = |binding: &mut BindingWorker| {
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
    };
    push_packet(&mut binding);

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
    let (event_handle, _event_rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let slow_path = second_packet.then(|| Arc::new(SlowPathReinjector::new_without_worker(1500)));
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
        slow_path: slow_path.as_ref(),
        shared_owner_rg_indexes: &shared_owner_rg_indexes,
        ike_exchanges: &ike_exchanges,
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

    // The two established sessions, stamped under the PREVIOUS generation —
    // exactly what an operator's edit leaves behind.
    let mut sessions = SessionTable::new();
    sessions.set_filter_revalidation_gen(STAMPED_GENERATION);
    assert!(sessions.install_with_protocol_with_origin(
        flow_key(FLOW_DST_PORT),
        revocation_decision(None),
        revocation_metadata(),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        flow_key(SIBLING_DST_PORT),
        revocation_decision(Some(SIBLING_SNAT_PORT)),
        revocation_metadata(),
        SessionOrigin::ForwardFlow,
        122_000_000_000,
        PROTO_TCP,
        0,
    ));
    if fresh_hit {
        // The per-packet PBR cell must enforce the route transition even
        // though this established entry already carries a live static stamp.
        sessions.set_filter_revalidation_gen(LIVE_GENERATION);
        sessions.mark_filter_revalidated(&flow_key(FLOW_DST_PORT), LAN_IFINDEX);
    }

    let mut screen = ScreenState::new();
    let mut batch = BatchCounters::default();
    let mut dbg = DebugPollCounters::default();
    let area_ptr = binding.umem.area() as *const MmapArea;

    let mut telemetry = TelemetryContext {
        dbg: &mut dbg,
        counters: &mut batch,
    };
    poll_binding_process_descriptor(
        &mut binding,
        0,
        area_ptr,
        1,
        &mut sessions,
        &mut screen,
        ValidationState {
            snapshot_installed: true,
            config_generation: LIVE_GENERATION,
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
    drop(telemetry);
    assert_eq!(
        batch.validated_packets, 1,
        "the descriptor must pass validation before filter revalidation"
    );
    assert_eq!(
        dbg.session_hit, 1,
        "the revocation fixture must exercise a real session hit"
    );
    if second_packet {
        push_packet(&mut binding);
        let mut telemetry = TelemetryContext {
            dbg: &mut dbg,
            counters: &mut batch,
        };
        poll_binding_process_descriptor(
            &mut binding,
            0,
            area_ptr,
            1,
            &mut sessions,
            &mut screen,
            ValidationState {
                snapshot_installed: true,
                config_generation: LIVE_GENERATION,
                fib_generation: 9,
            },
            124_000_000_000,
            124,
            0,
            0,
            -1,
            -1,
            &worker_ctx,
            &mut telemetry,
        );
    }

    PollOutcome {
        sessions,
        revoked_scratch: binding.scratch.scratch_filter_revoked_keys.clone(),
        revoked_count: dbg.filter_revoked_sessions,
        slow_path_packets: binding.live.slow_path_packets.load(Ordering::Relaxed),
        no_route: dbg.no_route,
        policy_deny: dbg.policy_deny,
        session_miss: dbg.session_miss,
    }
}

/// The issue's scenario, end to end. A static `then discard` attached to the
/// ingress interface AFTER the session was established revokes it on the next
/// packet: the session is gone from the table, the revocation is accounted, and
/// its key is handed to the flow-cache eviction so no cached descriptor can
/// serve the revoked tuple.
///
/// Deleting the teardown at the poll call site leaves the helper-level cells
/// green and reds only this one.
#[test]
fn static_discard_revokes_the_established_session_end_to_end_7212() {
    let out = drive_one_packet(vec![term("no-5201", "5201", "discard")]);

    let mut sessions = out.sessions;
    assert!(
        sessions
            .lookup(&flow_key(FLOW_DST_PORT), 124_000_000_000, 0)
            .is_none(),
        "the newly-denied session must be torn down, not merely have its packet \
         dropped"
    );
    assert_eq!(
        out.revoked_count, 1,
        "the revocation must be accounted exactly once"
    );
    assert!(
        out.revoked_scratch.contains(&flow_key(FLOW_DST_PORT)),
        "the revoked key must reach the flow-cache eviction, or a cached \
         descriptor keeps forwarding the revoked tuple (#6457 failure mode)"
    );
}

/// #10467 end-to-end bind: an established MAIN session that becomes subject
/// to a PBR steer into an empty VRF is dropped and revoked on the hit. The next
/// packet will take the session-miss path; this packet must never use MAIN.
#[test]
fn stale_pbr_empty_vrf_denies_and_revokes_the_established_hit_10467() {
    let out = drive_one_packet(vec![pbr_term("pbr-route", "5201")]);
    let mut sessions = out.sessions;
    assert!(
        sessions
            .lookup(&flow_key(FLOW_DST_PORT), 124_000_000_000, 0)
            .is_none(),
        "a stale PBR route transition must revoke the old MAIN session"
    );
    assert_eq!(
        out.revoked_count, 1,
        "the route transition must account for one revoked session"
    );
    assert!(
        out.revoked_scratch.contains(&flow_key(FLOW_DST_PORT)),
        "the route transition must evict the old flow-cache descriptor"
    );
}
/// A per-packet PBR term is evaluated even when the established entry's
/// generation/ingress stamp is Fresh. Its ordinary HIT evaluator returns
/// Accept, so the poll caller must still apply the route transition and revoke
/// the cached MAIN decision.
#[test]
fn fresh_per_packet_pbr_hit_revokes_cached_main_route_10467() {
    let out = drive_packets(
        vec![per_packet_pbr_term("pbr-syn", "5201")],
        false,
        true,
    );
    let mut sessions = out.sessions;
    assert!(
        sessions
            .lookup(&flow_key(FLOW_DST_PORT), 124_000_000_000, 0)
            .is_none(),
        "a matching per-packet PBR steer must revoke the cached MAIN session"
    );
    assert_eq!(out.revoked_count, 1);
    assert!(out.revoked_scratch.contains(&flow_key(FLOW_DST_PORT)));
}

/// The transition HIT is only half of the enforcement contract. After teardown,
/// the next packet is a session MISS and must perform the same explicit empty
/// table lookup without handing the original frame to the kernel MAIN FIB.
/// `drive_packets` uses a worker-less live reinjector so an accidental
/// slow-path enqueue is observable as `slow_path_packets == 1`.
#[test]
fn stale_pbr_empty_vrf_drops_the_followup_miss_10467() {
    let out = drive_packets(vec![pbr_term("pbr-route", "5201")], true, false);

    assert_eq!(
        out.slow_path_packets, 0,
        "the post-revocation MISS must not reinject the explicit-table NoRoute \
         frame into MAIN"
    );
    assert_eq!(out.no_route, 1, "the follow-up MISS must resolve in the empty RI");
    assert_eq!(
        out.policy_deny, 0,
        "the follow-up must reach route NoRoute, not fall through to policy deny"
    );
    assert_eq!(out.session_miss, 1, "the second packet must be a session MISS");
    assert_eq!(out.revoked_count, 1);
    assert!(out.revoked_scratch.contains(&flow_key(FLOW_DST_PORT)));
}

/// THE pinned acceptance case. A session on the SAME interface that the filter
/// still PERMITS is untouched — present, and with its source-NAT translated
/// port unchanged.
///
/// This is why the #5858 interface-keyed family purge was rejected: it would
/// drop this session with no packet of its own, and the non-persistent PAT
/// allocator would hand the recreated flow a DIFFERENT translated port, breaking
/// a connection the operator never touched.
#[test]
fn a_permitted_snat_session_on_the_same_interface_survives_with_its_port_7212() {
    let out = drive_one_packet(vec![term("no-5201", "5201", "discard")]);

    let mut sessions = out.sessions;
    let sibling = sessions
        .lookup(&flow_key(SIBLING_DST_PORT), 124_000_000_000, 0)
        .expect("a session the filter still permits must NOT be revoked");
    assert_eq!(
        sibling.decision.nat.rewrite_src_port,
        Some(SIBLING_SNAT_PORT),
        "the permitted flow's translated port must be unchanged"
    );
    assert_eq!(
        sibling.decision.nat.rewrite_src,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8)))
    );
    assert!(
        !out.revoked_scratch.contains(&flow_key(SIBLING_DST_PORT)),
        "a permitted session's key must never reach the eviction list"
    );
    assert_eq!(
        out.revoked_count, 1,
        "exactly the denied session was revoked"
    );
}

/// The control. With the same filter shape but an ACCEPT terminal, the driven
/// session survives too — so the revocation above is caused by the VERDICT and
/// not merely by the generation bump, the packet, or the presence of a filter.
#[test]
fn a_static_accept_filter_revokes_nothing_end_to_end_7212() {
    let out = drive_one_packet(vec![term("permit-5201", "5201", "accept")]);

    let mut sessions = out.sessions;
    assert!(
        sessions
            .lookup(&flow_key(FLOW_DST_PORT), 124_000_000_000, 0)
            .is_some(),
        "a permitted flow must survive its own revalidation"
    );
    assert!(
        sessions
            .lookup(&flow_key(SIBLING_DST_PORT), 124_000_000_000, 0)
            .is_some()
    );
    assert_eq!(out.revoked_count, 0);
    assert!(out.revoked_scratch.is_empty());
}
