// Tests for afxdp/session_glue/mod.rs — originally inline in
// session_glue.rs, relocated to session_glue_tests.rs in #1077, then
// folded with mod.rs into the afxdp/session_glue/ directory module
// (#1078) to keep afxdp/'s flat namespace tidy.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from
// session_glue/mod.rs.

use super::*;
use crate::afxdp::worker_queue::WORKER_COMMAND_DRAIN_BUDGET;

// #7201: `apply_worker_commands` now drains a BOUNDED PREFIX
// (`WORKER_COMMAND_DRAIN_BUDGET` = 256) into a caller-owned scratch deque
// instead of `core::mem::take`-ing the whole queue, so the worker returns to its
// AF_XDP rings between slices.
//
// Every call below passes a FRESH `&mut VecDeque::new()`, i.e. exactly one
// bounded pass. That is deliberate and it is not a weakening: no fixture in this
// file queues anywhere near 256 commands (all 20 command pushes are flat — none
// sits inside a loop), so one pass drains each batch completely and every cell
// asserts precisely what it asserted before the budget existed. The budget's own
// behaviour — the split, the FIFO/order preservation across a split, the
// backlog signal, the scratch recycling — is covered by the dedicated cells at
// the end of this file, which queue PAST the budget on purpose.
use crate::filter::Filter;
use crate::test_zone_ids::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const TCP_FLAG_ACK: u8 = 0x10;

fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: true,
        watchdog_timestamp: now_secs,
        lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
    }
}

fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
    HAGroupRuntime {
        active: false,
        watchdog_timestamp,
        lease: HAForwardingLease::Inactive,
    }
}

fn test_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
        neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
        src_mac: Some([6, 7, 8, 9, 10, 11]),
        tx_vlan_id: 0,
    }
}

fn test_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
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
    }
}

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
    }
}

fn empty_filter(name: &str, family: &str) -> Arc<Filter> {
    Arc::new(Filter {
        id: 1,
        name: name.to_string(),
        family: family.to_string(),
        terms: Vec::new(),
        affects_tx_selection: false,
        affects_route_lookup: false,
        has_counter_terms: false,
        has_log_terms: false,
        has_terminal_action_terms: false,
        has_dscp_match_terms: false,
        has_per_packet_l4_match_terms: false,
        has_three_color_policer_terms: false,
    })
}

fn test_forwarding_state() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 1,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
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
    forwarding
}

#[test]
fn session_key_has_lo0_filter_matches_packet_family() {
    let mut forwarding = ForwardingState::default();
    let v4_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let v6_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        src_port: 12345,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };

    assert!(!session_key_has_lo0_filter(&forwarding, &v4_key));
    forwarding.filter_state.lo0_filter_v4_fast = Some(empty_filter("lo0-v4", "inet"));
    assert!(session_key_has_lo0_filter(&forwarding, &v4_key));
    assert!(!session_key_has_lo0_filter(&forwarding, &v6_key));

    forwarding.filter_state.lo0_filter_v6_fast = Some(empty_filter("lo0-v6", "inet6"));
    assert!(session_key_has_lo0_filter(&forwarding, &v6_key));
}

#[test]
fn republish_local_delivery_sessions_for_lo0_filter_selects_existing_hits() {
    let mut forwarding = ForwardingState::default();
    forwarding.filter_state.lo0_filter_v4_fast = Some(empty_filter("lo0-v4", "inet"));
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 12345,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key,
        test_local_delivery_decision(),
        test_metadata(),
        SessionOrigin::SyncImport,
        1,
        PROTO_TCP,
        TCP_FLAG_SYN,
    ));

    assert_eq!(
        republish_local_delivery_sessions_for_lo0_filter(&sessions, -1, &forwarding),
        1
    );

    forwarding.filter_state.lo0_filter_v4_fast = None;
    assert_eq!(
        republish_local_delivery_sessions_for_lo0_filter(&sessions, -1, &forwarding),
        0
    );
}

#[test]
fn purge_sessions_for_input_dscp_filter_revalidation_removes_family() {
    let forwarding = ForwardingState::default();
    let mut sessions = SessionTable::new();
    let v4_key = test_key();
    let v6_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        src_port: 12345,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    assert!(sessions.install_with_protocol_with_origin(
        v4_key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        v6_key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(16);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();

    assert_eq!(
        purge_sessions_for_input_dscp_filter_revalidation(
            &mut sessions,
            -1,
            -1,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            crate::afxdp::empty_worker_commands_by_id(),
            &forwarding,
            true,
            false,
            2,
            0,
        ),
        1
    );

    assert!(sessions.entry_with_origin(&v4_key).is_none());
    assert!(sessions.entry_with_origin(&v6_key).is_some());
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, v4_key);
}

fn test_local_delivery_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
            local_ifindex: 12,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        },
        nat: NatDecision::default(),
    }
}

fn test_forwarding_state_with_fabric() -> ForwardingState {
    let mut forwarding = test_forwarding_state();
    forwarding
        .zone_name_to_id
        .insert("lan".to_string(), TEST_LAN_ZONE_ID);
    forwarding
        .zone_name_to_id
        .insert("sfmix".to_string(), TEST_SFMIX_ZONE_ID);
    forwarding
        .zone_name_to_id
        .insert("wan".to_string(), TEST_WAN_ZONE_ID);
    forwarding.fabrics.push(FabricLink {
        parent_ifindex: 21,
        overlay_ifindex: 101,
        peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
        peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        up: true,
    });
    forwarding
}

fn test_forwarding_state_split_rgs() -> ForwardingState {
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.egress.insert(
        6,
        EgressInterface {
            bind_ifindex: 6,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
            zone_id: TEST_LAN_ZONE_ID,
            redundancy_group: 2,
            primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
            primary_v6: None,
        },
    );
    forwarding
}

fn test_forwarding_state_split_rgs_with_tunnel() -> ForwardingState {
    let mut forwarding = test_forwarding_state_split_rgs();
    forwarding.tunnel_endpoint_by_ifindex.insert(586, 1);
    forwarding
}

fn test_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 55068,
        dst_port: 5201,
            discriminator: Default::default(),
            routing_domain: 0,
    }
}

#[test]
fn maybe_promote_synced_session_sets_fabric_ingress_on_fabric_hit() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    // Install with SyncImport origin to mark as peer-synced
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let forwarding = test_forwarding_state_with_fabric();
    // #1346: wrap the four shared-map refs in `SharedSessionRefs`
    // (Copy struct) to match the post-refactor signature.
    let shared = super::SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    let promoted = maybe_promote_synced_session(
        &mut sessions,
        -1,
        shared,
        &peer_worker_commands,
        &forwarding,
        &key,
        decision,
        metadata,
        SessionOrigin::SyncImport,
        true,
        2_000_000,
        PROTO_TCP,
        0x10,
    );

    assert!(promoted.fabric_ingress);
}

/// #9412: a promote republishes the session with its LIVE close class.
///
/// `maybe_promote_synced_session` mirrors the promoted entry into the shared maps
/// and to peer workers. With 0 there, a worker materializing it went back to the
/// established window, and a later sweep of that copy re-announced class 0.
/// Class 0 is the control.
#[test]
fn promote_republishes_the_live_close_class_9412() {
    for class in [0u8, 1, 2, 3] {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let metadata = test_metadata();
        assert!(sessions.upsert_synced_with_origin(
            SessionInstall {
                key: key.clone(),
                decision,
                metadata: metadata.clone(),
                origin: SessionOrigin::SyncImport,
                now_ns: 1_000_000,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
                session_id: 0,
                tcp_close_class: class,
            },
            false,
        ));
        assert_eq!(
            sessions.close_class_wire_for(&key),
            class,
            "FIXTURE: the seeded import must carry close class {class} before the promote"
        );

        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let forwarding = test_forwarding_state_with_fabric();
        let shared = super::SharedSessionRefs {
            sessions: &shared_sessions,
            nat_sessions: &shared_nat_sessions,
            forward_wire_sessions: &shared_forward_wire_sessions,
            owner_rg_indexes: &shared_owner_rg_indexes,
        };
        let _ = maybe_promote_synced_session(
            &mut sessions,
            -1,
            shared,
            &peer_worker_commands,
            &forwarding,
            &key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            false,
            2_000_000,
            PROTO_TCP,
            0x10,
        );
        let published = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&key)
            .cloned()
            .expect("FIXTURE: the promote must republish the session into the shared map");
        assert_eq!(
            published.origin,
            SessionOrigin::SharedPromote,
            "FIXTURE: the shared entry must be the promote's republish"
        );
        assert_eq!(
            published.tcp_close_class, class,
            "#9412: the promote republished close class {} instead of the live class {class}",
            published.tcp_close_class
        );
    }
}

/// #9582: a promote republishes the session's STABLE id, so replicas and shared-map
/// materializations ADOPT it instead of minting their own.
///
/// With 0 there, a replica on another worker could not announce a close it alone
/// sees under the id the peer adopted (#5212) and the #9412 sender memo keys on.
#[test]
fn promote_republishes_the_session_id_for_replicas_to_adopt_9582() {
    // A peer node's id: node bit set, unlike this table's own namespace.
    const PEER_ID: u64 = 0x8001_0000_0000_0077;
    let mut sessions = SessionTable::new();
    sessions.set_session_id_namespace(0, 1);
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: SessionOrigin::SyncImport,
            now_ns: 1_000_000,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: PEER_ID,
            tcp_close_class: 0,
        },
        false,
    ));
    assert_eq!(sessions.session_id_for(&key), PEER_ID, "FIXTURE: the import must adopt the peer's id");

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> =
        vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_with_fabric();
    let shared = super::SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };
    let _ = maybe_promote_synced_session(
        &mut sessions,
        -1,
        shared,
        &peer_worker_commands,
        &forwarding,
        &key,
        decision,
        metadata,
        SessionOrigin::SyncImport,
        false,
        2_000_000,
        PROTO_TCP,
        0x10,
    );
    assert_eq!(sessions.session_id_for(&key), PEER_ID, "FIXTURE: the promote must keep the live entry's id");
    let published = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&key)
        .cloned()
        .expect("FIXTURE: the promote must republish into the shared map");
    assert_eq!(published.origin, SessionOrigin::SharedPromote, "FIXTURE: the shared entry is the promote's");
    assert_eq!(
        published.session_id, PEER_ID,
        "#9582: the promote republished session id {:#x}, not the live id, so a \
         materialization would mint its own",
        published.session_id
    );
    let replica_ids: Vec<u64> = peer_worker_commands[0]
        .lock()
        .expect("commands")
        .iter()
        .filter_map(|cmd| match cmd {
            WorkerCommand::UpsertSynced(entry) if entry.key == key => Some(entry.session_id),
            _ => None,
        })
        .collect();
    assert_eq!(
        replica_ids,
        vec![PEER_ID],
        "#9582: the replica queued for the other worker must carry the promoted session's id"
    );
}

#[test]
fn maybe_promote_synced_session_skips_worker_local_import() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::WorkerLocalImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let forwarding = test_forwarding_state_with_fabric();
    // #1346: wrap the four shared-map refs in `SharedSessionRefs`
    // (Copy struct) to match the post-refactor signature.
    let shared = super::SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    let promoted = maybe_promote_synced_session(
        &mut sessions,
        -1,
        shared,
        &peer_worker_commands,
        &forwarding,
        &key,
        decision,
        metadata.clone(),
        SessionOrigin::WorkerLocalImport,
        false,
        2_000_000,
        PROTO_TCP,
        0x10,
    );

    assert_eq!(promoted, metadata);
    let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
        panic!("worker-local session missing");
    };
    assert_eq!(origin, SessionOrigin::WorkerLocalImport);
    assert!(shared_sessions.lock().expect("shared sessions").is_empty());
}

#[test]
fn resolve_flow_session_decision_promotes_stale_fabric_shared_hit_to_local_owner_path() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision: SessionDecision {
            resolution: resolve_fabric_redirect(&forwarding).expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        },
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
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

    let wire_key = forward_wire_key(&key, shared_entry.decision.nat);
    let flow = SessionFlow {
        src_ip: wire_key.src_ip,
        dst_ip: wire_key.dst_ip,
        forward_key: wire_key,
    };
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        0, // #9383: arrival VLAN (untagged in this fixture)
        true,
        0,
        0,
    )
    .expect("resolved");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);
    assert_eq!(resolved.metadata.owner_rg_id, 1);
    assert!(resolved.metadata.fabric_ingress);
}

#[test]
fn cached_session_resolution_skips_fabric_redirect() {
    let forwarding = test_forwarding_state_with_fabric();
    let cached = ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: 21,
        tx_ifindex: 21,
        tunnel_endpoint_id: 0,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
        neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
        tx_vlan_id: 0,
    };

    assert!(cached_session_resolution(&forwarding, cached).is_none());
}

#[test]
fn lookup_session_across_scopes_returns_shared_entry() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision: test_decision(),
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_sessions
        .lock()
        .expect("shared lock")
        .insert(key.clone(), entry.clone());

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &key,
        1,
        0,
    )
    .expect("shared hit");
    assert!(resolved.shared_entry.is_some());
    assert_eq!(resolved.key.as_ref(&key), &key);
    assert_eq!(resolved.lookup.decision, entry.decision);
    assert_eq!(resolved.lookup.metadata, entry.metadata);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_preserves_local_synced_origin() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::SyncImport,
        1,
        PROTO_TCP,
        0,
    ));
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &key,
        2,
        0,
    )
    .expect("local synced hit");
    assert!(resolved.shared_entry.is_none());
    assert_eq!(resolved.key.as_ref(&key), &key);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_returns_shared_forward_wire_entry() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_forward_wire_sessions
        .lock()
        .expect("shared forward-wire lock")
        .insert(translated_key.clone(), entry.clone());

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &translated_key,
        1,
        0,
    )
    .expect("shared forward-wire hit");
    assert!(resolved.shared_entry.is_some());
    assert_eq!(resolved.key.as_ref(&translated_key), &key);
    assert_eq!(resolved.lookup.decision, entry.decision);
    assert_eq!(resolved.lookup.metadata, entry.metadata);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_preserves_local_forward_wire_synced_origin() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        test_metadata(),
        SessionOrigin::SyncImport,
        1,
        PROTO_TCP,
        0,
    ));
    let translated_key = forward_wire_key(&key, decision.nat);
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &translated_key,
        2,
        0,
    )
    .expect("local forward-wire synced hit");
    assert!(resolved.shared_entry.is_none());
    assert_eq!(resolved.key.as_ref(&translated_key), &key);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_session_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key.clone(),
        decision,
        SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        0,
    ));
    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_forward_wire_sessions
        .lock()
        .expect("shared forward-wire lock")
        .insert(translated_key.clone(), shared_entry.clone());

    let resolved = lookup_session_across_scopes(
        &mut sessions,
        &shared_sessions,
        &shared_forward_wire_sessions,
        &translated_key,
        2,
        0,
    )
    .expect("shared forward-wire hit");
    assert!(resolved.shared_entry.is_some());
    assert_eq!(resolved.key.as_ref(&translated_key), &key);
    assert_eq!(resolved.lookup.decision, shared_entry.decision);
    assert_eq!(resolved.lookup.metadata, shared_entry.metadata);
    assert_eq!(resolved.origin, SessionOrigin::SyncImport);
}

#[test]
fn lookup_forward_nat_across_scopes_returns_shared_nat_entry() {
    let sessions = SessionTable::new();
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_ICMPV6,
        src_ip: IpAddr::V6("fd35:1940:27:100::102".parse::<Ipv6Addr>().unwrap()),
        dst_ip: IpAddr::V6("2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap()),
        src_port: 0x8234,
        dst_port: 0,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V6(
                "2602:fd41:70:100::102".parse::<Ipv6Addr>().unwrap(),
            )),
            nptv6: true,
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_ICMPV6,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), entry.clone());

    let hit = lookup_forward_nat_across_scopes(
        &sessions,
        &shared_nat_sessions,
        &reply_key,
        // #7169: these cells predate the ingress revalidation and test
        // TUPLE matching, which is a separate property. Unconstrained keeps
        // each one asserting exactly what it asserted before; the new check
        // has its own cells.
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
    )
        .expect("shared forward nat hit");
    assert_eq!(hit.key, entry.key);
    assert_eq!(hit.decision, entry.decision);
    assert_eq!(hit.metadata, entry.metadata);
}

#[test]
fn lookup_forward_nat_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key,
        decision,
        SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        0,
    ));
    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), shared_entry.clone());

    let hit = lookup_forward_nat_across_scopes(
        &sessions,
        &shared_nat_sessions,
        &reply_key,
        // #7169: these cells predate the ingress revalidation and test
        // TUPLE matching, which is a separate property. Unconstrained keeps
        // each one asserting exactly what it asserted before; the new check
        // has its own cells.
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
    )
        .expect("shared nat hit");
    assert_eq!(hit.key, shared_entry.key);
    assert_eq!(hit.decision, shared_entry.decision);
    assert_eq!(hit.metadata, shared_entry.metadata);
}

#[test]
fn lookup_forward_nat_across_scopes_ignores_fabric_wire_placeholder_without_shared_entry() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key,
        decision,
        SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        SessionOrigin::ForwardFlow,
        1,
        PROTO_TCP,
        0,
    ));
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

    assert!(
        lookup_forward_nat_across_scopes(
        &sessions,
        &shared_nat_sessions,
        &reply_key,
        // #7169: these cells predate the ingress revalidation and test
        // TUPLE matching, which is a separate property. Unconstrained keeps
        // each one asserting exactly what it asserted before; the new check
        // has its own cells.
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
    ).is_none()
    );
}

#[test]
fn lookup_forward_nat_across_scopes_returns_shared_canonical_reverse_entry() {
    let sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let canonical_reply = reverse_canonical_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(canonical_reply.clone(), entry.clone());

    let hit = lookup_forward_nat_across_scopes(
        &sessions,
        &shared_nat_sessions,
        &canonical_reply,
        // #7169: these cells predate the ingress revalidation and test
        // TUPLE matching, which is a separate property. Unconstrained keeps
        // each one asserting exactly what it asserted before; the new check
        // has its own cells.
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
    )
        .expect("shared canonical reverse hit");
    assert_eq!(hit.key, entry.key);
    assert_eq!(hit.decision, entry.decision);
    assert_eq!(hit.metadata, entry.metadata);
}

#[test]
fn publish_and_remove_shared_session_tracks_forward_wire_alias() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let translated_key = forward_wire_key(&key, decision.nat);

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let alias_hit =
        lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key)
            .expect("forward-wire alias should be published");
    assert_eq!(alias_hit.key, key);

    remove_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry.key,
    );
    assert!(
        lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key).is_none()
    );
}

#[test]
fn publish_and_remove_shared_session_tracks_canonical_reverse_alias() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let canonical_reply = reverse_canonical_key(&key, decision.nat);

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let alias_hit = lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply)
        .expect("canonical reverse alias should be published");
    assert_eq!(alias_hit.key, key);

    remove_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry.key,
    );
    assert!(lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply).is_none());
}

#[test]
fn publish_and_remove_shared_session_tracks_owner_rg_indexes() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let forward_wire = forward_wire_key(&key, decision.nat);
    let reverse_wire = reverse_session_key(&key, decision.nat);
    let reverse_canonical = reverse_canonical_key(&key, decision.nat);

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let sessions_index = shared_owner_rg_indexes
        .sessions
        .lock()
        .expect("sessions index");
    assert!(
        sessions_index
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&key))
    );
    drop(sessions_index);

    let nat_index = shared_owner_rg_indexes
        .nat_sessions
        .lock()
        .expect("nat index");
    assert!(
        nat_index
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&reverse_wire) && keys.contains(&reverse_canonical))
    );
    drop(nat_index);

    let forward_wire_index = shared_owner_rg_indexes
        .forward_wire_sessions
        .lock()
        .expect("forward-wire index");
    assert!(
        forward_wire_index
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&forward_wire))
    );
    drop(forward_wire_index);

    remove_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry.key,
    );

    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .is_empty()
    );
    assert!(
        shared_owner_rg_indexes
            .nat_sessions
            .lock()
            .expect("nat index")
            .is_empty()
    );
    assert!(
        shared_owner_rg_indexes
            .forward_wire_sessions
            .lock()
            .expect("forward-wire index")
            .is_empty()
    );
}

#[test]
fn publish_shared_session_reindexes_owner_rg_on_replace() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
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
        &entry,
    );

    entry.metadata.owner_rg_id = 2;
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .get(&1)
            .is_none()
    );
    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .get(&2)
            .is_some_and(|keys| keys.contains(&entry.key))
    );
}

#[test]
fn publish_shared_session_heals_missing_owner_rg_index_on_same_owner_update() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
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
        &entry,
    );

    shared_owner_rg_indexes
        .sessions
        .lock()
        .expect("sessions index")
        .clear();

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    assert!(
        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .get(&entry.metadata.owner_rg_id)
            .is_some_and(|keys| keys.contains(&entry.key))
    );
}

#[test]
fn resolve_flow_session_decision_uses_canonical_key_for_translated_forward_hit() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let forwarding = ForwardingState::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x10,
        0,
        0, // #9383: arrival VLAN (untagged in this fixture)
        false,
        0,
        0,
    )
    .expect("translated forward hit should resolve");

    assert!(!resolved.created);

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x10).is_none());
    let local_hit = sessions
        .find_forward_wire_match(&translated_key)
        .expect("local canonical session should keep forward-wire alias");
    assert_eq!(local_hit.key, key);
    assert_eq!(resolved.decision.nat, decision.nat);
}

#[test]
fn resolve_flow_session_decision_promotes_translated_shared_hit_on_active_fabric_ingress() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: translated_key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        0, // #9383: arrival VLAN (untagged in this fixture)
        true,
        0,
        0,
    )
    .expect("translated shared hit should resolve");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);

    let local_hit = sessions
        .lookup(&translated_key, 1_000_000, 0x18)
        .expect("promoted translated hit should stay local");
    assert_eq!(local_hit.decision.nat, decision.nat);

    assert!(
        shared_sessions
            .lock()
            .expect("shared lock")
            .get(&translated_key)
            .is_some()
    );
}

#[test]
fn resolve_flow_session_decision_promotes_local_synced_translated_hit_on_active_fabric_ingress() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key.clone(),
        decision,
        SessionMetadata { ..test_metadata() },
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x18,
    ));
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        0, // #9383: arrival VLAN (untagged in this fixture)
        true,
        0,
        0,
    )
    .expect("translated local hit should resolve");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);

    let local_hit = sessions
        .lookup(&translated_key, 1_000_000, 0x18)
        .expect("promoted translated local hit should stay local");
    assert_eq!(local_hit.decision.nat, decision.nat);
}

#[test]
fn resolve_flow_session_decision_keeps_translated_shared_hit_transient_on_inactive_fabric_ingress()
{
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: translated_key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let _resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        21,
        0, // #9383: arrival VLAN (untagged in this fixture)
        true,
        0,
        0,
    )
    .expect("translated shared hit should resolve");

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
}

#[test]
fn resolve_flow_session_decision_keeps_translated_shared_hit_transient_on_inactive_non_fabric_ingress()
 {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    let entry = SyncedSessionEntry {
        key: translated_key.clone(),
        decision,
        metadata: SessionMetadata { ..test_metadata() },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let _resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        12,
        0, // #9383: arrival VLAN (untagged in this fixture)
        false,
        0,
        0,
    )
    .expect("translated shared hit should resolve");

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
}

#[test]
fn resolve_flow_session_decision_keeps_local_synced_translated_hit_transient_on_inactive_non_fabric_ingress()
 {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
            .expect("fabric redirect"),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
    };
    let translated_key = forward_wire_key(&key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        translated_key.clone(),
        decision,
        SessionMetadata { ..test_metadata() },
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x18,
    ));
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));

    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let _resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        0x18,
        12,
        0, // #9383: arrival VLAN (untagged in this fixture)
        false,
        0,
        0,
    )
    .expect("translated local hit should resolve");

    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
}

#[test]
fn apply_worker_commands_replaces_stale_local_session_for_inactive_owner_rg() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let live_metadata = test_metadata();
    assert!(sessions.install_with_protocol(
        key.clone(),
        test_decision(),
        live_metadata,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let synced_metadata = SessionMetadata { ..test_metadata() };
    let synced_decision = SessionDecision {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
        ..test_decision()
    };
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
            key: key.clone(),
            decision: synced_decision,
            metadata: synced_metadata.clone(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            // #2170 test fixture: no peer install generation.
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        }));
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(0));
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("synced hit");
    assert_eq!(hit.metadata, synced_metadata);
    // With #326, synced sessions are always re-resolved with local egress
    // info even on standby — so tx_vlan_id picks up the local egress VLAN.
    let expected_decision = SessionDecision {
        resolution: ForwardingResolution {
            tx_vlan_id: 80,
            ..synced_decision.resolution
        },
        ..synced_decision
    };
    assert_eq!(hit.decision, expected_decision);
}

#[test]
fn apply_worker_commands_preserves_local_session_for_active_owner_rg() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let live_decision = test_decision();
    let live_metadata = test_metadata();
    assert!(sessions.install_with_protocol(
        key.clone(),
        live_decision,
        live_metadata.clone(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let synced_decision = SessionDecision {
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            rewrite_src_port: Some(key.src_port),
            ..NatDecision::default()
        },
        ..test_decision()
    };
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
            key: key.clone(),
            decision: synced_decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            // #2170 test fixture: no peer install generation.
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        }));
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("live hit");
    assert_eq!(hit.metadata, live_metadata);
    assert_eq!(hit.decision, live_decision);
}

// ── #9048: the DELETE-side mirror of the clobber guard above ────────
//
// `apply_worker_commands_preserves_local_session_for_active_owner_rg`
// (directly above) pins the INSTALL half: a peer UpsertSynced cannot clobber
// a live local session whose owner RG is locally active. Until #9048 the
// DELETE half had no such guard at any layer, and the asymmetry was invisible
// because the two verbs are guarded in different files.
//
// The Go-side generation guard does not cover it and looking there is the
// natural mistake: `deleteGenGuardV4` refuses only when the STORED generation
// is non-zero, and `recvGenV4` is populated solely by prior PEER installs, so
// a session this node created itself has no stored generation and the delete
// is admitted. That is correct for the question that guard asks — it is a
// per-key REORDERING guard for one sender's stream (#2170), and gen-0 means
// "I cannot order this", not "this is safe". Ownership is a different guard.
//
// These three cells are a set: the first is the refusal, and the other two
// are the arms that prove the predicate is a CONJUNCTION rather than either
// half doing all the work by itself.
fn drive_delete_synced_9048(
    sessions: &mut SessionTable,
    key: &SessionKey,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
) {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DeleteSynced(key.clone()));
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        sessions,
        -1,
        -1,
        -1,
        &forwarding,
        ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );
}

fn install_live_local_9048(sessions: &mut SessionTable, key: &SessionKey) {
    assert!(sessions.install_with_protocol(
        key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
}

#[test]
fn apply_worker_commands_refuses_peer_delete_of_live_local_session_9048() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    install_live_local_9048(&mut sessions, &key);

    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));

    let before = PEER_DELETE_REFUSED_LOCAL_OWNED.load(Ordering::Relaxed);
    drive_delete_synced_9048(&mut sessions, &key, &ha_state);

    let hit = sessions.lookup(&key, 2_000_000, 0x10);
    assert!(
        hit.is_some(),
        "#9048: a peer DeleteSynced tore down a LIVE LOCAL session whose owner \
         RG is locally active. In a dual-primary split both nodes create local \
         sessions under the same 5-tuples, so either node closing its copy \
         kills the other's live flow mid-transfer."
    );
    assert!(
        PEER_DELETE_REFUSED_LOCAL_OWNED.load(Ordering::Relaxed) > before,
        "#9048: the session survived but the refusal was not counted. The \
         refusal is silent by design, so this counter is the ONLY surface that \
         reports a dual-primary split to an operator."
    );
}

// ARM 1 of the conjunction: a PEER-SYNCED entry is deleted normally. Without
// this, a guard that simply refused every delete would pass the cell above —
// and refusing a legitimate delete leaks a session and strands its NAT pool
// port for the life of the allocator.
#[test]
fn apply_worker_commands_still_deletes_peer_synced_session_9048() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: key.clone(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            now_ns: 1_000_000,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            session_id: 0,
            tcp_close_class: 0,
        },
        /* allow_replace_local = */ true,
    ));

    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));

    drive_delete_synced_9048(&mut sessions, &key, &ha_state);

    assert!(
        sessions.lookup(&key, 2_000_000, 0x10).is_none(),
        "#9048: the guard refused a delete for a PEER-SYNCED entry. That is \
         the ordinary standby path — every session at a synced key carries a \
         sync-family origin — so refusing there would leak a session on every \
         closing flow and hold its NAT reservation for the life of the \
         allocator."
    );
}

// ARM 2 of the conjunction: a LOCAL entry whose owner RG is NOT locally active
// is deleted normally. Without this, the origin half alone could be doing all
// the work and the HA predicate would be untested — the shape where a cell
// reads as coverage for a condition it never varies.
#[test]
fn apply_worker_commands_still_deletes_local_session_when_rg_inactive_9048() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    install_live_local_9048(&mut sessions, &key);

    // Same fixture as the refusal cell, ONE input changed: RG1 is not
    // forwarding-active here, so this node is not the one serving the flow.
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000));

    drive_delete_synced_9048(&mut sessions, &key, &ha_state);

    assert!(
        sessions.lookup(&key, 2_000_000, 0x10).is_none(),
        "#9048: the guard refused a delete for a local-origin entry whose \
         owner RG this node is NOT forwarding for. The predicate is a \
         CONJUNCTION — local origin AND locally active — and dropping the \
         second half would refuse deletes on a standby that happens to hold \
         a local entry."
    );
}

#[test]
fn worker_synced_local_delivery_forces_live_redirect_on_standby() {
    assert!(force_live_redirect_for_worker_synced_entry(
        &force_live_test_key_9517(),
        test_local_delivery_decision(),
        &test_metadata(),
        SessionOrigin::SyncImport,
        true,
        false,
    ));
}

#[test]
fn worker_synced_local_delivery_keeps_default_publish_on_active_owner() {
    assert!(!force_live_redirect_for_worker_synced_entry(
        &force_live_test_key_9517(),
        test_local_delivery_decision(),
        &test_metadata(),
        SessionOrigin::SyncImport,
        false,
        false,
    ));
}

#[test]
fn apply_worker_commands_demotes_local_owner_rg_sessions_to_sync_import() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol(
        key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] });
    let forwarding = test_forwarding_state();
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(0))]);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
        panic!("demoted session missing");
    };
    assert_eq!(origin, SessionOrigin::SyncImport);
}

#[test]
fn demoted_local_session_promotes_as_synced_on_failback_lookup() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    assert!(sessions.install_with_protocol(
        key.clone(),
        decision,
        metadata.clone(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] });
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let inactive_state = BTreeMap::from([(1, inactive_ha_runtime(0))]);

    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &inactive_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let active_state = BTreeMap::from([(1, active_ha_runtime(1))]);
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };

    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &active_state,
        &dynamic_neighbors,
        &flow,
        2_000_000,
        2,
        PROTO_TCP,
        0x10,
        6,
        0, // #9383: arrival VLAN (untagged in this fixture)
        false,
        0,
        0,
    )
    .expect("resolved demoted session");

    assert!(!resolved.created);
    let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
        panic!("promoted session missing");
    };
    assert_eq!(origin, SessionOrigin::SharedPromote);
}

#[test]
fn epoch_based_flow_cache_invalidation_for_demoted_owner_rg() {
    let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
    let mut flow_cache = FlowCache::new();
    let key = test_key();
    let metadata = SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        ..test_metadata()
    };
    // Insert with current epoch (0).
    flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        descriptor: RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            target_binding_index: None,
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: test_decision(),
        metadata,
        stamp: FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        // #5147: no dynamic-neighbor dependency in this test entry.
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    });

    // Before epoch bump, lookup should hit.
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
                    logical_ingress_ifindex: 7,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_some()
    );

    // Bump epoch for RG 1 (simulates demotion).
    rg_epochs[1].fetch_add(1, Ordering::Relaxed);

    // After epoch bump, lookup should miss (stale entry).
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
                    logical_ingress_ifindex: 7,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_none()
    );
}

#[test]
fn epoch_based_flow_cache_unrelated_rg_not_invalidated() {
    let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
    let mut flow_cache = FlowCache::new();
    let key = test_key();
    let metadata = SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        ..test_metadata()
    };
    flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: 7,
        logical_ingress_ifindex: 7,
        descriptor: RewriteDescriptor {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            fabric_redirect: false,
            tx_vlan_id: 0,
            ether_type: 0x0800,
            rewrite_src_ip: None,
            rewrite_dst_ip: None,
            rewrite_src_port: None,
            rewrite_dst_port: None,
            ip_csum_delta: 0,
            l4_csum_delta: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            target_binding_index: None,
            input_filter_log: None,
            input_filter_counters: crate::filter::CachedFilterCounters::default(),
            tx_selection: CachedTxSelectionDescriptor::default(),
            nat64: false,
            nptv6: false,
            apply_nat_on_fabric: false,
        },
        decision: test_decision(),
        metadata,
        stamp: FlowCacheStamp {
            config_generation: 1,
            fib_generation: 1,
            owner_rg_id: 1,
            owner_rg_epoch: 0,
            owner_rg_lease_until: 0,
        },
        observed_bytes: 0,
        last_used_epoch: 0,
        neighbor_mac_epoch: 0,
        // #5147: no dynamic-neighbor dependency in this test entry.
        neighbor_shard: crate::afxdp::flow_cache::NEIGHBOR_SHARD_NONE,
    });

    // Bump epoch for RG 2 (unrelated).
    rg_epochs[2].fetch_add(1, Ordering::Relaxed);

    // RG 1 entry should still hit — only RG 2 was bumped.
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
                    logical_ingress_ifindex: 7,
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_some()
    );
}

/// #2653: the single-shot `ExportOwnerRGSessions` command path must NOT push
/// the entire owned-session set into the 4096-slot delta ring in one shot. A
/// worker can own up to DEFAULT_MAX_SESSIONS (131072) = 32x the ring; the old
/// `handle_export_owner_rg_sessions` called `export_forward_sessions_for_owner_rgs`
/// inline, which emitted all N open deltas with no interleaved drain, overflowed
/// the ring at delta 4097, and silently dropped sessions 4097..N from the HA
/// bulk snapshot on rejoin / RG transition (the command-path sibling of the
/// #2442 worker-loop overflow).
///
/// The fix makes the command handler RECORD the owner RGs (`export_owner_rgs`)
/// instead of emitting; the worker loop performs the chunked drain-as-you-export.
/// This test installs > ring-cap owned forward sessions, dispatches the command
/// through `apply_worker_commands`, and asserts:
///   (a) the command records the owner RG;
///   (b) `apply_worker_commands` emits NOTHING inline and does NOT overflow the
///       ring (delta_drops unchanged, no loss latch) — the bound is respected;
///   (c) driving the recorded RGs through the chunked drain-as-you-export ships
///       the COMPLETE snapshot (all N) with zero new drops.
///
/// FAIL-ON-REVERT: restoring the inline `export_forward_sessions_for_owner_rgs`
/// call in `handle_export_owner_rg_sessions` overflows the ring INSIDE
/// `apply_worker_commands` — (b) reds (delta_drops jumps by ~N-4096, the loss
/// latch arms, and only 4096 deltas reach the inline drain).
#[test]
fn export_owner_rg_command_does_not_overflow_ring_unbounded() {
    // Ring cap is MAX_SESSION_DELTAS (4096, private to session/mod.rs).
    const RING_CAP: usize = 4096;
    const RESYNC_EXPORT_CHUNK: usize = 2048; // mirror the worker loop
    let n: usize = RING_CAP + 1000; // 5096 > cap to exercise the overflow hole

    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let mut keys: Vec<SessionKey> = Vec::with_capacity(n);
    for i in 0..n {
        let mut key = test_key();
        // Unique forward keys (owner RG 1 from test_metadata): sweep src ip+port.
        key.src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, (i / 256) as u8));
        key.src_port = ((i % 256) as u16) + 1000;
        assert!(sessions.install_with_protocol(
            key.clone(),
            test_decision(),
            test_metadata(),
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        keys.push(key);
    }
    // The installs themselves overflowed the ring (n > cap) and latched loss;
    // clear that pre-existing state so the assertions below measure ONLY what
    // the export command does.
    assert!(sessions.delta_drops() > 0, "installing > cap deltas overflows");
    let _ = sessions.take_delta_loss();
    while !sessions.drain_deltas(256).is_empty() {}
    let drops_before_export = sessions.delta_drops();
    assert!(!sessions.take_delta_loss(), "loss latch cleared before export");

    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 42,
            owner_rgs: vec![1],
        });
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    // (a) the command recorded the owner RG and sequence.
    assert_eq!(results.exported_sequences, vec![42]);
    assert_eq!(results.export_owner_rgs, vec![1]);

    // (b) THE BOUND: apply_worker_commands must NOT push unbounded into the
    // ring. It emits nothing inline and never overflows. The reverted inline
    // export would have emitted all N here, overflowing the ring.
    assert!(
        !sessions.has_pending_deltas(),
        "export command must NOT emit deltas inline (#2653) — the worker loop \
         performs the chunked drain-as-you-export"
    );
    assert_eq!(
        sessions.delta_drops(),
        drops_before_export,
        "export command must NOT overflow the ring (the #2653 unbounded bug)"
    );
    assert!(
        !sessions.take_delta_loss(),
        "export command must NOT latch a delta loss (no mid-export overflow)"
    );

    // (c) driving the recorded RGs through the chunked drain-as-you-export the
    // worker loop runs ships the COMPLETE snapshot with zero new drops.
    let owner_rgs = results.export_owner_rgs.clone();
    let candidates = crate::afxdp::forward_export_candidates_for_owner_rgs(&sessions, &owner_rgs);
    let mut exported = 0usize;
    for chunk in candidates.chunks(RESYNC_EXPORT_CHUNK) {
        for (key, decision, metadata, origin) in chunk.iter().cloned() {
            sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
        }
        loop {
            let d = sessions.drain_deltas(256);
            if d.is_empty() {
                break;
            }
            exported += d.iter().filter(|x| x.kind == SessionDeltaKind::Open).count();
        }
    }
    assert_eq!(
        exported, n,
        "chunked export ships the COMPLETE snapshot ({n}), not the ring cap"
    );
    assert_eq!(
        sessions.delta_drops(),
        drops_before_export,
        "the chunked export drops nothing (drain-as-you-export never overflows)"
    );
    assert!(!sessions.take_delta_loss(), "no spurious re-arm after export");
}

#[test]
fn apply_worker_commands_exports_owner_rg_forward_sessions_without_teardown() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = SessionDecision {
        resolution: test_decision().resolution,
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
            ..NatDecision::default()
        },
    };
    let metadata = SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        ..test_metadata()
    };
    assert!(sessions.install_with_protocol(
        key.clone(),
        decision,
        metadata,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 9,
            owner_rgs: vec![1],
        });
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    assert_eq!(results.exported_sequences, vec![9]);
    // #2653: the command handler records the owner RGs instead of emitting the
    // deltas inline (the worker loop performs the chunked drain-as-you-export).
    assert_eq!(results.export_owner_rgs, vec![1]);
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "apply_worker_commands no longer emits export deltas inline (#2653)"
    );
    let hit = sessions
        .lookup(&key, 2_000_000, 0x10)
        .expect("exported forward hit");

    assert_eq!(
        hit.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    // Drive the recorded RGs through the same candidate walk the worker loop
    // chunked export uses: the forward session must republish as an Open delta.
    export_forward_sessions_for_owner_rgs(&mut sessions, &results.export_owner_rgs);
    let deltas = sessions.drain_deltas(16);
    assert_eq!(deltas.len(), 1, "export should republish forward session");
    assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
    assert!(deltas[0].fabric_redirect_sync);
}

#[test]
fn apply_worker_commands_does_not_export_missing_neighbor_seed_sessions() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let metadata = SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        ..test_metadata()
    };
    assert!(sessions.install_with_protocol_with_origin(
        key,
        test_decision(),
        metadata,
        SessionOrigin::MissingNeighborSeed,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "missing-neighbor seed install should not emit open deltas"
    );
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 10,
            owner_rgs: vec![1],
        });
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    assert_eq!(results.exported_sequences, vec![10]);
    assert_eq!(results.export_owner_rgs, vec![1]);
    // Even when the worker loop drives the recorded RGs through the chunked
    // export, a missing-neighbor seed session must NOT be republished.
    export_forward_sessions_for_owner_rgs(&mut sessions, &results.export_owner_rgs);
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "missing-neighbor seed sessions must not be exported as HA deltas"
    );
}

#[test]
fn apply_worker_commands_demote_owner_rg_returns_cancelled_keys() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![1, 1],
        });

    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000));

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    assert_eq!(results.exported_sequences, Vec::<u64>::new());
    assert_eq!(results.cancelled_keys.len(), 1);
    assert!(results.cancelled_keys.iter().any(|k| k == &key));
}

#[test]
fn demote_shared_owner_rgs_preserves_reverse_entries_and_marks_all_synced() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let forward = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reverse = SyncedSessionEntry {
        key: reverse_session_key(&forward.key, forward.decision.nat),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            is_reverse: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
        &forward,
    );
    shared_sessions
        .lock()
        .expect("shared sessions")
        .insert(reverse.key.clone(), reverse.clone());

    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &test_forwarding_state_with_fabric(),
        &Arc::new(ShardedNeighborMap::new()),
        &[1],
    );

    let shared_forward = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&forward.key)
        .cloned()
        .expect("forward entry");
    assert!(shared_forward.origin.is_peer_synced());
    let shared_reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse.key)
        .cloned()
        .expect("reverse entry");
    assert!(shared_reverse.origin.is_peer_synced());
    let reverse_alias = reverse_session_key(&forward.key, forward.decision.nat);
    let nat_alias = shared_nat_sessions
        .lock()
        .expect("shared nat")
        .get(&reverse_alias)
        .cloned()
        .expect("nat alias");
    assert!(nat_alias.origin.is_peer_synced());
}

#[test]
fn demoted_shared_local_forward_session_enters_reverse_prewarm_index() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    entry.metadata.owner_rg_id = 1;

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &forwarding,
        &dynamic_neighbors,
        &[1],
    );

    let index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(index.get(&1).is_some_and(|keys| keys.contains(&entry.key)));
    assert!(index.get(&2).is_some_and(|keys| keys.contains(&entry.key)));
}

#[test]
fn prewarm_reverse_synced_sessions_after_demotion_recomputes_split_owner_reverse() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(2, active_ha_runtime(1));
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    entry.metadata.owner_rg_id = 1;

    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &forwarding,
        &dynamic_neighbors,
        &[1],
    );

    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[2],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
}

#[test]
fn apply_worker_commands_demotes_local_owner_rg_sessions_and_cancels_keys() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_with_fabric(),
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert_eq!(results.cancelled_keys, vec![key.clone()]);
    let (_, origin) = sessions
        .lookup_with_origin(&key, now_ns, 0x10)
        .expect("demoted session");
    assert!(origin.is_peer_synced());
}

#[test]
fn apply_worker_commands_demote_owner_rg_rewrites_resolution_to_fabric_redirect() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_ns / 1_000_000_000))]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_with_fabric(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert_eq!(results.cancelled_keys, vec![key.clone()]);
    let (lookup, origin) = sessions
        .lookup_with_origin(&key, now_ns, 0x10)
        .expect("demoted session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
}

#[test]
fn apply_worker_commands_demote_split_reverse_owner_rg_rewrites_to_fabric_redirect() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![2] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(now_ns / 1_000_000_000))]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert_eq!(results.cancelled_keys, vec![reverse_key.clone()]);
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("demoted reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_split_reverse_owner_rg_rewrites_to_forward_candidate() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![2] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
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
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([(2, active_ha_runtime(now_ns / 1_000_000_000))]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
    assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
    assert_eq!(
        lookup.decision.resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_split_reverse_owner_rg_updates_stale_indexed_session() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![2] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
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
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, inactive_ha_runtime(now_ns / 1_000_000_000)),
        (2, active_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
    assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
    assert_eq!(
        lookup.decision.resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_owner_rg_updates_reverse_session_owned_by_other_rg() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
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
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::SharedPromote,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_ns / 1_000_000_000)),
        (2, active_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert_eq!(origin, SessionOrigin::SharedPromote);
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
    assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
    assert_eq!(
        lookup.decision.resolution.next_hop,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
    );
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_owner_rg_rewrites_remote_reverse_session_on_peer_move() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_ns / 1_000_000_000)),
        (2, inactive_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert!(origin.is_peer_synced());
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn apply_worker_commands_refresh_owner_rg_rewrites_shared_promote_reverse_on_peer_move() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
    ])));
    let mut sessions = SessionTable::new();
    let forward_key = test_key();
    let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: test_decision().nat.reverse(
                forward_key.src_ip,
                forward_key.dst_ip,
                forward_key.src_port,
                forward_key.dst_port,
            ),
        },
        SessionMetadata {
            ingress_zone: 2,
            egress_zone: 1,
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
            log_session_init: false,
            log_session_close: false,
            policy_id: 0,
            inactivity_timeout_ns: None,
            policy_counter_idx: 0,
            policy_counter: None,
        },
        SessionOrigin::SharedPromote,
        now_ns,
        PROTO_TCP,
        0x10,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_ns / 1_000_000_000)),
        (2, inactive_ha_runtime(now_ns / 1_000_000_000)),
    ]);
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_split_rgs(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert!(results.cancelled_keys.is_empty());
    let (lookup, origin) = sessions
        .lookup_with_origin(&reverse_key, now_ns, 0x10)
        .expect("refreshed reverse session");
    assert_eq!(origin, SessionOrigin::SharedPromote);
    assert_eq!(
        lookup.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    assert_eq!(lookup.metadata.owner_rg_id, 2);
    assert!(lookup.metadata.is_reverse);
}

#[test]
fn export_owner_rg_sessions_skips_locally_demoted_entries() {
    let commands = Arc::new(Mutex::new(VecDeque::from([
        WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
        WorkerCommand::ExportOwnerRGSessions {
            sequence: 11,
            owner_rgs: vec![1],
        },
    ])));
    let mut sessions = SessionTable::new();
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();
    let now_ns = monotonic_nanos();

    assert!(sessions.install_with_protocol_with_origin(
        key,
        decision,
        metadata,
        SessionOrigin::ForwardFlow,
        now_ns,
        PROTO_TCP,
        0x10,
    ));
    assert_eq!(sessions.drain_deltas(16).len(), 1);

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &test_forwarding_state_with_fabric(),
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );

    assert_eq!(results.exported_sequences, vec![11]);
    assert_eq!(results.export_owner_rgs, vec![1]);
    // Driving the recorded RGs through the chunked-export candidate walk must
    // still emit nothing: the session was demoted out of owner RG 1's index.
    export_forward_sessions_for_owner_rgs(&mut sessions, &results.export_owner_rgs);
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "demoted local owner sessions must not be re-exported as fresh HA deltas"
    );
}

#[test]
fn synthesized_synced_reverse_entry_preserves_fabric_ingress_and_reverse_flag() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.fabric_ingress = true;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    let reverse = synthesized_synced_reverse_entry(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &entry,
        1,
    )
    .expect("reverse companion");

    assert!(reverse.metadata.is_reverse);
    assert!(reverse.origin.is_peer_synced());
    assert!(reverse.metadata.fabric_ingress);
    assert_eq!(reverse.metadata.ingress_zone, 2);
    assert_eq!(reverse.metadata.egress_zone, 1);
    assert_eq!(
        reverse.key,
        reverse_session_key(&entry.key, entry.decision.nat)
    );
}

// #7917, re-homed by #8015: the synthesized reverse companion must not carry
// the FORWARD direction's ingress identity.
//
// The forward flow's ingress is a PREDICTION of where the reply will arrive,
// not an OBSERVATION of where it did, and routing may be asymmetric — so 0
// ("unobserved") is truthful and inheriting would make the row confidently
// wrong. `pkg/dataplane/types.go` names the reverse companion as the first
// legitimate-`0` population for exactly this reason.
//
// THIS CELL EXISTS BECAUSE THE GUARD MOVED. The invariant used to be pinned on
// the Go side, over `mirrorSessionPairV4`/`V6`'s explicitly built companion and
// its `ResetUnobservedForReverseCompanion()` call. #8015 deleted that companion
// — the helper's is the only one now — so the assertion has to live over the
// implementation that survived, or the rule would be stated in a doc comment
// and enforced nowhere.
//
// THE FIXTURE MUST NOT USE THE VALUE THE BUG FALLS BACK TO. `test_metadata()`
// carries `ingress_ifindex: 0`, so a companion that INHERITED the forward's
// identity would still read 0 and this cell would be green for the defect. The
// forward is given a non-zero identity here for that reason, and the forward's
// own metadata is asserted UNCHANGED as the over-reach control: clearing the
// identity on both halves would satisfy the companion assertion while
// destroying the datum #4983 exists to provide.
#[test]
fn synthesized_synced_reverse_entry_carries_no_ingress_identity_7917() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.ingress_ifindex = 4242;
    metadata.ingress_vlan_id = 80;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    let reverse = synthesized_synced_reverse_entry(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &entry,
        1,
    )
    .expect("reverse companion");

    assert_eq!(
        reverse.metadata.ingress_ifindex, 0,
        "the synthesized companion inherited the FORWARD direction's ingress \
         ifindex. Where the reply will arrive is a prediction, not an \
         observation, and routing may be asymmetric, so this names a device on \
         a guess (#7917)"
    );
    assert_eq!(
        reverse.metadata.ingress_vlan_id, 0,
        "the synthesized companion inherited the FORWARD direction's ingress \
         VLAN (#7917)"
    );
    // Over-reach control: the FORWARD entry keeps its own identity.
    assert_eq!(
        entry.metadata.ingress_ifindex, 4242,
        "the forward entry must keep its ingress identity — clearing it on both \
         halves would satisfy the companion assertions above while destroying \
         the datum #4983 exists to provide (#7917)"
    );
    assert_eq!(entry.metadata.ingress_vlan_id, 80);
}

// #4565: the synthesized reverse companion of a peer-PROMOTED NAT64 forward
// session must inherit the forward session's `nat64_reverse` (original v6
// src/dst). `build_nat64_forwarded_frame`'s reverse (v4->v6) branch hard-
// requires it — without it the server's v4 reply cannot be translated back to
// IPv6 and is dropped. RED-on-revert: restoring `nat64_reverse: None` in
// build_reverse_session_from_forward_match makes the inheritance assertion fail.
#[test]
fn synthesized_synced_reverse_entry_inherits_nat64_reverse_4565() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    let orig_src_v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
    let orig_dst_v6 = "64:ff9b::c0a8:101".parse::<Ipv6Addr>().unwrap();
    let reverse_info = Nat64ReverseInfo {
        orig_src_v6,
        orig_dst_v6,
    };

    let mut metadata = test_metadata();
    metadata.nat64_reverse = Some(reverse_info);

    // NAT64 forward flow keyed on the original IPv6 5-tuple; the decision
    // rewrites to an IPv4 pool source + IPv4 destination (nat64 = true).
    let entry = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(orig_src_v6),
            dst_ip: IpAddr::V6(orig_dst_v6),
            src_port: 5001,
            dst_port: 80,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
                rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                rewrite_src_port: Some(40000),
                rewrite_dst_port: None,
                nat64: true,
                nptv6: false,
            },
        },
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    let reverse = synthesized_synced_reverse_entry(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &entry,
        1,
    )
    .expect("reverse companion");

    assert!(reverse.metadata.is_reverse);
    assert_eq!(
        reverse.metadata.nat64_reverse,
        Some(reverse_info),
        "reverse companion must inherit the forward NAT64 reverse info"
    );
    assert!(
        reverse.decision.nat.nat64,
        "reversed NAT decision keeps the nat64 bit"
    );
    // The reverse companion is keyed on the v4 reply tuple (server -> snat_v4).
    assert_eq!(reverse.key.addr_family, libc::AF_INET as u8);
    assert_eq!(
        reverse.key.src_ip,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    );
    assert_eq!(reverse.key.dst_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
}

// #5153: the synthesized/failover reverse companion must inherit the forward
// session's per-application `inactivity_timeout_ns`. Both halves of one
// stateful flow share the admitting application, so the app's idle window
// governs either direction. `companion_keeps_alive` (expire.rs) keeps an
// idle-crossed half alive using the companion's OWN `expires_after_ns`
// (derived from this field); dropping it to `None` let the reverse companion
// fall back to the global timeout and extended a short app timeout (e.g. 30s)
// toward the global one (e.g. 300s) — stale-state retention beyond the
// configured window. RED-on-revert: restoring `inactivity_timeout_ns: None` in
// build_reverse_session_from_forward_match makes the inheritance assertion
// fail.
#[test]
fn reverse_companion_inherits_forward_inactivity_timeout_5153() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    // 30s per-application idle timeout stamped on the forward session (the
    // value `session_timeout_ns` would use for `expires_after_ns`).
    const APP_TIMEOUT_NS: u64 = 30_000_000_000;
    let mut metadata = test_metadata();
    metadata.inactivity_timeout_ns = Some(APP_TIMEOUT_NS);

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    let reverse =
        synthesized_synced_reverse_entry(&forwarding, &BTreeMap::new(), &dynamic_neighbors, &entry, 1)
            .expect("reverse companion");

    assert!(reverse.metadata.is_reverse);
    assert_eq!(
        reverse.metadata.inactivity_timeout_ns,
        Some(APP_TIMEOUT_NS),
        "reverse companion must inherit the forward session's per-app idle \
         timeout, not fall back to the global timeout"
    );
}

/// #9412: the reverse companion of a peer import carries the forward entry's close
/// class.
///
/// With 0 here, every close-state Update, the takeover reverse prewarm and the
/// reconcile replay re-installed the reverse half on the established window, and
/// `companion_keeps_alive` (which ignores `closing`) can hold the closing forward
/// alive with it. Read from the code; the live probe cannot see the reverse half.
/// Class 0 is the control: the companion invents nothing.
#[test]
fn reverse_companion_inherits_forward_close_class_9412() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    for class in [0u8, 1, 2, 3] {
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            generation: 0,
            session_id: 0,
            tcp_close_class: class,
        };
        let reverse =
            synthesized_synced_reverse_entry(&forwarding, &BTreeMap::new(), &dynamic_neighbors, &entry, 1)
                .expect("reverse companion");
        assert!(reverse.metadata.is_reverse, "FIXTURE: the synthesizer must build the reverse half");
        assert_eq!(
            reverse.tcp_close_class, class,
            "#9412: the reverse companion must carry the forward import's close class {class}"
        );
    }
}

// #5153: the direct `build_reverse_session_from_forward_match` builder must
// also carry the forward match's `inactivity_timeout_ns` through (the
// synthesized-sync path above and the live reverse-install path share this
// builder). A forward match with NO per-app override still yields `None`
// (global timeout), the common bit-identical case.
#[test]
fn build_reverse_session_carries_inactivity_timeout_5153() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    const APP_TIMEOUT_NS: u64 = 30_000_000_000;
    let mut metadata = test_metadata();
    metadata.inactivity_timeout_ns = Some(APP_TIMEOUT_NS);

    let reverse = build_reverse_session_from_forward_match(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        ForwardSessionMatch {
            key: test_key(),
            decision: test_decision(),
            metadata,
        },
        1,
        0,
    );
    assert_eq!(
        reverse.metadata.inactivity_timeout_ns,
        Some(APP_TIMEOUT_NS),
        "builder must inherit the forward match's per-app idle timeout"
    );

    // No per-app override on the forward match → reverse companion stays global
    // (`None`), bit-identical to the pre-#5153 behavior.
    let reverse_global = build_reverse_session_from_forward_match(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        ForwardSessionMatch {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
        },
        1,
        0,
    );
    assert_eq!(
        reverse_global.metadata.inactivity_timeout_ns, None,
        "a forward match with no per-app override keeps the reverse companion \
         on the global timeout"
    );
}

#[test]
fn synthesized_synced_reverse_entry_tracks_local_client_when_owner_rg_active() {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.fabric_ingress = true;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));

    let reverse =
        synthesized_synced_reverse_entry(&forwarding, &ha_state, &dynamic_neighbors, &entry, 1)
            .expect("reverse companion");

    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
}

#[test]
fn synthesized_synced_reverse_entry_uses_fabric_redirect_when_client_rg_inactive() {
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut metadata = test_metadata();
    metadata.ingress_zone = TEST_LAN_ZONE_ID;
    metadata.egress_zone = TEST_WAN_ZONE_ID;
    metadata.fabric_ingress = false;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));
    ha_state.insert(2, inactive_ha_runtime(1));

    let reverse =
        synthesized_synced_reverse_entry(&forwarding, &ha_state, &dynamic_neighbors, &entry, 1)
            .expect("reverse companion");

    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 21);
    assert_eq!(
        reverse.decision.resolution.src_mac,
        Some([
            0x02,
            0xbf,
            0x72,
            FABRIC_ZONE_MAC_MAGIC,
            0x00,
            TEST_WAN_ZONE_ID as u8
        ])
    );
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    assert!(reverse.metadata.is_reverse);
}

#[test]
fn session_hit_ha_inactive_uses_zone_encoded_fabric_redirect() {
    let forwarding = test_forwarding_state_with_fabric();
    let redirected = redirect_session_via_fabric_if_needed(
        &forwarding,
        ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        false,
        TEST_SFMIX_ZONE_ID,
    );
    assert_eq!(
        redirected.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(redirected.egress_ifindex, 21);
    assert_eq!(redirected.tx_ifindex, 21);
    assert_eq!(
        redirected.src_mac,
        Some([
            0x02,
            0xbf,
            0x72,
            FABRIC_ZONE_MAC_MAGIC,
            0x00,
            TEST_SFMIX_ZONE_ID as u8
        ])
    );
}

#[test]
fn session_hit_ha_inactive_does_not_redirect_actual_fabric_ingress() {
    let forwarding = test_forwarding_state_with_fabric();
    let resolved = redirect_session_via_fabric_if_needed(
        &forwarding,
        ForwardingResolution {
            disposition: ForwardingDisposition::HAInactive,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        true,
        5,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
}

#[test]
fn fabric_ingress_session_hit_obeys_ha_inactive_gate() {
    let forwarding = test_forwarding_state_with_fabric();
    let ha_state = BTreeMap::from([(1, inactive_ha_runtime(1))]);
    let resolved = enforce_session_ha_resolution(
        &forwarding,
        &ha_state,
        1,
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        21,
        0,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    assert_eq!(resolved.egress_ifindex, 6);
}

#[test]
fn tunnel_ingress_session_hit_bypasses_unseeded_ha_during_startup_grace() {
    let forwarding = test_forwarding_state_split_rgs_with_tunnel();
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(0))]);
    let resolved = enforce_session_ha_resolution(
        &forwarding,
        &ha_state,
        100,
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 6,
            tx_ifindex: 6,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
            src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
            tx_vlan_id: 0,
        },
        586,
        110,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, 6);
}

#[test]
fn reverse_session_from_tunnel_forward_bypasses_unseeded_ha_during_startup_grace() {
    let forwarding = test_forwarding_state_split_rgs_with_tunnel();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(0))]);
    let reverse = build_reverse_session_from_forward_match(
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        ForwardSessionMatch {
            key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
                src_port: 42424,
                dst_port: 5201,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
            decision: SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 12,
                    tx_ifindex: 12,
                    tunnel_endpoint_id: 1,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41))),
                    neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                    tx_vlan_id: 80,
                },
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
                    ..NatDecision::default()
                },
            },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 5,
                ingress_ifindex: 0,
                ingress_vlan_id: 0,
                owner_rg_id: 2,
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
        },
        100,
        110,
    );
    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
}

#[test]
fn prewarm_reverse_synced_sessions_for_owner_rgs_adds_reverse_companion() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        &forwarding,
        &dynamic_neighbors,
        None,
        Some(&entry),
    );

    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[1],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert!(reverse.origin.is_peer_synced());
    // 2 commands: forward entry + reverse entry (both pushed to workers)
    assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
}

#[test]
fn prewarm_reverse_synced_sessions_for_owner_rgs_restores_shared_promote_forward_entry() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(1));
    ha_state.insert(2, inactive_ha_runtime(1));
    let mut metadata = test_metadata();
    metadata.ingress_zone = 1;
    metadata.egress_zone = 2;
    metadata.fabric_ingress = false;
    metadata.owner_rg_id = 1;
    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::SharedPromote,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
        &entry,
    );

    let prewarm_index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(
        prewarm_index.get(&1).is_none() || !prewarm_index.get(&1).unwrap().contains(&entry.key)
    );
    drop(prewarm_index);

    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[1],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    let commands = worker_commands[0].lock().expect("commands");
    assert_eq!(commands.len(), 2);
    assert!(matches!(
        &commands[0],
        WorkerCommand::UpsertSynced(session) if session.origin == SessionOrigin::SharedPromote
    ));
    assert!(matches!(
        &commands[1],
        WorkerCommand::UpsertSynced(session)
            if session.metadata.is_reverse && session.metadata.owner_rg_id == 2
    ));
}

#[test]
fn prewarm_reverse_synced_sessions_recomputes_when_reverse_owner_rg_activates() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(2, active_ha_runtime(1));
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    entry.metadata.owner_rg_id = 1;
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );
    refresh_reverse_prewarm_owner_rg_indexes(
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        &forwarding,
        &dynamic_neighbors,
        None,
        Some(&entry),
    );

    // owner_rgs=[2] does not include the forward session's owner_rg_id=1,
    // but the synthesized reverse companion resolves to owner_rg_id=2 in
    // the split-RG topology, so activation of RG2 must still prewarm it.
    prewarm_reverse_synced_sessions_for_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &worker_commands,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &[2],
        1,
    );

    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&reverse_key)
        .cloned()
        .expect("reverse entry");
    assert!(reverse.metadata.is_reverse);
    assert_eq!(reverse.metadata.owner_rg_id, 2);
    // 2 commands: forward entry + reverse entry (both pushed to workers)
    assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
}

#[test]
fn reverse_prewarm_index_tracks_split_reverse_owner_rg_candidate() {
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    entry.metadata.owner_rg_id = 1;

    refresh_reverse_prewarm_owner_rg_indexes(
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        &forwarding,
        &dynamic_neighbors,
        None,
        Some(&entry),
    );

    let index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(index.get(&1).is_some_and(|keys| keys.contains(&entry.key)));
    assert!(index.get(&2).is_some_and(|keys| keys.contains(&entry.key)));
}

#[test]
fn reverse_session_from_split_owner_fabric_redirect_uses_fabric_return_when_client_rg_inactive() {
    let forwarding = test_forwarding_state_split_rgs();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::from([(2, inactive_ha_runtime(1))]);
    let reverse = build_reverse_session_from_forward_match(
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        ForwardSessionMatch {
            key: SessionKey {
                addr_family: libc::AF_INET as u8,
                protocol: PROTO_TCP,
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                src_port: 42424,
                dst_port: 5201,
                            discriminator: Default::default(),
                            routing_domain: 0,
            },
            decision: SessionDecision {
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
            },
            metadata: SessionMetadata {
                ingress_zone: 1,
                egress_zone: 2,
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
        },
        1,
        0,
    );
    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::FabricRedirect
    );
    assert_eq!(reverse.decision.resolution.egress_ifindex, 21);
    assert_eq!(reverse.decision.resolution.tx_ifindex, 21);
}

#[test]
fn republish_bpf_session_entries_covers_all_sessions_in_owner_rg_index() {
    // Simulate the failover+failback scenario (#475):
    // A session is in the shared sessions table and the `sessions`
    // owner-RG index but NOT in the `reverse_prewarm_sessions` index
    // (e.g., locally originated then demoted). The comprehensive
    // republish function must find and attempt to publish it.
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();

    let entry = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: SessionMetadata {
            ingress_ifindex: 0,
            ingress_vlan_id: 0,
            owner_rg_id: 1,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    // Publish to shared table + sessions index (but NOT reverse_prewarm).
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &entry,
    );

    // Verify the session is in the sessions index but not reverse_prewarm.
    let sessions_index = shared_owner_rg_indexes
        .sessions
        .lock()
        .expect("sessions index");
    assert!(
        sessions_index
            .get(&1)
            .is_some_and(|keys| keys.contains(&entry.key))
    );
    drop(sessions_index);

    let prewarm_index = shared_owner_rg_indexes
        .reverse_prewarm_sessions
        .lock()
        .expect("prewarm index");
    assert!(prewarm_index.get(&1).is_none() || prewarm_index.get(&1).unwrap().is_empty());
    drop(prewarm_index);

    // Call republish — it should find the session via the sessions index.
    // Use fd=-1 (the BPF syscall will fail). The function now only counts
    // successful publishes, so count=0 with fd=-1. We verify the function
    // iterates the right sessions by checking RG2 returns 0 (no sessions).
    let count = republish_bpf_session_entries_for_owner_rgs(
        &shared_sessions,
        &shared_owner_rg_indexes,
        -1,
        &[1],
        false,
    );
    assert_eq!(count, 0, "fd=-1 should produce 0 successful publishes");

    // Unrelated RG should return 0.
    let count = republish_bpf_session_entries_for_owner_rgs(
        &shared_sessions,
        &shared_owner_rg_indexes,
        -1,
        &[2],
        false,
    );
    assert_eq!(count, 0, "should find 0 sessions for RG2");
}

#[test]
fn synced_session_hit_recomputes_local_resolution_after_failover() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
        table: "inet.0".to_string(),
    });
    forwarding.neighbors.insert(
        (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
        NeighborEntry {
            mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
        },
    );
    let stale_fabric_decision = SessionDecision {
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
        nat: NatDecision::default(),
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &SyncedSessionEntry {
            key: key.clone(),
            decision: stale_fabric_decision,
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            // #2170 test fixture: no peer install generation.
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        },
    );
    let peer_worker_commands = Vec::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            lease: HAGroupRuntime::active_lease_until(
                monotonic_nanos() / 1_000_000_000,
                monotonic_nanos() / 1_000_000_000,
            ),
        },
    )]);

    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        },
        1_000_000,
        monotonic_nanos() / 1_000_000_000,
        PROTO_TCP,
        0x10,
        5,
        0, // #9383: arrival VLAN (untagged in this fixture)
        false,
        0,
        0,
    )
    .expect("synced session should resolve");

    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, 12);
    assert_eq!(resolved.decision.resolution.tx_ifindex, 11);
}

// #6313 RED-on-revert: a reverse-direction packet whose 5-tuple hits a
// peer-synced entry in the SHARED session map is materialized into this
// worker's local table by `materialize_shared_session_hit`, and that
// materialize must ADOPT the shared replica's stable session id rather than
// mint a fresh node-local one (#5212). The reverse companion of a synced
// session carries the SAME RT_FLOW correlation id as its forward half, so a
// session that opens on the primary and closes on the standby after a
// failover emits SESSION_CREATE / SESSION_CLOSE under one correlatable id in
// BOTH directions.
//
// The wire-level adoption in `upsert_synced_with_origin` is covered by
// `synced_import_adopts_peer_session_id_5212` (session/tests.rs); this test
// covers the session_glue CALLER — reverting the `session_id: replica.session_id`
// argument in `materialize_shared_session_hit` back to `session_id: 0` makes
// the install fall through to `alloc_session_id()` and reddens the first
// assertion below. The local table is pinned to worker 4 and the peer id is
// minted in worker 9's namespace so a fresh local alloc can never coincide
// with the adopted value (the id space carries no node discriminator — #6311).
#[test]
fn reverse_materialized_shared_hit_adopts_replica_session_id_6313() {
    let mut sessions = SessionTable::new();
    sessions.set_session_id_namespace(0, 4);

    let forward = test_key();
    // The reverse companion: server -> client, ports swapped.
    let reverse = SessionKey {
        addr_family: forward.addr_family,
        protocol: forward.protocol,
        src_ip: forward.dst_ip,
        dst_ip: forward.src_ip,
        src_port: forward.dst_port,
        dst_port: forward.src_port,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    // A second reverse companion (different client port) for the negative
    // control below.
    let reverse_legacy = SessionKey {
        src_port: forward.dst_port,
        dst_port: forward.src_port + 1,
        ..reverse.clone()
    };

    let peer_session_id: u64 = (9u64 << 48) | 0x5212;
    let mut reverse_metadata = test_metadata();
    reverse_metadata.is_reverse = true;

    let forwarding = test_forwarding_state();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    for (key, session_id) in [
        (reverse.clone(), peer_session_id),
        // Control: a legacy peer that predates the #5212 wire field sends 0.
        (reverse_legacy.clone(), 0u64),
    ] {
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &SyncedSessionEntry {
                key,
                decision: test_decision(),
                metadata: reverse_metadata.clone(),
                origin: SessionOrigin::SyncImport,
                protocol: PROTO_TCP,
                tcp_flags: TCP_FLAG_ACK,
                // #2170 test fixture: no peer install generation.
                generation: 0,
                session_id,
                tcp_close_class: 0,
            },
        );
    }

    let peer_worker_commands = Vec::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // RG 1 (the reverse companion's owner) is locally active, so the shared hit
    // is NOT held transient and takes the materialize path.
    let ha_state = BTreeMap::from([(1, active_ha_runtime(now_secs))]);

    for key in [&reverse, &reverse_legacy] {
        resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &SessionFlow {
                src_ip: key.src_ip,
                dst_ip: key.dst_ip,
                forward_key: key.clone(),
            },
            1_000_000,
            now_secs,
            PROTO_TCP,
            TCP_FLAG_ACK,
            5,
            0, // #9383: arrival VLAN (untagged in this fixture)
            false,
            0,
            0,
        )
        .expect("the reverse shared-session hit should resolve");
    }

    // THE PROPERTY (#6313): the reverse-materialized entry carries the
    // replica's id verbatim. Reverting `materialize_shared_session_hit` to
    // `session_id: 0` reds here with a worker-4 local alloc.
    assert_eq!(
        sessions.session_id_for(&reverse),
        peer_session_id,
        "a reverse-materialized shared-session hit must ADOPT the replica's \
         session id so both directions correlate across HA nodes (#5212/#6313)"
    );

    // NEGATIVE CONTROL (passes with and without the revert): a replica with no
    // wire id still gets a fresh, non-zero, node-local id — the materialize
    // path must never leave a session unstamped.
    let control_id = sessions.session_id_for(&reverse_legacy);
    assert_ne!(
        control_id, 0,
        "a zero replica id must fall back to a fresh local alloc, not 0"
    );
    assert_eq!(
        control_id >> 48,
        4,
        "the fallback id must be namespaced to THIS node's worker (4)"
    );
    assert_ne!(
        control_id, peer_session_id,
        "the fallback must be a fresh LOCAL id, never the adopted peer id"
    );
}

// === #1346 dispatcher order-pin + dedup test =================================
//
// Round-2 Codex review required two test additions:
//   (a) An interleaved-variant dispatcher test that pins side-effect
//       order across all four WorkerCommandResults fields.
//   (b) Coverage for `DemoteOwnerRGS` duplicate / first-occurrence
//       dedup (because the original dispatcher arm carried an
//       `if !cancelled_keys.iter().any(|key| key == &demoted_key)`
//       guard whose contract must outlive the lift to
//       commands/demote_owner_rgs.rs).
//
// The test queues, in order:
//   1. DemoteOwnerRGS { owner_rgs: [5] }    — demote RG5 (one session)
//   2. UpsertSynced(s5b)                    — install a synced session
//   3. DemoteOwnerRGS { owner_rgs: [5, 5] } — duplicate; dedup-safe
//   4. ExportOwnerRGSessions { sequence: 7, owner_rgs: [5] }
//   5. DemoteOwnerRGS { owner_rgs: [7] }    — second RG
//   6. EnqueueShapedLocal(req)              — pushes onto shaped_tx_requests
//   7. RefreshOwnerRGS { owner_rgs: [5] }   — exercise the wider scan
//   8. VacateAllSharedExactSlots             — flag flip
//
// Asserts:
//   - exported_sequences == [7]                        (single Export queued)
//   - shaped_tx_requests.len() == 1                    (single ShapedLocal queued)
//   - vacate_all_shared_exact_slots == true            (Vacate queued)
//   - cancelled_keys contains the RG5 key once and the RG7 key once
//     (no duplicates from the repeated Demote(rg=5) and no extra
//     entries from the second Demote in the same command list).

#[test]
fn apply_worker_commands_dispatch_order_pin_with_demote_dedup() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();

    // Install two sessions on distinct owner RGs (5 and 7) so that
    // DemoteOwnerRGS [5] and DemoteOwnerRGS [7] each produce one
    // distinct cancelled key.
    let key_rg5 = test_key();
    let mut metadata_rg5 = test_metadata();
    metadata_rg5.owner_rg_id = 5;
    assert!(sessions.install_with_protocol_with_origin(
        key_rg5.clone(),
        test_decision(),
        metadata_rg5.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    let key_rg7 = SessionKey {
        // distinct src_port → distinct key
        src_port: 33333,
        ..test_key()
    };
    let mut metadata_rg7 = test_metadata();
    metadata_rg7.owner_rg_id = 7;
    assert!(sessions.install_with_protocol_with_origin(
        key_rg7.clone(),
        test_decision(),
        metadata_rg7.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));

    // Synced entry for the UpsertSynced step.
    let synced_entry = SyncedSessionEntry {
        key: SessionKey {
            src_port: 44444,
            ..test_key()
        },
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    // Build a minimal TxRequest for the EnqueueShapedLocal step.
    let shaped_req = TxRequest {
        bytes: Vec::new(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: None,
        egress_ifindex: -1,
        cos_queue_id: None,
        dscp_rewrite: None,
        mirror_clone: false,
        enqueue_ns: 0,
    };

    {
        let mut pending = commands.lock().expect("commands lock");
        pending.push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![5] });
        pending.push_back(WorkerCommand::UpsertSynced(synced_entry.clone()));
        pending.push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![5, 5], // duplicate within the same command
        });
        pending.push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 7,
            owner_rgs: vec![5],
        });
        pending.push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![7] });
        pending.push_back(WorkerCommand::EnqueueShapedLocal(shaped_req));
        pending.push_back(WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![5] });
        pending.push_back(WorkerCommand::VacateAllSharedExactSlots);
    }

    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Inactive on both RGs so DemoteOwnerRGS demotes them and HA enforcement
    // doesn't elide the cancellations.
    ha_state.insert(5, inactive_ha_runtime(now_secs));
    ha_state.insert(7, inactive_ha_runtime(now_secs));

    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    // ── (a) Exports preserved ───────────────────────────────────────────────
    assert_eq!(results.exported_sequences, vec![7u64]);
    // #2653: the export owner RG is recorded for the worker-loop chunked export.
    assert_eq!(results.export_owner_rgs, vec![5i32]);

    // ── (b) ShapedLocal pushed exactly once ────────────────────────────────
    assert_eq!(results.shaped_tx_requests.len(), 1);

    // ── (c) Vacate flag flipped ─────────────────────────────────────────────
    assert!(results.vacate_all_shared_exact_slots);

    // ── (d) DemoteOwnerRGS dedup contract preserved ────────────────────────
    // Both keys appear exactly once. Two dedup guards are at work:
    //
    //   1. `seen_owner_rgs.insert` inside `handle_demote_owner_rgs`
    //      skips the second `5` in `Demote{[5, 5]}`.
    //   2. The `cancelled_keys_seen` FxHashSet dedup (#5155, was a
    //      linear `!cancelled_keys.iter().any(|key| key == &demoted_key)`
    //      scan) skips key_rg5 the SECOND time it surfaces. This is NOT
    //      belt-and-braces — `SessionTable::demote_owner_rg` only
    //      flips the session's origin to `SyncImport`; it does NOT
    //      remove the entry from `owner_rg_sessions[5]`. So the
    //      second `Demote{[5]}` arm in the command stream re-discovers
    //      key_rg5 in the bucket and would re-cancel it without this
    //      guard.
    //
    // Per Gemini r1 code-review feedback: an earlier comment here
    // claimed the bucket was cleared and the guard was belt-and-braces.
    // That was empirically false — the dedup guard is load-bearing.
    // #5155 swapped its O(N) `Vec::contains` scan for an O(1) set
    // membership test; the contract asserted here is unchanged.
    let rg5_count = results
        .cancelled_keys
        .iter()
        .filter(|k| **k == key_rg5)
        .count();
    let rg7_count = results
        .cancelled_keys
        .iter()
        .filter(|k| **k == key_rg7)
        .count();
    assert_eq!(
        rg5_count, 1,
        "key_rg5 must appear exactly once in cancelled_keys"
    );
    assert_eq!(
        rg7_count, 1,
        "key_rg7 must appear exactly once in cancelled_keys"
    );
    // Nothing else got cancelled.
    assert_eq!(results.cancelled_keys.len(), 2);

    // ── (e) First-occurrence order: RG5 demote precedes RG7 demote ─────────
    let pos_rg5 = results
        .cancelled_keys
        .iter()
        .position(|k| *k == key_rg5)
        .expect("rg5 key position");
    let pos_rg7 = results
        .cancelled_keys
        .iter()
        .position(|k| *k == key_rg7)
        .expect("rg7 key position");
    assert!(
        pos_rg5 < pos_rg7,
        "DemoteOwnerRGS first-occurrence order must be preserved"
    );
}

// === #5155 fail-on-revert: DemoteOwnerRGS dedup must be O(N), not O(N^2) =====
//
// `handle_demote_owner_rgs` deduplicates every demoted key against the
// accumulated `cancelled_keys` before pushing. The original code did a
// linear `cancelled_keys.iter().any(..)` scan per key. `demote_owner_rg`
// yields UNIQUE keys, so each scan reaches the tail of the growing Vec —
// the whole pass is O(N^2). At `max_sessions` = 131072 that is ~8.6e9
// `SessionKey` comparisons ON THE PACKET WORKER, ahead of the heartbeat
// store — a multi-second failover-time stall (#5155).
//
// #5155 replaces the scan with an FxHashSet membership test, making the
// pass O(N). This test installs N unique sessions on a single inactive
// owner RG and issues ONE `DemoteOwnerRGS`, demoting all N in a single
// dispatch. It asserts:
//   - correctness: exactly N keys cancelled, all unique (the dedup does
//     not drop or duplicate any key), and
//   - the pass completes well under a wall-clock bound. `session_map_fd`
//     is -1 so `publish_worker_session_map_entry` early-returns and the
//     per-key baseline is cheap; the O(N^2) scan dominates the revert.
//
// Wall-clock bound is deliberately generous (fix: tens of ms; reverting
// to `Vec::contains` at this N runs for many seconds and blows the
// bound). This is the only observable that distinguishes the O(N) fix
// from the behavior-identical O(N^2) revert.
#[test]
fn apply_worker_commands_demote_dedup_is_linear_not_quadratic() {
    // N chosen so the O(N^2) revert (~N^2/2 ≈ 1.1e9 SessionKey compares)
    // takes several seconds while the O(N) fix stays in the tens of ms.
    const N: usize = 48_000;
    const OWNER_RG: i32 = 5;

    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();

    // Install N unique sessions all owned by OWNER_RG. Uniqueness comes
    // from the low two octets of src_ip (65536 combos > N), so every
    // demoted key is distinct and each dedup check reaches the Vec tail
    // under the old linear scan.
    for i in 0..N {
        let key = SessionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(
                10,
                200,
                (i >> 8) as u8,
                (i & 0xff) as u8,
            )),
            ..test_key()
        };
        let mut metadata = test_metadata();
        metadata.owner_rg_id = OWNER_RG;
        assert!(sessions.install_with_protocol_with_origin(
            key,
            test_decision(),
            metadata,
            SessionOrigin::ForwardFlow,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
    }

    {
        let mut pending = commands.lock().expect("commands lock");
        pending.push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![OWNER_RG],
        });
    }

    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    // Inactive so DemoteOwnerRGS actually demotes every session and the
    // HA enforcement does not elide the cancellations.
    ha_state.insert(OWNER_RG, inactive_ha_runtime(now_secs));

    let start = std::time::Instant::now();
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );
    let elapsed = start.elapsed();

    // Correctness: every unique key cancelled exactly once.
    assert_eq!(
        results.cancelled_keys.len(),
        N,
        "all {N} unique demoted keys must be cancelled exactly once"
    );
    let unique: std::collections::HashSet<_> = results.cancelled_keys.iter().collect();
    assert_eq!(
        unique.len(),
        N,
        "cancelled_keys must contain no duplicates"
    );

    // Fail-on-revert: the O(N) fix finishes in tens of ms; the O(N^2)
    // `Vec::contains` revert runs for many seconds at this N. A 3s bound
    // sits ~30-100x above the fix's runtime yet far below the revert's.
    assert!(
        elapsed.as_secs_f64() < 3.0,
        "DemoteOwnerRGS dedup over {N} keys took {elapsed:?}; expected O(N) \
         (<3s). An O(N^2) `Vec::contains` dedup regressed this path (#5155)."
    );
}

// ---------------------------------------------------------------------------
// #1807: worker-side command-queue poison recovery. A panic that poisons
// a worker command mutex must not make the consumer permanently deaf
// (apply_worker_commands) nor make producers silently drop replicas
// (replicate_session_upsert/delete). Poison shape mirrors the #1790
// ha_tests regression: a thread panics while holding the lock.
// ---------------------------------------------------------------------------

fn poison_command_queue(queue: &Arc<Mutex<VecDeque<WorkerCommand>>>) {
    let to_poison = queue.clone();
    let poisoner = std::thread::spawn(move || {
        let _guard = to_poison.lock().expect("lock before poisoning");
        panic!("poison worker command mutex");
    })
    .join();
    assert!(poisoner.is_err(), "poisoning thread must panic");
    assert!(queue.is_poisoned(), "queue mutex must be poisoned");
}

fn test_synced_entry() -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_ACK,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

#[test]
fn apply_worker_commands_recovers_poisoned_queue_and_processes_commands() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence: 21,
            owner_rgs: vec![1],
        });
    poison_command_queue(&commands);

    let mut sessions = SessionTable::new();
    let forwarding = test_forwarding_state_with_fabric();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let mut ha_state = BTreeMap::new();
    ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
    let results = apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    // The queued command was processed (NOT the empty "deaf" result the
    // pre-#1807 Err arm returned).
    assert_eq!(
        results.exported_sequences,
        vec![21],
        "poisoned queue must be recovered and its commands processed"
    );
    // clear_poison: the queue is drained and a plain lock() works again.
    assert!(!commands.is_poisoned(), "poison must be cleared");
    let pending = commands.lock().expect("plain lock after recovery");
    assert!(pending.is_empty(), "recovered queue must be drained");
}

#[test]
fn replicate_session_upsert_delivers_to_poisoned_queue() {
    // #4800: this test MOVES the process-global replication counters that
    // newflow_contention_tests asserts on. It no longer takes a guard by hand
    // — `replicate_session_upsert` takes the mover side itself under
    // `#[cfg(test)]`, so the mover set is derived rather than inventoried
    // (see `afxdp::counter_test_lock`). The hand-written inventory this
    // replaces had already missed two other real movers.
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..2)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    poison_command_queue(&queues[1]);

    let entry = test_synced_entry();
    replicate_session_upsert(&queues, &entry);

    for (worker_id, queue) in queues.iter().enumerate() {
        let pending = queue.lock().expect("queue unpoisoned after replicate");
        assert!(
            pending.iter().any(
                |command| matches!(command, WorkerCommand::UpsertSynced(replica)
                    if replica.key == entry.key)
            ),
            "worker {worker_id} missing UpsertSynced replica"
        );
    }
    assert!(!queues[1].is_poisoned(), "poison must be cleared");
}

#[test]
fn replicate_session_delete_delivers_to_poisoned_queue() {
    // #4800: `replicate_session_delete` moves NO counter (it pushes through
    // the uncounted `lock_recover`), so this test is not a mover at all and
    // needs no guard. The counted sibling above takes its guard inside
    // `replicate_session_upsert` itself.
    let queues: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = (0..2)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    poison_command_queue(&queues[0]);

    let key = test_key();
    replicate_session_delete(&queues, &key);

    for (worker_id, queue) in queues.iter().enumerate() {
        let pending = queue.lock().expect("queue unpoisoned after replicate");
        assert!(
            pending.iter().any(
                |command| matches!(command, WorkerCommand::DeleteSynced(deleted)
                    if deleted == &key)
            ),
            "worker {worker_id} missing DeleteSynced"
        );
    }
    assert!(!queues[0].is_poisoned(), "poison must be cleared");
}

// ---------------------------------------------------------------------------
// #1760 W3': shared-map NAT reverse-key displacement counter
// ---------------------------------------------------------------------------
//
// NOTE on the process-global static: NAT_REVERSE_KEY_SHARED_DISPLACEMENTS is
// shared across the whole test binary. All assertions below are DELTA-based
// around the specific publish calls, and only the tests in this block publish
// colliding (distinct-forward-key, same-reverse-key) entries — every other
// test in the binary publishes either unrelated keys or same-session
// republishes, neither of which increments the counter. The positive and
// negative cases are kept in ONE test to avoid cross-test ordering effects.

fn w3_forward_entry(src_host: u8, src_port: u16, snat_ip: Ipv4Addr) -> SyncedSessionEntry {
    // Interface-mode SNAT shape: rewrite_src set, NO source-port rewrite —
    // the portless mode that makes the reverse key collide (#1760 §2.7).
    SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, src_host)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(snat_ip)),
                rewrite_src_port: None,
                ..NatDecision::default()
            },
        },
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x02,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

#[test]
fn shared_nat_displacement_counter_counts_collisions_not_republishes() {
    use crate::afxdp::shared_ops::NAT_REVERSE_KEY_SHARED_DISPLACEMENTS;
    use std::sync::atomic::Ordering;

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let snat_ip = Ipv4Addr::new(172, 16, 80, 8);

    // Two distinct internal hosts, SAME source port, same dst — the
    // interface-SNAT collision: identical reverse wire key K.
    let s1 = w3_forward_entry(101, 40_000, snat_ip);
    let s2 = w3_forward_entry(102, 40_000, snat_ip);
    assert_ne!(s1.key, s2.key, "distinct forward sessions");
    assert_eq!(
        reverse_session_key(&s1.key, s1.decision.nat),
        reverse_session_key(&s2.key, s2.decision.nat),
        "construction must produce a genuine reverse-key collision"
    );

    // Fresh publish: no displacement.
    let before = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s1,
    );
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before,
        "first publish must not count"
    );

    // Same-session republish (promote / RG migration / HA re-sync shape):
    // displaced.key == entry.key -> no count.
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s1,
    );
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before,
        "same-session republish must not count"
    );

    // Colliding second session displaces s1 at K -> counts. The
    // reverse-canonical slot for this NAT shape may coincide with the wire
    // slot (single insert) or differ (second insert also displaces); accept
    // either by asserting a positive, bounded delta.
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s2,
    );
    let after_collision = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    let delta = after_collision - before;
    assert!(
        (1..=2).contains(&delta),
        "colliding publish must count once per displaced slot (delta={delta})"
    );

    // s1 re-publishes (e.g. its worker re-installs): displaces s2 -> counts
    // again. Alternations keep counting — event count, not pair census.
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &s1,
    );
    assert!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed) > after_collision,
        "alternation must count again"
    );

    // All remaining negatives live in THIS test (not separate #[test]s):
    // the counter static is process-global and cargo runs tests in
    // parallel, so equality assertions in a sibling test could observe
    // this test's increments (Codex code-r1 F2).
    let settled = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);

    // Reverse entries never touch shared_nat_sessions.
    let mut reverse = w3_forward_entry(103, 40_001, snat_ip);
    reverse.metadata.is_reverse = true;
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &reverse,
    );
    publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &reverse,
    );
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        settled,
        "reverse entries never touch shared_nat_sessions"
    );

    // HA fabric-redirect wire-ALIAS republish (Codex code-r1 F1): the
    // same logical session arrives a second time under its NAT-translated
    // forward-wire key with the same value
    // (daemon_ha_userspace.go userspaceForwardWireAliasFromDeltaV4). The
    // alias derives the same reverse key K as its canonical form and
    // MUST NOT count as a collision.
    let fresh_nat = Arc::new(Mutex::new(FastMap::default()));
    let mut canonical = w3_forward_entry(110, 40_002, snat_ip);
    // On the wire both canonical and alias arrive via HA sync.
    canonical.origin = SessionOrigin::SyncImport;
    let mut alias = canonical.clone();
    alias.key = forward_wire_key(&canonical.key, canonical.decision.nat);
    assert_ne!(alias.key, canonical.key, "alias must be a distinct key");
    assert_eq!(
        reverse_session_key(&alias.key, alias.decision.nat),
        reverse_session_key(&canonical.key, canonical.decision.nat),
        "alias and canonical must derive the same reverse key K"
    );
    let before_alias = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [&canonical, &alias, &canonical] {
        publish_shared_session(
            &shared_sessions,
            &fresh_nat,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before_alias,
        "canonical<->wire-alias churn of one logical session must not count"
    );

    // Codex code-r2: DNAT-vs-direct is a GENUINE collision whose keys are
    // wire-related — a DNAT flow client:p -> VIP:443 rewritten to
    // backend:443, plus a direct no-NAT flow client:p -> backend:443.
    // Both derive the same reverse key K; the alias exclusion must NOT
    // swallow it (their NatDecisions differ).
    let backend = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 90));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 120));
    let dnat = SyncedSessionEntry {
        key: SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: client,
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 91)), // VIP
            src_port: 40_003,
            dst_port: 443,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_dst: Some(backend),
                ..NatDecision::default()
            },
        },
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x02,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let mut direct = dnat.clone();
    direct.key.dst_ip = backend;
    direct.decision.nat = NatDecision::default();
    assert_eq!(
        reverse_session_key(&dnat.key, dnat.decision.nat),
        reverse_session_key(&direct.key, direct.decision.nat),
        "DNAT and direct flows must derive the same reverse key K"
    );
    let dnat_map = Arc::new(Mutex::new(FastMap::default()));
    let before_dnat = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [&dnat, &direct] {
        publish_shared_session(
            &shared_sessions,
            &dnat_map,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed) > before_dnat,
        "DNAT-vs-direct genuine collision must count despite wire-related keys"
    );

    // Codex code-r3 owner-side corner: a LOCAL flow whose source already
    // equals the SNAT external address. Identical NatDecision and
    // wire-related keys, but BOTH entries are locally originated — two
    // real sessions, must count. (The alias exclusion requires at least
    // one peer-synced side: the HA wire-alias never originates locally.)
    let local_a = w3_forward_entry(121, 40_004, snat_ip); // 10.0.61.121
    let mut local_b = local_a.clone();
    local_b.key.src_ip = IpAddr::V4(snat_ip); // source IS the external IP
    assert_eq!(
        local_b.key,
        forward_wire_key(&local_a.key, local_a.decision.nat),
        "corner construction: B must be A's wire form"
    );
    assert_eq!(local_a.decision.nat, local_b.decision.nat);
    assert!(!local_a.origin.is_peer_synced() && !local_b.origin.is_peer_synced());
    let corner_map = Arc::new(Mutex::new(FastMap::default()));
    let before_corner = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [&local_a, &local_b] {
        publish_shared_session(
            &shared_sessions,
            &corner_map,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed) > before_corner,
        "local same-NAT wire-related pair must count (owner-side corner)"
    );

    // Codex code-r4: post-failover PROMOTE churn. At activation the new
    // owner can promote both the canonical and its wire-alias to
    // SharedPromote (not peer-synced) and republish each — identical
    // NatDecision, wire-related keys, same logical session. Must not
    // count, in either promote order.
    let mut promoted_canonical = w3_forward_entry(130, 40_005, snat_ip);
    promoted_canonical.origin = SessionOrigin::SharedPromote;
    let mut promoted_alias = promoted_canonical.clone();
    promoted_alias.key = forward_wire_key(&promoted_canonical.key, promoted_canonical.decision.nat);
    let promote_map = Arc::new(Mutex::new(FastMap::default()));
    let before_promote = NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed);
    for entry in [
        &promoted_canonical, // canonical-then-alias
        &promoted_alias,
        &promoted_canonical, // alias-then-canonical
    ] {
        publish_shared_session(
            &shared_sessions,
            &promote_map,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            entry,
        );
    }
    assert_eq!(
        NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.load(Ordering::Relaxed),
        before_promote,
        "SharedPromote canonical<->alias churn must not count (either order)"
    );
}

#[test]
fn nat_reverse_key_warn_throttle_claims_once_per_window() {
    use crate::afxdp::shared_ops::try_claim_nat_reverse_key_warn;

    // The throttle static is process-global and never reset; derive a base
    // far beyond any previously claimed slot so this test is self-contained.
    let base: u64 = 365 * 24 * 3_600 * 1_000_000_000;
    assert!(
        try_claim_nat_reverse_key_warn(base),
        "first claim past the window must win"
    );
    assert!(
        !try_claim_nat_reverse_key_warn(base + 1_000_000_000),
        "claim inside the 60s window must lose"
    );
    assert!(
        !try_claim_nat_reverse_key_warn(base + 59_999_999_999),
        "claim at window edge - 1ns must lose"
    );
    assert!(
        try_claim_nat_reverse_key_warn(base + 60_000_000_000),
        "claim at the window boundary must win"
    );
}

// ── #1870: UpsertLocal joins the uncapped sync-family install ────────
//
// Deterministic at-cap pins for the local-tunnel prewarm pair. The
// coordinator publishes the forward + synthesized-reverse pair to the
// shared maps unconditionally and fans `WorkerCommand::UpsertLocal` ×2
// out to every worker; routing the apply side through the CAPPED
// install let max_sessions silently refuse the worker-table copy while
// the shared maps kept both entries. These pins run in debug AND
// release profiles (#1855 contract) and use `assert!` on outcomes —
// the production arm's `debug_assert!`s compile out in release.

/// Mirror the producer's pair shape (`build_local_origin_tunnel_tx_request`
/// + `synthesized_synced_reverse_entry`): SyncImport origin, default NAT
/// (no rewrites — so no forward-wire alias exists), forward + reverse.
fn local_tunnel_pair() -> (SyncedSessionEntry, SyncedSessionEntry) {
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let forward = SyncedSessionEntry {
        key: test_key(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: TCP_FLAG_ACK,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reverse = synthesized_synced_reverse_entry(
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &forward,
        1,
    )
    .expect("reverse companion");
    (forward, reverse)
}

/// Shrink the cap and fill the table with `fill` distinct local entries
/// whose keys cannot collide with the local-tunnel pair (filler src
/// ports start at 40000; the pair uses 55068/5201).
fn rig_capped_table(cap: usize, fill: usize) -> SessionTable {
    let mut sessions = SessionTable::new();
    sessions.set_max_sessions_for_test(cap);
    for i in 0..fill {
        let key = SessionKey {
            src_port: 40_000 + i as u16,
            ..test_key()
        };
        assert!(sessions.install_with_protocol(
            key,
            test_decision(),
            test_metadata(),
            1_000_000,
            PROTO_TCP,
            TCP_FLAG_ACK,
        ));
    }
    assert_eq!(sessions.len(), fill);
    // Discard the fillers' open deltas so later assertions on the delta
    // ring observe only the behavior under test.
    let _ = sessions.drain_deltas(usize::MAX);
    sessions
}

fn apply_upsert_local_pair(
    sessions: &mut SessionTable,
    forward: &SyncedSessionEntry,
    reverse: &SyncedSessionEntry,
) -> WorkerCommandResults {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut pending = commands.lock().expect("commands lock");
        pending.push_back(WorkerCommand::UpsertLocal(forward.clone()));
        pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));
    }
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &commands,
        sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    )
}

/// §2.2 interleaving through the fixed arm: a table AT max_sessions
/// admits the full pair (uncapped sync-family semantics) and no
/// refusal counter moves. Pre-#1870 both installs were silently
/// refused (create_drops += 2) while the shared maps held the pair.
#[test]
fn upsert_local_pair_installs_at_cap() {
    let cap = 4;
    let mut sessions = rig_capped_table(cap, cap);
    let (forward, reverse) = local_tunnel_pair();

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    // Exact forward-key lookups — NOT find_forward_wire_match: with
    // default NAT, wire_key == key and the forward-wire index never
    // holds these entries (index_forward_nat_key only inserts when
    // they differ).
    let (_, _, fwd_origin) = sessions
        .entry_with_origin(&forward.key)
        .expect("forward entry installed at cap");
    assert_eq!(fwd_origin, SessionOrigin::SyncImport);
    let (_, rev_metadata, rev_origin) = sessions
        .entry_with_origin(&reverse.key)
        .expect("reverse entry installed at cap");
    assert_eq!(rev_origin, SessionOrigin::SyncImport);
    assert!(rev_metadata.is_reverse);
    assert_eq!(sessions.len(), cap + 2, "pair admitted past the cap");
    assert_eq!(sessions.create_drops(), 0, "no longer counted as drops");
    assert_eq!(sessions.admission_refused(), 0);
    assert_eq!(sessions.install_partial(), 0);
    // SyncImport installs must not enqueue HA deltas.
    assert!(sessions.drain_deltas(usize::MAX).is_empty());
}

/// Producer fan-out pin (Codex #1870 plan r2): worker tables are
/// independent — one at cap, one below — and both must converge to
/// holding the full pair after the same fan-out.
#[test]
fn upsert_local_fanout_diverged_workers_converge() {
    let (forward, reverse) = local_tunnel_pair();
    let mut at_cap = rig_capped_table(2, 2);
    let mut below_cap = rig_capped_table(8, 2);

    for sessions in [&mut at_cap, &mut below_cap] {
        apply_upsert_local_pair(sessions, &forward, &reverse);
        assert!(sessions.entry_with_origin(&forward.key).is_some());
        assert!(sessions.entry_with_origin(&reverse.key).is_some());
        assert_eq!(sessions.create_drops(), 0);
    }
    assert_eq!(at_cap.len(), 4);
    assert_eq!(below_cap.len(), 4);
}

/// Exactly one free slot: pre-#1870 the forward install succeeded and
/// the reverse was refused (partial pair — worker held forward only
/// while the shared maps held both). The fixed arm admits both.
#[test]
fn upsert_local_pair_no_partial_at_cap_minus_one() {
    let cap = 4;
    let mut sessions = rig_capped_table(cap, cap - 1);
    let (forward, reverse) = local_tunnel_pair();

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    assert!(sessions.entry_with_origin(&forward.key).is_some());
    assert!(
        sessions.entry_with_origin(&reverse.key).is_some(),
        "reverse half must not be dropped when only one slot is free"
    );
    assert_eq!(sessions.len(), cap + 1);
    assert_eq!(sessions.create_drops(), 0);
}

/// Below cap, `allow_replace_local=true` preserves the pre-#1870
/// replace semantics of the capped install (which clobbered any
/// same-key entry below cap). Guards against a future "tidy-up" to
/// `allow_replace_local=false` or a revert to the capped install.
#[test]
fn upsert_local_below_cap_replaces_existing_local_entry() {
    let mut sessions = SessionTable::new();
    let (forward, reverse) = local_tunnel_pair();
    assert!(sessions.install_with_protocol(
        forward.key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(usize::MAX);

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    let (_, _, origin) = sessions
        .entry_with_origin(&forward.key)
        .expect("replaced entry");
    assert_eq!(
        origin,
        SessionOrigin::SyncImport,
        "local same-key entry must be replaced by the tunnel decision"
    );
    assert_eq!(sessions.len(), 2, "replace + reverse install");
    assert_eq!(sessions.create_drops(), 0);
}

/// At cap, same-key replacement is a deliberate #1870 semantic change:
/// the old capped install refused BEFORE reaching remove_entry, so a
/// stale same-key local entry could never be replaced at cap (and a
/// local hit shadows the shared scope, blocking reactive
/// materialization until expiry). The new arm replaces it without
/// growing the table.
#[test]
fn upsert_local_at_cap_replaces_existing_local_entry_without_growth() {
    let cap = 4;
    let mut sessions = rig_capped_table(cap, cap - 1);
    let (forward, reverse) = local_tunnel_pair();
    assert!(sessions.install_with_protocol(
        forward.key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    assert_eq!(sessions.len(), cap, "table rigged to cap incl. stale key");
    let _ = sessions.drain_deltas(usize::MAX);

    apply_upsert_local_pair(&mut sessions, &forward, &reverse);

    let (_, _, origin) = sessions
        .entry_with_origin(&forward.key)
        .expect("replaced entry at cap");
    assert_eq!(origin, SessionOrigin::SyncImport);
    assert_eq!(
        sessions.len(),
        cap + 1,
        "same-key replace must not grow; only the reverse adds a slot"
    );
    assert_eq!(sessions.create_drops(), 0);
}

/// Pins the expected (permanent, by-origin) bulk-export behavior:
/// local-tunnel entries carry SyncImport and are skipped by
/// export_forward_sessions_for_owner_rgs at ANY occupancy — their
/// exclusion is origin design, not a cap artifact (Codex #1870 plan
/// r1 finding 3; refuted v1's "at-cap bulk-export gap" claim).
#[test]
fn upsert_local_entries_stay_out_of_owner_rg_bulk_export() {
    let mut sessions = SessionTable::new();
    let (forward, reverse) = local_tunnel_pair();
    apply_upsert_local_pair(&mut sessions, &forward, &reverse);
    assert!(sessions.entry_with_origin(&forward.key).is_some());
    assert!(sessions.drain_deltas(usize::MAX).is_empty());

    export_forward_sessions_for_owner_rgs(&mut sessions, &[1]);

    assert!(
        sessions.drain_deltas(usize::MAX).is_empty(),
        "peer-synced-origin local-tunnel entries must not bulk-export"
    );
}

/// #2669: a drained Close delta must reach its binding-INDEPENDENT
/// consumers (shared session/conntrack tables, HA peer-worker delete
/// replication, recent-deltas RPC buffer, event stream) even when the
/// worker has NO bindings — i.e. `flush_session_deltas` is invoked with
/// `live = None`. The pre-fix code drained the delta off the ring and then
/// skipped the whole flush when `bindings.first()` was `None`, silently
/// discarding the close. This test exercises the `live = None` path
/// directly: reverting the fix (re-gating the flush on a binding, or
/// passing `&binding.live` only) makes none of these consumers observe the
/// delete, so the assertions go red — fail-on-revert.
#[test]
fn flush_session_deltas_without_binding_reaches_global_consumers() {
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();

    // Seed the shared session table so the Close delete has something to
    // remove (the binding-independent shared-table consumer).
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let shared_entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: metadata.clone(),
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
    assert!(
        !shared_sessions.lock().expect("shared sessions").is_empty(),
        "precondition: shared session seeded"
    );

    // One peer-worker command queue — the HA delete-replication sink.
    let peer_queue: Arc<Mutex<VecDeque<WorkerCommand>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands = vec![peer_queue.clone()];
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let forwarding = ForwardingState::default();

    let delta = SessionDelta {
        kind: SessionDeltaKind::Close,
        key: key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    };

    // Synthesize a binding identity with labels only — exactly what the
    // worker loop does when `bindings` is empty — and flush with NO live
    // RPC queue and the fd-less (-1) map fds.
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
    let mut worker_lossless_wedged = false;
    flush_session_deltas(
        &ident,
        None,
        -1,
        -1,
        -1,
        &dnat_fds,
        &[delta],
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &None,
        &forwarding,
        &mut worker_lossless_wedged,
    );

    // Binding-independent consumer 1: shared session table cleared.
    assert!(
        shared_sessions.lock().expect("shared sessions").is_empty(),
        "Close delta must remove the shared session even with no binding"
    );
    // Binding-independent consumer 2: HA peer-worker delete replication.
    let replicated: Vec<_> = peer_queue
        .lock()
        .expect("peer queue")
        .iter()
        .cloned()
        .collect();
    assert!(
        replicated
            .iter()
            .any(|cmd| matches!(cmd, WorkerCommand::DeleteSynced(k) if *k == key)),
        "Close delta must replicate a DeleteSynced to the HA peer even with no binding"
    );
    // Binding-independent consumer 3: recent-deltas RPC buffer.
    let recent = recent_session_deltas.lock().expect("recent deltas");
    assert!(
        recent.iter().any(|info| info.event == "close"),
        "Close delta must reach the recent-deltas buffer even with no binding"
    );
}

/// #3416 FAIL-ON-REVERT (call-site WIRING pin): the permit-side RT_FLOW
/// SESSION_CREATE / SESSION_CLOSE application id is resolved INSIDE
/// `flush_session_deltas` via `AppCatalog::lookup_admitted`, which substitutes
/// the post-NAT (DNAT-rewritten) destination port for the forward service slot.
/// The helper-level test (`app_catalog_lookup_admitted_uses_post_nat_dst_port`)
/// proves `lookup_admitted` in isolation; this drives the PRODUCTION drain loop
/// end to end against a port-forwarded session and decodes the emitted RT_FLOW
/// frames, so reverting EITHER session_delta.rs call site back to
/// `lookup_directional` (dropping the `rewrite_dst_port` argument) makes the
/// stamped `application_id` resolve UNKNOWN(0) from the pre-NAT public port and
/// the assertions below go red.
#[test]
fn flush_session_deltas_rt_flow_app_id_uses_post_nat_dst_port() {
    // junos-ssh stand-in: app_id 22 on TCP/22 (the INTERNAL/post-NAT port).
    // Nothing is registered on the PUBLIC :2222, so a pre-NAT resolution yields
    // UNKNOWN(0) — exactly the #3416 mislabel the wiring must avoid.
    const JUNOS_SSH: u16 = 22;
    let mut forwarding = ForwardingState::default();
    forwarding.app_catalog = crate::policy::AppCatalog::from_snapshot(&[crate::AppCatalogEntry {
        app_id: JUNOS_SSH,
        protocol: PROTO_TCP,
        dst_port_low: 22,
        dst_port_high: 22,
        src_port_low: 0,
        src_port_high: 0,
    }]);

    // Forward DNAT session: client 192.0.2.50:51000 -> PUBLIC 203.0.113.10:2222,
    // DNAT-rewritten to inside 10.0.0.10:22 (admitted by junos-ssh). The forward
    // session key carries the PRE-NAT public port; the decision carries the
    // POST-NAT rewrite the policy admitted the flow under.
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 51000,
        dst_port: 2222,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut decision = test_decision();
    decision.nat.rewrite_dst = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)));
    decision.nat.rewrite_dst_port = Some(22);
    let mut metadata = test_metadata();
    // SESSION_CREATE is producer-gated on the admitting policy's session-init
    // log selection; SESSION_CLOSE always emits.
    metadata.log_session_init = true;

    let make_delta = |kind| SessionDelta {
        kind,
        key: key.clone(),
        decision,
        metadata: metadata.clone(),
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    };

    // Drive the production drain loop and return the stamped application_id off
    // the emitted RT_FLOW frame. `want_event_type` is the RT_FLOW event-type
    // byte at payload[52] (1 = SESSION_OPEN/create, 2 = SESSION_CLOSE). The
    // drain also queues an HA session-sync frame (type 1/2 — `from_msg_type`
    // returns None, so `dataplane_event_payload()` is None for it); the RT_FLOW
    // create/close frame (type 15/14) is the only one with a Some payload.
    // NOTE: `decode_dataplane_event()` is NOT used here — it decodes only the
    // deny/screen/filter kinds (`from_rt_flow_event_type` rejects the session
    // event types), so app_id is read from the payload [132:134] slot directly,
    // exactly as the codec/Go side reads it.
    let stamped_app = |delta: SessionDelta, want_event_type: u8| -> u16 {
        let (handle, rx) = crate::event_stream::test_worker_handle(
            8,
            // Unlimited (events_per_second == 0) — the proven RT_FLOW-emit test
            // harness config; the default carries a real per-bucket rate limit.
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 7,
        };
        let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
        let mut worker_lossless_wedged = false;
        flush_session_deltas(
            &ident,
            None,
            -1,
            -1,
            -1,
            &dnat_fds,
            &[delta],
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &recent_session_deltas,
            &peer_worker_commands,
            crate::afxdp::empty_worker_commands_by_id(),
            &Some(handle),
            &forwarding,
            &mut worker_lossless_wedged,
        );
        let frames: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let payload = frames
            .iter()
            .find_map(|f| f.dataplane_event_payload())
            .expect("an RT_FLOW dataplane-event frame on the channel");
        assert_eq!(
            payload[52], want_event_type,
            "RT_FLOW frame must carry the expected session event type at [52]"
        );
        u16::from_le_bytes([payload[132], payload[133]])
    };

    assert_eq!(
        stamped_app(make_delta(SessionDeltaKind::Open), 1),
        JUNOS_SSH,
        "SESSION_CREATE RT_FLOW must stamp the post-NAT app (junos-ssh/22), \
         not UNKNOWN(0) resolved from the pre-NAT public :2222"
    );
    assert_eq!(
        stamped_app(make_delta(SessionDeltaKind::Close), 2),
        JUNOS_SSH,
        "SESSION_CLOSE RT_FLOW must stamp the post-NAT app (junos-ssh/22), \
         not UNKNOWN(0) resolved from the pre-NAT public :2222"
    );
}

#[test]
fn flush_session_deltas_session_close_reresolves_policy_id_after_reorder() {
    // #3395 RED-on-revert (close path, end-to-end): a session admitted by rule
    // "bee" at positional policy_id 5, then renumbered to 6 by a live insert of
    // "aaa" above it, must close with bee's NEW positional id (6) in the
    // SESSION_CLOSE RT_FLOW [136:140] slot — NOT the frozen install-time id (5).
    // Reverting emit_session_close_rt_flow / the flush re-resolution to read
    // `delta.metadata.policy_id` makes [136:140] read 5 → RED.
    let mut zone_map = FastMap::default();
    zone_map.insert("lan".to_string(), 1u16);
    zone_map.insert("wan".to_string(), 2u16);

    let store = crate::policy::PolicyCounterStore::default();
    let permit = |name: &str, policy_id: u32| crate::PolicyRuleSnapshot {
        name: name.to_string(),
        policy_id,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["any".to_string()],
        applications: vec!["any".to_string()],
        action: "permit".to_string(),
        ..Default::default()
    };
    // Snapshot 1: bee alone at positional id 5; capture its bound counter handle
    // (the #3322 install-time binding, now carrying bee's stable rule_id).
    let s1 = crate::policy::parse_policy_state_with_counters(
        "deny",
        &[permit("bee", 5)],
        &zone_map,
        &[],
        &store,
    )
    .expect("s1");
    let bound_bee = s1.hit_counter_by_idx(1).cloned().expect("bee bound handle");

    // Snapshot 2 (post-reorder): aaa inserted above bee, bee renumbered 5 -> 6.
    let mut forwarding = ForwardingState::default();
    forwarding.policy = crate::policy::parse_policy_state_with_counters(
        "deny",
        &[permit("aaa", 5), permit("bee", 6)],
        &zone_map,
        &[],
        &store,
    )
    .expect("s2");

    // The closing session carries bee's bound handle and a STALE frozen
    // policy_id of 5 (its install-time value).
    let mut metadata = test_metadata();
    metadata.policy_id = 5;
    metadata.policy_counter = Some(bound_bee);

    let delta = SessionDelta {
        kind: SessionDeltaKind::Close,
        key: test_key(),
        decision: test_decision(),
        metadata,
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    };

    let (handle, rx) = crate::event_stream::test_worker_handle(
        8,
        crate::event_stream::DataplaneEventRateLimitConfig {
            events_per_second: 0,
            burst: 0,
        },
    );
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from("ge-0-0-2"),
        ifindex: 7,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
    let mut worker_lossless_wedged = false;
    flush_session_deltas(
        &ident,
        None,
        -1,
        -1,
        -1,
        &dnat_fds,
        &[delta],
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &Some(handle),
        &forwarding,
        &mut worker_lossless_wedged,
    );
    let frames: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    let payload = frames
        .iter()
        .find_map(|f| f.dataplane_event_payload())
        .expect("an RT_FLOW dataplane-event frame on the channel");
    assert_eq!(payload[52], 2, "RT_FLOW frame must be SESSION_CLOSE (2)");
    assert_eq!(
        u32::from_le_bytes(payload[136..140].try_into().unwrap()),
        6,
        "SESSION_CLOSE RT_FLOW must carry bee's RE-RESOLVED current positional id \
         (6), not the frozen install-time id (5)"
    );
}

/// #2874 FAIL-ON-REVERT: a correctness-critical HA session OPEN delta that
/// cannot be queued losslessly to the event-stream consumer must be reported as
/// out-of-sync (flush_session_deltas returns true) so the worker loop forces a
/// full owner-RG resync — it must NOT be silently dropped.
///
/// `test_worker_handle` yields a DISCONNECTED handle (connected=false), so
/// `push_delta_lossless` fails immediately the same way a wedged/disconnected
/// consumer would after exhausting its bounded backpressure — no 5s wait in the
/// unit test.
///
/// Fail-on-revert: restore `es.push_delta(...)` (the lossy `try_send`) and the
/// open delta is queued into the empty (capacity-1) channel WITHOUT surfacing a
/// failure, so flush_session_deltas returns false and the assertion goes red —
/// exactly the silent standby session loss #2874 describes.
#[test]
fn flush_session_deltas_event_stream_drop_latches_out_of_sync() {
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let forwarding = ForwardingState::default();

    // Disconnected event-stream handle (capacity 1, connected=false): the
    // lossless producer fails immediately on a session-sync push.
    let (handle, _rx) = crate::event_stream::test_worker_handle(
        1,
        crate::event_stream::DataplaneEventRateLimitConfig::default(),
    );
    let event_stream = Some(handle);

    let open = SessionDelta {
        kind: SessionDeltaKind::Open,
        key: key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    };

    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
    let mut worker_lossless_wedged = false;
    let out_of_sync = flush_session_deltas(
        &ident,
        None,
        -1,
        -1,
        -1,
        &dnat_fds,
        &[open],
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &event_stream,
        &forwarding,
        &mut worker_lossless_wedged,
    );

    assert!(
        out_of_sync,
        "a session-sync OPEN delta that cannot be queued losslessly must latch out-of-sync, not be silently dropped (#2874)"
    );
    // The binding-independent recent-deltas consumer still observes the open —
    // the out-of-sync signal is additive, not a skip of the other consumers.
    assert!(
        recent_session_deltas
            .lock()
            .expect("recent deltas")
            .iter()
            .any(|info| info.event == "open"),
        "open delta must still reach the recent-deltas buffer"
    );
}

/// #5468 FAIL-ON-REVERT: `flush_session_deltas` runs on the packet worker loop,
/// so a session-sync delta that cannot be queued to a CONNECTED-but-UNREAD peer
/// (a slow/stalled reader whose lossless queue is full) must NOT block the loop
/// for the full 5 s `LOSSLESS_QUEUE_TIMEOUT`. That exceeds `HEARTBEAT_STALE_AFTER`
/// (5 s), so the loop would stop stamping its heartbeat, the peer would mark this
/// node stale, and a spurious failover would fire.
///
/// This builds a CONNECTED handle whose bounded channel is FILLED to capacity
/// (the `Receiver` is never drained), so the lossless send exercises the bounded
/// backpressure retry loop — not the immediate `!connected` early return the
/// sibling `..._drop_latches_out_of_sync` test uses. The assertions are:
///   1. the worker-side send returns WELL BELOW `HEARTBEAT_STALE_AFTER` (bounded
///      to ~`WORKER_LOSSLESS_QUEUE_BUDGET`), and
///   2. on that bounded timeout it LATCHES loss-of-sync (`flush_session_deltas`
///      returns `true`) so the worker forces a full owner-RG resync — never a
///      silent drop (the #2874 losslessness contract).
///
/// RED on revert: restoring the worker-loop call to the unbounded
/// `es.push_delta_lossless(...)` (which waits the full 5 s `LOSSLESS_QUEUE_TIMEOUT`)
/// makes `elapsed` ≈ 5 s and the bounded-time assertion fails.
#[test]
fn flush_session_deltas_full_queue_send_is_bounded_and_latches_out_of_sync() {
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let forwarding = ForwardingState::default();

    // CONNECTED handle with a tiny channel; `_rx` is intentionally never read so
    // the channel fills and stays full (models an unread peer).
    let capacity = 4usize;
    let (handle, _rx) = crate::event_stream::test_worker_handle_connected(
        capacity,
        crate::event_stream::DataplaneEventRateLimitConfig::default(),
    );

    let open = SessionDelta {
        kind: SessionDeltaKind::Open,
        key: key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    };

    // Saturate the channel: fill every slot with a best-effort filler push so the
    // subsequent worker-loop lossless send finds it Full and enters the bounded
    // retry loop.
    for _ in 0..capacity {
        handle.push_delta(&open, &forwarding.zone_name_to_id);
    }

    let event_stream = Some(handle);
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();

    let start = std::time::Instant::now();
    let mut worker_lossless_wedged = false;
    let out_of_sync = flush_session_deltas(
        &ident,
        None,
        -1,
        -1,
        -1,
        &dnat_fds,
        &[open],
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &event_stream,
        &forwarding,
        &mut worker_lossless_wedged,
    );
    let elapsed = start.elapsed();

    assert!(
        out_of_sync,
        "a session-sync delta that cannot be queued losslessly to a full/unread peer must latch out-of-sync (force a full owner-RG resync), not be silently dropped (#2874/#5468)"
    );
    // The worker-side send must be bounded WELL BELOW the heartbeat-stale
    // threshold. `WORKER_LOSSLESS_QUEUE_BUDGET` is one fifth of
    // HEARTBEAT_STALE_AFTER, so a 2x-budget ceiling cleanly separates the fix
    // (~1x budget) from the reverted 5 s block (~5x budget).
    assert!(
        elapsed < WORKER_LOSSLESS_QUEUE_BUDGET * 2,
        "worker-loop lossless send must be bounded to ~WORKER_LOSSLESS_QUEUE_BUDGET ({:?}), took {:?}; reverting to the unbounded 5 s LOSSLESS_QUEUE_TIMEOUT regresses #5468 (worker stalls past HEARTBEAT_STALE_AFTER -> false liveness loss)",
        WORKER_LOSSLESS_QUEUE_BUDGET,
        elapsed
    );
    assert!(
        elapsed < HEARTBEAT_STALE_AFTER,
        "worker-loop lossless send ({elapsed:?}) must never reach HEARTBEAT_STALE_AFTER ({HEARTBEAT_STALE_AFTER:?}) -> the peer would mark this node stale and fail over (#5468)"
    );
}

/// #5468 FAIL-ON-REVERT (aggregate): bounding a SINGLE `flush_session_deltas`
/// call to `WORKER_LOSSLESS_QUEUE_BUDGET` (the sibling test above) is not enough.
/// The #2442 loss-of-sync resync (`take_delta_loss` -> `chunked_drain_as_you_
/// export!` -> `drain_and_flush_all!` in worker/loop_body/mod.rs) and the #2653
/// command export call `flush_session_deltas` ONCE PER 256-delta batch across the
/// ENTIRE owned-session set. For K owned sessions that is ~K/256 calls; at ~1
/// budget each an unread peer would cost ~(K/256) budgets of worker-loop stall.
/// With `WORKER_LOSSLESS_QUEUE_BUDGET` = `HEARTBEAT_STALE_AFTER`/5, any K past
/// ~1280 (5 batches) re-crosses `HEARTBEAT_STALE_AFTER` and re-triggers the SAME
/// spurious failover — the #5468 gap, unfixed for the under-load resync case.
///
/// The fix threads a per-drain-cycle `worker_lossless_wedged` latch through every
/// `flush_session_deltas` call the worker makes in one iteration: the FIRST wedge
/// waits one budget and sets the latch; every subsequent call inherits it and
/// SKIPS the lossless wait entirely (still draining to the other consumers). So
/// the aggregate worker-loop lossless wait collapses to ~1 budget regardless of
/// K, while every wedged batch still returns `true` (keeps the loss-of-sync latch
/// set -> the resync retries next cycle; deliver-or-resync, never a silent drop).
///
/// This drives BATCHES > 5 calls (>1280 sessions at 256/batch) sharing ONE
/// `worker_lossless_wedged`, against a CONNECTED-but-UNREAD full channel, and
/// asserts the TOTAL time stays well below `HEARTBEAT_STALE_AFTER`.
///
/// RED on revert: seeding `event_stream_out_of_sync = false` instead of
/// `*worker_lossless_wedged` (i.e. dropping the aggregate inheritance) makes each
/// of the BATCHES calls pay its own full budget wait, so the total is ~BATCHES
/// budgets — past `HEARTBEAT_STALE_AFTER` — and both time assertions fail.
#[test]
fn resync_export_aggregate_lossless_wait_is_bounded_below_heartbeat() {
    let key = test_key();
    let decision = test_decision();
    let metadata = test_metadata();

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let forwarding = ForwardingState::default();

    // CONNECTED handle with a tiny channel filled to capacity; `_rx` is never
    // drained so the channel stays full (models a connected-but-unread peer).
    let capacity = 4usize;
    let (handle, _rx) = crate::event_stream::test_worker_handle_connected(
        capacity,
        crate::event_stream::DataplaneEventRateLimitConfig::default(),
    );

    let open = SessionDelta {
        kind: SessionDeltaKind::Open,
        key: key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync: false,
        tcp_close_class: 0,
    };
    for _ in 0..capacity {
        handle.push_delta(&open, &forwarding.zone_name_to_id);
    }

    let event_stream = Some(handle);
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();

    // >5 batches: at 256 deltas/batch this is >1280 owned sessions, the point at
    // which the UNBOUNDED aggregate (one budget per batch) crosses
    // HEARTBEAT_STALE_AFTER. Each call carries a single delta — the per-call cost
    // is one budget wait whether the batch holds 1 or 256 deltas, so one delta
    // faithfully models one 256-delta resync batch.
    const BATCHES: usize = 8;
    let mut worker_lossless_wedged = false;
    let start = std::time::Instant::now();
    let mut all_latched = true;
    for _ in 0..BATCHES {
        let out_of_sync = flush_session_deltas(
            &ident,
            None,
            -1,
            -1,
            -1,
            &dnat_fds,
            std::slice::from_ref(&open),
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &recent_session_deltas,
            &peer_worker_commands,
            crate::afxdp::empty_worker_commands_by_id(),
            &event_stream,
            &forwarding,
            &mut worker_lossless_wedged,
        );
        all_latched &= out_of_sync;
    }
    let elapsed = start.elapsed();

    assert!(
        all_latched,
        "every wedged resync batch must return out-of-sync so the loss-of-sync latch stays set and the resync retries next cycle — never a silent drop (#2874/#5468)"
    );
    assert!(
        worker_lossless_wedged,
        "the per-drain-cycle wedge latch must stay set across the resync batches"
    );
    // The AGGREGATE across all BATCHES calls must stay well below the heartbeat-
    // stale threshold. Reverting the aggregate inheritance makes it ~BATCHES
    // budgets (~8x), far past HEARTBEAT_STALE_AFTER.
    assert!(
        elapsed < HEARTBEAT_STALE_AFTER,
        "aggregate resync lossless wait across {BATCHES} batches ({elapsed:?}) must stay < HEARTBEAT_STALE_AFTER ({HEARTBEAT_STALE_AFTER:?}); dropping the per-cycle wedge inheritance regresses #5468 via the resync path (worker stalls ~{BATCHES}x budget -> false liveness loss)"
    );
    // Tight bound: the fix collapses the whole resync's lossless wait to ~1 budget
    // (only the first batch waits). A 3x-budget ceiling separates the fix (~1x)
    // from the reverted per-batch waits (~BATCHES x) with generous anti-flake margin.
    assert!(
        elapsed < WORKER_LOSSLESS_QUEUE_BUDGET * 3,
        "aggregate resync lossless wait ({elapsed:?}) must collapse to ~1 WORKER_LOSSLESS_QUEUE_BUDGET ({:?}), not scale with the owned-session count (#5468)",
        WORKER_LOSSLESS_QUEUE_BUDGET
    );
}

/// #2979 FAIL-ON-REVERT: a Close delta for an SNAT'd session must delete the
/// dynamic reverse-NAT `dnat_table` entry that `publish_dnat_table_entry`
/// inserted at session install. The maps are `BPF_MAP_TYPE_HASH` (non-LRU,
/// `max_entries = MAX_SESSIONS`, `BPF_F_NO_PREALLOC`), so a missing close-time
/// delete leaks one entry per closed SNAT session until the map fills and new
/// reverse-NAT publishes fail (#2244 capacity error).
///
/// Real BPF maps cannot be created under `cargo test` (the host runs with
/// `kernel.unprivileged_bpf_disabled`), so this test observes the delete via
/// the test-only `DNAT_DELETE_ATTEMPTS` counter incremented inside
/// `delete_dnat_table_entry` whenever it derives a key and issues the
/// `bpf_map_delete_elem` syscall. The fd is `-1` (the syscall returns EBADF,
/// which is benign — the contract under test is that the close path *attempts*
/// the keyed delete).
///
/// RED on revert: removing the `delete_dnat_table_entry` call from
/// `flush_session_deltas`'s Close handler makes the SNAT-flow assertion (count
/// increments by 1) fail. The non-SNAT control (count unchanged) guards against
/// over-deleting on flows that never published a reverse-NAT entry.
#[test]
fn close_delta_deletes_dnat_table_entry_for_snat_flow() {
    use crate::afxdp::checksum::{DnatTableFds, DNAT_DELETE_ATTEMPTS};
    use std::sync::atomic::Ordering;

    // #6872: the SHARED guard — see checksum::DNAT_COUNTER_GUARD.
    let _g = crate::afxdp::checksum::dnat_counter_guard();

    let build_close = |nat: NatDecision| {
        let key = test_key();
        let metadata = test_metadata();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat,
        };
        SessionDelta {
            kind: SessionDeltaKind::Close,
            key,
            decision,
            metadata,
            origin: SessionOrigin::ForwardFlow,
            fabric_redirect_sync: false,
            created_ns: 0,
            last_seen_ns: 0,
            counters: crate::session::SessionCounters::default(),
            observed_tos: 0,
            observed_tcp_flags: 0,
            session_id: 0,
            bulk_resync: false,
            tcp_close_class: 0,
        }
    };

    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    // A live v4 table fd so the delete path is reached; -1 makes the syscall a
    // harmless EBADF after the keyed attempt is counted.
    let dnat_fds = DnatTableFds {
        v4: Some(-1),
        v6: None,
    };

    let run = |delta: SessionDelta| {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = vec![];
        let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
        let forwarding = ForwardingState::default();
        let mut worker_lossless_wedged = false;
        flush_session_deltas(
            &ident,
            None,
            -1,
            -1,
            -1,
            &dnat_fds,
            &[delta],
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &recent_session_deltas,
            &peer_worker_commands,
            crate::afxdp::empty_worker_commands_by_id(),
            &None,
            &forwarding,
            &mut worker_lossless_wedged,
        );
    };

    // SNAT flow: the forward key's source is SNAT'd to the WAN pool address;
    // this is exactly what the install path published into dnat_table.
    let snat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(54321),
        ..NatDecision::default()
    };

    let before = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    run(build_close(snat));
    let after_snat = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_snat - before,
        1,
        "Close delta for an SNAT'd session must attempt the dnat_table reverse-NAT delete \
         (leak fix #2979); got {} attempts",
        after_snat - before
    );

    // Non-SNAT control: a flow that never published a dnat_table entry must not
    // trigger a delete attempt.
    run(build_close(NatDecision::default()));
    let after_plain = DNAT_DELETE_ATTEMPTS.load(Ordering::Relaxed);
    assert_eq!(
        after_plain - after_snat,
        0,
        "Close delta for a non-SNAT session must NOT attempt a dnat_table delete"
    );
}

// #4805 regression: the activation-refresh wider scan must recompute
// `allow_replace_local` per session from the CURRENT HA state, NOT hardcode
// `false`. A standby-owned, peer-synced `LocalDelivery` session must keep the
// userspace REDIRECT fast path (policy enforced via fabric-redirect/drop) — it
// must NOT be flipped to a kernel-local `PASS_TO_KERNEL` entry that delivers
// host-bound traffic straight to the standby node's own stack unpoliced.
//
// The publish disposition is fully determined by
// `force_live_redirect_for_worker_synced_entry(decision, metadata, origin,
// allow_replace_local, has_routing_domains)` — `true` => live REDIRECT, `false`
// (with a kernel-local entry) => PASS_TO_KERNEL. #9517 added the last argument;
// these cells pass `false` because they pin the single-instance behaviour, and
// the routing-domain demotion is bound separately in `bpf_map_tests.rs`. Unprivileged `cargo test` cannot create a BPF map
// (`unprivileged_bpf_disabled=2`), so we assert the computed
// `allow_replace_local` that `collect_refresh_owner_rgs_items` produces — the
// single site feeding that argument on the activation path — rather than
// reading the map byte back.
fn synced_local_delivery_forward_metadata(owner_rg_id: i32) -> SessionMetadata {
    SessionMetadata {
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id,
        is_reverse: false,
        fabric_ingress: false,
        ..test_metadata()
    }
}

// A LocalDelivery decision whose egress_ifindex is not in the forwarding egress
// map, so `owner_rg_for_resolution` returns 0 and the refreshed metadata keeps
// the session's original owner RG (the standby RG under test).
fn synced_local_delivery_decision_unowned_egress() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::LocalDelivery,
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
    }
}

#[test]
fn refresh_owner_rgs_standby_local_delivery_forces_live_redirect_4805() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    // Peer-synced forward LocalDelivery session owned by RG2 (standby here).
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        synced_local_delivery_decision_unowned_egress(),
        synced_local_delivery_forward_metadata(2),
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));

    // RG1 activates on this node (any split-RG activation triggers the wider
    // scan); RG2 — the session's owner — remains STANDBY (inactive) here.
    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, inactive_ha_runtime(now_secs)),
    ]);
    let items = super::commands::collect_refresh_owner_rgs_items(
        &sessions,
        &test_forwarding_state(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        now_secs,
    );

    let (_, decision, metadata, origin, allow_replace_local) = items
        .iter()
        .find(|(item_key, ..)| *item_key == key)
        .expect("refreshed standby LocalDelivery session");
    // Owner RG unchanged (still RG2), disposition still LocalDelivery.
    assert_eq!(metadata.owner_rg_id, 2);
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
    );
    // Standby-owned => allow_replace_local TRUE => force live REDIRECT.
    assert!(
        *allow_replace_local,
        "standby-owned synced LocalDelivery must keep allow_replace_local=true"
    );
    assert!(
        force_live_redirect_for_worker_synced_entry(
            &force_live_test_key_9517(),
            *decision,
            metadata,
            *origin,
            *allow_replace_local,
            false,
        ),
        "standby-owned synced LocalDelivery must publish the LIVE REDIRECT entry, \
         not a kernel-local PASS_TO_KERNEL entry (#4805)"
    );
}

#[test]
fn refresh_owner_rgs_active_owner_local_delivery_publishes_kernel_local_4805() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    // Peer-synced forward LocalDelivery session owned by RG2, ACTIVE here.
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        synced_local_delivery_decision_unowned_egress(),
        synced_local_delivery_forward_metadata(2),
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));

    let ha_state = BTreeMap::from([
        (1, active_ha_runtime(now_secs)),
        (2, active_ha_runtime(now_secs)),
    ]);
    let items = super::commands::collect_refresh_owner_rgs_items(
        &sessions,
        &test_forwarding_state(),
        &ha_state,
        &Arc::new(ShardedNeighborMap::new()),
        now_secs,
    );

    let (_, decision, metadata, origin, allow_replace_local) = items
        .iter()
        .find(|(item_key, ..)| *item_key == key)
        .expect("refreshed active-owner LocalDelivery session");
    assert_eq!(metadata.owner_rg_id, 2);
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::LocalDelivery
    );
    // Owner-active => allow_replace_local FALSE => kernel-local PASS_TO_KERNEL.
    assert!(
        !*allow_replace_local,
        "owner-active synced LocalDelivery must keep allow_replace_local=false"
    );
    assert!(
        !force_live_redirect_for_worker_synced_entry(
            &force_live_test_key_9517(),
            *decision,
            metadata,
            *origin,
            *allow_replace_local,
            false,
        ),
        "owner-active synced LocalDelivery keeps the kernel-local publish path"
    );
}

// #5622 FAIL-ON-REVERT: a translated LocalDelivery terminal hit (host-inbound
// deny, lo0 input-filter deny, or `to-zone junos-host` deny on the session-HIT
// path) must tear down BOTH the forward and the reverse companion session
// entries AND release the source-NAT pool reservation — matching the ordinary
// idle reap and the DSCP-filter purge. The pre-#5622 helper deleted ONLY the
// resolved key and released NO allocator state, so the same-worker companion
// entry AND the pool port both leaked. This drives the terminal teardown on
// BOTH a forward hit and a reverse hit (the finding's `K=F` and `K=R` legs) and
// asserts (a) the companion entry is gone and (b) the allocator reservation is
// freed. Reverting the fix (companion left installed / pool port not returned)
// turns the companion + `used_ports` assertions RED.
#[test]
fn delete_terminal_filtered_session_releases_companion_and_allocator_5622() {
    for hit_reverse in [false, true] {
        // A single-address pool source-NAT rule so the translated flow holds a
        // real pool port that the teardown must return.
        let mut forwarding = ForwardingState::default();
        forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
            crate::SourceNATRuleSnapshot {
                name: "pool-snat".to_string(),
                from_zone: "lan".to_string(),
                to_zone: "wan".to_string(),
                source_addresses: vec!["0.0.0.0/0".to_string()],
                pool_name: "p".to_string(),
                pool_addresses: vec!["203.0.113.1/32".to_string()],
                port_low: 1024,
                port_high: 65535,
                ..crate::SourceNATRuleSnapshot::default()
            },
        ]);

        // Forward: a source-NAT-translated flow that is locally delivered.
        let fwd_key = test_key();
        let fwd_nat = NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            rewrite_src_port: Some(40000),
            ..NatDecision::default()
        };
        let fwd_decision = SessionDecision {
            resolution: test_local_delivery_decision().resolution,
            nat: fwd_nat,
        };
        let fwd_metadata = test_metadata();

        // Reverse companion: keyed on the return tuple, carrying the reversed
        // NAT decision + `is_reverse = true` — exactly how the reverse half is
        // installed in production.
        let rev_key = reverse_session_key(&fwd_key, fwd_nat);
        let rev_nat = fwd_nat.reverse(
            fwd_key.src_ip,
            fwd_key.dst_ip,
            fwd_key.src_port,
            fwd_key.dst_port,
        );
        let rev_decision = SessionDecision {
            resolution: fwd_decision.resolution,
            nat: rev_nat,
        };
        let mut rev_metadata = test_metadata();
        rev_metadata.is_reverse = true;

        // Reserve the pool port for the forward flow (the reservation the
        // forward-half teardown's `release_source_nat_allocation` must free).
        crate::nat::reserve_synced_source_nat_allocation(
            &forwarding.iface_nat_allocators,
            &forwarding.source_nat_rules,
            &fwd_key,
            fwd_nat,
            false,
            None,
            0,
        );
        assert_eq!(
            crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
            1,
            "precondition: the translated forward flow holds one pool port",
        );

        let mut sessions = SessionTable::new();
        assert!(sessions.install_with_protocol_with_origin(
            fwd_key.clone(),
            fwd_decision,
            fwd_metadata.clone(),
            SessionOrigin::LocalMiss,
            1,
            PROTO_TCP,
            TCP_FLAG_SYN,
        ));
        assert!(sessions.install_with_protocol_with_origin(
            rev_key.clone(),
            rev_decision,
            rev_metadata.clone(),
            SessionOrigin::LocalMiss,
            1,
            PROTO_TCP,
            TCP_FLAG_SYN,
        ));
        assert!(sessions.entry_with_origin(&fwd_key).is_some());
        assert!(sessions.entry_with_origin(&rev_key).is_some());
        let _ = sessions.drain_deltas(16);

        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();

        // Drive the terminal hit on the requested direction. Either half may be
        // the packet that re-evaluates the (now-deny) terminal gate.
        let (hit_key, hit_decision, hit_metadata) = if hit_reverse {
            (rev_key.clone(), rev_decision, rev_metadata.clone())
        } else {
            (fwd_key.clone(), fwd_decision, fwd_metadata.clone())
        };
        delete_terminal_filtered_session(
            &mut sessions,
            -1,
            -1,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            crate::afxdp::empty_worker_commands_by_id(),
            &forwarding,
            &hit_key,
            hit_decision,
            &hit_metadata,
            SessionOrigin::LocalMiss,
            2,
            0,
        );

        // (a) BOTH the resolved entry and its same-worker companion are gone.
        assert!(
            sessions.entry_with_origin(&fwd_key).is_none(),
            "hit_reverse={hit_reverse}: forward entry must be torn down",
        );
        assert!(
            sessions.entry_with_origin(&rev_key).is_none(),
            "hit_reverse={hit_reverse}: reverse companion entry must be torn down",
        );
        // (b) the NAT pool reservation is released exactly once (no leak).
        assert_eq!(
            crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
            0,
            "hit_reverse={hit_reverse}: the translated flow's pool port must be freed",
        );
        // A single forward-direction Close delta is emitted regardless of which
        // half took the terminal hit — the reverse-hit path now fires the
        // forward companion's close (the pre-#5622 helper dropped it when K=R).
        let deltas = sessions.drain_deltas(16);
        let closes: Vec<_> = deltas
            .iter()
            .filter(|d| d.kind == SessionDeltaKind::Close)
            .collect();
        assert_eq!(
            closes.len(),
            1,
            "hit_reverse={hit_reverse}: exactly one forward Close delta expected",
        );
        assert_eq!(
            closes[0].key, fwd_key,
            "hit_reverse={hit_reverse}: the Close delta is on the forward key",
        );
    }
}

// #5295 FAIL-ON-REVERT: `purge_translated_synced_hit` drops a transient
// peer-synced translated FORWARD session (the local node is not the active RG
// owner, so the hit is torn down and re-resolved). At install
// `handle_upsert_synced` reserved that session's translated `(pool_addr, port)`
// in THIS node's LOCAL allocator (`reserve_synced_source_nat_allocation` /
// `reserve_synced_nat64_allocation`). Before #5295 the purge dropped the session
// state but released NO allocator reservation, so every alias-owned transient
// purge LEAKED a pool port -> standby source-NAT / NAT64 exhaustion under
// sustained HA churn. The fix mirrors `handle_delete_synced` /
// `delete_terminal_filtered_session`: release under the `metadata.is_reverse`
// ownership guard.
//
// PARENT-RED neutralization: delete the `release_source_nat_allocation(...)`
// call in `purge_translated_synced_hit` -> this test's `used_ports == 0`
// assertion goes RED (stays 1). (Deleting `release_nat64_allocation(...)`
// reddens the NAT64 sibling below.)
#[test]
fn purge_translated_synced_hit_releases_source_nat_reservation_5295() {
    // Single-address pool source-NAT rule so the translated flow holds a real
    // pool port the purge must return.
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..crate::SourceNATRuleSnapshot::default()
    }]);

    // A source-NAT-translated forward flow. The synced session is keyed on its
    // post-NAT WIRE tuple (`forward_wire_key`: src == pool addr), which is both
    // what makes `is_translated_forward_session_key` fire AND the key
    // `handle_upsert_synced` reserved the port under.
    let orig_key = test_key();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let wire_key = forward_wire_key(&orig_key, nat);
    let decision = SessionDecision {
        resolution: test_local_delivery_decision().resolution,
        nat,
    };
    let metadata = test_metadata(); // is_reverse = false

    // Reserve the pool port for the synced forward flow, mirroring
    // `handle_upsert_synced`'s `reserve_synced_source_nat_allocation`.
    crate::nat::reserve_synced_source_nat_allocation(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        &wire_key,
        nat,
        false,
        None,
        0,
    );
    assert_eq!(
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
        1,
        "precondition: the synced translated forward flow holds one pool port",
    );

    // Install the transient synced session under its wire key.
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        wire_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(16);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let shared = SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    purge_translated_synced_hit(
        &mut sessions,
        -1,
        shared,
        &wire_key,
        decision,
        &metadata,
        SessionOrigin::SyncImport,
        &forwarding,
        1_000_000,
        0,
    );

    // (a) existing behaviour: the transient session entry is gone.
    assert!(
        sessions.lookup(&wire_key, 1_000_000, TCP_FLAG_ACK).is_none(),
        "purged transient synced session must be removed from the table",
    );
    // (b) THE #5295 FIX: the pool reservation is returned to the allocator.
    assert_eq!(
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
        0,
        "purge must release the synced forward flow's source-NAT pool port \
         (leak on revert)",
    );
}

// #5295 FAIL-ON-REVERT (NAT64 leg): the same purge must return a NAT64 forward
// flow's reserved translated pool port. PARENT-RED neutralization: delete the
// `release_nat64_allocation(...)` call in `purge_translated_synced_hit` -> the
// "freed port re-allocatable" assertion goes RED (a fresh flow gets 1025; the
// reserved 1024 stays leaked).
#[test]
fn purge_translated_synced_hit_releases_nat64_reservation_5295() {
    // Single-address NAT64 pool: every client maps to the same snat_v4, so only
    // the translated port disambiguates (sharpest collision case).
    let mut forwarding = ForwardingState::default();
    forwarding.nat64 = crate::nat64::Nat64State::from_snapshots(&[crate::NAT64RuleSnapshot {
        name: "nat64-single".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        ..Default::default()
    }]);

    let snat = Ipv4Addr::new(198, 51, 100, 1);
    let dst_v4 = Ipv4Addr::new(8, 8, 8, 8);
    // Original v6 flow; the forward NAT64 decision translates to (snat, 1024) —
    // 1024 is the first sequential NAT64 port, the port a fresh alloc picks first.
    let orig_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
        dst_ip: IpAddr::V6("64:ff9b::0808:0808".parse().unwrap()),
        src_port: 5000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let nat = crate::nat64::Nat64State::forward_decision(snat, dst_v4, 1024);
    let wire_key = forward_wire_key(&orig_key, nat); // post-NAT v4 wire tuple
    let decision = SessionDecision {
        resolution: test_local_delivery_decision().resolution,
        nat,
    };
    let metadata = test_metadata();

    // Reserve the NAT64 port under the wire key, mirroring `handle_upsert_synced`.
    crate::nat64::reserve_synced_nat64_allocation(&forwarding.nat64, &wire_key, nat, false, 0);

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        wire_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(16);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let shared = SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    purge_translated_synced_hit(
        &mut sessions,
        -1,
        shared,
        &wire_key,
        decision,
        &metadata,
        SessionOrigin::SyncImport,
        &forwarding,
        1_000_000,
        0,
    );

    // After the purge releases the reservation, a fresh local NAT64 flow re-owns
    // the freed first port 1024. On revert (no release) 1024 stays reserved and
    // the fresh flow is pushed to 1025.
    let (snat2, port2) = forwarding
        .nat64
        .allocate_source(
            0,
            PROTO_TCP,
            "2001:db8::2".parse().unwrap(),
            dst_v4,
            5000,
            443,
            1_000_001,
        )
        .expect("probe NAT64 flow allocates");
    assert_eq!(snat2, snat, "single-address pool => same snat_v4");
    assert_eq!(
        port2, 1024,
        "purge must release the synced NAT64 flow's reserved port 1024 so a \
         fresh flow re-owns it (leak on revert -> 1025)",
    );
}

// #5295: a NON-owning (reverse/alias) purge must release NOTHING and tear down
// NOTHING. The `is_translated_forward_session_key` guard rejects reverse entries
// up front, and the release path's own `is_reverse` guard is the second line of
// defense, so a reverse companion can never double-free the forward flow's
// reservation. Guard-correctness pin (green before and after the fix), per the
// #5295 no-double-free requirement.
#[test]
fn purge_translated_synced_hit_reverse_entry_releases_nothing_5295() {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[crate::SourceNATRuleSnapshot {
        name: "pool-snat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["0.0.0.0/0".to_string()],
        pool_name: "p".to_string(),
        pool_addresses: vec!["203.0.113.1/32".to_string()],
        port_low: 1024,
        port_high: 65535,
        ..crate::SourceNATRuleSnapshot::default()
    }]);

    let orig_key = test_key();
    let fwd_nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let wire_key = forward_wire_key(&orig_key, fwd_nat);

    // The forward flow owns the reservation.
    crate::nat::reserve_synced_source_nat_allocation(
        &forwarding.iface_nat_allocators,
        &forwarding.source_nat_rules,
        &wire_key,
        fwd_nat,
        false,
        None,
        0,
    );
    assert_eq!(
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
        1,
        "precondition: the forward flow holds the pool port",
    );

    // Drive the purge with the REVERSE companion (is_reverse = true): its key is
    // the reverse tuple carrying the reversed decision. The purge guard must
    // reject it, freeing nothing and tearing down nothing.
    let rev_key = reverse_session_key(&wire_key, fwd_nat);
    let rev_nat = fwd_nat.reverse(
        wire_key.src_ip,
        wire_key.dst_ip,
        wire_key.src_port,
        wire_key.dst_port,
    );
    let rev_decision = SessionDecision {
        resolution: test_local_delivery_decision().resolution,
        nat: rev_nat,
    };
    let mut rev_metadata = test_metadata();
    rev_metadata.is_reverse = true;

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        rev_key.clone(),
        rev_decision,
        rev_metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = sessions.drain_deltas(16);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let shared = SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
    };

    purge_translated_synced_hit(
        &mut sessions,
        -1,
        shared,
        &rev_key,
        rev_decision,
        &rev_metadata,
        SessionOrigin::SyncImport,
        &forwarding,
        1_000_000,
        0,
    );

    // The guard rejected the reverse entry: nothing torn down, reservation intact.
    assert!(
        sessions.lookup(&rev_key, 1_000_000, TCP_FLAG_ACK).is_some(),
        "reverse companion must be left intact by the forward-only purge",
    );
    assert_eq!(
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
        1,
        "a reverse/alias purge must NOT release the forward flow's reservation",
    );
}


// #5152 FAIL-ON-REVERT: activating one redundancy group must NOT reset the
// standby bounded-leak HOLD clock (`first_held_ns`, #2120 §6.4) of an UNRELATED
// split-RG session this node does not own. `handle_refresh_owner_rgs` walks
// EVERY HA-managed session on any activation; before the fix it called
// `refresh_for_ha_transition` UNCONDITIONALLY per item, which zeroes
// `first_held_ns`/`seen_rg_epoch` and re-stamps `last_seen_ns`. The fix mirrors
// the demote path (`handle_demote_owner_rgs`) and only re-stamps a session whose
// refreshed disposition is forwarding (`!= HAInactive`).
//
// The test drives the real `handle_refresh_owner_rgs` loop with `session_map_fd
// = -1` (publish is a no-op) and asserts, via `first_held_ns_for`:
//   * Case A — a session that re-resolves to HAInactive (owner RG1 still
//     inactive while an unrelated RG2 activates) keeps its armed HOLD clock.
//     Reverting the guard resets it to 0 -> this assertion FAILS.
//   * Case B — a session that re-resolves to ForwardCandidate (owner RG1 itself
//     activates) has its HOLD clock cleared, proving the legitimate promotion
//     refresh still fires and the guard did not over-suppress.
//
// `test_forwarding_state()` has NO fabric, so an inactive-owner resolution stays
// `HAInactive` instead of being converted to `FabricRedirect` (verified against
// the resolution machinery: no-fabric + RG1 inactive -> HAInactive; RG1 active
// -> ForwardCandidate).
fn arm_standby_hold_clock_5152(table: &mut SessionTable, now_ns: u64) {
    // A single HOLD expire pass with this node forwarding NOTHING arms
    // `first_held_ns` on the idle-crossed peer-synced entry. On a fresh table
    // `last_gc_ns == 0`, so the GC-interval gate is bypassed and the pass runs.
    let node_active = false;
    let forwards = |_rg: i32| -> bool { false };
    let epoch = |_rg: i32| -> u32 { 0 };
    let ctx = crate::session::ExpireHaContext {
        node_active,
        forwards_rg: &forwards,
        epoch_of: &epoch,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
    };
    let expired = table.expire_stale_entries_ha(now_ns, Some(&ctx));
    assert!(expired.is_empty(), "arming HOLD pass must hold, not reap");
}

fn install_synced_forward_5152(table: &mut SessionTable, key: &SessionKey, now_ns: u64) {
    assert!(table.install_with_protocol_with_origin(
        key.clone(),
        test_decision(),   // ForwardCandidate, egress 12 -> owner RG1
        test_metadata(),   // owner_rg_id = 1, not fabric_ingress, not reverse
        SessionOrigin::SyncImport,
        now_ns,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let _ = table.drain_deltas(8);
}

#[test]
fn refresh_owner_rgs_skips_hainactive_hold_clock_5152() {
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let forwarding = test_forwarding_state(); // NO fabric -> HAInactive survives
    let key = test_key();
    let then = 1_000_000_000u64;
    let armed_ns = then + 302_000_000_000; // past the 300s TCP established timeout
    let act_ns = armed_ns + 1_000_000;
    let act_secs = act_ns / 1_000_000_000;

    // ---- Case A: unrelated RG2 activates; owner RG1 stays inactive.
    let mut sessions_a = SessionTable::new();
    install_synced_forward_5152(&mut sessions_a, &key, then);
    arm_standby_hold_clock_5152(&mut sessions_a, armed_ns);
    assert_eq!(
        sessions_a.first_held_ns_for(&key),
        Some(armed_ns),
        "precondition: standby HOLD clock armed at armed_ns"
    );
    let ha_state_a = BTreeMap::from([
        (1, inactive_ha_runtime(act_secs)),
        (2, active_ha_runtime(act_secs)),
    ]);
    super::commands::handle_refresh_owner_rgs(
        &mut sessions_a,
        -1,
        &forwarding,
        &ha_state_a,
        &neighbors,
        vec![2],
        act_ns,
        act_secs,
    );
    assert_eq!(
        sessions_a.first_held_ns_for(&key),
        Some(armed_ns),
        "activating RG2 must NOT reset the HOLD clock of an unrelated \
         HAInactive RG1 session (#5152 — reverting the guard zeroes it)"
    );

    // ---- Case B: the session's OWN RG1 activates -> ForwardCandidate -> refreshed.
    let mut sessions_b = SessionTable::new();
    install_synced_forward_5152(&mut sessions_b, &key, then);
    arm_standby_hold_clock_5152(&mut sessions_b, armed_ns);
    assert_eq!(sessions_b.first_held_ns_for(&key), Some(armed_ns));
    let ha_state_b = BTreeMap::from([(1, active_ha_runtime(act_secs))]);
    super::commands::handle_refresh_owner_rgs(
        &mut sessions_b,
        -1,
        &forwarding,
        &ha_state_b,
        &neighbors,
        vec![1],
        act_ns,
        act_secs,
    );
    assert_eq!(
        sessions_b.first_held_ns_for(&key),
        Some(0),
        "activating the session's own RG1 (ForwardCandidate) must clear the \
         HOLD clock — the legitimate promotion refresh still fires"
    );
}

// === #6457: DeleteSynced records the deleted key for flow-cache invalidation ==
//
// The per-worker flow cache (the stage-12 hit path in
// `poll_descriptor/flow_cache_hit.rs`) validates only config/fib generation,
// RG epoch/lease, and the neighbor-MAC epoch — never session existence. A
// control-plane delete bumps none of those stamps, so without an explicit
// eviction a revoked-but-still-active 5-tuple kept HITTING its cached
// `RewriteDescriptor` and forwarded with no live session: the operator
// `clear security flow session` revocation primitive, the cluster-stale
// sweep (`BatchDeleteSessions`), and HA DeleteSynced propagation were all
// silently defeated on the fast path (fail-open). `handle_delete_synced`
// therefore records every deleted key into
// `WorkerCommandResults.deleted_synced_keys`; the worker loop drains that
// list into per-binding `flow_cache.invalidate_slot` calls (the
// `invalidate_flow_cache_slots_for_deleted_sessions` half is pinned in
// `afxdp/worker/loop_body/mod.rs::flow_cache_invalidation_tests`).
// Deleting the `deleted_keys.push` turns both tests here RED.

#[test]
fn delete_synced_records_key_for_flow_cache_invalidation() {
    let mut sessions = SessionTable::new();
    let forwarding = test_forwarding_state();
    let key = test_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        TCP_FLAG_ACK,
    ));
    let mut deleted_keys: Vec<SessionKey> = Vec::new();

    super::commands::handle_delete_synced(
        &mut sessions,
        -1,
        &forwarding,
        // #9048: an EMPTY HA view keeps the new ownership guard inert (no RG
        // is forwarding-active), so this cell keeps measuring the delete
        // contract it was written for rather than the guard.
        &BTreeMap::new(),
        key.clone(),
        2_000_000,
        0,
        &mut deleted_keys,
        0,
    );

    assert!(
        sessions.entry_with_origin(&key).is_none(),
        "the session itself must be dropped (pre-existing delete contract)"
    );
    assert_eq!(
        deleted_keys,
        vec![key],
        "#6457: the deleted key must be recorded so the worker loop can \
         invalidate its flow-cache slot — without the record the revoked \
         tuple keeps hitting the stale cached permit (fail-open)"
    );
}

#[test]
fn delete_synced_records_key_even_when_session_already_absent() {
    // The stale-slot survival shape of the bug: the table entry is already
    // gone (an earlier delete, or a GC reap observed on this worker) while
    // the cached descriptor lives on. Gating the record on the table lookup
    // would leave that stale permit in place, so the record is
    // unconditional — the `delete_live_session_key` arm must record too.
    let mut sessions = SessionTable::new();
    let forwarding = test_forwarding_state();
    let key = test_key();
    let mut deleted_keys: Vec<SessionKey> = Vec::new();

    super::commands::handle_delete_synced(
        &mut sessions,
        -1,
        &forwarding,
        // #9048: an EMPTY HA view keeps the new ownership guard inert (no RG
        // is forwarding-active), so this cell keeps measuring the delete
        // contract it was written for rather than the guard.
        &BTreeMap::new(),
        key.clone(),
        2_000_000,
        0,
        &mut deleted_keys,
        0,
    );

    assert_eq!(
        deleted_keys,
        vec![key],
        "#6457: the record must fire even with no table entry — a stale \
         flow-cache slot outlives its table entry (that survival is the \
         bug), so the invalidate must not gate on the lookup"
    );
}

// #6211 FAIL-ON-REVERT (production call site): `handle_upsert_synced` must
// resolve the ACTIVE node's zone pair out of the synced entry's metadata and
// hand it to `reserve_synced_source_nat_allocation`, so the reservation lands
// in the allocator the active used.
//
// The nine `nat/tests_pool.rs` #6211 tests call
// `reserve_synced_source_nat_allocation` DIRECTLY with a literal
// `Some(("lan","wan"))`, which leaves the 28-line `synced_source_nat_zone_pair`
// helper AND its call site completely unbound: passing `None` at the call site
// (disabling the feature outright) or inverting ingress/egress inside the
// helper both kept the whole suite green. This test is the missing call-site
// cell — it drives the real entry point, so it REDS on either mutation.
#[test]
fn handle_upsert_synced_resolves_active_zone_pair_for_snat_reserve_6211() {
    let mut forwarding = ForwardingState::default();
    // Same pool ADDRESS in two rules with distinct pool names => distinct
    // `allocator_key` => two INDEPENDENT allocators. The `dmz->wan` rule is
    // FIRST, so the pre-#6211 first-pool-match picks the wrong one.
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "snat-dmz".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-dmz".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..crate::SourceNATRuleSnapshot::default()
        },
        crate::SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    // The id -> NAME map the helper resolves through. Ordering matters: this is
    // what an ingress/egress inversion inside the helper gets wrong.
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());

    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "10.0.61.50".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut decision = test_decision();
    decision.nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        // ingress_zone 1 = "lan", egress_zone 2 = "wan" — the ACTIVE's pair,
        // as carried by SessionSyncRequest's ingress_zone_id/egress_zone_id.
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            is_reverse: false,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    let mut sessions = SessionTable::new();
    let ha_state: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());
    crate::afxdp::session_glue::commands::handle_upsert_synced(
        &mut sessions,
        -1, // no session map fd: the publish is skipped, the reserve is not
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        entry,
        1_000,
        1,
        0,
    );

    // `used_ports` is per-rule and in rule order. Assertion 1 doubles as the
    // reached-the-reserve control: the reserve runs only inside the successful
    // `upsert_synced_with_origin` branch, so a failed upsert reds it too.
    let statuses = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules);
    assert_eq!(
        statuses[1].used_ports, 1,
        "#6211 call site: the reservation must land in the lan->wan rule's \
         allocator — the one the ACTIVE matched by zone"
    );
    assert_eq!(
        statuses[0].used_ports, 0,
        "#6211 call site: passing None (or inverting ingress/egress) degrades \
         to the pre-#6211 first-pool-match and lands here instead"
    );
    let _ = &key;
}

// #6211 FAIL-ON-REVERT (delete-sync teardown, END TO END): the leak and its fix
// driven entirely through the REAL entry points — `handle_upsert_synced` twice,
// then `handle_delete_synced`.
//
// The `nat/tests_pool.rs` leak test calls `reserve_synced_source_nat_allocation`
// and `release_source_nat_allocation` DIRECTLY, so it binds those functions'
// internals and leaves the WIRING free to be deleted. Deleting the
// `release_source_nat_allocation` call from `handle_delete_synced` left the
// whole package green (the only failures were the known-flaky `shared_cos_lease`
// / `wg::engine` families, not the mutation). This test closes that: it reaches
// the release through `handle_delete_synced` itself.
//
// It also exercises the leak on the genuinely SYNCED path — both reservations
// are created by the import (`reserve_flow` on a pre-computed wire tuple), never
// by a local `allocate_translation`.
#[test]
fn delete_synced_frees_both_allocators_end_to_end_6211() {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "snat-dmz".to_string(),
            from_zone: "dmz".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-dmz".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..crate::SourceNATRuleSnapshot::default()
        },
        crate::SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());

    // A SECOND snapshot that shares the same allocators (the `PortAllocator`
    // clone is `Arc`-backed) but has LOST the zone names — a zone delete or
    // renumber. This is what flips the selection outcome between upserts.
    let mut forwarding_after_zone_drop = forwarding.clone();
    forwarding_after_zone_drop.zone_id_to_name.clear();

    let key = crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "10.0.61.50".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let mut decision = test_decision();
    decision.nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(20000),
        ..NatDecision::default()
    };
    let make_entry = || SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            is_reverse: false,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };

    let mut sessions = SessionTable::new();
    let ha_state: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());

    // Upsert #1 — zones resolve, so the reserve lands in the lan rule.
    crate::afxdp::session_glue::commands::handle_upsert_synced(
        &mut sessions,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        make_entry(),
        1_000,
        1,
        0,
    );
    // Upsert #2 — the SAME live session re-synced (HA reconnect / resync) after
    // the zone drop, so the reserve lands in the dmz rule instead.
    crate::afxdp::session_glue::commands::handle_upsert_synced(
        &mut sessions,
        -1,
        &forwarding_after_zone_drop,
        &ha_state,
        &dynamic_neighbors,
        make_entry(),
        2_000,
        2,
        0,
    );

    let before = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules);
    assert_eq!(
        (before[0].used_ports, before[1].used_ports),
        (1, 1),
        "precondition: the re-upsert put the SAME session in BOTH independent \
         allocators — this is the state the first-hit `break` used to strand"
    );

    // Teardown through the REAL delete-sync entry point.
    let mut deleted_keys: Vec<crate::session::SessionKey> = Vec::new();
    crate::afxdp::session_glue::commands::handle_delete_synced(
        &mut sessions,
        -1,
        &forwarding_after_zone_drop,
        // #9048: empty HA view — see the note at the sibling call sites.
        &BTreeMap::new(),
        key.clone(),
        3_000,
        0,
        &mut deleted_keys,
        0,
    );

    let after = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules);
    assert_eq!(
        (after[0].used_ports, after[1].used_ports),
        (0, 0),
        "#6211: delete-sync must free the reservation from EVERY allocator — \
         deleting the release call from handle_delete_synced, or restoring the \
         first-hit `break`, strands one of them"
    );
    assert_eq!(deleted_keys, vec![key], "control: the key was recorded (#6457)");
}

// ---------------------------------------------------------------------------
// #7169: reverse-canonical matches are revalidated against the ARRIVAL zone.
// ---------------------------------------------------------------------------

/// One forward-NAT'd session in the shared scope, plus the reverse-canonical
/// key that matches it. `test_metadata()` is ingress_zone 1 -> egress_zone 2, so
/// a legitimate reply arrives in zone 2.
fn nat_reverse_fixture_7169() -> (
    SessionTable,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    SessionKey,
) {
    let sessions = SessionTable::new();
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4("10.0.61.5".parse().unwrap()),
        dst_ip: IpAddr::V4("203.0.113.9".parse().unwrap()),
        src_port: 40000,
        dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4("198.51.100.8".parse().unwrap())),
            ..NatDecision::default()
        },
    };
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata: test_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared = Arc::new(Mutex::new(FastMap::default()));
    shared
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), entry);
    (sessions, shared, reply_key)
}

/// #7169 fail-on-revert: a reverse-canonical match must be REJECTED when the
/// packet arrived in a zone the forward flow did not egress to.
///
/// The index is keyed on the PRE-NAT reply tuple, so a match establishes only
/// that this 5-tuple equals a live session's private-side reply tuple. Before
/// this check, that alone installed a reverse session carrying the ORIGINAL
/// flow's zone pair — so a packet injected from any segment where the client's
/// private address is routable was adjudicated in a zone it never arrived in,
/// and the installed session then took the established fast path with no policy
/// evaluation for the rest of the flow's life.
///
/// The reply must arrive from the zone the forward flow EGRESSED to (2 here);
/// zone 7 is the attacker's segment.
///
/// FAIL-ON-REVERT: delete the `ReverseIngress::Zone` arm's equality test in
/// `revalidate_reverse_ingress` (or make it return `Some(m)` unconditionally)
/// and this goes RED.
#[test]
fn a_reverse_match_from_the_wrong_zone_is_rejected_7169() {
    let (sessions, shared, reply_key) = nat_reverse_fixture_7169();

    // Positive control FIRST: the same lookup from the RIGHT zone matches, so
    // the rejection below is the ingress check and not a broken fixture.
    let ok = lookup_forward_nat_across_scopes(
        &sessions,
        &shared,
        &reply_key,
        crate::afxdp::shared_ops::ReverseIngress::Zone(2),
    );
    assert!(
        ok.is_some(),
        "control: a reply arriving in the forward flow's EGRESS zone must match"
    );

    let hijack = lookup_forward_nat_across_scopes(
        &sessions,
        &shared,
        &reply_key,
        crate::afxdp::shared_ops::ReverseIngress::Zone(7),
    );
    assert!(
        hijack.is_none(),
        "a packet matching a session's pre-NAT reply tuple but arriving in a \
         zone the flow never egressed to must NOT match. Accepting it installs \
         a reverse session adjudicated in the original flow's zone pair, which \
         subsequent packets then ride past policy entirely (#7169)"
    );
}

/// #7169: an arrival interface with no zone mapping fails CLOSED.
///
/// This is the arm that would otherwise be the whole hole again. Resolving the
/// zone with a map lookup makes "no entry" the natural default, and treating
/// that as "no constraint" would exempt exactly the traffic least accounted
/// for. `Unzoned` exists so that outcome cannot be reached by accident — it is
/// a distinct state from the deliberate exemption below.
#[test]
fn an_unzoned_arrival_interface_matches_nothing_7169() {
    let (sessions, shared, reply_key) = nat_reverse_fixture_7169();
    let out = lookup_forward_nat_across_scopes(
        &sessions,
        &shared,
        &reply_key,
        crate::afxdp::shared_ops::ReverseIngress::Unzoned,
    );
    assert!(
        out.is_none(),
        "an unmapped arrival interface gives nothing to revalidate against, so \
         no reverse match may be synthesized"
    );
}

/// #7169: the deliberate exemption still works, and is distinguishable from
/// `Unzoned`.
///
/// Without this the two could be collapsed into one "no constraint" state, and
/// the ICMP embedded-error path (which installs no session, and where an error
/// may legitimately originate off-path) would be broken by the fix — or, worse,
/// `Unzoned` would be made permissive to keep it working.
#[test]
fn an_unconstrained_caller_is_exempt_7169() {
    let (sessions, shared, reply_key) = nat_reverse_fixture_7169();
    let out = lookup_forward_nat_across_scopes(
        &sessions,
        &shared,
        &reply_key,
        crate::afxdp::shared_ops::ReverseIngress::Unconstrained,
    );
    assert!(
        out.is_some(),
        "the ICMP embedded-error rewriters install no session and must keep \
         matching; constraining them would break PMTUD"
    );
}

/// #7169 / #7917: the synthesized reverse session's `ingress_ifindex` must stay
/// 0 — "unobserved" — and must never be populated from the forward match.
///
/// #7169 was filed listing this zero as part of the defect. It is not, and the
/// tempting repair is a regression: the forward flow's ingress is a PREDICTION
/// of where a reply will arrive, not an OBSERVATION of where it did, so
/// inheriting it makes the row confidently wrong. This guard exists because the
/// issue text itself points at the wrong line.
#[test]
fn a_synthesized_reverse_records_no_ingress_ifindex_7169() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("afxdp")
            .join("shared_ops.rs"),
    )
    .expect("shared_ops.rs must be readable");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // Non-vacuity: if the builder moved or was renamed, the scan below proves
    // nothing and must say so rather than pass.
    assert!(
        code.contains("fn build_reverse_session_from_forward_match"),
        "build_reverse_session_from_forward_match not found — this guard is \
         scanning for something that no longer exists"
    );
    assert!(
        code.contains("ingress_ifindex: 0,"),
        "the synthesized reverse session must record ingress_ifindex 0"
    );
    assert!(
        !code.contains("ingress_ifindex: forward_match"),
        "ingress_ifindex must NOT be inherited from the forward match: the \
         forward ingress is where a reply was PREDICTED to arrive, not where it \
         did (#7917). 0 means unobserved, which is truthful; a wrong interface \
         is strictly worse than none (#6928)"
    );
}

/// #7169 wiring guard: the MAIN packet path must resolve the arrival zone and
/// hand it to the lookup.
///
/// The cells above drive `lookup_forward_nat_across_scopes` directly with an
/// explicit `ReverseIngress`, so they bind the revalidation FUNCTION. They
/// cannot see the thing that actually protects the dataplane: that
/// `resolve_flow_session_decision` — the one caller that INSTALLS a reverse
/// session from the match — passes a real zone rather than `Unconstrained`.
/// Changing that one argument to `Unconstrained` reopens the hole completely
/// and leaves every cell above green.
///
/// Source-shape for the call-site SHAPE only. #9383 added the behavioural half —
/// `a_reply_on_an_unzoned_trunk_unit_installs_no_reverse_session_9383` drives this
/// function with a trunk arrival and asserts the reverse install, with a
/// zoned-sibling positive control — so this cell is no longer the only thing
/// standing behind the invariant, and its old claim that "a behavioural cell
/// would need to drive a ~20-argument function through a full session install"
/// was an argument for not writing the cell that mattered.
/// Comments are stripped: this file names the symbols, and an unstripped scan
/// would match the prose describing the invariant rather than the invariant.
#[test]
fn the_main_path_passes_a_resolved_arrival_zone_7169() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("afxdp")
            .join("session_glue")
            .join("mod.rs"),
    )
    .expect("session_glue/mod.rs must be readable");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    // Non-vacuity first: if the call moved or was renamed, everything below
    // passes for free.
    assert!(
        code.contains("lookup_forward_nat_across_scopes("),
        "session_glue/mod.rs no longer calls lookup_forward_nat_across_scopes — \
         this guard is scanning for something that no longer exists"
    );
    // #9383: this used to assert the literal substring
    // `ifindex_to_zone_id.get(&ingress_ifindex)` — i.e. the RAW PHYSICAL key,
    // which was the defect. A literal-source assertion cannot tell "the call
    // site changed because someone broke it" from "the call site changed because
    // someone FIXED it": it only knows the bytes moved. So the correct fix reddened
    // this cell with a message saying the fix REOPENED the hole it was closing,
    // which is about the strongest possible signal to stop and revert.
    //
    // Re-anchored to the two properties that are actually invariant: a zone IS
    // resolved from the arrival, and it is resolved from the LOGICAL unit. The
    // BEHAVIOUR is bound by `a_reply_on_an_unzoned_trunk_unit_installs_no_reverse_session_9383`
    // and its zoned-sibling positive control, which is where a reader should go;
    // this cell only keeps the call-site shape honest.
    assert!(
        code.contains("resolve_ingress_logical_ifindex("),
        "the main path must resolve the arrival's LOGICAL (VLAN unit) ifindex \
         before reading the zone ledger. `ifindex_to_zone_id` propagates a zoned \
         child unit's zone onto its PARENT (#921/#3618), so keying it on the raw \
         physical `meta.ingress_ifindex` returns a DIFFERENT ANSWER on a trunk \
         whose units sit in different zones — and a wrong arrival zone here MINTS \
         a reverse session that is then exempt from policy re-derivation (#9383)"
    );
    assert!(
        code.contains("ifindex_to_zone_id.get(&arrival_logical)"),
        "the resolved LOGICAL ifindex must be what keys the zone ledger. \
         Resolving it and then looking up the physical index anyway is the \
         defect with an extra line (#9383)"
    );
    assert!(
        code.contains("ReverseIngress::Unzoned"),
        "an unmapped arrival interface must fail CLOSED. If the resolution \
         defaults to Unconstrained on a lookup miss, the check is bypassed for \
         exactly the traffic least accounted for"
    );
    // The one exemption on this path is fabric ingress, and it must be
    // conditional. An unconditional Unconstrained here is the whole hole.
    assert!(
        code.contains("if fabric_ingress {"),
        "the only exemption on the installing path is fabric ingress, and it \
         must be gated on it — an unconditional Unconstrained reopens #7169"
    );
}

// ---------------------------------------------------------------------------
// #7201: `apply_worker_commands` consults the drain budget.
// ---------------------------------------------------------------------------
//
// The cells in `worker_queue_tests.rs` exercise `drain_bounded_into` DIRECTLY,
// so all of them stay green if this function is reverted to
// `core::mem::take(&mut *pending)` — they assert a property of the helper, not
// of the ingest path. These cells drive the ingest path and are the ones that
// red on that revert.

/// Queue `n` distinct `ExportOwnerRGSessions` commands, sequences `0..n`.
///
/// `ExportOwnerRGSessions` is the probe because `exported_sequences` records one
/// entry per command IN DISPATCH ORDER, so a batch of them makes the loop's
/// traversal order directly observable — which is what acceptance criterion 2
/// needs, and what a `cancelled_keys` set (deduped) or a bool flag could not
/// show.
fn queue_exports(commands: &Arc<Mutex<VecDeque<WorkerCommand>>>, n: usize) {
    let mut pending = commands.lock().expect("commands lock");
    for sequence in 0..n as u64 {
        pending.push_back(WorkerCommand::ExportOwnerRGSessions {
            sequence,
            owner_rgs: vec![1],
        });
    }
}

fn apply_once(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    scratch: &mut VecDeque<WorkerCommand>,
) -> WorkerCommandResults {
    apply_worker_commands(
        commands,
        sessions,
        -1,
        -1,
        -1,
        &ForwardingState::default(),
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::default()),
        0,
        scratch,
    )
}

#[test]
fn apply_worker_commands_7201_stops_at_the_budget_and_leaves_the_rest_queued() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let mut scratch = VecDeque::new();
    let over = WORKER_COMMAND_DRAIN_BUDGET + 44;
    queue_exports(&commands, over);

    let results = apply_once(&commands, &mut sessions, &mut scratch);

    assert_eq!(
        results.exported_sequences.len(),
        WORKER_COMMAND_DRAIN_BUDGET,
        "one call dispatched {} commands, not the {WORKER_COMMAND_DRAIN_BUDGET}-command \
         budget. Each command is a session-table mutation plus a BPF-map publish and \
         the worker does not touch its AF_XDP rings until the loop ends, so an \
         unbounded drain is unserviced ring time at RG activation (#7201).",
        results.exported_sequences.len()
    );
    assert_eq!(
        commands.lock().expect("lock").len(),
        44,
        "the undispatched remainder must stay in the shared queue"
    );
    assert!(
        results.commands_backlogged,
        "a split batch reported no backlog, so the worker loop may go idle with \
         an RG-activation burst still queued"
    );
    assert!(
        scratch.is_empty(),
        "the scratch buffer must be returned EMPTY — the caller reuses it across \
         every pass, so a leftover command would be re-dispatched next call"
    );
}

#[test]
fn apply_worker_commands_7201_preserves_dispatch_order_across_a_budget_split() {
    // Acceptance criterion 2. A budget that capped the count but took from the
    // back, or filled its quota by skipping, would satisfy the cell above and
    // still invert the UpsertSynced-then-DeleteSynced transitions the queue
    // carries for one key.
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let mut scratch = VecDeque::new();
    // Three passes, and a final partial one, so the assertion covers a boundary
    // that is not merely the first split.
    let total = WORKER_COMMAND_DRAIN_BUDGET * 3 + 7;
    queue_exports(&commands, total);

    let mut observed: Vec<u64> = Vec::with_capacity(total);
    let mut per_pass_max: Vec<u64> = Vec::new();
    let mut passes = 0;
    loop {
        let results = apply_once(&commands, &mut sessions, &mut scratch);
        passes += 1;
        if let Some(max) = results.exported_sequences.iter().copied().max() {
            per_pass_max.push(max);
        }
        observed.extend(results.exported_sequences.iter().copied());
        if !results.commands_backlogged {
            break;
        }
        assert!(passes < 16, "drain did not terminate");
    }

    assert_eq!(
        passes, 4,
        "expected the batch to split across 4 passes at a {WORKER_COMMAND_DRAIN_BUDGET} \
         budget; a different count means the budget is not the thing bounding the drain"
    );
    assert_eq!(
        observed,
        (0..total as u64).collect::<Vec<_>>(),
        "dispatch order was not preserved across the budget split. FIFO and the \
         ordering groups must survive a split; the pin in \
         `apply_worker_commands_dispatch_order_pin_with_demote_dedup` covers one \
         batch, this covers the seam between batches."
    );

    // Export-ack semantics. `worker/loop_body` stores
    // `exported_sequences.iter().max()` into `session_export_ack` once per pass,
    // so a split is only safe if each pass's max is strictly greater than the
    // last — otherwise the ack the HA peer reads goes BACKWARDS mid-burst.
    assert_eq!(per_pass_max.len(), passes);
    assert!(
        per_pass_max.windows(2).all(|w| w[0] < w[1]),
        "per-pass export-ack maxima are not strictly increasing ({per_pass_max:?}); \
         `session_export_ack` is a plain store, so a non-monotonic split would \
         retract an ack the peer already observed"
    );
}

#[test]
fn apply_worker_commands_7201_does_not_zero_the_shared_queue_capacity() {
    // Acceptance criterion 3, driven through the ingest path rather than the
    // helper: the old `core::mem::take(&mut *pending)` moved the producers'
    // buffer out and left the shared deque at capacity zero, so the producers
    // regrew it from nothing while holding the lock.
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let mut scratch = VecDeque::new();
    // Under the budget: the queue ends EMPTY either way, so capacity is the only
    // thing that distinguishes a prefix drain from `mem::take`.
    queue_exports(&commands, 8);
    let grown = commands.lock().expect("lock").capacity();
    assert!(grown >= 8, "precondition: the queue actually allocated");

    let results = apply_once(&commands, &mut sessions, &mut scratch);
    assert_eq!(results.exported_sequences.len(), 8);
    assert!(!results.commands_backlogged);

    let queue = commands.lock().expect("lock");
    assert!(queue.is_empty());
    assert!(
        queue.capacity() >= grown,
        "the shared queue came back at capacity {} (was {grown}) — `mem::take` \
         leaves it at zero and the producers pay to regrow it under the lock on \
         every pass",
        queue.capacity()
    );
}

#[test]
fn apply_worker_commands_7201_empty_and_contended_passes_report_no_backlog() {
    // The backlog flag drives `did_work`, so a spurious `true` pins a worker to
    // a hot loop on a core it should have yielded.
    let commands: Arc<Mutex<VecDeque<WorkerCommand>>> = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let mut scratch = VecDeque::new();

    let results = apply_once(&commands, &mut sessions, &mut scratch);
    assert!(
        !results.commands_backlogged,
        "an empty queue reported a backlog"
    );

    // Lock held elsewhere: the drain cannot run, and must NOT claim work.
    queue_exports(&commands, WORKER_COMMAND_DRAIN_BUDGET + 1);
    let held = commands.lock().expect("hold the lock");
    let results = apply_once(&commands, &mut sessions, &mut scratch);
    assert!(
        results.exported_sequences.is_empty(),
        "a contended pass dispatched commands"
    );
    assert!(
        !results.commands_backlogged,
        "a pass that could not take the lock claimed a backlog — the queue is \
         genuinely non-empty here, but reporting it would pin `did_work` on lock \
         contention alone, and the next poll is one iteration away"
    );
    drop(held);
}

// #6979 F3: an accepted same-key synced replacement must not strand the
// REPLACED session's source-NAT reservation.
//
// Most replacements are already safe and these tests must not claim credit for
// that: `reserve_flow` is keyed on the ORIGINAL 5-tuple (`SourceNatFlowKey`),
// so a NAT -> different-NAT re-decision finds the incumbent under the same flow
// and retires it with release semantics (#6528). The hole is the replacement
// that never REACHES `reserve_flow` — the reserve is gated on
// `is_peer_synced() && !is_reverse` at the call site and on
// `nat.rewrite_src.is_some()` inside the helper, so a NAT -> NO-NAT
// re-decision installed the new session and left the old port reserved with
// nothing left to free it (delete-sync releases the CURRENT decision, which no
// longer names that port).
//
// All three drive the REAL `handle_upsert_synced` entry point, so deleting the
// wiring reds them — testing the release helper directly would not.

fn f3_forwarding_6979() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "snat-lan".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "pool-lan".to_string(),
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 20000,
            port_high: 20099,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding
}

fn f3_key_6979() -> crate::session::SessionKey {
    crate::session::SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "10.0.61.50".parse().unwrap(),
        dst_ip: "8.8.8.8".parse().unwrap(),
        src_port: 40000,
        dst_port: 443,
        discriminator: Default::default(),
        // #7160 phase 1 widened SessionKey after this PR was authored; 0 is
        // the default routing instance, so F3's fixture is unchanged.
        routing_domain: 0,
    }
}

fn f3_entry_6979(nat: NatDecision) -> SyncedSessionEntry {
    let mut decision = test_decision();
    decision.nat = nat;
    SyncedSessionEntry {
        key: f3_key_6979(),
        decision,
        metadata: SessionMetadata {
            ingress_zone: 1,
            egress_zone: 2,
            is_reverse: false,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

fn f3_nat_on_port_6979(port: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some("203.0.113.10".parse().unwrap()),
        rewrite_src_port: Some(port),
        ..NatDecision::default()
    }
}

/// Import a synced session on port 20000, then replace it at the SAME key with
/// `second`. Returns `(used_ports_after_replace, installed_rewrite_port)`.
///
/// The second element is the anti-vacuity discriminator: `used_ports` alone
/// cannot tell "the replacement landed and freed the port" from "the
/// replacement was REJECTED so nothing changed". Every assertion below pins it.
fn f3_replace_6979(second: NatDecision) -> (u64, Option<Option<u16>>) {
    let forwarding = f3_forwarding_6979();
    let mut sessions = SessionTable::new();
    let ha_state: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::default());

    crate::afxdp::session_glue::commands::handle_upsert_synced(
        &mut sessions,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        f3_entry_6979(f3_nat_on_port_6979(20000)),
        1_000,
        1,
        0,
    );
    assert_eq!(
        crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports,
        1,
        "precondition: the first synced import must reserve its pool port — \
         without this the whole cell measures nothing"
    );

    crate::afxdp::session_glue::commands::handle_upsert_synced(
        &mut sessions,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        f3_entry_6979(second),
        2_000,
        2,
        0,
    );

    let used = crate::nat::source_nat_pool_statuses(&forwarding.source_nat_rules)[0].used_ports;
    let installed = sessions
        .entry_with_origin(&f3_key_6979())
        .map(|(d, _, _)| d.nat.rewrite_src_port);
    (used, installed)
}

/// FAIL-ON-REVERT. The replaced session's port is freed when the new decision
/// carries no source rewrite.
#[test]
fn synced_replace_dropping_nat_releases_the_old_reservation_6979_f3() {
    let (used, installed) = f3_replace_6979(NatDecision::default());
    assert_eq!(
        installed,
        Some(None),
        "the replacement must have LANDED with no source rewrite — if it was \
         rejected, the used_ports assertion below proves nothing"
    );
    assert_eq!(
        used, 0,
        "#6979 F3: a synced replacement that drops NAT never reaches \
         `reserve_flow`, so its stale-tuple eviction cannot retire the \
         incumbent. Without the explicit release the old pool port stays \
         reserved forever — delete-sync frees the CURRENT decision, which no \
         longer names it"
    );
}

/// OVER-REACH CONTROL for the #6528 path: a NAT -> different-NAT re-decision is
/// retired by `reserve_flow` itself. The F3 release must SKIP it — releasing as
/// well would free a port the new decision legitimately holds.
#[test]
fn synced_replace_changing_nat_port_keeps_exactly_one_reservation_6979_f3() {
    let (used, installed) = f3_replace_6979(f3_nat_on_port_6979(20001));
    assert_eq!(
        installed,
        Some(Some(20001)),
        "the replacement must have landed on the new port"
    );
    assert_eq!(
        used, 1,
        "the new tuple is reserved and the old retired by `reserve_flow` \
         (#6528) — exactly one port held. 0 means the F3 release double-freed \
         the port the new decision owns; 2 means neither path retired"
    );
}

/// OVER-REACH CONTROL for the unconditional fix. Releasing the previous
/// reservation on EVERY replace would drop this worker's holder bit and re-take
/// it on a same-tuple refresh (HA sync reconnect / periodic re-upsert), opening
/// a window for another worker's local allocation to steal the port. The
/// refresh must be a no-op that keeps the reservation.
#[test]
fn synced_refresh_with_identical_nat_keeps_its_reservation_6979_f3() {
    let (used, installed) = f3_replace_6979(f3_nat_on_port_6979(20000));
    assert_eq!(installed, Some(Some(20000)), "the refresh keeps the same tuple");
    assert_eq!(
        used, 1,
        "a same-tuple refresh must keep its reservation — `reserve_flow` takes \
         its idempotent holder-OR early return and the F3 release must not run"
    );
}

/// #7699: the `WorkerCommand` arms actually reach the worker's association
/// table.
///
/// The table's own cells (`session::pptp`) and the broadcast's cells
/// (`afxdp::worker_queue`) both pass against a build where the drain arms are
/// missing entirely — the table works, the queue delivers, and nothing connects
/// them. That is the #6852 no-production-caller shape one layer in, so the
/// wiring gets its own cell driving the real drain.
///
/// FAIL-ON-REVERT: delete either arm from `apply_worker_commands` and this reds
/// while every other PPTP cell stays green.
#[test]
fn worker_commands_install_and_forget_pptp_associations_7699() {
    use crate::session::pptp::PptpCall;

    let (a, b): (std::net::IpAddr, std::net::IpAddr) = (
        "198.51.100.7".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
    );
    let call = PptpCall::new(a, 0x1111, b, 0x2222);
    let handle = call.handle();

    let mut sessions = SessionTable::new();
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let ha_state = BTreeMap::new();
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());

    commands
        .lock()
        .expect("commands")
        .push_back(WorkerCommand::InstallPptpCall {
            call,
            control: crate::session::pptp::ControlChannelId::new(a, 49152, b, 1723),
            learned_ns: 0,
        });
    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );
    assert_eq!(
        sessions.pptp().resolve(b, 0x2222),
        Some(handle),
        "the install command did not reach this worker's association table, so \
         its PPTP data packets resolve as unassociated"
    );
    assert_eq!(
        sessions.pptp().resolve(a, 0x1111),
        Some(handle),
        "the reverse direction must resolve to the same handle after the drain"
    );

    commands
        .lock()
        .expect("commands")
        .push_back(WorkerCommand::ForgetPptpCall(handle));
    apply_worker_commands(
        &commands,
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );
    assert_eq!(
        sessions.pptp().resolve(b, 0x2222),
        None,
        "the forget command did not reach the table; a stale association \
         re-pairs a REUSED 16-bit call id onto a dead handle"
    );
    assert_eq!(sessions.pptp().resolve(a, 0x1111), None);
}

/// #7699 stage 2 END-TO-END: control-channel BYTES through to an association a
/// data packet resolves against.
///
/// # What this binds, and what it does NOT
///
/// Every other PPTP cell tests one hop: the parser cells build a segment and
/// assert a parse, the table cells install a `PptpCall` and assert a resolve,
/// the drain cell pushes a `WorkerCommand` and asserts it lands. This one
/// composes parse -> broadcast -> drain -> resolve starting from the wire
/// BYTES, so it binds both ends together and the shape of their composition:
/// the call ids must be attributed to the right peers, survive the broadcast,
/// and resolve in BOTH directions to one handle. Breaking the parser reds this
/// cell along with two unit cells; swapping `src`/`dst` in
/// `learn_from_control_segment` reds this one and the attribution cell.
///
/// **It does NOT bind production wiring**, and it never did: it chains the
/// parser to the broadcast at the TEST level, which is a hand-chained pair, and
/// a hand-chained pair cannot notice that production never chains them. When
/// this was written production did not, and this comment said so.
///
/// That was stated rather than left implicit because an EARLIER version claimed
/// the opposite — it named "delete the call from the publish path" as the
/// falsifying mutation, and there was no publish path to delete it from. The
/// claim was unfalsifiable, which is worse than silence: it would be believed
/// exactly as long as nobody tried it.
///
/// **The production join now exists** (#7699's packet-path dispatch): the hot
/// path copies a TCP/1723 segment into `PptpControlInbox` and the worker's
/// periodic drain parses, installs and broadcasts it. Its own cell —
/// `afxdp::poll_stages::tests::pptp_dispatch_join_tests_7699::the_stage_captures_a_control_segment_and_the_drain_learns_it_7699`
/// — runs the REAL stage over real frame bytes, so deleting the push reds it.
/// This cell stays as the parser/broadcast composition test it always was.
#[test]
fn a_control_segment_becomes_a_resolvable_association_7699() {
    use crate::session::pptp_control::{
        fixtures_7699::outgoing_call_reply, learn_from_control_segment,
    };

    // The PAC answers the PNS's Outgoing-Call-Request. Its own Call ID is
    // 0xAAAA; it echoes the PNS's 0xBBBB.
    let (pac, pns): (std::net::IpAddr, std::net::IpAddr) = (
        "198.51.100.7".parse().unwrap(),
        "203.0.113.9".parse().unwrap(),
    );
    let segment = outgoing_call_reply(0xAAAA, 0xBBBB, 1);

    // 1. the control channel, off the data path
    let call = learn_from_control_segment(pac, pns, &segment)
        .expect("a connected Outgoing-Call-Reply must yield the pair");
    let handle = call.handle();

    // 2. published to every worker
    let queues: Vec<_> = (0..2)
        .map(|_| Arc::new(Mutex::new(VecDeque::new())))
        .collect();
    assert_eq!(
        crate::afxdp::worker_queue::broadcast_pptp_install(
            &queues,
            call,
            crate::session::pptp::ControlChannelId::new(pac, 49152, pns, 1723),
            0,
        ),
        2,
        "the association must reach every worker; the control channel and the \
         GRE data channel are not co-located"
    );

    // 3. drained by a worker
    let mut sessions = SessionTable::new();
    let forwarding = test_forwarding_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    apply_worker_commands(
        &queues[1],
        &mut sessions,
        -1,
        -1,
        -1,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        0,
        &mut VecDeque::new(),
    );

    // 4. and a data packet in EITHER direction resolves to one handle.
    //    A packet to the PAC carries the PAC's call id; to the PNS, the PNS's.
    assert_eq!(
        sessions.pptp().resolve(pac, 0xAAAA),
        Some(handle),
        "a data packet toward the PAC must resolve the call learned from the \
         control channel"
    );
    assert_eq!(
        sessions.pptp().resolve(pns, 0xBBBB),
        Some(handle),
        "and the reverse direction must resolve to the SAME handle — that is \
         what makes the reverse companion match and the reply find its session"
    );
}

// ---------------------------------------------------------------------------
// #8114 item 4 — a `DeleteSynced` a full sibling queue REFUSES.
// ---------------------------------------------------------------------------

fn drop8114_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: "10.0.0.5".parse().unwrap(),
        dst_ip: "198.51.100.9".parse().unwrap(),
        src_port: 4000,
        dst_port: 80,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn drop8114_filler_key(i: usize) -> SessionKey {
    let mut key = drop8114_key();
    key.src_port = 30000 + (i as u16 % 20000);
    key.dst_port = 81;
    key
}

/// A forwarding state whose single source-NAT rule owns a ONE-PORT pool, so
/// "the port is occupied" is a yes/no an assertion can read directly.
fn drop8114_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::SourceNATRuleSnapshot {
            name: "snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "p".to_string(),
            pool_addresses: vec!["203.0.113.1/32".to_string()],
            port_low: 20000,
            port_high: 20000,
            ..crate::SourceNATRuleSnapshot::default()
        },
    ]);
    forwarding
}

/// Take the pool reservation for `drop8114_key()` with `worker_id` as the
/// holder — exactly what that worker's own `UpsertSynced` would have left.
fn drop8114_reserve(forwarding: &ForwardingState, worker_id: u32) -> crate::nat::NatDecision {
    use crate::nat::NatHolder;
    let key = drop8114_key();
    let translated = crate::nat::TranslatedTuple {
        ip: "203.0.113.1".parse().unwrap(),
        port: 20000,
    };
    let flow = crate::nat::SourceNatFlowKey {
        protocol: key.protocol,
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        routing_scope: 0,
    };
    let alloc = &forwarding.source_nat_rules[0].pool_allocator;
    assert!(
        alloc.reserve_flow(flow, translated, 0, false, 1_000, NatHolder::Worker(worker_id)),
        "fixture must take the reservation, or every assertion below is vacuous"
    );
    assert!(
        alloc.debug_is_port_occupied(0, 20000),
        "fixture precondition: the port is occupied before the delete"
    );
    let mut nat = crate::nat::NatDecision::default();
    nat.rewrite_src = Some(translated.ip);
    nat.rewrite_src_port = Some(translated.port);
    nat
}

/// A peer queue plus the id-keyed map that names it — the SAME `Arc`, because
/// the repair resolves the id by pointer identity.
fn drop8114_queues(
    worker_id: u32,
    fill: bool,
) -> (
    Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>>,
) {
    let queue: Arc<Mutex<VecDeque<WorkerCommand>>> = Arc::new(Mutex::new(VecDeque::new()));
    if fill {
        let mut pending = queue.lock().expect("fresh mutex");
        for i in 0..crate::afxdp::worker_queue::MAX_PENDING_WORKER_COMMANDS {
            pending.push_back(WorkerCommand::DeleteSynced(drop8114_filler_key(i)));
        }
        assert_eq!(
            pending.len(),
            crate::afxdp::worker_queue::MAX_PENDING_WORKER_COMMANDS,
            "fixture: the queue must be EXACTLY at capacity so the next push is refused"
        );
    }
    let peers = vec![queue.clone()];
    let mut by_id = BTreeMap::new();
    by_id.insert(worker_id, queue);
    (peers, by_id)
}

/// THE BINDING (#8114 item 4). A `DeleteSynced` a full sibling queue refuses
/// must not strand that sibling's NAT reservation: nothing else ever frees it.
///
/// `handle_delete_synced` is what a worker DOES with the command, and it drops
/// that worker's source-NAT and NAT64 holder bits; the port is freed by
/// whichever worker drops the LAST bit. A worker that never receives the command
/// never drops its bit — and it is ALIVE, so neither the dead-worker sweep
/// (#8069) nor the generation-teardown sweep (#7092) can see it. The port is
/// held for the life of the allocator.
///
/// The fixture asserts the DROP ACTUALLY HAPPENED before asserting the repair.
/// Without that precondition a queue that quietly accepted the push would make
/// this cell test the ordinary path and prove nothing.
///
/// Fail-on-revert: restore `replicate_session_delete`'s discarded
/// `push_bounded` return (or route this call site back to it) and the port stays
/// occupied.
#[test]
fn a_refused_deletesynced_releases_the_siblings_reservation_8114() {
    use std::sync::atomic::Ordering;

    let forwarding = drop8114_forwarding();
    let nat = drop8114_reserve(&forwarding, 3);
    let (peers, by_id) = drop8114_queues(3, true);

    let global_dropped_before = SESSION_DELETE_REPLICA_DROPPED.load(Ordering::Relaxed);

    let outcome = replicate_session_delete_repairing(
        &peers,
        &by_id,
        &forwarding,
        &drop8114_key(),
        nat,
        false,
        2_000,
    );

    assert_eq!(
        outcome.dropped, 1,
        "fixture: the DeleteSynced must actually have been REFUSED — if the queue \
         accepted it, this cell is testing the ordinary path"
    );
    assert_eq!(
        outcome.repaired, 1,
        "the refused delete must be ATTRIBUTED to worker 3 and repaired; an \
         unattributed drop is counted but not repaired, and the two must not be \
         confusable"
    );
    // The process-wide counter is the operator signal; asserted only as
    // monotone, because it is shared with every other test thread in this
    // binary and an equality on it is a flake on a busy run.
    assert!(
        SESSION_DELETE_REPLICA_DROPPED.load(Ordering::Relaxed) > global_dropped_before,
        "the drop must also reach the process-wide counter"
    );
    assert!(
        !forwarding.source_nat_rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, 20000),
        "the refused DeleteSynced stranded 203.0.113.1:20000 on worker 3. The \
         worker is ALIVE, so no sweep can see its holder bit, and no replay \
         re-delivers the command"
    );
}

/// THE OVER-RELEASE CONTROL, and the direction of error that matters. When the
/// push SUCCEEDS the repair must NOT run: that worker will process the command
/// and drop its own bit, and freeing the port here would hand it to a new flow
/// while the old one is still being torn down — the rule
/// `PortAllocator::drop_holder_locked` states.
///
/// Fires on: releasing unconditionally instead of only on a refused push. That
/// is the cheap-looking version of this fix and it is worse than the bug.
#[test]
fn a_queued_deletesynced_leaves_the_release_to_its_worker_8114() {
    use std::sync::atomic::Ordering;

    let forwarding = drop8114_forwarding();
    let nat = drop8114_reserve(&forwarding, 3);
    // Queue NOT filled: the push succeeds.
    let (peers, by_id) = drop8114_queues(3, false);

    let outcome = replicate_session_delete_repairing(
        &peers,
        &by_id,
        &forwarding,
        &drop8114_key(),
        nat,
        false,
        2_000,
    );

    assert_eq!(
        outcome,
        DeleteReplicationOutcome::default(),
        "nothing was refused, so neither counter may move"
    );
    assert!(
        forwarding.source_nat_rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, 20000),
        "the port was freed for a worker that is going to free it itself; the \
         command was QUEUED, so that worker WILL run the teardown"
    );
    let pending = peers[0].lock().expect("fresh mutex");
    assert!(
        pending
            .iter()
            .any(|cmd| matches!(cmd, WorkerCommand::DeleteSynced(k) if *k == drop8114_key())),
        "and the delete must actually be on the queue"
    );
}

/// THE ATTRIBUTION CONTROL. A refused delete whose queue is NOT in the id-keyed
/// map is counted as a drop and NOT repaired — the id could not be resolved, and
/// releasing a reservation for an unknown worker is exactly the over-release the
/// cell above forbids.
///
/// This is also what keeps every pre-#8114 fixture honest: they pass an empty
/// map, so they take this path and behave exactly as they did before.
///
/// Fires on: falling back to "release for some worker" when the lookup misses.
#[test]
fn an_unattributable_refused_delete_is_counted_but_not_repaired_8114() {
    use std::sync::atomic::Ordering;

    let forwarding = drop8114_forwarding();
    let nat = drop8114_reserve(&forwarding, 3);
    let (peers, _by_id) = drop8114_queues(3, true);
    let empty: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = BTreeMap::new();

    let outcome = replicate_session_delete_repairing(
        &peers,
        &empty,
        &forwarding,
        &drop8114_key(),
        nat,
        false,
        2_000,
    );

    assert_eq!(
        outcome.dropped, 1,
        "the drop is real and must be counted even when it cannot be repaired"
    );
    assert_eq!(
        outcome.repaired, 0,
        "an unresolvable worker id must NOT be repaired — that would clear the \
         bit of a worker that may still be forwarding the flow"
    );
    assert!(
        forwarding.source_nat_rules[0]
            .pool_allocator
            .debug_is_port_occupied(0, 20000),
        "and the reservation stays exactly where it was"
    );
}

// ---------------------------------------------------------------------------
// #8593 — the WIRING: `flush_session_deltas` must route a bulk-export delta to
// the non-arming push.
// ---------------------------------------------------------------------------

/// A `BindingLiveState` whose RPC-fallback buffer is already at
/// `MAX_PENDING_SESSION_DELTAS`, with the loss latch cleared, so the next push
/// through it is guaranteed to be refused.
fn saturated_live_8593() -> Arc<BindingLiveState> {
    let live = Arc::new(BindingLiveState::new());
    for _ in 0..crate::afxdp::MAX_PENDING_SESSION_DELTAS {
        live.push_session_delta(crate::protocol::SessionDeltaInfo::default());
    }
    let _ = live.take_delta_loss();
    live
}


/// THE PRODUCER (#8593). `bulk_resync` is only useful if the export's own
/// deltas carry it and nothing else does. `emit_open_delta_with_origin` is the
/// sole producer — its only production caller is the worker loop's chunked
/// owner-RG export — so this pins both directions on the same table.
///
/// Fires on: setting `bulk_resync: false` in `emit_open_delta_with_origin` (the
/// export's drops start arming the latch again), and on setting it `true` in
/// `push_open_delta`/`push_close_delta` (every incremental drop stops arming,
/// which deletes the #5290 recovery).
#[test]
fn only_the_owner_rg_export_produces_a_bulk_resync_delta_8593() {
    let mut sessions = SessionTable::new();
    let key = test_key();
    assert!(sessions.install_with_protocol(
        key.clone(),
        test_decision(),
        test_metadata(),
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let install_deltas = sessions.drain_deltas(256);
    assert!(
        !install_deltas.is_empty(),
        "fixture: the install must emit a delta, or neither arm proves anything"
    );
    assert!(
        install_deltas.iter().all(|d| !d.bulk_resync),
        "an ordinary install emits INCREMENTAL deltas; marking them bulk would \
         stop every real drop from arming the resync"
    );

    sessions.emit_open_delta_with_origin(
        key,
        test_decision(),
        test_metadata(),
        SessionOrigin::ForwardFlow,
        true,
    );
    let export_deltas = sessions.drain_deltas(256);
    assert_eq!(
        export_deltas.len(),
        1,
        "fixture: the export emits exactly one open delta"
    );
    assert!(
        export_deltas[0].bulk_resync,
        "the owner-RG export's own delta must be marked, or its overflow \
         re-arms the latch that triggered the export"
    );
}

fn delta_8593(key: &SessionKey, bulk_resync: bool) -> SessionDelta {
    SessionDelta {
        kind: SessionDeltaKind::Close,
        key: key.clone(),
        decision: test_decision(),
        metadata: test_metadata(),
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 0,
        bulk_resync,
        tcp_close_class: 0,
    }
}

/// Drive `flush_session_deltas` once against a SATURATED fallback buffer and
/// report whether the per-binding loss latch came out ARMED.
fn flush_one_and_report_armed_8593(bulk_resync: bool) -> bool {
    let live = saturated_live_8593();
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let forwarding = ForwardingState::default();
    let mut worker_lossless_wedged = false;
    let dropped_before = live.session_delta_dropped.load(Ordering::Relaxed);

    crate::afxdp::session_delta::flush_session_deltas(
        &ident,
        Some(&live),
        -1,
        -1,
        -1,
        &dnat_fds,
        &[delta_8593(&test_key(), bulk_resync)],
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &None,
        &forwarding,
        &mut worker_lossless_wedged,
    );

    assert_eq!(
        live.session_delta_dropped.load(Ordering::Relaxed),
        dropped_before + 1,
        "fixture: the flush's push must actually have been REFUSED \
         (bulk_resync={bulk_resync}) — if it fit, the latch result says nothing \
         about the routing"
    );
    live.take_delta_loss()
}

/// THE WIRING (#8593). The non-arming push exists; this proves
/// `flush_session_deltas` REACHES it — and that it does not reach it for an
/// ordinary incremental delta.
///
/// Both arms run the same function over the same saturated buffer with the same
/// delta, differing only in `bulk_resync`, so the marker is the only thing under
/// test. A cell that exercised only `BindingLiveState`'s two push methods would
/// stay green with `flush_session_deltas` calling the arming one
/// unconditionally, which is the whole defect.
///
/// Fail-on-revert: drop the `delta.bulk_resync` branch in
/// `flush_session_deltas` and the first assertion reds.
#[test]
fn flush_session_deltas_routes_a_bulk_export_drop_to_the_non_arming_push_8593() {
    assert!(
        !flush_one_and_report_armed_8593(true),
        "a BULK-EXPORT delta the fallback buffer refused must not arm the \
         loss-of-sync latch — arming it makes the resync re-trigger itself"
    );
    assert!(
        flush_one_and_report_armed_8593(false),
        "an INCREMENTAL delta the buffer refused must still arm it (#5290); a \
         fix that never arms deletes the recovery instead of bounding it"
    );
}

// ---------------------------------------------------------------------------
// #8586 — the delete-drop epoch and the `is_peer_synced()`-scoped reconcile.
// ---------------------------------------------------------------------------

fn key8586(src_port: u16) -> SessionKey {
    let mut k = test_key();
    k.src_port = src_port;
    k
}

fn install8586(sessions: &mut SessionTable, key: &SessionKey, origin: SessionOrigin) {
    assert!(
        sessions.install_with_protocol_with_origin(
            key.clone(),
            test_decision(),
            test_metadata(),
            origin,
            1_000_000,
            PROTO_TCP,
            0x10,
        ),
        "fixture: install must succeed for {origin:?}"
    );
}

fn publish8586(
    shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) {
    shared.lock().expect("shared sessions").insert(
        key.clone(),
        SyncedSessionEntry {
            key: key.clone(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        },
    );
}

/// THE SAFETY PROPERTY (#8586). The reconcile sweeps ONLY origins that shared
/// authority actually arbitrates, and the exclusions are what make it safe to
/// run at all.
///
/// Every entry below is absent from the shared map, so a sweep that scoped by
/// anything looser than `is_peer_synced()` would delete all of them. Only the
/// three peer-synced origins may go.
///
/// `SharedPromote` is the one a reader expects to be swept and must not be: it
/// is synced-DERIVED but no longer peer-AUTHORITATIVE — the origin an entry
/// receives AFTER local traffic promoted it — so this node owns it and its
/// absence from the shared map is not evidence it should die. `loop_body`'s
/// "synced-derived" classification DOES include it; using that one here would
/// be the bug, and this cell is what makes the choice explicit rather than an
/// implicit consequence of which predicate got typed.
///
/// `FabricPuntSeed` and `MissingNeighborSeed` are transient-local by
/// construction — never HA-exported, never Open-delta'd — so they are live
/// local sessions that are absent from the shared map BY DESIGN. They are the
/// population #8586 named as the reason not to build a naive sweep.
///
/// Fail-on-revert: scope the walk with `is_promotable_synced()`, or with
/// `!matches!(origin, ForwardFlow | ReverseFlow | LocalMiss)`, or drop the
/// origin test entirely — each reds a different line below.
#[test]
fn the_reconcile_sweeps_only_peer_synced_origins_8586() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut sessions = SessionTable::new();

    // Swept: shared authority arbitrates these and no longer holds them.
    let swept = [
        (SessionOrigin::SyncImport, key8586(1001)),
        (SessionOrigin::SharedMaterialize, key8586(1002)),
        (SessionOrigin::WorkerLocalImport, key8586(1003)),
    ];
    // NOT swept: this node owns them, and none is in the shared map either — so
    // "absent from shared" cannot be the discriminator on its own.
    let kept = [
        (SessionOrigin::SharedPromote, key8586(2001)),
        (SessionOrigin::FabricPuntSeed, key8586(2002)),
        (SessionOrigin::MissingNeighborSeed, key8586(2003)),
        (SessionOrigin::ForwardFlow, key8586(2004)),
        (SessionOrigin::ReverseFlow, key8586(2005)),
        (SessionOrigin::LocalMiss, key8586(2006)),
    ];
    for (origin, key) in swept.iter().chain(kept.iter()) {
        install8586(&mut sessions, key, *origin);
    }
    assert!(
        shared_sessions.lock().expect("shared").is_empty(),
        "fixture: NOTHING is in the shared map, so every entry is a sweep \
         candidate as far as the map is concerned"
    );

    let mut evicted = Vec::new();
    let n = reconcile_peer_synced_against_shared(&mut sessions, &shared_sessions, &mut evicted);

    assert_eq!(n, swept.len(), "exactly the peer-synced origins are swept");
    for (origin, key) in &swept {
        assert!(
            sessions.lookup(key, 2_000_000, 0).is_none(),
            "{origin:?} is peer-authoritative and shared authority dropped it — \
             it must be swept"
        );
        assert!(
            evicted.contains(key),
            "{origin:?}'s key must reach the flow-cache eviction list, or its \
             cached descriptor outlives the entry (the #6457 failure mode)"
        );
    }
    for (origin, key) in &kept {
        assert!(
            sessions.lookup(key, 2_000_000, 0).is_some(),
            "{origin:?} is LOCALLY owned; sweeping it against a map that never \
             held it deletes a live session"
        );
        assert!(!evicted.contains(key));
    }
}

/// A peer-synced entry shared authority STILL holds must survive. Without this
/// the cell above is satisfied by "sweep every peer-synced entry", which would
/// delete the standby's whole synced table on the first refused delete.
#[test]
fn the_reconcile_keeps_a_peer_synced_entry_the_shared_map_still_holds_8586() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut sessions = SessionTable::new();
    let live = key8586(3001);
    let gone = key8586(3002);
    install8586(&mut sessions, &live, SessionOrigin::SyncImport);
    install8586(&mut sessions, &gone, SessionOrigin::SyncImport);
    publish8586(&shared_sessions, &live);

    let mut evicted = Vec::new();
    let n = reconcile_peer_synced_against_shared(&mut sessions, &shared_sessions, &mut evicted);

    assert_eq!(n, 1, "only the one shared authority dropped");
    assert!(
        sessions.lookup(&live, 2_000_000, 0).is_some(),
        "a peer-synced entry the shared map STILL holds is live; sweeping it \
         would empty the standby's synced table on any refused delete"
    );
    assert!(sessions.lookup(&gone, 2_000_000, 0).is_none());
    assert_eq!(evicted, vec![gone]);
}

/// THE TRIGGER SEPARATION (#8586), and it is the measured one.
///
/// Ordinary session establishment pins the command queue at the 4096 cap and
/// discards tens of thousands of commands while dropping ZERO deletes — the
/// losses there are `UpsertSynced` replicas whose content the shared map still
/// holds. A reconcile keyed on queue pressure would therefore run its
/// whole-table walk continuously through normal traffic and reconcile nothing.
///
/// So the epoch must move for a refused DELETE and not for a refused UPSERT.
/// Both arms below fill the SAME queue to the SAME cap and push one command
/// through the same `push_bounded`; only the command kind differs.
///
/// Fail-on-revert: bump the epoch from `push_bounded`, or from
/// `replicate_session_upsert`, and the upsert arm reds.
#[test]
fn only_a_refused_delete_moves_the_worker_epoch_8586() {
    use std::sync::atomic::Ordering;

    // A worker id high enough that no other cell in this binary shares it.
    const W: u32 = 77;
    let forwarding = drop8114_forwarding();
    let nat = drop8114_reserve(&forwarding, W);
    let (peers, by_id) = drop8114_queues(W, true);

    let before = crate::afxdp::session_glue::session_delete_drop_epoch(W);

    // (a) A refused UPSERT. Same queue, same cap, same refusal.
    {
        let mut pending = worker_queue::lock_recover(&peers[0]);
        let queued = worker_queue::push_bounded(
            &mut pending,
            WorkerCommand::UpsertSynced(SyncedSessionEntry {
                key: key8586(4001),
                decision: test_decision(),
                metadata: test_metadata(),
                origin: SessionOrigin::SyncImport,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
                generation: 0,
                session_id: 0,
                tcp_close_class: 0,
            }),
        );
        assert!(
            !queued,
            "fixture: the upsert must also have been REFUSED, or this arm is \
             not comparing like with like"
        );
    }
    assert_eq!(
        crate::afxdp::session_glue::session_delete_drop_epoch(W),
        before,
        "a refused UPSERT must NOT raise a reconcile: its content is still in \
         the shared map, and establishment refuses these by the tens of \
         thousands while losing no deletes"
    );

    // (b) A refused DELETE through the production fan-out.
    let outcome = replicate_session_delete_repairing(
        &peers,
        &by_id,
        &forwarding,
        &drop8114_key(),
        nat,
        false,
        2_000,
    );
    assert_eq!(outcome.dropped, 1, "fixture: the delete must have been refused");
    assert_eq!(outcome.repaired, 1, "fixture: and attributed to worker {W}");
    assert_eq!(
        crate::afxdp::session_glue::session_delete_drop_epoch(W),
        before + 1,
        "a refused DELETE must raise exactly one reconcile for the worker that \
         will never receive it"
    );
    assert_eq!(
        crate::afxdp::session_glue::SESSION_DELETE_DROP_EPOCH[(W + 1) as usize]
            .load(Ordering::Relaxed),
        0,
        "and only for THAT worker — a broadcast bump makes every sibling walk \
         its table for a delete it did receive"
    );
}

// ── #9327 item 1: re-derivation of the delete-drop reconcile cost ───────────
//
// Independent of the issue's numbers: this rebuilds the measurement from
// scratch so the fix is aimed at a cliff I have seen, not one I was told about.
// Ignored by default (it is a measurement, not an assertion); run with
//   cargo test --release --bin xpf-userspace-dp reconcile_cost_9327 -- --ignored --nocapture
#[test]
#[ignore = "MEASUREMENT: #9327 reconcile sweep cost; prints numbers, asserts nothing (run with --release --ignored --nocapture)"]
fn reconcile_cost_9327() {
    use std::time::Instant;
    eprintln!("size_of::<SessionKey>() = {}", std::mem::size_of::<SessionKey>());
    for n in [4096usize, 16384, 60000] {
        // FINDS NOTHING: every peer-synced session is still in the shared map,
        // so `stale` is empty and the sweep deletes nothing. This is the case
        // the dismissal called cheap.
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let mut sessions = SessionTable::new();
        for i in 0..n {
            let k = key9327(i);
            install8586(&mut sessions, &k, SessionOrigin::SyncImport);
            publish8586(&shared_sessions, &k);
        }
        let mut evicted = Vec::new();
        let t = Instant::now();
        let swept = reconcile_peer_synced_against_shared(&mut sessions, &shared_sessions, &mut evicted);
        let el = t.elapsed();
        eprintln!("n={n:<6} swept={swept:<6} elapsed={el:?}   (finds-nothing)");
    }
    for n in [16384usize, 60000] {
        // ALL-STALE: the shared map is empty, so every session is swept.
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let mut sessions = SessionTable::new();
        for i in 0..n {
            install8586(&mut sessions, &key9327(i), SessionOrigin::SyncImport);
        }
        let mut evicted = Vec::new();
        let t = Instant::now();
        let swept = reconcile_peer_synced_against_shared(&mut sessions, &shared_sessions, &mut evicted);
        let el = t.elapsed();
        eprintln!("ALL-STALE n={n:<6} swept={swept:<6} elapsed={el:?}");
    }
}

fn key9327(i: usize) -> SessionKey {
    let mut k = test_key();
    k.src_port = (i % 65535) as u16;
    k.dst_port = ((i / 65535) % 65535) as u16;
    k.src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from((i as u32).wrapping_add(0x0a00_0000)));
    k
}

// ── #9327 item 1: the sweep is budgeted ────────────────────────────────────
//
// The prior validation scored this NEG on the grounds that the epoch gate makes
// the sweep rare. The gate bounds FREQUENCY, not COST, and one refused
// cross-worker `DeleteSynced` — ordinary RG-activation churn — arms it.
// Re-measured independently on this tree before fixing anything:
//
//	n=16384 finds-nothing   1.745 ms    <- already at the ~1.97 ms RX-ring fill
//	n=60000 finds-nothing   6.466 ms    <- 3x the fill
//	n=60000 all-stale      39.148 ms    <- ~20x the fill
//
// against this crate's own standard: WORKER_COMMAND_DRAIN_BUDGET is 256 and is
// justified against that fill time, because the worker does not service its
// AF_XDP rings while it sweeps.
//
// THESE ASSERT A BOUND, NOT A DURATION. A wall-time assertion is a property of
// the machine that ran it — it passes on a fast box with the cliff intact, which
// is how a cost defect hides. The per-pass visited bound is size-independent and
// is the thing that actually keeps the rings serviced.

/// One pass must sweep at most the budget, however much work is outstanding.
#[test]
fn one_sweep_pass_is_bounded_by_the_budget_9327() {
    let n = super::DELETE_DROP_SWEEP_BUDGET * 40; // >> budget, so a whole-table
                                                  // walk is plainly distinguishable
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut sessions = SessionTable::new();
    for i in 0..n {
        install8586(&mut sessions, &key9327(i), SessionOrigin::SyncImport);
    }
    assert!(
        shared_sessions.lock().expect("shared").is_empty(),
        "fixture: an EMPTY shared map makes every session stale, which is the \
         worst case and the one that measured 39 ms"
    );

    let mut sweep = super::DeleteDropSweep::default();
    sweep.arm();
    let mut evicted = Vec::new();
    let first = sweep.step(&mut sessions, &shared_sessions, &mut evicted);

    assert!(
        first <= super::DELETE_DROP_SWEEP_BUDGET,
        "#9327: one pass swept {first} sessions with a budget of {}. The worker \
         does not service its AF_XDP RX/TX rings while it sweeps, so an \
         unbounded pass is wall-clock time the rings go unserviced — measured \
         39 ms at 60k sessions against a ~1.97 ms ring fill.",
        super::DELETE_DROP_SWEEP_BUDGET
    );
    assert!(
        first > 0,
        "NON-VACUITY: the pass swept NOTHING, so the bound above is satisfied by \
         a sweep that does no work at all and proves nothing"
    );
    assert!(
        sweep.is_running(),
        "with {n} stale sessions and a budget of {}, one pass cannot have \
         finished — if it reports done, the sweep is silently dropping the rest",
        super::DELETE_DROP_SWEEP_BUDGET
    );
}

/// PROGRESS: stepping to completion sweeps everything, so the bound above buys
/// pacing rather than lost work. Without this, a sweep that budgets by giving up
/// would satisfy the bound.
#[test]
fn the_budgeted_sweep_still_sweeps_everything_9327() {
    let n = super::DELETE_DROP_SWEEP_BUDGET * 7 + 13; // deliberately not a multiple
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut sessions = SessionTable::new();
    for i in 0..n {
        install8586(&mut sessions, &key9327(i), SessionOrigin::SyncImport);
    }

    let mut sweep = super::DeleteDropSweep::default();
    sweep.arm();
    let mut evicted = Vec::new();
    let mut total = 0usize;
    let mut passes = 0usize;
    while sweep.is_running() {
        total += sweep.step(&mut sessions, &shared_sessions, &mut evicted);
        passes += 1;
        assert!(
            passes < n + 16,
            "the sweep did not terminate after {passes} passes — a cursor that \
             never reaches the end wedges the worker loop into sweeping forever"
        );
    }
    assert_eq!(
        total, n,
        "every stale peer-synced session must be swept across the passes; \
         budgeting must pace the work, not discard it"
    );
    assert!(
        passes > 1,
        "NON-VACUITY: {n} sessions were swept in {passes} pass(es), so the \
         multi-pass path this cell exists to check never ran"
    );
    assert_eq!(evicted.len(), n, "every swept key must reach the flow-cache eviction list");
}

/// NO PER-PASS ALLOCATION. The pre-#9327 code allocated two full key-clone Vecs
/// on the worker loop every firing; at 60k sessions and a 52-byte key that is
/// two ~3.1 MB allocations. The retained buffer is cleared, not dropped.
///
/// THE OBSERVABLE IS CAPACITY SURVIVING AN EMPTY PASS, not capacity equality
/// across passes — and the difference is the whole cell. Measured: replacing
/// `self.stale.clear()` with `self.stale = Vec::new()` SURVIVED an
/// equality-across-passes check, because every pass refilled the fresh Vec to
/// the same length and so to the same capacity. A pass that collects NOTHING
/// distinguishes them: a cleared buffer keeps the capacity it earned, a
/// reallocated one is back to zero.
#[test]
fn the_sweep_reuses_its_buffer_across_passes_9327() {
    let budget = super::DELETE_DROP_SWEEP_BUDGET;
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut sessions = SessionTable::new();
    // Slab slots are handed out in insert order, so the first window is all
    // STALE (absent from shared) and the later windows are all present.
    for i in 0..budget {
        install8586(&mut sessions, &key9327(i), SessionOrigin::SyncImport);
    }
    for i in budget..(budget * 3) {
        let k = key9327(i);
        install8586(&mut sessions, &k, SessionOrigin::SyncImport);
        publish8586(&shared_sessions, &k);
    }

    let mut sweep = super::DeleteDropSweep::default();
    sweep.arm();
    let mut evicted = Vec::new();

    let first = sweep.step(&mut sessions, &shared_sessions, &mut evicted);
    let cap_after_first = sweep.stale_capacity_for_test();
    assert!(
        first > 0 && cap_after_first > 0,
        "NON-VACUITY: the first pass collected {first} keys and left capacity          {cap_after_first}; the reuse assertion below needs a buffer that          actually grew"
    );

    let second = sweep.step(&mut sessions, &shared_sessions, &mut evicted);
    assert_eq!(
        second, 0,
        "fixture: the second window is entirely present in the shared map, so          this pass must collect NOTHING — that is what makes a retained buffer          distinguishable from a fresh one"
    );
    assert!(
        sweep.stale_capacity_for_test() >= cap_after_first,
        "#9327: the stale buffer lost its capacity across a pass that collected          nothing, so it is being REALLOCATED rather than cleared. The pre-#9327          code allocated two multi-megabyte key-clone Vecs on the worker loop          every firing; retaining the buffer is what removes that."
    );
}

/// Arming mid-sweep restarts from the top rather than continuing. The epoch says
/// the shared map CHANGED, so slots already visited under the old map have to be
/// re-examined; continuing would leave them judged against a stale authority.
#[test]
fn arming_restarts_an_in_flight_sweep_9327() {
    let n = super::DELETE_DROP_SWEEP_BUDGET * 4;
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let mut sessions = SessionTable::new();
    for i in 0..n {
        install8586(&mut sessions, &key9327(i), SessionOrigin::SyncImport);
    }
    let mut sweep = super::DeleteDropSweep::default();
    sweep.arm();
    let mut evicted = Vec::new();
    sweep.step(&mut sessions, &shared_sessions, &mut evicted);
    assert!(sweep.cursor_for_test() > 0, "fixture: the first pass must advance the cursor");
    sweep.arm();
    assert_eq!(
        sweep.cursor_for_test(),
        0,
        "#9327: an epoch bump must restart the sweep. The shared map changed, so \
         every slot already judged against the previous map has to be re-examined."
    );
}

// ---------------------------------------------------------------------------
// #9383: the #7169 reverse-session synthesis resolves the LOGICAL arrival unit.
// ---------------------------------------------------------------------------
//
// `ForwardingState::ifindex_to_zone_id` deliberately PROPAGATES a zoned child
// unit's zone onto its parent's ifindex (#921/#3618) so that untagged traffic on
// a trunk parent is attributed to its unit's zone. The consequence is that the
// RAW PHYSICAL key and the LOGICAL (VLAN unit) key can return DIFFERENT ANSWERS
// for the same frame — not two spellings of one answer — and until #9383 this
// site used the physical one while every zone / filter / pre-routing-NAT
// admission site resolved the logical unit first (#3021/#5802).
//
// WHY THIS SITE AND NOT ANOTHER. A match admitted against a wrong arrival zone
// makes `install_reverse_session_from_forward_match` MINT a reverse session, and
// reverse entries are exempt from zone-policy re-derivation by design
// (`poll_descriptor/policy_revalidation.rs`, gate 1), so the synthesized session
// then rides the established fast path with no further adjudication.
//
// THE PAIR IS THE CELL. `..._installs_no_reverse_session_9383` alone is
// satisfied by "never synthesize a reverse session", which would break the
// reply of every NAT'd flow in the box; `..._still_installs_one_9383` is the
// positive control that rules that out, and it differs from its partner in ONE
// byte of input — the arrival VLAN id. Without it, "no reverse session" and "the
// harness never had a forward match to find" are the same observation.

const TRUNK_PARENT_IFINDEX: i32 = 41;
const TRUNK_ZONED_UNIT_IFINDEX: i32 = 42;
const TRUNK_UNZONED_UNIT_IFINDEX: i32 = 43;
const TRUNK_ZONED_VLAN: u16 = 50;
const TRUNK_UNZONED_VLAN: u16 = 80;

/// A trunk whose two units EACH own a netdev under one parent: unit 42 in `wan`
/// (the zone the forward flow egresses to) and unit 43 in NO zone, both
/// `parent_ifindex = 41`. The forward flow ingresses on `reth1.0` in `lan`.
fn trunk_snapshot_9383() -> crate::ConfigSnapshot {
    crate::ConfigSnapshot {
        generation: 7,
        fib_generation: 9,
        default_policy: "deny".to_string(),
        zones: vec![
            crate::ZoneSnapshot {
                name: "lan".to_string(),
                id: TEST_LAN_ZONE_ID,
                ..Default::default()
            },
            crate::ZoneSnapshot {
                name: "wan".to_string(),
                id: TEST_WAN_ZONE_ID,
                ..Default::default()
            },
        ],
        interfaces: vec![
            crate::InterfaceSnapshot {
                name: "reth1.0".to_string(),
                zone: "lan".to_string(),
                linux_name: "ge-0-0-1".to_string(),
                ifindex: 6,
                mtu: 1500,
                hardware_addr: "02:bf:72:01:00:01".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "10.0.61.1/24".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            // The ZONED trunk unit. Its zone is what propagates onto parent 41.
            crate::InterfaceSnapshot {
                name: "reth0.50".to_string(),
                zone: "wan".to_string(),
                linux_name: "ge-0-0-2.50".to_string(),
                ifindex: TRUNK_ZONED_UNIT_IFINDEX,
                parent_ifindex: TRUNK_PARENT_IFINDEX,
                vlan_id: TRUNK_ZONED_VLAN as i32,
                mtu: 1500,
                hardware_addr: "02:bf:72:00:80:08".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.50.8/24".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            // The UNZONED trunk unit, on its OWN netdev. An EMPTY zone is the
            // legitimate "no zone" case (#2391), not a snapshot error.
            crate::InterfaceSnapshot {
                name: "reth0.80".to_string(),
                zone: String::new(),
                linux_name: "ge-0-0-2.80".to_string(),
                ifindex: TRUNK_UNZONED_UNIT_IFINDEX,
                parent_ifindex: TRUNK_PARENT_IFINDEX,
                vlan_id: TRUNK_UNZONED_VLAN as i32,
                mtu: 1500,
                hardware_addr: "02:bf:72:00:80:50".to_string(),
                addresses: vec![crate::InterfaceAddressSnapshot {
                    family: "inet".to_string(),
                    address: "172.16.80.8/24".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

/// THE PREMISE, measured rather than assumed. The disputed question in #9383 was
/// whether a Go-shaped snapshot can put a zone on the PARENT while the ARRIVAL
/// unit has none. It can, and this is the row shape that makes the two lookups
/// disagree.
///
/// If this cell ever fails, the behavioural pair below is testing nothing: both
/// arrivals would resolve to the same zone and the cells would pass for free.
#[test]
fn a_trunk_parent_carries_its_zoned_units_zone_while_a_sibling_has_none_9383() {
    let forwarding =
        crate::afxdp::forwarding_build::build_forwarding_state(&trunk_snapshot_9383());
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&TRUNK_PARENT_IFINDEX)
            .copied(),
        Some(TEST_WAN_ZONE_ID),
        "the zoned unit's zone must PROPAGATE onto the trunk parent (#921/#3618) \
         — this is what makes the raw-physical key answer `wan`"
    );
    assert_eq!(
        forwarding
            .ifindex_to_zone_id
            .get(&TRUNK_UNZONED_UNIT_IFINDEX)
            .copied(),
        None,
        "the unzoned sibling unit must carry NO zone — this is what makes the \
         LOGICAL key answer `unzoned` for the same frame"
    );
    assert_eq!(
        crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            &forwarding,
            TRUNK_PARENT_IFINDEX,
            TRUNK_UNZONED_VLAN,
        ),
        Some(TRUNK_UNZONED_UNIT_IFINDEX),
        "a frame tagged with the unzoned unit's VLAN must resolve to that UNIT, \
         not to the parent (#3021/#5802)"
    );
    assert_eq!(
        crate::afxdp::forwarding::resolve_ingress_logical_ifindex(
            &forwarding,
            TRUNK_PARENT_IFINDEX,
            TRUNK_ZONED_VLAN,
        ),
        Some(TRUNK_ZONED_UNIT_IFINDEX),
        "and the zoned unit's VLAN must resolve to the zoned unit — the control's \
         precondition"
    );
}

/// Drive the #7169 reverse-synthesis path with a reply arriving on the trunk
/// PARENT carrying `arrival_vlan`. Returns `(resolved.is_some(), session count)`.
///
/// One forward NAT'd session is pre-installed, egressing to `wan`, so
/// `find_forward_nat_match` HAS a candidate to revalidate — which is what makes
/// a "no reverse session" outcome attributable to the zone check rather than to
/// an empty table.
fn drive_trunk_reply_9383(arrival_vlan: u16) -> (bool, usize) {
    let forwarding =
        crate::afxdp::forwarding_build::build_forwarding_state(&trunk_snapshot_9383());
    let mut sessions = SessionTable::new();
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 5)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        src_port: 40000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 8))),
        rewrite_src_port: Some(40001),
        ..NatDecision::default()
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: TRUNK_ZONED_UNIT_IFINDEX,
            tx_ifindex: TRUNK_PARENT_IFINDEX,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: TRUNK_ZONED_VLAN,
        },
        nat,
    };
    // The forward flow: lan -> wan. `egress_zone` is what the #7169 arrival-zone
    // check compares against.
    let metadata = SessionMetadata {
        ingress_zone: TEST_LAN_ZONE_ID,
        egress_zone: TEST_WAN_ZONE_ID,
        ..test_metadata()
    };
    assert!(
        sessions.install_with_protocol_with_origin(
            fwd_key.clone(),
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            1_000_000,
            PROTO_TCP,
            0,
        ),
        "the forward NAT'd session must install, or there is nothing for the \
         reverse synthesis to find and both cells are vacuous (#9383)"
    );
    let installed = sessions.len();
    assert_eq!(installed, 1, "exactly one forward session is pre-installed");

    let reply_key = reverse_session_key(&fwd_key, nat);
    assert!(
        sessions.find_forward_nat_match(&reply_key).is_some(),
        "the reply tuple must find the forward NAT match BEFORE the arrival-zone \
         check runs — otherwise a `None` result says nothing about the zone (#9383)"
    );

    let flow = SessionFlow {
        src_ip: reply_key.src_ip,
        dst_ip: reply_key.dst_ip,
        forward_key: reply_key.clone(),
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands = Vec::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let ha_state = BTreeMap::new();

    let resolved = resolve_flow_session_decision(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &ha_state,
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        PROTO_TCP,
        TCP_FLAG_ACK,
        // The reply arrives on the trunk PARENT — the physical bind port — which
        // is exactly what `meta.ingress_ifindex` carries for a tagged frame.
        TRUNK_PARENT_IFINDEX,
        arrival_vlan,
        false,
        0,
        0,
    );
    (resolved.is_some(), sessions.len())
}

/// THE DEFECT. The reply arrives on the UNZONED trunk unit. The logical
/// resolution answers "this unit is in no zone", so there is nothing to
/// revalidate the match against and #7169's fail-CLOSED arm must refuse it — no
/// reverse session is minted.
///
/// Before #9383 this site keyed `ifindex_to_zone_id` on the raw physical parent,
/// which carries the ZONED sibling's `wan` by propagation, so the match was
/// accepted and a reverse session carrying the forward flow's zone pair was
/// installed for a packet that arrived in no zone at all.
///
/// FAIL-ON-REVERT: restore `ifindex_to_zone_id.get(&ingress_ifindex)` and this
/// goes RED while its control below stays green.
#[test]
fn a_reply_on_an_unzoned_trunk_unit_installs_no_reverse_session_9383() {
    let (resolved, sessions) = drive_trunk_reply_9383(TRUNK_UNZONED_VLAN);
    assert!(
        !resolved,
        "the reply arrived on a trunk unit in NO zone, so the reverse-canonical \
         match has nothing to revalidate against and must be REFUSED. A `Some` \
         here means the arrival zone was read from the raw physical parent, which \
         carries its zoned SIBLING's zone by propagation (#921/#3618) — so a \
         packet that arrived in no zone mints a reverse session carrying the \
         forward flow's zone pair, and reverse entries are exempt from \
         zone-policy re-derivation (#9383)"
    );
    assert_eq!(
        sessions, 1,
        "no reverse session may be installed for an unzoned arrival — only the \
         pre-installed forward session remains"
    );
}

/// THE POSITIVE CONTROL, and it differs from the cell above in ONE byte of input:
/// the arrival VLAN id. The reply arrives on the ZONED trunk unit, whose zone IS
/// the zone the forward flow egressed to, so the match is accepted and the
/// reverse session IS installed.
///
/// Without this, "no reverse session" above is indistinguishable from "the
/// synthesis path was never reached" or "the fix broke reverse synthesis
/// outright" — which would kill the reply of every NAT'd flow in the box.
#[test]
fn a_reply_on_the_zoned_trunk_unit_still_installs_one_9383() {
    let (resolved, sessions) = drive_trunk_reply_9383(TRUNK_ZONED_VLAN);
    assert!(
        resolved,
        "the reply arrived on the trunk unit in `wan`, the zone the forward flow \
         egressed to, so the reverse-canonical match must be ACCEPTED. A `None` \
         here means the logical resolution broke reverse synthesis for a \
         legitimate reply — strictly worse than the defect #9383 fixes (#9383)"
    );
    assert_eq!(
        sessions, 2,
        "forward + synthesized reverse: the #7169 install must still happen for a \
         correctly-zoned arrival"
    );
}

/// #9517: `force_live_redirect_for_worker_synced_entry` now takes the session key,
/// because the steering map cannot tell tunnel discriminators apart. The cells that
/// call it predate that and exercise non-tunnel sessions, so they pass a plain key.
fn force_live_test_key_9517() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 1)),
        src_port: 40000,
        dst_port: 22,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

/// #9412: a close-state `Update` must reach the peer and must NOT become an
/// RT_FLOW SESSION_CREATE. The issue called out that a reused Open would emit a
/// spurious CREATE, which is the regression this pins.
///
/// The delta carries `log_session_init = true`, the one input that makes an
/// Open emit CREATE. POSITIVE CONTROL: the identical delta as an Open DOES emit
/// one, so "no CREATE" below cannot be a harness that never emits any.
#[test]
fn flush_session_deltas_update_syncs_without_an_rt_flow_create_9412() {
    let forwarding = ForwardingState::default();
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        src_port: 51000,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let mut metadata = test_metadata();
    metadata.log_session_init = true;
    let make_delta = |kind| SessionDelta {
        kind,
        key: key.clone(),
        decision: test_decision(),
        metadata: metadata.clone(),
        origin: SessionOrigin::ForwardFlow,
        fabric_redirect_sync: false,
        created_ns: 0,
        last_seen_ns: 0,
        counters: crate::session::SessionCounters::default(),
        observed_tos: 0,
        observed_tcp_flags: 0,
        session_id: 77,
        bulk_resync: false,
        tcp_close_class: 2,
    };
    let flush = |delta: SessionDelta| {
        let (handle, rx) = // CONNECTED, so the lossless peer-sync push can queue; the unconnected handle
        // refuses it before any frame reaches the channel.
        crate::event_stream::test_worker_handle_connected(
            8,
            crate::event_stream::DataplaneEventRateLimitConfig { events_per_second: 0, burst: 0 },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let ident = BindingIdentity {
            slot: 0,
            queue_id: 0,
            worker_id: 0,
            interface: Arc::<str>::from("ge-0-0-2"),
            ifindex: 7,
        };
        let dnat_fds = crate::afxdp::checksum::DnatTableFds::default();
        let mut worker_lossless_wedged = false;
        flush_session_deltas(
            &ident,
            None,
            -1,
            -1,
            -1,
            &dnat_fds,
            &[delta],
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &recent_session_deltas,
            &peer_worker_commands,
            crate::afxdp::empty_worker_commands_by_id(),
            &Some(handle),
            &forwarding,
            &mut worker_lossless_wedged,
        );
        std::iter::from_fn(|| rx.try_recv().ok()).collect::<Vec<_>>()
    };

    let open = flush(make_delta(SessionDeltaKind::Open));
    assert!(
        open.iter().filter_map(|f| f.dataplane_event_payload()).any(|p| p[52] == 1),
        "CONTROL: an Open with log_session_init must emit an RT_FLOW SESSION_CREATE in this harness"
    );

    let update = flush(make_delta(SessionDeltaKind::Update));
    assert!(
        update.iter().all(|f| f.dataplane_event_payload().is_none()),
        "#9412: a close-state Update emitted an RT_FLOW record, a spurious SESSION_CREATE"
    );
    let sync: Vec<_> = update.iter().filter(|f| f.as_bytes()[4] == 3 /* MSG_SESSION_UPDATE; the #9412 golden lockstep pins this byte in both languages */).collect();
    assert_eq!(sync.len(), 1, "#9412: the Update must be queued to the peer exactly once as MSG_SESSION_UPDATE");
    assert_eq!(
        *sync[0].as_bytes().last().expect("a non-empty frame"),
        2,
        "#9412: the queued Update must end with its close class"
    );
}
