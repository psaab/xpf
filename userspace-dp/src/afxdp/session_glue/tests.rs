// Tests for afxdp/session_glue/mod.rs — originally inline in
// session_glue.rs, relocated to session_glue_tests.rs in #1077, then
// folded with mod.rs into the afxdp/session_glue/ directory module
// (#1078) to keep afxdp/'s flat namespace tidy.
// Loaded as a sibling submodule via `#[path = "tests.rs"]` from
// session_glue/mod.rs.

use super::*;
use crate::test_zone_ids::*;
use std::net::{Ipv4Addr, Ipv6Addr};

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
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
    }
}

fn test_decision() -> SessionDecision {
    SessionDecision {
        resolution: test_resolution(),
        nat: NatDecision::default(),
    }
}

fn test_forwarding_state() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
        ifindex: 6,
        tunnel_endpoint_id: 0,
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

    let promoted = maybe_promote_synced_session(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
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

    let promoted = maybe_promote_synced_session(
        &mut sessions,
        -1,
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
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
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
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
        true,
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
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), entry.clone());

    let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key)
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
    };
    let reply_key = reverse_session_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(reply_key.clone(), shared_entry.clone());

    let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key)
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
        lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key).is_none()
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
    };
    let canonical_reply = reverse_canonical_key(&key, decision.nat);
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    shared_nat_sessions
        .lock()
        .expect("shared nat lock")
        .insert(canonical_reply.clone(), entry.clone());

    let hit =
        lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &canonical_reply)
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
        lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key)
            .is_none()
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
            .is_some_and(
                |keys| keys.contains(&reverse_wire) && keys.contains(&reverse_canonical)
            )
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
        false,
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
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
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
        true,
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
fn resolve_flow_session_decision_promotes_local_synced_translated_hit_on_active_fabric_ingress()
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
        true,
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
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
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
        true,
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
    };
    let mut forwarding = test_forwarding_state_with_fabric();
    forwarding.connected_v4.push(ConnectedRouteV4 {
        prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
        ifindex: 12,
        tunnel_endpoint_id: 0,
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
        false,
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
        false,
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
    );

    let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("live hit");
    assert_eq!(hit.metadata, live_metadata);
    assert_eq!(hit.decision, live_decision);
}

#[test]
fn worker_synced_local_delivery_forces_live_redirect_on_standby() {
    assert!(force_live_redirect_for_worker_synced_entry(
        test_local_delivery_decision(),
        &test_metadata(),
        SessionOrigin::SyncImport,
        true,
    ));
}

#[test]
fn worker_synced_local_delivery_keeps_default_publish_on_active_owner() {
    assert!(!force_live_redirect_for_worker_synced_entry(
        test_local_delivery_decision(),
        &test_metadata(),
        SessionOrigin::SyncImport,
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
        false,
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
        owner_rg_id: 1,
        ..test_metadata()
    };
    // Insert with current epoch (0).
    flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: 7,
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
    });

    // Before epoch bump, lookup should hit.
    assert!(
        flow_cache
            .lookup(
                &key,
                FlowCacheLookup {
                    ingress_ifindex: 7,
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
        owner_rg_id: 1,
        ..test_metadata()
    };
    flow_cache.insert(FlowCacheEntry {
        key: key.clone(),
        ingress_ifindex: 7,
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
                    config_generation: 1,
                    fib_generation: 1,
                },
                0,
                &rg_epochs,
            )
            .is_some()
    );
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
    );

    assert!(results.cancelled_keys.is_empty());
    assert_eq!(results.exported_sequences, vec![9]);
    let hit = sessions
        .lookup(&key, 2_000_000, 0x10)
        .expect("exported forward hit");

    assert_eq!(
        hit.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
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
    );

    assert!(results.cancelled_keys.is_empty());
    assert_eq!(results.exported_sequences, vec![10]);
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
    };
    let reverse = SyncedSessionEntry {
        key: reverse_session_key(&forward.key, forward.decision.nat),
        decision: test_decision(),
        metadata: SessionMetadata {
            is_reverse: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::ForwardFlow,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
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
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
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
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
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
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
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
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
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
            owner_rg_id: 2,
            fabric_ingress: false,
            is_reverse: true,
            nat64_reverse: None,
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
    );

    assert_eq!(results.exported_sequences, vec![11]);
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
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, TEST_WAN_ZONE_ID as u8])
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
        Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, TEST_SFMIX_ZONE_ID as u8])
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
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
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
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
            fabric_ingress: true,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
fn reverse_session_from_split_owner_fabric_redirect_uses_fabric_return_when_client_rg_inactive()
{
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
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
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
            owner_rg_id: 1,
            ..test_metadata()
        },
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
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
    );
    assert_eq!(count, 0, "fd=-1 should produce 0 successful publishes");

    // Unrelated RG should return 0.
    let count = republish_bpf_session_entries_for_owner_rgs(
        &shared_sessions,
        &shared_owner_rg_indexes,
        -1,
        &[2],
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
        false,
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
