//! #16185: distinct-value wiring cells for the extended
//! `SharedSessionRefs` bundle (the #6961 mechanism applied to
//! signatures). The bundle removes the repeated bare-scalar
//! threading (two `c_int` fds and two `u64` clocks at every call
//! site, each a same-typed neighbour the compiler could not
//! distinguish), but named fields alone do not make a transposition
//! uncompilable: `v4: <the v6 fd>` still type-checks. What these
//! cells pin is narrower and honest: the bundle's named fields are
//! the values each consumer actually reads.
//! Coverage by field: cell 1 pins the shared sessions map and the
//! peer queue on the plain promote leg (which is the no-conntrack
//! wrapper, so it says nothing about fds); cell 4 pins
//! `ConntrackFds.v4` and the deferred-promotion `Tick.ns` graft on
//! the `_with_conntrack` promotion leg (origin-bit write — that
//! seam is family-dispatched in production code, so the legacy
//! sentinel in `v4` is genuinely transposition-sensitive there);
//! cell 2 pins `ConntrackFds.v4` + peer queue on the purge leg,
//! where the delete seam accepts the legacy sentinel in either
//! slot, so cell 2 uses the family-sensitive
//! `CONNTRACK_TEST_MAP_FD_V6` in `v4` (#16261); cell 3 pins
//! only the `detached`/`with_conntrack_tick` constructor values.
//! No cell observes a `Tick.secs` consumer: the resolve path's
//! seconds reading is exercised by the existing HA resolution
//! tests through their own bundles, not asserted here.

use super::*;
use std::net::{IpAddr, Ipv4Addr};

fn wiring_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
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
        nat_scope_ifindex: None,
    }
}

fn wiring_decision() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn wiring_key() -> SessionKey {
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

fn wiring_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_name_to_id.insert("lan".to_string(), 1);
    forwarding.zone_name_to_id.insert("wan".to_string(), 2);
    forwarding.zone_set_validated = true;
    forwarding
}

/// #16185 wiring cell 1: the plain promote leg publishes into the
/// bundle's shared sessions map and replicates on its peer queue.
///
/// This entry point is the documented no-conntrack wrapper (it
/// forces the fds to `-1,-1` inside), so this cell makes no fd or
/// timestamp claim; the conntrack origin-bit write is pinned by
/// cell 4 on the `_with_conntrack` leg.
#[test]
fn shared_refs_maps_and_peer_queue_reach_promote_16185() {
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    let key = wiring_key();
    let decision = wiring_decision();
    let metadata = wiring_metadata();
    // Seed the conntrack row as a peer-synced (cluster_synced) row.
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            -1,
            &key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            0,
            1,
            300,
            SessionOrigin::SyncImport,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written,
    );
    assert!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&key).is_some_and(|row| row.cluster_synced),
        "precondition: seeded row is cluster-synced",
    );

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let _ = sessions.drain_deltas(16);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_queue = Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands = vec![peer_queue.clone()];
    let by_id = WorkerCommandQueues::new(BTreeMap::from([(7u32, peer_queue.clone())]));

    let shared = SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: &by_id,
        conntrack: ConntrackFds {
            v4: crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            v6: -1,
        },
        tick: Tick {
            ns: 2_000_000,
            secs: 9,
        },
    };
    let promoted = maybe_promote_synced_session(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        shared,
        &wiring_forwarding(),
        &key,
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        false,
        PROTO_TCP,
        0x10,
        SessionHitVerdict::Owner,
    );
    assert_eq!(promoted, metadata);

    // The shared maps in the bundle received the promoted entry.
    assert_eq!(
        lock_shared_recover(&shared_sessions)
            .get(&key)
            .map(|entry| entry.origin),
        Some(SessionOrigin::SharedPromote),
        "#16185: promoted entry must land in SharedSessionRefs.sessions",
    );
    // The bundle's peer queue received the upsert replica.
    {
        let pending = peer_queue.lock().unwrap();
        assert!(
            pending.iter().any(|cmd| matches!(
                cmd,
                WorkerCommand::UpsertSynced(entry) if entry.key == key
            )),
            "#16185: upsert replica must reach SharedSessionRefs.peer_worker_commands, got {pending:?}",
        );
    }
}

/// #16185 wiring cell 2: the purge leg consumes `ConntrackFds.v4` and
/// the bundle's peer queue, on `purge_translated_synced_hit_with_context`
/// via the deferred purge in `maybe_promote_synced_session_with_conntrack`.
///
/// #16261 family-sensitive form: the bundle carries
/// `v4 = CONNTRACK_TEST_MAP_FD_V6` (recognised only in the slot
/// matching the key's family) and `v6 = -1`, deliberately NOT the
/// old `CONNTRACK_TEST_MAP_FD` sentinel: the delete seams accept
/// that sentinel in either slot, so with it a transposed bundle
/// (`v4: -1, v6: <sentinel>`) would still delete this IPv4 row and
/// the cell would pass on swapped wiring. With the family-sensitive
/// sentinel a transposition reaches the real-BPF branch on a
/// negative fd, the lookup errors, and the row survives — turning
/// this cell red. The key stays IPv4 (the purge leg's translated
/// forward key is derived from the IPv4 fixture); a v6 purge key
/// would need a NAT64 fixture this cell does not build.
#[test]
fn shared_refs_conntrack_v4_reaches_purge_16185() {
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    let orig_key = wiring_key();
    let nat = NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
        rewrite_src_port: Some(40000),
        ..NatDecision::default()
    };
    let wire_key = forward_wire_key(&orig_key, nat);
    let decision = SessionDecision {
        resolution: wiring_decision().resolution,
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = wiring_metadata();
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            -1,
            &wire_key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            0,
            1,
            300,
            SessionOrigin::SyncImport,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written,
    );

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        wire_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let _ = sessions.drain_deltas(16);

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
            key: wire_key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            session_id: 1,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            pptp_call_ids: 0,
            rev_packets: 0,
            source_nat_static: None,
            leak_incarnation: 0,
            tcp_flags: 0x10,
            generation: 0,
            fwd_packets: 0,
            rev_packets: 0,
        },
    );
    let peer_queue = Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands = vec![peer_queue.clone()];
    let shared = SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: empty_worker_commands_by_id(),
        conntrack: ConntrackFds {
            v4: crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD_V6,
            v6: -1,
        },
        tick: Tick {
            ns: 1_000_000,
            secs: 9,
        },
    };
    let mut resolved = ResolvedFlowSessionDecision {
        key: wire_key.clone(),
        session_id: 1,
        timeout_secs: 300,
        decision,
        source_nat_static: None,
        metadata: metadata.clone(),
        origin: SessionOrigin::SyncImport,
        source_nat_validation_key: None,
        created: false,
        install_failed: false,
        authority_deferred: false,
        deferred_forwarding_revalidation: None,
        deferred_synced_promotion: None,
        deferred_shared_materialization: None,
        deferred_synced_purge: Some(DeferredSyncedPurge {
            key: wire_key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: SessionOrigin::SyncImport,
            shared_identity: Some((1, 0)),
        }),
    };
    let mut evicted_keys: Vec<SessionKey> = Vec::new();
    maybe_promote_synced_session_with_conntrack(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        shared,
        &wiring_forwarding(),
        0x10,
        0,
        SessionHitVerdict::Owner,
        &mut resolved,
        &mut evicted_keys,
    );
    assert!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&wire_key).is_none(),
        "#16185: purge must delete the conntrack row through ConntrackFds.v4 \
         (a v4/v6 transposition leaves it present)",
    );
    assert!(
        evicted_keys.contains(&wire_key),
        "#16185: purge must record the evicted key, got {evicted_keys:?}",
    );
    {
        let pending = peer_queue.lock().unwrap();
        assert!(
            pending.iter().any(|cmd| matches!(
                cmd,
                WorkerCommand::DeleteSyncedConditional { key, expected_id, companion: None, .. }
                    if *key == wire_key && *expected_id == 1
            )),
            "#16185: purge must queue the conditional delete on the bundle peer queue, got {pending:?}",
        );
    }
}

/// #16185 wiring cell 3: constructor values only. `detached` is
/// the documented no-conntrack/no-clock form (`-1, -1`, zero tick)
/// and `with_conntrack_tick` grafts exactly the named fields. This
/// cell calls no timestamp or fd consumer; consumers are pinned by
/// cells 2 and 4.
#[test]
fn shared_refs_detached_is_no_conntrack_no_clock_16185() {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let shared = SharedSessionRefs::detached(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        empty_worker_commands_by_id(),
    );
    assert_eq!(shared.conntrack, ConntrackFds { v4: -1, v6: -1 });
    assert_eq!(shared.tick, Tick { ns: 0, secs: 0 });
    // with_conntrack_tick grafts exactly the named fields.
    let grafted =
        shared.with_conntrack_tick(ConntrackFds { v4: 11, v6: 22 }, Tick { ns: 33, secs: 44 });
    assert_eq!(grafted.conntrack, ConntrackFds { v4: 11, v6: 22 });
    assert_eq!(grafted.tick, Tick { ns: 33, secs: 44 });
    assert!(std::ptr::eq(grafted.sessions, &shared_sessions));
}

/// #16185 wiring cell 4: the deferred-promotion leg of
/// `maybe_promote_synced_session_with_conntrack` consumes
/// `ConntrackFds.v4` for the origin-bit write and grafts the
/// deferred promotion's own `now_ns` (not the bundle tick).
///
/// The conntrack row is seeded cluster-synced through the v4 test
/// fd; the bundle carries `v4 = CONNTRACK_TEST_MAP_FD, v6 = -1`
/// and a deliberately different bundle tick (`ns: 5`). The
/// deferred promotion carries `now_ns: 2_000_000`. After the call
/// the row's `cluster_synced` must be false: a v4/v6 transposition
/// at this construction (or inside `promote.rs`) sends the write
/// to `-1` and leaves it set.
#[test]
fn shared_refs_conntrack_v4_reaches_deferred_promotion_16185() {
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    let key = wiring_key();
    let decision = wiring_decision();
    let metadata = wiring_metadata();
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            -1,
            &key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            0,
            1,
            300,
            SessionOrigin::SyncImport,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written,
    );
    assert!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&key)
            .is_some_and(|row| row.cluster_synced),
        "precondition: seeded row is cluster-synced",
    );

    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let _ = sessions.drain_deltas(16);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_queue = Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands = vec![peer_queue.clone()];
    let shared = SharedSessionRefs {
        sessions: &shared_sessions,
        nat_sessions: &shared_nat_sessions,
        forward_wire_sessions: &shared_forward_wire_sessions,
        owner_rg_indexes: &shared_owner_rg_indexes,
        peer_worker_commands: &peer_worker_commands,
        worker_commands_by_id: empty_worker_commands_by_id(),
        conntrack: ConntrackFds {
            v4: crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            v6: -1,
        },
        tick: Tick { ns: 5, secs: 9 },
    };
    let mut resolved = ResolvedFlowSessionDecision {
        key: key.clone(),
        session_id: 1,
        timeout_secs: 300,
        decision,
        source_nat_static: None,
        metadata: metadata.clone(),
        origin: SessionOrigin::SyncImport,
        source_nat_validation_key: None,
        created: false,
        install_failed: false,
        authority_deferred: false,
        deferred_forwarding_revalidation: None,
        deferred_synced_promotion: Some(DeferredSyncedPromotion {
            key: key.clone(),
            decision,
            metadata: metadata.clone(),
            origin: SessionOrigin::SyncImport,
            fabric_ingress: false,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
            now_ns: 2_000_000,
        }),
        deferred_shared_materialization: None,
        deferred_synced_purge: None,
    };
    let mut evicted_keys: Vec<SessionKey> = Vec::new();
    maybe_promote_synced_session_with_conntrack(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        shared,
        &wiring_forwarding(),
        0x10,
        0,
        SessionHitVerdict::Owner,
        &mut resolved,
        &mut evicted_keys,
    );
    let row = crate::afxdp::bpf_map::conntrack_row_for_test(&key)
        .expect("conntrack row still present after deferred promotion");
    assert!(
        !row.cluster_synced,
        "#16185: deferred promotion must clear the synced origin bit through \
         ConntrackFds.v4 (a v4/v6 transposition leaves it set)",
    );
    assert_eq!(
        lock_shared_recover(&shared_sessions)
            .get(&key)
            .map(|entry| entry.origin),
        Some(SessionOrigin::SharedPromote),
        "#16185: deferred promotion must publish SharedPromote into the bundle sessions map",
    );
    // The promotion must be stamped with the deferred promotion's own
    // now_ns (2_000_000), not the bundle tick (ns: 5): promote grafts
    // promotion.now_ns into shared.tick.ns, which SessionUpdate
    // writes as last_seen_ns. Reading 5 here would mean the graft
    // consumed the bundle clock instead.
    assert_eq!(
        sessions.last_seen_ns(&key),
        Some(2_000_000),
        "#16185: deferred promotion must stamp last_seen_ns from promotion.now_ns, not the bundle tick",
    );
}
