//! Tests for `policy_revalidation`, split into a sibling file by #11600 to
//! hold the parent under the 2000-LOC [REFACTOR] floor (the same `#[path]`
//! convention as `session_hit_authority_tests.rs`). Pins the #10038
//! TUN-origin discriminator and the #11075 route-change alarm edge.

use super::*;

/// #11075: the route-change alarm fires exactly when a generation step
/// lands with live sessions, rate-limited to one line per interval.
#[test]
fn route_change_alarm_edge_matrix_11075() {
    // Advance + live sessions + never alarmed -> fire.
    assert!(should_alarm_route_change(7, 8, 100, 0, 1_000));
    // Same generation -> silent.
    assert!(!should_alarm_route_change(8, 8, 100, 0, 1_000));
    // No live sessions -> silent.
    assert!(!should_alarm_route_change(7, 8, 0, 0, 1_000));
    // Within the interval -> silent.
    assert!(!should_alarm_route_change(
        7,
        8,
        100,
        1_000,
        1_000 + ROUTE_CHANGE_ALARM_INTERVAL_NS - 1
    ));
    // Past the interval -> fire again.
    assert!(should_alarm_route_change(
        7,
        8,
        100,
        1_000,
        1_000 + ROUTE_CHANGE_ALARM_INTERVAL_NS
    ));
}

fn marker_forward_10038() -> (SessionDecision, SessionMetadata, SessionOrigin) {
    (
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 400,
                tx_ifindex: 6,
                tunnel_endpoint_id: 1,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        SessionMetadata {
            ingress_zone: 5,
            egress_zone: 5,
            ingress_zone_check: 0,
            egress_zone_check: 0,
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
        SessionOrigin::TunOrigin,
    )
}

/// #10038: the discriminator truth table — positive provenance. ONLY
/// `TunOrigin` matches; every other origin (the full HA-synced family
/// included — a `SyncImport` is NEVER TUN-origin, however closely its
/// metadata aliases) fails, as does flipping any shape conjunct alone.
#[test]
fn tun_origin_forward_table_10038() {
    let (decision, metadata, origin) = marker_forward_10038();
    assert!(tun_origin_forward(&decision, &metadata, origin));
    // Every other origin fails — including the whole HA-synced family:
    // SyncImport (the legacy-transit alias — see the dedicated cell
    // below), SharedMaterialize, WorkerLocalImport, SharedPromote (TUN
    // never promotes, so a promoted entry is by definition not TUN),
    // ForwardFlow/ReverseFlow (MISS installs, the spoof-plant shape),
    // LocalMiss and the transient seeds.
    for origin in [
        SessionOrigin::SyncImport,
        SessionOrigin::SharedMaterialize,
        SessionOrigin::WorkerLocalImport,
        SessionOrigin::SharedPromote,
        SessionOrigin::ForwardFlow,
        SessionOrigin::ReverseFlow,
        SessionOrigin::LocalMiss,
        SessionOrigin::MissingNeighborSeed,
        SessionOrigin::FabricPuntSeed,
    ] {
        assert!(
            !tun_origin_forward(&decision, &metadata, origin),
            "{origin:?} must not match"
        );
    }
    // Each remaining conjunct flipped alone.
    let mut rev = metadata.clone();
    rev.is_reverse = true;
    assert!(!tun_origin_forward(&decision, &rev, origin));
    let mut ingress = metadata.clone();
    ingress.ingress_ifindex = 400;
    assert!(!tun_origin_forward(&decision, &ingress, origin));
    let mut untunneled = decision;
    untunneled.resolution.tunnel_endpoint_id = 0;
    assert!(!tun_origin_forward(&untunneled, &metadata, origin));
    let mut admitted = metadata.clone();
    admitted.policy_counter_idx = 1;
    assert!(!tun_origin_forward(&decision, &admitted, origin));
}

/// #10038: the exemption's companion lookup — local-first (a non-marker
/// local forward DECIDES, shadowing a shared marker), shared-only marker
/// exempts (the WG production shape), lone reverse fails closed, and a
/// degenerate self-inverse key fails closed.
#[test]
fn tun_origin_reverse_exempt_lookup_10038() {
    let nat = NatDecision::default();
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 1)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 5)),
        src_port: 5001,
        dst_port: 5002,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let rev_key = crate::session::reverse_session_key(&fwd_key, nat);
    assert_ne!(fwd_key, rev_key);
    let (decision, metadata, _) = marker_forward_10038();
    let install_local =
        |sessions: &mut SessionTable, origin: SessionOrigin, ingress: u32, policy_idx: u32| {
            let mut meta = metadata.clone();
            meta.ingress_ifindex = ingress;
            meta.policy_counter_idx = policy_idx;
            assert!(
                sessions.install_with_protocol_with_origin(
                    fwd_key.clone(),
                    decision,
                    meta,
                    origin,
                    122_000_000_000,
                    17,
                    0,
                ),
                "local forward must install"
            );
        };
    let shared_entry = |origin: SessionOrigin| SyncedSessionEntry { key: fwd_key.clone(),
    decision,
    metadata: metadata.clone(),
    leak_incarnation: 0,
    origin,
    protocol: 17,
    tcp_flags: 0,
    generation: 0,
    session_id: 0,
    tcp_close_class: 0,
    tcp_handshake_state: 0, source_nat_static: None };
    let fresh_shared = || Arc::new(Mutex::new(FastMap::default()));

    // Local marker → exempt.
    let mut sessions = SessionTable::new();
    install_local(&mut sessions, SessionOrigin::TunOrigin, 0, 0);
    assert!(tun_origin_reverse_exempt(
        &sessions,
        &fresh_shared(),
        &rev_key,
        nat
    ));

    // Local non-marker + shared marker → DENY (local shadows shared).
    let mut sessions = SessionTable::new();
    install_local(&mut sessions, SessionOrigin::ForwardFlow, 400, 1);
    let shared = fresh_shared();
    shared
        .lock()
        .expect("shared map")
        .insert(fwd_key.clone(), shared_entry(SessionOrigin::TunOrigin));
    assert!(!tun_origin_reverse_exempt(
        &sessions, &shared, &rev_key, nat
    ));

    // Shared-only marker → exempt (WG production: the forward never
    // materializes locally).
    let sessions = SessionTable::new();
    let shared = fresh_shared();
    shared
        .lock()
        .expect("shared map")
        .insert(fwd_key.clone(), shared_entry(SessionOrigin::TunOrigin));
    assert!(tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat));

    // Shared-only non-marker → deny.
    let sessions = SessionTable::new();
    let shared = fresh_shared();
    shared
        .lock()
        .expect("shared map")
        .insert(fwd_key.clone(), shared_entry(SessionOrigin::ForwardFlow));
    assert!(!tun_origin_reverse_exempt(
        &sessions, &shared, &rev_key, nat
    ));

    // Lone reverse (no forward anywhere) → deny (fail-closed).
    let sessions = SessionTable::new();
    assert!(!tun_origin_reverse_exempt(
        &sessions,
        &fresh_shared(),
        &rev_key,
        nat
    ));

    // Degenerate self-inverse key (src==dst, ports equal) → deny.
    let loop_key = SessionKey {
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        src_port: 5,
        dst_port: 5,
        ..fwd_key.clone()
    };
    assert_eq!(
        crate::session::reverse_session_key(&loop_key, nat),
        loop_key
    );
    let sessions = SessionTable::new();
    assert!(!tun_origin_reverse_exempt(
        &sessions,
        &fresh_shared(),
        &loop_key,
        nat
    ));
}

/// #10522 Cell 3: an owner-arrival reverse LocalDelivery with a
/// TUN-origin forward companion is exempt from the two NEW-session gates.
/// That exemption is an explicit per-packet proof and keeps the trusted
/// outlet positive control intact.
#[test]
fn tun_origin_reverse_exempt_gate_proof_selects_trusted_10522() {
    let nat = NatDecision::default();
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 1)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 5)),
        src_port: 5001,
        dst_port: 5002,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let rev_key = crate::session::reverse_session_key(&fwd_key, nat);
    let (decision, metadata, _) = marker_forward_10038();
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        fwd_key,
        decision,
        metadata,
        SessionOrigin::TunOrigin,
        122_000_000_000,
        17,
        0,
    ));
    let shared = Arc::new(Mutex::new(FastMap::default()));
    let gate_proof = tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat);
    assert!(gate_proof, "owner-arrival TUN-origin reply must be exempt");
    assert!(
        crate::afxdp::tx::dispatch::reinject_host_authorized(
            ForwardingDisposition::LocalDelivery,
            gate_proof,
        ),
        "the exemption proof must preserve the trusted LocalDelivery outlet",
    );
}

/// Parent-review item 5: the legacy-HA-transit alias is closed. A
/// legacy-peer's transit import — `SyncImport`, tunnel egress, folded
/// zero ingress, zeroed counter (`session_sync.rs` defaults missing
/// fields to 0), even a PRESERVED admitting PolicyID (per
/// `sync_gen_guard_test.go`) — satisfies every shape conjunct yet must
/// NOT match: only positive `TunOrigin` provenance matches. Pinned at
/// both the predicate and the exemption-lookup level.
#[test]
fn tun_origin_legacy_ha_transit_import_does_not_match_10038() {
    let (decision, mut metadata, _) = marker_forward_10038();
    // The legacy import shape: admitting PolicyID preserved, counter
    // zeroed by wire truncation.
    metadata.policy_id = 41;
    assert!(
        !tun_origin_forward(&decision, &metadata, SessionOrigin::SyncImport),
        "a legacy transit import must not match, PolicyID or not"
    );
    // And through the exemption lookup: a shared SyncImport alias-shape
    // forward must not exempt its reverse.
    let nat = NatDecision::default();
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 17,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 1)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 5)),
        src_port: 5001,
        dst_port: 5002,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let rev_key = crate::session::reverse_session_key(&fwd_key, nat);
    let sessions = SessionTable::new();
    let shared = Arc::new(Mutex::new(FastMap::default()));
    shared.lock().expect("shared map").insert(
        fwd_key.clone(),
        SyncedSessionEntry { key: fwd_key.clone(),
        decision,
        metadata,
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
        protocol: 17,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0, source_nat_static: None },
    );
    assert!(
        !tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat),
        "a legacy alias-shape forward must not exempt"
    );
    // Provenance lifecycle: local (never peer-synced, never promoted),
    // preserved across materialize/replica (else the first HIT would
    // re-tag the marker away).
    assert!(SessionOrigin::TunOrigin.is_local_tun_origin());
    assert!(!SessionOrigin::TunOrigin.is_peer_synced());
    assert!(!SessionOrigin::TunOrigin.is_promotable_synced());
    assert_eq!(
        SessionOrigin::TunOrigin.materialized_shared_hit_origin(),
        SessionOrigin::TunOrigin
    );
    assert_eq!(
        SessionOrigin::TunOrigin.worker_replica_origin(),
        SessionOrigin::TunOrigin
    );
}

fn gate_current_base_10507() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 24,
        tx_ifindex: 24,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

/// #10507 rule-4 mapping pin: only would-forward WITH a valid egress
/// is LocalForwarding; would-forward WITHOUT egress is NoEgress
/// (fail-closed), never NonLocal (which would coast/retain). All
/// other dispositions map NonLocal via the wildcard arm.
#[test]
fn gate_current_splits_noegress_from_nonlocal_10507() {
    assert_eq!(
        policy_gate_current_for_resolution(gate_current_base_10507()),
        PolicyGateCurrent::LocalForwarding
    );
    let mut noegress = gate_current_base_10507();
    noegress.egress_ifindex = 0;
    noegress.tx_ifindex = 0;
    assert_eq!(
        policy_gate_current_for_resolution(noegress),
        PolicyGateCurrent::LocalForwardingNoEgress,
        "would-forward without egress is rule-4 fail-closed, never NonLocal"
    );
    let mut missing = gate_current_base_10507();
    missing.disposition = ForwardingDisposition::MissingNeighbor;
    assert_eq!(
        policy_gate_current_for_resolution(missing),
        PolicyGateCurrent::LocalForwarding
    );
    let mut missing_noegress = gate_current_base_10507();
    missing_noegress.disposition = ForwardingDisposition::MissingNeighbor;
    missing_noegress.egress_ifindex = 0;
    assert_eq!(
        policy_gate_current_for_resolution(missing_noegress),
        PolicyGateCurrent::LocalForwardingNoEgress
    );
    for disposition in [
        ForwardingDisposition::FabricRedirect,
        ForwardingDisposition::NoRoute,
        ForwardingDisposition::HAInactive,
        ForwardingDisposition::TableUnavailable,
        ForwardingDisposition::LocalDelivery,
        ForwardingDisposition::PolicyDenied,
        ForwardingDisposition::DiscardRoute,
        ForwardingDisposition::NextTableUnsupported,
    ] {
        let mut nonlocal = gate_current_base_10507();
        nonlocal.disposition = disposition;
        nonlocal.egress_ifindex = 0;
        assert_eq!(
            policy_gate_current_for_resolution(nonlocal),
            PolicyGateCurrent::NonLocal,
            "non-local dispositions stay NonLocal even with egress 0 (#9513 retention)"
        );
    }
}

fn imported_snat_forwarding(with_static: bool) -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.egress.insert(
        12,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 2,
            redundancy_group: 0,
            primary_v4: Some("203.0.113.254".parse().expect("egress IPv4")),
            primary_v6: None,
        },
    );
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::protocol::SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        },
    ]);
    if with_static {
        forwarding.static_nat = crate::nat::StaticNatTable::from_snapshots(
            &[crate::protocol::StaticNATRuleSnapshot {
                name: "static-snat".to_string(),
                from_zone: "wan".to_string(),
                external_ip: "203.0.113.10".to_string(),
                internal_ip: "10.0.0.1".to_string(),
                match_destination_port: 45_000,
                mapped_port: 45_000,
                ..Default::default()
            }],
            &crate::nat::NatCounterStore::default(),
        );
    }
    forwarding
}

fn imported_snat_request(source_nat_provenance: u8) -> crate::protocol::SessionSyncRequest {
    serde_json::from_value(serde_json::json!({
        "operation": "upsert",
        "addr_family": libc::AF_INET,
        "protocol": 6,
        "src_ip": "10.0.0.1",
        "dst_ip": "198.51.100.1",
        "src_port": 45000,
        "dst_port": 443,
        "ingress_zone_id": 1,
        "egress_zone_id": 2,
        "fabric_ingress": true,
        "owner_rg_id": 1,
        "egress_ifindex": 12,
        "tx_ifindex": 12,
        "neighbor_mac": "00:11:22:33:44:55",
        "nat_src_ip": "203.0.113.10",
        "nat_src_port": 45000,
        "session_id": 12_187_001,
        "source_nat_provenance": source_nat_provenance
    }))
    .expect("HA session-sync wire request")
}

#[test]
fn ha_imported_static_snat_survives_first_hit_12187() {
    let zones = rustc_hash::FxHashMap::from_iter([
        ("lan".to_string(), 1),
        ("wan".to_string(), 2),
    ]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(2),
        &zones,
        0,
    )
    .expect("static SNAT session imports from HA wire");
    let key = synced.key.clone();
    let decision = synced.decision.clone();
    let metadata = synced.metadata.clone();
    let origin = synced.origin;
    let source_nat_static = synced.source_nat_static;
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.upsert_synced_with_origin(synced.into_session_install(1), false));

    assert!(
        source_nat_revocation_on_session_hit(
            &imported_snat_forwarding(true),
            &mut sessions,
            &key,
            &metadata,
            decision,
            &flow,
            origin,
            source_nat_static,
            None,
        )
        .is_none(),
        "an imported static SNAT must survive its first hit with unchanged config"
    );
}

#[test]
fn ha_imported_dynamic_snat_survives_then_static_collision_revokes_12187() {
    let zones = rustc_hash::FxHashMap::from_iter([
        ("lan".to_string(), 1),
        ("wan".to_string(), 2),
    ]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1),
        &zones,
        0,
    )
    .expect("dynamic SNAT session imports from HA wire");
    let key = synced.key.clone();
    let decision = synced.decision.clone();
    let metadata = synced.metadata.clone();
    let origin = synced.origin;
    let source_nat_static = synced.source_nat_static;
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.upsert_synced_with_origin(synced.into_session_install(1), false));

    assert!(
        source_nat_revocation_on_session_hit(
            &imported_snat_forwarding(false),
            &mut sessions,
            &key,
            &metadata,
            decision,
            &flow,
            origin,
            source_nat_static,
            None,
        )
        .is_none(),
        "an imported dynamic SNAT must survive its first hit with unchanged config"
    );

    sessions.set_forwarding_revalidation_gen(2, 2);
    assert!(
        source_nat_revocation_on_session_hit(
            &imported_snat_forwarding(true),
            &mut sessions,
            &key,
            &metadata,
            decision,
            &flow,
            origin,
            source_nat_static,
            None,
        )
        .is_some(),
        "a later same-tuple static SNAT must not launder the imported dynamic allocation"
    );
}

#[test]
fn ha_imported_transient_dynamic_snat_uses_wire_provenance_12187() {
    let zones = rustc_hash::FxHashMap::from_iter([
        ("lan".to_string(), 1),
        ("wan".to_string(), 2),
    ]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1),
        &zones,
        0,
    )
    .expect("dynamic SNAT session imports from HA wire");
    let key = synced.key.clone();
    let translated_key = crate::session::forward_wire_key(&key, synced.decision.nat);
    let alias = SyncedSessionEntry {
        key: translated_key.clone(),
        ..synced.clone()
    };
    let flow = SessionFlow {
        src_ip: translated_key.src_ip,
        dst_ip: translated_key.dst_ip,
        forward_key: translated_key.clone(),
    };
    let mut sessions = SessionTable::new();
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = crate::afxdp::SharedSessionOwnerRgIndexes::default();
    crate::afxdp::publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &synced,
    );
    crate::afxdp::publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &alias,
    );
    let forwarding = imported_snat_forwarding(false);
    let dynamic_neighbors = Arc::new(crate::afxdp::ShardedNeighborMap::new());
    let peer_worker_commands = Vec::new();
    let resolved = crate::afxdp::session_glue::resolve_flow_session_decision(
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
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
        libc::IPPROTO_TCP as u8,
        0x18,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("translated shared alias resolves on the inactive peer");

    assert_eq!(resolved.key, translated_key);
    assert_eq!(resolved.session_id, synced.session_id);
    assert_eq!(
        resolved.source_nat_validation_key.as_ref(),
        Some(&key),
        "the alias must recover its original tuple through the matching HA session identity"
    );
    assert!(
        shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&translated_key)
            .is_none(),
        "transient resolution must purge the translated alias"
    );
    assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());

    assert!(
        source_nat_revocation_on_session_hit(
            &forwarding,
            &mut sessions,
            &resolved.key,
            &resolved.metadata,
            resolved.decision,
            &flow,
            resolved.origin,
            resolved.source_nat_static,
            resolved.source_nat_validation_key.as_ref(),
        )
        .is_none(),
        "transient imported dynamic SNAT must survive its unchanged first hit"
    );
    assert!(
        source_nat_revocation_on_session_hit(
            &imported_snat_forwarding(true),
            &mut sessions,
            &resolved.key,
            &resolved.metadata,
            resolved.decision,
            &flow,
            resolved.origin,
            resolved.source_nat_static,
            resolved.source_nat_validation_key.as_ref(),
        )
        .is_some(),
        "transient dynamic provenance must still reject a later static collision"
    );
    let mut collision = synced.clone();
    collision.key.src_ip = "10.0.0.2".parse().expect("colliding source IPv4");
    collision.session_id = 12_187_002;
    assert_eq!(
        crate::session::forward_wire_key(&collision.key, collision.decision.nat),
        translated_key,
        "the second original tuple must collide at the translated wire key"
    );
    crate::afxdp::publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &collision,
    );
    crate::afxdp::publish_shared_session(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &alias,
    );
    assert_eq!(
        shared_forward_wire_sessions
            .lock()
            .expect("shared forward-wire sessions")
            .get(&translated_key)
            .expect("colliding shared wire key")
            .session_id,
        collision.session_id
    );
    let mut collision_forwarding = imported_snat_forwarding(false);
    collision_forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::protocol::SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.2/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        },
    ]);
    let collision_resolved = crate::afxdp::session_glue::resolve_flow_session_decision(
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &collision_forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &flow,
        1_000_000,
        1,
        libc::IPPROTO_TCP as u8,
        0x18,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("translated alias resolves despite a shared wire-key collision");
    assert!(
        collision_resolved.source_nat_validation_key.is_none(),
        "a colliding original row with another session ID must not authorize this alias"
    );
    assert!(
        source_nat_revocation_on_session_hit(
            &collision_forwarding,
            &mut sessions,
            &collision_resolved.key,
            &collision_resolved.metadata,
            collision_resolved.decision,
            &flow,
            collision_resolved.origin,
            collision_resolved.source_nat_static,
            collision_resolved.source_nat_validation_key.as_ref(),
        )
        .is_some(),
        "ambiguous original-tuple identity must fail closed, not borrow another flow's rule"
    );
    assert_eq!(
        sessions.len(),
        0,
        "sessionless SNAT revalidation must not claim the peer's session"
    );
}
