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
    let shared_entry = |origin: SessionOrigin| SyncedSessionEntry {
        key: fwd_key.clone(),
        decision,
        metadata: metadata.clone(),
        leak_incarnation: 0,
        origin,
        protocol: 17,
        tcp_flags: 0,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        source_nat_static: None,
    };
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
        SyncedSessionEntry {
            key: fwd_key.clone(),
            decision,
            metadata,
            leak_incarnation: 0,
            origin: SessionOrigin::SyncImport,
            protocol: 17,
            tcp_flags: 0,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
            tcp_handshake_state: 0,
            source_nat_static: None,
        },
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
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        }]);
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

fn imported_snat_worker_forwarding(with_static: bool) -> ForwardingState {
    let mut forwarding = imported_snat_forwarding(with_static);
    forwarding.egress.insert(
        13,
        EgressInterface {
            bind_ifindex: 13,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 2,
            redundancy_group: 2,
            primary_v4: Some("203.0.113.254".parse().expect("local egress IPv4")),
            primary_v6: None,
        },
    );
    let next_hop = Ipv4Addr::new(192, 0, 2, 1);
    forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![RouteEntryV4 {
            prefix: PrefixV4::from_net(
                Ipv4Net::new(Ipv4Addr::new(198, 51, 100, 0), 24)
                    .expect("local egress route prefix"),
            ),
            next_hops: vec![RouteNextHopV4 {
                next_hop: Some(next_hop),
                ifindex: 13,
                logical_interface_id: 0,
                tunnel_endpoint_id: 0,
                weight: 1,
            }],
            discard: false,
            next_table: String::new(),
            preference: 0,
            mtu: 1500,
            rule_priority: 0,
        }],
    );
    forwarding.neighbors.insert(
        (13, IpAddr::V4(next_hop)),
        NeighborEntry {
            mac: [0x02, 0, 0, 0, 0, 13],
        },
    );
    forwarding
}

fn imported_snat_request(
    source_nat_provenance: u8,
    fabric_ingress: bool,
) -> crate::protocol::SessionSyncRequest {
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
        "fabric_ingress": fabric_ingress,
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
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(2, true),
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
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1, true),
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
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1, true),
        &zones,
        0,
    )
    .expect("dynamic SNAT session imports from HA wire");
    assert!(synced.metadata.fabric_ingress);
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
        crate::afxdp::session_glue::SessionHitVerdict::Owner,
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
    collision_forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "pool-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.2/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        }]);
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
        crate::afxdp::session_glue::SessionHitVerdict::Owner,
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

#[test]
fn ha_imported_transient_dynamic_snat_keeps_canonical_worker_entry_12187() {
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let mut request = imported_snat_request(1, false);
    request.next_hop = "192.0.2.254".to_string();
    let synced = crate::server::helpers::build_synced_session_entry(&request, &zones, 0)
        .expect("dynamic SNAT session imports from non-fabric HA wire");
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
    let forwarding = imported_snat_worker_forwarding(false);
    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.set_forwarding_for_test(forwarding.clone());
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        3,
        crate::afxdp::WorkerRuntimeRecord::for_test(crate::afxdp::WorkerHandle {
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            heartbeat: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            commands: worker_commands.clone(),
            session_export_ack: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cos_status: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
        }),
        None,
    );
    assert_eq!(
        coordinator.upsert_synced_session(synced.clone()),
        crate::afxdp::SyncedImportOutcome::Applied
    );
    assert_eq!(
        coordinator.upsert_synced_session(alias),
        crate::afxdp::SyncedImportOutcome::RejectedReserve,
        "the translated alias is refused after the canonical Go-order import"
    );

    let shared = &coordinator.sessions;
    let mut sessions = SessionTable::new();
    let dynamic_neighbors = Arc::new(crate::afxdp::ShardedNeighborMap::new());
    crate::afxdp::session_glue::apply_worker_commands(
        &worker_commands,
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        3,
        &mut VecDeque::new(),
    );
    let (local_decision, local_metadata, local_origin) = sessions
        .entry_with_origin(&key)
        .expect("real coordinator import reaches the worker under the canonical key");
    assert_eq!(local_decision.resolution.egress_ifindex, 13);
    assert_eq!(local_metadata.owner_rg_id, 2);
    assert!(local_origin.is_peer_synced());
    assert_eq!(sessions.session_id_for(&key), synced.session_id);

    let peer_worker_commands = Vec::new();
    let now_ns = crate::afxdp::monotonic_nanos();
    let mut resolved = None;
    for _ in 0..3 {
        let hit = crate::afxdp::session_glue::resolve_flow_session_decision(
            &mut sessions,
            crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
            &shared.synced,
            &shared.nat,
            &shared.forward_wire,
            &shared.owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &BTreeMap::new(),
            &dynamic_neighbors,
            &flow,
            now_ns,
            now_ns / 1_000_000_000,
            libc::IPPROTO_TCP as u8,
            0x18,
            0,
            0,
            false,
            0,
            3,
            crate::afxdp::session_glue::SessionHitVerdict::Owner,
        )
        .expect("translated worker lookup resolves to the canonical import");
        assert_eq!(hit.key, key);
        assert_eq!(hit.session_id, synced.session_id);
        assert_eq!(hit.decision.resolution.egress_ifindex, 13);
        assert_eq!(hit.metadata.owner_rg_id, 2);
        assert!(
            sessions.entry_with_origin(&key).is_some(),
            "a translated hit must not purge the canonical worker session"
        );
        assert!(
            shared
                .synced
                .lock()
                .expect("shared sessions")
                .contains_key(&key),
            "the canonical coordinator row remains authoritative"
        );
        assert!(
            source_nat_revocation_on_session_hit(
                &forwarding,
                &mut sessions,
                &hit.key,
                &hit.metadata,
                hit.decision,
                &flow,
                hit.origin,
                hit.source_nat_static,
                hit.source_nat_validation_key.as_ref(),
            )
            .is_none(),
            "unchanged dynamic SNAT survives each translated hit"
        );
        resolved = Some(hit);
    }
    let resolved = resolved.expect("three translated hits were resolved");
    assert!(
        source_nat_revocation_on_session_hit(
            &imported_snat_worker_forwarding(true),
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
        "a later same-tuple static SNAT still revokes the imported dynamic allocation"
    );
}

#[test]
fn ha_imported_transient_dynamic_snat_local_alias_keeps_shared_canonical_12187() {
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let mut request = imported_snat_request(1, false);
    request.next_hop = "192.0.2.254".to_string();
    let synced = crate::server::helpers::build_synced_session_entry(&request, &zones, 0)
        .expect("dynamic SNAT session imports from non-fabric HA wire");
    assert!(!synced.metadata.fabric_ingress);
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
    let forwarding = imported_snat_worker_forwarding(false);
    let mut coordinator = crate::afxdp::Coordinator::new();
    coordinator.set_forwarding_for_test(forwarding.clone());
    let worker_commands = Arc::new(Mutex::new(VecDeque::new()));
    coordinator.workers.register(
        3,
        crate::afxdp::WorkerRuntimeRecord::for_test(crate::afxdp::WorkerHandle {
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            heartbeat: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            commands: worker_commands.clone(),
            session_export_ack: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cos_status: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            runtime_atomics: Arc::new(crate::afxdp::worker_runtime::WorkerRuntimeAtomics::new()),
            cold_path_atomics: Arc::new(crate::afxdp::cold_path_hist::WorkerColdPathAtomics::new()),
        }),
        None,
    );
    assert_eq!(
        coordinator.upsert_synced_session(synced.clone()),
        crate::afxdp::SyncedImportOutcome::Applied
    );

    let shared = &coordinator.sessions;
    let mut sessions = SessionTable::new();
    let dynamic_neighbors = Arc::new(crate::afxdp::ShardedNeighborMap::new());
    crate::afxdp::session_glue::apply_worker_commands(
        &worker_commands,
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        3,
        &mut VecDeque::new(),
    );
    assert!(sessions.entry_with_origin(&key).is_some());
    worker_commands
        .lock()
        .expect("worker commands")
        .push_back(crate::afxdp::WorkerCommand::UpsertSynced(alias));
    crate::afxdp::session_glue::apply_worker_commands(
        &worker_commands,
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        3,
        &mut VecDeque::new(),
    );
    assert!(
        sessions.entry_with_origin(&translated_key).is_some(),
        "the translated alias is installed on the worker"
    );
    assert_eq!(sessions.session_id_for(&translated_key), synced.session_id);

    let peer_worker_commands = Vec::new();
    let now_ns = crate::afxdp::monotonic_nanos();
    let hit = crate::afxdp::session_glue::resolve_flow_session_decision(
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        &shared.synced,
        &shared.nat,
        &shared.forward_wire,
        &shared.owner_rg_indexes,
        &peer_worker_commands,
        &forwarding,
        &BTreeMap::new(),
        &dynamic_neighbors,
        &flow,
        now_ns,
        now_ns / 1_000_000_000,
        libc::IPPROTO_TCP as u8,
        0x18,
        0,
        0,
        false,
        0,
        3,
        crate::afxdp::session_glue::SessionHitVerdict::Owner,
    )
    .expect("translated local alias resolves against the shared canonical import");
    assert_eq!(hit.key, translated_key);
    assert_eq!(hit.session_id, synced.session_id);
    assert_eq!(
        hit.source_nat_validation_key.as_ref(),
        Some(&key),
        "the local alias must recover the original tuple using its pre-purge session ID"
    );
    assert!(
        sessions.entry_with_origin(&translated_key).is_none(),
        "the transient local alias is purged"
    );
    assert!(
        sessions.entry_with_origin(&key).is_some(),
        "purging the local alias leaves the canonical worker session"
    );
    assert!(
        shared
            .synced
            .lock()
            .expect("shared sessions")
            .contains_key(&key),
        "the shared canonical row remains authoritative"
    );
    assert!(
        !shared
            .synced
            .lock()
            .expect("shared sessions")
            .contains_key(&translated_key),
        "the worker-local alias is not installed in shared authority"
    );
    assert!(
        source_nat_revocation_on_session_hit(
            &forwarding,
            &mut sessions,
            &hit.key,
            &hit.metadata,
            hit.decision,
            &flow,
            hit.origin,
            hit.source_nat_static,
            hit.source_nat_validation_key.as_ref(),
        )
        .is_none(),
        "the local alias's unchanged dynamic SNAT survives sessionless revalidation"
    );
}

#[test]
fn ha_transient_snat_unknown_session_identity_fails_closed_12187() {
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let mut unknown = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1, true),
        &zones,
        0,
    )
    .expect("dynamic SNAT session imports from HA wire");
    unknown.session_id = 0;
    let wire_key = crate::session::forward_wire_key(&unknown.key, unknown.decision.nat);
    let mut known = unknown.clone();
    known.session_id = 12_187_001;
    let known_shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::from_iter([(
        wire_key.clone(),
        known.clone(),
    )])));
    assert_eq!(
        crate::afxdp::shared_ops::shared_source_nat_original_key(
            &known_shared_forward_wire_sessions,
            &wire_key,
            &wire_key,
            known.decision,
            &known.metadata,
            known.origin,
            known.source_nat_static,
            known.session_id,
        ),
        Some(known.key.clone())
    );
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::from_iter([(
        wire_key.clone(),
        unknown.clone(),
    )])));

    assert!(
        crate::afxdp::shared_ops::shared_source_nat_original_key(
            &shared_forward_wire_sessions,
            &wire_key,
            &wire_key,
            unknown.decision,
            &unknown.metadata,
            unknown.origin,
            unknown.source_nat_static,
            12_187_001,
        )
        .is_none(),
        "an unknown shared candidate identity cannot authorize source-NAT provenance"
    );
}

/// #12191: the real stale-zone-policy PERMIT edge must refresh the stored
/// conntrack AppID, not merely the RT_FLOW label resolved from the live catalog.
#[test]
fn permitted_stale_hit_restamps_conntrack_app_id_12191() {
    use crate::AppCatalogEntry;
    use crate::policy::AppCatalog;

    const PROTO_TCP: u8 = 6;
    const APP_A: u16 = 11;
    const APP_B: u16 = 22;
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
        src_port: 40000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                172, 16, 80, 1,
            ))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = SessionMetadata {
        ingress_zone: crate::test_zone_ids::TEST_LAN_ZONE_ID,
        egress_zone: crate::test_zone_ids::TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 24,
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

    let mut snapshot = crate::afxdp::test_fixtures::policy_deny_snapshot();
    snapshot.policies[0].from_zone = "lan".to_string();
    let mut forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
    let catalog_gen1 = AppCatalog::from_snapshot(&[AppCatalogEntry {
        app_id: APP_A,
        protocol: PROTO_TCP,
        dst_port_low: 443,
        dst_port_high: 443,
        src_port_low: 0,
        src_port_high: 0,
    }]);
    let catalog_gen2 = AppCatalog::from_snapshot(&[
        AppCatalogEntry {
            app_id: APP_A,
            protocol: PROTO_TCP,
            dst_port_low: 8443,
            dst_port_high: 8443,
            src_port_low: 0,
            src_port_high: 0,
        },
        AppCatalogEntry {
            app_id: APP_B,
            protocol: PROTO_TCP,
            dst_port_low: 443,
            dst_port_high: 443,
            src_port_low: 0,
            src_port_high: 0,
        },
    ]);
    forwarding.app_catalog = catalog_gen2;

    let mut sessions = SessionTable::new();
    sessions.set_app_id_catalog_epoch(catalog_gen1.epoch());
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        PROTO_TCP,
        0x02,
    ));
    sessions.set_policy_revalidation_gen(2);
    sessions.set_app_id_catalog_epoch(forwarding.app_catalog.epoch());
    let session_id = sessions.session_id_for(&key);
    assert_ne!(session_id, 0);
    let timeout_secs = sessions.timeout_secs_for(&key);

    let _publish_guard = crate::afxdp::bpf_map::take_conntrack_publish_guard();
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            &key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            catalog_gen1.lookup_admitted(
                key.protocol,
                key.src_port,
                key.dst_port,
                metadata.is_reverse,
                decision.nat.rewrite_dst_port,
            ),
            session_id,
            timeout_secs,
            SessionOrigin::ForwardFlow,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written
    );
    let before = crate::afxdp::bpf_map::conntrack_row_for_test(&key)
        .expect("create must publish the initial AppID row");
    assert_eq!(before.app_id, APP_A);
    assert_eq!(before.session_id, session_id);
    assert!(matches!(
        sessions.policy_revalidation_target(&key),
        PolicyRevalidationTarget::Stale(_)
    ));

    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let meta = crate::afxdp::tests_support::txn_meta_v4(24, 0x10, 54);
    let revocation = revalidate_zone_policy_on_session_hit(
        &forwarding,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        &mut sessions,
        &key,
        &metadata,
        decision,
        Some(&flow),
        meta,
        false,
        false,
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        1_100_000_000,
        1,
        24,
        0,
        SessionOrigin::ForwardFlow,
    );
    assert!(
        revocation.is_none(),
        "the configured lan -> wan permit must keep the live session"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&key),
        PolicyRevalidationTarget::Fresh,
        "the permit must stamp the stale session current"
    );
    let after = crate::afxdp::bpf_map::conntrack_row_for_test(&key)
        .expect("permitted revalidation must leave the row present");
    assert_eq!(
        after.app_id, APP_B,
        "the stale-hit permit must re-stamp the stored label from the live catalog"
    );
    assert_eq!(
        after.session_id, session_id,
        "label refresh must preserve the stable session identity"
    );
    // A current but non-live authorization can force a cold walk. It must not
    // refresh the conntrack label: only stale-generation permits do so.
    sessions.mark_policy_revalidated(&key, PolicyRevalidationKind::RecordedEgress);
    forwarding.app_catalog = AppCatalog::from_snapshot(&[AppCatalogEntry {
        app_id: 33,
        protocol: PROTO_TCP,
        dst_port_low: 443,
        dst_port_high: 443,
        src_port_low: 0,
        src_port_high: 0,
    }]);
    let forced_fresh_revocation = revalidate_zone_policy_on_session_hit(
        &forwarding,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        &mut sessions,
        &key,
        &metadata,
        decision,
        Some(&flow),
        crate::afxdp::tests_support::txn_meta_v4(24, 0x10, 54),
        false,
        false,
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        1_200_000_000,
        1,
        24,
        0,
        SessionOrigin::ForwardFlow,
    );
    assert!(
        forced_fresh_revocation.is_none(),
        "a Fresh-forced permit keeps the session"
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&key)
            .expect("Fresh-forced revalidation preserves the row")
            .app_id,
        APP_B,
        "Fresh-forced revalidation must not restamp the label"
    );
}

/// #12191: reverse IPv6 hits restamp the worker-published forward row, not a
/// reverse companion row (worker installs publish forward conntrack only).
#[test]
fn reverse_stale_hit_restamps_forward_ipv6_conntrack_row_12191() {
    use crate::AppCatalogEntry;
    use crate::policy::AppCatalog;

    const PROTO_TCP: u8 = 6;
    const APP_A: u16 = 11;
    const APP_B: u16 = 22;
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: "2001:db8:1::10".parse().unwrap(),
        dst_ip: "2001:db8:2::20".parse().unwrap(),
        src_port: 40_000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some("2001:db8:2::1".parse().unwrap()),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = SessionMetadata {
        ingress_zone: crate::test_zone_ids::TEST_LAN_ZONE_ID,
        egress_zone: crate::test_zone_ids::TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 24,
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
    let mut reverse_metadata = metadata.clone();
    reverse_metadata.is_reverse = true;
    let reverse_decision = decision;
    let reverse_key = crate::session::reverse_session_key(&fwd_key, decision.nat);
    let catalog1 = AppCatalog::from_snapshot(&[AppCatalogEntry {
        app_id: APP_A,
        protocol: PROTO_TCP,
        dst_port_low: 443,
        dst_port_high: 443,
        src_port_low: 0,
        src_port_high: 0,
    }]);
    let catalog2 = AppCatalog::from_snapshot(&[AppCatalogEntry {
        app_id: APP_B,
        protocol: PROTO_TCP,
        dst_port_low: 443,
        dst_port_high: 443,
        src_port_low: 0,
        src_port_high: 0,
    }]);
    let mut snapshot = crate::afxdp::test_fixtures::policy_deny_snapshot();
    snapshot.policies[0].from_zone = "lan".to_string();
    let mut forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
    forwarding.app_catalog = catalog2;

    let mut sessions = SessionTable::new();
    sessions.set_app_id_catalog_epoch(catalog1.epoch());
    sessions.set_policy_revalidation_gen(1);
    assert!(sessions.install_with_protocol_with_origin(
        fwd_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        PROTO_TCP,
        0x02,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse_decision,
        reverse_metadata.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    sessions.mark_policy_revalidated(&fwd_key, PolicyRevalidationKind::LiveEgress);
    sessions.set_policy_revalidation_gen(2);
    sessions.set_app_id_catalog_epoch(forwarding.app_catalog.epoch());
    let session_id = sessions.session_id_for(&fwd_key);
    let timeout_secs = sessions.timeout_secs_for(&fwd_key);
    let _publish_guard = crate::afxdp::bpf_map::take_conntrack_publish_guard();
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            -1,
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            &fwd_key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            catalog1.lookup_admitted(
                fwd_key.protocol,
                fwd_key.src_port,
                fwd_key.dst_port,
                false,
                decision.nat.rewrite_dst_port,
            ),
            session_id,
            timeout_secs,
            SessionOrigin::ForwardFlow,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&fwd_key)
            .expect("the test publishes the forward v6 row")
            .app_id,
        APP_A
    );
    assert!(matches!(
        sessions.policy_revalidation_target(&reverse_key),
        PolicyRevalidationTarget::Stale(_)
    ));
    let flow = SessionFlow {
        src_ip: fwd_key.src_ip,
        dst_ip: fwd_key.dst_ip,
        forward_key: fwd_key.clone(),
    };
    let revocation = revalidate_zone_policy_on_session_hit(
        &forwarding,
        -1,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        &mut sessions,
        &reverse_key,
        &reverse_metadata,
        reverse_decision,
        Some(&flow),
        crate::afxdp::tests_support::txn_meta_v4(24, 0x10, 54),
        false,
        false,
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        1_100_000_000,
        1,
        24,
        0,
        SessionOrigin::ReverseFlow,
    );
    assert!(
        revocation.is_none(),
        "the forward companion's current lan -> wan policy permits"
    );
    let after = crate::afxdp::bpf_map::conntrack_row_for_test(&fwd_key)
        .expect("reverse evidence must update the forward v6 row");
    assert_eq!(after.app_id, APP_B);
    assert_eq!(after.session_id, session_id);
}

fn app_id_revalidation_decision(nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some("172.16.80.1".parse().expect("next hop")),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: None,
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat,
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn app_id_revalidation_metadata(is_reverse: bool) -> SessionMetadata {
    SessionMetadata {
        ingress_zone: crate::test_zone_ids::TEST_LAN_ZONE_ID,
        egress_zone: crate::test_zone_ids::TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 24,
        ingress_vlan_id: 0,
        owner_rg_id: 0,
        fabric_ingress: false,
        is_reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
    }
}

fn app_id_revalidation_hit(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: &SessionFlow,
    origin: SessionOrigin,
) -> bool {
    revalidate_zone_policy_on_session_hit(
        forwarding,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        sessions,
        key,
        metadata,
        decision,
        Some(flow),
        crate::afxdp::tests_support::txn_meta_v4(24, 0x10, 54),
        false,
        false,
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        1_100_000_000,
        1,
        24,
        0,
        origin,
    )
    .is_none()
}

/// A new pair's first reverse and forward permits leave an already-correct
/// AppID row alone; after a catalog change, the next stale permit restamps it.
#[test]
fn new_pair_same_app_id_skips_restamp_write_and_later_restock_works_12191() {
    use crate::AppCatalogEntry;
    use crate::policy::AppCatalog;

    const PROTO_TCP: u8 = 6;
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "10.1.2.3".parse().expect("client"),
        dst_ip: "172.16.80.9".parse().expect("server"),
        src_port: 40_000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let decision = app_id_revalidation_decision(NatDecision::default());
    let metadata = app_id_revalidation_metadata(false);
    let reverse_metadata = app_id_revalidation_metadata(true);
    let reverse_key = crate::session::reverse_session_key(&fwd_key, decision.nat);
    let app_entry = |app_id| AppCatalogEntry {
        app_id,
        protocol: PROTO_TCP,
        dst_port_low: 443,
        dst_port_high: 443,
        src_port_low: 0,
        src_port_high: 0,
    };
    let mut snapshot = crate::afxdp::test_fixtures::policy_deny_snapshot();
    snapshot.policies[0].from_zone = "lan".to_string();
    snapshot.neighbors.push(crate::NeighborSnapshot {
        interface: "ge-0-0-0.80".into(),
        ifindex: 12,
        family: "inet".into(),
        ip: "172.16.80.9".into(),
        mac: "00:01:02:03:04:05".into(),
        state: "reachable".into(),
        router: false,
        link_local: false,
        ..Default::default()
    });
    let mut forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
    forwarding.app_catalog = AppCatalog::from_snapshot(&[app_entry(11)]);

    let mut sessions = SessionTable::new();
    sessions.set_app_id_catalog_epoch(AppCatalog::from_snapshot(&[app_entry(11)]).epoch());
    sessions.set_policy_revalidation_gen(5);
    assert!(sessions.install_with_protocol_with_origin(
        fwd_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        PROTO_TCP,
        0x02,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        decision,
        reverse_metadata.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000_000,
        PROTO_TCP,
        0x12,
    ));
    assert!(matches!(
        sessions.policy_revalidation_target(&reverse_key),
        PolicyRevalidationTarget::Stale(_)
    ));
    assert!(matches!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Stale(_)
    ));

    let _publish_guard = crate::afxdp::bpf_map::take_conntrack_publish_guard();
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    let session_id = sessions.session_id_for(&fwd_key);
    let timeout_secs = sessions.timeout_secs_for(&fwd_key);
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            -1,
            &fwd_key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            11,
            session_id,
            timeout_secs,
            SessionOrigin::ForwardFlow,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written
    );
    let flow = SessionFlow {
        src_ip: fwd_key.src_ip,
        dst_ip: fwd_key.dst_ip,
        forward_key: fwd_key.clone(),
    };
    assert!(app_id_revalidation_hit(
        &forwarding,
        &mut sessions,
        &reverse_key,
        &reverse_metadata,
        decision,
        &flow,
        SessionOrigin::ReverseFlow,
    ));
    assert_eq!(
        sessions.policy_revalidation_target(&reverse_key),
        PolicyRevalidationTarget::Fresh,
        "the first reverse permit must complete stale revalidation"
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_writes_for_test(),
        0,
        "the first reverse hit must skip a same-AppID map update"
    );
    assert!(app_id_revalidation_hit(
        &forwarding,
        &mut sessions,
        &fwd_key,
        &metadata,
        decision,
        &flow,
        SessionOrigin::ForwardFlow,
    ));
    assert_eq!(
        sessions.policy_revalidation_target(&fwd_key),
        PolicyRevalidationTarget::Fresh,
        "the first forward permit must complete stale revalidation"
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_writes_for_test(),
        0,
        "the first forward hit must skip a same-AppID map update"
    );
    let second_key = SessionKey {
        src_port: fwd_key.src_port + 1,
        ..fwd_key.clone()
    };
    let second_reverse_key = crate::session::reverse_session_key(&second_key, decision.nat);
    assert!(sessions.install_with_protocol_with_origin(
        second_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        PROTO_TCP,
        0x02,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        second_reverse_key,
        decision,
        reverse_metadata.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000_000,
        PROTO_TCP,
        0x12,
    ));
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            -1,
            &second_key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            11,
            sessions.session_id_for(&second_key),
            sessions.timeout_secs_for(&second_key),
            SessionOrigin::ForwardFlow,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written
    );
    let second_flow = SessionFlow {
        src_ip: second_key.src_ip,
        dst_ip: second_key.dst_ip,
        forward_key: second_key.clone(),
    };
    assert!(app_id_revalidation_hit(
        &forwarding,
        &mut sessions,
        &second_key,
        &metadata,
        decision,
        &second_flow,
        SessionOrigin::ForwardFlow,
    ));
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_lookups_for_test(),
        0,
        "unchanged catalog must not read conntrack for another new connection"
    );
    forwarding.app_catalog = AppCatalog::from_snapshot(&[app_entry(22)]);
    sessions.set_app_id_catalog_epoch(forwarding.app_catalog.epoch());
    sessions.set_policy_revalidation_gen(6);
    assert!(app_id_revalidation_hit(
        &forwarding,
        &mut sessions,
        &reverse_key,
        &reverse_metadata,
        decision,
        &flow,
        SessionOrigin::ReverseFlow,
    ));
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&fwd_key)
            .expect("forward conntrack row")
            .app_id,
        22,
        "a stale hit after catalog change must restock the live AppID"
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_writes_for_test(),
        1,
        "a changed AppID must perform exactly one map update"
    );
}

/// A reverse DNAT hit resolves the forward row with the post-NAT service port.
#[test]
fn reverse_stale_dnat_hit_restamps_post_nat_forward_row_12191() {
    use crate::AppCatalogEntry;
    use crate::policy::AppCatalog;

    const PROTO_TCP: u8 = 6;
    let entry = |app_id, port| AppCatalogEntry {
        app_id,
        protocol: PROTO_TCP,
        dst_port_low: port,
        dst_port_high: port,
        src_port_low: 0,
        src_port_high: 0,
    };
    let client = "10.1.2.3".parse().expect("client");
    let vip = "203.0.113.7".parse().expect("VIP");
    let real = "172.16.80.9".parse().expect("server");
    let fwd_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: client,
        dst_ip: vip,
        src_port: 40_000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let fwd_nat = NatDecision {
        rewrite_dst: Some(real),
        rewrite_dst_port: Some(8443),
        ..NatDecision::default()
    };
    let decision = app_id_revalidation_decision(fwd_nat);
    let reverse_decision = app_id_revalidation_decision(fwd_nat.reverse(client, vip, 40_000, 443));
    let metadata = app_id_revalidation_metadata(false);
    let reverse_metadata = app_id_revalidation_metadata(true);
    let reverse_key = crate::session::reverse_session_key(&fwd_key, fwd_nat);
    assert_eq!(
        crate::session::reverse_session_key(&reverse_key, reverse_decision.nat),
        fwd_key
    );

    let catalog1 = AppCatalog::from_snapshot(&[entry(11, 8443), entry(33, 443)]);
    let mut snapshot = crate::afxdp::test_fixtures::policy_deny_snapshot();
    snapshot.policies[0].from_zone = "lan".to_string();
    let mut forwarding = crate::afxdp::forwarding_build::build_forwarding_state(&snapshot);
    forwarding.app_catalog = AppCatalog::from_snapshot(&[entry(22, 8443), entry(33, 443)]);
    let mut sessions = SessionTable::new();
    sessions.set_app_id_catalog_epoch(catalog1.epoch());
    sessions.set_policy_revalidation_gen(1);
    assert!(sessions.install_with_protocol_with_origin(
        fwd_key.clone(),
        decision,
        metadata.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        PROTO_TCP,
        0x02,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse_decision,
        reverse_metadata.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000_000,
        PROTO_TCP,
        0x10,
    ));
    sessions.mark_policy_revalidated(&fwd_key, PolicyRevalidationKind::LiveEgress);
    sessions.set_policy_revalidation_gen(2);
    sessions.set_app_id_catalog_epoch(forwarding.app_catalog.epoch());
    assert!(matches!(
        sessions.policy_revalidation_target(&reverse_key),
        PolicyRevalidationTarget::Stale(_)
    ));

    let _publish_guard = crate::afxdp::bpf_map::take_conntrack_publish_guard();
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
    let session_id = sessions.session_id_for(&fwd_key);
    let timeout_secs = sessions.timeout_secs_for(&fwd_key);
    assert_eq!(
        crate::afxdp::bpf_map::publish_bpf_conntrack_entry(
            crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
            -1,
            &fwd_key,
            decision,
            &metadata,
            &FastMap::default(),
            0,
            catalog1.lookup_admitted(
                PROTO_TCP,
                fwd_key.src_port,
                fwd_key.dst_port,
                false,
                Some(8443),
            ),
            session_id,
            timeout_secs,
            SessionOrigin::ForwardFlow,
        ),
        crate::afxdp::bpf_map::ConntrackPublishResult::Written
    );
    let flow = SessionFlow {
        src_ip: fwd_key.src_ip,
        dst_ip: fwd_key.dst_ip,
        forward_key: fwd_key.clone(),
    };
    assert!(app_id_revalidation_hit(
        &forwarding,
        &mut sessions,
        &reverse_key,
        &reverse_metadata,
        reverse_decision,
        &flow,
        SessionOrigin::ReverseFlow,
    ));
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_row_for_test(&fwd_key)
            .expect("reverse hit updates the forward row")
            .app_id,
        22,
        "the post-NAT :8443 app must win over the wire :443 app"
    );
}
