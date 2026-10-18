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
            forward_ingress_vlan_id: None,
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
        pptp_call_ids: 0,
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
            pptp_call_ids: 0,
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
            reject: false,
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
            1_000_000_000,
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
            1_000_000_000,
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
            1_000_000_000,
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
            1_000_000_000,
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
            1_000_000_000,
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
            1_000_000_000,
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
                1_000_000_000,
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
            1_000_000_000,
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
            1_000_000_000,
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
        forward_ingress_vlan_id: None,
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
        None,
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
        None,
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
        forward_ingress_vlan_id: None,
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
        None,
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
        forward_ingress_vlan_id: None,
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
        None,
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
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
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
        "zone policy becomes fresh even when the AppID conntrack read fails"
    );
    assert!(sessions.app_id_catalog_stale(&fwd_key));
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_lookups_for_test(),
        1,
        "the first changed-catalog permit attempts a conntrack lookup"
    );

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
        "a later permitted hit must retry and restamp after the map recovers"
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_lookups_for_test(),
        2,
        "the recovered map must be read after the first failed attempt"
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_writes_for_test(),
        1,
        "a changed AppID must perform exactly one successful map update"
    );
    crate::afxdp::bpf_map::clear_conntrack_rows_for_test();
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
        sessions.policy_revalidation_target(&second_key),
        PolicyRevalidationTarget::Fresh
    );
    assert!(sessions.app_id_catalog_stale(&second_key));
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_lookups_for_test(),
        1
    );
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
        crate::afxdp::bpf_map::conntrack_row_for_test(&second_key)
            .expect("recovered second conntrack row")
            .app_id,
        22
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_lookups_for_test(),
        2
    );
    assert_eq!(
        crate::afxdp::bpf_map::conntrack_app_id_restamp_writes_for_test(),
        1
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

/// #12861 fixture: a VLAN trunk. Physical parent 11 inherits the FIRST
/// sub-interface's zone (dmz, 3) in `ifindex_to_zone_id`; the SNAT session
/// arrived on VLAN 50, whose logical unit 13 is in lan (1). Egress 12 is wan
/// (2). The SNAT rule is `lan -> wan`, so the session is valid ONLY when the
/// revalidation resolves `(11, VLAN 50) -> 13` before the zone-pair lookup.
fn snat_vlan_trunk_forwarding_12861() -> ForwardingState {
    let mut forwarding = imported_snat_forwarding(false);
    forwarding.zone_id_to_name.insert(3, "dmz".to_string());
    forwarding.ingress_logical_ifindex.insert((11, 50), 13);
    forwarding.ifindex_to_zone_id.insert(11, 3);
    forwarding.ifindex_to_zone_id.insert(13, 1);
    forwarding.ifindex_unambiguous_zone_id.insert(12, 2);
    forwarding
}

fn snat_vlan_trunk_case_12861(
    forwarding: ForwardingState,
    ingress_ifindex: u32,
    ingress_vlan_id: u16,
    fabric_ingress: bool,
) -> (
    ForwardingState,
    SessionDecision,
    SessionMetadata,
    SessionKey,
) {
    let key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        src_port: 45000,
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
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision {
            rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            rewrite_src_port: Some(45000),
            ..Default::default()
        },
        install_table_domain: 0,
        install_table_check: 0,
    };
    let metadata = SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex,
        ingress_vlan_id,
        owner_rg_id: 1,
        fabric_ingress,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        forward_ingress_vlan_id: None,
    };
    (forwarding, decision, metadata, key)
}

/// #12861 RED: a dynamic SNAT session admitted on VLAN 50 (lan) of a trunk
/// whose physical parent resolves to dmz must survive an unrelated SNAT
/// generation advance — the rule is `lan -> wan` and the mapping is unchanged.
/// Pre-fix the raw physical ifindex yields `dmz -> wan`, no rule matches, and
/// the live session is revoked.
#[test]
fn source_nat_revalidation_resolves_vlan_logical_ingress_12861() {
    let (forwarding, decision, metadata, key) =
        snat_vlan_trunk_case_12861(snat_vlan_trunk_forwarding_12861(), 11, 50, false);
    let (valid, static_nat) = source_nat_translation_still_valid(
        &forwarding,
        &decision,
        &metadata,
        &key,
        Some(false),
        1_000_000_000,
    );
    assert!(
        valid,
        "SNAT session on VLAN 50 (lan) must remain valid; raw physical parent resolves to dmz"
    );
    assert_eq!(static_nat, Some(false));
}

/// #12861 integration edge: advancing the forwarding/SNAT generations on an
/// installed dynamic mapping must not return a live-session revocation.
#[test]
fn source_nat_vlan_logical_ingress_survives_generation_advance_12861() {
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let mut synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1, false),
        &zones,
        0,
    )
    .expect("dynamic SNAT session imports");
    synced.metadata.ingress_ifindex = 11;
    synced.metadata.ingress_vlan_id = 50;
    synced.metadata.fabric_ingress = false;
    let key = synced.key.clone();
    let decision = synced.decision;
    let metadata = synced.metadata.clone();
    let origin = synced.origin;
    let static_nat = synced.source_nat_static;
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.upsert_synced_with_origin(synced.into_session_install(1), false));

    // Commit an unrelated source-NAT generation advance without changing the
    // dynamic pool rule or the established translation.
    sessions.set_forwarding_revalidation_gen(2, 2);
    assert!(
        source_nat_revocation_on_session_hit(
            &snat_vlan_trunk_forwarding_12861(),
            &mut sessions,
            &key,
            &metadata,
            decision,
            &flow,
            origin,
            static_nat,
            None,
            1_000_000_000,
        )
        .is_none(),
        "the unchanged SNAT mapping on VLAN 50 must survive revalidation"
    );
}

/// #12861: untagged ingress (VLAN 0) on the same trunk resolves through
/// `(11, 0)`. Pin 11's untagged unit to lan so the session stays valid —
/// the fix must not break the untagged path.
#[test]
fn source_nat_revalidation_untagged_trunk_stays_valid_12861() {
    let mut forwarding = snat_vlan_trunk_forwarding_12861();
    forwarding.ingress_logical_ifindex.insert((11, 0), 13);
    let (forwarding, decision, metadata, key) =
        snat_vlan_trunk_case_12861(forwarding, 11, 0, false);
    let (valid, _) = source_nat_translation_still_valid(
        &forwarding,
        &decision,
        &metadata,
        &key,
        Some(false),
        1_000_000_000,
    );
    assert!(valid, "untagged SNAT session on lan unit must remain valid");
}

/// #12861: when the physical ifindex itself is the lan unit (no VLAN
/// subdivision), resolution falls back to the physical index and the session
/// stays valid.
#[test]
fn source_nat_revalidation_physical_lan_stays_valid_12861() {
    let mut forwarding = snat_vlan_trunk_forwarding_12861();
    forwarding.ifindex_to_zone_id.insert(11, 1);
    let (forwarding, decision, metadata, key) =
        snat_vlan_trunk_case_12861(forwarding, 11, 0, false);
    let (valid, _) = source_nat_translation_still_valid(
        &forwarding,
        &decision,
        &metadata,
        &key,
        Some(false),
        1_000_000_000,
    );
    assert!(
        valid,
        "SNAT session on a physical lan port must remain valid"
    );
}

/// #12861: fabric-ingress identity keeps the recorded-zone shortcut — the
/// stored zones are authoritative and no live ifindex resolution applies.
#[test]
fn source_nat_revalidation_fabric_keeps_recorded_zones_12861() {
    let (forwarding, decision, metadata, key) =
        snat_vlan_trunk_case_12861(snat_vlan_trunk_forwarding_12861(), 0, 0, true);
    let (valid, _) = source_nat_translation_still_valid(
        &forwarding,
        &decision,
        &metadata,
        &key,
        Some(false),
        1_000_000_000,
    );
    assert!(
        valid,
        "fabric SNAT session must keep recorded lan->wan zones"
    );
}

/// #12861 anti-mutant: VLAN 60 legitimately lands in dmz, where no
/// `dmz -> wan` SNAT rule exists. The fix must still revoke — resolving the
/// logical unit must not launder a mapping the live rule set does not express.
#[test]
fn source_nat_revalidation_other_vlan_zone_still_revoked_12861() {
    let mut forwarding = snat_vlan_trunk_forwarding_12861();
    forwarding.ingress_logical_ifindex.insert((11, 60), 14);
    forwarding.ifindex_to_zone_id.insert(14, 3);
    let (forwarding, decision, metadata, key) =
        snat_vlan_trunk_case_12861(forwarding, 11, 60, false);
    let (valid, _) = source_nat_translation_still_valid(
        &forwarding,
        &decision,
        &metadata,
        &key,
        Some(false),
        1_000_000_000,
    );
    assert!(
        !valid,
        "SNAT session arriving on a dmz VLAN must not match the lan->wan rule"
    );
}

// ---------------------------------------------------------------------------
// #12867: zone-policy revalidation must judge the ORIGINAL pre-SNAT source of
// a translated forward-wire alias, never the public tuple on the wire.
// ---------------------------------------------------------------------------

/// #12867 scenario kit: a canonical SNAT session installed under its ORIGINAL
/// tuple — the production shape, since the local forward-wire index maps the
/// translated tuple onto exactly that row — plus the translated retransmission
/// that arrives carrying the public source.
struct SnatWireAliasCase12867 {
    original: SessionKey,
    wire: SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
}

fn snat_wire_alias_case_12867(nat: NatDecision) -> SnatWireAliasCase12867 {
    let original = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: libc::IPPROTO_TCP as u8,
        src_ip: "10.0.0.1".parse().expect("private source"),
        dst_ip: "198.51.100.9".parse().expect("public destination"),
        src_port: 45_000,
        dst_port: 443,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let decision = app_id_revalidation_decision(nat);
    let wire = crate::session::forward_wire_key(&original, decision.nat);
    SnatWireAliasCase12867 {
        original,
        wire,
        decision,
        metadata: app_id_revalidation_metadata(false),
    }
}

/// A `lan -> wan` permit whose source-address and source-port selectors are
/// separately controllable, so either field being read off the post-SNAT wire
/// alias is independently observable. Everything else is `any`.
fn snat_alias_policy_12867(source_addresses: &[&str], source_port: &str) -> ForwardingState {
    let mut snapshot = crate::afxdp::test_fixtures::policy_deny_snapshot();
    let rule = &mut snapshot.policies[0];
    rule.from_zone = "lan".to_string();
    rule.source_addresses = source_addresses.iter().map(|s| (*s).to_string()).collect();
    rule.applications = vec!["source-port-probe".to_string()];
    rule.application_terms = vec![crate::protocol::PolicyApplicationSnapshot {
        name: "source-port-probe".to_string(),
        protocol: "tcp".to_string(),
        source_port: source_port.to_string(),
        destination_port: String::new(),
        ..Default::default()
    }];
    crate::afxdp::forwarding_build::build_forwarding_state(&snapshot)
}

fn install_stale_alias_session_12867(
    case: &SnatWireAliasCase12867,
    install_key: &SessionKey,
) -> SessionTable {
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        install_key.clone(),
        case.decision,
        case.metadata.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        libc::IPPROTO_TCP as u8,
        0x10,
    ));
    sessions.set_policy_revalidation_gen(2);
    sessions
}

fn revalidate_alias_hit_12867(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    case: &SnatWireAliasCase12867,
    session_key: &SessionKey,
    flow: &SessionFlow,
) -> Option<PolicyRevocation> {
    revalidate_zone_policy_on_session_hit(
        forwarding,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        crate::afxdp::bpf_map::CONNTRACK_TEST_MAP_FD,
        sessions,
        session_key,
        &case.metadata,
        case.decision,
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
        SessionOrigin::ForwardFlow,
        // A stale local hit has no resolver-supplied original: the canonical
        // key of the entry it judged is the original-tuple supply.
        None,
    )
}

/// #12867 RED: a stale forward revalidation of a translated wire alias must
/// judge the canonical ORIGINAL source. Master judged the arriving public
/// tuple, so a permit naming only the original private source revoked the
/// live session (fail-closed against the wrong question), while a permit
/// naming only the translated public source kept it flowing — the fail-open
/// the issue reports. Both directions are pinned.
#[test]
fn zone_policy_snat_wire_alias_stale_judges_canonical_source_12867() {
    let case = snat_wire_alias_case_12867(NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("public pool source")),
        rewrite_src_port: Some(50_000),
        ..NatDecision::default()
    });
    assert_ne!(case.original.src_ip, case.wire.src_ip);
    assert_ne!(case.original.src_port, case.wire.src_port);
    let flow = SessionFlow {
        src_ip: case.wire.src_ip,
        dst_ip: case.wire.dst_ip,
        forward_key: case.wire.clone(),
    };

    // Permit names ONLY the original private source.
    let forwarding = snat_alias_policy_12867(&["10.0.0.1/32"], "");
    let mut sessions = install_stale_alias_session_12867(&case, &case.original);
    let revocation =
        revalidate_alias_hit_12867(&forwarding, &mut sessions, &case, &case.original, &flow);
    assert!(
        revocation.is_none(),
        "the stale alias must match its original-source permit"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&case.original),
        PolicyRevalidationTarget::Fresh,
        "the original-source permit must stamp the canonical row current"
    );

    // Permit names ONLY the translated public source: the alias must not
    // borrow it.
    let forwarding = snat_alias_policy_12867(&["203.0.113.10/32"], "");
    let mut sessions = install_stale_alias_session_12867(&case, &case.original);
    let revocation =
        revalidate_alias_hit_12867(&forwarding, &mut sessions, &case, &case.original, &flow);
    assert!(
        revocation
            .as_ref()
            .is_some_and(|revocation| revocation.canonical_key == Some(case.original.clone())),
        "a public-source permit must not keep the alias alive"
    );
}

/// #12867: the sessionless (#10582 keep-transient) verdict judges the
/// resolver-authenticated ORIGINAL tuple, and a translated sessionless
/// arrival without one fails closed instead of borrowing a public-source
/// permit.
#[test]
fn zone_policy_sessionless_snat_alias_uses_original_or_fails_closed_12867() {
    let case = snat_wire_alias_case_12867(NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("public pool source")),
        rewrite_src_port: Some(50_000),
        ..NatDecision::default()
    });
    let flow = SessionFlow {
        src_ip: case.wire.src_ip,
        dst_ip: case.wire.dst_ip,
        forward_key: case.wire.clone(),
    };
    let meta = crate::afxdp::tests_support::txn_meta_v4(24, 0x10, 54);
    let from_source = FromZoneSource::LiveIfindex {
        ifindex: 24,
        vlan: 0,
    };

    // The authenticated original matches an original-source permit: the
    // sessionless packet forwards.
    let forwarding = snat_alias_policy_12867(&["10.0.0.1/32"], "");
    assert!(
        sessionless_zone_policy_verdict(
            &forwarding,
            case.decision,
            &case.metadata,
            &flow,
            meta,
            from_source,
            SessionOrigin::SyncImport,
            1_100_000_000,
            Some(&case.original),
        )
        .is_none(),
        "the sessionless alias must match its original-source permit"
    );

    // Without the authenticated original, even an any-source permit must not
    // judge the public tuple: fail closed with a KEYLESS drop.
    let any_forwarding = snat_alias_policy_12867(&["any"], "");
    assert!(
        sessionless_zone_policy_verdict(
            &any_forwarding,
            case.decision,
            &case.metadata,
            &flow,
            meta,
            from_source,
            SessionOrigin::SyncImport,
            1_100_000_000,
            None,
        )
        .is_some_and(|revocation| revocation.canonical_key.is_none()),
        "an unauthenticated translated arrival must fail closed, not borrow a public-source permit"
    );
}

/// #12867 discriminator pins: a port-only translation (address preserved)
/// still judges the ORIGINAL port, and an original-direction packet of that
/// session is judged normally — the preserved address must not be misread as
/// a translated arrival.
#[test]
fn zone_policy_port_only_snat_judges_original_port_12867() {
    let case = snat_wire_alias_case_12867(NatDecision {
        rewrite_src: Some("10.0.0.1".parse().expect("address-preserving pool")),
        rewrite_src_port: Some(50_000),
        ..NatDecision::default()
    });
    // The alias differs from the original in the PORT only.
    assert_eq!(case.original.src_ip, case.wire.src_ip);
    assert_ne!(case.original.src_port, case.wire.src_port);

    // Permit names the ORIGINAL source port: the translated alias arrival
    // must match it through the canonical key (master judged the translated
    // port and revoked).
    let forwarding = snat_alias_policy_12867(&["any"], "45000");
    let alias_flow = SessionFlow {
        src_ip: case.wire.src_ip,
        dst_ip: case.wire.dst_ip,
        forward_key: case.wire.clone(),
    };
    let mut sessions = install_stale_alias_session_12867(&case, &case.original);
    let revocation = revalidate_alias_hit_12867(
        &forwarding,
        &mut sessions,
        &case,
        &case.original,
        &alias_flow,
    );
    assert!(
        revocation.is_none(),
        "the port-only alias must match its original source port"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&case.original),
        PolicyRevalidationTarget::Fresh,
        "the original-port permit must stamp the canonical row current"
    );

    // An ORIGINAL-direction packet of the same session is judged normally —
    // the preserved address must not trip the translated-arrival decline.
    let original_flow = SessionFlow {
        src_ip: case.original.src_ip,
        dst_ip: case.original.dst_ip,
        forward_key: case.original.clone(),
    };
    let mut sessions = install_stale_alias_session_12867(&case, &case.original);
    let revocation = revalidate_alias_hit_12867(
        &forwarding,
        &mut sessions,
        &case,
        &case.original,
        &original_flow,
    );
    assert!(
        revocation.is_none(),
        "an original-direction port-only SNAT packet must be judged, not declined"
    );
    assert_eq!(
        sessions.policy_revalidation_target(&case.original),
        PolicyRevalidationTarget::Fresh,
        "the original-direction packet must stamp the canonical row current"
    );
}

/// #12867: a row keyed on its own TRANSLATED tuple (a fabric wire seed or a
/// materialized alias replica) has no authenticated original on this node.
/// The stale arm must decline — neither judging nor stamping the public
/// tuple — rather than revoke on a verdict no walk derived. The next packet
/// resolves through the canonical row instead (the placeholder bypass in the
/// lookup), where the original selectors are derivable.
#[test]
fn zone_policy_translated_keyed_row_declines_without_stamping_12867() {
    let case = snat_wire_alias_case_12867(NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("public pool source")),
        rewrite_src_port: Some(50_000),
        ..NatDecision::default()
    });
    let flow = SessionFlow {
        src_ip: case.wire.src_ip,
        dst_ip: case.wire.dst_ip,
        forward_key: case.wire.clone(),
    };
    // No lan -> wan rule exists in the plain snapshot: only the default deny.
    let forwarding = crate::afxdp::forwarding_build::build_forwarding_state(
        &crate::afxdp::test_fixtures::policy_deny_snapshot(),
    );
    let mut sessions = install_stale_alias_session_12867(&case, &case.wire);
    let revocation =
        revalidate_alias_hit_12867(&forwarding, &mut sessions, &case, &case.wire, &flow);
    assert!(
        revocation.is_none(),
        "a translated-keyed row must be declined, not revoked on an underivable verdict"
    );
    assert!(
        matches!(
            sessions.policy_revalidation_target(&case.wire),
            PolicyRevalidationTarget::Stale(_)
        ),
        "the decline must not stamp the public tuple fresh"
    );
}

/// #13652: reverse-hit SNAT fixture. Builds the forward/reverse pair of an
/// imported dynamic-SNAT session (wire tuple 10.0.0.1:45000 ->
/// 198.51.100.1:443 translated to 203.0.113.10). Returns the call
/// arguments a reverse-direction session hit carries: the reverse row's
/// key/metadata/decision, the forward key, and the forward decision.
#[allow(clippy::type_complexity)]
fn reverse_snat_case_13652() -> (
    SessionKey,
    SessionKey,
    SessionDecision,
    SessionMetadata,
    SessionDecision,
    SessionMetadata,
    SessionOrigin,
    Option<bool>,
) {
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1, true),
        &zones,
        0,
    )
    .expect("dynamic SNAT session imports from HA wire");
    let forward_key = synced.key.clone();
    let forward_decision = synced.decision.clone();
    let reverse_key = crate::session::reverse_session_key(&forward_key, forward_decision.nat);
    let reverse_decision = SessionDecision {
        nat: forward_decision.nat.reverse(
            forward_key.src_ip,
            forward_key.dst_ip,
            forward_key.src_port,
            forward_key.dst_port,
        ),
        ..forward_decision
    };
    let mut reverse_metadata = synced.metadata.clone();
    reverse_metadata.is_reverse = true;
    reverse_metadata.ingress_zone = synced.metadata.egress_zone;
    reverse_metadata.egress_zone = synced.metadata.ingress_zone;
    (
        forward_key,
        reverse_key,
        forward_decision,
        synced.metadata.clone(),
        reverse_decision,
        reverse_metadata,
        synced.origin,
        synced.source_nat_static,
    )
}

fn reverse_snat_hit_13652(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    case: &(
        SessionKey,
        SessionKey,
        SessionDecision,
        SessionMetadata,
        SessionDecision,
        SessionMetadata,
        SessionOrigin,
        Option<bool>,
    ),
) -> Option<PolicyRevocation> {
    let flow = SessionFlow {
        src_ip: case.1.src_ip,
        dst_ip: case.1.dst_ip,
        forward_key: case.1.clone(),
    };
    let mut observed_metadata = case.5.clone_without_policy_counter();
    // The reverse row has no observed ingress identity; simulate a reply
    // arriving on VLAN 200, distinct from the forward ingress.
    observed_metadata.ingress_ifindex = 12;
    source_nat_revocation_on_session_hit_with_ingress(
        forwarding,
        sessions,
        &case.1,
        &observed_metadata,
        12,
        200,
        case.4,
        &flow,
        case.6,
        case.7,
        None,
        1_000_000_000,
    )
}

/// #13652: a keep-transient reverse hit (the reverse row is not in the
/// worker's local table) must still revalidate its forward companion's
/// translation when the SNAT rule has been withdrawn, exactly like the
/// forward `NoLocalEntry` arm checks the wire tuple sessionlessly. The
/// revocation derives from the forward entry: its canonical key, decision
/// and origin. Pre-fix this returned `None` at the first `?` — the stale
/// reply was reverse-translated and forwarded.
#[test]
fn reverse_transient_hit_revokes_when_snat_rule_withdrawn_13652() {
    let case = reverse_snat_case_13652();
    let mut no_rules = imported_snat_forwarding(false);
    no_rules.source_nat_rules = crate::nat::parse_source_nat_rules(&[]);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.0.clone(),
        case.2,
        case.3.clone(),
        case.6,
        1_000_000,
        case.0.protocol,
        0x02,
    ));
    sessions.mark_source_nat_revalidated(&case.0, Some(false));
    sessions.set_forwarding_revalidation_gen(2, 2);
    let revocation = reverse_snat_hit_13652(&no_rules, &mut sessions, &case);
    let revocation = revocation.expect(
        "a transient reverse hit whose translation the live NAT config no longer expresses must revoke",
    );
    assert_eq!(revocation.canonical_key.as_ref(), Some(&case.0));
    assert_eq!(revocation.decision.nat, case.2.nat);
    assert_eq!(revocation.origin, case.6);
    assert!(matches!(
        revocation.reason,
        PolicyRevocationReason::StaleSourceNat
    ));
}

/// #13652 control: an unchanged SNAT rule keeps the transient reverse hit
/// alive — the sessionless check must validate, not blanket-revoke.
#[test]
fn reverse_transient_hit_survives_unchanged_snat_13652() {
    let case = reverse_snat_case_13652();
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.0.clone(),
        case.2,
        case.3.clone(),
        case.6,
        1_000_000,
        case.0.protocol,
        0x02,
    ));
    sessions.mark_source_nat_revalidated(&case.0, Some(false));
    sessions.set_forwarding_revalidation_gen(2, 2);
    assert!(
        reverse_snat_hit_13652(&imported_snat_forwarding(false), &mut sessions, &case).is_none(),
        "an unchanged dynamic SNAT must survive a transient reverse hit"
    );
}

/// #13652: a locally present reverse row without its forward companion
/// must still run the reverse-translated tuple's sessionless source-NAT
/// check. Missing local ownership means drop-only revocation, not permission
/// to carry an obsolete translation.
#[test]
fn reverse_hit_without_local_forward_companion_revokes_sessionlessly_13652() {
    let case = reverse_snat_case_13652();
    let mut no_rules = imported_snat_forwarding(false);
    no_rules.source_nat_rules = crate::nat::parse_source_nat_rules(&[]);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.1.clone(),
        case.4,
        case.5.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000,
        case.1.protocol,
        0x10,
    ));
    let revocation = reverse_snat_hit_13652(&no_rules, &mut sessions, &case)
        .expect("a reverse hit with stale SNAT and no local forward row must drop");
    assert!(
        revocation.canonical_key.is_none(),
        "sessionless revocation must not claim ownership of a peer row"
    );
    assert!(matches!(
        revocation.reason,
        PolicyRevocationReason::StaleSourceNat
    ));
    assert_eq!(
        sessions.len(),
        1,
        "sessionless validation does not tear down a row"
    );
}

/// #13652 control (guarded twin): forward row installed and stale, reverse
/// row installed — the pre-existing path revokes on a withdrawn rule.
#[test]
fn reverse_installed_pair_revokes_when_snat_rule_withdrawn_13652() {
    let case = reverse_snat_case_13652();
    let mut no_rules = imported_snat_forwarding(false);
    no_rules.source_nat_rules = crate::nat::parse_source_nat_rules(&[]);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.0.clone(),
        case.2,
        case.3.clone(),
        case.6,
        1_000_000,
        case.0.protocol,
        0x02,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        case.1.clone(),
        case.4,
        case.5.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000,
        case.1.protocol,
        0x10,
    ));
    sessions.mark_source_nat_revalidated(&case.0, Some(false));
    sessions.set_forwarding_revalidation_gen(2, 2);
    let revocation = reverse_snat_hit_13652(&no_rules, &mut sessions, &case)
        .expect("an installed reverse hit must revoke when the SNAT rule is withdrawn");
    assert_eq!(revocation.canonical_key.as_ref(), Some(&case.0));
}

/// #13771 regression fixture: no reverse row retained. The synthesized
/// reverse metadata deliberately has no observed ingress interface, as in
/// production, and its resolution is for traffic back toward the client.
fn reverse_snat_case_from_production_13771(
    forwarding: &ForwardingState,
) -> (
    SessionKey,
    SessionKey,
    SessionDecision,
    SessionMetadata,
    SessionDecision,
    SessionMetadata,
    SessionOrigin,
    Option<bool>,
) {
    let (
        forward_key,
        _reverse_key,
        forward_decision,
        forward_metadata,
        _reverse_decision,
        _reverse_metadata,
        origin,
        provenance,
    ) = reverse_snat_case_13652();
    let forward_match = crate::session::ForwardSessionMatch {
        key: forward_key.clone(),
        decision: forward_decision,
        metadata: SessionMetadata {
            ingress_ifindex: 11,
            ingress_vlan_id: forwarding
                .egress
                .get(&11)
                .map(|iface| iface.vlan_id)
                .expect("LAN interface"),
            ..forward_metadata.clone()
        },
        forwarding_generation: crate::session::ForwardingGenerationStamp::default(),
        aux: crate::session::SessionLookupAux {
            session_id: 0,
            source_nat_static: provenance,
            leak_incarnation: 0,
        },
    };
    let reverse = crate::afxdp::shared_ops::build_reverse_session_from_forward_match(
        forwarding,
        &BTreeMap::new(),
        &Arc::new(crate::afxdp::ShardedNeighborMap::new()),
        forward_match,
        0,
        0,
    );
    let reverse_key = crate::session::reverse_session_key(&forward_key, forward_decision.nat);
    assert_eq!(reverse.aux.source_nat_static, Some(false));
    assert_eq!(
        reverse.decision.resolution.egress_ifindex, 11,
        "production reverse synthesis resolves toward the client-side LAN"
    );
    (
        forward_key,
        reverse_key,
        forward_decision,
        forward_metadata,
        reverse.decision,
        reverse.metadata,
        origin,
        reverse.aux.source_nat_static,
    )
}

/// #13771 fixture: distinct LAN (11) and WAN (12) interfaces, with an
/// unchanged interface-SNAT rule and optionally an interface-scoped pool.
fn reverse_snat_forwarding_13771(with_pool: bool) -> ForwardingState {
    let mut forwarding = imported_snat_forwarding(false);
    forwarding.ifindex_to_zone_id.insert(11, 1);
    forwarding.ifindex_to_zone_id.insert(12, 2);
    forwarding
        .ifindex_to_config_name
        .insert(11, "ge-0/0/0.0".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(12, "ge-0/0/1.0".to_string());
    forwarding.egress.insert(
        11,
        EgressInterface {
            bind_ifindex: 11,
            vlan_id: 0,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 1,
            redundancy_group: 0,
            primary_v4: Some("10.0.0.254".parse().expect("LAN IPv4")),
            primary_v6: None,
        },
    );
    forwarding
        .egress
        .get_mut(&12)
        .expect("WAN interface")
        .primary_v4 = Some("203.0.113.10".parse().expect("WAN IPv4"));
    let next_hop = Ipv4Addr::new(10, 0, 0, 254);
    forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![RouteEntryV4 {
            prefix: PrefixV4::from_net(
                Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 24).expect("LAN route"),
            ),
            next_hops: vec![RouteNextHopV4 {
                next_hop: Some(next_hop),
                ifindex: 11,
                logical_interface_id: 0,
                tunnel_endpoint_id: 0,
                weight: 1,
            }],
            discard: false,
            reject: false,
            next_table: String::new(),
            preference: 0,
            mtu: 1500,
            rule_priority: 0,
        }],
    );
    forwarding
        .neighbors
        .insert((11, IpAddr::V4(next_hop)), NeighborEntry { mac: [0; 6] });
    let rules = if with_pool {
        vec![crate::protocol::SourceNATRuleSnapshot {
            name: "scoped-pool".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            from_interface: "ge-0/0/0.0".to_string(),
            to_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        }]
    } else {
        vec![crate::protocol::SourceNATRuleSnapshot {
            name: "iface-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            interface_mode: true,
            ..Default::default()
        }]
    };
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&rules);
    forwarding
}

/// #13771: unchanged interface-SNAT must survive a reverse hit without a
/// local forward companion. The companion resolution points toward LAN, but
/// the source-NAT validator must use the original forward LAN->WAN context.
#[test]
fn reverse_without_companion_unchanged_interface_snat_survives_13771() {
    for with_pool in [false, true] {
        let forwarding = reverse_snat_forwarding_13771(with_pool);
        let case = reverse_snat_case_from_production_13771(&forwarding);
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(1, 1);
        assert!(
            reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_none(),
            "unchanged interface-SNAT must survive (pool={with_pool})"
        );
    }
}
/// #13789: reverse-side VLAN 200 must not replace forward ingress VLAN 100
/// when validating a companion-less SNAT translation.
#[test]
fn reverse_without_companion_uses_forward_vlan_for_snat_scope_13789() {
    let mut forwarding = reverse_snat_forwarding_13771(true);
    forwarding
        .egress
        .get_mut(&11)
        .expect("LAN interface")
        .vlan_id = 100;
    forwarding.ingress_logical_ifindex.insert((11, 200), 14);
    forwarding
        .ifindex_to_config_name
        .insert(11, "ge-0/0/0.100".to_string());
    forwarding
        .ifindex_to_config_name
        .insert(14, "ge-0/0/0.200".to_string());
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "forward-vlan-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            from_interface: "ge-0/0/0.100".to_string(),
            to_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        }]);
    let case = reverse_snat_case_from_production_13771(&forwarding);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(
        reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_none(),
        "forward VLAN 100 SNAT must survive reverse ingress on VLAN 200"
    );
}

/// #13789 symmetry control: equal forward/reverse VLANs still validate.
#[test]
fn reverse_without_companion_symmetric_vlan_snat_scope_survives_13789() {
    let mut forwarding = reverse_snat_forwarding_13771(true);
    forwarding
        .egress
        .get_mut(&11)
        .expect("LAN interface")
        .vlan_id = 200;
    forwarding.ingress_logical_ifindex.insert((11, 200), 14);
    forwarding
        .ifindex_to_config_name
        .insert(14, "ge-0/0/0.200".to_string());
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "symmetric-vlan-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            from_interface: "ge-0/0/0.200".to_string(),
            to_interface: "ge-0/0/1.0".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            ..Default::default()
        }]);
    let case = reverse_snat_case_from_production_13771(&forwarding);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(
        reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_none(),
        "symmetric VLAN SNAT scope must survive"
    );
}

/// #13771 negative control: withdrawing SNAT still revokes a
/// companion-less reverse hit.
#[test]
fn reverse_without_companion_withdrawn_snat_revokes_13771() {
    let forwarding = reverse_snat_forwarding_13771(false);
    let case = reverse_snat_case_from_production_13771(&forwarding);
    let mut no_rules = forwarding.clone();
    no_rules.source_nat_rules = crate::nat::parse_source_nat_rules(&[]);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    let revocation = reverse_snat_hit_13652(&no_rules, &mut sessions, &case)
        .expect("withdrawn SNAT must revoke a companion-less reverse hit");
    assert!(revocation.canonical_key.is_none());
    assert!(matches!(
        revocation.reason,
        PolicyRevocationReason::StaleSourceNat
    ));
}

/// #13771: when local-only SNAT provenance is missing, unchanged rules must
/// not validate a synthesized reverse row by guessing dynamic vs static.
#[test]
fn reverse_without_companion_missing_snat_provenance_fails_closed_13771() {
    let forwarding = reverse_snat_forwarding_13771(false);
    let mut case = reverse_snat_case_from_production_13771(&forwarding);
    case.7 = None;
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    let revocation = reverse_snat_hit_13652(&forwarding, &mut sessions, &case)
        .expect("missing SNAT provenance remains fail-closed");
    assert!(revocation.canonical_key.is_none());
    assert!(matches!(
        revocation.reason,
        PolicyRevocationReason::StaleSourceNat
    ));
}

/// #13910: #13789's early return skipped the provenance fail-closed arm for
/// companion-less NAT64/NPTv6 reverse hits too. The source-NAT validator
/// returns (true, None) unconditionally for NAT64/NPTv6, so missing forward
/// VLAN provenance was their only stale-translation guard.
#[test]
fn reverse_without_companion_nat64_nptv6_missing_provenance_fails_closed_13910() {
    for (shape, nat64, nptv6) in [
        ("nat64", true, false),
        ("nptv6", false, true),
        ("nat64+nptv6", true, true),
    ] {
        let forwarding = reverse_snat_forwarding_13771(false);
        let mut case = reverse_snat_case_from_production_13771(&forwarding);
        case.5.forward_ingress_vlan_id = None;
        assert!(
            case.5.forward_ingress_vlan_id.is_none(),
            "{shape}: fixture must have missing forward VLAN provenance"
        );
        case.4.nat.nat64 = nat64;
        case.4.nat.nptv6 = nptv6;
        case.4.nat.rewrite_src = Some("203.0.113.10".parse().expect("translated source"));
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(1, 1);
        let revocation =
            reverse_snat_hit_13652(&forwarding, &mut sessions, &case).unwrap_or_else(|| {
                panic!(
                    "{shape}: translated reverse hit without forward VLAN provenance \
                     must fail closed"
                )
            });
        assert!(revocation.canonical_key.is_none());
        assert!(matches!(
            revocation.reason,
            PolicyRevocationReason::StaleSourceNat
        ));
        assert_eq!(
            sessions.len(),
            0,
            "{shape}: drop-only verdict installs nothing"
        );
    }
}

/// #13910 control (NAT64): with recorded forward VLAN provenance the hit is
/// not rejected by the provenance arm. NAT64 stays exempt from rule-table
/// re-derivation (#14315: prefix-driven, no withdrawn rule to consult), so
/// provenance remains its only stale-translation guard.
/// The NPTv6 shape moved to
/// `reverse_without_companion_nptv6_rederived_14315`: #14315 now re-derives
/// NPTv6 from live state, and this fixture's forwarding carries no NPTv6 rule
/// (its rewrite is an IPv4 SNAT pool address), so it correctly fails closed.
#[test]
fn reverse_without_companion_nat64_nptv6_with_provenance_survives_13910() {
    let forwarding = reverse_snat_forwarding_13771(false);
    let mut case = reverse_snat_case_from_production_13771(&forwarding);
    case.5.forward_ingress_vlan_id = Some(100);
    case.4.nat.nat64 = true;
    case.4.nat.nptv6 = false;
    case.4.nat.rewrite_src = Some("203.0.113.10".parse().expect("translated source"));
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(
        reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_none(),
        "nat64: recorded forward provenance must let the reverse hit pass"
    );
}

/// #14315: a companion-less NPTv6 reverse hit is re-derived from live NPTv6
/// state. The #13910 fixture carries no such rule, so it now fails closed
/// even with forward VLAN provenance — the pre-#14315 blanket
/// `(destination_valid, None)` return for `nptv6` is gone.
#[test]
fn reverse_without_companion_nptv6_rederived_14315() {
    let forwarding = reverse_snat_forwarding_13771(false);
    let mut case = reverse_snat_case_from_production_13771(&forwarding);
    case.5.forward_ingress_vlan_id = Some(100);
    case.4.nat.nat64 = false;
    case.4.nat.nptv6 = true;
    case.4.nat.rewrite_src = Some("203.0.113.10".parse().expect("translated source"));
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(
        reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_some(),
        "nptv6: no live NPTv6 rule re-derives the stored rewrite, so it must fail closed (#14315)"
    );
}

/// #13910 pin of #13789's intended narrowing: a companion-less reverse hit
/// with NO source rewrite and no NAT64/NPTv6 translation is deliberately
/// permitted through to the ordinary policy gate despite missing forward
/// VLAN provenance.
#[test]
fn reverse_without_companion_no_rewrite_missing_provenance_permitted_13910() {
    let forwarding = reverse_snat_forwarding_13771(false);
    let mut case = reverse_snat_case_from_production_13771(&forwarding);
    case.5.forward_ingress_vlan_id = None;
    assert!(case.5.forward_ingress_vlan_id.is_none());
    case.4.nat.rewrite_src = None;
    case.4.nat.rewrite_dst = None;
    case.4.nat.nat64 = false;
    case.4.nat.nptv6 = false;
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(
        reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_none(),
        "untranslated reverse hit must pass through to the policy gate"
    );
}
#[test]
fn established_session_is_revoked_when_its_dnat_rule_is_withdrawn_13923() {
    let zones = rustc_hash::FxHashMap::from_iter([("lan".to_string(), 1), ("wan".to_string(), 2)]);
    let mut synced = crate::server::helpers::build_synced_session_entry(
        &imported_snat_request(1, true),
        &zones,
        0,
    )
    .expect("HA session fixture");
    let translated_dst: IpAddr = "10.0.0.10".parse().expect("translated destination");
    synced.decision.nat.rewrite_dst = Some(translated_dst);
    synced.decision.nat.rewrite_dst_port = Some(8443);
    let key = synced.key.clone();
    let decision = synced.decision;
    let metadata = synced.metadata.clone();
    let origin = synced.origin;
    let source_nat_static = synced.source_nat_static;
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key.clone(),
    };
    let rule = crate::protocol::DestinationNATRuleSnapshot {
        name: "web-forward".to_string(),
        destination_address: "198.51.100.1".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.0.10".to_string(),
        pool_port: 8443,
        ..Default::default()
    };
    let mut configured = imported_snat_forwarding(false);
    configured.dnat_table =
        crate::nat::DnatTable::from_snapshots(&[rule], &crate::nat::NatCounterStore::default());
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.upsert_synced_with_origin(synced.into_session_install(1), false));
    assert!(
        source_nat_revocation_on_session_hit(
            &configured,
            &mut sessions,
            &key,
            &metadata,
            decision,
            &flow,
            origin,
            source_nat_static,
            None,
            1_000_000_000,
        )
        .is_none(),
        "the session must survive while its port-forward still matches"
    );
    sessions.set_forwarding_revalidation_gen(2, 2);
    let withdrawn = imported_snat_forwarding(false);
    assert!(
        source_nat_revocation_on_session_hit(
            &withdrawn,
            &mut sessions,
            &key,
            &metadata,
            decision,
            &flow,
            origin,
            source_nat_static,
            None,
            1_000_000_000,
        )
        .is_some(),
        "withdrawing the destination-NAT rule must revoke the established session"
    );
}
#[test]
fn companionless_reverse_dnat_hit_revokes_after_rule_withdrawal_13923() {
    let (
        forward_key,
        _,
        mut forward_decision,
        forward_metadata,
        _,
        mut reverse_metadata,
        origin,
        _,
    ) = reverse_snat_case_13652();
    forward_decision.nat.rewrite_src = None;
    forward_decision.nat.rewrite_src_port = None;
    forward_decision.nat.rewrite_dst = Some("10.0.0.10".parse().expect("server address"));
    forward_decision.nat.rewrite_dst_port = Some(8443);
    let reverse_key = crate::session::reverse_session_key(&forward_key, forward_decision.nat);
    let reverse_decision = SessionDecision {
        nat: forward_decision.nat.reverse(
            forward_key.src_ip,
            forward_key.dst_ip,
            forward_key.src_port,
            forward_key.dst_port,
        ),
        ..forward_decision
    };
    reverse_metadata.forward_ingress_vlan_id = Some(0);
    let case = (
        forward_key,
        reverse_key,
        forward_decision,
        forward_metadata,
        reverse_decision,
        reverse_metadata,
        origin,
        None,
    );
    let rule = crate::protocol::DestinationNATRuleSnapshot {
        name: "web-forward".to_string(),
        destination_address: "198.51.100.1".to_string(),
        destination_port: 443,
        protocol: "tcp".to_string(),
        pool_address: "10.0.0.10".to_string(),
        pool_port: 8443,
        ..Default::default()
    };
    let mut configured = imported_snat_forwarding(false);
    configured.dnat_table =
        crate::nat::DnatTable::from_snapshots(&[rule], &crate::nat::NatCounterStore::default());
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.1.clone(),
        case.4,
        case.5.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000,
        case.1.protocol,
        0x10,
    ));
    assert!(
        reverse_snat_hit_13652(&configured, &mut sessions, &case).is_none(),
        "the reverse-only hit survives while its port-forward remains configured"
    );
    let withdrawn = imported_snat_forwarding(false);
    let revocation = reverse_snat_hit_13652(&withdrawn, &mut sessions, &case)
        .expect("a reverse-only DNAT hit must be revoked after the rule is withdrawn");
    assert!(
        revocation.canonical_key.is_none(),
        "sessionless revocation must not claim a forward row"
    );
}

// ---------------------------------------------------------------------------
// #14128: source-NAT revalidation on reverse-only sessions. Three bundled
// defects in the companion-less reverse reconstruction:
//   (a) `NatDecision::reverse` dropped `source_nat_icmp` (type/code), so a
//       PAT ICMP mapping reconstructed without type/code was misread as
//       portless and its translated identifier rejected;
//   (b) the reconstructed forward egress was the physical arrival ifindex,
//       not the logical VLAN unit `forwarding.egress` is keyed by, so
//       interface-SNAT on the logical unit was spuriously revoked;
//   (c) `source_nat_translation_matches` accepted a stored portless mapping
//       under a PAT rule when the ORIGINAL src_port fell in the pool range
//       (no-translation -> PAT laundering).
// ---------------------------------------------------------------------------

/// #14128 (a): companion-less reverse hit for an ICMP PAT flow. The forward
/// half is absent locally; the reverse row was synthesized from a forward
/// decision carrying `source_nat_icmp = (8,0)` (echo-request). Pre-fix the
/// double `reverse()` dropped the type/code and the validator took the
/// portless branch (`translated_src_port.is_none()` == false) -> false
/// `StaleSourceNat`. The typed pool rule (echo-request only) also pins that
/// the restored type/code actually reaches rule matching: a timestamp-only
/// rule must still revoke.
#[test]
fn reverse_only_icmp_pat_survives_revalidation_14128() {
    // Forward: 10.0.0.1 icmp-id 0x1234 -> 198.51.100.1, PAT to
    // 203.0.113.10 icmp-id 45000 under an echo-request pool rule.
    let forward_key = SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: libc::IPPROTO_ICMP as u8,
        src_ip: "10.0.0.1".parse().expect("client"),
        dst_ip: "198.51.100.1".parse().expect("server"),
        src_port: 0x1234,
        dst_port: 0,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    };
    let forward_nat = NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("pool address")),
        rewrite_src_port: Some(45_000),
        source_nat_icmp: Some((8, 0)),
        ..Default::default()
    };
    let forward_decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: forward_nat,
        install_table_domain: 0,
        install_table_check: 0,
    };
    let forward_metadata = SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 11,
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
        forward_ingress_vlan_id: None,
    };
    // Production reverse synthesis (also exercises the `reverse()` at
    // shared_ops/reverse_synth.rs, not just the revalidation one).
    let forward_match = crate::session::ForwardSessionMatch {
        key: forward_key.clone(),
        decision: forward_decision,
        metadata: SessionMetadata {
            ingress_ifindex: 11,
            ingress_vlan_id: 0,
            ..forward_metadata.clone()
        },
        forwarding_generation: crate::session::ForwardingGenerationStamp::default(),
        aux: crate::session::SessionLookupAux {
            session_id: 0,
            source_nat_static: Some(false),
            leak_incarnation: 0,
        },
    };
    let mut forwarding = reverse_snat_forwarding_13771(true);
    forwarding.ifindex_unambiguous_zone_id.insert(11, 1);
    forwarding.ifindex_unambiguous_zone_id.insert(12, 2);
    // Replace the TCP-scoped pool with a typed ICMP PAT pool: echo-request
    // (8,0) only, pool 203.0.113.10, identifier range 45000..=45000.
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "icmp-pat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            match_applications: vec![crate::protocol::NatAppTermWire {
                protocol: 1,
                icmp_type: Some(8),
                icmp_code: Some(0),
                ..Default::default()
            }],
            ..Default::default()
        }]);
    let reverse = crate::afxdp::shared_ops::build_reverse_session_from_forward_match(
        &forwarding,
        &BTreeMap::new(),
        &Arc::new(crate::afxdp::ShardedNeighborMap::new()),
        forward_match,
        0,
        0,
    );
    // The reverse decision must retain the forward type/code after the fix.
    assert_eq!(
        reverse.decision.nat.source_nat_icmp,
        Some((8, 0)),
        "reverse() must preserve source_nat_icmp (#14128)"
    );
    let reverse_key = crate::session::reverse_session_key(&forward_key, forward_nat);
    let case = (
        forward_key.clone(),
        reverse_key,
        forward_decision,
        forward_metadata,
        reverse.decision,
        reverse.metadata,
        SessionOrigin::SyncImport,
        reverse.aux.source_nat_static,
    );
    // Only the reverse row is installed locally — the forward half is absent,
    // so the hit takes the NoLocalEntry reconstruction.
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.1.clone(),
        case.4,
        case.5.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000,
        case.1.protocol,
        0x10,
    ));
    sessions.set_source_nat_static(&case.1, case.7);
    assert!(
        reverse_snat_hit_13652(&forwarding, &mut sessions, &case).is_none(),
        "unchanged ICMP PAT must survive a companion-less reverse hit (#14128)"
    );
    // Typed control: a rule for a DIFFERENT ICMP type (timestamp 13,0) must
    // not validate the echo mapping — the restored type/code is load-bearing,
    // not a blanket ICMP pass.
    let mut other_type = forwarding.clone();
    other_type.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "icmp-other-type".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.1/32".to_string()],
            pool_addresses: vec!["203.0.113.10/32".to_string()],
            port_low: 45_000,
            port_high: 45_000,
            match_applications: vec![crate::protocol::NatAppTermWire {
                protocol: 1,
                icmp_type: Some(13),
                icmp_code: Some(0),
                ..Default::default()
            }],
            ..Default::default()
        }]);
    let revocation = reverse_snat_hit_13652(&other_type, &mut sessions, &case)
        .expect("a different-type ICMP rule must revoke the echo PAT mapping");
    assert!(matches!(
        revocation.reason,
        PolicyRevocationReason::StaleSourceNat
    ));
}

/// #14128 (b): companion-less reverse hit arriving on a VLAN trunk. The WAN
/// egress is logical unit 13 (VLAN 50 on physical parent 12) whose primary
/// address is the interface-SNAT address; the parent row 12 carries a
/// DIFFERENT address. Pre-fix the reconstruction keyed `forwarding.egress`
/// on the physical arrival ifindex (12) and compared against the parent's
/// address -> false `StaleSourceNat`. The parent address must NOT validate:
/// only the logical unit's address expresses the interface translation.
#[test]
fn reverse_only_vlan_interface_snat_survives_14128() {
    let mut forwarding = reverse_snat_forwarding_13771(false);
    // WAN trunk: physical parent 12 (bind), logical unit 13 on VLAN 50.
    forwarding.egress.insert(
        13,
        EgressInterface {
            bind_ifindex: 12,
            vlan_id: 50,
            mtu: 1500,
            src_mac: [0; 6],
            zone_id: 2,
            redundancy_group: 0,
            primary_v4: Some("203.0.113.10".parse().expect("logical WAN IPv4")),
            primary_v6: None,
        },
    );
    forwarding
        .egress
        .get_mut(&12)
        .expect("WAN parent")
        .primary_v4 = Some("198.51.100.254".parse().expect("parent WAN IPv4"));
    forwarding.ingress_logical_ifindex.insert((12, 50), 13);
    // Interface-SNAT rule (unchanged): translate to the egress interface's
    // own address — the logical unit's 203.0.113.10, not the parent's.
    let case = reverse_snat_case_from_production_13771(&forwarding);
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    assert!(sessions.install_with_protocol_with_origin(
        case.1.clone(),
        case.4,
        case.5.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000,
        case.1.protocol,
        0x10,
    ));
    // The reply arrives on the physical parent with VLAN 50.
    let flow = SessionFlow {
        src_ip: case.1.src_ip,
        dst_ip: case.1.dst_ip,
        forward_key: case.1.clone(),
    };
    let mut observed_metadata = case.5.clone_without_policy_counter();
    observed_metadata.ingress_ifindex = 12;
    observed_metadata.ingress_vlan_id = 50;
    assert!(
        source_nat_revocation_on_session_hit_with_ingress(
            &forwarding,
            &mut sessions,
            &case.1,
            &observed_metadata,
            12,
            50,
            case.4,
            &flow,
            case.6,
            case.7,
            None,
            1_000_000_000,
        )
        .is_none(),
        "interface-SNAT on logical VLAN unit 13 must survive a companion-less reverse hit (#14128)"
    );
    // Anti-laundering control: if the logical unit's address changes so the
    // stored translation is no longer the interface address, the same hit
    // must revoke — logical resolution must not become a blanket pass.
    let mut changed = forwarding.clone();
    changed.egress.get_mut(&13).expect("logical WAN").primary_v4 =
        Some("203.0.113.99".parse().expect("changed logical IPv4"));
    assert!(
        source_nat_revocation_on_session_hit_with_ingress(
            &changed,
            &mut sessions,
            &case.1,
            &observed_metadata,
            12,
            50,
            case.4,
            &flow,
            case.6,
            case.7,
            None,
            1_000_000_000,
        )
        .is_some(),
        "a logical-unit address change must revoke the stale interface translation"
    );
}

/// #14128 (c): translation-provenance invariant at the validator. A session
/// installed under `port no-translation` (address-only, no translated port,
/// original src_port inside the pool range) must NOT survive a reconfigure
/// to PAT: the PAT rule never allocated that mapping. Pre-fix the
/// `translated_src_port.map_or(contains(&src_port))` fallback accepted it.
/// The genuine no-translation rule must still validate the same mapping,
/// and a real PAT mapping (translated port in range) must still validate.
#[test]
fn source_nat_translation_matches_no_translation_to_pat_revokes_14128() {
    let pat_rules = crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
        name: "pat".to_string(),
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["10.0.0.1/32".to_string()],
        pool_addresses: vec!["203.0.113.10/32".to_string()],
        port_low: 40_000,
        port_high: 50_000,
        ..Default::default()
    }]);
    let mut no_translation = pat_rules.clone();
    no_translation[0].no_translation = true;
    let src: IpAddr = "10.0.0.1".parse().expect("src");
    let dst: IpAddr = "198.51.100.1".parse().expect("dst");
    let translated: IpAddr = "203.0.113.10".parse().expect("translated");
    // Address-only mapping: original port 45000 (inside the PAT range),
    // no translated port — installed under `port no-translation`.
    assert!(
        crate::nat::source_nat_translation_matches(
            &no_translation,
            &crate::nat::NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            6,
            45_000,
            443,
            None,
            translated,
            None,
            None,
            None,
        ),
        "the address-only mapping must validate under its own no-translation rule"
    );
    assert!(
        !crate::nat::source_nat_translation_matches(
            &pat_rules,
            &crate::nat::NatScopeCtx::default(),
            "lan",
            "wan",
            src,
            dst,
            6,
            45_000,
            443,
            None,
            translated,
            None,
            None,
            None,
        ),
        "a portless mapping must not be laundered by a PAT rule via the original src_port (#14128)"
    );
    // Real PAT mapping still validates; out-of-range translated port does not.
    assert!(crate::nat::source_nat_translation_matches(
        &pat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        6,
        45_000,
        443,
        None,
        translated,
        Some(46_000),
        None,
        None,
    ));
    assert!(!crate::nat::source_nat_translation_matches(
        &pat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        6,
        45_000,
        443,
        None,
        translated,
        Some(60_000),
        None,
        None,
    ));
    // ICMP PAT without reconstructed type/code: the translated identifier
    // alone (in range) must validate — this is the (a) mechanism at the
    // validator level, independent of `NatDecision::reverse`.
    assert!(crate::nat::source_nat_translation_matches(
        &pat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        libc::IPPROTO_ICMP as u8,
        0x1234,
        0,
        None,
        translated,
        Some(45_000),
        None,
        None,
    ));
    // A PAT-typed stored port under a no-translation rule must not validate
    // (the inverse reconfigure direction stays fail-closed).
    assert!(!crate::nat::source_nat_translation_matches(
        &no_translation,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        src,
        dst,
        6,
        45_000,
        443,
        None,
        translated,
        Some(46_000),
        None,
        None,
    ));
}

// ---------------------------------------------------------------------------
// #14315: destination/source NAT revalidation must not bypass NPTv6 or
// non-TCP/UDP translations, must keep live Persistent-NAT inbound bindings,
// and must stay read-only w.r.t. per-rule hit counters.
// ---------------------------------------------------------------------------

const NOW_14315: u64 = 1_000_000_000;

fn meta_14315(ingress_zone: u16, egress_zone: u16) -> SessionMetadata {
    SessionMetadata {
        ingress_zone,
        egress_zone,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: 1,
        fabric_ingress: true,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        forward_ingress_vlan_id: None,
    }
}

fn key_14315(protocol: u8, src: &str, dst: &str, src_port: u16, dst_port: u16) -> SessionKey {
    SessionKey {
        addr_family: if src.contains(':') {
            libc::AF_INET6 as u8
        } else {
            libc::AF_INET as u8
        },
        protocol,
        src_ip: src.parse().expect("src ip"),
        dst_ip: dst.parse().expect("dst ip"),
        src_port,
        dst_port,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

fn decision_14315(nat: NatDecision) -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
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

/// (a1) A withdrawn ICMP DNAT rule must revoke: pre-fix the
/// `!has_l4_ports` early return kept every ICMP/GRE/ESP translation alive.
#[test]
fn withdrawn_icmp_dnat_revokes_14315() {
    let key = key_14315(
        libc::IPPROTO_ICMP as u8,
        "198.51.100.9",
        "203.0.113.7",
        0x1234,
        0,
    );
    let decision = decision_14315(NatDecision {
        rewrite_dst: Some("10.0.0.7".parse().expect("internal")),
        ..NatDecision::default()
    });
    let metadata = meta_14315(2, 1);
    let rule = crate::protocol::DestinationNATRuleSnapshot {
        name: "icmp-forward".to_string(),
        destination_address: "203.0.113.7".to_string(),
        pool_address: "10.0.0.7".to_string(),
        ..Default::default()
    };
    let mut configured = ForwardingState::default();
    configured.dnat_table =
        crate::nat::DnatTable::from_snapshots(&[rule], &crate::nat::NatCounterStore::default());
    assert!(
        destination_nat_translation_still_valid(&configured, &decision, &metadata, &key, NOW_14315),
        "ICMP DNAT session must validate while its rule exists"
    );
    let withdrawn = ForwardingState::default();
    assert!(
        !destination_nat_translation_still_valid(&withdrawn, &decision, &metadata, &key, NOW_14315),
        "withdrawing the ICMP DNAT rule must invalidate the session (#14315)"
    );
}

/// (a2) Same for a GRE static-NAT (whole-address) mapping.
#[test]
fn withdrawn_gre_static_nat_revokes_14315() {
    let key = key_14315(libc::IPPROTO_GRE as u8, "198.51.100.9", "203.0.113.8", 0, 0);
    let decision = decision_14315(NatDecision {
        rewrite_dst: Some("10.0.0.8".parse().expect("internal")),
        ..NatDecision::default()
    });
    let metadata = meta_14315(2, 1);
    let mut configured = ForwardingState::default();
    configured.static_nat = crate::nat::StaticNatTable::from_snapshots(
        &[crate::protocol::StaticNATRuleSnapshot {
            name: "gre-static".to_string(),
            external_ip: "203.0.113.8".to_string(),
            internal_ip: "10.0.0.8".to_string(),
            ..Default::default()
        }],
        &crate::nat::NatCounterStore::default(),
    );
    assert!(
        destination_nat_translation_still_valid(&configured, &decision, &metadata, &key, NOW_14315),
        "GRE static-NAT session must validate while its rule exists"
    );
    let withdrawn = ForwardingState::default();
    assert!(
        !destination_nat_translation_still_valid(&withdrawn, &decision, &metadata, &key, NOW_14315),
        "withdrawing the GRE static-NAT rule must invalidate the session (#14315)"
    );
}

fn nptv6_forwarding_14315() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.nptv6 =
        crate::nptv6::Nptv6State::from_snapshots(&[crate::protocol::Nptv6RuleSnapshot {
            name: "npt".to_string(),
            internal_prefix: "fd00:1::/48".to_string(),
            external_prefix: "2001:db8:1::/48".to_string(),
            ..Default::default()
        }]);
    forwarding
}

/// (a3) A withdrawn NPTv6 prefix rule must revoke both directions.
#[test]
fn withdrawn_nptv6_prefix_revokes_14315() {
    let configured = nptv6_forwarding_14315();
    let withdrawn = ForwardingState::default();
    // Inbound: wire dst in external prefix -> internal.
    let mut internal = "2001:db8:1::1234"
        .parse::<std::net::Ipv6Addr>()
        .expect("v6");
    assert!(configured.nptv6.translate_inbound(&mut internal, ""));
    let in_key = key_14315(6, "2001:db8:9::1", "2001:db8:1::1234", 40000, 443);
    let in_decision = decision_14315(NatDecision {
        rewrite_dst: Some(IpAddr::V6(internal)),
        nptv6: true,
        ..NatDecision::default()
    });
    let metadata = meta_14315(2, 1);
    assert!(
        destination_nat_translation_still_valid(
            &configured,
            &in_decision,
            &metadata,
            &in_key,
            NOW_14315
        ),
        "NPTv6 inbound session must validate while its prefix rule exists"
    );
    assert!(
        !destination_nat_translation_still_valid(
            &withdrawn,
            &in_decision,
            &metadata,
            &in_key,
            NOW_14315
        ),
        "withdrawing the NPTv6 prefix must invalidate the inbound session (#14315)"
    );
    // Outbound: internal src -> external.
    let mut external = "fd00:1::1234".parse::<std::net::Ipv6Addr>().expect("v6");
    assert!(configured.nptv6.translate_outbound(&mut external, ""));
    let out_key = key_14315(6, "fd00:1::1234", "2001:db8:9::1", 40000, 443);
    let out_decision = decision_14315(NatDecision {
        rewrite_src: Some(IpAddr::V6(external)),
        nptv6: true,
        ..NatDecision::default()
    });
    let (valid, _) = source_nat_translation_still_valid(
        &configured,
        &out_decision,
        &metadata,
        &out_key,
        None,
        NOW_14315,
    );
    assert!(
        valid,
        "NPTv6 outbound session must validate while its prefix rule exists"
    );
    let (valid, _) = source_nat_translation_still_valid(
        &withdrawn,
        &out_decision,
        &metadata,
        &out_key,
        None,
        NOW_14315,
    );
    assert!(
        !valid,
        "withdrawing the NPTv6 prefix must invalidate the outbound session (#14315)"
    );
}

/// (b) An inbound Persistent-NAT session (no static/DNAT entry) stays valid
/// while its binding lives in the pool allocator, and revokes once the
/// persistent rule (and thus its allocator) is withdrawn.
#[test]
fn persistent_nat_inbound_survives_revalidation_14315() {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "lan".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.source_nat_rules =
        crate::nat::parse_source_nat_rules(&[crate::protocol::SourceNATRuleSnapshot {
            name: "persistent-snat".to_string(),
            from_zone: "lan".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["0.0.0.0/0".to_string()],
            pool_name: "persistent-pool".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40010,
            persistent_nat: true,
            persistent_nat_permit_any_remote_host: true,
            persistent_nat_inactivity_timeout: 300,
            ..Default::default()
        }]);
    // Mint the binding exactly as an outbound flow would.
    let mut counter = None;
    let outbound = match crate::nat::match_source_nat_result_for_tuple(
        &crate::nat::InterfaceNatAllocators::default(),
        &forwarding.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.1.100".parse().expect("internal host"),
        "8.8.8.8".parse().expect("remote"),
        Some(6),
        12345,
        53,
        None,
        None,
        NOW_14315,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut counter,
    ) {
        crate::nat::SourceNatLookup::Matched(decision) => decision,
        other => panic!("expected matched persistent SNAT, got {other:?}"),
    };
    let public_ip = outbound.rewrite_src.expect("translated src");
    let public_port = outbound.rewrite_src_port.expect("translated port");
    // Unsolicited inbound packet to the persistent binding.
    let in_key = key_14315(6, "8.8.8.8", &public_ip.to_string(), 53, public_port);
    // Admission would use dst_port = public_port; the inbound flow key carries
    // it as dst_port, and the remote as src.
    let in_key = SessionKey {
        dst_port: public_port,
        ..in_key
    };
    let in_decision = decision_14315(NatDecision {
        rewrite_dst: Some("10.0.1.100".parse().expect("internal host")),
        rewrite_dst_port: Some(12345),
        ..NatDecision::default()
    });
    let metadata = meta_14315(2, 1);
    assert!(
        destination_nat_translation_still_valid(
            &forwarding,
            &in_decision,
            &metadata,
            &in_key,
            NOW_14315 + 1
        ),
        "live Persistent-NAT inbound binding must survive revalidation (#14315)"
    );
    let withdrawn = ForwardingState::default();
    assert!(
        !destination_nat_translation_still_valid(
            &withdrawn,
            &in_decision,
            &metadata,
            &in_key,
            NOW_14315 + 1
        ),
        "withdrawing the persistent rule must invalidate the inbound binding (#14315)"
    );
}

/// (b2) #14802/#14322: revalidation must thread the real zone pair into
/// `persistent_inbound_lookup`, not empty (unscoped) strings. Two rules
/// share ONE pool/allocator: `trust->dmz` mints an `any-remote-host`
/// grant, `trust->wan` is strict (`target-host-port`). An inbound session
/// arriving on `wan` from an arbitrary remote must NOT validate on the dmz
/// grant (empty args would admit any bucket and keep it alive), while the
/// same tuple arriving on `dmz` must validate. The outbound mint below
/// runs under zones (trust->dmz) that differ from the revalidation
/// fixture metadata (ingress zone 2 = wan), so the allocator's grant is
/// scoped (trust,dmz) and only a correctly-threaded (trust,wan) lookup
/// misses it.
#[test]
fn persistent_nat_cross_zone_grant_does_not_validate_revalidation_14802() {
    let mut forwarding = ForwardingState::default();
    forwarding.zone_id_to_name.insert(1, "trust".to_string());
    forwarding.zone_id_to_name.insert(2, "wan".to_string());
    forwarding.zone_id_to_name.insert(3, "dmz".to_string());
    forwarding.source_nat_rules = crate::nat::parse_source_nat_rules(&[
        crate::protocol::SourceNATRuleSnapshot {
            name: "dmz-any".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "dmz".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40010,
            persistent_nat: true,
            persistent_nat_permit: "any-remote-host".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..Default::default()
        },
        crate::protocol::SourceNATRuleSnapshot {
            name: "wan-strict".to_string(),
            from_zone: "trust".to_string(),
            to_zone: "wan".to_string(),
            source_addresses: vec!["10.0.0.0/24".to_string()],
            pool_name: "shared".to_string(),
            pool_addresses: vec!["203.0.113.10".to_string()],
            port_low: 40000,
            port_high: 40010,
            persistent_nat: true,
            persistent_nat_permit: "target-host-port".to_string(),
            persistent_nat_inactivity_timeout: 300,
            ..Default::default()
        },
    ]);
    assert_eq!(
        forwarding.source_nat_rules.len(),
        2,
        "fixture: both shared-pool rules must parse"
    );
    // Mint the binding via trust->dmz (any-remote-host grant).
    let mut counter = None;
    let outbound = match crate::nat::match_source_nat_result_for_tuple(
        &crate::nat::InterfaceNatAllocators::default(),
        &forwarding.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "trust",
        "dmz",
        "10.0.0.5".parse().expect("internal host"),
        "198.51.100.30".parse().expect("dmz remote"),
        Some(6),
        12345,
        443,
        None,
        None,
        NOW_14315,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut counter,
    ) {
        crate::nat::SourceNatLookup::Matched(decision) => decision,
        other => panic!("expected matched persistent SNAT via dmz, got {other:?}"),
    };
    let public_ip = outbound.rewrite_src.expect("translated src");
    let public_port = outbound.rewrite_src_port.expect("translated port");
    // Unsolicited inbound from an arbitrary remote to the shared tuple.
    let in_key = key_14315(6, "203.0.113.99", &public_ip.to_string(), 9999, public_port);
    let in_decision = decision_14315(NatDecision {
        rewrite_dst: Some("10.0.0.5".parse().expect("internal host")),
        rewrite_dst_port: Some(12345),
        ..NatDecision::default()
    });
    // Arriving on wan (zone 2): the dmz any-remote grant must NOT validate.
    let wan_metadata = meta_14315(2, 1);
    assert!(
        !destination_nat_translation_still_valid(
            &forwarding,
            &in_decision,
            &wan_metadata,
            &in_key,
            NOW_14315 + 1
        ),
        "dmz any-remote-host grant must not keep a wan-arriving session alive (#14802/#14322)"
    );
    // Arriving on dmz (zone 3): its own grant validates the same tuple.
    let dmz_metadata = meta_14315(3, 1);
    assert!(
        destination_nat_translation_still_valid(
            &forwarding,
            &in_decision,
            &dmz_metadata,
            &in_key,
            NOW_14315 + 1
        ),
        "dmz-arriving session must validate on its own any-remote-host grant (#14802)"
    );
}

/// (c) Revalidation is read-only: TCP DNAT + static SNAT revalidation leaves
/// every per-rule hit counter unchanged.
#[test]
fn revalidation_leaves_nat_rule_counters_unchanged_14315() {
    let store = crate::nat::NatCounterStore::default();
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
            primary_v4: Some("203.0.113.254".parse().expect("egress")),
            primary_v6: None,
        },
    );
    forwarding.dnat_table = crate::nat::DnatTable::from_snapshots(
        &[crate::protocol::DestinationNATRuleSnapshot {
            name: "web-forward".to_string(),
            counter_id: 77,
            destination_address: "198.51.100.1".to_string(),
            destination_port: 443,
            protocol: "tcp".to_string(),
            pool_address: "10.0.0.10".to_string(),
            pool_port: 8443,
            ..Default::default()
        }],
        &store,
    );
    forwarding.static_nat = crate::nat::StaticNatTable::from_snapshots(
        &[crate::protocol::StaticNATRuleSnapshot {
            name: "static-snat".to_string(),
            counter_id: 78,
            from_zone: "wan".to_string(),
            external_ip: "203.0.113.10".to_string(),
            internal_ip: "10.0.0.1".to_string(),
            ..Default::default()
        }],
        &store,
    );
    let before = store.snapshots();
    // TCP DNAT session.
    let dnat_key = key_14315(6, "198.51.100.9", "198.51.100.1", 40000, 443);
    let dnat_decision = decision_14315(NatDecision {
        rewrite_dst: Some("10.0.0.10".parse().expect("server")),
        rewrite_dst_port: Some(8443),
        ..NatDecision::default()
    });
    let metadata = meta_14315(2, 1);
    assert!(destination_nat_translation_still_valid(
        &forwarding,
        &dnat_decision,
        &metadata,
        &dnat_key,
        NOW_14315
    ));
    // Static SNAT session (also exercises the static destination branch).
    // Forward direction is lan -> wan; the validator resolves the zone pair
    // from the recorded zones on this fabric-ingress fixture.
    let snat_key = key_14315(6, "10.0.0.1", "198.51.100.1", 443, 443);
    let snat_decision = decision_14315(NatDecision {
        rewrite_src: Some("203.0.113.10".parse().expect("external")),
        ..NatDecision::default()
    });
    let snat_metadata = meta_14315(1, 2);
    let (valid, _) = source_nat_translation_still_valid(
        &forwarding,
        &snat_decision,
        &snat_metadata,
        &snat_key,
        Some(true),
        NOW_14315,
    );
    assert!(
        valid,
        "static SNAT session must validate while its rule exists"
    );
    let after = store.snapshots();
    assert_eq!(before.len(), after.len(), "counter row set must not change");
    for (b, a) in before.iter().zip(after.iter()) {
        assert_eq!(
            (b.packets, b.bytes),
            (a.packets, a.bytes),
            "revalidation must not increment NAT rule counter {} (#14315)",
            b.counter_id
        );
    }
}

/// #14941 fixture: lan (24) <-> wan (12, egress ifindex 12) with a
/// dmz (26) reply-egress. Zones lan=1, wan=2, dmz=7 (`policy_deny_snapshot`).
/// The forward flow 10.0.0.1:12345 -> 8.8.8.8:443 egresses wan; its reply
/// 8.8.8.8:443 -> 10.0.0.1:12345 egresses lan. Both routes resolve, so a
/// stale reverse hit re-resolves to a locally-forwarding LAN route —
/// exactly the shape that flipped `reverse.ingress_zone` WAN->LAN.
fn reverse_revalidation_forwarding_14941() -> ForwardingState {
    let mut snapshot = crate::afxdp::test_fixtures::policy_deny_snapshot();
    snapshot.interfaces.push(crate::InterfaceSnapshot {
        name: "reth2.0".to_string(),
        zone: "dmz".to_string(),
        egress_zone: "dmz".to_string(),
        linux_name: "ge-0-0-2".to_string(),
        ifindex: 26,
        hardware_addr: "02:bf:72:02:00:1a".to_string(),
        addresses: vec![crate::InterfaceAddressSnapshot {
            family: "inet".to_string(),
            address: "10.0.0.254/24".to_string(),
            scope: 0,
        }],
        ..Default::default()
    });
    snapshot.routes = vec![
        crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "8.8.8.8/32".to_string(),
            next_hops: vec!["172.16.80.1@reth0.80".to_string()],
            ..Default::default()
        },
        crate::RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "10.0.0.0/24".to_string(),
            next_hops: vec!["10.0.0.254@reth2.0".to_string()],
            ..Default::default()
        },
    ];
    snapshot.neighbors = vec![
        crate::NeighborSnapshot {
            interface: "reth0.80".to_string(),
            ifindex: 12,
            family: "inet".to_string(),
            ip: "172.16.80.1".to_string(),
            mac: "00:aa:bb:cc:dd:12".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        },
        crate::NeighborSnapshot {
            interface: "reth2.0".to_string(),
            ifindex: 26,
            family: "inet".to_string(),
            ip: "10.0.0.254".to_string(),
            mac: "00:aa:bb:cc:dd:1a".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        },
    ];
    crate::afxdp::forwarding_build::build_forwarding_state(&snapshot)
}

fn key_14941(src: &str, dst: &str, src_port: u16, dst_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: 6,
        src_ip: src.parse().expect("src IPv4"),
        dst_ip: dst.parse().expect("dst IPv4"),
        src_port,
        dst_port,
        discriminator: crate::session::TunnelDiscriminator::None,
        routing_domain: 0,
    }
}

fn pair_14941(
    sessions: &mut SessionTable,
) -> (SessionKey, SessionKey, SessionMetadata, SessionMetadata) {
    let forward = key_14941("10.0.0.1", "8.8.8.8", 12345, 443);
    let reverse = crate::session::reverse_session_key(&forward, NatDecision::default());
    let fwd_meta = SessionMetadata {
        ingress_zone: crate::test_zone_ids::TEST_LAN_ZONE_ID,
        egress_zone: crate::test_zone_ids::TEST_WAN_ZONE_ID,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 24,
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
    };
    let mut rev_meta = fwd_meta.clone();
    rev_meta.is_reverse = true;
    rev_meta.ingress_zone = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    rev_meta.egress_zone = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    rev_meta.ingress_ifindex = 0;
    let decision = SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some("172.16.80.1".parse().expect("WAN gateway")),
            neighbor_mac: Some([0, 0xaa, 0xbb, 0xcc, 0xdd, 0x12]),
            src_mac: None,
            tx_vlan_id: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mut rev_decision = decision;
    rev_decision.resolution.egress_ifindex = 24;
    rev_decision.resolution.tx_ifindex = 24;
    rev_decision.resolution.next_hop = Some("10.0.0.1".parse().expect("client"));
    assert!(sessions.install_with_protocol_with_origin(
        forward.clone(),
        decision,
        fwd_meta.clone(),
        SessionOrigin::ForwardFlow,
        1_000_000_000,
        6,
        0x12,
    ));
    assert!(sessions.install_with_protocol_with_origin(
        reverse.clone(),
        rev_decision,
        rev_meta.clone(),
        SessionOrigin::ReverseFlow,
        1_000_000_000,
        6,
        0x12,
    ));
    (forward, reverse, fwd_meta, rev_meta)
}

/// #14941: the mapping is direction-relative. Forward hits pass the
/// resolved zone through; reverse hits never let their resolved zone
/// (the forward ingress leg) become the forward egress.
#[test]
fn forward_egress_zone_mapping_is_direction_relative_14941() {
    use crate::afxdp::shared_ops::{ForwardEgressZone, forward_egress_zone_for_hit};
    let lan = crate::test_zone_ids::TEST_LAN_ZONE_ID;
    let wan = crate::test_zone_ids::TEST_WAN_ZONE_ID;
    assert_eq!(
        forward_egress_zone_for_hit(false, Some(wan), wan),
        ForwardEgressZone::Zone(wan),
        "forward hit: resolved zone is the forward egress"
    );
    assert_eq!(
        forward_egress_zone_for_hit(false, None, wan),
        ForwardEgressZone::Preserve,
        "forward hit with a terminal route preserves the recorded pair"
    );
    assert_eq!(
        forward_egress_zone_for_hit(true, Some(lan), wan),
        ForwardEgressZone::Preserve,
        "reverse hit: the resolved LAN zone is the forward INGRESS leg and \
         must not be written as the forward egress (WAN->LAN flip, #14941)"
    );
    assert_eq!(
        forward_egress_zone_for_hit(true, None, wan),
        ForwardEgressZone::Preserve
    );
    assert_eq!(ForwardEgressZone::Zone(wan).as_option(), Some(wan));
    assert_eq!(ForwardEgressZone::Preserve.as_option(), None);
}

/// #14941: a stale REVERSE hit revalidated at the descriptor level must
/// leave the pair's zones untouched (forward egress WAN, reverse
/// ingress WAN), and the packet stays an Owner so its deferred refresh
/// (`apply_deferred_owner_hit`) still runs. Pre-fix, the reverse
/// re-resolve wrote the LAN reply-egress into `reverse.ingress_zone`;
/// the next ACK arrived from WAN, classified Foreign, skipped refresh,
/// and the session idled out at ~28s (#14300).
#[test]
fn reverse_hit_revalidation_preserves_pair_zones_14941() {
    let forwarding = reverse_revalidation_forwarding_14941();
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    let (forward, reverse, ..) = pair_14941(&mut sessions);
    sessions.set_forwarding_revalidation_gen(2, 2);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat = Arc::new(Mutex::new(FastMap::default()));
    let shared_wire = Arc::new(Mutex::new(FastMap::default()));
    let owner_indexes = crate::afxdp::SharedSessionOwnerRgIndexes::default();
    let peer_commands: Vec<Arc<Mutex<std::collections::VecDeque<crate::afxdp::WorkerCommand>>>> =
        Vec::new();
    let flow = SessionFlow {
        src_ip: reverse.src_ip,
        dst_ip: reverse.dst_ip,
        forward_key: reverse.clone(),
    };
    let resolved = crate::afxdp::session_glue::resolve_flow_session_decision(
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat,
        &shared_wire,
        &owner_indexes,
        &peer_commands,
        &forwarding,
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        &flow,
        2_000_000_000,
        2,
        6,
        0x10,
        12,
        0,
        false,
        0,
        0,
        crate::afxdp::session_glue::SessionHitVerdict::Owner,
    )
    .expect("stale reverse hit resolves");
    assert!(resolved.metadata.is_reverse);

    let (_, stored_rev, _) = sessions
        .entry_with_origin(&reverse)
        .expect("reverse entry present");
    assert_eq!(
        stored_rev.ingress_zone,
        crate::test_zone_ids::TEST_WAN_ZONE_ID,
        "reverse ingress stays the forward egress zone (WAN); the reverse \
         re-resolve's LAN egress must not flip it (#14941)"
    );
    assert_eq!(
        stored_rev.egress_zone,
        crate::test_zone_ids::TEST_LAN_ZONE_ID,
        "reverse egress (forward ingress) is untouched by the forward-egress persist"
    );
    let (_, stored_fwd, _) = sessions
        .entry_with_origin(&forward)
        .expect("forward entry present");
    assert_eq!(
        stored_fwd.egress_zone,
        crate::test_zone_ids::TEST_WAN_ZONE_ID
    );
    assert_eq!(
        stored_fwd.ingress_zone,
        crate::test_zone_ids::TEST_LAN_ZONE_ID
    );

    // The ACK-refresh consequence: the same WAN arrival is still an
    // Owner (not Foreign), so the poll path replays the deferred hit
    // refresh. Assert both the authority verdict on the STORED zones
    // and that the deferred refresh machinery accepts the pair.
    let meta = crate::afxdp::tests_support::txn_meta_v4(12, 0x10, 54);
    assert_eq!(
        session_hit_authority(
            &forwarding,
            &stored_rev,
            SessionOrigin::ReverseFlow,
            meta,
            false,
            None,
        ),
        HitAuthority::Owner,
        "ACK arriving from WAN after reverse revalidation is Owner, not Foreign"
    );
    // Deferred refresh is the poll path's Owner-only replay; it must
    // still find the pair (a Foreign verdict would skip it entirely).
    sessions.apply_deferred_owner_hit(&reverse, 3_000_000_000, 0x10);
    assert!(
        sessions.entry_with_origin(&reverse).is_some(),
        "deferred owner refresh keeps the reverse entry live"
    );
}

/// #14941 control: a stale FORWARD hit revalidated to a NEW egress zone
/// still rebinds the pair (forward egress and reverse ingress move
/// together) — the #14318 reroute behaviour is not regressed by the
/// direction-relative mapping.
#[test]
fn forward_hit_revalidation_still_rebinds_pair_14941() {
    let mut forwarding = reverse_revalidation_forwarding_14941();
    // Move 8.8.8.8 onto the dmz egress (ifindex 26): the forward
    // re-resolve now names dmz as the new forward egress zone.
    forwarding.routes_v4.insert(
        "inet.0".to_string(),
        vec![crate::afxdp::RouteEntryV4 {
            prefix: crate::afxdp::PrefixV4::from_net(
                ipnet::Ipv4Net::new(Ipv4Addr::new(8, 8, 8, 0), 24).expect("server prefix"),
            ),
            next_hops: vec![crate::afxdp::RouteNextHopV4 {
                next_hop: Some(Ipv4Addr::new(10, 0, 0, 254)),
                ifindex: 26,
                logical_interface_id: 0,
                tunnel_endpoint_id: 0,
                weight: 1,
            }],
            discard: false,
            reject: false,
            next_table: String::new(),
            preference: 0,
            mtu: 1500,
            rule_priority: 0,
        }],
    );
    let mut sessions = SessionTable::new();
    sessions.set_forwarding_revalidation_gen(1, 1);
    let (forward, reverse, ..) = pair_14941(&mut sessions);
    sessions.set_forwarding_revalidation_gen(2, 2);

    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat = Arc::new(Mutex::new(FastMap::default()));
    let shared_wire = Arc::new(Mutex::new(FastMap::default()));
    let owner_indexes = crate::afxdp::SharedSessionOwnerRgIndexes::default();
    let peer_commands: Vec<Arc<Mutex<std::collections::VecDeque<crate::afxdp::WorkerCommand>>>> =
        Vec::new();
    let flow = SessionFlow {
        src_ip: forward.src_ip,
        dst_ip: forward.dst_ip,
        forward_key: forward.clone(),
    };
    let resolved = crate::afxdp::session_glue::resolve_flow_session_decision(
        &mut sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat,
        &shared_wire,
        &owner_indexes,
        &peer_commands,
        &forwarding,
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        &flow,
        2_000_000_000,
        2,
        6,
        0x10,
        24,
        0,
        false,
        0,
        0,
        crate::afxdp::session_glue::SessionHitVerdict::Owner,
    )
    .expect("stale forward hit resolves");
    let (_, stored_fwd, _) = sessions
        .entry_with_origin(&forward)
        .expect("forward entry present");
    assert_eq!(
        stored_fwd.egress_zone,
        crate::test_zone_ids::TEST_DMZ_ZONE_ID,
        "forward reroute to dmz rebinds the forward egress zone (#14318)"
    );
    let (_, stored_rev, _) = sessions
        .entry_with_origin(&reverse)
        .expect("reverse entry present");
    assert_eq!(
        stored_rev.ingress_zone,
        crate::test_zone_ids::TEST_DMZ_ZONE_ID,
        "reverse ingress follows the forward egress on a forward reroute"
    );
}
