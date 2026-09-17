//! #9951: an established session keeps its cached forwarding resolution
//! across REMOVAL of the inter-VRF leak it rides — a tenancy revocation the
//! documented WAN-failover pinning was not scoped to cover.
//!
//! Cell 1 (the regression): install leak -> miss resolves via the leak ->
//! cache on the session -> remove the leak -> the session hit must re-resolve
//! and be denied (NoRoute), not serve the stale cached leak resolution.
//! RED pre-fix: the hit serves the stale ForwardCandidate.
//!
//! Cells 2-3 (controls, green pre- AND post-fix): a next-hop change in the
//! leak TARGET table still pins (the multi-wan parity decision, which this
//! issue does not re-litigate), and removing an UNRELATED leak leaves the
//! session pinned (revocation is per-leak, never a global epoch).
//! Cells 4-8 cover local/shared promotion, peer rematerialization, demotion,
//! remove/re-add ABA rejection, and reverse-session synthesis. Cells 9-10
//! cover nonzero UpsertSynced sibling installation and bring-up replay.

use super::*;
use crate::{ConfigSnapshot, RouteSnapshot};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn leak_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        src_port: 55068,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn leak_flow() -> SessionFlow {
    let key = leak_key();
    SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    }
}

fn leak_snapshot() -> ConfigSnapshot {
    super::super::test_fixtures::forwarding_snapshot_with_next_table(true)
}

fn noroute_decision() -> SessionDecision {
    SessionDecision {
        resolution: super::super::no_route_resolution(None),
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn leak_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 0,
        egress_zone: 0,
        ingress_ifindex: 12,
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

fn rebuild_with_previous(snapshot: &ConfigSnapshot, previous: &ForwardingState) -> ForwardingState {
    build_forwarding_state_with_policy_counters_and_previous(
        snapshot,
        &crate::policy::PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(previous),
    )
    .expect("9951 fixture rebuild")
}

fn install_cached_leak_session(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    flow: &SessionFlow,
    decision: SessionDecision,
) {
    assert!(sessions.install_with_protocol_with_origin(
        flow.forward_key.clone(),
        decision,
        leak_metadata(),
        SessionOrigin::ForwardFlow,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let target = resolution_target_for_session(flow, decision);
    let incarnation =
        crate::afxdp::forwarding::leak_incarnation_for_resolution(forwarding, target, None)
            .expect("9951 fixture resolution must identify its leak");
    sessions.stamp_leak_incarnation(&flow.forward_key, incarnation);
}

fn reverse_worker_entry_fixture(
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    origin: SessionOrigin,
) -> (SessionFlow, SyncedSessionEntry, u64) {
    let mut forward_key = leak_key();
    forward_key.src_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    forward_key.dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let reverse_key = reverse_session_key(&forward_key, NatDecision::default());
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        &BTreeMap::new(),
        neighbors,
        ForwardSessionMatch {
            key: forward_key,
            decision: noroute_decision(),
            metadata: leak_metadata(),
        },
        1,
        0,
    );
    assert_eq!(
        reverse.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "9951 reverse fixture must resolve through the leak"
    );
    let incarnation = crate::afxdp::forwarding::leak_incarnation_for_resolution(
        forwarding,
        reverse_key.dst_ip,
        None,
    )
    .expect("9951 reverse fixture leak");
    let reverse_flow = SessionFlow {
        src_ip: reverse_key.src_ip,
        dst_ip: reverse_key.dst_ip,
        forward_key: reverse_key.clone(),
    };
    let entry = SyncedSessionEntry {
        key: reverse_key,
        decision: reverse.decision,
        metadata: reverse.metadata,
        leak_incarnation: incarnation,
        origin,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    (reverse_flow, entry, incarnation)
}

fn apply_upsert_synced_9951(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    entry: SyncedSessionEntry,
) {
    super::commands::handle_upsert_synced(
        sessions,
        SteeringMap::unshared_for_test(-1),
        forwarding,
        &BTreeMap::new(),
        neighbors,
        entry,
        2_000_000,
        1,
        0,
    );
}

fn resolve_cached_hit(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    neighbors: &Arc<ShardedNeighborMap>,
    flow: &SessionFlow,
) -> ForwardingResolution {
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let resolved = resolve_flow_session_decision(
        sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        forwarding,
        &BTreeMap::new(),
        neighbors,
        flow,
        2_000_000,
        1,
        PROTO_TCP,
        0x10,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("9951 cached session hit");
    resolved.decision.resolution
}

/// #9951 cell 1: the leak a session rides is removed mid-session. The next
/// packet must re-resolve and be denied — the withdrawal of a tenant's
/// permission to reach another VRF, not a next-hop preference change.
#[test]
fn leak_removed_mid_session_reresolves_and_denies_9951() {
    let snapshot = leak_snapshot();
    let with_leak = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let mut sessions = SessionTable::new();

    // Miss-time resolution rides the leak into blue.
    let miss =
        lookup_forwarding_resolution_for_session(&with_leak, &neighbors, &flow, noroute_decision());
    assert_eq!(
        miss.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise broken: 8.8.8.8 must resolve via the leak"
    );
    assert_eq!(
        miss.egress_ifindex, 12,
        "premise broken: blue egress is ifindex 12"
    );
    assert!(
        miss.neighbor_mac.is_some(),
        "premise broken: the static neighbor must give the cached path a MAC"
    );
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    install_cached_leak_session(&mut sessions, &with_leak, &flow, decision);
    // Sanity: pinned while the leak lives.
    let pinned = resolve_cached_hit(&mut sessions, &with_leak, &neighbors, &flow);
    assert_eq!(
        pinned.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise broken: the session must pin while its leak exists"
    );

    // Remove the v4 leak (routes[0]); the target-table route stays.
    let mut removed = snapshot;
    assert_eq!(
        removed.routes[0].next_table, "blue.inet.0",
        "premise broken: routes[0] must be the v4 leak"
    );
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);

    // Fresh flows are denied without the leak ...
    let fresh = lookup_forwarding_resolution_for_session(
        &without_leak,
        &neighbors,
        &flow,
        noroute_decision(),
    );
    assert_eq!(
        fresh.disposition,
        ForwardingDisposition::NoRoute,
        "premise broken: without the leak 8.8.8.8 is unroutable"
    );

    // ... and so is the established session. RED pre-fix: stale cached Forward.
    let hit = resolve_cached_hit(&mut sessions, &without_leak, &neighbors, &flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::NoRoute,
        "leak removed mid-session must re-resolve and deny, not serve the \
         stale cached leak resolution (#9951)"
    );
}

/// #9951 cell 2 (control): a next-hop change in the leak TARGET table is the
/// documented WAN-failover pinning case — the established session stays
/// pinned. Green pre-fix (existing behavior) and must stay green post-fix.
#[test]
fn next_hop_change_in_target_table_still_pins_9951() {
    let snapshot = leak_snapshot();
    let with_leak = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let mut sessions = SessionTable::new();

    let miss =
        lookup_forwarding_resolution_for_session(&with_leak, &neighbors, &flow, noroute_decision());
    assert_eq!(
        miss.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise broken: 8.8.8.8 must resolve via the leak"
    );
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    install_cached_leak_session(&mut sessions, &with_leak, &flow, decision);

    // Retarget blue's 8.8.8.0/24 at an UNRESOLVED gateway (no neighbor): a
    // next-hop change with no alternate — fresh lookups miss the neighbor.
    let mut changed = snapshot;
    assert!(
        changed.routes[1].next_table.is_empty(),
        "premise broken: routes[1] must be blue's forwarding route"
    );
    changed.routes[1].next_hops = vec!["172.16.50.2@ge-0/0/0.50".to_string()];
    let changed_state = rebuild_with_previous(&changed, &with_leak);
    let fresh = lookup_forwarding_resolution_for_session(
        &changed_state,
        &neighbors,
        &flow,
        noroute_decision(),
    );
    assert_eq!(
        fresh.disposition,
        ForwardingDisposition::MissingNeighbor,
        "premise broken: the retargeted gateway must be unresolved"
    );

    // The established session pins to the failed next-hop (multi-wan parity).
    let hit = resolve_cached_hit(&mut sessions, &changed_state, &neighbors, &flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::ForwardCandidate,
        "a next-hop change in the target table must still pin the established \
         session (documented multi-wan parity, #9951 control)"
    );
    assert_eq!(
        hit.neighbor_mac, decision.resolution.neighbor_mac,
        "pinning means the OLD neighbor, not a re-resolution"
    );
}

/// #9951 cell 3 (control): removing an UNRELATED leak leaves this session
/// pinned — revocation is per-leak. Green pre-fix; kills any global-epoch
/// design post-fix.
#[test]
fn unrelated_leak_removal_leaves_session_pinned_9951() {
    let mut snapshot = leak_snapshot();
    // A second, unrelated leak + its target route.
    snapshot.routes.push(RouteSnapshot {
        table: "inet.0".to_string(),
        family: "inet".to_string(),
        destination: "9.9.9.0/24".to_string(),
        next_hops: vec![],
        next_table: "blue.inet.0".to_string(),
        rule_priority: 150,
        ..Default::default()
    });
    snapshot.routes.push(RouteSnapshot {
        table: "blue.inet.0".to_string(),
        family: "inet".to_string(),
        destination: "9.9.9.0/24".to_string(),
        next_hops: vec!["172.16.50.1@ge-0/0/0.50".to_string()],
        ..Default::default()
    });
    let with_both = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let mut sessions = SessionTable::new();

    let miss =
        lookup_forwarding_resolution_for_session(&with_both, &neighbors, &flow, noroute_decision());
    assert_eq!(
        miss.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise broken: 8.8.8.8 must resolve via its leak"
    );
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    install_cached_leak_session(&mut sessions, &with_both, &flow, decision);

    // Remove ONLY the unrelated leak, while changing the established leak's
    // target-table next hop to an unresolved gateway. This distinguishes
    // per-leak provenance from a global forwarding epoch.
    snapshot.routes[1].next_hops = vec!["172.16.50.2@ge-0/0/0.50".to_string()];
    snapshot
        .routes
        .retain(|r| !(r.destination == "9.9.9.0/24" && !r.next_table.is_empty()));
    let without_unrelated = rebuild_with_previous(&snapshot, &with_both);
    let fresh = lookup_forwarding_resolution_for_session(
        &without_unrelated,
        &neighbors,
        &flow,
        noroute_decision(),
    );
    assert_eq!(
        fresh.disposition,
        ForwardingDisposition::MissingNeighbor,
        "premise broken: target-table change must make fresh resolution miss its neighbor"
    );

    let hit = resolve_cached_hit(&mut sessions, &without_unrelated, &neighbors, &flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::ForwardCandidate,
        "removing an UNRELATED leak must not unpin this session (#9951 control)"
    );
    assert_eq!(
        hit.neighbor_mac, decision.resolution.neighbor_mac,
        "unrelated-leak removal must preserve the old cached next hop"
    );
}

/// A promoted shared entry must carry the local leak stamp through
/// eviction/rematerialization; otherwise a worker can resurrect a revoked
/// tenancy from the shared cache after its local row disappears.
#[test]
fn promoted_shared_hit_rechecks_removed_leak_9951() {
    let snapshot = leak_snapshot();
    let with_leak = build_forwarding_state(&snapshot);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let miss =
        lookup_forwarding_resolution_for_session(&with_leak, &neighbors, &flow, noroute_decision());
    assert_eq!(miss.disposition, ForwardingDisposition::ForwardCandidate);
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let mut sessions = SessionTable::new();
    assert!(sessions.install_with_protocol_with_origin(
        flow.forward_key.clone(),
        decision,
        leak_metadata(),
        SessionOrigin::SyncImport,
        1_000_000,
        PROTO_TCP,
        0x10,
    ));
    let incarnation =
        crate::afxdp::forwarding::leak_incarnation_for_resolution(&with_leak, flow.dst_ip, None)
            .expect("9951 promotion fixture leak");
    sessions.stamp_leak_incarnation(&flow.forward_key, incarnation);

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
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    maybe_promote_synced_session(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        shared,
        &peer_worker_commands,
        &with_leak,
        &flow.forward_key,
        decision,
        leak_metadata(),
        SessionOrigin::SyncImport,
        false,
        1_500_000,
        PROTO_TCP,
        0x10,
    );
    let promoted = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&flow.forward_key)
        .cloned()
        .expect("promoted shared entry");
    assert_eq!(promoted.origin, SessionOrigin::SharedPromote);
    assert_eq!(promoted.leak_incarnation, incarnation);

    sessions.delete(&flow.forward_key);
    let mut removed = snapshot;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &without_leak,
        &BTreeMap::new(),
        &neighbors,
        &flow,
        2_000_000,
        1,
        PROTO_TCP,
        0x10,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("rematerialized shared hit");
    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "promoted shared state must not resurrect a removed leak (#9951)"
    );
}

#[test]
fn removed_and_readded_leak_does_not_resurrect_old_session_9951() {
    let original = leak_snapshot();
    let with_leak = build_forwarding_state(&original);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let mut sessions = SessionTable::new();
    let miss =
        lookup_forwarding_resolution_for_session(&with_leak, &neighbors, &flow, noroute_decision());
    assert_eq!(miss.disposition, ForwardingDisposition::ForwardCandidate);
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    install_cached_leak_session(&mut sessions, &with_leak, &flow, decision);

    let mut removed = original;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let readded = rebuild_with_previous(&leak_snapshot(), &without_leak);
    let fresh =
        lookup_forwarding_resolution_for_session(&readded, &neighbors, &flow, noroute_decision());
    assert_eq!(
        fresh.disposition,
        ForwardingDisposition::ForwardCandidate,
        "premise broken: the re-added leak is usable for a new flow"
    );

    let hit = resolve_cached_hit(&mut sessions, &readded, &neighbors, &flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::NoRoute,
        "a removed/re-added leak must not resurrect an old session (#9951 ABA)"
    );
}

#[test]
fn peer_shared_materialize_promote_rechecks_removed_leak_9951() {
    let original = leak_snapshot();
    let with_leak = build_forwarding_state(&original);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let miss =
        lookup_forwarding_resolution_for_session(&with_leak, &neighbors, &flow, noroute_decision());
    assert_eq!(miss.disposition, ForwardingDisposition::ForwardCandidate);
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let incarnation =
        crate::afxdp::forwarding::leak_incarnation_for_resolution(&with_leak, flow.dst_ip, None)
            .expect("9951 peer fixture leak");
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let peer_entry = SyncedSessionEntry {
        key: flow.forward_key.clone(),
        decision,
        metadata: leak_metadata(),
        leak_incarnation: 0,
        origin: SessionOrigin::SyncImport,
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
        &peer_entry,
    );

    let mut sessions = SessionTable::new();
    let first = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &with_leak,
        &BTreeMap::new(),
        &neighbors,
        &flow,
        2_000_000,
        1,
        PROTO_TCP,
        0x10,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("peer shared materialization");
    assert_eq!(
        first.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        sessions.leak_incarnation(&flow.forward_key),
        Some(incarnation)
    );
    let promoted = shared_sessions
        .lock()
        .expect("shared sessions")
        .get(&flow.forward_key)
        .cloned()
        .expect("peer promotion");
    assert_eq!(promoted.origin, SessionOrigin::SharedPromote);
    assert_eq!(promoted.leak_incarnation, incarnation);

    sessions.delete(&flow.forward_key);
    let mut removed = original;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let second = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &without_leak,
        &BTreeMap::new(),
        &neighbors,
        &flow,
        3_000_000,
        1,
        PROTO_TCP,
        0x10,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("peer shared rematerialization");
    assert_eq!(
        second.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "peer shared provenance must survive promotion and revoke after leak removal"
    );
}

#[test]
fn demoted_shared_leak_rematerialization_rechecks_removed_leak_9951() {
    let original = leak_snapshot();
    let with_leak = build_forwarding_state(&original);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let flow = leak_flow();
    let miss =
        lookup_forwarding_resolution_for_session(&with_leak, &neighbors, &flow, noroute_decision());
    assert_eq!(miss.disposition, ForwardingDisposition::ForwardCandidate);
    let decision = SessionDecision {
        resolution: miss,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    };
    let incarnation =
        crate::afxdp::forwarding::leak_incarnation_for_resolution(&with_leak, flow.dst_ip, None)
            .expect("9951 demotion fixture leak");
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let mut metadata = leak_metadata();
    metadata.owner_rg_id = 1;
    let shared_entry = SyncedSessionEntry {
        key: flow.forward_key.clone(),
        decision,
        metadata,
        leak_incarnation: incarnation,
        origin: SessionOrigin::SharedPromote,
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
    demote_shared_owner_rgs(
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &with_leak,
        &neighbors,
        &[1],
    );
    assert_eq!(
        shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&flow.forward_key)
            .map(|entry| entry.origin),
        Some(SessionOrigin::SyncImport)
    );

    let mut removed = original;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let mut sessions = SessionTable::new();
    let first = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &without_leak,
        &BTreeMap::new(),
        &neighbors,
        &flow,
        2_000_000,
        1,
        PROTO_TCP,
        0x10,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("demoted shared materialization");
    assert_eq!(
        first.decision.resolution.disposition,
        ForwardingDisposition::NoRoute
    );
    assert_eq!(
        sessions.leak_incarnation(&flow.forward_key),
        Some(incarnation)
    );

    sessions.delete(&flow.forward_key);
    let second = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &without_leak,
        &BTreeMap::new(),
        &neighbors,
        &flow,
        3_000_000,
        1,
        PROTO_TCP,
        0x10,
        12,
        0,
        false,
        0,
        0,
    )
    .expect("demoted shared rematerialization");
    assert_eq!(
        second.decision.resolution.disposition,
        ForwardingDisposition::NoRoute,
        "demoted shared state must preserve leak provenance after removal"
    );
}

#[test]
fn reverse_synthesis_stamps_and_revokes_leak_riding_session_9951() {
    let original = leak_snapshot();
    let with_leak = build_forwarding_state(&original);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let mut forward_key = leak_key();
    forward_key.src_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    forward_key.dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102));
    let forward_match = ForwardSessionMatch {
        key: forward_key.clone(),
        decision: noroute_decision(),
        metadata: leak_metadata(),
    };
    let reverse_key = reverse_session_key(&forward_key, NatDecision::default());
    let reverse_flow = SessionFlow {
        src_ip: reverse_key.src_ip,
        dst_ip: reverse_key.dst_ip,
        forward_key: reverse_key.clone(),
    };
    let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
    let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let mut sessions = SessionTable::new();
    let (_, installed) = install_reverse_session_from_forward_match(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared_sessions,
        &shared_nat_sessions,
        &shared_forward_wire_sessions,
        &shared_owner_rg_indexes,
        &peer_worker_commands,
        &with_leak,
        &BTreeMap::new(),
        &neighbors,
        &reverse_key,
        forward_match,
        1_000_000,
        1,
        0,
        PROTO_TCP,
        0x10,
    );
    assert!(installed, "reverse synthesis fixture must install");
    let incarnation = crate::afxdp::forwarding::leak_incarnation_for_resolution(
        &with_leak,
        reverse_key.dst_ip,
        None,
    )
    .expect("9951 reverse fixture leak");
    assert_eq!(
        sessions.leak_incarnation(&reverse_key),
        Some(incarnation),
        "reverse synthesis must stamp its local session"
    );
    assert_eq!(
        shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&reverse_key)
            .map(|entry| entry.leak_incarnation),
        Some(incarnation),
        "reverse synthesis must publish the same revocation stamp"
    );

    let mut removed = original;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let hit = resolve_cached_hit(&mut sessions, &without_leak, &neighbors, &reverse_flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::NoRoute,
        "reverse session riding a removed leak must be revoked (#9951)"
    );
}

#[test]
fn worker_local_import_upsert_preserves_nonzero_leak_stamp_9951() {
    let original = leak_snapshot();
    let with_leak = build_forwarding_state(&original);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let (reverse_flow, entry, incarnation) =
        reverse_worker_entry_fixture(&with_leak, &neighbors, SessionOrigin::WorkerLocalImport);

    // A sibling receives a locally published nonzero replica after the leak
    // has already been removed. Reverse UpsertSynced deliberately retains its
    // cached decision, so only preserving the incoming token can revoke it.
    let mut removed = original;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let mut sessions = SessionTable::new();
    apply_upsert_synced_9951(&mut sessions, &without_leak, &neighbors, entry);
    assert_eq!(
        sessions.leak_incarnation(&reverse_flow.forward_key),
        Some(incarnation),
        "sibling UpsertSynced must preserve its published leak token"
    );
    let hit = resolve_cached_hit(&mut sessions, &without_leak, &neighbors, &reverse_flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::NoRoute,
        "a sibling replay of a removed leak must be revoked, not use synced fallback"
    );
}

#[test]
fn bringup_replay_preserves_nonzero_leak_stamp_9951() {
    let original = leak_snapshot();
    let with_leak = build_forwarding_state(&original);
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let (reverse_flow, entry, incarnation) =
        reverse_worker_entry_fixture(&with_leak, &neighbors, SessionOrigin::SharedPromote);
    let replay = synced_replica_entry(&entry);
    assert_eq!(
        replay.origin,
        SessionOrigin::WorkerLocalImport,
        "bring-up replay must map the shared row to a worker replica"
    );

    // This is the late bring-up shape: replay maps the authoritative shared
    // row to a sibling replica after removal, then the worker drains
    // UpsertSynced. The old unconditional recompute erased the token here.
    let mut removed = original;
    removed.routes.remove(0);
    let without_leak = rebuild_with_previous(&removed, &with_leak);
    let mut sessions = SessionTable::new();
    apply_upsert_synced_9951(&mut sessions, &without_leak, &neighbors, replay);
    assert_eq!(
        sessions.leak_incarnation(&reverse_flow.forward_key),
        Some(incarnation),
        "bring-up replay must preserve the shared row's nonzero leak token"
    );
    let hit = resolve_cached_hit(&mut sessions, &without_leak, &neighbors, &reverse_flow);
    assert_eq!(
        hit.disposition,
        ForwardingDisposition::NoRoute,
        "late bring-up of a removed leak must fail closed"
    );
}
