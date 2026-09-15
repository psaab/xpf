//! #9752: a PBR `then routing-instance` session keeps its installing table.
//!
//! Formation (filter term -> stamp) is pinned in
//! `frame/tests_parse_forward_pbr.rs::install_table_stamp_matrix_9752`; these
//! cells prove the stamped table is HONORED on every downstream re-resolve and
//! that an unresolvable stamp serves terminal — never default-table leakage.
//!
//! Fixture: `lan` ingress (ifindex 24, unnumbered); `blue` owns ge-0-0-2 (12,
//! 172.16.50.0/24, RG 1); the default table owns ge-0-0-3 (13,
//! 172.16.60.0/24, RG 1). 8.8.8.8 is reachable in BOTH tables via divergent
//! gateways, each with a static reachable neighbor — so a wrong-table lookup
//! still resolves, and the test fails on the wrong EGRESS (13), not on
//! NoRoute. 1.1.1.1 is reachable in the default table ONLY (blue carries just
//! the 8.8.8.8/32 host route), which lets the validation cells distinguish "no
//! X-table candidate" from "no candidate at all".

use super::*;
use crate::afxdp::worker_queue::{
    MAX_PENDING_WORKER_COMMANDS, WORKER_COMMAND_QUEUE_DROPS,
};
use crate::session::install_table_identity;
use crate::{
    ConfigSnapshot, InterfaceAddressSnapshot, InterfaceSnapshot, NeighborSnapshot, RouteSnapshot,
    ZoneSnapshot,
};
use super::super::types::{RuntimeView, RuntimeViewChannel, ValidationState};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;

const BLUE_IFINDEX: i32 = 12;
const DEFAULT_IFINDEX: i32 = 13;
const LAN_IFINDEX: i32 = 24;
const RG1: i32 = 1;
const NOW_NS: u64 = 1_000_000_000;
const NOW_SECS: u64 = 1;

fn blue_stamp() -> (u32, u32) {
    // Keyed by INSTANCE name (the miss path stamps
    // `install_table_identity(routing_instance)`); the registry row preforms
    // `blue.inet.0` / `blue.inet6.0` from it.
    install_table_identity("blue")
}

fn pbr_snapshot() -> ConfigSnapshot {
    let mut snapshot = super::super::test_fixtures::policy_deny_snapshot();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "lan".to_string(),
            id: 1,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "wan".to_string(),
            id: 2,
            ..Default::default()
        },
        // The inherited `dmz->wan/allow-other` policy references dmz; keep
        // the zone so the snapshot stays coherent (policy is inert here —
        // these cells never drive the miss path).
        ZoneSnapshot {
            name: "dmz".to_string(),
            id: 3,
            ..Default::default()
        },
    ];
    snapshot.interfaces = vec![
        InterfaceSnapshot {
            name: "reth1.0".to_string(),
            zone: "lan".to_string(),
            linux_name: "ge-0-0-1".to_string(),
            ifindex: LAN_IFINDEX,
            ..Default::default()
        },
        InterfaceSnapshot {
            name: "ge-0/0/2".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-2".to_string(),
            ifindex: BLUE_IFINDEX,
            routing_instance: "blue".to_string(),
            hardware_addr: "02:bf:72:00:02:0c".to_string(),
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.50.1/24".to_string(),
                scope: 0,
            }],
            redundancy_group: RG1,
            ..Default::default()
        },
        InterfaceSnapshot {
            name: "ge-0/0/3".to_string(),
            zone: "wan".to_string(),
            linux_name: "ge-0-0-3".to_string(),
            ifindex: DEFAULT_IFINDEX,
            hardware_addr: "02:bf:72:00:03:0d".to_string(),
            addresses: vec![InterfaceAddressSnapshot {
                family: "inet".to_string(),
                address: "172.16.60.1/24".to_string(),
                scope: 0,
            }],
            redundancy_group: RG1,
            ..Default::default()
        },
    ];
    snapshot.routes = vec![
        RouteSnapshot {
            table: "blue.inet.0".to_string(),
            family: "inet".to_string(),
            destination: "8.8.8.8/32".to_string(),
            next_hops: vec!["172.16.50.254".to_string()],
            ..Default::default()
        },
        RouteSnapshot {
            table: "inet.0".to_string(),
            family: "inet".to_string(),
            destination: "0.0.0.0/0".to_string(),
            next_hops: vec!["172.16.60.254".to_string()],
            ..Default::default()
        },
    ];
    snapshot.neighbors = vec![
        NeighborSnapshot {
            interface: "ge-0-0-2".to_string(),
            ifindex: BLUE_IFINDEX,
            family: "inet".to_string(),
            ip: "172.16.50.254".to_string(),
            mac: "00:aa:bb:cc:dd:01".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        },
        NeighborSnapshot {
            interface: "ge-0-0-3".to_string(),
            ifindex: DEFAULT_IFINDEX,
            family: "inet".to_string(),
            ip: "172.16.60.254".to_string(),
            mac: "00:aa:bb:cc:dd:02".to_string(),
            state: "reachable".to_string(),
            ..Default::default()
        },
    ];
    snapshot
}

fn pbr_state() -> ForwardingState {
    super::super::forwarding_build::build_forwarding_state(&pbr_snapshot())
}

// The #6592 canary reads each file standalone and cannot see the `#[cfg(test)]`
// on this module's `mod` line, so the construction below needs the redundant
// attribute plus the marker — the same dance as
// `first_policy_purge_rotation_9526_tests.rs`.
#[cfg(test)]
fn publish_pbr_view(
    channel: &RuntimeViewChannel,
    generation: u64,
    forwarding: Arc<ForwardingState>,
) {
    channel.publish(Arc::new(RuntimeView::new( // runtime-view-canary: test-local
        ValidationState {
            snapshot_installed: true,
            config_generation: generation,
            fib_generation: generation as u32,
        },
        forwarding,
    )));
}

fn pbr_key() -> SessionKey {
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

fn pbr_flow() -> SessionFlow {
    let key = pbr_key();
    SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    }
}

fn pbr_metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        owner_rg_id: RG1,
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

fn unusable_resolution() -> ForwardingResolution {
    ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    }
}

fn stamped_decision(resolution: ForwardingResolution) -> SessionDecision {
    let (domain, check) = blue_stamp();
    SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: domain,
        install_table_check: check,
    }
}

fn unstamped_decision(resolution: ForwardingResolution) -> SessionDecision {
    SessionDecision {
        resolution,
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn active_ha() -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(
        RG1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: NOW_SECS,
            lease: HAGroupRuntime::active_lease_until(NOW_SECS, NOW_SECS),
        },
    )])
}

fn inactive_ha() -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(
        RG1,
        HAGroupRuntime {
            active: false,
            watchdog_timestamp: 0,
            lease: HAForwardingLease::Inactive,
        },
    )])
}

struct SharedMaps {
    sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    owner_rg_indexes: SharedSessionOwnerRgIndexes,
    peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
}

fn shared_maps() -> SharedMaps {
    SharedMaps {
        sessions: Arc::new(Mutex::new(FastMap::default())),
        nat_sessions: Arc::new(Mutex::new(FastMap::default())),
        forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
        owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
        peer_worker_commands: Vec::new(),
    }
}

/// C1: a synced hit re-resolves in the installing table and keeps the stamp.
#[test]
fn synced_hit_reresolves_in_installing_table_keeps_stamp() {
    let forwarding = pbr_state();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        stamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    let shared = shared_maps();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &shared.peer_worker_commands,
        &forwarding,
        &active_ha(),
        &dynamic_neighbors,
        &pbr_flow(),
        NOW_NS,
        NOW_SECS,
        PROTO_TCP,
        0x18,
        LAN_IFINDEX,
        0,
        false,
        0,
        0,
    )
    .expect("synced session must hit");
    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, BLUE_IFINDEX);
    let (domain, check) = blue_stamp();
    assert_eq!(resolved.decision.install_table_domain, domain);
    assert_eq!(resolved.decision.install_table_check, check);
}

/// C8 (control): a zero-stamped session still resolves in the default table.
#[test]
fn unstamped_hit_resolves_in_default_table() {
    let forwarding = pbr_state();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        unstamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    let shared = shared_maps();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &shared.peer_worker_commands,
        &forwarding,
        &active_ha(),
        &dynamic_neighbors,
        &pbr_flow(),
        NOW_NS,
        NOW_SECS,
        PROTO_TCP,
        0x18,
        LAN_IFINDEX,
        0,
        false,
        0,
        0,
    )
    .expect("synced session must hit");
    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(
        resolved.decision.resolution.egress_ifindex, DEFAULT_IFINDEX,
        "zero stamp must keep default-table behavior bit-exact"
    );
}

/// C2: synced import re-resolves in the installing table (wire stamp honored).
#[test]
fn synced_import_reresolves_in_installing_table() {
    let forwarding = pbr_state();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    let entry = SyncedSessionEntry {
        key: key.clone(),
        decision: stamped_decision(unusable_resolution()),
        metadata: pbr_metadata(),
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x18,
        // #2170 test fixture: no peer install generation.
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    };
    super::commands::handle_upsert_synced(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &forwarding,
        &active_ha(),
        &Arc::new(ShardedNeighborMap::new()),
        entry,
        NOW_NS,
        NOW_SECS,
        0,
    );
    let (decision, _, _) = sessions
        .entry_with_origin(&key)
        .expect("imported session must exist");
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(decision.resolution.egress_ifindex, BLUE_IFINDEX);
    let (domain, check) = blue_stamp();
    assert_eq!(decision.install_table_domain, domain);
    assert_eq!(decision.install_table_check, check);
}

/// C3: owner-RG refresh re-resolves in the installing table.
#[test]
fn owner_rg_refresh_reresolves_in_installing_table() {
    let forwarding = pbr_state();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        stamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    // Standby-owned (RG inactive): refresh recomputes in blue, then HA
    // enforcement gates it to HAInactive. The TABLE is proven by the egress
    // (12 = blue); the disposition proves the gate still applies.
    let items = super::commands::collect_refresh_owner_rgs_items(
        &sessions,
        &forwarding,
        &inactive_ha(),
        &Arc::new(ShardedNeighborMap::new()),
        NOW_SECS,
    );
    let (_, decision, _, _, _) = items
        .iter()
        .find(|(item_key, ..)| *item_key == key)
        .expect("refreshed session must be present");
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::HAInactive
    );
    assert_eq!(decision.resolution.egress_ifindex, BLUE_IFINDEX);
}

/// C4: a real MissingNeighbor seed install reseeds in its installing table.
/// The seed decision comes from the REAL miss-path table lookup (neighbor
/// absent => MissingNeighbor), stamped by the REAL stamp fn, installed under
/// the REAL seed origin; the reseed is a dynamic-neighbor learn followed by
/// the REAL hit path. Nothing hand-stamped except fixture + metadata.
#[test]
fn missing_neighbor_seed_install_and_reseed_stay_in_table() {
    use super::super::forwarding::lookup_forwarding_resolution_in_table_with_dynamic;
    use super::super::types::NeighborEntry;
    // Neighbor-absent blue: route + connected present, no neighbor anywhere.
    let mut snapshot = pbr_snapshot();
    snapshot.neighbors.retain(|n| n.ip != "172.16.50.254");
    let forwarding = super::super::forwarding_build::build_forwarding_state(&snapshot);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    // Real miss-path lookup in X with no neighbor => MissingNeighbor seed.
    let miss = lookup_forwarding_resolution_in_table_with_dynamic(
        &forwarding,
        &dynamic_neighbors,
        dst,
        Some("blue.inet.0"),
    );
    assert_eq!(miss.disposition, ForwardingDisposition::MissingNeighbor);
    // Real stamp fn: a neighbor-miss resolved in X still stamps X.
    let (domain, check) = super::super::forwarding::install_table_stamp_for_miss(
        Some(blue_stamp()),
        true,
        miss,
    );
    assert_eq!((domain, check), blue_stamp());
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        SessionDecision {
            resolution: miss,
            nat: NatDecision::default(),
            install_table_domain: domain,
            install_table_check: check,
        },
        pbr_metadata(),
        SessionOrigin::MissingNeighborSeed,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    // Reseed trigger: the gateway neighbor is learned dynamically.
    dynamic_neighbors.insert(
        (
            BLUE_IFINDEX,
            IpAddr::V4(Ipv4Addr::new(172, 16, 50, 254)),
        ),
        NeighborEntry {
            mac: [0, 0xaa, 0xbb, 0xcc, 0xdd, 0x01],
        },
    );
    // Real hit path over the seed.
    let shared = shared_maps();
    let resolved = resolve_flow_session_decision(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &shared.peer_worker_commands,
        &forwarding,
        &active_ha(),
        &dynamic_neighbors,
        &pbr_flow(),
        NOW_NS,
        NOW_SECS,
        PROTO_TCP,
        0x18,
        LAN_IFINDEX,
        0,
        false,
        0,
        0,
    )
    .expect("seeded session must hit");
    assert_eq!(
        resolved.decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.decision.resolution.egress_ifindex, BLUE_IFINDEX);
}

/// C4b: the name resolver exposes the stamped table to validation callers.
#[test]
fn install_table_name_resolver_exposes_stamped_table() {
    let forwarding = pbr_state();
    assert_eq!(
        install_table_name_for_session(
            &forwarding,
            stamped_decision(unusable_resolution()),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ),
        Some("blue.inet.0")
    );
    assert_eq!(
        install_table_name_for_session(
            &forwarding,
            unstamped_decision(unusable_resolution()),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ),
        None
    );
}

/// C5 (control): the reverse session resolves in the DEFAULT table, unstamped.
/// PBR is directional — the forward leg was steered into blue, but the return
/// leg routes back to the client (10.0.61.102) via the normal FIB, exactly as
/// the miss path installs it (no PBR evaluation on session install). Inheriting
/// the blue stamp here would blackhole the return (blue has no 10/8 route).
#[test]
fn reverse_session_resolves_unstamped_in_default() {
    let forwarding = pbr_state();
    let forward = ForwardSessionMatch {
        key: pbr_key(),
        decision: stamped_decision(unusable_resolution()),
        metadata: pbr_metadata(),
    };
    let lookup = super::super::shared_ops::build_reverse_session_from_forward_match(
        &forwarding,
        &active_ha(),
        &Arc::new(ShardedNeighborMap::new()),
        forward,
        NOW_SECS,
        0,
    );
    assert_eq!(lookup.decision.install_table_domain, 0);
    assert_eq!(lookup.decision.install_table_check, 0);
    assert_eq!(lookup.decision.resolution.egress_ifindex, DEFAULT_IFINDEX);
}

/// C6: demote preserves the stamp (failover does not lose the table).
#[test]
fn demote_preserves_installing_table() {
    let commands = Arc::new(Mutex::new(VecDeque::new()));
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        stamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    commands
        .lock()
        .expect("commands lock")
        .push_back(WorkerCommand::DemoteOwnerRGS {
            owner_rgs: vec![RG1],
        });
    let forwarding = pbr_state();
    apply_worker_commands(
        &commands,
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &forwarding,
        &inactive_ha(),
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );
    let (decision, _, _) = sessions
        .entry_with_origin(&key)
        .expect("demoted session must survive");
    let (domain, check) = blue_stamp();
    assert_eq!(decision.install_table_domain, domain);
    assert_eq!(decision.install_table_check, check);
}

/// C10: terminal matrix — unknown / mismatched / absent stamps serve terminal
/// (never default-table leakage), without touching the ifindex-0 counter.
#[test]
fn unresolvable_stamp_serves_terminal_not_default() {
    let forwarding = pbr_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let before =
        super::super::forwarding::LOCAL_DELIVERY_IFINDEX0.load(Ordering::Relaxed);
    // Unknown domain (no such table): terminal.
    let unknown = SessionDecision {
        resolution: unusable_resolution(),
        nat: NatDecision::default(),
        install_table_domain: 999_999_999,
        install_table_check: 1,
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        unknown,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::TableUnavailable,
        "unknown stamp must be terminal"
    );
    assert_ne!(
        resolved.egress_ifindex, DEFAULT_IFINDEX,
        "unknown stamp must not leak into the default table"
    );
    // Mismatched check (right domain band, wrong table): terminal.
    let (domain, check) = blue_stamp();
    let mismatched = SessionDecision {
        resolution: unusable_resolution(),
        nat: NatDecision::default(),
        install_table_domain: domain,
        install_table_check: check.wrapping_add(1),
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        mismatched,
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::TableUnavailable,
        "mismatched stamp must be terminal"
    );
    // Absent for family (blue.inet.0 has no v6 half): a v6 target is terminal.
    let v6_flow = SessionFlow {
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        forward_key: SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            src_port: 55068,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &v6_flow,
        stamped_decision(unusable_resolution()),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::TableUnavailable,
        "family-absent stamp must be terminal"
    );
    assert_eq!(
        super::super::forwarding::LOCAL_DELIVERY_IFINDEX0.load(Ordering::Relaxed),
        before,
        "terminal-for-unresolvable must not bump the table-owned-no-ifindex counter"
    );
}

/// C12: validation judges the X-table candidate (not default) on both arms.
#[test]
fn validation_judges_installing_table_candidate() {
    use super::super::forwarding::cached_flow_decision_valid;
    let forwarding = pbr_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    // Active HA: the arm enforces the local candidate BEFORE matching, so an
    // empty HA map would wrap it to HAInactive and the arm could never fire.
    let ha = active_ha();
    // 1.1.1.1: default covers it, blue does not. A cached FabricRedirect is
    // INVALID under the default table (a local candidate appears) but VALID
    // under blue (no blue candidate) — proving the table threads.
    let cached_redirect = ForwardingResolution {
        disposition: ForwardingDisposition::FabricRedirect,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    };
    let target_default_only = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    assert!(
        !cached_flow_decision_valid(
            &forwarding,
            &ha,
            &dynamic_neighbors,
            NOW_SECS,
            0,
            false,
            target_default_only,
            None,
            cached_redirect,
        ),
        "default table has a local candidate: redirect must invalidate"
    );
    assert!(
        cached_flow_decision_valid(
            &forwarding,
            &ha,
            &dynamic_neighbors,
            NOW_SECS,
            0,
            false,
            target_default_only,
            Some("blue.inet.0"),
            cached_redirect,
        ),
        "blue has no candidate for 1.1.1.1: redirect must stay valid"
    );
    // 8.8.8.8: BOTH tables cover it — invalid under both (the X lookup fires).
    let target_both = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(
        !cached_flow_decision_valid(
            &forwarding,
            &ha,
            &dynamic_neighbors,
            NOW_SECS,
            0,
            false,
            target_both,
            Some("blue.inet.0"),
            cached_redirect,
        ),
        "blue has a local candidate for 8.8.8.8: redirect must invalidate"
    );
}

/// C13: retirement — a session whose table vanishes is purged by the walk.
#[test]
fn purge_removes_session_whose_table_vanished() {
    let channel = RuntimeViewChannel::default();
    let forwarding = Arc::new(pbr_state());
    publish_pbr_view(&channel, 7, forwarding.clone());
    let reader = channel.reader();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        stamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    // Rotate: the new forwarding half has NO blue table (default only).
    let mut rotated_snapshot = pbr_snapshot();
    rotated_snapshot.routes.retain(|r| r.table == "inet.0");
    // Presence includes connected routes: re-home the blue interface into the
    // default table too, so `blue` vanishes from the registry entirely (the
    // realistic "instance deleted" rotation).
    for iface in &mut rotated_snapshot.interfaces {
        if iface.ifindex == BLUE_IFINDEX {
            iface.routing_instance.clear();
        }
    }
    let rotated = Arc::new(super::super::forwarding_build::build_forwarding_state(
        &rotated_snapshot,
    ));
    publish_pbr_view(&channel, 8, rotated.clone());
    let shared = shared_maps();
    let mut purge = super::install_table_purge::InstallTablePurge::default();
    purge.arm(8);
    let mut evicted = Vec::new();
    let purged = purge.step(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &shared.peer_worker_commands,
        &rotated,
        &reader,
        8,
        NOW_NS,
        0,
        &mut evicted,
    );
    assert_eq!(purged, 1, "the blue-stamped session must be purged");
    assert!(sessions.entry_with_origin(&key).is_none());
    assert_eq!(evicted, vec![key]);
}

/// C15: precedence pins — validated-then-early-return and zero-stamp bypass.
#[test]
fn install_table_precedence_pins() {
    let forwarding = pbr_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    // A zero-stamped LocalDelivery resolution is served WITHOUT consulting the
    // registry — even when the registry is empty (proves the bypass precedes
    // validation rather than validation preceding the bypass for unstamped).
    let empty = ForwardingState::default();
    let local_delivery = ForwardingResolution {
        disposition: ForwardingDisposition::LocalDelivery,
        local_ifindex: LAN_IFINDEX,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &empty,
        &dynamic_neighbors,
        &pbr_flow(),
        unstamped_decision(local_delivery),
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    // A blue-stamped session against an empty registry is terminal (proves
    // validation precedes the cached/lookup fallback for STAMPED sessions).
    let resolved = lookup_forwarding_resolution_for_session(
        &empty,
        &dynamic_neighbors,
        &pbr_flow(),
        stamped_decision(unusable_resolution()),
    );
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::TableUnavailable,
        "stamped session with no registry must be terminal"
    );
    // Sanity: the same stamped decision against the live table forwards blue.
    let resolved = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        stamped_decision(unusable_resolution()),
    );
    assert_eq!(resolved.egress_ifindex, BLUE_IFINDEX);
}

/// C16: refused replication counts the drop and keeps the valid entry.
#[test]
fn refused_replication_counts_drop_keeps_valid_entry() {
    use crate::afxdp::worker_queue::push_bounded;
    let channel = RuntimeViewChannel::default();
    let forwarding = Arc::new(pbr_state());
    publish_pbr_view(&channel, 7, forwarding.clone());
    let reader = channel.reader();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        stamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    // Fill a recipient queue to the bound so the conditional replicate refuses.
    let recipient = Arc::new(Mutex::new(VecDeque::new()));
    {
        let mut queue = recipient.lock().expect("recipient lock");
        for _ in 0..MAX_PENDING_WORKER_COMMANDS {
            assert!(push_bounded(&mut queue, WorkerCommand::DeleteSynced(key.clone())));
        }
    }
    let drops_before = WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed);
    // Rotate away blue so the walk wants to replicate a delete for the key.
    let mut rotated_snapshot = pbr_snapshot();
    rotated_snapshot.routes.retain(|r| r.table == "inet.0");
    // Presence includes connected routes: re-home the blue interface into the
    // default table too, so `blue` vanishes from the registry entirely (the
    // realistic "instance deleted" rotation).
    for iface in &mut rotated_snapshot.interfaces {
        if iface.ifindex == BLUE_IFINDEX {
            iface.routing_instance.clear();
        }
    }
    let rotated = Arc::new(super::super::forwarding_build::build_forwarding_state(
        &rotated_snapshot,
    ));
    publish_pbr_view(&channel, 8, rotated.clone());
    let shared = shared_maps();
    let peer_cmds = vec![recipient.clone()];
    let mut purge = super::install_table_purge::InstallTablePurge::default();
    purge.arm(8);
    let mut evicted = Vec::new();
    let purged = purge.step(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &peer_cmds,
        &rotated,
        &reader,
        8,
        NOW_NS,
        0,
        &mut evicted,
    );
    assert_eq!(purged, 1);
    assert!(
        WORKER_COMMAND_QUEUE_DROPS.load(Ordering::Relaxed) > drops_before,
        "a refused replicate must count the drop"
    );
    assert_eq!(
        recipient.lock().expect("recipient lock").len(),
        MAX_PENDING_WORKER_COMMANDS,
        "a refused queue must keep its committed prefix intact"
    );
}

fn pbr_key_for(src_port: u16, dst: Ipv4Addr) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(dst),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

/// C11: per-flow ECMP spread is preserved WITHIN the installing table.
#[test]
fn ecmp_spread_preserved_within_installing_table() {
    let mut snapshot = pbr_snapshot();
    snapshot.routes.push(RouteSnapshot {
        table: "blue.inet.0".to_string(),
        family: "inet".to_string(),
        destination: "9.9.9.9/32".to_string(),
        next_hops: vec![
            "172.16.50.253".to_string(),
            "172.16.50.254".to_string(),
        ],
        ..Default::default()
    });
    snapshot.neighbors.push(NeighborSnapshot {
        interface: "ge-0-0-2".to_string(),
        ifindex: BLUE_IFINDEX,
        family: "inet".to_string(),
        ip: "172.16.50.253".to_string(),
        mac: "00:aa:bb:cc:dd:03".to_string(),
        state: "reachable".to_string(),
        ..Default::default()
    });
    let forwarding =
        super::super::forwarding_build::build_forwarding_state(&snapshot);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let dst = Ipv4Addr::new(9, 9, 9, 9);
    let mut next_hops = std::collections::BTreeSet::new();
    for src_port in 40000..40010u16 {
        let key = pbr_key_for(src_port, dst);
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key,
        };
        let resolved = lookup_forwarding_resolution_for_session(
            &forwarding,
            &dynamic_neighbors,
            &flow,
            stamped_decision(unusable_resolution()),
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate,
            "port {src_port}: must forward"
        );
        assert_eq!(
            resolved.egress_ifindex, BLUE_IFINDEX,
            "port {src_port}: must stay in blue, not leak to default"
        );
        next_hops.insert(resolved.next_hop);
    }
    assert!(
        next_hops.len() >= 2,
        "distinct flows must spread across blue ECMP members, got {next_hops:?}"
    );
}

/// C14: a NAT64 v6->v4 rewrite reads family presence off the POST-NAT target.
#[test]
fn nat64_reresolve_uses_post_nat_family_table() {
    let forwarding = pbr_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    // v6 flow, but NAT64 rewrites the target to v4 8.8.8.8. Blue has v4
    // presence only: post-NAT family (v4) -> blue.inet.0 -> egress 12. A
    // pre-NAT family read (v6) would find blue.inet6.0 absent -> terminal.
    let key = SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x808, 0x808)),
        src_port: 55068,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    };
    let flow = SessionFlow {
        src_ip: key.src_ip,
        dst_ip: key.dst_ip,
        forward_key: key,
    };
    let (domain, check) = blue_stamp();
    let decision = SessionDecision {
        resolution: unusable_resolution(),
        nat: NatDecision {
            nat64: true,
            rewrite_dst: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            ..NatDecision::default()
        },
        install_table_domain: domain,
        install_table_check: check,
    };
    let resolved =
        lookup_forwarding_resolution_for_session(&forwarding, &dynamic_neighbors, &flow, decision);
    assert_eq!(
        resolved.disposition,
        ForwardingDisposition::ForwardCandidate
    );
    assert_eq!(resolved.egress_ifindex, BLUE_IFINDEX);
}

/// C10 (any-table): an unscoped-NAT-owned target stays local even when the
/// installing table is unresolvable — table-independent local wins over
/// terminal, without touching the ifindex-0 counter.
#[test]
fn unresolvable_stamp_serves_any_table_local() {
    let mut forwarding = pbr_state();
    let target = Ipv4Addr::new(8, 8, 8, 8);
    forwarding.local_v4.insert(target);
    forwarding.local_nat_any_table_v4.insert(target);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let before =
        super::super::forwarding::LOCAL_DELIVERY_IFINDEX0.load(Ordering::Relaxed);
    let unknown = SessionDecision {
        resolution: unusable_resolution(),
        nat: NatDecision::default(),
        install_table_domain: 999_999_999,
        install_table_check: 1,
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        unknown,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, 0);
    assert_eq!(
        super::super::forwarding::LOCAL_DELIVERY_IFINDEX0.load(Ordering::Relaxed),
        before
    );
}

/// C10 (interface-NAT): an interface-NAT-owned target stays local under an
/// unresolvable stamp, with its real ifindex.
#[test]
fn unresolvable_stamp_serves_interface_nat_local() {
    let mut forwarding = pbr_state();
    forwarding
        .interface_nat_v4
        .insert(Ipv4Addr::new(8, 8, 8, 8), LAN_IFINDEX);
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let unknown = SessionDecision {
        resolution: unusable_resolution(),
        nat: NatDecision::default(),
        install_table_domain: 999_999_999,
        install_table_check: 1,
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        unknown,
    );
    assert_eq!(resolved.disposition, ForwardingDisposition::LocalDelivery);
    assert_eq!(resolved.local_ifindex, LAN_IFINDEX);
}

/// C7/C10b: a tunnel-marked stored resolution takes the tunnel arm with no
/// table interaction — stamped or not, the outcome is identical and never a
/// blue FIB result.
#[test]
fn tunnel_resolution_bypasses_install_table() {
    let forwarding = pbr_state();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    let tunneled = ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        local_ifindex: 0,
        egress_ifindex: 0,
        tx_ifindex: 0,
        tunnel_endpoint_id: 99,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    };
    let stamped = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        stamped_decision(tunneled),
    );
    let unstamped = lookup_forwarding_resolution_for_session(
        &forwarding,
        &dynamic_neighbors,
        &pbr_flow(),
        unstamped_decision(tunneled),
    );
    assert_eq!(stamped.disposition, unstamped.disposition);
    assert_eq!(stamped.egress_ifindex, unstamped.egress_ifindex);
    assert_ne!(
        stamped.egress_ifindex, BLUE_IFINDEX,
        "tunnel arm must never serve a blue FIB result"
    );
}

/// GPT-3: re-requests during an active walk must not restart the cursor —
/// 300 stale entries (>1 budget of 256) with a re-arm before EVERY pass
/// still complete. Pre-fix the second pass re-examined vacant slots 0-256
/// forever and slots 256-300 starved.
#[test]
fn purge_rearm_mid_walk_does_not_starve_beyond_budget() {
    use super::install_table_purge::INSTALL_TABLE_PURGE_BUDGET;
    let channel = RuntimeViewChannel::default();
    let forwarding = Arc::new(pbr_state());
    publish_pbr_view(&channel, 7, forwarding.clone());
    let reader = channel.reader();
    let mut sessions = SessionTable::new();
    let dst = Ipv4Addr::new(8, 8, 8, 8);
    let total = INSTALL_TABLE_PURGE_BUDGET + 44;
    for i in 0..total {
        let key = pbr_key_for(30000 + i as u16, dst);
        assert!(
            sessions.install_with_protocol_with_origin(
                key,
                stamped_decision(unusable_resolution()),
                pbr_metadata(),
                SessionOrigin::SyncImport,
                NOW_NS,
                PROTO_TCP,
                0x18,
            ),
            "install {i}"
        );
    }
    let mut rotated_snapshot = pbr_snapshot();
    rotated_snapshot.routes.retain(|r| r.table == "inet.0");
    for iface in &mut rotated_snapshot.interfaces {
        if iface.ifindex == BLUE_IFINDEX {
            iface.routing_instance.clear();
        }
    }
    let rotated = Arc::new(super::super::forwarding_build::build_forwarding_state(
        &rotated_snapshot,
    ));
    publish_pbr_view(&channel, 8, rotated.clone());
    let shared = shared_maps();
    let mut purge = super::install_table_purge::InstallTablePurge::default();
    let mut evicted = Vec::new();
    let mut purged_total = 0usize;
    let mut passes = 0u32;
    purge.arm(8);
    while purge.is_running() && passes < 10 {
        purge.arm(8); // re-request every pass: retained, never restarting
        purged_total += purge.step(
            &mut sessions,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            &shared.sessions,
            &shared.nat_sessions,
            &shared.forward_wire_sessions,
            &shared.owner_rg_indexes,
            &shared.peer_worker_commands,
            &rotated,
            &reader,
            8,
            NOW_NS,
            0,
            &mut evicted,
        );
        passes += 1;
    }
    assert!(
        !purge.is_running(),
        "walk must complete despite per-pass re-arms ({passes} passes)"
    );
    assert_eq!(purged_total, total);
    assert_eq!(evicted.len(), total);
    for i in 0..total {
        assert!(sessions
            .entry_with_origin(&pbr_key_for(30000 + i as u16, dst))
            .is_none());
    }
}

fn rotated_blue_gone_state() -> ForwardingState {
    let mut rotated_snapshot = pbr_snapshot();
    rotated_snapshot.routes.retain(|r| r.table == "inet.0");
    // Presence includes connected routes: re-home the blue interface into the
    // default table too, so `blue` vanishes from the registry entirely (the
    // realistic "instance deleted" rotation).
    for iface in &mut rotated_snapshot.interfaces {
        if iface.ifindex == BLUE_IFINDEX {
            iface.routing_instance.clear();
        }
    }
    super::super::forwarding_build::build_forwarding_state(&rotated_snapshot)
}

fn synced_entry_for(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key: key.clone(),
        decision,
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: 0,
        tcp_close_class: 0,
    }
}

fn flush_deltas_for_test(
    deltas: &[SessionDelta],
    shared: &SharedMaps,
    peer_queue: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    forwarding: &ForwardingState,
) {
    use crate::afxdp::checksum::DnatTableFds;
    let ident = BindingIdentity {
        slot: 0,
        queue_id: 0,
        worker_id: 0,
        interface: Arc::<str>::from(""),
        ifindex: -1,
    };
    let dnat_fds = DnatTableFds::default();
    let recent_session_deltas = Arc::new(Mutex::new(VecDeque::new()));
    let peer_worker_commands = vec![peer_queue.clone()];
    let mut worker_lossless_wedged = false;
    flush_session_deltas(
        &ident,
        None,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &dnat_fds,
        deltas,
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &recent_session_deltas,
        &peer_worker_commands,
        crate::afxdp::empty_worker_commands_by_id(),
        &None,
        forwarding,
        &mut worker_lossless_wedged,
    );
}

/// GPT-2a: a table re-added between scan and teardown skips everything —
/// no local churn, no delta, and the (empty) flush preserves shared state.
#[test]
fn purge_table_readd_skips_all_through_flush() {
    let channel = RuntimeViewChannel::default();
    let forwarding = Arc::new(pbr_state());
    publish_pbr_view(&channel, 7, forwarding.clone());
    let reader = channel.reader();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    let decision = stamped_decision(unusable_resolution());
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    let shared = shared_maps();
    publish_shared_session(
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &synced_entry_for(&key, decision, pbr_metadata()),
    );
    // Latest re-adds blue while the step still scans the rotated view.
    publish_pbr_view(&channel, 8, forwarding.clone());
    let rotated = rotated_blue_gone_state();
    let peer_queue: Arc<Mutex<VecDeque<WorkerCommand>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let peer_cmds = vec![peer_queue.clone()];
    let mut purge = super::install_table_purge::InstallTablePurge::default();
    purge.arm(8);
    let mut evicted = Vec::new();
    let purged = purge.step(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &peer_cmds,
        &rotated,
        &reader,
        8,
        NOW_NS,
        0,
        &mut evicted,
    );
    assert_eq!(purged, 0, "re-added table must skip all teardown");
    assert!(sessions.entry_with_origin(&key).is_some());
    assert!(evicted.is_empty());
    let deltas = sessions.drain_deltas(64);
    assert!(deltas.is_empty(), "no close may be emitted on re-add skip");
    flush_deltas_for_test(&deltas, &shared, &peer_queue, &rotated);
    assert!(shared.sessions.lock().expect("lock").contains_key(&key));
    assert!(peer_queue.lock().expect("lock").is_empty());
}

/// GPT-2b: a fenced decline (shared stamp changed under the walk) emits no
/// close — the flush that follows must preserve the shared entry and queue
/// nothing, even though local teardown ran.
#[test]
fn purge_fence_decline_emits_no_close_through_flush() {
    let channel = RuntimeViewChannel::default();
    let forwarding = Arc::new(pbr_state());
    publish_pbr_view(&channel, 7, forwarding.clone());
    let reader = channel.reader();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    let decision = stamped_decision(unusable_resolution());
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    // Shared entry carries a DIFFERENT nonzero stamp: predicate-true under
    // the rotated view (unknown domain) but stamp-mismatched, so the fence
    // declines on identity alone.
    let mut diverged = decision;
    diverged.install_table_domain = 12345;
    diverged.install_table_check = 999;
    let shared = shared_maps();
    publish_shared_session(
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &synced_entry_for(&key, diverged, pbr_metadata()),
    );
    let rotated = Arc::new(rotated_blue_gone_state());
    publish_pbr_view(&channel, 8, rotated.clone());
    let peer_queue: Arc<Mutex<VecDeque<WorkerCommand>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let peer_cmds = vec![peer_queue.clone()];
    let mut purge = super::install_table_purge::InstallTablePurge::default();
    purge.arm(8);
    let mut evicted = Vec::new();
    let purged = purge.step(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &peer_cmds,
        &rotated,
        &reader,
        8,
        NOW_NS,
        0,
        &mut evicted,
    );
    assert_eq!(purged, 1, "local teardown still runs on decline");
    assert!(sessions.entry_with_origin(&key).is_none());
    assert_eq!(evicted, vec![key.clone()]);
    let deltas = sessions.drain_deltas(64);
    assert!(deltas.is_empty(), "decline must emit no close");
    flush_deltas_for_test(&deltas, &shared, &peer_queue, &rotated);
    assert!(
        shared.sessions.lock().expect("lock").contains_key(&key),
        "fenced shared entry must survive the flush"
    );
    assert!(
        peer_queue.lock().expect("lock").is_empty(),
        "decline must replicate nothing"
    );
}

/// GPT-2c: a rejected (ambiguous) companion survives the forward close's
/// flush — no reverse derivation, no ordinary replicate. The forward close
/// carries the purge-retirement flag; the peer queue holds exactly the one
/// conditional delete the walk sent, nothing the drain added.
#[test]
fn purge_rejected_companion_survives_close_flush() {
    let channel = RuntimeViewChannel::default();
    let forwarding = Arc::new(pbr_state());
    publish_pbr_view(&channel, 7, forwarding.clone());
    let reader = channel.reader();
    let mut sessions = SessionTable::new();
    let key = pbr_key();
    let decision = stamped_decision(unusable_resolution());
    assert!(sessions.install_with_protocol_with_origin(
        key.clone(),
        decision,
        pbr_metadata(),
        SessionOrigin::SyncImport,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    // Simultaneous-open forward squatting the derived reverse slot: the
    // backlink check rejects it (not reverse), so the purge preserves it.
    let rk = reverse_session_key(&key, NatDecision::default());
    assert_ne!(rk, key);
    assert!(sessions.install_with_protocol_with_origin(
        rk.clone(),
        unstamped_decision(unusable_resolution()),
        pbr_metadata(),
        SessionOrigin::ForwardFlow,
        NOW_NS,
        PROTO_TCP,
        0x18,
    ));
    let shared = shared_maps();
    publish_shared_session(
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &synced_entry_for(&key, decision, pbr_metadata()),
    );
    publish_shared_session(
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &synced_entry_for(&rk, unstamped_decision(unusable_resolution()), pbr_metadata()),
    );
    let rotated = Arc::new(rotated_blue_gone_state());
    publish_pbr_view(&channel, 8, rotated.clone());
    let peer_queue: Arc<Mutex<VecDeque<WorkerCommand>>> =
        Arc::new(Mutex::new(VecDeque::new()));
    let peer_cmds = vec![peer_queue.clone()];
    // Clear install-time deltas (F2's Open) so the ring holds exactly what
    // the walk emits.
    sessions.drain_deltas(64);
    let mut purge = super::install_table_purge::InstallTablePurge::default();
    purge.arm(8);
    let mut evicted = Vec::new();
    let purged = purge.step(
        &mut sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &shared.sessions,
        &shared.nat_sessions,
        &shared.forward_wire_sessions,
        &shared.owner_rg_indexes,
        &peer_cmds,
        &rotated,
        &reader,
        8,
        NOW_NS,
        0,
        &mut evicted,
    );
    assert_eq!(purged, 1);
    assert!(sessions.entry_with_origin(&key).is_none());
    assert!(
        sessions.entry_with_origin(&rk).is_some(),
        "rejected companion stays local"
    );
    let deltas = sessions.drain_deltas(64);
    assert_eq!(deltas.len(), 1, "exactly the forward close");
    assert_eq!(deltas[0].kind, SessionDeltaKind::Close);
    assert_eq!(deltas[0].key, key);
    assert!(
        deltas[0].purge_retirement,
        "purge close must carry the retirement flag"
    );
    {
        let q = peer_queue.lock().expect("lock");
        assert_eq!(q.len(), 1, "walk sends exactly the conditional delete");
        assert!(
            matches!(
                &q[0],
                WorkerCommand::DeleteSyncedIfTableUnknown { key: k, .. } if *k == key
            ),
            "unexpected peer command: {:?}",
            q[0]
        );
    }
    flush_deltas_for_test(&deltas, &shared, &peer_queue, &rotated);
    assert!(
        !shared.sessions.lock().expect("lock").contains_key(&key),
        "removed forward stays removed"
    );
    assert!(
        shared.sessions.lock().expect("lock").contains_key(&rk),
        "rejected companion must survive the close flush (no reverse derivation)"
    );
    assert!(
        sessions.entry_with_origin(&rk).is_some(),
        "rejected companion stays local through flush"
    );
    let q = peer_queue.lock().expect("lock");
    assert_eq!(
        q.len(),
        1,
        "drain must add no ordinary replicate for a purge close, got {q:?}"
    );
}
