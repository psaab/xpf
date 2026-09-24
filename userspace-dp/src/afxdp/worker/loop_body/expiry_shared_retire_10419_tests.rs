use super::*;
use crate::afxdp::shared_ops::publish_shared_session;
use crate::afxdp::types::SharedSessionOwnerRgIndexes;
use crate::afxdp::worker::SyncedSessionEntry;
use crate::nat::NatDecision;
use crate::session::{ExpiredSession, SessionDecision, SessionKey, SessionMetadata, SessionOrigin};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

// These cells bind the #10419 retirement predicate to both pieces of identity
// carried by the local expiry record. A revert that removes only the helper
// call, drops the session-id fence, or broadens it to ordinary origins goes RED.
type SharedMap = Arc<Mutex<rustc_hash::FxHashMap<SessionKey, SyncedSessionEntry>>>;

struct SharedMaps {
    sessions: SharedMap,
    nat_sessions: SharedMap,
    forward_wire_sessions: SharedMap,
    owner_rg_indexes: SharedSessionOwnerRgIndexes,
}

impl SharedMaps {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(rustc_hash::FxHashMap::default())),
            nat_sessions: Arc::new(Mutex::new(rustc_hash::FxHashMap::default())),
            forward_wire_sessions: Arc::new(Mutex::new(rustc_hash::FxHashMap::default())),
            owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
        }
    }

    fn publish(&self, entry: &SyncedSessionEntry) {
        publish_shared_session(
            &self.sessions,
            &self.nat_sessions,
            &self.forward_wire_sessions,
            &self.owner_rg_indexes,
            entry,
        );
    }
}

fn key(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port,
        dst_port: 5201,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn decision() -> SessionDecision {
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
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn metadata() -> SessionMetadata {
    SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
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
    }
}

fn entry(key: SessionKey, origin: SessionOrigin, session_id: u64) -> SyncedSessionEntry {
    SyncedSessionEntry {
        key,
        decision: decision(),
        metadata: metadata(),
        leak_incarnation: 0,
        origin,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id,
        tcp_close_class: 0,
    }
}

fn expired(entry: &SyncedSessionEntry) -> ExpiredSession {
    ExpiredSession {
        key: entry.key.clone(),
        decision: entry.decision,
        metadata: entry.metadata.clone(),
        origin: entry.origin,
        session_id: entry.session_id,
        close_class: 0,
        install_epoch: 0,
        overflow_close: None,
    }
}

fn retire(maps: &SharedMaps, entries: &[ExpiredSession]) {
    super::retire_expired_missing_neighbor_seeds(
        entries,
        &maps.sessions,
        &maps.nat_sessions,
        &maps.forward_wire_sessions,
        &maps.owner_rg_indexes,
    );
}

#[test]
fn expired_missing_neighbor_seed_retires_shared_wire_state_10419() {
    let maps = SharedMaps::new();
    let seed = entry(key(5201), SessionOrigin::MissingNeighborSeed, 41);
    maps.publish(&seed);

    retire(&maps, &[expired(&seed)]);

    assert!(
        crate::afxdp::shared_ops::lock_shared_recover(&maps.sessions)
            .get(&seed.key)
            .is_none(),
        "the expired seed's primary shared row must be removed"
    );
    assert!(
        crate::afxdp::shared_ops::lock_shared_recover(&maps.nat_sessions)
            .values()
            .all(|candidate| candidate.session_id != seed.session_id),
        "the expired seed's shared NAT aliases must be removed"
    );
    assert!(
        crate::afxdp::shared_ops::lock_shared_recover(&maps.forward_wire_sessions)
            .values()
            .all(|candidate| candidate.session_id != seed.session_id),
        "the expired seed's shared wire aliases must be removed"
    );
}

#[test]
fn seed_retirement_preserves_same_key_replacement_10419() {
    let maps = SharedMaps::new();
    let key = key(5202);
    let expired_seed = entry(key.clone(), SessionOrigin::MissingNeighborSeed, 41);
    let replacement = entry(key, SessionOrigin::MissingNeighborSeed, 42);
    maps.publish(&expired_seed);
    maps.publish(&replacement);

    retire(&maps, &[expired(&expired_seed)]);

    let stored = crate::afxdp::shared_ops::lock_shared_recover(&maps.sessions)
        .get(&replacement.key)
        .cloned()
        .expect("same-key replacement must remain published");
    assert_eq!(stored.session_id, replacement.session_id);
    assert_eq!(stored.origin, replacement.origin);
}

#[test]
fn seed_retirement_preserves_same_id_non_seed_replacement_10419() {
    let maps = SharedMaps::new();
    let replacement = entry(key(5203), SessionOrigin::ForwardFlow, 41);
    maps.publish(&replacement);

    let expired_seed = entry(
        replacement.key.clone(),
        SessionOrigin::MissingNeighborSeed,
        replacement.session_id,
    );
    retire(&maps, &[expired(&expired_seed)]);

    let stored = crate::afxdp::shared_ops::lock_shared_recover(&maps.sessions)
        .get(&replacement.key)
        .cloned()
        .expect("a non-seed same-id replacement must remain published");
    assert_eq!(stored.origin, SessionOrigin::ForwardFlow);
    assert_eq!(stored.session_id, replacement.session_id);
}

/// #10419 wiring guard: the helper cells above bind seed retirement, while
/// this production-order pin binds the worker bridge that drains ordinary
/// expiry Close deltas before the next poll. Removing the bridge or moving
/// seed retirement after resource teardown makes this cell RED.
#[test]
fn worker_loop_orders_expiry_teardown_before_poll_10419() {
    let src = include_str!("mod.rs");
    let executable_lines: Vec<_> = src
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect();
    let expiry = executable_lines
        .iter()
        .position(|line| line.starts_with("let expired_entries = sessions.expire_stale_entries_ha"))
        .expect("worker loop must run the expiry walk");
    let retire = executable_lines
        .iter()
        .position(|line| line.starts_with("retire_expired_missing_neighbor_seeds("))
        .expect("worker loop must retire published seed state");
    let reap = executable_lines
        .iter()
        .position(|line| line.starts_with("reap_expired_sessions("))
        .expect("worker loop must reap expiry resources");
    let overflow = executable_lines
        .iter()
        .position(|line| {
            line.starts_with("expiry_overflow_deltas.extend(")
        })
        .expect("worker loop must retain expiry overflow records");
    let drain = executable_lines
        .iter()
        .enumerate()
        .skip(reap)
        .find(|(_, line)| **line == "let _ = drain_and_flush_all!();")
        .map(|(index, _)| index)
        .expect("worker loop must drain expiry teardown");
    let poll = executable_lines
        .iter()
        .position(|line| line.starts_with("if poll_binding("))
        .expect("worker loop must poll bindings");
    // The 1278 drain (first match past reap) flushes the expiry walk's
    // ring-accepted Closes before overflow collection; d2425efb5's extra
    // pre-chunk drain does not disturb this order.
    assert!(
        expiry < retire && retire < reap && reap < drain && drain < overflow && overflow < poll,
        "expiry must retire seeds, reap resources, drain Close deltas, then poll"
    );
}
