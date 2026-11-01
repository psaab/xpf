//! #18655: the ct-slice's shared `(stage, fwd, rev)` read must be exact and
//! must do bounded work.
//!
//! Before the fix, `shared_row_stage_and_counts` scanned BOTH whole shared
//! maps once for EVERY emit key while holding both global mutexes. Every
//! worker holds a copy of every session, so a slice cost
//! `sessions × shared rows`. On tcp at 4000 sessions this held the mutexes
//! ~100% of the time (17k calls/s × 57 µs) and stalled every worker.
//!
//! These cells pin three things:
//! 1. EXACTNESS. Over a mixed shared state, the batched pass returns
//!    exactly what the old per-key scan (copied verbatim below as the
//!    reference) returned, for every key. The state covers forward,
//!    reverse and NAT'd wire-alias rows, a stale alias left by a NAT
//!    change, an alias inserted under the caller's NAT, cross-flow key
//!    collisions, duplicate and absent keys. The census in
//!    `docs/log/18655.md` shows wire rows are not stored under their own
//!    `entry.key`, so keyed `get()` would diverge here.
//! 2. WORK. One batch visits each shared row exactly once, whatever the
//!    batch size. Reverting to a per-key scan makes it `keys × rows`.
//! 3. The batched count restamp leaves the maps exactly as the per-pair
//!    helper does.

use super::*;
use crate::session::{SessionOrigin, TcpHandshakeState};
use std::net::{IpAddr, Ipv4Addr};

type Map = Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>;

/// The pre-#18655 per-key helper, verbatim apart from taking the guarded
/// maps directly. It is the reference the batch must reproduce exactly.
fn scan_reference(
    holders: &FastMap<SessionKey, SyncedSessionEntry>,
    wires: &FastMap<SessionKey, SyncedSessionEntry>,
    forward_key: &SessionKey,
    nat: crate::nat::NatDecision,
) -> (u8, u64, u64) {
    let reverse_key = crate::session::reverse_session_key(forward_key, nat);
    let wire_key = crate::session::forward_wire_key(forward_key, nat);
    let mut stage = 0u8;
    let mut fwd = 0u64;
    let mut rev = 0u64;
    for (map, is_wire) in [(holders, false), (wires, true)] {
        for entry in map.values() {
            let vouches = if is_wire {
                entry.key == *forward_key || entry.key == reverse_key || entry.key == wire_key
            } else {
                entry.key == *forward_key || entry.key == reverse_key
            };
            if !vouches {
                continue;
            }
            if !entry.metadata.is_reverse {
                stage = stage.max(entry.tcp_handshake_state);
            }
            fwd = fwd.max(entry.fwd_packets);
            rev = rev.max(entry.rev_packets);
        }
    }
    (stage, fwd, rev)
}

pub(in crate::afxdp) fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

pub(in crate::afxdp) fn key(src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16, protocol: u8) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol,
        src_ip: src,
        dst_ip: dst,
        src_port,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn no_nat() -> crate::nat::NatDecision {
    crate::nat::NatDecision::default()
}

pub(in crate::afxdp) fn snat(port: Option<u16>) -> crate::nat::NatDecision {
    crate::nat::NatDecision {
        rewrite_src: Some(v4(172, 16, 80, 8)),
        rewrite_src_port: port,
        ..crate::nat::NatDecision::default()
    }
}

fn dnat() -> crate::nat::NatDecision {
    crate::nat::NatDecision {
        rewrite_dst: Some(v4(10, 0, 61, 200)),
        rewrite_dst_port: Some(8080),
        ..crate::nat::NatDecision::default()
    }
}

#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn row(
    key: &SessionKey,
    nat: crate::nat::NatDecision,
    stage: u8,
    fwd: u64,
    rev: u64,
    reverse: bool,
    session_id: u64,
) -> SyncedSessionEntry {
    let metadata = crate::session::SessionMetadata {
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: reverse,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    };
    SyncedSessionEntry {
        key: key.clone(),
        decision: crate::session::SessionDecision {
            resolution: crate::afxdp::ForwardingResolution {
                disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat,
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        persistent_lease_hold: None,
        source_nat_static: None,
        leak_incarnation: 0,
        origin: SessionOrigin::ForwardFlow,
        protocol: key.protocol,
        tcp_flags: 0,
        generation: 0,
        session_id,
        tcp_close_class: 0,
        tcp_handshake_state: stage,
        rev_packets: rev,
        fwd_packets: fwd,
        pptp_call_ids: 0,
    }
}

fn maps() -> (Map, Map, Map, SharedSessionOwnerRgIndexes) {
    (
        Arc::new(Mutex::new(FastMap::default())),
        Arc::new(Mutex::new(FastMap::default())),
        Arc::new(Mutex::new(FastMap::default())),
        SharedSessionOwnerRgIndexes::default(),
    )
}

/// Deterministic LCG, so the generated population is reproducible.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A mixed shared state built through the production publish and restamp
/// paths, plus the aliasing shapes from the census that keyed `get()`
/// cannot reach. Returns the maps and the `(key, nat)` queries to compare
/// (each flow under its own NAT, some under a foreign NAT, absent keys,
/// duplicates).
fn mixed_state() -> (Map, Map, Vec<(SessionKey, crate::nat::NatDecision)>) {
    let (shared, nat_map, wire_map, indexes) = maps();
    let mut rng = Lcg(18655);
    let stages = [
        0u8,
        TcpHandshakeState::Opening.to_wire(),
        TcpHandshakeState::HandshakePending.to_wire(),
        TcpHandshakeState::Established.to_wire(),
    ];
    let mut queries = Vec::new();
    let client = v4(10, 0, 61, 102);
    let server = v4(172, 16, 80, 200);
    for i in 0..48u16 {
        let protocol = if i % 3 == 0 { crate::ip_proto::PROTO_UDP } else { crate::ip_proto::PROTO_TCP };
        let forward = key(client, 20000 + i, server, 5201 + (i % 4), protocol);
        let nat = match i % 4 {
            0 => no_nat(),
            1 => snat(Some(40000 + i)),
            2 => snat(None),
            _ => dnat(),
        };
        let sid = 1000 + u64::from(i);
        let stage = stages[rng.pick(4) as usize];
        let fwd_row = row(&forward, nat, stage, rng.pick(50), rng.pick(50), false, sid);
        publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &fwd_row);
        if i % 5 != 4 {
            let reverse = crate::session::reverse_session_key(&forward, nat);
            let rev_row = row(&reverse, nat, stages[rng.pick(4) as usize], rng.pick(50), rng.pick(90), true, sid);
            publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &rev_row);
        }
        queries.push((forward.clone(), nat));
        if i % 7 == 0 {
            // A query under a foreign NAT (R and W derive differently).
            queries.push((forward.clone(), snat(Some(41000 + i))));
        }
    }
    // A completed pair whose wire alias is (re)inserted by the ct-slice
    // alias restamp under the CALLER's NAT (census site lookup.rs, the
    // `wire_sessions.insert(wire_key, aliased)` arm).
    let restamped = key(client, 30001, server, 443, crate::ip_proto::PROTO_TCP);
    publish_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &row(&restamped, snat(Some(45001)), stages[2], 7, 3, false, 3001),
    );
    {
        let wire_key = crate::session::forward_wire_key(&restamped, snat(Some(45001)));
        lock_shared_recover(&wire_map).remove(&wire_key);
    }
    restamp_shared_forward_wire_established(&shared, &wire_map, &[(restamped.clone(), snat(Some(45999)))]);
    queries.push((restamped.clone(), snat(Some(45001))));
    queries.push((restamped.clone(), snat(Some(45999))));
    // A republish of the SAME canonical key under a changed NAT. publish
    // inserts the new alias and leaves the old one under the old wire key
    // with `entry.key == F`. Keyed get(fwk(F, new_nat)) cannot see the old
    // alias, but the scan matches it.
    let renatted = key(client, 30002, server, 443, crate::ip_proto::PROTO_TCP);
    publish_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &row(&renatted, snat(Some(46001)), stages[3], 90, 80, false, 3002),
    );
    publish_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &row(&renatted, snat(Some(46002)), stages[1], 1, 0, false, 3003),
    );
    queries.push((renatted.clone(), snat(Some(46002))));
    // Cross-flow collisions: a forward session whose canonical key equals
    // another flow's REVERSE key, and one whose canonical key equals
    // another flow's WIRE key, both NAT'd so they carry wire aliases.
    let base = key(client, 30003, server, 443, crate::ip_proto::PROTO_TCP);
    let base_nat = snat(Some(47001));
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&base, base_nat, stages[2], 5, 1, false, 3004));
    let base_reverse = crate::session::reverse_session_key(&base, base_nat);
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&base_reverse, dnat(), stages[3], 33, 44, false, 3005));
    let base_wire = crate::session::forward_wire_key(&base, base_nat);
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&base_wire, snat(Some(47002)), stages[3], 55, 66, false, 3006));
    queries.push((base.clone(), base_nat));
    queries.push((base_reverse.clone(), dnat()));
    queries.push((base_wire.clone(), snat(Some(47002))));
    // A row stored directly under its own wire tuple (the shape the B5
    // cell pins) and a reverse row in the wire map.
    {
        let direct = key(client, 30004, server, 443, crate::ip_proto::PROTO_TCP);
        let nat = snat(Some(48001));
        let wire_key = crate::session::forward_wire_key(&direct, nat);
        let mut w = lock_shared_recover(&wire_map);
        w.insert(wire_key.clone(), row(&wire_key, nat, stages[3], 12, 13, false, 3007));
        let reverse = crate::session::reverse_session_key(&direct, nat);
        w.insert(reverse.clone(), row(&reverse, nat, stages[3], 21, 31, true, 3007));
        drop(w);
        queries.push((direct, nat));
    }
    // Absent keys and a duplicate query.
    queries.push((key(v4(192, 0, 2, 1), 1, v4(192, 0, 2, 2), 2, crate::ip_proto::PROTO_TCP), snat(Some(1))));
    queries.push((key(v4(192, 0, 2, 1), 1, v4(192, 0, 2, 2), 2, crate::ip_proto::PROTO_UDP), no_nat()));
    let dup = queries[1].clone();
    queries.push(dup);
    (shared, wire_map, queries)
}

#[test]
fn batched_stage_counts_equal_the_per_key_scan_18655() {
    let (shared, wire_map, queries) = mixed_state();
    let batched = shared_rows_stage_and_counts(&shared, &wire_map, &queries);
    assert_eq!(batched.len(), queries.len());
    let holders = lock_shared_recover(&shared);
    let wires = lock_shared_recover(&wire_map);
    let mut nonzero = 0usize;
    for ((key, nat), got) in queries.iter().zip(&batched) {
        let want = scan_reference(&holders, &wires, key, *nat);
        assert_eq!(*got, want, "#18655: batch diverged from the per-key scan for {key:?} under {nat:?}");
        nonzero += usize::from(want != (0, 0, 0));
    }
    // The fixture must exercise the arms it claims: most queries match
    // rows, and both maps hold rows.
    assert!(nonzero > queries.len() / 2, "fixture: too few matching queries ({nonzero})");
    assert!(!wires.is_empty() && !holders.is_empty(), "fixture: both maps must be populated");
    // Each query must also be answered the same when it is the only one
    // in its batch (no cross-key leakage through shared slots).
    drop(wires);
    drop(holders);
    for (index, query) in queries.iter().enumerate() {
        let single = shared_rows_stage_and_counts(&shared, &wire_map, std::slice::from_ref(query));
        assert_eq!(single[0], batched[index], "#18655: single-key batch differs for {query:?}");
    }
}

/// The aliasing shapes that make keyed `get()` inexact are real in this
/// fixture: for at least one query the matching wire row sits under a map
/// key other than `forward_wire_key(F, nat)`. If this ever stops holding,
/// the equivalence cell above has lost its discriminating rows.
#[test]
fn fixture_holds_wire_rows_keyed_get_cannot_reach_18655() {
    let (shared, wire_map, queries) = mixed_state();
    let _ = shared;
    let wires = lock_shared_recover(&wire_map);
    let mut unreachable = 0usize;
    for (key, nat) in &queries {
        let reverse_key = crate::session::reverse_session_key(key, *nat);
        let wire_key = crate::session::forward_wire_key(key, *nat);
        for (map_key, entry) in wires.iter() {
            let vouches = entry.key == *key || entry.key == reverse_key || entry.key == wire_key;
            let keyed_reach = *map_key == *key || *map_key == reverse_key || *map_key == wire_key;
            if vouches && !keyed_reach {
                unreachable += 1;
            }
        }
    }
    assert!(unreachable > 0, "fixture: no wire row outside keyed reach; the equivalence cell would be blind");
}

#[test]
fn one_pass_visits_each_shared_row_once_per_batch_18655() {
    let (shared, wire_map, queries) = mixed_state();
    let rows = {
        let h = lock_shared_recover(&shared);
        let w = lock_shared_recover(&wire_map);
        (h.len() + w.len()) as u64
    };
    for batch in [&queries[..1], &queries[..8], &queries[..]] {
        let before = STAGE_COUNTS_WORK_18655.with(|w| w.get());
        let _ = shared_rows_stage_and_counts(&shared, &wire_map, batch);
        let after = STAGE_COUNTS_WORK_18655.with(|w| w.get());
        assert_eq!(after.0 - before.0, 1, "#18655: one pass per batch");
        assert_eq!(
            after.1 - before.1,
            rows,
            "#18655: a batch of {} keys must visit each of the {rows} shared rows exactly once \
             (a per-key scan visits keys × rows)",
            batch.len()
        );
    }
    // The pure pass reports the same count.
    let holders = lock_shared_recover(&shared);
    let wires = lock_shared_recover(&wire_map);
    let mut out = vec![(0, 0, 0); 1];
    let mut wanted = FastMap::default();
    wanted.insert(queries[0].0.clone(), vec![(0usize, false)]);
    assert_eq!(super::lookup::stage_and_counts_pass(&holders, &wires, &wanted, &mut out) as u64, rows);
}

#[test]
fn empty_batch_takes_no_lock_and_no_pass_18655() {
    let (shared, wire_map, _) = mixed_state();
    let before = STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let out = shared_rows_stage_and_counts(&shared, &wire_map, &[]);
    assert!(out.is_empty());
    assert_eq!(STAGE_COUNTS_WORK_18655.with(|w| w.get()), before);
}

fn snapshot(map: &Map) -> Vec<(SessionKey, u64, u64)> {
    let mut rows: Vec<_> = lock_shared_recover(map)
        .iter()
        .map(|(k, e)| (k.clone(), e.fwd_packets, e.rev_packets))
        .collect();
    rows.sort_by(|a, b| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)));
    rows
}

#[test]
fn batched_count_restamp_equals_per_pair_restamp_18655() {
    let (shared_a, wire_a, queries) = mixed_state();
    let (shared_b, wire_b, _) = mixed_state();
    let mut rng = Lcg(55018);
    let pairs: Vec<(SessionKey, crate::nat::NatDecision, u64, u64)> = queries
        .iter()
        .map(|(k, n)| {
            let fwd = if rng.pick(3) == 0 { 0 } else { rng.pick(200) };
            let rev = if rng.pick(3) == 0 { 0 } else { rng.pick(200) };
            (k.clone(), *n, fwd, rev)
        })
        .collect();
    assert!(pairs.iter().any(|p| p.2 == 0 && p.3 == 0), "fixture: include zero-count pairs");
    for (k, n, f, r) in &pairs {
        restamp_shared_packet_counts(&shared_a, &wire_a, k, *n, *f, *r);
    }
    restamp_shared_packet_counts_batch(&shared_b, &wire_b, &pairs);
    assert_eq!(snapshot(&shared_a), snapshot(&shared_b), "#18655: batched shared restamp diverged");
    assert_eq!(snapshot(&wire_a), snapshot(&wire_b), "#18655: batched wire restamp diverged");
    assert_ne!(snapshot(&shared_a), snapshot(&mixed_state().0), "fixture: the restamp must change something");
}

/// `restamp_shared_forward_wire_established` now finds the canonical row
/// for a missing alias through a first-wins map instead of `iter().find`.
/// Two completed keys that share one wire key (colliding translations)
/// must still clone the FIRST key's canonical row into the alias, as the
/// linear find did.
#[test]
fn wire_alias_restamp_keeps_first_canonical_on_collision_18655() {
    let (shared, nat_map, wire_map, indexes) = maps();
    let client = v4(10, 0, 61, 102);
    let server = v4(172, 16, 80, 200);
    // Same translated tuple for both: SNAT to one address and one port.
    let nat = snat(Some(49001));
    let first = key(client, 31001, server, 443, crate::ip_proto::PROTO_TCP);
    let second = key(v4(10, 0, 61, 103), 31001, server, 443, crate::ip_proto::PROTO_TCP);
    let wire_key = crate::session::forward_wire_key(&first, nat);
    assert_eq!(wire_key, crate::session::forward_wire_key(&second, nat), "fixture: colliding wire keys");
    let pending = TcpHandshakeState::HandshakePending.to_wire();
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&first, nat, pending, 1, 1, false, 5001));
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&second, nat, pending, 2, 2, false, 5002));
    lock_shared_recover(&wire_map).remove(&wire_key);
    restamp_shared_forward_wire_established(&shared, &wire_map, &[(first.clone(), nat), (second.clone(), nat)]);
    let alias = lock_shared_recover(&wire_map).get(&wire_key).cloned().expect("alias reinserted");
    assert_eq!(alias.key, first, "#18655: the alias must clone the FIRST completed key's canonical row");
    assert_eq!(alias.session_id, 5001);
}
