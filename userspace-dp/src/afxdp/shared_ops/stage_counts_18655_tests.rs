//! #18655: the ct-slice's shared `(stage, fwd, rev)` read must be exact and
//! must do bounded work.
//!
//! Before the fix, `shared_row_stage_and_counts` scanned BOTH whole shared
//! maps once for EVERY emit key while holding both global mutexes. Every
//! worker holds a copy of every session, so a slice cost
//! `sessions × shared rows`. On tcp at 4000 sessions this held the mutexes
//! ~100% of the time (17k calls/s × 57 µs) and stalled every worker.
//!
//! These cells pin four things:
//! 1. EXACTNESS. Over a mixed shared state, the batched pass returns exactly
//!    what the old per-key scan (copied verbatim below as the reference)
//!    returned. Fixtures cover forward/reverse/NAT aliases, stale/caller-NAT
//!    aliases, collisions, duplicate and absent keys.
//! 2. LOCK BOUNDS. `STAGE_COUNTS_WORK_18655` records actual rows fetched per
//!    dual-map hold at small and 64k populations, not merely query keys.
//! 3. FAN-OUT WORK. Lookup candidates and every output-slot fold iteration
//!    share a 16,384-operation invocation budget while each map-lock hold is
//!    limited to 128 visits; the collision and 65,536-duplicate cells exercise
//!    both forms of fan-out.
//! 4. The batched count restamp leaves the maps exactly as the per-pair helper
//!    does. Stable-slot lifecycle and between-hold cells pin mutation behavior.

use super::*;
use crate::session::{SessionOrigin, TcpHandshakeState};
use std::net::{IpAddr, Ipv4Addr};

type Map = Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>;
const EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662: usize = 128;
pub(crate) const EXPECTED_STAGE_COUNTS_INVOCATION_BUDGET_18662: usize = 16_384;


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
    let metadata = crate::session::SessionMetadata { forward_wire_alias_origin: false,
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
        sibling_last_seen_ns: 0, last_served_ns: 0, close_claim_until_ns: 0,
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
fn mixed_state() -> (Map, Map, SharedSessionOwnerRgIndexes, Vec<(SessionKey, crate::nat::NatDecision)>) {
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
    // alias restamp under the CALLER's NAT (census site restamp.rs:546, the
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
        let mut wires = lock_shared_recover(&wire_map);
        let removed = wires.remove(&wire_key).expect("published alias present");
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &wire_key,
            Some(&removed),
            None,
        );
    }
    restamp_shared_forward_wire_established(&shared, &wire_map, &indexes, &[(restamped.clone(), snat(Some(45999)))]);
    {
        let wire_index = lock_shared_recover(&indexes.stage_counts_forward_wire_sessions);
        let aliases = wire_index
            .get(&restamped)
            .expect("#18662: restamp keeps a reserved entry-key bucket");
        assert_eq!(aliases.iter().filter(|slot| slot.live).count(), 1);
        assert!(
            !aliases.spilled(),
            "#18662: restoring one wire alias stays in the two-slot inline bucket"
        );
    }
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
    // A no-NAT forward row whose canonical key equals another flow's WIRE
    // key. It has no alias of its own, so it lives only in
    // `shared_sessions`, where the W role must NOT vouch (W is wire-only).
    // Without this row a mutant that lets W vouch in `shared_sessions`
    // survives, because every other W-keyed row also has a wire alias
    // carrying the same values.
    let shadow = key(client, 30005, server, 443, crate::ip_proto::PROTO_TCP);
    let shadow_nat = snat(Some(47101));
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&shadow, shadow_nat, stages[1], 2, 0, false, 3008));
    let shadow_wire = crate::session::forward_wire_key(&shadow, shadow_nat);
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &row(&shadow_wire, no_nat(), stages[3], 77, 88, false, 3009));
    queries.push((shadow.clone(), shadow_nat));
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
    (shared, wire_map, indexes, queries)
}

#[test]
fn batched_stage_counts_equal_the_per_key_scan_18655() {
    let (shared, wire_map, indexes, queries) = mixed_state();
    let batched = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, &queries);
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
    // The shadow row (keyed by another flow's wire key, shared map only)
    // must not leak into that flow's answer.
    let shadow_q = queries
        .iter()
        .position(|(k, _)| k.src_port == 30005)
        .expect("fixture: shadow query present");
    assert_eq!(batched[shadow_q].1, 2, "#18655: a W-keyed shared_sessions row must not vouch");
    // Each query must also be answered the same when it is the only one
    // in its batch (no cross-key leakage through shared slots).
    drop(wires);
    drop(holders);
    for (index, query) in queries.iter().enumerate() {
        let single = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, std::slice::from_ref(query));
        assert_eq!(single[0], batched[index], "#18655: single-key batch differs for {query:?}");
    }
}

/// The aliasing shapes that make keyed `get()` inexact are real in this
/// fixture: for at least one query the matching wire row sits under a map
/// key other than `forward_wire_key(F, nat)`. If this ever stops holding,
/// the equivalence cell above has lost its discriminating rows.
#[test]
fn fixture_holds_wire_rows_keyed_get_cannot_reach_18655() {
    let (shared, wire_map, _indexes, queries) = mixed_state();
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
fn indexed_stage_counts_bound_each_hold_small_18662() {
    let (shared, wire_map, indexes, queries) = mixed_state();
    let rows = {
        let h = lock_shared_recover(&shared);
        let w = lock_shared_recover(&wire_map);
        (h.len() + w.len()) as u64
    };
    for batch in [&queries[..1], &queries[..8], &queries[..]] {
        let before = STAGE_COUNTS_WORK_18655.with(|w| w.get());
        let _ = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, batch);
        let after = STAGE_COUNTS_WORK_18655.with(|w| w.get());
        assert_eq!(after.0 - before.0, 1, "#18662: one indexed batch call");
        assert!(
            after.1 - before.1 <= rows.saturating_mul(4),
            "#18662: indexed reads stay proportional to the table, not per-key scans"
        );
        assert!(
            after.2 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
            "#18662: max rows fetched in one dual-map lock hold is {}, bound is {}",
            after.2,
            EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662
        );
        assert!(
            after.3 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
            "#18662: max lookup candidates in one hold is {}, bound is {}",
            after.3,
            EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662
        );
    }
}

#[test]
fn indexed_stage_counts_bound_each_hold_at_64k_18662() {
    const ROWS: usize = 65_536;
    let shared: Map = Arc::new(Mutex::new(FastMap::default()));
    let wire_map: Map = Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let server = v4(172, 16, 80, 200);
    let nat = |i: usize| snat(Some(30_000u16.wrapping_add(i as u16)));
    let mut queries = Vec::with_capacity(ROWS);
    {
        let mut holders = lock_shared_recover(&shared);
        let mut wires = lock_shared_recover(&wire_map);
        for i in 0..ROWS {
            let forward = key(
                v4(10, 0, (i >> 8) as u8, i as u8),
                20_000 + (i % 40_000) as u16,
                server,
                5201,
                crate::ip_proto::PROTO_TCP,
            );
            let decision = nat(i);
            let entry = row(
                &forward,
                decision,
                TcpHandshakeState::Established.to_wire(),
                i as u64,
                1,
                false,
                i as u64 + 1,
            );
            let wire_key = crate::session::forward_wire_key(&forward, decision);
            holders.insert(forward.clone(), entry.clone());
            wires.insert(wire_key.clone(), entry.clone());
            update_stage_counts_entry_key_index(
                &indexes.stage_counts_forward_wire_sessions,
                &wire_key,
                None,
                Some(&entry),
            );
            queries.push((forward, decision));
        }
    }
    let before = STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let out = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, &queries);
    let after = STAGE_COUNTS_WORK_18655.with(|w| w.get());
    assert_eq!(out.len(), ROWS);
    for (i, actual) in out.iter().enumerate() {
        assert_eq!(
            *actual,
            (TcpHandshakeState::Established.to_wire(), i as u64, 1),
            "#18662: exact stage/count result for row {i}"
        );
    }
    assert_eq!(after.0 - before.0, 1, "#18662: 64k rows use one indexed call");
    assert_eq!(
        after.4 - before.4,
        ROWS as u64,
        "#18662: 64k input keys are processed exactly once"
    );
    let total_rows = (ROWS * 2) as u64;
    assert!(
        after.1 - before.1 <= total_rows * 2,
        "#18662: 64k indexed reads stay linear instead of rescanning per query"
    );
    assert!(
        after.2 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "#18662: 64k population caps rows fetched per dual-map lock hold"
    );
    assert!(
        after.3 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "#18662: 64k population caps visited lookup candidates per hold"
    );
}

#[test]
fn wire_alias_index_removal_preserves_stable_slot_18662() {
    const CHUNK: usize = 128;
    const DIRECT_LOOKUPS: usize = 2;
    const CURSOR_AFTER_FIRST_HOLD: usize = CHUNK - DIRECT_LOOKUPS;
    const ALIASES: usize = CURSOR_AFTER_FIRST_HOLD + 2;
    let (shared, _nat_map, wire_map, indexes) = maps();
    let client = v4(10, 0, 61, 102);
    let server = v4(172, 16, 80, 200);
    let forward = key(client, 20_000, server, 443, crate::ip_proto::PROTO_TCP);
    let nat = no_nat();
    let stage = TcpHandshakeState::Established.to_wire();
    let mut map_keys = Vec::with_capacity(ALIASES);
    {
        let mut wires = lock_shared_recover(&wire_map);
        for i in 0..ALIASES {
            let map_key = key(
                client,
                30_000 + i as u16,
                server,
                443,
                crate::ip_proto::PROTO_TCP,
            );
            let entry = row(&forward, nat, stage, i as u64, i as u64, false, i as u64 + 1);
            wires.insert(map_key.clone(), entry.clone());
            update_stage_counts_entry_key_index(
                &indexes.stage_counts_forward_wire_sessions,
                &map_key,
                None,
                Some(&entry),
            );
            map_keys.push(map_key);
        }
    }

    // Structural check for the stable-slot invariant: removal tombstones
    // slot 0 without shifting the slot a bounded cursor may already have
    // passed. The between-holds cells below exercise the actual cursor.
    {
        let mut wires = lock_shared_recover(&wire_map);
        let removed = wires.remove(&map_keys[0]).expect("first alias exists");
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &map_keys[0],
            Some(&removed),
            None,
        );
    }
    {
        let wire_index = lock_shared_recover(&indexes.stage_counts_forward_wire_sessions);
        let aliases = wire_index.get(&forward).expect("alias bucket remains reserved");
        assert_eq!(aliases.len(), ALIASES);
        assert!(!aliases[0].live, "removed alias leaves a stable tombstone");
        assert!(aliases[CURSOR_AFTER_FIRST_HOLD].live);
        assert_eq!(
            aliases[CURSOR_AFTER_FIRST_HOLD].map_key,
            map_keys[CURSOR_AFTER_FIRST_HOLD],
            "removing an earlier slot must not move a row behind the saved cursor"
        );
    }
    let restored = row(&forward, nat, stage, 0, 0, false, 1);
    {
        let mut wires = lock_shared_recover(&wire_map);
        wires.insert(map_keys[0].clone(), restored.clone());
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &map_keys[0],
            None,
            Some(&restored),
        );
    }
    {
        let wire_index = lock_shared_recover(&indexes.stage_counts_forward_wire_sessions);
        let aliases = wire_index.get(&forward).expect("restored bucket is reserved");
        assert_eq!(aliases.len(), ALIASES, "restamp must reuse the stable slot");
        assert!(aliases[0].live);
        assert_eq!(aliases[0].map_key, map_keys[0]);
    }

    let out = shared_rows_stage_and_counts(
        &shared,
        &wire_map,
        &indexes,
        &[(forward, nat)],
    );
    assert_eq!(
        out,
        vec![(stage, (ALIASES - 1) as u64, (ALIASES - 1) as u64)],
        "#18662: redundant aggregate check; the stable-slot positions above are the cursor proof"
    );
}


fn requested_with_passed_first_alias_18662(forward: &SessionKey) -> Vec<SessionKey> {
    let server = v4(172, 16, 80, 200);
    let mut requested = Vec::with_capacity(64);
    requested.push(forward.clone());
    requested.extend((0..63).map(|i| {
        key(
            v4(10, 0, 62, i),
            30_000 + u16::from(i),
            server,
            443,
            crate::ip_proto::PROTO_TCP,
        )
    }));
    requested
}

fn wanted_for_alias_18662(forward: &SessionKey, nat: crate::nat::NatDecision) -> StageCountsWanted {
    let mut wanted = StageCountsWanted::default();
    wanted.entry(forward.clone()).or_default().push((0, false));
    wanted
        .entry(crate::session::forward_wire_key(forward, nat))
        .or_default()
        .push((0, true));
    wanted
}

#[test]
fn alias_revived_after_passed_slot_is_picked_up_next_cycle_18662() {
    let (shared, _nat_map, wire_map, indexes) = maps();
    let forward = key(
        v4(10, 0, 61, 102),
        20_000,
        v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let nat = snat(Some(49_000));
    let stale_map_key = key(
        v4(192, 0, 2, 56),
        45_004,
        v4(198, 51, 100, 99),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let original = row(&forward, nat, 1, 1, 1, false, 6_001);
    {
        let mut wires = lock_shared_recover(&wire_map);
        wires.insert(stale_map_key.clone(), original.clone());
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &stale_map_key,
            None,
            Some(&original),
        );
        let removed = wires.remove(&stale_map_key).expect("initial alias exists");
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &stale_map_key,
            Some(&removed),
            None,
        );
    }
    let wanted = wanted_for_alias_18662(&forward, nat);
    let requested = requested_with_passed_first_alias_18662(&forward);
    let mut out = [(0, 0, 0)];
    let restored = row(
        &forward,
        nat,
        TcpHandshakeState::Established.to_wire(),
        9,
        11,
        false,
        6_002,
    );
    let mut revived = false;
    stage_and_counts_pass_with_hook(
        &shared,
        &wire_map,
        &indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut out,
        &requested,
        || {
            if revived {
                return;
            }
            revived = true;
            let mut wires = lock_shared_recover(&wire_map);
            wires.insert(stale_map_key.clone(), restored.clone());
            update_stage_counts_entry_key_index(
                &indexes.stage_counts_forward_wire_sessions,
                &stale_map_key,
                None,
                Some(&restored),
            );
        },
    );
    assert!(revived, "fixture: the pass released its first lock hold");
    assert_eq!(out, [(0, 0, 0)], "the already-passed tombstone is deferred");

    let mut next_cycle = [(0, 0, 0)];
    stage_and_counts_pass(
        &shared,
        &wire_map,
        &indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut next_cycle,
        &requested,
    );
    assert_eq!(
        next_cycle,
        [(TcpHandshakeState::Established.to_wire(), 9, 11)],
        "the next cycle starts at slot zero and sees the revived alias"
    );
}

fn assert_alias_reinsert_after_pass_18662(prune_bucket: bool) {
    let (shared, _nat_map, wire_map, indexes) = maps();
    let forward = key(
        v4(10, 0, 61, 103),
        20_001,
        v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let nat = snat(Some(49_001));
    let stale_map_key = key(
        v4(192, 0, 2, 57),
        45_005,
        v4(198, 51, 100, 99),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let original = row(&forward, nat, 1, 5, 7, false, 6_101);
    {
        let mut wires = lock_shared_recover(&wire_map);
        wires.insert(stale_map_key.clone(), original.clone());
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &stale_map_key,
            None,
            Some(&original),
        );
    }
    let wanted = wanted_for_alias_18662(&forward, nat);
    let requested = requested_with_passed_first_alias_18662(&forward);
    let mut current_cycle = [(0, 0, 0)];
    let replacement = row(
        &forward,
        nat,
        TcpHandshakeState::Established.to_wire(),
        9,
        11,
        false,
        6_102,
    );
    let mut reinserted = false;
    stage_and_counts_pass_with_hook(
        &shared,
        &wire_map,
        &indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut current_cycle,
        &requested,
        || {
            if reinserted {
                return;
            }
            reinserted = true;
            let mut wires = lock_shared_recover(&wire_map);
            let removed = wires.remove(&stale_map_key).expect("passed alias exists");
            update_stage_counts_entry_key_index(
                &indexes.stage_counts_forward_wire_sessions,
                &stale_map_key,
                Some(&removed),
                None,
            );
            if prune_bucket {
                prune_empty_stage_counts_entry_key_index(
                    &indexes.stage_counts_forward_wire_sessions,
                    &forward,
                );
            }
            wires.insert(stale_map_key.clone(), replacement.clone());
            update_stage_counts_entry_key_index(
                &indexes.stage_counts_forward_wire_sessions,
                &stale_map_key,
                None,
                Some(&replacement),
            );
        },
    );
    assert!(reinserted, "fixture: the pass released its first lock hold");
    assert_eq!(
        current_cycle,
        [(1, 5, 7)],
        "current cycle keeps the snapshot taken before removal/reinsert"
    );

    let mut next_cycle = [(0, 0, 0)];
    stage_and_counts_pass(
        &shared,
        &wire_map,
        &indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut next_cycle,
        &requested,
    );
    assert_eq!(
        next_cycle,
        [(TcpHandshakeState::Established.to_wire(), 9, 11)],
        "next cycle sees the replacement even when its bucket was pruned/recreated"
    );
}

#[test]
fn alias_remove_reinsert_at_passed_slot_is_seen_next_cycle_18662() {
    assert_alias_reinsert_after_pass_18662(false);
}

#[test]
fn alias_prune_recreate_at_passed_slot_is_seen_next_cycle_18662() {
    assert_alias_reinsert_after_pass_18662(true);
}

#[test]
fn cross_bucket_displacement_is_key_scoped_and_converges_next_cycle_18662() {
    let (shared, _nat_map, wire_map, indexes) = maps();
    let server = v4(172, 16, 80, 200);
    let old_owner = key(v4(10, 0, 61, 105), 20_003, server, 443, crate::ip_proto::PROTO_TCP);
    let new_owner = key(v4(10, 0, 61, 106), 20_004, server, 443, crate::ip_proto::PROTO_TCP);
    let nat = no_nat();
    let stale_alias_key = key(
        v4(192, 0, 2, 55),
        45_003,
        v4(198, 51, 100, 99),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    assert_ne!(stale_alias_key, old_owner);
    assert_ne!(stale_alias_key, new_owner);
    let old_row = row(&old_owner, nat, 1, 5, 7, false, 6_401);
    {
        let mut wires = lock_shared_recover(&wire_map);
        wires.insert(stale_alias_key.clone(), old_row.clone());
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &stale_alias_key,
            None,
            Some(&old_row),
        );
    }
    let replacement = row(
        &new_owner,
        nat,
        TcpHandshakeState::Established.to_wire(),
        9,
        11,
        false,
        6_402,
    );
    let mut wanted = wanted_for_alias_18662(&old_owner, nat);
    wanted.entry(new_owner.clone()).or_default().extend([(1, false), (1, true)]);
    let mut requested = requested_with_passed_first_alias_18662(&old_owner);
    requested.push(new_owner.clone());
    let mut mixed = [(0, 0, 0); 2];
    let mut displaced = false;
    stage_and_counts_pass_with_hook(
        &shared,
        &wire_map,
        &indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut mixed,
        &requested,
        || {
            if displaced {
                return;
            }
            displaced = true;
            let mut wires = lock_shared_recover(&wire_map);
            let removed = wires
                .remove(&stale_alias_key)
                .expect("the first owner alias was already visited");
            wires.insert(stale_alias_key.clone(), replacement.clone());
            update_stage_counts_entry_key_index(
                &indexes.stage_counts_forward_wire_sessions,
                &stale_alias_key,
                Some(&removed),
                Some(&replacement),
            );
        },
    );
    assert!(displaced, "fixture: the first candidate chunk completed");
    assert_eq!(
        mixed,
        [(1, 5, 7), (TcpHandshakeState::Established.to_wire(), 9, 11)],
        "the processed owner keeps pre-displacement evidence; the later owner sees its own new row"
    );

    let mut next_cycle = [(0, 0, 0); 2];
    stage_and_counts_pass(
        &shared,
        &wire_map,
        &indexes.stage_counts_forward_wire_sessions,
        &wanted,
        &mut next_cycle,
        &requested,
    );
    assert_eq!(
        next_cycle,
        [(0, 0, 0), (TcpHandshakeState::Established.to_wire(), 9, 11)],
        "the next cycle converges to the current owner without transferring old evidence"
    );
}

#[test]
fn shared_wire_key_collision_folds_many_outputs_outside_lock_hold_18662() {
    const FORWARDS: usize = 2_048;
    let (shared, _nat_map, wire_map, indexes) = maps();
    let server = v4(172, 16, 80, 200);
    let nat = snat(Some(45_000));
    let mut queries = Vec::with_capacity(FORWARDS);
    for i in 0..FORWARDS {
        let forward = key(
            v4(10, 0, (i >> 8) as u8, i as u8),
            20_000 + i as u16,
            server,
            443,
            crate::ip_proto::PROTO_TCP,
        );
        queries.push((forward, nat));
    }
    let shared_wire_key = crate::session::forward_wire_key(&queries[0].0, nat);
    assert!(
        queries
            .iter()
            .all(|(forward, nat)| crate::session::forward_wire_key(forward, *nat) == shared_wire_key),
        "fixture: all forward keys collapse to one NAT wire key"
    );
    let shared_wire_row = row(
        &shared_wire_key,
        no_nat(),
        TcpHandshakeState::Established.to_wire(),
        17,
        23,
        false,
        6_201,
    );
    lock_shared_recover(&wire_map).insert(shared_wire_key, shared_wire_row);

    let before = STAGE_COUNTS_WORK_18655.with(|work| work.get());
    let actual = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, &queries);
    let after = STAGE_COUNTS_WORK_18655.with(|work| work.get());
    assert_eq!(actual.len(), FORWARDS);
    assert!(actual.iter().all(|row| *row == (4, 17, 23)));
    assert_eq!(after.0 - before.0, 1);
    assert!(
        after.2 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "the collision's 2,048 output folds do not extend a map-lock hold"
    );
    assert!(
        after.3 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "lookup candidates and slot-fold iterations are jointly charged to each chunk"
    );
}

#[test]
fn duplicate_query_fanout_is_charged_to_bounded_work_18662() {
    const DUPLICATES: usize = 65_536;
    let (shared, _nat_map, wire_map, indexes) = maps();
    let forward = key(
        v4(10, 0, 61, 104),
        20_002,
        v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let nat = snat(Some(49_002));
    let row = row(
        &forward,
        nat,
        TcpHandshakeState::Established.to_wire(),
        17,
        23,
        false,
        6_301,
    );
    lock_shared_recover(&shared).insert(forward.clone(), row);
    let queries = vec![(forward, nat); DUPLICATES];

    let before = STAGE_COUNTS_WORK_18655.with(|work| work.get());
    let actual = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, &queries);
    let after = STAGE_COUNTS_WORK_18655.with(|work| work.get());
    assert_eq!(actual.len(), DUPLICATES);
    assert!(actual.iter().all(|row| *row == (4, 17, 23)));
    assert_eq!(after.0 - before.0, 1);
    assert!(
        after.2 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "65,536 duplicate outputs do not increase rows fetched under one lock hold"
    );
    assert!(
        after.3 <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "65,536 slot folds are split into fixed-work chunks"
    );
}

#[test]
fn packet_completion_restamp_reactivates_published_alias_slot_18662() {
    let (shared, nat_map, wire_map, indexes) = maps();
    let client = v4(10, 0, 61, 102);
    let server = v4(172, 16, 80, 200);
    let forward = key(client, 31_001, server, 443, crate::ip_proto::PROTO_TCP);
    let nat = snat(Some(49_001));
    let entry = row(
        &forward,
        nat,
        TcpHandshakeState::HandshakePending.to_wire(),
        1,
        1,
        false,
        5_001,
    );
    publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &entry);
    let wire_key = crate::session::forward_wire_key(&forward, nat);

    {
        let mut wires = lock_shared_recover(&wire_map);
        let removed = wires.remove(&wire_key).expect("published alias exists");
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &wire_key,
            Some(&removed),
            None,
        );
    }
    {
        let wire_index = lock_shared_recover(&indexes.stage_counts_forward_wire_sessions);
        let aliases = wire_index.get(&forward).expect("published slot remains reserved");
        assert_eq!(aliases.len(), 1);
        assert!(!aliases[0].live);
        assert!(!aliases.spilled());
    }

    let transitioned =
        restamp_shared_forward_wire_established(&shared, &wire_map, &indexes, &[(forward.clone(), nat)]);
    assert_eq!(transitioned, vec![(forward.clone(), nat)]);
    {
        let wire_index = lock_shared_recover(&indexes.stage_counts_forward_wire_sessions);
        let aliases = wire_index.get(&forward).expect("restamp reuses published slot");
        assert_eq!(aliases.len(), 1, "no third distinct key is appended");
        assert!(aliases[0].live);
        assert_eq!(aliases[0].map_key, wire_key);
        assert!(!aliases.spilled(), "same-key completion restamp stays inline");
    }
    let alias = lock_shared_recover(&wire_map)
        .get(&wire_key)
        .cloned()
        .expect("alias restored");
    assert_eq!(alias.key, forward);
    assert_eq!(alias.tcp_handshake_state, TcpHandshakeState::Established.to_wire());
}
#[test]
fn empty_batch_takes_no_lock_and_no_pass_18655() {
    let (shared, wire_map, indexes, _) = mixed_state();
    let before = STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let out = shared_rows_stage_and_counts(&shared, &wire_map, &indexes, &[]);
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
    let (shared_a, wire_a, _indexes_a, queries) = mixed_state();
    let (shared_b, wire_b, _indexes_b, _) = mixed_state();
    let mut rng = Lcg(55018);
    let pairs: Vec<(SessionKey, crate::nat::NatDecision, u64, u64, u64)> = queries
        .iter()
        .map(|(k, n)| {
            let fwd = if rng.pick(3) == 0 { 0 } else { rng.pick(200) };
            let rev = if rng.pick(3) == 0 { 0 } else { rng.pick(200) };
            (k.clone(), *n, fwd, rev, 0)
        })
        .collect();
    assert!(pairs.iter().any(|p| p.2 == 0 && p.3 == 0), "fixture: include zero-count pairs");
    for (k, n, f, r, last_seen_ns) in &pairs {
        restamp_shared_packet_counts(&shared_a, &wire_a, k, *n, 0, *last_seen_ns, *f, *r);
    }
    restamp_shared_packet_counts_batch(&shared_b, &wire_b, 0, &pairs);
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
    let mut wires = lock_shared_recover(&wire_map);
    let removed = wires.remove(&wire_key).expect("published alias present");
    update_stage_counts_entry_key_index(
        &indexes.stage_counts_forward_wire_sessions,
        &wire_key,
        Some(&removed),
        None,
    );
    drop(wires);
    restamp_shared_forward_wire_established(&shared, &wire_map, &indexes, &[(first.clone(), nat), (second.clone(), nat)]);
    let alias = lock_shared_recover(&wire_map).get(&wire_key).cloned().expect("alias reinserted");
    assert_eq!(alias.key, first, "#18655: the alias must clone the FIRST completed key's canonical row");
    assert_eq!(alias.session_id, 5001);
}

#[test]
fn retained_alias_fanout_resumes_with_constant_invocation_budget_18662() {
    const ALIAS_COUNTS: [usize; 4] = [1, 64, 512, 8_192];
    let server = v4(172, 16, 80, 200);
    for alias_count in ALIAS_COUNTS {
        let (shared, nat_map, wire_map, indexes) = maps();
        let forward = key(
            v4(10, 0, 61, 105),
            32_001,
            server,
            443,
            crate::ip_proto::PROTO_TCP,
        );
        let mut query_nat = snat(Some(30_000));
        for i in 0..alias_count {
            query_nat = snat(Some(30_000 + i as u16));
            let stage = if i % 3 == 0 {
                TcpHandshakeState::Established.to_wire()
            } else {
                TcpHandshakeState::HandshakePending.to_wire()
            };
            publish_shared_session(
                &shared,
                &nat_map,
                &wire_map,
                &indexes,
                &row(
                    &forward,
                    query_nat,
                    stage,
                    10 + i as u64,
                    20 + i as u64,
                    false,
                    8_000 + i as u64,
                ),
            );
        }
        let alias_count_live = lock_shared_recover(&indexes.stage_counts_forward_wire_sessions)
            .get(&forward)
            .expect("the repeated canonical row retains its alias bucket")
            .iter()
            .filter(|slot| slot.live)
            .count();
        assert_eq!(alias_count_live, alias_count);

        let requested = vec![(forward.clone(), query_nat)];
        assert_eq!(requested.len(), 1, "worker-row count stays fixed");
        let expected = {
            let holders = lock_shared_recover(&shared);
            let wires = lock_shared_recover(&wire_map);
            scan_reference(&holders, &wires, &forward, query_nat)
        };
        let mut traversal = StageCountsTraversal::new(requested.clone());
        let mut max_invocation_work = 0usize;
        let mut invocations = 0usize;
        loop {
            let (complete, _visited, max_hold, work) = traversal.advance(
                &shared,
                &wire_map,
                &indexes.stage_counts_forward_wire_sessions,
                usize::MAX,
            );
            assert!(
                work <= EXPECTED_STAGE_COUNTS_INVOCATION_BUDGET_18662,
                "A={alias_count}: lookup plus slot-fold work exceeded the independent per-invocation cap"
            );
            assert!(
                max_hold <= EXPECTED_STAGE_COUNTS_LOCK_CHUNK_18662,
                "A={alias_count}: map-lock hold exceeded the unchanged per-hold cap"
            );
            max_invocation_work = max_invocation_work.max(work);
            invocations += 1;
            assert!(invocations < 16, "A={alias_count}: traversal must finish");
            if complete {
                let (finished_keys, _identities, actual) = traversal.finish();
                assert_eq!(finished_keys, requested);
                assert_eq!(actual, vec![expected], "A={alias_count}: complete fold must match scan");
                break;
            }
        }
        if alias_count == 8_192 {
            assert!(
                invocations > 1,
                "A=8,192 exceeds one invocation and resumes instead of delaying RX"
            );
        }
        assert!(
            max_invocation_work <= EXPECTED_STAGE_COUNTS_INVOCATION_BUDGET_18662,
            "A={alias_count}: every invocation stays at the independent fixed cap"
        );
    }
}

#[test]
fn reverse_companion_distinct_session_id_still_contributes_evidence_18662() {
    let (shared, nat_map, wire_map, indexes) = maps();
    let forward = key(
        v4(10, 0, 61, 107),
        32_003,
        v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let nat = snat(Some(30_123));
    let stage = TcpHandshakeState::HandshakePending.to_wire();
    let forward_id = 41_001;
    let reverse_id = 42_002;
    publish_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &row(&forward, nat, stage, 0, 0, false, forward_id),
    );
    let reverse_key = crate::session::reverse_session_key(&forward, nat);
    publish_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &row(&reverse_key, nat, stage, 0, 9, true, reverse_id),
    );

    let mut traversal = StageCountsTraversal::new_with_identities(
        vec![(forward.clone(), nat)],
        vec![Some((forward_id, nat))],
    );
    loop {
        let (complete, _, _, _) = traversal.advance(
            &shared,
            &wire_map,
            &indexes.stage_counts_forward_wire_sessions,
            STAGE_COUNTS_INVOCATION_BUDGET_18662,
        );
        if complete {
            break;
        }
    }
    let (_, identities, counts) = traversal.finish();
    assert_eq!(identities, vec![Some((forward_id, nat))]);
    assert_eq!(
        counts,
        vec![(stage, 0, 9)],
        "a canonical reverse companion has its own session ID but still supplies reverse counts"
    );
}

#[test]
fn snat_wire_key_alias_from_old_session_does_not_vouch_for_new_output_18662() {
    let (shared, _nat_map, wire_map, indexes) = maps();
    let forward = key(
        v4(10, 0, 61, 108),
        32_004,
        v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let nat = snat(Some(30_124));
    let translated_wire_key = crate::session::forward_wire_key(&forward, nat);
    assert_ne!(translated_wire_key, forward, "fixture uses a translated wire key");
    let alias_map_key = key(
        v4(192, 0, 2, 57),
        45_005,
        v4(198, 51, 100, 100),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let stale_id = 43_003;
    let current_id = 44_004;
    let stale_alias = row(
        &translated_wire_key,
        nat,
        TcpHandshakeState::Established.to_wire(),
        0,
        17,
        false,
        stale_id,
    );
    {
        let mut wires = lock_shared_recover(&wire_map);
        wires.insert(alias_map_key.clone(), stale_alias.clone());
        update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &alias_map_key,
            None,
            Some(&stale_alias),
        );
    }

    let fold_for_owner = |owner_id| {
        let mut traversal = StageCountsTraversal::new_with_identities(
            vec![(forward.clone(), nat)],
            vec![Some((owner_id, nat))],
        );
        loop {
            let (complete, _, _, _) = traversal.advance(
                &shared,
                &wire_map,
                &indexes.stage_counts_forward_wire_sessions,
                STAGE_COUNTS_INVOCATION_BUDGET_18662,
            );
            if complete {
                break;
            }
        }
        traversal.finish().2
    };

    assert_eq!(
        fold_for_owner(current_id),
        vec![(0, 0, 0)],
        "a retained translated wire alias from an old session cannot vouch for its replacement"
    );
    assert_eq!(
        fold_for_owner(stale_id),
        vec![(TcpHandshakeState::Established.to_wire(), 0, 17)],
        "same-incarnation translated wire aliases remain eligible"
    );
}
