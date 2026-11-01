//! #18533: per-packet session-table cost of a steady-state ESTABLISHED
//! flow-cache hit — the three calls `flow_cache_hit.rs` makes for every
//! admitted cache-served packet (deferring probe, TX-admission emit,
//! stage-transition take) — for a same-worker pair and a split-worker pair
//! (authoritative pair on worker A serving the forward direction, a
//! `WorkerLocalImport` replica pair on worker B serving the reverse
//! direction, the shape #18520's relay leaves Established on both).
//!
//! The 2026-10-20 probe (`69c7c69af6`) paid one key lookup for a forward
//! hit and two for a reverse hit. #15947's rollback fold, #16042's ack
//! expectation and #16223's stamp snapshots each added per-packet lookups
//! (8 per forward data hit at the #18520 head). One cell pins the totals;
//! one cell per optional lookup proves the steady state skips it and the
//! transition that needs it still runs it. The `MEASUREMENT` cell times the
//! same workloads (`docs/log/18533.md` has the numbers).

use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::nat::NatDecision;
use crate::tcp_flags::{TCP_ACK, TCP_PSH, TCP_SYN};
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::net::{IpAddr, Ipv4Addr};

const MS: u64 = 1_000_000;
const MSS: u32 = 1448;
const START_NS: u64 = 1_000 * 1_000_000_000;
const HOT_FLOWS: u16 = 8;
const CLIENT_ISN: u32 = 0x1000_0000;
const SERVER_ISN: u32 = 0x5000_0000;
const HITS: u64 = 64;

fn flow_key(i: u16) -> SessionKey {
    SessionKey {
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61 + (i / 250) as u8, (i % 250) as u8 + 2)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 40_000u16.wrapping_add(i),
        dst_port: 5201,
        ..key_v4()
    }
}

fn snat(i: u16) -> NatDecision {
    NatDecision {
        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
        rewrite_src_port: Some(1_024 + i),
        ..NatDecision::default()
    }
}

fn reverse_metadata() -> SessionMetadata {
    let mut rev = metadata();
    rev.is_reverse = true;
    rev.ingress_zone = TEST_WAN_ZONE_ID;
    rev.egress_zone = TEST_LAN_ZONE_ID;
    rev
}

/// Install SNAT'd pair `i` from the client SYN (forward ISN seeded, as the
/// poll path does) and admit the server SYN-ACK on the slow path, leaving
/// the pair promoted and `handshake_pending` with a known #16042 expected
/// ack (`SERVER_ISN + 1`) for the forward completing ACK.
fn pending_pair(table: &mut SessionTable, i: u16, origin: SessionOrigin, now: u64) -> (SessionKey, SessionKey) {
    let fwd = flow_key(i);
    let nat = snat(i);
    let rev = reverse_session_key(&fwd, nat);
    let rev_nat = nat.reverse(fwd.src_ip, fwd.dst_ip, fwd.src_port, fwd.dst_port);
    let reverse_origin = if origin == SessionOrigin::ForwardFlow {
        SessionOrigin::ReverseFlow
    } else {
        origin
    };
    assert!(table.install_with_protocol_with_origin(
        fwd.clone(),
        SessionDecision { nat, ..decision() },
        metadata(),
        origin,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    table.seed_tcp_isn(&fwd, CLIENT_ISN, 0, TCP_SYN);
    assert!(table.install_with_protocol_with_origin(
        rev.clone(),
        SessionDecision { nat: rev_nat, ..decision() },
        reverse_metadata(),
        reverse_origin,
        now,
        PROTO_TCP,
        TCP_SYN,
    ));
    assert!(table
        .lookup_with_origin_with_ack(&rev, now + MS, TCP_SYN | TCP_ACK, 0, Some(CLIENT_ISN + 1))
        .is_some());
    table.note_tcp_seq(&rev, SERVER_ISN, CLIENT_ISN + 1, 65_535, 0, TCP_SYN | TCP_ACK, 0);
    (fwd, rev)
}

/// `pending_pair` completed by the client ACK on the slow path: both
/// halves established, not pending, not closing.
fn established_pair(table: &mut SessionTable, i: u16, origin: SessionOrigin, now: u64) -> (SessionKey, SessionKey) {
    let (fwd, rev) = pending_pair(table, i, origin, now);
    assert!(table
        .lookup_with_origin_with_ack(&fwd, now + 2 * MS, TCP_ACK, 0, Some(SERVER_ISN + 1))
        .is_some());
    for key in [&fwd, &rev] {
        let entry = table.entry_by_key(key).expect("installed half");
        assert!(
            entry.established && !entry.handshake_pending && !entry.closing,
            "fixture: {key:?} must be steady-state established"
        );
    }
    (fwd, rev)
}

/// One admitted cache-served packet, as `stage_flow_cache_hit` drives the
/// session table for a flow with no cached output-filter drop and no
/// three-color policer (round 2: `rollback_possible = false`, so no undo).
fn cached_hit_with_ack(
    table: &mut SessionTable,
    key: &SessionKey,
    now: u64,
    flags: u8,
    payload: u32,
    ack: u32,
) -> bool {
    cached_hit_with_rollback(table, key, now, flags, payload, ack, false)
}

/// `cached_hit_with_ack` for a flow whose cached replay CAN still drop the
/// packet (an output `then discard` or a policer), so the probe records its
/// rollback undo.
fn cached_hit_with_rollback(
    table: &mut SessionTable,
    key: &SessionKey,
    now: u64,
    flags: u8,
    payload: u32,
    ack: u32,
    rollback_possible: bool,
) -> bool {
    let live = table.probe_hit_deferring_state_update_with_ack_rollback(
        key,
        now,
        u64::from(payload) + 66,
        flags,
        payload,
        0,
        Some(ack),
        rollback_possible,
    );
    table.emit_probe_hit_state_update(key);
    let _ = table.take_probe_stage_transition_forward(key);
    live
}

fn data_hit(table: &mut SessionTable, key: &SessionKey, now: u64) -> bool {
    cached_hit_with_ack(table, key, now, TCP_ACK | TCP_PSH, MSS, SERVER_ISN + 1)
}

fn data_hit_droppable(table: &mut SessionTable, key: &SessionKey, now: u64) -> bool {
    cached_hit_with_rollback(table, key, now, TCP_ACK | TCP_PSH, MSS, SERVER_ISN + 1, true)
}

fn ack_hit(table: &mut SessionTable, key: &SessionKey, now: u64) -> bool {
    cached_hit_with_ack(table, key, now, TCP_ACK, 0, CLIENT_ISN + 1)
}

fn drain_all(table: &mut SessionTable) {
    while !table.drain_deltas(4096).is_empty() {}
}

/// Same-worker table, split-worker A (authoritative, serves forward) and
/// split-worker B (`WorkerLocalImport` replica, serves reverse), each
/// holding `HOT_FLOWS + background` established pairs. Every pair has
/// carried admitted traffic in the direction(s) its table serves, so the
/// node-served stamps and counters look like a loaded worker's.
fn loaded_tables(background: u16) -> (SessionTable, SessionTable, SessionTable, Vec<(SessionKey, SessionKey)>) {
    let mut same = SessionTable::new();
    let mut split_a = SessionTable::new();
    let mut split_b = SessionTable::new();
    let mut hot = Vec::new();
    let warm = START_NS + 3 * MS;
    for i in 0..(HOT_FLOWS + background) {
        let (fwd, rev) = established_pair(&mut same, i, SessionOrigin::ForwardFlow, START_NS);
        established_pair(&mut split_a, i, SessionOrigin::ForwardFlow, START_NS);
        established_pair(&mut split_b, i, SessionOrigin::WorkerLocalImport, START_NS);
        assert!(data_hit(&mut same, &fwd, warm));
        assert!(ack_hit(&mut same, &rev, warm));
        assert!(data_hit(&mut split_a, &fwd, warm));
        assert!(ack_hit(&mut split_b, &rev, warm));
        if i < HOT_FLOWS {
            hot.push((fwd, rev));
        }
    }
    for table in [&mut same, &mut split_a, &mut split_b] {
        drain_all(table);
    }
    (same, split_a, split_b, hot)
}

fn key_hashes() -> u64 {
    SESSION_KEY_HASHES_FOR_TEST.with(|count| count.get())
}

/// `SessionKey` hashes per admitted hit over `HITS` steady-state packets.
fn hashes_per_hit(
    table: &mut SessionTable,
    key: &SessionKey,
    start: u64,
    hit: fn(&mut SessionTable, &SessionKey, u64) -> bool,
) -> u64 {
    let before = key_hashes();
    for n in 0..HITS {
        assert!(hit(table, key, start + n * 10_000), "steady-state hit must stay live");
    }
    let total = key_hashes() - before;
    assert_eq!(total % HITS, 0, "every steady-state hit must cost the same: {total} over {HITS}");
    total / HITS
}

fn probe_cost_delta(table: &SessionTable, before: (u64, u64, u64)) -> (u64, u64, u64) {
    let now = table.probe_cost_counts_for_test();
    (now.0 - before.0, now.1 - before.1, now.2 - before.2)
}

/// The totals. A forward hit resolves its own record once (the 10-20
/// cost); a reverse hit resolves its own record, the forward companion it
/// charges (#2501/#2749 accounting) and writes the #16223 node-served stamp
/// (one lookup). None of the optional lookups run.
#[test]
fn established_cached_hit_session_key_hashes_18533() {
    let (mut same, mut split_a, mut split_b, hot) = loaded_tables(64);
    let (fwd, rev) = hot[0].clone();
    let t = START_NS + 10 * MS;
    let same_before = same.probe_cost_counts_for_test();
    let a_before = split_a.probe_cost_counts_for_test();
    let b_before = split_b.probe_cost_counts_for_test();
    let same_fwd = hashes_per_hit(&mut same, &fwd, t, data_hit);
    let same_rev = hashes_per_hit(&mut same, &rev, t + MS, ack_hit);
    let split_fwd = hashes_per_hit(&mut split_a, &fwd, t, data_hit);
    let split_rev = hashes_per_hit(&mut split_b, &rev, t, ack_hit);
    eprintln!(
        "#18533 SessionKey hashes per established cached hit: same-worker fwd={same_fwd} rev={same_rev}; \
         split-worker A fwd={split_fwd} B rev={split_rev}"
    );
    assert_eq!((same_fwd, split_fwd), (1, 1), "forward hit: one record lookup");
    assert_eq!(
        (same_rev, split_rev),
        (3, 3),
        "reverse hit: own record + charged forward companion + stamp write"
    );
    for (label, table, before) in [
        ("same", &same, same_before),
        ("split A", &split_a, a_before),
        ("split B", &split_b, b_before),
    ] {
        assert_eq!(
            probe_cost_delta(table, before),
            (0, 0, 0),
            "{label}: steady state must take no expected-ack, undo-capture or emit-resolve lookup"
        );
        assert_eq!(table.pending_probe_undo_len_for_test(), 0, "{label}: admitted hits leave no undo");
    }
}

/// #16042 expected ack: resolved only for a classic completion candidate.
/// Steady state never; a pending pair's completing segment once per probe,
/// and a known-but-wrong ack still refuses the classic completion.
#[test]
fn expected_ack_lookup_runs_only_for_a_pending_completion_candidate_18533() {
    let mut table = SessionTable::new();
    let (est_fwd, est_rev) = established_pair(&mut table, 1, SessionOrigin::ForwardFlow, START_NS);
    let (fwd, _rev) = pending_pair(&mut table, 2, SessionOrigin::ForwardFlow, START_NS);
    assert_eq!(table.handshake_expected_ack(&fwd), Some(SERVER_ISN + 1), "premise");
    drain_all(&mut table);
    let t = START_NS + 3 * MS;
    let before = table.probe_cost_counts_for_test();
    assert!(data_hit(&mut table, &est_fwd, t));
    assert!(ack_hit(&mut table, &est_rev, t));
    assert_eq!(probe_cost_delta(&table, before).0, 0, "established hits must not resolve the expected ack");
    // Pending pair, bare ACK (no payload, so the #16223 companion arm
    // cannot complete it) with a wrong ack: resolved, and refused.
    let before = table.probe_cost_counts_for_test();
    assert!(cached_hit_with_ack(&mut table, &fwd, t, TCP_ACK, 0, SERVER_ISN + 7));
    assert_eq!(probe_cost_delta(&table, before).0, 1, "a completion candidate resolves the expected ack");
    assert_eq!(
        table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::HandshakePending.to_wire(),
        "#16042: a wrong-ack completing segment must not complete the pair"
    );
    assert!(cached_hit_with_ack(&mut table, &fwd, t + MS, TCP_ACK, 0, SERVER_ISN + 1));
    assert_eq!(probe_cost_delta(&table, before).0, 2);
    assert_eq!(
        table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::Established.to_wire(),
        "the expected ack completes the pair"
    );
}

/// Completion undo (companion record + pressure-shed membership): looked
/// up only on the completing packet, and a dropped completion still
/// restores both halves and the shed membership.
#[test]
fn completion_undo_capture_runs_only_on_the_completing_hit_18533() {
    let mut table = SessionTable::new();
    let (est_fwd, est_rev) = established_pair(&mut table, 1, SessionOrigin::ForwardFlow, START_NS);
    let (fwd, rev) = pending_pair(&mut table, 2, SessionOrigin::ForwardFlow, START_NS);
    drain_all(&mut table);
    let t = START_NS + 3 * MS;
    let before = table.probe_cost_counts_for_test();
    assert!(data_hit(&mut table, &est_fwd, t));
    assert!(ack_hit(&mut table, &est_rev, t));
    assert_eq!(probe_cost_delta(&table, before).1, 0, "steady state takes no undo-capture lookup");
    let shed_before = table.pressure_shed_unreplied.contains_key(&fwd);
    assert!(shed_before, "premise: a pending pair is pressure-sheddable");
    let fwd_before = table.entry_by_key(&fwd).map(ProbeHalfUndo::of).expect("forward");
    let rev_before = table.entry_by_key(&rev).map(ProbeHalfUndo::of).expect("reverse");
    let before = table.probe_cost_counts_for_test();
    assert!(table.probe_hit_deferring_state_update_with_ack(&fwd, t, 66, TCP_ACK, 0, 0, Some(SERVER_ISN + 1)));
    assert_eq!(probe_cost_delta(&table, before).1, 2, "the completing hit captures companion + shed");
    assert!(!table.pressure_shed_unreplied.contains_key(&fwd), "premise: completion left the shed index");
    assert!(table.rollback_dropped_probe_hit(&fwd, 66, TCP_ACK));
    let fwd_after = table.entry_by_key(&fwd).map(ProbeHalfUndo::of).expect("forward");
    let rev_after = table.entry_by_key(&rev).map(ProbeHalfUndo::of).expect("reverse");
    for (label, b, a) in [("forward", fwd_before, fwd_after), ("reverse", rev_before, rev_after)] {
        assert_eq!(
            (a.counters, a.established, a.handshake_pending, a.syn_ack_first, a.expires_after_ns),
            (b.counters, b.established, b.handshake_pending, b.syn_ack_first, b.expires_after_ns),
            "{label} half must be restored by the dropped completion's rollback"
        );
    }
    assert!(table.pressure_shed_unreplied.contains_key(&fwd), "shed membership must be restored");
}

/// Reverse fold: the charged forward companion and the stamp write are
/// captured from their own borrow/lookup, and a dropped reverse hit
/// restores both exactly — an existing stamp to its prior value, a stamp
/// the probe created removed.
#[test]
fn dropped_reverse_hit_restores_forward_charge_and_stamp_18533() {
    let mut table = SessionTable::new();
    let (fwd, rev) = established_pair(&mut table, 1, SessionOrigin::ForwardFlow, START_NS);
    drain_all(&mut table);
    let t = START_NS + 3 * MS;
    // First reverse traffic on a row with no stamp yet (the slow-path
    // completion above stamped one; a replica table's pair has none until
    // its first served reverse packet): the probe CREATES the stamp, and a
    // drop removes it.
    table.node_served_stamps.remove(&fwd);
    let counters_before = table.session_counters(&fwd).expect("forward counters");
    assert!(table.probe_hit_deferring_state_update_with_ack(&rev, t, 66, TCP_ACK, 0, 0, Some(CLIENT_ISN + 1)));
    assert_eq!(table.session_counters(&fwd).map(|c| c.rev_packets), Some(counters_before.rev_packets + 1));
    assert!(table.node_served_stamps.get(&fwd).is_some(), "premise: the reverse fold stamped");
    table.rollback_dropped_probe_hit(&rev, 66, TCP_ACK);
    assert_eq!(table.session_counters(&fwd), Some(counters_before), "dropped reverse hit must not charge the forward entry");
    assert_eq!(table.node_served_stamps.get(&fwd), None, "a stamp the dropped probe created must be removed");
    // Admitted reverse traffic, then a dropped one: the stamp returns to
    // its prior value, not merely to "present".
    assert!(ack_hit(&mut table, &rev, t + MS));
    assert!(ack_hit(&mut table, &rev, t + 2 * MS));
    let stamp_before = table.node_served_stamps.get(&fwd).copied();
    assert_eq!(stamp_before.map(|s| s.1), Some(2), "premise: two admitted reverse packets stamped");
    let counters_before = table.session_counters(&fwd).expect("forward counters");
    assert!(table.probe_hit_deferring_state_update_with_ack(&rev, t + 3 * MS, 66, TCP_ACK, 0, 0, Some(CLIENT_ISN + 1)));
    assert_eq!(table.node_served_stamps.get(&fwd).map(|s| s.1), Some(3), "premise: the probe advanced the stamp");
    table.rollback_dropped_probe_hit(&rev, 66, TCP_ACK);
    assert_eq!(table.session_counters(&fwd), Some(counters_before), "forward charge restored");
    assert_eq!(table.node_served_stamps.get(&fwd).copied(), stamp_before, "stamp restored to its exact prior value");
}

/// Admission emit: no canonical resolution in the steady state; an alias
/// packet key still resolves, and consumes its canonical undo.
#[test]
fn emit_resolves_the_canonical_key_only_off_the_steady_state_18533() {
    let mut table = SessionTable::new();
    let (fwd_a, rev_a) = established_pair(&mut table, 1, SessionOrigin::ForwardFlow, START_NS);
    drain_all(&mut table);
    let t = START_NS + 3 * MS;
    let before = table.probe_cost_counts_for_test();
    assert!(data_hit(&mut table, &fwd_a, t));
    assert!(ack_hit(&mut table, &rev_a, t));
    assert_eq!(probe_cost_delta(&table, before).2, 0, "steady-state admission must not resolve");
    assert_eq!(table.pending_probe_undo_len_for_test(), 0);
    // Alias packet key (the translated reverse tuple): resolves, consumes.
    let rev_nat = table.entry_by_key(&rev_a).map(|e| e.decision.nat).expect("reverse");
    let alias = translated_session_key(&rev_a, rev_nat);
    assert_ne!(alias, rev_a, "premise: the alias differs from the stored reverse key");
    let before = table.probe_cost_counts_for_test();
    assert!(table.probe_hit_deferring_state_update_with_ack(&alias, t + MS, 66, TCP_ACK, 0, 0, Some(CLIENT_ISN + 1)));
    assert_eq!(table.pending_probe_undo_len_for_test(), 1, "premise: the alias probe recorded its undo");
    table.emit_probe_hit_state_update(&alias);
    assert_eq!(probe_cost_delta(&table, before).2, 1, "an alias admission resolves its canonical key");
    assert_eq!(table.pending_probe_undo_len_for_test(), 0, "the alias admission consumes the canonical undo");
}

/// Admission emit, behavioural half: flow A probed (not yet admitted or
/// dropped), flow B admitted. B's admission must take the resolving path
/// and leave A's undo for A's own rollback, which still un-charges A.
#[test]
fn another_flows_admission_keeps_this_flows_undo_18533() {
    let mut table = SessionTable::new();
    let (fwd_a, _rev_a) = established_pair(&mut table, 1, SessionOrigin::ForwardFlow, START_NS);
    let (fwd_b, _rev_b) = established_pair(&mut table, 2, SessionOrigin::ForwardFlow, START_NS);
    drain_all(&mut table);
    let t = START_NS + 3 * MS;
    let a_before = table.session_counters(&fwd_a).expect("A counters");
    assert!(table.probe_hit_deferring_state_update_with_ack(&fwd_a, t + 2 * MS, 1514, TCP_ACK | TCP_PSH, MSS, 0, Some(SERVER_ISN + 1)));
    let before = table.probe_cost_counts_for_test();
    table.emit_probe_hit_state_update(&fwd_b);
    assert_eq!(table.pending_probe_undo_len_for_test(), 1, "flow A's undo must survive flow B's admission");
    table.rollback_dropped_probe_hit(&fwd_a, 1514, TCP_ACK | TCP_PSH);
    assert_eq!(table.session_counters(&fwd_a), Some(a_before), "flow A's dropped packet is un-charged");
    // Checked last so a regression in the behaviour above is reported first.
    assert_eq!(probe_cost_delta(&table, before).2, 1, "another flow's admission resolves");
}

/// MEASUREMENT: ns per admitted established cache hit (probe + emit +
/// take) on loaded tables, round-robin over `HOT_FLOWS` flows. Run with
/// `cargo test --release --bin xpf-userspace-dp -- --ignored --nocapture
/// established_cached_hit_probe_ns_18533`. Test builds carry the
/// `#[cfg(test)]` instruments (a thread-local add per key hash, a relaxed
/// atomic add per primary resolve), so absolute numbers run high and
/// scale with the lookup count being removed.
#[test]
#[ignore = "MEASUREMENT: #18533 per-probe ns on the established cache-hit path; prints, asserts nothing about time"]
fn established_cached_hit_probe_ns_18533() {
    const BACKGROUND: u16 = 4096;
    const ROUNDS: u64 = 250_000;
    const REPS: usize = 7;
    let (mut same, mut split_a, mut split_b, hot) = loaded_tables(BACKGROUND);
    let mut now = START_NS + 10 * MS;
    let mut run = |label: &str, table: &mut SessionTable, reverse: bool| {
        let mut samples = Vec::with_capacity(REPS);
        for _ in 0..REPS {
            let started = std::time::Instant::now();
            for _ in 0..ROUNDS {
                for (fwd, rev) in &hot {
                    now += 1_000;
                    let live = if reverse {
                        ack_hit(table, rev, now)
                    } else {
                        data_hit(table, fwd, now)
                    };
                    std::hint::black_box(live);
                }
            }
            let probes = ROUNDS * hot.len() as u64;
            samples.push(started.elapsed().as_nanos() as f64 / probes as f64);
        }
        samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        eprintln!(
            "#18533 {label}: min {:.1} ns/probe, median {:.1} ns/probe ({REPS} reps x {} probes)",
            samples[0],
            samples[REPS / 2],
            ROUNDS * hot.len() as u64
        );
    };
    run("same-worker forward data", &mut same, false);
    run("same-worker reverse ack", &mut same, true);
    run("split-worker A forward data", &mut split_a, false);
    run("split-worker B reverse ack", &mut split_b, true);
    // Round 2: the same forward hit when the cached replay can still drop it
    // (output filter or policer configured), which records the undo.
    let mut samples = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            for (fwd, _) in &hot {
                now += 1_000;
                std::hint::black_box(data_hit_droppable(&mut split_a, fwd, now));
            }
        }
        samples.push(started.elapsed().as_nanos() as f64 / (ROUNDS * hot.len() as u64) as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    eprintln!(
        "#18533 split-worker A forward data, rollback possible (undo recorded): min {:.1} ns/probe, median {:.1} ns/probe",
        samples[0],
        samples[REPS / 2]
    );
    // Decomposition, not a production shape: the same forward hit through
    // the NON-deferring probe, which records no rollback undo. The gap to
    // "split-worker A forward data" is what the #15947 undo record costs.
    let mut samples = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let started = std::time::Instant::now();
        for _ in 0..ROUNDS {
            for (fwd, _) in &hot {
                now += 1_000;
                let live = split_a.probe_hit_with_ack(fwd, now, 1514, TCP_ACK | TCP_PSH, MSS, 0, Some(SERVER_ISN + 1));
                split_a.emit_probe_hit_state_update(fwd);
                let _ = split_a.take_probe_stage_transition_forward(fwd);
                std::hint::black_box(live);
            }
        }
        samples.push(started.elapsed().as_nanos() as f64 / (ROUNDS * hot.len() as u64) as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    eprintln!(
        "#18533 split-worker A forward data, non-deferring probe (no undo; decomposition floor): min {:.1} ns/probe, median {:.1} ns/probe",
        samples[0],
        samples[REPS / 2]
    );
}

/// Round 2: the deferring probe records its rollback undo only when the
/// caller can still drop the packet. Without it a steady-state hit builds no
/// record (and costs the same single lookup); with it the undo is recorded and
/// a dropped packet is un-charged exactly as before.
#[test]
fn undo_is_recorded_only_when_a_drop_is_still_possible_18533() {
    let mut table = SessionTable::new();
    let (fwd, _rev) = established_pair(&mut table, 1, SessionOrigin::ForwardFlow, START_NS);
    drain_all(&mut table);
    let t = START_NS + 3 * MS;
    let records = table.probe_undo_records_for_test();
    let hashes = key_hashes();
    assert!(table.probe_hit_deferring_state_update_with_ack_rollback(&fwd, t, 1514, TCP_ACK | TCP_PSH, MSS, 0, Some(SERVER_ISN + 1), false));
    assert_eq!(key_hashes() - hashes, 1, "still one record lookup");
    assert_eq!(table.probe_undo_records_for_test() - records, 0, "no drop possible: no undo built");
    assert_eq!(table.pending_probe_undo_len_for_test(), 0);
    table.emit_probe_hit_state_update(&fwd);
    // Transition: a droppable packet records its undo and is un-charged.
    let before = table.session_counters(&fwd).expect("counters");
    assert!(table.probe_hit_deferring_state_update_with_ack_rollback(&fwd, t + MS, 1514, TCP_ACK | TCP_PSH, MSS, 0, Some(SERVER_ISN + 1), true));
    assert_eq!(table.probe_undo_records_for_test() - records, 1, "a possible drop builds the undo");
    table.rollback_dropped_probe_hit(&fwd, 1514, TCP_ACK | TCP_PSH);
    assert_eq!(table.session_counters(&fwd), Some(before), "the dropped packet is un-charged");
}

/// Round 2: a completion through a probe that recorded no undo still queues
/// its HA Update and stage marker under the CANONICAL key — the admission key
/// is resolved on the completing packet instead of read from the undo — so an
/// admission through the translated alias publishes it exactly once.
#[test]
fn completion_without_an_undo_publishes_under_its_canonical_key_18533() {
    let mut table = SessionTable::new();
    let now = START_NS;
    let fwd = flow_key(3);
    let nat = snat(3);
    // SYN-ACK-first: both halves install from SYN|ACK, pending, and the
    // completing segment is the reverse ACK (classic arm, reverse half).
    assert!(table.install_with_protocol(
        fwd.clone(),
        SessionDecision { nat, ..decision() },
        metadata(),
        now,
        PROTO_TCP,
        TCP_SYN | TCP_ACK,
    ));
    let rev = reverse_session_key(&fwd, nat);
    let rev_nat = nat.reverse(fwd.src_ip, fwd.dst_ip, fwd.src_port, fwd.dst_port);
    assert!(table.install_with_protocol(
        rev.clone(),
        SessionDecision { nat: rev_nat, ..decision() },
        reverse_metadata(),
        now,
        PROTO_TCP,
        TCP_SYN | TCP_ACK,
    ));
    drain_all(&mut table);
    let alias = translated_session_key(&rev, rev_nat);
    assert_ne!(alias, rev, "premise: the alias differs from the stored reverse key");
    assert!(table.probe_hit_deferring_state_update_with_ack_rollback(&alias, now + MS, 66, TCP_ACK, 0, 0, None, false));
    assert_eq!(table.pending_probe_undo_len_for_test(), 0, "no undo was recorded");
    assert_eq!(
        table.handshake_state_wire_for(&fwd),
        TcpHandshakeState::Established.to_wire(),
        "premise: the alias ACK completed the pair"
    );
    table.emit_probe_hit_state_update(&alias);
    let updates = table
        .drain_deltas(16)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .count();
    assert_eq!(updates, 1, "the alias admission publishes the canonical Update once");
    assert!(
        table.take_probe_stage_transition_forward(&alias).is_some(),
        "the stage marker is keyed so the alias admission takes it"
    );
}
