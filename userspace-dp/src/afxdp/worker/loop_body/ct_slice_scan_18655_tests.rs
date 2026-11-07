//! #18655: the production `run_ct_slice` must read the shared
//! `(stage, fwd, rev)` for its whole emit set in ONE pass over the shared
//! maps. It must also dedup its pair lists in O(1) per pair, with the
//! answer `Vec::contains` gave.
//!
//! Before the fix, the emit leg called a per-key helper that scanned both
//! whole shared maps under both global mutexes for every key. That was one
//! pass per emit key, `keys × rows` visits per slice. These cells drive the
//! real slice. They turn RED on a revert to per-key reads (passes == keys),
//! on a revert to the old helper (no pass counted at all), and on a
//! misaligned zip of keys to results (Updates for the wrong rows).

use super::{CtSlicePairSet, run_ct_slice};
use super::*;
use crate::afxdp::shared_ops::stage_counts_18655_tests as fx;
use crate::session::{SessionDeltaKind, SessionInstall, SessionOrigin, TcpHandshakeState};

const ROWS_18655: usize = 12;

/// Worker table: serving forward rows (`WorkerLocalImport`, locally
/// Established), so every row is collected. Shared maps: the same rows
/// published, half with shared `rev > 0` and half with `rev == 0`.
fn slice_fixture_18655(rows: usize) -> (
    crate::session::SessionTable,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    SharedSessionOwnerRgIndexes,
    Vec<SessionKey>,
) {
    let established = TcpHandshakeState::Established.to_wire();
    let mut sessions = crate::session::SessionTable::new();
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let nat_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let wire_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let server = fx::v4(172, 16, 80, 200);
    let mut announced = Vec::new();
    for i in 0..rows {
        let client = fx::v4(10, 0, (i >> 8) as u8, i as u8);
        let forward = fx::key(
            client,
            21000 + (i % 40000) as u16,
            server,
            5201,
            crate::ip_proto::PROTO_TCP,
        );
        let nat = fx::snat(Some(42000u16.wrapping_add(i as u16)));
        let shared_rev = if i % 2 == 0 { 3 } else { 0 };
        let e = fx::row(&forward, nat, established, 5, shared_rev, false, 7000 + i as u64);
        assert!(
            sessions.upsert_synced_with_origin(
                SessionInstall {
                    key: forward.clone(),
                    decision: e.decision,
                    metadata: e.metadata.clone(),
                    source_nat_static: None,
                    origin: SessionOrigin::WorkerLocalImport,
                    now_ns: 1_000_000_000,
                    protocol: crate::ip_proto::PROTO_TCP,
                    tcp_flags: 0,
                    session_id: e.session_id,
                    tcp_close_class: 0,
                    tcp_handshake_state: established,
                    persistent_lease_hold: None,
                    fwd_packets: 0,
                    rev_packets: 0,
                },
                false,
            ),
            "fixture: install row {i}"
        );
        crate::afxdp::shared_ops::publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &e);
        if shared_rev > 0 {
            announced.push(forward);
        }
    }
    for i in 0..30u16 {
        let other = fx::key(fx::v4(10, 0, 62, 50), 33000 + i, server, 80, crate::ip_proto::PROTO_UDP);
        let e = fx::row(&other, fx::snat(Some(43000 + i)), 1, 1, 0, false, 9000 + u64::from(i));
        crate::afxdp::shared_ops::publish_shared_session(&shared, &nat_map, &wire_map, &indexes, &e);
    }
    let _ = sessions.drain_deltas(4096);
    (sessions, shared, wire_map, indexes, announced)
}

/// One production slice at `now_ns`. The BPF fds are -1, so the conntrack
fn run_slice_18655(
    sessions: &mut crate::session::SessionTable,
    shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_map: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    indexes: &SharedSessionOwnerRgIndexes,
    clocks: &mut (usize, u64, u64, u64, usize),
    now_ns: u64,
) {
    let mut forwarding = Arc::new(ForwardingState::default());
    let shared_fabrics = Arc::new(ArcSwap::from_pointee(Vec::<FabricLink>::new()));
    let wg_queues = Arc::new(ArcSwap::from_pointee(std::collections::BTreeMap::new()));
    let mut wg_batch = crate::afxdp::wg_uncovered_forward::WgUncoveredInjectedBatch::new();
    let (cursor, cycle_start, last_slice, high_water, est_cursor) = clocks;
    run_ct_slice(
        sessions,
        &mut forwarding,
        now_ns,
        -1,
        -1,
        cursor,
        cycle_start,
        last_slice,
        high_water,
        &shared_fabrics,
        &wg_queues,
        &mut wg_batch,
        0,
        shared,
        wire_map,
        indexes,
        est_cursor,
    );
}

fn shared_rows(
    shared: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_map: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
) -> u64 {
    (crate::afxdp::shared_ops::lock_shared_recover(shared).len()
        + crate::afxdp::shared_ops::lock_shared_recover(wire_map).len()) as u64
}

#[test]
fn ct_slice_reads_shared_stage_in_one_bounded_chunk_18662() {
    let (mut sessions, shared, wire_map, indexes, announced) =
        slice_fixture_18655(ROWS_18655);
    let mut clocks = (0usize, 0u64, 0u64, 0u64, 0usize);
    let work = || crate::afxdp::shared_ops::STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let before = work();
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        20_000_000_000,
    );
    let after = work();
    assert_eq!(after.0 - before.0, 1, "#18662: one chunked stage/count call");
    assert_eq!(
        after.1 - before.1,
        (ROWS_18655 * 2) as u64,
        "#18662: only the matching canonical and wire-alias rows are fetched"
    );
    assert_eq!(
        after.4 - before.4,
        ROWS_18655 as u64,
        "#18662: the worker leg requested exactly its current chunk"
    );
    assert!(
        after.2 <= crate::afxdp::shared_ops::STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "#18662: rows in a dual-map lock hold exceed the fixed stage chunk"
    );
    // The batch results land on the right keys: Updates are queued for
    // exactly the rows whose shared row carries rev > 0.
    let mut updated: Vec<SessionKey> = sessions
        .drain_deltas(4096)
        .into_iter()
        .filter(|d| d.kind == SessionDeltaKind::Update)
        .map(|d| d.key)
        .collect();
    let mut want = announced.clone();
    let order = |a: &SessionKey, b: &SessionKey| a.src_port.cmp(&b.src_port);
    updated.sort_by(order);
    want.sort_by(order);
    assert_eq!(updated, want, "#18655: Updates must follow each key's OWN shared row");
    // A pass that is not due does not read the shared maps at all.
    let quiet = work();
    run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, 20_050_000_000);
    assert_eq!(work(), quiet, "#18655: an off-cadence tick must not read the shared maps");
}

#[test]
fn pair_set_dedup_matches_vec_contains_18655() {
    let client = fx::v4(10, 0, 61, 102);
    let server = fx::v4(172, 16, 80, 200);
    let mk = |port: u16, nat_port: Option<u16>| {
        (
            fx::key(client, port, server, 443, crate::ip_proto::PROTO_TCP),
            match nat_port {
                Some(p) => fx::snat(Some(p)),
                None => crate::nat::NatDecision::default(),
            },
        )
    };
    // Duplicates, the same key under two NATs, and a seed that itself
    // repeats a pair.
    let seed = vec![mk(1, None), mk(2, Some(9)), mk(1, None)];
    let incoming = vec![
        mk(2, Some(9)),
        mk(2, Some(8)),
        mk(3, None),
        mk(1, None),
        mk(3, None),
        mk(4, Some(7)),
        mk(2, Some(8)),
    ];
    let mut by_vec = seed.clone();
    for pair in &incoming {
        if !by_vec.contains(pair) {
            by_vec.push(pair.clone());
        }
    }
    let mut by_set = seed.clone();
    let mut seen = CtSlicePairSet::seeded(&by_set);
    for pair in &incoming {
        if seen.insert(pair) {
            by_set.push(pair.clone());
        }
    }
    assert_eq!(by_set, by_vec, "#18655: set dedup must keep Vec::contains order and content");
    assert_eq!(by_set.len(), 6, "fixture: 3 seed + 3 new pairs (incl. same key, other NAT)");
}

/// #18662: the worker-table cursor advances by one fixed chunk per ct-slice,
/// including when the BPF cursor reaches the table end first. This pins
/// bounded worker visits and progress across cycle slices.
#[test]
fn ct_slice_shared_evidence_cursor_advances_in_bounded_chunks_18662() {
    const CHUNK: usize = 2048;
    const ROWS: usize = 3 * CHUNK + 1;
    let (mut sessions, shared, wire_map, indexes, _announced) = slice_fixture_18655(ROWS);
    let mut clocks = (0usize, 0u64, 0u64, 0u64, 0usize);
    let work = || crate::afxdp::shared_ops::STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let before = work();
    let start = 20_000_000_000u64;
    let mut now = start;
    run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, now);
    assert_ne!(clocks.0, 0, "fixture: the BPF cycle needs multiple slices");
    assert_eq!(clocks.4, CHUNK, "#18662: worker leg visits at most 2048 rows on first slice");
    let mut slices = 1;
    while clocks.0 != 0 || clocks.4 != 0 {
        now += 100_000_000;
        run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, now);
        slices += 1;
        assert!(clocks.4 == 0 || clocks.4 % CHUNK == 0);
        assert!(slices < 64, "fixture: the evidence cursor never completed");
    }
    let after = work();
    assert_eq!(
        after.0 - before.0,
        4,
        "#18662: 3*chunk+1 worker rows require four fixed chunks (slices={slices})"
    );
    assert_eq!(
        after.4 - before.4,
        ROWS as u64,
        "#18662: the worker cursor requested every row exactly once"
    );
    assert!(
        after.2 <= crate::afxdp::shared_ops::STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "#18662: fetched shared rows per lock hold stay within stage chunk"
    );
    assert!(
        after.3 <= crate::afxdp::shared_ops::STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "#18662: lookup candidates per lock hold stay within stage chunk"
    );
    // Between cycles nothing runs.
    now += 100_000_000;
    run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, now);
    assert_eq!(work().0, after.0, "#18662: no leg between cycles");
    // The next cycle starts a fresh worker cursor.
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        start + 10_000_000_000,
    );
    assert_eq!(work().0 - after.0, 1, "#18662: the next cycle starts a bounded chunk");
    assert_eq!(clocks.4, super::super::slice_pacing::CT_EVIDENCE_CHUNK);
}
