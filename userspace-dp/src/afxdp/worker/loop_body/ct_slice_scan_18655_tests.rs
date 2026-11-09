//! #18655: the production `run_ct_slice` must read shared `(stage, fwd, rev)`
//! for its emit set through bounded, resumable indexed lookups, releasing the
//! maps between chunks and preserving the answer `Vec::contains` gave.
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
    stage_counts_pending: &mut Option<PendingStageCountsEmission>,
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
        stage_counts_pending,
    );
}


#[test]
fn ct_slice_reads_shared_stage_in_one_bounded_chunk_18662() {
    let (mut sessions, shared, wire_map, indexes, announced) =
        slice_fixture_18655(ROWS_18655);
    let mut clocks = (0usize, 0u64, 0u64, 0u64, 0usize);
    let mut pending = None;
    let work = || crate::afxdp::shared_ops::STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let before = work();
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        &mut pending,
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
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        &mut pending,
        20_050_000_000,
    );
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
    let mut pending = None;
    let work = || crate::afxdp::shared_ops::STAGE_COUNTS_WORK_18655.with(|w| w.get());
    let before = work();
    let start = 20_000_000_000u64;
    let mut now = start;
    run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, &mut pending, now);
    assert_ne!(clocks.0, 0, "fixture: the BPF cycle needs multiple slices");
    assert_eq!(clocks.4, 0, "#18662: worker cursor waits for complete stage/count results");
    assert!(pending.is_some(), "#18662: unfinished stage/count traversal persists");
    let mut slices = 1;
    while clocks.0 != 0 || clocks.4 != 0 || pending.is_some() {
        now += 100_000_000;
        run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, &mut pending, now);
        slices += 1;
        assert!(clocks.4 == 0 || clocks.4 % CHUNK == 0);
        assert!(slices < 128, "fixture: the evidence cursor never completed");
    }
    let after = work();
    assert!(
        after.0 - before.0 >= 4,
        "#18662: each of four worker chunks needs stage/count traversal work (slices={slices})"
    );
    assert_eq!(
        after.4 - before.4,
        ROWS as u64,
        "#18662: the worker cursor requested every row exactly once"
    );
    assert!(
        after.3 <= fx::EXPECTED_STAGE_COUNTS_INVOCATION_BUDGET_18662 as u64,
        "#18662: total stage/count work per invocation stays within independent bound"
    );
    assert!(
        after.2 <= crate::afxdp::shared_ops::STAGE_COUNTS_LOCK_CHUNK_18662 as u64,
        "#18662: fetched shared rows per lock hold stay within stage chunk"
    );
    // Between cycles nothing runs.
    now += 100_000_000;
    run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, &mut pending, now);
    assert_eq!(work().0, after.0, "#18662: no leg between cycles");
    // The next cycle starts a fresh worker cursor and carries its unfinished
    // stage/count output over later cadence invocations.
    let next_cycle_before = work();
    now = start + 10_000_000_000;
    run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, &mut pending, now);
    assert!(pending.is_some(), "#18662: large emit sets resume across worker calls");
    let mut next_cycle_slices = 1;
    while pending.is_some() {
        now += 100_000_000;
        run_slice_18655(&mut sessions, &shared, &wire_map, &indexes, &mut clocks, &mut pending, now);
        next_cycle_slices += 1;
        assert!(next_cycle_slices < 64);
    }
    assert!(work().0 - next_cycle_before.0 > 1, "the traversal resumes on later slices");
    assert_eq!(
        work().4 - next_cycle_before.4,
        CHUNK as u64,
        "the worker chunk is requested once, not once per traversal resume"
    );
    assert_eq!(clocks.4, super::super::slice_pacing::CT_EVIDENCE_CHUNK);
}

/// #18662: shared pending-row evidence is gathered under one lock pair per
/// bounded worker chunk, not one pair for every row.
#[test]
fn ct_slice_batches_pending_shared_evidence_lock_pair_18662() {
    const PENDING: usize = 2048;
    let mut sessions = crate::session::SessionTable::new();
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let wire_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let server = fx::v4(172, 16, 80, 200);
    for i in 0..PENDING {
        let forward = fx::key(
            fx::v4(10, 0, (i >> 8) as u8, i as u8),
            21_000 + i as u16,
            server,
            5201,
            crate::ip_proto::PROTO_TCP,
        );
        let nat = fx::snat(Some(45_000 + i as u16));
        let entry = fx::row(
            &forward,
            nat,
            TcpHandshakeState::HandshakePending.to_wire(),
            1,
            1,
            false,
            20_000 + i as u64,
        );
        assert!(sessions.upsert_synced_with_origin(
            SessionInstall {
                key: forward.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
                source_nat_static: None,
                origin: SessionOrigin::WorkerLocalImport,
                now_ns: 1_000_000_000,
                protocol: crate::ip_proto::PROTO_TCP,
                tcp_flags: 0,
                session_id: entry.session_id,
                tcp_close_class: 0,
                tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
                persistent_lease_hold: None,
                fwd_packets: 0,
                rev_packets: 0,
            },
            false,
        ));
        crate::afxdp::shared_ops::lock_shared_recover(&shared)
            .insert(forward, entry);
    }
    // A row just beyond the first 2,048-slot chunk keeps the next cursor
    // nonzero, so this test can prove it is committed only after stage output.
    let spare_key = fx::key(
        fx::v4(10, 0, 63, 255),
        50_001,
        server,
        5201,
        crate::ip_proto::PROTO_TCP,
    );
    let spare = fx::row(
        &spare_key,
        fx::snat(Some(49_001)),
        TcpHandshakeState::Established.to_wire(),
        0,
        0,
        false,
        40_000,
    );
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: spare_key,
            decision: spare.decision,
            metadata: spare.metadata.clone(),
            source_nat_static: None,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: 1_000_000_000,
            protocol: crate::ip_proto::PROTO_TCP,
            tcp_flags: 0,
            session_id: spare.session_id,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::Established.to_wire(),
            persistent_lease_hold: None,
            fwd_packets: 0,
            rev_packets: 0,
        },
        false,
    ));
    let _ = sessions.drain_deltas(PENDING + 1);
    let before = crate::afxdp::shared_ops::SHARED_COMPLETION_EVIDENCE_BATCH_LOCK_PAIRS_18662
        .with(|count| {
            let before = count.get();
            count.set(0);
            before
        });
    let pending_before =
        crate::afxdp::shared_ops::SHARED_COMPLETION_EVIDENCE_BATCH_PENDING_ROWS_18662
            .with(|count| {
                let before = count.get();
                count.set(0);
                before
            });
    let mut cursor = 0usize;
    let mut stage_counts_pending = None;
    run_shared_evidence_leg(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut cursor,
        &mut stage_counts_pending,
    );
    assert!(
        stage_counts_pending.is_some(),
        "#18662: positive 2,048-row stage/count output resumes after its budget"
    );
    assert!(
        sessions.drain_deltas(PENDING + 1).is_empty(),
        "#18662: the first partial fold does not emit incomplete rows"
    );
    {
        let rows = crate::afxdp::shared_ops::lock_shared_recover(&shared);
        assert_eq!(rows.len(), PENDING);
        assert!(
            rows.values().all(|entry| {
                entry.tcp_handshake_state == TcpHandshakeState::Established.to_wire()
            }),
            "#18662: positive batched shared evidence advances every matching row"
        );
    }
    let mut traversal_calls = 1usize;
    while stage_counts_pending.is_some() {
        run_shared_evidence_leg(
            &mut sessions,
            &shared,
            &wire_map,
            &indexes,
            &mut cursor,
            &mut stage_counts_pending,
        );
        traversal_calls += 1;
        assert!(traversal_calls < 8, "positive batch finishes incrementally");
    }
    assert!(traversal_calls > 1, "the stage/count pass resumes after its first return");
    let updates: Vec<_> = sessions
        .drain_deltas(PENDING + 1)
        .into_iter()
        .filter(|delta| delta.kind == SessionDeltaKind::Update)
        .collect();
    assert_eq!(
        updates.len(),
        PENDING,
        "#18662: positive batched shared evidence propagates through the stage/count emit"
    );
    let acquired =
        crate::afxdp::shared_ops::SHARED_COMPLETION_EVIDENCE_BATCH_LOCK_PAIRS_18662
            .with(|count| {
                let acquired = count.get();
                count.set(before);
                acquired
            });
    let pending_rows =
        crate::afxdp::shared_ops::SHARED_COMPLETION_EVIDENCE_BATCH_PENDING_ROWS_18662
            .with(|count| {
                let pending_rows = count.get();
                count.set(pending_before);
                pending_rows
            });
    assert_eq!(acquired, 1, "2,048 pending rows need one shared-map lock pair");
    assert_eq!(pending_rows, PENDING as u64, "the batch covers all pending rows");
    assert_eq!(
        cursor, PENDING,
        "the worker cursor commits only after all stage/count outputs complete"
    );

}

#[test]
fn ct_slice_withholds_partial_alias_folds_until_resumed_pass_completes_18662() {
    const ALIASES: usize = 8_192;
    let mut sessions = crate::session::SessionTable::new();
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let nat_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let wire_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let forward = fx::key(
        fx::v4(10, 0, 61, 106),
        32_002,
        fx::v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let mut nat = fx::snat(Some(30_000));
    for i in 0..ALIASES {
        nat = fx::snat(Some(30_000 + i as u16));
        let shared_row = fx::row(
            &forward,
            nat,
            TcpHandshakeState::HandshakePending.to_wire(),
            10 + i as u64,
            20 + i as u64,
            false,
            30_000 + i as u64,
        );
        crate::afxdp::shared_ops::publish_shared_session(
            &shared,
            &nat_map,
            &wire_map,
            &indexes,
            &shared_row,
        );
    }
    let alias_rows = crate::afxdp::shared_ops::lock_shared_recover(
        &indexes.stage_counts_forward_wire_sessions,
    )
    .get(&forward)
    .expect("same-key republication retains wire aliases")
    .iter()
    .filter(|slot| slot.live)
    .count();
    assert_eq!(alias_rows, ALIASES);

    let established = TcpHandshakeState::Established.to_wire();
    let local = fx::row(&forward, nat, established, 1, 1, false, 40_001);
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: local.decision,
            metadata: local.metadata.clone(),
            source_nat_static: None,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: 1_000_000_000,
            protocol: crate::ip_proto::PROTO_TCP,
            tcp_flags: 0,
            session_id: local.session_id,
            tcp_close_class: 0,
            tcp_handshake_state: established,
            persistent_lease_hold: None,
            fwd_packets: 1,
            rev_packets: 1,
        },
        false,
    ));
    let _ = sessions.drain_deltas(16);

    let mut clocks = (0usize, 0u64, 0u64, 0u64, 0usize);
    let mut pending = None;
    let work = || crate::afxdp::shared_ops::STAGE_COUNTS_WORK_18655.with(|value| value.get());
    let before = work();
    let mut now = 30_000_000_000u64;
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        &mut pending,
        now,
    );
    assert!(pending.is_some(), "A=8,192 must persist unfinished lookup/fold state");
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "partial stage/count folds must not be consumed as complete"
    );

    let mut invocations = 1;
    while pending.is_some() {
        now += 100_000_000;
        run_slice_18655(
            &mut sessions,
            &shared,
            &wire_map,
            &indexes,
            &mut clocks,
            &mut pending,
            now,
        );
        invocations += 1;
        assert!(invocations < 8, "retained aliases must finish incrementally");
    }
    let after = work();
    assert!(invocations > 1, "the alias traversal resumed after its first return");
    assert_eq!(after.0 - before.0, invocations as u64);
    assert!(
        after.3 <= fx::EXPECTED_STAGE_COUNTS_INVOCATION_BUDGET_18662 as u64,
        "every run_ct_slice stage/count step stays within the independent total-work cap"
    );
    let updates: Vec<_> = sessions
        .drain_deltas(16)
        .into_iter()
        .filter(|delta| delta.kind == SessionDeltaKind::Update)
        .collect();
    // Same-incarnation control: the completed paced fold still emits once.
    assert_eq!(updates.len(), 1, "the completed fold emits exactly one Update");
    assert_eq!(updates[0].key, forward);
    assert_eq!(updates[0].tcp_handshake_state, established);
}
#[test]
fn ct_slice_drops_stale_pending_update_after_same_key_reinstall_18662() {
    const ALIASES: usize = 8_192;
    let mut sessions = crate::session::SessionTable::new();
    let shared: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let nat_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let wire_map: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let forward = fx::key(
        fx::v4(10, 0, 61, 106),
        32_002,
        fx::v4(172, 16, 80, 200),
        443,
        crate::ip_proto::PROTO_TCP,
    );
    let nat = fx::snat(Some(30_000 + (ALIASES - 1) as u16));
    let established = TcpHandshakeState::Established.to_wire();
    let old_local = fx::row(&forward, nat, established, 1, 1, false, 40_001);
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: old_local.decision,
            metadata: old_local.metadata.clone(),
            source_nat_static: None,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: 1_000_000_000,
            protocol: crate::ip_proto::PROTO_TCP,
            tcp_flags: 0,
            session_id: old_local.session_id,
            tcp_close_class: 0,
            tcp_handshake_state: established,
            persistent_lease_hold: None,
            fwd_packets: 1,
            rev_packets: 1,
        },
        false,
    ));
    let old_id = sessions.session_id_for(&forward);
    assert_ne!(old_id, 0, "fixture: old incarnation has an ID");
    let _ = sessions.drain_deltas(16);

    for i in 0..ALIASES {
        let alias_nat = fx::snat(Some(30_000 + i as u16));
        let shared_row = fx::row(
            &forward,
            alias_nat,
            TcpHandshakeState::HandshakePending.to_wire(),
            10 + i as u64,
            20 + i as u64,
            false,
            old_id,
        );
        crate::afxdp::shared_ops::publish_shared_session(
            &shared,
            &nat_map,
            &wire_map,
            &indexes,
            &shared_row,
        );
    }

    let mut clocks = (0usize, 0u64, 0u64, 0u64, 0usize);
    let mut pending = None;
    let mut now = 30_000_000_000u64;
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        &mut pending,
        now,
    );
    assert!(pending.is_some(), "the alias fold must span paced slices");
    assert!(
        sessions.drain_deltas(16).is_empty(),
        "an incomplete traversal emits no partial Update"
    );

    sessions.delete(&forward);
    let replacement = fx::row(&forward, nat, established, 0, 0, false, 50_001);
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: forward.clone(),
            decision: replacement.decision,
            metadata: replacement.metadata.clone(),
            source_nat_static: None,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: 2_000_000_000,
            protocol: crate::ip_proto::PROTO_TCP,
            tcp_flags: 0,
            session_id: replacement.session_id,
            tcp_close_class: 0,
            tcp_handshake_state: established,
            persistent_lease_hold: None,
            fwd_packets: 0,
            rev_packets: 0,
        },
        false,
    ));
    assert_ne!(
        sessions.session_id_for(&forward),
        old_id,
        "fixture: the same key now names a different incarnation"
    );
    let _ = sessions.drain_deltas(16);

    let mut invocations = 1;
    while pending.is_some() {
        now += 100_000_000;
        run_slice_18655(
            &mut sessions,
            &shared,
            &wire_map,
            &indexes,
            &mut clocks,
            &mut pending,
            now,
        );
        invocations += 1;
        assert!(invocations < 8, "the old alias traversal must complete");
    }
    let updates: Vec<_> = sessions
        .drain_deltas(16)
        .into_iter()
        .filter(|delta| delta.kind == SessionDeltaKind::Update)
        .collect();
    assert!(
        updates.is_empty(),
        "old Established evidence must not emit an Update for the replacement incarnation"
    );
    crate::afxdp::shared_ops::remove_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &forward,
    );
    let replacement_shared =
        fx::row(&forward, nat, established, 0, 0, false, replacement.session_id);
    crate::afxdp::shared_ops::publish_shared_session(
        &shared,
        &nat_map,
        &wire_map,
        &indexes,
        &replacement_shared,
    );
    let stale_aliases = crate::afxdp::shared_ops::lock_shared_recover(&wire_map)
        .values()
        .filter(|entry| entry.key == forward && entry.session_id == old_id)
        .count();
    assert_eq!(
        stale_aliases,
        ALIASES - 1,
        "removal leaves old incarnation aliases for the provenance check"
    );
    let replacement_identity = sessions
        .ct_slice_emit_identity_for(&forward)
        .expect("fixture: replacement identity is live");
    let fold_replacement = || {
        let mut traversal =
            crate::afxdp::shared_ops::StageCountsTraversal::new_with_identities(
                vec![(forward.clone(), nat.clone())],
                vec![Some(replacement_identity.clone())],
            );
        loop {
            let (complete, _, _, _) = traversal.advance(
                &shared,
                &wire_map,
                &indexes.stage_counts_forward_wire_sessions,
                crate::afxdp::shared_ops::STAGE_COUNTS_INVOCATION_BUDGET_18662,
            );
            if complete {
                break;
            }
        }
        traversal.finish().2
    };
    assert_eq!(
        fold_replacement(),
        vec![(established, 0, 0)],
        "wire aliases from A cannot contribute B's reverse counts"
    );

    // The next cycle sees B's own stage/count row, not A's retained aliases.
    now = 40_000_000_000;
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        &mut pending,
        now,
    );
    let mut next_cycle_invocations = 1;
    while pending.is_some() {
        now += 100_000_000;
        run_slice_18655(
            &mut sessions,
            &shared,
            &wire_map,
            &indexes,
            &mut clocks,
            &mut pending,
            now,
        );
        next_cycle_invocations += 1;
        assert!(next_cycle_invocations < 8, "replacement evidence traversal must finish");
    }
    assert!(
        sessions
            .drain_deltas(16)
            .into_iter()
            .all(|delta| delta.kind != SessionDeltaKind::Update),
        "stale A reverse counts must not emit a B Update"
    );

    // A genuinely retained alias belonging to B remains valid evidence even
    // when the canonical shared row still has rev=0.
    let retained_nat = fx::snat(Some(60_000));
    let retained_alias =
        fx::row(&forward, retained_nat, established, 0, 7, false, replacement.session_id);
    let retained_wire_key = crate::session::forward_wire_key(&forward, retained_nat);
    {
        let mut wires = crate::afxdp::shared_ops::lock_shared_recover(&wire_map);
        assert!(
            wires
                .insert(retained_wire_key.clone(), retained_alias.clone())
                .is_none(),
            "fixture: retained control alias has a distinct wire key"
        );
        crate::afxdp::shared_ops::update_stage_counts_entry_key_index(
            &indexes.stage_counts_forward_wire_sessions,
            &retained_wire_key,
            None,
            Some(&retained_alias),
        );
    }
    assert_eq!(
        fold_replacement(),
        vec![(established, 0, 7)],
        "same-incarnation retained aliases still contribute counts"
    );

    now = 50_000_000_000;
    run_slice_18655(
        &mut sessions,
        &shared,
        &wire_map,
        &indexes,
        &mut clocks,
        &mut pending,
        now,
    );
    let mut retained_alias_invocations = 1;
    while pending.is_some() {
        now += 100_000_000;
        run_slice_18655(
            &mut sessions,
            &shared,
            &wire_map,
            &indexes,
            &mut clocks,
            &mut pending,
            now,
        );
        retained_alias_invocations += 1;
        assert!(retained_alias_invocations < 8, "B alias evidence traversal must finish");
    }
    let replacement_updates: Vec<_> = sessions
        .drain_deltas(16)
        .into_iter()
        .filter(|delta| delta.kind == SessionDeltaKind::Update)
        .collect();
    assert_eq!(
        replacement_updates.len(),
        1,
        "B's own retained alias supplies the only first reverse evidence"
    );
    assert_eq!(replacement_updates[0].session_id, replacement.session_id);
    assert_eq!(replacement_updates[0].tcp_handshake_state, established);
    assert_eq!(
        replacement_updates[0].counters.rev_packets,
        0,
        "B itself has no local reverse packet; only its retained alias vouches"
    );
}

/// A worker row replaced in a slab slot already passed by this cycle is
/// deferred until the cursor wraps, then picked up from the beginning.
#[test]
fn ct_slice_worker_row_reinsert_after_pass_is_seen_next_cycle_18662() {
    const CHUNK: usize = 2048;
    let (mut sessions, _shared, _wire_map, _indexes, announced) =
        slice_fixture_18655(CHUNK + 1);
    let target = announced[0].clone();
    let mut first = Vec::new();
    assert_eq!(
        sessions.ct_slice_forward_pairs(0, CHUNK, &mut first),
        CHUNK,
        "fixture: first worker chunk leaves one row"
    );
    assert!(first.iter().any(|(key, _, _, _, _, _)| key == &target));

    // Reinstall the first row in the slab slot the cursor has already passed.
    // The slab's free slot is reused, so the remaining current-cycle chunk
    // must not see this new incarnation.
    sessions.delete(&target);
    let replacement = fx::row(
        &target,
        fx::snat(Some(42_000)),
        TcpHandshakeState::HandshakePending.to_wire(),
        99,
        3,
        false,
        99_999,
    );
    assert!(sessions.upsert_synced_with_origin(
        SessionInstall {
            key: target.clone(),
            decision: replacement.decision,
            metadata: replacement.metadata.clone(),
            source_nat_static: None,
            origin: SessionOrigin::WorkerLocalImport,
            now_ns: 2_000_000_000,
            protocol: crate::ip_proto::PROTO_TCP,
            tcp_flags: 0,
            session_id: replacement.session_id,
            tcp_close_class: 0,
            tcp_handshake_state: TcpHandshakeState::HandshakePending.to_wire(),
            persistent_lease_hold: None,
            fwd_packets: 99,
            rev_packets: 3,
        },
        false,
    ));
    let mut rest_of_cycle = Vec::new();
    assert_eq!(
        sessions.ct_slice_forward_pairs(CHUNK, CHUNK, &mut rest_of_cycle),
        0,
        "fixture: cursor wraps at the table end"
    );
    assert!(
        !rest_of_cycle.iter().any(|(key, _, _, _, _, _)| key == &target),
        "replacement in the passed slot is deferred for this cycle"
    );

    let mut next_cycle = Vec::new();
    let _ = sessions.ct_slice_forward_pairs(0, CHUNK, &mut next_cycle);
    assert_eq!(
        next_cycle
            .iter()
            .find(|(key, _, _, _, _, _)| key == &target)
            .map(|(_, _, fwd, rev, _, _)| (*fwd, *rev)),
        Some((99, 3)),
        "the next cycle restarts at slot zero and observes the replacement"
    );
}
