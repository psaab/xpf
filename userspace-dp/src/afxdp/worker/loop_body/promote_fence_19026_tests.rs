// #19026 Part 2: the restore close fence through the worker's production
// wiring — `run_session_housekeeping` builds the `ExpireHaContext` (with the
// production `shared_ops::shared_row_identity` read) and drains the Close
// deltas into the loop's flush, and `reap_expired_sessions` takes the fenced
// teardown. The rules themselves are pinned in
// `session/promote_copy_close_fence_19026_tests.rs`.

use super::*;
use crate::afxdp::testfx::{test_key, test_metadata, test_resolution};
use std::sync::atomic::AtomicU32;

const SEC: u64 = 1_000_000_000;
const SESSION_ID: u64 = 0x0001_0000_0000_1908;
const SEEDED: u64 = 12;

fn promoted_row() -> SyncedSessionEntry {
    let mut metadata = test_metadata();
    metadata.owner_rg_id = 1;
    metadata.fabric_ingress = false;
    metadata.is_reverse = false;
    SyncedSessionEntry {
        sibling_last_seen_ns: 0,
        key: test_key(),
        decision: SessionDecision {
            resolution: test_resolution(),
            nat: crate::nat::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        },
        metadata,
        leak_incarnation: 0,
        origin: SessionOrigin::SharedPromote,
        protocol: PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: SESSION_ID,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: SEEDED,
        fwd_packets: SEEDED,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

/// One restored, never-served `SharedPromote` copy on this worker, the
/// shared primary row with `shared_packets`, and the worker's housekeeping
/// run past the copy's idle window. Returns (Close deltas the loop flushed
/// for the key, shared row still present, copy still in the table).
fn run_restored_copy(shared_packets: u64, closer: bool) -> (usize, bool, bool) {
    let row = promoted_row();
    let install_ns = 10_000 * SEC;
    let mut sessions = SessionTable::new();
    assert!(
        sessions.upsert_synced_with_origin(row.clone().into_session_install(install_ns), false),
        "FIXTURE: restore install"
    );
    if closer {
        assert!(sessions.mark_restore_closer(&row.key, SESSION_ID));
    }
    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let mut published = row.clone();
    published.fwd_packets = shared_packets / 2;
    published.rev_packets = shared_packets - shared_packets / 2;
    crate::afxdp::shared_ops::publish_shared_session(
        &shared_sessions,
        &shared_nat,
        &shared_wire,
        &indexes,
        &published,
    );

    let now_ns = install_ns + 3 * 3_600 * SEC;
    let now_secs = now_ns / SEC;
    let mut ha_runtime: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();
    ha_runtime.insert(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        },
    );
    let rg_epochs: [AtomicU32; crate::afxdp::flow_cache::MAX_RG_EPOCHS] =
        std::array::from_fn(|_| AtomicU32::new(0));
    let runtime = RuntimeViewChannel::default();
    let shared_runtime = runtime.reader();
    let worker_command_queues = crate::afxdp::types::WorkerCommandQueues::new(BTreeMap::new());
    let pptp_control = crate::session::pptp_control::PptpControlInbox::default();
    let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
    let mut bindings: Vec<BindingWorker> = Vec::new();
    let mut shared_recycles = Vec::new();
    let mut overflow = Vec::new();
    let mut wedged = false;
    let mut barrier = super::close_barrier::ClosePermitBarrier::default();
    let mut flushed: Vec<SessionDelta> = Vec::new();
    let mut flush_deltas =
        |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, deltas: &[SessionDelta]| {
            flushed.extend(deltas.iter().cloned());
        };
    let _ = run_session_housekeeping(
        &mut sessions,
        &mut bindings,
        &WorkerBindingLookup::default(),
        &ForwardingState::default(),
        &ha_runtime,
        now_ns,
        now_secs,
        &rg_epochs,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        0,
        &worker_command_queues,
        &pptp_control,
        None,
        &peer_worker_commands,
        &shared_sessions,
        &shared_nat,
        &shared_wire,
        &indexes,
        &shared_runtime,
        &mut wedged,
        &mut shared_recycles,
        &mut overflow,
        &mut barrier,
        &mut flush_deltas,
    );
    let closes = flushed
        .iter()
        .filter(|d| d.kind == SessionDeltaKind::Close && d.key == row.key)
        .count();
    let shared_present = crate::afxdp::shared_ops::lock_shared_recover(&shared_sessions)
        .contains_key(&row.key);
    (closes, shared_present, sessions.entry_with_origin(&row.key).is_some())
}

/// Cell 1 (production wiring): while another worker serves — the shared
/// row's counters advanced past this copy's seeded ones — the worker's
/// housekeeping removes its non-serving restored copy without handing the
/// loop's flush any Close (the sole carrier of the shared removal, sibling
/// `DeleteSynced` and HA delete). Holds for the designated closer too.
#[test]
fn housekeeping_silences_non_serving_restored_copy_19026() {
    for closer in [false, true] {
        let (closes, shared_present, copy_present) = run_restored_copy(2 * SEEDED + 40, closer);
        assert!(!copy_present, "closer={closer}: the idle copy is removed");
        assert_eq!(closes, 0, "#19026: closer={closer}: no Close reaches the flush");
        assert!(shared_present, "the serving copy's shared row is untouched");
    }
}

/// Twin: a never-served restored session (shared counters NOT advanced)
/// still closes through the designated copy, and only through it.
#[test]
fn housekeeping_closes_stale_restore_only_on_the_closer_19026() {
    assert_eq!(run_restored_copy(2 * SEEDED, true).0, 1, "the closer closes");
    assert_eq!(run_restored_copy(2 * SEEDED, false).0, 0, "a non-closer is silent");
}

/// The fenced reap keeps the tuple's conntrack mirror row (under the same
/// session id it is the live incarnation's) while the ordinary reap of the
/// same record deletes it.
#[test]
fn fenced_reap_keeps_the_live_conntrack_mirror_row_19026() {
    use crate::afxdp::bpf_map::{
        CONNTRACK_TEST_MAP_FD, clear_conntrack_rows_for_test, conntrack_row_for_test,
        publish_bpf_conntrack_entry_with_source_nat,
    };
    let row = promoted_row();
    for close_fenced in [true, false] {
        clear_conntrack_rows_for_test();
        assert_eq!(
            publish_bpf_conntrack_entry_with_source_nat(
                CONNTRACK_TEST_MAP_FD,
                CONNTRACK_TEST_MAP_FD,
                &row.key,
                row.decision,
                &row.metadata,
                &FastMap::default(),
                0,
                0,
                SESSION_ID,
                300,
                SessionOrigin::SharedPromote,
                None,
            ),
            crate::afxdp::bpf_map::ConntrackPublishResult::Written
        );
        let expired = crate::session::ExpiredSession {
            key: row.key.clone(),
            decision: row.decision,
            metadata: row.metadata.clone(),
            persistent_lease_hold: None,
            origin: SessionOrigin::SharedPromote,
            session_id: SESSION_ID,
            close_class: 0,
            install_epoch: 0,
            overflow_close: None,
            close_fenced,
        };
        let deferred = reap_expired_sessions(
            &mut [],
            &[expired],
            &ForwardingState::default(),
            SteeringMap::unshared_for_test(-1),
            CONNTRACK_TEST_MAP_FD,
            CONNTRACK_TEST_MAP_FD,
            1_000 * SEC,
            0,
            &Arc::new(Mutex::new(FastMap::default())),
        );
        assert!(deferred.is_empty());
        assert_eq!(
            conntrack_row_for_test(&row.key).is_some(),
            close_fenced,
            "#19026: close_fenced={close_fenced}: the fenced reap keeps the mirror row, \
             the ordinary reap deletes it"
        );
    }
    clear_conntrack_rows_for_test();
}
