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
        sibling_last_seen_ns: 0, last_served_ns: 0,
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
/// shared primary row (with `last_served_ns` = `served_at`, 0 = never), and
/// the worker's housekeeping run at `checks` (absolute offsets past the
/// install). Returns (Close deltas the loop flushed for the key, shared row
/// still present, copy still in the table).
fn run_restored_copy(served_at: Option<u64>, checks: &[u64]) -> (usize, bool, bool) {
    let row = promoted_row();
    let install_ns = 10_000 * SEC;
    let mut sessions = SessionTable::new();
    assert!(
        sessions.upsert_synced_with_origin(row.clone().into_session_install(install_ns), false),
        "FIXTURE: restore install"
    );
    let shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let shared_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>> =
        Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    let mut published = row.clone();
    published.last_served_ns = served_at.map_or(0, |offset| install_ns + offset);
    crate::afxdp::shared_ops::publish_shared_session(
        &shared_sessions,
        &shared_nat,
        &shared_wire,
        &indexes,
        &published,
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
    for check in checks {
    let now_ns = install_ns + check;
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
    }
    let closes = flushed
        .iter()
        .filter(|d| d.kind == SessionDeltaKind::Close && d.key == row.key)
        .count();
    let shared_present = crate::afxdp::shared_ops::lock_shared_recover(&shared_sessions)
        .contains_key(&row.key);
    (closes, shared_present, sessions.entry_with_origin(&row.key).is_some())
}

/// Cell 1 (production wiring): while another worker on this node serves —
/// the shared row's `last_served_ns`, which every worker's restamp stamps,
/// is inside the window — the worker's housekeeping keeps its idle restored
/// copy and hands the loop's flush no Close (the sole carrier of the shared
/// removal, sibling `DeleteSynced` and HA delete).
#[test]
fn housekeeping_keeps_idle_copy_while_another_serves_19026() {
    let late = 3 * 3_600 * SEC;
    let (closes, shared_present, copy_present) = run_restored_copy(Some(late - 10 * SEC), &[late]);
    assert!(copy_present, "the idle copy is kept while the node serves");
    assert_eq!(closes, 0, "#19026: no Close reaches the flush");
    assert!(shared_present, "the serving copy's shared row is untouched");
}

/// The production claim: a genuinely idle restored copy is held for the
/// evidence cadence + GC interval (13 s + 1 s with the default slab), then
/// claims the shared row through `shared_ops::claim_shared_close` and closes.
#[test]
fn housekeeping_holds_then_claims_an_idle_restore_19026() {
    let late = 3 * 3_600 * SEC;
    let held = run_restored_copy(None, &[late]);
    assert_eq!(held, (0, true, true), "inside the hold: kept, no Close, shared intact");
    let claimed = run_restored_copy(None, &[late, late + 15 * SEC]);
    assert_eq!(claimed, (1, false, false), "after the hold: one Close, shared retired");
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

type SharedMap = Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>;

fn shared_maps_with(row: &SyncedSessionEntry) -> (SharedMap, SharedMap, SharedMap, SharedSessionOwnerRgIndexes) {
    let sessions: SharedMap = Arc::new(Mutex::new(FastMap::default()));
    let nat: SharedMap = Arc::new(Mutex::new(FastMap::default()));
    let wire: SharedMap = Arc::new(Mutex::new(FastMap::default()));
    let indexes = SharedSessionOwnerRgIndexes::default();
    crate::afxdp::shared_ops::publish_shared_session(&sessions, &nat, &wire, &indexes, row);
    (sessions, nat, wire, indexes)
}

/// The claim is a compare-and-remove: a stale expectation (the row was
/// restamped after the fence read it) neither removes the row nor wins; the
/// exact current identity removes it once, and a second claim finds nothing.
#[test]
fn claim_shared_close_is_compare_and_remove_19026() {
    let row = promoted_row();
    let (sessions, nat, wire, indexes) = shared_maps_with(&row);
    let key = row.key.clone();
    let read = crate::afxdp::shared_ops::shared_row_identity(&sessions, &key).expect("row");
    crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
        &sessions,
        &wire,
        1,
        &[(key.clone(), crate::nat::NatDecision::default(), SEEDED + 1, SEEDED, 77 * SEC)],
    );
    let claim = |expected| {
        crate::afxdp::shared_ops::claim_shared_close(&sessions, &nat, &wire, &indexes, &key, expected)
    };
    assert!(!claim(read), "a stale identity must not win the claim");
    assert!(crate::afxdp::shared_ops::lock_shared_recover(&sessions).contains_key(&key));
    let current = crate::afxdp::shared_ops::shared_row_identity(&sessions, &key).expect("row");
    assert_eq!(current.last_served_ns, 77 * SEC);
    assert!(claim(current), "the exact identity wins");
    assert!(!crate::afxdp::shared_ops::lock_shared_recover(&sessions).contains_key(&key));
    assert!(!claim(current), "exactly one winner");
}

/// `last_served_ns` is stamped by EVERY worker's restamp, the minting
/// worker included (namespace 0 here, `session_id >> 48`), max-merged;
/// `sibling_last_seen_ns` keeps its #18742 meaning (minting excluded).
/// Same-incarnation republication keeps the larger value; a new incarnation
/// starts from its own.
#[test]
fn last_served_is_stamped_by_every_worker_and_kept_per_incarnation_19026() {
    let row = promoted_row();
    assert_eq!(row.session_id >> 48, 1, "FIXTURE: minted in namespace 1");
    let (sessions, nat, wire, indexes) = shared_maps_with(&row);
    let key = row.key.clone();
    let restamp = |namespace: u16, packet_seen_ns: u64| {
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &sessions,
            &wire,
            namespace,
            &[(key.clone(), crate::nat::NatDecision::default(), SEEDED, SEEDED, packet_seen_ns)],
        );
    };
    let read = || {
        let map = crate::afxdp::shared_ops::lock_shared_recover(&sessions);
        let entry = map.get(&key).expect("row");
        (entry.last_served_ns, entry.sibling_last_seen_ns)
    };
    restamp(1, 50 * SEC);
    assert_eq!(read(), (50 * SEC, 0), "the minting worker stamps last_served only");
    restamp(2, 40 * SEC);
    assert_eq!(read(), (50 * SEC, 40 * SEC), "max-merged; a sibling stamps both");
    restamp(2, 60 * SEC);
    assert_eq!(read(), (60 * SEC, 60 * SEC));
    // The single-pair restamp (cache-hit stage transition) stamps it too.
    crate::afxdp::shared_ops::restamp_shared_packet_counts(
        &sessions,
        &wire,
        &key,
        crate::nat::NatDecision::default(),
        1,
        65 * SEC,
        SEEDED,
        SEEDED,
    );
    assert_eq!(read(), (65 * SEC, 60 * SEC), "single-pair restamp, minting worker");
    crate::afxdp::shared_ops::publish_shared_session(&sessions, &nat, &wire, &indexes, &row);
    assert_eq!(read().0, 65 * SEC, "same-incarnation republication keeps it");
    let mut next = row.clone();
    next.session_id += 1;
    crate::afxdp::shared_ops::publish_shared_session(&sessions, &nat, &wire, &indexes, &next);
    assert_eq!(read().0, 0, "a new incarnation starts from its own");
}
