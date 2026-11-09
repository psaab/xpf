//! #19026 Part 2: the activation prewarm designates exactly one restore
//! closer for a `SharedPromote` row, and the respawn -> activation path
//! still ends in exactly one Close.
//!
//! The prewarm restores a locally promoted row as `SharedPromote` on every
//! live worker (#15950). The expiry fence (session/expire.rs) silences the
//! copies that never served; when NO copy served after the restore, only the
//! designated closer may emit the Close. The prewarm knows which queues
//! accepted its push, so it hands the first accepting queue (lowest index)
//! `WorkerCommand::UpsertSyncedRestoreCloser` and every other queue the plain
//! `UpsertSynced`.

use super::*;
use crate::afxdp::testfx::{test_forwarding_state_split_rgs, test_key, test_metadata, test_resolution};
use crate::session::{
    ExpireHaContext, NodeServedEvidence, STALE_SYNCED_CEILING_ABS_NS,
    STALE_SYNCED_CEILING_MULT, SessionDecision, SessionDeltaKind, SessionTable,
};

const SEC: u64 = 1_000_000_000;
const SESSION_ID: u64 = 0x0001_0000_0000_1907;

fn active_ha(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    let mut ha = BTreeMap::new();
    for rg in [1, 2] {
        ha.insert(
            rg,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: now_secs,
                lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
            },
        );
    }
    ha
}

fn promoted_row(origin: SessionOrigin) -> SyncedSessionEntry {
    let mut metadata = test_metadata();
    metadata.ingress_zone = 1;
    metadata.egress_zone = 2;
    metadata.fabric_ingress = false;
    metadata.owner_rg_id = 1;
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
        origin,
        protocol: crate::ip_proto::PROTO_TCP,
        tcp_flags: 0x10,
        generation: 0,
        session_id: SESSION_ID,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        rev_packets: 12,
        fwd_packets: 12,
        pptp_call_ids: 0,
        persistent_lease_hold: None,
        source_nat_static: None,
    }
}

struct Shared19026 {
    sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    indexes: SharedSessionOwnerRgIndexes,
}

impl Shared19026 {
    fn with(row: &SyncedSessionEntry) -> Self {
        let shared = Self {
            sessions: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            wire: Arc::new(Mutex::new(FastMap::default())),
            indexes: SharedSessionOwnerRgIndexes::default(),
        };
        publish_shared_session(&shared.sessions, &shared.nat, &shared.wire, &shared.indexes, row);
        shared
    }

    fn prewarm(&self, queues: &[Arc<Mutex<VecDeque<WorkerCommand>>>], now_secs: u64) {
        prewarm_reverse_synced_sessions_for_owner_rgs(
            &self.sessions,
            &self.nat,
            &self.wire,
            &self.indexes,
            queues,
            SteeringMap::unshared_for_test(-1),
            &test_forwarding_state_split_rgs(),
            &active_ha(now_secs),
            &Arc::new(ShardedNeighborMap::new()),
            &[1],
            now_secs,
        );
    }
}

fn queues(n: usize) -> Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> {
    (0..n).map(|_| Arc::new(Mutex::new(VecDeque::new()))).collect()
}

/// (closer commands, plain forward upserts) for `key` on one queue.
fn forward_commands(queue: &Arc<Mutex<VecDeque<WorkerCommand>>>, key: &SessionKey) -> (usize, usize) {
    let pending = queue.lock().expect("queue");
    let closer = pending
        .iter()
        .filter(|c| matches!(c, WorkerCommand::UpsertSyncedRestoreCloser(e) if e.key == *key))
        .count();
    let plain = pending
        .iter()
        .filter(|c| matches!(c, WorkerCommand::UpsertSynced(e) if e.key == *key))
        .count();
    (closer, plain)
}

#[test]
fn prewarm_designates_exactly_one_restore_closer_19026() {
    let row = promoted_row(SessionOrigin::SharedPromote);
    let shared = Shared19026::with(&row);
    let workers = queues(4);
    shared.prewarm(&workers, 1);
    let per_worker: Vec<_> = workers.iter().map(|q| forward_commands(q, &row.key)).collect();
    assert_eq!(per_worker[0], (1, 0), "the lowest accepting queue is the closer");
    for (worker, counts) in per_worker.iter().enumerate().skip(1) {
        assert_eq!(*counts, (0, 1), "worker {worker} gets the plain restore");
    }
    // A raw local row is restored as a peer-synced replica: replicas age
    // silently, so no closer is designated for it.
    let raw = promoted_row(SessionOrigin::ForwardFlow);
    let shared = Shared19026::with(&raw);
    let workers = queues(3);
    shared.prewarm(&workers, 1);
    for queue in &workers {
        assert_eq!(forward_commands(queue, &raw.key), (0, 1));
    }
}

#[test]
fn prewarm_moves_the_closer_past_a_refusing_queue_19026() {
    let row = promoted_row(SessionOrigin::SharedPromote);
    let shared = Shared19026::with(&row);
    let workers = queues(3);
    {
        let mut full = workers[0].lock().expect("queue");
        while worker_queue::push_bounded(&mut full, WorkerCommand::DeleteSynced(test_key())) {}
    }
    shared.prewarm(&workers, 1);
    assert_eq!(forward_commands(&workers[0], &row.key), (0, 0), "full queue refused");
    assert_eq!(
        forward_commands(&workers[1], &row.key),
        (1, 0),
        "#19026: the closer role moves to the first queue that ACCEPTED"
    );
    assert_eq!(forward_commands(&workers[2], &row.key), (0, 1));
}

/// Cell 3: respawn, then activation. The respawn replay demotes the
/// promoted row to `WorkerLocalImport` replicas on every worker (#19030's
/// gap, out of scope here); the activation prewarm restores `SharedPromote`
/// with one designated closer. The authority is held again, and when the
/// flow (never served after the restore) idles out it closes EXACTLY once.
#[test]
fn respawn_then_activation_restores_authority_and_closes_once_19026() {
    let row = promoted_row(SessionOrigin::SharedPromote);
    let shared = Shared19026::with(&row);
    let workers = queues(3);
    let forwarding = test_forwarding_state_split_rgs();
    let neighbors = Arc::new(ShardedNeighborMap::new());
    let now_secs = monotonic_nanos() / SEC;
    let ha = active_ha(now_secs);
    let mut tables: Vec<SessionTable> = (0..3).map(|_| SessionTable::new()).collect();

    // Respawn replay (bringup.rs `replay_late_synced_sessions`).
    for queue in &workers {
        queue
            .lock()
            .expect("queue")
            .push_back(WorkerCommand::UpsertSynced(synced_replica_entry(&row)));
    }
    let apply = |tables: &mut Vec<SessionTable>| {
        for (worker, (queue, table)) in workers.iter().zip(tables.iter_mut()).enumerate() {
            apply_worker_commands(
                queue,
                table,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                &forwarding,
                &ha,
                &neighbors,
                worker as u32,
                &mut VecDeque::new(),
            );
        }
    };
    apply(&mut tables);
    for table in &tables {
        assert_eq!(
            table.entry_with_origin(&row.key).map(|(_, _, o)| o),
            Some(SessionOrigin::WorkerLocalImport),
            "FIXTURE: the respawn replay leaves replicas only"
        );
    }

    // Activation.
    shared.prewarm(&workers, now_secs);
    apply(&mut tables);
    for (worker, table) in tables.iter().enumerate() {
        assert_eq!(
            table.entry_with_origin(&row.key).map(|(_, _, o)| o),
            Some(SessionOrigin::SharedPromote),
            "worker {worker}: the activation restores the promoted authority"
        );
    }

    // The flow never serves again and idles out.
    let forwards_rg = |_rg: i32| true;
    let epoch_of = |_rg: i32| 0u32;
    let shared_row = |key: &SessionKey| shared_row_identity(&shared.sessions, key);
    let ctx = ExpireHaContext {
        node_active: true,
        forwards_rg: &forwards_rg,
        epoch_of: &epoch_of,
        ceiling_mult: STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: STALE_SYNCED_CEILING_ABS_NS,
        node_served: &|_| NodeServedEvidence::default(),
        shared_row: &shared_row,
    };
    let later = monotonic_nanos() + 4 * 3_600 * SEC;
    let mut closes = 0;
    for table in tables.iter_mut() {
        let _ = table.expire_stale_entries_ha(later, Some(&ctx));
        closes += table
            .drain_deltas(4096)
            .into_iter()
            .filter(|d| d.kind == SessionDeltaKind::Close && d.key == row.key)
            .count();
        assert!(table.entry_with_origin(&row.key).is_none(), "every copy idled out");
    }
    assert_eq!(closes, 1, "#19026: respawn + activation still closes exactly once");
}
