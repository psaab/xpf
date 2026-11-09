// #19026 Part 2 fold (Codex P1 #1-#4, P2 #6): restored `SharedPromote`
// copies on several workers, driven through the PRODUCTION paths end to end:
//
// - install: the RG-activation prewarm
//   (`prewarm_reverse_synced_sessions_for_owner_rgs`) into real per-worker
//   command queues, applied by `apply_worker_commands`;
// - service: the read path (`lookup_with_origin` + `account_packet`) and the
//   ct-slice restamp (`restamp_shared_packet_counts_batch`);
// - expiry: `run_session_housekeeping` (which builds the production
//   `ExpireHaContext`) on EVERY worker in the same instant, collecting the
//   deltas each one hands its flush;
// - close: then the REAL flush (`flush_session_deltas_loop`: shared removal,
//   sibling `DeleteSynced` fan-out, and the HA close and RT_FLOW
//   SESSION_CLOSE sent on a connected event stream), and the siblings' queues
//   applied.
//
// "HA closes" below counts the type-2 session-sync CLOSE frames the flush
// actually DELIVERED on that event stream for the session's tuple (Codex R15
// P2#6: not the `recent_session_deltas` status history, which is appended
// whether or not any HA path delivered), and `rt_flow_closes` the type-14
// RT_FLOW SESSION_CLOSE frames carrying the session's stable id.
//
// The file deliberately names no type or field added by the fold, so the
// same cells run unchanged against bb9608f1a6 (the pre-fold head), where
// each Codex cell is RED.

use super::*;
use crate::afxdp::testfx::{test_forwarding_state_split_rgs, test_key, test_metadata, test_resolution};
use crate::protocol::SessionDeltaInfo;
use std::sync::atomic::AtomicU32;

const SEC: u64 = 1_000_000_000;
const WORKERS: usize = 3;

struct Worker {
    table: SessionTable,
    queue: Arc<Mutex<VecDeque<WorkerCommand>>>,
    barrier: super::housekeeping::ClosePermitBarrier,
    overflow: Vec<SessionDelta>,
    recycles: Vec<(u32, u64)>,
    wedged: bool,
    pending_flush: Vec<SessionDelta>,
}

struct Fixture {
    /// The activation instant: the REAL monotonic clock at fixture creation,
    /// because `apply_worker_commands` stamps installs with it.
    t0: u64,
    workers: Vec<Worker>,
    /// Workers that still run (a "dead" worker's queue is never applied
    /// and its loop never runs).
    alive: Vec<bool>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    indexes: SharedSessionOwnerRgIndexes,
    recent: Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    /// The connected event stream the flush delivers HA and RT_FLOW frames
    /// on, and every frame received from it so far.
    event_stream: Option<crate::event_stream::EventStreamWorkerHandle>,
    event_rx: std::sync::mpsc::Receiver<crate::event_stream::codec::EventFrame>,
    frames: Vec<crate::event_stream::codec::EventFrame>,
    runtime: RuntimeViewChannel,
    rg_epochs: [AtomicU32; crate::afxdp::flow_cache::MAX_RG_EPOCHS],
    pptp: crate::session::pptp_control::PptpControlInbox,
    forwarding: ForwardingState,
    neighbors: Arc<ShardedNeighborMap>,
    row: SyncedSessionEntry,
}

fn ha_at(now_ns: u64) -> BTreeMap<i32, HAGroupRuntime> {
    let now_secs = now_ns / SEC;
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

impl Fixture {
    /// The locally promoted TCP row (owner RG 1) minted by `minting_worker`.
    fn new(minting_worker: u64) -> Self {
        Self::with_protocol(minting_worker, PROTO_TCP)
    }

    /// The same row for `protocol` (TCP rows also take the #18722
    /// node-evidence keep-alive before the fence; UDP rows reach the fence
    /// directly).
    fn with_protocol(minting_worker: u64, protocol: u8) -> Self {
        let req = crate::SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: libc::AF_INET as u8,
            protocol,
            src_ip: "10.0.61.102".to_string(),
            dst_ip: "172.16.80.200".to_string(),
            src_port: 55068,
            dst_port: 5201,
            owner_rg_id: 1,
            session_id: (minting_worker << 48) | 0x1906,
            fwd_packets: 12,
            rev_packets: 12,
            ..crate::SessionSyncRequest::default()
        };
        let mut row = crate::server::helpers::build_synced_session_entry(
            &req,
            &rustc_hash::FxHashMap::default(),
            0,
        )
        .expect("FIXTURE: synced entry");
        row.key = SessionKey {
            protocol,
            ..test_key()
        };
        row.decision = SessionDecision {
            resolution: test_resolution(),
            nat: crate::nat::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        };
        let mut metadata = test_metadata();
        metadata.inactivity_timeout_ns = Some(60 * SEC);
        row.metadata = metadata;
        row.origin = SessionOrigin::SharedPromote;
        row.tcp_flags = if protocol == PROTO_TCP {
            crate::tcp_flags::TCP_ACK
        } else {
            0
        };
        let workers = (0..WORKERS)
            .map(|w| {
                let mut table = SessionTable::new();
                table.set_session_id_namespace(0, w as u32);
                Worker {
                    table,
                    queue: Arc::new(Mutex::new(VecDeque::new())),
                    barrier: Default::default(),
                    overflow: Vec::new(),
                    recycles: Vec::new(),
                    wedged: false,
                    pending_flush: Vec::new(),
                }
            })
            .collect();
        let (event_handle, event_rx) = crate::event_stream::test_worker_handle_connected(
            1 << 16,
            crate::event_stream::DataplaneEventRateLimitConfig {
                events_per_second: 0,
                burst: 0,
                session_close_events_per_second: 0,
                session_close_burst: 0,
                session_create_events_per_second: 0,
                session_create_burst: 0,
            },
        );
        let fixture = Self {
            t0: crate::afxdp::neighbor::monotonic_nanos(),
            workers,
            alive: vec![true; WORKERS],
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat: Arc::new(Mutex::new(FastMap::default())),
            shared_wire: Arc::new(Mutex::new(FastMap::default())),
            indexes: SharedSessionOwnerRgIndexes::default(),
            recent: Arc::new(Mutex::new(VecDeque::new())),
            event_stream: Some(event_handle),
            event_rx,
            frames: Vec::new(),
            runtime: RuntimeViewChannel::default(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            pptp: crate::session::pptp_control::PptpControlInbox::default(),
            forwarding: test_forwarding_state_split_rgs(),
            neighbors: Arc::new(ShardedNeighborMap::new()),
            row,
        };
        crate::afxdp::shared_ops::publish_shared_session(
            &fixture.shared_sessions,
            &fixture.shared_nat,
            &fixture.shared_wire,
            &fixture.indexes,
            &fixture.row,
        );
        fixture
    }

    fn queues(&self) -> Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> {
        self.workers.iter().map(|w| w.queue.clone()).collect()
    }

    /// RG activation: the production prewarm pushes the restore to every
    /// worker queue it is handed.
    fn prewarm(&self, now_ns: u64) {
        crate::afxdp::shared_ops::prewarm_reverse_synced_sessions_for_owner_rgs(
            &self.shared_sessions,
            &self.shared_nat,
            &self.shared_wire,
            &self.indexes,
            &self.queues(),
            SteeringMap::unshared_for_test(-1),
            &self.forwarding,
            &ha_at(now_ns),
            &self.neighbors,
            &[1],
            now_ns / SEC,
        );
    }

    /// Each live worker drains its command queue (the loop top).
    fn apply_commands(&mut self, now_ns: u64) {
        let ha = ha_at(now_ns);
        for (w, worker) in self.workers.iter_mut().enumerate() {
            if !self.alive[w] {
                continue;
            }
            crate::afxdp::session_glue::apply_worker_commands(
                &worker.queue,
                &mut worker.table,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                &self.forwarding,
                &ha,
                &self.neighbors,
                w as u32,
                &mut VecDeque::new(),
            );
        }
    }

    /// One packet of the flow served on worker `w` (read path + accounting),
    /// then optionally published by that worker's ct-slice restamp.
    fn serve(&mut self, w: usize, now_ns: u64, restamp: bool) {
        let key = self.row.key.clone();
        self.serve_key(w, &key, now_ns, restamp);
    }

    /// One packet of the REVERSE direction served on worker `w`: the hit
    /// stamps the reverse half; `account_packet` folds its count onto the
    /// forward copy; the restamp publishes the forward pair.
    fn serve_reverse(&mut self, w: usize, now_ns: u64, restamp: bool) {
        let reverse = crate::session::reverse_session_key(&self.row.key, self.row.decision.nat);
        self.serve_key(w, &reverse, now_ns, restamp);
    }

    fn serve_key(&mut self, w: usize, key: &SessionKey, now_ns: u64, restamp: bool) {
        let flags = self.row.tcp_flags;
        let table = &mut self.workers[w].table;
        assert!(
            table.lookup_with_origin(key, now_ns, flags).is_some(),
            "FIXTURE: worker {w} serves {key:?}"
        );
        table.account_packet(key, 64, flags, 0);
        if restamp {
            self.restamp(w);
        }
    }

    fn restamp(&self, w: usize) {
        let key = &self.row.key;
        let table = &self.workers[w].table;
        crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
            &self.shared_sessions,
            &self.shared_wire,
            table.session_id_namespace(),
            &[(
                key.clone(),
                crate::nat::NatDecision::default(),
                table.fwd_packets_for(key),
                table.rev_packets_for(key),
                table.packet_counts_and_last_packet_seen_for(key).2,
            )],
        );
    }

    /// Every live worker runs its housekeeping in the same instant (each
    /// expiry pass reads shared state before any flush), then each worker's
    /// collected deltas go through the REAL flush, then queues apply.
    fn round(&mut self, now_ns: u64) {
        let ha = ha_at(now_ns);
        let queues = self.queues();
        let by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = queues
            .iter()
            .enumerate()
            .map(|(w, q)| (w as u32, q.clone()))
            .collect();
        let command_queues = crate::afxdp::types::WorkerCommandQueues::new(by_id.clone());
        let shared_runtime = self.runtime.reader();
        for w in 0..WORKERS {
            if !self.alive[w] {
                continue;
            }
            let peers: Vec<_> = queues
                .iter()
                .enumerate()
                .filter(|(p, _)| *p != w)
                .map(|(_, q)| q.clone())
                .collect();
            let worker = &mut self.workers[w];
            let collected = &mut worker.pending_flush;
            let mut collect =
                |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, deltas: &[SessionDelta]| {
                    collected.extend(deltas.iter().cloned());
                };
            let _ = run_session_housekeeping(
                &mut worker.table,
                &mut Vec::new(),
                &WorkerBindingLookup::default(),
                &self.forwarding,
                &ha,
                now_ns,
                now_ns / SEC,
                &self.rg_epochs,
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                w as u32,
                &command_queues,
                &self.pptp,
                Some(&worker.queue),
                &peers,
                &self.shared_sessions,
                &self.shared_nat,
                &self.shared_wire,
                &self.indexes,
                &shared_runtime,
                &mut worker.wedged,
                &mut worker.recycles,
                &mut worker.overflow,
                &mut worker.barrier,
                &mut collect,
            );
        }
        for w in 0..WORKERS {
            if !self.alive[w] {
                continue;
            }
            let peers: Vec<_> = queues
                .iter()
                .enumerate()
                .filter(|(p, _)| *p != w)
                .map(|(_, q)| q.clone())
                .collect();
            let worker = &mut self.workers[w];
            let deltas = std::mem::take(&mut worker.pending_flush);
            if deltas.is_empty() {
                continue;
            }
            super::flush_session_deltas_loop(
                &mut worker.table,
                &[],
                SteeringMap::unshared_for_test(-1),
                -1,
                -1,
                &self.shared_sessions,
                &self.shared_nat,
                &self.shared_wire,
                &self.indexes,
                &self.recent,
                &peers,
                &by_id,
                &self.event_stream,
                &self.forwarding,
                &shared_runtime,
                &mut worker.wedged,
                w as u32,
                &deltas,
            );
        }
        self.apply_commands(now_ns);
    }

    /// Pull every frame the flush has delivered so far.
    fn drain_frames(&mut self) {
        while let Ok(frame) = self.event_rx.try_recv() {
            self.frames.push(frame);
        }
    }

    /// HA session-sync CLOSE frames (type 2) DELIVERED for the session's
    /// tuple (protocol and ports at the payload's head).
    fn ha_closes(&mut self) -> usize {
        self.drain_frames();
        let key = self.row.key.clone();
        let header = crate::event_stream::codec::FRAME_HEADER_SIZE;
        self.frames
            .iter()
            .map(|frame| frame.as_bytes())
            .filter(|bytes| {
                bytes.len() >= header + 6
                    && bytes[4] == crate::event_stream::codec::MSG_SESSION_CLOSE
                    && bytes[header + 1] == key.protocol
                    && u16::from_le_bytes([bytes[header + 2], bytes[header + 3]]) == key.src_port
                    && u16::from_le_bytes([bytes[header + 4], bytes[header + 5]]) == key.dst_port
            })
            .count()
    }

    /// RT_FLOW SESSION_CLOSE frames (type 14) DELIVERED for `session_id`
    /// (the stable id at payload [152:160]).
    fn rt_flow_closes(&mut self, session_id: u64) -> usize {
        self.drain_frames();
        let at = crate::event_stream::codec::FRAME_HEADER_SIZE + 152;
        self.frames
            .iter()
            .map(|frame| frame.as_bytes())
            .filter(|bytes| {
                bytes.len() >= at + 8
                    && bytes[4] == crate::event_stream::codec::MSG_SESSION_CLOSE_RT_FLOW
                    && u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
                        == session_id
            })
            .count()
    }

    fn shared_present(&self) -> bool {
        crate::afxdp::shared_ops::lock_shared_recover(&self.shared_sessions).contains_key(&self.row.key)
    }

    fn has_row(&self, w: usize) -> bool {
        self.workers[w].table.entry_with_origin(&self.row.key).is_some()
    }

    /// The copies' idle window, read from whichever workers hold one (a
    /// worker without a copy reads 0).
    fn window_ns(&self) -> u64 {
        let secs = self
            .workers
            .iter()
            .map(|worker| worker.table.timeout_secs_for(&self.row.key))
            .max()
            .unwrap_or(0);
        assert!(secs > 0, "FIXTURE: some worker holds a restored copy");
        u64::from(secs) * SEC
    }

    /// When a genuinely idle restored session has closed by. Not one window:
    /// at the first expiry pass the reverse replica's node-evidence arm
    /// (#16223/#18722, `opening_companion_keeps_alive`) sees the shared row's
    /// counters for the first time, counts that as a change, and re-stamps
    /// both halves once (`align_node_kept_companion`). The pair then ages one
    /// more window, the forward copy is held for the fence (cadence + GC),
    /// and only then claims. Three windows bound that with room to spare.
    fn idle_close_horizon(&self) -> u64 {
        self.t0 + 3 * self.window_ns() + 40 * SEC
    }

    /// RG activation at `now`: prewarm + every live worker applies it.
    fn activate(&mut self, now_ns: u64) {
        self.prewarm(now_ns);
        self.apply_commands(now_ns);
        for w in 0..WORKERS {
            if self.alive[w] {
                assert_eq!(
                    self.workers[w].table.entry_with_origin(&self.row.key).map(|(_, _, o)| o),
                    Some(SessionOrigin::SharedPromote),
                    "FIXTURE: worker {w} holds the restored copy"
                );
            }
        }
    }

    /// Run 1 s rounds from `from` (exclusive) to `to` (inclusive).
    fn rounds(&mut self, from: u64, to: u64) {
        let mut now = from;
        while now < to {
            now += SEC;
            self.round(now);
        }
    }
}

/// Codex P1 #1: a copy that served, then went quiet while ANOTHER worker
/// kept serving (minting or not), must never close the live flow. On
/// bb9608f1a6 the served copy took R3 and closed it.
#[test]
fn served_copy_never_closes_while_another_worker_serves_19026() {
    for (minting, early, late) in [(0u64, 1usize, 0usize), (2, 1, 0), (0, 2, 1)] {
        let mut f = Fixture::new(minting);
        let t0 = f.t0;
        f.activate(t0);
        let window = f.window_ns();
        // `early` serves for 5 s, then the flow moves to `late` for good.
        for s in 1..=5u64 {
            f.serve(early, t0 + s * SEC, true);
        }
        let end = t0 + window * 3;
        let mut now = t0 + 5 * SEC;
        while now < end {
            now += SEC;
            f.serve(late, now, ((now - t0) / SEC) % 10 == 0);
            f.round(now);
            assert_eq!(
                f.ha_closes(),
                0,
                "#19026 Codex P1 #1 (minting={minting} early={early} late={late}): \
                 no HA close while worker {late} serves (t=t0+{}s)",
                (now - t0) / SEC
            );
        }
        assert!(f.shared_present(), "the live session's shared row survives");
        assert!(f.has_row(late), "the serving copy survives");
    }
}

/// Codex P1 #2: serving evidence lags (the ct-slice restamps every ~10 s);
/// traffic that resumes on another worker shortly before an idle copy's
/// window ends must not let that copy close the session. On bb9608f1a6 the
/// designated closer (queue 0) saw unchanged shared counters and closed.
#[test]
fn counter_lag_never_authorizes_a_close_19026() {
    let mut f = Fixture::new(1);
    let t0 = f.t0;
    f.activate(t0);
    let window = f.window_ns();
    // Nobody serves; just before worker 0's window ends, worker 1 starts
    // serving, but its restamp only lands after worker 0 crosses.
    let resume = t0 + window - 2 * SEC;
    f.rounds(t0, resume - SEC);
    let mut now = resume - SEC;
    let mut served_at = Vec::new();
    while now < t0 + window + 30 * SEC {
        now += SEC;
        f.serve(1, now, now >= t0 + window + 8 * SEC);
        served_at.push(now);
        f.round(now);
        assert_eq!(
            f.ha_closes(),
            0,
            "#19026 Codex P1 #2: lagging evidence authorized a close at t0+{}s",
            (now - t0) / SEC
        );
    }
    assert!(f.shared_present() && f.has_row(1), "the resumed flow is intact");
}

/// Codex P1 #3: the copy that would have closed is lost (its worker dies
/// after the activation); a genuinely idle session must still close exactly
/// once. On bb9608f1a6 the designated closer was the dead worker and no
/// survivor closed: the shared row and the peer's copy leaked.
#[test]
fn lost_closer_still_closes_exactly_once_19026() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    f.activate(t0);
    f.alive[0] = false; // queue 0 accepted the restore; worker 0 then died
    let horizon = f.idle_close_horizon();
    f.rounds(t0, horizon);
    assert_eq!(f.ha_closes(), 1, "#19026 Codex P1 #3: exactly one HA close");
    assert!(!f.shared_present(), "the shared row is retired");
    assert!(!f.has_row(1) && !f.has_row(2), "every surviving copy is gone");
}

/// Codex P1 #4: two prewarms of the same incarnation (the second with the
/// first closer's queue full) still produce exactly one Close, even when
/// every copy's expiry reads the shared row before any flush. On bb9608f1a6
/// two copies carried the closer bit and both closed.
#[test]
fn double_prewarm_still_closes_exactly_once_19026() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    f.activate(t0);
    {
        let mut full = f.workers[0].queue.lock().expect("queue");
        while crate::afxdp::worker_queue::push_bounded(&mut full, WorkerCommand::DeleteSynced(test_key()))
        {}
    }
    f.prewarm(t0 + SEC);
    f.workers[0].queue.lock().expect("queue").clear();
    f.apply_commands(t0 + SEC);
    let horizon = f.idle_close_horizon();
    f.rounds(t0 + SEC, horizon);
    assert_eq!(f.ha_closes(), 1, "#19026 Codex P1 #4: exactly one HA close");
    assert!(!f.shared_present());
}

/// The genuinely idle case through the real flush: one HA close, the shared
/// row retired, every copy gone, and nothing closes early.
#[test]
fn genuinely_idle_restored_session_closes_exactly_once_19026() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    f.activate(t0);
    let window = f.window_ns();
    f.rounds(t0, t0 + window - SEC);
    assert_eq!(f.ha_closes(), 0, "nothing closes inside the window");
    let horizon = f.idle_close_horizon();
    f.rounds(t0 + window - SEC, horizon);
    assert_eq!(f.ha_closes(), 1, "exactly one HA close");
    assert!(!f.shared_present());
    for w in 0..WORKERS {
        assert!(!f.has_row(w), "worker {w}'s copy is gone");
    }
}

/// Cell 3 (respawn, then activation): the respawn replay demotes the
/// promoted row to `WorkerLocalImport` replicas on every worker (#19030's
/// gap, out of scope here); the activation prewarm restores `SharedPromote`
/// on all of them. When the never-again-served session idles out, it closes
/// exactly once.
#[test]
fn respawn_then_activation_closes_exactly_once_19026() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    for queue in f.queues() {
        queue.lock().expect("queue").push_back(WorkerCommand::UpsertSynced(
            crate::afxdp::shared_ops::synced_replica_entry(&f.row),
        ));
    }
    f.apply_commands(t0 - SEC);
    for w in 0..WORKERS {
        assert_eq!(
            f.workers[w].table.entry_with_origin(&f.row.key).map(|(_, _, o)| o),
            Some(SessionOrigin::WorkerLocalImport),
            "FIXTURE: worker {w} holds only a replica after the respawn replay"
        );
    }
    f.activate(t0);
    let horizon = f.idle_close_horizon();
    f.rounds(t0, horizon);
    assert_eq!(f.ha_closes(), 1, "#19026: respawn + activation still closes exactly once");
    assert!(!f.shared_present());
}

// ---------------------------------------------------------------------------
// R14 review cells (findings F1-F4, F5(b)), ported from the review's
// table-level cells (`/var/worktrees/.cache/reviews/19026-R14-bb9608f1a6-cells.patch`)
// onto the production paths above so they compile, unchanged, at bb9608f1a6
// (where F1-F4 are RED) and at the folded head (GREEN). UDP rows reach the
// fence directly (no #18722 TCP node-evidence keep-alive in front of it).
// ---------------------------------------------------------------------------

/// Run 1 s rounds while `serving` serves the forward direction every second
/// from `from` (exclusive) to `to` (inclusive), restamping every 10 s of the
/// fixture clock (the ct-slice cadence), and assert no HA close in any round.
fn serve_rounds_without_close(f: &mut Fixture, serving: usize, from: u64, to: u64, cell: &str) {
    let mut now = from;
    while now < to {
        now += SEC;
        f.serve(serving, now, ((now - f.t0) / SEC) % 10 == 0);
        f.round(now);
        assert_eq!(
            f.ha_closes(),
            0,
            "{cell}: HA close while worker {serving} serves (t=t0+{}s)",
            (now - f.t0) / SEC
        );
    }
}

/// R14 F1: a copy that served briefly after the restore (the fabric-ingress
/// worker K while the other RG was still on the peer), then went idle
/// because the flow moved to another worker F, must never close F's live
/// session. When the flow later moves BACK to K, K's copy (kept, re-stamped
/// from the node's service) still serves it; once the flow idles the session
/// closes exactly once. RED at bb9608f1a6: K's served-since-install copy took
/// R3 at ~A+62 and closed.
#[test]
fn r14_served_then_moved_copy_must_not_close_live_session() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let (transient, serving) = (1usize, 2usize);
    for s in 1..=2u64 {
        f.serve(transient, t0 + s * SEC, true);
        f.round(t0 + s * SEC);
    }
    let last = t0 + 2 * f.window_ns();
    serve_rounds_without_close(&mut f, serving, t0 + 2 * SEC, last, "R14 F1");
    assert!(f.shared_present() && f.has_row(serving), "the live session is intact");
    // A 5 s gap (inside every window), then the flow moves back to K.
    f.rounds(last, last + 5 * SEC);
    assert_eq!(f.ha_closes(), 0, "R14 F1: no close in a 5 s gap");
    let back = last + 15 * SEC;
    serve_rounds_without_close(&mut f, transient, last + 5 * SEC, back, "R14 F1 (moved back)");
    assert!(f.has_row(transient), "K's kept copy serves the returned flow");
    f.restamp(transient);
    f.rounds(back, back + 3 * f.window_ns());
    assert_eq!(f.ha_closes(), 1, "R14 F1: the idle session then closes exactly once");
    assert!(!f.shared_present());
}

/// R14 F2: after the restore only the REVERSE direction is served (on a
/// worker that is not queue 0), then the session idles. It must close
/// exactly once (shared row, steering claims and the HA peer copy must not
/// leak). RED at bb9608f1a6: 0 closes.
#[test]
fn r14_reverse_only_served_session_still_closes_once() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let r = 1usize;
    for s in 1..=10u64 {
        f.serve_reverse(r, t0 + s * SEC, s % 5 == 0);
        f.round(t0 + s * SEC);
        assert_eq!(f.ha_closes(), 0, "no close while the reverse direction is served");
    }
    let horizon = t0 + 10 * SEC + 3 * f.window_ns();
    f.rounds(t0 + 10 * SEC, horizon);
    assert_eq!(
        f.ha_closes(),
        1,
        "R14 F2: a reverse-only-served restored session that went idle must close exactly once"
    );
    assert!(!f.shared_present(), "the shared row is retired");
    for w in 0..WORKERS {
        assert!(!f.has_row(w), "worker {w}'s copy is gone");
    }
}

/// Control twin for R14 F2: the same fixture with the FORWARD direction
/// served closes exactly once (the harness can see a close, so F2's 0 at
/// bb9608f1a6 is the rule, not the instrument). GREEN at both heads.
#[test]
fn r14_control_forward_served_session_closes_once() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let r = 1usize;
    for s in 1..=10u64 {
        f.serve(r, t0 + s * SEC, s % 5 == 0);
        f.round(t0 + s * SEC);
    }
    let horizon = t0 + 10 * SEC + 3 * f.window_ns();
    f.rounds(t0 + 10 * SEC, horizon);
    assert_eq!(f.ha_closes(), 1, "control: a forward-served restored session closes once");
    assert!(!f.shared_present());
}

/// R14 F4: the shared row advances only when the serving worker's ct-slice
/// restamps it (one evidence cadence). A first post-restore packet at +55 s
/// whose restamp lands at +65 s must not let an idle copy that crosses at
/// ~+61 s close the session. RED at bb9608f1a6: the closer (queue 0) read
/// the unchanged row at +61 s and closed.
#[test]
fn r14_closer_must_not_close_before_server_restamp_cadence() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let server = 2usize;
    f.rounds(t0, t0 + 54 * SEC);
    f.serve(server, t0 + 55 * SEC, false);
    let mut now = t0 + 54 * SEC;
    let quiet_end = t0 + 55 * SEC + f.window_ns();
    while now < quiet_end {
        now += SEC;
        if now == t0 + 65 * SEC {
            f.restamp(server); // the server's ct-slice reaches the row
        }
        f.round(now);
        assert_eq!(
            f.ha_closes(),
            0,
            "R14 F4: a close while the server forwarded at +55 s (t=t0+{}s)",
            (now - t0) / SEC
        );
    }
    assert!(f.shared_present() && f.has_row(server), "the served session is intact");
    f.rounds(quiet_end, quiet_end + 3 * f.window_ns());
    assert_eq!(f.ha_closes(), 1, "R14 F4: the idle session then closes exactly once");
}

/// R14 F3: the first activation prewarm runs while queue 0 is backlogged
/// (it refuses; a 24k-session prewarm pushes ~48k commands per 4096-deep
/// queue), the second (the session's other RG, or an RG flap) after it
/// drained. The never-served session still closes exactly once, even with
/// every copy's expiry reading the shared row before any flush. RED at
/// bb9608f1a6: the two prewarms designated two closers and both closed.
#[test]
fn r14_two_prewarms_under_backlog_still_close_exactly_once() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    {
        let mut full = f.workers[0].queue.lock().expect("queue");
        while crate::afxdp::worker_queue::push_bounded(&mut full, WorkerCommand::DeleteSynced(test_key()))
        {}
    }
    f.prewarm(t0);
    f.workers[0].queue.lock().expect("queue").clear();
    f.apply_commands(t0);
    f.activate(t0);
    let horizon = f.idle_close_horizon();
    f.rounds(t0, horizon);
    assert_eq!(f.ha_closes(), 1, "R14 F3: exactly one HA close after two prewarms");
    assert!(!f.shared_present());
}

/// Control for R14 F3: one prewarm under the same backlog (queue 0 never
/// gets the restore) closes exactly once. GREEN at both heads.
#[test]
fn r14_single_prewarm_under_backlog_closes_exactly_once() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    {
        let mut full = f.workers[0].queue.lock().expect("queue");
        while crate::afxdp::worker_queue::push_bounded(&mut full, WorkerCommand::DeleteSynced(test_key()))
        {}
    }
    f.prewarm(t0);
    f.workers[0].queue.lock().expect("queue").clear();
    f.apply_commands(t0);
    let horizon = f.idle_close_horizon();
    f.rounds(t0, horizon);
    assert_eq!(f.ha_closes(), 1, "control: one prewarm closes exactly once");
    assert!(!f.shared_present());
}

/// R14 F5(b): a close-fenced restored TCP/1723 copy (here: its shared row was
/// replaced by a new incarnation, fenced at both heads) must not fan
/// `ForgetPptpControlChannel` out to the sibling workers, one of which still
/// serves the control channel. GREEN at both heads; RED with housekeeping's
/// `close_fenced` skip removed (R14 mutant M2, which no other cell kills).
#[test]
fn r14_fenced_pptp_control_copy_does_not_forget_sibling_channel() {
    let pptp_key = SessionKey {
        dst_port: crate::session::pptp_control::PPTP_CONTROL_PORT,
        ..test_key()
    };
    let mut f = Fixture::new(0);
    f.row.key = pptp_key.clone();
    // Handshake not yet Established on the wire, as R14's cell: keeps the
    // #18722 TCP node-evidence keep-alive out of the way, so the copy idles.
    f.row.tcp_handshake_state = 0;
    let install_ns = 10_000 * SEC;
    let mut sessions = SessionTable::new();
    assert!(
        sessions.upsert_synced_with_origin(f.row.clone().into_session_install(install_ns), false),
        "FIXTURE: restored copy"
    );
    let mut replaced = f.row.clone();
    replaced.session_id = f.row.session_id + 1;
    crate::afxdp::shared_ops::publish_shared_session(
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &replaced,
    );
    let now_ns = install_ns + 3 * 3_600 * SEC;
    let shared_runtime = f.runtime.reader();
    let worker_command_queues = crate::afxdp::types::WorkerCommandQueues::new(BTreeMap::new());
    let serving_sibling: Arc<Mutex<VecDeque<WorkerCommand>>> = Arc::new(Mutex::new(VecDeque::new()));
    let peers = vec![serving_sibling.clone()];
    let mut barrier = super::housekeeping::ClosePermitBarrier::default();
    let mut flushed: Vec<SessionDelta> = Vec::new();
    let mut flush_deltas =
        |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, deltas: &[SessionDelta]| {
            flushed.extend(deltas.iter().cloned());
        };
    let _ = run_session_housekeeping(
        &mut sessions,
        &mut Vec::new(),
        &WorkerBindingLookup::default(),
        &ForwardingState::default(),
        &ha_at(now_ns),
        now_ns,
        now_ns / SEC,
        &f.rg_epochs,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        0,
        &worker_command_queues,
        &f.pptp,
        None,
        &peers,
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &shared_runtime,
        &mut false,
        &mut Vec::new(),
        &mut Vec::new(),
        &mut barrier,
        &mut flush_deltas,
    );
    assert!(sessions.entry_with_origin(&pptp_key).is_none(), "FIXTURE: the fenced copy left");
    assert_eq!(
        flushed.iter().filter(|d| d.kind == SessionDeltaKind::Close).count(),
        0,
        "FIXTURE: the copy was close-fenced"
    );
    let forgets = serving_sibling
        .lock()
        .expect("queue")
        .iter()
        .filter(|c| matches!(c, WorkerCommand::ForgetPptpControlChannel { .. }))
        .count();
    assert_eq!(
        forgets, 0,
        "#19026 R14 F5(b): a close-fenced TCP/1723 copy must not forget the sibling's live PPTP channel"
    );
}

// ---------------------------------------------------------------------------
// Fold cycle 2: Codex R15 and R14 (2e7dfd349b) cells, ported onto this
// fixture so they compile unchanged against 2e7dfd349b (where the claimant-exit
// and resume-inside-hold cells are RED) and the cycle-2 head (GREEN).
// ---------------------------------------------------------------------------

/// Hold the session's tuple permit, run until a claim winner's Close is
/// parked behind it, and return that worker (the claim is detected by the
/// parked Close: 2e7dfd349b removed the shared row at the claim, cycle 2 only
/// marks it). `None` if nobody claimed within the horizon.
fn run_until_a_close_parks(f: &mut Fixture) -> (Option<usize>, u64) {
    let t0 = f.t0;
    let horizon = f.idle_close_horizon();
    let mut now = t0;
    while now < horizon {
        now += SEC;
        f.round(now);
        if let Some(w) = (0..WORKERS).find(|&w| !f.workers[w].barrier.parked.is_empty()) {
            return (Some(w), now);
        }
    }
    (None, now)
}

/// Codex R15 P1#2: the claim winner cannot take its tuple permit, parks its
/// Close, and exits (its loop-local state dies) before the permit returns.
/// The surviving copies must still close the session exactly once. On
/// 2e7dfd349b the claim had already removed the shared row, every survivor
/// read that as "closed" and dropped silently: 0 Closes ever flushed.
#[test]
fn claimant_exit_does_not_lose_the_close_19026() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([f.row.key.clone()])
        .expect("hold the session's close permit");
    let (winner, now) = run_until_a_close_parks(&mut f);
    let winner = winner.expect("FIXTURE: a claim winner parked its blocked Close");
    assert_eq!(f.ha_closes(), 0, "FIXTURE: no Close delivered yet");
    f.alive[winner] = false;
    f.workers[winner].barrier = Default::default();
    f.workers[winner].table = SessionTable::new();
    drop(held);
    f.rounds(now, now + 240 * SEC);
    assert_eq!(
        f.ha_closes(),
        1,
        "#19026 Codex R15 P1#2: the survivors must finish the claimed Close exactly once"
    );
    assert_eq!(f.rt_flow_closes(f.row.session_id), 1, "one RT_FLOW SESSION_CLOSE");
    assert!(!f.shared_present(), "the shared row is retired by the delivered Close");
    for w in 0..WORKERS {
        if f.alive[w] {
            assert!(!f.has_row(w), "surviving worker {w}'s copy is gone");
        }
    }
}

/// Control twin: the same parked Close, but the claimant survives; its own
/// Close flushes once the permit returns, exactly once (GREEN at both heads).
#[test]
fn surviving_claimant_closes_once_after_its_permit_returns_19026() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([f.row.key.clone()])
        .expect("hold the session's close permit");
    let (winner, now) = run_until_a_close_parks(&mut f);
    assert!(winner.is_some(), "FIXTURE: a claim winner parked its blocked Close");
    drop(held);
    f.rounds(now, now + 240 * SEC);
    assert_eq!(f.ha_closes(), 1, "control: the claimant's own Close, exactly once");
    assert!(!f.shared_present());
}

/// R14 (2e7dfd349b re-review) Q2: reverse-only service sustained across
/// THREE windows on a non-zero worker (restamped on the ct-slice cadence)
/// never closes the session; once it idles, it closes exactly once and every
/// copy is gone.
#[test]
fn r14b_reverse_only_live_for_three_windows_never_closes() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let window = f.window_ns();
    let r = 2usize;
    let live_end = t0 + 3 * window;
    let mut now = t0;
    while now < live_end {
        now += SEC;
        f.serve_reverse(r, now, ((now - t0) / SEC) % 10 == 0);
        f.round(now);
        assert_eq!(
            f.ha_closes(),
            0,
            "R14 Q2: HA close while worker {r} serves the reverse direction (t=t0+{}s)",
            (now - t0) / SEC
        );
    }
    for w in 0..WORKERS {
        assert!(f.has_row(w), "R14 Q2: worker {w}'s copy is kept while the node serves");
    }
    f.rounds(live_end, live_end + 3 * window);
    assert_eq!(f.ha_closes(), 1, "R14 Q2: the idle session then closes exactly once");
    assert!(!f.shared_present());
    for w in 0..WORKERS {
        assert!(!f.has_row(w), "worker {w}'s copy is gone");
    }
}

/// R14 G1: during the fence hold a crossed copy stays in the table but is
/// fail-closed for lookups. A forward packet in that window takes the
/// first-packet path and REPLACES the copy with a new local session; every
/// other copy then finds the shared row replaced and stays silent. The old,
/// idled-out incarnation must still get its one Close. 2e7dfd349b: 0.
#[test]
fn r14b_forward_resume_inside_hold_still_closes_old_session() {
    r14b_forward_resume_after(4);
}

/// TRUE twin of the cell above: the same resume and install, after the hold
/// (the old incarnation already claimed and closed). Exactly one Close.
#[test]
fn r14b_twin_forward_resume_after_hold_closes_old_session_once() {
    r14b_forward_resume_after(30);
}

fn r14b_forward_resume_after(secs_past_window: u64) {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    let window = f.window_ns();
    let old_id = f.row.session_id;
    let resume = t0 + window + secs_past_window * SEC;
    f.rounds(t0, resume);
    let key = f.row.key.clone();
    let w = 2usize;
    if f.has_row(w) {
        assert_eq!(f.ha_closes(), 0, "FIXTURE: nothing closed yet (copies held)");
        assert!(
            f.workers[w].table.lookup_with_origin(&key, resume, 0).is_none(),
            "FIXTURE premise: the held copy is fail-closed for lookups"
        );
    }
    // The first-packet path on worker w: a new local session for the tuple
    // (replacing the crossed row, if any), published and replicated.
    let (decision, metadata) = (f.row.decision, f.row.metadata.clone());
    assert!(
        f.workers[w].table.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            resume,
            PROTO_UDP,
            0,
        ),
        "FIXTURE: the new session installs over the crossed copy"
    );
    let fresh = f.workers[w].table.synced_entry_for(&key).expect("new row");
    assert_ne!(fresh.session_id, old_id, "FIXTURE: a new incarnation");
    crate::afxdp::shared_ops::publish_shared_session(
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &fresh,
    );
    for (p, q) in f.queues().iter().enumerate() {
        if p != w {
            q.lock().expect("queue").push_back(WorkerCommand::UpsertSynced(
                crate::afxdp::shared_ops::synced_replica_entry(&fresh),
            ));
        }
    }
    // Well before the new session's own idle close (resume + window).
    f.rounds(resume, resume + 40 * SEC);
    let old_closes = f.rt_flow_closes(old_id);
    assert_eq!(
        old_closes, 1,
        "R14 G1: the idled-out old incarnation got {old_closes} Closes after a resume \
         {secs_past_window} s past its window"
    );
}

/// Codex R15 P1#1 (RESIDUAL, also on master; not fixed by #19026). A copy
/// installed 20 s late (a later prewarm reached a refusing worker) starts
/// serving at +73 s, inside an idle copy's hold; its first restamp is due at
/// +82 s, so at +76 s the idle copy still reads unchanged evidence, wins the
/// claim and closes the live session. The claim synchronizes with
/// PUBLICATION, not packet admission; no fixed hold closes that window.
/// Tracked in #19046; this cell is the reproduction and stays ignored
/// until that lands.
#[test]
#[ignore = "residual tracked in #19046 (Codex R15 P1#1); fails by design"]
fn late_service_inside_the_hold_must_survive_19026() {
    let mut f = Fixture::with_protocol(0, PROTO_UDP);
    let t0 = f.t0;
    f.activate(t0);
    f.workers[2].table = SessionTable::new();
    f.workers[2].table.set_session_id_namespace(0, 2);
    assert!(f.workers[2].table.upsert_synced_with_origin(
        f.row.clone().into_session_install(t0 + 20 * SEC),
        false
    ));
    f.rounds(t0, t0 + 72 * SEC);
    assert_eq!(f.ha_closes(), 0, "FIXTURE: the hold has not closed");
    for s in 73..=80u64 {
        f.serve(2, t0 + s * SEC, false);
        f.round(t0 + s * SEC);
        assert_eq!(
            f.ha_closes(),
            0,
            "Codex R15 P1#1: live service at +{s}s must survive until the +82s restamp"
        );
    }
}
