// #19063 (Part 2a): restored `SharedPromote` copies never close a session
// this node still serves.
//
// The cells drive several workers through the PRODUCTION paths end to end:
// - install: the RG-activation prewarm
//   (`prewarm_reverse_synced_sessions_for_owner_rgs`) into real per-worker
//   command queues, applied by `apply_worker_commands`;
// - service: the read path (`lookup_with_origin` + `account_packet`) and the
//   ct-slice restamp (`restamp_shared_packet_counts_batch`, identity-bound);
// - expiry: `run_session_housekeeping` (which builds the production
//   `ExpireHaContext`) on EVERY worker in the same instant;
// - close: the REAL flush (`flush_session_deltas_loop`) on a connected event
//   stream, then the siblings' command queues.
//
// `ha_closes` counts the type-2 HA session-sync CLOSE frames delivered for
// the tuple, and `rt_flow_closes` the type-14 RT_FLOW SESSION_CLOSE frames
// carrying the session's id. Part 2a claims NO exactly-once: an idle restored
// session closes at most once per copy (#19068).
//
// The fixture is cycle 3's (`fix/19026-promote-prewarm-close` at 973b11b0d9)
// without its directory, so the RED runs at Part 1 use the same harness.

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
    /// This worker's production ct-slice state (`run_ct_slice`): cursor,
    /// cycle start, last slice, volume high water, established cursor.
    ct: (usize, u64, u64, u64, usize),
    ct_pending: Option<super::ct_slice::PendingStageCountsEmission>,
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
        Self::with_key(
            minting_worker,
            SessionKey {
                protocol,
                ..test_key()
            },
        )
    }

    /// The same row on `key` (IPv4 or IPv6).
    fn with_key(minting_worker: u64, key: SessionKey) -> Self {
        let protocol = key.protocol;
        let req = crate::SessionSyncRequest {
            operation: "upsert".to_string(),
            addr_family: key.addr_family,
            protocol,
            src_ip: key.src_ip.to_string(),
            dst_ip: key.dst_ip.to_string(),
            src_port: key.src_port,
            dst_port: key.dst_port,
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
        row.key = key;
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
        let indexes = SharedSessionOwnerRgIndexes::default();
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
                    ct: (0, 0, 0, 0, 0),
                    ct_pending: None,
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
            indexes,
            recent: Arc::new(Mutex::new(VecDeque::new())),
            event_stream: Some(event_handle),
            event_rx,
            frames: Vec::new(),
            runtime: RuntimeViewChannel::default(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            pptp: crate::session::pptp_control::PptpControlInbox::default(),
            forwarding: fence_forwarding_state(),
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
                // #19063: the source incarnation (identity-bound evidence).
                table.session_id_for(key),
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

/// The split-RG forwarding fixture plus an IPv6 LAN route and the client's
/// IPv6 neighbour, so a v6 restored row resolves exactly like the v4 one.
fn fence_forwarding_state() -> ForwardingState {
    let mut forwarding = test_forwarding_state_split_rgs();
    forwarding.connected_v6.push(ConnectedRouteV6 {
        prefix: PrefixV6::from_net(
            Ipv6Net::new("2001:559:8585:bf01::".parse().expect("v6"), 64).expect("v6 net"),
        ),
        host: "2001:559:8585:bf01::".parse().expect("v6"),
        scope: 0,
        ifindex: 6,
        tunnel_endpoint_id: 0,
        table: "inet6.0".to_string(),
    });
    forwarding.neighbors.insert(
        (6, "2001:559:8585:bf01::102".parse().expect("v6")),
        NeighborEntry {
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
        },
    );
    forwarding
}

fn udp_v4_key() -> SessionKey {
    SessionKey {
        protocol: PROTO_UDP,
        ..test_key()
    }
}

fn udp_v6_key() -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET6 as u8,
        protocol: PROTO_UDP,
        src_ip: "2001:559:8585:bf01::102".parse().expect("v6"),
        dst_ip: "2001:559:8585:80::200".parse().expect("v6"),
        ..test_key()
    }
}

fn icmp_v4_key() -> SessionKey {
    SessionKey {
        protocol: crate::ip_proto::PROTO_ICMP,
        ..test_key()
    }
}

/// HA map with every RG inactive: a whole-node standby.
fn ha_inactive(now_ns: u64) -> BTreeMap<i32, HAGroupRuntime> {
    let mut ha = ha_at(now_ns);
    for group in ha.values_mut() {
        group.active = false;
    }
    ha
}

impl Fixture {
    /// One round on a whole-node standby (no RG forwarded here): the same
    /// housekeeping and flush, with `ha_inactive`.
    fn standby_round(&mut self, now_ns: u64) {
        let ha = ha_inactive(now_ns);
        let queues = self.queues();
        let by_id: BTreeMap<u32, Arc<Mutex<VecDeque<WorkerCommand>>>> = queues
            .iter()
            .enumerate()
            .map(|(w, q)| (w as u32, q.clone()))
            .collect();
        let command_queues = crate::afxdp::types::WorkerCommandQueues::new(by_id);
        let shared_runtime = self.runtime.reader();
        for w in 0..WORKERS {
            let peers: Vec<_> = queues
                .iter()
                .enumerate()
                .filter(|(p, _)| *p != w)
                .map(|(_, q)| q.clone())
                .collect();
            let worker = &mut self.workers[w];
            let mut discard =
                |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, _: &[SessionDelta]| {};
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
                &mut discard,
            );
        }
    }

    /// Serve `w` forward every second from `from` (exclusive) to `to`
    /// (inclusive), restamping every 10 s of fixture time (the ct-slice
    /// cadence), asserting no Close of the session in any round.
    fn serve_without_close(&mut self, w: usize, reverse: bool, from: u64, to: u64, cell: &str) {
        let id = self.row.session_id;
        let mut now = from;
        while now < to {
            now += SEC;
            let restamp = ((now - self.t0) / SEC) % 10 == 0;
            if reverse {
                self.serve_reverse(w, now, restamp);
            } else {
                self.serve(w, now, restamp);
            }
            self.round(now);
            assert_eq!(
                (self.ha_closes(), self.rt_flow_closes(id)),
                (0, 0),
                "{cell}: a Close of the session worker {w} serves (t=t0+{}s)",
                (now - self.t0) / SEC
            );
        }
    }
}

// ---------------------------------------------------------------------------
// End-to-end cells
// ---------------------------------------------------------------------------

/// #19063 core: after an RG activation the prewarm restores the session on
/// every worker; one worker serves it, the others' copies cross their idle
/// deadline. No copy may close the live session: no HA Close, no RT_FLOW
/// Close, the shared row and every copy survive. On master (and Part 1) the
/// idle copies close at the first crossing and their key-keyed sibling
/// `DeleteSynced` removes the serving copy (the udp acceptance pair's live
/// closes). IPv4 and IPv6 UDP, and ICMP (the live pings of #19026).
fn served_elsewhere_never_closes(key: SessionKey) {
    let mut f = Fixture::with_key(0, key.clone());
    let t0 = f.t0;
    f.activate(t0);
    let end = t0 + 3 * f.window_ns();
    f.serve_without_close(1, false, t0, end, &format!("forward {key:?}"));
    assert!(f.shared_present(), "the live session's shared row survives ({key:?})");
    for w in 0..WORKERS {
        assert!(f.has_row(w), "worker {w}'s copy survives ({key:?})");
    }
}

#[test]
fn restored_copies_never_close_a_session_another_worker_serves_19063() {
    served_elsewhere_never_closes(udp_v4_key());
}

#[test]
fn restored_copies_never_close_a_v6_session_another_worker_serves_19063() {
    served_elsewhere_never_closes(udp_v6_key());
}

#[test]
fn restored_copies_never_close_an_icmp_session_another_worker_serves_19063() {
    served_elsewhere_never_closes(icmp_v4_key());
}

/// The same with only the REVERSE direction served, on a worker that did
/// not mint the row. Reverse service reaches the node evidence through the
/// restamp's either-direction packet TIME (the reverse half's
/// `last_packet_seen_ns`), not through `account_packet`'s counter fold.
#[test]
fn restored_copies_never_close_a_session_served_only_in_reverse_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let end = t0 + 3 * f.window_ns();
    f.serve_without_close(2, true, t0, end, "reverse only");
    assert!(f.shared_present());
    for w in 0..WORKERS {
        assert!(f.has_row(w), "worker {w}'s copy survives");
    }
}

/// R14 F4 (restamp lag): the first post-restore packet arrives at +55 s on
/// worker 2, and its restamp lands only at +65 s, after the idle copies
/// cross at about +61 s. The hold covers that lag: no Close.
#[test]
fn restamp_lag_inside_the_hold_never_closes_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let id = f.row.session_id;
    let server = 2usize;
    f.rounds(t0, t0 + 54 * SEC);
    f.serve(server, t0 + 55 * SEC, false);
    let mut now = t0 + 55 * SEC;
    let end = t0 + 55 * SEC + f.window_ns();
    while now < end {
        now += SEC;
        if now == t0 + 65 * SEC {
            f.restamp(server);
        }
        f.round(now);
        assert_eq!(
            (f.ha_closes(), f.rt_flow_closes(id)),
            (0, 0),
            "R14 F4: lagging evidence must not let an idle copy close (t=t0+{}s)",
            (now - t0) / SEC
        );
    }
    assert!(f.shared_present() && f.has_row(server));
}

/// The reverse twin of the restamp-lag cell: the only packet is a REPLY at
/// +55 s (worker 2), published at +65 s. The node evidence carries it only
/// through the restamp's either-direction packet TIME (the reverse half's
/// `last_packet_seen_ns`), so an idle copy that crosses at about +61 s must
/// keep the session until that packet's own window ends.
#[test]
fn restamp_lag_of_a_reply_inside_the_hold_never_closes_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let id = f.row.session_id;
    let server = 2usize;
    f.rounds(t0, t0 + 54 * SEC);
    f.serve_reverse(server, t0 + 55 * SEC, false);
    let mut now = t0 + 55 * SEC;
    let end = t0 + 55 * SEC + f.window_ns();
    while now < end {
        now += SEC;
        if now == t0 + 65 * SEC {
            f.restamp(server);
        }
        f.round(now);
        assert_eq!(
            (f.ha_closes(), f.rt_flow_closes(id)),
            (0, 0),
            "a reply's lagging evidence must not let an idle copy close (t=t0+{}s)",
            (now - t0) / SEC
        );
    }
    assert!(f.shared_present() && f.has_row(server));
}

/// A genuinely idle restored session still closes, through master's
/// ordinary expiry Close, only after its window plus the hold, and leaves
/// nothing behind. NOT exactly once: every copy that crosses in the same
/// pass emits (at most one per copy; #19068).
#[test]
fn an_idle_restored_session_closes_after_the_hold_and_leaves_nothing_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let id = f.row.session_id;
    let window = f.window_ns();
    // The copies cross at about the window; the hold keeps them at least
    // one evidence cadence (12.8 s at the default slab) past it.
    f.rounds(t0, t0 + window + 10 * SEC);
    assert_eq!(
        (f.ha_closes(), f.rt_flow_closes(id)),
        (0, 0),
        "no Close inside the window plus the hold"
    );
    let horizon = f.idle_close_horizon();
    f.rounds(t0 + window + 10 * SEC, horizon);
    let (ha, rt) = (f.ha_closes(), f.rt_flow_closes(id));
    assert!((1..=WORKERS).contains(&ha), "HA Closes for the key: {ha}, want 1..={WORKERS}");
    assert!((1..=WORKERS).contains(&rt), "RT_FLOW Closes of A: {rt}, want 1..={WORKERS}");
    assert!(!f.shared_present(), "the shared row is retired");
    for w in 0..WORKERS {
        assert!(!f.has_row(w), "worker {w}'s copy is gone");
    }
}

/// Fence scope: on a whole-node standby (no RG forwarded here) the fence
/// does not run; the copy follows the standby arms (master behaviour until
/// #19065 routes them through the standby HOLD). The cell checks the fence's
/// scope only (no fence hold is ever armed), so it survives #19065.
#[test]
fn the_fence_does_not_run_on_a_whole_node_standby_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let key = f.row.key.clone();
    let horizon = t0 + 2 * f.window_ns();
    let mut now = t0;
    while now < horizon {
        now += SEC;
        f.standby_round(now);
        for w in 0..WORKERS {
            assert!(
                f.workers[w].table.promote_fence_hold_for(&key).is_none(),
                "worker {w}: the fence armed a hold off-RG (t=t0+{}s)",
                (now - t0) / SEC
            );
        }
    }
}

/// RESIDUAL (#19046 class): the hold is an ESTIMATE of node-wide
/// publication lag (the closing worker's slab-based cadence), not a bound.
/// A restamp that lands after the hold ends (an unequal cadence, a pending
/// traversal, a stalled publisher) closes a live session. The assertion is
/// the CORRECT outcome; it fails today and stays ignored with its issue.
#[test]
#[ignore = "residual: evidence published after the hold ends (#19046 class)"]
fn evidence_published_after_the_hold_still_keeps_the_session_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let id = f.row.session_id;
    let server = 2usize;
    f.rounds(t0, t0 + 54 * SEC);
    f.serve(server, t0 + 55 * SEC, false);
    let mut now = t0 + 55 * SEC;
    while now < t0 + 100 * SEC {
        now += SEC;
        if now == t0 + 85 * SEC {
            f.restamp(server);
        }
        f.round(now);
    }
    assert_eq!((f.ha_closes(), f.rt_flow_closes(id)), (0, 0));
}

/// RESIDUAL (stated, G1-lite dropped): a forward resume that installs B over
/// a held copy drops that copy's A silently (master's `Replace`). With no
/// other copy left to close A, A's RT_FLOW record is lost. The assertion is
/// the CORRECT outcome; ignored with #19068.
#[test]
#[ignore = "residual: G1 replacement record (#19068)"]
fn a_forward_resume_over_a_held_single_copy_keeps_the_old_record_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let key = f.row.key.clone();
    let id = f.row.session_id;
    for w in 1..WORKERS {
        f.workers[w].table.delete(&key);
    }
    let window = f.window_ns();
    f.rounds(t0, t0 + window + 3 * SEC);
    assert!(
        f.workers[0].table.promote_fence_hold_for(&key).is_some(),
        "FIXTURE: the single copy is held"
    );
    let now = t0 + window + 4 * SEC;
    assert!(f.workers[0].table.install_with_protocol_with_origin(
        key.clone(),
        f.row.decision,
        f.row.metadata.clone(),
        SessionOrigin::ForwardFlow,
        now,
        PROTO_UDP,
        0,
    ));
    let fresh = f.workers[0].table.synced_entry_for(&key).expect("B");
    crate::afxdp::shared_ops::publish_shared_session(
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &fresh,
    );
    f.rounds(now, now + 3 * window);
    assert_eq!(f.rt_flow_closes(id), 1, "A's RT_FLOW record");
}

// ---------------------------------------------------------------------------
// Unit cells on the fence step and the identity-bound restamp
// ---------------------------------------------------------------------------

const CADENCE: u64 = 13 * SEC;
const SESSION_GC_INTERVAL_NS: u64 = crate::session::SESSION_GC_INTERVAL_NS;
const WINDOW: u64 = 60 * SEC;

fn fence_ctx<'a>(
    shared_row: &'a dyn Fn(&SessionKey) -> Option<crate::session::SharedRowIdentity>,
    forwards: &'a dyn Fn(i32) -> bool,
    epoch: &'a dyn Fn(i32) -> u32,
    node_served: &'a dyn Fn(&SessionKey) -> crate::session::NodeServedEvidence,
) -> crate::session::ExpireHaContext<'a> {
    crate::session::ExpireHaContext {
        node_active: true,
        forwards_rg: forwards,
        epoch_of: epoch,
        ceiling_mult: crate::session::STALE_SYNCED_CEILING_MULT,
        ceiling_abs_ns: crate::session::STALE_SYNCED_CEILING_ABS_NS,
        node_served,
        shared_row,
        fence_evidence_cadence_ns: CADENCE,
    }
}

fn identity(session_id: u64, packets: u64, last_served_ns: u64) -> crate::session::SharedRowIdentity {
    crate::session::SharedRowIdentity {
        session_id,
        packets,
        last_served_ns,
    }
}

/// Codex r2 P1 (reverse half): this copy's own either-direction service is
/// read FIRST, so a shared row that is absent or names another incarnation
/// cannot override it. With the copy idle, those rows close it (master's
/// path).
#[test]
fn own_service_keeps_a_copy_whatever_the_shared_row_says_19063() {
    let key = udp_v4_key();
    let (forwards, epoch) = (|_: i32| true, |_: i32| 0u32);
    let served = |_: &SessionKey| crate::session::NodeServedEvidence::default();
    let now = 1_000 * SEC;
    let own_recent = now - 5 * SEC;
    let own_stale = now - 2 * WINDOW;
    let absent = |_: &SessionKey| None;
    let replaced = |_: &SessionKey| Some(identity(99, 10, now));
    for (name, shared) in [
        ("absent", &absent as &dyn Fn(&SessionKey) -> Option<_>),
        ("replaced", &replaced as &dyn Fn(&SessionKey) -> Option<_>),
    ] {
        let ha = fence_ctx(shared, &forwards, &epoch, &served);
        let mut table = SessionTable::new();
        assert_eq!(
            table.promote_fence_step(&ha, &key, 7, own_stale, own_recent, WINDOW, now),
            crate::session::PromoteFence::KeepAlive {
                last_seen_ns: own_recent
            },
            "{name}: own service keeps the copy"
        );
        assert_eq!(
            table.promote_fence_step(&ha, &key, 7, own_stale, own_stale, WINDOW, now),
            crate::session::PromoteFence::Close,
            "{name}: an idle copy closes"
        );
    }
}

/// R14 r2 A, and the coordinator's "tie a hold to what it was armed under".
/// A hold closes only on the `last_seen_ns` AND the evidence it was armed
/// under. A re-stamped row (an HA-transition refresh, SELF-HEAL, a
/// keep-alive) gets a FULL fresh hold, and so does any change of
/// `last_served_ns`, even one still outside the window.
#[test]
fn a_hold_closes_only_on_its_own_anchor_and_evidence_19063() {
    let key = udp_v4_key();
    let (forwards, epoch) = (|_: i32| true, |_: i32| 0u32);
    let served = |_: &SessionKey| crate::session::NodeServedEvidence::default();
    let t = 1_000 * SEC;
    let idle_since = t - 2 * WINDOW;
    let armed = identity(7, 24, idle_since);
    let same = |_: &SessionKey| Some(armed);
    let restamped_stale = |_: &SessionKey| Some(identity(7, 24, idle_since + SEC));
    let ha = fence_ctx(&same, &forwards, &epoch, &served);
    let mut table = SessionTable::new();
    let until = match table.promote_fence_step(&ha, &key, 7, idle_since, 0, WINDOW, t) {
        crate::session::PromoteFence::Defer { until_ns } => until_ns,
        other => panic!("FIXTURE: an idle copy is held first, got {other:?}"),
    };
    assert_eq!(until, t + CADENCE + SESSION_GC_INTERVAL_NS);
    let after = until + SEC;

    // The row was re-stamped while held (anchor moved): a full fresh hold.
    let mut moved = SessionTable::new();
    let _ = moved.promote_fence_step(&ha, &key, 7, idle_since, 0, WINDOW, t);
    assert_eq!(
        moved.promote_fence_step(&ha, &key, 7, idle_since + 30 * SEC, 0, WINDOW, after),
        crate::session::PromoteFence::Defer {
            until_ns: after + CADENCE + SESSION_GC_INTERVAL_NS
        },
        "R14 A: a re-stamped row never inherits an expired hold"
    );

    // A restamp landed (last_served changed, still outside the window).
    let ha_restamped = fence_ctx(&restamped_stale, &forwards, &epoch, &served);
    let mut changed = SessionTable::new();
    let _ = changed.promote_fence_step(&ha, &key, 7, idle_since, 0, WINDOW, t);
    assert_eq!(
        changed.promote_fence_step(&ha_restamped, &key, 7, idle_since, 0, WINDOW, after),
        crate::session::PromoteFence::Defer {
            until_ns: after + CADENCE + SESSION_GC_INTERVAL_NS
        },
        "changed evidence arms a fresh hold"
    );

    // Control: the same anchor and the same evidence close.
    assert_eq!(
        table.promote_fence_step(&ha, &key, 7, idle_since, 0, WINDOW, after),
        crate::session::PromoteFence::Close
    );
    assert!(table.promote_fence_hold_for(&key).is_none(), "the hold is dropped");
}


/// Codex r2 P2#4: the restamp's serving evidence is bound to the source
/// incarnation. A delayed restamp of the old incarnation A (another
/// worker's copy) must not stamp A's service onto its replacement B under
/// the same key, in either restamp writer; B's own restamp does.
#[test]
fn a_delayed_old_incarnation_restamp_never_stamps_the_replacement_19063() {
    let f = Fixture::with_key(0, udp_v4_key());
    let key = f.row.key.clone();
    let a = f.row.session_id;
    let mut b_row = f.row.clone();
    b_row.session_id = a + 1;
    crate::afxdp::shared_ops::publish_shared_session(
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &b_row,
    );
    let last_served = || {
        crate::afxdp::shared_ops::lock_shared_recover(&f.shared_sessions)
            .get(&key)
            .map(|row| (row.session_id, row.last_served_ns))
    };
    assert_eq!(last_served(), Some((a + 1, 0)), "FIXTURE: B starts from its own value");
    let nat = crate::nat::NatDecision::default();
    crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
        &f.shared_sessions,
        &f.shared_wire,
        0,
        &[(key.clone(), nat, 50, 50, 777 * SEC, a)],
    );
    crate::afxdp::shared_ops::restamp_shared_packet_counts(
        &f.shared_sessions,
        &f.shared_wire,
        &key,
        nat,
        0,
        a,
        778 * SEC,
        51,
        51,
    );
    assert_eq!(last_served(), Some((a + 1, 0)), "A's restamps leave B's evidence alone");
    crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
        &f.shared_sessions,
        &f.shared_wire,
        0,
        &[(key.clone(), nat, 52, 52, 800 * SEC, a + 1)],
    );
    assert_eq!(last_served(), Some((a + 1, 800 * SEC)), "B's own restamp stamps it");
    crate::afxdp::shared_ops::restamp_shared_packet_counts(
        &f.shared_sessions,
        &f.shared_wire,
        &key,
        nat,
        0,
        a + 1,
        801 * SEC,
        53,
        53,
    );
    assert_eq!(last_served(), Some((a + 1, 801 * SEC)), "and so does the single-pair writer");
}

/// Publication keeps the serving evidence monotonic per incarnation: a
/// same-incarnation republication carrying a smaller `last_served_ns` keeps
/// the larger value, and a new incarnation starts from its own.
#[test]
fn republication_keeps_last_served_per_incarnation_19063() {
    let f = Fixture::with_key(0, udp_v4_key());
    let key = f.row.key.clone();
    let read = || {
        crate::afxdp::shared_ops::lock_shared_recover(&f.shared_sessions)
            .get(&key)
            .map(|row| row.last_served_ns)
    };
    let publish = |row: &SyncedSessionEntry| {
        crate::afxdp::shared_ops::publish_shared_session(
            &f.shared_sessions,
            &f.shared_nat,
            &f.shared_wire,
            &f.indexes,
            row,
        )
    };
    let mut served = f.row.clone();
    served.last_served_ns = 65 * SEC;
    publish(&served);
    assert_eq!(read(), Some(65 * SEC));
    publish(&f.row);
    assert_eq!(read(), Some(65 * SEC), "same-incarnation republication keeps it");
    let mut next = f.row.clone();
    next.session_id += 1;
    publish(&next);
    assert_eq!(read(), Some(0), "a new incarnation starts from its own");
}

// ---------------------------------------------------------------------------
// Fold cycle 1 (reviews of 9a599d0900): the production evidence publisher
// ---------------------------------------------------------------------------

impl Fixture {
    /// Worker `w`'s production ct-slice (`run_ct_slice`, which runs at its
    /// own cadence and publishes the evidence), instead of `Fixture::restamp`.
    fn ct_slice(&mut self, w: usize, now_ns: u64) {
        let mut forwarding = Arc::new(self.forwarding.clone());
        let fabrics = Arc::new(arc_swap::ArcSwap::from_pointee(Vec::<FabricLink>::new()));
        let wg_queues = Arc::new(arc_swap::ArcSwap::from_pointee(std::collections::BTreeMap::new()));
        let mut wg_batch = crate::afxdp::wg_uncovered_forward::WgUncoveredInjectedBatch::new();
        let worker = &mut self.workers[w];
        let (cursor, cycle_start, last_slice, high_water, est_cursor) = &mut worker.ct;
        super::ct_slice::run_ct_slice(
            &mut worker.table,
            &mut forwarding,
            now_ns,
            -1,
            -1,
            cursor,
            cycle_start,
            last_slice,
            high_water,
            &fabrics,
            &wg_queues,
            &mut wg_batch,
            w as u32,
            &self.shared_sessions,
            &self.shared_wire,
            &self.indexes,
            est_cursor,
            &mut worker.ct_pending,
        );
    }

    /// One round with every worker's production ct-slice first.
    fn round_with_ct_slice(&mut self, now_ns: u64) {
        for w in 0..WORKERS {
            self.ct_slice(w, now_ns);
        }
        self.round(now_ns);
    }
}

/// Codex review of 9a599d0900 (P1): a single-FIN half-close is live service:
/// the non-FINed direction keeps flowing. `ct_slice_forward_pairs` skips
/// CLOSING rows (their stage/count policy), so that service never reached
/// `last_served_ns`. The extras collector carries it, for `last_served_ns`
/// only, with the reply's packet time.
#[test]
fn half_close_service_is_collected_19063() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    f.activate(t0);
    let key = f.row.key.clone();
    let fin = crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK;
    assert!(f.workers[2].table.lookup_with_origin(&key, t0 + SEC, fin).is_some());
    f.workers[2].table.account_packet_at(&key, 64, fin, 0, t0 + SEC);
    f.serve_reverse(2, t0 + 2 * SEC, false);
    let table = &f.workers[2].table;
    assert_eq!(
        table.packet_counts_and_last_packet_seen_for(&key).2,
        t0 + 2 * SEC,
        "FIXTURE: the reply is this pair's newest packet"
    );
    let mut pairs = Vec::new();
    table.ct_slice_forward_pairs(0, usize::MAX, &mut pairs);
    assert!(
        !pairs.iter().any(|p| p.0 == key),
        "FIXTURE: the closing forward is outside the stage/count publisher"
    );
    let mut extras = Vec::new();
    table.ct_slice_last_served_extras(0, usize::MAX, &mut extras);
    assert!(
        extras.iter().any(|e| e.0 == key && e.2 == t0 + 2 * SEC && e.3 == f.row.session_id),
        "Codex P1: admitted half-close service reaches the serving-evidence publisher"
    );
}

/// The end-to-end twin, through every worker's PRODUCTION ct-slice: worker 2
/// sees one FIN, then serves replies every second through the other copies'
/// window plus hold. No copy may close the live half-closed session.
#[test]
fn a_half_closed_session_served_on_another_worker_never_closes_19063() {
    let mut f = Fixture::new(0);
    let t0 = f.t0;
    f.activate(t0);
    let key = f.row.key.clone();
    let id = f.row.session_id;
    let fin = crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK;
    assert!(f.workers[2].table.lookup_with_origin(&key, t0 + SEC, fin).is_some());
    f.workers[2].table.account_packet_at(&key, 64, fin, 0, t0 + SEC);
    let end = t0 + 3 * f.window_ns();
    let mut now = t0 + SEC;
    while now < end {
        now += SEC;
        f.serve_reverse(2, now, false);
        f.round_with_ct_slice(now);
        assert_eq!(
            (f.ha_closes(), f.rt_flow_closes(id)),
            (0, 0),
            "Codex P1: a Close of the half-closed session worker 2 serves (t=t0+{}s)",
            (now - t0) / SEC
        );
    }
    assert!(f.shared_present(), "the live session's shared row survives");
}

/// R7 review of 9a599d0900 (F1): the serving worker holds only the REVERSE
/// half (its restored forward copy is gone: the prewarm missed it, or it was
/// evicted). Its reply service is published onto the shared FORWARD row
/// through the production ct-slice, so the idle copies keep the session.
#[test]
fn reverse_only_service_on_another_worker_keeps_the_session_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let forward = f.row.key.clone();
    let reverse = crate::session::reverse_session_key(&forward, f.row.decision.nat);
    f.workers[2].table.delete(&forward);
    assert!(
        f.workers[2].table.entry_with_origin(&forward).is_none()
            && f.workers[2].table.entry_with_origin(&reverse).is_some(),
        "FIXTURE: worker 2 holds only the reverse half"
    );
    let id = f.row.session_id;
    let end = t0 + 3 * f.window_ns();
    let mut now = t0;
    while now < end {
        now += SEC;
        f.serve_reverse(2, now, false);
        f.round_with_ct_slice(now);
        assert_eq!(
            (f.ha_closes(), f.rt_flow_closes(id)),
            (0, 0),
            "R7 F1: a Close of the session worker 2 serves in reverse only (t=t0+{}s)",
            (now - t0) / SEC
        );
    }
    assert!(f.shared_present());
    assert!(f.workers[2].table.entry_with_origin(&reverse).is_some(), "the serving row survives");
}

/// Codex review of 9a599d0900 (P2a): a surviving reverse row of an OLDER
/// incarnation A at the derived companion key of forward B is not B's
/// service. Neither the fence's own evidence nor the publisher may relabel
/// A's reply time with B's id.
#[test]
fn old_reverse_service_is_not_new_forward_service_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let key = f.row.key.clone();
    let reverse = crate::session::reverse_session_key(&key, f.row.decision.nat);
    let a = f.row.session_id;
    let mut b = f.row.clone();
    b.session_id = a + 1;
    assert!(f.workers[0].table.upsert_synced_with_origin(
        b.clone().into_session_install(t0 + SEC),
        true
    ));
    assert_eq!(f.workers[0].table.session_id_for(&reverse), a, "FIXTURE: reverse A survives");
    crate::afxdp::shared_ops::publish_shared_session(
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &b,
    );
    f.serve_reverse(0, t0 + 2 * SEC, false);
    let foreign = t0 + 2 * SEC;
    assert_ne!(
        f.workers[0].table.packet_counts_and_last_packet_seen_for(&key).2,
        foreign,
        "the fence's own evidence for B excludes A's reply"
    );
    let mut pairs = Vec::new();
    f.workers[0].table.ct_slice_forward_pairs(0, usize::MAX, &mut pairs);
    assert!(
        pairs.iter().all(|p| p.0 != key || p.4 != foreign),
        "the publisher does not carry A's reply as B's service"
    );
    crate::afxdp::shared_ops::restamp_shared_packet_counts_batch(
        &f.shared_sessions,
        &f.shared_wire,
        f.workers[0].table.session_id_namespace(),
        &pairs,
    );
    let rows = crate::afxdp::shared_ops::lock_shared_recover(&f.shared_sessions);
    assert_ne!(rows.get(&key).expect("B").last_served_ns, foreign, "B's evidence excludes A's reply");
}

/// Codex review of 9a599d0900 (P2b): an unknown id (0) is not "the same
/// incarnation" for `last_served_ns`. Publishing an id-0 row and then a
/// different B must not carry A's service into B.
#[test]
fn an_unknown_id_never_bridges_last_served_into_another_session_19063() {
    let f = Fixture::with_key(0, udp_v4_key());
    let key = f.row.key.clone();
    let read = || {
        crate::afxdp::shared_ops::lock_shared_recover(&f.shared_sessions)
            .get(&key)
            .map(|row| row.last_served_ns)
    };
    let publish = |row: &SyncedSessionEntry| {
        crate::afxdp::shared_ops::publish_shared_session(
            &f.shared_sessions,
            &f.shared_nat,
            &f.shared_wire,
            &f.indexes,
            row,
        )
    };
    let mut served = f.row.clone();
    served.last_served_ns = 65 * SEC;
    publish(&served);
    assert_eq!(read(), Some(65 * SEC), "FIXTURE: A is served");
    let mut unknown = f.row.clone();
    unknown.session_id = 0;
    publish(&unknown);
    let mut b = f.row.clone();
    b.session_id += 1;
    publish(&b);
    assert_eq!(read(), Some(0), "an unknown identity must not bridge A's service into B");
}

/// Codex review of 9a599d0900 (P3): the scheduler, not just the helper. An
/// installed idle cohort is driven through housekeeping on EVERY GC tick
/// from before the crossing to past the hold. Each copy reads the shared row
/// at its crossing and at its hold end, and nowhere in between. A Defer that
/// revisited every GC interval would read about 14 times per copy.
#[test]
fn an_idle_cohort_reads_the_shared_row_only_at_crossing_and_hold_end_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let id = f.row.session_id;
    let horizon = f.idle_close_horizon();
    let mut now = t0;
    while now < horizon && f.rt_flow_closes(id) == 0 {
        now += SEC;
        f.round(now);
    }
    let reads: u64 = (0..WORKERS)
        .map(|w| f.workers[w].table.promote_fence_shared_reads_for_test())
        .sum();
    eprintln!("#19063 cohort shared-row reads: {reads} for {WORKERS} copies, closed at t0+{}s", (now - t0) / SEC);
    assert!(f.rt_flow_closes(id) >= 1, "FIXTURE: the idle cohort closed");
    assert!(
        reads <= 2 * WORKERS as u64,
        "Codex P3: {reads} shared-row reads for {WORKERS} copies; at most one at the crossing and one at hold end each"
    );
}


/// The extras publisher does NOT widen the RST/TIME_WAIT policy: a pair that
/// has seen both FINs, or an RST, publishes no service.
#[test]
fn time_wait_and_reset_pairs_publish_no_service_19063() {
    let fin = crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK;
    let rst = crate::tcp_flags::TCP_RST | crate::tcp_flags::TCP_ACK;
    for case in ["both FINs", "RST"] {
        let mut f = Fixture::new(0);
        let t0 = f.t0;
        f.activate(t0);
        let key = f.row.key.clone();
        let reverse = crate::session::reverse_session_key(&key, f.row.decision.nat);
        let table = &mut f.workers[2].table;
        match case {
            "both FINs" => {
                assert!(table.lookup_with_origin(&key, t0 + SEC, fin).is_some());
                table.account_packet_at(&key, 64, fin, 0, t0 + SEC);
                let _ = table.lookup_with_origin(&reverse, t0 + 2 * SEC, fin);
                table.account_packet_at(&reverse, 64, fin, 0, t0 + 2 * SEC);
            }
            _ => {
                let _ = table.lookup_with_origin(&key, t0 + SEC, rst);
                table.account_packet_at(&key, 64, rst, 0, t0 + SEC);
            }
        }
        assert!(
            table.entry_with_origin(&key).is_some(),
            "FIXTURE ({case}): the closing forward row is still in the table"
        );
        let mut extras = Vec::new();
        table.ct_slice_last_served_extras(0, usize::MAX, &mut extras);
        assert!(
            !extras.iter().any(|e| e.0 == key),
            "{case}: a terminal pair publishes no serving evidence"
        );
    }
}

/// The REACHABLE mixed pair (Codex review of 9a599d0900, P2a): forward B
/// replaced A while A's reverse stayed. A's later reply is excluded, AND what
/// #18722/#18742 protect still holds for B: B's own forward service is still
/// published, both as the sibling packet recency (#18742: real packet time,
/// from a non-minting worker) and as `last_served_ns`. Worker 1 holds the
/// pair, so its namespace differs from B's minting namespace.
#[test]
fn a_replaced_forward_keeps_publishing_its_own_service_beside_a_stale_reverse_19063() {
    let mut f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    f.activate(t0);
    let key = f.row.key.clone();
    let reverse = crate::session::reverse_session_key(&key, f.row.decision.nat);
    let a = f.row.session_id;
    let mut b = f.row.clone();
    b.session_id = a + 1;
    let w = 1usize;
    assert!(f.workers[w].table.upsert_synced_with_origin(
        b.clone().into_session_install(t0 + SEC),
        true
    ));
    assert_eq!(f.workers[w].table.session_id_for(&reverse), a, "FIXTURE: reverse A survives");
    crate::afxdp::shared_ops::publish_shared_session(
        &f.shared_sessions,
        &f.shared_nat,
        &f.shared_wire,
        &f.indexes,
        &b,
    );
    let own = t0 + 2 * SEC;
    let foreign = t0 + 3 * SEC;
    f.serve(w, own, false);
    f.serve_reverse(w, foreign, false);
    assert_eq!(
        f.workers[w].table.packet_counts_and_last_packet_seen_for(&key).2,
        own,
        "B's pair time is its own forward packet, not A's later reply"
    );
    f.restamp(w);
    let rows = crate::afxdp::shared_ops::lock_shared_recover(&f.shared_sessions);
    let row = rows.get(&key).expect("B");
    assert_eq!(row.session_id, a + 1);
    assert_eq!(row.last_served_ns, own, "B's own service is published as its evidence");
    assert_eq!(
        row.sibling_last_seen_ns, own,
        "#18742: the sibling recency is B's real packet time, not A's reply"
    );
}

/// The production pair whose halves have DIFFERENT ids: an import with a
/// wire id of 0 (a legacy peer, a tunnel replica) allocates a fresh id per
/// half. The reverse was installed after the forward, so it is the forward's
/// companion, and its reply still counts as the pair's service.
#[test]
fn a_fresh_id_import_companion_still_counts_its_reply_19063() {
    let f = Fixture::with_key(0, udp_v4_key());
    let t0 = f.t0;
    let key = f.row.key.clone();
    let reverse_key = crate::session::reverse_session_key(&key, f.row.decision.nat);
    let mut table = SessionTable::new();
    table.set_session_id_namespace(0, 2);
    let mut forward = f.row.clone();
    forward.session_id = 0;
    assert!(table.upsert_synced_with_origin(forward.into_session_install(t0), true));
    let mut reverse = f.row.clone();
    reverse.key = reverse_key.clone();
    reverse.metadata.is_reverse = true;
    reverse.session_id = 0;
    assert!(table.upsert_synced_with_origin(reverse.into_session_install(t0), true));
    let (fid, rid) = (table.session_id_for(&key), table.session_id_for(&reverse_key));
    assert!(fid != 0 && rid != 0 && fid != rid, "FIXTURE: fresh, different ids ({fid}, {rid})");
    assert!(table.lookup_with_origin(&reverse_key, t0 + 5 * SEC, 0).is_some());
    table.account_packet(&reverse_key, 64, 0, 0);
    assert_eq!(
        table.packet_counts_and_last_packet_seen_for(&key).2,
        t0 + 5 * SEC,
        "a companion installed after its forward counts, whatever its id"
    );
}
