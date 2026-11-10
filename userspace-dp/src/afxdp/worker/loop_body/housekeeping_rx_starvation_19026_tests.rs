// #19026 (Part 1): a requeued Close whose tuple install permit is not
// available must not starve the worker's RX poll.
//
// `run_session_housekeeping` returns `true` ("skip the rest of this tick")
// when a Close delta cannot take its tuple install permits; the worker loop
// then `continue`s BEFORE `poll_binding` (worker/loop_body/mod.rs). The
// heartbeat is stored before housekeeping, so a worker whose requeued Close
// never gets its permit stays "healthy" to the liveness watchdog while it
// polls no RX at all and black-holes every flow it serves. These cells drive
// the production housekeeping fn tick by tick with the permit held by
// another holder and assert forward progress (some ticks poll RX), that the
// Close is retained while it waits, and that it completes exactly once once
// the permit returns.

use super::*;
use crate::nat::NatDecision;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU32;

fn key_19026(src_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 63, 106)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 211)),
        src_port,
        dst_port: 443,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn decision_19026() -> SessionDecision {
    SessionDecision {
        resolution: ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
            source_ifindex: 0,
            route_mtu: 0,
            transport_route_mtu: 0,
        },
        nat: NatDecision::default(),
        install_table_domain: 0,
        install_table_check: 0,
    }
}

fn metadata_19026() -> SessionMetadata {
    SessionMetadata {
        forward_wire_alias_origin: false,
        ingress_zone: 1,
        egress_zone: 2,
        ingress_zone_check: 0,
        egress_zone_check: 0,
        ingress_ifindex: 0,
        ingress_vlan_id: 0,
        forward_ingress_vlan_id: None,
        owner_rg_id: 1,
        fabric_ingress: false,
        is_reverse: false,
        nat64_reverse: None,
        log_session_init: false,
        log_session_close: false,
        policy_id: 0,
        inactivity_timeout_ns: None,
        policy_counter_idx: 0,
        policy_counter: None,
        nat_scope_ifindex: None,
    }
}

/// The production housekeeping fn with the smallest worker around it: no
/// bindings, no HA groups, no BPF maps (`-1` fds). `flushed` records every
/// delta the loop's flush closure is handed, in order.
struct Harness19026 {
    sessions: SessionTable,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    runtime: RuntimeViewChannel,
    rg_epochs: [AtomicU32; crate::afxdp::flow_cache::MAX_RG_EPOCHS],
    worker_command_queues: crate::afxdp::types::WorkerCommandQueues,
    pptp_control: crate::session::pptp_control::PptpControlInbox,
    shared_recycles: Vec<(u32, u64)>,
    deferred_expiry_overflow_deltas: Vec<SessionDelta>,
    wedged: bool,
    close_barrier: super::close_barrier::ClosePermitBarrier,
    flushed: Vec<SessionDelta>,
    /// When `Some(n)`, the flush closure models `flush_session_deltas`
    /// losing the close permit race: it requeues what it was handed (as the
    /// production flush does on a busy permit) for its first `n` calls.
    flush_requeues_remaining: Option<u64>,
    flush_calls: u64,
    /// This worker's own command queue (`worker_commands_by_id`).
    own_queue: Arc<Mutex<VecDeque<WorkerCommand>>>,
}

impl Harness19026 {
    fn new() -> Self {
        Self {
            sessions: SessionTable::new(),
            shared_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_nat_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_forward_wire_sessions: Arc::new(Mutex::new(FastMap::default())),
            shared_owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            runtime: RuntimeViewChannel::default(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            worker_command_queues: crate::afxdp::types::WorkerCommandQueues::new(
                BTreeMap::new(),
            ),
            pptp_control: crate::session::pptp_control::PptpControlInbox::default(),
            shared_recycles: Vec::new(),
            deferred_expiry_overflow_deltas: Vec::new(),
            wedged: false,
            close_barrier: Default::default(),
            flushed: Vec::new(),
            flush_requeues_remaining: None,
            flush_calls: 0,
            own_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn queue_close(&mut self, key: SessionKey, session_id: u64) {
        self.sessions.emit_close_delta_with_origin(
            key,
            decision_19026(),
            metadata_19026(),
            SessionOrigin::ForwardFlow,
            false,
            session_id,
        );
    }

    /// One worker tick's housekeeping. Returns `true` when the loop would
    /// `continue` BEFORE polling RX (the production skip-tick contract).
    fn tick(&mut self, now_ns: u64) -> bool {
        let mut bindings: Vec<BindingWorker> = Vec::new();
        let binding_lookup = WorkerBindingLookup::default();
        let forwarding = ForwardingState::default();
        let ha_runtime: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();
        let shared_runtime = self.runtime.reader();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let flushed = &mut self.flushed;
        let requeues = &mut self.flush_requeues_remaining;
        let calls = &mut self.flush_calls;
        let mut flush_deltas =
            |sessions: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, deltas: &[SessionDelta]| {
                *calls += 1;
                if let Some(remaining) = requeues.as_mut()
                    && *remaining > 0
                {
                    *remaining -= 1;
                    sessions.requeue_deltas_front(deltas);
                    return;
                }
                flushed.extend(deltas.iter().cloned());
            };
        run_session_housekeeping(
            &mut self.sessions,
            &mut bindings,
            &binding_lookup,
            &forwarding,
            &ha_runtime,
            now_ns,
            now_ns / 1_000_000_000,
            &self.rg_epochs,
            SteeringMap::unshared_for_test(-1),
            -1,
            -1,
            0,
            &self.worker_command_queues,
            &self.pptp_control,
            Some(&self.own_queue),
            &peer_worker_commands,
            &self.shared_sessions,
            &self.shared_nat_sessions,
            &self.shared_forward_wire_sessions,
            &self.shared_owner_rg_indexes,
            &shared_runtime,
            &mut self.wedged,
            &mut self.shared_recycles,
            &mut self.deferred_expiry_overflow_deltas,
            &mut self.close_barrier,
            &mut flush_deltas,
        )
    }

    fn pending_closes_for(&mut self, key: &SessionKey) -> usize {
        let drained = self.sessions.drain_deltas(4096);
        let count = drained
            .iter()
            .filter(|delta| delta.kind == SessionDeltaKind::Close && delta.key == *key)
            .count();
        self.sessions.requeue_deltas_front(&drained);
        count
    }

    /// Retained anywhere the worker keeps a Close it still owes: the ring,
    /// the deferred overflow suffix, or the parked side slot.
    fn retained_closes_for(&mut self, key: &SessionKey) -> usize {
        let in_ring = self.pending_closes_for(key);
        let elsewhere = self
            .deferred_expiry_overflow_deltas
            .iter()
            .chain(self.close_barrier.parked.iter())
            .filter(|delta| delta.kind == SessionDeltaKind::Close && delta.key == *key)
            .count();
        in_ring + elsewhere
    }

    fn queue_open(&mut self, key: SessionKey) {
        self.sessions.emit_open_delta_with_origin(
            key,
            decision_19026(),
            metadata_19026(),
            SessionOrigin::ForwardFlow,
            false,
        );
    }

    fn flushed_opens(&self) -> usize {
        self.flushed
            .iter()
            .filter(|delta| delta.kind == SessionDeltaKind::Open)
            .count()
    }

    fn flushed_closes_for(&self, key: &SessionKey) -> usize {
        self.flushed
            .iter()
            .filter(|delta| delta.kind == SessionDeltaKind::Close && delta.key == *key)
            .count()
    }
}

/// 100 us per worker tick: ten ticks span one `CLOSE_PERMIT_BARRIER_NS`.
/// The busiest real loop ticks far faster, so this under-counts the ticks a
/// stuck close would starve.
const TICK_NS: u64 = 100_000;
const BASE_NS: u64 = 10_000_000_000;
const BARRIER_TICKS: u64 = super::close_barrier::CLOSE_PERMIT_BARRIER_NS / TICK_NS;
/// Ticks past which every head that has blocked since the run began is
/// parked on any head (cycle 2 parks at the RX bound; 2e7dfd349b parked at
/// 10 ms). A literal so these cells compile unchanged against both heads.
const PARKED_BY_TICKS: u64 = 105;

/// #19026 Part 1: while a requeued Close cannot take its tuple install
/// permit, the worker must keep polling RX. Master returned "skip the tick"
/// on every pass (measured on b57a950e21: 2000 of 2000 ticks skipped), so a
/// permit that never returns starved RX forever while the heartbeat — stored
/// before housekeeping — stayed fresh.
#[test]
fn requeued_close_without_permit_keeps_polling_rx_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_026);
    h.queue_close(stuck.clone(), 0x1902_6001);

    // Another holder owns the tuple and does not give it back.
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("test holds the stuck tuple's install permit");

    // Two simulated seconds of worker ticks.
    let ticks = 20_000u64;
    let mut rx_polled = 0u64;
    let mut longest_skip_run = 0u64;
    let mut skip_run = 0u64;
    for tick in 0..ticks {
        if h.tick(BASE_NS + tick * TICK_NS) {
            skip_run += 1;
            longest_skip_run = longest_skip_run.max(skip_run);
        } else {
            rx_polled += 1;
            skip_run = 0;
        }
    }
    let still_pending = h.retained_closes_for(&stuck);
    let flushed_while_held = h.flushed_closes_for(&stuck);
    let parked = h.close_barrier.parked.len();
    drop(held);

    assert!(
        rx_polled > 0,
        "#19026: a Close waiting on a tuple permit must not starve RX: \
         {ticks} ticks, {rx_polled} polled RX (longest skip run {longest_skip_run})"
    );
    assert!(
        longest_skip_run <= BARRIER_TICKS,
        "#19026: the RX barrier for one stuck Close is bounded by \
         CLOSE_PERMIT_BARRIER_NS ({BARRIER_TICKS} ticks); the longest run of \
         RX-skipping ticks was {longest_skip_run}"
    );
    assert_eq!(
        rx_polled,
        ticks - longest_skip_run,
        "after the bound every tick polls RX (the barrier does not re-arm \
         while the same episode lasts)"
    );
    assert_eq!(
        flushed_while_held, 0,
        "the Close must not be flushed (its teardown run) without its permit"
    );
    assert_eq!(
        still_pending, 1,
        "the Close must be retained exactly once while its permit is unavailable"
    );
    assert_eq!(parked, 1, "R13 F1: past the bound the Close sits in the side slot");
}

/// #19026 (guard against over-correction): ordinary permit contention that
/// clears inside the bound keeps the #10419/#10512 teardown-before-poll
/// ordering — no RX tick runs before the blocked Close is retired.
#[test]
fn transient_close_contention_keeps_teardown_before_poll_19026() {
    let mut h = Harness19026::new();
    let busy = key_19026(19_029);
    h.queue_close(busy.clone(), 0x1902_6004);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([busy.clone()])
        .expect("test holds the tuple's install permit");
    let mut now = BASE_NS;
    // Five ticks = 500 us of contention, inside the 1 ms bound.
    let short = 5u64;
    assert!(
        short * TICK_NS < super::close_barrier::CLOSE_PERMIT_BARRIER_NS,
        "FIXTURE: the contention must clear inside the bound"
    );
    for _ in 0..short {
        assert!(
            h.tick(now),
            "inside the bound a blocked Close still withholds RX (teardown first)"
        );
        now += TICK_NS;
    }
    drop(held);
    assert!(
        !h.tick(now),
        "the permit returned: the Close retires and this same tick polls RX"
    );
    assert_eq!(h.flushed_closes_for(&busy), 1, "retired exactly once");
    assert!(!h.sessions.has_pending_deltas());
    assert!(h.close_barrier.parked.is_empty(), "nothing parked inside the bound");
}

/// #19026 Part 1 (companion): once the permit returns, the retained Close
/// completes exactly once and the queue drains; the bound never drops it.
#[test]
fn requeued_close_completes_once_after_permit_returns_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_027);
    let unrelated = key_19026(19_028);
    h.queue_close(stuck.clone(), 0x1902_6002);
    h.queue_close(unrelated.clone(), 0x1902_6003);

    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("test holds the stuck tuple's install permit");
    let mut now = BASE_NS;
    // Fixed tick counts (never scaled by the bound) so a mutated bound
    // fails an assertion instead of hanging the cell.
    for _ in 0..500 {
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.flushed_closes_for(&stuck), 0, "no flush without the permit");
    assert_eq!(
        h.flushed_closes_for(&unrelated),
        1,
        "R13 F1: once the stuck Close is parked the Close queued behind it flows"
    );
    drop(held);

    for _ in 0..500 {
        if !h.tick(now) && !h.sessions.has_pending_deltas() {
            break;
        }
        now += TICK_NS;
    }
    assert!(
        !h.sessions.has_pending_deltas(),
        "the retained Close must drain once its permit returns"
    );
    assert_eq!(
        h.flushed_closes_for(&stuck),
        1,
        "#19026: the stuck Close completes exactly once"
    );
    assert_eq!(
        h.flushed_closes_for(&unrelated),
        1,
        "a Close queued behind the stuck one completes exactly once"
    );
}

/// #19026: the second retry site. `drain_and_flush_all_impl` drains, purges
/// (permits free), then flushes; `flush_session_deltas` takes the permits
/// AGAIN and requeues the suffix when one is busy. Master's drain loop then
/// re-drained the same Close immediately, inside ONE housekeeping call — a
/// spin with neither RX nor a heartbeat for as long as the race kept losing.
/// The flush closure here models that losing race for its first 1000 calls.
#[test]
fn flush_side_permit_loss_yields_instead_of_spinning_19026() {
    let mut h = Harness19026::new();
    let key = key_19026(19_030);
    h.queue_close(key.clone(), 0x1902_6005);
    h.flush_requeues_remaining = Some(1_000);

    let skipped = h.tick(BASE_NS);
    assert_eq!(
        h.flush_calls, 1,
        "#19026: one housekeeping call must try the losing flush once and \
         yield, not re-drain it in a loop (calls in one tick: {})",
        h.flush_calls
    );
    assert!(skipped, "a requeued close inside the bound withholds RX");
    assert_eq!(h.pending_closes_for(&key), 1, "the Close is retained");

    // Past the bound the tick polls RX while the flush keeps losing.
    let mut now = BASE_NS;
    let mut rx_polled = 0;
    for _ in 0..40 {
        now += TICK_NS;
        if !h.tick(now) {
            rx_polled += 1;
        }
    }
    assert!(rx_polled > 0, "#19026: a flush-side permit loss must not starve RX");
    h.flush_requeues_remaining = Some(0);
    now += TICK_NS;
    assert!(!h.tick(now), "the race is won: retire and poll RX");
    assert_eq!(h.flushed_closes_for(&key), 1, "retired exactly once");
    assert!(!h.sessions.has_pending_deltas());
}

/// #19026: the bound is per blocked EPISODE. Once a blocked Close retires,
/// the next Close that blocks gets the full teardown-before-poll window
/// again; a barrier that never re-armed would silently drop the #10419
/// ordering for every later contention on this worker.
#[test]
fn barrier_rearms_for_each_blocked_episode_19026() {
    let mut h = Harness19026::new();
    let first = key_19026(19_031);
    let second = key_19026(19_032);
    let gate = crate::afxdp::bpf_map::global_tuple_gate();

    h.queue_close(first.clone(), 0x1902_6006);
    let held = gate.try_acquire_installs([first.clone()]).expect("hold first");
    let mut now = BASE_NS;
    for _ in 0..30 {
        h.tick(now);
        now += TICK_NS;
    }
    drop(held);
    assert!(!h.tick(now), "first episode retires");
    assert_eq!(h.flushed_closes_for(&first), 1);

    now += 10 * super::close_barrier::CLOSE_PERMIT_BARRIER_NS;
    h.queue_close(second.clone(), 0x1902_6007);
    let held = gate.try_acquire_installs([second.clone()]).expect("hold second");
    let held_first_tick = h.tick(now);
    drop(held);
    assert!(
        held_first_tick,
        "#19026: a new blocked episode re-arms the barrier (teardown first)"
    );
}

// ---- #19026 R13 fold cells (F1-F5) and Codex P2 #5 ----

/// R13 F1: a Close stuck past the park bound leaves the FIFO, so every other
/// delta this worker produces keeps flowing (HA sync, RT_FLOW) instead of
/// filling the 4096 ring and latching delta-loss. On b57a950e21..bb9608f1a6 the
/// opens queued behind the stuck Close never flushed and the ring overflowed.
#[test]
fn stuck_close_is_parked_and_later_deltas_flow_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_040);
    h.queue_close(stuck.clone(), 0x1902_6010);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the stuck tuple");
    let mut now = BASE_NS;
    for _ in 0..PARKED_BY_TICKS {
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.close_barrier.parked.len(), 1, "parked past the bound");
    // "RX" now produces 5000 opens across 100 ticks.
    for tick in 0..100u16 {
        for i in 0..50u16 {
            h.queue_open(key_19026(20_000 + tick * 50 + i));
        }
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.flushed_opens(), 5000, "R13 F1: deltas behind a parked Close flow");
    assert_eq!(h.sessions.delta_drops(), 0, "R13 F1: the ring never overflows");
    assert_eq!(h.flushed_closes_for(&stuck), 0, "the stuck Close waits for its permit");
    assert_eq!(h.retained_closes_for(&stuck), 1, "and is retained exactly once");
    drop(held);
    h.tick(now);
    assert_eq!(h.flushed_closes_for(&stuck), 1, "it retires once the permit returns");
    assert!(h.close_barrier.parked.is_empty());
}

/// A parked Close whose retry loses the FLUSH-side permit race goes back to
/// the side slot. That flush takes the permits again and, finding one busy,
/// requeues the Close at the ring head. Left there, the Close would block the
/// next ring drain and hold RX for a fresh bound on every lost race. The
/// flush closure here loses its first two calls: the parked retries before
/// and after the drains.
#[test]
fn parked_close_that_loses_the_flush_race_is_parked_again_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_050);
    h.queue_close(stuck.clone(), 0x1902_6050);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the stuck tuple");
    let mut now = BASE_NS;
    for _ in 0..PARKED_BY_TICKS {
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.close_barrier.parked.len(), 1, "FIXTURE: parked past the bound");
    drop(held);
    h.flush_requeues_remaining = Some(2);
    let calls_before = h.flush_calls;
    let skipped = h.tick(now);
    // Two attempts, both from the parked slot: the retry before the drains
    // and, since the Codex review of af0ea8415c, the retry after them. Both
    // lose the race and the Close goes back to the slot each time. It is
    // never left in the ring to be re-drained (that would hold RX: below).
    assert_eq!(
        h.flush_calls - calls_before,
        2,
        "two parked retries this tick (before and after the drains), no ring re-drain"
    );
    assert!(!skipped, "a parked Close that lost the flush race does not hold RX");
    assert_eq!(h.close_barrier.parked.len(), 1, "it is back in the side slot");
    assert_eq!(h.pending_closes_for(&stuck), 0, "and not left at the ring head");
    h.flush_requeues_remaining = Some(0);
    now += TICK_NS;
    assert!(!h.tick(now), "the race is won: retire and poll RX");
    assert_eq!(h.flushed_closes_for(&stuck), 1, "retired exactly once");
    assert!(h.close_barrier.parked.is_empty());
}

/// R13 F3: a blocked head is re-tested with one permit try per tick; a
/// blocked tick moves no delta (master drained 256 and requeued them, twice
/// per tick, while the permit was held).
#[test]
fn blocked_tick_moves_no_delta_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_041);
    h.queue_close(stuck.clone(), 0x1902_6011);
    for i in 0..4000u16 {
        h.queue_open(key_19026(30_000 + i));
    }
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the stuck tuple");
    let mut now = BASE_NS;
    h.tick(now); // discovers the block
    let drained_before = h.sessions.delta_drained_for_test();
    for _ in 0..5 {
        now += TICK_NS;
        assert!(h.tick(now), "inside the RX bound");
    }
    let drained = h.sessions.delta_drained_for_test() - drained_before;
    drop(held);
    assert_eq!(drained, 0, "R13 F3: blocked ticks drained {drained} deltas");
}

/// R13 F2: the post-RX export slice leaves a blocked head to housekeeping
/// instead of re-draining it and `continue`ing past the loop bottom.
#[test]
fn export_slice_leaves_a_blocked_head_to_housekeeping_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_042);
    h.queue_close(stuck.clone(), 0x1902_6012);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the stuck tuple");
    let mut now = BASE_NS;
    // Inside the RX bound (past it, cycle 2 parks the head and clears the
    // bit; the export slice then drains freely behind the parked Close).
    for _ in 0..2 {
        h.tick(now);
        now += TICK_NS;
    }
    assert!(h.sessions.close_head_blocked(), "housekeeping marked the head");
    let drained_before = h.sessions.delta_drained_for_test();
    let shared_runtime = h.runtime.reader();
    let export_buffer = ExportBufferState::new();
    let session_export_ack = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut worker_export: Option<WorkerExportState> = None;
    let mut echo: Vec<(SessionKey, SessionDecision, SessionMetadata, SessionOrigin)> = Vec::new();
    let mut flushes = 0;
    let mut flush =
        |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, _: &[SessionDelta]| {
            flushes += 1;
        };
    let (skip_tick, _) = run_export_slice(
        &mut h.sessions,
        &mut Vec::new(),
        &WorkerBindingLookup::default(),
        &ForwardingState::default(),
        &mut worker_export,
        Vec::new(),
        Vec::new(),
        None,
        &export_buffer,
        &mut echo,
        &mut h.shared_recycles,
        &shared_runtime,
        &h.shared_sessions,
        &h.shared_owner_rg_indexes,
        &session_export_ack,
        0,
        &mut flush,
        &mut h.wedged,
    );
    drop(held);
    assert!(!skip_tick, "R13 F2: the export slice must not skip the rest of the tick");
    assert_eq!(flushes, 0);
    assert_eq!(h.sessions.delta_drained_for_test(), drained_before, "no re-drain");
}

/// R13 F2, the loss-resync twin of the cell above. While housekeeping holds a
/// blocked head, `run_delta_recovery` leaves an armed delta-loss latch for a
/// later tick. Without the peek it consumed the latch, re-drained the blocked
/// ring, failed, re-armed the latch and skipped the rest of the tick, on every
/// tick of the block.
#[test]
fn delta_recovery_leaves_a_blocked_head_to_housekeeping_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_051);
    h.queue_close(stuck.clone(), 0x1902_6051);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the stuck tuple");
    let mut now = BASE_NS;
    // Inside the RX bound, as in the export-slice cell.
    for _ in 0..2 {
        h.tick(now);
        now += TICK_NS;
    }
    assert!(h.sessions.close_head_blocked(), "housekeeping marked the head");
    h.sessions.set_delta_loss();
    let drained_before = h.sessions.delta_drained_for_test();
    let shared_runtime = h.runtime.reader();
    let mut flushes = 0;
    let mut flush =
        |_: &mut SessionTable, _: &mut [BindingWorker], _: &mut bool, _: &[SessionDelta]| {
            flushes += 1;
        };
    let mut last_delete_drop_epoch = 0u64;
    let mut delete_drop_sweep = crate::afxdp::session_glue::DeleteDropSweep::default();
    let mut install_table_purge = crate::afxdp::session_glue::InstallTablePurge::default();
    let skip_tick = run_delta_recovery(
        &mut h.sessions,
        &mut Vec::new(),
        &WorkerBindingLookup::default(),
        &ForwardingState::default(),
        0,
        0,
        now,
        -1,
        -1,
        &[],
        true,
        SteeringMap::unshared_for_test(-1),
        &h.shared_sessions,
        &h.shared_nat_sessions,
        &h.shared_forward_wire_sessions,
        &h.shared_owner_rg_indexes,
        &mut last_delete_drop_epoch,
        &mut delete_drop_sweep,
        &mut install_table_purge,
        &mut h.shared_recycles,
        &shared_runtime,
        &mut h.wedged,
        &mut flush,
    );
    let drained = h.sessions.delta_drained_for_test() - drained_before;
    let latch_still_armed = h.sessions.take_delta_loss();
    drop(held);
    assert!(!skip_tick, "R13 F2: the loss-resync slice must not skip the rest of the tick");
    assert_eq!(flushes, 0);
    assert_eq!(drained, 0, "no re-drain of the blocked ring");
    assert!(
        latch_still_armed,
        "the resync stays armed for the tick after housekeeping parks or retires the head"
    );
}

/// Codex R15 P1#4 (cycle 2): while RX polled with the Close blocked, a
/// packet re-materialized a same-id local row, and an `UpsertSynced` of a
/// REPLACEMENT incarnation is queued for this worker. When the old Close
/// retires, the replacement must survive the command drain. 2e7dfd349b's
/// zombie retirement appended a bare `DeleteSynced(key)` behind the queued
/// upsert, so the drain installed the replacement and then deleted it.
#[test]
fn close_drain_preserves_a_queued_replacement_19026() {
    let mut h = Harness19026::new();
    let key = key_19026(19_043);
    let old_id = 0x1902_6013;
    let new_id = 0x1902_6913;
    h.queue_close(key.clone(), old_id);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([key.clone()])
        .expect("hold the tuple");
    let mut now = BASE_NS;
    for _ in 0..PARKED_BY_TICKS {
        h.tick(now);
        now += TICK_NS;
    }
    let install = |id: u64, origin: SessionOrigin, at: u64| crate::session::SessionInstall {
        key: key.clone(),
        decision: decision_19026(),
        metadata: metadata_19026(),
        source_nat_static: None,
        origin,
        now_ns: at,
        protocol: PROTO_TCP,
        tcp_flags: crate::tcp_flags::TCP_ACK,
        session_id: id,
        tcp_close_class: 0,
        tcp_handshake_state: 0,
        persistent_lease_hold: None,
        fwd_packets: 0,
        rev_packets: 0,
    };
    // The re-materialized replica of the closing session (same id) ...
    assert!(h.sessions.upsert_synced_with_origin(
        install(old_id, SessionOrigin::SharedMaterialize, now),
        true
    ));
    // ... and a replacement incarnation already queued for this worker.
    let req = crate::SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: "10.0.63.106".to_string(),
        dst_ip: "172.16.80.211".to_string(),
        src_port: key.src_port,
        dst_port: key.dst_port,
        owner_rg_id: 1,
        session_id: new_id,
        ..crate::SessionSyncRequest::default()
    };
    let mut replacement = crate::server::helpers::build_synced_session_entry(
        &req,
        &rustc_hash::FxHashMap::default(),
        0,
    )
    .expect("FIXTURE: replacement entry");
    replacement.key = key.clone();
    replacement.decision = decision_19026();
    replacement.metadata = metadata_19026();
    replacement.origin = SessionOrigin::WorkerLocalImport;
    replacement.session_id = new_id;
    h.own_queue
        .lock()
        .expect("own queue")
        .push_back(WorkerCommand::UpsertSynced(replacement));
    drop(held);
    for _ in 0..3 {
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.flushed_closes_for(&key), 1, "FIXTURE: the old Close retired");
    crate::afxdp::session_glue::apply_worker_commands(
        &h.own_queue,
        &mut h.sessions,
        SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        &ForwardingState::default(),
        &BTreeMap::new(),
        &Arc::new(ShardedNeighborMap::new()),
        0,
        &mut VecDeque::new(),
    );
    assert_eq!(
        h.sessions.session_id_for(&key),
        new_id,
        "#19026 Codex R15 P1#4: the queued replacement must survive the old Close's retirement"
    );
}

/// R13 F5 (cycle-2 form): a Close that blocks after a tick polled RX gets its
/// own teardown-before-poll window, even right after an earlier Close was
/// parked (master/bb9608f1a6 let it inherit the first's expired episode and
/// poll RX at once).
#[test]
fn chained_blocked_closes_each_get_their_own_window_19026() {
    let mut h = Harness19026::new();
    let first = key_19026(19_045);
    let second = key_19026(19_046);
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    h.queue_close(first.clone(), 0x1902_6014);
    let hold_first = gate.try_acquire_installs([first.clone()]).expect("hold first");
    let mut now = BASE_NS;
    for _ in 0..PARKED_BY_TICKS {
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.close_barrier.parked.len(), 1, "FIXTURE: the first Close parked");
    assert!(!h.tick(now), "FIXTURE: this tick polls RX");
    now += TICK_NS;
    h.queue_close(second.clone(), 0x1902_6015);
    let hold_second = gate.try_acquire_installs([second.clone()]).expect("hold second");
    assert!(
        h.tick(now),
        "#19026 R13 F5: the second blocked Close starts its own RX window"
    );
    drop(hold_first);
    drop(hold_second);
}

/// R13 N1 (cycle 2): ONE RX bound per run of held ticks, whichever Closes
/// block in it. Five Closes, each blocked 0.9 ms and freed in order, kept
/// 2e7dfd349b skipping RX for ~49 consecutive ticks (each Close opened a
/// fresh window) with no log line.
#[test]
fn back_to_back_short_blocks_share_one_rx_bound_19026() {
    let mut h = Harness19026::new();
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    let keys: Vec<SessionKey> = (0..5u16).map(|i| key_19026(19_060 + i)).collect();
    let mut holds = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        h.queue_close(key.clone(), 0x1902_6060 + i as u64);
        holds.push(Some(gate.try_acquire_installs([key.clone()]).expect("hold")));
    }
    let mut now = BASE_NS;
    let mut run = 0u64;
    let mut longest = 0u64;
    for tick in 0..80u64 {
        // Close i's holder lets go 0.9 ms after Close i-1's did.
        for (i, hold) in holds.iter_mut().enumerate() {
            if tick == 9 * (i as u64 + 1) {
                hold.take();
            }
        }
        if h.tick(now) {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
        now += TICK_NS;
    }
    holds.clear();
    for _ in 0..3 {
        h.tick(now);
        now += TICK_NS;
    }
    assert!(
        longest <= BARRIER_TICKS,
        "#19026 R13 N1: back-to-back blocked Closes withheld RX for {longest} consecutive \
         ticks; the bound is {BARRIER_TICKS} per run"
    );
    for key in &keys {
        assert_eq!(h.flushed_closes_for(key), 1, "every Close retires exactly once");
    }
}

/// R13 R1(b) (cycle 2): when the RX bound expires, the Closes queued BEHIND the
/// blocked one (their permits are free) retire before the first tick that
/// polls RX, so only the blocked tuple is exposed to RX (#10419). On
/// 2e7dfd349b they waited behind it while RX polled until the 10 ms park.
#[test]
fn closes_behind_a_blocked_head_retire_before_rx_polls_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_070);
    let behind = key_19026(19_071);
    h.queue_close(stuck.clone(), 0x1902_6070);
    h.queue_close(behind.clone(), 0x1902_6071);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the stuck tuple");
    let mut now = BASE_NS;
    let mut first_rx_tick = None;
    for tick in 0..PARKED_BY_TICKS {
        if !h.tick(now) {
            first_rx_tick = Some(tick);
            break;
        }
        now += TICK_NS;
    }
    let behind_flushed = h.flushed_closes_for(&behind);
    drop(held);
    assert!(first_rx_tick.is_some(), "FIXTURE: RX polls within the bound");
    assert_eq!(
        behind_flushed, 1,
        "#19026 R13 R1(b): the free Close behind the blocked one must retire before RX polls"
    );
}

/// The same with TWO blocked Closes in the ring, each with a free Close
/// behind it. Past the bound, the drain parks the first blocked Close and
/// keeps going, parks the second and keeps going, so both free Closes retire
/// before RX polls. The final ring drain after the overflow suffix (Codex
/// review of bbe57884f2, P2#3) covers only ONE more stop, so it cannot stand
/// in for "keep draining after a park".
#[test]
fn closes_behind_two_blocked_heads_retire_before_rx_polls_19026() {
    let mut h = Harness19026::new();
    let stuck = [key_19026(19_072), key_19026(19_074)];
    let behind = [key_19026(19_073), key_19026(19_075)];
    h.queue_close(stuck[0].clone(), 0x1902_6072);
    h.queue_close(behind[0].clone(), 0x1902_6073);
    h.queue_close(stuck[1].clone(), 0x1902_6074);
    h.queue_close(behind[1].clone(), 0x1902_6075);
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck[0].clone(), stuck[1].clone()])
        .expect("hold both stuck tuples");
    let mut now = BASE_NS;
    let mut first_rx_tick = None;
    for tick in 0..PARKED_BY_TICKS {
        if !h.tick(now) {
            first_rx_tick = Some(tick);
            break;
        }
        now += TICK_NS;
    }
    let behind_flushed = [h.flushed_closes_for(&behind[0]), h.flushed_closes_for(&behind[1])];
    let parked = h.close_barrier.parked.len();
    drop(held);
    assert!(first_rx_tick.is_some(), "FIXTURE: RX polls within the bound");
    assert_eq!(parked, 2, "both blocked Closes are parked");
    assert_eq!(
        behind_flushed,
        [1, 1],
        "#19026 R13 R1(b): every free Close behind a blocked one retires before RX polls"
    );
}

/// Codex R15 P1#3 / R13 N2 (cycle 2): a deferred overflow Close must not
/// overtake an OLDER Open of its own session still queued in the ring behind
/// a blocked head. 2e7dfd349b retried the deferred suffix before the ring and
/// emitted [Close(X), Open(X)].
#[test]
fn overflow_close_never_overtakes_its_own_older_open_19026() {
    let mut h = Harness19026::new();
    let stuck = key_19026(19_081);
    let key = key_19026(19_082);
    h.queue_close(stuck.clone(), 0x1902_6081);
    h.queue_open(key.clone());
    for p in 20_000..24_094u16 {
        h.queue_open(key_19026(p));
    }
    assert_eq!(h.sessions.pending_delta_count(), 4096, "FIXTURE: the ring is full");
    let mut overflow = Harness19026::new();
    overflow.queue_close(key.clone(), 0x1902_6082);
    h.deferred_expiry_overflow_deltas
        .push(overflow.sessions.pop_front_delta().expect("overflow close"));
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([stuck.clone()])
        .expect("hold the head");
    let mut now = BASE_NS;
    h.tick(now);
    drop(held);
    for _ in 0..PARKED_BY_TICKS {
        now += TICK_NS;
        h.tick(now);
    }
    let order: Vec<bool> = h
        .flushed
        .iter()
        .filter(|d| d.key == key)
        .map(|d| d.kind == SessionDeltaKind::Close)
        .collect();
    assert_eq!(
        order,
        vec![false, true],
        "#19026 Codex R15 P1#3: Open(X) must precede its own overflow Close(X)"
    );
}

/// Codex P2 #5: an overflow Close deferred by an earlier tick, blocked past
/// the bound, is parked and retried first on every tick, so once its permit
/// frees it flushes before newer ring events (RX-era opens) that housekeeping
/// drains. (The post-RX export slice may drain such a newer delta first:
/// different sessions carry no order; see the session README.)
#[test]
fn deferred_overflow_close_precedes_newer_ring_events_19026() {
    let mut h = Harness19026::new();
    let old = key_19026(19_047);
    let newer = key_19026(19_048);
    let mut close = None;
    h.sessions.emit_close_delta_with_origin(
        old.clone(),
        decision_19026(),
        metadata_19026(),
        SessionOrigin::ForwardFlow,
        false,
        0x1902_6016,
    );
    if let Some(delta) = h.sessions.pop_front_delta() {
        close = Some(delta);
    }
    h.deferred_expiry_overflow_deltas.push(close.expect("FIXTURE: overflow close"));
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([old.clone()])
        .expect("hold the overflow close's tuple");
    let mut now = BASE_NS;
    for _ in 0..(BARRIER_TICKS + 2) {
        h.tick(now);
        now += TICK_NS;
    }
    h.queue_open(newer.clone()); // produced by RX after the bound
    drop(held);
    h.tick(now);
    let order: Vec<_> = h
        .flushed
        .iter()
        .map(|d| (d.kind == SessionDeltaKind::Close, d.key.clone()))
        .collect();
    assert_eq!(
        order,
        vec![(true, old), (false, newer)],
        "#19026 Codex P2 #5: the older overflow Close flushes before the newer open"
    );
}

// ---- R13 F6: the diagnostic's pure pieces ----

#[test]
fn barrier_warn_throttle_is_one_line_per_interval_19026() {
    use super::close_barrier::{CLOSE_PERMIT_BARRIER_WARN_INTERVAL_NS as I, close_barrier_warn_due};
    assert!(close_barrier_warn_due(0, 5), "never emitted: due");
    assert!(!close_barrier_warn_due(1_000, 1_000 + I - 1), "inside the interval: suppressed");
    assert!(close_barrier_warn_due(1_000, 1_000 + I), "at the interval: due");
}

#[test]
fn barrier_line_names_the_tuple_and_the_holder_class_19026() {
    let key = key_19026(19_049);
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    let held = gate.try_acquire_installs([key.clone()]).expect("hold");
    let mut h = Harness19026::new();
    h.queue_close(key.clone(), 0x1902_6017);
    let delta = h.sessions.front_pending_delta().expect("queued close").clone();
    let [fwd, rev] = crate::afxdp::session_delta::close_install_keys(&delta);
    let line = super::close_barrier::format_close_barrier_line(
        3,
        "waiting",
        2_500_000,
        &delta,
        gate.probe(&fwd),
        gate.probe(&rev),
        7,
        4,
    );
    drop(held);
    for needle in [
        "w3: #19026 session close waiting 2500 us",
        "10.0.63.106:19049 -> 172.16.80.211:443",
        "id=0x19026017",
        "state: \"publishing\"",
        "installs: 1",
        "queued=7",
        "since last line: 4",
    ] {
        assert!(line.contains(needle), "missing {needle:?} in {line}");
    }
}

// ---- #19026 Codex review of af0ea8415c: the cost of ONE parking pass ----

/// Drive `h` until its first post-bound pass, then up to `max_ticks` more
/// passes. Returns, per pass, the ring deltas drained and whether the pass
/// skipped RX.
fn parking_passes(h: &mut Harness19026, max_ticks: u64, done: &dyn Fn(&mut Harness19026) -> bool) -> Vec<(u64, bool)> {
    let mut now = BASE_NS;
    assert!(h.tick(now), "FIXTURE: the first blocked tick holds RX");
    now += super::close_barrier::CLOSE_PERMIT_BARRIER_NS;
    let mut passes = Vec::new();
    for _ in 0..max_ticks {
        let before = h.sessions.delta_drained_for_test();
        let skipped = h.tick(now);
        passes.push((h.sessions.delta_drained_for_test() - before, skipped));
        now += TICK_NS;
        if done(h) {
            break;
        }
    }
    passes
}

/// One parking pass is bounded by one ring's worth of re-drain
/// (`CLOSE_PARK_PASS_BUDGET`), not by the number of blocked Closes. Here
/// blocked Closes alternate with free ones, so every park re-drains a batch.
/// At af0ea8415c one pass re-drained about 255 deltas per blocked Close, so
/// 2,048 of them took about half a million drains in ONE pass. Now every pass
/// stays within budget plus one ring, RX polls every pass, and the run
/// carries over, so later passes park at once without a fresh hold.
#[test]
fn one_parking_pass_is_bounded_with_interleaved_blocked_closes_19026() {
    let mut h = Harness19026::new();
    let blocked: Vec<SessionKey> = (0..2048u16).map(|i| key_19026(40_000 + i)).collect();
    for (i, key) in blocked.iter().enumerate() {
        h.queue_close(key.clone(), 0x1902_7000 + i as u64);
        h.queue_close(key_19026(44_100 + i as u16), 0x1902_9000 + i as u64);
    }
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs(blocked.clone())
        .expect("hold every blocked tuple");
    let passes = parking_passes(&mut h, 400, &|h| h.close_barrier.parked.len() == 2048);
    let parked = h.close_barrier.parked.len();
    let free_flushed = (0..2048u16)
        .filter(|i| h.flushed_closes_for(&key_19026(44_100 + i)) == 1)
        .count();
    drop(held);
    let bound = (super::close_barrier::CLOSE_PARK_PASS_BUDGET
        + crate::session::MAX_SESSION_DELTAS
        + 256) as u64;
    for (pass, (drained, skipped)) in passes.iter().enumerate() {
        assert!(
            *drained <= bound,
            "Codex (af0ea8415c): pass {pass} drained {drained} deltas, over {bound}"
        );
        assert!(!skipped, "pass {pass}: past the bound every pass polls RX (the run carries over)");
    }
    assert_eq!(parked, 2048, "every blocked Close is parked in the end");
    assert_eq!(free_flushed, 2048, "every free Close retired");
}

/// Dense blocked Closes (no free delta between them) park with one permit
/// try each: a newly exposed blocked head is marked, so it is not re-drained.
#[test]
fn dense_blocked_closes_park_without_redraining_19026() {
    let mut h = Harness19026::new();
    let blocked: Vec<SessionKey> = (0..4096u16).map(|i| key_19026(48_000 + i)).collect();
    for (i, key) in blocked.iter().enumerate() {
        h.queue_close(key.clone(), 0x1902_b000 + i as u64);
    }
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs(blocked.clone())
        .expect("hold every blocked tuple");
    let passes = parking_passes(&mut h, 8, &|h| h.close_barrier.parked.len() == 4096);
    let parked = h.close_barrier.parked.len();
    drop(held);
    let drained: u64 = passes.iter().map(|(d, _)| d).sum();
    assert_eq!(parked, 4096, "every blocked Close is parked within a few passes");
    assert!(
        drained <= 2 * 256,
        "dense blocked heads cost one permit try each, not a re-drain: {drained} drains"
    );
    assert!(passes.iter().all(|(_, skipped)| !skipped), "RX polls every pass");
}

/// Blocked Closes in the deferred #10309 overflow suffix: each park copies
/// the rest of the suffix, so one pass parks only as many as its budget
/// covers, and the rest wait for later passes (RX polls in between).
#[test]
fn overflow_parking_is_bounded_per_pass_19026() {
    let mut h = Harness19026::new();
    let blocked: Vec<SessionKey> = (0..1024u16).map(|i| key_19026(53_000 + i)).collect();
    let mut producer = SessionTable::new();
    for (i, key) in blocked.iter().enumerate() {
        producer.emit_close_delta_with_origin(
            key.clone(),
            decision_19026(),
            metadata_19026(),
            SessionOrigin::ForwardFlow,
            false,
            0x1902_d000 + i as u64,
        );
    }
    h.deferred_expiry_overflow_deltas = producer.drain_deltas(4096);
    assert_eq!(h.deferred_expiry_overflow_deltas.len(), 1024, "FIXTURE: overflow suffix");
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs(blocked.clone())
        .expect("hold every blocked tuple");
    let mut now = BASE_NS;
    assert!(h.tick(now), "FIXTURE: the first blocked tick holds RX");
    now += super::close_barrier::CLOSE_PERMIT_BARRIER_NS;
    let mut parks_per_pass = Vec::new();
    for _ in 0..2000 {
        let before = h.close_barrier.parked.len();
        assert!(!h.tick(now), "past the bound every pass polls RX");
        parks_per_pass.push(h.close_barrier.parked.len() - before);
        now += TICK_NS;
        if h.close_barrier.parked.len() == 1024 {
            break;
        }
    }
    drop(held);
    assert_eq!(h.close_barrier.parked.len(), 1024, "every blocked overflow Close parks in the end");
    assert!(
        parks_per_pass[0] < 1024,
        "Codex (af0ea8415c): one pass must not copy a 1,024-delta suffix 1,024 times"
    );
}

/// Codex review of af0ea8415c (passing control, kept as a cell): a
/// cancellation record cancels only the exact key and session id, and a
/// record taken while nothing is parked cannot cancel a later obligation.
#[test]
fn parked_close_cancellations_are_scoped_and_consumed_19026() {
    let mut h = Harness19026::new();
    let a = key_19026(19_083);
    h.queue_close(a.clone(), 101);
    let delta = h.sessions.drain_deltas(1).pop().unwrap();
    h.close_barrier.parked.push(delta.clone());
    // A stale id and a different full key must both leave A alone.
    assert!(!h.sessions.cancel_pending_close(&a, 100));
    let mut scope = a.clone();
    scope.routing_domain += 1;
    assert!(!h.sessions.cancel_pending_close(&scope, 101));
    let held = crate::afxdp::bpf_map::global_tuple_gate()
        .try_acquire_installs([a.clone()]).unwrap();
    h.tick(BASE_NS);
    assert_eq!(h.close_barrier.parked.len(), 1);
    assert!(h.sessions.take_parked_close_cancellations().is_empty());
    assert!(!h.sessions.cancel_pending_close(&a, 101));
    h.tick(BASE_NS + TICK_NS);
    assert!(h.close_barrier.parked.is_empty());
    assert!(h.sessions.take_parked_close_cancellations().is_empty());
    // Even a matching-id stale record is consumed when there is no parked row.
    assert!(!h.sessions.cancel_pending_close(&a, 101));
    h.tick(BASE_NS + 2*TICK_NS);
    h.close_barrier.parked.push(delta);
    h.tick(BASE_NS + 3*TICK_NS);
    assert_eq!(h.close_barrier.parked.len(), 1, "stale record cannot cancel a later obligation");
    drop(held);
    h.tick(BASE_NS + 4*TICK_NS);
    assert_eq!(h.flushed_closes_for(&a), 1);
}
