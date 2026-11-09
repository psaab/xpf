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
    /// This worker's own command queue (R13 F4 zombie retirement lands here).
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
const PARK_TICKS: u64 = super::close_barrier::CLOSE_PARK_AFTER_NS / TICK_NS;

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
    assert_eq!(h.close_barrier.expired_episodes, 1, "one blocked episode");
    assert_eq!(parked, 1, "R13 F1: past the park bound the Close sits in the side slot");
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
    assert_eq!(h.close_barrier.expired_episodes, 0, "no episode outlived the bound");
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
    assert_eq!(h.close_barrier.expired_episodes, 1, "only the first episode expired");
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
    for _ in 0..(PARK_TICKS + 5) {
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
    for _ in 0..(BARRIER_TICKS + 2) {
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

/// R13 F4: while RX polled with the Close blocked, a packet re-materialized a
/// same-id local row. When the Close retires, that zombie is queued for
/// `DeleteSynced` on THIS worker (the flush fans out to siblings only).
#[test]
fn rx_exposed_zombie_is_retired_when_the_close_drains_19026() {
    for park in [false, true] {
        let mut h = Harness19026::new();
        let key = key_19026(if park { 19_044 } else { 19_043 });
        let id = 0x1902_6013;
        h.queue_close(key.clone(), id);
        let held = crate::afxdp::bpf_map::global_tuple_gate()
            .try_acquire_installs([key.clone()])
            .expect("hold the tuple");
        let mut now = BASE_NS;
        let ticks = if park { PARK_TICKS + 2 } else { BARRIER_TICKS + 2 };
        for _ in 0..ticks {
            h.tick(now);
            now += TICK_NS;
        }
        // The re-materialized replica of the closing session (same id).
        assert!(h.sessions.upsert_synced_with_origin(
            crate::session::SessionInstall {
                key: key.clone(),
                decision: decision_19026(),
                metadata: metadata_19026(),
                source_nat_static: None,
                origin: SessionOrigin::SharedMaterialize,
                now_ns: now,
                protocol: PROTO_TCP,
                tcp_flags: crate::tcp_flags::TCP_ACK,
                session_id: id,
                tcp_close_class: 0,
                tcp_handshake_state: 0,
                persistent_lease_hold: None,
                fwd_packets: 0,
                rev_packets: 0,
            },
            true,
        ));
        drop(held);
        h.tick(now);
        now += TICK_NS;
        h.tick(now);
        assert_eq!(h.flushed_closes_for(&key), 1, "park={park}: the Close retired");
        let queued = h
            .own_queue
            .lock()
            .expect("own queue")
            .iter()
            .filter(|c| matches!(c, WorkerCommand::DeleteSynced(k) if *k == key))
            .count();
        assert_eq!(
            queued,
            1,
            "#19026 R13 F4 (park={park}): the same-id zombie is queued for DeleteSynced here"
        );
    }
}

/// R13 F5: two different Closes blocked back to back are two episodes; the
/// second gets its own teardown-before-poll window (master/bb9608f1a6 let it
/// inherit the first's expired episode and poll RX at once).
#[test]
fn chained_blocked_closes_each_get_their_own_window_19026() {
    let mut h = Harness19026::new();
    let first = key_19026(19_045);
    let second = key_19026(19_046);
    h.queue_close(first.clone(), 0x1902_6014);
    h.queue_close(second.clone(), 0x1902_6015);
    let gate = crate::afxdp::bpf_map::global_tuple_gate();
    let hold_first = gate.try_acquire_installs([first.clone()]).expect("hold first");
    let hold_second = gate.try_acquire_installs([second.clone()]).expect("hold second");
    let mut now = BASE_NS;
    for _ in 0..(BARRIER_TICKS + 3) {
        h.tick(now);
        now += TICK_NS;
    }
    assert_eq!(h.close_barrier.expired_episodes, 1);
    drop(hold_first);
    assert!(
        h.tick(now),
        "#19026 R13 F5: the second blocked Close starts its own RX window"
    );
    for _ in 0..(BARRIER_TICKS + 2) {
        now += TICK_NS;
        h.tick(now);
    }
    drop(hold_second);
    assert_eq!(h.close_barrier.expired_episodes, 2, "two episodes, each counted");
    assert_eq!(h.flushed_closes_for(&first), 1);
}

/// Codex P2 #5: overflow Closes deferred by an earlier tick are retired before
/// newer ring events (RX-era opens) once their permit frees.
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
