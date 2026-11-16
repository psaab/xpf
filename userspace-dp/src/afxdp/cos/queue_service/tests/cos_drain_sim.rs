//! Multi-worker shaped-drain simulation (#18748), shared by the CoS cells
//! that need several workers contending for one root.
//!
//! It drives the production drain entry (`drain_shaped_tx`), the production
//! enqueue (`enqueue_cos_item`, admission gates and exact-backlog publish
//! included), the production shared root lease, the production v8 exact
//! queue leases and the production shared exact backlog, with an injected
//! clock and a played kernel side of each worker's TX ring (submitted frames
//! complete before the worker's next pass).
//!
//! Each simulated microsecond every worker, in an order shuffled from the
//! seed, services its shaped queues until noop the way
//! `service_shaped_until_noop` does, bounded by a per-worker TX capacity (the
//! live per-worker forwarding ceiling; unused capacity banks up to
//! `TX_CREDIT_MAX`, an overdraw is carried as debt). Non-exact queues are kept
//! backlogged (open loop); exact arrivals are open loop at an offered rate,
//! spread round-robin over each worker's flows.
//!
//! The root lease starts DRAINED, and the root lease and the residual pool
//! are drained again when the window opens, so the window measures the
//! root's rate and not burst banked before it; `assert_every_seed` checks
//! every arm delivers at most 1.01 x the shaping rate.

use super::*;
use crate::afxdp::cos::builders::build_cos_interface_runtime;
use crate::afxdp::tx::cos_classify::enqueue_cos_item_for_test;
use crate::afxdp::tx::reap_tx_completions;
use crate::afxdp::types::{CoSInterfaceConfig, CoSPendingTxItem};
use crate::xsk_ffi::XdpDesc;

pub(super) const IFX: i32 = 42;
pub(super) const GBIT: u64 = 1_000_000_000 / 8;
pub(super) const SHAPING_BYTES: u64 = 25 * GBIT;
pub(super) const SHAPING_GBIT: f64 = 25.0;
pub(super) const FRAME: usize = 1500;
const STEP_NS: u64 = 1_000;
/// The exact classes' queue ids, in index order (the lab's 24g class is 10).
pub(super) const EXACT_QUEUE_IDS: [u8; 4] = [10, 9, 8, 7];
pub(super) const NONEXACT_QUEUE: u8 = 11;
/// Non-exact items kept queued per backlogged worker (always backlogged).
const NONEXACT_DEPTH: usize = 48;
/// Exact arrivals are offered to the production admission while the queue
/// holds less than this (open loop, so an over-offered class stays bounded).
const EXACT_MAX_DEPTH: u64 = 2_000 * FRAME as u64;
/// A worker banks at most this much unused TX capacity.
const TX_CREDIT_MAX: i64 = 8 * FRAME as i64;
/// Drain calls per worker per step (the until-noop loop's bound).
const MAX_PASSES: usize = 64;
const WARMUP_NS: u64 = 10_000_000;
pub(super) const WINDOW_NS: u64 = 60_000_000;
/// The committed seeds. A cell is green when every one of these passes; the
/// floors are derived from wider seed sweeps recorded in docs/log/18748.md.
pub(super) const SEEDS: [u64; 5] = [
    0x0000_1874_8001,
    0x0100_495d_8003,
    0x0200_7a46_8005,
    0x0300_ab2f_8007,
    0x0400_dc18_8009,
];
/// A backlogged non-exact instance must be served at least once in every
/// window this long (simulated time; the window under test is 60 ms).
pub(super) const MAX_UNSERVED_NS: u64 = 10_000_000;

pub(super) fn queue_config(queue_id: u8, transmit_rate_bytes: u64, exact: bool) -> CoSQueueConfig {
    CoSQueueConfig {
        queue_id,
        forwarding_class: format!("q{queue_id}").into(),
        priority: 5,
        transmit_rate_bytes,
        guarantee_enabled: exact,
        exact,
        surplus_sharing: false,
        equal_flow_enforcement: false,
        equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
        surplus_weight: 1,
        // The production default buffer: 1% of the queue's rate.
        buffer_bytes: transmit_rate_bytes / 100,
        dscp_rewrite: None,
        codel_target_ns: 0,
    }
}

/// The lab's `reth0.80`: 25 Gb/s shaping with `root_burst_bytes`,
/// `oversubscription-policy guarantee-rate 0.7`, the exact classes at
/// `exact_rates` (indices 0..k) and the uncapped non-exact class at index k
/// (transmit rate = the shaping rate, the builder's fallback for a
/// no-transmit-rate class).
pub(super) fn lab_runtime(exact_rates: &[u64], root_burst_bytes: u64) -> CoSInterfaceRuntime {
    let mut queues: Vec<CoSQueueConfig> = exact_rates
        .iter()
        .enumerate()
        .map(|(i, rate)| queue_config(EXACT_QUEUE_IDS[i], *rate, true))
        .collect();
    queues.push(queue_config(NONEXACT_QUEUE, SHAPING_BYTES, false));
    build_cos_interface_runtime(
        &CoSInterfaceConfig {
            queue_id_bitmap: [0; 4],
            shaping_rate_bytes: SHAPING_BYTES,
            burst_bytes: root_burst_bytes,
            default_queue: NONEXACT_QUEUE,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            inet_precedence_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            inet_precedence_queue_by_prec: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues,
            oversubscription_policy: CoSOversubscriptionPolicy::GuaranteeRate,
            oversubscription_guarantee_fraction: 0.7,
            priority_low_min_share_bytes: 0,
        },
        0,
    )
}

pub(super) fn sim_item(queue_id: u8, src_port: u16, now_ns: u64) -> CoSPendingTxItem {
    sim_item_len(queue_id, src_port, now_ns, FRAME)
}

/// `sim_item` with a packet of `len` bytes.
pub(super) fn sim_item_len(
    queue_id: u8,
    src_port: u16,
    now_ns: u64,
    len: usize,
) -> CoSPendingTxItem {
    CoSPendingTxItem::Local(TxRequest {
        bytes: vec![0; len].into(),
        expected_ports: None,
        expected_addr_family: libc::AF_INET as u8,
        expected_protocol: PROTO_TCP,
        flow_key: Some(test_session_key(src_port, 5200 + u16::from(queue_id))),
        egress_ifindex: IFX,
        cos_queue_id: Some(queue_id),
        dscp_rewrite: None,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: now_ns,
    })
}

/// The production enqueue. Returns whether admission accepted the item.
pub(super) fn sim_enqueue(
    binding: &mut BindingWorker,
    queue_id: u8,
    item: CoSPendingTxItem,
) -> bool {
    let now_ns = match &item {
        CoSPendingTxItem::Local(req) => req.enqueue_ns,
        CoSPendingTxItem::Prepared(req) => req.enqueue_ns,
    };
    enqueue_cos_item_for_test(binding, IFX, queue_id, item, now_ns).is_ok()
}

pub(super) fn queued_bytes(binding: &BindingWorker, queue_idx: usize) -> u64 {
    binding.cos.cos_interfaces.get(&IFX).expect("root").queues[queue_idx]
        .hot
        .queued_bytes
}

fn queue_sent(binding: &BindingWorker, queue_idx: usize) -> u64 {
    binding.cos.cos_interfaces.get(&IFX).expect("root").queues[queue_idx]
        .telemetry
        .owner_profile
        .drain_sent_bytes
        .load(std::sync::atomic::Ordering::Relaxed)
}

fn tx_total(binding: &BindingWorker) -> u64 {
    binding
        .live
        .tx_bytes
        .load(std::sync::atomic::Ordering::Relaxed)
}

/// One exact class of a simulated traffic shape.
#[derive(Clone, Debug)]
pub(super) struct ExactClass {
    /// Configured transmit-rate.
    pub(super) rate_bytes: u64,
    /// Arrivals per worker (bytes/s).
    pub(super) offered_bytes: Vec<u64>,
    /// Distinct flows per worker the arrivals are spread over.
    pub(super) flows: Vec<u16>,
    /// The class's buffer (and so its v8 lease burst) when it differs from
    /// the production default of 1% of its rate.
    pub(super) buffer_bytes: Option<u64>,
}

/// When an exact class's arrivals run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arrivals {
    /// From the start of the run (warm-up included).
    Always,
    /// Idle through the warm-up, then at the offered rate from the start of
    /// the measured window: an idle class waking up beside best-effort that
    /// has had the root to itself.
    FromWindowStart,
    /// Alternating `on_ns` at the offered rate and `off_ns` idle, from the
    /// start of the run.
    OnOff { on_ns: u64, off_ns: u64 },
}

/// One simulated traffic shape.
#[derive(Clone, Debug)]
pub(super) struct Arm {
    pub(super) workers: usize,
    pub(super) exact: Vec<ExactClass>,
    /// Which workers carry an always-backlogged non-exact instance.
    pub(super) nonexact_backlogged: Vec<bool>,
    /// Per-worker TX capacity (bytes/s).
    pub(super) worker_tx_cap_bytes: u64,
    /// The interface burst (the root lease's credit pool); the production
    /// default is 1% of the shaping rate.
    pub(super) root_burst_bytes: u64,
    /// #18748 review cycle 3: how often each worker drains, in simulated
    /// microseconds (1 = every step). A worker polled every `p` steps gets
    /// `p` steps of TX capacity at each poll.
    pub(super) poll_period_steps: Vec<u64>,
    /// A transmit-rate guarantee for every instance of the non-exact class
    /// (its buffer is 1% of it), or `None` for best-effort surplus only.
    pub(super) nonexact_guarantee_bytes: Option<u64>,
    /// When the exact classes' arrivals run (every class alike).
    pub(super) exact_arrivals: Arrivals,
    /// The measured window (the production cells use `WINDOW_NS`).
    pub(super) window_ns: u64,
    /// The non-exact class's `surplus_weight` (#19025: a weight above 1
    /// makes one surplus batch several frames, so a pass that is not bounded
    /// by its budget shows up as rate, not just as burst).
    pub(super) nonexact_surplus_weight: u32,
    /// #19025 review: a worker's own TX capacity when it differs from
    /// `worker_tx_cap_bytes` (bytes/s), for unequal-capacity shapes.
    pub(super) worker_tx_cap_override: Vec<Option<u64>>,
    /// #19025 review: an open-loop non-exact arrival rate (bytes/s) for a
    /// worker whose `nonexact_backlogged` is set, instead of keeping its
    /// queue full. A rate below what the worker gets lets the queue empty,
    /// so the set of backlogged non-exact bindings changes mid-window.
    pub(super) nonexact_offered_bytes: Vec<Option<u64>>,
    /// #19100: distinct non-exact flows per worker (default 4); each
    /// worker's arrivals cycle over them. Per-flow bytes are measured.
    pub(super) nonexact_flows: Vec<u16>,
    /// #19100: the arm's cells read per-flow bytes. Flow-fair buckets are
    /// seeded from OS entropy (`cos_flow_hash_seed_from_os`), so two flows
    /// occasionally share a bucket and cannot be told apart; such a run is
    /// re-drawn (new seeds) up to `ATTRIBUTION_ATTEMPTS` times.
    pub(super) needs_per_flow: bool,
    /// #19100 v6.1 (Codex v6 P1-2): the packet-cost model. Exact and
    /// non-exact packet sizes, and a fixed per-packet cost charged against
    /// the worker's TX capacity on top of the bytes (0 = bytes only).
    pub(super) exact_len: usize,
    pub(super) nonexact_len: usize,
    pub(super) packet_overhead_bytes: u64,
}

/// #19100: attempts to draw bucket seeds that keep every backlogged worker's
/// flows attributable (a 4-flow collision is about 0.6% per worker per run).
const ATTRIBUTION_ATTEMPTS: u32 = 4;

impl Arm {
    /// `workers` workers capped at `cap_gbit`, one exact class configured at
    /// `cfg_gbit` with `offered_gbit[w]` arriving on worker `w` (one flow per
    /// worker), and an always-backlogged non-exact instance on every worker.
    pub(super) fn new(workers: usize, cap_gbit: u64, cfg_gbit: u64, offered_gbit: &[u64]) -> Self {
        let mut offered_bytes = vec![0; workers];
        for (w, gbit) in offered_gbit.iter().enumerate() {
            offered_bytes[w] = gbit * GBIT;
        }
        Self {
            workers,
            exact: vec![ExactClass {
                rate_bytes: cfg_gbit * GBIT,
                offered_bytes,
                flows: vec![1; workers],
                buffer_bytes: None,
            }],
            nonexact_backlogged: vec![true; workers],
            worker_tx_cap_bytes: cap_gbit * GBIT,
            root_burst_bytes: SHAPING_BYTES / 100,
            poll_period_steps: vec![1; workers],
            nonexact_guarantee_bytes: None,
            exact_arrivals: Arrivals::Always,
            window_ns: WINDOW_NS,
            nonexact_surplus_weight: 1,
            worker_tx_cap_override: vec![None; workers],
            nonexact_offered_bytes: vec![None; workers],
            nonexact_flows: vec![4; workers],
            needs_per_flow: false,
            exact_len: FRAME,
            nonexact_len: FRAME,
            packet_overhead_bytes: 0,
        }
    }

    /// Exact bytes/s offered on worker `w`, over every class.
    pub(super) fn exact_offered_on(&self, w: usize) -> u64 {
        self.exact.iter().map(|class| class.offered_bytes[w]).sum()
    }
}

#[derive(Debug)]
pub(super) struct Outcome {
    /// Exact bytes sent per worker, every class.
    pub(super) exact_bytes: Vec<u64>,
    /// Exact bytes sent per class, every worker.
    pub(super) exact_class_bytes: Vec<u64>,
    pub(super) nonexact_bytes: Vec<u64>,
    /// Longest stretch, per backlogged non-exact instance, that sent nothing.
    pub(super) longest_unserved_ns: Vec<u64>,
    /// #18748 review cycle 2: longest stretch in the window in which no
    /// worker sent anything while some queue held work.
    pub(super) longest_global_stall_ns: u64,
    /// #18748 review cycle 3 (Codex: the global stall resets on any send, so
    /// it cannot see one class starved while another moves): per exact
    /// class, the longest stretch in the window in which the class had work
    /// queued on some worker and sent nothing.
    pub(super) longest_exact_class_stall_ns: Vec<u64>,
    pub(super) exact_root_parks: u64,
    pub(super) exact_queue_parks: u64,
    /// The measured window's length.
    pub(super) window_ns: u64,
    /// Per exact class, from the start of the window to the first step in
    /// which the class had sent something in the window.
    pub(super) first_exact_send_ns: Vec<Option<u64>>,
    /// Per exact class, `drain_shaped_tx` calls (every worker) from the start
    /// of the window through the step of its first send.
    pub(super) drains_to_first_exact: Vec<u64>,
    /// Per exact class, bytes sent in the first 1, 10 and 100 ms of the
    /// window (0 past the window's end).
    pub(super) exact_class_bytes_by_mark: Vec<[u64; 3]>,
    /// Per exact class, bytes that arrived in the window, and bytes of those
    /// the enqueue did not admit (the simulation's depth cap or admission).
    pub(super) exact_arrived_bytes: Vec<u64>,
    pub(super) exact_dropped_bytes: Vec<u64>,
    /// #19100: non-exact bytes sent in the window per worker per flow
    /// (`Arm::nonexact_flows` order).
    /// `None` for a worker whose flows could not be attributed (two flows
    /// in one flow-fair bucket, or several flows on a FIFO queue).
    pub(super) nonexact_flow_bytes: Vec<Option<Vec<u64>>>,
    /// #19100 attribution: per-worker drain counters over the window.
    pub(super) diag: Vec<SimDiag>,
    /// #19100 (Codex v6.1 P2-6): per worker, this simulation's colocated
    /// turn counters over the measurement window only (warm-up subtracted).
    pub(super) turns: Vec<crate::afxdp::types::V61TestCounters>,
}

/// #19100 attribution counters, per worker, over the measured window.
#[derive(Clone, Debug, Default)]
pub(super) struct SimDiag {
    /// Drain calls that sent exact / non-exact bytes, and those bytes.
    pub(super) exact_drains: u64,
    pub(super) exact_drain_bytes: u64,
    pub(super) nonexact_drains: u64,
    pub(super) nonexact_drain_bytes: u64,
    /// Drain calls that sent nothing while this worker's non-exact queue
    /// held backlog (with TX credit to spend).
    pub(super) noop_with_nonexact_backlog: u64,
    /// Steps the worker entered with no TX credit (paying a batch's debt).
    pub(super) tx_blocked_steps: u64,
    /// Steps on which any worker had published exact demand.
    pub(super) demand_steps: u64,
}

/// The marks of `Outcome::exact_class_bytes_by_mark`.
pub(super) const EXACT_MARKS_NS: [u64; 3] = [1_000_000, 10_000_000, 100_000_000];

impl Outcome {
    /// Bytes over a production `WINDOW_NS` window, in Gb/s.
    pub(super) fn gbps(bytes: u64) -> f64 {
        bytes as f64 * 8.0 / WINDOW_NS as f64
    }
    /// Bytes over this outcome's window, in Gb/s.
    fn rate(&self, bytes: u64) -> f64 {
        bytes as f64 * 8.0 / self.window_ns as f64
    }
    pub(super) fn exact_gbps(&self) -> f64 {
        self.rate(self.exact_bytes.iter().sum())
    }
    pub(super) fn exact_class_gbps(&self, class: usize) -> f64 {
        self.rate(self.exact_class_bytes[class])
    }
    pub(super) fn nonexact_gbps(&self, worker: usize) -> f64 {
        self.rate(self.nonexact_bytes[worker])
    }
    pub(super) fn nonexact_total_gbps(&self) -> f64 {
        self.rate(self.nonexact_bytes.iter().sum())
    }
    pub(super) fn total_gbps(&self) -> f64 {
        self.exact_gbps() + self.nonexact_total_gbps()
    }
    pub(super) fn report(&self, label: &str) -> String {
        let round = |b: &u64| (self.rate(*b) * 100.0).round() / 100.0;
        format!(
            "{label}: total {:.2}; exact {:.2} per class {:?} per worker {:?}; non-exact {:.2} per worker {:?}; \
             longest unserved ms {:?}; longest global stall us {}; longest stall us per exact class {:?}; \
             exact parks root/queue {}/{}",
            self.total_gbps(),
            self.exact_gbps(),
            self.exact_class_bytes.iter().map(round).collect::<Vec<_>>(),
            self.exact_bytes.iter().map(round).collect::<Vec<_>>(),
            self.nonexact_total_gbps(),
            self.nonexact_bytes.iter().map(round).collect::<Vec<_>>(),
            self.longest_unserved_ns
                .iter()
                .map(|ns| ns / 1_000_000)
                .collect::<Vec<_>>(),
            self.longest_global_stall_ns / 1_000,
            self.longest_exact_class_stall_ns
                .iter()
                .map(|ns| ns / 1_000)
                .collect::<Vec<_>>(),
            self.exact_root_parks,
            self.exact_queue_parks,
        )
    }
}

/// #19100: the source port of non-exact flow `flow` on worker `w`.
fn nonexact_flow_port(w: usize, flow: u16) -> u16 {
    40_000 + (w as u16) * 100 + flow
}

/// #19100: bytes of each of worker `w`'s non-exact flows still queued, from
/// the flow-fair buckets. A worker's flows must land in distinct buckets,
/// or the per-flow attribution is undefined and the harness says so.
fn nonexact_flow_queued(binding: &BindingWorker, queue_idx: usize, flows: u16) -> Option<Vec<u64>> {
    let flows = flows.max(1);
    let queue = &binding.cos.cos_interfaces.get(&IFX).expect("root").queues[queue_idx];
    let Some(ffs) = queue.flow_fair_state.as_ref() else {
        // A FIFO queue: one flow, or nothing queued (a worker with no
        // non-exact traffic, whose queue never promoted).
        let queued = queued_bytes(binding, queue_idx);
        if flows > 1 && queued > 0 {
            return None;
        }
        let mut out = vec![0; usize::from(flows)];
        out[0] = queued;
        return Some(out);
    };
    let buckets: Vec<usize> = (0..flows)
        .map(|f| {
            let key = test_session_key(nonexact_flow_port(binding.slot as usize, f), 5200 + u16::from(NONEXACT_QUEUE));
            cos_flow_bucket_index(ffs.flow_hash_seed, Some(&key))
        })
        .collect();
    for (i, b) in buckets.iter().enumerate() {
        if buckets[..i].contains(b) {
            return None;
        }
    }
    Some(buckets.iter().map(|b| ffs.flow_bucket_bytes[*b]).collect())
}

/// `simulate`, re-drawn while a backlogged worker's flows are not
/// attributable and the arm needs per-flow bytes (see `Arm::needs_per_flow`).
pub(super) fn simulate_attributed(arm: &Arm, seed: u64) -> Outcome {
    let mut outcome = simulate(arm, seed);
    for _ in 1..ATTRIBUTION_ATTEMPTS {
        let attributable = !arm.needs_per_flow
            || (0..arm.workers)
                .filter(|w| arm.nonexact_backlogged[*w])
                .all(|w| outcome.nonexact_flow_bytes[w].is_some());
        if attributable {
            break;
        }
        outcome = simulate(arm, seed);
    }
    outcome
}

pub(super) fn simulate(arm: &Arm, seed: u64) -> Outcome {
    let workers = arm.workers;
    let classes = arm.exact.len();
    let nonexact_idx = classes;
    let start_ns = 1_000_000_000u64;
    let root_lease = Arc::new(SharedCoSRootLease::new(
        SHAPING_BYTES,
        arm.root_burst_bytes,
        workers,
    ));
    // Start from a drained root: the initial credit pool is the 1%-of-rate
    // burst, and with every worker backlogged it would otherwise leak into the
    // measured window as rate above the shaping rate.
    loop {
        let granted = root_lease.acquire(start_ns, u64::MAX);
        if granted == 0 {
            break;
        }
        root_lease.consume(granted);
    }
    // The production exact-queue leases (coordinator/cos_leases.rs): v8,
    // burst = the queue's buffer, default rate mode.
    let exact_leases: Vec<Arc<SharedCoSQueueLease>> = arm
        .exact
        .iter()
        .map(|class| {
            Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
                class.rate_bytes,
                class.buffer_bytes.unwrap_or(class.rate_bytes / 100),
                workers,
                workers - 1,
                V8RateMode::CstructDefault,
                EqualFlowTargetPolicy::Slowest,
            ))
        })
        .collect();
    let exact_rates: Vec<u64> = arm.exact.iter().map(|class| class.rate_bytes).collect();
    let backlog = Arc::new(SharedCoSExactBacklog::new(workers - 1));
    let mut bindings: Vec<BindingWorker> = (0..workers)
        .map(|w| {
            let mut entries: Vec<(u8, WorkerCoSQueueFastPath)> = exact_leases
                .iter()
                .enumerate()
                .map(|(i, lease)| {
                    (
                        EXACT_QUEUE_IDS[i],
                        test_queue_fast_path(true, 0, None, Some(lease.clone())),
                    )
                })
                .collect();
            entries.push((NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)));
            let mut fast = test_cos_fast_interfaces(
                IFX,
                IFX,
                NONEXACT_QUEUE,
                entries,
                None,
                Some(root_lease.clone()),
            );
            fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
            let fast_path = fast.get(&IFX).expect("fast path").clone();
            // Production materialization (`ensure_cos_interface_runtime`):
            // the queues are promoted onto the flow-fair path for their
            // worker. Without it the v8 exact lease sees no active buckets
            // on any worker and never grants.
            let mut runtime = lab_runtime(&exact_rates, arm.root_burst_bytes);
            for (c, class) in arm.exact.iter().enumerate() {
                if let Some(buffer) = class.buffer_bytes {
                    runtime.queues[c].config.buffer_bytes = buffer;
                }
            }
            runtime.queues[nonexact_idx].config.surplus_weight = arm.nonexact_surplus_weight;
            runtime.shared_root_lease = fast_path.shared_root_lease.clone();
            if let Some(guarantee) = arm.nonexact_guarantee_bytes {
                let config = &mut runtime.queues[nonexact_idx].config;
                config.guarantee_enabled = true;
                config.transmit_rate_bytes = guarantee;
                config.buffer_bytes = guarantee / 100;
            }
            apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path.queue_fast_path, w as u32);
            BindingWorker::new_for_cos_drain_test(w as u32, w as u32, IFX, runtime, fast_path)
        })
        .collect();
    let mut recycles = Vec::new();
    let mut descs: Vec<XdpDesc> = Vec::new();
    let mut exact_credit = vec![vec![0u64; workers]; classes];
    let mut exact_flow_cursor = vec![vec![0u16; workers]; classes];
    let mut diag = vec![SimDiag::default(); workers];
    let mut nonexact_cursor = vec![0u16; workers];
    let mut flow_admitted: Vec<Vec<u64>> = (0..workers)
        .map(|w| vec![0u64; usize::from(arm.nonexact_flows[w].max(1))])
        .collect();
    let mut flow_base: Vec<Vec<u64>> = flow_admitted.clone();
    let mut flow_measurable = vec![false; workers];
    let mut base_nonexact = vec![0u64; workers];
    let mut base_turns = vec![crate::afxdp::types::V61TestCounters::default(); workers];
    let mut base_exact = vec![0u64; workers];
    let mut base_class = vec![0u64; classes];
    let mut last_progress = vec![0u64; workers];
    let mut last_sent = vec![0u64; workers];
    let mut longest = vec![0u64; workers];
    let mut global_last_sent = 0u64;
    let mut global_last_progress = 0u64;
    let mut longest_global_stall = 0u64;
    let mut class_last_sent = vec![0u64; classes];
    let mut class_last_progress = vec![0u64; classes];
    let mut longest_class_stall = vec![0u64; classes];
    let mut order: Vec<usize> = (0..workers).collect();
    let cap_per_step: Vec<i64> = (0..workers)
        .map(|w| {
            let cap = arm.worker_tx_cap_override[w].unwrap_or(arm.worker_tx_cap_bytes);
            (cap * STEP_NS / 1_000_000_000) as i64
        })
        .collect();
    let mut nonexact_credit = vec![0u64; workers];
    let mut tx_credit = vec![0i64; workers];
    let mut rng: u64 = seed | 1;
    let measure_ns = start_ns + WARMUP_NS;
    let end_ns = measure_ns + arm.window_ns;
    let mut first_send: Vec<Option<u64>> = vec![None; classes];
    let mut drains_to_first = vec![0u64; classes];
    let mut by_mark = vec![[0u64; 3]; classes];
    let mut arrived = vec![0u64; classes];
    let mut dropped = vec![0u64; classes];
    let mut drains_in_step = 0u64;
    let class_sent = |bindings: &Vec<BindingWorker>, class: usize| -> u64 {
        bindings.iter().map(|b| queue_sent(b, class)).sum()
    };
    let mut now = start_ns;
    while now < end_ns {
        let arriving = match arm.exact_arrivals {
            Arrivals::Always => true,
            Arrivals::FromWindowStart => now >= measure_ns,
            Arrivals::OnOff { on_ns, off_ns } => (now - start_ns) % (on_ns + off_ns) < on_ns,
        };
        for w in 0..workers {
            for (c, class) in arm.exact.iter().enumerate() {
                if !arriving {
                    continue;
                }
                exact_credit[c][w] += class.offered_bytes[w] * STEP_NS / 1_000_000_000;
                while exact_credit[c][w] >= arm.exact_len as u64 {
                    exact_credit[c][w] -= arm.exact_len as u64;
                    let admitted = queued_bytes(&bindings[w], c) < EXACT_MAX_DEPTH && {
                        let flows = class.flows[w].max(1);
                        exact_flow_cursor[c][w] = (exact_flow_cursor[c][w] + 1) % flows;
                        let port = 30_000
                            + (c as u16) * 1_000
                            + (w as u16) * 100
                            + exact_flow_cursor[c][w];
                        let item = sim_item_len(EXACT_QUEUE_IDS[c], port, now, arm.exact_len);
                        sim_enqueue(&mut bindings[w], EXACT_QUEUE_IDS[c], item)
                    };
                    if now >= measure_ns {
                        arrived[c] += arm.exact_len as u64;
                        if !admitted {
                            dropped[c] += arm.exact_len as u64;
                        }
                    }
                }
            }
            if arm.nonexact_backlogged[w] {
                if let Some(rate) = arm.nonexact_offered_bytes[w] {
                    nonexact_credit[w] += rate * STEP_NS / 1_000_000_000;
                }
                while queued_bytes(&bindings[w], nonexact_idx) < (NONEXACT_DEPTH * FRAME) as u64 {
                    if arm.nonexact_offered_bytes[w].is_some() {
                        if nonexact_credit[w] < FRAME as u64 {
                            break;
                        }
                        nonexact_credit[w] -= FRAME as u64;
                    }
                    let flows = arm.nonexact_flows[w].max(1);
                    nonexact_cursor[w] = (nonexact_cursor[w] + 1) % flows;
                    let port = nonexact_flow_port(w, nonexact_cursor[w]);
                    let item = sim_item_len(NONEXACT_QUEUE, port, now, arm.nonexact_len);
                    if !sim_enqueue(&mut bindings[w], NONEXACT_QUEUE, item) {
                        break;
                    }
                    flow_admitted[w][usize::from(nonexact_cursor[w])] += arm.nonexact_len as u64;
                }
            }
        }
        // Live workers interleave arbitrarily; a fixed order would hand
        // every root refill to whichever worker always drains first.
        for i in (1..workers).rev() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            order.swap(i, (rng % (i as u64 + 1)) as usize);
        }
        let step = (now - start_ns) / STEP_NS;
        for &w in &order {
            let period = arm.poll_period_steps[w].max(1);
            if (step + w as u64 * 7) % period != 0 {
                continue;
            }
            let poll_cap = cap_per_step[w] * period as i64;
            tx_credit[w] = (tx_credit[w] + poll_cap).min(TX_CREDIT_MAX.max(poll_cap));
            let binding = &mut bindings[w];
            let in_window = now >= measure_ns;
            if in_window {
                if tx_credit[w] <= 0 {
                    diag[w].tx_blocked_steps += 1;
                }
                if !backlog.peer_exact_demand_queue_mask(u32::MAX).is_empty() {
                    diag[w].demand_steps += 1;
                }
            }
            for _ in 0..MAX_PASSES {
                if tx_credit[w] <= 0 {
                    break;
                }
                let before = tx_total(binding);
                let nonexact_before = queue_sent(binding, nonexact_idx);
                drains_in_step += 1;
                let serviced = drain_shaped_tx(binding, now, &mut recycles);
                descs.clear();
                binding.xsk.tx.take_submitted_for_test(&mut descs);
                for desc in &descs {
                    binding.xsk.device.push_comp_for_test(desc.addr);
                }
                let _ = reap_tx_completions(binding, &mut recycles);
                recycles.clear();
                let sent = tx_total(binding) - before;
                let packets_sent = descs.len() as u64;
                let nonexact_sent = queue_sent(binding, nonexact_idx) - nonexact_before;
                if in_window {
                    let d = &mut diag[w];
                    if nonexact_sent > 0 {
                        d.nonexact_drains += 1;
                        d.nonexact_drain_bytes += nonexact_sent;
                    }
                    if sent > nonexact_sent {
                        d.exact_drains += 1;
                        d.exact_drain_bytes += sent - nonexact_sent;
                    }
                    if sent == 0 && queued_bytes(binding, nonexact_idx) > 0 {
                        d.noop_with_nonexact_backlog += 1;
                    }
                }
                tx_credit[w] -= (sent + packets_sent * arm.packet_overhead_bytes) as i64;
                if serviced.is_none() || sent == 0 {
                    break;
                }
            }
        }
        if now == measure_ns {
            // The window starts with empty interface pools: root or residual
            // credit banked while warm-up ramped up (the residual starts
            // closed, so non-exact sends nothing at first and the root banks)
            // would otherwise be spent inside the window as rate above the
            // shaping rate.
            // Credit the workers hold locally goes back to the lease first,
            // then the lease's available credit is spent: the window starts
            // with no root credit anywhere.
            for binding in bindings.iter_mut() {
                if let Some(root) = binding.cos.cos_interfaces.get_mut(&IFX) {
                    let held = core::mem::take(&mut root.tokens);
                    if held > 0 {
                        root_lease.release_unused(held);
                    }
                }
            }
            loop {
                let granted = root_lease.acquire(now, u64::MAX);
                if granted == 0 {
                    break;
                }
                root_lease.consume(granted);
            }
            // #19100 v3 (Codex): empty the residual pool through its own
            // reset (zero tokens, new generation), not by spending it.
            backlog.reset_residual_surplus_budget(now);
            for (w, binding) in bindings.iter().enumerate() {
                base_nonexact[w] = queue_sent(binding, nonexact_idx);
                base_turns[w] = binding.cos.cos_interfaces[&IFX].v61_test;
                base_exact[w] = tx_total(binding) - base_nonexact[w];
                last_sent[w] = base_nonexact[w];
                last_progress[w] = now;
            }
            for (c, base) in base_class.iter_mut().enumerate() {
                *base = class_sent(&bindings, c);
            }
            for w in 0..workers {
                flow_measurable[w] = false;
                if let Some(queued) = nonexact_flow_queued(&bindings[w], nonexact_idx, arm.nonexact_flows[w]) {
                    flow_measurable[w] = true;
                    for (f, base) in flow_base[w].iter_mut().enumerate() {
                        *base = flow_admitted[w][f] - queued[f];
                    }
                }
            }
        } else if now > measure_ns {
            for (w, binding) in bindings.iter().enumerate() {
                if !arm.nonexact_backlogged[w] {
                    continue;
                }
                let sent = queue_sent(binding, nonexact_idx);
                if sent > last_sent[w] {
                    last_sent[w] = sent;
                    last_progress[w] = now;
                } else {
                    longest[w] = longest[w].max(now - last_progress[w]);
                }
            }
        }
        if now >= measure_ns {
            let sent: u64 = bindings.iter().map(tx_total).sum();
            let queued = bindings.iter().any(|binding| {
                binding
                    .cos
                    .cos_interfaces
                    .get(&IFX)
                    .is_some_and(|root| root.nonempty_queues > 0)
            });
            if now == measure_ns || sent > global_last_sent || !queued {
                global_last_sent = sent;
                global_last_progress = now;
            } else {
                longest_global_stall = longest_global_stall.max(now - global_last_progress);
            }
        }
        if now >= measure_ns {
            for c in 0..classes {
                let in_window = class_sent(&bindings, c) - base_class[c];
                if first_send[c].is_none() {
                    drains_to_first[c] += drains_in_step;
                    if in_window > 0 {
                        first_send[c] = Some(now - measure_ns);
                    }
                }
                for (m, mark) in EXACT_MARKS_NS.iter().enumerate() {
                    if now - measure_ns + STEP_NS == *mark {
                        by_mark[c][m] = in_window;
                    }
                }
            }
        }
        drains_in_step = 0;
        if now >= measure_ns {
            for c in 0..classes {
                let sent = class_sent(&bindings, c);
                let queued = bindings.iter().any(|binding| queued_bytes(binding, c) > 0);
                if now == measure_ns || sent > class_last_sent[c] || !queued {
                    class_last_sent[c] = sent;
                    class_last_progress[c] = now;
                } else {
                    longest_class_stall[c] =
                        longest_class_stall[c].max(now - class_last_progress[c]);
                }
            }
        }
        now += STEP_NS;
    }
    let nonexact_bytes: Vec<u64> = bindings
        .iter()
        .enumerate()
        .map(|(w, b)| queue_sent(b, nonexact_idx) - base_nonexact[w])
        .collect();
    let nonexact_flow_bytes: Vec<Option<Vec<u64>>> = (0..workers)
        .map(|w| {
            if !flow_measurable[w] {
                return None;
            }
            let queued = nonexact_flow_queued(&bindings[w], nonexact_idx, arm.nonexact_flows[w])?;
            Some(
                (0..flow_admitted[w].len())
                    .map(|f| flow_admitted[w][f] - queued[f] - flow_base[w][f])
                    .collect(),
            )
        })
        .collect();
    // #19100 v3 (Codex): per-flow bytes are admissions less what is still
    // queued, so a post-admission drop would count as sent. Reconcile each
    // worker's flow sum with its committed non-exact TX bytes.
    for (w, flows) in nonexact_flow_bytes.iter().enumerate() {
        let Some(flows) = flows else { continue };
        let sum: u64 = flows.iter().sum();
        assert_eq!(
            sum, nonexact_bytes[w],
            "harness: worker {w}: per-flow bytes {sum} != committed non-exact TX {} \
             (a post-admission drop?)",
            nonexact_bytes[w]
        );
    }
    let exact_bytes: Vec<u64> = bindings
        .iter()
        .enumerate()
        .map(|(w, b)| tx_total(b) - queue_sent(b, nonexact_idx) - base_exact[w])
        .collect();
    let exact_class_bytes: Vec<u64> = (0..classes)
        .map(|c| class_sent(&bindings, c) - base_class[c])
        .collect();
    let (exact_root_parks, exact_queue_parks) = bindings.iter().fold((0, 0), |acc, b| {
        let root = b.cos.cos_interfaces.get(&IFX).expect("root");
        root.queues[..classes].iter().fold(acc, |acc, q| {
            (
                acc.0 + q.telemetry.drop_counters.root_token_starvation_parks,
                acc.1 + q.telemetry.drop_counters.queue_token_starvation_parks,
            )
        })
    });
    Outcome {
        exact_bytes,
        exact_class_bytes,
        nonexact_bytes,
        longest_unserved_ns: longest,
        longest_global_stall_ns: longest_global_stall,
        longest_exact_class_stall_ns: longest_class_stall,
        exact_root_parks,
        exact_queue_parks,
        window_ns: arm.window_ns,
        first_exact_send_ns: first_send,
        drains_to_first_exact: drains_to_first,
        exact_class_bytes_by_mark: by_mark,
        exact_arrived_bytes: arrived,
        exact_dropped_bytes: dropped,
        nonexact_flow_bytes,
        diag,
        turns: bindings
            .iter()
            .enumerate()
            .map(|(w, b)| {
                let now = b.cos.cos_interfaces[&IFX].v61_test;
                let base = base_turns[w];
                crate::afxdp::types::V61TestCounters {
                    funded_builds: now.funded_builds - base.funded_builds,
                    minimum_builds: now.minimum_builds - base.minimum_builds,
                    turn_submits: now.turn_submits - base.turn_submits,
                    turn_bytes: now.turn_bytes - base.turn_bytes,
                    turn_packets: now.turn_packets - base.turn_packets,
                }
            })
            .collect(),
    }
}

/// Run `arm` once per committed seed and check `property` on every outcome,
/// failing with every seed's report so a red cell shows the whole matrix.
/// Every outcome must also conserve the root: at most 1.01 x the shaping rate.
pub(super) fn assert_every_seed(
    name: &str,
    arm: &Arm,
    property: impl Fn(&Outcome) -> Result<(), String>,
) {
    if let Err(failure) = check_every_seed(name, arm, property) {
        panic!("{failure}");
    }
}

/// `assert_every_seed` without the panic: `Err` carries every failing seed's
/// report and reason and every seed's report, so a cell can check several
/// arms and report every arm that failed.
pub(super) fn check_every_seed(
    name: &str,
    arm: &Arm,
    property: impl Fn(&Outcome) -> Result<(), String>,
) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut reports = Vec::new();
    for seed in SEEDS {
        let outcome = simulate_attributed(arm, seed);
        let report = outcome.report(&format!("{name} seed {seed:#x}"));
        let verdict = if outcome.total_gbps() > 1.01 * SHAPING_GBIT {
            Err(format!(
                "harness: {:.2} Gb/s through a {SHAPING_GBIT:.0} Gb/s root",
                outcome.total_gbps()
            ))
        } else {
            property(&outcome)
        };
        if let Err(why) = verdict {
            failures.push(format!("{report}\n    -> {why}"));
        }
        reports.push(report);
    }
    if failures.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{name}: {} of {} seeds failed:\n  {}\nall seeds:\n  {}",
        failures.len(),
        SEEDS.len(),
        failures.join("\n  "),
        reports.join("\n  ")
    ))
}
