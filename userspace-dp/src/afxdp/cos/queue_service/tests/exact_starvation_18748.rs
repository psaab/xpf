//! #18748: a backlogged EXACT class starves the per-worker instances of a
//! NON-exact class under root saturation, and the exact class itself falls
//! far below its guarantee.
//!
//! Live (tcp lab, `reth0.80` shaped 25 Gb/s, `guarantee-rate 0.7`): an exact
//! `iperf-24g` class carrying 2 TCP flows plus the non-exact `iperf-uncapped`
//! class (8 TCP flows). Every worker drew about an equal share of the root.
//! On a worker that carried an exact flow, the exact queue's guarantee
//! priority spent that whole share, the colocated non-exact flow got about
//! nothing (0.026 Gbit/s, head age 4.1 s), and the exact class ran at about
//! one worker's share (2.2-3.5 Gb/s per flow) against its 24 Gb/s guarantee.
//!
//! This is a multi-worker drain simulation on the production drain entry
//! (`drain_shaped_tx`), the production shared root lease, the production v8
//! exact queue lease and the production shared exact backlog, with an
//! injected clock and a played kernel side of each worker's TX ring. Each
//! simulated microsecond every worker, in a shuffled order, services its
//! shaped queues until noop the way `service_shaped_until_noop` does, bounded
//! by a per-worker TX capacity (the live per-worker forwarding ceiling).
//! Non-exact queues are kept backlogged (open loop); exact arrivals are
//! open loop at an offered rate.
//!
//! Every cell runs `SEEDS` (the worker order is shuffled per step from the
//! seed) and every seed must pass. On master (#hb166 T-6(b) predicate:
//! runnable AND root tokens AND queue tokens cover the head) the colocated,
//! cross-worker and self-limited cells fail in most seeds: a root-parked
//! exact queue dropped out of the demand masks, so peers never reserved root
//! for it. The release cell and the no-exact control pass on both; the
//! release cell is what keeps the T-6(b) protection honest.

use super::*;
use crate::afxdp::cos::builders::build_cos_interface_runtime;
use crate::afxdp::cos::queue_ops::cos_queue_is_empty;
use crate::afxdp::cos::tx_completion::mark_cos_queue_runnable;
use crate::afxdp::tx::reap_tx_completions;
use crate::afxdp::types::{CoSInterfaceConfig, CoSPendingTxItem};
use crate::xsk_ffi::XdpDesc;

const IFX: i32 = 42;
const GBIT: u64 = 1_000_000_000 / 8;
const SHAPING_BYTES: u64 = 25 * GBIT;
const FRAME: usize = 1500;
const STEP_NS: u64 = 1_000;
const EXACT_QUEUE: u8 = 10;
const NONEXACT_QUEUE: u8 = 11;
const EXACT_IDX: usize = 0;
const NONEXACT_IDX: usize = 1;
/// Non-exact items kept queued per backlogged worker (always backlogged).
const NONEXACT_DEPTH: usize = 48;
/// Exact arrivals beyond this queued depth are tail-dropped (open loop, so
/// an over-offered class must not grow without bound).
const EXACT_MAX_DEPTH: u64 = 2_000 * FRAME as u64;
/// A worker banks at most this much unused TX capacity.
const TX_CREDIT_MAX: i64 = 8 * FRAME as i64;
/// Drain calls per worker per step (the until-noop loop's bound).
const MAX_PASSES: usize = 64;
const WARMUP_NS: u64 = 10_000_000;
const WINDOW_NS: u64 = 60_000_000;
const SEEDS: [u64; 5] = [
    0x0000_1874_8001,
    0x0100_495d_8003,
    0x0200_7a46_8005,
    0x0300_ab2f_8007,
    0x0400_dc18_8009,
];
/// A backlogged non-exact instance must be served at least once in every
/// window this long (simulated time; the window under test is 60 ms).
const MAX_UNSERVED_NS: u64 = 10_000_000;

fn queue_config(queue_id: u8, transmit_rate_bytes: u64, exact: bool) -> CoSQueueConfig {
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

/// The lab's `reth0.80`: 25 Gb/s shaping with the default burst (1% of the
/// rate), `oversubscription-policy guarantee-rate 0.7`, an exact class at
/// `exact_rate_bytes` and the uncapped non-exact class (transmit rate = the
/// shaping rate, the builder's fallback for a no-transmit-rate class).
fn lab_runtime(exact_rate_bytes: u64) -> CoSInterfaceRuntime {
    build_cos_interface_runtime(
        &CoSInterfaceConfig {
            queue_id_bitmap: [0; 4],
            shaping_rate_bytes: SHAPING_BYTES,
            burst_bytes: SHAPING_BYTES / 100,
            default_queue: NONEXACT_QUEUE,
            dscp_classifier: String::new(),
            ieee8021_classifier: String::new(),
            inet_precedence_classifier: String::new(),
            dscp_queue_by_dscp: [u8::MAX; 64],
            ieee8021_queue_by_pcp: [u8::MAX; 8],
            inet_precedence_queue_by_prec: [u8::MAX; 8],
            queue_by_forwarding_class: FastMap::default(),
            queues: vec![
                queue_config(EXACT_QUEUE, exact_rate_bytes, true),
                queue_config(NONEXACT_QUEUE, SHAPING_BYTES, false),
            ],
            oversubscription_policy: CoSOversubscriptionPolicy::GuaranteeRate,
            oversubscription_guarantee_fraction: 0.7,
            priority_low_min_share_bytes: 0,
        },
        0,
    )
}

fn sim_item(queue_id: u8, src_port: u16, now_ns: u64) -> CoSPendingTxItem {
    CoSPendingTxItem::Local(TxRequest {
        bytes: vec![0; FRAME].into(),
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

/// The production enqueue's queue/root bookkeeping (`enqueue_cos_item`,
/// tx/cos_classify.rs) for an accepted item, including the exact-backlog
/// publish, without its admission gates.
fn sim_enqueue(binding: &mut BindingWorker, queue_idx: usize, item: CoSPendingTxItem) {
    let mut root_became_nonempty = false;
    let exact;
    {
        let root = binding.cos.cos_interfaces.get_mut(&IFX).expect("root");
        let root_was_empty = root.nonempty_queues == 0;
        let queue = &mut root.queues[queue_idx];
        exact = queue.config.exact;
        let queue_was_empty = cos_queue_is_empty(queue);
        queue.hot.queued_bytes = queue.hot.queued_bytes.saturating_add(FRAME as u64);
        cos_queue_push_back(queue, item);
        if queue_was_empty {
            root.nonempty_queues = root.nonempty_queues.saturating_add(1);
            root_became_nonempty = root_was_empty;
        }
        if !queue.hot.parked && !queue.hot.runnable {
            root.runnable_queues = root.runnable_queues.saturating_add(1);
        }
        if !queue.hot.parked {
            mark_cos_queue_runnable(queue);
        }
    }
    if root_became_nonempty {
        binding.cos.cos_nonempty_interfaces = binding.cos.cos_nonempty_interfaces.saturating_add(1);
    }
    if exact {
        crate::afxdp::cos::publish_cos_exact_backlog(binding, IFX);
    }
}

fn queued_bytes(binding: &BindingWorker, queue_idx: usize) -> u64 {
    binding.cos.cos_interfaces.get(&IFX).expect("root").queues[queue_idx]
        .hot
        .queued_bytes
}

fn nonexact_sent(binding: &BindingWorker) -> u64 {
    binding.cos.cos_interfaces.get(&IFX).expect("root").queues[NONEXACT_IDX]
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

/// One simulated traffic shape.
#[derive(Clone, Debug)]
struct Arm {
    workers: usize,
    /// Configured transmit-rate of the exact class.
    exact_rate_bytes: u64,
    /// Exact arrivals per worker (bytes/s).
    exact_offered_bytes: Vec<u64>,
    /// Which workers carry an always-backlogged non-exact instance.
    nonexact_backlogged: Vec<bool>,
    /// Per-worker TX capacity (bytes/s).
    worker_tx_cap_bytes: u64,
    /// `false` builds the exact queue without its shared lease, so its own
    /// token bucket never covers a head: a backlogged class limited by
    /// ITSELF that ships zero bytes (the #hb166 T-6(b) release state).
    exact_has_lease: bool,
}

impl Arm {
    /// `workers` workers capped at `cap_gbit`, an exact class configured at
    /// `cfg_gbit` with `offered_gbit[w]` arriving on worker `w`, and an
    /// always-backlogged non-exact instance on every worker.
    fn new(workers: usize, cap_gbit: u64, cfg_gbit: u64, offered_gbit: &[u64]) -> Self {
        let mut exact_offered_bytes = vec![0; workers];
        for (w, gbit) in offered_gbit.iter().enumerate() {
            exact_offered_bytes[w] = gbit * GBIT;
        }
        Self {
            workers,
            exact_rate_bytes: cfg_gbit * GBIT,
            exact_offered_bytes,
            nonexact_backlogged: vec![true; workers],
            worker_tx_cap_bytes: cap_gbit * GBIT,
            exact_has_lease: true,
        }
    }
}

#[derive(Debug)]
struct Outcome {
    exact_bytes: Vec<u64>,
    nonexact_bytes: Vec<u64>,
    /// Longest stretch, per backlogged non-exact instance, that sent nothing.
    longest_unserved_ns: Vec<u64>,
    exact_root_parks: u64,
    exact_queue_parks: u64,
}

impl Outcome {
    fn gbps(bytes: u64) -> f64 {
        bytes as f64 * 8.0 / WINDOW_NS as f64
    }
    fn exact_gbps(&self) -> f64 {
        Self::gbps(self.exact_bytes.iter().sum())
    }
    fn nonexact_gbps(&self, worker: usize) -> f64 {
        Self::gbps(self.nonexact_bytes[worker])
    }
    fn nonexact_total_gbps(&self) -> f64 {
        Self::gbps(self.nonexact_bytes.iter().sum())
    }
    fn report(&self, label: &str) -> String {
        format!(
            "{label}: total {:.2}; exact {:.2} {:?}; non-exact {:.2} per worker {:?}; longest unserved ms {:?}; exact parks root/queue {}/{}",
            self.exact_gbps() + self.nonexact_total_gbps(),
            self.exact_gbps(),
            self.exact_bytes
                .iter()
                .map(|b| (Self::gbps(*b) * 100.0).round() / 100.0)
                .collect::<Vec<_>>(),
            self.nonexact_total_gbps(),
            self.nonexact_bytes
                .iter()
                .map(|b| (Self::gbps(*b) * 100.0).round() / 100.0)
                .collect::<Vec<_>>(),
            self.longest_unserved_ns
                .iter()
                .map(|ns| ns / 1_000_000)
                .collect::<Vec<_>>(),
            self.exact_root_parks,
            self.exact_queue_parks,
        )
    }
}

fn simulate(arm: &Arm, seed: u64) -> Outcome {
    let workers = arm.workers;
    let root_lease = Arc::new(SharedCoSRootLease::new(
        SHAPING_BYTES,
        SHAPING_BYTES / 100,
        workers,
    ));
    // The production exact-queue lease (coordinator/cos_leases.rs): v8,
    // burst = the queue's buffer, default rate mode.
    let exact_lease = Arc::new(SharedCoSQueueLease::new_v8_with_rate_mode_and_policy(
        arm.exact_rate_bytes,
        arm.exact_rate_bytes / 100,
        workers,
        workers - 1,
        V8RateMode::CstructDefault,
        EqualFlowTargetPolicy::Slowest,
    ));
    let backlog = Arc::new(SharedCoSExactBacklog::new(workers - 1));
    let mut bindings: Vec<BindingWorker> = (0..workers)
        .map(|w| {
            let mut fast = test_cos_fast_interfaces(
                IFX,
                IFX,
                NONEXACT_QUEUE,
                vec![
                    (
                        EXACT_QUEUE,
                        test_queue_fast_path(
                            true,
                            0,
                            None,
                            arm.exact_has_lease.then(|| exact_lease.clone()),
                        ),
                    ),
                    (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
                ],
                None,
                Some(root_lease.clone()),
            );
            fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
            let fast_path = fast.get(&IFX).expect("fast path").clone();
            // Production materialization (`ensure_cos_interface_runtime`):
            // the queues are promoted onto the flow-fair path for their
            // worker. Without it the v8 exact lease sees no active buckets
            // on any worker and never grants.
            let mut runtime = lab_runtime(arm.exact_rate_bytes);
            runtime.shared_root_lease = fast_path.shared_root_lease.clone();
            apply_cos_queue_flow_fair_promotion(&mut runtime, &fast_path.queue_fast_path, w as u32);
            BindingWorker::new_for_cos_drain_test(w as u32, w as u32, IFX, runtime, fast_path)
        })
        .collect();
    let mut recycles = Vec::new();
    let mut descs: Vec<XdpDesc> = Vec::new();
    let mut exact_credit = vec![0u64; workers];
    let mut nonexact_port: Vec<u16> = (0..workers).map(|w| 40_000 + (w as u16) * 100).collect();
    let mut base_nonexact = vec![0u64; workers];
    let mut base_exact = vec![0u64; workers];
    let mut last_progress = vec![0u64; workers];
    let mut last_sent = vec![0u64; workers];
    let mut longest = vec![0u64; workers];
    let mut order: Vec<usize> = (0..workers).collect();
    let cap_per_step = (arm.worker_tx_cap_bytes * STEP_NS / 1_000_000_000) as i64;
    let mut tx_credit = vec![0i64; workers];
    let mut rng: u64 = seed | 1;
    let start_ns = 1_000_000_000u64;
    let measure_ns = start_ns + WARMUP_NS;
    let end_ns = measure_ns + WINDOW_NS;
    let mut now = start_ns;
    while now < end_ns {
        for w in 0..workers {
            exact_credit[w] += arm.exact_offered_bytes[w] * STEP_NS / 1_000_000_000;
            while exact_credit[w] >= FRAME as u64 {
                exact_credit[w] -= FRAME as u64;
                if queued_bytes(&bindings[w], EXACT_IDX) < EXACT_MAX_DEPTH {
                    let item = sim_item(EXACT_QUEUE, 30_000 + w as u16, now);
                    sim_enqueue(&mut bindings[w], EXACT_IDX, item);
                }
            }
            if arm.nonexact_backlogged[w] {
                while queued_bytes(&bindings[w], NONEXACT_IDX) < (NONEXACT_DEPTH * FRAME) as u64 {
                    nonexact_port[w] = 40_000 + (w as u16) * 100 + ((nonexact_port[w] + 1) % 4);
                    let item = sim_item(NONEXACT_QUEUE, nonexact_port[w], now);
                    sim_enqueue(&mut bindings[w], NONEXACT_IDX, item);
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
        for &w in &order {
            tx_credit[w] = (tx_credit[w] + cap_per_step).min(TX_CREDIT_MAX);
            let binding = &mut bindings[w];
            for _ in 0..MAX_PASSES {
                if tx_credit[w] <= 0 {
                    break;
                }
                let before = tx_total(binding);
                let serviced = drain_shaped_tx(binding, now, &mut recycles);
                descs.clear();
                binding.xsk.tx.take_submitted_for_test(&mut descs);
                for desc in &descs {
                    binding.xsk.device.push_comp_for_test(desc.addr);
                }
                let _ = reap_tx_completions(binding, &mut recycles);
                recycles.clear();
                let sent = tx_total(binding) - before;
                tx_credit[w] -= sent as i64;
                if serviced.is_none() || sent == 0 {
                    break;
                }
            }
        }
        if now == measure_ns {
            for (w, binding) in bindings.iter().enumerate() {
                base_nonexact[w] = nonexact_sent(binding);
                base_exact[w] = tx_total(binding) - base_nonexact[w];
                last_sent[w] = base_nonexact[w];
                last_progress[w] = now;
            }
        } else if now > measure_ns {
            for (w, binding) in bindings.iter().enumerate() {
                if !arm.nonexact_backlogged[w] {
                    continue;
                }
                let sent = nonexact_sent(binding);
                if sent > last_sent[w] {
                    last_sent[w] = sent;
                    last_progress[w] = now;
                } else {
                    longest[w] = longest[w].max(now - last_progress[w]);
                }
            }
        }
        now += STEP_NS;
    }
    let nonexact_bytes: Vec<u64> = bindings
        .iter()
        .enumerate()
        .map(|(w, b)| nonexact_sent(b) - base_nonexact[w])
        .collect();
    let exact_bytes: Vec<u64> = bindings
        .iter()
        .enumerate()
        .map(|(w, b)| tx_total(b) - nonexact_sent(b) - base_exact[w])
        .collect();
    let (exact_root_parks, exact_queue_parks) = bindings.iter().fold((0, 0), |acc, b| {
        let q = &b.cos.cos_interfaces.get(&IFX).expect("root").queues[EXACT_IDX];
        (
            acc.0 + q.telemetry.drop_counters.root_token_starvation_parks,
            acc.1 + q.telemetry.drop_counters.queue_token_starvation_parks,
        )
    });
    Outcome {
        exact_bytes,
        nonexact_bytes,
        longest_unserved_ns: longest,
        exact_root_parks,
        exact_queue_parks,
    }
}

/// Run `arm` once per seed and check `property` on every outcome, failing
/// with every seed's report so a red cell shows the whole matrix.
fn assert_every_seed(name: &str, arm: &Arm, property: impl Fn(&Outcome) -> Result<(), String>) {
    let mut failures = Vec::new();
    let mut reports = Vec::new();
    for seed in SEEDS {
        let outcome = simulate(arm, seed);
        let report = outcome.report(&format!("{name} seed {seed:#x}"));
        if let Err(why) = property(&outcome) {
            failures.push(format!("{report}\n    -> {why}"));
        }
        reports.push(report);
    }
    assert!(
        failures.is_empty(),
        "{name}: {} of {} seeds failed:\n  {}\nall seeds:\n  {}",
        failures.len(),
        SEEDS.len(),
        failures.join("\n  "),
        reports.join("\n  ")
    );
}

/// The colocated non-exact instance on a worker that carries an exact class
/// must keep its share of that worker: at least half of what the worker can
/// still send after the exact class's offered load, and never unserved for
/// longer than `MAX_UNSERVED_NS`. Master: X starves it to 0.22 Gb/s with
/// 53 ms gaps in 4 of these 5 seeds; L8 to 0.02-1.4 Gb/s with gaps up to the
/// whole window.
fn colocated_share(arm: &Arm) -> impl Fn(&Outcome) -> Result<(), String> + '_ {
    move |o: &Outcome| {
        for w in 0..arm.workers {
            if arm.exact_offered_bytes[w] == 0 || !arm.nonexact_backlogged[w] {
                continue;
            }
            let remainder =
                (arm.worker_tx_cap_bytes - arm.exact_offered_bytes[w]) as f64 * 8.0 / 1e9;
            let got = o.nonexact_gbps(w);
            if got < 0.5 * remainder {
                return Err(format!(
                    "worker {w}: colocated non-exact {got:.2} Gb/s < half the {remainder:.2} Gb/s left after the exact class"
                ));
            }
            if o.longest_unserved_ns[w] > MAX_UNSERVED_NS {
                return Err(format!(
                    "worker {w}: colocated non-exact unserved for {} ms > {} ms",
                    o.longest_unserved_ns[w] / 1_000_000,
                    MAX_UNSERVED_NS / 1_000_000
                ));
            }
        }
        Ok(())
    }
}

/// The exact class must reach min(configured, offered) within 5%.
fn exact_guarantee(arm: &Arm) -> impl Fn(&Outcome) -> Result<(), String> + '_ {
    move |o: &Outcome| {
        let offered: u64 = arm.exact_offered_bytes.iter().sum();
        let want = arm.exact_rate_bytes.min(offered) as f64 * 8.0 / 1e9;
        if o.exact_gbps() < 0.95 * want {
            return Err(format!(
                "exact class {:.2} Gb/s < 95% of min(configured, offered) = {want:.2}",
                o.exact_gbps()
            ));
        }
        Ok(())
    }
}

/// #18748 (b): a non-exact instance colocated with an exact class keeps its
/// share of its worker. X is the live shape (one exact flow on a worker that
/// also carries non-exact traffic); L8 spreads 8 workers with exact flows on
/// two of them.
#[test]
fn colocated_nonexact_instance_keeps_its_share_18748() {
    let x = Arm::new(4, 10, 24, &[8]);
    assert_every_seed("X cfg24 off8 cap10", &x, colocated_share(&x));
    let l8 = Arm::new(8, 6, 24, &[4, 4]);
    assert_every_seed("L8 cfg24 off4+4 cap6", &l8, colocated_share(&l8));
}

/// #18748 (a): the exact class reaches min(configured, offered) when its
/// flows sit on two workers and the root is saturated by non-exact traffic.
/// Master: 5.7-8.0 of 12 Gb/s (X2) and 0.52-4.1 of 8 Gb/s (L8) in most seeds.
#[test]
fn exact_class_reaches_its_guarantee_across_workers_18748() {
    let x2 = Arm::new(4, 10, 24, &[6, 6]);
    assert_every_seed("X2 cfg24 off6+6 cap10", &x2, exact_guarantee(&x2));
    let l8 = Arm::new(8, 6, 24, &[4, 4]);
    assert_every_seed("L8 cfg24 off4+4 cap6", &l8, exact_guarantee(&l8));
}

/// An exact class offered more than its rate is limited by its own tokens:
/// it must still reach its configured rate (master: 2.5-2.9 of 8 Gb/s, every
/// seed), and while it parks on its own tokens it releases the rest of the
/// root, so non-exact traffic gets at least 95% of root minus that rate.
#[test]
fn self_limited_exact_class_meets_its_rate_and_releases_the_rest_18748() {
    let mut arm = Arm::new(4, 15, 8, &[12]);
    arm.nonexact_backlogged[0] = false;
    let shaping_gbit = SHAPING_BYTES as f64 * 8.0 / 1e9;
    let guarantee = exact_guarantee(&arm);
    assert_every_seed("R1b cfg8 off12 cap15", &arm, |o| {
        guarantee(o)?;
        let floor = 0.95 * (shaping_gbit - 8.0);
        if o.nonexact_total_gbps() < floor {
            return Err(format!(
                "non-exact {:.2} Gb/s < {floor:.2}: the self-limited class over-reserved",
                o.nonexact_total_gbps()
            ));
        }
        Ok(())
    });
}

/// The #hb166 T-6(b) release rule, end to end: an exact class that is
/// backlogged but whose own bucket never covers its head ships nothing, so
/// it must reserve nothing. Non-exact traffic keeps at least 95% of the root
/// and the instance on the exact worker stays served. A predicate that
/// counted every backlogged queue (the pre-T-6(b) "non-empty" rule) would
/// hold non-exact traffic to the 1 Gb/s residual of a 24 Gb/s reservation.
#[test]
fn exact_class_short_of_its_own_tokens_reserves_nothing_18748() {
    let mut arm = Arm::new(4, 10, 24, &[8]);
    arm.exact_has_lease = false;
    let shaping_gbit = SHAPING_BYTES as f64 * 8.0 / 1e9;
    assert_every_seed("V8STARVED cfg24 off8 cap10", &arm, |o| {
        if o.exact_gbps() > 0.0 {
            return Err(format!(
                "fixture: the leaseless exact class sent {:.2} Gb/s",
                o.exact_gbps()
            ));
        }
        if o.nonexact_total_gbps() < 0.95 * shaping_gbit {
            return Err(format!(
                "non-exact {:.2} Gb/s < 95% of the {shaping_gbit:.0} Gb/s root: a class that ships nothing reserved root",
                o.nonexact_total_gbps()
            ));
        }
        if o.longest_unserved_ns[0] > MAX_UNSERVED_NS {
            return Err(format!(
                "worker 0 non-exact unserved for {} ms",
                o.longest_unserved_ns[0] / 1_000_000
            ));
        }
        Ok(())
    });
}

/// Harness control, matching live arm Z: with no exact traffic the root,
/// saturated by non-exact traffic alone, is fully used and no instance goes
/// unserved. A simulation that starved here would be measuring itself.
#[test]
fn nonexact_alone_saturating_the_root_starves_no_instance_18748() {
    let arm = Arm::new(4, 10, 24, &[]);
    let shaping_gbit = SHAPING_BYTES as f64 * 8.0 / 1e9;
    assert_every_seed("Z no exact cap10", &arm, |o| {
        if o.nonexact_total_gbps() < 0.95 * shaping_gbit {
            return Err(format!("non-exact {:.2} Gb/s", o.nonexact_total_gbps()));
        }
        if let Some((w, ns)) = o
            .longest_unserved_ns
            .iter()
            .enumerate()
            .find(|(_, ns)| **ns > MAX_UNSERVED_NS)
        {
            return Err(format!("worker {w} unserved for {} ms", ns / 1_000_000));
        }
        Ok(())
    });
}

fn predicate_root(queue_tokens: u64, root_tokens: u64, items: usize) -> CoSInterfaceRuntime {
    let mut root = test_cos_runtime_with_queues(
        SHAPING_BYTES,
        vec![queue_config(EXACT_QUEUE, 24 * GBIT, true)],
    );
    root.tokens = root_tokens;
    let queue = &mut root.queues[0];
    queue.hot.runnable = true;
    queue.hot.tokens = queue_tokens;
    for _ in 0..items {
        queue.hot.items.push_back(test_cos_item(FRAME));
    }
    queue.hot.queued_bytes = (items * FRAME) as u64;
    root
}

fn park(root: &mut CoSInterfaceRuntime) {
    let queue = &mut root.queues[0];
    queue.hot.runnable = false;
    queue.hot.parked = true;
    queue.hot.next_wakeup_tick = 7;
}

/// The demand predicate, state by state. Kept: backlogged with its own
/// tokens covering the head, whether the root is short (runnable or parked
/// on root). Released: empty, own tokens short, parked on its own tokens.
#[test]
fn exact_demand_keeps_root_starved_and_releases_self_limited_queues_18748() {
    let head = FRAME as u64;
    let kept = [
        ("serviceable", predicate_root(10_000, 100_000, 2), false),
        ("root short, runnable", predicate_root(10_000, 0, 2), false),
        ("parked on root", predicate_root(10_000, 0, 2), true),
        (
            "own tokens exactly cover the head",
            predicate_root(head, 0, 2),
            true,
        ),
    ];
    for (state, mut root, parked) in kept {
        if parked {
            park(&mut root);
        }
        assert!(
            local_exact_demand_mask(&root).counts(0),
            "{state}: an exact queue limited only by the root must keep its reservation"
        );
    }
    let released = [
        ("empty", predicate_root(10_000, 100_000, 0), false),
        (
            "own tokens short, runnable",
            predicate_root(head - 1, 100_000, 2),
            false,
        ),
        (
            "parked on its own tokens",
            predicate_root(0, 100_000, 2),
            true,
        ),
        (
            "parked on root and own tokens short",
            predicate_root(head - 1, 0, 2),
            true,
        ),
    ];
    for (state, mut root, parked) in released {
        if parked {
            park(&mut root);
        }
        assert!(
            !local_exact_demand_mask(&root).counts(0),
            "{state}: an exact queue limited by itself must release its reservation"
        );
    }
}

/// Peers learn of a root-parked exact queue: `publish_cos_exact_backlog`
/// publishes it in the demand mask and in the serviceable-bytes signal.
#[test]
fn published_backlog_carries_a_root_parked_exact_queue_18748() {
    let mut root = predicate_root(10_000, 0, 2);
    park(&mut root);
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        EXACT_QUEUE,
        vec![(EXACT_QUEUE, test_queue_fast_path(true, 0, None, None))],
        None,
        None,
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog.clone());
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    let binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);

    crate::afxdp::cos::publish_cos_exact_backlog(&binding, IFX);

    assert!(
        backlog.peer_exact_demand_queue_mask(1).counts(0),
        "a peer must see the root-parked exact queue as demand"
    );
    assert!(
        backlog.has_peer_serviceable_backlog(1),
        "the published demand bytes must agree with the published mask"
    );
}

/// The local half of the reservation: while this worker's own exact queue
/// waits on root (parked, own tokens covering its head), its own non-exact
/// surplus is metered by the residual budget like every peer's, so it cannot
/// take the root that the parked exact queue is waiting for. The fresh shared
/// residual holds nothing yet, so no surplus batch is built. Under the
/// #hb166 T-6(b) predicate the parked queue was not demand and the worker's
/// own non-exact queue drained unconstrained.
#[test]
fn own_root_parked_exact_queue_meters_this_workers_surplus_18748() {
    let mut root = lab_runtime(24 * GBIT);
    root.tokens = 100_000;
    {
        let exact = &mut root.queues[EXACT_IDX];
        exact.hot.tokens = 10_000;
        exact.hot.items.push_back(test_cos_item(FRAME));
        exact.hot.queued_bytes = FRAME as u64;
    }
    park(&mut root);
    {
        let nonexact = &mut root.queues[NONEXACT_IDX];
        nonexact.hot.runnable = true;
        nonexact.hot.items.push_back(test_cos_item(FRAME));
        nonexact.hot.queued_bytes = FRAME as u64;
    }
    root.nonempty_queues = 2;
    root.runnable_queues = 1;
    let backlog = Arc::new(SharedCoSExactBacklog::new(1));
    let mut fast = test_cos_fast_interfaces(
        IFX,
        IFX,
        NONEXACT_QUEUE,
        vec![
            (EXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
            (NONEXACT_QUEUE, test_queue_fast_path(true, 0, None, None)),
        ],
        None,
        None,
    );
    fast.get_mut(&IFX).expect("fast path").shared_exact_backlog = Some(backlog);
    let fast_path = fast.get(&IFX).expect("fast path").clone();
    let mut binding = BindingWorker::new_for_cos_drain_test(0, 0, IFX, root, fast_path);

    assert!(
        build_nonexact_cos_batch(&mut binding, IFX, 2_000_000_000).is_none(),
        "this worker's non-exact surplus took root while its own exact queue was parked on root"
    );
}
