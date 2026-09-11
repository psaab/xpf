// CoS interface-runtime construction. `ensure_cos_interface_runtime`
// sits on the steady-state enqueue path (every enqueue checks
// whether the runtime exists for the egress ifindex) and carries
// `#[inline]`.

use std::collections::VecDeque;

use super::COS_MIN_BURST_BYTES;
use super::admission::apply_cos_queue_flow_fair_promotion;
use super::tx_completion::cos_tick_for_ns;
use crate::afxdp::types::{
    COS_PRIORITY_LEVELS, CoSInterfaceConfig, CoSInterfaceRuntime, CoSOversubscriptionPolicy,
    CoSQueueConfigState, CoSQueueDropCounters, CoSQueueHotState, CoSQueueOwnerProfile,
    CoSQueueRuntime, CoSQueueSojourn, CoSQueueTelemetry, CoSQueueWaterfillCounters,
    CoSTimerWheelRuntime, ExactDemandQueueMask,
    ForwardingState, VMinQueueState,
};
#[allow(unused_imports)]
use CoSOversubscriptionPolicy as _;
use crate::afxdp::worker::BindingWorker;

#[inline]
pub(in crate::afxdp) fn ensure_cos_interface_runtime(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    now_ns: u64,
) -> bool {
    if egress_ifindex <= 0 {
        return false;
    }
    // #774 fast path: if the runtime is already materialised,
    // that's the dominant case on steady state. A single
    // `contains_key` on the cos_interfaces hot map skips the two
    // forwarding.cos.interfaces + cos_fast_interfaces lookups
    // and the later-pass duplicate. Profiled at 0.9% CPU before
    // this fix.
    if binding.cos.cos_interfaces.contains_key(&egress_ifindex) {
        return true;
    }
    // #1755: the build/insert tail materialises a ~36 KB `CoSInterfaceRuntime`
    // by value, which forces a `__rust_probestack` 36 KB-frame loop. With
    // this `#[inline]` outer fn doing only the two early-exits above, that
    // probe ran on EVERY ingress packet before the `contains_key` hot exit.
    // Out-line the cold tail so the 36 KB frame lives only in the callee,
    // which fires at most once per (binding, egress-ifindex).
    ensure_cos_interface_runtime_cold(binding, forwarding, egress_ifindex, now_ns)
}

#[cold]
#[inline(never)]
fn ensure_cos_interface_runtime_cold(
    binding: &mut BindingWorker,
    forwarding: &ForwardingState,
    egress_ifindex: i32,
    now_ns: u64,
) -> bool {
    let Some(config) = forwarding.cos.interfaces.get(&egress_ifindex) else {
        return false;
    };
    if !binding
        .cos
        .cos_fast_interfaces
        .contains_key(&egress_ifindex)
    {
        return false;
    }
    let mut runtime = build_cos_interface_runtime(config, now_ns);
    if let Some(iface_fast) = binding.cos.cos_fast_interfaces.get(&egress_ifindex) {
        apply_cos_queue_flow_fair_promotion(
            &mut runtime,
            &iface_fast.queue_fast_path,
            binding.worker_id,
        );
    }
    binding.cos.cos_interfaces.insert(egress_ifindex, runtime);
    binding.cos.cos_interface_order.push(egress_ifindex);
    binding.cos.cos_interface_order.sort_unstable();
    true
}

pub(in crate::afxdp) fn build_cos_interface_runtime(
    config: &CoSInterfaceConfig,
    now_ns: u64,
) -> CoSInterfaceRuntime {
    let mut queue_indices_by_priority: [Vec<usize>; COS_PRIORITY_LEVELS] =
        std::array::from_fn(|_| Vec::new());
    for (idx, queue) in config.queues.iter().enumerate() {
        let priority = usize::from(queue.priority).min(COS_PRIORITY_LEVELS - 1);
        queue_indices_by_priority[priority].push(idx);
    }
    // #1614 A1: pre-sort exact queues by ascending `transmit_rate_bytes`
    // for the GuaranteeRate waterfill phase-1 greedy honor loop. Built
    // once at config-apply time; runtime is read-only. Stable sort so
    // queues with identical rates retain their original (queue_id)
    // order, eliminating AGY r2 #1's equal-rate starvation concern.
    let mut exact_queues_by_rate_ascending: Vec<usize> = (0..config.queues.len())
        .filter(|&idx| config.queues[idx].exact && config.queues[idx].guarantee_enabled)
        .collect();
    exact_queues_by_rate_ascending
        .sort_by_key(|&idx| config.queues[idx].transmit_rate_bytes);
    // #1732: the GuaranteeRate waterfill honored-set bitset is a `u64`
    // keyed by ordinal position in `exact_queues_by_rate_ascending`, so it
    // tracks at most 64 exact guarantee-rate queues per interface. Beyond
    // 64, ordinals ≥64 are conservatively untracked (the selector guards
    // the shift with `ordinal < 64`), which means those queues are
    // honor-eligible every selector call and may be over-served relative to
    // the waterfill contract. This is far outside any realistic Junos CoS
    // config (hardware queues are conventionally 0..7), but surface it to
    // the operator via journald so the condition is observable rather than
    // silent. Control-plane cold path: this runs when a per-worker
    // per-interface runtime is built (first enqueue for that ifindex, and
    // again on a runtime rebuild), so for an offending >64-queue config the
    // line may repeat per worker/per rebuild rather than literally once
    // globally — acceptable for a misconfiguration warning, and still off
    // the per-packet hot path entirely.
    if exact_queues_by_rate_ascending.len() > 64 {
        eprintln!(
            "xpf-userspace-dp: CoS interface has {} exact guarantee-rate \
             queues (>64); waterfill honored-set tracking is capped at 64 — \
             exact queues beyond the first 64 (by ascending rate) may be \
             over-served",
            exact_queues_by_rate_ascending.len()
        );
    }
    // #9365: the exact-demand mask (`ExactDemandQueueMask`) has one bit per
    // index into `queues`, sized for every u8 queue id. More queues than that
    // can only come from a tolerated config that breaks the strict
    // forwarding-class <-> queue bijection. Past it the mask saturates: exact
    // queues beyond the tracked range count as demanding whenever any exact
    // queue does, and a backlog on one of them reserves every exact queue's
    // rate. Same cold path and repeat caveat as the warning above.
    if config.queues.len() > ExactDemandQueueMask::BITS {
        eprintln!(
            "xpf-userspace-dp: CoS interface has {} queues (>{}); exact-demand \
             tracking is capped there, so exact queues past it are reserved \
             whenever any exact queue is backlogged",
            config.queues.len(),
            ExactDemandQueueMask::BITS
        );
    }
    // #916: transparent root. When `shaping_rate_bytes == 0` the root
    // bucket is bypassed by `maybe_top_up_cos_root_lease`; pre-fill
    // tokens to the burst cap so the very first packet doesn't see
    // an empty bucket on the cold path before the first top-up call.
    let initial_root_tokens = if config.shaping_rate_bytes == 0 {
        config.burst_bytes.max(COS_MIN_BURST_BYTES)
    } else {
        0
    };
    CoSInterfaceRuntime {
        shaping_rate_bytes: config.shaping_rate_bytes,
        burst_bytes: config.burst_bytes.max(COS_MIN_BURST_BYTES),
        tokens: initial_root_tokens,
        nonexact_surplus_under_exact_tokens: 0,
        nonexact_surplus_under_exact_last_refill_ns: 0,
        default_queue: config.default_queue,
        nonempty_queues: 0,
        runnable_queues: 0,
        oversubscription_policy: config.oversubscription_policy,
        oversubscription_guarantee_fraction: config.oversubscription_guarantee_fraction,
        priority_low_min_share_bytes: config.priority_low_min_share_bytes,
        priority_low_reserved_tokens: 0,
        priority_low_last_refill_ns: now_ns,
        exact_queues_by_rate_ascending,
        waterfill_pass1_remaining_bytes: 0,
        waterfill_phase2_cursor: 0,
        waterfill_honored_epoch_bits: 0,
        waterfill_epochs: 0,
        waterfill_phase1_budget_breaks: 0,
        // #1743: 0 forces the first selector call to take the budget-spent
        // refill path (pass1 starts at 0) which seeds epoch_start_ns to
        // the live now_ns; from then on the time-based refresh drives it.
        waterfill_epoch_start_ns: 0,
        // #1743 (Codex r3): true forces the first refill to also clear the
        // honored bitset (a clean first epoch); the Phase-2 wrap path
        // re-arms it on each genuine epoch boundary.
        waterfill_epoch_wrap_pending: true,
        exact_guarantee_rr: 0,
        nonexact_guarantee_rr: 0,
        #[cfg(test)]
        legacy_guarantee_rr: 0,
        queues: config
            .queues
            .iter()
            .map(|queue| CoSQueueRuntime {
                config: CoSQueueConfigState {
                    queue_id: queue.queue_id,
                    priority: queue.priority,
                    transmit_rate_bytes: queue.transmit_rate_bytes,
                    guarantee_enabled: queue.guarantee_enabled,
                    exact: queue.exact,
                    // #915: copy the opt-in flag from the intermediate
                    // CoSQueueConfig (populated in forwarding_build.rs
                    // from CoSSchedulerSnapshot.surplus_sharing).
                    surplus_sharing: queue.surplus_sharing,
                    equal_flow_enforcement: queue.equal_flow_enforcement,
                    // #1735: set by `promote_cos_queue_flow_fair`. The
                    // runtime flow-fair gate is `flow_fair_state.is_some()`;
                    // this bit only marks eligibility for lazy promotion.
                    flow_fair_eligible: false,
                    // Populated by `promote_cos_queue_flow_fair` from the
                    // live `WorkerCoSQueueFastPath.shared_exact` signal.
                    shared_exact: false,
                    surplus_weight: queue.surplus_weight,
                    buffer_bytes: queue.buffer_bytes.max(COS_MIN_BURST_BYTES),
                    dscp_rewrite: queue.dscp_rewrite,
                    // #1614 A3: copy CoDel target from intermediate
                    // CoSQueueConfig (populated in forwarding_build
                    // /cos.rs from CoSSchedulerSnapshot.codel_target_ns).
                    codel_target_ns: queue.codel_target_ns,
                },
                hot: CoSQueueHotState {
                    surplus_deficit: 0,
                    // #916: transparent queue (no scheduler rate AND
                    // no parent shaping rate). Pre-fill tokens to the
                    // buffer cap; otherwise an exact queue starts at 0
                    // and waits forever for a top-up that never arrives.
                    //
                    // #5156 (init half): a non-exact LEASE-METERED queue
                    // (`is_shared_lease_metered`) also starts at 0, exactly
                    // like exact. Its buffer_bytes are then acquired through
                    // the shared queue lease at runtime
                    // (`maybe_top_up_cos_queue_lease` -> `acquire_via_lease`),
                    // charging the lease's `outstanding` word. Pre-filling
                    // it un-metered (the old `else` arm) put buffer_bytes ×
                    // N_workers into circulation with no matching shared
                    // charge, defeating the #4265 metering at startup and
                    // leaving the teardown give-back nothing consistent to
                    // return. Only a truly un-leased non-exact queue
                    // (single-owner low-rate: a private per-worker bucket,
                    // no shared lease) keeps pre-filling its burst.
                    tokens: if queue.transmit_rate_bytes == 0 {
                        queue.buffer_bytes.max(COS_MIN_BURST_BYTES)
                    } else if queue.exact || queue.is_shared_lease_metered() {
                        0
                    } else {
                        queue.buffer_bytes.max(COS_MIN_BURST_BYTES)
                    },
                    last_refill_ns: if queue.exact && queue.transmit_rate_bytes != 0 {
                        0
                    } else {
                        now_ns
                    },
                    queued_bytes: 0,
                    runnable: false,
                    parked: false,
                    next_wakeup_tick: 0,
                    wheel_level: 0,
                    wheel_slot: 0,
                    items: VecDeque::new(),
                    local_item_count: 0,
                    cos_demote_empty_settles: 0,
                },
                flow_fair_state: None,
                v_min: VMinQueueState {
                    vtime_floor: None,
                    worker_id: 0,
                    consecutive_v_min_skips: 0,
                    v_min_suspended_remaining: 0,
                    v_min_hard_cap_overrides_scratch: 0,
                    v_min_throttles_scratch: 0,
                    v_min_suspended_batches_scratch: 0,
                    v_min_suspension_window: super::queue_ops::V_MIN_SUSPENSION_BATCHES,
                    v_min_pop_count: 0,
                },
                telemetry: CoSQueueTelemetry {
                    drop_counters: CoSQueueDropCounters::default(),
                    waterfill_counters: CoSQueueWaterfillCounters::default(),
                    owner_profile: CoSQueueOwnerProfile::new(),
                    sojourn: CoSQueueSojourn::default(),
                },
                queue_lease_v8: None,
            })
            .collect(),
        queue_indices_by_priority,
        rr_index_by_priority: [0; COS_PRIORITY_LEVELS],
        timer_wheel: CoSTimerWheelRuntime {
            current_tick: cos_tick_for_ns(now_ns),
            level0: std::array::from_fn(|_| Vec::new()),
            level1: std::array::from_fn(|_| Vec::new()),
            scratch: Default::default(),
        },
    }
}

#[cfg(test)]
#[path = "builders_tests.rs"]
mod tests;
