// CoS TX-completion + timer-wheel. Owns the interface timer wheel
// (advance / cascade / wake-due slot management), the TX-completion
// apply path (apply_direct_exact_send_result, apply_cos_send_result,
// apply_cos_prepared_result) and the refresh / restore helpers they
// use, plus prime_cos_root_for_service (single drain-cycle entry
// called by queue_service before each service pass).

use std::collections::VecDeque;
use std::sync::atomic::Ordering;

use std::sync::Arc;

use crate::afxdp::types::{
    COS_TIMER_WHEEL_L0_SLOTS, COS_TIMER_WHEEL_L1_SLOTS, CoSInterfaceRuntime, CoSPendingTxItem,
    CoSQueueRuntime, ExactDemandQueueMask, PreparedTxRequest, SharedCoSQueueLease, TxRequest,
};
use crate::afxdp::worker::BindingWorker;

use super::exact_demand::{exact_demand_rate_bytes_for_mask, serviceable_exact_demand_mask};
use super::queue_ops::{
    cos_exact_queue_serviceable, cos_item_len, cos_queue_front, cos_queue_is_empty,
    cos_queue_push_front, maybe_demote_drained_best_effort,
};
use super::token_bucket::{maybe_top_up_cos_root_lease, release_cos_root_lease};

// ============================================================================
// Service phase + park-reason types
// ============================================================================

/// Drain phases the scheduler walks through per tick. `Guarantee`
/// services queues against their per-queue token bucket; `Surplus`
/// distributes remaining root-bucket bytes across runnable queues
/// using deficit round-robin.
#[derive(Clone, Copy)]
pub(in crate::afxdp) enum CoSServicePhase {
    Guarantee,
    Surplus,
}

// #710: park-reason classification used at every `park_cos_queue` call
// site to attribute the wait to its upstream cause. `RootTokenStarvation`
// means the interface-level shaper token bucket was empty; the queue
// itself had work and tokens to send but the root could not admit more
// bytes this tick. `QueueTokenStarvation` means the per-queue (exact)
// token bucket was empty — the queue's own rate cap is the limiter.
// Both are "parks" rather than "drops" because the timer wheel will
// wake the queue when tokens refill; no packet is lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::afxdp) enum ParkReason {
    RootTokenStarvation,
    QueueTokenStarvation,
}

#[inline]
pub(in crate::afxdp) fn count_park_reason(
    root: &mut CoSInterfaceRuntime,
    queue_idx: usize,
    reason: ParkReason,
) {
    if let Some(queue) = root.queues.get_mut(queue_idx) {
        match reason {
            ParkReason::RootTokenStarvation => {
                queue.telemetry.drop_counters.root_token_starvation_parks = queue
                    .telemetry
                    .drop_counters
                    .root_token_starvation_parks
                    .wrapping_add(1);
            }
            ParkReason::QueueTokenStarvation => {
                queue.telemetry.drop_counters.queue_token_starvation_parks = queue
                    .telemetry
                    .drop_counters
                    .queue_token_starvation_parks
                    .wrapping_add(1);
            }
        }
    }
}

pub(in crate::afxdp) fn park_cos_queue(
    root: &mut CoSInterfaceRuntime,
    queue_idx: usize,
    wake_tick: u64,
) {
    let (level, slot) = cos_timer_wheel_level_and_slot(root.timer_wheel.current_tick, wake_tick);
    let Some(queue) = root.queues.get_mut(queue_idx) else {
        return;
    };
    if queue.hot.runnable {
        root.runnable_queues = root.runnable_queues.saturating_sub(1);
    }
    queue.hot.runnable = false;
    queue.hot.parked = true;
    queue.hot.next_wakeup_tick = wake_tick;
    queue.hot.wheel_level = level;
    queue.hot.wheel_slot = slot;
    if level == 0 {
        root.timer_wheel.level0[slot].push(queue_idx);
    } else {
        root.timer_wheel.level1[slot].push(queue_idx);
    }
}

// ============================================================================
// Constants
// ============================================================================

pub(in crate::afxdp) const COS_TIMER_WHEEL_TICK_NS: u64 = 50_000;
const COS_TIMER_WHEEL_L0_HORIZON_TICKS: u64 = COS_TIMER_WHEEL_L0_SLOTS as u64;

/// #1782 Step-2 (§5.2 mechanism (i)): total wheel horizon in ticks.
/// Level 0 indexes `wake_tick % L0_SLOTS` (256 ticks); level 1 indexes
/// `(wake_tick / L0_SLOTS) % L1_SLOTS`, so the combined wheel
/// distinguishes wake ticks up to `L0_SLOTS * L1_SLOTS` = 65,536 ticks
/// (~3.28 s at 50 µs/tick) ahead of `current_tick` before slot
/// indexing wraps. A catch-up lag beyond this guarantees the per-tick
/// loop would visit every L0 slot (>= 256 full L0 revolutions) and
/// cascade every L1 slot (>= 256 cascades at consecutive
/// `current_tick / L0_SLOTS` values), i.e. it would drain the entire
/// wheel — which is what makes the over-horizon snap in
/// `advance_cos_timer_wheel` provably behavior-identical.
pub(in crate::afxdp) const COS_TIMER_WHEEL_TOTAL_HORIZON_TICKS: u64 =
    (COS_TIMER_WHEEL_L0_SLOTS * COS_TIMER_WHEEL_L1_SLOTS) as u64;

// ============================================================================
// Timer-wheel cluster
// ============================================================================

#[inline]
pub(in crate::afxdp) fn cos_tick_for_ns(now_ns: u64) -> u64 {
    now_ns / COS_TIMER_WHEEL_TICK_NS
}

#[inline]
pub(in crate::afxdp) fn cos_timer_wheel_level_and_slot(
    current_tick: u64,
    wake_tick: u64,
) -> (u8, usize) {
    if wake_tick.saturating_sub(current_tick) < COS_TIMER_WHEEL_L0_HORIZON_TICKS {
        (0, (wake_tick % COS_TIMER_WHEEL_L0_SLOTS as u64) as usize)
    } else {
        (
            1,
            ((wake_tick / COS_TIMER_WHEEL_L0_SLOTS as u64) % COS_TIMER_WHEEL_L1_SLOTS as u64)
                as usize,
        )
    }
}

fn wake_cos_queue(root: &mut CoSInterfaceRuntime, queue_idx: usize) {
    let Some(queue) = root.queues.get_mut(queue_idx) else {
        return;
    };
    if cos_queue_is_empty(queue) {
        queue.hot.runnable = false;
        queue.hot.parked = false;
        queue.hot.next_wakeup_tick = 0;
        return;
    }
    if !queue.hot.runnable {
        root.runnable_queues = root.runnable_queues.saturating_add(1);
    }
    mark_cos_queue_runnable(queue);
}

// #710: count an exact-drain TX submit stall on a specific queue.
// NOT packet loss — on the exact path, `writer.insert == 0` leaves
// the FIFO items in `queue.hot.items` or restores them (flow-fair path);
// frames that had been copied into UMEM are released back to
// `free_tx_frames`, and the items get another chance next drain tick.
// The counter signals TX-ring / completion-reap pressure, which is
// an upstream cause for the downstream effects operators chase
// (#706 mutex contention, #709 owner-worker hotspot).
//
// Non-exact transmit paths (`transmit_batch`, `transmit_prepared_queue`)
// do not carry queue identity at the submit site and do not reach
// this helper. Their frame-level failures are counted in the binding-
// level `tx_submit_error_drops` counter instead.
#[inline]
pub(in crate::afxdp) fn count_tx_ring_full_submit_stall(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    stalled_packets: u64,
) {
    if stalled_packets == 0 {
        return;
    }
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.telemetry.drop_counters.tx_ring_full_submit_stalls = queue
                .telemetry
                .drop_counters
                .tx_ring_full_submit_stalls
                .wrapping_add(stalled_packets);
        }
    }
}

fn rearm_cos_queue(root: &mut CoSInterfaceRuntime, queue_idx: usize, wake_tick: u64) {
    park_cos_queue(root, queue_idx, wake_tick);
}

#[inline]
pub(in crate::afxdp) fn mark_cos_queue_runnable(queue: &mut CoSQueueRuntime) {
    queue.hot.runnable = true;
    queue.hot.parked = false;
    queue.hot.next_wakeup_tick = 0;
}

#[inline]
pub(in crate::afxdp) fn normalize_cos_queue_state(queue: &mut CoSQueueRuntime) {
    if cos_queue_is_empty(queue) {
        queue.hot.runnable = false;
        queue.hot.parked = false;
        queue.hot.next_wakeup_tick = 0;
        queue.hot.surplus_deficit = 0;
        return;
    }
    // Non-empty queues have only two valid steady states:
    // 1. parked with a wakeup tick
    // 2. runnable immediately
    // Anything else can strand backlog forever.
    if queue.hot.parked && queue.hot.next_wakeup_tick > 0 {
        queue.hot.runnable = false;
        return;
    }
    mark_cos_queue_runnable(queue);
}

/// Advance the interface timer wheel to `now_ns`. Returns the number
/// of ticks advanced by THIS call
/// (`now_tick - current_tick` at entry) — the #1782 Step-1 §4(i)
/// catch-up instrument. The return value is computed once before the
/// loop (O(1), no extra clock reads) and reports the TRUE lag even
/// when the #1782 Step-2 over-horizon snap below short-circuits the
/// loop, so `cos_wheel_ticks_advanced_total/_max` keep recording the
/// snapped amount (Step-1's 2.2M-tick cold-start signal stays
/// visible; only its wall cost is gone).
///
/// #1782 Step-2 (§5.2 mechanism (i)): when the lag exceeds the full
/// wheel horizon — the first shaped drain after a long per-worker
/// idle period — the per-tick loop is pure O(lag) catch-up (~111 s of
/// 50 µs ticks replayed for one cold connect in the Step-1 evidence).
/// `snap_cos_timer_wheel_over_horizon` replaces it with an
/// O(slots + queues) snap. Parked queues that are already due
/// are woken, while future parks are reinserted from their absolute
/// wake ticks against the snapped current tick. In-horizon lag
/// (`<= COS_TIMER_WHEEL_TOTAL_HORIZON_TICKS`) always takes the
/// existing per-tick loop unchanged.
#[inline]
pub(in crate::afxdp) fn advance_cos_timer_wheel(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> u64 {
    advance_cos_timer_wheel_counting_iterations(root, now_ns).0
}

/// Implementation split out so regression tests can distinguish the
/// true elapsed-tick telemetry from the amount of synchronous per-tick
/// work. The second tuple field is optimized away in production callers.
#[inline]
fn advance_cos_timer_wheel_counting_iterations(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
) -> (u64, u64) {
    let now_tick = cos_tick_for_ns(now_ns);
    let ticks_advanced = now_tick.saturating_sub(root.timer_wheel.current_tick);
    if ticks_advanced > COS_TIMER_WHEEL_TOTAL_HORIZON_TICKS {
        snap_cos_timer_wheel_over_horizon(root, now_tick);
        return (ticks_advanced, 0);
    }
    let mut iterations = 0;
    while root.timer_wheel.current_tick < now_tick {
        iterations += 1;
        root.timer_wheel.current_tick = root.timer_wheel.current_tick.saturating_add(1);
        if root.timer_wheel.current_tick % COS_TIMER_WHEEL_L0_SLOTS as u64 == 0 {
            cascade_cos_timer_wheel_level1(root);
        }
        wake_due_cos_timer_slot(root);
    }
    (ticks_advanced, iterations)
}

/// #1782 Step-2 (§5.2 mechanism (i)), extended by #5803: bounded wheel
/// catch-up for an over-horizon lag.
///
/// Correctness (plan Codex F1 + AGY F1 fold): the "wheel is empty at
/// idle" shortcut is FALSE — `park_cos_queue` pushes queue indices
/// into `level0`/`level1` and `normalize_cos_queue_state` clears only
/// queue flags, never the slot vectors; stale entries are filtered
/// lazily by the `parked`/`wheel_level`/`wheel_slot` checks in
/// `wake_due_cos_timer_slot` / `cascade_cos_timer_wheel_level1`. So
/// The snap clears all old slot entries and sets `current_tick =
/// now_tick`. It then rebuilds every valid parked entry from the
/// queue's absolute `next_wakeup_tick`: due queues wake immediately,
/// and future queues are re-parked through `park_cos_queue`, which
/// re-derives their level and slot relative to the new tick. This is
/// the same final state as visiting every elapsed tick, including for
/// wake ticks far beyond the wheel horizon, but costs O(slots + queue
/// count) rather than O(elapsed ticks).
///
/// Cold-path-only: reached only when lag > ~3.28 s, i.e. the first
/// shaped drain after idle. `Vec::clear` frees nothing (capacity
/// retained) — no allocation either way.
#[cold]
fn snap_cos_timer_wheel_over_horizon(root: &mut CoSInterfaceRuntime, now_tick: u64) {
    for slot in root.timer_wheel.level0.iter_mut() {
        slot.clear();
    }
    for slot in root.timer_wheel.level1.iter_mut() {
        slot.clear();
    }
    root.timer_wheel.current_tick = now_tick;

    let mut rearm = core::mem::take(&mut root.timer_wheel.scratch.rearm);
    let mut wake = core::mem::take(&mut root.timer_wheel.scratch.wake);
    rearm.clear();
    wake.clear();
    for (queue_idx, queue) in root.queues.iter().enumerate() {
        if !queue.hot.parked {
            continue;
        }
        if queue.hot.next_wakeup_tick <= now_tick {
            wake.push(queue_idx);
        } else {
            rearm.push((queue_idx, queue.hot.next_wakeup_tick));
        }
    }
    for queue_idx in wake.iter().copied() {
        wake_cos_queue(root, queue_idx);
    }
    for (queue_idx, wake_tick) in rearm.iter().copied() {
        park_cos_queue(root, queue_idx, wake_tick);
    }
    rearm.clear();
    wake.clear();
    root.timer_wheel.scratch.rearm = rearm;
    root.timer_wheel.scratch.wake = wake;
}

fn cascade_cos_timer_wheel_level1(root: &mut CoSInterfaceRuntime) {
    let slot = ((root.timer_wheel.current_tick / COS_TIMER_WHEEL_L0_SLOTS as u64)
        % COS_TIMER_WHEEL_L1_SLOTS as u64) as usize;
    // #4270 (R-9): take the persistent scratch out of `root` so the
    // `&mut root` rearm calls below borrow cleanly; restored before return.
    let mut drain = core::mem::take(&mut root.timer_wheel.scratch.drain);
    let mut rearm = core::mem::take(&mut root.timer_wheel.scratch.rearm);
    drain.clear();
    rearm.clear();
    // Swap the slot's queued indices into `drain` WITHOUT freeing the
    // slot's capacity: the slot receives `drain`'s emptied buffer, so the
    // next park into it reuses that capacity instead of reallocating.
    core::mem::swap(&mut drain, &mut root.timer_wheel.level1[slot]);
    for queue_idx in drain.iter().copied() {
        let Some(queue) = root.queues.get(queue_idx) else {
            continue;
        };
        if !queue.hot.parked || queue.hot.wheel_level != 1 || queue.hot.wheel_slot != slot {
            continue;
        }
        rearm.push((queue_idx, queue.hot.next_wakeup_tick));
    }
    for (queue_idx, wake_tick) in rearm.iter().copied() {
        rearm_cos_queue(root, queue_idx, wake_tick);
    }
    drain.clear();
    rearm.clear();
    root.timer_wheel.scratch.drain = drain;
    root.timer_wheel.scratch.rearm = rearm;
}

fn wake_due_cos_timer_slot(root: &mut CoSInterfaceRuntime) {
    let slot = (root.timer_wheel.current_tick % COS_TIMER_WHEEL_L0_SLOTS as u64) as usize;
    // #4270 (R-9): reuse the persistent scratch (drain/rearm/wake) — no
    // per-slot allocation on the per-tick catch-up loop.
    let mut drain = core::mem::take(&mut root.timer_wheel.scratch.drain);
    let mut rearm = core::mem::take(&mut root.timer_wheel.scratch.rearm);
    let mut wake = core::mem::take(&mut root.timer_wheel.scratch.wake);
    drain.clear();
    rearm.clear();
    wake.clear();
    // Swap out the slot (capacity-preserving, see cascade above).
    core::mem::swap(&mut drain, &mut root.timer_wheel.level0[slot]);
    for queue_idx in drain.iter().copied() {
        let Some(queue) = root.queues.get(queue_idx) else {
            continue;
        };
        if !queue.hot.parked || queue.hot.wheel_level != 0 || queue.hot.wheel_slot != slot {
            continue;
        }
        if queue.hot.next_wakeup_tick <= root.timer_wheel.current_tick {
            wake.push(queue_idx);
        } else {
            rearm.push((queue_idx, queue.hot.next_wakeup_tick));
        }
    }
    for queue_idx in wake.iter().copied() {
        wake_cos_queue(root, queue_idx);
    }
    for (queue_idx, wake_tick) in rearm.iter().copied() {
        rearm_cos_queue(root, queue_idx, wake_tick);
    }
    drain.clear();
    rearm.clear();
    wake.clear();
    root.timer_wheel.scratch.drain = drain;
    root.timer_wheel.scratch.rearm = rearm;
    root.timer_wheel.scratch.wake = wake;
}

/// Conservative pre-prime gate for `drain_shaped_tx`.
///
/// Runnable queues still need priming because root leases and the timer
/// wheel may make a token-starved queue serviceable on this pass. Parked
/// queues with a future wake tick cannot service on this pass, so callers
/// can skip the root prime until a wake tick is due.
#[inline]
pub(in crate::afxdp) fn cos_root_can_service_after_prime(
    root: &CoSInterfaceRuntime,
    now_ns: u64,
) -> bool {
    if root.nonempty_queues == 0 {
        return false;
    }
    if root.runnable_queues > 0 {
        return true;
    }
    let now_tick = cos_tick_for_ns(now_ns);
    root.queues.iter().any(|queue| {
        !cos_queue_is_empty(queue)
            && queue.hot.parked
            && queue.hot.next_wakeup_tick > 0
            && queue.hot.next_wakeup_tick <= now_tick
    })
}

// ============================================================================
// TX-completion cluster
// ============================================================================

#[inline]
pub(in crate::afxdp) fn prime_cos_root_for_service(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> bool {
    // #4972: borrow the root lease from the disjoint `cos_fast_interfaces`
    // field rather than cloning the `Arc` per prime call. The mutable
    // borrow below is of the separate `cos_interfaces` field, so the
    // read-borrow coexists (same borrow-split the exact paths use).
    let shared_root_lease = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref());
    let ticks_advanced;
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return false;
        };
        ticks_advanced = advance_cos_timer_wheel(root, now_ns);
        if let Some(shared_root_lease) = shared_root_lease {
            maybe_top_up_cos_root_lease(root, shared_root_lease, now_ns);
        }
    }
    // #1782 Step-1 (§5.2 mechanism (i)): accumulate the wheel
    // catch-up in worker-local plain u64s on `WorkerCos` (NOT on the
    // CoSInterfaceRuntime, which is rebuilt on config apply and would
    // reset the published counter). Flushed to the per-worker atomics
    // at the existing ~1s publish tick. O(1) per prime call.
    if ticks_advanced > 0 {
        binding.cos.cos_wheel_ticks_advanced_total = binding
            .cos
            .cos_wheel_ticks_advanced_total
            .wrapping_add(ticks_advanced);
        if ticks_advanced > binding.cos.cos_wheel_ticks_advanced_max {
            binding.cos.cos_wheel_ticks_advanced_max = ticks_advanced;
        }
    }
    true
}

/// #915: phase-gated `shared_queue_lease` consumption helper.
///
/// The per-queue lease represents the configured exact rate cap.
/// In Surplus phase a `surplus_sharing` exact queue is drawing
/// from root tokens (not its own bucket), so debiting the
/// per-queue lease here would re-impose the per-queue cap on the
/// surplus draw and defeat the point of #915. Phase-gating keeps
/// the lease as a Guarantee-phase-only concept.
///
/// For non-surplus-sharing exact queues this is a no-op because
/// they never reach Surplus phase: `select_cos_surplus_batch`
/// skips them via `queue.config.exact && !queue.config.surplus_sharing`.
///
/// Extracted into a helper so the gate logic has a direct unit
/// test (Codex code-review MEDIUM): both Local and Prepared
/// apply paths route through this single function.
#[inline]
pub(in crate::afxdp) fn maybe_consume_exact_queue_lease(
    shared_queue_lease: Option<&Arc<SharedCoSQueueLease>>,
    phase: CoSServicePhase,
    sent_bytes: u64,
) {
    if !matches!(phase, CoSServicePhase::Guarantee) {
        return;
    }
    if let Some(lease) = shared_queue_lease {
        lease.consume(sent_bytes);
    }
}

#[inline]
fn root_has_backlogged_exact_queue(root: &CoSInterfaceRuntime) -> bool {
    root.queues
        .iter()
        .any(|queue| queue.config.exact && !cos_queue_is_empty(queue))
}

#[inline]
fn exact_backlog_bytes(root: &CoSInterfaceRuntime) -> u64 {
    root.queues
        .iter()
        .filter(|queue| queue.config.exact)
        .fold(0u64, |acc, queue| {
            acc.saturating_add(queue.hot.queued_bytes)
        })
}

#[inline]
fn serviceable_exact_backlog_bytes(root: &CoSInterfaceRuntime) -> u64 {
    // #hb166 T-6(b): share the serviceability predicate with the demand
    // masks (queue_ops::cos_exact_queue_serviceable) so the published
    // serviceable-bytes signal and the demand mask agree byte-for-byte.
    let root_tokens = root.tokens;
    root.queues
        .iter()
        .filter(|queue| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && cos_exact_queue_serviceable(root_tokens, queue)
        })
        .fold(0u64, |acc, queue| acc.saturating_add(queue.hot.queued_bytes))
}

#[inline]
pub(in crate::afxdp) fn publish_cos_exact_backlog(binding: &BindingWorker, root_ifindex: i32) {
    let Some(shared_exact_backlog) = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref())
    else {
        return;
    };
    let Some(root) = binding.cos.cos_interfaces.get(&root_ifindex) else {
        shared_exact_backlog.publish(binding.slot, 0);
        return;
    };
    shared_exact_backlog.publish_with_serviceable(
        binding.slot,
        exact_backlog_bytes(root),
        serviceable_exact_backlog_bytes(root),
        serviceable_exact_demand_mask(root),
    );
}

#[inline]
pub(in crate::afxdp) fn clear_all_cos_exact_backlogs_for_binding(binding: &BindingWorker) {
    for iface_fast in binding.cos.cos_fast_interfaces.values() {
        if let Some(shared_exact_backlog) = iface_fast.shared_exact_backlog.as_ref() {
            shared_exact_backlog.publish(binding.slot, 0);
        }
    }
}

#[inline]
fn interface_has_backlogged_exact_queue(
    root: &CoSInterfaceRuntime,
    peer_exact_backlogged: bool,
) -> bool {
    root_has_backlogged_exact_queue(root) || peer_exact_backlogged
}

#[inline]
fn peer_exact_demand_queue_mask(
    binding: &BindingWorker,
    root_ifindex: i32,
) -> ExactDemandQueueMask {
    binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref())
        .map(|backlog| backlog.peer_exact_demand_queue_mask(binding.slot))
        .unwrap_or(ExactDemandQueueMask::EMPTY)
}

#[inline]
fn account_queue_drain_sent_bytes(
    queue: &mut CoSQueueRuntime,
    phase: CoSServicePhase,
    sent_bytes: u64,
    exact_backlogged: bool,
) {
    if sent_bytes == 0 {
        return;
    }
    let profile = &queue.telemetry.owner_profile;
    profile
        .drain_sent_bytes
        .fetch_add(sent_bytes, Ordering::Relaxed);
    match phase {
        CoSServicePhase::Guarantee => {
            profile
                .drain_guarantee_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
        }
        CoSServicePhase::Surplus => {
            profile
                .drain_surplus_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
        }
    }
    if exact_backlogged && !queue.config.exact {
        profile
            .drain_nonexact_sent_bytes_while_exact_backlogged
            .fetch_add(sent_bytes, Ordering::Relaxed);
    }
}

#[inline]
pub(in crate::afxdp) fn apply_direct_exact_queue_accounting(
    root: &mut CoSInterfaceRuntime,
    queue_idx: usize,
    sent_bytes: u64,
) {
    if let Some(queue) = root.queues.get_mut(queue_idx) {
        queue.hot.queued_bytes = queue.hot.queued_bytes.saturating_sub(sent_bytes);
        queue.hot.tokens = queue.hot.tokens.saturating_sub(sent_bytes);
        // #760 instrumentation: record the exact-owner-local send at
        // the same place the token bucket decrements. Divide by a
        // scrape window to get an observed per-queue drain rate and
        // compare against `queue.transmit_rate_bytes()` to detect a
        // cap bypass.
        account_queue_drain_sent_bytes(queue, CoSServicePhase::Guarantee, sent_bytes, false);
    }
    root.tokens = root.tokens.saturating_sub(sent_bytes);
}

#[inline]
pub(in crate::afxdp) fn apply_direct_exact_send_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    sent_packets: u64,
    sent_bytes: u64,
) {
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        apply_direct_exact_queue_accounting(root, queue_idx, sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    if let Some(shared_queue_lease) = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
        .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
    {
        shared_queue_lease.consume(sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
    if sent_packets > 0 {
        binding
            .live
            .tx_packets
            .fetch_add(sent_packets, Ordering::Relaxed);
        binding
            .live
            .tx_bytes
            .fetch_add(sent_bytes, Ordering::Relaxed);
        // #760 instrumentation, exact-owner-local path. Paired with
        // tx_bytes unconditionally — if the per-queue drain_sent_bytes
        // above (guarded by `if let Some(queue)`) ever undercounts
        // this, the gap is an `apply_*` early-return / queue-miss.
        binding
            .live
            .owner_profile_owner
            .drain_sent_bytes_shaped_unconditional
            .fetch_add(sent_bytes, Ordering::Relaxed);
    }
}

#[inline]
pub(in crate::afxdp) fn refresh_cos_interface_activity(
    binding: &mut BindingWorker,
    root_ifindex: i32,
) {
    let mut new_nonempty = 0usize;
    let mut new_runnable = 0usize;
    // (queue_idx, worker_id, released_bytes). #4972: reuse the per-binding
    // scratch Vec instead of heap-allocating one per settle. `mem::take`
    // swaps in an empty Vec (no alloc) and hands us the retained-capacity
    // buffer; it is stored back at the end of the function. The deferred-
    // return structure (lease re-credits run after the `cos_interfaces`
    // mutable borrow ends) is preserved EXACTLY — only the allocation is
    // removed.
    let mut released_queue_leases = core::mem::take(&mut binding.cos.released_queue_leases_scratch);
    released_queue_leases.clear();
    let old_nonempty = binding
        .cos
        .cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.nonempty_queues)
        .unwrap_or(0);
    // #4246 R-5(a): only zero (and give back) an empty exact queue's
    // banked burst when a shared lease will actually RECEIVE it. A
    // single-owner exact queue (exact but no lease attached) previously had
    // `hot.tokens` zeroed unconditionally with nowhere to give it back —
    // destroying the token-bucket burst on every brief drain (a burst-less
    // rate limiter for on/off traffic). The lease-presence probe reads the
    // disjoint `cos_fast_interfaces` field, so it coexists with the
    // `cos_interfaces` mutable borrow below.
    let iface_fast = binding.cos.cos_fast_interfaces.get(&root_ifindex);
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        for (queue_idx, queue) in root.queues.iter_mut().enumerate() {
            normalize_cos_queue_state(queue);
            // #4265 (R-2): give back an empty queue's banked burst whenever a
            // shared lease is attached — this now includes the non-exact
            // guaranteed sharded queue's legacy lease, not just exact
            // queues. The `has_lease` probe is still the actual gate for the
            // `mem::take` (R-5(a)): a no-lease queue (single-owner exact OR
            // single-owner non-exact) keeps its banked burst intact, since
            // there is nowhere to give it back. `release_unused_v8` reduces
            // to the legacy `release_unused` for a legacy (v8=None) lease.
            if cos_queue_is_empty(queue) && queue.hot.tokens > 0 {
                let has_lease = iface_fast
                    .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
                    .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
                    .is_some();
                if has_lease {
                    let worker_id = queue.v_min.worker_id as usize;
                    released_queue_leases.push((
                        queue_idx,
                        worker_id,
                        core::mem::take(&mut queue.hot.tokens),
                    ));
                }
                // No lease: leave `hot.tokens` intact (R-5(a)) — nowhere to
                // give it back, so keep the banked burst for this queue.
            }
            if cos_queue_is_empty(queue) {
                continue;
            }
            new_nonempty = new_nonempty.saturating_add(1);
            if queue.hot.runnable {
                new_runnable = new_runnable.saturating_add(1);
            }
        }
        root.nonempty_queues = new_nonempty;
        root.runnable_queues = new_runnable;
    }
    publish_cos_exact_backlog(binding, root_ifindex);
    if old_nonempty == 0 && new_nonempty > 0 {
        binding.cos.cos_nonempty_interfaces = binding.cos.cos_nonempty_interfaces.saturating_add(1);
    } else if old_nonempty > 0 && new_nonempty == 0 {
        binding.cos.cos_nonempty_interfaces = binding.cos.cos_nonempty_interfaces.saturating_sub(1);
        release_cos_root_lease(binding, root_ifindex);
    }
    if let Some(iface_fast) = binding.cos.cos_fast_interfaces.get(&root_ifindex) {
        for &(queue_idx, worker_id, released) in &released_queue_leases {
            if let Some(shared_queue_lease) = iface_fast
                .queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
            {
                // #4246 (T-1): re-credit the v8 epoch ledger, not just the
                // legacy outstanding word. No-op v8 leg for legacy leases.
                shared_queue_lease.release_unused_v8(worker_id, released);
            }
        }
    }
    // #4972: return the scratch buffer (with its retained capacity) so the
    // next settle reuses the allocation instead of making a fresh one.
    binding.cos.released_queue_leases_scratch = released_queue_leases;
}

// #4973: returns the drained (now-empty) `retry` deque so the CoSBatch submit
// handler can store it back into the per-worker Local batch scratch, reusing the
// ring-buffer allocation. On the queue-torn-down early return the deque is
// returned undrained (its items are dropped by the next `build_cos_batch_from_queue`
// `clear()`, exactly as the previous by-value drop dropped them — the queue is
// gone, so those items were already unrecoverable). Behavior is otherwise
// identical; only the deque's ownership is threaded back out.
#[inline]
pub(in crate::afxdp) fn apply_cos_send_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    sent_bytes: u64,
    mut retry: VecDeque<TxRequest>,
) -> VecDeque<TxRequest> {
    // #4265 (R-2): the serviced queue's shared lease is debited in the
    // Guarantee phase regardless of `exact` — a non-exact guaranteed
    // sharded queue now carries a legacy lease that meters its class-wide
    // admission, so its guarantee-phase sends must debit that lease too.
    // `maybe_consume_exact_queue_lease` still gates on phase == Guarantee
    // and lease-presence, so a non-leased queue or a surplus-phase send is
    // a no-op (surplus draws from root tokens, not the per-queue lease —
    // the #915 rationale).
    let mut lease_consume_queue_idx = None;
    let binding_slot = binding.slot;
    // #4972: borrow the shared exact-backlog `Arc` from the disjoint
    // `cos_fast_interfaces` field instead of cloning it per settlement.
    // The mutable borrow below is of `cos_interfaces` (a separate field),
    // and `peer_exact_demand_queue_mask` takes `&BindingWorker`, so the
    // read-borrow held across both is sound.
    let shared_exact_backlog = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref());
    let peer_exact_backlogged = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref())
        .is_some_and(|backlog| backlog.has_peer_backlog(binding_slot));
    let peer_exact_demand_mask = peer_exact_demand_queue_mask(binding, root_ifindex);
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return retry;
        };
        let exact_demand_mask = serviceable_exact_demand_mask(root) | peer_exact_demand_mask;
        let exact_demand_rate = exact_demand_rate_bytes_for_mask(root, exact_demand_mask);
        let exact_backlogged = sent_bytes > 0
            && root
                .queues
                .get(queue_idx)
                .is_some_and(|queue| !queue.config.exact)
            && interface_has_backlogged_exact_queue(root, peer_exact_backlogged);
        let mut debit_nonexact_surplus_budget = false;
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            lease_consume_queue_idx = Some(queue_idx);
            debit_nonexact_surplus_budget = sent_bytes > 0
                && !queue.config.exact
                && matches!(phase, CoSServicePhase::Surplus)
                && exact_demand_rate > 0;
            let retry_bytes = restore_cos_local_items_inner(queue, &mut retry);
            queue.hot.queued_bytes = queue
                .hot
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
            match phase {
                CoSServicePhase::Guarantee => {
                    queue.hot.tokens = queue.hot.tokens.saturating_sub(sent_bytes);
                }
                CoSServicePhase::Surplus => {
                    queue.hot.surplus_deficit =
                        queue.hot.surplus_deficit.saturating_sub(sent_bytes);
                }
            }
            // #760 instrumentation: record non-exact / surplus /
            // shared-exact sends at the same site the queue's token
            // or surplus accounting is debited. Paired with the
            // apply_direct_exact_send_result write so the sum across
            // all sites equals the bytes the CoS scheduler accounted.
            account_queue_drain_sent_bytes(queue, phase, sent_bytes, exact_backlogged);
            // #1735: lazy demotion at this quiescent settle boundary —
            // strictly after restore_cos_local_items_inner and the
            // queued_bytes settle above, so a partial-commit retry
            // leaves the queue non-quiescent and is NOT demoted. No-op
            // on exact / non-eligible / non-promoted queues.
            maybe_demote_drained_best_effort(queue);
        }
        if debit_nonexact_surplus_budget {
            if let Some(backlog) = shared_exact_backlog {
                backlog.consume_residual_surplus_budget(sent_bytes);
            } else {
                root.nonexact_surplus_under_exact_tokens = root
                    .nonexact_surplus_under_exact_tokens
                    .saturating_sub(sent_bytes);
            }
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    // #915: phase-gate `shared_queue_lease` consumption to the
    // Guarantee phase only. See `maybe_consume_exact_queue_lease`
    // for rationale.
    if let Some(queue_idx) = lease_consume_queue_idx {
        let shared_queue_lease = binding
            .cos
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref());
        maybe_consume_exact_queue_lease(shared_queue_lease, phase, sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
    // #4973: hand the drained deque back for batch-scratch reuse.
    retry
}

// #4973: prepared variant of `apply_cos_send_result` — returns the drained
// deque so the submit handler can reuse it as the per-worker Prepared batch
// scratch. See `apply_cos_send_result` for the ownership rationale.
#[inline]
pub(in crate::afxdp) fn apply_cos_prepared_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    sent_bytes: u64,
    mut retry: VecDeque<PreparedTxRequest>,
) -> VecDeque<PreparedTxRequest> {
    // #4265 (R-2): the serviced queue's shared lease is debited in the
    // Guarantee phase regardless of `exact` — a non-exact guaranteed
    // sharded queue now carries a legacy lease that meters its class-wide
    // admission, so its guarantee-phase sends must debit that lease too.
    // `maybe_consume_exact_queue_lease` still gates on phase == Guarantee
    // and lease-presence, so a non-leased queue or a surplus-phase send is
    // a no-op (surplus draws from root tokens, not the per-queue lease —
    // the #915 rationale).
    let mut lease_consume_queue_idx = None;
    let binding_slot = binding.slot;
    // #4972: borrow the shared exact-backlog `Arc` from the disjoint
    // `cos_fast_interfaces` field instead of cloning it per settlement
    // (see `apply_cos_send_result` for the borrow-split rationale).
    let shared_exact_backlog = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref());
    let peer_exact_backlogged = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref())
        .is_some_and(|backlog| backlog.has_peer_backlog(binding_slot));
    let peer_exact_demand_mask = peer_exact_demand_queue_mask(binding, root_ifindex);
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return retry;
        };
        let exact_demand_mask = serviceable_exact_demand_mask(root) | peer_exact_demand_mask;
        let exact_demand_rate = exact_demand_rate_bytes_for_mask(root, exact_demand_mask);
        let exact_backlogged = sent_bytes > 0
            && root
                .queues
                .get(queue_idx)
                .is_some_and(|queue| !queue.config.exact)
            && interface_has_backlogged_exact_queue(root, peer_exact_backlogged);
        let mut debit_nonexact_surplus_budget = false;
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            lease_consume_queue_idx = Some(queue_idx);
            debit_nonexact_surplus_budget = sent_bytes > 0
                && !queue.config.exact
                && matches!(phase, CoSServicePhase::Surplus)
                && exact_demand_rate > 0;
            let retry_bytes = restore_cos_prepared_items_inner(queue, &mut retry);
            queue.hot.queued_bytes = queue
                .hot
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
            match phase {
                CoSServicePhase::Guarantee => {
                    queue.hot.tokens = queue.hot.tokens.saturating_sub(sent_bytes);
                }
                CoSServicePhase::Surplus => {
                    queue.hot.surplus_deficit =
                        queue.hot.surplus_deficit.saturating_sub(sent_bytes);
                }
            }
            // #760 instrumentation, the FOURTH apply_* site. This is
            // the prepared-batch path (CoSBatch::Prepared, in-place
            // rewrite — the common case for forwarded traffic). The
            // initial instrumentation commit missed this site; the
            // first 120 s iperf3 measurement showed only ~987 Mbps
            // on drain_sent_bytes while the receiver reported 1.55
            // Gbps, leaving ~563 Mbps unaccounted — all of it
            // flowing through this path. Same Relaxed semantics as
            // the other three apply_* sites.
            account_queue_drain_sent_bytes(queue, phase, sent_bytes, exact_backlogged);
            // #1735: lazy demotion at this quiescent settle boundary
            // (prepared variant). See apply_cos_send_result for the
            // ordering rationale.
            maybe_demote_drained_best_effort(queue);
        }
        if debit_nonexact_surplus_budget {
            if let Some(backlog) = shared_exact_backlog {
                backlog.consume_residual_surplus_budget(sent_bytes);
            } else {
                root.nonexact_surplus_under_exact_tokens = root
                    .nonexact_surplus_under_exact_tokens
                    .saturating_sub(sent_bytes);
            }
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    // #915: phase-gate `shared_queue_lease` consumption to the
    // Guarantee phase only. See `maybe_consume_exact_queue_lease`
    // for rationale.
    if let Some(queue_idx) = lease_consume_queue_idx {
        let shared_queue_lease = binding
            .cos
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref());
        maybe_consume_exact_queue_lease(shared_queue_lease, phase, sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
    // #4973: hand the drained deque back for batch-scratch reuse.
    retry
}

// #4973: `retry` is drained in place (`&mut`) rather than consumed by value, so
// the caller (`apply_cos_send_result` / the submit-side restore wrapper) keeps
// ownership of the now-empty deque and can hand it back to the per-worker batch
// scratch, retaining its ring-buffer allocation. `pop_back` still empties it, so
// behavior is identical; only the ownership transfer moved to the caller.
#[inline]
pub(in crate::afxdp) fn restore_cos_local_items_inner(
    queue: &mut CoSQueueRuntime,
    retry: &mut VecDeque<TxRequest>,
) -> u64 {
    let mut retry_bytes = 0u64;
    while let Some(req) = retry.pop_back() {
        retry_bytes = retry_bytes.saturating_add(req.bytes.len() as u64);
        cos_queue_push_front(queue, CoSPendingTxItem::Local(req));
    }
    if !cos_queue_is_empty(queue) {
        mark_cos_queue_runnable(queue);
    }
    retry_bytes
}

#[inline]
pub(in crate::afxdp) fn restore_cos_prepared_items_inner(
    queue: &mut CoSQueueRuntime,
    retry: &mut VecDeque<PreparedTxRequest>,
) -> u64 {
    let mut retry_bytes = 0u64;
    while let Some(req) = retry.pop_back() {
        retry_bytes = retry_bytes.saturating_add(req.len as u64);
        cos_queue_push_front(queue, CoSPendingTxItem::Prepared(req));
    }
    if !cos_queue_is_empty(queue) {
        mark_cos_queue_runnable(queue);
    }
    retry_bytes
}

#[cfg(test)]
#[path = "tx_completion_tests.rs"]
mod tests;
