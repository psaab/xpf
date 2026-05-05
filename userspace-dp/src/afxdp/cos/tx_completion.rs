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
    CoSInterfaceRuntime, CoSPendingTxItem, CoSQueueRuntime, SharedCoSQueueLease,
    PreparedTxRequest, TxRequest,
    COS_TIMER_WHEEL_L0_SLOTS, COS_TIMER_WHEEL_L1_SLOTS,
};
use crate::afxdp::worker::BindingWorker;

use super::queue_ops::{cos_queue_is_empty, cos_queue_push_front};
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
                queue.drop_counters.root_token_starvation_parks = queue
                    .drop_counters
                    .root_token_starvation_parks
                    .wrapping_add(1);
            }
            ParkReason::QueueTokenStarvation => {
                queue.drop_counters.queue_token_starvation_parks = queue
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
    if queue.runnable {
        root.runnable_queues = root.runnable_queues.saturating_sub(1);
    }
    queue.runnable = false;
    queue.parked = true;
    queue.next_wakeup_tick = wake_tick;
    queue.wheel_level = level;
    queue.wheel_slot = slot;
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
        queue.runnable = false;
        queue.parked = false;
        queue.next_wakeup_tick = 0;
        return;
    }
    if !queue.runnable {
        root.runnable_queues = root.runnable_queues.saturating_add(1);
    }
    mark_cos_queue_runnable(queue);
}

// #710: count an exact-drain TX submit stall on a specific queue.
// NOT packet loss — on the exact path, `writer.insert == 0` leaves
// the FIFO items in `queue.items` or restores them (flow-fair path);
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
            queue.drop_counters.tx_ring_full_submit_stalls = queue
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
    queue.runnable = true;
    queue.parked = false;
    queue.next_wakeup_tick = 0;
}

#[inline]
pub(in crate::afxdp) fn normalize_cos_queue_state(queue: &mut CoSQueueRuntime) {
    if cos_queue_is_empty(queue) {
        queue.runnable = false;
        queue.parked = false;
        queue.next_wakeup_tick = 0;
        queue.surplus_deficit = 0;
        return;
    }
    // Non-empty queues have only two valid steady states:
    // 1. parked with a wakeup tick
    // 2. runnable immediately
    // Anything else can strand backlog forever.
    if queue.parked && queue.next_wakeup_tick > 0 {
        queue.runnable = false;
        return;
    }
    mark_cos_queue_runnable(queue);
}

#[inline]
pub(in crate::afxdp) fn advance_cos_timer_wheel(root: &mut CoSInterfaceRuntime, now_ns: u64) {
    let now_tick = cos_tick_for_ns(now_ns);
    while root.timer_wheel.current_tick < now_tick {
        root.timer_wheel.current_tick = root.timer_wheel.current_tick.saturating_add(1);
        if root.timer_wheel.current_tick % COS_TIMER_WHEEL_L0_SLOTS as u64 == 0 {
            cascade_cos_timer_wheel_level1(root);
        }
        wake_due_cos_timer_slot(root);
    }
}

fn cascade_cos_timer_wheel_level1(root: &mut CoSInterfaceRuntime) {
    let slot = ((root.timer_wheel.current_tick / COS_TIMER_WHEEL_L0_SLOTS as u64)
        % COS_TIMER_WHEEL_L1_SLOTS as u64) as usize;
    let queued = core::mem::take(&mut root.timer_wheel.level1[slot]);
    let mut rearm = Vec::with_capacity(queued.len());
    for queue_idx in queued {
        let Some(queue) = root.queues.get(queue_idx) else {
            continue;
        };
        if !queue.parked || queue.wheel_level != 1 || queue.wheel_slot != slot {
            continue;
        }
        rearm.push((queue_idx, queue.next_wakeup_tick));
    }
    for (queue_idx, wake_tick) in rearm {
        rearm_cos_queue(root, queue_idx, wake_tick);
    }
}

fn wake_due_cos_timer_slot(root: &mut CoSInterfaceRuntime) {
    let slot = (root.timer_wheel.current_tick % COS_TIMER_WHEEL_L0_SLOTS as u64) as usize;
    let queued = core::mem::take(&mut root.timer_wheel.level0[slot]);
    let mut rearm = Vec::with_capacity(queued.len());
    let mut wake = Vec::with_capacity(queued.len());
    for queue_idx in queued {
        let Some(queue) = root.queues.get(queue_idx) else {
            continue;
        };
        if !queue.parked || queue.wheel_level != 0 || queue.wheel_slot != slot {
            continue;
        }
        if queue.next_wakeup_tick <= root.timer_wheel.current_tick {
            wake.push(queue_idx);
        } else {
            rearm.push((queue_idx, queue.next_wakeup_tick));
        }
    }
    for queue_idx in wake {
        wake_cos_queue(root, queue_idx);
    }
    for (queue_idx, wake_tick) in rearm {
        rearm_cos_queue(root, queue_idx, wake_tick);
    }
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
    let shared_root_lease = binding
        .cos.cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.clone());
    let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
        return false;
    };
    advance_cos_timer_wheel(root, now_ns);
    if let Some(shared_root_lease) = shared_root_lease.as_ref() {
        maybe_top_up_cos_root_lease(root, shared_root_lease, now_ns);
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
/// skips them via `queue.exact && !queue.surplus_sharing`.
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
pub(in crate::afxdp) fn apply_direct_exact_send_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    sent_packets: u64,
    sent_bytes: u64,
) {
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.queued_bytes = queue.queued_bytes.saturating_sub(sent_bytes);
            queue.tokens = queue.tokens.saturating_sub(sent_bytes);
            // #760 instrumentation: record the exact-owner-local
            // send at the same place the token bucket decrements.
            // Divide by a scrape window to get an observed per-queue
            // drain rate and compare against
            // `queue.transmit_rate_bytes` to detect a cap bypass.
            queue
                .owner_profile
                .drain_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos.cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    if let Some(shared_queue_lease) = binding
        .cos.cos_fast_interfaces
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
    let mut released_queue_leases = Vec::<(usize, u64)>::new();
    let old_nonempty = binding
        .cos.cos_interfaces
        .get(&root_ifindex)
        .map(|root| root.nonempty_queues)
        .unwrap_or(0);
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        for (queue_idx, queue) in root.queues.iter_mut().enumerate() {
            normalize_cos_queue_state(queue);
            if cos_queue_is_empty(queue) && queue.exact && queue.tokens > 0 {
                released_queue_leases.push((queue_idx, core::mem::take(&mut queue.tokens)));
            }
            if cos_queue_is_empty(queue) {
                continue;
            }
            new_nonempty = new_nonempty.saturating_add(1);
            if queue.runnable {
                new_runnable = new_runnable.saturating_add(1);
            }
        }
        root.nonempty_queues = new_nonempty;
        root.runnable_queues = new_runnable;
    }
    if old_nonempty == 0 && new_nonempty > 0 {
        binding.cos.cos_nonempty_interfaces = binding.cos.cos_nonempty_interfaces.saturating_add(1);
    } else if old_nonempty > 0 && new_nonempty == 0 {
        binding.cos.cos_nonempty_interfaces = binding.cos.cos_nonempty_interfaces.saturating_sub(1);
        release_cos_root_lease(binding, root_ifindex);
    }
    if let Some(iface_fast) = binding.cos.cos_fast_interfaces.get(&root_ifindex) {
        for (queue_idx, released) in released_queue_leases {
            if let Some(shared_queue_lease) = iface_fast
                .queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref())
            {
                shared_queue_lease.release_unused(released);
            }
        }
    }
}

#[inline]
pub(in crate::afxdp) fn apply_cos_send_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    sent_bytes: u64,
    retry: VecDeque<TxRequest>,
) {
    let mut exact_queue_idx = None;
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            exact_queue_idx = queue.exact.then_some(queue_idx);
            let retry_bytes = restore_cos_local_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
            match phase {
                CoSServicePhase::Guarantee => {
                    queue.tokens = queue.tokens.saturating_sub(sent_bytes);
                }
                CoSServicePhase::Surplus => {
                    queue.surplus_deficit = queue.surplus_deficit.saturating_sub(sent_bytes);
                }
            }
            // #760 instrumentation: record non-exact / surplus /
            // shared-exact sends at the same site the queue's token
            // or surplus accounting is debited. Paired with the
            // apply_direct_exact_send_result write so the sum across
            // all sites equals the bytes the CoS scheduler accounted.
            queue
                .owner_profile
                .drain_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos.cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    // #915: phase-gate `shared_queue_lease` consumption to the
    // Guarantee phase only. See `maybe_consume_exact_queue_lease`
    // for rationale.
    if let Some(queue_idx) = exact_queue_idx {
        let shared_queue_lease = binding
            .cos
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref());
        maybe_consume_exact_queue_lease(shared_queue_lease, phase, sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

#[inline]
pub(in crate::afxdp) fn apply_cos_prepared_result(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    phase: CoSServicePhase,
    batch_bytes: u64,
    sent_bytes: u64,
    retry: VecDeque<PreparedTxRequest>,
) {
    let mut exact_queue_idx = None;
    {
        let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) else {
            return;
        };
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            exact_queue_idx = queue.exact.then_some(queue_idx);
            let retry_bytes = restore_cos_prepared_items_inner(queue, retry);
            queue.queued_bytes = queue
                .queued_bytes
                .saturating_sub(batch_bytes)
                .saturating_add(retry_bytes);
            match phase {
                CoSServicePhase::Guarantee => {
                    queue.tokens = queue.tokens.saturating_sub(sent_bytes);
                }
                CoSServicePhase::Surplus => {
                    queue.surplus_deficit = queue.surplus_deficit.saturating_sub(sent_bytes);
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
            queue
                .owner_profile
                .drain_sent_bytes
                .fetch_add(sent_bytes, Ordering::Relaxed);
        }
        root.tokens = root.tokens.saturating_sub(sent_bytes);
    }
    if let Some(shared_root_lease) = binding
        .cos.cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_root_lease.as_ref())
    {
        shared_root_lease.consume(sent_bytes);
    }
    // #915: phase-gate `shared_queue_lease` consumption to the
    // Guarantee phase only. See `maybe_consume_exact_queue_lease`
    // for rationale.
    if let Some(queue_idx) = exact_queue_idx {
        let shared_queue_lease = binding
            .cos
            .cos_fast_interfaces
            .get(&root_ifindex)
            .and_then(|iface_fast| iface_fast.queue_fast_path.get(queue_idx))
            .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref());
        maybe_consume_exact_queue_lease(shared_queue_lease, phase, sent_bytes);
    }
    refresh_cos_interface_activity(binding, root_ifindex);
}

#[inline]
pub(in crate::afxdp) fn restore_cos_local_items_inner(
    queue: &mut CoSQueueRuntime,
    mut retry: VecDeque<TxRequest>,
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
    mut retry: VecDeque<PreparedTxRequest>,
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

