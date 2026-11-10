// Residual-surplus stage of the worker CoS service pipeline: the
// interface-wide residual budget that bounds non-exact surplus while exact
// classes demand their reservation (#18748), and the colocated non-exact
// turn that draws on it (#19025). Split out of queue_service/mod.rs to keep
// it under the #13065 800-line ceiling.

use super::*;
use crate::afxdp::cos::exact_demand::local_exact_demand_mask;

/// #19025: the colocated non-exact turn, if this binding has one.
///
/// The drain serves a worker's exact guarantee before anything else, so on a
/// worker whose exact class takes every opportunity (held by the worker's
/// TX capacity, say) the colocated non-exact queue was never visited
/// (#19023: 0 Gb/s for the whole window), and on a busy exact worker it
/// polled the shared residual far less often than its peers (#19025: a
/// fraction of their share). So after each exact service on this binding
/// (`nonexact_turn`), while this binding has exact demand of its own and
/// non-exact backlog, one non-exact surplus batch goes before the next exact
/// service. The batch draws on the interface-wide residual like every other
/// non-exact surplus batch (`nonexact_surplus_budget_under_exact_demand`), so
/// non-exact traffic stays within the residual whoever sends it and residual
/// one binding cannot use stays available to the others. A turn is one
/// surplus quantum (`surplus_weight` frames), so the exact class keeps at
/// least every other service on its own worker. Only non-exact queues are
/// eligible (surplus-sharing exact queues wait for the normal surplus pass).
/// Cheap exits first: no turn pending, no exact class on the interface, or
/// fewer than two non-empty queues.
#[inline]
pub(super) fn build_colocated_nonexact_turn_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> Option<CoSBatch> {
    let slot = binding.slot;
    let shared_exact_backlog = binding
        .cos
        .cos_fast_interfaces
        .get(&root_ifindex)
        .and_then(|iface_fast| iface_fast.shared_exact_backlog.as_ref());
    let local_scratch = &mut binding.cos.cos_local_batch_scratch;
    let prepared_scratch = &mut binding.cos.cos_prepared_batch_scratch;
    let root = binding.cos.cos_interfaces.get_mut(&root_ifindex)?;
    if !root.nonexact_turn
        || root.exact_queues_by_rate_ascending.is_empty()
        || root.nonempty_queues < 2
    {
        return None;
    }
    let local_demand_mask = local_exact_demand_mask(root);
    if local_demand_mask.is_empty()
        || !root
            .queues
            .iter()
            .any(|queue| !queue.config.exact && !cos_queue_is_empty(queue))
    {
        return None;
    }
    let peer_exact_demand_mask = shared_exact_backlog
        .map(|backlog| backlog.peer_exact_demand_queue_mask(slot))
        .unwrap_or(ExactDemandQueueMask::EMPTY);
    let exact_demand_rate =
        exact_demand_rate_bytes_for_mask(root, local_demand_mask | peer_exact_demand_mask);
    let budget = nonexact_surplus_budget_under_exact_demand(
        root,
        slot,
        now_ns,
        exact_demand_rate,
        shared_exact_backlog.map(|backlog| &**backlog),
    )?;
    // An empty budget has nothing to give. A budget under the head is left
    // to the selector, which skips a non-exact head its budget cannot cover
    // (a gate at one full UMEM frame wasted turns a 1,500-byte head could
    // have used).
    if budget == 0 {
        return None;
    }
    // #18748 (the demand-gated pool floor): the turn is non-exact surplus,
    // so on a root with an exact class it takes root per batch leaving the
    // pool floor, like every other non-exact batch. The turn runs only with
    // local exact demand, so an exact class has work and the floor is on.
    let floor_on = cos_root_credit_per_batch(root) && cos_exact_floor_on(root, true, now_ns);
    let root_limit = match root.shared_root_lease.as_ref() {
        Some(lease) if floor_on => RootGrantLimit::nonexact(lease.max_total_leased()),
        _ => RootGrantLimit::FULL,
    };
    select_cos_surplus_batch_filtered(
        root,
        now_ns,
        true,
        Some(budget),
        root_limit,
        local_scratch,
        prepared_scratch,
    )
}

#[inline]
pub(super) fn reset_nonexact_surplus_under_exact_budget(
    root: &mut CoSInterfaceRuntime,
    now_ns: u64,
    shared_exact_backlog: Option<&SharedCoSExactBacklog>,
) {
    root.nonexact_surplus_under_exact_tokens = 0;
    root.nonexact_surplus_under_exact_last_refill_ns = now_ns;
    if let Some(backlog) = shared_exact_backlog {
        backlog.reset_residual_surplus_budget(now_ns);
    }
}

#[inline]
pub(super) fn residual_rate_and_burst(
    root: &CoSInterfaceRuntime,
    exact_demand_rate: u64,
) -> Option<(u64, u64)> {
    if exact_demand_rate == 0 || root.shaping_rate_bytes == 0 {
        return None;
    }
    let residual_rate = root.shaping_rate_bytes.saturating_sub(exact_demand_rate);
    if residual_rate == 0 {
        return Some((0, 0));
    }
    let residual_burst = (residual_rate / 100)
        .max(COS_MIN_BURST_BYTES)
        .min(cos_effective_burst_bytes(root.burst_bytes));
    Some((residual_rate, residual_burst))
}

#[inline]
pub(super) fn nonexact_surplus_budget_under_exact_demand(
    root: &mut CoSInterfaceRuntime,
    binding_slot: u32,
    now_ns: u64,
    exact_demand_rate: u64,
    shared_exact_backlog: Option<&SharedCoSExactBacklog>,
) -> Option<u64> {
    let Some((residual_rate, residual_burst)) = residual_rate_and_burst(root, exact_demand_rate)
    else {
        reset_nonexact_surplus_under_exact_budget(root, now_ns, shared_exact_backlog);
        return None;
    };
    if residual_rate == 0 {
        reset_nonexact_surplus_under_exact_budget(root, now_ns, shared_exact_backlog);
        return Some(0);
    }
    if let Some(backlog) = shared_exact_backlog {
        root.nonexact_surplus_under_exact_tokens = 0;
        root.nonexact_surplus_under_exact_last_refill_ns = now_ns;
        // #19025: only a binding with non-exact backlog asks, and so holds a
        // claim. One whose surplus pass runs with nothing non-exact queued
        // (its exact pass fell through, or only a surplus-sharing exact
        // queue waits) would reserve a part of the residual that nobody
        // spends. The budget bounds non-exact queues only, so with none
        // queued it is never read.
        if !root
            .queues
            .iter()
            .any(|queue| !queue.config.exact && !cos_queue_is_empty(queue))
        {
            return Some(0);
        }
        // #19025: the interface-wide residual pool, with this binding's
        // per-epoch claim on it (`SharedCoSExactBacklog::nonexact_surplus_budget`).
        return Some(backlog.nonexact_surplus_budget(
            binding_slot,
            now_ns,
            residual_rate,
            residual_burst,
        ));
    }
    refill_cos_tokens(
        &mut root.nonexact_surplus_under_exact_tokens,
        residual_rate,
        residual_burst,
        &mut root.nonexact_surplus_under_exact_last_refill_ns,
        now_ns,
    );
    Some(root.nonexact_surplus_under_exact_tokens)
}
