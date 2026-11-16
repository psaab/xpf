// Residual-surplus stage of the worker CoS service pipeline: the
// interface-wide residual budget that bounds non-exact surplus while exact
// classes demand their reservation (#18748), and the colocated non-exact
// turn (#19025, #19100), which is worker-local and never draws on it. Split out of queue_service/mod.rs to keep
// it under the #13065 800-line ceiling.

use super::*;
use crate::afxdp::cos::exact_demand::local_exact_demand_mask;

/// #19025 / #19100: the colocated non-exact turn, if this binding has one.
///
/// The drain serves a worker's exact guarantee before anything else, so on a
/// worker whose exact class takes every opportunity (held by the worker's TX
/// capacity, say) the colocated non-exact queue was never visited (#19023,
/// #19100: 0 Gb/s for the whole window). After each exact service on this
/// binding (`nonexact_turn`), while it has exact backlog and non-exact
/// backlog, one non-exact batch may go before the next exact service. Turns
/// are worker-local (#19100 v6): they never touch the shared residual pool.
/// They are paid from two local credits that committed exact work earns at
/// phi/(1-phi), phi = min(R_local / shaping, 1/32) (`v61_accrue_turn_credit`):
/// - a FUNDED turn needs the worker behind its exact pace with exact tokens
///   unspent (capacity-bound) and both credits positive;
/// - the MINIMUM turn, one packet per local 1 ms epoch from the queue the
///   selector serves, needs only both credits out of debt.
/// Every committed turn byte and packet is charged to them
/// (`v61_settle_turn`), so turns of either kind stay within phi/(1-phi) of
/// committed exact bytes and packets, plus the caps and one batch.
/// Only non-exact queues are eligible, and an attempt that cannot be built
/// leaves the queues and the #18748 floor hold as it found them.
#[inline]
pub(super) fn build_colocated_nonexact_turn_batch(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    now_ns: u64,
) -> Option<CoSBatch> {
    let local_scratch = &mut binding.cos.cos_local_batch_scratch;
    let prepared_scratch = &mut binding.cos.cos_prepared_batch_scratch;
    let root = binding.cos.cos_interfaces.get_mut(&root_ifindex)?;
    if !root.nonexact_turn
        || root.exact_queues_by_rate_ascending.is_empty()
        || root.nonempty_queues < 2
    {
        return None;
    }
    // Codex v6 P1-1: the local epoch advances, and the minimum turn is
    // decided, BEFORE any exit that needs cached exact tokens. A backlogged
    // exact queue whose tokens the selector has not yet topped up is not
    // "serviceable", and an exit on that skipped the minimum for good.
    const V6_EPOCH_NS: u64 = 1_000_000;
    let epoch = now_ns / V6_EPOCH_NS;
    if root.v6_epoch != epoch {
        root.v6_epoch = epoch;
        root.v6_min_turn_done = false;
        // The pace window reopens at this epoch's first coherent share
        // observation (below), not at the epoch boundary.
        root.v61_pace_valid = false;
    }
    if !root
        .queues
        .iter()
        .any(|queue| !queue.config.exact && !cos_queue_is_empty(queue))
        || !root.queues.iter().any(|queue| {
            queue.config.exact && queue.config.guarantee_enabled && !cos_queue_is_empty(queue)
        })
    {
        return None;
    }
    let frame = crate::afxdp::tx_frame_capacity() as u64;
    let local_demand_mask = local_exact_demand_mask(root);
    let exact_sent_now = v61_exact_sent_bytes(root);
    // Pace (needs serviceable local demand). Codex v6.1 P2-3: the share is a
    // coherent observation or nothing. A failed read leaves the window
    // unopened (no funded turn on this check), never the full class rate;
    // and the window opens WHERE the share is observed, so a share is never
    // applied to time before it was read.
    let mut behind = false;
    if !local_demand_mask.is_empty() {
        if !root.v61_pace_valid
            && let Some(share) = v61_pace_share(root, local_demand_mask)
        {
            root.v61_pace_share = share;
            root.v61_pace_valid = true;
            root.v6_anchor_ns = now_ns;
            root.v6_exact_at_epoch_start = exact_sent_now;
            root.v6_turn_sent = 0;
        }
        if root.v61_pace_valid {
            let elapsed = now_ns.saturating_sub(root.v6_anchor_ns);
            let pace = (root.v61_pace_share as u128 * elapsed as u128 * 98 / 100 / 1_000_000_000u128)
                .min(u64::MAX as u128) as u64;
            // Lifetime counters wrap (relaxed `fetch_add`), so the window's
            // progress is a wrapping difference.
            let committed = exact_sent_now
                .wrapping_sub(root.v6_exact_at_epoch_start)
                .saturating_add(root.v6_turn_sent);
            let exact_holds_tokens = root.queues.iter().enumerate().any(|(queue_idx, queue)| {
                queue.config.exact
                    && local_demand_mask.counts(queue_idx)
                    && crate::afxdp::cos::queue_ops::cos_queue_front(queue)
                        .is_some_and(|head| queue.hot.tokens >= crate::afxdp::cos::cos_item_len(head))
            });
            behind = elapsed >= 100_000 && committed < pace && exact_holds_tokens;
        }
    }
    let funded = behind && v61_funded_credits(root);
    #[cfg(test)]
    {
        use std::sync::atomic::Ordering::Relaxed;
        V61_DIAG[0].fetch_add(1, Relaxed);
        if local_demand_mask.is_empty() { V61_DIAG[1].fetch_add(1, Relaxed); }
        if behind { V61_DIAG[2].fetch_add(1, Relaxed); }
        if root.v61_byte_credit > 0 { V61_DIAG[3].fetch_add(1, Relaxed); }
        if root.v61_opp_credit > 0 { V61_DIAG[4].fetch_add(1, Relaxed); }
        if funded { V61_DIAG[5].fetch_add(1, Relaxed); }
        V61_DIAG[6].store(root.v61_pace_share, Relaxed);
        V61_DIAG[7].store(root.v6_credit_den, Relaxed);
    }
    // A funded turn spends at most its byte credit (at most one TX batch)
    // and at most the whole packets its opportunity credit holds, both hard
    // limits, so it never borrows. The minimum is one packet, only out of
    // debt (`v61_minimum_credits`). The selector applies both to the queue it
    // actually serves (Codex v6.1 P2-4, v6.2 P2-2).
    let (turn_bytes, pass) = if funded {
        (
            ((root.v61_byte_credit >> V61_CREDIT_SHIFT) as u64).min(64 * frame),
            SurplusPass::Colocated {
                max_packets: (root.v61_opp_credit >> V61_CREDIT_SHIFT) as u64,
            },
        )
    } else if !root.v6_min_turn_done && v61_minimum_credits(root) {
        (frame, SurplusPass::Colocated { max_packets: 1 })
    } else {
        return None;
    };
    if turn_bytes == 0 {
        return None;
    }
    // #18748 (the demand-gated pool floor): the turn is non-exact surplus,
    // so on a root with an exact class it takes root per batch leaving the
    // pool floor, like every other non-exact batch. The floor is on: this
    // root has exact backlog (checked above). The turn READS that and does
    // not refresh the floor's hold (`cos_exact_floor_on` stamps
    // `exact_work_seen_ns`): the hold is timed from the ordinary non-exact
    // builds. #19100 v6.1 (C3): a turn is attempted after every exact
    // service, so stamping here kept the floor on without a gap; at a 12 KB
    // root best-effort then parked against it in the ordinary pass
    // (1.64 Gb/s against 3.66;
    // `a_steady_exact_class_below_its_rate_keeps_the_floor_through_its_gaps_18748`).
    let floor_on = cos_root_credit_per_batch(root);
    let root_limit = match root.shared_root_lease.as_ref() {
        Some(lease) if floor_on => RootGrantLimit::nonexact(lease.max_total_leased()),
        _ => RootGrantLimit::FULL,
    };
    // The turn's byte budget reaches both the root request and the builder
    // through the surplus deficit, over every queue index; restored after.
    let mut saved_deficits = [0u64; 256];
    for (i, queue) in root.queues.iter_mut().enumerate().take(256) {
        saved_deficits[i] = queue.hot.surplus_deficit;
        if !queue.config.exact && !cos_queue_is_empty(queue) {
            queue.hot.surplus_deficit = queue.hot.surplus_deficit.max(turn_bytes);
        }
    }
    let batch = select_cos_surplus_batch_filtered(
        root,
        now_ns,
        pass,
        Some(turn_bytes),
        root_limit,
        local_scratch,
        prepared_scratch,
    );
    for (i, queue) in root.queues.iter_mut().enumerate().take(256) {
        queue.hot.surplus_deficit = saved_deficits[i];
    }
    #[cfg(test)]
    if batch.is_some() {
        if funded {
            root.v61_test.funded_builds += 1;
        } else {
            root.v61_test.minimum_builds += 1;
        }
    }
    // Every non-exact build states whether its batch is a turn (Codex v6
    // P1-5); settlement consumes it.
    root.v6_inflight_turn = batch.is_some();
    batch
}

/// Committed exact guarantee bytes on this root (the pace's numerator).
#[inline]
fn v61_exact_sent_bytes(root: &CoSInterfaceRuntime) -> u64 {
    root.queues
        .iter()
        .filter(|queue| queue.config.exact && queue.config.guarantee_enabled)
        .map(|queue| {
            queue
                .telemetry
                .owner_profile
                .drain_sent_bytes
                .load(std::sync::atomic::Ordering::Relaxed)
        })
        .fold(0u64, u64::wrapping_add)
}

/// #19100: this worker's exact pace over the demanding exact queues, from
/// ONE coherent observation of each queue's v8 allotment (Codex v6 P1-4). A
/// queue with a v8 lease whose snapshot is unavailable (the seqlock reader
/// gave up, or the epoch has no cap) makes the whole observation unavailable:
/// `None`, never the full configured rate (Codex v6.1 P2-3). A queue without
/// a v8 lease paces at its configured rate (it has no allotment to slice).
#[inline]
pub(in crate::afxdp) fn v61_pace_share(
    root: &CoSInterfaceRuntime,
    demand: ExactDemandQueueMask,
) -> Option<u64> {
    let mut share = 0u64;
    for (queue_idx, queue) in root.queues.iter().enumerate() {
        if !(queue.config.exact && queue.config.guarantee_enabled && demand.counts(queue_idx)) {
            continue;
        }
        let part = match queue.queue_lease_v8.as_ref() {
            Some(lease) => {
                lease.v8_worker_share_of_rate(queue.v_min.worker_id as usize, queue.transmit_rate_bytes())?
            }
            None => queue.transmit_rate_bytes(),
        };
        share = share.saturating_add(part);
    }
    Some(share)
}

/// #19100: turn credits are Q32 fixed point: 1 << `V61_CREDIT_SHIFT` units
/// are one byte (byte credit) or one packet (opportunity credit). Accrual
/// loses under one unit per commit, so neither a denominator change nor a
/// tiny phi can floor a commit's earnings to zero (Codex v6.1 P1-1: two exact
/// classes alternating 64-byte commits at 124,999,000 and 124,998,000 B/s on
/// a 125 MB/s root earned floor(64 x 1,000 / 124,999,000) = 0 bytes each
/// commit, the remainder reset at every change, and the minimum never
/// returned).
pub(in crate::afxdp) const V61_CREDIT_SHIFT: u32 = 32;
const V61_ONE: i64 = 1 << V61_CREDIT_SHIFT;
/// phi_max: the colocated share never exceeds 1/32 of a worker.
pub(in crate::afxdp) const V61_PHI_MAX_DEN: u64 = 32;
/// The opportunity credit's cap: one TX batch of packets.
const V61_OPP_CAP_PACKETS: i64 = 64;

/// A funded turn needs at least one byte and one WHOLE packet of opportunity
/// credit, and takes at most the whole packets it holds (a true builder
/// limit), so funded turns never borrow (Codex v6.2 P2-2). Only the minimum
/// leaves debt, of at most one packet and one frame.
#[inline]
pub(in crate::afxdp) fn v61_funded_credits(root: &CoSInterfaceRuntime) -> bool {
    root.v61_byte_credit >= V61_ONE && root.v61_opp_credit >= V61_ONE
}

/// The minimum turn needs both credits out of debt (Codex v6 P1-3): it is
/// charged like any turn, so the next one waits until committed exact work
/// has repaid it. Without the wait it cost one packet per ms whatever the
/// residual: at R = 0 it took 12% of an exact class at a full 100 Mb/s root
/// (`a_low_rate_exact_class_keeps_its_rate_at_any_poll_period_18748`).
#[inline]
pub(in crate::afxdp) fn v61_minimum_credits(root: &CoSInterfaceRuntime) -> bool {
    root.v61_byte_credit >= 0 && root.v61_opp_credit >= 0
}

/// #19100: earn the colocated turn credit as exact work COMMITS (Codex v6
/// P2-7), at the local ratio in force now: phi_eff = min(R_local / shaping,
/// 1/32), with R_local = shaping - the committing queue's rate - every other
/// locally backlogged exact queue's. Each committed exact byte earns
/// phi_eff/(1-phi_eff) bytes and each committed exact PACKET earns
/// phi_eff/(1-phi_eff) packets (Codex v6.1 P1-2: the same unit the turn is
/// charged in, so short exact batches earn proportionally less). Q32, with
/// the sub-unit remainders carried exactly under a fixed denominator and
/// rescaled across a change. Credits carry debt (signed) and are capped above
/// at one TX batch, 64 frames of bytes and 64 packets, and the cap bounds the
/// whole represented balance (a full bank keeps no remainder).
///
/// Progress bound (Codex v6.2 P1, v6.3 P1). Let V = credit + rem / d in Q32
/// units, and r / d' the exact ratio above, whose numerator r >= 1 whenever
/// R_local > 0 (r = R_local below the cap, r = 1 at it). A commit of s bytes
/// (or packets) raises V by exactly s x r x 2^32 / d', and a denominator
/// change lowers it by under 1 / d'. So every commit that does not hit the
/// upper cap raises V by more than (s x r x 2^32 - 1) / d' >= (2^32 - 1) / d'
/// > 0, for bytes and packets alike, over the whole integer-rate domain
/// (shaping < 2^64 B/s, any reserved < shaping), for TX-batch-sized commits
/// (s <= 64 x 4,096 bytes, s <= 64 packets: with r < 2^59 the shifted
/// products stay below 2^109). A debt never meets the upper cap before it is
/// repaid.
/// In Codex's terms, r_phi x b_min - eps > 0 and r_phi x p_min - eps > 0 with
/// eps < 2^-32 / d'. A debt of D units is therefore repaid within
/// ceil((D + 1) x d_max / (s_min x r_min x 2^32 - 1)) commits: finite,
/// though at r = 1 B/s on a 100 Gb/s root that is about 1.25 x 10^10
/// one-packet commits per packet, the residual contract itself. With R = 0
/// nothing accrues and nothing is owed.
#[inline]
pub(in crate::afxdp) fn v61_accrue_turn_credit(
    root: &mut CoSInterfaceRuntime,
    queue_idx: usize,
    sent_bytes: u64,
    sent_packets: u64,
) {
    if sent_bytes == 0 || root.shaping_rate_bytes == 0 {
        return;
    }
    let shaping = root.shaping_rate_bytes;
    // Priced at commit: the committing exact queue plus every other locally
    // backlogged exact guarantee queue. (The serviceable mask is empty here:
    // the queue has just spent its own tokens and its root grant.)
    let reserved: u64 = root
        .queues
        .iter()
        .enumerate()
        .filter(|(idx, queue)| {
            queue.config.exact
                && queue.config.guarantee_enabled
                && (*idx == queue_idx || !cos_queue_is_empty(queue))
        })
        .map(|(_, queue)| queue.transmit_rate_bytes())
        .fold(0u64, u64::saturating_add);
    if reserved == 0 || reserved >= shaping {
        return;
    }
    // phi/(1-phi) as the exact integer ratio residual / reserved_eff, with
    // phi = min(R_local / shaping, 1/32). Below the cap it is R_local /
    // reserved, with R_local >= 1; at the cap it is exactly 1/31 (phi = 1/32
    // exactly, not rounded up). Codex v6.3 P1: min(R_local, shaping / 32)
    // floored a positive share to zero below 32 B/s (shaping 31, reserved
    // 30: residual 0, so nothing ever accrued).
    let local = shaping - reserved;
    let (residual, reserved_eff) = if V61_PHI_MAX_DEN as u128 * local as u128 <= shaping as u128 {
        (local, reserved)
    } else {
        (1, V61_PHI_MAX_DEN - 1)
    };
    if root.v6_credit_den != reserved_eff {
        // Codex v6.2 P1: carry the sub-unit remainders ACROSS the change,
        // rescaled to the new denominator: rho' = floor(rho x d' / d)
        // (rho < d <= 2^64, so the product fits u128 and rho' < d'). The
        // carried value loses under 1/d' of a Q32 unit per change. Resetting
        // them instead lost everything below one unit at every change: at
        // residuals of 1 and 2 B/s on a 100 Gb/s root each commit earned
        // floor(2^32 / 12,499,999,999) = 0 packet units and the minimum
        // never returned. See `v61_accrue_turn_credit`'s progress bound.
        let old = root.v6_credit_den;
        let rescale = |rem: u64| -> u64 {
            if old == 0 {
                0
            } else {
                (rem as u128 * reserved_eff as u128 / old as u128) as u64
            }
        };
        root.v6_credit_rem = rescale(root.v6_credit_rem);
        root.v61_opp_rem = rescale(root.v61_opp_rem);
        root.v6_credit_den = reserved_eff;
    }
    #[cfg(test)]
    V61_ACCRUALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let den = reserved_eff as u128;
    let num = ((sent_bytes as u128 * residual as u128) << V61_CREDIT_SHIFT) + root.v6_credit_rem as u128;
    let add = (num / den).min(i64::MAX as u128) as i64;
    root.v6_credit_rem = (num % den) as u64;
    let frame = crate::afxdp::tx_frame_capacity() as i64;
    // The cap bounds the WHOLE represented balance: at the cap the sub-unit
    // remainder is dropped too, so a full bank is exactly the cap and the
    // interval bound "earned + 64 + 1" holds without a fractional excess
    // (Codex v6.3 P2: a retained remainder above a full bank let 66 turn
    // packets through against 66 - 1/d allowed).
    let byte_cap = (64 * frame) << V61_CREDIT_SHIFT;
    let byte_credit = root.v61_byte_credit.saturating_add(add);
    if byte_credit >= byte_cap {
        root.v61_byte_credit = byte_cap;
        root.v6_credit_rem = 0;
    } else {
        root.v61_byte_credit = byte_credit;
    }
    let opp_num = ((sent_packets as u128 * residual as u128) << V61_CREDIT_SHIFT) + root.v61_opp_rem as u128;
    let opp_add = (opp_num / den).min(i64::MAX as u128) as i64;
    root.v61_opp_rem = (opp_num % den) as u64;
    let opp_cap = V61_OPP_CAP_PACKETS << V61_CREDIT_SHIFT;
    let opp_credit = root.v61_opp_credit.saturating_add(opp_add);
    if opp_credit >= opp_cap {
        root.v61_opp_credit = opp_cap;
        root.v61_opp_rem = 0;
    } else {
        root.v61_opp_credit = opp_credit;
    }
}

/// #19100: settle a committed turn at its TRUE committed counts (Codex v6.1
/// P2-5: the submit's returned packet count, not built minus retried, which
/// counted drops as sent). Charged to the pace window and to both credits,
/// carrying debt (Codex v6 P1-3). One helper for both settle arms.
#[inline]
pub(in crate::afxdp) fn v61_settle_turn(
    root: &mut CoSInterfaceRuntime,
    sent_bytes: u64,
    sent_packets: u64,
) {
    root.v6_turn_sent = root.v6_turn_sent.saturating_add(sent_bytes);
    if sent_bytes == 0 {
        return;
    }
    let bytes = ((sent_bytes as u128) << V61_CREDIT_SHIFT).min(i64::MAX as u128) as i64;
    let packets = ((sent_packets.max(1) as u128) << V61_CREDIT_SHIFT).min(i64::MAX as u128) as i64;
    root.v61_byte_credit = root.v61_byte_credit.saturating_sub(bytes);
    root.v61_opp_credit = root.v61_opp_credit.saturating_sub(packets);
    root.v6_min_turn_done = true;
    #[cfg(test)]
    {
        root.v61_test.turn_bytes += sent_bytes;
        root.v61_test.turn_packets += sent_packets;
    }
}

#[cfg(test)]
pub(in crate::afxdp) static V61_ACCRUALS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(test)]
pub(in crate::afxdp) static V61_DIAG: [std::sync::atomic::AtomicU64; 8] = [const { std::sync::atomic::AtomicU64::new(0) }; 8];

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
        // #19100 v6-local: the shared residual pool without #19025's
        // per-binding claims (#18748 v3's metering), for non-turn surplus.
        let _ = binding_slot;
        return Some(backlog.residual_surplus_budget(now_ns, residual_rate, residual_burst));
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
