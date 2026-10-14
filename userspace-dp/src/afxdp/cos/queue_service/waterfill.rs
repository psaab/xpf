// Two-phase `GuaranteeRate` waterfill scheduler for the exact-guarantee
// selection path (#1614 A1), plus the Phase-1 honor refund that undoes a
// selection which transmitted zero bytes (hb166 T-2). Extracted from
// queue_service/mod.rs (#13065, source finding D1-14) so the refund and
// the Phase-1 walk that commits the honor cannot drift apart; the
// selector dispatch that calls into here lives in selectors.rs, the
// settlement helpers in settle.rs. Pure code motion: no logic changed.

use super::*;

// #1614 A1: two-phase waterfill selector for `guarantee-rate`
// oversubscription policy. Activated when the interface's
// `oversubscription_policy == GuaranteeRate` AND `guarantee_fraction
// > 0`. Implements an operator-tunable budget split between Phase 1
// (small-first honored set) and Phase 2 (residual distributed
// across larger queues).
//
// Per-call state (carried on `CoSInterfaceRuntime`):
//   - `waterfill_pass1_remaining_bytes`: Phase 1 budget remaining
//     in the current epoch. #1743: refilled to
//     `(shaping_rate_bytes × COS_GUARANTEE_VISIT_NS / 1e9 ×
//     guarantee_fraction)` for a SHAPED root (the documented
//     "fraction × cap" contract), or the legacy
//     `(quantum_sum × guarantee_fraction)` for a transparent
//     (unshaped) root, clamped to ≥ one min-quantum. Refilled on
//     EITHER the exhausted (`pass1 == 0`) path OR the time-based
//     path (`elapsed ≥ COS_GUARANTEE_VISIT_NS`).
//   - `waterfill_phase2_cursor`: where Phase 2's descending walk
//     last stopped; lets the selector resume on subsequent calls.
//     Reset to 0 ONLY on a genuine Phase-2 WRAP (the end-of-function
//     `None` path); NEITHER refill path touches it, so the descending
//     walk advances continuously across epochs (#1743 Hunk C / r2).
//   - `waterfill_epoch_start_ns`: timestamp of the last refill,
//     drives the time-based refresh (#1743).
//   - `waterfill_epoch_wrap_pending`: set by the Phase-2 wrap (`None`)
//     path; gates the honored-bitset clear so a bare mid-walk
//     `pass1 == 0` refill does NOT re-honor an exact-fit queue
//     (#1743 r3 livelock fix).
//
// Each call returns ONE queue selection. The selector first tries
// Phase 1 (ascending walk; each Phase-1 honor decrements
// `pass1_remaining` by the chosen queue's STABLE configured
// quantum `phase1_cost`, #1743 Hunk B — NOT the token-clamped
// send budget). When Phase 1 has insufficient budget for the next
// ascending queue, the selector enters Phase 2 (descending walk
// through queues NOT honored in Phase 1; Phase 2 does NOT debit
// `pass1`). When Phase 2 exhausts, the epoch resets and Phase 1
// budget is refilled.
//
// AGY r2 #1's equal-rate starvation concern is bounded by
// stable sort (queues with identical rates retain queue_id
// order). Codex code-r1 #1's fraction-honoring contract is
// preserved: `fraction = 0.4` and `fraction = 0.7` produce
// measurably different Phase 1 budgets and therefore different
// distributions.
#[inline]
pub(super) fn select_exact_cos_guarantee_queue_waterfill(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
) -> Option<ExactCoSQueueSelection> {
    let queue_count = root.queues.len();
    if queue_count == 0 || root.exact_queues_by_rate_ascending.is_empty() {
        return None;
    }
    // Phase 1 epoch refill (#4408 Increment 3a). See
    // `refill_waterfill_epoch` for the two refill triggers, the
    // epoch-boundary gate on the honored bitset, and the #1743 r2/r3
    // ordering hazard that keeps that block atomic.
    refill_waterfill_epoch(root, now_ns);
    let ascending_len = root.exact_queues_by_rate_ascending.len();
    debug_assert_eq!(
        root.waterfill_honored_epoch_bits.len(),
        ascending_len.div_ceil(u64::BITS as usize),
        "waterfill honored bitset must cover every exact guarantee ordinal"
    );
    // Phase 1: ascending-rate walk (#4408 Increment 3b). `None` means
    // "budget exhausted or nothing eligible" — both of the original body's
    // non-selecting Phase-1 exits — and falls through to Phase 2.
    if let Some(selection) = waterfill_phase1_select(
        root,
        queue_fast_path,
        now_ns,
        lease_telemetry,
        queue_count,
        ascending_len,
    ) {
        return Some(selection);
    }
    // Phase 2: descending-rate residual walk (#4408 Increment 3b). `None`
    // means the descending cycle serviced nothing, which is the genuine
    // Phase-2 WRAP handled by the tail below.
    if let Some(selection) = waterfill_phase2_select(
        root,
        queue_fast_path,
        now_ns,
        lease_telemetry,
        queue_count,
        ascending_len,
    ) {
        return Some(selection);
    }
    // Genuine Phase-2 WRAP: a full descending cycle serviced nothing, so the
    // epoch is fully consumed. Reset the Phase-1 budget and the cursor for
    // the next call, and arm `epoch_wrap_pending` so the refill above clears
    // the honored bitset (a true epoch boundary). #1743 (Codex r3): this is
    // the ONLY place that arms the honored-bits clear besides the time tick —
    // a bare mid-walk `pass1 == 0` does not, which avoids the all-min-quantum
    // re-honor livelock.
    root.waterfill_pass1_remaining_bytes = 0;
    root.waterfill_phase2_cursor = 0;
    root.waterfill_epoch_wrap_pending = true;
    None
}

// Phase 1: ascending-rate walk. Pick the first runnable queue
// whose secondary_budget ≤ pass1_remaining that has NOT already been
// honored this epoch.
//
// #1732: the honored set is the persistent `waterfill_honored_epoch_bits`
// on `root`, keyed by the ASCENDING-VEC ORDINAL `i` (NOT `queue_idx`).
// It is read by BOTH phases and cleared at the epoch refill above, so
// each queue is honored at most once per epoch: without the Phase-1 skip
// the smallest-rate queue would be re-honored on every selector call and
// monopolise the Phase-1 budget (the lowest-rate skew this fix targets).
// Iterating by index over the persistent vec avoids the per-call heap
// clone the old code used solely to dodge the `&mut root.queues` borrow
// conflict; `queue_idx` is copied out (a `Copy` `usize`) before the
// `&mut` borrow, so borrow-split holds with no allocation.
//
// #4408 Increment 3b: lifted verbatim out of
// `select_exact_cos_guarantee_queue_waterfill`. Every non-selecting exit of
// this walk — the `break` and loop exhaustion alike — already converged on
// the SAME successor in the original body, so `None` encodes them faithfully
// rather than inventing an outcome protocol. `#[inline(always)]` +
// same-module keeps the post-inline IR the shape it was (plan §2d); no
// coldness claim is made or needed.
//
// The interior of this walk is NOT further decomposable: `queue`'s `&mut`
// borrow of `root.queues` coexists with reads of the disjoint `root.tokens`
// and then ends so `count_park_reason`/`park_cos_queue` can take `&mut root`
// whole. That is NLL-precise; splitting inside would have to re-derive it.
#[inline(always)]
fn waterfill_phase1_select(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
    queue_count: usize,
    ascending_len: usize,
) -> Option<ExactCoSQueueSelection> {
    for i in 0..ascending_len {
        let queue_idx = root.exact_queues_by_rate_ascending[i];
        // #1732: at-most-once Phase-1 honor per epoch. Skip a queue already
        // honored this epoch (by ORDINAL `i`) so the ascending walk advances
        // to the next-smallest queue instead of re-honoring the smallest one
        // every call. The bitset is sized for every exact-queue ordinal.
        let word = i / u64::BITS as usize;
        let bit = i % u64::BITS as usize;
        if (root.waterfill_honored_epoch_bits[word] & (1u64 << bit)) != 0 {
            continue;
        }
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue)
            || !queue.hot.runnable
            || !queue.config.guarantee_enabled
            || !queue.config.exact
        {
            continue;
        }
        let top_up = maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        lease_telemetry.add_assign(top_up);
        let Some(head) = cos_queue_front(queue) else {
            continue;
        };
        let head_len = cos_item_len(head);
        // #1628 (r4 AGY): hoist `kind` next to `head_len` so `head`'s
        // immutable borrow of `queue` ends HERE — both are `Copy`. This
        // lets the per-queue telemetry mutations below (`&mut queue`)
        // compile, and the `return` reuses `kind` instead of re-matching
        // `head`.
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        // #1628 site 2: Phase-1 eligible visit — counted after the
        // eligibility gate + head-present, BEFORE the token gate, so a
        // token-starved-but-owned queue is still a visit.
        queue.telemetry.waterfill_counters.eligible_visits = queue
            .telemetry
            .waterfill_counters
            .eligible_visits
            .wrapping_add(1);
        if root.tokens < head_len {
            queue
                .telemetry
                .owner_profile
                .drain_park_root_tokens
                .fetch_add(1, Ordering::Relaxed);
            if queue.config.surplus_sharing {
                continue;
            }
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::RootTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        if queue.hot.tokens < head_len {
            queue
                .telemetry
                .owner_profile
                .drain_park_queue_tokens
                .fetch_add(1, Ordering::Relaxed);
            // #1782 Step-1 (ii): waterfill selector-site under-grant
            // attribution — same contract as the legacy RR site above.
            lease_telemetry.count_v8_undergrant(top_up.v8_shortfall_cause);
            if queue.config.surplus_sharing {
                continue;
            }
            if let Some(wake_tick) = estimate_cos_queue_wakeup_tick(
                root.tokens,
                root.shaping_rate_bytes,
                queue.hot.tokens,
                queue.transmit_rate_bytes(),
                head_len,
                now_ns,
                true,
            ) {
                count_park_reason(root, queue_idx, ParkReason::QueueTokenStarvation);
                park_cos_queue(root, queue_idx, wake_tick);
            }
            continue;
        }
        // Picked. #1630 (P2): decouple the two roles the quantum used
        // to play. The Phase-1 budget gate / consumption stays on the
        // RATE-SCALED quantum (`phase1_cost`) so the small-first
        // ordering and the shaper-anchored Phase-1 budget remain
        // consistent with `oversubscription_guarantee_fraction`.
        // The actual per-visit send budget (`send_budget`) is the
        // FRAME-count cap so a queue whose token bucket has banked
        // several frames (#1630 P1) drains them whole instead of
        // discarding the sub-frame remainder of the small quantum.
        //
        // #1743 Hunk B: charge the STABLE configured quantum, NOT
        // `queue.hot.tokens.min(quantum)`. Under v8-lease pressure
        // `queue.hot.tokens` collapses toward one frame, which collapsed
        // `phase1_cost` to `head_len`: the queue then trivially passed
        // the budget gate, consumed almost none of `pass1`, yet was
        // marked fully honored (below) — so Phase-2 skipped it
        // (phase2_admit stayed 0) while pass1 never neared exhaustion.
        // The honor decision must reflect the queue's full guaranteed
        // share for the epoch, independent of its current token bank.
        // (`send_budget` keeps the token clamp — it bounds the bytes
        // actually drained this visit, which legitimately tracks tokens.)
        let phase1_cost = cos_guarantee_quantum_bytes(queue).max(head_len);
        let send_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        // Phase 1 gate: if the rate-scaled cost for this queue exceeds
        // the remaining Phase 1 byte budget, this queue is past the
        // Phase 1 boundary. Mark all queues up to this point as
        // honored (they're the small classes that fit), break to
        // Phase 2 descending walk.
        if phase1_cost > root.waterfill_pass1_remaining_bytes {
            // Budget exhausted before this ascending queue could
            // be honored. Fall through to Phase 2 (descending walk over
            // queues NOT in the persistent honored set).
            // #1628 site 3: Phase-1 budget-exhausted break. Per-INTERFACE
            // (the break only sees the first crossing queue). Disjoint
            // `root` field, same pattern as the `:913` write below.
            root.waterfill_phase1_budget_breaks =
                root.waterfill_phase1_budget_breaks.wrapping_add(1);
            break;
        }
        // Phase 1 honor: consume the budget, mark honored, return.
        root.waterfill_pass1_remaining_bytes = root
            .waterfill_pass1_remaining_bytes
            .saturating_sub(phase1_cost);
        // #1732: mark this queue honored for the rest of the epoch by its
        // ASCENDING-VEC ORDINAL `i` (persists into later selector calls; both
        // phases skip it). The pre-sized word vector covers all ordinals.
        let word = i / u64::BITS as usize;
        let bit = i % u64::BITS as usize;
        root.waterfill_honored_epoch_bits[word] |= 1u64 << bit;
        root.exact_guarantee_rr = (queue_idx + 1) % queue_count;
        // #1628 site 4: Phase-1 honor admission. `head` already dropped
        // (kind hoisted above), so this `&mut queue` write compiles.
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.telemetry.waterfill_counters.phase1_admissions = queue
                .telemetry
                .waterfill_counters
                .phase1_admissions
                .wrapping_add(1);
        }
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget: send_budget,
            kind,
            // hb166 T-2: carry the epoch honor just committed above
            // (budget debit at `:1104`, honored bit at `:1112`) so the
            // service wrapper can REFUND it if this queue transmits zero
            // bytes. `cost_bytes` is always debited; the matching ordinal is
            // captured so a zero-TX refund clears the same honor bit.
            phase1_honor: Some(Phase1HonorRefund {
                cost_bytes: phase1_cost,
                bit_ordinal: i,
            }),
        });
    }
    None
}

// Phase 2: descending-rate walk over queues NOT honored in Phase 1
// this epoch.
//
// #1732: this reads the SAME persistent `waterfill_honored_epoch_bits`
// that Phase 1 sets, keyed by the ascending-vec ORDINAL `pos_from_end`,
// so it correctly skips queues that already took their Phase-1 guarantee
// this epoch and serves the residual to the larger un-honored queues —
// the documented descending-residual intent. (Previously this checked an
// empty function-local `honored_mask`, which is why the old comment here
// admitted it only "approximated".) Iterating `exact_queues_by_rate_
// ascending` by index avoids the heap clone the old code used.
//
// #4408 Increment 3b: lifted verbatim out of
// `select_exact_cos_guarantee_queue_waterfill`. Every non-selecting exit of
// this walk — the `break` and loop exhaustion alike — already converged on
// the SAME successor in the original body, so `None` encodes them faithfully
// rather than inventing an outcome protocol. `#[inline(always)]` +
// same-module keeps the post-inline IR the shape it was (plan §2d); no
// coldness claim is made or needed.
#[inline(always)]
fn waterfill_phase2_select(
    root: &mut CoSInterfaceRuntime,
    queue_fast_path: &[WorkerCoSQueueFastPath],
    now_ns: u64,
    lease_telemetry: &mut CoSQueueLeaseAcquireTelemetry,
    queue_count: usize,
    ascending_len: usize,
) -> Option<ExactCoSQueueSelection> {
    let mut phase2_idx = root.waterfill_phase2_cursor;
    if phase2_idx >= ascending_len {
        phase2_idx = 0;
    }
    let start_phase2 = phase2_idx;
    // Walk descending starting from the cursor position
    // (interpreted as "position in the descending walk"). Use a
    // bounded loop to avoid scanning forever.
    for _step in 0..ascending_len {
        // Map cursor → descending iteration: the ascending vec is
        // ascending, so index from the END. `pos_from_end` is the
        // ascending-vec ORDINAL of the queue visited here — the same key
        // Phase 1 set.
        let pos_from_end = ascending_len - 1 - phase2_idx;
        let queue_idx = root.exact_queues_by_rate_ascending[pos_from_end];
        // Skip queues honored in Phase 1 this epoch (persistent bitset,
        // keyed by ordinal). The word vector covers every exact ordinal.
        let word = pos_from_end / u64::BITS as usize;
        let bit = pos_from_end % u64::BITS as usize;
        if (root.waterfill_honored_epoch_bits[word] & (1u64 << bit)) != 0 {
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        }
        let queue = &mut root.queues[queue_idx];
        if cos_queue_is_empty(queue)
            || !queue.hot.runnable
            || !queue.config.guarantee_enabled
            || !queue.config.exact
        {
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        }
        let top_up = maybe_top_up_cos_queue_lease(
            queue,
            queue_fast_path
                .get(queue_idx)
                .and_then(|queue_fast| queue_fast.shared_queue_lease.as_ref()),
            now_ns,
        );
        lease_telemetry.add_assign(top_up);
        let Some(head) = cos_queue_front(queue) else {
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        };
        let head_len = cos_item_len(head);
        // #1628 (r4 AGY): hoist `kind` so `head`'s borrow of `queue` ends
        // here (both `Copy`), allowing the per-queue telemetry writes
        // below to compile.
        let kind = match head {
            CoSPendingTxItem::Local(_) => ExactCoSQueueKind::Local,
            CoSPendingTxItem::Prepared(_) => ExactCoSQueueKind::Prepared,
        };
        // #1628 site 5: Phase-2 eligible visit — counted after the
        // eligibility gate + head-present, BEFORE the token gate.
        queue.telemetry.waterfill_counters.eligible_visits = queue
            .telemetry
            .waterfill_counters
            .eligible_visits
            .wrapping_add(1);
        if root.tokens < head_len || queue.hot.tokens < head_len {
            // Don't park in Phase 2 — the queue may legitimately
            // wait for next epoch. The legacy selector parks; we
            // skip silently here because Phase 2 service is
            // best-effort residual, not a guarantee.
            phase2_idx = (phase2_idx + 1) % ascending_len;
            if phase2_idx == start_phase2 {
                break;
            }
            continue;
        }
        // Phase 2 selection: return and advance cursor. #1630 (P2):
        // per-visit FRAME-count cap (Phase 2 has no Phase-1 budget
        // accounting, so there is no rate-scaled cost to preserve here).
        let candidate_budget = queue
            .hot
            .tokens
            .min(cos_guarantee_visit_cap_bytes())
            .max(head_len);
        root.waterfill_phase2_cursor = (phase2_idx + 1) % ascending_len;
        root.exact_guarantee_rr = (queue_idx + 1) % queue_count;
        // #1628 site 6: Phase-2 admission. `head` already dropped (kind
        // hoisted above), so this `&mut queue` write compiles.
        if let Some(queue) = root.queues.get_mut(queue_idx) {
            queue.telemetry.waterfill_counters.phase2_admissions = queue
                .telemetry
                .waterfill_counters
                .phase2_admissions
                .wrapping_add(1);
        }
        return Some(ExactCoSQueueSelection {
            queue_idx,
            secondary_budget: candidate_budget,
            kind,
            // Phase 2 debits no Phase-1 budget and sets no honored bit, so
            // a zero-byte TX here loses nothing — nothing to refund.
            phase1_honor: None,
        });
    }
    None
}

// Phase 1 epoch refill. The BUDGET is refilled on two triggers:
//   (a) `pass1 == 0` — budget spent. Covers both the genuine Phase-2
//       wrap (the `None` path zeroes pass1 and arms wrap-pending) and a
//       mid-walk Phase-1 exact-fit honor that subtracted the last bytes.
//       Also the first-call path (pass1 seeds to 0 in the builder).
//   (b) #1743 time-based: `elapsed >= COS_GUARANTEE_VISIT_NS` since the
//       last refill. Phase-2 selections do NOT decrement `pass1`, so
//       under saturation `pass1` freezes at a small non-zero value below
//       every remaining quantum and small classes stop being honored;
//       the time tick refreshes the budget once per 200µs window.
//
// The honored BITSET, however, is cleared (allowing re-honoring) ONLY on
// a genuine epoch boundary: the time tick OR a Phase-2 WRAP
// (`waterfill_epoch_wrap_pending`). #1743 r3: a bare mid-walk `pass1 == 0`
// refills the budget but must NOT clear the bits, else an all-min-quantum
// exact-fit config livelocks Phase 1 on q0 and never reaches Phase 2.
//
// CRITICAL: NEITHER refill path resets `waterfill_phase2_cursor`
// (#1743 r2 — only the genuine Phase-2 wrap at the end-of-function `None`
// path does) so the descending RR walk advances through ALL large classes
// across epochs rather than restarting at the largest (the
// residual-starvation regression #1630 r4 caught).
//
// #4408 Increment 3a: lifted verbatim out of
// `select_exact_cos_guarantee_queue_waterfill` so the selector reads as
// three named phases rather than one 432-line body. This block MUST stay
// atomic: the order of the `waterfill_epochs` bump, the
// `epoch_boundary`-gated honored-bitset clear, and the
// `waterfill_epoch_wrap_pending = false` reset IS the #1743 r3 livelock
// fix. Do not split it further into "compute budget" + "clear bits".
//
// `#[inline(always)]` + same-module is deliberate: the post-inline IR is
// by construction the shape it was before the split, so no coldness claim
// is made or needed (plan §2d).
#[inline(always)]
fn refill_waterfill_epoch(root: &mut CoSInterfaceRuntime, now_ns: u64) {
    let elapsed_since_refresh = now_ns.saturating_sub(root.waterfill_epoch_start_ns);
    let time_refresh = elapsed_since_refresh >= COS_GUARANTEE_VISIT_NS;
    let exhausted = root.waterfill_pass1_remaining_bytes == 0;
    if time_refresh || exhausted {
        // fraction is clamped 0.0..1.0 at config-apply time; the
        // dispatch gate also requires fraction > 0. We use f64 → u64
        // with a floor + saturating cast guarded by the multiplication.
        let frac = root.oversubscription_guarantee_fraction;
        let raw_pass1 = if root.shaping_rate_bytes == 0 {
            // Transparent (unshaped) root: there is no shaper-delivered
            // cap to anchor against, so fall back to the legacy
            // `quantum_sum × fraction` over the current eligible set.
            // The result fits in u64 because quantum_sum ≤ 512 KB ×
            // N_queues and fraction ≤ 1.0.
            let mut quantum_sum: u64 = 0;
            for &qi in &root.exact_queues_by_rate_ascending {
                quantum_sum =
                    quantum_sum.saturating_add(cos_guarantee_quantum_bytes(&root.queues[qi]));
            }
            ((quantum_sum as f64) * frac).floor() as u64
        } else {
            // #1743 Hunk A: anchor pass1 to the shaper-delivered bytes
            // per epoch × fraction — the documented contract "fraction ×
            // cap" where cap = shaper × VISIT_NS (docs/fairness-regimes.md).
            // The legacy `quantum_sum × fraction` over-provisioned pass1
            // by ~4× for any oversubscribed config (Σ R_i > shaper), so
            // Phase 2 never fired and the selector degenerated to
            // ascending RR over all classes. shaping_rate_bytes is
            // bytes/sec; the u128 product is overflow-safe.
            let cap_per_epoch = ((root.shaping_rate_bytes as u128)
                * (COS_GUARANTEE_VISIT_NS as u128)
                / 1_000_000_000u128) as u64;
            ((cap_per_epoch as f64) * frac).floor() as u64
        };
        // AGY RISK-1 (Codex code-r1 #2): a tiny-positive fraction floors
        // `raw_pass1` to 0 on EITHER branch — the dispatch gate admits any
        // `fraction > 0`, including transparent + tiny-fraction. A zero
        // budget makes `exhausted` true on every selector call → refill +
        // cursor-reset thrash → Phase-2 starves from index 0. Clamp BOTH
        // branches to at least one min-quantum so the smallest class is
        // honorable and the exhausted path can't fire every call. (The
        // clamp is a no-op for normal fractions where raw_pass1 already
        // exceeds the smallest quantum.)
        let pass1 = raw_pass1.max(COS_GUARANTEE_QUANTUM_MIN_BYTES);
        root.waterfill_pass1_remaining_bytes = pass1;
        root.waterfill_epoch_start_ns = now_ns;
        // #1743 (Codex code-r3): clear the persistent honored bitset ONLY on
        // a genuine epoch boundary — the time tick OR a Phase-2 WRAP
        // (`waterfill_epoch_wrap_pending`, set by the end-of-function `None`
        // path). A bare `exhausted` (pass1 == 0) that did NOT come from a
        // wrap — e.g. a Phase-1 exact-fit honor that subtracted the last
        // bytes mid-walk — must NOT clear the bits: clearing there re-enabled
        // a degenerate all-min-quantum livelock where q0 is honored, pass1
        // hits 0, the next call clears its bit, q0 is re-honored, and Phase 2
        // is never reached. With the bits intact, the already-honored small
        // queue is skipped, so the walk advances
        // to the next queue or breaks to Phase 2 — guaranteeing forward
        // progress. The budget is still refilled on a bare `exhausted` so
        // Phase 1 can resume against the un-honored queues.
        let epoch_boundary = time_refresh || root.waterfill_epoch_wrap_pending;
        if epoch_boundary {
            root.waterfill_honored_epoch_bits.fill(0);
        }
        root.waterfill_epoch_wrap_pending = false;
        // #1743 (Codex code-r2): the refill never resets the Phase-2 cursor.
        // The cursor's ONLY reset is the genuine Phase-2 WRAP at the
        // end-of-function `None` path (which also re-arms epoch_wrap_pending),
        // so the descending walk advances continuously across epochs — the
        // #1630 r4 continuity invariant.
        //
        // #1628 site 1: completed-epoch / Phase-1-refill counter. Bumped
        // here (no `queue` borrowed yet) on every refill, either trigger.
        root.waterfill_epochs = root.waterfill_epochs.wrapping_add(1);
    }
}

/// hb166 T-2: undo the Phase-1 waterfill honor for a queue that was
/// SELECTED via the Phase-1 honored walk but transmitted zero bytes (TX
/// ring full / no free UMEM frame / frame-build Drop → service returned
/// `progress == false`).
///
/// The waterfill selector commits the honor at SELECTION: it debits
/// `waterfill_pass1_remaining_bytes` by the queue's stable `phase1_cost`
/// and sets the queue's ascending-ordinal bit in
/// `waterfill_honored_epoch_bits`, marking it "already took its guarantee
/// this epoch" so BOTH phases skip it until the epoch refills (~200 us).
/// A zero-byte TX must NOT burn that guarantee — the small class should
/// keep its honor and retry once the interface-wide TX-ring / free-frame
/// pressure clears. This refund restores the debit and clears the bit so
/// the queue is re-selectable this same epoch.
///
/// Correctness: the debit is undone by the exact `cost_bytes` captured at
/// selection, and nothing else mutates `waterfill_pass1_remaining_bytes`
/// between selection and this refund on the single-threaded owner (so the
/// `saturating_add` cannot exceed the pre-selection budget → no honor
/// leak). A queue that DID transmit keeps its honor consumed (this runs
/// only on `progress == false` → no double-consume). Telemetry:
/// `phase1_admissions` was bumped at selection, so decrement it (it must
/// count only progressing services) and record the no-progress in
/// `phase1_selected_no_progress`.
#[inline]
pub(super) fn refund_phase1_waterfill_honor(
    binding: &mut BindingWorker,
    root_ifindex: i32,
    queue_idx: usize,
    refund: Phase1HonorRefund,
) {
    if let Some(root) = binding.cos.cos_interfaces.get_mut(&root_ifindex) {
        apply_phase1_waterfill_honor_refund(root, queue_idx, refund);
    }
}

/// Root-scoped body of the Phase-1 honor refund (see
/// `refund_phase1_waterfill_honor`), split out so it is exercisable
/// without a full `BindingWorker`. Restores the debited budget, clears
/// the honored-epoch bit, and corrects the telemetry.
#[inline]
pub(super) fn apply_phase1_waterfill_honor_refund(
    root: &mut CoSInterfaceRuntime,
    queue_idx: usize,
    refund: Phase1HonorRefund,
) {
    root.waterfill_pass1_remaining_bytes = root
        .waterfill_pass1_remaining_bytes
        .saturating_add(refund.cost_bytes);
    let word = refund.bit_ordinal / u64::BITS as usize;
    let bit = refund.bit_ordinal % u64::BITS as usize;
    root.waterfill_honored_epoch_bits[word] &= !(1u64 << bit);
    if let Some(queue) = root.queues.get_mut(queue_idx) {
        let counters = &mut queue.telemetry.waterfill_counters;
        counters.phase1_admissions = counters.phase1_admissions.saturating_sub(1);
        counters.phase1_selected_no_progress =
            counters.phase1_selected_no_progress.wrapping_add(1);
    }
}
