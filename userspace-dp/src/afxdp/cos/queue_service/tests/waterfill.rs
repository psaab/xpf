//! queue_service waterfill tests (#1614): waterfill selector modes and
//! Phase-1 honored-set admission accounting.

use super::*;

// #1614 A1: waterfill selector tests.

#[test]
fn waterfill_default_proportional_mode_uses_legacy_rr() {
    // Default oversubscription_policy (Proportional) + fraction 0
    // must bypass the new waterfill and use legacy RR cursor. The
    // selector advances `exact_guarantee_rr` per call.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    assert!(matches!(
        root.oversubscription_policy,
        CoSOversubscriptionPolicy::Proportional
    ));
    assert_eq!(root.oversubscription_guarantee_fraction, 0.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 2");
    // Legacy RR walks exact queues 0 → 2 → 0 → 2.
    assert_eq!(s1.queue_idx, 0);
    assert_eq!(s2.queue_idx, 2);
}

#[test]
fn waterfill_guarantee_rate_mode_picks_smallest_rate_first() {
    // GuaranteeRate mode with fraction > 0 routes to the waterfill
    // selector which iterates `exact_queues_by_rate_ascending`.
    // With two exact queues at SAME slow_rate (test_mixed_class
    // fixture), sorted-stable preserves queue_id order so the
    // smaller-queue_idx is selected first.
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 0.7;
    // Build the sorted vector now (in production this happens at
    // config-apply time).
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    // Both exact queues have the same slow_rate; stable-sorted order
    // preserves queue_idx ascending, so queue_idx 0 picks first.
    assert_eq!(s1.queue_idx, 0);
}

#[test]
fn waterfill_guarantee_rate_skips_non_exact_queues() {
    // The waterfill iterates only over exact queues (via
    // exact_queues_by_rate_ascending). Non-exact queues are
    // unaffected.
    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 0.5;
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    // Drain both exact queues entirely.
    for _ in 0..4 {
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    // After draining exacts, non-exact selector still works.
    let batch = select_nonexact_cos_guarantee_batch(&mut root, &[], 1);
    assert!(batch.is_some(), "non-exact RR must remain reachable");
}

#[test]
fn waterfill_guarantee_rate_fraction_consulted_by_selector() {
    // Step-1 coverage: confirm the selector consults the
    // `guarantee_fraction` value rather than using it as a boolean.
    // Direct internal-state check: after one Phase 1 selection at
    // fraction=0.2, `waterfill_pass1_remaining_bytes` is strictly
    // less than the corresponding value at fraction=1.0 (the
    // budget refills to `quantum_sum * fraction`, so 0.2 produces
    // a strictly smaller initial budget and a strictly smaller
    // remaining value after one decrement).
    //
    // Note: this test does NOT pin the VISIBLE per-queue
    // distribution change under oversubscription — that is the
    // step-2 #1625 contract and requires the per-queue
    // per-epoch byte allocation mechanism not implemented in
    // step-1. Codex r1 #1+#2 are deferred to #1625.
    fn pass1_remaining_after_one_selection(frac: f64) -> u64 {
        let mut root = test_mixed_class_root_with_primed_queues();
        root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
        root.oversubscription_guarantee_fraction = frac;
        root.exact_queues_by_rate_ascending = (0..root.queues.len())
            .filter(|&idx| {
                root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled
            })
            .collect();
        // Give every exact queue a large per-queue token budget so
        // the only gate is the Phase 1 byte budget.
        for queue in &mut root.queues {
            if queue.config.exact {
                queue.hot.tokens = 128 * 1024;
            }
        }
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        // One selection in GuaranteeRate mode triggers the
        // Phase-1 budget refill via `pass1_remaining_bytes == 0`
        // gate, then decrements by the chosen queue's
        // secondary_budget. So `pass1_remaining_bytes` after one
        // selection is `(quantum_sum * frac).floor() - first_budget`.
        let _ =
            select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
        root.waterfill_pass1_remaining_bytes
    }
    let r_lo = pass1_remaining_after_one_selection(0.2);
    let r_hi = pass1_remaining_after_one_selection(1.0);
    // Internal-state invariant: fraction=1.0 refills the budget
    // to the full quantum_sum and fraction=0.2 refills to 20%
    // of it. After one identical decrement, the lower fraction
    // MUST leave a strictly smaller remaining budget. This
    // proves the selector consults `oversubscription_guarantee_fraction`
    // as a numeric value, not a boolean.
    assert!(
        r_hi > r_lo,
        "fraction=1.0 pass1_remaining ({r_hi}) must exceed fraction=0.2 ({r_lo})"
    );
    // Also: fraction=0.2 must produce a strictly smaller initial
    // budget than fraction=1.0 by at least 4x (1.0 / 0.2 = 5x).
    // After one decrement, the gap shrinks slightly; assert ≥ 2x
    // remains as a robust invariant.
    assert!(
        r_hi >= r_lo.saturating_mul(2),
        "fraction ratio not reflected in pass1_remaining: lo={r_lo} hi={r_hi}"
    );
}

/// #1732: build a GuaranteeRate root with THREE exact queues at distinct,
/// unequal `transmit_rate_bytes` chosen so each queue's
/// `cos_guarantee_quantum_bytes` is DISTINCT and strictly above the
/// `COS_GUARANTEE_QUANTUM_MIN_BYTES` (1500) floor (so the Phase-1 cost
/// ordering is rate-driven, not all clamped to the min). queue_idx order ==
/// ascending-rate order so a returned `queue_idx` directly names the
/// ascending ordinal. Every queue gets abundant per-queue tokens AND the
/// root gets abundant tokens, so the ONLY gate is the Phase-1 byte budget
/// (`fraction × quantum_sum`) — the selector gates on root tokens (`:856`,
/// `:1034`) and queue tokens (`:879`), all made non-binding here.
///
/// Rates: 100 Mbps / 400 Mbps / 1 Gbps → quantums 2500 / 10000 / 25000 B
/// (rate_bytes × 200_000 ns / 1e9). quantum_sum = 37500.
fn waterfill_three_unequal_exact_root(frac: f64) -> CoSInterfaceRuntime {
    fn exact_queue(queue_id: u8, fc: &str, rate_bytes: u64) -> CoSQueueConfig {
        CoSQueueConfig {
            queue_id,
            forwarding_class: fc.into(),
            priority: 5,
            transmit_rate_bytes: rate_bytes,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        }
    }
    // #1743: the Phase-1 budget is now `shaper × VISIT_NS × fraction`, not
    // `quantum_sum × fraction`. Pin the shaper so cap_per_epoch equals the
    // quantum_sum (37,500 B) — `shaper × 200µs = 37,500` ⇒ shaper =
    // 187,500,000 B/s (1.5 Gbps). That keeps the per-epoch budget identical
    // to the pre-#1743 `quantum_sum`-based value at any fraction, so the
    // budget-break-into-Phase-2 semantics these tests pin are preserved
    // under the corrected formula.
    let mut root = test_cos_runtime_with_queues(
        187_500_000,
        vec![
            exact_queue(0, "exact-100m", 100_000_000 / 8),
            exact_queue(1, "exact-400m", 400_000_000 / 8),
            exact_queue(2, "exact-1g", 1_000_000_000 / 8),
        ],
    );
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = frac;
    // Built at config-apply time in production; rebuild here (stable sort by
    // ascending rate keeps queue_idx order, so ordinal i == queue_idx).
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    root.exact_queues_by_rate_ascending
        .sort_by_key(|&idx| root.queues[idx].config.transmit_rate_bytes);
    // Root tokens abundant so the root-token gate never fires.
    root.tokens = 8 * 1024 * 1024;
    for queue in &mut root.queues {
        // Abundant per-queue tokens (queue-token gate never fires) + frozen
        // refill clock so the selector sees a steady token bucket. Multi-item
        // backlog so no queue drains to empty across the epoch's selections.
        queue.hot.tokens = 1024 * 1024;
        queue.hot.last_refill_ns = 1;
        queue.hot.runnable = true;
        for _ in 0..8 {
            queue.hot.items.push_back(test_cos_item(1500));
        }
        queue.hot.queued_bytes = 8 * 1500;
    }
    root.nonempty_queues = root.queues.len();
    root.runnable_queues = root.queues.len();
    root
}

#[test]
fn waterfill_persistent_honored_set_distributes_phase1_across_queues() {
    // #1732: the persistent honored set makes Phase 1 honor each exact
    // queue AT MOST ONCE per epoch, smallest-rate-first, instead of
    // re-honoring the smallest queue on every selector call (the lowest-rate
    // skew the issue reports). With three exact queues at quantums
    // 2500/10000/25000 and fraction=0.4, the Phase-1 budget is
    // floor(37500 * 0.4) = 15000 bytes:
    //   - selection 1: honor q0 (cost 2500), budget -> 12500
    //   - selection 2: q0 SKIPPED (already honored), honor q1 (cost 10000),
    //     budget -> 2500
    //   - selection 3: q0,q1 SKIPPED; q1->q2 cost 25000 > 2500 -> Phase 1
    //     breaks, Phase 2 serves the largest un-honored queue q2
    // The OLD (broken) selector would re-honor q0 on selections 2 and 3
    // because Phase 1 had no honored-skip, monopolising the budget on the
    // smallest queue.
    let mut root = waterfill_three_unequal_exact_root(0.4);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 2");
    let s3 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 3");

    // Per-epoch service order across >1 selection: ascending, at-most-once.
    assert_eq!(s1.queue_idx, 0, "selection 1 honors the smallest-rate queue");
    assert_eq!(
        s2.queue_idx, 1,
        "selection 2 must advance to the next-smallest queue, NOT re-honor q0 \
         (this is the broken-mask behavior the fix corrects)"
    );
    assert_eq!(
        s3.queue_idx, 2,
        "selection 3 must reach the largest queue (Phase 2 residual after the \
         Phase-1 budget is exhausted), NOT re-serve a honored queue"
    );

    // Each of the two small queues took exactly one Phase-1 admission; the
    // largest queue took a Phase-2 admission (no Phase-1 honor — its cost
    // exceeded the residual budget).
    assert_eq!(
        root.queues[0].telemetry.waterfill_counters.phase1_admissions, 1,
        "q0 honored once in Phase 1"
    );
    assert_eq!(
        root.queues[1].telemetry.waterfill_counters.phase1_admissions, 1,
        "q1 honored once in Phase 1"
    );
    assert_eq!(
        root.queues[2].telemetry.waterfill_counters.phase1_admissions, 0,
        "q2 not honored in Phase 1 (budget exhausted before it)"
    );
    assert_eq!(
        root.queues[2].telemetry.waterfill_counters.phase2_admissions, 1,
        "q2 served as Phase-2 residual"
    );

    // The persistent bitset carries q0 and q1's ORDINAL bits across calls
    // within the epoch (ordinal == queue_idx here). q2 (ordinal 2) is never
    // honored in Phase 1, so its bit stays clear.
    assert_eq!(
        root.waterfill_honored_epoch_bits[0] & 0b011,
        0b011,
        "BOTH ordinals 0 and 1 must be marked honored within the epoch \
         (each small queue took exactly one Phase-1 honor)"
    );
    assert_eq!(
        root.waterfill_honored_epoch_bits[0] & 0b100,
        0,
        "ordinal 2 (the Phase-2-served queue) must NOT be marked Phase-1-honored"
    );
}

#[test]
fn waterfill_honored_set_clears_on_epoch_refill() {
    // #1732: the honored bitset must clear at the lazy Phase-1 refill so a
    // new epoch starts with a fresh honored set (otherwise the smallest
    // queue would be permanently skipped after its first honor). Drive the
    // selector until the epoch exhausts, force a refill by zeroing the
    // Phase-1 budget, and confirm the bitset is cleared and the smallest
    // queue is honored FIRST again in the next epoch.
    let mut root = waterfill_three_unequal_exact_root(0.4);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    // Epoch 1: drive three selections (q0, q1, then Phase-2 q2).
    for _ in 0..3 {
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    assert!(
        !root.waterfill_honored_epoch_bits.is_empty(),
        "honored bits accumulate within an epoch"
    );

    // Force a GENUINE epoch boundary: zero the Phase-1 budget AND arm
    // `waterfill_epoch_wrap_pending`, exactly as the end-of-function Phase-2
    // WRAP (`None`) path does. #1743 r3: a bare `pass1 == 0` alone refills the
    // budget but does NOT clear the honored bits (that avoids the exact-fit
    // livelock); only the time tick or a genuine wrap clears them — which is
    // what this #1732 test means by "epoch boundary".
    root.waterfill_pass1_remaining_bytes = 0;
    root.waterfill_epoch_wrap_pending = true;
    let epochs_before = root.waterfill_epochs;

    let s_next = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection of the new epoch");

    assert_eq!(
        root.waterfill_epochs,
        epochs_before + 1,
        "refill must bump the epoch counter"
    );
    assert_eq!(
        s_next.queue_idx, 0,
        "after the refill clears the honored set, the smallest queue is \
         honored first again (not permanently skipped)"
    );
    // Only q0's ordinal bit is set in the fresh epoch.
    assert_eq!(
        root.waterfill_honored_epoch_bits[0], 0b001,
        "fresh epoch: only the just-honored smallest queue (ordinal 0) is marked"
    );
}

// #1628: per-class waterfill trace-counter tests. These pin that the
// counters increment at the right SITES (not that any one counter is a
// unique fingerprint — that interpretation requires pairing with
// queued_bytes + *_starvation_parks per the struct docs).

#[test]
fn waterfill_counters_phase1_honor_increments_admission_and_visit() {
    // fraction=1.0: the full quantum_sum budget easily honors the first
    // (smallest) exact queue in Phase 1.
    let mut root = waterfill_guarantee_rate_root(1.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("phase-1 selection");
    let q = &root.queues[s.queue_idx];
    assert_eq!(
        q.telemetry.waterfill_counters.phase1_admissions, 1,
        "Phase-1 honor must bump phase1_admissions on the chosen queue"
    );
    assert_eq!(
        q.telemetry.waterfill_counters.phase2_admissions, 0,
        "a Phase-1 honor must NOT bump phase2_admissions"
    );
    assert!(
        q.telemetry.waterfill_counters.eligible_visits >= 1,
        "the honored queue must have been counted as an eligible visit"
    );
    // The epoch refill ran exactly once on this first call.
    assert_eq!(
        root.waterfill_epochs, 1,
        "first selection lazily refills the Phase-1 budget = one epoch"
    );
    // Budget was sufficient: no Phase-1 break.
    assert_eq!(
        root.waterfill_phase1_budget_breaks, 0,
        "fraction=1.0 must not exhaust the Phase-1 budget on the first queue"
    );
}

#[test]
fn waterfill_counters_proportional_mode_stays_zero() {
    // Counter-factual: on the Proportional (legacy RR) path, NONE of the
    // waterfill counters may move. A wrong write site (outside the
    // waterfill fn) would light these up here.
    let mut root = test_mixed_class_root_with_primed_queues();
    for queue in &mut root.queues {
        if queue.config.exact {
            queue.hot.tokens = 128 * 1024;
        }
    }
    assert!(matches!(
        root.oversubscription_policy,
        CoSOversubscriptionPolicy::Proportional
    ));
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("legacy RR selection");
    assert_eq!(root.waterfill_epochs, 0);
    assert_eq!(root.waterfill_phase1_budget_breaks, 0);
    for q in &root.queues {
        assert_eq!(q.telemetry.waterfill_counters.phase1_admissions, 0);
        assert_eq!(q.telemetry.waterfill_counters.phase2_admissions, 0);
        assert_eq!(q.telemetry.waterfill_counters.eligible_visits, 0);
    }
}

#[test]
fn waterfill_counters_budget_break_into_phase2() {
    // A tiny fraction makes the Phase-1 budget too small to honor even
    // the first ascending queue's rate-scaled cost, forcing the break
    // into Phase 2 — which then admits a queue. Assert the per-interface
    // budget-break counter fires AND a Phase-2 admission is recorded.
    //
    // fraction is clamped 0.0..=1.0 at config-apply; here we set it
    // directly. With frac so small that floor(quantum_sum * frac) <
    // any single queue's quantum, the first ascending queue's
    // phase1_cost exceeds the remaining budget at mod.rs:906.
    let mut root = waterfill_guarantee_rate_root(0.0001);
    // #1743: use a TRANSPARENT root (shaping_rate_bytes == 0) so the
    // Phase-1 budget takes the legacy `quantum_sum × fraction` path. After
    // bumping the exact queues to 3 Gbps (quantum 75,000 B), raw pass1 =
    // floor(quantum_sum × 0.0001) is a few bytes, which the symmetric
    // anti-thrash clamp (Codex r1 #2) raises to one min-quantum (1500 B).
    // To force the Phase-1 break we need every exact queue's quantum to
    // EXCEED that clamped 1500 B floor — 75,000 B ≫ 1500 — so the clamped
    // budget is below every quantum and Phase 1 breaks immediately into
    // Phase 2. (The clamp itself is verified separately in
    // waterfill_pass1_tiny_fraction_clamped_to_min_quantum.)
    root.shaping_rate_bytes = 0;
    for q in &mut root.queues {
        if q.config.exact {
            q.config.transmit_rate_bytes = 3_000_000_000 / 8;
        }
    }
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("phase-2 selection after budget break");
    assert_eq!(
        root.waterfill_phase1_budget_breaks, 1,
        "an exhausted Phase-1 budget must bump the per-interface break counter"
    );
    let q = &root.queues[s.queue_idx];
    assert_eq!(
        q.telemetry.waterfill_counters.phase2_admissions, 1,
        "the Phase-2 walk must bump phase2_admissions on the chosen queue"
    );
    assert_eq!(
        q.telemetry.waterfill_counters.phase1_admissions, 0,
        "a Phase-2 admission must NOT bump phase1_admissions"
    );
    // Epoch refilled once (budget was 0 on entry).
    assert_eq!(root.waterfill_epochs, 1);
}

#[test]
fn waterfill_counters_phase1_admit_flake_5x() {
    // Stability pin: the Phase-1 honor counters are deterministic across
    // repeated fresh roots (the selector has no RNG on this path).
    for _ in 0..5 {
        let mut root = waterfill_guarantee_rate_root(1.0);
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
            .expect("phase-1 selection");
        assert_eq!(
            root.queues[s.queue_idx]
                .telemetry
                .waterfill_counters
                .phase1_admissions,
            1
        );
        assert_eq!(root.waterfill_epochs, 1);
    }
}

// ---------------------------------------------------------------------------
// #1743: shaper-anchored Phase-1 budget + stable honor charge + time refresh.
// ---------------------------------------------------------------------------

#[test]
fn waterfill_pass1_anchored_to_shaper_per_epoch() {
    // #1743 Hunk A: for a SHAPED root the Phase-1 budget must be
    // `shaper × VISIT_NS × fraction`, NOT `quantum_sum × fraction`. The
    // smoke fixture is oversubscribed (Σ R_i ≫ shaper), so the old formula
    // over-budgeted pass1 by ~4× and Phase-2 never fired. Pin the corrected
    // budget directly: a 25 Gbps shaper at fraction 0.7 yields
    // floor(25e9/8 × 200µs × 0.7) = floor(625_000 × 0.7) = 437_500 B,
    // regardless of how large the sum of configured class rates is.
    let mut root = waterfill_three_unequal_exact_root(0.7);
    root.shaping_rate_bytes = 25_000_000_000 / 8;
    // First selector call takes the exhausted refill path (pass1 seeded 0)
    // and computes the shaper-anchored budget. Inspect it before any honor
    // debit by checking the value the refill installs: drive one call then
    // add back the single honor charge it consumed.
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection");
    let charged = cos_guarantee_quantum_bytes(&root.queues[s.queue_idx])
        .max(1500 /* head_len of the primed 1500-byte item */);
    let installed_budget = root.waterfill_pass1_remaining_bytes + charged;
    assert_eq!(
        installed_budget, 437_500,
        "Phase-1 budget must be shaper × VISIT_NS × fraction (437,500 B at \
         25 Gbps / 0.7), not the oversubscribed quantum_sum × fraction"
    );
}

#[test]
fn waterfill_pass1_transparent_root_fallback_to_quantum_sum() {
    // #1743 Hunk A: a TRANSPARENT root (shaping_rate_bytes == 0) has no
    // shaper-delivered cap to anchor against, so it must fall back to the
    // legacy quantum_sum × fraction. Quanta 2500/10000/25000, sum 37,500;
    // fraction 0.4 ⇒ budget floor(37_500 × 0.4) = 15_000 B.
    let mut root = waterfill_three_unequal_exact_root(0.4);
    root.shaping_rate_bytes = 0;
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection");
    let charged = cos_guarantee_quantum_bytes(&root.queues[s.queue_idx]).max(1500);
    let installed_budget = root.waterfill_pass1_remaining_bytes + charged;
    assert_eq!(
        installed_budget, 15_000,
        "transparent-root budget must use quantum_sum × fraction (15,000 B)"
    );
}

#[test]
fn waterfill_phase1_honor_charge_is_configured_quantum_not_tokens() {
    // #1743 Hunk B: the Phase-1 honor charge must be the STABLE configured
    // quantum, NOT `queue.hot.tokens.min(quantum)`. Under v8-lease pressure
    // tokens collapse toward one frame; the old charge then fell to head_len,
    // the queue was marked fully honored for ~one frame, and Phase-2 skipped
    // it. With the fixed charge a token-pressured small queue still consumes
    // its full quantum against pass1 (or is left for Phase-2 if it does not
    // fit), so the budget is spent honestly.
    //
    // Shaper anchored so the budget equals quantum_sum (37,500 B) at frac 1.0
    // (see waterfill_three_unequal_exact_root). Pin q1's tokens to exactly
    // one frame; its configured quantum is 10,000 B (400 Mbps × 200µs).
    let mut root = waterfill_three_unequal_exact_root(1.0);
    // q0 quantum 2,500; q1 quantum 10,000; q2 quantum 25,000; sum 37,500.
    // Starve q1's token bank to one frame to exercise the old undercharge.
    root.queues[1].hot.tokens = 1500;
    let q1_quantum = cos_guarantee_quantum_bytes(&root.queues[1]);
    assert!(
        q1_quantum > root.queues[1].hot.tokens,
        "precondition: configured quantum exceeds the depleted token bank"
    );
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // Selection 1 honors q0 (smallest). Selection 2 reaches q1.
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 1");
    let budget_before_q1 = root.waterfill_pass1_remaining_bytes;
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("selection 2");
    assert_eq!(s2.queue_idx, 1, "selection 2 honors q1");
    let charged = budget_before_q1 - root.waterfill_pass1_remaining_bytes;
    assert_eq!(
        charged, q1_quantum,
        "Phase-1 must charge q1's FULL configured quantum ({q1_quantum} B), \
         not its depleted token bank (1500 B) — the #1743 undercharge"
    );
}

#[test]
fn waterfill_pass1_refreshes_on_time_tick_clears_honored_bits() {
    // #1743 Hunk C: under saturation Phase-2 does not decrement pass1, so the
    // budget never hits 0 and the legacy exhausted-refill never fires. The
    // time-based path must refresh pass1 AND clear the persistent honored
    // bitset once `now_ns - epoch_start >= COS_GUARANTEE_VISIT_NS`, while
    // PRESERVING the Phase-2 cursor.
    //
    // Codex code-r1: use the DEFAULT 187,500,000 B/s shaper (cap_per_epoch
    // == quantum_sum == 37,500 B) so at fraction 0.7 the budget is 26,250 B
    // — enough to honor q0 (2,500) + q1 (10,000) in Phase 1 but NOT q2
    // (25,000) — which forces a Phase-2 admit and advances the cursor to a
    // NONZERO value. A 25 Gbps override here would budget 437,500 B, honor
    // all three queues in Phase 1, never advance Phase 2, and leave the
    // cursor at 0 — making the preservation assertion vacuous.
    let mut root = waterfill_three_unequal_exact_root(0.7);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // Epoch 1 at t = 1ns: honor q0+q1 (sets honored bits) and serve q2 in
    // Phase 2 (advances the cursor to nonzero).
    for _ in 0..3 {
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    assert!(
        !root.waterfill_honored_epoch_bits.is_empty(),
        "honored bits accumulate within epoch 1"
    );
    let cursor_after_epoch1 = root.waterfill_phase2_cursor;
    assert_ne!(
        cursor_after_epoch1, 0,
        "epoch 1 must have advanced the Phase-2 cursor (a Phase-2 admit \
         occurred) so the preservation assertion below is non-vacuous"
    );
    let pass1_mid_epoch = root.waterfill_pass1_remaining_bytes;
    assert_ne!(pass1_mid_epoch, 0, "pass1 is non-zero mid-epoch (not exhausted)");
    let epochs_before = root.waterfill_epochs;

    // Advance the clock past one VISIT_NS without ever zeroing pass1. The
    // time-based refresh must fire on the next call.
    let next_ns = 1 + COS_GUARANTEE_VISIT_NS + 1;
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], next_ns, &mut tel)
        .expect("selection after time refresh");

    assert_eq!(
        root.waterfill_epochs,
        epochs_before + 1,
        "the time-based refresh must bump the epoch counter"
    );
    assert_eq!(
        root.waterfill_epoch_start_ns, next_ns,
        "the refresh must re-seed epoch_start_ns to now_ns"
    );
    // The honored bitset was cleared at the refresh, then the smallest queue
    // was re-honored on this same call — so only ordinal 0's bit is set now.
    assert_eq!(
        root.waterfill_honored_epoch_bits[0], 0b001,
        "timed refresh must clear honored bits, then Phase-1 re-honors q0"
    );
    assert_eq!(
        root.waterfill_phase2_cursor, cursor_after_epoch1,
        "the time-based refresh must PRESERVE the Phase-2 cursor (#1743 r2: \
         neither refill path resets it — only a genuine Phase-2 wrap does)"
    );
}

#[test]
fn waterfill_pass1_undersubscribed_shaper_honors_all_classes() {
    // Codex r1 #6: when the shaper is UNDERSUBSCRIBED (shaper > Σ R_i) the
    // cap-anchored budget is ≥ quantum_sum, so Phase-1 can honor every class
    // without spuriously pushing any to Phase-2. Shaper 10 Gbps, quanta
    // 2500/10000/25000 (sum 37,500), fraction 1.0 ⇒ cap_per_epoch =
    // floor(10e9/8 × 200µs) = 250,000 B ⇒ budget 250,000 ≫ 37,500.
    let mut root = waterfill_three_unequal_exact_root(1.0);
    root.shaping_rate_bytes = 10_000_000_000 / 8;
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("s1");
    let s2 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("s2");
    let s3 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("s3");
    assert_eq!((s1.queue_idx, s2.queue_idx, s3.queue_idx), (0, 1, 2));
    for qi in 0..3 {
        assert_eq!(
            root.queues[qi].telemetry.waterfill_counters.phase1_admissions, 1,
            "queue {qi} must be honored in Phase 1 under an undersubscribed shaper"
        );
        assert_eq!(
            root.queues[qi].telemetry.waterfill_counters.phase2_admissions, 0,
            "no class should fall to Phase 2 when shaper > Σ R_i"
        );
    }
}

#[test]
fn waterfill_pass1_tiny_fraction_clamped_to_min_quantum() {
    // AGY RISK-1: a tiny-positive fraction floors the shaped budget to 0,
    // which would make `exhausted` true every call → refill + cursor-reset
    // thrash. The shaped path clamps pass1 to ≥ COS_GUARANTEE_QUANTUM_MIN_BYTES
    // so at least the smallest class is honorable and the exhausted path does
    // not fire on every selector call.
    let mut root = waterfill_three_unequal_exact_root(0.0000001);
    root.shaping_rate_bytes = 25_000_000_000 / 8;
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // The tiny fraction floors raw to 0; the clamp installs pass1 =
    // COS_GUARANTEE_QUANTUM_MIN_BYTES (1500). 1500 is below the smallest
    // class quantum (2500), so Phase-1 breaks immediately into Phase-2 —
    // which still admits the largest un-honored queue. The point: pass1 is
    // NOT 0, so the exhausted path does not fire on every call.
    let s = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("first selection still admits via Phase-2");
    // Phase-1 broke before honoring anyone and Phase-2 does not debit pass1,
    // so the installed clamped budget is observable directly.
    assert_eq!(
        root.waterfill_pass1_remaining_bytes, COS_GUARANTEE_QUANTUM_MIN_BYTES,
        "a tiny fraction must clamp the Phase-1 budget to one min-quantum, \
         not floor it to 0"
    );
    assert_eq!(
        root.queues[s.queue_idx].telemetry.waterfill_counters.phase2_admissions, 1,
        "the budget-broke selection is served by Phase-2"
    );
    assert_eq!(
        root.waterfill_phase1_budget_breaks, 1,
        "Phase-1 broke because the clamped budget (1500) is below the \
         smallest quantum (2500)"
    );
}

#[test]
fn waterfill_exhausted_refill_does_not_reset_phase2_cursor() {
    // #1743 (Codex code-r2): the exhausted (`pass1 == 0`) refill path must
    // NOT reset the Phase-2 cursor. A degenerate config can land pass1 at
    // exactly 0 after a Phase-1 honor (phase1_cost == the remaining budget),
    // returning before Phase 2 — so an exhausted-refill cursor reset on the
    // next call would restart the descending walk from the largest class and
    // starve it. Only a genuine Phase-2 wrap (the end-of-function `None`
    // path) may reset the cursor. Pin that an exhausted refill preserves a
    // nonzero cursor.
    let mut root = waterfill_three_unequal_exact_root(0.7);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    // Drive epoch 1 to advance the Phase-2 cursor to a nonzero value (q0+q1
    // honored Phase-1, q2 served Phase-2 — see the time-tick test).
    for _ in 0..3 {
        let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    }
    let cursor = root.waterfill_phase2_cursor;
    assert_ne!(cursor, 0, "precondition: Phase-2 cursor advanced in epoch 1");
    // Force the exhausted refill path WITHOUT advancing the clock (so it is
    // the exhausted trigger, not the time-based one) by zeroing pass1.
    root.waterfill_pass1_remaining_bytes = 0;
    let _ = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel);
    assert_eq!(
        root.waterfill_phase2_cursor, cursor,
        "the exhausted refill path must PRESERVE the Phase-2 cursor; only a \
         genuine Phase-2 wrap (`None` path) may reset it"
    );
}

#[test]
fn waterfill_exact_fit_honor_does_not_livelock_phase1() {
    // #1743 (Codex code-r3): the deeper degenerate-config defect. When a
    // Phase-1 exact-fit honor subtracts the budget to exactly 0, the next
    // call's bare `exhausted` refill must NOT clear the honored bitset — only
    // a genuine epoch boundary (time tick OR Phase-2 wrap) clears it.
    // Clearing on a bare mid-walk `pass1 == 0` re-enabled a livelock: q0
    // honored → pass1=0 → next call clears q0's bit → q0 re-honored → … with
    // Phase 2 NEVER reached, starving every larger class.
    //
    // Fixture: shaper 187,500,000 B/s (cap_per_epoch == quantum_sum ==
    // 37,500 B); fraction tuned so the Phase-1 budget == q0's quantum exactly
    // (2,500 B). q0 (100m, quantum 2,500) is an exact-fit honor; q1 (400m,
    // 10,000) and q2 (1g, 25,000) must still get Phase-2 service.
    let mut root = waterfill_three_unequal_exact_root(2_500.0 / 37_500.0);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    // Call 1: Phase-1 honors q0 (cost 2,500), pass1 → 0.
    let s1 = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("call 1");
    assert_eq!(s1.queue_idx, 0, "call 1 honors q0 (smallest, exact-fit)");
    assert_eq!(
        root.waterfill_pass1_remaining_bytes, 0,
        "the exact-fit honor drained pass1 to exactly 0"
    );

    // Drive several more calls at the SAME now_ns (no time tick) and confirm
    // a non-q0 queue is serviced — i.e. Phase 2 IS reached, no livelock. With
    // the pre-r3 bug (clearing bits on bare exhausted) q0 would be re-honored
    // on every call and q1/q2 would never run.
    let mut serviced_non_q0 = false;
    let mut q0_admits = 0u64;
    for _ in 0..8 {
        if let Some(s) =
            select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        {
            if s.queue_idx == 0 {
                q0_admits += 1;
            } else {
                serviced_non_q0 = true;
            }
        }
    }
    assert!(
        serviced_non_q0,
        "Phase 2 must service a larger class within a few calls — q0's \
         exact-fit honor must not livelock Phase 1 (the #1743 r3 defect)"
    );
    // q0 is honored at most once per genuine epoch boundary, not on every
    // bare-exhausted refill. Over 8 same-tick calls it cannot dominate.
    assert!(
        q0_admits <= 2,
        "q0 must not be re-honored on every bare-exhausted refill (got \
         {q0_admits} Phase-1 admits in 8 same-tick calls)"
    );
}


/// Drives Phase 2 to a state the pre-#4408 suite never reached: a
/// descending walk whose FIRST candidate is a queue Phase 1 already
/// honored this epoch.
///
/// Every prior waterfill fixture enters Phase 2 with the largest class
/// un-honored (Phase 1 walks ascending and runs out of budget before it),
/// so the cursor starts at 0, lands on the largest, and selects it —
/// Phase 2's honored-skip and its cursor arithmetic are never exercised.
/// The #4408 mutation grid caught that: removing Phase 2's honored check
/// and forcing its cursor to 0 both left the whole suite GREEN.
///
/// The trick is to honor the LARGEST class first by making the two small
/// ones momentarily empty, then refill them:
///   - fraction 0.7 over quantum_sum 37500 -> Phase-1 budget 26250
///   - q0/q1 empty, so Phase 1 skips both and honors q2 (cost 25000),
///     leaving 1250 and ordinal bit 2 set
///   - refill q0/q1; the next call cannot honor q0 (2500 > 1250), so
///     Phase 1 breaks and Phase 2 runs with the largest class HONORED
///
/// Same tick throughout (`now_ns = 1`), so no time refresh clears the
/// bitset and no bare-exhausted refill fires (1250 != 0).
fn waterfill_phase2_root_with_largest_honored() -> (CoSInterfaceRuntime, CoSQueueLeaseAcquireTelemetry)
{
    let mut root = waterfill_three_unequal_exact_root(0.7);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();

    for idx in [0usize, 1usize] {
        root.queues[idx].hot.items.clear();
        root.queues[idx].hot.queued_bytes = 0;
    }

    let first = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("Phase 1 honors the only backlogged class");
    assert_eq!(
        first.queue_idx, 2,
        "precondition: with q0/q1 empty, Phase 1 must honor the LARGEST class"
    );
    assert_eq!(
        root.waterfill_honored_epoch_bits[0] & 0b100,
        0b100,
        "precondition: ordinal 2 is marked Phase-1-honored"
    );
    assert_eq!(
        root.waterfill_pass1_remaining_bytes, 1250,
        "precondition: 26250 - 25000 leaves less than q0's 2500 quantum, so \
         the next call breaks Phase 1 into Phase 2"
    );

    for idx in [0usize, 1usize] {
        for _ in 0..8 {
            root.queues[idx].hot.items.push_back(test_cos_item(1500));
        }
        root.queues[idx].hot.queued_bytes = 8 * 1500;
    }
    (root, tel)
}

#[test]
fn waterfill_phase2_skips_a_queue_honored_in_phase1() {
    // #1732 via #4408: Phase 2 reads the SAME persistent honored bitset
    // Phase 1 sets, so a class that already took its Phase-1 guarantee this
    // epoch must NOT also collect the descending residual. The walk starts
    // at the largest (cursor 0 -> pos_from_end 2 -> q2), which IS honored,
    // so the correct selection is the next un-honored class down, q1.
    let (mut root, mut tel) = waterfill_phase2_root_with_largest_honored();

    let second = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("Phase 2 residual selection");

    assert_eq!(
        second.queue_idx, 1,
        "Phase 2 must SKIP the Phase-1-honored largest class and serve the \
         next un-honored class down; selecting q2 again would hand it both \
         its guarantee and the residual in one epoch"
    );
    assert_eq!(
        root.queues[2].telemetry.waterfill_counters.phase2_admissions, 0,
        "the honored class must take NO Phase-2 admission this epoch"
    );
    assert_eq!(
        root.queues[1].telemetry.waterfill_counters.phase2_admissions, 1,
        "the residual goes to the largest UN-honored class"
    );
}

#[test]
fn waterfill_phase2_cursor_resumes_instead_of_restarting_at_the_largest() {
    // #1630 r4 via #4408: `waterfill_phase2_cursor` is seeded from `root`
    // and written back on selection precisely so the descending walk
    // advances through ALL large classes across calls instead of
    // restarting at the largest every time. Re-entering Phase 2 must
    // resume where it stopped.
    //
    // This is a DISTINCT assertion from the refill-side cursor test
    // (`waterfill_exhausted_refill_does_not_reset_phase2_cursor`), which
    // pins that the refill leaves the cursor alone; this one pins that
    // Phase 2 itself consumes the cursor rather than ignoring it.
    let (mut root, mut tel) = waterfill_phase2_root_with_largest_honored();

    let second = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("Phase 2 residual selection 1");
    assert_eq!(second.queue_idx, 1, "precondition: first residual is q1");
    assert_eq!(
        root.waterfill_phase2_cursor, 2,
        "precondition: the cursor advanced past the honored q2 and the \
         selected q1"
    );

    let third = select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], 1, &mut tel)
        .expect("Phase 2 residual selection 2");

    assert_eq!(
        third.queue_idx, 0,
        "Phase 2 must RESUME the descending walk from the stored cursor and \
         reach the smallest un-honored class; restarting at the largest \
         would re-serve q1 forever and starve q0 (the #1630 r4 residual \
         starvation)"
    );
    assert_eq!(
        root.queues[1].telemetry.waterfill_counters.phase2_admissions, 1,
        "q1 took exactly one residual — the walk moved on rather than \
         re-serving it"
    );
}

/// #6958: the Phase-2 WRAP tail arms the epoch boundary, and the next call
/// resumes selection.
///
/// The tail — three writes and a `None` at the end of
/// `select_exact_cos_guarantee_queue_waterfill` — had ZERO binding coverage.
/// Deleting all three left the whole bin suite green, and a `panic!` probe in
/// its place fails exactly one test
/// (`waterfill_guarantee_rate_skips_non_exact_queues`), which reaches the tail
/// incidentally while asserting nothing about its effects. Reached once,
/// checked never. Re-derived at master before writing this.
///
/// What the writes are FOR: `epoch_boundary = time_refresh ||
/// waterfill_epoch_wrap_pending` in `refill_waterfill_epoch` is what clears
/// `waterfill_honored_epoch_bits`. Lose the tail and `pass1_remaining` stays
/// non-zero (so the `exhausted` trigger never fires), `epoch_wrap_pending`
/// stays false, the honored bitset is never cleared, and every class honored
/// in Phase 1 is skipped by BOTH phases — a `guarantee-rate` interface with
/// fully backlogged queues goes idle for up to a whole epoch, silently, with
/// no counter recording it.
///
/// TIME IS FROZEN, and that is the load-bearing fixture decision. `now_ns` is
/// passed as a constant so `elapsed_since_refresh` stays 0 and `time_refresh`
/// can never fire. `epoch_boundary` has TWO sources, and the wrap is only one
/// of them.
///
/// Measured, not reasoned. With the tail deleted and the resumption assertion
/// isolated:
///
///   frozen  `now_ns`                -> FAILS  (the assertion has teeth)
///   thawed  `now_ns + 10_000_000`   -> PASSES (the time tick clears the
///                                              honored bits by itself)
///
/// So a version of this cell written with a running clock would have been
/// toothless in exactly the way it looks rigorous: it would exercise the wrap,
/// reach the resumption, and pass on the fallback path with the code under
/// test deleted.
#[test]
fn waterfill_phase2_wrap_arms_epoch_boundary_and_resumes_6958() {
    // Frozen: every call uses this same instant.
    const NOW_NS: u64 = 1;
    const TOKENS: u64 = 128 * 1024;

    let mut root = test_mixed_class_root_with_primed_queues();
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 0.5;
    root.exact_queues_by_rate_ascending = (0..root.queues.len())
        .filter(|&idx| root.queues[idx].config.exact && root.queues[idx].config.guarantee_enabled)
        .collect();
    let prime = |root: &mut CoSInterfaceRuntime| {
        for queue in &mut root.queues {
            if queue.config.exact {
                queue.hot.tokens = TOKENS;
            }
        }
    };
    prime(&mut root);

    // Seed the Phase-2 cursor NON-ZERO, and that is not decoration.
    //
    // The cursor legitimately persists across epochs — the wrap tail is its
    // only reset, so the descending walk advances continuously (#1743 r2), and
    // a non-zero cursor is ordinary steady state. Starting it at 0 makes the
    // `phase2_cursor == 0` assertion below VACUOUS: a full descending cycle
    // returns the cursor to where it began, so 0 holds whether or not the tail
    // writes it. Measured — with the cursor seeded at 0 this cell PASSED with
    // `root.waterfill_phase2_cursor = 0` deleted from the tail, and the
    // mutation matrix is what exposed it. Seeded at 1, the walk arrives at the
    // tail still holding 1, so only the write can produce 0.
    root.waterfill_phase2_cursor = 1;

    // Drive until the selector actually WRAPS. The wrap is asserted as a
    // measured precondition rather than assumed from a loop count: a fixture
    // that stops one call short of the tail exercises none of this and would
    // pass with the tail deleted.
    let mut wrapped = false;
    for _ in 0..64 {
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        if select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], NOW_NS, &mut tel)
            .is_none()
        {
            wrapped = true;
            break;
        }
    }
    assert!(
        wrapped,
        "fixture never reached the Phase-2 wrap tail, so nothing below is being \
         measured (#6958)"
    );

    // The three writes, individually, so a partial loss localizes.
    assert_eq!(
        root.waterfill_pass1_remaining_bytes, 0,
        "the wrap must zero pass1_remaining; left non-zero, refill_waterfill_epoch's \
         `exhausted` trigger never fires and the epoch never refills (#6958)"
    );
    assert_eq!(
        root.waterfill_phase2_cursor, 0,
        "the wrap must reset the Phase-2 cursor — it is the ONLY site that does, \
         and neither refill path touches it (#1743 r2)"
    );
    assert!(
        root.waterfill_epoch_wrap_pending,
        "the wrap must arm epoch_wrap_pending; it is what makes the next refill a \
         genuine epoch boundary and clears the honored bitset (#6958)"
    );

    // The CONSEQUENCE, which is why those three writes exist. Asserting the
    // fields alone pins plumbing; this pins the behaviour they buy.
    //
    // Re-prime tokens first: after the drain the queues are empty, and a `None`
    // from an out-of-tokens queue would look identical to a `None` from an
    // unarmed epoch boundary. Without this the assertion could fail for a
    // reason that has nothing to do with the tail.
    prime(&mut root);
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    let resumed =
        select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], NOW_NS, &mut tel);
    assert!(
        resumed.is_some(),
        "the selector stayed idle after the wrap. With the clock frozen, the ONLY \
         thing that can clear waterfill_honored_epoch_bits is the epoch boundary the \
         wrap tail arms — so every class honored in Phase 1 is now skipped by both \
         phases and a fully backlogged guarantee-rate interface transmits nothing \
         until the 200us tick (#6958)"
    );
    assert!(
        !root.waterfill_epoch_wrap_pending,
        "the refill must consume epoch_wrap_pending; leaving it armed would clear the \
         honored bitset on every subsequent refill, not just at a genuine boundary"
    );
}

/// #11680: >64 exact guarantee queues — every ordinal honored at most once
/// per waterfill epoch.
///
/// The honored set was a `u64` keyed by ascending-vec ordinal with an
/// `i < 64` shift guard, so ordinals ≥64 were never marked honored: Phase 1
/// re-honored them on every selector call while ordinals <64 were honored
/// once per epoch, skewing the guarantee distribution toward the small exact
/// classes past ordinal 64.
///
/// Fixture: 65 exact queues at one below-min rate (every quantum clamps to
/// the 1500-byte min) on a TRANSPARENT root (`shaping_rate_bytes == 0`), so
/// the Phase-1 budget is exactly `quantum_sum × fraction = 65 × 1500 × 1.0`
/// and one epoch honors every class exactly once with no Phase-2 break.
/// Equal rates keep the builder's stable sort in queue_idx order, so
/// ascending ordinal == queue_idx. The clock is FROZEN (`now_ns` constant)
/// so the 200µs time tick can never clear the honored set mid-epoch — the
/// only thing that may re-arm an ordinal is a genuine Phase-2 wrap.
///
/// What is pinned is OBSERVABLE, not plumbing: the first 65 selections cover
/// all 65 queues exactly once (all Phase-1 admissions), and the 66th call —
/// still the same epoch — wraps (`None`) instead of re-honoring ordinal 64.
/// Pre-fix the 66th call returns `Some(ordinal 64)` and its
/// `phase1_admissions` climbs to 2.
#[test]
fn waterfill_sixty_five_exact_queues_honor_each_ordinal_once_per_epoch() {
    const NOW_NS: u64 = 1;
    const N: usize = 65;
    let slow_rate = 1_000_000 / 8; // 1 Mbps → quantum clamps to the 1500 floor
    let queues: Vec<CoSQueueConfig> = (0..N as u8)
        .map(|queue_id| CoSQueueConfig {
            queue_id,
            forwarding_class: format!("fc-{queue_id}").into(),
            priority: 5,
            transmit_rate_bytes: slow_rate,
            guarantee_enabled: true,
            exact: true,
            surplus_sharing: false,
            equal_flow_enforcement: false,
            equal_flow_target_policy: EqualFlowTargetPolicy::Slowest,
            surplus_weight: 1,
            buffer_bytes: COS_MIN_BURST_BYTES,
            dscp_rewrite: None,
            codel_target_ns: 0,
        })
        .collect();
    let mut root = test_cos_runtime_with_queues(0, queues);
    root.oversubscription_policy = CoSOversubscriptionPolicy::GuaranteeRate;
    root.oversubscription_guarantee_fraction = 1.0;
    assert_eq!(
        root.exact_queues_by_rate_ascending.len(),
        N,
        "all 65 exact queues must land in the ascending vec"
    );
    root.tokens = 8 * 1024 * 1024;
    for queue in &mut root.queues {
        queue.hot.tokens = 1024 * 1024;
        queue.hot.last_refill_ns = NOW_NS;
        queue.hot.runnable = true;
        for _ in 0..2 {
            queue.hot.items.push_back(test_cos_item(1500));
        }
        queue.hot.queued_bytes = 2 * 1500;
    }
    root.nonempty_queues = N;
    root.runnable_queues = N;

    // One epoch honors every class exactly once, smallest-first.
    let mut order = Vec::with_capacity(N);
    for _ in 0..N {
        let mut tel = CoSQueueLeaseAcquireTelemetry::default();
        let s =
            select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], NOW_NS, &mut tel)
                .expect("one epoch must honor all 65 exact queues");
        order.push(s.queue_idx);
    }
    order.sort_unstable();
    assert_eq!(
        order,
        (0..N).collect::<Vec<_>>(),
        "the epoch's 65 selections must cover every queue exactly once"
    );
    for (queue_idx, queue) in root.queues.iter().enumerate() {
        assert_eq!(
            queue.telemetry.waterfill_counters.phase1_admissions, 1,
            "queue {queue_idx} must be honored exactly once in Phase 1"
        );
        assert_eq!(
            queue.telemetry.waterfill_counters.phase2_admissions, 0,
            "queue {queue_idx} must take no Phase-2 residual in a full-budget epoch"
        );
    }

    // The epoch is consumed but NOT wrapped: the 66th call (same frozen
    // instant, no time tick) must run the Phase-2 wrap and return `None`.
    // Pre-fix it re-honors ordinal 64 in Phase 1 — the never-marked ordinal
    // the `u64` bitset could not name.
    let mut tel = CoSQueueLeaseAcquireTelemetry::default();
    assert!(
        select_exact_cos_guarantee_queue_with_lease_telemetry(&mut root, &[], NOW_NS, &mut tel)
            .is_none(),
        "the 66th call must wrap the epoch (None), not re-honor ordinal 64 (#11680)"
    );
    assert_eq!(
        root.queues[N - 1].telemetry.waterfill_counters.phase1_admissions, 1,
        "ordinal 64 must stay honored exactly once — a second Phase-1 \
         admission is the >64 re-honor skew (#11680)"
    );
}
