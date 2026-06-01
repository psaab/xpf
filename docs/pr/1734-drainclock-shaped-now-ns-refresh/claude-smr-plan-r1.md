# Claude-SMR adversarial plan review r1 — #1734 DrainClock

Verdict: **PLAN-KILL** (converges with AGY; Codex's three MAJORs, worked
through quantitatively, also point at KILL rather than a fixable plan).

## Reconciliation of the three reviews

- **AGY: PLAN-KILL** on a quantitative no-op proof + a new cross-worker
  shared-lease skew hazard.
- **Codex: PLAN-NEEDS-MAJOR.** Its #2 ("the gate does not measure the
  realistic no-op question") and #3 ("EWMA timing feeds the cap-aware MQFQ
  selector, needs fairness validation") are exactly the open questions whose
  *answers* (computed below) establish the no-op. Codex correctly declined to
  KILL without the measurement; AGY supplied the measurement-equivalent math.
- **SMR (this doc): KILL.** I verified AGY's two load-bearing claims and the
  new hazard against source, and confirmed Codex's EWMA-feeds-selector claim.

## Verified mechanisms

1. **Cap-aware selector does consume EWMA** (Codex #3 confirmed):
   `cos_queue_front_with_cap` -> `cos_queue_min_finish_bucket(ff, target_bps)`
   skips buckets where `flow_bucket_observed_bps[b] > target_bps`
   (queue_ops/mod.rs:113-117,147-160). So EWMA is scheduler-affecting, not
   telemetry-only — Codex is right to demand fairness validation.

2. **But EWMA does not change within a pass even with the fix** (AGY #4
   confirmed): a single `drain_shaped_tx` services <=1 batch <=64 frames.
   The inter-selection `dt` is one batch transmission, ~0.3–80 us, strictly
   below `EWMA_MIN_DT_NS = 100_000` (fairness.rs:26,74). The roll is deferred
   whether the clock is frozen or advanced by one batch. The fix therefore
   does NOT alter the observed_bps the selector reads within a pass. The
   only thing that rolls the EWMA is the next poll tick's fresh
   `loop_now_ns` — which already happens. => the fix is a no-op for the one
   mechanism that actually affects scheduling.

3. **Token refill is a no-op at realistic batch sizes** (AGY #1 confirmed):
   refill during one batch = T*R = B*S*(R/L), R<<L for a shaped class, so a
   pass cannot accrue another batch's worth mid-pass; the pass ends on token
   depletion regardless, and residual is refilled on the next poll tick µs
   later. `refill_cos_tokens` guard `now_ns <= *last_refill_ns`
   (token_bucket.rs:267) only matters across a *frozen* pass, but the amount
   at stake is sub-batch and sub-poll-tick.

4. **Park/wake tick is marginal**: `cos_tick_for_ns` granularity is 50 us
   (COS_TIMER_WHEEL_TICK_NS, tx_completion.rs:104,112). A pass advancing the
   clock by <50 us never crosses a tick; even crossing one defers at most one
   poll tick of service, which the next tick recovers.

5. **NEW HAZARD verified** (AGY #3): the shaped drain reaches
   `maybe_top_up_cos_queue_lease` -> `acquire_via_lease` -> `acquire_v8(...,
   now_ns, ...)` (token_bucket.rs:154+) which calls
   `self.maybe_rotate_epoch_v8(now_ns)` (shared_cos_lease/mod.rs:1176;
   rotate_epoch_v8.rs:27-39) with `EPOCH_DURATION_NS = 200_000`
   (mod.rs:241). Advancing one worker's clock past the 200 us epoch boundary
   mid-pass makes it the rotation winner using a clock that runs ahead of
   peers still on their poll-loop `loop_now_ns`. This is a real
   fairness/correctness REGRESSION the fix would introduce against
   #1231/#1219/#1217 — the opposite of the issue's goal.

## Decisive reasoning

The fix only has any effect if the clock advances enough to change a
threshold-gated decision. The thresholds are: token-bucket refill (continuous,
but sub-batch), EWMA 100 us, tick 50 us, epoch 200 us. A single shaped-drain
pass advances real time by at most a handful of batch transmissions
(microseconds), which is below the EWMA and (typically) tick thresholds, and
the token effect is sub-poll-tick. So:

- Where the fix would matter (crossing epoch 200 us), it introduces a
  cross-worker skew hazard.
- Where it is safe (sub-threshold), it changes nothing.

This is precisely the MEMORY #1317 unverified-perf-claim kill class: a
structurally-real freeze with no measurable consequence, where the remedy adds
risk. The #1731 plan already flagged finding #5 as "possibly a no-op,
measure-gated." The measurement (AGY's math + the threshold analysis above)
shows it IS a no-op at realistic batch sizes, with downside. **KILL.**

## If revisited

Reopen only with a captured perf trace / live counter showing a real CoS-load
drain pass that (a) runs many selections AND (b) advances real time past 100 us
within a single pass WITHOUT crossing the 200 us epoch boundary in a
peer-skewing way. Absent that evidence, the change is net-negative.
