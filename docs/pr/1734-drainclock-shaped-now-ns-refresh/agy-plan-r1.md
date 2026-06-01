# AGY adversarial plan review r1 — #1734 DrainClock

Job: adversarial-review-mpug5j8f-63wt15. Verdict: **PLAN-KILL**.

## Core argument: no-op at realistic batch sizes + introduces a hazard
1. **No-op proof (token refill).** To send a batch B=64 frames of S bytes a
   queue needs B*S tokens; transmission takes T = B*S/L. Refill during T is
   T*R = B*S*(R/L). Shaped R < line rate L (often R<<L), so mid-batch refill is
   a tiny fraction of a batch's cost — the clock advancing can NEVER accrue
   enough to enable another batch in the same pass; the queue still depletes
   and the pass ends. Residual is collected on the very next poll tick (us
   scale) vs ms-scale shaping => functionally invisible. (token_bucket.rs:267.)
2. **The "free" clock read is not free on the bail-out path.** When
   drain_shaped_tx returns None the loop breaks BEFORE the end
   monotonic_nanos() (phase_shaped.rs:48,126), so there is no end sample to
   reuse; a DrainClock would need a fresh vDSO or carry stale state — added
   branch/complexity on the hot path.
3. **NEW HAZARD — cross-worker shared-lease skew.** CoS leases are shared.
   Advancing ONE worker's now_ns mid-pass while peers use their poll-loop clock:
   - Premature v8 epoch rotation: acquire_v8 -> maybe_rotate_epoch_v8(now_ns)
     (mod.rs:1176; rotate_epoch_v8.rs:39) rotates when
     now_ns >= start + EPOCH_DURATION_NS (200us). An advanced worker rotates
     early, forcing peers (still at poll-start clock) onto a fresh epoch =>
     zero/negative elapsed, torn fair-share. Breaks #1231/#1219.
   - Premature surplus-bypass grace cross (mod.rs:1323
     `bypass && now_ns < grace`) shuts the worker's bypass while peers keep it.
4. **EWMA guard renders the refresh useless anyway.** dt between selections is
   one batch (0.3–80us) < EWMA_MIN_DT_NS=100us (fairness.rs:74), so the roll is
   STILL deferred whether the clock is frozen or advanced => no EWMA change.
5. **Half-fix.** phase_backup.rs:80,165 and the leftover enqueue (:150-156)
   still use frozen ctx.now_ns, creating an asymmetric clock view in the same
   pass.

## Conclusion
Frozen clock has no practical shaping impact (us poll vs ms shaping); advancing
mid-pass adds zero value and introduces shared-lease synchronization skew.
KILL.
