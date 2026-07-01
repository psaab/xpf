# Claude SMR — hostile plan review r4 (#3607)

Reviewing `plan.md` v4. AGY was PLAN-READY on v3; Codex held the sketch
fail-closed as a BLOCKER (twice) and added two spec MAJORs. v4 resolves Codex by
DEFERRING the contested sketch migration and tightening the specs.

## Verdict: PLAN-READY on Option B (reduced scope), PLAN-DEFER-operator as fallback

## Round-3 findings → v4 resolution
- **Sketch fail-closed** (Codex BLOCKER, held twice): v4 §5b DEFERS the #3315
  sketch migration entirely — the contested stay-tripped→rate-enforced change is
  removed from scope and becomes a follow-up with its own fail-closed analysis.
  This is Codex's own offered resolution and also removes `now_ns` from
  `syn_rate.rs` (smaller blast radius). ✓
- **Alarm gating** (Codex MAJOR): v4 §5a pins the alarm branch to the MEASURED
  `over_attack`/`over_alarm` from the unchanged `increment_and_classify`; the OFF
  bucket drives only the drop. `syn-flood-alarm` semantics are provably unchanged
  (an over-attack SYN never reaches the `!over_attack`-gated alarm branch). ✓
- **TokenBucket cold-start** (Codex MAJOR, AGY MINOR): v4 §5 starts the bucket FULL
  on first use (`last_refill_ns == 0`), matching today's first-window admission; ✓
- **saturating_sub on the clock delta** (AGY MINOR): §5. ✓

## Residual hostile checks on v4 (no blocker)
- **Is deferring the sketch a cop-out that guts the value?** No — the standby-ACK
  failover case (item 2) is the strongest and most concrete #3607 impact and is
  retained; ICMP/UDP flood + cookie-OFF SYN are retained. The per-dest busy-server
  false-positive is the one deferred symptom, with a clear rationale (fail-closed
  semantics of a no-eviction sketch need dedicated analysis). Honest scoping, not
  avoidance.
- **Does the cold-start-full open a burst-evasion?** No more than today: the
  current `RateCounter` also admits the first `threshold` events on a fresh
  window; the token bucket's capacity = threshold caps the cold-start burst at
  exactly that, and #2937's micro-burst bound still holds.
- **Alarm ordering hole?** Checked: today `over_attack` returns before the alarm
  branch; in the OFF path an over-attack SYN that the bucket ADMITS now proceeds
  past the (skipped, `!over_attack`) alarm branch to the per-IP caps — identical
  to how an admitted packet flows today. No double-alarm, no missed alarm.
- **Convergence, not churn?** The core architecture (token-bucket shapers +
  untouched RateCounter for latch/dampener/sketch) has been stable since v2;
  rounds 3-4 only narrowed scope (deferred the sketch) and pinned
  polarity/alarm/cold-start. Converging.

## Bottom line
v4 resolves every round-3 finding, is internally consistent, and is the minimal
defensible scope both companions can accept. PLAN-READY on Option B (ICMP/UDP
flood + standby-ACK + cookie-OFF SYN aggregate; sketch deferred). Issue stays
open, label `plan-deferred-research`, awaiting manual `/engineer`.
PLAN-DEFER-operator remains an explicit fallback.
