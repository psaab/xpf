# Codex plan review r1 — #1734 DrainClock

Verdict: **PLAN-NEEDS-MAJOR** (not KILL). Session: foreground isolated.
Plan commit reviewed: bbbe9069c (content via current plan.md).

## Findings
1. **MAJOR** — End-sample refresh leaves the FIRST selection stale. The
   first `drain_shaped_tx(clock.now())` runs before `clock.observe(end_ns)`;
   refill stamps `last_refill_ns=now_ns` (token_bucket.rs:262,276) so a stale
   first selection can park/fail before any refresh. Fix: `clock.observe(start_ns)`
   BEFORE the call (reuse the already-paid START sample), same 2 reads,
   removes the backdating gap. (worker/loop_body/mod.rs:311,732;
   lifecycle.rs:79; phase_shaped.rs:45,46.)
2. **MAJOR** — Measure-first gate does NOT measure the realistic no-op
   question. Loop is uncapped (phase_shaped.rs:44; drain/mod.rs:315), batch
   <=64 (mod.rs:226; queue_service/mod.rs:1471), tick wake 50us
   (tx_completion.rs:104), EWMA 100us (fairness.rs:26). Fake-clock proves the
   mechanism, NOT that real passes last long enough. Add a live gate:
   selections/pass, pass duration, counts of passes crossing 50us/100us under
   CoS load. If almost all passes are 1 selection or below thresholds, KILL or
   narrow hard.
3. **MAJOR** — EWMA roll timing is NOT telemetry-only: it feeds the cap-aware
   MQFQ selector (`cos_queue_min_finish_bucket` skips buckets where
   observed_bps > target — queue_ops/mod.rs:88,113). #1217 is a structural-CoV
   gate (fairness-regimes.md:1061). Test plan must run a mixed-CoS/fairness
   harness or explicitly justify why EWMA timing cannot affect #1217.
4. **MINOR** — Shared-lease reasoning too narrow: root/queue leases have a
   SHARED atomic last_refill_ns (shared_cos_lease/mod.rs:943,963; residual
   surplus :172,191). No correctness hazard seen (stale peer => no refill via
   the `now<=last` guard) but say so explicitly.
5. **MINOR** — Re-ingest wording overclaims: enqueue does NOT stamp per-item
   enqueue time; now_ns materializes runtime state (cos_classify.rs:443;
   builders.rs:158); push has no timestamp (queue_ops/push.rs:20).

## Confirmed
- Within-batch coherence holds: drain_shaped_tx returns after one exact direct
  service or one submitted batch (queue_service/mod.rs:177,201), batch is one
  queue bounded by TX_BATCH_SIZE (:1457). Stack u64 clock: no borrow/lifetime
  risk.
