# Codex hostile plan-review — #1742 r1

Session: research-1742-r1-1780321523 (fresh, effort=high). Review-only,
no writes to production source.

**Verdict: PLAN-NEEDS-MAJOR** (not PLAN-READY; not PLAN-KILL yet — kill
may be right operationally but r1 had concrete kernel/math defects).

## Blocking findings

1. **"No new core" claim overbroad.** plan.md:107/:137. True only if
   bottleneck is RX/NAPI/hw bandwidth. If the worker is processing-bound
   (policy/conntrack/TX-prep) and spare cores exist, a second same-queue
   XSK worker adds real user-space service capacity. Quantified
   (split-hottest): β=1.00 → Δ≈0; β=1.25 → −0.04; β=2.0 → −0.06..−0.12.
   "The processing-bound counterargument flips the conclusion if fanout
   raises the hot queue's effective service capacity by even ~25%."
   Correct model: `hot_queue_capacity_after = min(hw ceiling, m ×
   per_worker_processing_capacity)`.

2. **Simulator not sound for hash fanout.** Metric matches production
   (population CoV, fairness.rs:20/:53; seed fine). But fanout_sim.py:69
   `c//2, c-c//2` is a *perfect* split; the real stateless 5-tuple hash
   gives Binomial(c, 0.5). Realistic split: β=1 → +0.04/+0.027/+0.022
   (WORSE), not "≈0". The r1 "delta≈0 at every N" is an artifact of the
   balanced sub-split.

3. **AF_XDP shared-UMEM ring claim wrong.** plan.md:36/:95. For same
   (netdev,queue_id): each socket own RX/TX, but ONE FILL + ONE
   COMPLETION ring per UMEM-queue tuple, SPSC. "Not 'two workers each own
   FILL/CQ'; it is two RX consumers, one shared UMEM FILL/CQ
   owner/synchronized discipline." Plan understates the frame-allocator
   problem.

4. **Blast radius real, stop calling it 'likely'.** CoS single-owner:
   coordinator/mod.rs:1355 inserts one owner_worker_id per
   (egress_ifindex,queue_id); mod.rs:1247 collapses to None on divergent
   owners; types/cos.rs:946 owner-thread single-writer. Session
   per-table (session/mod.rs:138); HA replay broadcasts synced entries
   without sub-queue slot identity (shared_ops.rs:148).

5. **Scope directionally right, overclaims evidence.** state.md:545/:583
   support "no failing workload" but cover P=12/6/24/12-push, NOT the
   motivating P=48 (plan.md:166). Weakens the evidence chain; doesn't
   rescue the design.

## Required revision
Rewrite Section 4 around β = fanned-queue-capacity / baseline; model the
binomial sub-split, not c//2. Fix Section 2.1: own RX/TX per socket,
shared FILL/CQ per (netdev,queue_id) UMEM tuple. "After those fixes, this
probably still kills on blast radius plus no failing production
workload."
