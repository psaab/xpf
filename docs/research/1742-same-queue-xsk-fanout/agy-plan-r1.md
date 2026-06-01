# AGY adversarial plan-review — #1742 r1

Job: adversarial-review-mpv9rb4z-c3gnq7 (exit 0). Review-only.

**Verdict: PLAN-KILL (Path C).**

## Core findings (independently reproduced the simulation)

1. **XDP_SHARED_UMEM SPSC ring sharing (kernel-level blocker).** Plan r1
   (lines 40-41, 95) claimed each same-queue socket gets own
   FILL/COMPLETION rings. Reality: all sockets sharing one UMEM share the
   single FR + CR of that UMEM (per netdev,queue_id). Rings are lock-free
   SPSC; two workers draining one hw queue must both produce to the same
   FILL ring and consume the same COMPLETION ring → violates SPSC,
   requires userspace locking → lock contention + cache-line bouncing
   destroys zero-copy performance.

2. **Simulation unsoundness — perfect-split overstatement.**
   fanout_sim.py:43 `c//2` is deterministic; real stateless 5-tuple hash
   is Binomial(c, 0.5). Monte Carlo (100k trials, β=1.0): N=12 baseline
   0.5105, perfect 0.5100, binomial 0.5105 (no win); N=24 0.5029 / 0.5035
   / 0.5029; N=48 0.3469 / 0.3472 / 0.3469. The perfect-split model
   overstates the benefit.

3. **Capacity (β) sweep.** Processing-bound with extra cores: improves
   (N=12: −13.1% at β=1.4, −18.7% at β=2.0). Does NOT flip kill because
   (a) 6 queues / 6 workers / 6 cores → a secondary worker must steal a
   core, dropping that worker to 0 → #1243 dedicated-CPU cancellation;
   (b) shared-FILL/CQ synchronization overhead degrades effective β back
   toward 1.0, erasing software gains.

4. **Blast radius.** #1183 funnel: two ingress workers feeding one egress
   CoS queue = multi-producer bottleneck violating CoS v8
   single-owner-per-queue → reproduces the catastrophic 10× #1183
   regression. Session table split across two workers' local tables →
   session-creation races.

5. **Scope.** Plan admits (lines 169-171) no empirically failing
   workload; #1217 contract PASSes real workloads (CGNAT, CDN, proxy).

## Recommendation
Path C (PLAN-KILL). "Dead on arrival." Update state.md +
fairness-regimes.md lineage with these findings to complete the kill
archive and prevent future attempts.
